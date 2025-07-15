package de.gdata.test.integration;

import com.google.gson.Gson;
import de.gdata.vaas.Sha256;
import de.gdata.vaas.Vaas;
import de.gdata.vaas.VaasConfig;
import de.gdata.vaas.authentication.ClientCredentialsGrantAuthenticator;
import de.gdata.vaas.authentication.IAuthenticator;
import de.gdata.vaas.exceptions.VaasAuthenticationException;
import de.gdata.vaas.exceptions.VaasClientException;
import de.gdata.vaas.exceptions.VaasServerException;
import de.gdata.vaas.messages.*;
import de.gdata.vaas.options.ForFileOptions;
import de.gdata.vaas.options.ForSha256Options;
import de.gdata.vaas.options.ForStreamOptions;
import de.gdata.vaas.options.ForUrlOptions;
import io.github.cdimascio.dotenv.Dotenv;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

@Slf4j
public class RealApiIntegrationTests {
    private static final String EICAR_URL = "https://samples.develop.vaas.gdatasecurity.de/eicar.com.txt";

    private static final Dotenv dotenv = Dotenv.configure()
            .ignoreIfMissing()
            .load();

    private static final SamplesFixture samplesFixture = new SamplesFixture();
    private static final IAuthenticator authenticatorFixture;
    private static final Vaas vaasWithDefaultConfig;


    static {
        authenticatorFixture = getAuthenticator();
        vaasWithDefaultConfig = getVaasWithAuthenticator(authenticatorFixture);
    }

    private static String getEnvironmentKey(String key) {
        var value = dotenv.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Environment variable " + key + " must be set.");
        }
        return value;
    }

    private static IAuthenticator getAuthenticator() {
        var clientId = getEnvironmentKey("CLIENT_ID");
        var clientSecret = getEnvironmentKey("CLIENT_SECRET");
        var tokenUrl = URI.create(getEnvironmentKey("TOKEN_URL"));
        return new ClientCredentialsGrantAuthenticator(clientId, clientSecret, tokenUrl);
    }

    private static IAuthenticator getAuthenticator(HttpClient httpClient) {
        var clientId = getEnvironmentKey("CLIENT_ID");
        var clientSecret = getEnvironmentKey("CLIENT_SECRET");
        var tokenUrl = URI.create(getEnvironmentKey("TOKEN_URL"));
        return new ClientCredentialsGrantAuthenticator(clientId, clientSecret, tokenUrl, httpClient);
    }

    private static Vaas getVaasWithAuthenticator(IAuthenticator authenticator) {
        var vaasUrl = getEnvironmentKey("VAAS_URL");
        var config = new VaasConfig(URI.create(vaasUrl));
        return new Vaas(config, authenticator);
    }

    private static Vaas getVaasWithMockedClient(HttpClient httpClient) {
        var vaasUrl = getEnvironmentKey("VAAS_URL");
        var config = new VaasConfig(URI.create(vaasUrl));
        return new Vaas(config, authenticatorFixture, httpClient);
    }

    public static byte[] readContent(HttpRequest.BodyPublisher bodyPublisher) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        bodyPublisher.subscribe(new Flow.Subscriber<>() {

            @Override
            public void onSubscribe(Flow.Subscription subscription) {
                subscription.request(Long.MAX_VALUE);
            }

            @Override
            public void onNext(ByteBuffer item) {
                byte[] bytes = new byte[item.remaining()];
                item.get(bytes);
                outputStream.write(bytes, 0, bytes.length);
            }

            @Override
            public void onError(Throwable throwable) {
                throwable.printStackTrace();
            }

            @Override
            public void onComplete() {
            }
        });
        return outputStream.toByteArray();
    }

    @ParameterizedTest
    @CsvSource({
            "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e, CLEAN",
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f, MALICIOUS",
            "d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad, PUP"
    })
    public void forSha256_ReturnsVerdict(String sha256, Verdict verdict) {
        var sha256sum = new Sha256(sha256);

        var vaasVerdict = vaasWithDefaultConfig.forSha256Async(sha256sum).join();

        assertEquals(sha256, vaasVerdict.getSha256());
        assertEquals(verdict, vaasVerdict.getVerdict());
    }

    @SuppressWarnings("unchecked")
    @ParameterizedTest
    @CsvSource({
            "false, false",
            "false, true",
            "true, false",
            "true, true",
    })
    @Tag("Mock")
    public void forSha256_SendOptions(boolean useCache, boolean useHashLookup) {
        var sha256 = new Sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
        var requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        var mockHttpClient = mock(HttpClient.class);
        var mockResponse = mock(HttpResponse.class);
        var forSha256Options = new ForSha256Options(useCache, useHashLookup, "foobar");
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(
                new Gson().toJson(new FileReport(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                        Verdict.UNKNOWN, null, null, null)));
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);
        var vaasVerdict = vaas.forSha256Async(sha256, forSha256Options).join();
        verify(mockHttpClient).sendAsync(requestCaptor.capture(), any(HttpResponse.BodyHandler.class));
        var capturedUri = requestCaptor.getValue().uri();

        assertTrue(capturedUri.toString().contains(String.format("useCache=%s", useCache)));
        assertTrue(capturedUri.toString()
                .contains(String.format("useHashLookup=%s", useHashLookup)));
        assertEquals(Verdict.UNKNOWN, vaasVerdict.getVerdict());
        assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                .equalsIgnoreCase(vaasVerdict.getSha256()));
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forSha256_SendUserAgent() {
        var sha256 = new Sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
        var requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        var mockHttpClient = mock(HttpClient.class);
        var mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(
                new Gson().toJson(new FileReport(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                        Verdict.UNKNOWN, null, null, null)));
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);
        var vaasVerdict = vaas.forSha256Async(sha256).join();
        verify(mockHttpClient).sendAsync(requestCaptor.capture(), any(HttpResponse.BodyHandler.class));
        var capturedUserAgent = requestCaptor.getValue().headers().firstValue("User-Agent");

        assertTrue(capturedUserAgent.toString().contains("Java"));
        assertEquals(Verdict.UNKNOWN, vaasVerdict.getVerdict());
        assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                .equalsIgnoreCase(vaasVerdict.getSha256()));
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forSha256_IfVaasRequestIdIsSet_SendTraceState() {
        var sha256 = new Sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
        var requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        var mockHttpClient = mock(HttpClient.class);
        var mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(
                new Gson().toJson(new FileReport(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                        Verdict.UNKNOWN, null, null, null)));
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);
        var forSha256Options = new ForSha256Options(true, true, "foobar");
        var vaasVerdict = vaas.forSha256Async(sha256, forSha256Options).join();

        verify(mockHttpClient).sendAsync(requestCaptor.capture(), any(HttpResponse.BodyHandler.class));
        var capturedTraceState = requestCaptor.getValue().headers().firstValue("tracestate");

        assertTrue(capturedTraceState.toString().contains("foobar"));
        assertEquals(Verdict.UNKNOWN, vaasVerdict.getVerdict());
        assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                .equalsIgnoreCase(vaasVerdict.getSha256()));
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forSha256_IfBadRequest_ThrowsVaasClientException() {
        var sha256 = new Sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
        var mockHttpClient = mock(HttpClient.class);
        var mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(400);
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockResponse));
        when(mockResponse.body()).thenReturn(
                new Gson().toJson(new ProblemDetails("VaasClientException", "Bad Request")));

        var vaas = getVaasWithMockedClient(mockHttpClient);

        var exception = assertThrows(CompletionException.class, () -> vaas.forSha256Async(sha256).join());
        assertInstanceOf(VaasClientException.class, exception.getCause());
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forSha256_IfInternalServerError_ThrowsVaasServerException() {
        var sha256 = new Sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
        var mockHttpClient = mock(HttpClient.class);
        var mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(500);
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);

        var exception = assertThrows(CompletionException.class, () -> vaas.forSha256Async(sha256).join());
        assertInstanceOf(VaasServerException.class, exception.getCause());
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forSha256_IfUnauthorized_ThrowsVaasAuthenticationException() {
        var sha256 = new Sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
        var mockHttpClient = mock(HttpClient.class);
        var mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(401);
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockResponse));

        var authenticator = getAuthenticator(mockHttpClient);
        var vaas = getVaasWithAuthenticator(authenticator);

        assertThrows(VaasAuthenticationException.class, () -> vaas.forSha256(sha256));
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forSha256_IfAuthenticatorFailed_ThrowsVaasAuthenticationException() throws Exception {
        var sha256 = new Sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
        var mockHttpClient = mock(HttpClient.class);
        var mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(401);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> mockResponse);

        var authenticator = getAuthenticator(mockHttpClient);
        var vaas = getVaasWithAuthenticator(authenticator);

        assertThrows(VaasAuthenticationException.class, () -> vaas.forSha256(sha256));
    }

    @Test
    public void forSha256_IfCancellationIsRequested_ThrowsCancellationException() {
        var sha256 = new Sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");

        var future = vaasWithDefaultConfig.forSha256Async(sha256);

        var result = future.cancel(true);
        assertTrue(result);
        assertThrows(CancellationException.class, future::get);
    }

    @ParameterizedTest
    @MethodSource("provideForFileParams")
    public void forFile_ReturnsVerdict(Path tmpFile, Verdict verdict) throws Exception {
        var vaasVerdict = vaasWithDefaultConfig.forFileAsync(tmpFile).join();

        assertEquals(verdict, vaasVerdict.getVerdict());
    }

    private static Stream<Arguments> provideForFileParams() throws VaasClientException, IOException, InterruptedException {
        return Stream.of(
                Arguments.of(samplesFixture.getCleanSample(), Verdict.CLEAN),
                Arguments.of(samplesFixture.getEicarSample(), Verdict.MALICIOUS),
                Arguments.of(samplesFixture.getPupSample(), Verdict.PUP)
        );
    }

    @SuppressWarnings("unchecked")
    @ParameterizedTest
    @CsvSource({
            "false, false",
            "false, true",
            "true, false",
            "true, true",
    })
    @Tag("Mock")
    public void forFile_SendOptions(boolean useCache, boolean useHashLookup) throws Exception {
        var tmpFile = samplesFixture.getEicarSample();
        var requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        var mockHttpClient = mock(HttpClient.class);
        var mockPostResponse = mock(HttpResponse.class);
        var mockGetResponse = mock(HttpResponse.class);
        var forFileOptions = new ForFileOptions(useCache, useHashLookup, "foobar");

        when(mockGetResponse.statusCode()).thenReturn(200);
        when(mockGetResponse.body()).thenReturn(
                new Gson().toJson(new FileReport(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                        Verdict.UNKNOWN, null, null, null)));
        when(mockPostResponse.statusCode()).thenReturn(200);
        when(mockPostResponse.body()).thenReturn(new Gson().toJson(new FileAnalysisStarted(
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")));

        when(mockHttpClient.sendAsync(
                argThat(getRequest -> getRequest != null
                        && getRequest.method().equals("GET")
                        && getRequest.uri().toString().contains(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
                        && getRequest.uri().toString()
                        .contains("useCache=" + useCache)
                        && getRequest.uri().toString().contains(
                        "useHashLookup=" + useHashLookup)),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockGetResponse));

        if (!useCache) {
            when(mockHttpClient.sendAsync(
                    argThat(getRequest -> getRequest != null
                            && getRequest.method().equals("GET")
                            && getRequest.uri().toString().contains(
                            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
                            && getRequest.uri().toString()
                            .contains("useCache=" + true)
                            && getRequest.uri().toString()
                            .contains("useHashLookup=" + useHashLookup)),
                    any(HttpResponse.BodyHandler.class)))
                    .thenAnswer(invocation -> CompletableFuture.completedFuture(mockGetResponse));
        }

        when(mockHttpClient.sendAsync(
                argThat(postRequest -> postRequest != null
                        && postRequest.method().equals("POST")
                        && postRequest.uri().toString().contains("files")
                        && postRequest.uri().toString().contains(
                        "useHashLookup=" + useHashLookup)),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockPostResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);
        var vaasVerdict = vaas.forFileAsync(tmpFile, forFileOptions).join();
        verify(mockHttpClient, times(3)).sendAsync(requestCaptor.capture(),
                any(HttpResponse.BodyHandler.class));
        var firstRequestUri = requestCaptor.getAllValues().get(0).uri();
        var secondRequestUri = requestCaptor.getAllValues().get(1).uri();
        var thirdRequestUri = requestCaptor.getAllValues().get(2).uri();

        assertTrue(firstRequestUri.toString().contains(String.format("useCache=%s", useCache)));
        assertTrue(firstRequestUri.toString()
                .contains(String.format("useHashLookup=%s", useHashLookup)));
        assertTrue(secondRequestUri.toString()
                .contains(String.format("useHashLookup=%s", useHashLookup)));
        assertTrue(thirdRequestUri.toString()
                .contains(String.format("useHashLookup=%s", useHashLookup)));
        assertEquals(Verdict.UNKNOWN, vaasVerdict.getVerdict());
        assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                .equalsIgnoreCase(vaasVerdict.getSha256()));
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forFile_SendUserAgent() throws Exception {
        var tmpFile = samplesFixture.getEicarSample();

        var requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        var mockHttpClient = mock(HttpClient.class);
        var mockPostResponse = mock(HttpResponse.class);
        var mockGetResponse = mock(HttpResponse.class);
        when(mockGetResponse.statusCode()).thenReturn(200);
        when(mockGetResponse.body()).thenReturn(
                new Gson().toJson(new FileReport(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                        Verdict.UNKNOWN, null, null, null)));
        when(mockPostResponse.statusCode()).thenReturn(200);
        when(mockPostResponse.body()).thenReturn(new Gson().toJson(new FileAnalysisStarted(
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")));

        when(mockHttpClient.sendAsync(
                argThat(getRequest -> getRequest != null
                        && getRequest.method().equals("GET")
                        && getRequest.uri().toString().contains(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
                        && getRequest.uri().toString()
                        .contains("useCache=" + true)
                        && getRequest.uri().toString()
                        .contains("useHashLookup=" + true)
                        && getRequest.headers().firstValue("User-Agent").toString()
                        .contains("Java")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockGetResponse));

        when(mockHttpClient.sendAsync(
                argThat(postRequest -> postRequest != null
                        && postRequest.method().equals("POST")
                        && postRequest.uri().toString().contains("files")
                        && postRequest.uri().toString()
                        .contains("useHashLookup=" + true)
                        && postRequest.headers().firstValue("User-Agent").toString()
                        .contains("Java")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockPostResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);
        var vaasVerdict = vaas.forFileAsync(tmpFile).join();
        verify(mockHttpClient, times(3)).sendAsync(requestCaptor.capture(),
                any(HttpResponse.BodyHandler.class));
        var firstRequestHeaders = requestCaptor.getAllValues().get(0).headers().firstValue("User-Agent");
        var secondRequestHeaders = requestCaptor.getAllValues().get(1).headers().firstValue("User-Agent");
        var thirdRequestHeaders = requestCaptor.getAllValues().get(2).headers().firstValue("User-Agent");

        assertTrue(firstRequestHeaders.toString().contains("Java"));
        assertTrue(secondRequestHeaders.toString().contains("Java"));
        assertTrue(thirdRequestHeaders.toString().contains("Java"));
        assertEquals(Verdict.UNKNOWN, vaasVerdict.getVerdict());
        assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                .equalsIgnoreCase(vaasVerdict.getSha256()));
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forFile_IfVaasRequestIdIsSet_SendTraceState() throws Exception {
        var tmpFile = samplesFixture.getEicarSample();

        var requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        var mockHttpClient = mock(HttpClient.class);
        var mockPostResponse = mock(HttpResponse.class);
        var mockGetResponse = mock(HttpResponse.class);
        when(mockGetResponse.statusCode()).thenReturn(200);
        when(mockGetResponse.body()).thenReturn(
                new Gson().toJson(new FileReport(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                        Verdict.UNKNOWN, null, null, null)));
        when(mockPostResponse.statusCode()).thenReturn(200);
        when(mockPostResponse.body()).thenReturn(new Gson().toJson(new FileAnalysisStarted(
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")));

        when(mockHttpClient.sendAsync(
                argThat(getRequest -> getRequest != null
                        && getRequest.method().equals("GET")
                        && getRequest.uri().toString().contains(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
                        && getRequest.uri().toString()
                        .contains("useCache=" + true)
                        && getRequest.uri().toString()
                        .contains("useHashLookup=" + true)
                        && getRequest.headers().firstValue("tracestate").toString()
                        .contains("foobar")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockGetResponse));

        when(mockHttpClient.sendAsync(
                argThat(postRequest -> postRequest != null
                        && postRequest.method().equals("POST")
                        && postRequest.uri().toString().contains("files")
                        && postRequest.uri().toString()
                        .contains("useHashLookup=" + true)
                        && postRequest.headers().firstValue("tracestate").toString()
                        .contains("foobar")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockPostResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);
        var forFileOptions = new ForFileOptions(true, true, "foobar");
        var vaasVerdict = vaas.forFileAsync(tmpFile, forFileOptions).join();
        verify(mockHttpClient, times(3)).sendAsync(requestCaptor.capture(),
                any(HttpResponse.BodyHandler.class));
        var firstRequestHeaders = requestCaptor.getAllValues().get(0).headers().firstValue("tracestate");
        var secondRequestHeaders = requestCaptor.getAllValues().get(1).headers().firstValue("tracestate");
        var thirdRequestHeaders = requestCaptor.getAllValues().get(2).headers().firstValue("tracestate");

        assertTrue(firstRequestHeaders.toString().contains("foobar"));
        assertTrue(secondRequestHeaders.toString().contains("foobar"));
        assertTrue(thirdRequestHeaders.toString().contains("foobar"));
        assertEquals(Verdict.UNKNOWN, vaasVerdict.getVerdict());
        assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                .equalsIgnoreCase(vaasVerdict.getSha256()));
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forFile_IfBadRequest_ThrowsVaasClientException() throws Exception {
        var tmpFile = samplesFixture.getEicarSample();

        var mockHttpClient = mock(HttpClient.class);
        var mockPostResponse = mock(HttpResponse.class);
        var mockGetResponse = mock(HttpResponse.class);
        when(mockGetResponse.statusCode()).thenReturn(200);
        when(mockGetResponse.body()).thenReturn(
                new Gson().toJson(new FileReport(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                        Verdict.UNKNOWN, null, null, null)));
        when(mockPostResponse.statusCode()).thenReturn(400);
        when(mockPostResponse.body()).thenReturn(new Gson()
                .toJson(new ProblemDetails("VaasClientException", "Client-side error occurred")));

        when(mockHttpClient.sendAsync(
                argThat(getRequest -> getRequest != null
                        && getRequest.method().equals("GET")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockGetResponse));

        when(mockHttpClient.sendAsync(
                argThat(postRequest -> postRequest != null
                        && postRequest.method().equals("POST")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockPostResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);

        var exception = assertThrows(CompletionException.class, () -> vaas.forFileAsync(tmpFile).join());
        assertInstanceOf(VaasClientException.class, exception.getCause());
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forFile_IfInternalServerError_ThrowsVaasServerException()
            throws Exception {
        var tmpFile = samplesFixture.getEicarSample();

        var mockHttpClient = mock(HttpClient.class);
        var mockPostResponse = mock(HttpResponse.class);
        var mockGetResponse = mock(HttpResponse.class);
        when(mockGetResponse.statusCode()).thenReturn(200);
        when(mockGetResponse.body()).thenReturn(
                new Gson().toJson(new FileReport(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                        Verdict.UNKNOWN, null, null, null)));
        when(mockPostResponse.statusCode()).thenReturn(500);
        when(mockPostResponse.body()).thenReturn(new Gson()
                .toJson(new ProblemDetails("VaasServerException", "Server-side error occurred")));

        when(mockHttpClient.sendAsync(
                argThat(getRequest -> getRequest != null
                        && getRequest.method().equals("GET")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockGetResponse));

        when(mockHttpClient.sendAsync(
                argThat(postRequest -> postRequest != null
                        && postRequest.method().equals("POST")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockPostResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);

        var exception = assertThrows(CompletionException.class, () -> vaas.forFileAsync(tmpFile).join());
        assertInstanceOf(VaasServerException.class, exception.getCause());
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forFile_IfUnauthorized_ThrowsVaasAuthenticationException()
            throws Exception {
        var tmpFile = samplesFixture.getEicarSample();

        var mockHttpClient = mock(HttpClient.class);
        var mockPostResponse = mock(HttpResponse.class);
        var mockGetResponse = mock(HttpResponse.class);
        when(mockGetResponse.statusCode()).thenReturn(200);
        when(mockGetResponse.body()).thenReturn(
                new Gson().toJson(new FileReport(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                        Verdict.UNKNOWN, null, null, null)));
        when(mockPostResponse.statusCode()).thenReturn(401);
        when(mockPostResponse.body()).thenReturn(new Gson()
                .toJson(new ProblemDetails("VaasAuthenticationException", "Authentication failed.")));

        when(mockHttpClient.sendAsync(
                argThat(getRequest -> getRequest != null
                        && getRequest.method().equals("GET")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockGetResponse));

        when(mockHttpClient.sendAsync(
                argThat(postRequest -> postRequest != null
                        && postRequest.method().equals("POST")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockPostResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);

        var exception = assertThrows(CompletionException.class, () -> vaas.forFileAsync(tmpFile).join());
        assertInstanceOf(VaasAuthenticationException.class, exception.getCause());
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forFile_IfAuthenticatorFailed_ThrowsVaasAuthenticationException() throws Exception {
        var tmpFile = samplesFixture.getEicarSample();

        var mockHttpClient = mock(HttpClient.class);
        var mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(401);
        when(mockHttpClient.send(any(HttpRequest.class),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> mockResponse);

        var authenticator = getAuthenticator(mockHttpClient);
        var vaas = getVaasWithAuthenticator(authenticator);

        assertThrows(VaasAuthenticationException.class, () -> vaas.forFile(tmpFile));
    }

    @Test
    public void forFile_IfCancellationIsRequested_ThrowsCancellationException()
            throws Exception {
        var tmpFile = samplesFixture.getEicarSample();

        var future = vaasWithDefaultConfig.forFileAsync(tmpFile);

        var result = future.cancel(true);
        assertTrue(result);
        assertThrows(CancellationException.class, future::get);
    }

    @Test
    @Disabled("This test is disabled because it takes too long to run.")
    public void forFile_BigFileWithSmallTimeout_ThrowsTimeoutException()
            throws Exception {
        var tmpFile = Path.of(System.getProperty("java.io.tmpdir"), "file.txt");
        var url = URI.create("https://ash-speed.hetzner.com/1GB.bin").toURL();
        var conn = url.openConnection();
        var inputStream = conn.getInputStream();
        Files.copy(inputStream, tmpFile, StandardCopyOption.REPLACE_EXISTING);

        var vaasUrl = getEnvironmentKey("VAAS_URL");
        var config = new VaasConfig(1000, URI.create(vaasUrl));
        var vaas = new Vaas(config, authenticatorFixture);
        var forFileOptions = new ForFileOptions(false, false, null);

        var exception = assertThrows(ExecutionException.class, () -> vaas.forFileAsync(tmpFile, forFileOptions).get());
        assertInstanceOf(TimeoutException.class, exception.getCause());
    }

    @Test
    public void forFile_EmptyFile_ReturnsVerdict() throws Exception {
        var file = new File(System.getProperty("java.io.tmpdir"), "empty.txt");
        file.createNewFile();

        var vaasVerdict = vaasWithDefaultConfig.forFileAsync(file.toPath()).join();

        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", vaasVerdict.getSha256());
        assertEquals(Verdict.CLEAN, vaasVerdict.getVerdict());
    }

    @Test
    public void forStream_ReturnsVerdict() throws Exception {
        var url = URI.create(EICAR_URL).toURL();
        var conn = url.openConnection();
        var inputStream = conn.getInputStream();
        var contentLength = conn.getContentLength();
        var forStreamOptions = new ForStreamOptions(true, "foobar");

        var verdict = vaasWithDefaultConfig.forStreamAsync(inputStream, contentLength, forStreamOptions).join();

        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
        assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                .equalsIgnoreCase(verdict.getSha256()));
    }

    @SuppressWarnings("unchecked")
    @ParameterizedTest
    @CsvSource({
            "false",
            "true",
    })
    @Tag("Mock")
    public void forStream_SendOptions(boolean useHashLookup) throws Exception {
        var url = URI.create(EICAR_URL).toURL();
        var conn = url.openConnection();
        var inputStream = conn.getInputStream();
        var contentLength = conn.getContentLength();

        var requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        var mockHttpClient = mock(HttpClient.class);
        var mockPostResponse = mock(HttpResponse.class);
        var mockGetResponse = mock(HttpResponse.class);
        var forStreamOptions = new ForStreamOptions(useHashLookup, "foobar");

        when(mockGetResponse.statusCode()).thenReturn(200);
        when(mockGetResponse.body()).thenReturn(
                new Gson().toJson(new FileReport(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                        Verdict.UNKNOWN, null, null, null)));
        when(mockPostResponse.statusCode()).thenReturn(200);
        when(mockPostResponse.body()).thenReturn(new Gson().toJson(new FileAnalysisStarted(
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")));

        when(mockHttpClient.sendAsync(
                argThat(getRequest -> getRequest != null
                        && getRequest.method().equals("GET")
                        && getRequest.uri().toString().contains(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
                        && getRequest.uri().toString()
                        .contains("useCache=" + true)
                        && getRequest.uri().toString()
                        .contains("useHashLookup=" + useHashLookup)),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockGetResponse));

        when(mockHttpClient.sendAsync(
                argThat(postRequest -> postRequest != null
                        && postRequest.method().equals("POST")
                        && postRequest.uri().toString().contains("files")
                        && postRequest.uri().toString().contains(
                        "useHashLookup=" + useHashLookup)),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockPostResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);
        var vaasVerdict = vaas.forStreamAsync(inputStream, contentLength, forStreamOptions).join();
        verify(mockHttpClient, times(2)).sendAsync(requestCaptor.capture(),
                any(HttpResponse.BodyHandler.class));
        var firstRequestUri = requestCaptor.getAllValues().get(0).uri();
        var secondRequestUri = requestCaptor.getAllValues().get(1).uri();

        assertTrue(firstRequestUri.toString()
                .contains(String.format("useHashLookup=%s", useHashLookup)));
        assertTrue(secondRequestUri.toString()
                .contains(String.format("useHashLookup=%s", useHashLookup)));
        assertEquals(Verdict.UNKNOWN, vaasVerdict.getVerdict());
        assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                .equalsIgnoreCase(vaasVerdict.getSha256()));
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forStream_SendUserAgent() throws Exception {
        var url = URI.create(EICAR_URL).toURL();
        var conn = url.openConnection();
        var inputStream = conn.getInputStream();
        var contentLength = conn.getContentLength();

        var requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        var mockHttpClient = mock(HttpClient.class);
        var mockPostResponse = mock(HttpResponse.class);
        var mockGetResponse = mock(HttpResponse.class);
        when(mockGetResponse.statusCode()).thenReturn(200);
        when(mockGetResponse.body()).thenReturn(
                new Gson().toJson(new FileReport(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                        Verdict.UNKNOWN, null, null, null)));
        when(mockPostResponse.statusCode()).thenReturn(200);
        when(mockPostResponse.body()).thenReturn(new Gson().toJson(new FileAnalysisStarted(
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")));

        when(mockHttpClient.sendAsync(
                argThat(getRequest -> getRequest != null
                        && getRequest.method().equals("GET")
                        && getRequest.uri().toString().contains(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
                        && getRequest.uri().toString()
                        .contains("useCache=" + true)
                        && getRequest.uri().toString()
                        .contains("useHashLookup=" + true)
                        && getRequest.headers().firstValue("User-Agent").toString()
                        .contains("Java")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockGetResponse));

        when(mockHttpClient.sendAsync(
                argThat(postRequest -> postRequest != null
                        && postRequest.method().equals("POST")
                        && postRequest.uri().toString().contains("files")
                        && postRequest.uri().toString()
                        .contains("useHashLookup=" + true)
                        && postRequest.headers().firstValue("User-Agent").toString()
                        .contains("Java")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockPostResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);
        var vaasVerdict = vaas.forStreamAsync(inputStream, contentLength).join();
        verify(mockHttpClient, times(2)).sendAsync(requestCaptor.capture(),
                any(HttpResponse.BodyHandler.class));
        var firstRequestHeaders = requestCaptor.getAllValues().get(0).headers().firstValue("User-Agent");
        var secondRequestHeaders = requestCaptor.getAllValues().get(1).headers().firstValue("User-Agent");

        assertTrue(firstRequestHeaders.toString().contains("Java"));
        assertTrue(secondRequestHeaders.toString().contains("Java"));
        assertEquals(Verdict.UNKNOWN, vaasVerdict.getVerdict());
        assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                .equalsIgnoreCase(vaasVerdict.getSha256()));
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forStream_IfVaasRequestIdIsSet_SendTraceState() throws Exception {
        var url = URI.create(EICAR_URL).toURL();
        var conn = url.openConnection();
        var inputStream = conn.getInputStream();
        var contentLength = conn.getContentLength();

        var requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        var mockHttpClient = mock(HttpClient.class);
        var mockPostResponse = mock(HttpResponse.class);
        var mockGetResponse = mock(HttpResponse.class);
        when(mockGetResponse.statusCode()).thenReturn(200);
        when(mockGetResponse.body()).thenReturn(
                new Gson().toJson(new FileReport(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                        Verdict.UNKNOWN, null, null, null)));
        when(mockPostResponse.statusCode()).thenReturn(200);
        when(mockPostResponse.body()).thenReturn(new Gson().toJson(new FileAnalysisStarted(
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")));

        when(mockHttpClient.sendAsync(
                argThat(getRequest -> getRequest != null
                        && getRequest.method().equals("GET")
                        && getRequest.uri().toString().contains(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
                        && getRequest.uri().toString()
                        .contains("useCache=" + true)
                        && getRequest.uri().toString()
                        .contains("useHashLookup=" + true)
                        && getRequest.headers().firstValue("tracestate").toString()
                        .contains("foobar")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockGetResponse));

        when(mockHttpClient.sendAsync(
                argThat(postRequest -> postRequest != null
                        && postRequest.method().equals("POST")
                        && postRequest.uri().toString().contains("files")
                        && postRequest.uri().toString()
                        .contains("useHashLookup=" + true)
                        && postRequest.headers().firstValue("tracestate").toString()
                        .contains("foobar")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockPostResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);
        var forFileOptions = new ForStreamOptions(true, "foobar");
        var vaasVerdict = vaas.forStreamAsync(inputStream, contentLength, forFileOptions).join();
        verify(mockHttpClient, times(2)).sendAsync(requestCaptor.capture(),
                any(HttpResponse.BodyHandler.class));
        var firstRequestHeaders = requestCaptor.getAllValues().get(0).headers().firstValue("tracestate");
        var secondRequestHeaders = requestCaptor.getAllValues().get(1).headers().firstValue("tracestate");

        assertTrue(firstRequestHeaders.toString().contains("foobar"));
        assertTrue(secondRequestHeaders.toString().contains("foobar"));
        assertEquals(Verdict.UNKNOWN, vaasVerdict.getVerdict());
        assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                .equalsIgnoreCase(vaasVerdict.getSha256()));
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forStream_IfBadRequest_ThrowsVaasClientException() throws Exception {
        var url = URI.create(EICAR_URL).toURL();
        var conn = url.openConnection();
        var inputStream = conn.getInputStream();
        var contentLength = conn.getContentLength();

        var mockHttpClient = mock(HttpClient.class);
        var mockPostResponse = mock(HttpResponse.class);
        var mockGetResponse = mock(HttpResponse.class);
        when(mockGetResponse.statusCode()).thenReturn(200);
        when(mockGetResponse.body()).thenReturn(
                new Gson().toJson(new FileReport(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                        Verdict.UNKNOWN, null, null, null)));
        when(mockPostResponse.statusCode()).thenReturn(400);
        when(mockPostResponse.body()).thenReturn(new Gson()
                .toJson(new ProblemDetails("VaasClientException", "Client-side error occurred")));

        when(mockHttpClient.sendAsync(
                argThat(getRequest -> getRequest != null
                        && getRequest.method().equals("GET")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockGetResponse));

        when(mockHttpClient.sendAsync(
                argThat(postRequest -> postRequest != null
                        && postRequest.method().equals("POST")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockPostResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);

        var exception = assertThrows(CompletionException.class, () -> vaas.forStreamAsync(inputStream, contentLength).join());
        assertInstanceOf(VaasClientException.class, exception.getCause());
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forStream_IfInternalServerError_ThrowsVaasServerException()
            throws Exception {
        var url = URI.create(EICAR_URL).toURL();
        var conn = url.openConnection();
        var inputStream = conn.getInputStream();
        var contentLength = conn.getContentLength();

        var mockHttpClient = mock(HttpClient.class);
        var mockPostResponse = mock(HttpResponse.class);
        var mockGetResponse = mock(HttpResponse.class);
        when(mockGetResponse.statusCode()).thenReturn(200);
        when(mockGetResponse.body()).thenReturn(
                new Gson().toJson(new FileReport(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                        Verdict.UNKNOWN, null, null, null)));
        when(mockPostResponse.statusCode()).thenReturn(500);
        when(mockPostResponse.body()).thenReturn(new Gson()
                .toJson(new ProblemDetails("VaasServerException", "Server-side error occurred")));

        when(mockHttpClient.sendAsync(
                argThat(getRequest -> getRequest != null
                        && getRequest.method().equals("GET")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockGetResponse));

        when(mockHttpClient.sendAsync(
                argThat(postRequest -> postRequest != null
                        && postRequest.method().equals("POST")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockPostResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);

        var exception = assertThrows(CompletionException.class, () -> vaas.forStreamAsync(inputStream, contentLength).join());
        assertInstanceOf(VaasServerException.class, exception.getCause());
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forStream_IfUnauthorized_ThrowsVaasAuthenticationException()
            throws Exception {
        var url = URI.create(EICAR_URL).toURL();
        var conn = url.openConnection();
        var inputStream = conn.getInputStream();
        var contentLength = conn.getContentLength();

        var mockHttpClient = mock(HttpClient.class);
        var mockPostResponse = mock(HttpResponse.class);
        var mockGetResponse = mock(HttpResponse.class);
        when(mockGetResponse.statusCode()).thenReturn(200);
        when(mockGetResponse.body()).thenReturn(
                new Gson().toJson(new FileReport(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                        Verdict.UNKNOWN, null, null, null)));
        when(mockPostResponse.statusCode()).thenReturn(401);
        when(mockPostResponse.body()).thenReturn(new Gson()
                .toJson(new ProblemDetails("VaasAuthenticationException", "Authentication failed.")));

        when(mockHttpClient.sendAsync(
                argThat(getRequest -> getRequest != null
                        && getRequest.method().equals("GET")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockGetResponse));

        when(mockHttpClient.sendAsync(
                argThat(postRequest -> postRequest != null
                        && postRequest.method().equals("POST")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockPostResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);

        var exception = assertThrows(CompletionException.class, () -> vaas.forStreamAsync(inputStream, contentLength).join());
        assertInstanceOf(VaasAuthenticationException.class, exception.getCause());
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forStream_IfAuthenticatorFailed_ThrowsVaasAuthenticationException() throws Exception {
        var url = URI.create(EICAR_URL).toURL();
        var conn = url.openConnection();
        var inputStream = conn.getInputStream();
        var contentLength = conn.getContentLength();

        var mockHttpClient = mock(HttpClient.class);
        var mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(401);
        when(mockHttpClient.send(any(HttpRequest.class),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> mockResponse);

        var authenticator = getAuthenticator(mockHttpClient);
        var vaas = getVaasWithAuthenticator(authenticator);

        assertThrows(VaasAuthenticationException.class, () -> vaas.forStream(inputStream, contentLength));
    }

    @Test
    public void forStream_IfCancellationIsRequested_ThrowsCancellationException()
            throws Exception {
        var url = URI.create(EICAR_URL).toURL();
        var conn = url.openConnection();
        var inputStream = conn.getInputStream();
        var contentLength = conn.getContentLength();

        var future = vaasWithDefaultConfig.forStreamAsync(inputStream, contentLength);

        var result = future.cancel(true);
        assertTrue(result);
        assertThrows(CancellationException.class, future::get);
    }

    @Test
    @Disabled("Fails for unknown reason in some environments. TODO: Rewrite using a stream, that does not provide data.")
    public void forStream_BigFileWithSmallTimeout_ThrowsTimeoutException()
            throws Exception {
        var url = URI.create("https://ash-speed.hetzner.com/1GB.bin").toURL();
        var conn = url.openConnection();
        var inputStream = conn.getInputStream();
        var contentLength = conn.getContentLength();

        var vaasUrl = getEnvironmentKey("VAAS_URL");
        var config = new VaasConfig(1000, URI.create(vaasUrl));
        var vaas = new Vaas(config, authenticatorFixture);
        var forStreamOptions = new ForStreamOptions(false, null);

        var exception = assertThrows(ExecutionException.class, () -> vaas.forStreamAsync(inputStream, contentLength, forStreamOptions).get());
        assertInstanceOf(TimeoutException.class, exception.getCause());
    }

    @Test
    public void forStream_EmptyFile_ReturnsVerdict() throws Exception {
        var stream = new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8));

        var vaasVerdict = vaasWithDefaultConfig.forStreamAsync(stream, 0).join();

        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", vaasVerdict.getSha256());
        assertEquals(Verdict.CLEAN, vaasVerdict.getVerdict());
    }

    @Test
    public void forUrl_ReturnsVerdict() throws Exception {
        var url = URI.create(EICAR_URL).toURL();

        var verdict = vaasWithDefaultConfig.forUrlAsync(url).join();

        assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
        assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                .equalsIgnoreCase(verdict.getSha256()));
    }

    @SuppressWarnings("unchecked")
    @ParameterizedTest
    @CsvSource({
            "false",
            "true",
    })
    @Tag("Mock")
    public void forUrl_SendOptions(boolean useHashLookup) throws Exception {
        var url = URI.create(EICAR_URL).toURL();

        var requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        var mockHttpClient = mock(HttpClient.class);
        var mockPostResponse = mock(HttpResponse.class);
        var mockGetResponse = mock(HttpResponse.class);
        var forUrlOptions = new ForUrlOptions(useHashLookup, "foobar");

        when(mockGetResponse.statusCode()).thenReturn(200);
        when(mockGetResponse.body()).thenReturn(
                new Gson().toJson(new UrlReport(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                        Verdict.UNKNOWN, url.toString(), null, null, null)));
        when(mockPostResponse.statusCode()).thenReturn(200);
        when(mockPostResponse.body()).thenReturn(new Gson().toJson(new UrlAnalysisStarted("id")));

        when(mockHttpClient.sendAsync(
                argThat(getRequest -> getRequest != null
                        && getRequest.method().equals("GET")
                        && getRequest.uri().toString().contains("id")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockGetResponse));

        when(mockHttpClient.sendAsync(
                argThat(postRequest -> postRequest != null
                        && postRequest.method().equals("POST")
                        && postRequest.uri().toString().contains("urls")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockPostResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);
        var vaasVerdict = vaas.forUrlAsync(url, forUrlOptions).join();
        verify(mockHttpClient, times(2)).sendAsync(requestCaptor.capture(),
                any(HttpResponse.BodyHandler.class));
        var bodyRequest = new String(readContent(Objects.requireNonNull(requestCaptor.getAllValues().get(0).bodyPublisher().orElse(null))));
        var urlAnalysisRequest = new Gson().fromJson(bodyRequest, UrlAnalysisRequest.class);
        var reportUri = requestCaptor.getAllValues().get(1).uri();

        assertEquals(useHashLookup, urlAnalysisRequest.isUseHashLookup());
        assertEquals(EICAR_URL, urlAnalysisRequest.getUrl());
        assertTrue(reportUri.toString()
                .contains(String.format("useHashLookup=%s", useHashLookup)));
        assertEquals(Verdict.UNKNOWN, vaasVerdict.getVerdict());
        assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                .equalsIgnoreCase(vaasVerdict.getSha256()));
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forUrl_SendUserAgent() throws Exception {
        var url = URI.create(EICAR_URL).toURL();

        var requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        var mockHttpClient = mock(HttpClient.class);
        var mockPostResponse = mock(HttpResponse.class);
        var mockGetResponse = mock(HttpResponse.class);

        when(mockGetResponse.statusCode()).thenReturn(200);
        when(mockGetResponse.body()).thenReturn(
                new Gson().toJson(new UrlReport(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                        Verdict.UNKNOWN, url.toString(), null, null, null)));
        when(mockPostResponse.statusCode()).thenReturn(200);
        when(mockPostResponse.body()).thenReturn(new Gson().toJson(new UrlAnalysisStarted("id")));

        when(mockHttpClient.sendAsync(
                argThat(getRequest -> getRequest != null
                        && getRequest.method().equals("GET")
                        && getRequest.uri().toString().contains("id")
                        && getRequest.headers().firstValue("User-Agent").toString()
                        .contains("Java")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockGetResponse));

        when(mockHttpClient.sendAsync(
                argThat(postRequest -> postRequest != null
                        && postRequest.method().equals("POST")
                        && postRequest.uri().toString().contains("urls")
                        && postRequest.headers().firstValue("User-Agent").toString()
                        .contains("Java")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockPostResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);
        var vaasVerdict = vaas.forUrlAsync(url).join();
        verify(mockHttpClient, times(2)).sendAsync(requestCaptor.capture(),
                any(HttpResponse.BodyHandler.class));
        var firstRequestHeaders = requestCaptor.getAllValues().get(0).headers().firstValue("User-Agent");
        var secondRequestHeaders = requestCaptor.getAllValues().get(1).headers().firstValue("User-Agent");

        assertTrue(firstRequestHeaders.toString().contains("Java"));
        assertTrue(secondRequestHeaders.toString().contains("Java"));
        assertEquals(Verdict.UNKNOWN, vaasVerdict.getVerdict());
        assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                .equalsIgnoreCase(vaasVerdict.getSha256()));
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forUrl_IfVaasRequestIdIsSet_SendTraceState() throws Exception {
        var url = URI.create(EICAR_URL).toURL();

        var requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        var mockHttpClient = mock(HttpClient.class);
        var mockPostResponse = mock(HttpResponse.class);
        var mockGetResponse = mock(HttpResponse.class);

        when(mockGetResponse.statusCode()).thenReturn(200);
        when(mockGetResponse.body()).thenReturn(
                new Gson().toJson(new UrlReport(
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                        Verdict.UNKNOWN, url.toString(), null, null, null)));
        when(mockPostResponse.statusCode()).thenReturn(200);
        when(mockPostResponse.body()).thenReturn(new Gson().toJson(new UrlAnalysisStarted("id")));

        when(mockHttpClient.sendAsync(
                argThat(getRequest -> getRequest != null
                        && getRequest.method().equals("GET")
                        && getRequest.uri().toString().contains("id")
                        && getRequest.headers().firstValue("tracestate").toString()
                        .contains("foobar")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockGetResponse));

        when(mockHttpClient.sendAsync(
                argThat(postRequest -> postRequest != null
                        && postRequest.method().equals("POST")
                        && postRequest.uri().toString().contains("urls")
                        && postRequest.headers().firstValue("tracestate").toString()
                        .contains("foobar")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockPostResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);
        var forUrlOptions = new ForUrlOptions(true, "foobar");
        var vaasVerdict = vaas.forUrlAsync(url, forUrlOptions).join();
        verify(mockHttpClient, times(2)).sendAsync(requestCaptor.capture(),
                any(HttpResponse.BodyHandler.class));
        var firstRequestHeaders = requestCaptor.getAllValues().get(0).headers().firstValue("tracestate");
        var secondRequestHeaders = requestCaptor.getAllValues().get(1).headers().firstValue("tracestate");

        assertTrue(firstRequestHeaders.toString().contains("foobar"));
        assertTrue(secondRequestHeaders.toString().contains("foobar"));
        assertEquals(Verdict.UNKNOWN, vaasVerdict.getVerdict());
        assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                .equalsIgnoreCase(vaasVerdict.getSha256()));
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forUrl_IfBadRequest_ThrowsVaasClientException() throws Exception {
        var url = URI.create(EICAR_URL).toURL();

        var mockHttpClient = mock(HttpClient.class);
        var mockPostResponse = mock(HttpResponse.class);
        when(mockPostResponse.statusCode()).thenReturn(400);
        when(mockPostResponse.body()).thenReturn(new Gson()
                .toJson(new ProblemDetails("VaasClientException", "Client-side error occurred")));

        when(mockHttpClient.sendAsync(
                argThat(postRequest -> postRequest != null
                        && postRequest.method().equals("POST")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockPostResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);

        var exception = assertThrows(CompletionException.class, () -> vaas.forUrlAsync(url).join());
        assertInstanceOf(VaasClientException.class, exception.getCause());
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forUrl_IfInternalServerError_ThrowsVaasServerException()
            throws Exception {
        var url = URI.create(EICAR_URL).toURL();

        var mockHttpClient = mock(HttpClient.class);
        var mockPostResponse = mock(HttpResponse.class);
        when(mockPostResponse.statusCode()).thenReturn(500);
        when(mockPostResponse.body()).thenReturn(new Gson()
                .toJson(new ProblemDetails("VaasServerException", "Server-side error occurred")));

        when(mockHttpClient.sendAsync(
                argThat(postRequest -> postRequest != null
                        && postRequest.method().equals("POST")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockPostResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);

        var exception = assertThrows(CompletionException.class, () -> vaas.forUrlAsync(url).join());
        assertInstanceOf(VaasServerException.class, exception.getCause());
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forUrl_IfUnauthorized_ThrowsVaasAuthenticationException()
            throws Exception {
        var url = URI.create(EICAR_URL).toURL();

        var mockHttpClient = mock(HttpClient.class);
        var mockPostResponse = mock(HttpResponse.class);
        when(mockPostResponse.statusCode()).thenReturn(401);
        when(mockPostResponse.body()).thenReturn(new Gson()
                .toJson(new ProblemDetails("VaasAuthenticationException", "Authentication failed.")));

        when(mockHttpClient.sendAsync(
                argThat(postRequest -> postRequest != null
                        && postRequest.method().equals("POST")),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockPostResponse));

        var vaas = getVaasWithMockedClient(mockHttpClient);

        var exception = assertThrows(CompletionException.class, () -> vaas.forUrlAsync(url).join());
        assertInstanceOf(VaasAuthenticationException.class, exception.getCause());
    }

    @SuppressWarnings("unchecked")
    @Test
    @Tag("Mock")
    public void forUrl_IfAuthenticatorFailed_ThrowsVaasAuthenticationException() throws Exception {
        var url = URI.create(EICAR_URL).toURL();

        var mockHttpClient = mock(HttpClient.class);
        var mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(401);
        when(mockHttpClient.send(any(HttpRequest.class),
                any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> mockResponse);

        var authenticator = getAuthenticator(mockHttpClient);
        var vaas = getVaasWithAuthenticator(authenticator);

        assertThrows(VaasAuthenticationException.class, () -> vaas.forUrl(url));
    }

    @Test
    public void forUrl_IfCancellationIsRequested_ThrowsCancellationException()
            throws Exception {
        var url = URI.create(EICAR_URL).toURL();

        var future = vaasWithDefaultConfig.forUrlAsync(url);

        var result = future.cancel(true);
        assertTrue(result);
        assertThrows(CancellationException.class, future::get);
    }

    @Test
    @Disabled("Fails for unknown reason in some environments. TODO: Use samples server.")
    public void forUrl_BigFileWithSmallTimeout_ThrowsTimeoutException()
            throws Exception {
        var url = URI.create("https://ash-speed.hetzner.com/1GB.bin").toURL();

        var vaasUrl = getEnvironmentKey("VAAS_URL");
        var config = new VaasConfig(1000, URI.create(vaasUrl));
        var vaas = new Vaas(config, authenticatorFixture);

        var exception = assertThrows(ExecutionException.class, () -> vaas.forUrlAsync(url).get());
        assertInstanceOf(TimeoutException.class, exception.getCause());
    }

    @Test
    @Disabled()
    public void forFileAsync_WithSmallTimeout_DoesNotShowNegativeResources() {
        var config = new VaasConfig(45, false, false, URI.create(getEnvironmentKey("VAAS_URL")));
        var vaas = new Vaas(config, authenticatorFixture);
        var file = Path.of(System.getProperty("java.io.tmpdir"), "file.txt");
        try (var writer = Files.newBufferedWriter(file)) {
            writer.write(UUID.randomUUID().toString());
        } catch (IOException e) {
            e.printStackTrace();
        }

        while (true) {
            try {
                vaas.forFile(file);
                System.out.print("+");
                System.out.flush();
            } catch (Exception e) {
                System.out.print("-");
                System.out.flush();
            }
        }
    }

    @Test
    @Disabled()
    public void forFileAsync_WithSmallTimeoutInParallel_DoesNotShowNegativeResources() {
        var config = new VaasConfig(45, false, false, URI.create(getEnvironmentKey("VAAS_URL")));
        var vaas = new Vaas(config, authenticatorFixture);
        var file1 = Path.of(System.getProperty("java.io.tmpdir"), "file.txt");
        var file2 = Path.of(System.getProperty("java.io.tmpdir"), "file2.txt");
        var file3 = Path.of(System.getProperty("java.io.tmpdir"), "file3.txt");
        var file4 = Path.of(System.getProperty("java.io.tmpdir"), "file4.txt");
        var fileList = List.of(file1, file2, file3, file4);
        for (var file : fileList) {
            try (var writer = Files.newBufferedWriter(file)) {
                writer.write(UUID.randomUUID().toString());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        while (true) {
            fileList.parallelStream().forEach((key) -> {
                try {
                    vaas.forFile(key);
                    System.out.print("+");
                    System.out.flush();
                } catch (Exception e) {
                    System.out.print("-");
                    System.out.flush();
                }
            });
        }
    }
}
