package de.gdata.test.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import com.google.gson.Gson;

import de.gdata.vaas.ClientCredentialsGrantAuthenticator;
import de.gdata.vaas.IAuthenticator;
import de.gdata.vaas.Sha256;
import de.gdata.vaas.Vaas;
import de.gdata.vaas.VaasConfig;
import de.gdata.vaas.exceptions.VaasAuthenticationException;
import de.gdata.vaas.exceptions.VaasClientException;
import de.gdata.vaas.exceptions.VaasServerException;
import de.gdata.vaas.messages.FileReport;
import de.gdata.vaas.messages.Verdict;
import de.gdata.vaas.options.ForSha256Options;
import de.gdata.vaas.options.ForStreamOptions;
import io.github.cdimascio.dotenv.Dotenv;

public class VaasTests {
        private static final Dotenv dotenv = Dotenv.configure()
                        .ignoreIfMissing()
                        .load();

        private static Vaas vaas;

        // @BeforeAll
        // public static void setUpAll() throws URISyntaxException,
        // InterruptedException, IOException, ExecutionException,
        // TimeoutException, VaasAuthenticationException {
        // vaas = getVaasWithCredentials();
        // }

        private static String getEnvironmentKey(String key) {
                var value = dotenv.get(key);
                if (value == null) {
                        throw new IllegalArgumentException("Environment variable " + key + " must be set.");
                }
                return value;
        }

        private static IAuthenticator getAuthenticator() throws URISyntaxException {
                var clientId = getEnvironmentKey("CLIENT_ID");
                var clientSecret = getEnvironmentKey("CLIENT_SECRET");
                var tokenUrl = new URI(getEnvironmentKey("TOKEN_URL"));
                return new ClientCredentialsGrantAuthenticator(clientId, clientSecret, tokenUrl);
        }

        private static IAuthenticator getAuthenticator(HttpClient httpClient) throws URISyntaxException {
                var clientId = getEnvironmentKey("CLIENT_ID");
                var clientSecret = getEnvironmentKey("CLIENT_SECRET");
                var tokenUrl = new URI(getEnvironmentKey("TOKEN_URL"));
                return new ClientCredentialsGrantAuthenticator(clientId, clientSecret, tokenUrl, httpClient);
        }

        private static Vaas getVaasWithCredentials(IAuthenticator authenticator)
                        throws URISyntaxException, InterruptedException, IOException, ExecutionException,
                        TimeoutException,
                        VaasAuthenticationException {

                var vaasUrl = getEnvironmentKey("VAAS_URL");
                var config = new VaasConfig(new URI(vaasUrl));
                var vaas = new Vaas(config, authenticator);
                return vaas;
        }

        private static Vaas getVaasWithCredentials(HttpClient httpClient)
                        throws URISyntaxException, InterruptedException, IOException, ExecutionException,
                        TimeoutException,
                        VaasAuthenticationException {

                var vaasUrl = getEnvironmentKey("VAAS_URL");
                var authenticator = getAuthenticator();
                var config = new VaasConfig(new URI(vaasUrl));
                var vaas = new Vaas(config, authenticator, httpClient);
                return vaas;
        }

        private static Vaas getVaasWithCredentials()
                        throws URISyntaxException, InterruptedException, IOException, ExecutionException,
                        TimeoutException,
                        VaasAuthenticationException {

                var vaasUrl = getEnvironmentKey("VAAS_URL");
                var authenticator = getAuthenticator();
                var config = new VaasConfig(new URI(vaasUrl));
                var vaas = new Vaas(config, authenticator);
                return vaas;
        }

        @ParameterizedTest
        @CsvSource({
                        "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e, CLEAN",
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f, MALICIOUS",
                        "d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad, PUP"
        })
        public void forSha256_ReturnsVerdict(String sha256, Verdict verdict) throws Exception {
                var sha256sum = new Sha256(sha256);
                vaas = getVaasWithCredentials();

                var vaasVerdict = vaas.forSha256(sha256sum).join();

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
        public void forSha256_SendOptions(boolean useCache, boolean useHashLookup) throws Exception {
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

                vaas = getVaasWithCredentials(mockHttpClient);
                var vaasVerdict = vaas.forSha256(sha256, forSha256Options).join();
                verify(mockHttpClient).sendAsync(requestCaptor.capture(), any(HttpResponse.BodyHandler.class));
                var capturedUri = requestCaptor.getValue().uri();

                assertTrue(capturedUri.toString().contains(String.format("useCache=%s", String.valueOf(useCache))));
                assertTrue(capturedUri.toString()
                                .contains(String.format("useHashLookup=%s", String.valueOf(useHashLookup))));
                assertEquals(Verdict.UNKNOWN, vaasVerdict.getVerdict());
                assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                                .equalsIgnoreCase(vaasVerdict.getSha256()));
        }

        @SuppressWarnings("unchecked")
        @Test
        public void forSha256_SendUserAgent() throws Exception {
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

                vaas = getVaasWithCredentials(mockHttpClient);
                var vaasVerdict = vaas.forSha256(sha256).join();
                verify(mockHttpClient).sendAsync(requestCaptor.capture(), any(HttpResponse.BodyHandler.class));
                var capturedUserAgent = requestCaptor.getValue().headers().firstValue("User-Agent");

                assertTrue(capturedUserAgent.toString().contains("Java"));
                assertEquals(Verdict.UNKNOWN, vaasVerdict.getVerdict());
                assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                                .equalsIgnoreCase(vaasVerdict.getSha256()));
        }

        @SuppressWarnings("unchecked")
        @Test
        public void forSha256_IfVaasRequestIdIsSet_SendTraceState() throws Exception {
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

                vaas = getVaasWithCredentials(mockHttpClient);
                var forSha256Options = new ForSha256Options(true, true, "foobar");
                var vaasVerdict = vaas.forSha256(sha256, forSha256Options).join();

                verify(mockHttpClient).sendAsync(requestCaptor.capture(), any(HttpResponse.BodyHandler.class));
                var capturedTraceState = requestCaptor.getValue().headers().firstValue("tracestate");

                assertTrue(capturedTraceState.toString().contains("foobar"));
                assertEquals(Verdict.UNKNOWN, vaasVerdict.getVerdict());
                assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                                .equalsIgnoreCase(vaasVerdict.getSha256()));
        }

        @SuppressWarnings("unchecked")
        @Test
        public void forSha256_IfBadRequest_ThrowsVaasClientException() throws Exception {
                var sha256 = new Sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
                var mockHttpClient = mock(HttpClient.class);
                var mockResponse = mock(HttpResponse.class);
                when(mockResponse.statusCode()).thenReturn(400);
                when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockResponse));

                vaas = getVaasWithCredentials(mockHttpClient);

                var exception = assertThrows(CompletionException.class, () -> {
                        vaas.forSha256(sha256).join();
                });
                assertTrue(exception.getCause() instanceof VaasClientException);
        }

        @SuppressWarnings("unchecked")
        @Test
        public void forSha256_IfInternalServerError_ThrowsVaasServerException() throws Exception {
                var sha256 = new Sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
                var mockHttpClient = mock(HttpClient.class);
                var mockResponse = mock(HttpResponse.class);
                when(mockResponse.statusCode()).thenReturn(500);
                when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockResponse));

                vaas = getVaasWithCredentials(mockHttpClient);

                var exception = assertThrows(CompletionException.class, () -> {
                        vaas.forSha256(sha256).join();
                });
                assertTrue(exception.getCause() instanceof VaasServerException);
        }

        @SuppressWarnings("unchecked")
        @Test
        public void forSha256_IfUnauthorized_ThrowsVaasAuthenticationException() throws Exception {
                var sha256 = new Sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
                var mockHttpClient = mock(HttpClient.class);
                var mockResponse = mock(HttpResponse.class);
                when(mockResponse.statusCode()).thenReturn(401);
                when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                                .thenAnswer(invocation -> CompletableFuture.completedFuture(mockResponse));

                vaas = getVaasWithCredentials(mockHttpClient);

                var exception = assertThrows(CompletionException.class, () -> {
                        vaas.forSha256(sha256).join();
                });
                assertTrue(exception.getCause() instanceof VaasAuthenticationException);
        }

        @SuppressWarnings("unchecked")
        @Test
        public void forSha256_IfAuthenticatorFailed_ThrowsVaasAuthenticationException() throws Exception {
                var sha256 = new Sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
                var mockHttpClient = mock(HttpClient.class);
                var mockResponse = mock(HttpResponse.class);
                when(mockResponse.statusCode()).thenReturn(401);
                when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                                .thenAnswer(invocation -> mockResponse);

                var authenticator = getAuthenticator(mockHttpClient);
                vaas = getVaasWithCredentials(authenticator);

                assertThrows(VaasAuthenticationException.class, () -> {
                        vaas.forSha256(sha256).join();
                });
        }

        @Test
        public void forSha256_IfCancellationIsRequested_ThrowsCancellationException() throws Exception {
                var sha256 = new Sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
                vaas = getVaasWithCredentials();

                var future = vaas.forSha256(sha256);

                var result = future.cancel(true);
                assertTrue(result);
                assertThrows(CancellationException.class, future::get);
        }

        @Test
        public void forFile_ReturnsVerdict() throws Exception {
                var tmpFile = Path.of(System.getProperty("java.io.tmpdir"), "eicar.txt");
                var url = new URL("https://secure.eicar.org/eicar.com.txt");
                var conn = url.openConnection();
                var inputStream = conn.getInputStream();
                Files.copy(inputStream, tmpFile, StandardCopyOption.REPLACE_EXISTING);

                vaas = getVaasWithCredentials();
                var verdict = vaas.forFile(tmpFile).join();

                assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
                assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                                .equalsIgnoreCase(verdict.getSha256()));
        }

        @Test
        public void forStream_ReturnsVerdict() throws Exception {
                var url = new URL("https://secure.eicar.org/eicar.com.txt");
                var conn = url.openConnection();
                var inputStream = conn.getInputStream();
                var contentLength = conn.getContentLength();
                var forStreamOptions = new ForStreamOptions(true, "foobar");

                var vaas = getVaasWithCredentials();
                var verdict = vaas.forStream(inputStream, contentLength, forStreamOptions).join();

                assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
                assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                                .equalsIgnoreCase(verdict.getSha256()));
        }

        @Test
        public void forUrl_ReturnsVerdict() throws Exception {
                var url = new URL("https://secure.eicar.org/eicar.com.txt");

                vaas = getVaasWithCredentials();
                var verdict = vaas.forUrl(url).join();

                assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
                assertTrue("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                                .equalsIgnoreCase(verdict.getSha256()));
        }
}
