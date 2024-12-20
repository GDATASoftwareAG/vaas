package de.gdata.vaas;

import de.gdata.vaas.messages.*;
import de.gdata.vaas.options.ForFileOptions;
import de.gdata.vaas.options.ForSha256Options;
import de.gdata.vaas.options.ForStreamOptions;
import de.gdata.vaas.options.ForUrlOptions;
import de.gdata.vaas.exceptions.*;
import lombok.Getter;
import lombok.NonNull;

import org.java_websocket.exceptions.WebsocketNotConnectedException;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;

public class Vaas implements AutoCloseable, IVaas {
    private static final int connectionRetryDelayInMs = 1000;
    private static final int connectionTimeoutInMs = 10000;
    private static final String userAgent = "Java/9.0.0";

    @Getter
    @NonNull
    private final VaasConfig config;

    private final IAuthenticator authenticator;
    private final HttpClient httpClient;
    private WebSocketClient client;

    public Vaas(@NonNull VaasConfig config, @NonNull IAuthenticator authenticator) {
        this.config = config;
        this.authenticator = authenticator;
        this.httpClient = HttpClient.newHttpClient();
    }

    public Vaas(VaasConfig config, IAuthenticator authenticator, HttpClient httpClient) {
        this.config = config;
        this.authenticator = authenticator;
        this.httpClient = httpClient;
    }

    /**
     * Connect and authenticate with the VaaS Backend
     * 
     * @throws IOException                 if an I/O error occurs when getting the
     *                                     token from the identity provider
     * @throws InterruptedException        if the operation is interrupted by
     *                                     Thread.interrupt()
     * @throws VaasAuthenticationException if the token returned by the identity
     *                                     provider is invalid
     * @throws TimeoutException            if the connection or authentication to
     *                                     the VaaS backend takes too long
     */
    public void connect() throws IOException, InterruptedException, VaasAuthenticationException, TimeoutException {
        var timer = new SimpleTimer(connectionTimeoutInMs, TimeUnit.MILLISECONDS);
        while (true) {
            if (this.client != null) {
                this.client.close();
            }
            this.client = new WebSocketClient(this.getConfig(), authenticator);
            if (this.client.connectBlocking(timer.getRemainingMs(), TimeUnit.MILLISECONDS)) {
                try {
                    this.client.Authenticate(timer.getRemainingMs(), TimeUnit.MILLISECONDS);
                    break;
                } catch (WebsocketNotConnectedException ignored) {
                } catch (ExecutionException e) {
                    throw new VaasAuthenticationException();
                }
            }
            TimeUnit.MILLISECONDS.sleep(connectionRetryDelayInMs);
        }
    }

    /**
     * Disconnect from the Vaas backend
     *
     * @throws InterruptedException if the operation is interrupted by
     *                              Thread.interrupt()
     */
    public void disconnect() throws InterruptedException {
        if (this.client != null) {
            this.client.closeBlocking();
        }
    }

    private void throwVaasException(ExecutionException e) throws VaasClientException, VaasServerException {
        var errorCause = e.getCause();
        if (errorCause instanceof VaasClientException) {
            throw (VaasClientException) errorCause;
        } else if (errorCause instanceof VaasServerException) {
            throw (VaasServerException) errorCause;
        }
        throw new VaasClientException("Unexpected error.");
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable> void throwAsUnchecked(Exception exception) throws E {
        throw (E) exception;
    }

    @Override
    public void close() throws Exception {
        try {
            this.disconnect();
        } catch (Exception e) {
            // ignored
        }
    }

    private static <T, R> Function<T, R> handleException(ThrowingFunction<T, R> function) {
        return input -> {
            try {
                return function.apply(input);
            } catch (Exception e) {
                throw new RuntimeException(e); // Wrappen in eine RuntimeException
            }
        };
    }

    @FunctionalInterface
    interface ThrowingFunction<T, R> {
        R apply(T t) throws Exception;
    }

    private static String encodeParams(Map<String, String> params) {
        StringBuilder encodedParams = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (encodedParams.length() > 0) {
                encodedParams.append("&");
            }
            encodedParams.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8))
                    .append("=")
                    .append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
        }
        return encodedParams.toString();
    }

    private static CompletableFuture<VaasVerdict> parseVaasError(HttpResponse response)
            throws VaasClientException, VaasServerException, VaasAuthenticationException {
        var problemDetails = response.body() != null ? ProblemDetails.fromJson(response.body().toString()) : new ProblemDetails();
        switch (response.statusCode()) {
            case 400:
                return CompletableFuture.failedFuture(new VaasClientException(problemDetails.detail));
            case 401:
                return CompletableFuture.failedFuture(new VaasAuthenticationException());
            default:
                return CompletableFuture.failedFuture(new VaasServerException(problemDetails.detail));
        }
    }

    private static CompletableFuture<VaasVerdict> sendFileWithRetry(HttpClient httpClient, HttpRequest request) {
        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenCompose(handleException(response -> {
                    switch (response.statusCode()) {
                        case 200:
                            var fileReport = FileReport.fromJson(response.body());
                            return CompletableFuture.completedFuture(VaasVerdict.From(fileReport));
                        case 201:
                            return sendFileWithRetry(httpClient, request);
                        default:
                            return parseVaasError(response);
                    }
                }));
    }

    private static CompletableFuture<VaasVerdict> sendUrlWithRetry(HttpClient httpClient, HttpRequest request) {
        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenCompose(handleException(response -> {
                    switch (response.statusCode()) {
                        case 200:
                            var urlReport = UrlReport.fromJson(response.body());
                            return CompletableFuture.completedFuture(VaasVerdict.From(urlReport));
                        case 201:
                            return sendUrlWithRetry(httpClient, request);
                        default:
                            return parseVaasError(response);
                    }
                }));
    }

    public HttpRequest.Builder CreateHttpRequestBuilderWithHeaders(URI uri, String requestId)
            throws IOException, InterruptedException, VaasAuthenticationException {
        var token = this.authenticator.getToken();
        return HttpRequest.newBuilder()
                .uri(uri)
                .header("Authorization", "Bearer " + token)
                .header("User-Agent", userAgent)
                .header("tracestate", "vaasrequestid=" + requestId);
    }

    @Override
    public CompletableFuture<VaasVerdict> forSha256(Sha256 sha256)
            throws URISyntaxException, IOException, InterruptedException, VaasAuthenticationException {
        var forSha256Options = new ForSha256Options();
        forSha256Options.setUseCache(true);
        forSha256Options.setUseHashLookup(true);
        return this.forSha256(sha256, forSha256Options);
    }

    @Override
    public CompletableFuture<VaasVerdict> forSha256(Sha256 sha256, ForSha256Options options)
            throws IOException, InterruptedException, VaasAuthenticationException {
        var params = Map.of(
                "useCache", String.valueOf(options.isUseCache()),
                "useHashLookup", String.valueOf(options.isUseHashLookup()));
        var filesReportUri = this.config.getUrl() + String.format("/files/%s/report?", sha256.getValue())
                + encodeParams(params);
        var request = CreateHttpRequestBuilderWithHeaders(URI.create(filesReportUri), options.getVaasRequestId())
                .GET()
                .build();

        if (options.getVaasRequestId() == null || options.getVaasRequestId().isBlank()) {
            options.setVaasRequestId(UUID.randomUUID().toString());
        }

        return sendFileWithRetry(httpClient, request);
    }

    @Override
    public CompletableFuture<VaasVerdict> forFile(Path file)
            throws NoSuchAlgorithmException, IOException, URISyntaxException, InterruptedException,
            VaasAuthenticationException {
        var forFileOptions = new ForFileOptions();
        forFileOptions.setUseCache(true);
        forFileOptions.setUseHashLookup(true);
        return forFile(file, forFileOptions);
    }

    @Override
    public CompletableFuture<VaasVerdict> forFile(Path file, ForFileOptions options)
            throws NoSuchAlgorithmException, IOException, InterruptedException, VaasAuthenticationException {
        var sha256 = new Sha256(file);
        var forSha256Options = new ForSha256Options(options.isUseCache(), options.isUseHashLookup(),
                options.getVaasRequestId());

        return forSha256(sha256, forSha256Options)
                .thenCompose(handleException(vaasVerdict -> {
                    var verdictWithoutDetection = vaasVerdict.getVerdict() == Verdict.MALICIOUS
                            || (vaasVerdict.getVerdict() == Verdict.PUP && vaasVerdict.getDetection() == null)
                            || (vaasVerdict.getDetection() != null && vaasVerdict.getDetection().isBlank());

                    if (vaasVerdict.getVerdict() != Verdict.UNKNOWN && verdictWithoutDetection
                            && vaasVerdict.getFileType() != null
                            && !vaasVerdict.getFileType().isBlank()
                            && vaasVerdict.getMimeType() != null
                            && !vaasVerdict.getMimeType().isEmpty()) {
                        return CompletableFuture.completedFuture(vaasVerdict);
                    } else {
                        var inputstream = Files.newInputStream(file, StandardOpenOption.READ);
                        var forStreamOptions = new ForStreamOptions();
                        forStreamOptions.setUseHashLookup(options.isUseHashLookup());
                        forStreamOptions.setVaasRequestId(options.getVaasRequestId());

                        return forStream(inputstream, file.toFile().length(), forStreamOptions);
                    }
                }));
    }

    @Override
    public CompletableFuture<VaasVerdict> forStream(InputStream stream, long contentLength)
            throws URISyntaxException, IOException, InterruptedException, VaasAuthenticationException {
        var forStreamOptions = new ForStreamOptions();
        forStreamOptions.setUseHashLookup(true);
        return forStream(stream, contentLength, forStreamOptions);
    }

    @Override
    public CompletableFuture<VaasVerdict> forStream(InputStream inputStream, long contentLength,
            ForStreamOptions options)
            throws IOException, InterruptedException, VaasAuthenticationException {
        var params = Map.of("useHashLookup", String.valueOf(options.isUseHashLookup()));

        var filesUri = this.config.getUrl() + "/files?" + encodeParams(params);

        var bodyPublisher = BodyPublishers.fromPublisher(BodyPublishers.ofInputStream(() -> inputStream),
                contentLength);
        var request = CreateHttpRequestBuilderWithHeaders(URI.create(filesUri), options.getVaasRequestId())
                .POST(bodyPublisher)
                .header("Content-Type", "application/octet-stream")
                .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenCompose(handleException(response -> {
                    var statusCode = response.statusCode();
                    if (statusCode < 200 || statusCode >= 300) {
                        return parseVaasError(response);
                    }
                    var fileResponseStarted = FileAnalysisStarted.fromJson(response.body());
                    var sha256 = new Sha256(fileResponseStarted.getSha256());
                    var forSha256Options = new ForSha256Options();
                    forSha256Options.setUseHashLookup(options.isUseHashLookup());
                    forSha256Options.setVaasRequestId(options.getVaasRequestId());

                    return forSha256(sha256, forSha256Options);
                }));
    }

    @Override
    public CompletableFuture<VaasVerdict> forUrl(URL url) throws URISyntaxException, IOException, InterruptedException,
            VaasAuthenticationException, VaasClientException, VaasServerException {
        var forUrlOptions = new ForUrlOptions();
        forUrlOptions.setUseHashLookup(true);
        return forUrl(url, forUrlOptions);
    }

    @Override
    public CompletableFuture<VaasVerdict> forUrl(URL url, ForUrlOptions options)
            throws IOException, InterruptedException, VaasAuthenticationException, VaasClientException,
            VaasServerException {
        var params = Map.of("useHashLookup", String.valueOf(options.isUseHashLookup()));
        var urlsUri = this.config.getUrl() + "/urls";
        var urlAnalysisRequest = new UrlAnalysisRequest(url.toString(), options.isUseHashLookup());
        var request = CreateHttpRequestBuilderWithHeaders(URI.create(urlsUri), options.getVaasRequestId())
                .POST(HttpRequest.BodyPublishers.ofString(UrlAnalysisRequest.ToJson(urlAnalysisRequest)))
                .header("Content-Type", "application/json")
                .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply(handleException(response -> {
                    var statusCode = response.statusCode();
                    if (statusCode < 200 || statusCode >= 300) {
                        parseVaasError(response);
                    }
                    return UrlAnalysisStarted.fromJson(response.body());
                }))
                .thenCompose(handleException(urlAnalysisStarted -> {
                    var urlsReportUri = this.config.getUrl()
                            + String.format("/urls/%s/report?", urlAnalysisStarted.getId()) + encodeParams(params);
                    if (options.getVaasRequestId() == null || options.getVaasRequestId().isBlank()) {
                        options.setVaasRequestId(UUID.randomUUID().toString());
                    }
                    var request2 = CreateHttpRequestBuilderWithHeaders(URI.create(urlsReportUri),
                            options.getVaasRequestId())
                            .GET()
                            .build();
                    return sendUrlWithRetry(httpClient, request2);
                }))
                .thenApply(vaasVerdict -> {
                    return vaasVerdict;
                });
    }
}
