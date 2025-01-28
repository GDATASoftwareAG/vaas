package de.gdata.vaas;

import com.google.gson.Gson;
import de.gdata.vaas.authentication.IAuthenticator;
import de.gdata.vaas.exceptions.VaasAuthenticationException;
import de.gdata.vaas.exceptions.VaasClientException;
import de.gdata.vaas.exceptions.VaasServerException;
import de.gdata.vaas.messages.*;
import de.gdata.vaas.options.ForFileOptions;
import de.gdata.vaas.options.ForSha256Options;
import de.gdata.vaas.options.ForStreamOptions;
import de.gdata.vaas.options.ForUrlOptions;
import lombok.Getter;
import lombok.NonNull;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
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
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static de.gdata.vaas.CompletableFutureExceptionHandler.handleException;

public class Vaas implements IVaas {
    private static final String userAgent = "Java/9.0.0";

    @Getter
    @NonNull
    private final VaasConfig config;

    private final IAuthenticator authenticator;
    private final HttpClient httpClient;

    public Vaas(@NonNull VaasConfig config, @NonNull IAuthenticator authenticator) {
        this.config = config;
        this.authenticator = authenticator;
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofMillis(config.getDefaultTimeoutInMs()))
                .build();
    }

    public Vaas(@NotNull VaasConfig config, IAuthenticator authenticator, HttpClient httpClient) {
        this.config = config;
        this.authenticator = authenticator;
        this.httpClient = httpClient;
    }

    public Vaas(IAuthenticator authenticator) {
        this(new VaasConfig(), authenticator);
    }

    private static String encodeParams(Map<String, String> params) {
        StringBuilder encodedParams = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (!encodedParams.isEmpty()) {
                encodedParams.append("&");
            }
            encodedParams.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8))
                    .append("=")
                    .append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
        }
        return encodedParams.toString();
    }

    private static CompletableFuture<VaasVerdict> sendUrlWithRetry(HttpClient httpClient, HttpRequest request) {
        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenCompose(handleException(response -> switch (response.statusCode()) {
                    case 200 -> {
                        var urlReport = UrlReport.fromJson(response.body());
                        yield CompletableFuture.completedFuture(VaasVerdict.From(urlReport));
                    }
                    case 201, 202 -> sendUrlWithRetry(httpClient, request);
                    default -> throw parseVaasError(response);
                }));
    }

    private static Exception parseVaasError(HttpResponse<String> response) {
        String responseBody = response.body();
        try {
            var problemDetails = new Gson().fromJson(responseBody, Map.class);
            if (problemDetails != null) {
                var type = (String) problemDetails.getOrDefault("type", "");
                var detail = (String) problemDetails.getOrDefault("detail", "Unknown error");
                if (type.equals("VaasClientException")) {
                    return new VaasClientException(detail);
                } else if (type.equals("VaasAuthenticationException")) {
                    return new VaasAuthenticationException(detail);
                }
                return new VaasServerException(detail);
            } else {
                return new VaasServerException("Invalid JSON error response from server");
            }
        } catch (Exception e) {
            if (response.statusCode() == 401) {
                return new VaasAuthenticationException(
                        "Server did not accept token from identity provider. Check if you are using the correct identity provider and credentials.");
            } else if (response.statusCode() >= 400 && response.statusCode() < 500) {
                return new VaasClientException("HTTP Error: " + response.statusCode());
            } else {
                return new VaasServerException("HTTP Error: " + response.statusCode());
            }
        }
    }

    private CompletableFuture<VaasVerdict> sendFileWithRetry(HttpClient httpClient, URI uri, String vaasRequestId)
            throws VaasAuthenticationException {
        var request = CreateHttpRequestBuilderWithHeaders(uri, vaasRequestId)
                .GET()
                .build();
        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenCompose(handleException(response -> switch (response.statusCode()) {
                    case 200 -> {
                        var fileReport = FileReport.fromJson(response.body());
                        yield CompletableFuture.completedFuture(VaasVerdict.From(fileReport));
                    }
                    case 201, 202 -> sendFileWithRetry(httpClient, uri, vaasRequestId);
                    default -> throw parseVaasError(response);
                }));
    }

    private HttpRequest.Builder CreateHttpRequestBuilderWithHeaders(URI uri, String requestId)
            throws VaasAuthenticationException {
        String token;
        try {
            token = this.authenticator.getToken().get();
        } catch (Exception e) {
            throw new VaasAuthenticationException("Failed to get token", e);
        }

        var httpRequestBuilder = HttpRequest.newBuilder()
                .uri(uri)
                .header("Authorization", "Bearer " + token)
                .header("User-Agent", userAgent);
        if (requestId != null && !requestId.isBlank()) {
            httpRequestBuilder.header("tracestate", "vaasrequestid=" + requestId);
        }
        return httpRequestBuilder;
    }

    @Override
    public CompletableFuture<VaasVerdict> forSha256Async(Sha256 sha256) throws VaasAuthenticationException {
        return this.forSha256Async(sha256, ForSha256Options.fromVaasConfig(this.config));
    }

    @Override
    public CompletableFuture<VaasVerdict> forSha256Async(Sha256 sha256, ForSha256Options options) throws VaasAuthenticationException {
        var params = Map.of(
                "useCache", String.valueOf(options.isUseCache()),
                "useHashLookup", String.valueOf(options.isUseHashLookup()));
        var filesReportUri = this.config.getUrl() + String.format("/files/%s/report?", sha256.getValue())
                + encodeParams(params);

        return sendFileWithRetry(httpClient, URI.create(filesReportUri), options.getVaasRequestId()).orTimeout(
                this.config.getDefaultTimeoutInMs(),
                TimeUnit.MILLISECONDS);
    }

    @Override
    public VaasVerdict forSha256(Sha256 sha256) throws InterruptedException, ExecutionException, VaasAuthenticationException {
        return forSha256Async(sha256).get();
    }

    @Override
    public VaasVerdict forSha256(Sha256 sha256, ForSha256Options options) throws InterruptedException, ExecutionException, VaasAuthenticationException {
        return forSha256Async(sha256, options).get();
    }

    @Override
    public CompletableFuture<VaasVerdict> forFileAsync(Path file) throws NoSuchAlgorithmException, IOException, VaasAuthenticationException {
        return forFileAsync(file, ForFileOptions.fromVaaSConfig(this.config));
    }

    @Override
    public CompletableFuture<VaasVerdict> forFileAsync(Path file, ForFileOptions options) throws NoSuchAlgorithmException, IOException, VaasAuthenticationException {
        var sha256 = new Sha256(file);
        var contentLength = Files.size(file);
        var forSha256Options = new ForSha256Options(options.isUseCache(), options.isUseHashLookup(),
                options.getVaasRequestId());
        return forSha256Async(sha256, forSha256Options)
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
                        try {
                            var inputstream = Files.newInputStream(file, StandardOpenOption.READ);
                            var forStreamOptions = new ForStreamOptions();
                            forStreamOptions.setUseHashLookup(options.isUseHashLookup());
                            forStreamOptions.setVaasRequestId(options.getVaasRequestId());

                            return forStreamAsync(inputstream, contentLength, forStreamOptions)
                                    .whenComplete((result, ex) -> {
                                        try {
                                            inputstream.close();
                                        } catch (IOException e) {
                                            throw new CompletionException(e);
                                        }
                                    });
                        } catch (IOException e) {
                            return CompletableFuture.failedFuture(e);
                        }
                    }
                })).orTimeout(this.config.getDefaultTimeoutInMs(), TimeUnit.MILLISECONDS);
    }

    @Override
    public VaasVerdict forFile(Path file) throws NoSuchAlgorithmException, InterruptedException, ExecutionException, IOException, VaasAuthenticationException {
        return forFileAsync(file).get();
    }

    @Override
    public VaasVerdict forFile(Path file, ForFileOptions options) throws NoSuchAlgorithmException, InterruptedException, ExecutionException, IOException, VaasAuthenticationException {
        return forFileAsync(file, options).get();
    }

    @Override
    public CompletableFuture<VaasVerdict> forStreamAsync(InputStream stream, long contentLength) throws VaasAuthenticationException {
        return forStreamAsync(stream, contentLength, ForStreamOptions.fromVaasConfig(this.config));
    }

    @Override
    public CompletableFuture<VaasVerdict> forStreamAsync(InputStream inputStream, long contentLength,
                                                         ForStreamOptions options) throws VaasAuthenticationException {
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
                        throw parseVaasError(response);
                    }
                    var fileResponseStarted = FileAnalysisStarted.fromJson(response.body());
                    var sha256 = new Sha256(fileResponseStarted.getSha256());
                    var forSha256Options = new ForSha256Options();
                    forSha256Options.setUseHashLookup(options.isUseHashLookup());
                    forSha256Options.setVaasRequestId(options.getVaasRequestId());

                    return forSha256Async(sha256, forSha256Options);
                })).orTimeout(this.config.getDefaultTimeoutInMs(), TimeUnit.MILLISECONDS);
    }

    @Override
    public VaasVerdict forStream(InputStream stream, long contentLength) throws InterruptedException, ExecutionException, VaasAuthenticationException {
        return forStreamAsync(stream, contentLength).get();
    }

    @Override
    public VaasVerdict forStream(InputStream stream, long contentLength, ForStreamOptions options) throws InterruptedException, ExecutionException, VaasAuthenticationException {
        return forStreamAsync(stream, contentLength, options).get();
    }

    @Override
    public CompletableFuture<VaasVerdict> forUrlAsync(URL url) throws VaasAuthenticationException {
        return forUrlAsync(url, ForUrlOptions.fromVaasConfig(this.config));
    }

    @Override
    public CompletableFuture<VaasVerdict> forUrlAsync(URL url, ForUrlOptions options) throws VaasAuthenticationException {
        var params = Map.of("useHashLookup", String.valueOf(options.isUseHashLookup()));
        var urlsUri = this.config.getUrl() + "/urls";
        var urlAnalysisRequest = new UrlAnalysisRequest(url.toString(), options.isUseHashLookup());
        var postRequest = CreateHttpRequestBuilderWithHeaders(URI.create(urlsUri), options.getVaasRequestId())
                .POST(HttpRequest.BodyPublishers.ofString(UrlAnalysisRequest.ToJson(urlAnalysisRequest)))
                .header("Content-Type", "application/json")
                .build();

        return httpClient.sendAsync(postRequest, HttpResponse.BodyHandlers.ofString())
                .thenCompose(handleException(response -> {
                    var statusCode = response.statusCode();
                    if (statusCode < 200 || statusCode >= 300) {
                        throw parseVaasError(response);
                    }
                    var urlAnalysisStarted = UrlAnalysisStarted.fromJson(response.body());
                    var urlsReportUri = this.config.getUrl()
                            + String.format("/urls/%s/report?", urlAnalysisStarted.getId()) + encodeParams(params);
                    if (options.getVaasRequestId() == null || options.getVaasRequestId().isBlank()) {
                        options.setVaasRequestId(UUID.randomUUID().toString());
                    }
                    var getRequest = CreateHttpRequestBuilderWithHeaders(URI.create(urlsReportUri),
                            options.getVaasRequestId())
                            .GET()
                            .build();
                    return sendUrlWithRetry(httpClient, getRequest).orTimeout(this.config.getDefaultTimeoutInMs(),
                            TimeUnit.MILLISECONDS);
                }))
                .orTimeout(this.config.getDefaultTimeoutInMs(), TimeUnit.MILLISECONDS);
    }

    @Override
    public VaasVerdict forUrl(URL url) throws InterruptedException, ExecutionException, VaasAuthenticationException {
        return forUrlAsync(url).get();
    }

    @Override
    public VaasVerdict forUrl(URL url, ForUrlOptions options) throws InterruptedException, ExecutionException, VaasAuthenticationException {
        return forUrlAsync(url, options).get();
    }

    @FunctionalInterface
    interface ThrowingFunction<T, R> {
        R apply(T t) throws Exception;
    }
}
