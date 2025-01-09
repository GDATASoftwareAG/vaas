package de.gdata.vaas;

import de.gdata.vaas.messages.*;
import de.gdata.vaas.options.ForFileOptions;
import de.gdata.vaas.options.ForSha256Options;
import de.gdata.vaas.options.ForStreamOptions;
import de.gdata.vaas.options.ForUrlOptions;
import de.gdata.vaas.exceptions.*;
import lombok.Getter;
import lombok.NonNull;
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
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

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
        this.httpClient = HttpClient.newHttpClient();
    }

    public Vaas(VaasConfig config, IAuthenticator authenticator, HttpClient httpClient) {
        this.config = config;
        this.authenticator = authenticator;
        this.httpClient = httpClient;
    }

    private static <T, R> Function<T, CompletableFuture<R>> handleException(
            ThrowingFunction<T, CompletableFuture<R>> function) {
        return input -> {
            try {
                return function.apply(input);
            } catch (Exception e) {
                return CompletableFuture.failedFuture(e);
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

    private static CompletableFuture<VaasVerdict> parseVaasError(HttpResponse<String> response) {
        var problemDetails = response.body() != null ? ProblemDetails.fromJson(response.body()) : new ProblemDetails();
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
    public CompletableFuture<VaasVerdict> forSha256Async(Sha256 sha256)
            throws IOException, InterruptedException, VaasAuthenticationException {
        var forSha256Options = new ForSha256Options();
        forSha256Options.setUseCache(true);
        forSha256Options.setUseHashLookup(true);
        return this.forSha256Async(sha256, forSha256Options);
    }

    @Override
    public CompletableFuture<VaasVerdict> forSha256Async(Sha256 sha256, ForSha256Options options)
            throws IOException, InterruptedException, VaasAuthenticationException {
        var params = Map.of(
                "useCache", String.valueOf(options.isUseCache()),
                "useHashLookup", String.valueOf(options.isUseHashLookup()));
        var filesReportUri = this.config.getUrl() + String.format("/files/%s/report?", sha256.getValue())
                + encodeParams(params);
        var request = CreateHttpRequestBuilderWithHeaders(URI.create(filesReportUri), options.getVaasRequestId())
                .GET()
                .build();

        return sendFileWithRetry(httpClient, request).orTimeout(this.config.getDefaultTimeoutInMs(),
                TimeUnit.MILLISECONDS);
    }

    @Override
    public VaasVerdict forSha256(Sha256 sha256) throws URISyntaxException, IOException, InterruptedException,
            VaasClientException, VaasAuthenticationException, ExecutionException {
        return forSha256Async(sha256).get();
    }

    @Override
    public VaasVerdict forSha256(Sha256 sha256, ForSha256Options options) throws URISyntaxException, IOException,
            InterruptedException, VaasClientException, VaasAuthenticationException, ExecutionException {
        return forSha256Async(sha256, options).get();
    }

    @Override
    public CompletableFuture<VaasVerdict> forFileAsync(Path file)
            throws NoSuchAlgorithmException, IOException, InterruptedException,
            VaasAuthenticationException {
        var forFileOptions = new ForFileOptions();
        forFileOptions.setUseCache(true);
        forFileOptions.setUseHashLookup(true);
        return forFileAsync(file, forFileOptions);
    }

    @Override
    public CompletableFuture<VaasVerdict> forFileAsync(Path file, ForFileOptions options)
            throws NoSuchAlgorithmException, IOException, InterruptedException, VaasAuthenticationException {
        var sha256 = new Sha256(file);
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
                        var inputstream = Files.newInputStream(file, StandardOpenOption.READ);
                        var forStreamOptions = new ForStreamOptions();
                        forStreamOptions.setUseHashLookup(options.isUseHashLookup());
                        forStreamOptions.setVaasRequestId(options.getVaasRequestId());

                        return forStreamAsync(inputstream, file.toFile().length(), forStreamOptions);
                    }
                })).orTimeout(this.config.getDefaultTimeoutInMs(), TimeUnit.MILLISECONDS);
    }

    @Override
    public VaasVerdict forFile(Path file) throws NoSuchAlgorithmException, IOException, URISyntaxException,
            InterruptedException, VaasAuthenticationException, ExecutionException {
        return forFileAsync(file).get();
    }

    @Override
    public VaasVerdict forFile(Path file, ForFileOptions options) throws NoSuchAlgorithmException, IOException,
            URISyntaxException, InterruptedException, VaasAuthenticationException, ExecutionException {
        return forFileAsync(file, options).get();
    }

    @Override
    public CompletableFuture<VaasVerdict> forStreamAsync(InputStream stream, long contentLength)
            throws IOException, InterruptedException, VaasAuthenticationException {
        var forStreamOptions = new ForStreamOptions();
        forStreamOptions.setUseHashLookup(true);
        return forStreamAsync(stream, contentLength, forStreamOptions);
    }

    @Override
    public CompletableFuture<VaasVerdict> forStreamAsync(InputStream inputStream, long contentLength,
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

                    return forSha256Async(sha256, forSha256Options);
                })).orTimeout(this.config.getDefaultTimeoutInMs(), TimeUnit.MILLISECONDS);
    }

    @Override
    public VaasVerdict forStream(InputStream stream, long contentLength)
            throws URISyntaxException, IOException, InterruptedException, VaasAuthenticationException,
            ExecutionException {
        return forStreamAsync(stream, contentLength).get();
    }

    @Override
    public VaasVerdict forStream(InputStream stream, long contentLength, ForStreamOptions options)
            throws URISyntaxException, IOException, InterruptedException, VaasAuthenticationException,
            ExecutionException {
        return forStreamAsync(stream, contentLength, options).get();
    }

    @Override
    public CompletableFuture<VaasVerdict> forUrlAsync(URL url) throws IOException, InterruptedException,
            VaasAuthenticationException {
        var forUrlOptions = new ForUrlOptions();
        forUrlOptions.setUseHashLookup(true);
        return forUrlAsync(url, forUrlOptions);
    }

    @Override
    public CompletableFuture<VaasVerdict> forUrlAsync(URL url, ForUrlOptions options)
            throws IOException, InterruptedException, VaasAuthenticationException {
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
                        return parseVaasError(response);
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
    public VaasVerdict forUrl(URL url) throws URISyntaxException, IOException, InterruptedException,
            VaasAuthenticationException, VaasClientException, VaasServerException, ExecutionException {
        return forUrlAsync(url).get();
    }

    @Override
    public VaasVerdict forUrl(URL url, ForUrlOptions options) throws URISyntaxException, IOException,
            InterruptedException, VaasAuthenticationException, VaasClientException, VaasServerException,
            ExecutionException {
        return forUrlAsync(url, options).get();
    }
}
