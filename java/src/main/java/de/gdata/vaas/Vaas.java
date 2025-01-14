package de.gdata.vaas;

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
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
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

    public Vaas(@NotNull VaasConfig config, IAuthenticator authenticator, HttpClient httpClient) {
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

    private static CompletableFuture<VaasVerdict> parseVaasError(HttpResponse<String> response) {
        var problemDetails = response.body() != null ? ProblemDetails.fromJson(response.body()) : new ProblemDetails();
        return switch (response.statusCode()) {
            case 400 -> CompletableFuture.failedFuture(new VaasClientException(problemDetails.detail));
            case 401 -> CompletableFuture.failedFuture(new VaasAuthenticationException());
            default -> CompletableFuture.failedFuture(new VaasServerException(problemDetails.detail));
        };
    }

    private static CompletableFuture<VaasVerdict> sendFileWithRetry(HttpClient httpClient, HttpRequest request) {
        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenCompose(handleException(response -> switch (response.statusCode()) {
                    case 200 -> {
                        var fileReport = FileReport.fromJson(response.body());
                        yield CompletableFuture.completedFuture(VaasVerdict.From(fileReport));
                    }
                    case 201 -> sendFileWithRetry(httpClient, request);
                    default -> parseVaasError(response);
                }));
    }

    private static CompletableFuture<VaasVerdict> sendUrlWithRetry(HttpClient httpClient, HttpRequest request) {
        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenCompose(handleException(response -> switch (response.statusCode()) {
                    case 200 -> {
                        var urlReport = UrlReport.fromJson(response.body());
                        yield CompletableFuture.completedFuture(VaasVerdict.From(urlReport));
                    }
                    case 201 -> sendUrlWithRetry(httpClient, request);
                    default -> parseVaasError(response);
                }));
    }

    private HttpRequest.Builder CreateHttpRequestBuilderWithHeaders(URI uri, String requestId)
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

    /**
     * Asynchronously retrieves a {@link CompletableFuture} containing the
     * {@link VaasVerdict} for the given SHA-256 hash.
     * This method uses cache and hash lookup options by default.
     *
     * @param sha256 the SHA-256 hash to retrieve the verdict for
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict} for
     * the hash
     * @throws IOException                 If an I/O error occurs during the
     *                                     request.
     * @throws InterruptedException        If the operation is interrupted.
     * @throws VaasAuthenticationException If there is an authentication error.
     */
    @Override
    public CompletableFuture<VaasVerdict> forSha256Async(Sha256 sha256)
            throws IOException, InterruptedException, VaasAuthenticationException {
        var forSha256Options = new ForSha256Options();
        forSha256Options.setUseCache(true);
        forSha256Options.setUseHashLookup(true);
        return this.forSha256Async(sha256, forSha256Options);
    }

    /**
     * Asynchronously retrieves a {@link CompletableFuture} containing the
     * {@link VaasVerdict} for the given SHA-256 hash.
     *
     * @param sha256  the SHA-256 hash to retrieve the verdict for
     * @param options The options to customize the request, such as using the cache
     *                and hash lookup.
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict} for
     * the hash
     * @throws IOException                 If an I/O error occurs during the
     *                                     request.
     * @throws InterruptedException        If the operation is interrupted.
     * @throws VaasAuthenticationException If there is an authentication error.
     */
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

    /**
     * Retrieves a {@link VaasVerdict} for the given SHA-256 hash.
     * This method uses cache and hash lookup options by default.
     *
     * @param sha256 the SHA-256 hash to retrieve the verdict for
     * @return the {@link VaasVerdict} for the given SHA-256 hash
     * @throws InterruptedException        if the thread is interrupted while
     *                                     waiting for the result
     * @throws ExecutionException          if the computation threw an exception
     * @throws IOException                 if an I/O error occurs
     * @throws VaasAuthenticationException if there is an authentication error
     */
    @Override
    public VaasVerdict forSha256(Sha256 sha256)
            throws InterruptedException, ExecutionException, IOException, VaasAuthenticationException {
        return forSha256Async(sha256).get();
    }

    /**
     * Retrieves a {@link VaasVerdict} for the given SHA-256 hash.
     * This method uses cache and hash lookup options by default.
     *
     * @param sha256  the SHA-256 hash to retrieve the verdict for
     * @param options The options to customize the request, such as using the cache
     *                and hash lookup.
     * @return the {@link VaasVerdict} for the given SHA-256 hash
     * @throws InterruptedException        if the thread is interrupted while
     *                                     waiting for the result
     * @throws ExecutionException          if the computation threw an exception
     * @throws IOException                 if an I/O error occurs
     * @throws VaasAuthenticationException if there is an authentication error
     */
    @Override
    public VaasVerdict forSha256(Sha256 sha256, ForSha256Options options)
            throws InterruptedException, ExecutionException, IOException, VaasAuthenticationException {
        return forSha256Async(sha256, options).get();
    }

    /**
     * Asynchronously processes a file and returns a {@link CompletableFuture}
     * containing the {@link VaasVerdict}.
     * This method uses default options for file processing, including using the
     * cache and hash lookup.
     *
     * @param file the {@link Path} to the file to be processed
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict} for
     * the file
     * @throws IOException                 if an I/O error occurs
     * @throws InterruptedException        if the operation is interrupted
     * @throws VaasAuthenticationException if authentication fails
     * @throws NoSuchAlgorithmException    if the algorithm for hash lookup is not
     *                                     available
     */
    @Override
    public CompletableFuture<VaasVerdict> forFileAsync(Path file)
            throws IOException, InterruptedException, VaasAuthenticationException, NoSuchAlgorithmException {
        var forFileOptions = new ForFileOptions();
        forFileOptions.setUseCache(true);
        forFileOptions.setUseHashLookup(true);
        return forFileAsync(file, forFileOptions);
    }

    /**
     * Asynchronously processes a file and returns a {@link CompletableFuture}
     * containing the {@link VaasVerdict}.
     * This method uses default options for file processing, including using the
     * cache and hash lookup.
     *
     * @param file    the {@link Path} to the file to be processed
     * @param options The options to customize the request, such as using the cache
     *                and hash lookup.
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict} for
     * the file
     * @throws IOException                 if an I/O error occurs
     * @throws InterruptedException        if the operation is interrupted
     * @throws VaasAuthenticationException if authentication fails
     * @throws NoSuchAlgorithmException    if the algorithm for hash lookup is not
     *                                     available
     */
    @Override
    public CompletableFuture<VaasVerdict> forFileAsync(Path file, ForFileOptions options)
            throws IOException, InterruptedException, VaasAuthenticationException, NoSuchAlgorithmException {
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
                        try {
                            var inputstream = Files.newInputStream(file, StandardOpenOption.READ);
                            var forStreamOptions = new ForStreamOptions();
                            forStreamOptions.setUseHashLookup(options.isUseHashLookup());
                            forStreamOptions.setVaasRequestId(options.getVaasRequestId());

                            return forStreamAsync(inputstream, file.toFile().length(), forStreamOptions)
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

    /**
     * Processes a file and returns the {@link VaasVerdict}.
     * This method uses default options for file processing, including using the
     * cache and hash lookup.
     *
     * @param file the {@link Path} to the file to be processed
     * @return the {@link VaasVerdict} for the file
     * @throws IOException                 if an I/O error occurs
     * @throws InterruptedException        if the operation is interrupted
     * @throws VaasAuthenticationException if authentication fails
     * @throws NoSuchAlgorithmException    if the algorithm for hash lookup is not
     *                                     available
     */
    @Override
    public VaasVerdict forFile(Path file) throws NoSuchAlgorithmException, InterruptedException, ExecutionException,
            IOException, VaasAuthenticationException {
        return forFileAsync(file).get();
    }

    /**
     * Processes a file and returns the {@link VaasVerdict}.
     *
     * @param file    the {@link Path} to the file to be processed
     * @param options The options to customize the request, such as using the cache
     *                and hash lookup.
     * @return the {@link VaasVerdict} for the file
     * @throws IOException                 if an I/O error occurs
     * @throws InterruptedException        if the operation is interrupted
     * @throws VaasAuthenticationException if authentication fails
     * @throws NoSuchAlgorithmException    if the algorithm for hash lookup is not
     *                                     available
     */
    @Override
    public VaasVerdict forFile(Path file, ForFileOptions options) throws NoSuchAlgorithmException, InterruptedException,
            ExecutionException, IOException, VaasAuthenticationException {
        return forFileAsync(file, options).get();
    }

    /**
     * Asynchronously processes a given input stream and returns a
     * {@link CompletableFuture}
     * containing the {@link VaasVerdict}.
     * This method uses the hash lookup option by default.
     *
     * @param stream        the input stream to be processed
     * @param contentLength the length of the content in the input stream
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict}
     * @throws IOException                 if an I/O error occurs
     * @throws InterruptedException        if the operation is interrupted
     * @throws VaasAuthenticationException if authentication fails
     */
    @Override
    public CompletableFuture<VaasVerdict> forStreamAsync(InputStream stream, long contentLength)
            throws IOException, InterruptedException, VaasAuthenticationException {
        var forStreamOptions = new ForStreamOptions();
        forStreamOptions.setUseHashLookup(true);
        return forStreamAsync(stream, contentLength, forStreamOptions);
    }

    /**
     * Asynchronously processes a given input stream and returns a
     * {@link CompletableFuture}
     * containing the {@link VaasVerdict}.
     *
     * @param inputStream   the input stream to be processed
     * @param contentLength the length of the content in the input stream
     * @param options       The options to customize the request, such as using the
     *                      hash lookup.
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict}
     * @throws IOException                 if an I/O error occurs
     * @throws InterruptedException        if the operation is interrupted
     * @throws VaasAuthenticationException if authentication fails
     */
    @Override
    public CompletableFuture<VaasVerdict> forStreamAsync(InputStream inputStream, long contentLength,
                                                         ForStreamOptions options) throws IOException, InterruptedException, VaasAuthenticationException {
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

    /**
     * Processes a given input stream and returns the {@link VaasVerdict}.
     * This method uses the hash lookup option by default.
     *
     * @param stream        the input stream to be processed
     * @param contentLength the length of the content in the input stream
     * @return the {@link VaasVerdict}
     * @throws InterruptedException        if the operation is interrupted
     * @throws ExecutionException          if the computation threw an exception
     * @throws IOException                 if an I/O error occurs
     * @throws VaasAuthenticationException if there is an authentication error
     */
    @Override
    public VaasVerdict forStream(InputStream stream, long contentLength)
            throws InterruptedException, ExecutionException, IOException, VaasAuthenticationException {
        return forStreamAsync(stream, contentLength).get();
    }

    /**
     * Processes a given input stream and returns the {@link VaasVerdict}.
     *
     * @param stream        the input stream to be processed
     * @param contentLength the length of the content in the input stream
     * @param options       The options to customize the request, such as using the
     *                      hash lookup.
     * @return the {@link VaasVerdict}
     * @throws InterruptedException        if the operation is interrupted
     * @throws ExecutionException          if the computation threw an exception
     * @throws IOException                 if an I/O error occurs
     * @throws VaasAuthenticationException if there is an authentication error
     */
    @Override
    public VaasVerdict forStream(InputStream stream, long contentLength, ForStreamOptions options)
            throws InterruptedException, ExecutionException, IOException, VaasAuthenticationException {
        return forStreamAsync(stream, contentLength, options).get();
    }

    /**
     * Asynchronously retrieves a {@link CompletableFuture} containing the
     * {@link VaasVerdict} for the given URL.
     * This method uses hash lookup by default.
     *
     * @param url the URL to retrieve the verdict for
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict} for
     * the
     * URL
     * @throws IOException                 If an I/O error occurs during the
     *                                     request.
     * @throws InterruptedException        If the operation is interrupted.
     * @throws VaasAuthenticationException If there is an authentication error.
     */
    @Override
    public CompletableFuture<VaasVerdict> forUrlAsync(URL url)
            throws IOException, InterruptedException, VaasAuthenticationException {
        var forUrlOptions = new ForUrlOptions();
        forUrlOptions.setUseHashLookup(true);
        return forUrlAsync(url, forUrlOptions);
    }

    /**
     * Asynchronously retrieves a {@link CompletableFuture} containing the
     * {@link VaasVerdict} for the given URL.
     *
     * @param url     the URL to retrieve the verdict for
     * @param options The options to customize the request, such as using hash
     *                lookup.
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict} for
     * the
     * URL
     * @throws IOException                 If an I/O error occurs during the
     *                                     request.
     * @throws InterruptedException        If the operation is interrupted.
     * @throws VaasAuthenticationException If there is an authentication error.
     */
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

    /**
     * Retrieves a {@link VaasVerdict} for the given URL.
     * This method uses hash lookup by default.
     *
     * @param url the URL to retrieve the verdict for
     * @return the {@link VaasVerdict} for the URL
     * @throws InterruptedException        if the thread is interrupted while
     *                                     waiting
     *                                     for the result
     * @throws ExecutionException          if the computation threw an exception
     * @throws IOException                 if an I/O error occurs
     * @throws VaasAuthenticationException if there is an authentication error
     */
    @Override
    public VaasVerdict forUrl(URL url)
            throws InterruptedException, ExecutionException, IOException, VaasAuthenticationException {
        return forUrlAsync(url).get();
    }

    /**
     * Retrieves a {@link VaasVerdict} for the given URL.
     *
     * @param url     the URL to retrieve the verdict for
     * @param options The options to customize the request, such as using hash
     *                lookup.
     * @return the {@link VaasVerdict} for the URL
     * @throws InterruptedException        if the thread is interrupted while
     *                                     waiting
     *                                     for the result
     * @throws ExecutionException          if the computation threw an exception
     * @throws IOException                 if an I/O error occurs
     * @throws VaasAuthenticationException if there is an authentication error
     */
    @Override
    public VaasVerdict forUrl(URL url, ForUrlOptions options)
            throws InterruptedException, ExecutionException, IOException, VaasAuthenticationException {
        return forUrlAsync(url, options).get();
    }

    @FunctionalInterface
    interface ThrowingFunction<T, R> {
        R apply(T t) throws Exception;
    }
}
