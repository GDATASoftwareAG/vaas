package de.gdata.vaas;

import de.gdata.vaas.messages.*;
import de.gdata.vaas.exceptions.*;
import lombok.Getter;
import lombok.NonNull;
import org.java_websocket.exceptions.WebsocketNotConnectedException;
import java.io.IOException;
import java.io.InputStream;
import java.io.Closeable;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest.BodyPublishers;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class Vaas implements Closeable{
    private static final int connectionRetryDelayInMs = 1000;
    private static final int connectionTimeoutInMs = 10000;

    @Getter
    @NonNull
    private final VaasConfig config;

    @Getter
    @NonNull
    private VaasOptions options;

    @Getter
    @NonNull
    private final IAuthenticator authenticator;
    private final HttpClient httpClient = HttpClient.newBuilder().build();
    private WebSocketClient client;

    public Vaas(@NonNull VaasConfig config, @NonNull IAuthenticator authenticator) {
        this.config = config;
        this.authenticator = authenticator;
        this.options = new VaasOptions();
    }

    public Vaas(VaasConfig config, IAuthenticator authenticator,
            VaasOptions options) {
        this.config = config;
        this.authenticator = authenticator;
        this.options = options;
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
        var clientToken = authenticator.getToken();
        while (true) {
            this.client = new WebSocketClient(this.getConfig(), clientToken);
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

    /**
     * Request verdict for url
     * 
     * @param url the URL to analyze
     * @return the Vaas verdict
     * @throws VaasInvalidStateException     if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException if the connection to the Vaas backend
     *                                       is closed
     * @throws ExecutionException            if the request fails
     * @throws InterruptedException          if the operation is interrupted by
     *                                       Thread.interrupt()
     * @throws TimeoutException              if the request times out
     */
    public VaasVerdict forUrl(URL url) throws VaasInvalidStateException, VaasConnectionClosedException,
            ExecutionException, InterruptedException, TimeoutException, VaasClientException, VaasServerException, URISyntaxException {
        return this.forUrl(url, UUID.randomUUID(), null);
    }

    /**
     * Request verdict for url
     * 
     * @param url                      the URL to analyze
     * @param verdictRequestAttributes additional attributes for the request
     * @return the Vaas verdict
     * @throws VaasInvalidStateException     if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException if the connection to the Vaas backend
     *                                       is closed
     * @throws InterruptedException          if the operation is interrupted
     * @throws TimeoutException              if the request times out
     */
    public VaasVerdict forUrl(URL url, VerdictRequestAttributes verdictRequestAttributes)
            throws VaasInvalidStateException, VaasConnectionClosedException,
            InterruptedException, TimeoutException, VaasClientException, VaasServerException, URISyntaxException {
        return this.forUrl(url, UUID.randomUUID(), verdictRequestAttributes);
    }

    /**
     * Request verdict for url
     * 
     * @param url  the URL to analyze
     * @param guid a custom guid
     * @return the Vaas verdict
     * @throws VaasInvalidStateException     if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException if the connection to the Vaas backend
     *                                       is closed
     * @throws InterruptedException          if the operation is interrupted
     * @throws TimeoutException              if the request times out
     */
    public VaasVerdict forUrl(URL url, UUID guid) throws VaasInvalidStateException, VaasConnectionClosedException,
            InterruptedException, TimeoutException, VaasClientException, VaasServerException, URISyntaxException {
        return this.forUrl(url, guid, null);
    }

    /**
     * Request verdict for url
     * 
     * @param url                      the URL to analyze
     * @param guid                     a custom guid
     * @param verdictRequestAttributes additional attributes for the request
     * @return the Vaas verdict
     * @throws VaasInvalidStateException     if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException if the connection to the Vaas backend
     *                                       is closed
     * @throws InterruptedException          if the operation is interrupted by
     *                                       Thread.interrupt()
     * @throws TimeoutException              if the request times out
     */
    public VaasVerdict forUrl(@NonNull URL url, UUID guid, VerdictRequestAttributes verdictRequestAttributes)
            throws VaasInvalidStateException, VaasConnectionClosedException,
            InterruptedException, TimeoutException, VaasClientException, VaasServerException, URISyntaxException {
        EnsureClientIsConnectedAndAuthenticated();
        try {
            var verdictResponse = this.forUrlAsync(url, guid, verdictRequestAttributes).get(
                    this.config.getDefaultTimeout().toMillis(),
                    TimeUnit.MILLISECONDS);
            return new VaasVerdict(verdictResponse);
        } catch (ExecutionException e) {
            throwVaasException(e);
            // never reached
            return null;
        }
    }

    private CompletableFuture<VerdictResponse> forUrlAsync(URL url, UUID guid,
            VerdictRequestAttributes verdictRequestAttributes)
            throws VaasConnectionClosedException, URISyntaxException {
        url.toURI();
        var request = new VerdictRequestForUrl(url, this.client.getSessionId(), guid, verdictRequestAttributes,
                this.options);
        return this.forUrlRequestAsync(request);
    }

    /**
     * Request verdict for Sha256
     * 
     * @return the Vaas verdict
     * @throws InterruptedException          if the operation is interrupted by
     *                                       Thread.interrupt()
     * @throws TimeoutException              if the request times out
     * @throws VaasInvalidStateException     if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException if the connection to the Vaas backend
     *                                       is closed
     */
    public VaasVerdict forSha256(Sha256 sha256) throws InterruptedException, TimeoutException,
            VaasInvalidStateException, VaasConnectionClosedException, VaasClientException, VaasServerException {
        return this.forSha256(sha256, UUID.randomUUID(), null);
    }

    /**
     * Request verdict for Sha256
     *
     * @param sha256                   the hashsum to analyze
     * @param verdictRequestAttributes additional attributes for the request*
     * @return the Vaas verdict
     * @throws InterruptedException          if the operation is interrupted by
     *                                       Thread.interrupt()
     * @throws TimeoutException              if the request times out
     * @throws VaasInvalidStateException     if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException if the connection to the Vaas backend
     *                                       is closed
     */
    public VaasVerdict forSha256(Sha256 sha256, VerdictRequestAttributes verdictRequestAttributes)
            throws InterruptedException, TimeoutException,
            VaasInvalidStateException, VaasConnectionClosedException, VaasClientException, VaasServerException {
        return this.forSha256(sha256, UUID.randomUUID(), verdictRequestAttributes);
    }

    /**
     * Request verdict for Sha256
     *
     * @param sha256 the hashsum to analyze
     * @param guid   a custom guid
     * @return the Vaas verdict
     * @throws InterruptedException          if the operation is interrupted by
     *                                       Thread.interrupt()
     * @throws TimeoutException              if the request times out
     * @throws VaasInvalidStateException     if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException if the connection to the Vaas backend
     *                                       is closed
     */
    public VaasVerdict forSha256(Sha256 sha256, UUID guid)
            throws InterruptedException, TimeoutException,
            VaasInvalidStateException, VaasConnectionClosedException, VaasClientException, VaasServerException {
        return this.forSha256(sha256, guid, null);
    }

    /**
     * Request verdict for Sha256
     * 
     * @param sha256                   the sha256 to analyze
     * @param verdictRequestAttributes additional attributes for the request
     * @return the Vaas verdict
     * @throws InterruptedException          if the operation is interrupted by
     *                                       Thread.interrupt()
     * @throws TimeoutException              if the request times out
     * @throws VaasInvalidStateException     if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException if the connection to the Vaas backend
     *                                       is closed
     */
    public VaasVerdict forSha256(@NonNull Sha256 sha256, UUID guid, VerdictRequestAttributes verdictRequestAttributes)
            throws InterruptedException, TimeoutException, VaasInvalidStateException,
            VaasConnectionClosedException, VaasClientException, VaasServerException {
        EnsureClientIsConnectedAndAuthenticated();
        try {
            var verdictResponse = this.forSha256Async(sha256, guid, verdictRequestAttributes).get(
                    this.config.getDefaultTimeout().toMillis(),
                    TimeUnit.MILLISECONDS);
            return new VaasVerdict(verdictResponse);
        } catch (ExecutionException e) {
            throwVaasException(e);
            // never reached
            return null;
        }
    }

    private CompletableFuture<VerdictResponse> forSha256Async(Sha256 sha256, UUID guid,
            VerdictRequestAttributes verdictRequestAttributes) throws VaasConnectionClosedException {
        var request = new VerdictRequest(sha256, this.client.getSessionId(), guid, verdictRequestAttributes,
                this.options);
        return this.forRequest(request);
    }

    /**
     * Request verdict for File
     * 
     * @param file the file to analyze
     * @return the Vaas verdict
     * @throws VaasInvalidStateException     - if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException - if the connection to the Vaas backend
     *                                       is closed
     * @throws IOException                   - if the file can not be read
     * @throws NoSuchAlgorithmException      - if a particular cryptographic
     *                                       algorithm is requested but is not
     *                                       available in the environment
     * @throws ExecutionException            - if the request fails
     * @throws InterruptedException          - if the operation is interrupted by
     *                                       Thread.interrupt()
     * @throws TimeoutException              - if the request times out
     */
    public VaasVerdict forFile(Path file) throws VaasInvalidStateException, VaasConnectionClosedException, IOException,
            NoSuchAlgorithmException, ExecutionException, InterruptedException, TimeoutException {
        EnsureClientIsConnectedAndAuthenticated();
        return forFile(file, UUID.randomUUID(), null);
    }

    /**
     * Request verdict for File
     * 
     * @param file                     the file to analyze
     * @param verdictRequestAttributes additional attributes for the request *
     * @return the Vaas verdict
     * @throws VaasInvalidStateException     - if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException - if the connection to the Vaas backend
     *                                       is closed
     * @throws IOException                   - if the file can not be read
     * @throws NoSuchAlgorithmException      - if a particular cryptographic
     *                                       algorithm is requested but is not
     *                                       available in the environment
     * @throws ExecutionException            - if the request fails
     * @throws InterruptedException          - if the operation is interrupted by
     *                                       Thread.interrupt()
     * @throws TimeoutException              - if the request times out
     */
    public VaasVerdict forFile(Path file, VerdictRequestAttributes verdictRequestAttributes)
            throws VaasInvalidStateException, VaasConnectionClosedException, IOException,
            NoSuchAlgorithmException, ExecutionException, InterruptedException, TimeoutException {
        return forFile(file, UUID.randomUUID(), verdictRequestAttributes);
    }

    /**
     * Request verdict for File
     * 
     * @param file the file to analyze
     * @param guid a custom guid
     * @return the Vaas verdict
     * @throws VaasInvalidStateException     if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException if the connection to the Vaas backend
     *                                       is closed
     * @throws IOException                   if the file can not be read
     * @throws NoSuchAlgorithmException      if a particular cryptographic algorithm
     *                                       is requested but is not
     *                                       available in the environment
     * @throws ExecutionException            if the request fails
     * @throws InterruptedException          if the operation is interrupted by
     *                                       Thread.interrupt()
     * @throws TimeoutException              if the request times out
     */
    public VaasVerdict forFile(Path file, UUID guid)
            throws VaasInvalidStateException, VaasConnectionClosedException, IOException,
            NoSuchAlgorithmException, ExecutionException, InterruptedException, TimeoutException {
        return forFile(file, guid, null);
    }

    /**
     * Request verdict for File
     * 
     * @param file                     the file to analyze
     * @param guid                     a custom guid
     * @param verdictRequestAttributes additional attributes for the request
     * @return the Vaas verdict
     * @throws VaasInvalidStateException     if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException if the connection to the Vaas backend
     *                                       is closed
     * @throws IOException                   if the file can not be read
     * @throws NoSuchAlgorithmException      if a particular cryptographic algorithm
     *                                       is requested but is not
     *                                       available in the environment
     * @throws ExecutionException            if the request fails
     * @throws InterruptedException          if the operation is interrupted by
     *                                       Thread.interrupt()
     * @throws TimeoutException              if the request times out
     */
    public VaasVerdict forFile(@NonNull Path file, UUID guid, VerdictRequestAttributes verdictRequestAttributes)
            throws VaasInvalidStateException, VaasConnectionClosedException, IOException, NoSuchAlgorithmException,
            ExecutionException, InterruptedException, TimeoutException {
        EnsureClientIsConnectedAndAuthenticated();
        var verdictResponse = this.forFileAsync(file, guid, verdictRequestAttributes).get(
                this.config.getDefaultTimeout().toMillis(),
                TimeUnit.MILLISECONDS);
        return new VaasVerdict(verdictResponse);
    }

    /**
     * Request verdict for input stream
     * 
     * @param stream the input stream to analyze
     * @return the Vaas verdict
     * @throws VaasInvalidStateException     if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException if the connection to the Vaas backend
     *                                       is closed
     * @throws ExecutionException            if the request fails
     * @throws InterruptedException          if the operation is interrupted by
     *                                       Thread.interrupt()
     * @throws TimeoutException              if the request times out
     */
    public VaasVerdict forStream(InputStream stream, long contentLength)
            throws VaasInvalidStateException, VaasConnectionClosedException,
            ExecutionException, InterruptedException, TimeoutException {
        EnsureClientIsConnectedAndAuthenticated();
        var verdictResponse = this.forStreamAsync(stream, contentLength, UUID.randomUUID(), null).get(
                this.config.getDefaultTimeout().toMillis(),
                TimeUnit.MILLISECONDS);
        return new VaasVerdict(verdictResponse);
    }

    /**
     * Request verdict for input stream
     * 
     * @param stream the input stream to analyze
     * @return the Vaas verdict
     * @throws VaasInvalidStateException     if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException if the connection to the Vaas backend
     *                                       is closed
     * @throws ExecutionException            if the request fails
     * @throws InterruptedException          if the operation is interrupted by
     *                                       Thread.interrupt()
     * @throws TimeoutException              if the request times out
     */
    public VaasVerdict forStream(InputStream stream, long contentLength, UUID guid)
            throws VaasInvalidStateException, VaasConnectionClosedException,
            ExecutionException, InterruptedException, TimeoutException {
        EnsureClientIsConnectedAndAuthenticated();
        var verdictResponse = this.forStreamAsync(stream, contentLength, guid, null).get(
                this.config.getDefaultTimeout().toMillis(),
                TimeUnit.MILLISECONDS);
        return new VaasVerdict(verdictResponse);
    }

    /**
     * Request verdict for input stream
     * 
     * @param stream the input stream to analyze
     * @return the Vaas verdict
     * @throws VaasInvalidStateException     if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException if the connection to the Vaas backend
     *                                       is closed
     * @throws ExecutionException            if the request fails
     * @throws InterruptedException          if the operation is interrupted by
     *                                       Thread.interrupt()
     * @throws TimeoutException              if the request times out
     */
    public VaasVerdict forStream(InputStream stream, long contentLength,
            VerdictRequestAttributes verdictRequestAttributes)
            throws VaasInvalidStateException, VaasConnectionClosedException,
            ExecutionException, InterruptedException, TimeoutException {
        EnsureClientIsConnectedAndAuthenticated();
        var verdictResponse = this.forStreamAsync(stream, contentLength, UUID.randomUUID(), verdictRequestAttributes)
                .get(
                        this.config.getDefaultTimeout().toMillis(),
                        TimeUnit.MILLISECONDS);
        return new VaasVerdict(verdictResponse);
    }

    /**
     * Request verdict for input stream
     * 
     * @param stream the input stream to analyze
     * @return the Vaas verdict
     * @throws VaasInvalidStateException     if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException if the connection to the Vaas backend
     *                                       is closed
     * @throws ExecutionException            if the request fails
     * @throws InterruptedException          if the operation is interrupted by
     *                                       Thread.interrupt()
     * @throws TimeoutException              if the request times out
     */
    public VaasVerdict forStream(InputStream stream, long contentLength, UUID guid,
            VerdictRequestAttributes verdictRequestAttributes)
            throws VaasInvalidStateException, VaasConnectionClosedException,
            ExecutionException, InterruptedException, TimeoutException {
        EnsureClientIsConnectedAndAuthenticated();
        var verdictResponse = this.forStreamAsync(stream, contentLength, guid, verdictRequestAttributes).get(
                this.config.getDefaultTimeout().toMillis(),
                TimeUnit.MILLISECONDS);
        return new VaasVerdict(verdictResponse);
    }

    private CompletableFuture<VerdictResponse> forStreamAsync(InputStream stream, long contentLength, UUID guid,
            VerdictRequestAttributes verdictRequestAttributes)
            throws VaasConnectionClosedException {
        var verdictRequestForStream = new VerdictRequestForStream(this.client.getSessionId(), guid,
                verdictRequestAttributes, this.options);

        return this.forRequest(verdictRequestForStream)
                .thenCompose(verdictResponse -> {
                    var verdict = verdictResponse.getVerdict();
                    if (verdict != Verdict.UNKNOWN) {
                        throwAsUnchecked(new VaasServerException("Server returned verdict without receiving content"));
                        return null;
                    }

                    try {
                        var uploadResponseFuture = this.client.waitForVerdict(verdictRequestForStream.getGuid());

                        return uploadStream(stream, contentLength, verdictResponse.getUploadUrl(),
                                verdictResponse.getUploadToken())
                                .thenCompose((v) -> uploadResponseFuture);
                    } catch (Exception e) {
                        throwAsUnchecked(e);
                        return null;
                    }
                });
    }

    private CompletableFuture<VerdictResponse> forFileAsync(Path file, UUID guid,
            VerdictRequestAttributes verdictRequestAttributes)
            throws NoSuchAlgorithmException, IOException, VaasConnectionClosedException {
        var sha256 = new Sha256(file);
        var verdictRequest = new VerdictRequest(sha256, this.client.getSessionId(), guid, verdictRequestAttributes,
                this.options);

        return this.forRequest(verdictRequest)
                .thenCompose(verdictResponse -> {
                    var verdict = verdictResponse.getVerdict();
                    if (verdict != Verdict.UNKNOWN) {
                        return CompletableFuture.completedStage(verdictResponse);
                    }
                    try {
                        var uploadResponseFuture = this.client.waitForVerdict(verdictRequest.getGuid());

                        return uploadFile(file, verdictResponse.getUploadUrl(), verdictResponse.getUploadToken())
                                .thenCompose((v) -> uploadResponseFuture);
                    } catch (Exception e) {
                        throwAsUnchecked(e);
                        return null;
                    }
                });
    }

    private CompletableFuture<Void> uploadFile(Path file, String url, String authToken)
            throws IOException, URISyntaxException {

        var builder = HttpRequest
                .newBuilder(new URI(url))
                .header("Authorization", authToken)
                .version(Version.HTTP_1_1)
                .PUT(HttpRequest.BodyPublishers.ofFile(file));
        var request = builder.build();

        var futureResponse = this.httpClient
                .sendAsync(request, HttpResponse.BodyHandlers.ofString());

        return futureResponse.thenAccept(response -> {
            if (response.statusCode() != 200) {
                throwAsUnchecked(new IOException(
                        "Failed to upload file. HTTP Status Code: " + response.statusCode() + " Error: "
                                + response.body()));
            }
        });
    }

    private CompletableFuture<Void> uploadStream(InputStream stream, long contentLength, String url, String authToken)
            throws URISyntaxException {
        var bodyPublisher = BodyPublishers.fromPublisher(BodyPublishers.ofInputStream(() -> stream), contentLength);
        var request = HttpRequest
                .newBuilder(new URI(url))
                .header("Authorization", authToken)
                .PUT(bodyPublisher)
                .build();

        var futureResponse = this.httpClient
                .sendAsync(request, HttpResponse.BodyHandlers.ofString());

        return futureResponse.thenAccept(response -> {
            if (response.statusCode() != 200) {
                throwAsUnchecked(new IOException(
                        "Failed to upload file. HTTP Status Code: " + response.statusCode() + " Error: "
                                + response.body()));
            }
        });
    }

    private CompletableFuture<VerdictResponse> forRequest(VerdictRequest verdictRequest)
            throws VaasConnectionClosedException {
        var verdictResponse = this.client.waitForVerdict(verdictRequest.getGuid());

        verdictRequest.setSessionId(this.client.getSessionId());
        try {
            this.client.send(verdictRequest.toJson());
        } catch (WebsocketNotConnectedException ignored) {
            throw new VaasConnectionClosedException();
        }

        return verdictResponse;
    }

    private CompletableFuture<VerdictResponse> forRequest(VerdictRequestForStream verdictRequest)
            throws VaasConnectionClosedException {
        var verdictResponse = this.client.waitForVerdict(verdictRequest.getGuid());

        verdictRequest.setSessionId(this.client.getSessionId());
        try {
            this.client.send(verdictRequest.toJson());
        } catch (WebsocketNotConnectedException ignored) {
            throw new VaasConnectionClosedException();
        }

        return verdictResponse;
    }

    private CompletableFuture<VerdictResponse> forUrlRequestAsync(VerdictRequestForUrl verdictRequestForUrl)
            throws VaasConnectionClosedException {
        var verdictResponse = this.client.waitForVerdict(verdictRequestForUrl.getGuid());

        verdictRequestForUrl.setSessionId(this.client.getSessionId());
        try {
            this.client.send(verdictRequestForUrl.toJson());
        } catch (WebsocketNotConnectedException ignored) {
            throw new VaasConnectionClosedException();
        }

        return verdictResponse;
    }

    private void EnsureClientIsConnectedAndAuthenticated()
            throws VaasConnectionClosedException, VaasInvalidStateException {
        if (this.client == null) {
            throw new VaasInvalidStateException("connect() was not called");
        }
        if (this.client.isClosed()) {
            throw new VaasConnectionClosedException();
        }
        this.client.EnsureIsAuthenticated();
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
    public void close() throws IOException {
        try {
            this.disconnect();
        } catch (InterruptedException e) {
            throwAsUnchecked(e);
        }
    }
}
