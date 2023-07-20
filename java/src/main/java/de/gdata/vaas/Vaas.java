package de.gdata.vaas;

import de.gdata.vaas.exceptions.VaasAuthenticationException;
import de.gdata.vaas.exceptions.VaasConnectionClosedException;
import de.gdata.vaas.exceptions.VaasInvalidStateException;
import de.gdata.vaas.messages.*;
import lombok.Getter;
import lombok.NonNull;
import org.java_websocket.exceptions.WebsocketNotConnectedException;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class Vaas {
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
    private final IClientCredentialsGrantAuthenticator clientCredentialsGrantAuthenticator;
    private final HttpClient httpClient = HttpClient.newBuilder().build();
    private WebSocketClient client;

    public Vaas(VaasConfig config, IClientCredentialsGrantAuthenticator clientCredentialsGrantAuthenticator) {
        this.config = config;
        this.clientCredentialsGrantAuthenticator = clientCredentialsGrantAuthenticator;
        this.options = new VaasOptions();
    }

    public Vaas(VaasConfig config, IClientCredentialsGrantAuthenticator clientCredentialsGrantAuthenticator,
            VaasOptions options) {
        this.config = config;
        this.clientCredentialsGrantAuthenticator = clientCredentialsGrantAuthenticator;
        this.options = options;
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable> void throwAsUnchecked(Exception exception) throws E {
        throw (E) exception;
    }

    /**
     * Connect and authenticate with the VaaS Backend
     * 
     * @throws IOException  if an I/O error occurs when getting the
     *                      token from the identity provider
     * @throws InterruptedException  if the operation is interrupted by
     *                               Thread.interrupt()
     * @throws VaasAuthenticationException  if the token returned by the identity
     *                                      provider is invalid
     * @throws TimeoutException  if the connection or authentication to
     *                           the VaaS backend takes too long
     */
    public void connect() throws IOException, InterruptedException, VaasAuthenticationException, TimeoutException {
        var timer = new SimpleTimer(connectionTimeoutInMs, TimeUnit.MILLISECONDS);
        var clientToken = clientCredentialsGrantAuthenticator.getToken();
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
     * @throws InterruptedException  if the operation is interrupted by
     *                               Thread.interrupt()
     */
    public void disconnect() throws InterruptedException {
        if (this.client != null) {
            this.client.closeBlocking();
        }
    }

    /**
     * Request verdict for url
     * 
     * @param url  the URL to analyze
     * @return the Vaas verdict
     * @throws VaasInvalidStateException  if the connection is in an invalid state
     * @throws VaasConnectionClosedException  if the connection to the Vaas backend is closed
     * @throws ExecutionException  if the request fails
     * @throws InterruptedException  if the operation is interrupted by Thread.interrupt()
     * @throws TimeoutException  if the request times out
     */
    public VaasVerdict forUrl(URL url) throws VaasInvalidStateException, VaasConnectionClosedException,
            ExecutionException, InterruptedException, TimeoutException {
        return this.forUrl(url, UUID.randomUUID(), null);
    }

    /**
     * Request verdict for url
     * 
     * @param url  the URL to analyze
     * @param verdictRequestAttributes  additional attributes for the request
     * @return the Vaas verdict
     * @throws VaasInvalidStateException  if the connection is in an invalid state
     * @throws VaasConnectionClosedException  if the connection to the Vaas backend is closed
     * @throws ExecutionException  if the request fails
     * @throws InterruptedException  if the operation is interrupted
     * @throws TimeoutException  if the request times out
     */
    public VaasVerdict forUrl(URL url, VerdictRequestAttributes verdictRequestAttributes)
            throws VaasInvalidStateException, VaasConnectionClosedException,
            ExecutionException, InterruptedException, TimeoutException {
        return this.forUrl(url, UUID.randomUUID(), verdictRequestAttributes);
    }

    /**
     * Request verdict for url
     * 
     * @param url  the URL to analyze
     * @param guid  a custom guid
     * @return the Vaas verdict
     * @throws VaasInvalidStateException  if the connection is in an invalid state
     * @throws VaasConnectionClosedException  if the connection to the Vaas backend is closed
     * @throws ExecutionException  if the request fails
     * @throws InterruptedException  if the operation is interrupted
     * @throws TimeoutException  if the request times out
     */
    public VaasVerdict forUrl(URL url, UUID guid) throws VaasInvalidStateException, VaasConnectionClosedException,
            ExecutionException, InterruptedException, TimeoutException {
        return this.forUrl(url, guid, null);
    }

    /**
     * Request verdict for url
     * 
     * @param url  the URL to analyze
     * @param guid  a custom guid
     * @param verdictRequestAttributes additional attributes for the request
     * @return the Vaas verdict
     * @throws VaasInvalidStateException  if the connection is in an invalid state
     * @throws VaasConnectionClosedException  if the connection to the Vaas backend is closed
     * @throws ExecutionException  if the request fails
     * @throws InterruptedException  if the operation is interrupted by Thread.interrupt()
     * @throws TimeoutException  if the request times out
     */
    public VaasVerdict forUrl(URL url, UUID guid, VerdictRequestAttributes verdictRequestAttributes)
            throws VaasInvalidStateException, VaasConnectionClosedException, ExecutionException,
            InterruptedException, TimeoutException {
        EnsureClientIsConnectedAndAuthenticated();
        var verdictResponse = this.forUrlAsync(url, guid, verdictRequestAttributes).get(
                this.config.getDefaultTimeout().toMillis(),
                TimeUnit.MILLISECONDS);
        return new VaasVerdict(verdictResponse);
    }

    private CompletableFuture<VerdictResponse> forUrlAsync(URL url, UUID guid,
            VerdictRequestAttributes verdictRequestAttributes)
            throws VaasConnectionClosedException {
        var request = new VerdictRequestForUrl(url, this.client.getSessionId(), guid, verdictRequestAttributes, this.options);
        return this.forUrlRequestAsync(request);
    }

    /**
     * Request verdict for Sha256
     *
     * @param sha256  the hashsum to analyze
     * @return the Vaas verdict
     * @throws ExecutionException  if the request fails
     * @throws InterruptedException  if the operation is interrupted by Thread.interrupt()
     * @throws TimeoutException  if the request times out
     * @throws VaasInvalidStateException  if the connection is in an invalid state
     * @throws VaasConnectionClosedException  if the connection to the Vaas backend is closed
     */
    public VaasVerdict forSha256(Sha256 sha256) throws ExecutionException, InterruptedException, TimeoutException,
            VaasInvalidStateException, VaasConnectionClosedException {
        return this.forSha256(sha256, UUID.randomUUID(), null);
    }

    /**
     * Request verdict for Sha256
     *
     * @param sha256  the hashsum to analyze
     * @param verdictRequestAttributes additional attributes for the request*
     * @return the Vaas verdict
     * @throws ExecutionException  if the request fails
     * @throws InterruptedException  if the operation is interrupted by Thread.interrupt()
     * @throws TimeoutException  if the request times out
     * @throws VaasInvalidStateException  if the connection is in an invalid state
     * @throws VaasConnectionClosedException  if the connection to the Vaas backend is closed
     */
    public VaasVerdict forSha256(Sha256 sha256, VerdictRequestAttributes verdictRequestAttributes)
            throws ExecutionException, InterruptedException, TimeoutException,
            VaasInvalidStateException, VaasConnectionClosedException {
        return this.forSha256(sha256, UUID.randomUUID(), verdictRequestAttributes);
    }

    /**
     * Request verdict for Sha256
     *
     * @param sha256  the hashsum to analyze
     * @param guid  a custom guid
     * @return the Vaas verdict
     * @throws ExecutionException  if the request fails
     * @throws InterruptedException  if the operation is interrupted by Thread.interrupt()
     * @throws TimeoutException  if the request times out
     * @throws VaasInvalidStateException  if the connection is in an invalid state
     * @throws VaasConnectionClosedException  if the connection to the Vaas backend is closed
     */
    public VaasVerdict forSha256(Sha256 sha256, UUID guid)
            throws ExecutionException, InterruptedException, TimeoutException,
            VaasInvalidStateException, VaasConnectionClosedException {
        return this.forSha256(sha256, guid, null);
    }

    /**
     * Request verdict for Sha256
     * 
     * @param sha256  the sha256 to analyze
     * @param guid  a custom guid
     * @param verdictRequestAttributes  additional attributes for the request
     * @return the Vaas verdict
     * @throws ExecutionException  if the request fails
     * @throws InterruptedException  if the operation is interrupted by Thread.interrupt()
     * @throws TimeoutException  if the request times out
     * @throws VaasInvalidStateException  if the connection is in an invalid state
     * @throws VaasConnectionClosedException  if the connection to the Vaas backend is closed
     */
    public VaasVerdict forSha256(Sha256 sha256, UUID guid, VerdictRequestAttributes verdictRequestAttributes)
            throws ExecutionException, InterruptedException, TimeoutException, VaasInvalidStateException,
            VaasConnectionClosedException {
        EnsureClientIsConnectedAndAuthenticated();
        var verdictResponse = this.forSha256Async(sha256, guid, verdictRequestAttributes).get(
                this.config.getDefaultTimeout().toMillis(),
                TimeUnit.MILLISECONDS);
        return new VaasVerdict(verdictResponse);
    }

    private CompletableFuture<VerdictResponse> forSha256Async(Sha256 sha256, UUID guid,
            VerdictRequestAttributes verdictRequestAttributes) throws VaasConnectionClosedException {
        var request = new VerdictRequest(sha256, this.client.getSessionId(), guid, verdictRequestAttributes, this.options);
        return this.forRequest(request);
    }

    /**
     * Request verdict for File
     * 
     * @param file  the file to analyze
     * @return the Vaas verdict
     * @throws VaasInvalidStateException  if the connection is in an invalid state
     * @throws VaasConnectionClosedException  if the connection to the Vaas backend is closed
     * @throws IOException  if the file can not be read
     * @throws NoSuchAlgorithmException  if a particular cryptographic algorithm is requested but is not
     *                                   available in the environment
     * @throws ExecutionException  if the request fails
     * @throws InterruptedException  if the operation is interrupted by Thread.interrupt()
     * @throws TimeoutException  if the request times out
     */
    public VaasVerdict forFile(Path file) throws VaasInvalidStateException, VaasConnectionClosedException, IOException,
            NoSuchAlgorithmException, ExecutionException, InterruptedException, TimeoutException {
        return forFile(file, UUID.randomUUID(), null);
    }

    /**
     * Request verdict for File
     * 
     * @param file  the file to analyze
     * @param verdictRequestAttributes  additional attributes for the request
     * @return the Vaas verdict
     * @throws VaasInvalidStateException  if the connection is in an invalid state
     * @throws VaasConnectionClosedException  if the connection to the Vaas backend is closed
     * @throws IOException  if the file can not be read
     * @throws NoSuchAlgorithmException  if a particular cryptographic algorithm is requested but is not
     *                                   available in the environment
     * @throws ExecutionException  if the request fails
     * @throws InterruptedException  if the operation is interrupted by Thread.interrupt()
     * @throws TimeoutException  if the request times out
     */
    public VaasVerdict forFile(Path file, VerdictRequestAttributes verdictRequestAttributes)
            throws VaasInvalidStateException, VaasConnectionClosedException, IOException,
            NoSuchAlgorithmException, ExecutionException, InterruptedException, TimeoutException {
        return forFile(file, UUID.randomUUID(), verdictRequestAttributes);
    }

    /**
     * Request verdict for File
     * 
     * @param file  the file to analyze
     * @param guid  a custom guid
     * @return the Vaas verdict
     * @throws VaasInvalidStateException  if the connection is in an invalid state
     * @throws VaasConnectionClosedException  if the connection to the Vaas backend is closed
     * @throws IOException  if the file can not be read
     * @throws NoSuchAlgorithmException  if a particular cryptographic algorithm is requested but is not
     *                                   available in the environment
     * @throws ExecutionException  if the request fails
     * @throws InterruptedException  if the operation is interrupted by Thread.interrupt()
     * @throws TimeoutException  if the request times out
     */
    public VaasVerdict forFile(Path file, UUID guid)
            throws VaasInvalidStateException, VaasConnectionClosedException, IOException,
            NoSuchAlgorithmException, ExecutionException, InterruptedException, TimeoutException {
        return forFile(file, guid, null);
    }

    /**
     * Request verdict for File
     * 
     * @param file  the file to analyze
     * @param guid  a custom guid
     * @param verdictRequestAttributes  additional attributes for the request
     * @return the Vaas verdict
     * @throws VaasInvalidStateException  if the connection is in an invalid state
     * @throws VaasConnectionClosedException  if the connection to the Vaas backend is closed
     * @throws IOException  if the file can not be read
     * @throws NoSuchAlgorithmException  if a particular cryptographic algorithm is requested but is not
     *                                   available in the environment
     * @throws ExecutionException  if the request fails
     * @throws InterruptedException  if the operation is interrupted by Thread.interrupt()
     * @throws TimeoutException  if the request times out
     */
    public VaasVerdict forFile(Path file, UUID guid, VerdictRequestAttributes verdictRequestAttributes)
            throws VaasInvalidStateException, VaasConnectionClosedException, IOException, NoSuchAlgorithmException,
            ExecutionException, InterruptedException, TimeoutException {
        EnsureClientIsConnectedAndAuthenticated();
        var verdictResponse = this.forFileAsync(file, guid, verdictRequestAttributes).get(
                this.config.getDefaultTimeout().toMillis(),
                TimeUnit.MILLISECONDS);
        return new VaasVerdict(verdictResponse);
    }

    private CompletableFuture<VerdictResponse> forFileAsync(Path file, UUID guid,
            VerdictRequestAttributes verdictRequestAttributes)
            throws NoSuchAlgorithmException, IOException, VaasConnectionClosedException {
        var sha256 = new Sha256(file);
        var verdictRequest = new VerdictRequest(sha256, this.client.getSessionId(), guid, verdictRequestAttributes, this.options);

        return this.forRequest(verdictRequest)
                .thenCompose(verdictResponse -> {
                    var verdict = verdictResponse.getVerdict();
                    if (verdict != Verdict.UNKNOWN) {
                        return CompletableFuture.completedStage(verdictResponse);
                    }
                    try {
                        var uploadResponseFuture = this.client.waitForVerdict(verdictRequest.getGuid());

                        return UploadFile(file, verdictResponse.getUploadUrl(), verdictResponse.getUploadToken())
                                .thenCompose((v) -> uploadResponseFuture);
                    } catch (Exception e) {
                        throwAsUnchecked(e);
                        return null;
                    }
                });
    }

    private CompletableFuture<Void> UploadFile(Path file, String url, String authToken)
            throws IOException, URISyntaxException {
        var bytes = Files.readAllBytes(file);
        var request = HttpRequest
                .newBuilder(new URI(url))
                .header("Authorization", authToken)
                .PUT(HttpRequest.BodyPublishers.ofByteArray(bytes))
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
}
