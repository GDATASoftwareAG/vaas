package de.gdata.vaas;

import de.gdata.vaas.exceptions.VaasAuthenticationException;
import de.gdata.vaas.exceptions.VaasConnectionClosedException;
import de.gdata.vaas.exceptions.VaasInvalidStateException;
import de.gdata.vaas.messages.*;
import lombok.Getter;
import lombok.NonNull;

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
    @Getter
    @NonNull
    private final VaasConfig config;

    @Getter
    @NonNull
    private final VaasOptions options;

    @Getter
    @NonNull
    private final IClientCredentialsGrantAuthenticator clientCredentialsGrantAuthenticator;
    private final HttpClient httpClient = HttpClient.newBuilder().build();
    private WebSocketClient client;

    public Vaas(VaasConfig config, IClientCredentialsGrantAuthenticator clientCredentialsGrantAuthenticator) {
        this.config = config;
        this.clientCredentialsGrantAuthenticator = clientCredentialsGrantAuthenticator;
    }

    public Vaas(VaasConfig config, IClientCredentialsGrantAuthenticator clientCredentialsGrantAuthenticator, VaasOptions options) {
        this(config, clientCredentialsGrantAuthenticator);
        this.options = options;
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable> void throwAsUnchecked(Exception exception) throws E {
        throw (E) exception;
    }

    /**
     * Connect and authenticate with the VaaS Backend
     * 
     * @throws IOException                 if an I/O error occurs when getting the
     *                                     token from the identity provide
     * @throws InterruptedException        if the operation is interrupted
     * @throws VaasAuthenticationException if the token returned by the identity
     *                                     provider is invalid
     * @throws TimeoutException            if the authentication in the VaaS backend
     *                                     takes too long
     */
    public void connect() throws IOException, InterruptedException, VaasAuthenticationException, TimeoutException {
        this.client = new WebSocketClient(this.getConfig(), clientCredentialsGrantAuthenticator.getToken());
        this.client.connectBlocking();
        try {
            this.client.Authenticate();
        } catch (ExecutionException e) {
            throw new VaasAuthenticationException();
        }
    }

    /**
     * Disconnect from the Vaas backend
     *
     * @throws InterruptedException if the operation is interrupted
     */
    public void disconnect() throws InterruptedException {
        if (this.client != null) {
            this.client.closeBlocking();
        }
    }

    private CompletableFuture<VerdictResponse> forUrlAsync(URL url, UUID guid,
            VerdictRequestAttributes verdictRequestAttributes)
            throws VaasInvalidStateException, VaasConnectionClosedException {
        EnsureClientIsCreatedAndAuthenticated();
        var request = new VerdictRequestForUrl(url, this.client.getSessionId(), guid, verdictRequestAttributes);
        return this.forUrlRequestAsync(request);
    }

    /**
     * Request verdict for url
     * 
     * @param url the URL to analyze
     * @return the Vaas verdict
     * @throws VaasInvalidStateException     - if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException - if the connection to the Vaas backend
     *                                       is closed
     * @throws ExecutionException            - if the request fails
     * @throws InterruptedException          - if the operation is interrupted
     * @throws TimeoutException              - if the request times out
     */
    public VaasVerdict forUrl(URL url) throws VaasInvalidStateException, VaasConnectionClosedException,
            ExecutionException, InterruptedException, TimeoutException {
        return this.forUrl(url, UUID.randomUUID(),null);
    }

    /**
     * Request verdict for url
     * 
     * @param url the URL to analyze
     * @return the Vaas verdict
     * @throws VaasInvalidStateException     - if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException - if the connection to the Vaas backend
     *                                       is closed
     * @throws ExecutionException            - if the request fails
     * @throws InterruptedException          - if the operation is interrupted
     * @throws TimeoutException              - if the request times out
     */
    public VaasVerdict forUrl(URL url, UUID guid) throws VaasInvalidStateException, VaasConnectionClosedException,
            ExecutionException, InterruptedException, TimeoutException {
        return this.forUrl(url, guid, null);
    }

    /**
     * Request verdict for url
     * 
     * @param url the URL to analyze
     * @return the Vaas verdict
     * @throws VaasInvalidStateException     - if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException - if the connection to the Vaas backend
     *                                       is closed
     * @throws ExecutionException            - if the request fails
     * @throws InterruptedException          - if the operation is interrupted
     * @throws TimeoutException              - if the request times out
     */
    public VaasVerdict forUrl(URL url, VerdictRequestAttributes verdictRequestAttributes) throws VaasInvalidStateException, VaasConnectionClosedException,
            ExecutionException, InterruptedException, TimeoutException {
        return this.forUrl(url, UUID.randomUUID(), verdictRequestAttributes);
    }        

    /**
     * Request verdict for url
     * 
     * @param url                      the URL to analyze
     * @param verdictRequestAttributes - additional attributes for the request
     * @return the Vaas verdict
     * @throws VaasInvalidStateException     - if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException - if the connection to the Vaas backend
     *                                       is closed
     * @throws ExecutionException            - if the request fails
     * @throws InterruptedException          - if the operation is interrupted
     * @throws TimeoutException              - if the request times out
     */
    public VaasVerdict forUrl(URL url, UUID guid, VerdictRequestAttributes verdictRequestAttributes)
            throws VaasInvalidStateException, VaasConnectionClosedException, ExecutionException,
            InterruptedException, TimeoutException {
        var verdictResponse = this.forUrlAsync(url, guid, verdictRequestAttributes).get(
                this.config.getDefaultTimeout().toMillis(),
                TimeUnit.MILLISECONDS);
        return new VaasVerdict(verdictResponse);
    }

    /**
     * Request verdict for Sha256
     * 
     * @return the Vaas verdict
     * @throws ExecutionException            - if the request fails
     * @throws InterruptedException          - if the operation is interrupted
     * @throws TimeoutException              - if the request times out
     * @throws VaasInvalidStateException     - if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException - if the connection to the Vaas backend
     *                                       is closed
     */
    public VaasVerdict forSha256(Sha256 sha256) throws ExecutionException, InterruptedException, TimeoutException,
            VaasInvalidStateException, VaasConnectionClosedException {
        return this.forSha256(sha256, null);
    }

    /**
     * Request verdict for Sha256
     * 
     * @param sha256                   the sha256 to analyze
     * @param verdictRequestAttributes additional attributes for the request
     * @return the Vaas verdict
     * @throws ExecutionException            - if the request fails
     * @throws InterruptedException          - if the operation is interrupted
     * @throws TimeoutException              - if the request times out
     * @throws VaasInvalidStateException     - if the connection is in an invalid
     *                                       state
     * @throws VaasConnectionClosedException - if the connection to the Vaas backend
     *                                       is closed
     */
    public VaasVerdict forSha256(Sha256 sha256, VerdictRequestAttributes verdictRequestAttributes)
            throws ExecutionException, InterruptedException, TimeoutException, VaasInvalidStateException,
            VaasConnectionClosedException {
        var verdictResponse = this.forSha256Async(sha256, verdictRequestAttributes).get(
                this.config.getDefaultTimeout().toMillis(),
                TimeUnit.MILLISECONDS);
        return new VaasVerdict(verdictResponse);
    }

    private CompletableFuture<VerdictResponse> forSha256Async(Sha256 sha256,
            VerdictRequestAttributes verdictRequestAttributes)
            throws VaasInvalidStateException, VaasConnectionClosedException {
        EnsureClientIsCreatedAndAuthenticated();
        var request = new VerdictRequest(sha256, this.client.getSessionId(), verdictRequestAttributes);
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
     * @throws InterruptedException          - if the operation is interrupted
     * @throws TimeoutException              - if the request times out
     */
    public VaasVerdict forFile(Path file) throws VaasInvalidStateException, VaasConnectionClosedException, IOException,
            NoSuchAlgorithmException, ExecutionException, InterruptedException, TimeoutException {
        return forFile(file, null);
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
     * @throws InterruptedException          - if the operation is interrupted
     * @throws TimeoutException              - if the request times out
     */
    public VaasVerdict forFile(Path file, VerdictRequestAttributes verdictRequestAttributes)
            throws VaasInvalidStateException, VaasConnectionClosedException, IOException, NoSuchAlgorithmException,
            ExecutionException, InterruptedException, TimeoutException {
        var verdictResponse = this.forFileAsync(file, verdictRequestAttributes).get(
                this.config.getDefaultTimeout().toMillis(),
                TimeUnit.MILLISECONDS);
        return new VaasVerdict(verdictResponse);
    }

    private CompletableFuture<VerdictResponse> forFileAsync(Path file,
            VerdictRequestAttributes verdictRequestAttributes)
            throws VaasInvalidStateException, VaasConnectionClosedException, NoSuchAlgorithmException, IOException {
        EnsureClientIsCreatedAndAuthenticated();
        var sha256 = new Sha256(file);
        var verdictRequest = new VerdictRequest(sha256, this.client.getSessionId(), verdictRequestAttributes);

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

    private CompletableFuture<VerdictResponse> forRequest(VerdictRequest verdictRequest) {
        var verdictResponse = this.client.waitForVerdict(verdictRequest.getGuid());

        verdictRequest.setSessionId(this.client.getSessionId());
        this.client.send(verdictRequest.toJson());

        return verdictResponse;
    }

    private CompletableFuture<VerdictResponse> forUrlRequestAsync(VerdictRequestForUrl verdictRequestForUrl) {
        var verdictResponse = this.client.waitForVerdict(verdictRequestForUrl.getGuid());

        verdictRequestForUrl.setSessionId(this.client.getSessionId());
        this.client.send(verdictRequestForUrl.toJson());

        return verdictResponse;
    }

    private void EnsureClientIsCreatedAndAuthenticated()
            throws VaasConnectionClosedException, VaasInvalidStateException {
        if (client == null) {
            throw new VaasInvalidStateException("connect() was not called");
        }
        this.client.EnsureIsAuthenticated();
    }
}
