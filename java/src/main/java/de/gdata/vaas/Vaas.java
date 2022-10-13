package de.gdata.vaas;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import de.gdata.vaas.exceptions.VaasAuthenticationException;
import de.gdata.vaas.exceptions.VaasConnectionClosedException;
import de.gdata.vaas.exceptions.VaasInvalidStateException;
import de.gdata.vaas.messages.Verdict;
import de.gdata.vaas.messages.VerdictRequest;
import de.gdata.vaas.messages.VerdictResult;
import lombok.Getter;
import lombok.NonNull;

public class Vaas {
    private final Duration defaultTimeout = Duration.ofMinutes(10);

    @Getter
    @NonNull
    private final WebSocketConfig config;

    @Getter
    @NonNull
    private final ClientCredentialsGrantAuthenticator clientCredentialsGrantAuthenticator;

    private WebSocketClient client;

    private HttpClient httpClient = HttpClient.newBuilder().build();

    public Vaas(WebSocketConfig config, ClientCredentialsGrantAuthenticator clientCredentialsGrantAuthenticator) {
        this.config = config;
        this.clientCredentialsGrantAuthenticator = clientCredentialsGrantAuthenticator;
    }

    public void connect() throws URISyntaxException, IOException, InterruptedException, VaasAuthenticationException,
            ExecutionException, TimeoutException {
        this.client = new WebSocketClient(this.getConfig(), clientCredentialsGrantAuthenticator.getToken());
        this.client.connectBlocking();
        this.client.Authenticate();
    }

    public void disconnect() throws InterruptedException {
        if (this.client != null) {
            this.client.closeBlocking();
        }
    }

    public VerdictResult forSha256(Sha256 sha256) throws Exception {
        return this.forSha256(sha256, defaultTimeout);
    }

    public VerdictResult forSha256(Sha256 sha256, Duration timeout)
            throws Exception {
        return this.forSha256Async(sha256).get(timeout.toNanos(), TimeUnit.NANOSECONDS);
    }

    public VerdictResult forSha256(Sha256 sha256, long timeout, TimeUnit unit)
            throws Exception {
        return this.forSha256Async(sha256).get(timeout, unit);
    }

    public CompletableFuture<VerdictResult> forSha256Async(Sha256 sha256) throws Exception {
        EnsureClientIsCreatedAndAuthenticated();
        var request = new VerdictRequest(sha256, this.client.getSessionId());
        return this.forRequest(request);
    }

    public VerdictResult forFile(Path file) throws Exception {
        return forFile(file, defaultTimeout);
    }

    public VerdictResult forFile(Path file, Duration timeout) throws Exception {
        return forFile(file, timeout.toNanos(), TimeUnit.NANOSECONDS);
    }

    public VerdictResult forFile(Path file, long timeout, TimeUnit unit) throws Exception {
        return forFileAsync(file).get(timeout, unit);
    }

    public CompletableFuture<VerdictResult> forFileAsync(Path file) throws Exception {
        EnsureClientIsCreatedAndAuthenticated();
        var sha256 = new Sha256(file);
        var verdictRequest = new VerdictRequest(sha256, this.client.getSessionId());

        var verdictResultFuture = this.forRequest(verdictRequest)
                .thenCompose(verdictResult -> {
                    var verdict = verdictResult.getVerdict();
                    if (verdict != Verdict.UNKNOWN) {
                        return CompletableFuture.completedStage(verdictResult);
                    }
                    try {
                        var uploadResponseFuture = this.client.waitForVerdict(verdictRequest.getGuid());

                        return UploadFile(file, verdictResult.getUploadUrl(), verdictResult.getUploadToken())
                                .thenCompose((v) -> uploadResponseFuture)
                                .thenApply(uploadResponse -> new VerdictResult(uploadResponse));
                    } catch (Exception e) {
                        throwAsUnchecked(e);
                        return null;
                    }
                });
        return verdictResultFuture;
    }

    private CompletableFuture<Void> UploadFile(Path file, String url, String authToken)
            throws IOException, URISyntaxException, InterruptedException {
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

    @SuppressWarnings("unchecked")
    private static <E extends Throwable> void throwAsUnchecked(Exception exception) throws E {
        throw (E) exception;
    }

    private CompletableFuture<VerdictResult> forRequest(VerdictRequest verdictRequest) throws Exception {
        var verdictResponse = this.client.waitForVerdict(verdictRequest.getGuid());

        verdictRequest.setSessionId(this.client.getSessionId());
        this.client.send(verdictRequest.toJson());

        return verdictResponse
                .thenApply(response -> new VerdictResult(response));
    }

    private void EnsureClientIsCreatedAndAuthenticated()
            throws VaasConnectionClosedException, VaasInvalidStateException {
        if (client == null) {
            throw new VaasInvalidStateException("connect() was not called");
        }
        this.client.EnsureIsAuthenticated();
    }
}
