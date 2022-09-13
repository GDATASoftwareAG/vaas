package de.gdata.vaas;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import de.gdata.vaas.messages.Verdict;
import de.gdata.vaas.messages.VerdictRequest;
import de.gdata.vaas.messages.VerdictResult;
import lombok.Getter;
import lombok.NonNull;

public class Vaas {
    private final int defaultTimeout = 10;
    private final TimeUnit defaultTimeoutUnit = TimeUnit.MINUTES;

    @Getter
    @NonNull
    private final WsConfig config;

    private WsClient client;

    private HttpClient httpClient = HttpClient.newBuilder().build();

    public Vaas(WsConfig config) {
        this.config = config;
    }

    public void connect()
            throws InterruptedException, URISyntaxException, IOException, ExecutionException, TimeoutException {
        this.client = new WsClient(this.getConfig());
        this.client.connectBlocking();
        this.client.authenticate();
    }

    public void disconnect() throws InterruptedException {
        this.client.closeBlocking();
    }

    public VerdictResult forSha256(Sha256 sha256)
            throws Exception {
        return this.forSha256(sha256, defaultTimeout, defaultTimeoutUnit);
    }

    public VerdictResult forSha256(Sha256 sha256, long timeout, TimeUnit unit)
            throws Exception {
        var request = new VerdictRequest(sha256, this.client.getSessionId());
        return this.forRequest(request).get(timeout, unit);
    }

    public VerdictResult forFile(Path file) throws Exception {
        return forFile(file, defaultTimeout, defaultTimeoutUnit);
    }

    public VerdictResult forFile(Path file, long timeout, TimeUnit unit) throws Exception {
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
        return verdictResultFuture.get(timeout, unit);
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
}
