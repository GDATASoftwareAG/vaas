package de.gdata.vaas;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import de.gdata.vaas.messages.Verdict;
import de.gdata.vaas.messages.VerdictRequest;
import de.gdata.vaas.messages.VerdictResult;
import lombok.Getter;
import lombok.NonNull;

public class Vaas {

    @Getter
    @NonNull
    private final WsConfig config;

    private WsClient client;

    public Vaas(WsConfig config) {
        this.config = config;
    }

    // TODO: Custom exception or documentation
    public void connect() throws InterruptedException, URISyntaxException, IOException, ExecutionException {
        this.client = new WsClient(this.getConfig());
        this.client.connectBlocking();
        this.client.authenticate();
    }

    public void disconnect() throws InterruptedException {
        this.client.closeBlocking();
    }

    public VerdictResult forSha256(Sha256 sha256)
            throws TimeoutException, InterruptedException, ExecutionException {
        return this.forSha256(sha256, 10, TimeUnit.MINUTES);
    }

    public VerdictResult forSha256(Sha256 sha256, long timeout, TimeUnit unit)
            throws TimeoutException, InterruptedException, ExecutionException {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<VerdictResult> future = executor.submit(() -> {
            var request = new VerdictRequest(sha256, this.client.getSessionId());
            return this.forRequest(request);
        });
        return future.get(timeout, unit);
    }

    public VerdictResult forFile(Path file) throws Exception {
        var sha256 = new Sha256(file);
        var verdictRequest = new VerdictRequest(sha256, this.client.getSessionId());
        var verdict = this.forRequest(verdictRequest);

        if (verdict == null) {
            return null;
        } else if (verdict.getVerdict() == Verdict.UNKNOWN) {
            var response = this.client.waitForVerdict(verdictRequest.getGuid());

            UploadFile(file, verdict.getUploadUrl(), verdict.getUploadToken());

            // TODO: Handle timeouts and cancellation
            return new VerdictResult(response.get());
        } else {
            return verdict;
        }
    }

    private void UploadFile(Path file, String url, String authToken)
            throws IOException, URISyntaxException, InterruptedException {
        var bytes = Files.readAllBytes(file);
        var request = HttpRequest
                .newBuilder(new URI(url))
                .header("Authorization", authToken)
                .PUT(HttpRequest.BodyPublishers.ofByteArray(bytes))
                .build();

        // TODO: Timeout and cancellation
        var response = HttpClient
                .newBuilder()
                .build()
                .send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IOException(
                    "Failed to upload file. HTTP Status Code: " + response.statusCode() + " Error: " + response.body());
        }
    }

    private VerdictResult forRequest(VerdictRequest verdictRequest) throws Exception {
        var verdictResponse = this.client.waitForVerdict(verdictRequest.getGuid());

        verdictRequest.setSessionId(this.client.getSessionId());
        this.client.send(verdictRequest.toJson());

        // TODO: Timeout and cancellation
        return new VerdictResult(verdictResponse.get());
    }
}
