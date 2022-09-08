package de.gdata.vaas;

import de.gdata.vaas.messages.Verdict;
import de.gdata.vaas.messages.VerdictRequest;
import de.gdata.vaas.messages.VerdictResult;
import lombok.Getter;
import lombok.NonNull;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;

public class Vaas {

    @Getter
    @NonNull
    private final WsConfig config;

    private WsClient client;

    public Vaas(WsConfig config) {
        this.config = config;
    }

    public void connect() throws InterruptedException, URISyntaxException, IOException {
        this.client = new WsClient(this.getConfig());
        this.client.connectBlocking();
        this.client.authenticate();
    }

    public void disconnect() throws InterruptedException {
        this.client.closeBlocking();
    }

    public VerdictResult forSha256(Sha256 sha256, @NotNull CancellationTokenSource cts) throws Exception {
        var request = new VerdictRequest(sha256, this.client.getSessionId());
        return this.forRequest(request, cts.getToken());
    }

    public List<VerdictResult> forSha256List(List<Sha256> sha256List, @NotNull CancellationTokenSource cts)
            throws Exception {
        return sha256List.stream().map(sha256 -> {
            try {
                return this.forSha256(sha256, cts);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).collect(Collectors.toList());
    }

    public List<VerdictResult> forFileList(List<Path> fileList, @NotNull CancellationTokenSource cts)
            throws Exception {
        return fileList.stream().map(file -> {
            try {
                return this.forFile(file, cts);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).collect(Collectors.toList());
    }

    public VerdictResult forFile(Path file, CancellationTokenSource cts) throws Exception {
        var sha256 = new Sha256(file);
        var ct = cts.getToken();
        var verdictRequest = new VerdictRequest(sha256, this.client.getSessionId());
        var verdict = this.forRequest(verdictRequest, ct);

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

        var response = HttpClient
                .newBuilder()
                .build()
                .send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IOException(
                    "Failed to upload file. HTTP Status Code: " + response.statusCode() + " Error: " + response.body());
        }
    }

    private VerdictResult forRequest(VerdictRequest verdictRequest, CancellationToken ct) throws Exception {
        // Ensure that we are authenticated, before we send the request
        if (this.client.isAuthenticationFailed()) {
            throw new Exception("Authentication failed");
        }

        if (!this.client.isAuthenticated()) {
            // We are not authenticated yet, wait a short time for the AuthResponse.
            // If it does not arrive in time, we will throw an exception.
            for (int i = 0; i < 20; i++) {
                if (this.client.isAuthenticated()) {
                    break;
                }
                // TODO: Wastes 100ms for 1st request
                Thread.sleep(100);
            }

            if (!this.client.isAuthenticated()) {
                throw new Exception("No authentication response received");
            }
        }

        var verdictResponse = this.client.waitForVerdict(verdictRequest.getGuid());

        verdictRequest.setSessionId(this.client.getSessionId());
        this.client.send(verdictRequest.toJson());

        return new VerdictResult(verdictResponse.get());
    }
}
