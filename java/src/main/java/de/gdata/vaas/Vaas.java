package de.gdata.vaas;

import de.gdata.vaas.messages.Verdict;
import de.gdata.vaas.messages.VerdictRequest;
import de.gdata.vaas.messages.VerdictResponse;
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

    public VerdictResult forFile(Path file, CancellationTokenSource cts) throws Exception {
        var sha256 = new Sha256(file);
        var ct = cts.getToken();
        var verdictRequest = new VerdictRequest(sha256, this.client.getSessionId());
        var verdict = this.forRequest(verdictRequest, ct);

        if (verdict == null) {
            return null;
        } else if (verdict.getVerdict() == Verdict.UNKNOWN) {
            UploadFile(file, verdict.getUploadUrl(), verdict.getUploadToken());
            return this.waitForVerdict(verdictRequest.getGuid(), ct);
        } else {
            return verdict;
        }
    }

    private void UploadFile(Path file, String url, String authToken) throws IOException, URISyntaxException, InterruptedException {
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
            throw new IOException("Failed to upload file. HTTP Status Code: " + response.statusCode() + " Error: " + response.body());
        }
    }

    private VerdictResult forRequest(VerdictRequest verdictRequest, CancellationToken ct) throws Exception {
        // Ensure that we are authenticated, before we send the request
        if(this.client.isAuthenticated()) {
            verdictRequest.setSessionId(this.client.getSessionId());
            this.client.send(verdictRequest.toJson());
        }
        else if(this.client.isAuthenticationFailed()) {
            throw new Exception("Authentication failed");
        }
        else {
            // We are not authenticated yet, wait a short time for the AuthResponse.
            // If it does not arrive in time, we will throw an exception.
            for(int i = 0; i < 20; i++) {
                if(this.client.isAuthenticated()) {
                    verdictRequest.setSessionId(this.client.getSessionId());
                    this.client.send(verdictRequest.toJson());
                    break;
                }
                Thread.sleep(100);
            }
            if(!this.client.isAuthenticated()) {
                throw new Exception("No authentication response received");
            }
        }

        return this.waitForVerdict(verdictRequest.getGuid(), ct);
    }

    private VerdictResult waitForVerdict(String guid, CancellationToken ct) throws InterruptedException {
        VerdictResponse verdictResponse = null;

        int ping_cnt = 0;
        // Pull for a result until we get one, or are cancelled.
        while (ct.isNotCancelled()) {
            Thread.sleep(this.config.getPullDelayMs());

            // Send a ping message every 10 pull,
            // to keep the connection alive.
            if(ping_cnt == 10) {
                ping_cnt = 0;
                this.client.sendPing();
            } else {
                ping_cnt++;
            }

            if(this.client.getErrorResponses() != null){
                throw new Error(this.client.getErrorResponses().getText());
            }

            var resp = client.popResponse(guid);

            if (resp.isPresent()) {
                verdictResponse = resp.get();
                break;
            }

            if(ping_cnt == 200) {
                client.sendPing();
                ping_cnt = 0;
            }
            ping_cnt++;
        }

        if (verdictResponse == null) {
            // Cancellation case
            return null;
        } else {
            return new VerdictResult(verdictResponse);
        }
    }
}
