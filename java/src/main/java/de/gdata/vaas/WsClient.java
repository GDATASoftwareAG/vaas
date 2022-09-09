package de.gdata.vaas;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;

import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

import de.gdata.vaas.messages.AuthRequest;
import de.gdata.vaas.messages.AuthResponse;
import de.gdata.vaas.messages.Error;
import de.gdata.vaas.messages.Kind;
import de.gdata.vaas.messages.MessageType;
import de.gdata.vaas.messages.VerdictResponse;
import lombok.Getter;
import lombok.NonNull;

public class WsClient extends WebSocketClient {

    private ConcurrentHashMap<String, CompletableFuture<VerdictResponse>> verdictResponses = new ConcurrentHashMap<String, CompletableFuture<VerdictResponse>>();

    @Getter
    private Error errorResponses = null;

    @Getter
    @NonNull
    private String token;

    private CompletableFuture<Void> authenticated = new CompletableFuture<Void>();

    @Getter
    private String sessionId = null;

    private Thread pingThread;

    private void pingThread() {
        try {
            while (true) {
                Thread.sleep(20000);
                this.sendPing();
            }
        } catch (InterruptedException e) {
        }
    }

    public WsClient(WsConfig config) throws URISyntaxException, IOException, InterruptedException {
        super(config.getUrl());
        this.token = config.getToken();
    }

    public void authenticate() throws InterruptedException, ExecutionException {
        var authRequest = new AuthRequest(this.getToken());
        this.send(authRequest.toJson());
        waitForAuthentication();
    }

    private void waitForAuthentication() throws InterruptedException, ExecutionException {
        // TODO: Test authentication error
        this.authenticated.get();
        // TODO: Timeout
        // throw new Exception("No authentication response received");
    }

    public CompletableFuture<VerdictResponse> waitForVerdict(String requestId) throws Exception {
        var future = new CompletableFuture<VerdictResponse>();
        var previousValue = verdictResponses.putIfAbsent(requestId, future);
        if (previousValue != null) {
            throw new Exception("requestId already exists");
        }
        return future;
    }

    private void completeVerdict(String requestId, VerdictResponse response) {
        var verdictResponse = verdictResponses.remove(requestId);
        if (verdictResponse == null) {
            // Error: Server sent guid we are not waiting for, ignore it
            return;
        }
        verdictResponse.complete(response);
    }

    @Override
    public void onOpen(ServerHandshake handshakeData) {
        pingThread = new Thread(() -> pingThread());
        this.pingThread.start();
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
        this.pingThread.interrupt();
        try {
            this.pingThread.join();
        } catch (InterruptedException e) {
        }
    }

    @Override
    public void onMessage(String message) {

        var msg = MessageType.fromJson(message);

        if (msg.getKind() == Kind.AuthResponse) {
            var authResp = AuthResponse.fromJson(message);
            if (authResp.isSuccess()) {
                this.sessionId = authResp.getSessionId();
                this.authenticated.complete(null);
            } else {
                // TODO:
                this.authenticated.completeExceptionally(new Exception("Authentication failed"));
            }
        } else if (msg.getKind() == Kind.VerdictResponse) {
            var verdictResp = VerdictResponse.fromJson(message);
            completeVerdict(verdictResp.getGuid(), verdictResp);
        } else if (msg.getKind() == Kind.Error) {
            var error = Error.fromJson(message);
            this.errorResponses = error;
        } else {
            throw new IllegalArgumentException("Unknown message type");
        }
    }

    @Override
    public void onMessage(ByteBuffer message) {
    }

    @Override
    public void onError(Exception ex) {
        System.out.println(ex);
        throw new RuntimeException(ex);
    }
}