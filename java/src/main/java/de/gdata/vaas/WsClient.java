package de.gdata.vaas;

import de.gdata.vaas.messages.Error;
import de.gdata.vaas.messages.*;
import lombok.Getter;
import lombok.NonNull;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;

public class WsClient extends WebSocketClient {

    private ConcurrentHashMap<String, CompletableFuture<VerdictResponse>> verdictResponses = new ConcurrentHashMap<String, CompletableFuture<VerdictResponse>>();

    @Getter
    private Error errorResponses = null;
    @Getter
    @NonNull
    private String token;
    @Getter
    private boolean authenticated = false;
    @Getter
    private boolean authenticationFailed = false;
    @Getter
    private String sessionId = null;

    public WsClient(WsConfig config) throws URISyntaxException, IOException, InterruptedException {
        super(config.getUrl());
        this.token = config.getToken();
    }

    public void authenticate() {
        var authRequest = new AuthRequest(this.getToken());
        this.send(authRequest.toJson());
    }

    public Future<VerdictResponse> waitForVerdict(String requestId) {
        var future = new CompletableFuture<VerdictResponse>();
        // TODO: What happens if the requestId already exists?
        verdictResponses.put(requestId, future);
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
        this.sendPing();
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
    }

    @Override
    public void onMessage(String message) {

        var msg = MessageType.fromJson(message);

        if (msg.getKind() == Kind.AuthResponse) {
            var authResp = AuthResponse.fromJson(message);
            if (authResp.isSuccess()) {
                this.authenticated = true;
                this.sessionId = authResp.getSessionId();
            } else {
                this.authenticationFailed = true;
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