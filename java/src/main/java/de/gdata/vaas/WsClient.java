package de.gdata.vaas;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;

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
    @Getter
    private boolean authenticated = false;
    @Getter
    private boolean authenticationFailed = false;
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