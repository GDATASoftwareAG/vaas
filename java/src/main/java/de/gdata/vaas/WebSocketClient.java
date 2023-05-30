package de.gdata.vaas;

import de.gdata.vaas.exceptions.VaasAuthenticationException;
import de.gdata.vaas.exceptions.VaasConnectionClosedException;
import de.gdata.vaas.exceptions.VaasInvalidStateException;
import de.gdata.vaas.messages.Error;
import de.gdata.vaas.messages.*;
import lombok.Getter;
import lombok.NonNull;
import org.java_websocket.enums.ReadyState;
import org.java_websocket.handshake.ServerHandshake;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.util.concurrent.*;

public class WebSocketClient extends org.java_websocket.client.WebSocketClient {

    private final int AuthenticationTimeoutInS = 10;

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

    public WebSocketClient(VaasConfig config, String token) {
        super(config.getUrl());
        this.token = token;
    }

    public void EnsureIsAuthenticated() throws VaasConnectionClosedException, VaasInvalidStateException {
        if (this.getReadyState() != ReadyState.OPEN) {
            throw new VaasConnectionClosedException();
        }
        if (this.sessionId == null) {
            throw new VaasInvalidStateException("Not yet authenticated");
        }
    }

    public void Authenticate()
            throws VaasAuthenticationException, InterruptedException, ExecutionException, TimeoutException {
        var authRequest = new AuthRequest(this.getToken());
        this.send(authRequest.toJson());
        waitForAuthentication();
        if (this.sessionId == null) {
            throw new VaasAuthenticationException();
        }
    }

    private void waitForAuthentication()
            throws InterruptedException, ExecutionException, TimeoutException {
        this.authenticated.get(AuthenticationTimeoutInS, TimeUnit.SECONDS);
    }

    public CompletableFuture<VerdictResponse> waitForVerdict(String requestId) {
        var future = new CompletableFuture<VerdictResponse>();
        var previousValue = verdictResponses.putIfAbsent(requestId, future);
        if (previousValue != null) {
            return CompletableFuture.failedFuture(new Exception("requestId already exists"));
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
                this.authenticated.completeExceptionally(new VaasAuthenticationException());
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