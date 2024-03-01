package de.gdata.vaas;

import de.gdata.vaas.exceptions.*;
import de.gdata.vaas.messages.Error;
import de.gdata.vaas.messages.*;
import lombok.Getter;
import lombok.NonNull;
import org.java_websocket.enums.ReadyState;
import org.java_websocket.exceptions.WebsocketNotConnectedException;
import org.java_websocket.handshake.ServerHandshake;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;

public class WebSocketClient extends org.java_websocket.client.WebSocketClient {

    private final Map<String, CompletableFuture<VerdictResponse>> verdictResponses = new HashMap<>();

    @Getter
    private Error errorResponses = null;

    @Getter
    @NonNull
    private String token;

    private final CompletableFuture<Void> authenticated = new CompletableFuture<Void>();

    @Getter
    private String sessionId = null;

    private Thread pingThread;

    private void pingThread() {
        try {
            while (true) {
                Thread.sleep(20000);
                try {
                    this.sendPing();
                } catch (WebsocketNotConnectedException ignored) {
                }
            }
        } catch (InterruptedException ignored) {
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

    public void Authenticate(long timeout, TimeUnit timeUnit)
            throws VaasAuthenticationException, InterruptedException, ExecutionException, TimeoutException,
            WebsocketNotConnectedException {
        var authRequest = new AuthRequest(this.getToken());
        this.send(authRequest.toJson());
        waitForAuthentication(timeout, timeUnit);
        if (this.sessionId == null) {
            throw new VaasAuthenticationException();
        }
    }

    private void waitForAuthentication(long timeout, TimeUnit timeUnit)
            throws InterruptedException, ExecutionException, TimeoutException {
        this.authenticated.get(timeout, timeUnit);
    }

    public CompletableFuture<VerdictResponse> waitForVerdict(String requestId) {
        var future = new CompletableFuture<VerdictResponse>();
        synchronized (verdictResponses) {
            var previousValue = verdictResponses.putIfAbsent(requestId, future);
            if (previousValue != null) {
                return CompletableFuture.failedFuture(new Exception("requestId already exists"));
            }
        }
        return future;
    }

    private void completeVerdict(String requestId, VerdictResponse response) {
        CompletableFuture<VerdictResponse> verdictResponse;
        synchronized (verdictResponses) {
            verdictResponse = verdictResponses.remove(requestId);
        }
        if (verdictResponse == null) {
            // Error: Server sent guid we are not waiting for, ignore it
            return;
        }
        verdictResponse.complete(response);
    }

    private void completeRequestResponseExceptionally(String requestId, Error error) {
        CompletableFuture<VerdictResponse> verdictResponse;
        synchronized (verdictResponses) {
            verdictResponse = verdictResponses.remove(requestId);
        }
        if (verdictResponse == null) {
            // Error: Server sent guid we are not waiting for, ignore it
            return;
        }
        var problemDetails = error.getProblemDetails();
        var detail = problemDetails != null ? problemDetails.getDetail() : null;
        if (error.getType().equals("ClientError")) {
            verdictResponse.completeExceptionally(new VaasClientException(detail));
        } else {
            verdictResponse.completeExceptionally(new VaasServerException(detail));
        }
    }

    @Override
    public void onOpen(ServerHandshake handshakeData) {
        pingThread = new Thread(this::pingThread);
        this.pingThread.start();
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
        synchronized (verdictResponses) {
            var responses = new ArrayList<>(verdictResponses.values());
            verdictResponses.clear();
            for (CompletableFuture<VerdictResponse> response : responses) {
                response.completeExceptionally(new VaasConnectionClosedException());
            }
        }

        if (this.pingThread != null) {
            this.pingThread.interrupt();
            try {
                this.pingThread.join();
            } catch (InterruptedException ignored) {
            }
        }
    }

    @Override
    public void onMessage(String message) {

        var msg = MessageType.fromJson(message);

        switch (msg.getKind()) {
            case AuthResponse:
                var authResp = AuthResponse.fromJson(message);
                if (authResp.isSuccess()) {
                    this.sessionId = authResp.getSessionId();
                    this.authenticated.complete(null);
                } else {
                    this.authenticated.completeExceptionally(new VaasAuthenticationException());
                }
                break;
            case VerdictResponse:
                var verdictResp = VerdictResponse.fromJson(message);
                completeVerdict(verdictResp.getGuid(), verdictResp);
                break;
            case Error:
                var error = Error.fromJson(message);
                this.errorResponses = error;
                var requestId = error.getRequestId();
                if (requestId != null) {
                    completeRequestResponseExceptionally(requestId, error);
                }
                break;
            default:
                break;
        }
    }

    @Override
    public void onMessage(ByteBuffer message) {
    }

    @Override
    public void onError(Exception ex) {
        throw new RuntimeException(ex);
    }
}