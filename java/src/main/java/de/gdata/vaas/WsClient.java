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
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

public class WsClient extends WebSocketClient {

    @NonNull
    private List<VerdictResponse> verdictResponses;
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
        this.verdictResponses = new LinkedList<>();
        this.token = config.getToken();
    }

    public void authenticate() {
        var authRequest = new AuthRequest(this.getToken());
        this.send(authRequest.toJson());
    }

    public Optional<VerdictResponse> popResponse(String guid) {
        var op = this.findMessage(guid);

        if (op.isPresent()) {
            this.removeMessage(guid);
            return Optional.of((VerdictResponse) op.get());
        } else {
            return Optional.empty();
        }
    }

    private void removeMessage(String guid) {
        var resp = this.findMessage(guid);
        if (resp.isPresent()) {
            this.verdictResponses.remove(resp.get());
        }
    }

    private @NotNull Optional<VerdictResponse> findMessage(String guid) {
        return this.verdictResponses
                .stream()
                .filter(m -> m.getGuid().equals(guid))
                .findFirst();
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
            this.verdictResponses.add(verdictResp);
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