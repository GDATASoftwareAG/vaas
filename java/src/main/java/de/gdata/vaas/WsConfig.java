package de.gdata.vaas;

import java.net.URI;
import java.net.URISyntaxException;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

public class WsConfig {

    @Getter
    private String clientID, clientSecret;

    @Getter
    @Setter
    @NonNull
    private URI url;

    @Getter
    @Setter
    @NonNull
    private URI tokenEndpoint;

    @Getter
    @Setter
    private int PullDelayMs;

    public WsConfig(String clientId, String clientSecret) throws URISyntaxException {
        this(clientId, clientSecret,
                new URI("https://keycloak-vaas.gdatasecurity.de/realms/vaas/protocol/openid-connect/token"),
                new URI("wss://gateway-vaas.gdatasecurity.de"));
    }

    public WsConfig(String clientId, String clientSecret, URI tokenEndpoint, URI url) throws URISyntaxException {
        this.clientID = clientId;
        this.clientSecret = clientSecret;
        this.tokenEndpoint = tokenEndpoint;
        this.url = url;
        this.PullDelayMs = 100;
    }
}
