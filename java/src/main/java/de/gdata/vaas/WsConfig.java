package de.gdata.vaas;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

import java.net.URI;
import java.net.URISyntaxException;

public class WsConfig {
    @Getter @NonNull
    private String token;

    @Getter @Setter @NonNull
    private URI url;

    @Getter @Setter
    private int PullDelayMs;

    public WsConfig(String token) throws URISyntaxException {
        this.token = token;
        this.url = new URI("wss://gateway-vaas.gdatasecurity.de");
        this.PullDelayMs = 100;
    }
}
