package de.gdata.vaas;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

import java.net.URI;
import java.net.URISyntaxException;

public class VaasConfig {
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

    public VaasConfig() throws URISyntaxException {
        this(
                new URI("https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"),
                new URI("wss://gateway.production.vaas.gdatasecurity.de"));
    }

    public VaasConfig(URI tokenEndpoint, URI url) {
        this.tokenEndpoint = tokenEndpoint;
        this.url = url;
        this.PullDelayMs = 100;
    }
}
