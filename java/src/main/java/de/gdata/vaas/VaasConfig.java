package de.gdata.vaas;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;

public class VaasConfig {
    @Getter
    @Setter
    @NonNull
    private URI url;

    @Getter
    @Setter
    private int PullDelayMs;

    @Getter
    @Setter
    Duration defaultTimeout = Duration.ofMinutes(10);

    public VaasConfig() throws URISyntaxException {
        this(
                new URI("wss://gateway.production.vaas.gdatasecurity.de"));
    }

    public VaasConfig(URI url) {
        this.url = url;
        this.PullDelayMs = 100;
    }

    public VaasConfig(URI url, Duration timeout) {
        this.url = url;
        this.defaultTimeout = timeout;
    }
}
