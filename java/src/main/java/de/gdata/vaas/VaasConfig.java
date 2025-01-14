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
    long defaultTimeoutInMs = 120000;

    public VaasConfig() throws URISyntaxException {
        this(new URI("https://gateway.production.vaas.gdatasecurity.de"));
    }

    public VaasConfig(URI url) {
        this.url = url;
    }

    public VaasConfig(long defaultTimeoutInMs) throws URISyntaxException {
        this(new URI("https://gateway.production.vaas.gdatasecurity.de"), defaultTimeoutInMs);
    }

    public VaasConfig(URI url, long defaultTimeoutInMs) {
        this.url = url;
        this.defaultTimeoutInMs = defaultTimeoutInMs;
    }
}
