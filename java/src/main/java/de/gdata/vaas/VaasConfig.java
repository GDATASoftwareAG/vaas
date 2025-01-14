package de.gdata.vaas;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import org.jetbrains.annotations.NotNull;

import java.net.URI;
import java.net.URISyntaxException;

@Setter
@Getter
public class VaasConfig {
    @NonNull
    private URI url;

    long defaultTimeoutInMs = 120000;

    public VaasConfig() throws URISyntaxException {
        this(new URI("https://gateway.production.vaas.gdatasecurity.de"));
    }

    public VaasConfig(@NotNull URI url) {
        this.url = url;
    }

    public VaasConfig(long defaultTimeoutInMs) throws URISyntaxException {
        this(new URI("https://gateway.production.vaas.gdatasecurity.de"), defaultTimeoutInMs);
    }

    public VaasConfig(@NotNull URI url, long defaultTimeoutInMs) {
        this.url = url;
        this.defaultTimeoutInMs = defaultTimeoutInMs;
    }
}
