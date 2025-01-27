package de.gdata.vaas;

import lombok.Getter;
import lombok.Setter;

import java.net.URI;
import java.net.URISyntaxException;

@Setter
@Getter
public class VaasConfig {
    long defaultTimeoutInMs = 300000;
    boolean useCache = true;
    boolean useHashLookup = true;
    private URI url = new URI("https://gateway.production.vaas.gdatasecurity.de");

    public VaasConfig() throws URISyntaxException {
    }

    public VaasConfig(long defaultTimeoutInMs) throws URISyntaxException {
        this.defaultTimeoutInMs = defaultTimeoutInMs;
    }

    public VaasConfig(boolean useCache, boolean useHashLookup) throws URISyntaxException {
        this.useCache = useCache;
        this.useHashLookup = useHashLookup;
    }

    public VaasConfig(URI url) throws URISyntaxException {
        this.url = url;
    }

    public VaasConfig(long defaultTimeoutInMs, boolean useCache, boolean useHashLookup) throws URISyntaxException {
        this.defaultTimeoutInMs = defaultTimeoutInMs;
        this.useCache = useCache;
        this.useHashLookup = useHashLookup;
    }

    public VaasConfig(long defaultTimeoutInMs, URI url) throws URISyntaxException {
        this.defaultTimeoutInMs = defaultTimeoutInMs;
        this.url = url;
    }

    public VaasConfig(boolean useCache, boolean useHashLookup, URI url) throws URISyntaxException {
        this.useCache = useCache;
        this.useHashLookup = useHashLookup;
        this.url = url;
    }

    public VaasConfig(long defaultTimeoutInMs, boolean useCache, boolean useHashLookup, URI url) throws URISyntaxException {
        this.defaultTimeoutInMs = defaultTimeoutInMs;
        this.useCache = useCache;
        this.useHashLookup = useHashLookup;
        this.url = url;
    }
}
