package de.gdata.vaas;

import lombok.Getter;
import lombok.Setter;

import java.net.URI;

@Setter
@Getter
public class VaasConfig {
    long defaultTimeoutInMs = 300000;
    boolean useCache = true;
    boolean useHashLookup = true;
    private URI url = URI.create("https://gateway.production.vaas.gdatasecurity.de");

    public VaasConfig() {
    }

    public VaasConfig(long defaultTimeoutInMs) {
        this.defaultTimeoutInMs = defaultTimeoutInMs;
    }

    public VaasConfig(boolean useCache, boolean useHashLookup) {
        this.useCache = useCache;
        this.useHashLookup = useHashLookup;
    }

    public VaasConfig(URI url) {
        this.url = url;
    }

    public VaasConfig(long defaultTimeoutInMs, boolean useCache, boolean useHashLookup) {
        this.defaultTimeoutInMs = defaultTimeoutInMs;
        this.useCache = useCache;
        this.useHashLookup = useHashLookup;
    }

    public VaasConfig(long defaultTimeoutInMs, URI url) {
        this.defaultTimeoutInMs = defaultTimeoutInMs;
        this.url = url;
    }

    public VaasConfig(boolean useCache, boolean useHashLookup, URI url) {
        this.useCache = useCache;
        this.useHashLookup = useHashLookup;
        this.url = url;
    }

    public VaasConfig(long defaultTimeoutInMs, boolean useCache, boolean useHashLookup, URI url) {
        this.defaultTimeoutInMs = defaultTimeoutInMs;
        this.useCache = useCache;
        this.useHashLookup = useHashLookup;
        this.url = url;
    }
}
