package de.gdata.vaas.messages;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import org.jetbrains.annotations.Nullable;

import java.net.URL;
import java.util.UUID;

public class VerdictRequestForUrl extends MessageType {
    @Getter
    @NonNull
    String url;
    @Getter
    @Setter
    @NonNull
    @SerializedName("session_id")
    String sessionId;
    @Getter
    @NonNull
    String guid;
    @Getter
    @Setter
    @SerializedName("verdict_request_attributes")
    VerdictRequestAttributes verdictRequestAttributes;
    @Getter
    @SerializedName("use_hash_lookup")
    transient boolean UseHashLookup;
    @Getter
    @SerializedName("use_cache")
    boolean UseCache;

    public VerdictRequestForUrl(URL url, String sessionId, UUID guid) {
        super(Kind.VerdictRequestForUrl);
        this.sessionId = sessionId;
        this.guid = guid.toString();
        this.url = url.toString();
    }

    public VerdictRequestForUrl(URL url, String sessionId, UUID guid, VerdictRequestAttributes verdictRequestAttributes) {
        this(url, sessionId, guid);
        this.verdictRequestAttributes = verdictRequestAttributes;
    }

    public VerdictRequestForUrl(URL url, String sessionId, UUID guid, VaasOptions options) {
        this(url, sessionId, guid);
        this.UseCache = options.UseCache;
        this.UseHashLookup = options.UseHashLookup;
    }

    public VerdictRequestForUrl(URL url, String sessionId, UUID guid, VerdictRequestAttributes verdictRequestAttributes, VaasOptions options) {
        this(url, sessionId, guid);
        this.verdictRequestAttributes = verdictRequestAttributes;
    }


    public String toJson() {
        return new Gson().toJson(this);
    }
}
