package de.gdata.vaas.messages;

import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import org.jetbrains.annotations.Nullable;

import java.util.UUID;

public class VerdictRequestForStream extends MessageType {
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
    @Setter
    @Nullable
    @SerializedName("use_hash_lookup")
    boolean UseHashLookup;
    @Getter
    @Setter
    @Nullable
    @SerializedName("use_cache")
    boolean UseCache;

    public VerdictRequestForStream(String sessionId) {
        super(Kind.VerdictRequestForStream);
        this.sessionId = sessionId;
        this.guid = UUID.randomUUID().toString();
    }

    public VerdictRequestForStream(String sessionId, UUID guid) {
        super(Kind.VerdictRequestForStream);
        this.sessionId = sessionId;
        this.guid = guid.toString();
    }

    public VerdictRequestForStream(String sessionId, VerdictRequestAttributes verdictRequestAttributes) {
        this(sessionId);
        this.verdictRequestAttributes = verdictRequestAttributes;
    }

    public VerdictRequestForStream(String sessionId, VaasOptions options) {
        this(sessionId);
        this.UseCache = options.UseCache;
        this.UseHashLookup = options.UseHashLookup;
    }

    public VerdictRequestForStream(String sessionId, UUID guid, VerdictRequestAttributes verdictRequestAttributes) {
        this(sessionId, guid);
        this.verdictRequestAttributes = verdictRequestAttributes;
    }

    public VerdictRequestForStream(String sessionId, UUID guid, VaasOptions options) {
        this(sessionId, guid);
        this.UseCache = options.UseCache;
        this.UseHashLookup = options.UseHashLookup;
    }

    public VerdictRequestForStream(String sessionId, UUID guid, VerdictRequestAttributes verdictRequestAttributes, VaasOptions options) {
        this(sessionId, guid, options);
        this.verdictRequestAttributes = verdictRequestAttributes;
    }

    public String toJson() {
        return new GsonBuilder().serializeNulls().create().toJson(this);
    }
}