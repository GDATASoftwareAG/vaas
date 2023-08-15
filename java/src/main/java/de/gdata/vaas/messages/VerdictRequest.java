package de.gdata.vaas.messages;

import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;
import de.gdata.vaas.Sha256;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import org.jetbrains.annotations.Nullable;

import java.util.UUID;

public class VerdictRequest extends MessageType {
    @Getter
    @NonNull
    String sha256;
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

    public VerdictRequest(Sha256 sha256, String sessionId) {
        super(Kind.VerdictRequest);
        this.sessionId = sessionId;
        this.guid = UUID.randomUUID().toString();
        this.sha256 = sha256.getValue();
    }

    public VerdictRequest(Sha256 sha256, String sessionId, UUID guid) {
        super(Kind.VerdictRequest);
        this.sessionId = sessionId;
        this.guid = guid.toString();
        this.sha256 = sha256.getValue();
    }

    public VerdictRequest(Sha256 sha256, String sessionId, VerdictRequestAttributes verdictRequestAttributes) {
        this(sha256, sessionId);
        this.verdictRequestAttributes = verdictRequestAttributes;
    }

    public VerdictRequest(Sha256 sha256, String sessionId, VaasOptions options) {
        this(sha256, sessionId);
        this.UseCache = options.UseCache;
        this.UseHashLookup = options.UseHashLookup;
    }

    public VerdictRequest(Sha256 sha256, String sessionId, UUID guid, VerdictRequestAttributes verdictRequestAttributes) {
        this(sha256, sessionId, guid);
        this.verdictRequestAttributes = verdictRequestAttributes;
    }

    public VerdictRequest(Sha256 sha256, String sessionId, UUID guid, VaasOptions options) {
        this(sha256, sessionId, guid);
        this.UseCache = options.UseCache;
        this.UseHashLookup = options.UseHashLookup;
    }

    public VerdictRequest(Sha256 sha256, String sessionId, UUID guid, VerdictRequestAttributes verdictRequestAttributes, VaasOptions options) {
        this(sha256, sessionId, guid, options);
        this.verdictRequestAttributes = verdictRequestAttributes;
    }

    public String toJson() {
        return new GsonBuilder().serializeNulls().create().toJson(this);
    }
}