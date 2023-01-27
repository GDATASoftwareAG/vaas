package de.gdata.vaas.messages;

import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;
import de.gdata.vaas.Sha256;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

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
    @SerializedName("verdict_request_options")
    VerdictRequestOptions verdictRequestOptions;

    public VerdictRequest(Sha256 sha256, String sessionId) {
        super(Kind.VerdictRequest);
        this.sessionId = sessionId;
        this.guid = UUID.randomUUID().toString();
        this.sha256 = sha256.getValue();
    }

    public VerdictRequest(Sha256 sha256, String sessionId, VerdictRequestOptions verdictRequestOptions) {
        this(sha256, sessionId);
        this.verdictRequestOptions = verdictRequestOptions;
    }

    public String toJson() {
        return new GsonBuilder().serializeNulls().create().toJson(this);
    }
}
