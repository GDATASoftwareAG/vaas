package de.gdata.vaas.messages;

import com.google.gson.Gson;
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

    public VerdictRequest(Sha256 sha256, String sessionId) {
        super(Kind.VerdictRequest);
        this.sessionId = sessionId;
        this.guid = UUID.randomUUID().toString();
        this.sha256 = sha256.getValue();
    }

    public String toJson() {
        return new Gson().toJson(this);
    }
}
