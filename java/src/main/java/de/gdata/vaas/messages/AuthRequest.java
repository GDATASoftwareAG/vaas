package de.gdata.vaas.messages;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import lombok.Getter;
import lombok.NonNull;

public class AuthRequest extends MessageType {

    @Getter @NonNull public String token;
    @Getter @SerializedName("session_id") public String sessionId;

    public AuthRequest(String token) {
        super(Kind.AuthRequest);
        this.token = token;
    }

    public AuthRequest(String token, String sessionId) {
        this(token);
        this.sessionId = sessionId;
    }

    public String toJson() {
        return new Gson().toJson(this);
    }
}
