package de.gdata.vaas.messages;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import lombok.Getter;
import lombok.NonNull;

public class AuthResponse extends MessageType {
    @Getter
    @NonNull
    public String text;
    @Getter
    @SerializedName("session_id")
    public String sessionId;
    @Getter boolean success;

    private AuthResponse() {
        super(Kind.AuthResponse);
    }

    public static AuthResponse fromJson(String json) {
        return new Gson().fromJson(json, AuthResponse.class);
    }
}
