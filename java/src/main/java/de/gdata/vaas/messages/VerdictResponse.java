package de.gdata.vaas.messages;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import lombok.Getter;
import lombok.NonNull;

public class VerdictResponse extends MessageType {
    @Getter
    @NonNull
    String sha256;
    @Getter
    @NonNull
    @SerializedName("session_id")
    String sessionId;
    @Getter
    @NonNull
    String guid;
    @Getter
    @NonNull
    Verdict verdict;
    @Getter
    String url;
    @Getter
    @SerializedName("upload_token")
    String uploadToken;

    private VerdictResponse() {
        super(Kind.VerdictResponse);
    }

    public static VerdictResponse fromJson(String json) {
        return new Gson().fromJson(json, VerdictResponse.class);
    }
}