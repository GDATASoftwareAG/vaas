package de.gdata.vaas.messages;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import lombok.Getter;
import lombok.NonNull;
import java.util.ArrayList;

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
    @SerializedName("url")
    String uploadUrl;
    @Getter
    @SerializedName("upload_token")
    String uploadToken;
    @Getter
    @SerializedName("detection")
    String detection;
    @Getter
    @SerializedName("file_type")
    String fileType;
    @Getter
    @SerializedName("mime_type")
    String mimeType;

    private VerdictResponse() {
        super(Kind.VerdictResponse);
    }

    public static VerdictResponse fromJson(String json) {
        return new Gson().fromJson(json, VerdictResponse.class);
    }
}