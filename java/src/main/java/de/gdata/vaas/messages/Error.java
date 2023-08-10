package de.gdata.vaas.messages;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import lombok.Getter;
import lombok.NonNull;

public class Error extends MessageType {
    @Getter
    @NonNull String type;

    @Getter
    @NonNull String text;

    @Getter
    @SerializedName("request_id")
    String requestId;

    @Getter
    @SerializedName("problem_details")
    ProblemDetails problemDetails;

    private Error() {
        super(Kind.Error);
    }

    public static Error fromJson(String json) {
        return new Gson().fromJson(json, Error.class);
    }
}
