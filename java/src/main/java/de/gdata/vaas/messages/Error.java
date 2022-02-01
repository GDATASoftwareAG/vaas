package de.gdata.vaas.messages;

import com.google.gson.Gson;
import lombok.Getter;
import lombok.NonNull;

public class Error extends MessageType {
    @Getter
    @NonNull String type;
    @Getter
    @NonNull String text;
    private Error() {
        super(Kind.Error);
    }

    public static Error fromJson(String json) {
        return new Gson().fromJson(json, Error.class);
    }
}
