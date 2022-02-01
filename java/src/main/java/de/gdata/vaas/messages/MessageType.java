package de.gdata.vaas.messages;

import com.google.gson.Gson;
import lombok.Getter;
import lombok.NonNull;

public class MessageType {
    @Getter @NonNull
    public Kind kind;

    public MessageType(Kind kind) {
        this.kind = kind;
    }

    public static MessageType fromJson(String json) {
        return new Gson().fromJson(json, MessageType.class);
    }
}
