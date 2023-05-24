package de.gdata.vaas.messages;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.UUID;

public class VerdictRequestForUrl extends MessageType {
    @Getter
    @NonNull
    String url;
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
    VerdictRequestAttributes verdictRequestAttributes;

    public VerdictRequestForUrl(URL url, String sessionId) throws MalformedURLException {
        super(Kind.VerdictRequestForUrl);
        this.sessionId = sessionId;
        this.guid = UUID.randomUUID().toString();
        this.url = url.toString();
    }

    public VerdictRequestForUrl(URL url, String sessionId, VerdictRequestAttributes verdictRequestAttributes)
            throws MalformedURLException {
        this(url, sessionId);
        this.verdictRequestAttributes = verdictRequestAttributes;
    }

    public String toJson() {
        return new Gson().toJson(this);
    }
}
