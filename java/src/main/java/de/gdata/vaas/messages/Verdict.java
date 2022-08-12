package de.gdata.vaas.messages;

import com.google.gson.annotations.SerializedName;

public enum Verdict {
    @SerializedName("Unknown")
    UNKNOWN,
    @SerializedName("Clean")
    CLEAN,
    @SerializedName("Malicious")
    MALICIOUS,
    @SerializedName("Pup")
    PUP
}
