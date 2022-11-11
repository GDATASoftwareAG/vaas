package de.gdata.vaas.messages;

import com.google.gson.annotations.SerializedName;

public enum Kind {
    @SerializedName("VerdictRequest")
    VerdictRequest,
    @SerializedName("VerdictResponse")
    VerdictResponse,
    @SerializedName("AuthRequest")
    AuthRequest,
    @SerializedName("AuthResponse")
    AuthResponse,
    @SerializedName("Error")
    Error,
    @SerializedName("VerdictRequestForUrl")
    VerdictRequestForUrl
}    
