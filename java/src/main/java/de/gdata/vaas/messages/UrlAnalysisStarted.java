package de.gdata.vaas.messages;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

import lombok.Getter;

public class UrlAnalysisStarted {
    @Getter
    @SerializedName("id")
    String Id;
    public static UrlAnalysisStarted fromJson(String json) {
        return new Gson().fromJson(json, UrlAnalysisStarted.class);
    }    
}
