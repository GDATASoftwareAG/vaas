package de.gdata.vaas.messages;

import com.google.gson.Gson;

import lombok.Getter;

public class UrlAnalysisStarted {
    @Getter
    String Id;
    public static UrlAnalysisStarted fromJson(String json) {
        return new Gson().fromJson(json, UrlAnalysisStarted.class);
    }    
}
