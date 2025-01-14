package de.gdata.vaas.messages;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
public class UrlAnalysisStarted {
    @Getter
    @SerializedName("id")
    String Id;
    public static UrlAnalysisStarted fromJson(String json) {
        return new Gson().fromJson(json, UrlAnalysisStarted.class);
    }    
}
