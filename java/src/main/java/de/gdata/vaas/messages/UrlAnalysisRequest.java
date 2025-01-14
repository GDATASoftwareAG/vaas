package de.gdata.vaas.messages;

import com.google.gson.Gson;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class UrlAnalysisRequest {
    
    String url;

    boolean UseHashLookup = true;

    public static String ToJson(UrlAnalysisRequest urlAnalysisRequest) {
        return new Gson().toJson(urlAnalysisRequest);
    }    
}
