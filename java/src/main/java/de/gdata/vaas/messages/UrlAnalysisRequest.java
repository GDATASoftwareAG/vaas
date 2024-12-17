package de.gdata.vaas.messages;

import org.jetbrains.annotations.Nullable;

import com.google.gson.Gson;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
public class UrlAnalysisRequest {
    
    @Getter
    @Setter
    String url;

    @Getter
    @Setter
    @Nullable
    boolean UseHashLookup = true;

    public static String ToJson(UrlAnalysisRequest urlAnalysisRequest) {
        return new Gson().toJson(urlAnalysisRequest);
    }    
}
