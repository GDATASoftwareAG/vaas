package de.gdata.vaas.messages;

import com.google.gson.Gson;

import lombok.Getter;
import lombok.NonNull;

@Getter
public class UrlReport {
    @NonNull
    String sha256;
    @NonNull
    Verdict verdict;
    @NonNull
    String url;    
    String detection;
    String fileType;
    String mimeType;

    public UrlReport(@NonNull String sha256, @NonNull Verdict verdict, @NonNull String url, String detection, String fileType,
            String mimeType) {
        this.sha256 = sha256;
        this.verdict = verdict;
        this.url = url;
        this.detection = detection;
        this.fileType = fileType;
        this.mimeType = mimeType;
    }

    public static UrlReport fromJson(String json) {
        return new Gson().fromJson(json, UrlReport.class);
    }
}
