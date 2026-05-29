package de.gdata.vaas.messages;

import com.google.gson.Gson;

import lombok.Getter;
import lombok.NonNull;

@Getter
public class FileReport {
    @NonNull
    String sha256;
    @NonNull
    Verdict verdict;
    String detection;
    String fileType;
    String mimeType;
    Boolean isEncrypted;

    public FileReport(@NonNull String sha256, @NonNull Verdict verdict, String detection, String fileType,
            String mimeType, Boolean isEncrypted) {
        this.sha256 = sha256;
        this.verdict = verdict;
        this.detection = detection;
        this.fileType = fileType;
        this.mimeType = mimeType;
        this.isEncrypted = isEncrypted;
    }

    public static FileReport fromJson(String json) {
        return new Gson().fromJson(json, FileReport.class);
    }
}
