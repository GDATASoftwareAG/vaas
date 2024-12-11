package de.gdata.vaas.messages;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

import lombok.Getter;

public class FileAnalysisStarted {

    @Getter
    @SerializedName("sha256")
    String Sha256;
    public static FileAnalysisStarted fromJson(String json) {
        return new Gson().fromJson(json, FileAnalysisStarted.class);
    }
}
