package de.gdata.vaas.messages;

import com.google.gson.Gson;

import lombok.Getter;

public class FileAnalysisStarted {

    @Getter
    String Sha256;
    public static FileAnalysisStarted fromJson(String json) {
        return new Gson().fromJson(json, FileAnalysisStarted.class);
    }
}
