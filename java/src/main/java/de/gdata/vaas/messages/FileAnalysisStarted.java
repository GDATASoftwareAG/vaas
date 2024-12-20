package de.gdata.vaas.messages;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
public class FileAnalysisStarted {

    @Getter
    @SerializedName("sha256")
    String Sha256;
    public static FileAnalysisStarted fromJson(String json) {
        return new Gson().fromJson(json, FileAnalysisStarted.class);
    }
}
