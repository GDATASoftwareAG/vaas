package de.gdata.vaas.messages;

import com.google.gson.annotations.SerializedName;

import lombok.Getter;
import lombok.NonNull;

@Getter
public class Detection {
    int engine;

    @NonNull
    @SerializedName("file_name")
    String fileName;

    @NonNull
    String virus;
}
