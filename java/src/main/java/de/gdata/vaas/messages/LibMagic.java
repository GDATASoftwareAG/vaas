package de.gdata.vaas.messages;

import com.google.gson.annotations.SerializedName;

import lombok.Getter;
import lombok.NonNull;

@Getter
public class LibMagic {
    @NonNull
    @SerializedName("file_type")
    String fileType;

    @NonNull
    @SerializedName("mime_type")
    String mimeType;
}
