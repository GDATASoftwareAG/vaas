package de.gdata.vaas.messages;

import lombok.Getter;
import lombok.NonNull;

@Getter
public class LibMagic {
    @NonNull
    String fileType;
    
    @NonNull
    String mimeType;
}
