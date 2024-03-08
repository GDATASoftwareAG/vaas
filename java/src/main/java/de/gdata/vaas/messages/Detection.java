package de.gdata.vaas.messages;

import lombok.Getter;
import lombok.NonNull;

@Getter
public class Detection {
    int engine;

    @NonNull
    String fileName;
    
    @NonNull
    String virus;
}
