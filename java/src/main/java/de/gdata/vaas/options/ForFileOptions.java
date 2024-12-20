package de.gdata.vaas.options;

import org.jetbrains.annotations.Nullable;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
public class ForFileOptions {
    
    @Setter
    @Getter
    boolean UseCache = true;

    @Setter
    @Getter
    boolean UseHashLookup = true;

    @Setter
    @Getter
    @Nullable 
    String VaasRequestId;
}
