package de.gdata.vaas.options;

import org.jetbrains.annotations.Nullable;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Options for configuring forStream requests.
 * It includes options for using hash lookup and specifying a Vaas request ID.
 * 
 * <p>
 * The {@code UseHashLookup} field indicates whether hash lookup should be used.
 * The {@code VaasRequestId} field can hold a nullable string representing the Vaas request ID.
 * </p>
 */
@AllArgsConstructor
@NoArgsConstructor
public class ForStreamOptions {
    @Setter
    @Getter
    boolean UseHashLookup = true;

    @Setter
    @Getter
    @Nullable 
    String VaasRequestId;    
}
