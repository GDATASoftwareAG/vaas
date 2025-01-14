package de.gdata.vaas.options;

import org.jetbrains.annotations.Nullable;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Options for configuring forUrl requests.
 * It includes options for using hash lookup and specifying a VaaS request ID.
 * 
 * <p>
 * Fields:
 * <ul>
 *   <li>{@code UseHashLookup} - A boolean flag indicating whether to use hash lookup. Default is {@code true}.</li>
 *   <li>{@code VaasRequestId} - An optional string representing the VaaS request ID.</li>
 * </ul>
 * </p>
 * 
 */
@AllArgsConstructor
@NoArgsConstructor
public class ForUrlOptions {
    @Setter
    @Getter
    boolean UseHashLookup = true;

    @Setter
    @Getter
    @Nullable 
    String VaasRequestId;    
}
