package de.gdata.vaas.options;

import de.gdata.vaas.VaasConfig;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.jetbrains.annotations.Nullable;

/**
 * <p>Options for configuring forUrl requests.
 * It includes options for using hash lookup and specifying a VaaS request ID.</p>
 *
 *
 * Fields:
 * <ul>
 *   <li>{@code UseHashLookup} - A boolean flag indicating whether to use hash lookup. Default is {@code true}.</li>
 *   <li>{@code VaasRequestId} - An optional string representing the VaaS request ID.</li>
 * </ul>
 */
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ForUrlOptions {
    boolean UseHashLookup = true;

    @Nullable
    String VaasRequestId;

    public static ForUrlOptions fromVaasConfig(VaasConfig config) {
        return new ForUrlOptions(config.isUseHashLookup(), null);
    }
}
