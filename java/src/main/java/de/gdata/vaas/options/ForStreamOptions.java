package de.gdata.vaas.options;

import de.gdata.vaas.VaasConfig;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.jetbrains.annotations.Nullable;

/**
 * Options for configuring forStream requests.
 * It includes options for using hash lookup and specifying a Vaas request ID.
 *
 * <p>
 * The {@code UseHashLookup} field indicates whether hash lookup should be used.
 * The {@code VaasRequestId} field can hold a nullable string representing the Vaas request ID.
 * </p>
 */
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ForStreamOptions {
    boolean UseHashLookup = true;

    @Nullable
    String VaasRequestId;

    public static ForStreamOptions fromVaasConfig(VaasConfig config) {
        return new ForStreamOptions(config.isUseHashLookup(), null);
    }
}
