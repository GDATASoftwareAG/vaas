package de.gdata.vaas.options;

import de.gdata.vaas.VaasConfig;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.jetbrains.annotations.Nullable;

/**
 * Options for configuring forFile requests.
 *
 * <p>This class provides configuration options for file processing, including
 * whether to use cache, hash lookup, and an optional VaaS request ID.</p>
 *
 * <p>Fields:</p>
 * <ul>
 *   <li>{@code boolean UseCache} - Indicates whether to use cache. Default is {@code true}.</li>
 *   <li>{@code boolean UseHashLookup} - Indicates whether to use hash lookup. Default is {@code true}.</li>
 *   <li>{@code String VaasRequestId} - Optional VaaS request ID. Can be {@code null}.</li>
 * </ul>
 */
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ForFileOptions {

    boolean UseCache = true;

    boolean UseHashLookup = true;

    @Nullable
    String VaasRequestId;

    public static ForFileOptions fromVaaSConfig(VaasConfig config) {
        return new ForFileOptions(config.isUseCache(), config.isUseHashLookup(), null);
    }
}
