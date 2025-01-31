package de.gdata.vaas.options;

import de.gdata.vaas.VaasConfig;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.jetbrains.annotations.Nullable;

import java.util.UUID;

/**
 * Options for configuring forSha256 requests.
 *
 * <p>This class provides configuration options for SHA-256 processing, including
 * whether to use cache, hash lookup, and a Vaas request ID.</p>
 *
 * <p>Fields:</p>
 * <ul>
 *   <li>{@code boolean UseCache} - Indicates whether to use cache. Default is {@code true}.</li>
 *   <li>{@code boolean UseHashLookup} - Indicates whether to use hash lookup. Default is {@code true}.</li>
 *   <li>{@code String VaasRequestId} - The Vaas request ID. Default is a randomly generated UUID.</li>
 * </ul>
 */
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ForSha256Options {

    boolean UseCache = true;

    boolean UseHashLookup = true;

    @Nullable
    String VaasRequestId = UUID.randomUUID().toString();

    public static ForSha256Options fromVaasConfig(VaasConfig config) {
        return new ForSha256Options(config.isUseCache(), config.isUseHashLookup(), null);
    }
}
