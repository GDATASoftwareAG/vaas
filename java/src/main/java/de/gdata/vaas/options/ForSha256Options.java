package de.gdata.vaas.options;

import java.util.UUID;

import org.jetbrains.annotations.Nullable;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
public class ForSha256Options {

    @Setter
    @Getter
    boolean UseCache = true;

    @Setter
    @Getter
    boolean UseHashLookup = true;

    @Setter
    @Getter
    @Nullable
    String VaasRequestId = UUID.randomUUID().toString();
}
