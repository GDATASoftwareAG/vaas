package de.gdata.vaas.messages;

import com.google.gson.annotations.SerializedName;
import lombok.Getter;
import lombok.Setter;

public class VaasOptions {

    @Getter
    @Setter
    @SerializedName("use_hash_lookup")
    boolean UseHashLookup;

    @Getter
    @Setter
    @SerializedName("use_cache")
    boolean UseCache;

    public VaasOptions() {
        this.UseCache = true;
        this.UseHashLookup = true;
    }
}