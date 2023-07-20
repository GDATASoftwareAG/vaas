package de.gdata.vaas.messages;

import com.beust.jcommander.internal.Nullable;
import com.google.gson.annotations.SerializedName;
import lombok.Getter;
import lombok.Setter;

public class VaasOptions {

    @Getter
    @Setter
    @SerializedName("use_shed")
    boolean UseShed;

    @Getter
    @Setter
    @SerializedName("use_cache")
    boolean UseCache;

    public VaasOptions() {
        this.UseCache = false;
        this.UseShed = true;
    }
}
