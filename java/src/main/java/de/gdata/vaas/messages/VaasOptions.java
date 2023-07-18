package de.gdata.vaas.messages;

import com.beust.jcommander.internal.Nullable;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;
import lombok.Getter;
import lombok.Setter;

public class VaasOptions {

    @Getter
    @Setter
    @Nullable
    @SerializedName("use_shed")
    boolean UseShed;

    @Getter
    @Setter
    @Nullable
    @SerializedName("use_cache")
    boolean UseCache;

    public VaasOptions() {

    }
    public String toJson() {
        return new GsonBuilder().serializeNulls().create().toJson(this);
    }

}
