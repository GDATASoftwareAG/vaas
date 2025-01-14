package de.gdata.vaas.messages;

import org.jetbrains.annotations.Nullable;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ProblemDetails
{
    @Nullable
    @SerializedName("type")
    public String type;

    @Nullable
    @SerializedName("detail")
    public String detail;

    public static ProblemDetails fromJson(String json) {
        return new Gson().fromJson(json, ProblemDetails.class);
    }
}
