package de.gdata.vaas.messages;

import org.jetbrains.annotations.NotNull;

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
    @NotNull
    @SerializedName("type")
    public String type;

    @NotNull
    @SerializedName("detail")
    public String detail;

    public static ProblemDetails fromJson(String json) {
        return new Gson().fromJson(json, ProblemDetails.class);
    }
}
