package de.gdata.vaas.messages;

import com.google.gson.annotations.SerializedName;
import lombok.Getter;

@Getter
public class ProblemDetails
{
    @SerializedName("type")
    public String type;

    @SerializedName("detail")
    public String detail;
}
