package de.gdata.vaas.messages;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;
import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.Nullable;

public class VerdictRequestAttributes {
  @Getter
  @Setter
  @Nullable
  @SerializedName("tenantId")
  String tenantId;

  public VerdictRequestAttributes() {
  }

  public String toJson() {
    return new GsonBuilder().serializeNulls().create().toJson(this);
  }

  public static MessageType fromJson(String json) {
    return new Gson().fromJson(json, MessageType.class);
  }
}