package de.gdata.vaas.messages;

import com.google.gson.annotations.SerializedName;
import lombok.Getter;
import lombok.Setter;

public class VerdictRequestAttributes {
  @Getter
  @Setter
  @SerializedName("tenantId")
  String tenantId;
}