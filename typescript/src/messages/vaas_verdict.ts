import { JsonProperty, JsonObject } from "typescript-json-serializer";
import { Verdict } from "../Verdict";

@JsonObject()
export class VaasVerdict {
  public constructor(
    @JsonProperty() public sha256: string,
    @JsonProperty() public verdict: Verdict
  ) {  }
}
