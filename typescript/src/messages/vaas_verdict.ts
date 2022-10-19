import { Serializable, JsonProperty } from "typescript-json-serializer";
import { Verdict } from "../Verdict";

@Serializable()
export class VaasVerdict {
  public constructor(
    @JsonProperty() public sha256: string,
    @JsonProperty() public verdict: Verdict
  ) {  }
}
