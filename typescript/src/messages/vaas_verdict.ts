import { JsonProperty, JsonObject } from "typescript-json-serializer";
import { Verdict } from "../Verdict";

@JsonObject()
export class VaasVerdict {
  public constructor(
    @JsonProperty() public sha256: string,
    @JsonProperty() public verdict: Verdict,
    @JsonProperty() public detection: string | undefined,
    @JsonProperty() public file_type: string | undefined,
    @JsonProperty() public mime_type: string | undefined,      
  ) {}
}
