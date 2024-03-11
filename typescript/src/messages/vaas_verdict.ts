import { JsonProperty, JsonObject } from "typescript-json-serializer";
import { Verdict } from "../Verdict";
import { Detection } from "./detection";
import { LibMagic } from "./lib_magic";

@JsonObject()
export class VaasVerdict {
  public constructor(
    @JsonProperty() public sha256: string,
    @JsonProperty() public verdict: Verdict,
    @JsonProperty() public detections: Detection[] | undefined,
    @JsonProperty() public libMagic: LibMagic | undefined,        
  ) {}
}
