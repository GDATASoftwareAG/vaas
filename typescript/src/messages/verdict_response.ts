import { JsonProperty, JsonObject } from "typescript-json-serializer";
import { Kind, Message } from "./message";
import { Verdict } from "../Verdict";
import { Detection } from "./detection";
import { LibMagic } from "./lib_magic";

@JsonObject()
export class VerdictResponse extends Message {
  public constructor(
    @JsonProperty() public sha256: string,
    @JsonProperty() public guid: string,
    @JsonProperty() public verdict: Verdict,
    @JsonProperty() public upload_token: string | undefined,
    @JsonProperty() public url: string | undefined,
    @JsonProperty() public detections: Detection[] | undefined,
    @JsonProperty() public libMagic: LibMagic | undefined,    
  ) {
    super(Kind.VerdictResponse);
  }
}
