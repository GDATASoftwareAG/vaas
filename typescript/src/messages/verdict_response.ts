import { Serializable, JsonProperty } from "typescript-json-serializer";
import { Kind, Message } from "./message";
import { Verdict } from "../verdict";

@Serializable()
export class VerdictResponse extends Message {
  public constructor(
    @JsonProperty() public sha256: string,
    @JsonProperty() public guid: string,
    @JsonProperty() public verdict: Verdict,
    @JsonProperty() public upload_token: string | undefined,
    @JsonProperty() public url: string | undefined
  ) {
    super(Kind.VerdictResponse);
  }
}
