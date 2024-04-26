import { JsonProperty, JsonObject } from "typescript-json-serializer";
import { Kind, Message } from "./message";
import { Verdict } from "../Verdict";

@JsonObject()
export class VerdictResponse extends Message {
  public constructor(
    @JsonProperty() public sha256: string,
    @JsonProperty() public guid: string,
    @JsonProperty() public verdict: Verdict,
    @JsonProperty() public upload_token: string | undefined,
    @JsonProperty() public url: string | undefined,
    @JsonProperty() public detection: string | undefined,
    @JsonProperty() public file_type: string | undefined,
    @JsonProperty() public mime_type: string | undefined,
  ) {
    super(Kind.VerdictResponse);
  }
}
