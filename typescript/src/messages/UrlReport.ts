import { JsonProperty, JsonObject } from "typescript-json-serializer";
import { Verdict } from "../Verdict";

@JsonObject()
export class UrlReport {
  public constructor(
    @JsonProperty() public sha256: string,
    @JsonProperty() public verdict: Verdict,
    @JsonProperty() public url: string,
    @JsonProperty() public detection: string | undefined,
    @JsonProperty({ name: "fileType" }) public file_type: string | undefined,
    @JsonProperty({ name: "mimeType" }) public mime_type: string | undefined,
    @JsonProperty({ name: "isEncrypted" })
    public is_encrypted: boolean | undefined,
  ) {}
}
