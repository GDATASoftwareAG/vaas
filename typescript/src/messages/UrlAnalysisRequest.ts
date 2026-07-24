import { JsonProperty, JsonObject } from "typescript-json-serializer";

@JsonObject()
export class UrlAnalysisRequest {
  public constructor(
    @JsonProperty() public url: string,
    @JsonProperty({ name: "useHashLookup" }) public use_hash_lookup: boolean,
  ) {}
}
