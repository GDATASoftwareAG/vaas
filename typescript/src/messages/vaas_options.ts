import { JsonProperty, JsonObject } from "typescript-json-serializer";

@JsonObject()
export class VaasOptions {
  public constructor(
    @JsonProperty() public use_shed: boolean,
    @JsonProperty() public use_cache: boolean
  ) {  }
}
