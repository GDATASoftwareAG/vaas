import { JsonProperty, JsonObject } from "typescript-json-serializer";

@JsonObject()
export class Detection {
  public constructor(
    @JsonProperty() public engine: number,
    @JsonProperty() public fileName: string,
    @JsonProperty() public virus: string,
  ) {}
}
