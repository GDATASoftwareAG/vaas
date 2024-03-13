import { JsonProperty, JsonObject } from "typescript-json-serializer";

@JsonObject()
export class Detection {
  public constructor(
    @JsonProperty() public engine: number,
    @JsonProperty() public file_name: string,
    @JsonProperty() public virus: string,
  ) { }
}
