import { JsonProperty, JsonObject } from "typescript-json-serializer";

@JsonObject()
export class LibMagic {
  public constructor(
    @JsonProperty() public file_type: number,
    @JsonProperty() public mime_type: string,
  ) { }
}
