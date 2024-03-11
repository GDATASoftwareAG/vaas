import { JsonProperty, JsonObject } from "typescript-json-serializer";

@JsonObject()
export class LibMagic {
  public constructor(
    @JsonProperty() public fileType: number,
    @JsonProperty() public mimeType: string,
  ) {}
}
