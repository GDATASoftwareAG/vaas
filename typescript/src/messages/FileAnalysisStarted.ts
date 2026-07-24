import { JsonProperty, JsonObject } from "typescript-json-serializer";

@JsonObject()
export class FileAnalysisStarted {
  public constructor(@JsonProperty() public sha256: string) {}
}
