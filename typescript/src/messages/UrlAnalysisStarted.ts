import { JsonProperty, JsonObject } from "typescript-json-serializer";

@JsonObject()
export class UrlAnalysisStarted {
  public constructor(@JsonProperty() public id: string) {}
}
