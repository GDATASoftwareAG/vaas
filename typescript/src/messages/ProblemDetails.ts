import { JsonProperty, JsonObject } from "typescript-json-serializer";

@JsonObject()
export class ProblemDetails {
  public constructor(
    @JsonProperty() public type: string,
    @JsonProperty() public detail: string,
  ) {}
}
