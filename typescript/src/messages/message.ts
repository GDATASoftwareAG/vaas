import { JsonProperty, JsonObject } from "typescript-json-serializer";

export enum Kind {
  Error = "Error",
  AuthRequest = "AuthRequest",
  AuthResponse = "AuthResponse",
  VerdictRequest = "VerdictRequest",
  VerdictResponse = "VerdictResponse",
  DetectionRequest = "DetectionRequest",
  DetectionResponse = "DetectionResponse",
  PersistedRequest = "PersistedRequest",
  SampleProcessingResponse = "SampleProcessingResponse",
  VerdictRequestForUrl = "VerdictRequestForUrl"
}

@JsonObject()
export class Message {
  @JsonProperty() public kind: Kind;
  public constructor(kind: Kind) {
    this.kind = kind;
  }
}
