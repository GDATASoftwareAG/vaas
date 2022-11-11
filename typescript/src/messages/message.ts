import { Serializable, JsonProperty } from "typescript-json-serializer";

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

@Serializable()
export class Message {
  public constructor(@JsonProperty() public kind: Kind) {}
}
