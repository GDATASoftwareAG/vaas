import { JsonProperty, JsonObject } from "typescript-json-serializer";
import { Kind, Message } from "./message";

@JsonObject()
export class VerdictRequestForStream extends Message {
  public constructor(guid: string, session_id: string) {
    super(Kind.VerdictRequestForStream);
    this.session_id = session_id;
    this.guid = guid;
  }

  @JsonProperty() public guid: string;
  @JsonProperty() public session_id: string;
}
