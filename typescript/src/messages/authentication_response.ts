import { JsonProperty, JsonObject } from "typescript-json-serializer";
import { Message, Kind } from "./message";

@JsonObject()
export class AuthenticationResponse extends Message {
  public constructor(session_id: string, success: boolean, text: string) {
    super(Kind.AuthResponse);
    this.session_id = session_id;
    this.success = success;
    this.text = text;
  }

  @JsonProperty() public session_id: string;
  @JsonProperty() public success: boolean;
  @JsonProperty() public text: string;
}
