import { JsonProperty, Serializable } from "typescript-json-serializer";
import { Kind, Message } from "./message";

@Serializable()
export class VerdictRequestForUrl extends Message {
  public constructor(url: URL, guid: string, session_id: string) {
    super(Kind.VerdictRequestForUrl);
    this.url = url.toString();
    this.session_id = session_id;
    this.guid = guid;
  }

  @JsonProperty() public url: string;
  @JsonProperty() public guid: string;
  @JsonProperty() public session_id: string;
}
