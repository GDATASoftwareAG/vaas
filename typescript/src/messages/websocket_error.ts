import { Serializable, JsonProperty } from "typescript-json-serializer";
import { Kind, Message } from "./message";

@Serializable()
export class WebsocketError extends Message {
  public constructor(
    @JsonProperty() public type: string,
    @JsonProperty() public text: string
  ) {
    super(Kind.Error);
  }
}
