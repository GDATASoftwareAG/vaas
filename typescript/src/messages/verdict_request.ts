import {JsonProperty, Serializable} from 'typescript-json-serializer';
import {Kind, Message} from "./message";

@Serializable()
export class VerdictRequest extends Message{
    public constructor(
        sha256: string,
        guid: string,
        session_id: string,
    ) {
        super(Kind.VerdictRequest)
        this.sha256 = sha256;
        this.session_id = session_id;
        this.guid = guid;
    }

    @JsonProperty() public sha256: string;
    @JsonProperty() public guid: string;
    @JsonProperty() public session_id: string;
}