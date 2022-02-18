use crate::error::Error;
use crate::message::VerdictResponse;
use std::convert::TryFrom;

pub enum MessageType {
    Ping,
    Pong,
    Close,
    Response(VerdictResponse),
}

impl TryFrom<&String> for MessageType {
    type Error = Error;

    fn try_from(json: &String) -> Result<Self, Self::Error> {
        if let Ok(resp) = VerdictResponse::try_from(json) {
            return Ok(MessageType::Response(resp));
        }
        Err(Error::InvalidMessage(json.to_string()))
    }
}
