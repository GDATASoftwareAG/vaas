use crate::error::Error;
use crate::message::error::ErrorResponse;
use crate::message::VerdictResponse;
use std::convert::TryFrom;

pub enum MessageType {
    Ping,
    Pong,
    Close,
    VerdictResponse(VerdictResponse),
}

impl TryFrom<&String> for MessageType {
    type Error = Error;

    fn try_from(json: &String) -> Result<Self, Self::Error> {
        if let Ok(resp) = VerdictResponse::try_from(json) {
            return Ok(MessageType::VerdictResponse(resp));
        }
        if let Ok(err) = ErrorResponse::try_from(json) {
            return Err(Error::ErrorResponse(err));
        }
        Err(Error::InvalidMessage(json.to_string()))
    }
}
