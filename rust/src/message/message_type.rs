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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_verdict_response() {
        let msg = r#"
        {
            "kind": "VerdictResponse",
            "sha256": "ED2456914E48C1E17B7BD922177291EF8B7F553EDF1B1F66B6FC1A076524B22F",
            "guid": "9dae843d-e947-41db-ad39-ec73704529ed",
            "verdict": "Clean",
            "url": null,
            "upload_token": null
        }
        "#.to_string();

        let message_type = MessageType::try_from(&msg).unwrap();

        let is_correct_type = match message_type {
            MessageType::VerdictResponse(_) => true,
            _ => false
        };

        assert!(is_correct_type);
    }

    #[test]
    fn deserialize_error_response() {
        let msg = r#"
        {
            "kind": "Error",
            "type": "UniqueErrorType",
            "text": "Something went wrong..."
        }
        "#.to_string();

        let message_type = MessageType::try_from(&msg);

        let is_correct_type = match message_type {
            Err(Error::ErrorResponse(_)) => true,
            _ => false
        };

        assert!(is_correct_type);
    }
}