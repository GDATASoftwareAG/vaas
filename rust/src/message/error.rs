use crate::error::Error;
use crate::message::kind::Kind;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ErrorResponse {
    #[serde(alias = "type")]
    pub error_type: String,
    pub text: String,
    pub kind: Kind,
}

impl TryFrom<&String> for ErrorResponse {
    type Error = Error;
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Ok(serde_json::from_str(value)?)
    }
}
