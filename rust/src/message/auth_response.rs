use crate::error::Error;
use crate::message::kind::Kind;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthResponse {
    pub kind: Kind,
    pub success: bool,
    pub session_id: String,
    pub text: String,
}

impl TryFrom<&String> for AuthResponse {
    type Error = Error;
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Ok(serde_json::from_str(value)?)
    }
}
