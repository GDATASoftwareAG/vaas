use serde::{Deserialize, Serialize};
use crate::error::Error;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OpenIdConnectTokenResponse {
    pub access_token: String,
}

impl TryFrom<&String> for OpenIdConnectTokenResponse {
    type Error = Error;
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Ok(serde_json::from_str(value)?)
    }
}