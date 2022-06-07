use crate::error::Error;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OpenIdConnectTokenResponse {
    pub access_token: String,
}

impl TryFrom<&String> for OpenIdConnectTokenResponse {
    type Error = Error;
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        serde_json::from_str(value).map_err(|e| e.into())
    }
}
