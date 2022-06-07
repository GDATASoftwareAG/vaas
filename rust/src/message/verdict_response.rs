use crate::error::Error;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerdictResponse {
    pub sha256: String,
    pub guid: String,
    pub verdict: String,
    pub url: Option<String>,
    pub upload_token: Option<String>,
}

impl TryFrom<&String> for VerdictResponse {
    type Error = Error;
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        serde_json::from_str(value).map_err(|e| e.into())
    }
}
