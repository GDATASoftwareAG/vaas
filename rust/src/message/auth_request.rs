use crate::error::VResult;
use crate::message::kind::Kind;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthRequest {
    pub kind: Kind,
    pub token: String,
    pub session_id: Option<String>,
}

impl AuthRequest {
    pub fn new(token: String, session_id: Option<String>) -> Self {
        Self {
            kind: Kind::AuthRequest,
            token,
            session_id,
        }
    }

    pub fn to_json(&self) -> VResult<String> {
        serde_json::to_string(self).map_err(|e| e.into())
    }
}
