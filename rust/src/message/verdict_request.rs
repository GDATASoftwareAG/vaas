use crate::message::kind::Kind;
use crate::{error::VResult, sha256::Sha256};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerdictRequest {
    pub sha256: String,
    pub kind: Kind,
    pub guid: String,
    pub session_id: String,
}

impl VerdictRequest {
    pub fn new(sha256: &Sha256, session_id: String) -> Self {
        Self {
            guid: uuid::Uuid::new_v4().to_string(),
            sha256: sha256.to_string(),
            kind: Kind::VerdictRequest,
            session_id,
        }
    }

    pub fn to_json(&self) -> VResult<String> {
        Ok(serde_json::to_string(self)?)
    }
    pub fn guid(&self) -> &str {
        &self.guid
    }
}
