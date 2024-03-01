use crate::message::kind::Kind;
use crate::{error::VResult, sha256::Sha256};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerdictRequest {
    pub sha256: String,
    pub kind: Kind,
    pub guid: String,
    pub session_id: String,
    pub use_shed: bool,
    pub use_cache: bool,
}

impl VerdictRequest {
    pub fn new(sha256: &Sha256, session_id: String, use_cache: bool, use_shed: bool) -> Self {
        Self {
            guid: uuid::Uuid::new_v4().to_string(),
            sha256: sha256.to_string(),
            kind: Kind::VerdictRequest,
            session_id,
            use_cache,
            use_shed,
        }
    }

    pub fn to_json(&self) -> VResult<String> {
        serde_json::to_string(self).map_err(|e| e.into())
    }
    pub fn guid(&self) -> &str {
        &self.guid
    }
}
