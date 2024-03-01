use crate::error::VResult;
use crate::message::kind::Kind;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerdictRequestForStream {
    pub kind: Kind,
    pub guid: String,
    pub session_id: String,
}

impl VerdictRequestForStream {
    pub fn new(session_id: String) -> Self {
        Self {
            guid: uuid::Uuid::new_v4().to_string(),
            kind: Kind::VerdictRequestForStream,
            session_id,
        }
    }

    pub fn to_json(&self) -> VResult<String> {
        serde_json::to_string(self).map_err(|e| e.into())
    }
    pub fn guid(&self) -> &str {
        &self.guid
    }
}
