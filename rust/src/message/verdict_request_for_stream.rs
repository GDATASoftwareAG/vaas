use super::VerdictRequest;
use crate::message::kind::Kind;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerdictRequestForStream {
    pub kind: Kind,
    pub guid: String,
    pub session_id: String,
    pub use_shed: bool,
    pub use_cache: bool,
}

impl VerdictRequestForStream {
    pub fn new(session_id: String, use_cache: bool, use_shed: bool) -> Self {
        Self {
            guid: uuid::Uuid::new_v4().to_string(),
            kind: Kind::VerdictRequestForStream,
            session_id,
            use_cache,
            use_shed,
        }
    }
}

impl VerdictRequest for VerdictRequestForStream {
    fn guid(&self) -> &str {
        &self.guid
    }
}
