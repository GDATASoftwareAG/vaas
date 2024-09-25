use crate::message::kind::Kind;
use crate::sha256::Sha256;
use serde::{Deserialize, Serialize};

use super::VerdictRequest;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerdictRequestFile {
    pub sha256: String,
    pub kind: Kind,
    pub guid: String,
    pub session_id: String,
    pub use_hash_lookup: bool,
    pub use_cache: bool,
}

impl VerdictRequestFile {
    pub fn new(
        sha256: &Sha256,
        session_id: String,
        use_cache: bool,
        use_hash_lookup: bool,
    ) -> Self {
        Self {
            guid: uuid::Uuid::new_v4().to_string(),
            sha256: sha256.to_string(),
            kind: Kind::VerdictRequest,
            session_id,
            use_cache,
            use_hash_lookup,
        }
    }
}

impl VerdictRequest for VerdictRequestFile {
    fn guid(&self) -> &str {
        &self.guid
    }
}
