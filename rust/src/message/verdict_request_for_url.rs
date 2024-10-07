use super::VerdictRequest;
use crate::message::kind::Kind;
use reqwest::Url;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerdictRequestForUrl {
    pub url: String,
    pub kind: Kind,
    pub guid: String,
    pub session_id: String,
    pub use_shed: bool,
    pub use_cache: bool,
}

impl VerdictRequestForUrl {
    pub fn new(url: &Url, session_id: String, use_cache: bool, use_shed: bool) -> Self {
        Self {
            guid: uuid::Uuid::new_v4().to_string(),
            url: url.to_string(),
            kind: Kind::VerdictRequestForUrl,
            session_id,
            use_cache,
            use_shed,
        }
    }
}

impl VerdictRequest for VerdictRequestForUrl {
    fn guid(&self) -> &str {
        &self.guid
    }
}
