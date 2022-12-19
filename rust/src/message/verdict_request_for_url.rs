use crate::error::VResult;
use crate::message::kind::Kind;
use reqwest::Url;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerdictRequestForUrl {
    pub url: String,
    pub kind: Kind,
    pub guid: String,
    pub session_id: String,
}

impl VerdictRequestForUrl {
    pub fn new(url: &Url, session_id: String) -> Self {
        Self {
            guid: uuid::Uuid::new_v4().to_string(),
            url: url.to_string(),
            kind: Kind::VerdictRequestForUrl,
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
