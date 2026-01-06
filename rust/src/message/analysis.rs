use crate::Sha256;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Deserialize)]
pub struct FileAnalysisStarted {
    pub sha256: Sha256,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UrlAnalysisRequest<'a> {
    pub url: &'a Url,
    pub use_hash_lookup: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UrlAnalysisStarted {
    pub id: String,
}
