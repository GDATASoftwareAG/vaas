use crate::Sha256;
use crate::message::verdict::Verdict;
use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(rename_all = "camelCase")]
pub struct FileReport {
    pub sha256: Sha256,
    pub verdict: Verdict,
    pub detection: Option<String>,
    pub file_type: Option<String>,
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(rename_all = "camelCase")]
pub struct UrlReport {
    pub sha256: Sha256,
    pub verdict: Verdict,
    pub url: Url,
    pub detection: Option<String>,
    pub file_type: Option<String>,
    pub mime_type: Option<String>,
}
