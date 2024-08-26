//! # VaaS Verdict
//!
//! The `VaaSVerdict` is the result of a request for a verdict. It contains the verdict itself and the SHA256 hash of the requested file.

use crate::error::Error;
use crate::message::{Verdict, VerdictResponse};
use crate::sha256::Sha256;
use std::convert::TryFrom;

#[derive(Debug, Clone)]

/// Response object from the api.
pub struct VaasVerdict {
    /// Sha256 of the requested file
    pub sha256: Sha256,
    /// Verdict for the file
    pub verdict: Verdict,
    /// File type as classified by https://www.darwinsys.com/file/
    pub file_type: Option<String>,
    /// mime type as classified by https://www.darwinsys.com/file/
    pub mime_type: Option<String>,
}

impl TryFrom<VerdictResponse> for VaasVerdict {
    type Error = Error;
    fn try_from(verdict_response: VerdictResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            sha256: Sha256::try_from(verdict_response.sha256.as_str())?,
            verdict: Verdict::try_from(&verdict_response)?,
            file_type: verdict_response.file_type,
            mime_type: verdict_response.mime_type,
        })
    }
}
