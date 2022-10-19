use crate::error::Error;
use crate::message::{Verdict, VerdictResponse};
use crate::sha256::Sha256;
use std::convert::TryFrom;

#[derive(Debug, Clone)]

/// VaaS Verdict.
pub struct VaasVerdict {
    /// Sha256
    pub sha256: Sha256,
    /// Verdict
    pub verdict: Verdict,
}

impl TryFrom<VerdictResponse> for VaasVerdict {
    type Error = Error;
    fn try_from(verdict_response: VerdictResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            sha256: Sha256::try_from(verdict_response.sha256.as_str())?,
            verdict: Verdict::try_from(&verdict_response)?,
        })
    }
}
