use crate::error::Error;
use crate::message::{Verdict, VerdictResponse};
use crate::sha256::Sha256;
use std::convert::TryFrom;

#[derive(Debug, Clone)]
pub struct VaasVerdict {
    pub sha256: Sha256,
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
