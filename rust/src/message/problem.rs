//! Contains messages related to errors.
use serde::Deserialize;
use std::fmt::{Display, Formatter};
use thiserror::Error;

/// `ProblemDetails` contains information send by the server describing why an operation failed.
/// Conforms to RFC7807.
#[derive(Debug, Clone, Deserialize, Error)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct ProblemDetails {
    /// Problem type as per RFC7807
    #[serde(rename = "type")]
    pub r#type: String,
    /// Problem details as per RFC7807
    pub detail: String,
}

impl Display for ProblemDetails {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} - {} ", self.r#type, self.detail)
    }
}
