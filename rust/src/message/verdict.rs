//! Types related to verdicts
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// The `Verdict` indicates whether the
/// submission is `Clean`, `Malicious`, `Pup` or `Unknown`.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum Verdict {
    /// No malicious content found.
    Clean,
    /// Malicious content found.
    Malicious,
    /// Potentially unwanted content found.
    Pup,
    /// Unknown if clean or malicious.
    Unknown,
}

impl Display for Verdict {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
