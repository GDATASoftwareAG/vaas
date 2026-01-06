use serde::{Deserialize, Serialize};

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
