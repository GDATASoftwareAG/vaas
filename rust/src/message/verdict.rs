use crate::error::Error;
use crate::error::Error::NoUploadUrl;
use crate::message::upload_url::UploadUrl;
use crate::message::VerdictResponse;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt;

/// A `Verdict` is a response from the server that indicates whether the
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
    Unknown {
        /// Pre-signed URL to submit a file for further analysis to get a `Clean` or `Malicious` verdict.
        upload_url: UploadUrl,
    },
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Unknown { upload_url: _ } => write!(f, "Unknown"),
            _ => write!(f, "{self:?}"),
        }
    }
}

impl TryFrom<&VerdictResponse> for Verdict {
    type Error = Error;

    fn try_from(value: &VerdictResponse) -> Result<Self, Self::Error> {
        match value.verdict.as_str() {
            "Clean" => Ok(Verdict::Clean),
            "Malicious" => Ok(Verdict::Malicious),
            "Pup" => Ok(Verdict::Pup),
            "Unknown" => Ok(Verdict::Unknown {
                upload_url: UploadUrl(value.url.to_owned().ok_or(NoUploadUrl)?),
            }),
            v => Err(Error::InvalidVerdict(v.to_string())),
        }
    }
}

impl TryFrom<&str> for Verdict {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // It is not possible to construct a Verdict::Unknown from a string, as the upload_url is not known.
        match value {
            "Clean" => Ok(Verdict::Clean),
            "Malicious" => Ok(Verdict::Malicious),
            "Pup" => Ok(Verdict::Pup),
            v => Err(Error::InvalidVerdict(v.to_string())),
        }
    }
}
