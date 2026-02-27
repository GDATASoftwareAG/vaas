//! # VaaS Verdict
//!
//! The `VaaSVerdict` is the result of a request for a verdict. It contains the analysis results from the server.

use crate::message::report::{FileReport, UrlReport};
use crate::message::verdict::Verdict;
use crate::sha256::Sha256;

/// Response with all information regarding an analysis.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VaasVerdict {
    /// Sha256 of the requested file
    pub sha256: Sha256,
    /// Verdict for the file
    pub verdict: Verdict,
    /// The detected malware or PUP found in the file, if any
    pub detection: Option<String>,
    /// File type as classified by https://www.darwinsys.com/file/
    pub file_type: Option<String>,
    /// mime type as classified by https://www.darwinsys.com/file/
    pub mime_type: Option<String>,
}

impl From<FileReport> for VaasVerdict {
    fn from(report: FileReport) -> Self {
        Self {
            sha256: report.sha256,
            verdict: report.verdict,
            detection: report.detection,
            file_type: report.file_type,
            mime_type: report.mime_type,
        }
    }
}

impl From<UrlReport> for VaasVerdict {
    fn from(report: UrlReport) -> Self {
        Self {
            sha256: report.sha256,
            verdict: report.verdict,
            detection: report.detection,
            file_type: report.file_type,
            mime_type: report.mime_type,
        }
    }
}
