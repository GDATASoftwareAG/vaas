//! The `Error` type is returned by the `vaas` API everywhere, where an error can occur.

use crate::message::problem::ProblemDetails;
use thiserror::Error;

/// VaaS Result type.
pub type VResult<T> = Result<T, Error>;

/// `Error` is the only error type in the `vaas` API.
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum Error {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Invalid Vaas url: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("Request was cancelled")]
    Cancelled,
    #[error("Failed to obtain authorization token - check your credentials: {0}")]
    AuthorizationFailed(String),
    #[error("Unauthorized request: {0}")]
    Unauthorized(String),
    #[error("The server reported an error: {0}")]
    ServerError(#[from] ProblemDetails),
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Invalid SHA256 hash value: {0}")]
    InvalidSha256(String),
}
