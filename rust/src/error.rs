//! The `Error` type is returned by the `vaas` API everywhere, where an error can occur.

use crate::message::problem::ProblemDetails;
use thiserror::Error;

/// VaaS Result type.
pub type VResult<T> = Result<T, Error>;

/// `Error` is the only error type in the `vaas` API.
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum Error {
    /// HTTP error
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    /// A given URL was not valid
    #[error("Invalid url: {0}")]
    InvalidUrl(#[from] url::ParseError),
    /// A `CancellationToken` was canceled prior to an operation completing
    #[error("Request was canceled")]
    Canceled,
    /// Unable to obtain a valid authorization token. The most common cause is incorrect credentials.
    #[error("Failed to obtain authorization token - check your credentials: {0}")]
    AuthorizationFailed(String),
    /// The request was not authorized despite sending an authorization token
    #[error("Unauthorized request: {0}")]
    Unauthorized(String),
    /// The VaaS server reported an internal error
    #[error("The server reported an internal error: {0}")]
    ServerError(#[from] ProblemDetails),
    /// The VaaS server reported an error caused by the client. Retry only after identifying the root cause.
    #[error("The server reported an error caused by the client: {0}")]
    ClientError(#[source] ProblemDetails),
    #[error("IO Error: {0}")]
    /// An I/O error occurred
    IoError(#[from] std::io::Error),
    /// The given SHA256 value is not valid
    #[error("Invalid SHA256 hash value: {0}")]
    InvalidSha256(String),
}
