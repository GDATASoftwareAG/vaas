//! The `Error` type is returned by the `vaas` API everywhere, where an error can occur.

use crate::message::{ErrorResponse, VerdictResponse};
use reqwest::StatusCode;
use std::sync::PoisonError;
use thiserror::Error;
use tokio::sync::broadcast::error::{RecvError, SendError};
use tokio::time::error::Elapsed;
use websockets::WebSocketError;

/// VaaS Result type.
pub type VResult<T> = Result<T, Error>;

/// `Error` is the only error type in the `vaas` API.
#[derive(Error, Debug, Clone)]
pub enum Error {
    /// A websocket error occurred.
    #[error("WebSocket Error: `{0}`")]
    WebSocket(String),
    /// A serialization or deserialization error occurred.
    #[error("Serialization Error: `{0}`")]
    DeSerialization(String),
    /// Failed to acquire the message lock.
    #[error("Cannot acquire message lock: `{0}`")]
    Lock(String),
    /// Received an invalid verdict type.
    #[error("Received an invalid verdict type: `{0}`")]
    InvalidVerdict(String),
    /// Request was cancelled due to a timeout.
    #[error("Request was cancelled")]
    Cancelled,
    /// Received an invalid frame from the websocket.
    #[error("Invalid frame received")]
    InvalidFrame,
    /// Received an invalid message from the endpoint.
    #[error("Invalid message received: `{0}`")]
    InvalidMessage(String),
    /// No connection was established between the client and server. Did you forget to call `connect()`?
    #[error("No connection established. Did you forget to connect?")]
    NoConnection,
    /// The upload URL is not set but expected to be.
    #[error("Upload URL not set but expected")]
    NoUploadUrl,
    /// A generic IO error occurred.
    #[error("IO Error: `{0}`")]
    IoError(String),
    /// The provided string is not a valid SHA256.
    #[error("Invalid SHA256: `{0}`")]
    InvalidSha256(String),
    /// Failed create a request to upload a file.
    #[error("Failed to send file: `{0}`")]
    FailedRequest(String),
    /// Failed to upload the file. Server answered with an non-200 status code.
    #[error("Server answered with status code: `{0}` `{1}`")]
    FailedUploadFile(StatusCode, String),
    /// Authentication token for the file upload in the response message is missing.
    #[error("Missing authentication token for file upload")]
    MissingAuthToken,
    /// Unauthorized
    #[error("Unauthorized: `{0}`")]
    Unauthorized(String),
    /// Broadcast send/receive error between threads occurred.
    #[error("The result channel failed: `{0}`")]
    ResultChannelError(String),
    /// Server returned an error.
    #[error("Error response from the server")]
    ErrorResponse(ErrorResponse),
    /// Failed to get authentication token from the OpenID provider.
    #[error("Failed to get authentication token. Status code `{0}` with message `{1}`")]
    FailedAuthTokenRequest(StatusCode, String),
    /// For an successful authentication response, a session id has to be send by the server.
    /// If no session id is send, but the response has the success flag that, this error is used.
    #[error("No session id in authentication response set")]
    NoSessionIdInAuthResp,
}

impl From<PoisonError<std::sync::MutexGuard<'_, websockets::WebSocketWriteHalf>>> for Error {
    fn from(e: PoisonError<std::sync::MutexGuard<'_, websockets::WebSocketWriteHalf>>) -> Self {
        Self::Lock(e.to_string())
    }
}

impl From<WebSocketError> for Error {
    fn from(e: WebSocketError) -> Self {
        Self::WebSocket(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::DeSerialization(e.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e.to_string())
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Self::FailedRequest(e.to_string())
    }
}

impl From<tokio::sync::broadcast::error::SendError<Result<VerdictResponse, Error>>> for Error {
    fn from(e: SendError<Result<VerdictResponse, Error>>) -> Self {
        Self::ResultChannelError(e.to_string())
    }
}

impl From<tokio::sync::broadcast::error::RecvError> for Error {
    fn from(e: RecvError) -> Self {
        Self::ResultChannelError(e.to_string())
    }
}

impl From<Elapsed> for Error {
    fn from(_: Elapsed) -> Self {
        Self::Cancelled
    }
}
