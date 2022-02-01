//! The `Error` type is returned by the `vaas` API everywhere, where an error can occur.

use crate::message;
use crate::message::State;
use crate::vaas::ThreadSyncMsg;
use reqwest::StatusCode;
use std::collections::HashMap;
use std::sync::mpsc::SendError;
use std::sync::{MutexGuard, PoisonError};
use thiserror::Error;
use websockets::WebSocketError;

/// VaaS Result type.
pub type VResult<T> = Result<T, Error>;

/// `Error` is the only error type in the `vaas` API.
#[derive(Error, Debug)]
pub enum Error {
    /// A websocket error occurred.
    #[error("WebSocket Error: `{0}`")]
    WebSocket(#[from] WebSocketError),
    /// A serialization or deserialization error occurred.
    #[error("Serialization Error: `{0}`")]
    DeSerialization(#[from] serde_json::Error),
    /// Failed to acquire the message lock.
    #[error("Cannot acquire message lock: `{0}`")]
    Lock(String),
    /// Received an invalid verdict type.
    #[error("Received an invalid verdict type: `{0}`")]
    InvalidVerdict(String),
    /// Request was cancelled due to a timeout.
    #[error("Request was cancelled")]
    Cancelled,
    /// Failed to send a sync message between threads.
    #[error("Failed to send message between threads")]
    ThreadSendMsg,
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
    IoError(#[from] std::io::Error),
    /// The provided string is not a valid SHA256.
    #[error("Invalid SHA256: `{0}`")]
    InvalidSha256(String),
    /// Failed create a request to upload a file.
    #[error("Failed to send file: `{0}`")]
    FailedRequest(#[from] reqwest::Error),
    /// Failed to upload the file. Server answered with an non-200 status code.
    #[error("Server answered with status code: `{0}`")]
    FailedUploadFile(StatusCode),
    /// Authentication token for the file upload in the response message is missing.
    #[error("Missing authentication token for file upload")]
    MissingAuthToken,
    /// Unauthorized
    #[error("Unauthorized")]
    Unauthorized,
}

impl From<PoisonError<std::sync::MutexGuard<'_, HashMap<std::string::String, message::State>>>>
    for Error
{
    fn from(e: PoisonError<MutexGuard<'_, HashMap<String, State>>>) -> Self {
        Self::Lock(e.to_string())
    }
}

impl From<PoisonError<std::sync::MutexGuard<'_, std::sync::mpsc::Sender<ThreadSyncMsg>>>>
    for Error
{
    fn from(
        e: PoisonError<std::sync::MutexGuard<'_, std::sync::mpsc::Sender<ThreadSyncMsg>>>,
    ) -> Self {
        Self::Lock(e.to_string())
    }
}

impl From<PoisonError<std::sync::MutexGuard<'_, websockets::WebSocketWriteHalf>>> for Error {
    fn from(e: PoisonError<std::sync::MutexGuard<'_, websockets::WebSocketWriteHalf>>) -> Self {
        Self::Lock(e.to_string())
    }
}

impl From<SendError<ThreadSyncMsg>> for Error {
    fn from(_e: SendError<ThreadSyncMsg>) -> Self {
        Self::ThreadSendMsg
    }
}

impl From<tokio::sync::mpsc::error::SendError<ThreadSyncMsg>> for Error {
    fn from(_e: tokio::sync::mpsc::error::SendError<ThreadSyncMsg>) -> Self {
        Self::ThreadSendMsg
    }
}

impl From<flume::SendError<ThreadSyncMsg>> for Error {
    fn from(e: flume::SendError<ThreadSyncMsg>) -> Self {
        Self::Lock(e.to_string())
    }
}

impl From<PoisonError<std::sync::MutexGuard<'_, flume::Sender<ThreadSyncMsg>>>> for Error {
    fn from(e: PoisonError<std::sync::MutexGuard<'_, flume::Sender<ThreadSyncMsg>>>) -> Self {
        Self::Lock(e.to_string())
    }
}
