//! # Cancellation
//!
//! As a request for a verdict can take some time if, for example the file is huge or the network connection is slow, it is possible to cancel
//! each verdict request after some time. This is done by using a `CancellationToken` which can be created from a `Duration`.
//! If the duration is up, the request is aborted and an error is returned.

use std::time::Duration;

/// The `CancellationToken` allows to cancel a request after a specific time
/// if no response was received from the server.
pub struct CancellationToken {
    /// Duration after which the request is cancelled.
    pub duration: Duration,
}

impl CancellationToken {
    /// Create a new `CancellationToken` from seconds.
    pub fn from_seconds(secs: u64) -> Self {
        Self {
            duration: Duration::from_secs(secs),
        }
    }

    /// Create a new `CancellationToken` from minutes.
    pub fn from_minutes(mins: u64) -> Self {
        Self {
            duration: Duration::from_secs(60 * mins),
        }
    }
}
