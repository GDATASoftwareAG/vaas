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
