//! The `Builder` struct create a new [Vaas] instance with the expected default values and allows the custom configuration.
use reqwest::Url;

use crate::error::VResult;
use crate::options::Options;
use crate::vaas::Vaas;

/// Builder struct to create a new Vaas instance with the expected default values.
/// ```rust
/// // Create a new [Vaas] instance from the builder.
/// # fn main() -> vaas::error::VResult<()> {
/// use vaas::Builder;
///
/// let vaas = Builder::new(String::from("mytoken")).build()?;
/// # Ok(()) }
/// ```
pub struct Builder {
    token: String,
    url: Url,
    options: Options,
}

impl Builder {
    /// Create a new VaasBuilder to create a [Vaas] instance.
    pub fn new(token: String) -> Self {
        Self {
            token,
            ..Self::default()
        }
    }

    /// Set the delay in which a Ping is sent to the server to keep the connection alive.
    /// Defaults to 10s.
    pub fn keep_alive_delay_ms(self, delay: u64) -> Self {
        Self {
            options: Options {
                keep_alive_delay_ms: delay,
                ..self.options
            },
            ..self
        }
    }

    /// Enable or disable periodic pings to the server to keep the connection alive.
    /// Defaults to enabled (true).
    pub fn keep_alive(self, keep_alive: bool) -> Self {
        Self {
            options: Options {
                keep_alive,
                ..self.options
            },
            ..self
        }
    }

    /// Set the channel capacity of the internal results channel.
    /// Increase the value if a `ResultChannelError("channel lagged by X")` is received.
    /// Defaults to 100.
    pub fn channel_capacity(self, capacity: usize) -> Self {
        Self {
            options: Options {
                channel_capacity: capacity,
                ..self.options
            },
            ..self
        }
    }

    /// Change the URL of the VaaS API.
    pub fn url(self, url: Url) -> Self {
        Self { url, ..self }
    }

    /// Create a [Vaas] struct from the `VaasBuilder`.
    pub fn build(self) -> VResult<Vaas> {
        Ok(Vaas {
            options: self.options,
            token: self.token,
            url: self.url,
        })
    }
}

impl Default for Builder {
    fn default() -> Self {
        use std::str::FromStr;
        Self {
            options: Options {
                keep_alive_delay_ms: 10_000,
                keep_alive: true,
                channel_capacity: 100,
            },
            token: String::new(),
            url: Url::from_str("wss://gateway-vaas.gdatasecurity.de").unwrap(),
        }
    }
}
