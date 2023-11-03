//! The `Builder` struct create a new [Vaas] instance with the expected default values and allows the custom configuration.

use crate::auth::Authenticator;
use crate::error::VResult;
use crate::options::Options;
use crate::vaas::Vaas;
use reqwest::Url;

/// Builder struct to create a new Vaas instance with the expected default values.
/// ```rust
/// // Create a new [Vaas] instance from the builder.
/// # fn main() -> vaas::error::VResult<()> {
/// use vaas::Builder;
/// use vaas::auth::authenticators::ClientCredentials;
///
/// let authenticator = ClientCredentials::new("client_id".to_string(), "client_secret".to_string());
///
/// let vaas = Builder::new(authenticator).build()?;
/// # Ok(()) }
/// ```
pub struct Builder<A: Authenticator> {
    authenticator: A,
    url: Url,
    options: Options,
}

impl<A: Authenticator> Builder<A> {
    /// Create a new VaasBuilder to create a [Vaas] instance.
    pub fn new(authenticator: A) -> Self {
        use std::str::FromStr;
        Self {
            options: Options {
                keep_alive_delay_ms: 10_000,
                keep_alive: true,
                channel_capacity: 100,
            },
            authenticator,
            url: Url::from_str("wss://gateway.production.vaas.gdatasecurity.de").unwrap(),
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
    pub fn build(self) -> VResult<Vaas<A>> {
        Ok(Vaas {
            options: self.options,
            authenticator: self.authenticator,
            url: self.url,
        })
    }
}
