//! The `Builder` struct create a new [Vaas] instance with the expected default values and allows the custom configuration.

use reqwest::Url;

use crate::error::VResult;
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
    poll_delay_ms: u64,
    url: Url,
}

impl Builder {
    /// Create a new VaasBuilder to create a [Vaas] instance.
    pub fn new(token: String) -> Self {
        Self {
            token,
            ..Self::default()
        }
    }

    /// Set the delay between each poll of the API for results. Defaults to 100ms.
    pub fn poll_delay_ms(self, delay: u64) -> Self {
        Self {
            poll_delay_ms: delay,
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
            poll_delay_ms: self.poll_delay_ms,
            token: self.token,
            url: self.url,
        })
    }
}

impl Default for Builder {
    fn default() -> Self {
        use std::str::FromStr;
        Self {
            poll_delay_ms: 100,
            token: String::new(),
            url: Url::from_str("wss://gateway-vaas.gdatasecurity.de").unwrap(),
        }
    }
}
