//! The `Builder` struct create a new [Vaas] instance with the expected default values and allows the custom configuration.

use crate::authentication::Authenticator;
use crate::error::VResult;
use crate::vaas::Vaas;
use reqwest::Url;
use std::str::FromStr;

/// Builder struct to create a new Vaas instance with the expected default values.
/// ```rust
/// // Create a new [Vaas] instance from the builder.
/// # fn main() -> vaas::error::VResult<()> {
/// use vaas::Builder;
/// use vaas::authentication::ClientCredentials;
///
/// let authenticator = ClientCredentials::try_new("client_id".to_string(), "client_secret".to_string())?;
///
/// let vaas = Builder::new(authenticator).build()?;
/// # Ok(()) }
/// ```
pub struct Builder {
    authenticator: Box<dyn Authenticator>,
    url: Url,
}

impl Builder {
    /// Create a new `VaasBuilder` to create a [Vaas] instance.
    pub fn new(authenticator: impl Authenticator + Send + Sync + 'static) -> Self {
        let authenticator = Box::new(authenticator);
        Self {
            authenticator,
            url: Url::from_str("https://gateway.production.vaas.gdatasecurity.de").unwrap(),
        }
    }

    /// Change the URL of the VaaS API.
    pub fn url(self, url: Url) -> Self {
        Self { url, ..self }
    }

    /// Create a [Vaas] struct from the `VaasBuilder`.
    /// Returns an error if the HTTP client cannot be initialized
    pub fn build(self) -> VResult<Vaas> {
        Vaas::try_new(self.authenticator, self.url)
    }
}
