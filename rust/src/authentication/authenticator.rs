use crate::error::VResult;
use async_trait::async_trait;
use std::fmt::Debug;

pub static DEFAULT_TOKEN_URL: &str =
    "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token";

/// This trait has to be implemented by any authentication methods for VaaS.
#[async_trait]
pub trait Authenticator: Debug + Send + Sync {
    /// Return a valid token that can be used to authenticate against the VaaS service.
    async fn get_token(&mut self) -> VResult<String>;
}
