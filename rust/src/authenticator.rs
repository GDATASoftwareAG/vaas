use crate::error::VResult;
use async_trait::async_trait;

#[async_trait]
pub trait Authenticator {
    async fn get_token(self) -> VResult<String>;
}
