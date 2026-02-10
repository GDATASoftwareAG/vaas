use crate::authentication::authenticator::Authenticator;
use crate::authentication::secret_string::SecretString;
use crate::authentication::token_receiver::TokenReceiver;
use crate::error::VResult;
use async_trait::async_trait;
use reqwest::Url;
use std::fmt::Debug;

/// Authenticator for the VaaS service using the client credentials flow.
/// Expects a client id and a client secret.
#[derive(Debug, Clone)]
pub struct ClientCredentials {
    client_id: String,
    client_secret: SecretString,
    receiver: TokenReceiver,
}

impl ClientCredentials {
    /// Create a new authenticator for the VaaS service using the client credentials flow.
    /// Returns an error if the HTTP client cannot be initialized
    pub fn try_new(client_id: String, client_secret: String) -> VResult<Self> {
        Ok(Self {
            client_id,
            client_secret: client_secret.into(),
            receiver: TokenReceiver::try_new()?,
        })
    }

    /// Set the token URL to be used for authentication.
    pub fn with_token_url(mut self, token_url: Url) -> Self {
        self.receiver = self.receiver.set_token_url(token_url);
        self
    }
}

#[async_trait]
impl Authenticator for ClientCredentials {
    async fn get_token(&mut self) -> VResult<String> {
        let params = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("grant_type", "client_credentials"),
        ];
        self.receiver.get_token(&params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[tokio::test]
    async fn authenticator_returns_token() {
        let token_url: Url = dotenv::var("TOKEN_URL")
            .expect("No TOKEN_URL environment variable set to be used in the integration tests")
            .parse()
            .expect("Failed to parse TOKEN_URL environment variable");
        let client_id = dotenv::var("CLIENT_ID").expect(
            "No VAAS_CLIENT_ID environment variable set to be used in the integration tests",
        );
        let client_secret = dotenv::var("CLIENT_SECRET").expect(
            "No VAAS_PASSWORD environment variable set to be used in the integration tests",
        );
        let mut authenticator = ClientCredentials::try_new(client_id, client_secret)
            .unwrap()
            .with_token_url(token_url);

        let token = authenticator.get_token().await;

        assert!(token.is_ok())
    }

    #[tokio::test]
    async fn authenticator_caches_token() {
        let token_url: Url = dotenv::var("TOKEN_URL")
            .expect("No TOKEN_URL environment variable set to be used in the integration tests")
            .parse()
            .expect("Failed to parse TOKEN_URL environment variable");
        let client_id = dotenv::var("CLIENT_ID").expect(
            "No VAAS_CLIENT_ID environment variable set to be used in the integration tests",
        );
        let client_secret = dotenv::var("CLIENT_SECRET").expect(
            "No VAAS_PASSWORD environment variable set to be used in the integration tests",
        );
        let mut authenticator = ClientCredentials::try_new(client_id, client_secret)
            .unwrap()
            .with_token_url(token_url);

        let token1 = authenticator.get_token().await.unwrap();
        let token2 = authenticator.get_token().await.unwrap();

        assert_eq!(token1, token2, "Token should have been re-used");
    }

    #[tokio::test]
    async fn authenticator_wrong_credentials() {
        let token_url: Url = dotenv::var("TOKEN_URL")
            .expect("No TOKEN_URL environment variable set to be used in the integration tests")
            .parse()
            .expect("Failed to parse TOKEN_URL environment variable");
        let client_id = "invalid".to_string();
        let client_secret = "invalid".to_string();
        let mut authenticator = ClientCredentials::try_new(client_id, client_secret)
            .unwrap()
            .with_token_url(token_url);

        let token = authenticator.get_token().await;

        assert!(token.is_err());
        assert!(match token {
            Ok(_) => false,
            Err(Error::AuthorizationFailed(_)) => true,
            _ => false,
        })
    }
}
