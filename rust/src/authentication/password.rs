use crate::authentication::Authenticator;
use crate::authentication::secret_string::SecretString;
use crate::authentication::token_receiver::TokenReceiver;
use crate::error::VResult;
use async_trait::async_trait;
use reqwest::Url;
use std::fmt::Debug;

/// Authenticator for the VaaS service using the password flow.
/// Expects a client id, a username and a password.
#[derive(Debug, Clone)]
pub struct Password {
    client_id: String,
    username: String,
    password: SecretString,
    receiver: TokenReceiver,
}

impl Password {
    /// Create a new authenticator for the VaaS service using the password flow.
    /// Returns an error if the HTTP client cannot be initialized
    pub fn try_new(client_id: String, username: String, password: String) -> VResult<Self> {
        Ok(Self {
            client_id,
            username,
            password: password.into(),
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
impl Authenticator for Password {
    async fn get_token(&mut self) -> VResult<String> {
        let params = [
            ("client_id", self.client_id.as_str()),
            ("username", self.username.as_str()),
            ("password", self.password.as_unredacted_str()),
            ("grant_type", "password"),
        ];
        self.receiver.get_token(&params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    // Keycloak is sometimes flaky when tests are run in parallel, so force serialization
    static AUTH_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn authenticator_returns_token() {
        let lock = AUTH_LOCK.lock().await;
        let token_url: Url = dotenv::var("TOKEN_URL")
            .expect("No TOKEN_URL environment variable set to be used in the integration tests")
            .parse()
            .expect("Failed to parse TOKEN_URL environment variable");
        let client_id = dotenv::var("VAAS_CLIENT_ID").expect(
            "No VAAS_CLIENT_ID environment variable set to be used in the integration tests",
        );
        let user_name = dotenv::var("VAAS_USER_NAME").expect(
            "No VAAS_USER_NAME environment variable set to be used in the integration tests",
        );
        let password = dotenv::var("VAAS_PASSWORD").expect(
            "No VAAS_PASSWORD environment variable set to be used in the integration tests",
        );
        let mut authenticator = Password::try_new(client_id, user_name, password)
            .unwrap()
            .with_token_url(token_url);

        let token = authenticator.get_token().await;

        assert!(token.is_ok());
        drop(lock);
    }

    #[tokio::test]
    async fn authenticator_caches_token() {
        let lock = AUTH_LOCK.lock().await;
        let token_url: Url = dotenv::var("TOKEN_URL")
            .expect("No TOKEN_URL environment variable set to be used in the integration tests")
            .parse()
            .expect("Failed to parse TOKEN_URL environment variable");
        let client_id = dotenv::var("VAAS_CLIENT_ID").expect(
            "No VAAS_CLIENT_ID environment variable set to be used in the integration tests",
        );
        let user_name = dotenv::var("VAAS_USER_NAME").expect(
            "No VAAS_USER_NAME environment variable set to be used in the integration tests",
        );
        let password = dotenv::var("VAAS_PASSWORD").expect(
            "No VAAS_PASSWORD environment variable set to be used in the integration tests",
        );
        let mut authenticator = Password::try_new(client_id, user_name, password)
            .unwrap()
            .with_token_url(token_url);

        let token1 = authenticator.get_token().await.unwrap();
        let token2 = authenticator.get_token().await.unwrap();

        assert_eq!(token1, token2, "Token should have been re-used");
        drop(lock);
    }

    #[tokio::test]
    async fn authenticator_wrong_credentials() {
        let lock = AUTH_LOCK.lock().await;
        let token_url: Url = dotenv::var("TOKEN_URL")
            .expect("No TOKEN_URL environment variable set to be used in the integration tests")
            .parse()
            .expect("Failed to parse TOKEN_URL environment variable");
        let client_id = "invalid".to_string();
        let user_name = "invalid".to_string();
        let password = "invalid".to_string();
        let mut authenticator = Password::try_new(client_id, user_name, password)
            .unwrap()
            .with_token_url(token_url);

        let token = authenticator.get_token().await;

        assert!(token.is_err());
        assert!(match token {
            Ok(_) => false,
            Err(Error::AuthorizationFailed(_)) => true,
            _ => false,
        });
        drop(lock);
    }
}
