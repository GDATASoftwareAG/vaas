use crate::auth::authenticator::{Authenticator, DEFAULT_TOKEN_URL};
use crate::error::{Error, VResult};
use crate::message::OpenIdConnectTokenResponse;
use async_trait::async_trait;
use reqwest::StatusCode;
use reqwest::Url;

/// Authenticator for the VaaS service using the client credentials flow.
/// Expects a client id and a client secret.
#[derive(Clone)]
pub struct ClientCredentials {
    client_id: String,
    client_secret: String,
    token_url: Url,
}

impl ClientCredentials {
    /// Create a new authenticator for the VaaS service using the client credentials flow.
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
            token_url: Url::parse(DEFAULT_TOKEN_URL).unwrap(), // Safe to unwrap, as this is a constant URL and will always be valid.
        }
    }
    /// Set the token URL to be used for authentication.
    pub fn with_token_url(mut self, token_url: Url) -> Self {
        self.token_url = token_url;
        self
    }
}

#[async_trait]
impl Authenticator for ClientCredentials {
    async fn get_token(&self) -> VResult<String> {
        let params = [
            ("client_id", self.client_id.clone()),
            ("client_secret", self.client_secret.clone()),
            ("grant_type", "client_credentials".to_string()),
        ];
        let client = reqwest::Client::new();
        let token_response = client
            .post(self.token_url.clone())
            .form(&params)
            .send()
            .await?;

        match token_response.status() {
            StatusCode::OK => {
                let json_string = token_response.text().await?;
                Ok(OpenIdConnectTokenResponse::try_from(&json_string)?.access_token)
            }
            status => Err(Error::FailedAuthTokenRequest(
                status,
                token_response.text().await.unwrap_or_default(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error::FailedAuthTokenRequest;

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
        let authenticator =
            ClientCredentials::new(client_id, client_secret).with_token_url(token_url);

        let token = authenticator.get_token().await;

        assert!(token.is_ok())
    }

    #[tokio::test]
    async fn authenticator_wrong_credentials() {
        let token_url: Url = dotenv::var("TOKEN_URL")
            .expect("No TOKEN_URL environment variable set to be used in the integration tests")
            .parse()
            .expect("Failed to parse TOKEN_URL environment variable");
        let client_id = "invalid".to_string();
        let client_secret = "invalid".to_string();
        let authenticator =
            ClientCredentials::new(client_id, client_secret).with_token_url(token_url);

        let token = authenticator.get_token().await;

        assert!(token.is_err());
        assert!(match token {
            Ok(_) => false,
            Err(FailedAuthTokenRequest(_, _)) => true,
            _ => false,
        })
    }
}
