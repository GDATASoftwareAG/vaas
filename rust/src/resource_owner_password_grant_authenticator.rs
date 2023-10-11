use crate::error::{Error, VResult};
use crate::{authenticator::Authenticator, message::OpenIdConnectTokenResponse};
use async_trait::async_trait;
use reqwest::{StatusCode, Url};

pub(crate) struct ResourceOwnerPasswordGrantAuthenticator {
    client_id: String,
    user_name: String,
    password: String,
    token_url: Url,
}

impl ResourceOwnerPasswordGrantAuthenticator {
    pub fn new(client_id: &str, user_name: &str, password: &str, token_url: &Url) -> Self {
        Self {
            client_id: client_id.to_string(),
            user_name: user_name.to_string(),
            password: password.to_string(),
            token_url: token_url.clone(),
        }
    }
}

#[async_trait]
impl Authenticator for ResourceOwnerPasswordGrantAuthenticator {
    async fn get_token(self) -> VResult<String> {
        let params = [
            ("client_id", self.client_id.as_str()),
            ("username", self.user_name.as_str()),
            ("password", self.password.as_str()),
            ("grant_type", "password"),
        ];
        let client = reqwest::Client::new();
        let token_response = client.post(self.token_url).form(&params).send().await?;

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

    #[tokio::test]
    async fn get_token_returns_token() {
        let token_url: Url = dotenv::var("TOKEN_URL")
            .expect("No TOKEN_URL environment variable set to be used in the integration tests")
            .parse()
            .expect("Failed to parse TOKEN_URL environment variable");
        let client_id = dotenv::var("VAAS_CLIENT_ID")
            .expect("No CLIENT_ID environment variable set to be used in the integration tests");
        let user_name = dotenv::var("VAAS_USER_NAME").expect(
            "No VAAS_USER_NAME environment variable set to be used in the integration tests",
        );
        let password = dotenv::var("VAAS_PASSWORD").expect(
            "No VAAS_PASSWORD environment variable set to be used in the integration tests",
        );
        let authenticator = ResourceOwnerPasswordGrantAuthenticator::new(
            client_id.as_str(),
            user_name.as_str(),
            password.as_str(),
            &token_url,
        );
        let token = authenticator.get_token().await;

        assert!(token.is_ok())
    }
}
