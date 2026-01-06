use crate::authentication::authenticator::DEFAULT_TOKEN_URL;
use crate::error::{Error, VResult};
use crate::http;
use crate::message::token_response::TokenResponse;
use reqwest::{StatusCode, Url};
use serde::Serialize;
use std::fmt::Debug;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct TokenReceiver {
    client: reqwest::Client,
    token_url: Url,
    last_token: Option<CachedAccessToken>,
}

impl TokenReceiver {
    pub fn try_new() -> VResult<Self> {
        let token_url = Url::parse(DEFAULT_TOKEN_URL)?;
        Self::try_new_with_token_url(token_url)
    }

    pub fn try_new_with_token_url(token_url: Url) -> VResult<Self> {
        Ok(Self {
            client: http::new_http_client()?,
            token_url,
            last_token: None,
        })
    }

    /// Set the token URL to be used for authentication.
    pub fn set_token_url(mut self, token_url: Url) -> Self {
        self.token_url = token_url;
        self
    }

    async fn get_fresh_token<T: Serialize>(&mut self, form: &T) -> VResult<TokenResponse> {
        let token_response = self
            .client
            .post(self.token_url.clone())
            .form(form)
            .send()
            .await?;

        match token_response.status() {
            StatusCode::OK => {
                let token_response: TokenResponse = token_response.json().await?;
                Ok(token_response)
            }
            status => Err(Error::AuthorizationFailed(
                token_response.text().await.unwrap_or_default(),
            )),
        }
    }

    pub async fn get_token<T: Serialize + Sized>(&mut self, form: &T) -> VResult<String> {
        if let Some(cached_token) = self.last_token.as_ref()
            && cached_token.valid_until <= SystemTime::now()
        {
            Ok(cached_token.access_token.clone())
        } else {
            let new_token = self.get_fresh_token(form).await?;
            let valid_until = SystemTime::now() + Duration::from_secs(new_token.expires_in);
            let cached_token = CachedAccessToken {
                access_token: new_token.access_token.clone(),
                valid_until,
            };
            self.last_token = Some(cached_token);
            Ok(new_token.access_token)
        }
    }
}

#[derive(Clone)]
struct CachedAccessToken {
    access_token: String,
    valid_until: SystemTime,
}

impl Debug for CachedAccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedAccessToken")
            .field("access_token", &"<redacted>")
            .field("valid_until", &self.valid_until)
            .finish()
    }
}
