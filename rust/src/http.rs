use crate::authentication::Authenticator;
use crate::error::VResult;
use reqwest::{Request, RequestBuilder};
use tokio::sync::Mutex;
use url::Url;

const USER_AGENT: &str = concat!("vaas/rust/", env!("CARGO_PKG_VERSION"));

/// Retrieve a new HTTP client pre-configured for VaaS usage.
/// Returns an error if the HTTP backend cannot be initialized.
pub fn new_http_client() -> VResult<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .http1_only()
        .build()?)
}

pub async fn send_get_request(
    client: &reqwest::Client,
    authenticator: &Mutex<Box<dyn Authenticator>>,
    url: Url,
) -> VResult<reqwest::Response> {
    let request = Request::new(reqwest::Method::GET, url);
    let client = client.clone(); // internally an ARC, so cheap clone
    send_request(authenticator, RequestBuilder::from_parts(client, request)).await
}

pub async fn send_post_request(
    client: &reqwest::Client,
    authenticator: &Mutex<Box<dyn Authenticator>>,
    body: reqwest::Body,
    content_length: u64,
    url: Url,
) -> VResult<reqwest::Response> {
    let request = Request::new(reqwest::Method::POST, url);
    let client = client.clone();
    send_request(
        authenticator,
        RequestBuilder::from_parts(client, request)
            .body(body)
            .header(reqwest::header::CONTENT_LENGTH, content_length),
    )
    .await
}

pub async fn send_json_request<T: serde::Serialize>(
    client: &reqwest::Client,
    authenticator: &Mutex<Box<dyn Authenticator>>,
    body: &T,
    url: Url,
) -> VResult<reqwest::Response> {
    let request = Request::new(reqwest::Method::POST, url);
    let client = client.clone();
    send_request(
        authenticator,
        RequestBuilder::from_parts(client, request).json(body),
    )
    .await
}

async fn send_request(
    authenticator: &Mutex<Box<dyn Authenticator>>,
    request: RequestBuilder,
) -> VResult<reqwest::Response> {
    let token = {
        let mut authenticator = authenticator.lock().await;
        authenticator.get_token().await?
    };
    let response = request.bearer_auth(token).send().await?;
    Ok(response)
}
