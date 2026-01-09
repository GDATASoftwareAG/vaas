//! The `Vaas` module provides all needed functions to check a hash or file for malicious content.

use crate::authentication::Authenticator;
use crate::builder::Builder;
use crate::error::{Error, VResult};
use crate::message::analysis::{FileAnalysisStarted, UrlAnalysisRequest, UrlAnalysisStarted};
use crate::message::problem::ProblemDetails;
use crate::message::report::{FileReport, UrlReport};
use crate::message::verdict::Verdict;
use crate::options::{ForFileOptions, ForSha256Options, ForStreamOptions, ForUrlOptions};
use crate::{CancellationToken, Sha256, VaasVerdict, http};
use reqwest::{Body, StatusCode, Url};
use std::path::Path;
use tokio::sync::Mutex;
use tokio_util::bytes::Bytes;
use tokio_util::io::ReaderStream;

/// Provides all functionality needed to check a hash or file for malicious content.
#[derive(Debug)]
pub struct Vaas {
    authenticator: Mutex<Box<dyn Authenticator>>,
    vaas_url: Url,
    client: reqwest::Client,
}

impl Vaas {
    /// Create a new [Builder] instance to configure the `Vaas` instance.
    /// Equivalent to `Builder::new(authenticator)`
    pub fn builder(authenticator: impl Authenticator + 'static) -> Builder {
        Builder::new(authenticator)
    }

    pub(crate) fn try_new(authenticator: Box<dyn Authenticator>, vaas_url: Url) -> VResult<Self> {
        Ok(Self {
            authenticator: Mutex::new(authenticator),
            vaas_url,
            client: http::new_http_client()?,
        })
    }

    /// Request a verdict for a SHA256 file hash.
    pub async fn for_sha256(
        &self,
        sha256: &Sha256,
        options: ForSha256Options,
        ct: &CancellationToken,
    ) -> VResult<VaasVerdict> {
        let use_cache = if options.use_cache { "true" } else { "false" };
        let use_hash_lookup = if options.use_hash_lookup {
            "true"
        } else {
            "false"
        };
        let report_uri = Url::parse_with_params(
            self.vaas_url
                .join(&format!("/files/{sha256}/report"))?
                .as_str(),
            &[("useCache", use_cache), ("useHashLookup", use_hash_lookup)],
        )?;

        while !ct.is_cancelled() {
            let request_future =
                http::send_get_request(&self.client, &self.authenticator, report_uri.clone());
            let response = tokio::select! {
                response = request_future => response,
                _ = ct.cancelled() => break,
            }?;

            let report: FileReport = match response.status() {
                StatusCode::OK => Ok(response.json().await?),
                StatusCode::ACCEPTED => continue,
                StatusCode::UNAUTHORIZED => Err(Error::Unauthorized(response.text().await?)),
                _ => Err(parse_vaas_error(response).await),
            }?;
            return Ok(report.into());
        }
        Err(Error::Canceled)
    }

    /// Request a verdict for a file.
    pub async fn for_file(
        &self,
        file: &Path,
        options: ForFileOptions,
        ct: &CancellationToken,
    ) -> VResult<VaasVerdict> {
        if options.use_cache || options.use_hash_lookup {
            let sha256 = Sha256::hash_file(file)?;
            let verdict = self.for_sha256(&sha256, options.clone().into(), ct).await;
            if let Ok(verdict) = verdict
                && verdict.verdict != Verdict::Unknown
                && verdict.detection.is_some()
                && verdict.file_type.is_some()
                && verdict.mime_type.is_some()
            {
                return Ok(verdict);
            }
        }

        let file = tokio::fs::File::open(&file).await?;
        let metadata = file.metadata().await?;
        let stream = ReaderStream::new(file);
        self.for_stream(stream, metadata.len(), options.into(), ct)
            .await
    }

    /// Request a verdict for a byte stream
    pub async fn for_stream<S>(
        &self,
        stream: S,
        content_length: u64,
        options: ForStreamOptions,
        ct: &CancellationToken,
    ) -> VResult<VaasVerdict>
    where
        S: futures_util::stream::TryStream + Send + Sync + 'static,
        S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        Bytes: From<S::Ok>,
    {
        let use_hash_lookup = if options.use_hash_lookup {
            "true"
        } else {
            "false"
        };
        let upload_url = Url::parse_with_params(
            self.vaas_url.join("/files")?.as_str(),
            &[("useCache", "true"), ("useHashLookup", use_hash_lookup)],
        )?;

        let body = Body::wrap_stream(stream);
        let upload_response = http::send_post_request(
            &self.client,
            &self.authenticator,
            body,
            content_length,
            upload_url,
        )
        .await?;

        let analysis_started: FileAnalysisStarted = match upload_response.status() {
            StatusCode::OK => Ok(upload_response.json().await?),
            _ => Err(parse_vaas_error(upload_response).await),
        }?;

        self.for_sha256(&analysis_started.sha256, options.into(), ct)
            .await
    }

    /// Request a verdict for a buffer.
    pub async fn for_buf(
        &self,
        buf: Vec<u8>,
        options: ForStreamOptions,
        ct: &CancellationToken,
    ) -> VResult<VaasVerdict> {
        let len = buf.len();
        let stream = futures::stream::once(async move { Ok::<_, std::io::Error>(buf) });
        self.for_stream(stream, len as u64, options, ct).await
    }

    /// Request a verdict for a file behind a URL.
    pub async fn for_url(
        &self,
        url: &Url,
        options: ForUrlOptions,
        ct: &CancellationToken,
    ) -> VResult<VaasVerdict> {
        let url_analysis = self.vaas_url.join("/urls")?;
        let request = UrlAnalysisRequest {
            url,
            use_hash_lookup: options.use_hash_lookup,
        };
        let response =
            http::send_json_request(&self.client, &self.authenticator, &request, url_analysis)
                .await?;
        let analysis_started: UrlAnalysisStarted = match response.status() {
            StatusCode::OK => Ok(response.json().await?),
            _ => Err(parse_vaas_error(response).await),
        }?;
        let report_url = self
            .vaas_url
            .join(&format!("/urls/{}/report", analysis_started.id))?;

        while !ct.is_cancelled() {
            let request_future =
                http::send_get_request(&self.client, &self.authenticator, report_url.clone());
            let response = tokio::select! {
                response = request_future => response,
                _ = ct.cancelled() => break,
            }?;

            let url_report: UrlReport = match response.status() {
                StatusCode::OK => Ok(response.json().await?),
                StatusCode::ACCEPTED => continue,
                StatusCode::UNAUTHORIZED => Err(Error::Unauthorized(response.text().await?)),
                _ => Err(parse_vaas_error(response).await),
            }?;
            return Ok(url_report.into());
        }
        Err(Error::Canceled)
    }
}

async fn parse_vaas_error(response: reqwest::Response) -> Error {
    let status = response.status();
    if let Ok(problem_details) = response.json().await {
        Error::ServerError(problem_details)
    } else {
        Error::ServerError(ProblemDetails {
            r#type: None,
            details: Some("Unknown server error - ".to_string() + &status.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::authentication::ClientCredentials;
    use crate::error::{Error, VResult};
    use crate::message::problem::ProblemDetails;
    use crate::message::report::FileReport;
    use crate::message::verdict::Verdict;
    use crate::options::ForSha256Options;
    use crate::{Sha256, Vaas};
    use mockito::{Matcher, ServerGuard};
    use serde::Serialize;
    use tokio_util::sync::CancellationToken;
    use url::Url;

    const MOCK_USERNAME: &str = "vaas-user";
    const MOCK_PASSWORD: &str = "foobar";
    const MOCK_CLIENT: &str = "vaas";
    const MOCK_CLIENT_SECRET: &str = "qwertz";
    const TEST_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    struct AuthenticationMock {
        pub auth_url: Url,
        pub server_guard: ServerGuard,
    }

    struct ClientCredentialsMock {
        authenticator: ClientCredentials,
        server_guard: ServerGuard,
    }

    struct VaasMock {
        vaas: Vaas,
        vaas_server: ServerGuard,
        auth_server: ServerGuard,
    }

    async fn mock_auth_server() -> AuthenticationMock {
        let mut server = mockito::Server::new_async().await;
        let auth_url = Url::parse(&(server.url() + "/authorize")).unwrap();
        server
            .mock("POST", "/authorize")
            .with_body(r#"{"access_token": "mock-token", "expires_in": 1}"#)
            .expect_at_least(0)
            .create_async()
            .await;
        AuthenticationMock {
            auth_url,
            server_guard: server,
        }
    }

    async fn mock_client_credentials() -> ClientCredentialsMock {
        let auth_mock = mock_auth_server().await;
        let client_credentials =
            ClientCredentials::try_new(MOCK_CLIENT.to_string(), MOCK_CLIENT_SECRET.to_string())
                .unwrap()
                .with_token_url(auth_mock.auth_url);
        ClientCredentialsMock {
            authenticator: client_credentials,
            server_guard: auth_mock.server_guard,
        }
    }

    async fn mock_vaas() -> VaasMock {
        let auth_mock = mock_client_credentials().await;
        let vaas_server = mockito::Server::new_async().await;
        let vaas_url = Url::parse(&vaas_server.url()).unwrap();
        let vaas = Vaas::builder(auth_mock.authenticator)
            .url(vaas_url)
            .build()
            .unwrap();
        VaasMock {
            vaas,
            vaas_server,
            auth_server: auth_mock.server_guard,
        }
    }

    fn json<T: Serialize>(value: T) -> String {
        serde_json::to_string_pretty(&value).unwrap()
    }

    #[tokio::test]
    async fn test_for_sha256_sends_options() -> VResult<()> {
        let mut vaas_mock = mock_vaas().await;
        let sha256 = Sha256::try_from(TEST_SHA256)?;
        let mock = vaas_mock
            .vaas_server
            .mock("GET", format!("/files/{TEST_SHA256}/report").as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("useCache".into(), "true".into()),
                Matcher::UrlEncoded("useHashLookup".into(), "true".into()),
            ]))
            .with_body(json(FileReport {
                sha256: sha256.clone(),
                verdict: Verdict::Malicious,
                detection: None,
                file_type: None,
                mime_type: None,
            }))
            .create_async()
            .await;

        vaas_mock
            .vaas
            .for_sha256(
                &sha256,
                ForSha256Options::default(),
                &CancellationToken::new(),
            )
            .await?;

        mock.assert_async().await;
        Ok(())
    }

    #[tokio::test]
    async fn test_for_sha256_if_client_error_returns_error() -> VResult<()> {
        let mut vaas_mock = mock_vaas().await;
        let sha256 = Sha256::try_from(TEST_SHA256)?;
        let mock = vaas_mock
            .vaas_server
            .mock("GET", format!("/files/{TEST_SHA256}/report").as_str())
            .match_query(Matcher::Any)
            .with_body(json(ProblemDetails {
                r#type: Some("VaasClientException".to_string()),
                details: Some("Mocked client-side error".to_string()),
            }))
            .with_status(reqwest::StatusCode::BAD_REQUEST.as_u16() as usize)
            .create_async()
            .await;

        let maybe_err = vaas_mock
            .vaas
            .for_sha256(
                &sha256,
                ForSha256Options::default(),
                &CancellationToken::new(),
            )
            .await;

        mock.assert_async().await;
        assert!(
            matches!(maybe_err, Err(Error::ServerError(_))),
            "Expected ServerError, got {maybe_err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_for_sha256_if_server_error_returns_error() -> VResult<()> {
        let mut vaas_mock = mock_vaas().await;
        let sha256 = Sha256::try_from(TEST_SHA256)?;
        let mock = vaas_mock
            .vaas_server
            .mock("GET", format!("/files/{TEST_SHA256}/report").as_str())
            .match_query(Matcher::Any)
            .with_body(json(ProblemDetails {
                r#type: Some("VaasServerException".to_string()),
                details: Some("Mocked server-side error".to_string()),
            }))
            .with_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR.as_u16() as usize)
            .create_async()
            .await;

        let maybe_err = vaas_mock
            .vaas
            .for_sha256(
                &sha256,
                ForSha256Options::default(),
                &CancellationToken::new(),
            )
            .await;

        mock.assert_async().await;
        assert!(
            matches!(maybe_err, Err(Error::ServerError(_))),
            "Expected ServerError, got {maybe_err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_for_sha256_if_authenticator_error_returns_error() -> VResult<()> {
        let mut vaas_mock = mock_vaas().await;
        let sha256 = Sha256::try_from(TEST_SHA256)?;
        // remove existing auth mocks
        vaas_mock.auth_server.reset();
        let mock = vaas_mock
            .auth_server
            .mock("POST", "/authorize")
            .with_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR.as_u16() as usize)
            .create_async()
            .await;

        let maybe_err = vaas_mock
            .vaas
            .for_sha256(
                &sha256,
                ForSha256Options::default(),
                &CancellationToken::new(),
            )
            .await;

        mock.assert_async().await;
        assert!(
            matches!(maybe_err, Err(Error::AuthorizationFailed(_))),
            "expected AuthorizationFailed, got {maybe_err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_for_sha256_if_401_error_returns_error() -> VResult<()> {
        let mut vaas_mock = mock_vaas().await;
        let sha256 = Sha256::try_from(TEST_SHA256)?;
        let mock = vaas_mock
            .vaas_server
            .mock("GET", format!("/files/{TEST_SHA256}/report").as_str())
            .match_query(Matcher::Any)
            .with_body("invalid token")
            .with_status(reqwest::StatusCode::UNAUTHORIZED.as_u16() as usize)
            .create_async()
            .await;

        let maybe_err = vaas_mock
            .vaas
            .for_sha256(
                &sha256,
                ForSha256Options::default(),
                &CancellationToken::new(),
            )
            .await;

        mock.assert_async().await;
        assert!(
            matches!(maybe_err, Err(Error::Unauthorized(_))),
            "expected unauthorized, got {maybe_err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_for_sha256_if_canceled_returns_error() -> VResult<()> {
        let vaas_mock = mock_vaas().await;
        let sha256 = Sha256::try_from(TEST_SHA256)?;
        let ct = CancellationToken::new();
        ct.cancel();

        let maybe_err = vaas_mock
            .vaas
            .for_sha256(&sha256, ForSha256Options::default(), &ct)
            .await;

        assert!(
            matches!(maybe_err, Err(Error::Canceled)),
            "expected Canceled, got {maybe_err:?}"
        );
        Ok(())
    }
}
