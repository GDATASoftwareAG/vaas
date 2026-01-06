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
use bytes::Bytes;
use reqwest::{Body, StatusCode, Url};
use std::path::Path;
use tokio::sync::Mutex;
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
            &(self.vaas_url.to_string() + &format!("/files/{sha256}/report")),
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
        Err(Error::Cancelled)
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
            &(self.vaas_url.to_string() + "/files"),
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
        let url_analysis = Url::parse(&(self.vaas_url.to_string() + "/urls"))?;
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
        let report_url = Url::parse(
            &(self.vaas_url.to_string() + &format!("/urls/{}/report", analysis_started.id)),
        )?;

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
        Err(Error::Cancelled)
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
