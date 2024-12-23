//! The `Connection` module provides all functionality to create an active connection to the verdict backend.

use crate::error::{Error, VResult};
use crate::message::{
    MessageType, UploadUrl, Verdict, VerdictRequest, VerdictRequestFile, VerdictRequestForStream,
    VerdictRequestForUrl, VerdictResponse,
};
use crate::options::Options;
use crate::sha256::Sha256;
use crate::vaas_verdict::VaasVerdict;
use crate::response_broker::ResponseBroker;
use crate::CancellationToken;
use bytes::Bytes;
use futures::future::join_all;
use futures_util::FutureExt;
use reqwest::{Body, Response, Url, Version};
use serde::Serialize;
use std::convert::TryFrom;
use std::future::Future;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use websockets::{Frame, WebSocketError, WebSocketReadHalf, WebSocketWriteHalf};

type ThreadHandle = JoinHandle<Result<(), Error>>;
type WebSocketWriter = Arc<Mutex<WebSocketWriteHalf>>;
type VaasResponseBroker = ResponseBroker<VerdictResponse, Error>;

/// Active connection to the verdict server.
#[derive(Debug)]
pub struct Connection {
    ws_writer: WebSocketWriter,
    session_id: String,
    reader_thread: ThreadHandle,
    keep_alive_thread: Option<ThreadHandle>,
    responses: Arc<VaasResponseBroker>,
    options: Options,
}

impl Connection {
    pub(crate) async fn start(
        ws_writer: WebSocketWriteHalf,
        ws_reader: WebSocketReadHalf,
        session_id: String,
        options: Options,
    ) -> Self {
        let ws_writer = Arc::new(Mutex::new(ws_writer));
        let responses = Arc::new(ResponseBroker::new());

        let reader_loop = Connection::start_reader_loop(ws_reader, responses.clone()).await;
        let keep_alive_loop = Self::start_keep_alive(&options, &ws_writer, responses.clone()).await;

        Connection {
            ws_writer,
            session_id,
            reader_thread: reader_loop,
            keep_alive_thread: keep_alive_loop,
            responses,
            options,
        }
    }

    async fn start_keep_alive(
        options: &Options,
        ws_writer: &Arc<Mutex<WebSocketWriteHalf>>,
        responses: Arc<VaasResponseBroker>,
    ) -> Option<ThreadHandle> {
        if !options.keep_alive {
            return None;
        }
        Some(
            Connection::keep_alive_loop(ws_writer.clone(), options.keep_alive_delay_ms, responses)
                .await,
        )
    }

    /// Request a verdict for a file behind a URL.
    pub async fn for_url(&self, url: &Url, ct: &CancellationToken) -> VResult<VaasVerdict> {
        let request = VerdictRequestForUrl::new(
            url,
            self.session_id.clone(),
            self.options.use_cache,
            self.options.use_hash_lookup,
        );
        let response =
            self.for_request(request, ct).await?;
        VaasVerdict::try_from(response)
    }

    /// Request a verdict for files behind a list of URLs.
    pub async fn for_url_list(
        &self,
        url_list: &[Url],
        ct: &CancellationToken,
    ) -> Vec<VResult<VaasVerdict>> {
        let req = url_list
            .iter()
            .map(|url| self.for_url(url, ct))
            .collect::<Vec<_>>();

        join_all(req).await
    }

    /// Request a verdict for a SHA256 file hash.
    pub async fn for_sha256(
        &self,
        sha256: &Sha256,
        ct: &CancellationToken,
    ) -> VResult<VaasVerdict> {
        let request = VerdictRequestFile::new(
            sha256,
            self.session_id.clone(),
            self.options.use_cache,
            self.options.use_hash_lookup,
        );
        let response =
            self.for_request(request, ct).await?;
        VaasVerdict::try_from(response)
    }

    /// Request a verdict for a SHA256 file hash.
    pub async fn for_stream<S>(
        &self,
        stream: S,
        content_length: usize,
        ct: &CancellationToken,
    ) -> VResult<VaasVerdict>
    where
        S: futures_util::stream::TryStream + Send + Sync + 'static,
        S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        Bytes: From<S::Ok>,
    {
        let request = VerdictRequestForStream::new(
            self.session_id.clone(),
            self.options.use_cache,
            self.options.use_hash_lookup,
        );
        let guid = request.guid.to_string();

        let response =
            self.for_request(request, ct).await?;

        let verdict = Verdict::try_from(&response)?;

        match verdict {
            Verdict::Unknown { upload_url } => {
                self.handle_unknown_stream(
                    stream,
                    content_length,
                    guid,
                    response,
                    upload_url,
                    ct,
                )
                .await
            }
            _ => Err(Error::Cancelled),
        }
    }

    /// Request verdicts for a list of SHA256 file hashes.
    /// The order of the output is the same order as the provided input.
    pub async fn for_sha256_list(
        &self,
        sha256_list: &[Sha256],
        ct: &CancellationToken,
    ) -> Vec<VResult<VaasVerdict>> {
        let req = sha256_list
            .iter()
            .map(|sha256| self.for_sha256(sha256, ct))
            .collect::<Vec<_>>();
        join_all(req).await
    }

    /// Request a verdict for a file.
    pub async fn for_file(&self, file: &Path, ct: &CancellationToken) -> VResult<VaasVerdict> {
        let buf = tokio::fs::read(file).await?;
        self.for_buf(buf, ct).await
    }

    /// Request a verdict for a buffer.
    pub async fn for_buf(&self, buf: Vec<u8>, ct: &CancellationToken) -> VResult<VaasVerdict> {
        let sha256 = Sha256::from(buf.as_slice());
        let request = VerdictRequestFile::new(
            &sha256,
            self.session_id.clone(),
            self.options.use_cache,
            self.options.use_hash_lookup,
        );
        let guid = request.guid.to_string();

        let response =
            self.for_request(request, ct).await?;

        let verdict = Verdict::try_from(&response)?;
        match verdict {
            Verdict::Unknown { upload_url } => {
                self.handle_unknown(buf, guid, response, upload_url, ct).await
            }
            _ => VaasVerdict::try_from(response),
        }
    }

    async fn handle_unknown(
        &self,
        buf: Vec<u8>,
        guid: String,
        response: VerdictResponse,
        upload_url: UploadUrl,
        ct: &CancellationToken,
    ) -> Result<VaasVerdict, Error> {
        let auth_token = response
            .upload_token
            .as_ref()
            .ok_or(Error::MissingAuthToken)?;
        let resp = self.wait_for_response(guid, ct);
        let response = upload_buf(buf, upload_url, auth_token).await?;

        Self::ensure_http_success(response).await?;
        VaasVerdict::try_from(resp.await?)
    }

    async fn handle_unknown_stream<S>(
        &self,
        stream: S,
        content_length: usize,
        guid: String,
        response: VerdictResponse,
        upload_url: UploadUrl,
        ct: &CancellationToken,
    ) -> Result<VaasVerdict, Error>
    where
        S: futures_util::stream::TryStream + Send + Sync + 'static,
        S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        Bytes: From<S::Ok>,
    {
        let auth_token = response
            .upload_token
            .as_ref()
            .ok_or(Error::MissingAuthToken)?;
        let resp = self.wait_for_response(guid, ct);
        let response = upload_stream(stream, content_length, upload_url, auth_token).await?;

        Self::ensure_http_success(response).await?;
        VaasVerdict::try_from(resp.await?)
    }

    async fn ensure_http_success(response: Response) -> Result<(), Error> {
        if response.status() != 200 {
            return Err(Error::FailedUploadFile(
                response.status(),
                response
                    .text()
                    .await
                    .unwrap_or("failed to get payload".to_string()),
            ));
        }
        Ok(())
    }

    /// Request a verdict for a list of files.
    /// The order of the output is the same order as the provided input.
    pub async fn for_file_list(
        &self,
        files: &[PathBuf],
        ct: &CancellationToken,
    ) -> Vec<VResult<VaasVerdict>> {
        let req = files.iter().map(|f| self.for_file(f, ct));
        join_all(req).await
    }

    async fn for_request<T: VerdictRequest + Serialize>(
        &self,
        request: T,
        ct: &CancellationToken,
    ) -> VResult<VerdictResponse> {
        let guid = request.guid().to_string();
        let response = self.wait_for_response(guid, ct);
        self.ws_writer.lock().await.send_text(request.to_json()?).await?;
        response.await
    }

    fn wait_for_response(
        &self,
        guid: String,
        ct: &CancellationToken,
    ) -> impl Future<Output = VResult<VerdictResponse>> {
        let response = self.responses.get_response(guid);
        timeout(ct.duration, response).map(|outer| outer?)
    }

    // TODO: Move this functionality into the underlying websocket library.
    async fn keep_alive_loop(
        ws_writer: WebSocketWriter,
        keep_alive_delay_ms: u64,
        responses: Arc<VaasResponseBroker>,
    ) -> ThreadHandle {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(keep_alive_delay_ms)).await;
                if let Err(e) = ws_writer.lock().await.send_ping(None).await {
                    responses.set_all_responses(Err(e.into()));
                }
                if let Err(e) = ws_writer.lock().await.flush().await {
                    responses.set_all_responses(Err(e.into()));
                }
            }
        })
    }

    async fn start_reader_loop(
        mut ws_reader: WebSocketReadHalf,
        responses: Arc<VaasResponseBroker>,
    ) -> ThreadHandle {
        tokio::spawn(async move {
            loop {
                let frame = ws_reader.receive().await;
                match Self::parse_frame(frame) {
                    Ok(MessageType::VerdictResponse(vr)) => {
                        responses.set_response(&vr.guid.clone(), Ok(vr));
                    }
                    Ok(MessageType::Close) => {
                        responses.set_all_responses(Err(Error::ConnectionClosed));
                    }
                    Err(e) => {
                        responses.set_all_responses(Err(e));
                    }
                    _ => {}
                }
            }
        })
    }

    fn parse_frame(frame: Result<Frame, WebSocketError>) -> VResult<MessageType> {
        match frame {
            Ok(Frame::Text { payload: json, .. }) => MessageType::try_from(&json),
            Ok(Frame::Ping { .. }) => Ok(MessageType::Ping),
            Ok(Frame::Pong { .. }) => Ok(MessageType::Pong),
            Ok(Frame::Close { .. }) => Ok(MessageType::Close),
            Ok(_) => Err(Error::InvalidFrame),
            Err(e) => Err(e.into()),
        }
    }
}

async fn upload_buf(buf: Vec<u8>, upload_url: UploadUrl, auth_token: &str) -> VResult<Response> {
    let content_length = buf.len();
    upload_internal(buf, content_length, upload_url, auth_token).await
}

async fn upload_stream<S>(
    stream: S,
    content_length: usize,
    upload_url: UploadUrl,
    auth_token: &str,
) -> VResult<Response>
where
    S: futures_util::stream::TryStream + Send + Sync + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    Bytes: From<S::Ok>,
{
    let body = Body::wrap_stream(stream);
    upload_internal(body, content_length, upload_url, auth_token).await
}

async fn upload_internal<T: Into<Body>>(
    body: T,
    content_length: usize,
    upload_url: UploadUrl,
    auth_token: &str,
) -> VResult<Response> {
    let client = reqwest::Client::new();
    let response = client
        .put(upload_url.deref())
        .version(Version::HTTP_11)
        .body(body)
        .header("Authorization", auth_token)
        .header("Content-Length", content_length)
        .send()
        .await?;

    Ok(response)
}

impl Drop for Connection {
    fn drop(&mut self) {
        // Abort the spawned threads in the case that the connection
        // is dropped.
        // If the threads are not aborted, they will live past the connection
        // lifetime which is not what the user expects.
        // Abort is only safe if we never block or wait for mutex in the thread.
        // If we had a mutex in the thread blocked and aborted the thread, we would deadlock.
        self.reader_thread.abort();
        if self.keep_alive_thread.is_some() {
            self.keep_alive_thread.as_ref().unwrap().abort();
        }
    }
}
