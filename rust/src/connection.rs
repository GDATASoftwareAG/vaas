//! The `Connection` module provides all functionality to create an active connection to the verdict backend.

use crate::error::{Error, VResult};
use crate::message::{MessageType, UploadUrl, Verdict, VerdictRequest, VerdictResponse};
use crate::options::Options;
use crate::sha256::Sha256;
use crate::CancellationToken;
use futures::future::join_all;
use std::convert::TryFrom;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use websockets::{Frame, WebSocketError, WebSocketReadHalf, WebSocketWriteHalf};

type ThreadHandle = JoinHandle<Result<(), Error>>;
type WebSocketWriter = Arc<Mutex<WebSocketWriteHalf>>;
type ResultChannelRx = Mutex<Receiver<VResult<VerdictResponse>>>;
type ResultChannelTx = Sender<VResult<VerdictResponse>>;

/// Active connection to the verdict server.
pub struct Connection {
    ws_writer: WebSocketWriter,
    session_id: String,
    reader_thread: ThreadHandle,
    keep_alive_thread: Option<ThreadHandle>,
    result_channel: ResultChannelRx,
}

impl Connection {
    pub(crate) async fn start(
        ws_writer: WebSocketWriteHalf,
        ws_reader: WebSocketReadHalf,
        session_id: String,
        options: Options,
    ) -> Self {
        let ws_writer = Arc::new(Mutex::new(ws_writer));
        let (tx, rx) = tokio::sync::broadcast::channel(5);

        let reader_loop = Connection::start_reader_loop(ws_reader, tx.clone()).await;
        let keep_alive_loop = Self::start_keep_alive(&options, &ws_writer, tx.clone()).await;

        Connection {
            ws_writer,
            session_id,
            reader_thread: reader_loop,
            keep_alive_thread: keep_alive_loop,
            result_channel: Mutex::new(rx),
        }
    }

    async fn start_keep_alive(
        options: &Options,
        ws_writer: &Arc<Mutex<WebSocketWriteHalf>>,
        tx: ResultChannelTx,
    ) -> Option<ThreadHandle> {
        if options.keep_alive {
            Some(
                Connection::keep_alive_loop(ws_writer.clone(), options.keep_alive_delay_ms, tx)
                    .await,
            )
        } else {
            None
        }
    }

    /// Request a verdict for a SHA256 file hash.
    pub async fn for_sha256(&self, sha256: &Sha256, ct: &CancellationToken) -> VResult<Verdict> {
        let request = VerdictRequest::new(sha256, self.session_id.clone());
        let response = self.for_request(request, ct).await?;
        Ok(Verdict::try_from(&response)?)
    }

    /// Request verdicts for a list of SHA256 file hashes.
    /// The order of the output is the same order as the provided input.
    pub async fn for_sha256_list(
        &self,
        sha256_list: &[Sha256],
        ct: &CancellationToken,
    ) -> Vec<VResult<Verdict>> {
        let req = sha256_list
            .iter()
            .map(|sha256| self.for_sha256(sha256, ct))
            .collect::<Vec<_>>();
        join_all(req).await
    }

    /// Request a verdict for a file.
    pub async fn for_file(&self, file: &Path, ct: &CancellationToken) -> VResult<Verdict> {
        let sha256 = Sha256::try_from(file)?;
        let request = VerdictRequest::new(&sha256, self.session_id.clone());
        let guid = request.guid().to_string();

        let response = self.for_request(request, ct).await?;
        let verdict = Verdict::try_from(&response)?;
        match verdict {
            Verdict::Unknown { upload_url } => {
                self.handle_unknown(file, ct, &guid, response, upload_url)
                    .await
            }
            _ => Ok(verdict),
        }
    }

    async fn handle_unknown(
        &self,
        file: &Path,
        ct: &CancellationToken,
        guid: &String,
        response: VerdictResponse,
        upload_url: UploadUrl,
    ) -> Result<Verdict, Error> {
        let auth_token = response
            .upload_token
            .as_ref()
            .ok_or(Error::MissingAuthToken)?;
        let response = upload_file(file, upload_url, auth_token).await?;

        if response.status() != 200 {
            return Err(Error::FailedUploadFile(response.status()));
        }

        let resp = self.wait_for_response(&guid, ct).await?;
        Ok(Verdict::try_from(&resp)?)
    }

    /// Request a verdict for a list of files.
    /// The order of the output is the same order as the provided input.
    pub async fn for_file_list(
        &self,
        files: &[PathBuf],
        ct: &CancellationToken,
    ) -> Vec<VResult<Verdict>> {
        let req = files.iter().map(|f| self.for_file(f, ct));
        join_all(req).await
    }

    async fn for_request(
        &self,
        request: VerdictRequest,
        ct: &CancellationToken,
    ) -> VResult<VerdictResponse> {
        let guid = request.guid().to_string();

        self.ws_writer
            .lock()
            .await
            .send_text(request.to_json()?)
            .await?;

        self.wait_for_response(&guid, ct).await
    }

    // TODO Refactor this function.
    // Idea: Do not loop, but get a result from the channel.
    async fn wait_for_response(
        &self,
        guid: &str,
        ct: &CancellationToken,
    ) -> VResult<VerdictResponse> {
        loop {
            let timeout = timeout(ct.duration, self.result_channel.lock().await.recv()).await??;

            match timeout {
                Ok(vr) => {
                    if vr.guid == guid {
                        break Ok(vr);
                    }
                }
                Err(e) => break Err(e),
            }
        }
    }

    // TODO: Move this functionality into the underlying websocket library.
    async fn keep_alive_loop(
        ws_writer: WebSocketWriter,
        keep_alive_delay_ms: u64,
        result_channel: ResultChannelTx,
    ) -> ThreadHandle {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(keep_alive_delay_ms)).await;
                if let Err(e) = ws_writer.lock().await.send_ping(None).await {
                    result_channel.send(Err(e.into()))?;
                }
                if let Err(e) = ws_writer.lock().await.flush().await {
                    result_channel.send(Err(e.into()))?;
                }
            }
        })
    }

    async fn start_reader_loop(
        mut ws_reader: WebSocketReadHalf,
        result_channel: ResultChannelTx,
    ) -> ThreadHandle {
        tokio::spawn(async move {
            loop {
                let frame = ws_reader.receive().await;
                match Self::parse_frame(frame) {
                    Ok(MessageType::VerdictResponse(vr)) => {
                        result_channel.send(Ok(vr))?;
                    }
                    Err(e) => {
                        result_channel.send(Err(e))?;
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

async fn upload_file(
    file: &Path,
    upload_url: UploadUrl,
    auth_token: &str,
) -> VResult<reqwest::Response> {
    let body = tokio::fs::read(&file).await?;
    let client = reqwest::Client::new();
    let response = client
        .put(upload_url.deref())
        .body(body)
        .header("Authorization", auth_token)
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
