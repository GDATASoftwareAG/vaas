//! The `Connection` module provides all functionality to create an active connection to the verdict backend.

use crate::error::{Error, VResult};
use crate::message::{MessageType, State, UploadUrl, Verdict, VerdictRequest, VerdictResponse};
use crate::options::Options;
use crate::sha256::Sha256;
use cancellation::*;
use futures::future::join_all;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use websockets::{Frame, WebSocketError, WebSocketReadHalf, WebSocketWriteHalf};

type ThreadHandle = JoinHandle<Result<(), Error>>;
type MessageStates = Arc<Mutex<HashMap<String, State>>>;
type AsyncWriterHalf = Arc<Mutex<WebSocketWriteHalf>>;
type AsyncRecv = Arc<Mutex<Receiver<Error>>>;

/// Active connection to the verdict server.
pub struct Connection {
    ws_writer: AsyncWriterHalf,
    session_id: String,
    message_states: MessageStates,
    options: Options,
    reader_thread: ThreadHandle,
    keep_alive_thread: Option<ThreadHandle>,
    error_channel_receiver: AsyncRecv,
}

impl Connection {
    pub(crate) async fn start(
        ws_writer: WebSocketWriteHalf,
        ws_reader: WebSocketReadHalf,
        session_id: String,
        options: Options,
    ) -> Self {
        let ws_writer = Arc::new(Mutex::new(ws_writer));
        let message_states = Arc::new(Mutex::new(HashMap::new()));
        let reader_messages = message_states.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(5);
        let reader_loop =
            Connection::start_reader_loop(ws_reader, reader_messages, tx.clone()).await;

        let keep_alive_loop = if options.keep_alive {
            Some(
                Connection::start_keep_alive(
                    ws_writer.clone(),
                    options.keep_alive_delay_ms,
                    tx.clone(),
                )
                .await,
            )
        } else {
            None
        };

        Connection {
            ws_writer,
            session_id,
            message_states,
            options,
            reader_thread: reader_loop,
            keep_alive_thread: keep_alive_loop,
            error_channel_receiver: Arc::new(Mutex::new(rx)),
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
            _ => Ok(verdict),
        }
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

        self.message_states
            .lock()
            .await
            .insert(guid.to_string(), State::Send(request));

        self.wait_for_response(&guid, ct).await
    }

    async fn wait_for_response(
        &self,
        guid: &str,
        ct: &CancellationToken,
    ) -> VResult<VerdictResponse> {
        let result = loop {
            tokio::time::sleep(Duration::from_millis(self.options.poll_delay_ms)).await;

            // Check if the request has been cancelled
            if ct.is_canceled() {
                break Err(Error::Cancelled);
            }

            // Check if the keep-alive or reader thread has died
            match self.error_channel_receiver.lock().await.try_recv() {
                Ok(e) => break Err(e),
                Err(TryRecvError::Disconnected) => break Err(Error::ThreadsDropped),
                Err(TryRecvError::Empty) => { // continue
                }
            }

            // Pull a response from the message_states map
            if let Some(State::Received(resp)) = self.message_states.lock().await.get(guid) {
                break Ok((*resp).clone());
            }
        };
        // Remove guid/message from internal state, as we would gather infinite
        // messages if we never clean up.
        self.message_states.lock().await.remove(guid);
        result
    }

    // TODO: Move this functionality into the underlying websocket library.
    async fn start_keep_alive(
        ws_writer: AsyncWriterHalf,
        keep_alive_delay_ms: u64,
        thread_sender: Sender<Error>,
    ) -> ThreadHandle {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(keep_alive_delay_ms)).await;
                if let Err(e) = ws_writer.lock().await.send_ping(None).await {
                    thread_sender.send(e.into()).await?;
                }
                if let Err(e) = ws_writer.lock().await.flush().await {
                    thread_sender.send(e.into()).await?;
                }
            }
        })
    }

    async fn start_reader_loop(
        mut ws_reader: WebSocketReadHalf,
        message_states: MessageStates,
        error_channel_sender: Sender<Error>,
    ) -> ThreadHandle {
        tokio::spawn(async move {
            loop {
                let frame = ws_reader.receive().await;
                match Self::parse_frame(frame) {
                    Ok(message) => {
                        Self::transition_state(message, &message_states).await;
                    }
                    Err(e) => {
                        error_channel_sender.send(e).await?;
                    }
                }
            }
        })
    }

    async fn transition_state(
        message: MessageType,
        message_states: &Arc<Mutex<HashMap<String, State>>>,
    ) {
        match message {
            MessageType::Response(resp) => {
                message_states
                    .lock()
                    .await
                    .insert(resp.guid.clone(), State::Received(resp));
            }
            MessageType::Ping => (),
            MessageType::Pong => (),
            MessageType::Close => (),
        }
    }

    fn parse_frame(frame: Result<Frame, WebSocketError>) -> VResult<MessageType> {
        match frame {
            Ok(Frame::Text { payload: json, .. }) => MessageType::try_from(&json),
            Ok(Frame::Ping { .. }) => Ok(MessageType::Ping),
            Ok(Frame::Pong { .. }) => Ok(MessageType::Pong),
            Ok(Frame::Close { .. }) => Ok(MessageType::Close),
            Ok(_) => Err(Error::InvalidFrame),
            Err(e) => Err(Error::WebSocket(e)),
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
