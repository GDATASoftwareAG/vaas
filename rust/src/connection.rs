//! The `Connection` module provides all functionallity to create an active connection to the verdict backend.

use crate::error::{Error, VResult};
use crate::message::{MessageType, State, UploadUrl, Verdict, VerdictRequest, VerdictResponse};
use crate::sha256::Sha256;
use crate::vaas::ThreadSyncMsg;
use cancellation::*;
use flume::{Receiver, Sender, TryRecvError};
use futures::future::join_all;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use websockets::{Frame, WebSocketError, WebSocketReadHalf, WebSocketWriteHalf};

/// Active connection to the verdict server.
pub struct Connection {
    pub(super) ws_writer: Arc<Mutex<WebSocketWriteHalf>>,
    pub(super) session_id: String,
    pub(super) message_states: Arc<Mutex<HashMap<String, State>>>,
    pub(super) ch_sender: Sender<ThreadSyncMsg>,
    pub(super) poll_delay_ms: u64,
}

impl Connection {
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
        let mut ping_cnt = 0;
        let result = loop {
            tokio::time::sleep(Duration::from_millis(self.poll_delay_ms)).await;
            if ct.is_canceled() {
                break Err(Error::Cancelled);
            }
            if let Some(State::Received(resp)) = self.message_states.lock().await.get(guid) {
                break Ok((*resp).clone());
            }

            if ping_cnt == 200 {
                self.ws_writer.lock().await.send_ping(None).await?;
                self.ws_writer.lock().await.flush().await?;
                ping_cnt = 0;
            }
            ping_cnt += 1;
        };
        // Remove guid/message from internal state, as we would gather infinite
        // messages if we never clean up.
        self.message_states.lock().await.remove(guid);
        result
    }

    pub(super) async fn start_reader_loop(
        mut ws_reader: WebSocketReadHalf,
        ch_receiver: Receiver<ThreadSyncMsg>,
        message_states: Arc<Mutex<HashMap<String, State>>>,
    ) {
        tokio::spawn(async move {
            loop {
                let frame = ws_reader.receive().await;
                match Self::parse_frame(frame) {
                    Ok(message) => {
                        Self::transition_state(message, &message_states).await;
                    }
                    Err(e) => {
                        // TODO: Better error handling.
                        // Log a not parsable message?
                        // Infinite loop occurs if only errors are received... Notify user and exit?
                        println!("Frame error: {:?}", e);
                        continue;
                    }
                };

                match ch_receiver.try_recv() {
                    Ok(ThreadSyncMsg::StopReader) => break,
                    Err(TryRecvError::Empty) => continue,
                    // TODO: Handle errors in thread. If the reader thread panics, currently nobody will notice and no new results will be received.
                    // This should not happen as we have the channel under control but you never know...
                    Err(TryRecvError::Disconnected) => panic!("Channel receiver disconnected."),
                }
            }
        });
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

    async fn stop_reader(&self) -> VResult<()> {
        Ok(self.ch_sender.send(ThreadSyncMsg::StopReader)?)
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
        // Best effort: If the reader is hung up, we are out of luck
        // and the thread cannot be terminated.
        let _result = self.stop_reader();
    }
}
