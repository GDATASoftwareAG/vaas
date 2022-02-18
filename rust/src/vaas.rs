//! The `Vaas` module provides all needed functions to check a hash or file for malicious content.

use crate::builder::Builder;
use crate::connection::Connection;
use crate::error::{Error, VResult};
use crate::message::{AuthRequest, AuthResponse};
use reqwest::Url;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use websockets::{Frame, WebSocket, WebSocketReadHalf, WebSocketWriteHalf};

#[derive(PartialEq)]
pub(super) enum ThreadSyncMsg {
    StopReader,
}

/// Provides all functionality needed to check a hash or file for malicious content.
#[derive(Debug, Clone)]
pub struct Vaas {
    pub(super) token: String,
    pub(super) poll_delay_ms: u64,
    pub(super) url: Url,
}

impl Vaas {
    /// Create a new [Builder] instance to configure the `Vaas` instance.
    pub fn builder(token: String) -> Builder {
        Builder::new(token)
    }

    /// Connect to the server endpoints to request a verdict for a hash or file.
    pub async fn connect(self) -> VResult<Connection> {
        let (mut ws_reader, mut ws_writer) = self.open_websocket().await?;
        let (ch_sender, ch_receiver) = flume::unbounded();
        let message_states = Arc::new(Mutex::new(HashMap::new()));
        let reader_messages = message_states.clone();

        let session_id = self.authenticate(&mut ws_reader, &mut ws_writer).await?;

        let connection = Connection {
            ws_writer: Arc::new(Mutex::new(ws_writer)),
            session_id,
            message_states,
            ch_sender,
            poll_delay_ms: self.poll_delay_ms,
        };

        Connection::start_reader_loop(ws_reader, ch_receiver, reader_messages).await;
        Ok(connection)
    }

    async fn open_websocket(&self) -> VResult<(WebSocketReadHalf, WebSocketWriteHalf)> {
        let (reader, writer) = WebSocket::builder()
            .connect(self.url.as_str())
            .await?
            .split();
        Ok((reader, writer))
    }

    async fn authenticate(
        &self,
        ws_reader: &mut WebSocketReadHalf,
        ws_writer: &mut WebSocketWriteHalf,
    ) -> VResult<String> {
        let auth_request = AuthRequest::new(self.token.clone(), None).to_json()?;

        ws_writer.send_text(auth_request).await?;

        let frame = ws_reader.receive().await?;

        let response = match frame {
            Frame::Text { payload: json, .. } => AuthResponse::try_from(&json)?,
            _ => return Err(Error::InvalidFrame),
        };

        if response.success {
            Ok(response.session_id)
        } else {
            Err(Error::Unauthorized)
        }
    }
}
