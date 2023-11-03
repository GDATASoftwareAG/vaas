//! The `Vaas` module provides all needed functions to check a hash or file for malicious content.

use crate::auth::Authenticator;
use crate::builder::Builder;
use crate::connection::Connection;
use crate::error::{Error, VResult};
use crate::message::{AuthRequest, AuthResponse};
use crate::options::Options;
use reqwest::Url;
use websockets::{Frame, WebSocket, WebSocketReadHalf, WebSocketWriteHalf};

/// Provides all functionality needed to check a hash or file for malicious content.
#[derive(Debug, Clone)]
pub struct Vaas<A: Authenticator> {
    pub(super) authenticator: A,
    pub(super) url: Url,
    pub(super) options: Options,
}

impl<A: Authenticator> Vaas<A> {
    /// Create a new [Builder] instance to configure the `Vaas` instance.
    pub fn builder(authenticator: A) -> Builder<A> {
        Builder::new(authenticator)
    }

    /// Connect to the server endpoints to request a verdict for a hash or file.
    pub async fn connect(self) -> VResult<Connection> {
        let (mut ws_reader, mut ws_writer) = self.open_websocket().await?;
        let session_id = self.authenticate(&mut ws_reader, &mut ws_writer).await?;
        let connection = Connection::start(ws_writer, ws_reader, session_id, self.options).await;
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
        let token = self.authenticator.get_token().await?;
        let auth_request = AuthRequest::new(token, None).to_json()?;
        ws_writer.send_text(auth_request).await?;

        let frame = ws_reader.receive().await?;
        let response = match frame {
            Frame::Text { payload: json, .. } => AuthResponse::try_from(&json)?,
            _ => return Err(Error::InvalidFrame),
        };

        if response.success {
            let session_id = response.session_id.ok_or(Error::NoSessionIdInAuthResp)?;
            Ok(session_id)
        } else {
            Err(Error::Unauthorized(response.text))
        }
    }
}
