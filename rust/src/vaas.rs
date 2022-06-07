//! The `Vaas` module provides all needed functions to check a hash or file for malicious content.

use crate::builder::Builder;
use crate::connection::Connection;
use crate::error::{Error, VResult};
use crate::message::{AuthRequest, AuthResponse, OpenIdConnectTokenResponse};
use crate::options::Options;
use reqwest::{StatusCode, Url};
use websockets::{Frame, WebSocket, WebSocketReadHalf, WebSocketWriteHalf};

/// Provides all functionality needed to check a hash or file for malicious content.
#[derive(Debug, Clone)]
pub struct Vaas {
    pub(super) token: String,
    pub(super) url: Url,
    pub(super) options: Options,
}

impl Vaas {
    /// Get an OpenID Connect token to use for authentication.
    pub async fn get_token(
        client_id: String,
        client_secret: String,
        token_endpoint: String,
    ) -> VResult<String> {
        let params = [
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("grant_type", "client_credentials".to_string()),
        ];
        let client = reqwest::Client::new();
        let token_response = client.post(token_endpoint).form(&params).send().await?;

        match token_response.status() {
            StatusCode::OK => {
                let json_string = token_response.text().await?;
                Ok(OpenIdConnectTokenResponse::try_from(&json_string)?.access_token)
            }
            status => Err(Error::FailedAuthTokenRequest(
                status,
                token_response.text().await.unwrap_or_default(),
            )),
        }
    }

    /// Create a new [Builder] instance to configure the `Vaas` instance.
    pub fn builder(token: String) -> Builder {
        Builder::new(token)
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
        let auth_request = AuthRequest::new(self.token.clone(), None).to_json()?;
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
