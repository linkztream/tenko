//! The Home Assistant API client: REST under `/api/` with a long-lived access token as a
//! bearer token, and a WebSocket session on `/api/websocket` for the registries. Read-only:
//! GET requests and list commands only.

use std::time::Duration;

use reqwest::{StatusCode, header::HeaderValue};
use serde_json::Value;
use tenko_connect::{
    ConnectorError,
    sdk::http::{self, Failure, TlsSettings, WebClient},
};
use zeroize::Zeroizing;

use crate::ws::{self, ConnectError, WebSocket, WsError};

/// Timeout of one REST request and of the WebSocket handshake.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Timeout of one WebSocket answer.
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest REST answer accepted, in bytes.
pub const BODY_LIMIT: usize = 64 * 1024 * 1024;

/// Why a request got no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fail {
    /// The transport failed (TLS, connection, timeout).
    Transport(Failure),
    /// The answer was refused or could not be read.
    Answer(ConnectorError),
}

impl From<Fail> for ConnectorError {
    fn from(fail: Fail) -> Self {
        match fail {
            Fail::Transport(failure) => failure.into_error(),
            Fail::Answer(error) => error,
        }
    }
}

/// The client of one instance for one call.
pub struct Api {
    web: WebClient,
    bearer: HeaderValue,
    token: Zeroizing<String>,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("web", &self.web)
            .finish_non_exhaustive()
    }
}

impl Api {
    /// The client of a base URL with the access token.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::InvalidSettings`] for settings that cannot be used.
    pub fn new(url: &str, tls: &TlsSettings, token: &str) -> Result<Self, ConnectorError> {
        let token = token.trim();
        if token.is_empty() {
            return Err(ConnectorError::invalid_settings(
                "the secret `access_token` is empty",
            ));
        }
        let web = WebClient::new(
            url,
            tls,
            REQUEST_TIMEOUT,
            &format!("tenko-connect-hass/{}", crate::version()),
        )?;
        let value = Zeroizing::new(format!("Bearer {token}"));
        let bearer = http::sensitive_header(&value, "the access token")?;
        Ok(Self {
            web,
            bearer,
            token: Zeroizing::new(token.to_owned()),
        })
    }

    /// The web client.
    pub fn web(&self) -> &WebClient {
        &self.web
    }

    /// GET a REST path (`/api/...`) and read its JSON.
    ///
    /// # Errors
    ///
    /// [`Fail::Transport`] when no answer arrived; [`Fail::Answer`] with
    /// [`ConnectorError::Unauthorized`] for 401, [`ConnectorError::Forbidden`] for 403,
    /// [`ConnectorError::InvalidSettings`] for 404 (the URL does not lead to the API), and the
    /// usual mapping for other statuses and unreadable bodies.
    pub async fn get(&self, path: &str) -> Result<Value, Fail> {
        let response = self
            .web
            .get(path)
            .header(reqwest::header::AUTHORIZATION, self.bearer.clone())
            .send()
            .await
            .map_err(|error| Fail::Transport(self.web.failure(&error)))?;
        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Err(Fail::Answer(ConnectorError::invalid_settings(
                "the URL does not lead to the Home Assistant API (404)",
            )));
        }
        if !status.is_success() {
            return Err(Fail::Answer(http::status_error(
                status,
                http::retry_after(&response),
            )));
        }
        http::read_json(response, BODY_LIMIT)
            .await
            .map_err(Fail::Answer)
    }

    /// Opens an authenticated WebSocket session.
    ///
    /// # Errors
    ///
    /// [`Fail::Transport`] when the server cannot be reached; [`Fail::Answer`] with
    /// [`ConnectorError::Unauthorized`] when the token is refused and
    /// [`ConnectorError::Protocol`] when the server does not speak the API.
    pub async fn session(&self) -> Result<Session, Fail> {
        let url = self.web.url("/api/websocket");
        let socket = match ws::connect(self.web.client(), url).await {
            Ok(socket) => socket,
            Err(ConnectError::Request(error)) => {
                return Err(Fail::Transport(self.web.failure(&error)));
            }
            Err(ConnectError::Handshake(error)) => {
                return Err(Fail::Answer(ConnectorError::protocol(format!(
                    "the WebSocket API did not open: {error}"
                ))));
            }
        };
        let mut session = Session { socket, next_id: 0 };
        session.authenticate(&self.token).await?;
        Ok(session)
    }
}

/// The answer of a command: its `result`, or the error code and message Home Assistant
/// gave.
pub type Answer = Result<Value, (String, String)>;

/// An authenticated WebSocket session.
pub struct Session {
    socket: WebSocket<reqwest::Upgraded>,
    next_id: u64,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("next_id", &self.next_id)
            .finish_non_exhaustive()
    }
}

fn ws_error(error: &WsError) -> ConnectorError {
    match error {
        WsError::Io(_) | WsError::Closed(_) => ConnectorError::Unreachable,
        other => ConnectorError::protocol(other.to_string()),
    }
}

impl Session {
    /// The next JSON message.
    async fn receive(&mut self) -> Result<Value, Fail> {
        let text = tokio::time::timeout(ANSWER_TIMEOUT, self.socket.recv_text())
            .await
            .map_err(|_| Fail::Transport(Failure::Timeout))?
            .map_err(|error| Fail::Answer(ws_error(&error)))?;
        http::from_json(text.as_bytes()).map_err(Fail::Answer)
    }

    async fn send(&mut self, text: &str) -> Result<(), Fail> {
        tokio::time::timeout(ANSWER_TIMEOUT, self.socket.send_text(text))
            .await
            .map_err(|_| Fail::Transport(Failure::Timeout))?
            .map_err(|error| Fail::Answer(ws_error(&error)))
    }

    /// The authentication phase: `auth_required`, then `auth` with the token, then
    /// `auth_ok` or `auth_invalid`.
    async fn authenticate(&mut self, token: &str) -> Result<(), Fail> {
        let hello = self.receive().await?;
        if hello.get("type").and_then(Value::as_str) != Some("auth_required") {
            return Err(Fail::Answer(ConnectorError::protocol(
                "the WebSocket API did not ask for authentication",
            )));
        }
        let auth = Zeroizing::new(
            serde_json::json!({ "type": "auth", "access_token": token }).to_string(),
        );
        self.send(&auth).await?;
        drop(auth);
        let answer = self.receive().await?;
        match answer.get("type").and_then(Value::as_str) {
            Some("auth_ok") => Ok(()),
            Some("auth_invalid") => Err(Fail::Answer(ConnectorError::Unauthorized)),
            _ => Err(Fail::Answer(ConnectorError::protocol(
                "the WebSocket API answered the authentication with an unknown message",
            ))),
        }
    }

    /// Sends a command without arguments (`{"id": n, "type": kind}`) and waits for its
    /// result, skipping other messages.
    ///
    /// # Errors
    ///
    /// [`Fail`] when no result arrives.
    pub async fn command(&mut self, kind: &str) -> Result<Answer, Fail> {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&serde_json::json!({ "id": id, "type": kind }).to_string())
            .await?;
        for _ in 0..1_000 {
            let message = self.receive().await?;
            if message.get("id").and_then(Value::as_u64) != Some(id)
                || message.get("type").and_then(Value::as_str) != Some("result")
            {
                continue;
            }
            if message.get("success").and_then(Value::as_bool) == Some(true) {
                return Ok(Ok(message.get("result").cloned().unwrap_or(Value::Null)));
            }
            let error = message.get("error").cloned().unwrap_or(Value::Null);
            let field = |key: &str| {
                error
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .chars()
                    .take(200)
                    .collect::<String>()
            };
            return Ok(Err((field("code"), field("message"))));
        }
        Err(Fail::Answer(ConnectorError::protocol(format!(
            "no result for the command {kind}"
        ))))
    }

    /// Closes the session, best effort.
    pub async fn close(mut self) {
        let _ = tokio::time::timeout(Duration::from_secs(2), self.socket.close()).await;
    }
}
