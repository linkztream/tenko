//! The Proxmox VE API client: API-token authentication, the certificate checks of the
//! settings, JSON answers under `data`, GET only.

use std::time::Duration;

use reqwest::{StatusCode, header::HeaderValue};
use serde_json::Value;
use tenko_connect::{
    ConnectorError,
    sdk::http::{self, Failure, WebClient},
};
use zeroize::Zeroizing;

use crate::Settings;

/// Timeout of one request.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Timeout of one guest agent request: an agent that does not answer must not hold up the
/// poll.
pub const AGENT_TIMEOUT: Duration = Duration::from_secs(8);

/// Largest answer accepted, in bytes.
pub const BODY_LIMIT: usize = 64 * 1024 * 1024;

/// An answer of the API.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// A success with its `data` member (`null` when absent).
    Data(Value),
    /// An HTTP status other than success.
    Status(StatusCode),
}

/// Why a request got no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fail {
    /// The transport failed (TLS, connection, timeout).
    Transport(Failure),
    /// The answer could not be read.
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
#[derive(Debug)]
pub struct Api {
    web: WebClient,
    auth: HeaderValue,
}

impl Api {
    /// The client of the settings with the token secret.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::InvalidSettings`] for settings that cannot be used.
    pub fn new(settings: &Settings, secret: &str) -> Result<Self, ConnectorError> {
        let secret = secret.trim();
        if secret.is_empty() {
            return Err(ConnectorError::invalid_settings(
                "the secret `token_secret` is empty",
            ));
        }
        let web = WebClient::new(
            &settings.url,
            &settings.tls(),
            REQUEST_TIMEOUT,
            &format!("tenko-connect-proxmox/{}", crate::version()),
        )?;
        let value = Zeroizing::new(format!("PVEAPIToken={}={secret}", settings.token_id.trim()));
        let auth = http::sensitive_header(&value, "the API token")?;
        Ok(Self { web, auth })
    }

    /// The web client.
    pub fn web(&self) -> &WebClient {
        &self.web
    }

    /// GET `/api2/json<path>`, with an optional shorter timeout.
    ///
    /// # Errors
    ///
    /// [`Fail`] when no answer could be read.
    pub async fn fetch(&self, path: &str, timeout: Option<Duration>) -> Result<Reply, Fail> {
        let mut request = self
            .web
            .get(&format!("/api2/json{path}"))
            .header(reqwest::header::AUTHORIZATION, self.auth.clone());
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        let response = request
            .send()
            .await
            .map_err(|error| Fail::Transport(self.web.failure(&error)))?;
        let status = response.status();
        if !status.is_success() {
            return Ok(Reply::Status(status));
        }
        let body: Value = http::read_json(response, BODY_LIMIT)
            .await
            .map_err(Fail::Answer)?;
        Ok(Reply::Data(
            body.get("data").cloned().unwrap_or(Value::Null),
        ))
    }

    /// GET `/api2/json<path>` where any status but success fails the call.
    ///
    /// # Errors
    ///
    /// The transport or answer failure, or the error of the status.
    pub async fn get(&self, path: &str) -> Result<Value, ConnectorError> {
        match self.fetch(path, None).await? {
            Reply::Data(data) => Ok(data),
            Reply::Status(status) => Err(status_error(status)),
        }
    }
}

/// The error of a status: Proxmox's own 59x codes (a node in the cluster that does not
/// answer) count as unreachable.
pub fn status_error(status: StatusCode) -> ConnectorError {
    if status.as_u16() >= 590 {
        ConnectorError::Unreachable
    } else {
        http::status_error(status, None)
    }
}

/// Whether a status means that the request may succeed later (a server error or an
/// unreachable cluster node), as opposed to a refusal.
pub fn transient(status: StatusCode) -> bool {
    status.is_server_error()
}
