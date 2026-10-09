//! The handshake over standard input and output, before any gRPC call.
//!
//! 1. The host starts the plugin with its standard input and output piped and writes one
//!    line of JSON, a [`HostHello`]: the handshake format, the protocol versions the host
//!    speaks, the endpoint to serve on, the per-launch token and the expected plugin name.
//! 2. The plugin picks the highest protocol version both sides speak, starts serving gRPC on
//!    the endpoint, and answers with one line of JSON, a [`PluginHello`]: the chosen
//!    version and its manifest. When it cannot (no common version, a wrong name, the
//!    endpoint cannot be created) it answers with an [`HandshakeFailure`] instead and exits
//!    with a non-zero status.
//! 3. The host checks the answer against the manifest it launched the plugin with, connects
//!    to the endpoint and pings the plugin with the token.
//!
//! After the handshake, the plugin's standard output and standard error are log lines that
//! the host forwards to its own log. The plugin keeps its standard input open and exits
//! when it closes, so a plugin never outlives its host.
//!
//! The token travels only over standard input: never on the command line and never in the
//! environment, where other local processes could read it.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{manifest::Manifest, transport::Endpoint};

/// The handshake format; the `tenko_plugin` member of both lines.
pub const HANDSHAKE_FORMAT: u32 = 1;

/// Longest handshake line, in bytes (the plugin's line carries the manifest).
pub const MAX_LINE: usize = 512 * 1024;

/// The token length in bytes (64 hexadecimal characters on the wire).
pub const TOKEN_BYTES: usize = 32;

/// The first line, from the host to the plugin.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostHello {
    /// [`HANDSHAKE_FORMAT`].
    pub tenko_plugin: u32,
    /// The protocol versions the host speaks.
    pub protocol: Vec<u32>,
    /// Where the plugin serves gRPC.
    pub endpoint: Endpoint,
    /// The per-launch token: 64 lowercase hexadecimal characters. Every call of the host
    /// carries it in the `x-tenko-plugin-token` metadata entry.
    pub token: String,
    /// The plugin name the host expects (the manifest name).
    pub plugin: String,
    /// The version of the host.
    pub host_version: String,
}

impl std::fmt::Debug for HostHello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostHello")
            .field("tenko_plugin", &self.tenko_plugin)
            .field("protocol", &self.protocol)
            .field("endpoint", &self.endpoint)
            .field("token", &"<redacted>")
            .field("plugin", &self.plugin)
            .field("host_version", &self.host_version)
            .finish()
    }
}

/// The answer, from the plugin to the host: ready, or a failure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginHello {
    /// [`HANDSHAKE_FORMAT`].
    pub tenko_plugin: u32,
    /// The chosen protocol version, when the plugin is ready.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<u32>,
    /// The manifest, when the plugin is ready.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<Manifest>,
    /// Why the plugin cannot serve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<HandshakeFailure>,
}

/// A handshake the plugin refuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeFailure {
    /// `protocol_mismatch`, `wrong_plugin`, `endpoint` or `startup`.
    pub code: String,
    /// English detail.
    pub message: String,
    /// The protocol versions the plugin speaks (for `protocol_mismatch`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported: Vec<u32>,
}

/// Failure codes of the plugin side.
pub mod failure {
    /// The plugin speaks none of the offered protocol versions.
    pub const PROTOCOL_MISMATCH: &str = "protocol_mismatch";
    /// The host expected another plugin.
    pub const WRONG_PLUGIN: &str = "wrong_plugin";
    /// The endpoint could not be created.
    pub const ENDPOINT: &str = "endpoint";
    /// The plugin failed to start otherwise.
    pub const STARTUP: &str = "startup";
}

impl PluginHello {
    /// A ready answer.
    pub fn ready(protocol: u32, manifest: Manifest) -> Self {
        Self {
            tenko_plugin: HANDSHAKE_FORMAT,
            protocol: Some(protocol),
            manifest: Some(manifest),
            error: None,
        }
    }

    /// A refusal.
    pub fn failed(code: &str, message: impl Into<String>, supported: Vec<u32>) -> Self {
        Self {
            tenko_plugin: HANDSHAKE_FORMAT,
            protocol: None,
            manifest: None,
            error: Some(HandshakeFailure {
                code: code.to_owned(),
                message: message.into(),
                supported,
            }),
        }
    }
}

/// A handshake line that cannot be read.
#[derive(Debug, thiserror::Error)]
pub enum LineError {
    /// The stream ended before a line arrived.
    #[error("the stream closed before the handshake line")]
    Closed,
    /// The line is longer than [`MAX_LINE`].
    #[error("the handshake line is longer than {MAX_LINE} bytes")]
    TooLong,
    /// Reading failed.
    #[error("reading the handshake failed: {0}")]
    Io(#[from] std::io::Error),
    /// The line is not the expected JSON.
    #[error("the handshake line is not valid: {0}")]
    Json(String),
}

/// Reads one JSON line of at most [`MAX_LINE`] bytes. Blank lines before it are skipped;
/// a line that does not start with `{` is returned through `noise` (a plugin that prints
/// before the handshake) and skipped.
///
/// # Errors
///
/// [`LineError`].
pub async fn read_line<T, R>(reader: &mut R, mut noise: impl FnMut(&str)) -> Result<T, LineError>
where
    T: serde::de::DeserializeOwned,
    R: AsyncBufRead + Unpin,
{
    loop {
        let mut line = Vec::new();
        let mut limited = (&mut *reader).take(MAX_LINE as u64 + 1);
        let read = limited.read_until(b'\n', &mut line).await?;
        if read == 0 {
            return Err(LineError::Closed);
        }
        if line.len() > MAX_LINE {
            return Err(LineError::TooLong);
        }
        let text = String::from_utf8_lossy(&line);
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        if !text.starts_with('{') {
            noise(text);
            continue;
        }
        return serde_json::from_str(text).map_err(|error| LineError::Json(error.to_string()));
    }
}

/// Writes one JSON line and flushes.
///
/// # Errors
///
/// An I/O error.
pub async fn write_line<T, W>(writer: &mut W, value: &T) -> std::io::Result<()>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    let mut line = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    line.push(b'\n');
    writer.write_all(&line).await?;
    writer.flush().await
}

/// Whether a token has the wire shape: 64 lowercase hexadecimal characters.
pub fn is_token(token: &str) -> bool {
    token.len() == TOKEN_BYTES * 2
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Compares two tokens in constant time.
pub fn token_matches(expected: &str, presented: &[u8]) -> bool {
    #[allow(
        deprecated,
        reason = "the replacement is not in the pinned aws-lc-rs release"
    )]
    let equal =
        aws_lc_rs::constant_time::verify_slices_are_equal(expected.as_bytes(), presented).is_ok();
    equal
}

#[cfg(test)]
mod tests {
    use tokio::io::BufReader;

    use super::*;
    use crate::transport::Transport;

    fn hello() -> HostHello {
        HostHello {
            tenko_plugin: HANDSHAKE_FORMAT,
            protocol: vec![1],
            endpoint: Endpoint {
                transport: Transport::Pipe,
                address: r"\\.\pipe\tenko-plugin-0011".to_owned(),
            },
            token: "ab".repeat(32),
            plugin: "sample".to_owned(),
            host_version: "0.0.1".to_owned(),
        }
    }

    #[tokio::test]
    async fn lines_round_trip_and_noise_is_skipped() {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(b"\nstarting up\n");
        write_line(&mut buffer, &hello()).await.expect("write");
        let mut reader = BufReader::new(buffer.as_slice());
        let mut skipped = Vec::new();
        let back: HostHello = read_line(&mut reader, |line| skipped.push(line.to_owned()))
            .await
            .expect("read");
        assert_eq!(back, hello());
        assert_eq!(skipped, vec!["starting up".to_owned()]);
        assert!(matches!(
            read_line::<HostHello, _>(&mut reader, |_| {}).await,
            Err(LineError::Closed)
        ));
    }

    #[tokio::test]
    async fn oversized_and_malformed_lines_are_refused() {
        let long = format!("{{\"x\":\"{}\"}}\n", "a".repeat(MAX_LINE));
        let mut reader = BufReader::new(long.as_bytes());
        assert!(matches!(
            read_line::<HostHello, _>(&mut reader, |_| {}).await,
            Err(LineError::TooLong)
        ));
        let mut reader = BufReader::new(&b"{\"tenko_plugin\":1}\n"[..]);
        assert!(matches!(
            read_line::<HostHello, _>(&mut reader, |_| {}).await,
            Err(LineError::Json(_))
        ));
    }

    #[test]
    fn tokens_are_checked_and_never_printed() {
        let hello = hello();
        assert!(is_token(&hello.token));
        assert!(!is_token("AB"));
        assert!(token_matches(&hello.token, hello.token.as_bytes()));
        assert!(!token_matches(&hello.token, b"abab"));
        assert!(!format!("{hello:?}").contains(&hello.token));
    }

    #[test]
    fn failures_serialize_compactly() {
        let failure = PluginHello::failed(failure::PROTOCOL_MISMATCH, "no common version", vec![2]);
        let json = serde_json::to_string(&failure).expect("json");
        assert_eq!(
            json,
            r#"{"tenko_plugin":1,"error":{"code":"protocol_mismatch","message":"no common version","supported":[2]}}"#
        );
    }
}
