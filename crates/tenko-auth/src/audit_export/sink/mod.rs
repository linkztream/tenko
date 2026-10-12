//! The transports of the sinks: syslog over UDP (RFC 5426), TCP with octet counting
//! (RFC 6587) and TLS (RFC 5425), and a file rotated by size.
//!
//! A [`Transport`] takes rendered messages ([`super::format::render`]) and adds its own
//! framing: one datagram per message, `<length> <message>` on a stream, one line per
//! message in a file. [`Opener::open`] connects a sink; the exporter owns the retry.

mod file;
pub(crate) mod net;

use std::{path::PathBuf, sync::Arc, time::Duration};

use tenko_core::{RequestCtx, SystemComponent};
use tenko_vault::Vault;

pub use self::file::FileTransport;
pub use self::net::{TcpTransport, UdpTransport, client_config};
use super::{
    error::{FailureKind, SinkError},
    model::{Sink, SinkTarget, SyslogTransport},
};

/// The largest datagram a UDP sink sends; a longer message is cut at a character
/// boundary (the structured data with sequence and hash comes first).
pub const MAX_DATAGRAM: usize = 65_000;

/// Time limits of the network transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// Name resolution, the TCP connection and the TLS handshake together.
    pub connect: Duration,
    /// One write including its flush.
    pub write: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            write: Duration::from_secs(30),
        }
    }
}

/// A connected sink.
#[async_trait::async_trait]
pub trait Transport: Send {
    /// Writes the messages in order, each with the transport's framing, and flushes them
    /// to the operating system (a file also to its disk with `sync_data`). On an error
    /// some of them may have been written; the caller sends them again.
    ///
    /// # Errors
    ///
    /// [`SinkError`] with [`FailureKind::Send`] or [`FailureKind::File`].
    async fn send(&mut self, messages: &[Vec<u8>]) -> Result<(), SinkError>;

    /// Whether writing a message of `len` bytes now would exceed the file's size, so the
    /// caller rotates first. Always false for network transports.
    fn needs_rotation(&self, len: usize) -> bool {
        let _ = len;
        false
    }

    /// Rotates the file: `<file>.<n>` becomes `<file>.<n+1>` (the oldest beyond `keep` is
    /// removed), the file becomes `<file>.1`, and writing goes on in a new, empty file.
    /// A no-op for network transports.
    ///
    /// # Errors
    ///
    /// [`SinkError`] with [`FailureKind::File`].
    async fn rotate(&mut self) -> Result<(), SinkError> {
        Ok(())
    }
}

/// Opens the transport of a sink.
#[derive(Clone)]
pub struct Opener {
    /// The directory of file sinks (`[audit_export] file_dir`); `None`: file sinks fail
    /// with [`FailureKind::Config`].
    pub file_dir: Option<PathBuf>,
    /// The vault that holds TLS client keys.
    pub vault: Option<Arc<dyn Vault>>,
    /// Time limits.
    pub timeouts: Timeouts,
}

impl std::fmt::Debug for Opener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opener")
            .field("file_dir", &self.file_dir)
            .field("vault", &self.vault.is_some())
            .field("timeouts", &self.timeouts)
            .finish()
    }
}

impl Opener {
    /// Connects the sink (or opens its file for appending).
    ///
    /// # Errors
    ///
    /// [`SinkError`]: resolution, connection, TLS, client key, file or configuration.
    pub async fn open(&self, sink: &Sink) -> Result<Box<dyn Transport>, SinkError> {
        match &sink.target {
            SinkTarget::File(target) => {
                let dir = self.file_dir.as_ref().ok_or_else(|| {
                    SinkError::new(
                        FailureKind::Config,
                        "this controller has no audit export directory ([audit_export] file_dir)",
                    )
                })?;
                Ok(Box::new(FileTransport::open(dir, target).await?))
            }
            SinkTarget::Syslog(target) => match target.transport {
                SyslogTransport::Udp => Ok(Box::new(
                    UdpTransport::connect(target, self.timeouts).await?,
                )),
                SyslogTransport::Tcp => Ok(Box::new(
                    TcpTransport::connect(target, None, self.timeouts).await?,
                )),
                SyslogTransport::Tls => {
                    let key = match target.tls.client_key {
                        Some(secret) => Some(self.client_key(secret).await?),
                        None => None,
                    };
                    let config = client_config(&target.tls, key.as_deref().map(Vec::as_slice))?;
                    Ok(Box::new(
                        TcpTransport::connect(target, Some(config), self.timeouts).await?,
                    ))
                }
            },
        }
    }

    /// The PEM text of a TLS client key from the vault.
    async fn client_key(
        &self,
        secret: tenko_core::SecretId,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, SinkError> {
        let vault = self.vault.as_ref().ok_or_else(|| {
            SinkError::new(
                FailureKind::ClientKey,
                "no vault is available for the client key",
            )
        })?;
        let ctx = RequestCtx::system(SystemComponent::AuditExport);
        let value = vault
            .get_system(&ctx, tenko_core::secret::SecretRef { secret })
            .await
            .map_err(|error| {
                SinkError::new(
                    FailureKind::ClientKey,
                    format!("the client key {secret} cannot be read from the vault: {error}"),
                )
            })?;
        Ok(zeroize::Zeroizing::new(value.expose().to_vec()))
    }
}
