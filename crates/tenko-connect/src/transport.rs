//! Local endpoints of the protocol: a Unix socket in a private directory, or a Windows
//! named pipe.
//!
//! The host chooses the endpoint and hands it to the plugin in the handshake; the plugin
//! serves gRPC on it and the host connects.
//!
//! - **Unix.** The host creates a directory with mode `0700` under its runtime directory
//!   (the system temporary directory by default) with a random name, and names the socket
//!   `plugin.sock` inside it. Only the Tenko account (and root) can reach the socket. The
//!   host removes the directory when the plugin stops.
//! - **Windows.** The host chooses a pipe name with 128 random bits,
//!   `\\.\pipe\tenko-plugin-<hex>`, passed only over the plugin's standard input. The
//!   plugin creates the pipe as its first instance (so nobody can create it before or beside
//!   it) and rejects remote clients; the default security descriptor of a pipe gives write
//!   access only to the creating account, `LocalSystem` and administrators.
//!
//! On both platforms every call also carries the per-launch token
//! ([`crate::status::TOKEN_METADATA`]), so a process that reaches the endpoint without the
//! token is refused.

use std::{
    io,
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures::Stream;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// How a plugin endpoint is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// A Unix domain socket; the address is its path.
    Unix,
    /// A Windows named pipe; the address is its name (`\\.\pipe\...`).
    Pipe,
}

/// A local endpoint, as the handshake carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// The transport.
    pub transport: Transport,
    /// The socket path or the pipe name.
    pub address: String,
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.transport {
            Transport::Unix => write!(f, "unix:{}", self.address),
            Transport::Pipe => write!(f, "pipe:{}", self.address),
        }
    }
}

/// Longest Unix socket path this host accepts (`sun_path` is 104 bytes on macOS and 108 on
/// Linux, including the terminating zero).
pub const MAX_UNIX_PATH: usize = 100;

/// `n` random bytes as lowercase hexadecimal.
///
/// # Errors
///
/// An I/O error when the system random generator fails.
pub fn random_hex(n: usize) -> io::Result<String> {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};
    let mut bytes = vec![0u8; n];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("the system random generator failed"))?;
    Ok(bytes
        .iter()
        .fold(String::with_capacity(n * 2), |mut hex, byte| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
            hex
        }))
}

/// An endpoint the host allocated for one launch. Dropping it removes the private
/// directory of a Unix socket.
#[derive(Debug)]
pub struct Allocation {
    endpoint: Endpoint,
    dir: Option<PathBuf>,
}

impl Allocation {
    /// Allocates an endpoint for one launch. `runtime_dir` is where Unix sockets live (the
    /// system temporary directory when `None`); Windows ignores it.
    ///
    /// # Errors
    ///
    /// An I/O error when the private directory cannot be created or its path is too long
    /// for a socket.
    pub fn new(runtime_dir: Option<&Path>) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let base = runtime_dir.map_or_else(std::env::temp_dir, Path::to_path_buf);
            Self::unix(&base)
        }
        #[cfg(not(unix))]
        {
            let _ = runtime_dir;
            Ok(Self {
                endpoint: Endpoint {
                    transport: Transport::Pipe,
                    address: format!(r"\\.\pipe\tenko-plugin-{}", random_hex(16)?),
                },
                dir: None,
            })
        }
    }

    #[cfg(unix)]
    fn unix(base: &Path) -> io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        for _ in 0..8 {
            let dir = base.join(format!("tenko-plugin-{}", random_hex(8)?));
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {
                    let socket = dir.join("plugin.sock");
                    let address = socket.to_string_lossy().into_owned();
                    if address.len() > MAX_UNIX_PATH {
                        let _ = std::fs::remove_dir_all(&dir);
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "the socket path {address} is longer than {MAX_UNIX_PATH} bytes; \
                                 choose a shorter runtime directory"
                            ),
                        ));
                    }
                    return Ok(Self {
                        endpoint: Endpoint {
                            transport: Transport::Unix,
                            address,
                        },
                        dir: Some(dir),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::other(
            "no free name for a private plugin directory",
        ))
    }

    /// The endpoint.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
}

impl Drop for Allocation {
    fn drop(&mut self) {
        if let Some(dir) = &self.dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// A connection to or from a plugin endpoint.
#[derive(Debug)]
pub struct Conn {
    inner: ConnInner,
}

#[cfg(unix)]
#[derive(Debug)]
enum ConnInner {
    Unix(tokio::net::UnixStream),
}

#[cfg(windows)]
#[derive(Debug)]
enum ConnInner {
    PipeClient(tokio::net::windows::named_pipe::NamedPipeClient),
    PipeServer(tokio::net::windows::named_pipe::NamedPipeServer),
}

macro_rules! delegate {
    ($self:ident, $inner:ident => $call:expr) => {
        match &mut $self.get_mut().inner {
            #[cfg(unix)]
            ConnInner::Unix($inner) => $call,
            #[cfg(windows)]
            ConnInner::PipeClient($inner) => $call,
            #[cfg(windows)]
            ConnInner::PipeServer($inner) => $call,
        }
    };
}

impl AsyncRead for Conn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        delegate!(self, inner => Pin::new(inner).poll_read(cx, buf))
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        delegate!(self, inner => Pin::new(inner).poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        delegate!(self, inner => Pin::new(inner).poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        delegate!(self, inner => Pin::new(inner).poll_shutdown(cx))
    }
}

impl tonic::transport::server::Connected for Conn {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

/// Connects to a plugin endpoint (host side). A busy pipe is retried until `timeout`.
///
/// # Errors
///
/// An I/O error when the endpoint does not answer, or `Unsupported` for a transport this
/// platform lacks.
pub async fn connect(endpoint: &Endpoint, timeout: Duration) -> io::Result<Conn> {
    match endpoint.transport {
        #[cfg(unix)]
        Transport::Unix => {
            let stream =
                tokio::time::timeout(timeout, tokio::net::UnixStream::connect(&endpoint.address))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "connecting timed out")
                    })??;
            Ok(Conn {
                inner: ConnInner::Unix(stream),
            })
        }
        #[cfg(windows)]
        Transport::Pipe => {
            use tokio::net::windows::named_pipe::ClientOptions;
            // ERROR_PIPE_BUSY: every instance is connected; wait for the next one.
            const PIPE_BUSY: i32 = 231;
            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                match ClientOptions::new().open(&endpoint.address) {
                    Ok(client) => {
                        return Ok(Conn {
                            inner: ConnInner::PipeClient(client),
                        });
                    }
                    Err(error)
                        if error.raw_os_error() == Some(PIPE_BUSY)
                            && tokio::time::Instant::now() < deadline =>
                    {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        #[allow(unreachable_patterns, reason = "one transport per platform")]
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("the transport of {endpoint} is not available on this platform"),
        )),
    }
}

/// Opens a gRPC channel to a plugin endpoint (host side). The channel reconnects on demand
/// through the same endpoint.
///
/// # Errors
///
/// The transport error of the first connection.
pub async fn channel(
    endpoint: &Endpoint,
    connect_timeout: Duration,
) -> Result<tonic::transport::Channel, tonic::transport::Error> {
    let endpoint = endpoint.clone();
    tonic::transport::Endpoint::from_static("http://plugin.invalid")
        .connect_timeout(connect_timeout)
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let endpoint = endpoint.clone();
            async move {
                connect(&endpoint, connect_timeout)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await
}

/// Incoming connections of a plugin endpoint (plugin side).
pub type Incoming = Pin<Box<dyn Stream<Item = io::Result<Conn>> + Send>>;

/// Listens on an endpoint the host named (plugin side).
///
/// # Errors
///
/// An I/O error when the endpoint cannot be created (the pipe exists already, the socket
/// directory is missing) or `Unsupported` for a transport this platform lacks.
pub fn listen(endpoint: &Endpoint) -> io::Result<Incoming> {
    match endpoint.transport {
        #[cfg(unix)]
        Transport::Unix => {
            let listener = tokio::net::UnixListener::bind(&endpoint.address)?;
            Ok(Box::pin(futures::stream::unfold(
                listener,
                |listener| async move {
                    let accepted = listener.accept().await.map(|(stream, _)| Conn {
                        inner: ConnInner::Unix(stream),
                    });
                    Some((accepted, listener))
                },
            )))
        }
        #[cfg(windows)]
        Transport::Pipe => {
            use tokio::net::windows::named_pipe::ServerOptions;
            let name = endpoint.address.clone();
            let first = ServerOptions::new()
                .first_pipe_instance(true)
                .reject_remote_clients(true)
                .create(&name)?;
            Ok(Box::pin(futures::stream::unfold(
                Some(first),
                move |server| {
                    let name = name.clone();
                    async move {
                        let server = server?;
                        if let Err(error) = server.connect().await {
                            return Some((Err(error), None));
                        }
                        // The next instance exists before this one is handed out, so a
                        // client never finds the pipe missing.
                        let next = ServerOptions::new()
                            .reject_remote_clients(true)
                            .create(&name);
                        match next {
                            Ok(next) => Some((
                                Ok(Conn {
                                    inner: ConnInner::PipeServer(server),
                                }),
                                Some(next),
                            )),
                            Err(error) => Some((Err(error), None)),
                        }
                    }
                },
            )))
        }
        #[allow(unreachable_patterns, reason = "one transport per platform")]
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("the transport of {endpoint} is not available on this platform"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[test]
    fn random_hex_has_the_requested_length() {
        let token = random_hex(32).expect("random");
        assert_eq!(token.len(), 64);
        assert!(
            token
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_ne!(token, random_hex(32).expect("random"));
    }

    #[tokio::test]
    async fn an_allocated_endpoint_carries_bytes_both_ways() {
        let allocation = Allocation::new(None).expect("allocation");
        let endpoint = allocation.endpoint().clone();
        let mut incoming = listen(&endpoint).expect("listen");
        let server = tokio::spawn(async move {
            let mut conn = incoming.next().await.expect("one").expect("accepted");
            let mut buf = [0u8; 4];
            conn.read_exact(&mut buf).await.expect("read");
            conn.write_all(&buf).await.expect("write");
            // A second client is accepted too.
            let mut second = incoming.next().await.expect("two").expect("accepted");
            second.write_all(b"ok").await.expect("write");
        });
        let mut client = connect(&endpoint, Duration::from_secs(5))
            .await
            .expect("connect");
        client.write_all(b"ping").await.expect("write");
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ping");
        let mut second = connect(&endpoint, Duration::from_secs(5))
            .await
            .expect("connect");
        let mut ok = [0u8; 2];
        second.read_exact(&mut ok).await.expect("read");
        assert_eq!(&ok, b"ok");
        server.await.expect("server");
        #[cfg(unix)]
        {
            let dir = Path::new(&endpoint.address)
                .parent()
                .expect("dir")
                .to_path_buf();
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir).expect("dir").permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
            drop(allocation);
            assert!(!dir.exists());
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn a_pipe_name_cannot_be_taken_twice() {
        let allocation = Allocation::new(None).expect("allocation");
        let _first = listen(allocation.endpoint()).expect("listen");
        assert!(listen(allocation.endpoint()).is_err());
    }
}
