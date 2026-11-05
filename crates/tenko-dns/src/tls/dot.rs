//! DNS over TLS (RFC 7858): the length-prefixed messages of RFC 7766 inside a TLS stream
//! (or, behind a reverse proxy, the plain stream the proxy opens).
//!
//! The loop is the one of [`transport::tcp`](crate::transport::tcp) over any stream: queries
//! are read in arrival order, pipelined queries already received are answered before
//! anything is written, and the answers go out together (and are flushed, which a TLS
//! stream needs) when no further query is buffered or 32 KiB wait. A write that takes
//! longer than the write deadline closes the connection, as on TCP. The query buffers are
//! the runtime thread's, shared with TCP, so a query allocates nothing once the connection
//! is up; a forwarded query's answer arrives through a channel as a fresh buffer.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

use crate::{
    resolver::Resolver,
    respond::{Conn, Responder},
    transport::tcp::{TcpSettings, serve_split},
};

/// Serves one connection until the client closes it, a message is cut, it stays idle for
/// the idle time, a write runs out of time, or the server stops. `tls` when this node ended
/// TLS: a transfer over it is XoT. The shutdown sends the TLS `close_notify` before the
/// socket closes, within the write deadline.
pub(super) async fn connection<R, S>(
    stream: S,
    conn: Conn,
    responder: Arc<Responder<R>>,
    settings: TcpSettings,
    stop: CancellationToken,
    tls: bool,
) where
    R: Resolver + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reader, writer) = tokio::io::split(stream);
    serve_split(reader, writer, conn, responder, settings, stop, tls).await;
}
