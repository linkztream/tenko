//! DNS over TLS (RFC 7858): the length-prefixed messages of RFC 7766 inside a TLS stream
//! (or, behind a reverse proxy, the plain stream the proxy opens).
//!
//! The loop is the one of [`transport::tcp`](crate::transport::tcp) over any stream: queries
//! are read in arrival order, pipelined queries already received are answered before
//! anything is written, and the answers go out together (and are flushed, which a TLS
//! stream needs) when no further query is buffered or 32 KiB wait. The query buffers are
//! the runtime thread's, shared with TCP, so a query allocates nothing once the connection
//! is up; a forwarded query's answer arrives through a channel as a fresh buffer.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, WriteHalf},
    sync::{Mutex as AsyncMutex, mpsc},
};
use tokio_util::sync::CancellationToken;

use crate::{
    resolver::Resolver,
    respond::{Clock, Conn, Reply, ReplyPath, Responder, Scratch},
    transport::tcp::SCRATCH,
    wire::MAX_MESSAGE_LEN,
};

/// Answers waiting beyond this many octets are written even while queries are buffered.
const FLUSH_AT: usize = 32 * 1024;

/// The answers waiting to be written, each with its length.
fn frame(pending: &mut Vec<u8>, message: &[u8]) {
    let len = u16::try_from(message.len()).unwrap_or(u16::MAX);
    pending.extend_from_slice(&len.to_be_bytes());
    pending.extend_from_slice(message);
}

/// Serves one connection until the client closes it, a message is cut, it stays idle for
/// `idle`, or the server stops.
pub(super) async fn connection<R, S>(
    stream: S,
    conn: Conn,
    responder: Arc<Responder<R>>,
    idle: Duration,
    stop: CancellationToken,
) where
    R: Resolver + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reader, writer) = tokio::io::split(stream);
    let mut reader = BufReader::with_capacity(16 * 1024, reader);
    let writer = Arc::new(AsyncMutex::new(writer));
    let mut message = vec![0u8; MAX_MESSAGE_LEN];
    let mut pending: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut forwarded: Option<mpsc::Sender<Vec<u8>>> = None;
    let mut clock = Clock::now();
    loop {
        let read = tokio::select! {
            () = stop.cancelled() => break,
            read = tokio::time::timeout(idle, reader.read_u16()) => read,
        };
        let Ok(Ok(len)) = read else {
            break;
        };
        let len = usize::from(len);
        let body = tokio::select! {
            () = stop.cancelled() => break,
            body = tokio::time::timeout(idle, reader.read_exact(&mut message[..len])) => body,
        };
        if !matches!(body, Ok(Ok(_))) {
            break;
        }
        let now = Instant::now();
        clock.refresh(now);
        let query = &message[..len];
        let reply = SCRATCH.with(|cell| {
            let mut slot = cell.borrow_mut();
            let scratch = slot.get_or_insert_with(Scratch::new);
            let reply = responder.respond(query, &conn, &clock, now, scratch);
            if reply == Reply::Send {
                frame(&mut pending, &scratch.out);
            }
            reply
        });
        if let Reply::Forward { .. } = reply {
            let sender = forwarded.get_or_insert_with(|| forward_writer(Arc::clone(&writer)));
            responder.forward(query, &conn, reply, ReplyPath::Tcp(sender.clone()));
        }
        if (reader.buffer().is_empty() || pending.len() >= FLUSH_AT) && !pending.is_empty() {
            let mut writer = writer.lock().await;
            if writer.write_all(&pending).await.is_err() || writer.flush().await.is_err() {
                break;
            }
            pending.clear();
        }
    }
    let mut writer = writer.lock().await;
    // Sends the TLS close_notify before the socket closes.
    let _ = writer.shutdown().await;
}

/// A channel into the connection for the forwarder's answers, written as they arrive.
fn forward_writer<S>(writer: Arc<AsyncMutex<WriteHalf<S>>>) -> mpsc::Sender<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(64);
    tokio::spawn(async move {
        let mut framed = Vec::new();
        while let Some(message) = receiver.recv().await {
            framed.clear();
            frame(&mut framed, &message);
            let mut writer = writer.lock().await;
            if writer.write_all(&framed).await.is_err() || writer.flush().await.is_err() {
                break;
            }
        }
    });
    sender
}
