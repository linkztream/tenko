//! DNS over TCP (RFC 7766) on the tokio runtime.
//!
//! Each message is preceded by its length in two octets. A client may send several queries
//! without waiting (pipelining); they are answered in the order they arrive, and the
//! answers are written together when no more input is buffered. A connection is closed
//! after [`TcpSettings::idle`] without a query (10 seconds by default), when a message is
//! cut, or when the server stops. The node accepts at most
//! [`TcpSettings::max_connections`] open connections (1,000 by default) and
//! [`TcpSettings::per_client`] from one client address (10 by default); a connection over
//! either cap is closed at once.
//!
//! The query path is the one of UDP: the [`Responder`] with a [`Scratch`] kept per runtime
//! thread, so a query allocates nothing; only an answer from the forwarder, which arrives
//! later through a channel, is a fresh buffer.

use std::{
    cell::RefCell,
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use socket2::{Domain, Protocol, Socket, Type};
use tenko_core::dns::QueryTransport;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, tcp::OwnedWriteHalf},
    sync::{Mutex as AsyncMutex, mpsc},
};
use tokio_util::sync::CancellationToken;

use crate::{
    resolver::Resolver,
    respond::{Clock, Conn, Reply, ReplyPath, Responder, Scratch},
    wire::MAX_MESSAGE_LEN,
};

/// The limits of the TCP listeners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSettings {
    /// Open connections per node.
    pub max_connections: usize,
    /// Open connections per client address.
    pub per_client: usize,
    /// Time without a query before a connection is closed.
    pub idle: Duration,
}

impl Default for TcpSettings {
    fn default() -> Self {
        Self {
            max_connections: 1000,
            per_client: 10,
            idle: Duration::from_secs(10),
        }
    }
}

/// The open connections, in total and per client.
#[derive(Debug, Default)]
pub(crate) struct Limits {
    open: AtomicUsize,
    refused: AtomicU64,
    clients: Mutex<HashMap<IpAddr, usize>>,
}

impl Limits {
    pub(crate) fn open(&self) -> usize {
        self.open.load(Ordering::Relaxed)
    }

    pub(crate) fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// A place for a connection from `client`, or `None` over a cap.
    fn acquire(self: &Arc<Self>, client: IpAddr, settings: &TcpSettings) -> Option<Permit> {
        let mut clients = self.clients.lock().unwrap_or_else(PoisonError::into_inner);
        let count = clients.entry(client).or_insert(0);
        if self.open.load(Ordering::Relaxed) >= settings.max_connections
            || *count >= settings.per_client
        {
            if *count == 0 {
                clients.remove(&client);
            }
            self.refused.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        *count += 1;
        self.open.fetch_add(1, Ordering::Relaxed);
        Some(Permit {
            limits: Arc::clone(self),
            client,
        })
    }
}

/// One open connection, given back when dropped.
struct Permit {
    limits: Arc<Limits>,
    client: IpAddr,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut clients = self
            .limits
            .clients
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = clients.get_mut(&self.client) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                clients.remove(&self.client);
            }
        }
        self.limits.open.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Binds a TCP listener: IPv6-only for an IPv6 address, address reuse on Unix so that a
/// restart does not wait for the old connections.
pub(crate) fn bind(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.set_tcp_nodelay(true)?;
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

/// Answers waiting beyond this many octets are written even while queries are buffered.
const FLUSH_AT: usize = 32 * 1024;

thread_local! {
    /// The query buffers of a runtime thread; borrowed only between two awaits.
    static SCRATCH: RefCell<Option<Scratch>> = const { RefCell::new(None) };
}

/// Accepts connections until `stop` is cancelled.
pub(crate) async fn serve<R: Resolver + 'static>(
    listener: TcpListener,
    responder: Arc<Responder<R>>,
    limits: Arc<Limits>,
    settings: TcpSettings,
    stop: CancellationToken,
) {
    let Ok(local) = listener.local_addr() else {
        return;
    };
    loop {
        let accepted = tokio::select! {
            () = stop.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, client)) = accepted else {
            // Out of file descriptors and the like: let the system recover.
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        };
        let Some(permit) = limits.acquire(client.ip(), &settings) else {
            drop(stream);
            continue;
        };
        let _ = stream.set_nodelay(true);
        let conn = Conn {
            client,
            local,
            transport: QueryTransport::Tcp,
        };
        tokio::spawn(connection(
            stream,
            conn,
            Arc::clone(&responder),
            settings,
            stop.clone(),
            permit,
        ));
    }
}

/// The answers waiting to be written, each with its length.
fn frame(pending: &mut Vec<u8>, message: &[u8]) {
    let len = u16::try_from(message.len()).unwrap_or(u16::MAX);
    pending.extend_from_slice(&len.to_be_bytes());
    pending.extend_from_slice(message);
}

async fn connection<R: Resolver + 'static>(
    stream: TcpStream,
    conn: Conn,
    responder: Arc<Responder<R>>,
    settings: TcpSettings,
    stop: CancellationToken,
    _permit: Permit,
) {
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::with_capacity(16 * 1024, reader);
    let writer = Arc::new(AsyncMutex::new(writer));
    let mut message = vec![0u8; MAX_MESSAGE_LEN];
    let mut pending: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut forwarded: Option<mpsc::Sender<Vec<u8>>> = None;
    let mut clock = Clock::now();
    loop {
        let read = tokio::select! {
            () = stop.cancelled() => break,
            read = tokio::time::timeout(settings.idle, reader.read_u16()) => read,
        };
        let Ok(Ok(len)) = read else {
            break;
        };
        let len = usize::from(len);
        let body = tokio::select! {
            () = stop.cancelled() => break,
            body = tokio::time::timeout(settings.idle, reader.read_exact(&mut message[..len])) => body,
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
        // Pipelined queries already received are answered before anything is written, up
        // to a bound on what waits.
        if (reader.buffer().is_empty() || pending.len() >= FLUSH_AT) && !pending.is_empty() {
            let mut writer = writer.lock().await;
            if writer.write_all(&pending).await.is_err() {
                break;
            }
            pending.clear();
        }
    }
    let mut writer = writer.lock().await;
    let _ = writer.shutdown().await;
}

/// A channel into the connection for the forwarder's answers, written as they arrive.
fn forward_writer(writer: Arc<AsyncMutex<OwnedWriteHalf>>) -> mpsc::Sender<Vec<u8>> {
    let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(64);
    tokio::spawn(async move {
        let mut framed = Vec::new();
        while let Some(message) = receiver.recv().await {
            framed.clear();
            frame(&mut framed, &message);
            if writer.lock().await.write_all(&framed).await.is_err() {
                break;
            }
        }
    });
    sender
}
