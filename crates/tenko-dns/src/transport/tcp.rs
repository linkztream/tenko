//! DNS over TCP (RFC 7766) on the tokio runtime.
//!
//! Each message is preceded by its length in two octets. A client may send several queries
//! without waiting (pipelining); they are answered in the order they arrive, and the
//! answers are written together when no more input is buffered. A connection is closed
//! after [`TcpSettings::idle`] without a query (10 seconds by default), when a write of
//! answers takes longer than [`TcpSettings::write_timeout`] (5 seconds by default: a
//! client that does not read its answers loses the connection, not the node a writer),
//! when a message is cut, or when the server stops. The node accepts at most
//! [`TcpSettings::max_connections`] open connections (1,000 by default) and
//! [`TcpSettings::per_client`] from one client (10 by default), where a client is an IPv4
//! address or an IPv6 /64, as the rate limiter groups them; a connection over either cap
//! is closed at once.
//!
//! The query path is the one of UDP: the [`Responder`] with a [`Scratch`] kept per runtime
//! thread, so a query allocates nothing; only an answer from the forwarder, which arrives
//! later through a channel, is a fresh buffer. The forwarder hands its answers over without
//! waiting ([`ReplyPath::deliver`]): an answer a connection has no room for is dropped and
//! counted, never held while the forwarder's in-flight permit is.
//!
//! DoT ([`crate::tls`]) runs the same loop ([`serve_split`]) over a TLS stream.

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

use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use tenko_core::dns::QueryTransport;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{Mutex as AsyncMutex, mpsc},
};
use tokio_util::sync::CancellationToken;

use crate::{
    rate::limiter::prefix_bits,
    resolver::Resolver,
    respond::{Clock, Conn, Reply, ReplyPath, Responder, Scratch},
    wire::MAX_MESSAGE_LEN,
};

/// The limits of the TCP listeners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSettings {
    /// Open connections per node.
    pub max_connections: usize,
    /// Open connections per client: an IPv4 address, or an IPv6 /64.
    pub per_client: usize,
    /// Time without a query before a connection is closed.
    pub idle: Duration,
    /// Time a write of answers to a client may take before the connection is closed
    /// (`tcp.write_timeout_secs`).
    pub write_timeout: Duration,
}

impl Default for TcpSettings {
    fn default() -> Self {
        Self {
            max_connections: 1000,
            per_client: 10,
            idle: Duration::from_secs(10),
            write_timeout: Duration::from_secs(5),
        }
    }
}

/// The client a connection is counted under: the address family and the bits of its
/// prefix, a /32 for IPv4 and a /64 for IPv6 (the grouping of the rate limiter, so that
/// one /64 is one client).
type ClientKey = (u8, u128);

fn client_key(client: IpAddr) -> ClientKey {
    prefix_bits(client, 32, 64)
}

/// The open connections, in total and per client.
#[derive(Debug, Default)]
pub(crate) struct Limits {
    open: AtomicUsize,
    refused: AtomicU64,
    clients: Mutex<HashMap<ClientKey, usize>>,
}

impl Limits {
    pub(crate) fn open(&self) -> usize {
        self.open.load(Ordering::Relaxed)
    }

    pub(crate) fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// A place for a connection from `client`, or `None` over a cap.
    pub(crate) fn acquire(
        self: &Arc<Self>,
        client: IpAddr,
        settings: &TcpSettings,
    ) -> Option<Permit> {
        let key = client_key(client);
        let mut clients = self.clients.lock().unwrap_or_else(PoisonError::into_inner);
        let count = clients.entry(key).or_insert(0);
        if self.open.load(Ordering::Relaxed) >= settings.max_connections
            || *count >= settings.per_client
        {
            if *count == 0 {
                clients.remove(&key);
            }
            self.refused.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        *count += 1;
        self.open.fetch_add(1, Ordering::Relaxed);
        Some(Permit {
            limits: Arc::clone(self),
            client: key,
        })
    }
}

/// One open connection, given back when dropped.
pub(crate) struct Permit {
    limits: Arc<Limits>,
    client: ClientKey,
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

/// Sets the options of an accepted connection: no delay, keepalive probes once the
/// connection has been quiet for the idle time, and, where the platform has it, the
/// kernel's own deadline on unacknowledged data (`TCP_USER_TIMEOUT` on Linux) at the write
/// deadline, so that a peer that stopped acknowledging is dropped by the kernel as the
/// writer drops it. An option the platform refuses is skipped.
pub(crate) fn tune(stream: &TcpStream, settings: &TcpSettings) {
    let socket = SockRef::from(stream);
    let _ = socket.set_tcp_nodelay(true);
    let second = Duration::from_secs(1);
    let keepalive = TcpKeepalive::new().with_time(settings.idle.max(second));
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    let keepalive = keepalive.with_interval(settings.write_timeout.max(second));
    let _ = socket.set_tcp_keepalive(&keepalive);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let _ = socket.set_tcp_user_timeout(Some(settings.write_timeout.max(second)));
}

/// Answers waiting beyond this many octets are written even while queries are buffered.
const FLUSH_AT: usize = 32 * 1024;

/// Forwarded answers waiting for a connection's writer; an answer beyond it is dropped and
/// counted ([`crate::respond::replies_dropped`]).
const FORWARD_CHANNEL: usize = 64;

thread_local! {
    /// The query buffers of a runtime thread; borrowed only between two awaits (DoT and DoH
    /// share them, `crate::tls`).
    pub(crate) static SCRATCH: RefCell<Option<Scratch>> = const { RefCell::new(None) };
}

/// Accepts connections until `stop` is canceled.
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
        tune(&stream, &settings);
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
pub(crate) fn frame(pending: &mut Vec<u8>, message: &[u8]) {
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
    serve_split(reader, writer, conn, responder, settings, stop, false).await;
}

/// Writes `data` under the writer's lock within the write deadline. `false` when the write
/// failed, ran out of time or the server stops: the connection is then closed, so a
/// client that does not read holds nothing but its own connection, and the lock is never
/// held longer than the deadline.
async fn write<W: AsyncWrite + Unpin>(
    writer: &AsyncMutex<W>,
    data: &[u8],
    settings: &TcpSettings,
    stop: &CancellationToken,
) -> bool {
    let write = async {
        let mut writer = writer.lock().await;
        writer.write_all(data).await.is_ok() && writer.flush().await.is_ok()
    };
    tokio::select! {
        () = stop.cancelled() => false,
        done = tokio::time::timeout(settings.write_timeout, write) => done.unwrap_or(false),
    }
}

/// Serves one length-prefixed stream, split into its halves, until the client closes it, a
/// message is cut, it stays idle, a write runs out of time, or the server stops. `xot`
/// when this node ended TLS on it: a transfer over it is XoT. Pipelined queries already
/// received are answered before anything is written, up to a bound on what waits; a
/// forwarded query's answer is written as it arrives.
pub(crate) async fn serve_split<R, Rd, W>(
    reader: Rd,
    writer: W,
    conn: Conn,
    responder: Arc<Responder<R>>,
    settings: TcpSettings,
    stop: CancellationToken,
    xot: bool,
) where
    R: Resolver + 'static,
    Rd: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut reader = BufReader::with_capacity(16 * 1024, reader);
    let writer = Arc::new(AsyncMutex::new(writer));
    // Canceled when a write failed or ran out of time, by whichever side wrote.
    let ended = CancellationToken::new();
    let mut message = vec![0u8; MAX_MESSAGE_LEN];
    let mut pending: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut forwarded: Option<mpsc::Sender<Vec<u8>>> = None;
    let mut clock = Clock::now();
    loop {
        let read = tokio::select! {
            () = stop.cancelled() => break,
            () = ended.cancelled() => break,
            read = tokio::time::timeout(settings.idle, reader.read_u16()) => read,
        };
        let Ok(Ok(len)) = read else {
            break;
        };
        let len = usize::from(len);
        let body = tokio::select! {
            () = stop.cancelled() => break,
            () = ended.cancelled() => break,
            body = tokio::time::timeout(settings.idle, reader.read_exact(&mut message[..len])) => body,
        };
        if !matches!(body, Ok(Ok(_))) {
            break;
        }
        let now = Instant::now();
        clock.refresh(now);
        let query = &message[..len];
        // WP6.1: a transfer streams its messages after the answers already waiting.
        if let Some(mut transfer) = responder.transfer_stream(query, &conn, xot) {
            if !pending.is_empty() {
                if !write(&writer, &pending, &settings, &stop).await {
                    break;
                }
                pending.clear();
            }
            let mut failed = false;
            loop {
                let answer = tokio::select! {
                    () = stop.cancelled() => {
                        failed = true;
                        break;
                    }
                    () = ended.cancelled() => {
                        failed = true;
                        break;
                    }
                    next = transfer.recv() => match next {
                        Some(answer) => answer,
                        None => break,
                    },
                };
                pending.clear();
                frame(&mut pending, &answer);
                if !write(&writer, &pending, &settings, &stop).await {
                    failed = true;
                    break;
                }
            }
            pending.clear();
            if failed {
                break;
            }
            continue;
        }
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
            let sender = forwarded.get_or_insert_with(|| {
                forward_writer(Arc::clone(&writer), settings, stop.clone(), ended.clone())
            });
            responder.forward(query, &conn, reply, ReplyPath::Tcp(sender.clone()));
        }
        // Pipelined queries already received are answered before anything is written, up
        // to a bound on what waits.
        if (reader.buffer().is_empty() || pending.len() >= FLUSH_AT) && !pending.is_empty() {
            if !write(&writer, &pending, &settings, &stop).await {
                break;
            }
            pending.clear();
        }
    }
    // The close (for TLS, the close_notify) waits no longer than a write may take: a
    // connection whose client stopped reading is dropped as it is.
    let _ = tokio::time::timeout(settings.write_timeout, async {
        let _ = writer.lock().await.shutdown().await;
    })
    .await;
    ended.cancel();
}

/// A channel into the connection for the forwarder's answers, written as they arrive. The
/// writer task ends the connection when a write fails or runs out of time, and leaves when
/// the connection ends.
fn forward_writer<W>(
    writer: Arc<AsyncMutex<W>>,
    settings: TcpSettings,
    stop: CancellationToken,
    ended: CancellationToken,
) -> mpsc::Sender<Vec<u8>>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(FORWARD_CHANNEL);
    tokio::spawn(async move {
        let mut framed = Vec::new();
        loop {
            let message = tokio::select! {
                () = ended.cancelled() => break,
                () = stop.cancelled() => break,
                next = receiver.recv() => match next {
                    Some(message) => message,
                    None => break,
                },
            };
            framed.clear();
            frame(&mut framed, &message);
            if !write(&writer, &framed, &settings, &stop).await {
                ended.cancel();
                break;
            }
        }
    });
    sender
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use tenko_core::Revision;

    use super::*;
    use crate::{
        authoritative::Authoritative,
        catalog::{Catalog, CatalogHandle},
        cookie::CookieSecret,
        feed::DnsData,
    };

    /// A writer whose client never reads: every write stays pending.
    struct Stalled;

    impl AsyncWrite for Stalled {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    fn responder() -> Arc<Responder<Authoritative>> {
        let catalog = CatalogHandle::new(Catalog::build(&DnsData::at(Revision(1))));
        Arc::new(
            Responder::new(
                Authoritative::new(catalog),
                CookieSecret::with_secret([7; 16]),
            )
            .with_metrics(false),
        )
    }

    fn conn() -> Conn {
        Conn {
            client: "192.0.2.77:40000".parse().expect("client"),
            local: "192.0.2.53:53".parse().expect("local"),
            transport: QueryTransport::Tcp,
        }
    }

    /// `example.test` A, framed for a stream.
    fn framed_query() -> Vec<u8> {
        let mut message = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        message.extend_from_slice(b"\x07example\x04test\x00\x00\x01\x00\x01");
        let mut out = Vec::new();
        frame(&mut out, &message);
        out
    }

    /// A connection whose client sends queries and never reads the answers is closed once
    /// a write has waited the write deadline, and its place under the caps is given back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_client_that_does_not_read_is_closed_at_the_write_deadline() {
        let settings = TcpSettings {
            idle: Duration::from_secs(30),
            write_timeout: Duration::from_millis(200),
            ..TcpSettings::default()
        };
        let limits = Arc::new(Limits::default());
        let permit = limits
            .acquire(conn().client.ip(), &settings)
            .expect("a place");
        assert_eq!(limits.open(), 1);
        let (mut client, from_client) = tokio::io::duplex(64 * 1024);
        let stop = CancellationToken::new();
        let served = tokio::spawn(async move {
            let _permit = permit;
            serve_split(
                from_client,
                Stalled,
                conn(),
                responder(),
                settings,
                stop,
                false,
            )
            .await;
        });
        client.write_all(&framed_query()).await.expect("a query");
        let started = Instant::now();
        tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("the connection ends at the deadline")
            .expect("the task joins");
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(200),
            "the write waited its deadline: {took:?}"
        );
        assert!(
            took < Duration::from_secs(3),
            "the connection ended soon after: {took:?}"
        );
        assert_eq!(limits.open(), 0, "the permit is given back");
    }

    /// The per-client cap counts an IPv6 /64 as one client and IPv4 addresses one by one.
    #[test]
    fn the_per_client_cap_groups_an_ipv6_64() {
        let settings = TcpSettings {
            per_client: 2,
            ..TcpSettings::default()
        };
        let limits = Arc::new(Limits::default());
        let first = limits
            .acquire("2001:db8:1:2::1".parse().expect("ip"), &settings)
            .expect("the first of the /64");
        let second = limits
            .acquire(
                "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().expect("ip"),
                &settings,
            )
            .expect("the second of the /64");
        assert!(
            limits
                .acquire("2001:db8:1:2:8000::1".parse().expect("ip"), &settings)
                .is_none(),
            "a third address of the same /64 is over the cap"
        );
        assert_eq!(limits.refused(), 1);
        let other = limits
            .acquire("2001:db8:1:3::1".parse().expect("ip"), &settings)
            .expect("the next /64 is another client");
        drop(first);
        let _again = limits
            .acquire("2001:db8:1:2::77".parse().expect("ip"), &settings)
            .expect("a place is free again");
        let v4_a = limits
            .acquire("192.0.2.1".parse().expect("ip"), &settings)
            .expect("ipv4");
        let v4_b = limits
            .acquire("192.0.2.1".parse().expect("ip"), &settings)
            .expect("ipv4 again");
        assert!(
            limits
                .acquire("192.0.2.1".parse().expect("ip"), &settings)
                .is_none()
        );
        let _neighbor = limits
            .acquire("192.0.2.2".parse().expect("ip"), &settings)
            .expect("another IPv4 address is another client");
        assert_eq!(limits.open(), 6);
        drop((second, other, v4_a, v4_b));
        assert_eq!(limits.open(), 2);
    }
}
