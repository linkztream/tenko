//! The UDP workers (ADR 0009): blocking threads, per-worker buffers and counters, one
//! `SO_REUSEPORT` socket per worker on Linux and one shared socket on Windows.
//!
//! A worker blocks in `recv_from` with a read timeout of [`STOP_POLL`], so that it sees the
//! stop flag within that time; it reads the wall clock once a second, not per query. Its
//! receive buffer holds the largest datagram, so an oversized query is read whole and
//! answered (FORMERR or the answer), never cut.

use std::{
    io,
    net::{SocketAddr, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use socket2::{Domain, Protocol, Socket, Type};
use tenko_core::dns::QueryTransport;

use super::{SocketMode, WorkerCounters, WorkerSlot};
use crate::{
    resolver::Resolver,
    respond::{Clock, Conn, Reply, ReplyPath, Responder, Scratch},
    wire::MAX_MESSAGE_LEN,
};

/// How often a blocked worker wakes to look at the stop flag.
pub const STOP_POLL: Duration = Duration::from_millis(200);

/// The settings of the UDP listeners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSettings {
    /// Workers per listen address, at least 1.
    pub workers: usize,
    /// Socket per worker or one shared socket.
    pub mode: SocketMode,
    /// `SO_RCVBUF` in octets (0 keeps the system's).
    pub recv_buffer: usize,
    /// `SO_SNDBUF` in octets (0 keeps the system's).
    pub send_buffer: usize,
}

impl Default for UdpSettings {
    fn default() -> Self {
        Self {
            workers: std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get),
            mode: SocketMode::platform_default(),
            recv_buffer: 8 * 1024 * 1024,
            send_buffer: 8 * 1024 * 1024,
        }
    }
}

/// The sockets of one listen address.
#[derive(Debug)]
pub(crate) struct Bound {
    /// The address bound (the port the system chose for port 0).
    pub(crate) local: SocketAddr,
    pub(crate) sockets: Vec<Arc<UdpSocket>>,
}

#[cfg(target_os = "linux")]
fn set_reuse_port(socket: &Socket) -> io::Result<()> {
    socket.set_reuse_port(true)
}

#[cfg(not(target_os = "linux"))]
fn set_reuse_port(_socket: &Socket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_REUSEPORT spreading is a Linux feature; use the shared socket mode",
    ))
}

fn bind_one(address: SocketAddr, settings: &UdpSettings, reuse: bool) -> io::Result<UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    // The buffer sizes are wishes: the system caps them (net.core.rmem_max on Linux).
    if settings.recv_buffer > 0 {
        let _ = socket.set_recv_buffer_size(settings.recv_buffer);
    }
    if settings.send_buffer > 0 {
        let _ = socket.set_send_buffer_size(settings.send_buffer);
    }
    if reuse {
        set_reuse_port(&socket)?;
    }
    socket.bind(&address.into())?;
    let socket: UdpSocket = socket.into();
    socket.set_read_timeout(Some(STOP_POLL))?;
    Ok(socket)
}

/// Binds the sockets of one listen address: one per worker with `SO_REUSEPORT`, else one.
pub(crate) fn bind(address: SocketAddr, settings: &UdpSettings) -> io::Result<Bound> {
    let reuse = settings.mode == SocketMode::ReusePort;
    let first = bind_one(address, settings, reuse)?;
    let local = first.local_addr()?;
    let mut sockets = vec![Arc::new(first)];
    if reuse {
        for _ in 1..settings.workers.max(1) {
            sockets.push(Arc::new(bind_one(local, settings, true)?));
        }
    }
    Ok(Bound { local, sockets })
}

/// Starts the workers of one listen address.
pub(crate) fn spawn<R: Resolver + 'static>(
    bound: &Bound,
    settings: &UdpSettings,
    responder: &Arc<Responder<R>>,
    stop: &Arc<AtomicBool>,
    first_index: usize,
) -> io::Result<Vec<(JoinHandle<()>, WorkerSlot)>> {
    let mut workers = Vec::with_capacity(settings.workers);
    for worker in 0..settings.workers.max(1) {
        let socket_index = worker % bound.sockets.len();
        let socket = Arc::clone(&bound.sockets[socket_index]);
        let counters = Arc::new(WorkerCounters::default());
        let slot = WorkerSlot {
            listen: bound.local,
            socket: socket_index,
            counters: Arc::clone(&counters),
        };
        let responder = Arc::clone(responder);
        let stop = Arc::clone(stop);
        let local = bound.local;
        let handle = std::thread::Builder::new()
            .name(format!("dns-udp-{}", first_index + worker))
            .spawn(move || run(&socket, local, &responder, &stop, &counters))?;
        workers.push((handle, slot));
    }
    Ok(workers)
}

fn run<R: Resolver>(
    socket: &Arc<UdpSocket>,
    local: SocketAddr,
    responder: &Responder<R>,
    stop: &AtomicBool,
    counters: &WorkerCounters,
) {
    let mut buf = vec![0u8; MAX_MESSAGE_LEN];
    let mut scratch = Scratch::new();
    let mut clock = Clock::now();
    while !stop.load(Ordering::Relaxed) {
        let (len, client) = match socket.recv_from(&mut buf) {
            Ok(received) => received,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            // Windows reports the ICMP port unreachable of an earlier answer as a reset on
            // a later receive; nothing to do but count it.
            Err(_) => {
                WorkerCounters::bump(&counters.recv_errors);
                continue;
            }
        };
        let now = Instant::now();
        clock.refresh(now);
        WorkerCounters::bump(&counters.received);
        let conn = Conn {
            client,
            local,
            transport: QueryTransport::Udp,
        };
        let message = &buf[..len];
        match responder.respond(message, &conn, &clock, now, &mut scratch) {
            Reply::Send => match socket.send_to(&scratch.out, client) {
                Ok(_) => WorkerCounters::bump(&counters.sent),
                Err(_) => WorkerCounters::bump(&counters.send_errors),
            },
            Reply::Drop => WorkerCounters::bump(&counters.dropped),
            reply @ Reply::Forward { .. } => {
                WorkerCounters::bump(&counters.forwarded);
                responder.forward(message, &conn, reply, ReplyPath::Udp(Arc::clone(socket)));
            }
        }
    }
}
