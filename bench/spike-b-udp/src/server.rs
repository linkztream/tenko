//! The UDP responder: socket setup and the two I/O modes.
//!
//! Both modes run the same per-packet hot path, [`crate::backend::respond`],
//! with one receive buffer, one response buffer and one lookup key per
//! worker, all reused for every packet.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Context;
use socket2::{Domain as SockDomain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

#[cfg(feature = "backend-domain")]
use crate::backend::DomainCodec;
#[cfg(feature = "backend-hickory")]
use crate::backend::HickoryCodec;
use crate::backend::{BackendKind, Codec, respond};
use crate::zone::{NameKey, Zone};

/// I/O design of the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum IoMode {
    /// N tokio tasks on a multi-threaded runtime with N worker threads.
    Tokio,
    /// N OS threads blocking in `recv_from` / `send_to`.
    Threads,
}

impl IoMode {
    pub fn as_str(self) -> &'static str {
        match self {
            IoMode::Tokio => "tokio",
            IoMode::Threads => "threads",
        }
    }
}

#[derive(clap::Args, Debug, Clone)]
pub struct ServeArgs {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:5353")]
    pub listen: SocketAddr,
    /// DNS wire-format crate used for parse and build.
    #[arg(long, value_enum)]
    pub backend: BackendKind,
    /// I/O mode.
    #[arg(long, value_enum, default_value = "tokio")]
    pub mode: IoMode,
    /// Number of workers (tokio tasks and runtime threads, or OS threads).
    #[arg(long, default_value_t = 1)]
    pub workers: usize,
    /// Linux only: bind one SO_REUSEPORT socket per worker instead of sharing one socket.
    #[arg(long)]
    pub reuseport: bool,
    /// Number of `host-{n}` names in the zone.
    #[arg(long, default_value_t = crate::zone::DEFAULT_ZONE_SIZE)]
    pub zone_size: u32,
    /// SO_RCVBUF in bytes (0 keeps the OS default).
    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    pub rcvbuf: usize,
    /// SO_SNDBUF in bytes (0 keeps the OS default).
    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    pub sndbuf: usize,
}

/// Per-worker packet counters, padded to avoid false sharing.
#[derive(Default)]
#[repr(align(128))]
pub struct WorkerCounters {
    pub received: AtomicU64,
    pub sent: AtomicU64,
    pub dropped: AtomicU64,
    pub recv_errors: AtomicU64,
    pub send_errors: AtomicU64,
}

#[inline]
fn bump(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

/// Everything a worker needs, shared read-only.
struct Shared<C> {
    codec: C,
    zone: Zone,
    counters: Vec<WorkerCounters>,
    stop: AtomicBool,
}

/// Receive buffer size: larger than any UDP DNS query we answer.
const RECV_BUF: usize = 4096;
/// How often blocking workers wake up to check the stop flag.
const STOP_POLL: Duration = Duration::from_millis(200);

#[cfg(all(
    unix,
    not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin"))
))]
const REUSEPORT_SUPPORTED: bool = true;
#[cfg(not(all(
    unix,
    not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin"))
)))]
const REUSEPORT_SUPPORTED: bool = false;

#[cfg(all(
    unix,
    not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin"))
))]
fn set_reuse_port(s: &Socket) -> std::io::Result<()> {
    s.set_reuse_port(true)
}

#[cfg(not(all(
    unix,
    not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin"))
)))]
fn set_reuse_port(_s: &Socket) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "SO_REUSEPORT not available",
    ))
}

pub fn run(args: &ServeArgs) -> anyhow::Result<()> {
    anyhow::ensure!(args.workers >= 1, "--workers must be at least 1");
    if args.reuseport && !REUSEPORT_SUPPORTED {
        anyhow::bail!(
            "--reuseport needs SO_REUSEPORT load balancing (Linux); it is not available on this OS"
        );
    }
    match args.backend {
        #[cfg(feature = "backend-domain")]
        BackendKind::Domain => run_with::<DomainCodec>(args),
        #[cfg(feature = "backend-hickory")]
        BackendKind::Hickory => run_with::<HickoryCodec>(args),
    }
}

/// Creates one socket bound to `addr` with the requested buffer sizes.
fn bind_one(
    addr: SocketAddr,
    args: &ServeArgs,
    nonblocking: bool,
) -> anyhow::Result<std::net::UdpSocket> {
    let s = Socket::new(
        SockDomain::for_address(addr),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if args.rcvbuf > 0
        && let Err(e) = s.set_recv_buffer_size(args.rcvbuf)
    {
        tracing::warn!("SO_RCVBUF {}: {e}", args.rcvbuf);
    }
    if args.sndbuf > 0
        && let Err(e) = s.set_send_buffer_size(args.sndbuf)
    {
        tracing::warn!("SO_SNDBUF {}: {e}", args.sndbuf);
    }
    if args.reuseport {
        set_reuse_port(&s).context("SO_REUSEPORT")?;
    }
    s.set_nonblocking(nonblocking)?;
    s.bind(&addr.into())
        .with_context(|| format!("bind {addr}"))?;
    tracing::debug!(
        "socket bound to {addr}: SO_RCVBUF={:?} SO_SNDBUF={:?}",
        s.recv_buffer_size().ok(),
        s.send_buffer_size().ok()
    );
    Ok(s.into())
}

/// One shared socket, or (with `--reuseport`) one socket per worker on the same address.
fn bind_sockets(args: &ServeArgs, nonblocking: bool) -> anyhow::Result<Vec<std::net::UdpSocket>> {
    let first = bind_one(args.listen, args, nonblocking)?;
    let actual = first.local_addr()?;
    let mut socks = vec![first];
    if args.reuseport {
        for _ in 1..args.workers {
            socks.push(bind_one(actual, args, nonblocking)?);
        }
    }
    Ok(socks)
}

fn run_with<C: Codec>(args: &ServeArgs) -> anyhow::Result<()> {
    let shared = Arc::new(Shared {
        codec: C::new(),
        zone: Zone::new(args.zone_size),
        counters: (0..args.workers)
            .map(|_| WorkerCounters::default())
            .collect(),
        stop: AtomicBool::new(false),
    });
    let socks = bind_sockets(args, args.mode == IoMode::Tokio)?;
    let local = socks[0].local_addr()?;

    let announce = || -> anyhow::Result<()> {
        let mut out = std::io::stdout().lock();
        writeln!(
            out,
            "ready pid={} listen={} backend={} mode={} workers={} reuseport={} zone_size={}",
            std::process::id(),
            local,
            C::NAME,
            args.mode.as_str(),
            args.workers,
            args.reuseport,
            args.zone_size
        )?;
        out.flush()?;
        Ok(())
    };

    match args.mode {
        IoMode::Tokio => run_tokio(args.workers, socks, &shared, announce)?,
        IoMode::Threads => run_threads(args.workers, socks, &shared, announce)?,
    }
    print_stats(&shared.counters);
    Ok(())
}

fn print_stats(counters: &[WorkerCounters]) {
    let sum = |f: fn(&WorkerCounters) -> &AtomicU64| -> u64 {
        counters.iter().map(|c| f(c).load(Ordering::Relaxed)).sum()
    };
    let per_worker: Vec<u64> = counters
        .iter()
        .map(|c| c.received.load(Ordering::Relaxed))
        .collect();
    println!(
        "stats received={} sent={} dropped={} recv_errors={} send_errors={} per_worker_received={:?}",
        sum(|c| &c.received),
        sum(|c| &c.sent),
        sum(|c| &c.dropped),
        sum(|c| &c.recv_errors),
        sum(|c| &c.send_errors),
        per_worker
    );
}

// ---------------------------------------------------------------- tokio mode

fn run_tokio<C: Codec>(
    workers: usize,
    socks: Vec<std::net::UdpSocket>,
    shared: &Arc<Shared<C>>,
    announce: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_name("udp-worker")
        .enable_all()
        .build()?;
    rt.block_on(async {
        let socks: Vec<Arc<UdpSocket>> = socks
            .into_iter()
            .map(|s| UdpSocket::from_std(s).map(Arc::new))
            .collect::<Result<_, _>>()?;
        for i in 0..workers {
            // Shared socket: every task gets the same one. SO_REUSEPORT: one each.
            let sock = Arc::clone(&socks[i % socks.len()]);
            tokio::spawn(tokio_worker(sock, Arc::clone(shared), i));
        }
        announce()?;
        tokio::signal::ctrl_c().await?;
        shared.stop.store(true, Ordering::Relaxed);
        anyhow::Ok(())
    })?;
    rt.shutdown_timeout(Duration::from_secs(1));
    Ok(())
}

async fn tokio_worker<C: Codec>(sock: Arc<UdpSocket>, shared: Arc<Shared<C>>, idx: usize) {
    let ctr = &shared.counters[idx];
    let mut buf = vec![0u8; RECV_BUF];
    let mut out = Vec::with_capacity(RECV_BUF);
    let mut key = NameKey::new();
    loop {
        let (len, peer) = match sock.recv_from(&mut buf).await {
            Ok(r) => r,
            // Windows reports the ICMP port unreachable of an earlier send as
            // WSAECONNRESET on a later receive; it is not fatal.
            Err(_) => {
                bump(&ctr.recv_errors);
                continue;
            }
        };
        bump(&ctr.received);
        if respond(&shared.codec, &shared.zone, &buf[..len], &mut key, &mut out) {
            match sock.send_to(&out, peer).await {
                Ok(_) => bump(&ctr.sent),
                Err(_) => bump(&ctr.send_errors),
            }
        } else {
            bump(&ctr.dropped);
        }
    }
}

// -------------------------------------------------------------- threads mode

fn run_threads<C: Codec>(
    workers: usize,
    socks: Vec<std::net::UdpSocket>,
    shared: &Arc<Shared<C>>,
    announce: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut handles = Vec::with_capacity(workers);
    for i in 0..workers {
        // Shared socket: a duplicated handle of the same socket per thread.
        // SO_REUSEPORT: the thread's own socket.
        let sock = socks[i % socks.len()].try_clone()?;
        sock.set_read_timeout(Some(STOP_POLL))?;
        let shared = Arc::clone(shared);
        handles.push(
            std::thread::Builder::new()
                .name(format!("udp-worker-{i}"))
                .spawn(move || blocking_worker(&sock, &shared, i))?,
        );
    }
    drop(socks);
    announce()?;
    let signal_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    signal_rt.block_on(tokio::signal::ctrl_c())?;
    shared.stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

fn blocking_worker<C: Codec>(sock: &std::net::UdpSocket, shared: &Shared<C>, idx: usize) {
    let ctr = &shared.counters[idx];
    let mut buf = vec![0u8; RECV_BUF];
    let mut out = Vec::with_capacity(RECV_BUF);
    let mut key = NameKey::new();
    while !shared.stop.load(Ordering::Relaxed) {
        let (len, peer) = match sock.recv_from(&mut buf) {
            Ok(r) => r,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_) => {
                bump(&ctr.recv_errors);
                continue;
            }
        };
        bump(&ctr.received);
        if respond(&shared.codec, &shared.zone, &buf[..len], &mut key, &mut out) {
            match sock.send_to(&out, peer) {
                Ok(_) => bump(&ctr.sent),
                Err(_) => bump(&ctr.send_errors),
            }
        } else {
            bump(&ctr.dropped);
        }
    }
}
