//! The responder: the blocking-threads I/O mode of the Spike B responder, with the metrics
//! of `tenko_core::metrics` on its hot path when `--metrics on`.
//!
//! The worker loop is a copy of `blocking_worker` and `run_threads` in
//! `bench/spike-b-udp/src/server.rs` (N OS threads blocking in `recv_from` and `send_to` on
//! one shared socket, buffers reused for every packet), because the spike's library runs
//! its loop to the end and offers no hook for counters. The per-packet work, parse, lookup
//! and build, is the spike's own `backend::respond` with the `domain` codec, and the zone
//! is the spike's `example.test`. The spike's own per-worker counters are left out, so
//! `--metrics off` measures the responder with no instrumentation at all.
//!
//! With `--metrics on` every packet adds one to `bench_dns_queries_total{outcome}` and
//! records the time of `respond` (parse, lookup, build) in nanoseconds in
//! `bench_dns_query_duration_seconds`: a clock read before and after, one counter update and
//! one histogram observation per packet. The two variants are separate monomorphizations,
//! so the off variant carries no branch either.
//!
//! The server stops when its standard input closes, prints a `stats` line and exits.

use std::{
    io::{BufRead as _, Write as _},
    net::{SocketAddr, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::Context as _;
use socket2::{Domain, Protocol, Socket, Type};
use spike_b_udp::{
    backend::{Codec as _, DomainCodec, respond},
    zone::{DEFAULT_ZONE_SIZE, NameKey, Zone},
};
use tenko_core::metrics::{CounterVec, Desc, Histogram, Registry, encode};

/// Packets by outcome.
pub static QUERIES: CounterVec = CounterVec::fixed(
    Desc::counter("bench_dns_queries", "Packets by outcome.").labels(&["outcome"]),
    &[
        &["answered"],
        &["dropped"],
        &["recv_error"],
        &["send_error"],
    ],
);
/// Series of [`QUERIES`].
pub const ANSWERED: u16 = 0;
/// Series of [`QUERIES`].
pub const DROPPED: u16 = 1;
/// Series of [`QUERIES`].
pub const RECV_ERROR: u16 = 2;
/// Series of [`QUERIES`].
pub const SEND_ERROR: u16 = 3;

/// The time of `respond` per packet, in nanoseconds.
pub static QUERY_DURATION: Histogram = Histogram::new(Desc::histogram(
    "bench_dns_query_duration_seconds",
    "Time to parse a query, look the name up and build the response.",
    &[
        250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 1_000_000,
    ],
    1_000_000_000,
));

/// Receive buffer size: larger than any UDP DNS query that is answered.
const RECV_BUF: usize = 4096;
/// How often blocking workers wake up to check the stop flag.
const STOP_POLL: Duration = Duration::from_millis(200);

/// Whether the metrics are on the hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Metrics {
    /// Counters and the histogram on every packet.
    On,
    /// No instrumentation.
    Off,
}

impl Metrics {
    /// `on` or `off`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Metrics::On => "on",
            Metrics::Off => "off",
        }
    }
}

/// Options of `serve`.
#[derive(clap::Args, Debug, Clone)]
pub struct ServeArgs {
    /// Address to listen on (a loopback address).
    #[arg(long, default_value = "127.0.0.1:5399")]
    pub listen: SocketAddr,
    /// Number of worker threads on the shared socket.
    #[arg(long, default_value_t = 4)]
    pub workers: usize,
    /// Whether the metrics are on the hot path.
    #[arg(long, value_enum)]
    pub metrics: Metrics,
    /// Number of `host-{n}` names in the zone.
    #[arg(long, default_value_t = DEFAULT_ZONE_SIZE)]
    pub zone_size: u32,
    /// `SO_RCVBUF` and `SO_SNDBUF` in bytes (the spike's default).
    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    pub buffer: usize,
}

/// What every worker shares.
struct Shared {
    codec: DomainCodec,
    zone: Zone,
    stop: AtomicBool,
}

/// Runs the responder until standard input closes.
///
/// # Errors
///
/// A socket or thread error.
pub fn run(args: &ServeArgs) -> anyhow::Result<()> {
    anyhow::ensure!(args.workers >= 1, "--workers must be at least 1");
    anyhow::ensure!(
        args.listen.ip().is_loopback(),
        "--listen must be a loopback address"
    );
    let registry = Registry::new();
    if args.metrics == Metrics::On {
        registry.register(&QUERIES);
        registry.register(&QUERY_DURATION);
        // Seal both families before the first packet, so the hot path never allocates.
        let _ = (QUERIES.get(ANSWERED), QUERY_DURATION.get());
    }
    let socket = bind(args)?;
    let local = socket.local_addr()?;
    let shared = Arc::new(Shared {
        codec: DomainCodec::new(),
        zone: Zone::new(args.zone_size),
        stop: AtomicBool::new(false),
    });
    let mut handles = Vec::with_capacity(args.workers);
    for index in 0..args.workers {
        let socket = socket.try_clone()?;
        socket.set_read_timeout(Some(STOP_POLL))?;
        let shared = Arc::clone(&shared);
        let builder = std::thread::Builder::new().name(format!("udp-worker-{index}"));
        handles.push(match args.metrics {
            Metrics::On => builder.spawn(move || worker::<true>(&socket, &shared))?,
            Metrics::Off => builder.spawn(move || worker::<false>(&socket, &shared))?,
        });
    }
    drop(socket);
    {
        let mut out = std::io::stdout().lock();
        writeln!(
            out,
            "ready pid={} listen={local} workers={} metrics={} shards={}",
            std::process::id(),
            args.workers,
            args.metrics.as_str(),
            QUERIES.shards(),
        )?;
        out.flush()?;
    }
    // Serve until the parent closes standard input.
    for line in std::io::stdin().lock().lines() {
        if line.is_err() {
            break;
        }
    }
    shared.stop.store(true, Ordering::Relaxed);
    for handle in handles {
        let _ = handle.join();
    }
    if args.metrics == Metrics::On {
        let duration = QUERY_DURATION.get();
        println!(
            "stats answered={} dropped={} recv_errors={} send_errors={} observed={}",
            QUERIES.get(ANSWERED),
            QUERIES.get(DROPPED),
            QUERIES.get(RECV_ERROR),
            QUERIES.get(SEND_ERROR),
            duration.count(),
        );
        let mut text = String::new();
        encode(&registry.snapshot(), &mut text);
        eprint!("{text}");
    } else {
        println!("stats metrics=off");
    }
    Ok(())
}

/// One shared socket with the requested buffer sizes.
fn bind(args: &ServeArgs) -> anyhow::Result<UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(args.listen),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if args.buffer > 0 {
        let _ = socket.set_recv_buffer_size(args.buffer);
        let _ = socket.set_send_buffer_size(args.buffer);
    }
    socket
        .bind(&args.listen.into())
        .with_context(|| format!("bind {}", args.listen))?;
    Ok(socket.into())
}

/// The worker loop of the spike's blocking mode, with or without the metrics.
fn worker<const METRICS: bool>(socket: &UdpSocket, shared: &Shared) {
    let mut buf = vec![0_u8; RECV_BUF];
    let mut out = Vec::with_capacity(RECV_BUF);
    let mut key = NameKey::new();
    while !shared.stop.load(Ordering::Relaxed) {
        let (len, peer) = match socket.recv_from(&mut buf) {
            Ok(received) => received,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_) => {
                if METRICS {
                    QUERIES.inc(RECV_ERROR);
                }
                continue;
            }
        };
        let started = if METRICS { Some(Instant::now()) } else { None };
        let answer = respond(&shared.codec, &shared.zone, &buf[..len], &mut key, &mut out);
        if let Some(started) = started {
            QUERY_DURATION.observe(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
        }
        if answer {
            let sent = socket.send_to(&out, peer).is_ok();
            if METRICS {
                QUERIES.inc(if sent { ANSWERED } else { SEND_ERROR });
            }
        } else if METRICS {
            QUERIES.inc(DROPPED);
        }
    }
}
