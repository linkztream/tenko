//! Closed-loop UDP DNS load generator.
//!
//! Each client is one OS thread owning one connected UDP socket and keeping a
//! fixed number of queries outstanding: whenever a response arrives (or a query
//! times out) the slot is refilled immediately.
//!
//! * Matching is by DNS ID. A 65,536-entry table maps an ID to the slot that
//!   owns it; IDs come from a wrapping counter and skip IDs that are still
//!   outstanding, so a new query never reuses an ID that is in flight and a
//!   late response to a timed-out query is not confused with a newer one.
//! * Timeouts are found by scanning the slots every few milliseconds (at most
//!   4096 per client), so a lost query is noticed within `timeout` + one scan
//!   interval + one socket read timeout.
//! * All threads share one start instant. The measurement window is
//!   `[start + warmup, start + warmup + duration)`; only events inside it are
//!   counted. After the window the threads stop sending and drain for at most
//!   200 ms.
//! * Steady state does not allocate: query buffers are per slot and reused,
//!   the receive buffer is allocated once, latencies go into an HDR histogram.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, anyhow, bail};
use hdrhistogram::Histogram;
use rand::rngs::SmallRng;
use rand::{Rng, RngExt, SeedableRng};
use socket2::{Domain, Protocol, Socket, Type};

use crate::procstats::{self, ProcSample, RssSampler};
use crate::record::{LatencyUs, LoadResult, RunRecord, ServerStats};
use crate::wire;

/// EDNS UDP payload size advertised by the load generator.
const CLIENT_EDNS_UDP: u16 = 1232;
/// Socket read timeout: upper bound on how long a client sleeps without
/// looking at the clock.
const RECV_TIMEOUT: Duration = Duration::from_millis(5);
/// How often outstanding queries are checked for timeouts.
const SCAN_INTERVAL: Duration = Duration::from_millis(5);
/// How long clients keep reading responses after the window has ended.
const DRAIN_MAX: Duration = Duration::from_millis(200);
/// Requested SO_RCVBUF / SO_SNDBUF per client socket.
const SOCKET_BUF: usize = 4 * 1024 * 1024;
/// Receive buffer size (responses are at most 1232 octets with EDNS).
const RECV_BUF_LEN: usize = 4096;
/// Maximum number of outstanding queries per client.
const MAX_INFLIGHT: usize = 4096;
/// RSS polling interval for the server process.
const RSS_INTERVAL: Duration = Duration::from_millis(100);

#[derive(clap::Args, Debug, Clone)]
pub struct LoadArgs {
    /// Address of the DNS server under test.
    #[arg(long, default_value = "127.0.0.1:5353")]
    pub target: SocketAddr,
    /// Number of client sockets; each client is one OS thread.
    #[arg(long, default_value_t = 8)]
    pub clients: usize,
    /// Outstanding queries per client (closed loop), 1..=4096.
    #[arg(long, default_value_t = 32)]
    pub inflight: usize,
    /// Length of the measurement window.
    #[arg(long, default_value = "20s", value_parser = humantime::parse_duration)]
    pub duration: Duration,
    /// Load applied before the measurement window; not counted.
    #[arg(long, default_value = "2s", value_parser = humantime::parse_duration)]
    pub warmup: Duration,
    /// A query without a response after this long counts as a timeout.
    #[arg(long, default_value = "1s", value_parser = humantime::parse_duration)]
    pub timeout: Duration,
    /// Percentage of queries for names that do not exist (NXDOMAIN).
    #[arg(long, default_value_t = 5.0)]
    pub nx_percent: f64,
    /// Names are `host-{n}` with n uniform in 0..zone_size.
    #[arg(long, default_value_t = crate::zone::DEFAULT_ZONE_SIZE)]
    pub zone_size: u32,
    /// Do not send an EDNS OPT record (default: OPT with UDP size 1232).
    #[arg(long)]
    pub no_edns: bool,
    /// Sample CPU time and RSS of this server process during the run.
    #[arg(long)]
    pub server_pid: Option<u32>,
    /// Append the result as one JSON line to this file.
    #[arg(long)]
    pub json: Option<PathBuf>,
    /// Free-form label copied into the JSON record.
    #[arg(long)]
    pub label: Option<String>,
    /// RNG seed; client i uses seed + i.
    #[arg(long, default_value_t = 1)]
    pub seed: u64,
}

/// Parameters shared by all client threads (all `Copy`).
#[derive(Debug, Clone, Copy)]
struct Cfg {
    inflight: usize,
    timeout: Duration,
    zone_size: u32,
    /// A query is for a non-existent name if a random `u32` is below this.
    nx_threshold: u64,
    edns: Option<u16>,
    win_start: Instant,
    win_end: Instant,
}

impl Cfg {
    #[inline]
    fn in_window(&self, t: Instant) -> bool {
        t >= self.win_start && t < self.win_end
    }
}

/// Counters and latencies of one client thread.
struct ClientStats {
    sent: u64,
    received: u64,
    timeouts: u64,
    errors: u64,
    unexpected: u64,
    send_errors: u64,
    hist: Histogram<u64>,
}

fn new_histogram() -> anyhow::Result<Histogram<u64>> {
    // 1 ns ..= 60 s, 3 significant digits.
    Histogram::<u64>::new_with_bounds(1, 60_000_000_000, 3)
        .map_err(|e| anyhow!("cannot create latency histogram: {e:?}"))
}

/// Maps a DNS ID to the slot that owns it. 0 means "ID not outstanding".
struct IdTable {
    owner: Vec<u16>,
    next: u16,
}

impl IdTable {
    fn new(start: u16) -> IdTable {
        IdTable {
            owner: vec![0; 1 << 16],
            next: start,
        }
    }

    /// Hands out an ID that is not outstanding and binds it to `slot`.
    /// Needs fewer than 65,535 outstanding IDs, which `MAX_INFLIGHT` guarantees.
    fn alloc(&mut self, slot: usize) -> u16 {
        debug_assert!(slot < MAX_INFLIGHT);
        loop {
            self.next = self.next.wrapping_add(1);
            let cell = &mut self.owner[usize::from(self.next)];
            if *cell == 0 {
                *cell = slot as u16 + 1;
                return self.next;
            }
        }
    }

    #[inline]
    fn lookup(&self, id: u16) -> Option<usize> {
        match self.owner[usize::from(id)] {
            0 => None,
            v => Some(usize::from(v) - 1),
        }
    }

    #[inline]
    fn release(&mut self, id: u16) {
        self.owner[usize::from(id)] = 0;
    }
}

/// One of the `inflight` query positions of a client.
struct Slot {
    /// Query bytes; reused for every query sent from this slot.
    query: Vec<u8>,
    /// End of the question section in `query` (excludes the OPT record).
    qend: usize,
    id: u16,
    nx: bool,
    /// A query is outstanding (sent, or send failed and awaiting retry).
    active: bool,
    /// The last `send` failed, so no response can come: when the slot expires
    /// it is retried without counting a timeout.
    send_failed: bool,
    sent_at: Instant,
}

struct Client {
    sock: UdpSocket,
    cfg: Cfg,
    rng: SmallRng,
    slots: Vec<Slot>,
    ids: IdTable,
    /// Number of active slots.
    active: usize,
    rbuf: Vec<u8>,
    stats: ClientStats,
}

/// Checks a response whose ID matched an outstanding query.
///
/// `query[..qend]` is the query up to the end of its question section.
fn validate(h: &wire::RawHeader, resp: &[u8], query: &[u8], qend: usize, nx: bool) -> bool {
    if !h.qr || !h.aa || h.tc || h.qdcount != 1 {
        return false;
    }
    if resp.len() < qend || resp[wire::HEADER_LEN..qend] != query[wire::HEADER_LEN..qend] {
        return false;
    }
    if nx {
        h.rcode == wire::RCODE_NXDOMAIN && h.ancount == 0 && h.nscount >= 1
    } else {
        h.rcode == wire::RCODE_NOERROR && h.ancount == 1
    }
}

/// Errors from `recv` that say nothing about the run: read timeout, signal,
/// or an ICMP port-unreachable surfacing on the connected socket
/// (WSAECONNRESET on Windows, ECONNREFUSED on Linux).
fn is_transient_recv_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
    )
}

impl Client {
    fn new(sock: UdpSocket, cfg: Cfg, seed: u64) -> anyhow::Result<Client> {
        let mut rng = SmallRng::seed_from_u64(seed);
        let start_id = rng.next_u32() as u16;
        let now = Instant::now();
        let slots = (0..cfg.inflight)
            .map(|_| Slot {
                query: Vec::with_capacity(512),
                qend: 0,
                id: 0,
                nx: false,
                active: false,
                send_failed: false,
                sent_at: now,
            })
            .collect();
        Ok(Client {
            sock,
            cfg,
            rng,
            slots,
            ids: IdTable::new(start_id),
            active: 0,
            rbuf: vec![0; RECV_BUF_LEN],
            stats: ClientStats {
                sent: 0,
                received: 0,
                timeouts: 0,
                errors: 0,
                unexpected: 0,
                send_errors: 0,
                hist: new_histogram()?,
            },
        })
    }

    /// Builds a new query in slot `i` and sends it. The slot must be inactive.
    fn issue(&mut self, i: usize) {
        let id = self.ids.alloc(i);
        let n = self.rng.random_range(0..self.cfg.zone_size);
        let nx = u64::from(self.rng.next_u32()) < self.cfg.nx_threshold;
        let slot = &mut self.slots[i];
        wire::write_host_query(&mut slot.query, id, n, nx, self.cfg.edns);
        slot.qend = slot.query.len()
            - if self.cfg.edns.is_some() {
                wire::OPT_LEN
            } else {
                0
            };
        slot.id = id;
        slot.nx = nx;
        slot.active = true;
        self.active += 1;
        let t = Instant::now();
        slot.sent_at = t;
        let in_window = self.cfg.in_window(t);
        match self.sock.send(&slot.query) {
            Ok(_) => {
                slot.send_failed = false;
                if in_window {
                    self.stats.sent += 1;
                }
            }
            Err(_) => {
                slot.send_failed = true;
                if in_window {
                    self.stats.send_errors += 1;
                }
            }
        }
    }

    /// Marks slot `i` as no longer outstanding.
    fn free(&mut self, i: usize) {
        let slot = &mut self.slots[i];
        self.ids.release(slot.id);
        slot.active = false;
        self.active -= 1;
    }

    /// Handles the datagram in `rbuf[..len]` received at `now`.
    fn on_response(&mut self, len: usize, now: Instant) {
        let in_window = self.cfg.in_window(now);
        let resp = &self.rbuf[..len];
        let Some(h) = wire::parse_header(resp) else {
            if in_window {
                self.stats.unexpected += 1;
            }
            return;
        };
        let Some(i) = self.ids.lookup(h.id) else {
            if in_window {
                self.stats.unexpected += 1;
            }
            return;
        };
        if in_window {
            let slot = &self.slots[i];
            if validate(&h, resp, &slot.query, slot.qend, slot.nx) {
                let ns = now.saturating_duration_since(slot.sent_at).as_nanos();
                self.stats.received += 1;
                self.stats.hist.saturating_record((ns as u64).max(1));
            } else {
                self.stats.errors += 1;
            }
        }
        self.free(i);
        if now < self.cfg.win_end {
            self.issue(i);
        }
    }

    /// Replaces every query that has been outstanding longer than the timeout.
    fn scan_timeouts(&mut self, now: Instant) {
        let in_window = self.cfg.in_window(now);
        for i in 0..self.slots.len() {
            let slot = &self.slots[i];
            if slot.active && now.saturating_duration_since(slot.sent_at) > self.cfg.timeout {
                if in_window && !slot.send_failed {
                    self.stats.timeouts += 1;
                }
                self.free(i);
                self.issue(i);
            }
        }
    }

    fn run(&mut self) -> anyhow::Result<()> {
        for i in 0..self.slots.len() {
            self.issue(i);
        }
        let mut last_scan = Instant::now();
        loop {
            let res = self.sock.recv(&mut self.rbuf);
            let now = Instant::now();
            match res {
                Ok(len) => self.on_response(len, now),
                Err(e) if is_transient_recv_error(&e) => {}
                Err(e) => return Err(e).context("recv failed"),
            }
            if now >= self.cfg.win_end {
                break;
            }
            if now.saturating_duration_since(last_scan) >= SCAN_INTERVAL {
                self.scan_timeouts(now);
                last_scan = now;
            }
        }
        self.drain()
    }

    /// After the window: no new queries, read what is still on its way for at
    /// most `DRAIN_MAX`. Nothing read here is counted.
    fn drain(&mut self) -> anyhow::Result<()> {
        let deadline = Instant::now() + DRAIN_MAX;
        while self.active > 0 && Instant::now() < deadline {
            match self.sock.recv(&mut self.rbuf) {
                Ok(len) => self.on_response(len, Instant::now()),
                Err(e) if is_transient_recv_error(&e) => {}
                Err(e) => return Err(e).context("recv failed while draining"),
            }
        }
        Ok(())
    }
}

/// Creates a client socket: 4 MiB buffers, ephemeral port on the loopback
/// address (loopback targets: the target address itself) or the unspecified address (anything else) of
/// the target's IP family, connected to `target`, short read timeout.
fn make_socket(target: SocketAddr) -> anyhow::Result<UdpSocket> {
    let sock = Socket::new(
        Domain::for_address(target),
        Type::DGRAM,
        Some(Protocol::UDP),
    )
    .context("cannot create UDP socket")?;
    let _ = sock.set_recv_buffer_size(SOCKET_BUF);
    let _ = sock.set_send_buffer_size(SOCKET_BUF);
    // Loopback targets: bind to the target address itself, so both ends use
    // the same loopback address (WSL2 intercepts 127.0.0.1, so runs there
    // use another 127.0.0.0/8 address).
    let local: SocketAddr = match (target, target.ip().is_loopback()) {
        (_, true) => (target.ip(), 0).into(),
        (SocketAddr::V4(_), false) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        (SocketAddr::V6(_), false) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    sock.bind(&local.into())
        .with_context(|| format!("cannot bind {local}"))?;
    sock.connect(&target.into())
        .with_context(|| format!("cannot connect to {target}"))?;
    sock.set_read_timeout(Some(RECV_TIMEOUT))
        .context("cannot set read timeout")?;
    Ok(sock.into())
}

fn client_main(sock: UdpSocket, cfg: Cfg, seed: u64) -> anyhow::Result<ClientStats> {
    let mut client = Client::new(sock, cfg, seed)?;
    client.run()?;
    Ok(client.stats)
}

fn check_args(args: &LoadArgs) -> anyhow::Result<()> {
    if args.clients == 0 {
        bail!("--clients must be at least 1");
    }
    if !(1..=MAX_INFLIGHT).contains(&args.inflight) {
        bail!(
            "--inflight must be in 1..={MAX_INFLIGHT}, got {}",
            args.inflight
        );
    }
    if args.duration.is_zero() {
        bail!("--duration must be greater than zero");
    }
    if args.timeout.is_zero() {
        bail!("--timeout must be greater than zero");
    }
    if args.zone_size == 0 {
        bail!("--zone-size must be at least 1");
    }
    if !(0.0..=100.0).contains(&args.nx_percent) {
        bail!("--nx-percent must be in 0..=100, got {}", args.nx_percent);
    }
    Ok(())
}

fn sleep_until(t: Instant) {
    loop {
        let left = t.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        thread::sleep(left);
    }
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / 1_048_576.0
}

fn quantile_us(h: &Histogram<u64>, q: f64) -> f64 {
    h.value_at_quantile(q) as f64 / 1000.0
}

fn latency_us(h: &Histogram<u64>) -> LatencyUs {
    if h.is_empty() {
        return LatencyUs::default();
    }
    LatencyUs {
        p50: quantile_us(h, 0.50),
        p90: quantile_us(h, 0.90),
        p99: quantile_us(h, 0.99),
        p999: quantile_us(h, 0.999),
        max: h.max() as f64 / 1000.0,
        mean: h.mean() / 1000.0,
    }
}

/// Runs the load and returns the aggregated result of the measurement window.
pub fn run_load(args: &LoadArgs) -> anyhow::Result<LoadResult> {
    check_args(args)?;
    let measured_seconds = args.duration.as_secs_f64();

    // Sockets are created up front so that a failure aborts before any thread runs.
    let sockets = (0..args.clients)
        .map(|_| make_socket(args.target))
        .collect::<anyhow::Result<Vec<_>>>()?;

    // The server must exist before we start; it is checked again at the window end.
    if let Some(pid) = args.server_pid
        && procstats::sample(pid).is_none()
    {
        bail!("server process {pid} not found");
    }
    let rss = args
        .server_pid
        .map(|pid| RssSampler::start(pid, RSS_INTERVAL));

    let start = Instant::now();
    let win_start = start + args.warmup;
    let win_end = win_start + args.duration;
    let cfg = Cfg {
        inflight: args.inflight,
        timeout: args.timeout,
        zone_size: args.zone_size,
        nx_threshold: ((args.nx_percent / 100.0) * 4_294_967_296.0).round() as u64,
        edns: (!args.no_edns).then_some(CLIENT_EDNS_UDP),
        win_start,
        win_end,
    };

    let mut handles = Vec::with_capacity(args.clients);
    let mut spawn_error = None;
    for (i, sock) in sockets.into_iter().enumerate() {
        let seed = args.seed.wrapping_add(i as u64);
        match thread::Builder::new()
            .name(format!("load-client-{i}"))
            .spawn(move || client_main(sock, cfg, seed))
        {
            Ok(h) => handles.push(h),
            Err(e) => {
                spawn_error = Some(e);
                break;
            }
        }
    }

    // CPU time of the server and of this process at both ends of the window.
    let own_pid = std::process::id();
    sleep_until(win_start);
    let own0 = procstats::sample(own_pid);
    let srv0 = args.server_pid.and_then(procstats::sample);
    sleep_until(win_end);
    let own1 = procstats::sample(own_pid);
    let srv1 = args.server_pid.and_then(procstats::sample);
    let peak_rss_bytes = rss.map(RssSampler::stop);

    // Join every thread before looking at any error, so none is left running.
    let joined: Vec<_> = handles.into_iter().map(|h| h.join()).collect();
    if let Some(e) = spawn_error {
        return Err(e).context("cannot spawn client thread");
    }
    let mut hist = new_histogram()?;
    let (mut sent, mut received, mut timeouts) = (0u64, 0u64, 0u64);
    let (mut errors, mut unexpected, mut send_errors) = (0u64, 0u64, 0u64);
    for r in joined {
        let s = r.map_err(|_| anyhow!("client thread panicked"))??;
        sent += s.sent;
        received += s.received;
        timeouts += s.timeouts;
        errors += s.errors;
        unexpected += s.unexpected;
        send_errors += s.send_errors;
        hist.add(&s.hist)
            .map_err(|e| anyhow!("cannot merge latency histograms: {e:?}"))?;
    }

    let cpu_delta = |a: Option<ProcSample>, b: Option<ProcSample>| -> Option<f64> {
        Some(b?.cpu_time.saturating_sub(a?.cpu_time).as_secs_f64())
    };
    let server = match args.server_pid {
        None => None,
        Some(pid) => {
            let (Some(s0), Some(s1)) = (srv0, srv1) else {
                bail!("server process {pid} disappeared during the run");
            };
            let cpu_seconds = s1.cpu_time.saturating_sub(s0.cpu_time).as_secs_f64();
            let peak = peak_rss_bytes
                .unwrap_or(0)
                .max(s0.rss_bytes)
                .max(s1.rss_bytes);
            Some(ServerStats {
                pid,
                cpu_seconds,
                cpu_cores: cpu_seconds / measured_seconds,
                peak_rss_mib: mib(peak),
                end_rss_mib: mib(s1.rss_bytes),
            })
        }
    };
    let client_cpu_cores = cpu_delta(own0, own1).map(|s| s / measured_seconds);

    Ok(LoadResult {
        target: args.target.to_string(),
        clients: args.clients,
        inflight: args.inflight,
        edns: !args.no_edns,
        nx_percent: args.nx_percent,
        warmup_seconds: args.warmup.as_secs_f64(),
        measured_seconds,
        sent,
        received,
        timeouts,
        errors,
        unexpected,
        send_errors,
        qps: received as f64 / measured_seconds,
        latency_us: latency_us(&hist),
        server,
        client_cpu_cores,
    })
}

/// Formats an integer with ',' as thousands separator.
pub fn group_thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Prints a human-readable summary of `r` to stdout.
pub fn print_summary(r: &LoadResult) {
    let loopback = r
        .target
        .parse::<SocketAddr>()
        .is_ok_and(|a| a.ip().is_loopback());
    println!(
        "target        {}{}",
        r.target,
        if loopback {
            " (loopback: client and server share this host)"
        } else {
            ""
        }
    );
    println!(
        "load          {} clients x {} in flight, EDNS {}, {:.1}% NXDOMAIN",
        r.clients,
        r.inflight,
        if r.edns { "on" } else { "off" },
        r.nx_percent
    );
    println!(
        "window        {:.1} s measured after {:.1} s warmup",
        r.measured_seconds, r.warmup_seconds
    );
    println!("sent          {}", group_thousands(r.sent));
    println!("received      {}", group_thousands(r.received));
    println!("timeouts      {}", group_thousands(r.timeouts));
    println!("errors        {}", group_thousands(r.errors));
    println!("unexpected    {}", group_thousands(r.unexpected));
    println!("send errors   {}", group_thousands(r.send_errors));
    println!("qps           {}", group_thousands(r.qps.round() as u64));
    let l = &r.latency_us;
    println!(
        "latency (us)  p50 {:.1}  p90 {:.1}  p99 {:.1}  p99.9 {:.1}  max {:.1}  mean {:.1}",
        l.p50, l.p90, l.p99, l.p999, l.max, l.mean
    );
    if let Some(s) = &r.server {
        println!(
            "server        pid {}: cpu {:.2} cores ({:.2} s), rss peak {:.1} MiB, end {:.1} MiB",
            s.pid, s.cpu_cores, s.cpu_seconds, s.peak_rss_mib, s.end_rss_mib
        );
    }
    if let Some(c) = r.client_cpu_cores {
        println!("client cpu    {c:.2} cores");
    }
}

/// Appends `rec` as one JSON line to `path`, creating the file and its parent
/// directories if needed.
pub fn append_record(path: &Path, rec: &RunRecord) -> anyhow::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let mut line = serde_json::to_string(rec).context("cannot serialize result")?;
    line.push('\n');
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    // One write call, so concurrent appenders cannot interleave inside a line.
    file.write_all(line.as_bytes())
        .with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

/// Current time as an RFC 3339 UTC timestamp with second resolution.
pub fn now_rfc3339() -> String {
    humantime::format_rfc3339_seconds(SystemTime::now()).to_string()
}

/// Runs the load, prints the summary and optionally appends the JSON record.
pub fn run(args: &LoadArgs) -> anyhow::Result<()> {
    let result = run_load(args)?;
    print_summary(&result);
    if let Some(path) = &args.json {
        let rec = RunRecord {
            timestamp: now_rfc3339(),
            os: std::env::consts::OS.to_string(),
            label: args.label.clone(),
            backend: None,
            mode: None,
            workers: None,
            reuseport: None,
            result,
        };
        append_record(path, &rec)?;
        eprintln!("appended result to {}", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread::JoinHandle;

    /// What the in-test responder does with each query.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Behavior {
        /// Valid answer: NOERROR + 1 answer for `host-`, NXDOMAIN + 1 SOA-ish
        /// authority record for `nohost-`.
        Valid,
        /// Reads queries, never answers.
        Silent,
        /// Valid answer, but with a different ID.
        WrongId,
        /// SERVFAIL for every query.
        ServFail,
        /// Valid answer with TC set.
        Truncated,
    }

    struct Responder {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
        handle: Option<JoinHandle<()>>,
    }

    /// Turns the query `q` into a response according to `b`. Returns false if
    /// `q` is not a query.
    fn make_response(q: &[u8], b: Behavior, out: &mut Vec<u8>) -> bool {
        let Some(h) = wire::parse_header(q) else {
            return false;
        };
        let qend = if h.arcount == 1 {
            q.len() - wire::OPT_LEN
        } else {
            q.len()
        };
        let nx = q[wire::HEADER_LEN + 1..].starts_with(b"nohost-");
        out.clear();
        out.extend_from_slice(&q[..qend]);
        out[2] |= 0x80 | 0x04; // QR, AA
        out[10..12].copy_from_slice(&0u16.to_be_bytes()); // drop the OPT from ARCOUNT
        match b {
            Behavior::ServFail => out[3] = wire::RCODE_SERVFAIL,
            _ if nx => {
                out[3] = wire::RCODE_NXDOMAIN;
                out[8..10].copy_from_slice(&1u16.to_be_bytes());
                // owner = pointer to the question name, TYPE SOA, CLASS IN, TTL 60, RDLEN 0
                out.extend_from_slice(&[0xc0, 0x0c, 0, 6, 0, 1, 0, 0, 0, 60, 0, 0]);
            }
            _ => {
                out[3] = wire::RCODE_NOERROR;
                out[6..8].copy_from_slice(&1u16.to_be_bytes());
                // owner = pointer to the question name, TYPE A, CLASS IN, TTL 60, 127.0.0.1
                out.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
            }
        }
        if b == Behavior::Truncated {
            out[2] |= 0x02;
        }
        if b == Behavior::WrongId {
            out[0] ^= 0x80;
        }
        true
    }

    impl Responder {
        fn start(b: Behavior) -> Responder {
            let sock = UdpSocket::bind((crate::wire::test_loopback(), 0)).unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(20)))
                .unwrap();
            let addr = sock.local_addr().unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let stop2 = stop.clone();
            let handle = thread::spawn(move || {
                let mut buf = [0u8; 2048];
                let mut out = Vec::new();
                while !stop2.load(Ordering::Relaxed) {
                    let Ok((n, peer)) = sock.recv_from(&mut buf) else {
                        continue;
                    };
                    if b != Behavior::Silent && make_response(&buf[..n], b, &mut out) {
                        let _ = sock.send_to(&out, peer);
                    }
                }
            });
            Responder {
                addr,
                stop,
                handle: Some(handle),
            }
        }
    }

    impl Drop for Responder {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    fn test_args(target: SocketAddr) -> LoadArgs {
        LoadArgs {
            target,
            clients: 2,
            inflight: 8,
            duration: Duration::from_secs(1),
            warmup: Duration::from_millis(100),
            timeout: Duration::from_millis(500),
            nx_percent: 20.0,
            zone_size: 1000,
            no_edns: false,
            server_pid: None,
            json: None,
            label: None,
            seed: 7,
        }
    }

    fn header_of(q: &[u8], behavior: Behavior) -> Vec<u8> {
        let mut out = Vec::new();
        assert!(make_response(q, behavior, &mut out));
        out
    }

    #[test]
    fn closed_loop_against_valid_responder() {
        let r = Responder::start(Behavior::Valid);
        let res = run_load(&test_args(r.addr)).unwrap();
        assert!(res.received > 0, "{res:?}");
        assert_eq!(res.errors, 0, "{res:?}");
        assert_eq!(res.timeouts, 0, "{res:?}");
        assert_eq!(res.unexpected, 0, "{res:?}");
        assert_eq!(res.send_errors, 0, "{res:?}");
        assert!(res.sent > 0);
        assert!((res.qps - res.received as f64 / res.measured_seconds).abs() < 1e-6);
        assert_eq!(res.target, r.addr.to_string());
        assert!(res.edns);
        let l = &res.latency_us;
        assert!(
            l.p50 > 0.0 && l.p50 <= l.p90 && l.p90 <= l.p99 && l.p99 <= l.p999 && l.p999 <= l.max
        );
        assert!(res.server.is_none());
        assert!(res.client_cpu_cores.is_some());
    }

    #[test]
    fn all_nx_without_edns() {
        let r = Responder::start(Behavior::Valid);
        let mut args = test_args(r.addr);
        args.nx_percent = 100.0;
        args.no_edns = true;
        args.clients = 1;
        let res = run_load(&args).unwrap();
        assert!(res.received > 0, "{res:?}");
        assert_eq!(res.errors, 0, "{res:?}");
        assert_eq!(res.timeouts, 0, "{res:?}");
        assert!(!res.edns);
    }

    #[test]
    fn sampling_own_process_as_server() {
        let r = Responder::start(Behavior::Valid);
        let mut args = test_args(r.addr);
        args.server_pid = Some(std::process::id());
        args.clients = 1;
        let res = run_load(&args).unwrap();
        let s = res.server.expect("server stats");
        assert_eq!(s.pid, std::process::id());
        assert!(s.peak_rss_mib > 0.0 && s.peak_rss_mib >= s.end_rss_mib);
        assert!((s.cpu_cores - s.cpu_seconds / res.measured_seconds).abs() < 1e-9);
    }

    #[test]
    fn missing_server_pid_is_an_error() {
        let r = Responder::start(Behavior::Valid);
        let mut args = test_args(r.addr);
        args.server_pid = Some(4_000_000_001);
        assert!(run_load(&args).is_err());
    }

    #[test]
    fn silent_responder_times_out() {
        let r = Responder::start(Behavior::Silent);
        let mut args = test_args(r.addr);
        args.clients = 1;
        args.inflight = 4;
        args.warmup = Duration::ZERO;
        args.timeout = Duration::from_millis(200);
        let res = run_load(&args).unwrap();
        assert_eq!(res.received, 0, "{res:?}");
        assert!(res.timeouts > 0, "{res:?}");
        // 4 slots, 1 s window, 200 ms timeout: about 4 timeouts per slot if
        // each expiry is noticed promptly.
        assert!(res.timeouts >= 12, "timeouts noticed too late: {res:?}");
        assert!(res.sent >= res.timeouts, "{res:?}");
        assert_eq!(res.latency_us.max, 0.0);
    }

    #[test]
    fn wrong_id_is_unexpected_and_the_query_times_out() {
        let r = Responder::start(Behavior::WrongId);
        let mut args = test_args(r.addr);
        args.clients = 1;
        args.inflight = 4;
        args.warmup = Duration::ZERO;
        args.timeout = Duration::from_millis(200);
        let res = run_load(&args).unwrap();
        assert_eq!(res.received, 0, "{res:?}");
        assert!(res.unexpected > 0, "{res:?}");
        assert!(res.timeouts > 0, "{res:?}");
    }

    #[test]
    fn servfail_and_truncated_count_as_errors() {
        for b in [Behavior::ServFail, Behavior::Truncated] {
            let r = Responder::start(b);
            let mut args = test_args(r.addr);
            args.clients = 1;
            args.inflight = 4;
            args.duration = Duration::from_millis(500);
            let res = run_load(&args).unwrap();
            assert_eq!(res.received, 0, "{res:?}");
            assert!(res.errors > 0, "{res:?}");
            assert_eq!(res.timeouts, 0, "{res:?}");
            assert_eq!(res.unexpected, 0, "{res:?}");
        }
    }

    #[test]
    fn rejects_bad_arguments() {
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let ok = test_args(addr);
        assert!(check_args(&ok).is_ok());
        let mut a = ok.clone();
        a.inflight = 0;
        assert!(check_args(&a).is_err());
        a.inflight = 4097;
        assert!(check_args(&a).is_err());
        a.inflight = 4096;
        assert!(check_args(&a).is_ok());
        let mut a = ok.clone();
        a.clients = 0;
        assert!(check_args(&a).is_err());
        let mut a = ok.clone();
        a.nx_percent = 100.5;
        assert!(check_args(&a).is_err());
        let mut a = ok;
        a.timeout = Duration::ZERO;
        assert!(check_args(&a).is_err());
    }

    #[test]
    fn id_table_never_hands_out_an_outstanding_id() {
        let mut t = IdTable::new(65_500);
        let mut id_of = vec![0u16; MAX_INFLIGHT];
        for (slot, id) in id_of.iter_mut().enumerate() {
            *id = t.alloc(slot);
        }
        let mut rng = SmallRng::seed_from_u64(3);
        for _ in 0..300_000 {
            let slot = rng.random_range(0..MAX_INFLIGHT);
            t.release(id_of[slot]);
            assert_eq!(t.lookup(id_of[slot]), None);
            let id = t.alloc(slot);
            id_of[slot] = id;
        }
        // Every outstanding ID is distinct and maps back to its slot.
        for (slot, &id) in id_of.iter().enumerate() {
            assert_eq!(t.lookup(id), Some(slot));
        }
    }

    #[test]
    fn validate_checks_header_question_and_counts() {
        let mut q = Vec::new();
        wire::write_host_query(&mut q, 0x1234, 42, false, Some(1232));
        let qend = q.len() - wire::OPT_LEN;
        let mut qnx = Vec::new();
        wire::write_host_query(&mut qnx, 0x1235, 42, true, None);
        let qnx_end = qnx.len();

        let check = |resp: &[u8], query: &[u8], qend: usize, nx: bool| {
            let h = wire::parse_header(resp).unwrap();
            validate(&h, resp, query, qend, nx)
        };

        let good = header_of(&q, Behavior::Valid);
        assert!(check(&good, &q, qend, false));
        // An existing name answered with NXDOMAIN is not valid, and vice versa.
        assert!(!check(&good, &q, qend, true));
        let good_nx = header_of(&qnx, Behavior::Valid);
        assert!(check(&good_nx, &qnx, qnx_end, true));
        assert!(!check(&good_nx, &qnx, qnx_end, false));

        // Header bits.
        let mut bad = good.clone();
        bad[2] &= !0x80; // QR=0
        assert!(!check(&bad, &q, qend, false));
        let mut bad = good.clone();
        bad[2] &= !0x04; // AA=0
        assert!(!check(&bad, &q, qend, false));
        let mut bad = good.clone();
        bad[2] |= 0x02; // TC=1
        assert!(!check(&bad, &q, qend, false));
        let mut bad = good.clone();
        bad[5] = 0; // QDCOUNT=0
        assert!(!check(&bad, &q, qend, false));
        let mut bad = good.clone();
        bad[7] = 2; // ANCOUNT=2
        assert!(!check(&bad, &q, qend, false));
        let mut bad = good_nx.clone();
        bad[9] = 0; // NSCOUNT=0
        assert!(!check(&bad, &qnx, qnx_end, true));
        let mut bad = good_nx.clone();
        bad[7] = 1; // ANCOUNT=1 on NXDOMAIN
        assert!(!check(&bad, &qnx, qnx_end, true));

        // Question bytes differ / response cut short.
        let mut bad = good.clone();
        bad[13] = b'H';
        assert!(!check(&bad, &q, qend, false));
        assert!(!check(&good[..qend - 1], &q, qend, false));
    }

    #[test]
    fn thousands_separator() {
        assert_eq!(group_thousands(0), "0");
        assert_eq!(group_thousands(999), "999");
        assert_eq!(group_thousands(1000), "1,000");
        assert_eq!(group_thousands(123_456), "123,456");
        assert_eq!(group_thousands(1_234_567_890), "1,234,567,890");
    }

    #[test]
    fn append_record_writes_one_json_line_per_record() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp")
            .join(format!("load-{}", std::process::id()));
        let path = dir.join("nested").join("out.jsonl");
        let mut rec = RunRecord {
            timestamp: now_rfc3339(),
            os: std::env::consts::OS.to_string(),
            label: Some("t".into()),
            ..Default::default()
        };
        append_record(&path, &rec).unwrap();
        rec.workers = Some(4);
        append_record(&path, &rec).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let back: RunRecord = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(back.workers, Some(4));
        assert_eq!(back.label.as_deref(), Some("t"));
        assert!(back.timestamp.ends_with('Z'));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cli_definition_is_valid() {
        #[derive(clap::Parser)]
        struct Wrapper {
            #[command(flatten)]
            args: LoadArgs,
        }
        use clap::{CommandFactory, Parser};
        Wrapper::command().debug_assert();
        let w = Wrapper::try_parse_from(["x"]).unwrap();
        assert_eq!(
            w.args.target,
            "127.0.0.1:5353".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(w.args.clients, 8);
        assert_eq!(w.args.inflight, 32);
        assert_eq!(w.args.duration, Duration::from_secs(20));
        assert_eq!(w.args.warmup, Duration::from_secs(2));
        assert_eq!(w.args.timeout, Duration::from_secs(1));
        assert_eq!(w.args.nx_percent, 5.0);
        assert_eq!(w.args.zone_size, 100_000);
        assert!(!w.args.no_edns);
        assert_eq!(w.args.seed, 1);
        let w =
            Wrapper::try_parse_from(["x", "--duration", "500ms", "--no-edns", "--server-pid", "7"])
                .unwrap();
        assert_eq!(w.args.duration, Duration::from_millis(500));
        assert!(w.args.no_edns);
        assert_eq!(w.args.server_pid, Some(7));
    }
}
