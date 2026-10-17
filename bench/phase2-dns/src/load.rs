//! DNS load generator: UDP and TCP, closed loop or paced.
//!
//! Each client is one OS thread owning one connected UDP socket or one TCP
//! connection. Queries come from a names file ([`crate::names`]), picked
//! uniformly at random.
//!
//! * **Closed loop** (default): every client keeps `inflight` queries
//!   outstanding; whenever a response arrives (or a query times out) the slot
//!   is refilled immediately. The result is the saturation throughput.
//! * **Paced** (`--qps`): queries are sent at a fixed total rate, split evenly
//!   over the clients, with at most `inflight` outstanding per client. A
//!   latency is measured from the actual send, so a stalled run is not
//!   corrected for the delay (no coordinated-omission correction); a
//!   `qps` below the target says the server or the client saturated.
//! * Matching is by DNS ID. A 65,536-entry table maps an ID to the slot that
//!   owns it; IDs come from a wrapping counter and skip IDs that are still
//!   outstanding, so a new query never reuses an ID that is in flight and a
//!   late response to a timed-out query is not confused with a newer one.
//! * TCP uses one persistent connection per client with the queries
//!   pipelined (RFC 7766); responses may come back in any order. If the server
//!   closes the connection the client reconnects, counts the outstanding
//!   queries as timeouts and counts the reconnect.
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
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, anyhow, bail};
use hdrhistogram::Histogram;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use socket2::{Domain, Protocol, Socket, Type};

use crate::names::Names;
use crate::procstats::{self, ProcSample, RssSampler};
use crate::record::{LatencyUs, LoadResult, RunRecord, ServerStats};
use crate::wire;

/// EDNS UDP payload size advertised by the load generator.
const CLIENT_EDNS_UDP: u16 = 1232;
/// Socket read timeout of a closed-loop client: upper bound on how long it
/// sleeps without looking at the clock.
const RECV_TIMEOUT: Duration = Duration::from_millis(5);
/// Socket read timeout of a paced client, which has to send on time.
const PACED_RECV_TIMEOUT: Duration = Duration::from_millis(1);
/// How often outstanding queries are checked for timeouts.
const SCAN_INTERVAL: Duration = Duration::from_millis(5);
/// How long clients keep reading responses after the window has ended.
const DRAIN_MAX: Duration = Duration::from_millis(200);
/// Requested SO_RCVBUF / SO_SNDBUF per client socket.
const SOCKET_BUF: usize = 4 * 1024 * 1024;
/// Receive buffer size (responses are at most 1232 octets with EDNS over UDP;
/// a TCP read takes whatever is there up to this size).
const RECV_BUF_LEN: usize = 65_536;
/// Maximum number of outstanding queries per client.
const MAX_INFLIGHT: usize = 4096;
/// RSS polling interval for the server process.
const RSS_INTERVAL: Duration = Duration::from_millis(100);
/// How long a TCP client keeps trying to (re)connect.
const CONNECT_RETRY: Duration = Duration::from_secs(2);
/// A paced client that fell this far behind its schedule drops the backlog.
const PACE_MAX_DEBT: Duration = Duration::from_millis(100);

/// The transport the queries use.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    fn name(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        }
    }
}

/// `on` or `off`, for the `--metrics` label.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnOff {
    On,
    Off,
}

#[derive(clap::Args, Debug, Clone)]
pub struct LoadArgs {
    /// Address of the DNS server under test.
    #[arg(long, default_value = "127.0.0.1:5353")]
    pub target: SocketAddr,
    /// File with the queries, one `name [TYPE]` per line (see `zonegen`).
    #[arg(long)]
    pub names: PathBuf,
    /// Transport: UDP datagrams or pipelined queries on persistent TCP connections.
    #[arg(long, value_enum, default_value_t = Transport::Udp)]
    pub transport: Transport,
    /// Number of client sockets (UDP) or connections (TCP); each is one OS thread.
    #[arg(long, default_value_t = 8)]
    pub clients: usize,
    /// Outstanding queries per client, 1..=4096.
    #[arg(long, default_value_t = 32)]
    pub inflight: usize,
    /// Send at this total rate (queries per second) instead of a closed loop.
    #[arg(long)]
    pub qps: Option<f64>,
    /// Length of the measurement window.
    #[arg(long, default_value = "20s", value_parser = humantime::parse_duration)]
    pub duration: Duration,
    /// Load applied before the measurement window; not counted.
    #[arg(long, default_value = "2s", value_parser = humantime::parse_duration)]
    pub warmup: Duration,
    /// A query without a response after this long counts as a timeout.
    #[arg(long, default_value = "1s", value_parser = humantime::parse_duration)]
    pub timeout: Duration,
    /// Do not send an EDNS OPT record (default: OPT with UDP size 1232).
    #[arg(long)]
    pub no_edns: bool,
    /// Set the recursion-desired bit (default: clear, for authoritative servers).
    #[arg(long)]
    pub rd: bool,
    /// Count a response without the AA bit as an error (authoritative servers).
    #[arg(long)]
    pub require_aa: bool,
    /// Sample CPU time and RSS of this server process during the run.
    #[arg(long)]
    pub server_pid: Option<u32>,
    /// Append the result as one JSON line to this file.
    #[arg(long)]
    pub json: Option<PathBuf>,
    /// Free-form label copied into the JSON record, e.g. the server and its build.
    #[arg(long)]
    pub label: Option<String>,
    /// The worker setting of the server under test, copied into the JSON record.
    #[arg(long)]
    pub workers: Option<usize>,
    /// Whether the server's metrics were on or off, copied into the JSON record.
    #[arg(long, value_enum)]
    pub metrics: Option<OnOff>,
    /// RNG seed; client i uses seed + i.
    #[arg(long, default_value_t = 1)]
    pub seed: u64,
}

/// Parameters shared by all client threads (all `Copy`).
#[derive(Debug, Clone, Copy)]
struct Cfg {
    inflight: usize,
    timeout: Duration,
    edns: Option<u16>,
    rd: bool,
    require_aa: bool,
    /// Interval between two queries of one paced client; `None` for a closed loop.
    pace: Option<Duration>,
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
    answers: u64,
    nodata: u64,
    nxdomain: u64,
    timeouts: u64,
    errors: u64,
    unexpected: u64,
    send_errors: u64,
    reconnects: u64,
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
    /// `FRAME_PREFIX` octets of TCP length prefix, then the query message;
    /// reused for every query sent from this slot.
    query: Vec<u8>,
    /// End of the question section in the message (excludes the OPT record).
    qend: usize,
    id: u16,
    /// A query is outstanding (sent, or send failed and awaiting retry).
    active: bool,
    /// The last `send` failed, so no response can come: when the slot expires
    /// it is retried without counting a timeout.
    send_failed: bool,
    sent_at: Instant,
}

impl Slot {
    /// The DNS message without the TCP length prefix.
    fn message(&self) -> &[u8] {
        &self.query[wire::FRAME_PREFIX..]
    }
}

/// A persistent TCP connection and the bytes read from it that do not yet
/// form a whole frame.
struct TcpConn {
    stream: TcpStream,
    target: SocketAddr,
    acc: Vec<u8>,
}

enum Conn {
    Udp(UdpSocket),
    Tcp(TcpConn),
}

/// What a response says about its query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Answer,
    NoData,
    NxDomain,
    Bad,
}

struct Client {
    conn: Conn,
    cfg: Cfg,
    names: Arc<Names>,
    rng: SmallRng,
    slots: Vec<Slot>,
    ids: IdTable,
    /// Number of active slots.
    active: usize,
    /// Inactive slots (paced mode only; a closed loop refills at once).
    free_list: Vec<usize>,
    /// Paced mode: when the next query is due.
    next_due: Instant,
    /// TCP: the connection failed and must be re-opened.
    broken: bool,
    rbuf: Vec<u8>,
    stats: ClientStats,
}

/// Checks a response whose ID matched an outstanding query.
///
/// `query[..qend]` is the message up to the end of its question section.
fn validate(
    h: &wire::RawHeader,
    resp: &[u8],
    query: &[u8],
    qend: usize,
    require_aa: bool,
) -> Verdict {
    if !h.qr || h.tc || h.qdcount != 1 || (require_aa && !h.aa) {
        return Verdict::Bad;
    }
    if resp.len() < qend || resp[wire::HEADER_LEN..qend] != query[wire::HEADER_LEN..qend] {
        return Verdict::Bad;
    }
    match h.rcode {
        wire::RCODE_NXDOMAIN => Verdict::NxDomain,
        wire::RCODE_NOERROR if h.ancount > 0 => Verdict::Answer,
        wire::RCODE_NOERROR => Verdict::NoData,
        _ => Verdict::Bad,
    }
}

/// Errors from a read that say nothing about the run: read timeout or signal.
fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// Errors from a UDP `recv` that say nothing about the run: read timeout,
/// signal, or an ICMP port-unreachable surfacing on the connected socket
/// (WSAECONNRESET on Windows, ECONNREFUSED on Linux).
fn is_transient_udp_error(e: &io::Error) -> bool {
    is_timeout(e)
        || matches!(
            e.kind(),
            io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionAborted
        )
}

impl Client {
    fn new(conn: Conn, cfg: Cfg, names: Arc<Names>, seed: u64) -> anyhow::Result<Client> {
        let mut rng = SmallRng::seed_from_u64(seed);
        let start_id = rng.next_u32() as u16;
        let now = Instant::now();
        let slots = (0..cfg.inflight)
            .map(|_| Slot {
                query: Vec::with_capacity(512),
                qend: 0,
                id: 0,
                active: false,
                send_failed: false,
                sent_at: now,
            })
            .collect();
        Ok(Client {
            conn,
            cfg,
            names,
            rng,
            slots,
            ids: IdTable::new(start_id),
            active: 0,
            free_list: Vec::new(),
            next_due: now,
            broken: false,
            rbuf: vec![0; RECV_BUF_LEN],
            stats: ClientStats {
                sent: 0,
                received: 0,
                answers: 0,
                nodata: 0,
                nxdomain: 0,
                timeouts: 0,
                errors: 0,
                unexpected: 0,
                send_errors: 0,
                reconnects: 0,
                hist: new_histogram()?,
            },
        })
    }

    /// Builds a new query in slot `i` and sends it. The slot must be inactive.
    fn issue(&mut self, i: usize) {
        let id = self.ids.alloc(i);
        let (qname, qtype) = self.names.pick(&mut self.rng);
        let slot = &mut self.slots[i];
        slot.qend = wire::write_query(
            &mut slot.query,
            id,
            qname,
            qtype,
            self.cfg.edns,
            self.cfg.rd,
        );
        slot.id = id;
        slot.active = true;
        self.active += 1;
        let t = Instant::now();
        slot.sent_at = t;
        let in_window = self.cfg.in_window(t);
        let sent = match &mut self.conn {
            Conn::Udp(sock) => sock.send(slot.message()).map(|_| ()),
            Conn::Tcp(tcp) => {
                let len = (slot.query.len() - wire::FRAME_PREFIX) as u16;
                slot.query[..wire::FRAME_PREFIX].copy_from_slice(&len.to_be_bytes());
                tcp.stream.write_all(&slot.query)
            }
        };
        match sent {
            Ok(()) => {
                slot.send_failed = false;
                if in_window {
                    self.stats.sent += 1;
                }
            }
            Err(_) => {
                slot.send_failed = true;
                if matches!(self.conn, Conn::Tcp(_)) {
                    self.broken = true;
                }
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
        if self.cfg.pace.is_some() {
            self.free_list.push(i);
        }
    }

    /// Handles one response message received at `now`.
    fn on_response(&mut self, resp: &[u8], now: Instant) {
        let in_window = self.cfg.in_window(now);
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
            match validate(&h, resp, slot.message(), slot.qend, self.cfg.require_aa) {
                Verdict::Bad => self.stats.errors += 1,
                v => {
                    let ns = now.saturating_duration_since(slot.sent_at).as_nanos();
                    self.stats.received += 1;
                    self.stats.hist.saturating_record((ns as u64).max(1));
                    match v {
                        Verdict::Answer => self.stats.answers += 1,
                        Verdict::NoData => self.stats.nodata += 1,
                        _ => self.stats.nxdomain += 1,
                    }
                }
            }
        }
        self.free(i);
        if self.cfg.pace.is_none() && now < self.cfg.win_end {
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
                if self.cfg.pace.is_none() {
                    self.issue(i);
                }
            }
        }
    }

    /// Paced mode: sends the queries that are due, as far as slots are free.
    fn issue_due(&mut self, now: Instant) {
        let Some(interval) = self.cfg.pace else {
            return;
        };
        if now.saturating_duration_since(self.next_due) > PACE_MAX_DEBT {
            self.next_due = now;
        }
        while self.next_due <= now && now < self.cfg.win_end {
            let Some(i) = self.free_list.pop() else {
                break;
            };
            self.issue(i);
            self.next_due += interval;
        }
    }

    /// Reads once from the connection (waiting at most the read timeout) and
    /// handles what arrived.
    fn poll(&mut self) -> anyhow::Result<()> {
        let mut buf = std::mem::take(&mut self.rbuf);
        let result = self.poll_into(&mut buf);
        self.rbuf = buf;
        result
    }

    fn poll_into(&mut self, buf: &mut [u8]) -> anyhow::Result<()> {
        match &mut self.conn {
            Conn::Udp(sock) => {
                let res = sock.recv(buf);
                let now = Instant::now();
                match res {
                    Ok(len) => self.on_response(&buf[..len], now),
                    Err(e) if is_transient_udp_error(&e) => {}
                    Err(e) => return Err(e).context("recv failed"),
                }
            }
            Conn::Tcp(tcp) => {
                let res = tcp.stream.read(buf);
                let now = Instant::now();
                match res {
                    Ok(0) => self.broken = true,
                    Ok(n) => {
                        let mut acc = std::mem::take(&mut tcp.acc);
                        acc.extend_from_slice(&buf[..n]);
                        let mut pos = 0;
                        while acc.len() - pos >= wire::FRAME_PREFIX {
                            let len = usize::from(u16::from_be_bytes([acc[pos], acc[pos + 1]]));
                            let end = pos + wire::FRAME_PREFIX + len;
                            if acc.len() < end {
                                break;
                            }
                            self.on_response(&acc[pos + wire::FRAME_PREFIX..end], now);
                            pos = end;
                        }
                        acc.drain(..pos);
                        if let Conn::Tcp(tcp) = &mut self.conn {
                            tcp.acc = acc;
                        }
                    }
                    Err(e) if is_timeout(&e) => {}
                    Err(_) => self.broken = true,
                }
            }
        }
        Ok(())
    }

    /// TCP: opens a new connection and gives up on every outstanding query.
    fn reconnect(&mut self, now: Instant) -> anyhow::Result<()> {
        let Conn::Tcp(tcp) = &mut self.conn else {
            return Ok(());
        };
        tcp.stream = connect_tcp(tcp.target, self.cfg.pace.is_some())?;
        tcp.acc.clear();
        self.broken = false;
        let in_window = self.cfg.in_window(now);
        if in_window {
            self.stats.reconnects += 1;
        }
        for i in 0..self.slots.len() {
            if !self.slots[i].active {
                continue;
            }
            if in_window && !self.slots[i].send_failed {
                self.stats.timeouts += 1;
            }
            self.free(i);
            if self.cfg.pace.is_none() && now < self.cfg.win_end {
                self.issue(i);
            }
        }
        Ok(())
    }

    fn run(&mut self) -> anyhow::Result<()> {
        if self.cfg.pace.is_some() {
            self.free_list = (0..self.slots.len()).rev().collect();
            self.next_due = Instant::now();
        } else {
            for i in 0..self.slots.len() {
                self.issue(i);
            }
        }
        let mut last_scan = Instant::now();
        loop {
            if self.broken {
                self.reconnect(Instant::now())?;
            }
            self.issue_due(Instant::now());
            self.poll()?;
            let now = Instant::now();
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
        while self.active > 0 && !self.broken && Instant::now() < deadline {
            self.poll()?;
        }
        Ok(())
    }
}

/// The local address a client binds to: the target address itself for a
/// loopback target (WSL2 intercepts 127.0.0.1, so runs there use another
/// 127.0.0.0/8 address), else the unspecified address of the target's family.
fn local_addr(target: SocketAddr) -> SocketAddr {
    match (target, target.ip().is_loopback()) {
        (_, true) => (target.ip(), 0).into(),
        (SocketAddr::V4(_), false) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        (SocketAddr::V6(_), false) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    }
}

/// Creates a UDP client socket: 4 MiB buffers, connected to `target`, short
/// read timeout.
fn make_udp_socket(target: SocketAddr, paced: bool) -> anyhow::Result<UdpSocket> {
    let sock = Socket::new(
        Domain::for_address(target),
        Type::DGRAM,
        Some(Protocol::UDP),
    )
    .context("cannot create UDP socket")?;
    let _ = sock.set_recv_buffer_size(SOCKET_BUF);
    let _ = sock.set_send_buffer_size(SOCKET_BUF);
    let local = local_addr(target);
    sock.bind(&local.into())
        .with_context(|| format!("cannot bind {local}"))?;
    sock.connect(&target.into())
        .with_context(|| format!("cannot connect to {target}"))?;
    sock.set_read_timeout(Some(recv_timeout(paced)))
        .context("cannot set read timeout")?;
    Ok(sock.into())
}

fn recv_timeout(paced: bool) -> Duration {
    if paced {
        PACED_RECV_TIMEOUT
    } else {
        RECV_TIMEOUT
    }
}

/// Opens a TCP connection (retrying for a short while), with TCP_NODELAY and
/// a short read timeout.
fn connect_tcp(target: SocketAddr, paced: bool) -> anyhow::Result<TcpStream> {
    let deadline = Instant::now() + CONNECT_RETRY;
    loop {
        let sock = Socket::new(
            Domain::for_address(target),
            Type::STREAM,
            Some(Protocol::TCP),
        )
        .context("cannot create TCP socket")?;
        let _ = sock.set_recv_buffer_size(SOCKET_BUF);
        let _ = sock.set_send_buffer_size(SOCKET_BUF);
        let local = local_addr(target);
        sock.bind(&local.into())
            .with_context(|| format!("cannot bind {local}"))?;
        match sock.connect(&target.into()) {
            Ok(()) => {
                sock.set_tcp_nodelay(true)
                    .context("cannot set TCP_NODELAY")?;
                sock.set_read_timeout(Some(recv_timeout(paced)))
                    .context("cannot set read timeout")?;
                sock.set_write_timeout(Some(Duration::from_secs(1)))
                    .context("cannot set write timeout")?;
                return Ok(sock.into());
            }
            Err(e) if Instant::now() < deadline => {
                tracing::debug!("connect to {target} failed: {e}; retrying");
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e).with_context(|| format!("cannot connect to {target}")),
        }
    }
}

fn make_conn(target: SocketAddr, transport: Transport, paced: bool) -> anyhow::Result<Conn> {
    Ok(match transport {
        Transport::Udp => Conn::Udp(make_udp_socket(target, paced)?),
        Transport::Tcp => Conn::Tcp(TcpConn {
            stream: connect_tcp(target, paced)?,
            target,
            acc: Vec::new(),
        }),
    })
}

fn client_main(conn: Conn, cfg: Cfg, names: Arc<Names>, seed: u64) -> anyhow::Result<ClientStats> {
    let mut client = Client::new(conn, cfg, names, seed)?;
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
    if let Some(qps) = args.qps
        && !(qps.is_finite() && qps >= 1.0)
    {
        bail!("--qps must be at least 1, got {qps}");
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
    let names = Arc::new(Names::from_file(&args.names)?);
    let paced = args.qps.is_some();

    // Sockets and connections are created up front so that a failure aborts
    // before any thread runs.
    let conns = (0..args.clients)
        .map(|_| make_conn(args.target, args.transport, paced))
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
        edns: (!args.no_edns).then_some(CLIENT_EDNS_UDP),
        rd: args.rd,
        require_aa: args.require_aa,
        pace: args
            .qps
            .map(|qps| Duration::from_secs_f64(args.clients as f64 / qps)),
        win_start,
        win_end,
    };

    let mut handles = Vec::with_capacity(args.clients);
    let mut spawn_error = None;
    for (i, conn) in conns.into_iter().enumerate() {
        let seed = args.seed.wrapping_add(i as u64);
        let names = Arc::clone(&names);
        match thread::Builder::new()
            .name(format!("load-client-{i}"))
            .spawn(move || client_main(conn, cfg, names, seed))
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
    let mut total = ClientStats {
        sent: 0,
        received: 0,
        answers: 0,
        nodata: 0,
        nxdomain: 0,
        timeouts: 0,
        errors: 0,
        unexpected: 0,
        send_errors: 0,
        reconnects: 0,
        hist: new_histogram()?,
    };
    for r in joined {
        let s = r.map_err(|_| anyhow!("client thread panicked"))??;
        total.sent += s.sent;
        total.received += s.received;
        total.answers += s.answers;
        total.nodata += s.nodata;
        total.nxdomain += s.nxdomain;
        total.timeouts += s.timeouts;
        total.errors += s.errors;
        total.unexpected += s.unexpected;
        total.send_errors += s.send_errors;
        total.reconnects += s.reconnects;
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
        transport: args.transport.name().to_string(),
        clients: args.clients,
        inflight: args.inflight,
        target_qps: args.qps,
        edns: !args.no_edns,
        names_file: args.names.display().to_string(),
        names: names.len() as u64,
        warmup_seconds: args.warmup.as_secs_f64(),
        measured_seconds,
        sent: total.sent,
        received: total.received,
        answers: total.answers,
        nodata: total.nodata,
        nxdomain: total.nxdomain,
        timeouts: total.timeouts,
        errors: total.errors,
        unexpected: total.unexpected,
        send_errors: total.send_errors,
        reconnects: total.reconnects,
        qps: total.received as f64 / measured_seconds,
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
    let mode = match r.target_qps {
        Some(q) => format!("paced at {} QPS", group_thousands(q.round() as u64)),
        None => "closed loop".to_string(),
    };
    println!(
        "load          {} {}, {} clients x {} in flight, EDNS {}, {} queries from {}",
        r.transport,
        mode,
        r.clients,
        r.inflight,
        if r.edns { "on" } else { "off" },
        group_thousands(r.names),
        r.names_file
    );
    println!(
        "window        {:.1} s measured after {:.1} s warmup",
        r.measured_seconds, r.warmup_seconds
    );
    println!("sent          {}", group_thousands(r.sent));
    println!(
        "received      {} (answers {}, nodata {}, nxdomain {})",
        group_thousands(r.received),
        group_thousands(r.answers),
        group_thousands(r.nodata),
        group_thousands(r.nxdomain)
    );
    println!("timeouts      {}", group_thousands(r.timeouts));
    println!("errors        {}", group_thousands(r.errors));
    println!("unexpected    {}", group_thousands(r.unexpected));
    println!("send errors   {}", group_thousands(r.send_errors));
    if r.transport == "tcp" {
        println!("reconnects    {}", group_thousands(r.reconnects));
    }
    println!("qps           {}", group_thousands(r.qps.round() as u64));
    let l = &r.latency_us;
    println!(
        "latency (us)  p50 {:.1}  p90 {:.1}  p99 {:.1}  p99.9 {:.1}  max {:.1}  mean {:.1}",
        l.p50, l.p90, l.p99, l.p999, l.max, l.mean
    );
    if let Some(s) = &r.server {
        let per_query = if r.received > 0 && r.qps > 0.0 {
            format!(
                ", {:.2} us per query",
                s.cpu_seconds * 1e6 / (r.qps * r.measured_seconds)
            )
        } else {
            String::new()
        };
        println!(
            "server        pid {}: cpu {:.2} cores ({:.2} s{}), rss peak {:.1} MiB, end {:.1} MiB",
            s.pid, s.cpu_cores, s.cpu_seconds, per_query, s.peak_rss_mib, s.end_rss_mib
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
            workers: args.workers,
            metrics: args.metrics.map(|m| m == OnOff::On),
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
    use rand::RngExt;
    use std::net::TcpListener;
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
        /// Valid answer without AA.
        NoAa,
    }

    struct Responder {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
        handle: Option<JoinHandle<()>>,
    }

    /// Turns the query message `q` into a response according to `b`. Returns
    /// false if `q` is not a query.
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
            Behavior::ServFail => out[3] = 2,
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
        if b == Behavior::NoAa {
            out[2] &= !0x04;
        }
        if b == Behavior::WrongId {
            out[0] ^= 0x80;
        }
        true
    }

    impl Responder {
        fn start_udp(b: Behavior) -> Responder {
            let sock = UdpSocket::bind((wire::test_loopback(), 0)).unwrap();
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

        /// A TCP responder: one thread per connection, replies in order.
        /// `max_per_conn` closes a connection after that many queries.
        fn start_tcp(b: Behavior, max_per_conn: usize) -> Responder {
            let listener = TcpListener::bind((wire::test_loopback(), 0)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let addr = listener.local_addr().unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let stop2 = stop.clone();
            let handle = thread::spawn(move || {
                let mut workers = Vec::new();
                while !stop2.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut conn, _)) => {
                            conn.set_nonblocking(false).unwrap();
                            conn.set_read_timeout(Some(Duration::from_millis(20)))
                                .unwrap();
                            let stop3 = stop2.clone();
                            workers.push(thread::spawn(move || {
                                let mut acc: Vec<u8> = Vec::new();
                                let mut buf = [0u8; 8192];
                                let mut out = Vec::new();
                                let mut served = 0;
                                while !stop3.load(Ordering::Relaxed) {
                                    match conn.read(&mut buf) {
                                        Ok(0) => return,
                                        Ok(n) => acc.extend_from_slice(&buf[..n]),
                                        Err(e) if is_timeout(&e) => continue,
                                        Err(_) => return,
                                    }
                                    while acc.len() >= 2 {
                                        let len = usize::from(u16::from_be_bytes([acc[0], acc[1]]));
                                        if acc.len() < 2 + len {
                                            break;
                                        }
                                        if b != Behavior::Silent
                                            && make_response(&acc[2..2 + len], b, &mut out)
                                        {
                                            let mut frame =
                                                (out.len() as u16).to_be_bytes().to_vec();
                                            frame.extend_from_slice(&out);
                                            if conn.write_all(&frame).is_err() {
                                                return;
                                            }
                                        }
                                        acc.drain(..2 + len);
                                        served += 1;
                                        if served >= max_per_conn {
                                            return;
                                        }
                                    }
                                }
                            }));
                        }
                        Err(_) => thread::sleep(Duration::from_millis(5)),
                    }
                }
                for w in workers {
                    let _ = w.join();
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

    /// A names file in the target directory, removed on drop.
    struct TempNames(PathBuf);

    impl TempNames {
        fn new(tag: &str, text: &str) -> TempNames {
            let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("test-tmp");
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join(format!("names-{tag}-{}.txt", std::process::id()));
            fs::write(&path, text).unwrap();
            TempNames(path)
        }
    }

    impl Drop for TempNames {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    const MIX: &str = "host-1.example.test A\nhost-2.example.test A\nhost-3.example.test A\nnohost-9.example.test A\n";

    fn test_args(target: SocketAddr, names: &TempNames) -> LoadArgs {
        LoadArgs {
            target,
            names: names.0.clone(),
            transport: Transport::Udp,
            clients: 2,
            inflight: 8,
            qps: None,
            duration: Duration::from_secs(1),
            warmup: Duration::from_millis(100),
            timeout: Duration::from_millis(500),
            no_edns: false,
            rd: false,
            require_aa: true,
            server_pid: None,
            json: None,
            label: None,
            workers: None,
            metrics: None,
            seed: 7,
        }
    }

    fn response_of(q: &[u8], behavior: Behavior) -> Vec<u8> {
        let mut out = Vec::new();
        assert!(make_response(q, behavior, &mut out));
        out
    }

    #[test]
    fn udp_closed_loop_against_valid_responder() {
        let names = TempNames::new("udp", MIX);
        let r = Responder::start_udp(Behavior::Valid);
        let res = run_load(&test_args(r.addr, &names)).unwrap();
        assert!(res.received > 0, "{res:?}");
        assert_eq!(res.errors, 0, "{res:?}");
        assert_eq!(res.timeouts, 0, "{res:?}");
        assert_eq!(res.unexpected, 0, "{res:?}");
        assert_eq!(res.send_errors, 0, "{res:?}");
        assert_eq!(res.received, res.answers + res.nodata + res.nxdomain);
        assert!(res.answers > 0 && res.nxdomain > 0 && res.nodata == 0);
        assert!(res.sent > 0);
        assert!((res.qps - res.received as f64 / res.measured_seconds).abs() < 1e-6);
        assert_eq!(res.target, r.addr.to_string());
        assert_eq!(res.transport, "udp");
        assert_eq!(res.names, 4);
        assert!(res.edns);
        let l = &res.latency_us;
        assert!(
            l.p50 > 0.0 && l.p50 <= l.p90 && l.p90 <= l.p99 && l.p99 <= l.p999 && l.p999 <= l.max
        );
        assert!(res.server.is_none());
        assert!(res.client_cpu_cores.is_some());
    }

    #[test]
    fn udp_no_edns_all_nx() {
        let names = TempNames::new("nx", "nohost-1.example.test A\n");
        let r = Responder::start_udp(Behavior::Valid);
        let mut args = test_args(r.addr, &names);
        args.no_edns = true;
        args.clients = 1;
        let res = run_load(&args).unwrap();
        assert!(res.received > 0, "{res:?}");
        assert_eq!(res.nxdomain, res.received, "{res:?}");
        assert_eq!(res.errors, 0, "{res:?}");
        assert!(!res.edns);
    }

    #[test]
    fn tcp_closed_loop_against_valid_responder() {
        let names = TempNames::new("tcp", MIX);
        let r = Responder::start_tcp(Behavior::Valid, usize::MAX);
        let mut args = test_args(r.addr, &names);
        args.transport = Transport::Tcp;
        let res = run_load(&args).unwrap();
        assert!(res.received > 0, "{res:?}");
        assert_eq!(res.errors, 0, "{res:?}");
        assert_eq!(res.timeouts, 0, "{res:?}");
        assert_eq!(res.unexpected, 0, "{res:?}");
        assert_eq!(res.reconnects, 0, "{res:?}");
        assert_eq!(res.transport, "tcp");
    }

    #[test]
    fn tcp_reconnects_when_the_server_closes() {
        let names = TempNames::new("tcpre", MIX);
        let r = Responder::start_tcp(Behavior::Valid, 500);
        let mut args = test_args(r.addr, &names);
        args.transport = Transport::Tcp;
        args.clients = 1;
        args.inflight = 4;
        let res = run_load(&args).unwrap();
        assert!(res.received > 500, "{res:?}");
        assert!(res.reconnects > 0, "{res:?}");
    }

    #[test]
    fn paced_run_holds_the_rate() {
        let names = TempNames::new("paced", MIX);
        let r = Responder::start_udp(Behavior::Valid);
        let mut args = test_args(r.addr, &names);
        args.qps = Some(2000.0);
        args.duration = Duration::from_secs(2);
        let res = run_load(&args).unwrap();
        assert_eq!(res.target_qps, Some(2000.0));
        assert!(
            (1000.0..=2400.0).contains(&res.qps),
            "paced rate off target: {res:?}"
        );
        assert_eq!(res.errors, 0, "{res:?}");
    }

    #[test]
    fn sampling_own_process_as_server() {
        let names = TempNames::new("pid", MIX);
        let r = Responder::start_udp(Behavior::Valid);
        let mut args = test_args(r.addr, &names);
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
        let names = TempNames::new("nopid", MIX);
        let r = Responder::start_udp(Behavior::Valid);
        let mut args = test_args(r.addr, &names);
        args.server_pid = Some(4_000_000_001);
        assert!(run_load(&args).is_err());
    }

    #[test]
    fn silent_responder_times_out() {
        let names = TempNames::new("silent", MIX);
        let r = Responder::start_udp(Behavior::Silent);
        let mut args = test_args(r.addr, &names);
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
        let names = TempNames::new("wrongid", MIX);
        let r = Responder::start_udp(Behavior::WrongId);
        let mut args = test_args(r.addr, &names);
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
    fn bad_responses_count_as_errors() {
        for b in [Behavior::ServFail, Behavior::Truncated, Behavior::NoAa] {
            let names = TempNames::new("bad", MIX);
            let r = Responder::start_udp(b);
            let mut args = test_args(r.addr, &names);
            args.clients = 1;
            args.inflight = 4;
            args.duration = Duration::from_millis(500);
            let res = run_load(&args).unwrap();
            assert_eq!(res.received, 0, "{res:?}");
            assert!(res.errors > 0, "{res:?}");
        }
    }

    #[test]
    fn missing_aa_is_fine_without_require_aa() {
        let names = TempNames::new("noaa", MIX);
        let r = Responder::start_udp(Behavior::NoAa);
        let mut args = test_args(r.addr, &names);
        args.require_aa = false;
        args.clients = 1;
        args.duration = Duration::from_millis(500);
        let res = run_load(&args).unwrap();
        assert!(res.received > 0 && res.errors == 0, "{res:?}");
    }

    #[test]
    fn rejects_bad_arguments() {
        let names = TempNames::new("args", MIX);
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let ok = test_args(addr, &names);
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
        a.qps = Some(0.0);
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
        let mut names = Vec::new();
        crate::names::encode_name("host-42.example.test", &mut names).unwrap();
        let mut q = Vec::new();
        let qend = wire::write_query(&mut q, 0x1234, &names, 1, Some(1232), false);
        let q = q[wire::FRAME_PREFIX..].to_vec();
        let mut nxn = Vec::new();
        crate::names::encode_name("nohost-42.example.test", &mut nxn).unwrap();
        let mut qnx = Vec::new();
        let qnx_end = wire::write_query(&mut qnx, 0x1235, &nxn, 1, None, false);
        let qnx = qnx[wire::FRAME_PREFIX..].to_vec();

        let check = |resp: &[u8], query: &[u8], qend: usize| {
            let h = wire::parse_header(resp).unwrap();
            validate(&h, resp, query, qend, true)
        };

        let good = response_of(&q, Behavior::Valid);
        assert_eq!(check(&good, &q, qend), Verdict::Answer);
        let good_nx = response_of(&qnx, Behavior::Valid);
        assert_eq!(check(&good_nx, &qnx, qnx_end), Verdict::NxDomain);

        // NODATA: NOERROR without an answer.
        let mut nodata = good.clone();
        nodata[7] = 0;
        assert_eq!(check(&nodata, &q, qend), Verdict::NoData);

        // Header bits.
        let mut bad = good.clone();
        bad[2] &= !0x80; // QR=0
        assert_eq!(check(&bad, &q, qend), Verdict::Bad);
        let mut bad = good.clone();
        bad[2] &= !0x04; // AA=0
        assert_eq!(check(&bad, &q, qend), Verdict::Bad);
        let mut bad = good.clone();
        bad[2] |= 0x02; // TC=1
        assert_eq!(check(&bad, &q, qend), Verdict::Bad);
        let mut bad = good.clone();
        bad[5] = 0; // QDCOUNT=0
        assert_eq!(check(&bad, &q, qend), Verdict::Bad);
        let mut bad = good.clone();
        bad[3] = 2; // SERVFAIL
        assert_eq!(check(&bad, &q, qend), Verdict::Bad);

        // Question bytes differ / response cut short.
        let mut bad = good.clone();
        bad[13] = b'H';
        assert_eq!(check(&bad, &q, qend), Verdict::Bad);
        assert_eq!(check(&good[..qend - 1], &q, qend), Verdict::Bad);

        // AA is only required on request.
        let mut no_aa = good.clone();
        no_aa[2] &= !0x04;
        let h = wire::parse_header(&no_aa).unwrap();
        assert_eq!(validate(&h, &no_aa, &q, qend, false), Verdict::Answer);
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
        rec.metrics = Some(false);
        append_record(&path, &rec).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let back: RunRecord = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(back.workers, Some(4));
        assert_eq!(back.metrics, Some(false));
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
        assert!(
            Wrapper::try_parse_from(["x"]).is_err(),
            "--names is required"
        );
        let w = Wrapper::try_parse_from(["x", "--names", "q.txt"]).unwrap();
        assert_eq!(
            w.args.target,
            "127.0.0.1:5353".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(w.args.transport, Transport::Udp);
        assert_eq!(w.args.clients, 8);
        assert_eq!(w.args.inflight, 32);
        assert_eq!(w.args.duration, Duration::from_secs(20));
        assert_eq!(w.args.warmup, Duration::from_secs(2));
        assert_eq!(w.args.timeout, Duration::from_secs(1));
        assert!(!w.args.no_edns && !w.args.rd && !w.args.require_aa);
        assert_eq!(w.args.qps, None);
        assert_eq!(w.args.seed, 1);
        let w = Wrapper::try_parse_from([
            "x",
            "--names",
            "q.txt",
            "--duration",
            "500ms",
            "--no-edns",
            "--server-pid",
            "7",
            "--transport",
            "tcp",
            "--qps",
            "1000",
            "--metrics",
            "off",
        ])
        .unwrap();
        assert_eq!(w.args.duration, Duration::from_millis(500));
        assert!(w.args.no_edns);
        assert_eq!(w.args.server_pid, Some(7));
        assert_eq!(w.args.transport, Transport::Tcp);
        assert_eq!(w.args.qps, Some(1000.0));
        assert_eq!(w.args.metrics, Some(OnOff::Off));
    }
}
