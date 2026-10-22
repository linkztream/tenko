//! M31 (`bench/phase3-dhcp`): the rate of DDNS from DHCP end to end, with its own load
//! client for hosts without perfdhcp.
//!
//! ```text
//! ddns_load [--server 127.0.0.1:6767] [--bind 127.0.0.1:6868] [--dns 127.0.0.1:15354]
//!           [--zone lan.example.test] [--subnet 198.18.0.0] [--clients 70000]
//!           [--rate 1000] [--seconds 60] [--warmup 5] [--names on|off] [--prefix m31]
//!           [--offset 0] [--label TEXT] [--out FILE]
//! ```
//!
//! It acts as a relay agent at `--bind` against the relay-mode DHCP listener of a
//! `tenko serve --roles controller,dns,dhcp` node (`giaddr` is its address, option 118
//! selects the scope at `--subnet`, option 61 tells the clients apart, `chaddr` uses the
//! documentation MACs of RFC 7042 with the low octet of the client's index, `xid` is the
//! index). A paced open loop starts `--rate` exchanges per second, for `--warmup` seconds
//! unmeasured and then `--seconds` measured: DISCOVER, the OFFER answered by a REQUEST,
//! the ACK ends the exchange, each client once, in index order (`--clients` must exceed
//! `--rate` times `--warmup` plus `--seconds`). An exchange without its ACK after two
//! seconds is lost. `--offset` adds a number to every client index (identity, `xid` and
//! name), so that runs on one node use new clients.
//!
//! With `--names on` (the default) every DISCOVER and REQUEST carries option 81 (RFC 4702):
//! flags S and E, two zero RCODE octets and the partial name `<prefix>-<index>` as one
//! length-prefixed label, so that the server writes the A record, the DHCID and the PTR
//! record under the scope's forward zone (`--zone`). A second thread asks the DNS listener
//! (`--dns`) for `<prefix>-<index>.<zone>` every 10 ms for each acknowledged client (at most
//! 256 queries per pass, oldest first in turn) until an answer with RCODE 0 holds the
//! leased address, or 5 s after the ACK, when the update counts as lost. The DDNS latency
//! is from the receipt of the ACK to the receipt of that answer, so it holds the queue of
//! the update worker, the zone write and the DNS role's view of it, plus up to one polling
//! period. With `--names off` there is no option 81 and no option 12: the same DORA with
//! no DDNS, the baseline of the comparison.
//!
//! Only exchanges started after the warmup are measured. After the measured seconds the
//! tool waits until every measured exchange is acked or lost and every update answered or
//! lost, prints one line (started, acked and lost exchanges, the achieved rate, the
//! exchange latency percentiles in milliseconds and, with names, the updates answered and
//! lost and the percentiles of the DDNS latency) and appends a JSON line with the same
//! fields to `--out`.
//!
//! The figures are loopback, single-node figures from an own client on the same host, an
//! upper bound standing in for perfdhcp (and for a DNS client that polls), labelled so.

use std::{
    collections::{HashMap, VecDeque},
    fmt::Write as _,
    io::Write,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Receiver, Sender, TryRecvError},
    },
    time::{Duration, Instant},
};

use tenko_dhcp::v4::{BOOTREQUEST, Message, MessageBuilder, MessageType, code};
use tenko_dns::wire;

type Error = Box<dyn std::error::Error + Send + Sync>;

/// Seconds an exchange waits for its ACK.
const DHCP_TIMEOUT_US: u64 = 2_000_000;
/// Seconds after the ACK an update waits for its answer.
const DDNS_TIMEOUT: Duration = Duration::from_secs(5);
/// The period of the DNS prober's passes: each waiting name is asked once per pass, so the
/// figure holds up to one period of polling and the prober does not load the DNS role
/// more than a client that polls would.
const PROBE_TICK: Duration = Duration::from_millis(10);
/// The most queries one pass sends.
const PROBE_BUDGET: usize = 256;
const TYPE_A: u16 = 1;
/// Option 81's flags: S (the server updates the A record) and E (the name in wire form).
const FQDN_FLAGS: u8 = 0x05;

struct Args(Vec<String>);

impl Args {
    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .position(|arg| arg == name)
            .and_then(|at| self.0.get(at + 1))
            .map(String::as_str)
    }

    fn parse<T: std::str::FromStr>(&self, name: &str, default: T) -> Result<T, Error>
    where
        T::Err: std::fmt::Display,
    {
        match self.get(name) {
            Some(text) => text
                .parse()
                .map_err(|error| format!("{name} {text}: {error}").into()),
            None => Ok(default),
        }
    }
}

#[derive(Clone)]
struct Config {
    server: SocketAddrV4,
    bind: SocketAddrV4,
    dns: SocketAddr,
    zone: String,
    subnet: Ipv4Addr,
    clients: usize,
    rate: u64,
    seconds: u64,
    warmup: u64,
    names: bool,
    prefix: String,
    offset: u32,
    label: String,
    out: Option<String>,
}

impl Config {
    fn from_args(args: &Args) -> Result<Self, Error> {
        let names = match args.get("--names").unwrap_or("on") {
            "on" => true,
            "off" => false,
            other => return Err(format!("--names {other}: on or off").into()),
        };
        let config = Self {
            server: args.parse("--server", SocketAddrV4::new(Ipv4Addr::LOCALHOST, 6767))?,
            bind: args.parse("--bind", SocketAddrV4::new(Ipv4Addr::LOCALHOST, 6868))?,
            dns: args.parse("--dns", SocketAddr::from((Ipv4Addr::LOCALHOST, 15_354)))?,
            zone: args
                .get("--zone")
                .unwrap_or("lan.example.test")
                .trim_matches('.')
                .to_owned(),
            subnet: args.parse("--subnet", Ipv4Addr::new(198, 18, 0, 0))?,
            clients: args.parse("--clients", 70_000)?,
            rate: args.parse("--rate", 1_000)?,
            seconds: args.parse("--seconds", 60)?,
            warmup: args.parse("--warmup", 5)?,
            names,
            prefix: args.get("--prefix").unwrap_or("m31").to_owned(),
            offset: args.parse("--offset", 0)?,
            label: args.get("--label").unwrap_or("").to_owned(),
            out: args.get("--out").map(str::to_owned),
        };
        if config.rate == 0 || config.seconds == 0 {
            return Err("--rate and --seconds must be positive".into());
        }
        let needed = config.rate.saturating_mul(config.warmup + config.seconds);
        if (config.clients as u64) <= needed {
            return Err(format!(
                "--clients {} must exceed rate * (warmup + seconds) = {needed}: \
                 every client is used once",
                config.clients
            )
            .into());
        }
        if u32::try_from(config.clients)
            .ok()
            .and_then(|clients| clients.checked_add(config.offset))
            .is_none()
        {
            return Err("--offset plus --clients does not fit a 32-bit index".into());
        }
        if config.prefix.is_empty() || config.prefix.len() > 40 || config.prefix.contains('.') {
            return Err("--prefix: one label of 1 to 40 characters".into());
        }
        Ok(config)
    }
}

// ---------------------------------------------------------------------------------------
// The DHCP side

const IDLE: u8 = 0;
const DISCOVERING: u8 = 1;
const REQUESTING: u8 = 2;
const BOUND: u8 = 3;

struct Clients {
    phase: Vec<AtomicU8>,
    addr: Vec<AtomicU32>,
    server_id: Vec<AtomicU32>,
    started: Vec<AtomicU64>,
    base: Instant,
}

impl Clients {
    fn new(count: usize) -> Self {
        let zeros32 = || (0..count).map(|_| AtomicU32::new(0)).collect();
        Self {
            phase: (0..count).map(|_| AtomicU8::new(IDLE)).collect(),
            addr: zeros32(),
            server_id: zeros32(),
            started: (0..count).map(|_| AtomicU64::new(0)).collect(),
            base: Instant::now(),
        }
    }

    fn us_at(&self, at: Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.base).as_micros()).unwrap_or(u64::MAX)
    }

    fn now_us(&self) -> u64 {
        self.us_at(Instant::now())
    }
}

struct Load {
    socket: UdpSocket,
    server: SocketAddrV4,
    relay: Ipv4Addr,
    subnet: Ipv4Addr,
    names: bool,
    prefix: String,
    offset: u32,
    clients: Clients,
    /// The first measured client, `usize::MAX` until the warmup is over.
    measure_from: AtomicUsize,
    stop: AtomicBool,
}

impl Load {
    /// The index on the wire: the client's number plus the run's offset.
    fn wire_index(&self, client: usize) -> u32 {
        self.offset
            .saturating_add(u32::try_from(client).unwrap_or(u32::MAX))
    }

    fn packet(&self, kind: MessageType, client: usize, out: &mut [u8]) -> usize {
        let index = self.wire_index(client);
        let mut builder = MessageBuilder::new(out, 576).expect("a buffer");
        builder
            .op(BOOTREQUEST)
            .htype(1)
            .hlen(6)
            .hops(1)
            .xid(index)
            .giaddr(self.relay);
        let low = index.to_be_bytes()[3];
        builder
            .chaddr(&[0x00, 0x00, 0x5e, 0x00, 0x53, low])
            .expect("chaddr");
        let mut id = [0u8; 5];
        id[1..].copy_from_slice(&index.to_be_bytes());
        builder.message_type(kind).expect("53");
        builder.option(code::CLIENT_IDENTIFIER, &id).expect("61");
        if kind == MessageType::Request {
            let addr = Ipv4Addr::from(self.clients.addr[client].load(Ordering::Relaxed));
            builder
                .option(code::REQUESTED_ADDRESS, &addr.octets())
                .expect("50");
            let server = Ipv4Addr::from(self.clients.server_id[client].load(Ordering::Relaxed));
            builder.server_identifier(server).expect("54");
        }
        if self.names {
            // Option 81 (RFC 4702): flags, RCODE1, RCODE2, the partial name in wire form
            // without the terminating zero octet.
            let label = format!("{}-{index}", self.prefix);
            let mut data = vec![FQDN_FLAGS, 0, 0, u8::try_from(label.len()).unwrap_or(63)];
            data.extend_from_slice(label.as_bytes());
            builder.option(code::CLIENT_FQDN, &data).expect("81");
        }
        builder
            .option(code::SUBNET_SELECTION, &self.subnet.octets())
            .expect("118");
        builder
            .option(code::PARAMETER_REQUEST_LIST, &[1, 3, 6, 15, 51, 54])
            .expect("55");
        builder.finish().expect("finish")
    }

    fn send(&self, kind: MessageType, client: usize) {
        let mut buf = [0u8; 576];
        let len = self.packet(kind, client, &mut buf);
        let _ = self.socket.send_to(&buf[..len], self.server);
    }
}

/// A client acknowledged during the measurement, handed to the DNS prober.
struct Acked {
    index: u32,
    addr: Ipv4Addr,
    at: Instant,
}

/// What the DHCP receiver saw.
#[derive(Default)]
struct Received {
    /// Exchange latencies in microseconds of the measured exchanges that were acked.
    latencies: Vec<u32>,
    naks: u64,
}

/// Receives replies: an OFFER is answered with the REQUEST, an ACK ends the exchange and,
/// when it is measured, goes to the prober.
fn receive(load: &Load, acked: Option<&Sender<Acked>>) -> Received {
    let mut received = Received {
        latencies: Vec::with_capacity(1 << 17),
        naks: 0,
    };
    let mut buf = [0u8; 1500];
    while !load.stop.load(Ordering::Relaxed) {
        let Ok((len, _)) = load.socket.recv_from(&mut buf) else {
            continue;
        };
        let now = Instant::now();
        let Ok(message) = Message::parse(&buf[..len]) else {
            continue;
        };
        let Some(client) = message.xid().checked_sub(load.offset).map(|c| c as usize) else {
            continue;
        };
        if client >= load.clients.phase.len() {
            continue;
        }
        let phase = &load.clients.phase[client];
        match message.message_type() {
            Ok(Some(MessageType::Offer)) if phase.load(Ordering::Relaxed) == DISCOVERING => {
                let server = message
                    .server_identifier()
                    .ok()
                    .flatten()
                    .unwrap_or(*load.server.ip());
                load.clients.addr[client].store(u32::from(message.yiaddr()), Ordering::Relaxed);
                load.clients.server_id[client].store(u32::from(server), Ordering::Relaxed);
                phase.store(REQUESTING, Ordering::Relaxed);
                load.send(MessageType::Request, client);
            }
            Ok(Some(MessageType::Ack)) if phase.load(Ordering::Relaxed) == REQUESTING => {
                phase.store(BOUND, Ordering::Relaxed);
                if client < load.measure_from.load(Ordering::Relaxed) {
                    continue;
                }
                let started = load.clients.started[client].load(Ordering::Relaxed);
                let took = load.clients.us_at(now).saturating_sub(started);
                received
                    .latencies
                    .push(u32::try_from(took).unwrap_or(u32::MAX));
                if let Some(acked) = acked {
                    let _ = acked.send(Acked {
                        index: load.wire_index(client),
                        addr: message.yiaddr(),
                        at: now,
                    });
                }
            }
            Ok(Some(MessageType::Nak)) => received.naks += 1,
            _ => {}
        }
    }
    received
}

/// What the pacing loop counted over the measured exchanges.
struct Driven {
    started: u64,
    lost: u64,
}

/// Starts exchanges for the clients in order at `rate` per second for `warmup + seconds`
/// seconds, and then waits until every exchange is acked or lost. Only the exchanges
/// started after the warmup are counted.
fn drive(load: &Load, config: &Config) -> Driven {
    let start = Instant::now();
    let measure_at = start + Duration::from_secs(config.warmup);
    let deadline = measure_at + Duration::from_secs(config.seconds);
    let clients = config.clients;
    let mut driven = Driven {
        started: 0,
        lost: 0,
    };
    let mut ring: VecDeque<(usize, u64)> = VecDeque::new();
    let mut total = 0u64;
    let mut next = 0usize;
    loop {
        let now = Instant::now();
        // Reap: exchanges are started in order, so the oldest are at the front.
        while let Some(&(client, at)) = ring.front() {
            let phase = load.clients.phase[client].load(Ordering::Relaxed);
            if phase == BOUND {
                ring.pop_front();
            } else if load.clients.now_us().saturating_sub(at) > DHCP_TIMEOUT_US {
                ring.pop_front();
                if client >= load.measure_from.load(Ordering::Relaxed) {
                    driven.lost += 1;
                }
                load.clients.phase[client].store(IDLE, Ordering::Relaxed);
            } else {
                break;
            }
        }
        if next >= clients || now >= deadline {
            if ring.is_empty() || now >= deadline + Duration::from_secs(3) {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss,
            reason = "a count from a time and a rate"
        )]
        let due = (now.duration_since(start).as_secs_f64() * config.rate as f64) as u64;
        if total >= due {
            std::thread::sleep(Duration::from_micros(200));
            continue;
        }
        let client = next;
        next += 1;
        total += 1;
        if now >= measure_at {
            if load.measure_from.load(Ordering::Relaxed) == usize::MAX {
                load.measure_from.store(client, Ordering::Relaxed);
            }
            driven.started += 1;
        }
        load.clients.phase[client].store(DISCOVERING, Ordering::Relaxed);
        let at = load.clients.now_us();
        load.clients.started[client].store(at, Ordering::Relaxed);
        ring.push_back((client, at));
        load.send(MessageType::Discover, client);
    }
    driven
}

// ---------------------------------------------------------------------------------------
// The DNS side

/// The updates waiting for their answer, shared by the prober's two threads.
struct Probe {
    pending: HashMap<u32, Pending>,
    /// The pending indexes in the order they are asked for; an index that was answered
    /// leaves it when its turn comes.
    order: VecDeque<u32>,
    /// The index each query id was last used for.
    ids: Vec<u32>,
    /// ACK to answer, in microseconds, of the updates that came.
    answered: Vec<u32>,
    lost: u64,
}

struct Pending {
    addr: Ipv4Addr,
    at: Instant,
}

const NO_INDEX: u32 = u32::MAX;

impl Probe {
    fn new() -> Self {
        Self {
            pending: HashMap::new(),
            order: VecDeque::new(),
            ids: vec![NO_INDEX; 1 << 16],
            answered: Vec::new(),
            lost: 0,
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Asks the DNS listener for every pending name each pass until the channel closes and
/// nothing is pending.
fn probe_queries(
    socket: &UdpSocket,
    config: &Config,
    acked: &Receiver<Acked>,
    probe: &Mutex<Probe>,
) {
    let mut next_id = 0u16;
    let mut closed = false;
    let mut asks: Vec<(u16, u32)> = Vec::with_capacity(PROBE_BUDGET);
    let mut out = Vec::with_capacity(512);
    let mut tick = Instant::now();
    loop {
        loop {
            match acked.try_recv() {
                Ok(item) => {
                    let mut probe = lock(probe);
                    probe.order.push_back(item.index);
                    probe.pending.insert(
                        item.index,
                        Pending {
                            addr: item.addr,
                            at: item.at,
                        },
                    );
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    closed = true;
                    break;
                }
            }
        }
        asks.clear();
        let finished = {
            let mut probe = lock(probe);
            let now = Instant::now();
            for _ in 0..probe.order.len().min(PROBE_BUDGET) {
                let Some(index) = probe.order.pop_front() else {
                    break;
                };
                let Some(item) = probe.pending.get(&index) else {
                    continue;
                };
                if now.saturating_duration_since(item.at) > DDNS_TIMEOUT {
                    probe.pending.remove(&index);
                    probe.lost += 1;
                    continue;
                }
                probe.order.push_back(index);
                next_id = next_id.wrapping_add(1);
                probe.ids[usize::from(next_id)] = index;
                asks.push((next_id, index));
            }
            closed && probe.pending.is_empty()
        };
        for &(id, index) in &asks {
            let name = format!("{}-{index}.{}", config.prefix, config.zone);
            wire::write_query(&mut out, id, &name, TYPE_A, Some(1232));
            let _ = socket.send_to(&out, config.dns);
        }
        if finished {
            break;
        }
        tick += PROBE_TICK;
        let now = Instant::now();
        if tick > now {
            std::thread::sleep(tick - now);
        } else {
            tick = now;
        }
    }
}

/// Reads the answers: the first with RCODE 0 and the leased address resolves its update.
fn probe_answers(socket: &UdpSocket, probe: &Mutex<Probe>, stop: &AtomicBool) {
    let mut buf = vec![0u8; 4096];
    while !stop.load(Ordering::Relaxed) {
        let Ok((len, _)) = socket.recv_from(&mut buf) else {
            continue;
        };
        let now = Instant::now();
        let answer = &buf[..len];
        let Some(head) = wire::parse_header(answer) else {
            continue;
        };
        if !head.qr || head.rcode != 0 || head.ancount == 0 {
            continue;
        }
        let mut probe = lock(probe);
        let index = probe.ids[usize::from(head.id)];
        let Some(item) = probe.pending.get(&index) else {
            continue;
        };
        let octets = item.addr.octets();
        if answer.windows(4).any(|window| window == octets) {
            let took = now.saturating_duration_since(item.at).as_micros();
            probe.pending.remove(&index);
            probe.answered.push(u32::try_from(took).unwrap_or(u32::MAX));
        }
    }
}

// ---------------------------------------------------------------------------------------
// The results

/// The value at quantile `q` of the sorted microseconds, in milliseconds.
fn percentile_ms(sorted: &[u32], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "an index out of a length"
    )]
    let at = (((sorted.len() as f64) * q).ceil() as usize).clamp(1, sorted.len()) - 1;
    f64::from(sorted[at]) / 1000.0
}

/// Percentiles p50, p90, p99, p99.9 and max of sorted microseconds, in milliseconds.
fn percentiles(sorted: &[u32]) -> [f64; 5] {
    [0.5, 0.9, 0.99, 0.999, 1.0].map(|q| percentile_ms(sorted, q))
}

fn json_text(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            ch if ch.is_control() => out.push(' '),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[allow(
    clippy::cast_precision_loss,
    reason = "counts and durations printed as rates"
)]
fn report(
    config: &Config,
    driven: &Driven,
    received: &mut Received,
    probe: &mut Probe,
) -> Result<(), Error> {
    received.latencies.sort_unstable();
    probe.answered.sort_unstable();
    let acked = received.latencies.len() as u64;
    let rate = acked as f64 / config.seconds as f64;
    let exchange = percentiles(&received.latencies);
    let ddns = percentiles(&probe.answered);
    let answered = probe.answered.len() as u64;
    println!(
        "m31 names {}: started {}, acked {}, lost {}, naks {}, achieved {rate:.1} per second; \
         exchange ms p50 {:.3} p90 {:.3} p99 {:.3} p99.9 {:.3} max {:.3}{}",
        if config.names { "on" } else { "off" },
        driven.started,
        acked,
        driven.lost,
        received.naks,
        exchange[0],
        exchange[1],
        exchange[2],
        exchange[3],
        exchange[4],
        if config.names {
            format!(
                "; ddns answered {answered}, lost {}; ack-to-answer ms p50 {:.3} p90 {:.3} \
                 p99 {:.3} p99.9 {:.3} max {:.3}",
                probe.lost, ddns[0], ddns[1], ddns[2], ddns[3], ddns[4]
            )
        } else {
            String::new()
        }
    );
    let Some(path) = &config.out else {
        return Ok(());
    };
    let mut line = format!(
        "{{\"label\": {}, \"names\": {}, \"rate\": {}, \"seconds\": {}, \"warmup\": {}, \
         \"clients\": {}, \"offset\": {}, \"prefix\": {}, \"started\": {}, \"acked\": {acked}, \
         \"lost\": {}, \"naks\": {}, \"achieved_per_s\": {rate:.1}, \"exchange_p50_ms\": {:.3}, \
         \"exchange_p90_ms\": {:.3}, \"exchange_p99_ms\": {:.3}, \"exchange_p999_ms\": {:.3}, \
         \"exchange_max_ms\": {:.3}",
        json_text(&config.label),
        config.names,
        config.rate,
        config.seconds,
        config.warmup,
        config.clients,
        config.offset,
        json_text(&config.prefix),
        driven.started,
        driven.lost,
        received.naks,
        exchange[0],
        exchange[1],
        exchange[2],
        exchange[3],
        exchange[4],
    );
    if config.names {
        let _ = write!(
            line,
            ", \"ddns_answered\": {answered}, \"ddns_lost\": {}, \"ddns_p50_ms\": {:.3}, \
             \"ddns_p90_ms\": {:.3}, \"ddns_p99_ms\": {:.3}, \"ddns_p999_ms\": {:.3}, \
             \"ddns_max_ms\": {:.3}",
            probe.lost, ddns[0], ddns[1], ddns[2], ddns[3], ddns[4]
        );
    }
    line.push_str("}\n");
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?
        .write_all(line.as_bytes())?;
    Ok(())
}

fn main() -> Result<(), Error> {
    let args = Args(std::env::args().skip(1).collect());
    let config = Config::from_args(&args)?;
    let socket = UdpSocket::bind(config.bind)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    let sock_ref = socket2::SockRef::from(&socket);
    let _ = sock_ref.set_recv_buffer_size(8 * 1024 * 1024);
    let _ = sock_ref.set_send_buffer_size(8 * 1024 * 1024);
    let relay = match socket.local_addr()? {
        SocketAddr::V4(address) => *address.ip(),
        SocketAddr::V6(_) => return Err("an IPv4 relay address".into()),
    };
    let load = Arc::new(Load {
        socket,
        server: config.server,
        relay,
        subnet: config.subnet,
        names: config.names,
        prefix: config.prefix.clone(),
        offset: config.offset,
        clients: Clients::new(config.clients),
        measure_from: AtomicUsize::new(usize::MAX),
        stop: AtomicBool::new(false),
    });

    let probe = Arc::new(Mutex::new(Probe::new()));
    let (acked_tx, acked_rx) = mpsc::channel::<Acked>();
    let stop_probe = Arc::new(AtomicBool::new(false));
    let mut prober = Vec::new();
    if config.names {
        let bind: SocketAddr = if config.dns.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let dns_socket = Arc::new(UdpSocket::bind(bind)?);
        dns_socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        let sock_ref = socket2::SockRef::from(&*dns_socket);
        let _ = sock_ref.set_recv_buffer_size(8 * 1024 * 1024);
        let _ = sock_ref.set_send_buffer_size(8 * 1024 * 1024);
        let answers = {
            let (socket, probe, stop) = (
                Arc::clone(&dns_socket),
                Arc::clone(&probe),
                Arc::clone(&stop_probe),
            );
            std::thread::spawn(move || probe_answers(&socket, &probe, &stop))
        };
        let config = Arc::new(config.clone());
        let queries = {
            let probe = Arc::clone(&probe);
            std::thread::spawn(move || probe_queries(&dns_socket, &config, &acked_rx, &probe))
        };
        prober.push((queries, answers));
    }

    let dhcp_thread = {
        let load = Arc::clone(&load);
        let acked = config.names.then_some(acked_tx);
        std::thread::spawn(move || receive(&load, acked.as_ref()))
    };
    let driven = drive(&load, &config);
    load.stop.store(true, Ordering::Relaxed);
    let mut received = dhcp_thread
        .join()
        .map_err(|_| "the DHCP receiver panicked")?;
    // The receiver's end of the channel is gone: the prober finishes when every update
    // is answered or lost.
    for (queries, answers) in prober {
        queries.join().map_err(|_| "the DNS prober panicked")?;
        stop_probe.store(true, Ordering::Relaxed);
        answers.join().map_err(|_| "the DNS receiver panicked")?;
    }
    let mut probe = lock(&probe);
    report(&config, &driven, &mut received, &mut probe)
}
