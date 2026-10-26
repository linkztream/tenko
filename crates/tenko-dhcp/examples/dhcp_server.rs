//! The DHCPv4 engine on a port, for perfdhcp and the loopback measurements M26 to M28
//! (`bench/phase3-dhcp`), with its own load client for hosts without perfdhcp.
//!
//! ```text
//! dhcp_server serve [--listen 127.0.0.1:6767] [--relay-port 67] [--workers 4]
//!                   [--store mem|queue] [--seconds 60] [--lease-secs 3600]
//! dhcp_server load  [--server 127.0.0.1:6767] [--bind 127.0.0.1:6868] [--mode dora|renew]
//!                   [--clients 10000] [--rate 0] [--window 64] [--seconds 30]
//!                   [--subnet 198.18.0.0]
//! ```
//!
//! `serve` runs the engine's listener in relay mode over one scope, `198.18.0.0/15` (the
//! benchmarking range of RFC 2544) with a pool of about 131,000 addresses, selected by
//! option 118 (RFC 3011) or `giaddr`, so that perfdhcp as a relay and the load client both
//! reach it; replies go to the relay's port `--relay-port`. The store is the in-memory
//! reference `MemLeaseStore` (`mem`, the oracle of the contracts, whose commit walks every
//! row of the scope to keep its client index and so slows down as the leases grow), or
//! `queue`, the same hand-off and completion with no rows kept (the lease table holds them),
//! which isolates the engine and the commit hand-off. The lease table is a hash table here,
//! as WP7.2's production table is; the reference table's index walk would dominate at
//! 100,000 leases. After `--seconds` it prints the server's counters and exits.
//!
//! `load` acts as a relay agent at `--bind` (`giaddr` is its address, option 118 selects
//! the scope): in `dora` mode each of `--clients` clients runs DISCOVER, OFFER, REQUEST,
//! ACK once; in `renew` mode every client first gets a lease (not measured) and then
//! renews (REQUEST with `ciaddr`, ACK) round after round for `--seconds`. `--rate 0` keeps
//! `--window` exchanges in flight (closed loop, the ceiling); a rate paces new exchanges
//! (open loop, the latency at that rate). An exchange without its ACK after two seconds is
//! lost. It prints the rate, the losses and the latency percentiles from the first message
//! to the ACK. Clients are told apart by option 61; `chaddr` uses the documentation MACs
//! (RFC 7042). `--subnet` is the address option 118 carries (default `198.18.0.0`, the
//! scope of `serve`), so that the client can also fill a scope of `tenko serve` on another
//! network.

use std::{
    collections::{HashMap, VecDeque},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use ipnet::Ipv4Net;
use tenko_core::{
    NodeId, PrefixId, RangeId, Revision, VrfId,
    dhcp::{DdnsPolicy, Lease, LeaseTimes, OptionValue},
};
use tenko_dhcp::{
    image::{ConfigImage, ImageBuilder, PoolImage, ScopeImage},
    lease::{LeaseTable, LeaseView, PendingChange},
    metrics::EXCHANGE_BUCKETS_US,
    server::{DhcpServer, Listen, ServerConfig},
    store::{Completion, LeaseStore, MemLeaseStore, SubmitError, Ticket},
    v4::{BOOTREQUEST, Message, MessageBuilder, MessageType, code, engine::ListenMode},
};

type Error = Box<dyn std::error::Error + Send + Sync>;

fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => serve(&Args(args[1..].to_vec())),
        Some("load") => load(&Args(args[1..].to_vec())),
        _ => {
            eprintln!("usage: dhcp_server serve|load [options]; see the example's comment");
            std::process::exit(2);
        }
    }
}

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

// ---------------------------------------------------------------------------------------
// The server side

/// The scope's network: the benchmarking range of RFC 2544.
fn network() -> Ipv4Net {
    "198.18.0.0/15".parse().expect("a network")
}

fn image(lease_secs: u32) -> ConfigImage {
    let mut builder = ImageBuilder::new(Revision(1));
    let times = LeaseTimes::fixed(lease_secs);
    builder.scope(ScopeImage {
        prefix: PrefixId::generate(),
        vrf: VrfId::generate(),
        network: network(),
        authoritative: true,
        restricted: false,
        server_id: None,
        lease: times,
        shared_network: None,
        pools: vec![PoolImage {
            range: RangeId::generate(),
            first: Ipv4Addr::new(198, 18, 0, 10),
            last: Ipv4Addr::new(198, 19, 255, 250),
            lease: times,
            classes: Vec::new(),
            options: Vec::new(),
        }],
        excluded: Vec::new(),
        options: vec![
            OptionValue::v4(code::ROUTERS, vec![198, 18, 0, 1]),
            OptionValue::v4(code::DOMAIN_NAME_SERVERS, vec![198, 18, 0, 53]),
            OptionValue::v4(code::DOMAIN_NAME, b"example.test".to_vec()),
        ],
        classes: Vec::new(),
        ddns: DdnsPolicy::default(),
    });
    builder.build()
}

/// A lease table on hash maps: lookups without allocation, applies in constant time.
#[derive(Default)]
struct HashTable {
    rows: HashMap<(VrfId, Ipv4Addr), Lease>,
    by_client: HashMap<PrefixId, HashMap<Vec<u8>, (VrfId, Ipv4Addr)>>,
}

impl LeaseTable for HashTable {
    fn get(&self, vrf: VrfId, addr: Ipv4Addr) -> Option<LeaseView<'_>> {
        self.rows.get(&(vrf, addr)).map(LeaseView::of)
    }

    fn by_client(&self, scope: PrefixId, identity: &[u8]) -> Option<LeaseView<'_>> {
        let key = self.by_client.get(&scope)?.get(identity)?;
        self.rows.get(key).map(LeaseView::of)
    }

    fn lease(&self, vrf: VrfId, addr: Ipv4Addr) -> Option<Lease> {
        self.rows.get(&(vrf, addr)).cloned()
    }

    fn apply(&mut self, lease: Lease) {
        let key = (lease.vrf, lease.addr);
        if self
            .rows
            .get(&key)
            .is_some_and(|held| held.cltt > lease.cltt)
        {
            return;
        }
        let identity = lease.client.identity();
        let scope = lease.scope;
        if let Some(held) = self.rows.get(&key) {
            let previous = held.client.identity();
            if previous != identity
                && let Some(index) = self.by_client.get_mut(&held.scope)
                && index.get(&previous) == Some(&key)
            {
                index.remove(&previous);
            }
        }
        let cltt = lease.cltt;
        self.rows.insert(key, lease);
        let index = self.by_client.entry(scope).or_default();
        let newer = index
            .get(&identity)
            .and_then(|other| self.rows.get(other))
            .is_none_or(|other| other.cltt <= cltt);
        if newer {
            index.insert(identity, key);
        }
    }

    fn remove(&mut self, vrf: VrfId, addr: Ipv4Addr) {
        if let Some(held) = self.rows.remove(&(vrf, addr)) {
            let identity = held.client.identity();
            if let Some(index) = self.by_client.get_mut(&held.scope)
                && index.get(&identity) == Some(&(vrf, addr))
            {
                index.remove(&identity);
            }
        }
    }

    fn len(&self) -> usize {
        self.rows.len()
    }
}

/// The hand-off and completion of the `LeaseStore` contract, with no rows kept.
struct QueueStore {
    queue: Mutex<VecDeque<Ticket>>,
    done: Mutex<Vec<Completion>>,
    capacity: usize,
    revision: AtomicU64,
}

impl QueueStore {
    fn new(capacity: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::with_capacity(capacity)),
            done: Mutex::new(Vec::with_capacity(capacity)),
            capacity,
            revision: AtomicU64::new(0),
        }
    }

    fn commit(&self) {
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        let mut done = self.done.lock().unwrap_or_else(PoisonError::into_inner);
        for ticket in queue.drain(..) {
            let revision = self.revision.fetch_add(1, Ordering::Relaxed) + 1;
            done.push(Completion {
                ticket,
                outcome: Ok(Revision(revision)),
            });
        }
    }
}

impl LeaseStore for QueueStore {
    fn submit(&self, _change: &PendingChange, ticket: Ticket) -> Result<(), SubmitError> {
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        if queue.len() >= self.capacity {
            return Err(SubmitError::Full);
        }
        queue.push_back(ticket);
        Ok(())
    }

    fn completions(&self, out: &mut Vec<Completion>) {
        out.append(&mut self.done.lock().unwrap_or_else(PoisonError::into_inner));
    }

    fn accepting(&self) -> bool {
        true
    }
}

/// The upper bound of the bucket that holds the `q` quantile, in microseconds.
fn bucket_quantile(counts: &[u64], q: f64) -> String {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return "-".to_owned();
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "a rank out of a count"
    )]
    let rank = ((total as f64) * q).ceil() as u64;
    let mut seen = 0;
    for (index, count) in counts.iter().enumerate() {
        seen += count;
        if seen >= rank {
            return EXCHANGE_BUCKETS_US
                .get(index)
                .map_or_else(|| "> 1000000".to_owned(), |bound| format!("<= {bound}"));
        }
    }
    "-".to_owned()
}

fn serve(args: &Args) -> Result<(), Error> {
    let listen: SocketAddrV4 =
        args.parse("--listen", SocketAddrV4::new(Ipv4Addr::LOCALHOST, 6767))?;
    let workers: usize = args.parse("--workers", 4)?;
    let seconds: u64 = args.parse("--seconds", 60)?;
    let lease_secs: u32 = args.parse("--lease-secs", 3_600)?;
    let mut config = ServerConfig {
        listen: vec![Listen {
            address: listen,
            mode: ListenMode::Relay,
            interface: None,
        }],
        workers,
        pending: 8_192,
        offers: 262_144,
        node: NodeId(1),
        ..ServerConfig::default()
    };
    config.engine.relay_port = args.parse("--relay-port", 67)?;
    let kind = args.get("--store").unwrap_or("mem").to_owned();
    let (store, drive): (Arc<dyn LeaseStore>, Box<dyn Fn() + Send + Sync>) = match kind.as_str() {
        "mem" => {
            let store = Arc::new(MemLeaseStore::with_capacity(NodeId(1), 8_192));
            let driven = Arc::clone(&store);
            (
                store,
                Box::new(move || {
                    driven.commit();
                }),
            )
        }
        "queue" => {
            let store = Arc::new(QueueStore::new(8_192));
            let driven = Arc::clone(&store);
            (store, Box::new(move || driven.commit()))
        }
        other => return Err(format!("--store {other}: mem or queue").into()),
    };
    let server = DhcpServer::start(
        &config,
        image(lease_secs),
        HashTable::default(),
        store,
        Some(drive),
    )?;
    println!(
        "serving on {} with {workers} workers, store {kind}, for {seconds} s",
        server.local_addrs()[0]
    );
    // Stops at `--seconds`, or `--idle-exit` seconds after the last packet once traffic
    // came.
    let idle_exit: u64 = args.parse("--idle-exit", 0)?;
    let end = Instant::now() + Duration::from_secs(seconds);
    let (mut seen, mut quiet_since) = (0u64, Instant::now());
    while Instant::now() < end {
        std::thread::sleep(Duration::from_millis(200));
        let total: u64 = server.metrics().packets.iter().flatten().sum();
        if total != seen {
            (seen, quiet_since) = (total, Instant::now());
        } else if idle_exit > 0 && seen > 0 && quiet_since.elapsed().as_secs() >= idle_exit {
            break;
        }
    }
    let metrics = server.metrics();
    let leases = server.with_table(|table| table.len());
    println!(
        "server: discover answered {}, request answered {}, nak {}, dropped {:?}, leases {leases}",
        metrics.packets("discover", "answered"),
        metrics.packets("request", "answered"),
        metrics.naks,
        metrics.dropped,
    );
    for (label, histogram) in [
        ("offer", &metrics.exchange[0]),
        ("ack", &metrics.exchange[1]),
        ("commit", &metrics.commit),
    ] {
        println!(
            "server {label}: count {}, p50 {} us, p99 {} us",
            histogram.0.iter().sum::<u64>(),
            bucket_quantile(&histogram.0, 0.5),
            bucket_quantile(&histogram.0, 0.99),
        );
    }
    server.stop();
    Ok(())
}

// ---------------------------------------------------------------------------------------
// The load client

const IDLE: u8 = 0;
const DISCOVERING: u8 = 1;
const REQUESTING: u8 = 2;
const BOUND: u8 = 3;
const RENEWING: u8 = 4;

struct Clients {
    phase: Vec<AtomicU8>,
    addr: Vec<AtomicU32>,
    started: Vec<AtomicU64>,
    base: Instant,
}

impl Clients {
    fn new(count: usize) -> Self {
        Self {
            phase: (0..count).map(|_| AtomicU8::new(IDLE)).collect(),
            addr: (0..count).map(|_| AtomicU32::new(0)).collect(),
            started: (0..count).map(|_| AtomicU64::new(0)).collect(),
            base: Instant::now(),
        }
    }

    fn now_us(&self) -> u64 {
        u64::try_from(self.base.elapsed().as_micros()).unwrap_or(u64::MAX)
    }
}

struct Load {
    socket: UdpSocket,
    server: SocketAddrV4,
    relay: Ipv4Addr,
    /// The address option 118 carries.
    subnet: Ipv4Addr,
    clients: Clients,
    in_flight: AtomicUsize,
    stop: AtomicBool,
}

impl Load {
    fn packet(&self, kind: MessageType, client: usize, out: &mut [u8]) -> usize {
        let index = u32::try_from(client).unwrap_or(u32::MAX);
        let mut builder = MessageBuilder::new(out, 576).expect("a buffer");
        let ciaddr = if kind == MessageType::Request
            && self.clients.phase[client].load(Ordering::Relaxed) == RENEWING
        {
            Ipv4Addr::from(self.clients.addr[client].load(Ordering::Relaxed))
        } else {
            Ipv4Addr::UNSPECIFIED
        };
        builder
            .op(BOOTREQUEST)
            .htype(1)
            .hlen(6)
            .hops(1)
            .xid(index)
            .ciaddr(ciaddr)
            .giaddr(self.relay);
        let low = index.to_be_bytes()[3];
        builder
            .chaddr(&[0x00, 0x00, 0x5e, 0x00, 0x53, low])
            .expect("chaddr");
        let mut id = [0u8; 5];
        id[1..].copy_from_slice(&index.to_be_bytes());
        builder.message_type(kind).expect("53");
        builder.option(code::CLIENT_IDENTIFIER, &id).expect("61");
        if kind == MessageType::Request && ciaddr.is_unspecified() {
            let addr = Ipv4Addr::from(self.clients.addr[client].load(Ordering::Relaxed));
            builder
                .option(code::REQUESTED_ADDRESS, &addr.octets())
                .expect("50");
            builder.server_identifier(*self.server.ip()).expect("54");
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

/// Receives replies: an OFFER is answered with the REQUEST, an ACK ends the exchange.
fn receive(load: &Load, latencies: &mut Vec<u32>, naks: &mut u64) {
    let mut buf = [0u8; 1500];
    while !load.stop.load(Ordering::Relaxed) {
        let Ok((len, _)) = load.socket.recv_from(&mut buf) else {
            continue;
        };
        let Ok(message) = Message::parse(&buf[..len]) else {
            continue;
        };
        let client = message.xid() as usize;
        if client >= load.clients.phase.len() {
            continue;
        }
        let phase = &load.clients.phase[client];
        match message.message_type() {
            Ok(Some(MessageType::Offer)) if phase.load(Ordering::Relaxed) == DISCOVERING => {
                load.clients.addr[client].store(u32::from(message.yiaddr()), Ordering::Relaxed);
                phase.store(REQUESTING, Ordering::Relaxed);
                load.send(MessageType::Request, client);
            }
            Ok(Some(MessageType::Ack))
                if matches!(phase.load(Ordering::Relaxed), REQUESTING | RENEWING) =>
            {
                let started = load.clients.started[client].load(Ordering::Relaxed);
                let took = load.clients.now_us().saturating_sub(started);
                latencies.push(u32::try_from(took).unwrap_or(u32::MAX));
                phase.store(BOUND, Ordering::Relaxed);
                load.in_flight.fetch_sub(1, Ordering::Relaxed);
            }
            Ok(Some(MessageType::Nak)) => *naks += 1,
            _ => {}
        }
    }
}

/// Starts exchanges for `clients` (in order, repeated when `rounds` allows) at `rate` per
/// second or with `window` in flight, until every one ran or `seconds` passed. Returns
/// the exchanges started and the ones lost.
fn drive(
    load: &Load,
    clients: usize,
    renew: bool,
    (rate, window, seconds): (u64, usize, u64),
) -> (u64, u64) {
    let start = Instant::now();
    let deadline = start + Duration::from_secs(seconds);
    let mut started = 0u64;
    let mut lost = 0u64;
    let mut ring: VecDeque<(usize, u64)> = VecDeque::new();
    let mut next = 0usize;
    let timeout_us = 2_000_000;
    loop {
        let now = Instant::now();
        // Reap: exchanges are started in order, so the oldest are at the front.
        while let Some(&(client, at)) = ring.front() {
            let phase = load.clients.phase[client].load(Ordering::Relaxed);
            if phase == BOUND {
                ring.pop_front();
            } else if load.clients.now_us().saturating_sub(at) > timeout_us {
                ring.pop_front();
                lost += 1;
                load.clients.phase[client].store(IDLE, Ordering::Relaxed);
                load.in_flight.fetch_sub(1, Ordering::Relaxed);
            } else {
                break;
            }
        }
        let finished = if renew {
            now >= deadline
        } else {
            next >= clients || now >= deadline
        };
        if finished {
            if ring.is_empty() || now >= deadline + Duration::from_secs(3) {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }
        let may_start = if rate == 0 {
            load.in_flight.load(Ordering::Relaxed) < window
        } else {
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                clippy::cast_precision_loss,
                reason = "a count from a time and a rate"
            )]
            let due = (now.duration_since(start).as_secs_f64() * rate as f64) as u64;
            started < due
        };
        if !may_start {
            if rate == 0 {
                std::thread::yield_now();
            } else {
                std::thread::sleep(Duration::from_micros(200));
            }
            continue;
        }
        let client = next % clients;
        next += 1;
        let phase = &load.clients.phase[client];
        if renew {
            if phase.load(Ordering::Relaxed) != BOUND {
                continue;
            }
            phase.store(RENEWING, Ordering::Relaxed);
        } else {
            phase.store(DISCOVERING, Ordering::Relaxed);
        }
        let at = load.clients.now_us();
        load.clients.started[client].store(at, Ordering::Relaxed);
        load.in_flight.fetch_add(1, Ordering::Relaxed);
        ring.push_back((client, at));
        started += 1;
        load.send(
            if renew {
                MessageType::Request
            } else {
                MessageType::Discover
            },
            client,
        );
    }
    (started, lost)
}

fn percentile(sorted: &[u32], q: f64) -> f64 {
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
    f64::from(sorted[at])
}

#[allow(
    clippy::cast_precision_loss,
    reason = "counts and durations printed as rates"
)]
fn run_phase(load: &Arc<Load>, name: &str, clients: usize, renew: bool, pace: (u64, usize, u64)) {
    load.stop.store(false, Ordering::Relaxed);
    let receiver = {
        let load = Arc::clone(load);
        std::thread::spawn(move || {
            let mut latencies = Vec::with_capacity(1 << 20);
            let mut naks = 0;
            receive(&load, &mut latencies, &mut naks);
            (latencies, naks)
        })
    };
    let begin = Instant::now();
    let (started, lost) = drive(load, clients, renew, pace);
    let elapsed = begin.elapsed().as_secs_f64();
    load.stop.store(true, Ordering::Relaxed);
    let (mut latencies, naks) = receiver.join().expect("the receiver");
    latencies.sort_unstable();
    let completed = latencies.len();
    println!(
        "{name}: started {started}, completed {completed}, lost {lost}, naks {naks}, \
         {:.0} per second over {elapsed:.2} s; latency us p50 {:.0} p90 {:.0} p99 {:.0} \
         p99.9 {:.0} max {:.0}",
        completed as f64 / elapsed,
        percentile(&latencies, 0.5),
        percentile(&latencies, 0.9),
        percentile(&latencies, 0.99),
        percentile(&latencies, 0.999),
        percentile(&latencies, 1.0),
    );
}

fn load(args: &Args) -> Result<(), Error> {
    let server: SocketAddrV4 =
        args.parse("--server", SocketAddrV4::new(Ipv4Addr::LOCALHOST, 6767))?;
    let bind: SocketAddrV4 = args.parse("--bind", SocketAddrV4::new(Ipv4Addr::LOCALHOST, 6868))?;
    let clients: usize = args.parse("--clients", 10_000)?;
    let rate: u64 = args.parse("--rate", 0)?;
    let window: usize = args.parse("--window", 64)?;
    let seconds: u64 = args.parse("--seconds", 30)?;
    let mode = args.get("--mode").unwrap_or("dora").to_owned();
    let subnet: Ipv4Addr = args.parse("--subnet", network().network())?;
    let socket = UdpSocket::bind(bind)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    let socket2 = socket2::SockRef::from(&socket);
    let _ = socket2.set_recv_buffer_size(8 * 1024 * 1024);
    let _ = socket2.set_send_buffer_size(8 * 1024 * 1024);
    let relay = match socket.local_addr()? {
        SocketAddr::V4(address) => *address.ip(),
        SocketAddr::V6(_) => return Err("an IPv4 relay address".into()),
    };
    let load = Arc::new(Load {
        socket,
        server,
        relay,
        subnet,
        clients: Clients::new(clients),
        in_flight: AtomicUsize::new(0),
        stop: AtomicBool::new(false),
    });
    match mode.as_str() {
        "dora" => run_phase(&load, "dora", clients, false, (rate, window, seconds)),
        "renew" => {
            run_phase(&load, "fill", clients, false, (0, window, 600));
            run_phase(&load, "renew", clients, true, (rate, window, seconds));
        }
        other => return Err(format!("--mode {other}: dora or renew").into()),
    }
    Ok(())
}
