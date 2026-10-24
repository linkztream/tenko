//! The DHCPv6 listeners and workers (plan sections 2.5 and 2.10, WP9.1): the engine of
//! [`crate::v6::engine`] wrapped in UDP sockets on port 547 and the commit, as
//! [`crate::server::DhcpServer`] wraps the DHCPv4 engine.
//!
//! [`Dhcp6Server::start`] binds every listener ([`Listen6`], the `[dhcp] listen` entries
//! with an IPv6 address) and starts blocking UDP workers:
//!
//! | Mode | Linux | Elsewhere |
//! |---|---|---|
//! | `relay` | Binds the unicast address on port 547: relay agents send RELAY-FORW there, and only unicast arrives. One `SO_REUSEPORT` socket per worker | The unicast address; one socket shared by the workers |
//! | `direct` | Binds `[::]:547` with `SO_BINDTODEVICE` to the entry's interface and `SO_REUSEADDR`, and joins `All_DHCP_Relay_Agents_and_Servers` (`ff02::1:2`) on it; one socket the workers share, since a multicast reaches every socket of a reuse-port group | Binds `[::]:547` and joins `ff02::1:2` on the system's default interface |
//!
//! A worker runs the engine over the current image, the DHCPv6 lease table and the offers,
//! sends an ADVERTISE, a CONFIRM's REPLY or an INFORMATION-REQUEST's REPLY at once, and
//! for a REPLY that commits hands the change to the [`Lease6Store`] and parks the reply in
//! a slot; the committer thread sends it when the commit returns and drops it when the
//! commit fails, so no REPLY promises what is not durable. A reply goes to the relay's
//! address on port 547 (RFC 8415 section 19.3) or to the client's link-local address on
//! port 546.

use std::{
    io,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket},
    sync::{
        Arc, Mutex, PoisonError, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread::{JoinHandle, Thread},
    time::{Duration, Instant},
};

use socket2::{Domain, Protocol, Socket, Type};
use tenko_core::{NodeId, Timestamp};

use super::{
    ALL_DHCP_RELAY_AGENTS_AND_SERVERS, MessageType,
    engine::{
        self, Action6, Context6, Destination6, Engine6Settings, Metrics6Snapshot, Offers6,
        REPLY_CAPACITY6, Received6, Scratch6, WorkerMetrics6,
    },
    lease::{Lease6Index, Lease6Table as _, PendingChange6, SharedLeases6, store::Lease6Store},
};
use crate::{
    image::ConfigImage,
    server::{STOP_POLL, SocketLayout},
    store::{Completion, SubmitError, Ticket},
    v4::engine::{DropReason, ListenMode},
};

/// One DHCPv6 listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listen6 {
    /// The interface's unicast address and the port (547).
    pub address: SocketAddrV6,
    /// Relay or direct.
    pub mode: ListenMode,
    /// The interface of a direct listener.
    pub interface: Option<String>,
}

/// The settings of the DHCPv6 server.
#[derive(Debug, Clone)]
pub struct Server6Config {
    /// The listeners.
    pub listen: Vec<Listen6>,
    /// Workers per listener.
    pub workers: usize,
    /// The socket layout.
    pub layout: SocketLayout,
    /// The engine's settings.
    pub engine: Engine6Settings,
    /// How many commits may be in flight.
    pub pending: usize,
    /// How many offers the table holds about.
    pub offers: usize,
    /// `SO_RCVBUF` (0 keeps the system's).
    pub recv_buffer: usize,
    /// `SO_SNDBUF` (0 keeps the system's).
    pub send_buffer: usize,
    /// The node that writes the leases.
    pub node: NodeId,
    /// The server's DUID (option 2).
    pub server_duid: Vec<u8>,
}

impl Default for Server6Config {
    fn default() -> Self {
        Self {
            listen: Vec::new(),
            workers: std::thread::available_parallelism()
                .map_or(1, std::num::NonZeroUsize::get)
                .min(8),
            layout: SocketLayout::platform_default(),
            engine: Engine6Settings::default(),
            pending: 4_096,
            offers: 65_536,
            recv_buffer: 4 * 1024 * 1024,
            send_buffer: 4 * 1024 * 1024,
            node: NodeId(1),
            server_duid: server_duid(NodeId(1)),
        }
    }
}

/// The server's DUID when `[dhcp.v6] server_duid` sets none: a DUID-UUID (RFC 6355) whose
/// UUID is derived from the node identifier, so that it stays the same across restarts
/// (RFC 8415 section 11 asks for a stable DUID) and differs between the nodes of a cluster.
pub fn server_duid(node: NodeId) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let digest = Sha256::new()
        .chain_update(b"tenko dhcp6 server duid")
        .chain_update(node.0.to_be_bytes())
        .finalize();
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&digest[..16]);
    // A name-based UUID: version 5 in the high nibble of octet 6, the RFC 4122 variant.
    uuid[6] = (uuid[6] & 0x0f) | 0x50;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    let mut out = vec![0, 4];
    out.extend_from_slice(&uuid);
    out
}

/// What one listener is, for the role's status report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener6Info {
    /// The configured address and the port bound.
    pub address: SocketAddrV6,
    /// Relay or direct.
    pub mode: ListenMode,
    /// The interface of a direct listener.
    pub interface: Option<String>,
    /// Workers on it.
    pub workers: usize,
}

/// A reply waiting for its commit.
#[derive(Clone)]
struct Slot {
    used: bool,
    generation: u32,
    change: PendingChange6,
    reply: [u8; REPLY_CAPACITY6],
    len: usize,
    dest: Destination6,
    listener: usize,
    worker: usize,
    request: Option<MessageType>,
    received: Instant,
    submitted: Instant,
}

struct Pending {
    slots: Box<[Slot]>,
    free: Vec<u32>,
}

impl Pending {
    fn new(capacity: usize) -> Self {
        let now = Instant::now();
        let slot = Slot {
            used: false,
            generation: 0,
            change: PendingChange6::new(&[0, 0, 0], Timestamp::now()),
            reply: [0; REPLY_CAPACITY6],
            len: 0,
            dest: Destination6::Client(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 546, 0, 0)),
            listener: 0,
            worker: 0,
            request: None,
            received: now,
            submitted: now,
        };
        let capacity = u32::try_from(capacity.max(1)).unwrap_or(u32::MAX);
        Self {
            slots: vec![slot; capacity as usize].into_boxed_slice(),
            free: (0..capacity).rev().collect(),
        }
    }
}

fn ticket_of(index: u32, generation: u32) -> Ticket {
    Ticket((u64::from(generation) << 32) | u64::from(index))
}

fn split_ticket(ticket: Ticket) -> (usize, u32) {
    #[allow(clippy::cast_possible_truncation, reason = "the halves of the ticket")]
    ((ticket.0 & 0xffff_ffff) as usize, (ticket.0 >> 32) as u32)
}

struct Shared {
    image: RwLock<Arc<ConfigImage>>,
    generation: AtomicU64,
    table: SharedLeases6,
    applies_commits: bool,
    offers: Arc<Offers6>,
    store: Arc<dyn Lease6Store>,
    drive: Option<Box<dyn Fn() + Send + Sync>>,
    pending: Mutex<Pending>,
    in_flight: AtomicUsize,
    sockets: Vec<Arc<UdpSocket>>,
    last_commit_us: AtomicU64,
    metrics: Vec<WorkerMetrics6>,
    stop: AtomicBool,
    committer: Mutex<Option<Thread>>,
    settings: Engine6Settings,
    node: NodeId,
    server_duid: Vec<u8>,
}

impl Shared {
    fn wake_committer(&self) {
        if let Some(thread) = self
            .committer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            thread.unpark();
        }
    }
}

/// The running DHCPv6 listeners, workers and committer.
pub struct Dhcp6Server {
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
    listeners: Vec<Listener6Info>,
}

impl std::fmt::Debug for Dhcp6Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dhcp6Server")
            .field("listeners", &self.listeners)
            .finish_non_exhaustive()
    }
}

/// The sockets of one listener.
struct Bound {
    address: SocketAddrV6,
    local: Ipv6Addr,
    sockets: Vec<Arc<UdpSocket>>,
}

#[cfg(target_os = "linux")]
fn set_reuse_port(socket: &Socket) -> io::Result<()> {
    socket.set_reuse_port(true)
}

#[cfg(not(target_os = "linux"))]
fn set_reuse_port(_socket: &Socket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_REUSEPORT spreading is a Linux feature; use the shared socket layout",
    ))
}

/// The index of an interface (Linux: from `/sys/class/net`), 0 when unknown: the system's
/// default interface for the multicast join.
fn interface_index(name: Option<&str>) -> u32 {
    let Some(name) = name else {
        return 0;
    };
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return 0;
    }
    std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

#[cfg(target_os = "linux")]
fn bind_device(socket: &Socket, interface: Option<&str>) -> io::Result<()> {
    if let Some(interface) = interface {
        socket.bind_device(Some(interface.as_bytes()))?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "the Linux variant sets a socket option that fails"
)]
fn bind_device(_socket: &Socket, _interface: Option<&str>) -> io::Result<()> {
    Ok(())
}

fn bind_one(
    listen: &Listen6,
    port: u16,
    reuse: bool,
    buffers: (usize, usize),
) -> io::Result<(UdpSocket, SocketAddrV6)> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    if buffers.0 > 0 {
        let _ = socket.set_recv_buffer_size(buffers.0);
    }
    if buffers.1 > 0 {
        let _ = socket.set_send_buffer_size(buffers.1);
    }
    if reuse {
        set_reuse_port(&socket)?;
    }
    let address = match listen.mode {
        ListenMode::Relay => {
            let mut address = listen.address;
            address.set_port(port);
            address
        }
        ListenMode::Direct => {
            socket.set_reuse_address(true)?;
            bind_device(&socket, listen.interface.as_deref())?;
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)
        }
    };
    socket.bind(&SocketAddr::V6(address).into())?;
    if listen.mode == ListenMode::Direct {
        socket.join_multicast_v6(
            &ALL_DHCP_RELAY_AGENTS_AND_SERVERS,
            interface_index(listen.interface.as_deref()),
        )?;
    }
    let socket: UdpSocket = socket.into();
    socket.set_read_timeout(Some(STOP_POLL))?;
    let SocketAddr::V6(bound) = socket.local_addr()? else {
        return Err(io::Error::other("an IPv6 socket bound IPv4"));
    };
    Ok((socket, bound))
}

fn bind(
    listen: &Listen6,
    workers: usize,
    layout: SocketLayout,
    buffers: (usize, usize),
) -> io::Result<Bound> {
    // A multicast reaches every socket of a reuse-port group: one per direct listener.
    let reuse = layout == SocketLayout::ReusePort && listen.mode == ListenMode::Relay;
    let (first, bound) = bind_one(listen, listen.address.port(), reuse, buffers)?;
    let mut sockets = vec![Arc::new(first)];
    if reuse {
        for _ in 1..workers.max(1) {
            sockets.push(Arc::new(bind_one(listen, bound.port(), true, buffers)?.0));
        }
    }
    Ok(Bound {
        address: SocketAddrV6::new(*listen.address.ip(), bound.port(), 0, 0),
        local: *listen.address.ip(),
        sockets,
    })
}

impl Dhcp6Server {
    /// Binds the listeners and starts the workers and the committer over `image`, the
    /// table `table` and `store`. `applies_commits` says whether the store applies its
    /// commits to the table itself ([`StoreLeases6`](super::lease::commit::StoreLeases6)
    /// does); `drive`, when given, is called by the committer before it collects
    /// completions (the in-memory store commits there).
    ///
    /// # Errors
    ///
    /// A listener that cannot be bound, or a thread that cannot be started.
    pub fn start(
        config: &Server6Config,
        image: Arc<ConfigImage>,
        table: SharedLeases6,
        store: Arc<dyn Lease6Store>,
        applies_commits: bool,
        drive: Option<Box<dyn Fn() + Send + Sync>>,
    ) -> io::Result<Self> {
        let workers = config.workers.max(1);
        let mut bound = Vec::with_capacity(config.listen.len());
        for listen in &config.listen {
            bound.push(bind(
                listen,
                workers,
                config.layout,
                (config.recv_buffer, config.send_buffer),
            )?);
        }
        let total = bound.len() * workers;
        let listeners = config
            .listen
            .iter()
            .zip(&bound)
            .map(|(listen, bound)| Listener6Info {
                address: bound.address,
                mode: listen.mode,
                interface: listen.interface.clone(),
                workers,
            })
            .collect();
        let shared = Arc::new(Shared {
            image: RwLock::new(image),
            generation: AtomicU64::new(1),
            table,
            applies_commits,
            offers: Arc::new(Offers6::with_capacity(config.offers)),
            store,
            drive,
            pending: Mutex::new(Pending::new(config.pending)),
            in_flight: AtomicUsize::new(0),
            sockets: bound.iter().map(|b| Arc::clone(&b.sockets[0])).collect(),
            last_commit_us: AtomicU64::new(0),
            metrics: (0..=total).map(|_| WorkerMetrics6::default()).collect(),
            stop: AtomicBool::new(false),
            committer: Mutex::new(None),
            settings: config.engine,
            node: config.node,
            server_duid: config.server_duid.clone(),
        });
        let mut threads = Vec::with_capacity(total + 1);
        let committer = {
            let shared = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("dhcp6-commit".to_owned())
                .spawn(move || commit_loop(&shared))?
        };
        *shared
            .committer
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(committer.thread().clone());
        threads.push(committer);
        let mut index = 0;
        for (listener, listen) in bound.iter().enumerate() {
            let mode = config.listen[listener].mode;
            for worker in 0..workers {
                let socket = Arc::clone(&listen.sockets[worker % listen.sockets.len()]);
                let shared = Arc::clone(&shared);
                let local = listen.local;
                let me = index;
                index += 1;
                threads.push(
                    std::thread::Builder::new()
                        .name(format!("dhcp6-udp-{me}"))
                        .spawn(move || worker_loop(&shared, &socket, listener, me, local, mode))?,
                );
            }
        }
        Ok(Self {
            shared,
            threads,
            listeners,
        })
    }

    /// What each listener is.
    pub fn listeners(&self) -> &[Listener6Info] {
        &self.listeners
    }

    /// The addresses bound (the port the system chose for port 0).
    pub fn local_addrs(&self) -> Vec<SocketAddrV6> {
        self.listeners.iter().map(|info| info.address).collect()
    }

    /// Swaps the configuration image.
    pub fn set_image(&self, image: Arc<ConfigImage>) {
        *self
            .shared
            .image
            .write()
            .unwrap_or_else(PoisonError::into_inner) = image;
        self.shared.generation.fetch_add(1, Ordering::Release);
    }

    /// Replaces the image and, through `reset`, the table, under the table's write guard.
    pub fn swap(&self, image: Arc<ConfigImage>, reset: impl FnOnce(&mut Lease6Index)) {
        let mut table = self.shared.table.write();
        reset(&mut table);
        *self
            .shared
            .image
            .write()
            .unwrap_or_else(PoisonError::into_inner) = image;
        self.shared.generation.fetch_add(1, Ordering::Release);
    }

    /// The offers held.
    pub fn offers(&self) -> &Arc<Offers6> {
        &self.shared.offers
    }

    /// A function that wakes the committer.
    pub fn waker(&self) -> impl Fn() + Send + Sync + 'static {
        let shared = Arc::clone(&self.shared);
        move || shared.wake_committer()
    }

    /// The counters summed over the workers.
    pub fn metrics(&self) -> Metrics6Snapshot {
        WorkerMetrics6::total(&self.shared.metrics)
    }

    /// The last commit's time from hand-off to completion.
    pub fn last_commit(&self) -> Option<Duration> {
        match self.shared.last_commit_us.load(Ordering::Relaxed) {
            0 => None,
            micros => Some(Duration::from_micros(micros)),
        }
    }

    /// The commits in flight.
    pub fn in_flight(&self) -> usize {
        self.shared.in_flight.load(Ordering::Relaxed)
    }

    /// The server's DUID.
    pub fn server_duid(&self) -> &[u8] {
        &self.shared.server_duid
    }

    /// Stops the workers and the committer and waits for them.
    pub fn stop(mut self) {
        self.halt();
    }

    fn halt(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        self.shared.wake_committer();
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

impl Drop for Dhcp6Server {
    fn drop(&mut self) {
        self.halt();
    }
}

fn micros(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn worker_loop(
    shared: &Shared,
    socket: &UdpSocket,
    listener: usize,
    me: usize,
    local: Ipv6Addr,
    mode: ListenMode,
) {
    let metrics = &shared.metrics[me];
    let mut buf = vec![0u8; 65_536];
    let mut scratch = Scratch6::new();
    let mut seen = 0;
    let mut image = Arc::clone(&shared.image.read().unwrap_or_else(PoisonError::into_inner));
    while !shared.stop.load(Ordering::Relaxed) {
        let Ok((len, SocketAddr::V6(source))) = socket.recv_from(&mut buf) else {
            continue;
        };
        let received = Instant::now();
        let answer = {
            let table = shared.table.read();
            let generation = shared.generation.load(Ordering::Acquire);
            if generation != seen {
                image = Arc::clone(&shared.image.read().unwrap_or_else(PoisonError::into_inner));
                seen = generation;
            }
            let ctx = Context6 {
                image: &image,
                leases: &*table,
                offers: &shared.offers,
                settings: &shared.settings,
                server_duid: &shared.server_duid,
                accepting: shared.store.accepting6(),
                now: Timestamp::now(),
            };
            engine::handle(
                &ctx,
                &Received6 {
                    bytes: &buf[..len],
                    source,
                    local,
                    mode,
                },
                &mut scratch,
            )
        };
        metrics.count(&answer);
        match answer.action {
            Action6::Reply { kind, len, dest } => {
                if socket
                    .send_to(&scratch.reply[..len], dest.address())
                    .is_ok()
                    && kind == MessageType::Advertise
                {
                    metrics.exchange[0].record(micros(received));
                }
            }
            Action6::CommitThenReply { len, dest, .. } => {
                hand_off(
                    shared,
                    &scratch,
                    answer.request,
                    (len, dest),
                    (listener, me),
                    received,
                );
            }
            Action6::Drop(_) | Action6::Ignore(_) => {}
        }
    }
}

/// Parks the reply under a ticket and hands the change to the store.
fn hand_off(
    shared: &Shared,
    scratch: &Scratch6,
    request: Option<MessageType>,
    (len, dest): (usize, Destination6),
    (listener, worker): (usize, usize),
    received: Instant,
) {
    let metrics = &shared.metrics[worker];
    let ticket = {
        let mut pending = shared
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(index) = pending.free.pop() else {
            drop(pending);
            metrics.retract(request, DropReason::Queue);
            return;
        };
        let slot = &mut pending.slots[index as usize];
        slot.used = true;
        slot.generation = slot.generation.wrapping_add(1);
        slot.change.clone_from(&scratch.change);
        slot.reply[..len].copy_from_slice(&scratch.reply[..len]);
        slot.len = len;
        slot.dest = dest;
        slot.listener = listener;
        slot.worker = worker;
        slot.request = request;
        slot.received = received;
        slot.submitted = Instant::now();
        ticket_of(index, slot.generation)
    };
    shared.in_flight.fetch_add(1, Ordering::Relaxed);
    match shared.store.submit6(&scratch.change, ticket) {
        Ok(()) => shared.wake_committer(),
        Err(error) => {
            release(shared, ticket);
            shared.in_flight.fetch_sub(1, Ordering::Relaxed);
            let reason = match error {
                SubmitError::Full => DropReason::Queue,
                SubmitError::Refused => DropReason::StoreRefused,
            };
            metrics.retract(request, reason);
        }
    }
}

fn release(shared: &Shared, ticket: Ticket) -> Option<Slot> {
    let (index, generation) = split_ticket(ticket);
    let mut pending = shared
        .pending
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let slot = pending.slots.get_mut(index)?;
    if !slot.used || slot.generation != generation {
        return None;
    }
    slot.used = false;
    let taken = slot.clone();
    pending.free.push(u32::try_from(index).unwrap_or(u32::MAX));
    Some(taken)
}

fn commit_loop(shared: &Shared) {
    let committer = shared.metrics.len() - 1;
    let mut done: Vec<Completion> = Vec::with_capacity(1_024);
    loop {
        if let Some(drive) = &shared.drive {
            drive();
        }
        done.clear();
        shared.store.completions6(&mut done);
        if done.is_empty() {
            if shared.stop.load(Ordering::Relaxed) {
                break;
            }
            let idle = shared.in_flight.load(Ordering::Relaxed) == 0;
            std::thread::park_timeout(if idle {
                Duration::from_millis(50)
            } else {
                Duration::from_micros(200)
            });
            continue;
        }
        for completion in &done {
            let Some(slot) = release(shared, completion.ticket) else {
                continue;
            };
            shared.in_flight.fetch_sub(1, Ordering::Relaxed);
            let worker = &shared.metrics[slot.worker];
            if completion.outcome.is_err() {
                worker.retract(slot.request, DropReason::StoreRefused);
                continue;
            }
            if !shared.applies_commits {
                let mut table = shared.table.write();
                for binding in slot.change.bindings() {
                    let previous = table.get(binding.vrf, binding.addr).cloned();
                    let row = slot
                        .change
                        .to_lease(binding, shared.node, previous.as_ref());
                    table.apply_at(row, tenko_core::Revision::ZERO);
                }
            }
            let commit_us = micros(slot.submitted);
            shared.metrics[committer].commit.record(commit_us);
            shared
                .last_commit_us
                .store(commit_us.max(1), Ordering::Relaxed);
            if slot.len > 0
                && shared.sockets[slot.listener]
                    .send_to(&slot.reply[..slot.len], slot.dest.address())
                    .is_ok()
            {
                shared.metrics[committer].exchange[1].record(micros(slot.received));
            }
        }
    }
}
