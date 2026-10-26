//! The DHCPv4 listeners and workers (plan section 2.5, WP7.3): the engine wrapped in
//! sockets and the commit.
//!
//! [`DhcpServer::start`] binds every listener ([`Listen`], `[dhcp] listen`) and starts
//! blocking UDP workers, as the DNS role does (ADR 0009): one `SO_REUSEPORT` socket per
//! worker on Linux, one shared socket on Windows ([`SocketLayout`]). A worker receives a
//! datagram, runs [`engine::handle`] over the current image, the lease table and the offers,
//! and then:
//!
//! - sends an OFFER, a NAK or the ACK of an INFORM at once;
//! - for an ACK, hands the lease change to the [`LeaseStore`] with a [`Ticket`] and parks
//!   the reply in a fixed slot table; the worker goes on with the next datagram and never
//!   waits for the disk;
//! - for a DECLINE or RELEASE, hands the change over and sends nothing.
//!
//! The committer thread takes the store's completions: a committed change is applied to
//! the lease table at once (the feed's copy of the same row later changes nothing) and its
//! ACK is sent; a refused one is dropped and counted (`store_refused`), so no answer
//! promises what is not durable. A store that commits on its own thread only reports; the
//! in-memory reference ([`MemLeaseStore`](crate::store::MemLeaseStore)) is driven by the
//! `drive` hook, which the committer calls before it collects completions.
//!
//! Destinations ([`Destination`]): the relay at `giaddr` port 67, the client at `ciaddr`
//! port 68, the broadcast address port 68. A reply to a client's hardware address (direct
//! mode, no broadcast flag, no address yet) goes through the listener's link-layer socket
//! ([`link`], `AF_PACKET` with `CAP_NET_RAW` on Linux, WP7.5) when it has one; without one,
//! and always on Windows, it goes out as a broadcast, which every client accepts (RFC 2131
//! section 4.1 allows it when unicast is not possible).
//!
//! WP8.4: proxy DHCP listeners ([`ServerConfig::proxy`], port 4011 by default) answer boot
//! clients with the boot information and no address ([`engine::boot::proxy`]); one worker
//! each, nothing committed.
//!
//! WP7.5: the lease table is reached through a [`TableHandle`]: a table the server owns
//! (`RwLock<T>`, [`DhcpServer::start`]) or the role's [`SharedLeases`], which the
//! production lease store applies its commits to and the feed follows
//! ([`DhcpServer::start_with`]). A worker takes the table's read guard before it looks at
//! the image, so [`DhcpServer::swap`], which replaces both under the table's write guard,
//! is seen whole: no request is answered from a new image and an old table, or the
//! reverse.
//!
//! E32: the fixed tables (the pending commits, the offer slots, the conflict probe's
//! pending table and cache) are sized from the image ([`crate::sizing`]): the addresses
//! it can lease, between a floor and the configured sizes ([`ServerConfig::pending`],
//! [`ServerConfig::offers`], [`ConflictSettings`]), which are upper bounds. A new image
//! ([`DhcpServer::set_image`], [`DhcpServer::swap`]) grows them before the workers see it,
//! on the caller's thread; they never shrink while the server runs.

pub mod link;
mod socket;

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    sync::{
        Arc, Mutex, PoisonError, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread::{JoinHandle, Thread},
    time::{Duration, Instant},
};

pub use link::LinkSender;
pub use socket::STOP_POLL;
use tenko_core::{NodeId, Timestamp};

// WP8.5: conflict detection.
use crate::conflict::{
    self, ConflictSettings, Conflicts, Report, ReportKind,
    dispatch::{Hooks, Rerun},
    pending::{Parked, Parking},
    rules,
};
use crate::v4::engine::OfferBook as _;
use crate::{
    allocator::SingleNode,
    image::ConfigImage,
    lease::{LeaseTable, PendingChange, SharedLeases},
    sizing::{self, Limits, Room},
    store::{Completion, LeaseStore, SubmitError, Ticket},
    v4::{
        MessageType,
        engine::{
            self, Action, Context, Destination, DropReason, EngineSettings, HashedAllocator,
            ListenMode, MetricsSnapshot, OfferTable, REPLY_CAPACITY, Received, Scratch,
            WorkerMetrics,
        },
    },
};

/// One listener (`[dhcp] listen`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listen {
    /// The interface's unicast address and the port (67).
    pub address: SocketAddrV4,
    /// Relay or direct.
    pub mode: ListenMode,
    /// The interface (direct mode on Linux binds to it).
    pub interface: Option<String>,
}

/// How the workers of a listener share sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketLayout {
    /// One socket per worker with `SO_REUSEPORT` (Linux).
    ReusePort,
    /// One socket shared by the workers.
    Shared,
}

impl SocketLayout {
    /// `ReusePort` on Linux, `Shared` elsewhere.
    pub const fn platform_default() -> Self {
        if cfg!(target_os = "linux") {
            Self::ReusePort
        } else {
            Self::Shared
        }
    }
}

/// The settings of the server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// The listeners.
    pub listen: Vec<Listen>,
    /// Workers per listener (`[dhcp] workers`).
    pub workers: usize,
    /// The socket layout.
    pub layout: SocketLayout,
    /// The engine's settings.
    pub engine: EngineSettings,
    /// How many commits may be in flight at most; a request beyond is dropped (`queue`).
    /// E32: the table holds as many as the image can lease ([`crate::sizing`]), up to this.
    pub pending: usize,
    /// How many offers the offer table holds about at most; sized as `pending` is.
    pub offers: usize,
    /// `SO_RCVBUF` (0 keeps the system's).
    pub recv_buffer: usize,
    /// `SO_SNDBUF` (0 keeps the system's).
    pub send_buffer: usize,
    /// The node that writes the leases.
    pub node: NodeId,
    // WP8.5: conflict detection before an offer and the DECLINE limit.
    /// Conflict detection (`[dhcp.probe]`, `[dhcp.decline]`, TGL-16); without a probe none.
    pub conflict: ConflictSettings,
    // WP8.4: proxy DHCP (DHCP-05, P3-Q16).
    /// The proxy DHCP listeners: the unicast address and port (4011 for the boot server
    /// discovery of PXE), each answered by one worker with [`engine::boot::proxy`].
    pub proxy: Vec<SocketAddrV4>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: Vec::new(),
            workers: std::thread::available_parallelism()
                .map_or(1, std::num::NonZeroUsize::get)
                .min(8),
            layout: SocketLayout::platform_default(),
            engine: EngineSettings::default(),
            pending: 4_096,
            offers: 65_536,
            recv_buffer: 4 * 1024 * 1024,
            send_buffer: 4 * 1024 * 1024,
            node: NodeId(1),
            conflict: ConflictSettings::default(),
            proxy: Vec::new(),
        }
    }
}

// WP7.5: the table behind a handle, so that the role's shared table serves the workers.
/// Where the workers read the lease table, and where the committer writes it when the
/// lease store does not.
pub trait TableHandle: Send + Sync + 'static {
    /// The table.
    type Table: LeaseTable;

    /// A read guard: the DORA path's lookups.
    fn read(&self) -> impl std::ops::Deref<Target = Self::Table> + '_;

    /// A write guard.
    fn write(&self) -> impl std::ops::DerefMut<Target = Self::Table> + '_;

    /// Whether the lease store applies its commits to this table itself before it reports
    /// them ([`StoreLeases`](crate::lease::StoreLeases) does), so the committer does not.
    fn applies_commits(&self) -> bool {
        false
    }
}

impl<T: LeaseTable + Send + Sync + 'static> TableHandle for RwLock<T> {
    type Table = T;

    fn read(&self) -> impl std::ops::Deref<Target = T> + '_ {
        RwLock::read(self).unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> impl std::ops::DerefMut<Target = T> + '_ {
        RwLock::write(self).unwrap_or_else(PoisonError::into_inner)
    }
}

impl TableHandle for SharedLeases {
    type Table = crate::lease::LeaseIndex;

    fn read(&self) -> impl std::ops::Deref<Target = Self::Table> + '_ {
        SharedLeases::read(self)
    }

    fn write(&self) -> impl std::ops::DerefMut<Target = Self::Table> + '_ {
        SharedLeases::write(self)
    }

    fn applies_commits(&self) -> bool {
        true
    }
}

/// What one listener is, for the role's status report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerInfo {
    /// The configured address and the port bound.
    pub address: SocketAddrV4,
    /// Relay or direct.
    pub mode: ListenMode,
    /// The interface of a direct listener.
    pub interface: Option<String>,
    /// Workers on it.
    pub workers: usize,
    /// Whether direct replies to a hardware address go out at the link layer.
    pub link_layer: bool,
}

/// A reply waiting for its commit.
#[derive(Clone)]
struct Slot {
    used: bool,
    generation: u32,
    change: PendingChange,
    reply: [u8; REPLY_CAPACITY],
    len: usize,
    dest: Destination,
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

impl Slot {
    fn empty() -> Self {
        let now = Instant::now();
        Self {
            used: false,
            generation: 0,
            change: engine::empty_change(),
            reply: [0; REPLY_CAPACITY],
            len: 0,
            dest: Destination::Broadcast(68),
            listener: 0,
            worker: 0,
            request: None,
            received: now,
            submitted: now,
        }
    }
}

/// A slot count as the tickets' index half holds it.
fn slot_count(capacity: usize) -> u32 {
    u32::try_from(capacity.max(1)).unwrap_or(u32::MAX)
}

impl Pending {
    fn new(capacity: usize) -> Self {
        let capacity = slot_count(capacity);
        Self {
            slots: vec![Slot::empty(); capacity as usize].into_boxed_slice(),
            free: (0..capacity).rev().collect(),
        }
    }
}

// E32: the pending commits grow with the image.
/// Grows the pending commits to `capacity` slots: the new table is made outside the lock,
/// and under it the slots in use move to the same index, so every ticket handed out stays
/// valid. A smaller `capacity` changes nothing.
fn grow_pending(pending: &Mutex<Pending>, capacity: usize) {
    let capacity = slot_count(capacity);
    let held = pending
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .slots
        .len();
    if capacity as usize <= held {
        return;
    }
    let mut slots = vec![Slot::empty(); capacity as usize].into_boxed_slice();
    let mut free: Vec<u32> = Vec::with_capacity(capacity as usize);
    let old = {
        let mut pending = pending.lock().unwrap_or_else(PoisonError::into_inner);
        let held = pending.slots.len();
        if capacity as usize <= held {
            return;
        }
        for (new, old) in slots.iter_mut().zip(pending.slots.iter_mut()) {
            std::mem::swap(new, old);
        }
        free.extend((u32::try_from(held).unwrap_or(u32::MAX)..capacity).rev());
        free.extend_from_slice(&pending.free);
        pending.free = free;
        std::mem::replace(&mut pending.slots, slots)
    };
    drop(old);
}

fn ticket_of(index: u32, generation: u32) -> Ticket {
    Ticket((u64::from(generation) << 32) | u64::from(index))
}

fn split_ticket(ticket: Ticket) -> (usize, u32) {
    // The low half is the slot, the high half its generation.
    #[allow(clippy::cast_possible_truncation, reason = "the halves of the ticket")]
    ((ticket.0 & 0xffff_ffff) as usize, (ticket.0 >> 32) as u32)
}

/// What the workers and the committer share.
struct Shared<H> {
    image: RwLock<Arc<ConfigImage>>,
    generation: AtomicU64,
    table: H,
    offers: OfferTable,
    store: Arc<dyn LeaseStore>,
    drive: Option<Box<dyn Fn() + Send + Sync>>,
    pending: Mutex<Pending>,
    in_flight: AtomicUsize,
    /// The first socket of each listener, for the committer's sends.
    sockets: Vec<Arc<UdpSocket>>,
    // WP7.5: the link-layer replies of direct listeners.
    /// Each listener's address and port, and its link-layer socket when it has one.
    links: Vec<(SocketAddrV4, Option<LinkSender>)>,
    /// The last commit's time from hand-off to completion, in microseconds (0: none yet).
    last_commit_us: AtomicU64,
    /// One per worker, and the committer's last.
    metrics: Vec<WorkerMetrics>,
    stop: AtomicBool,
    committer: Mutex<Option<Thread>>,
    settings: EngineSettings,
    node: NodeId,
    // WP8.5: the pending table, the probe cache and the DECLINE limit.
    conflicts: Arc<Conflicts>,
    // E32: the configured sizes, the caps of the tables sized from the image.
    limits: Limits,
}

impl<H> Shared<H> {
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

/// The running listeners, workers and committer.
pub struct DhcpServer<H: TableHandle> {
    shared: Arc<Shared<H>>,
    threads: Vec<JoinHandle<()>>,
    locals: Vec<SocketAddrV4>,
    listeners: Vec<ListenerInfo>,
    // WP8.4: the proxy DHCP listeners bound.
    proxies: Vec<SocketAddrV4>,
}

impl<H: TableHandle> std::fmt::Debug for DhcpServer<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhcpServer")
            .field("listen", &self.locals)
            .finish_non_exhaustive()
    }
}

impl<T: LeaseTable + Send + Sync + 'static> DhcpServer<RwLock<T>> {
    /// Binds the listeners and starts the workers and the committer over `image`, the
    /// lease table `table` and `store`. `drive`, when given, is called by the committer
    /// before it collects completions (the in-memory store commits there).
    ///
    /// # Errors
    ///
    /// A listener that cannot be bound, or a thread that cannot be started.
    pub fn start(
        config: &ServerConfig,
        image: ConfigImage,
        table: T,
        store: Arc<dyn LeaseStore>,
        drive: Option<Box<dyn Fn() + Send + Sync>>,
    ) -> io::Result<Self> {
        Self::start_with(config, image, RwLock::new(table), store, drive)
    }
}

impl<H: TableHandle> DhcpServer<H> {
    /// [`DhcpServer::start`] over a table behind `table` (WP7.5: the role's
    /// [`SharedLeases`], which the production lease store applies its commits to).
    ///
    /// # Errors
    ///
    /// A listener that cannot be bound, or a thread that cannot be started.
    // WP8.4: the proxy DHCP listeners took the start past the line limit.
    #[allow(
        clippy::too_many_lines,
        reason = "the listeners, the shared state and the threads, started in order"
    )]
    pub fn start_with(
        config: &ServerConfig,
        image: ConfigImage,
        table: H,
        store: Arc<dyn LeaseStore>,
        drive: Option<Box<dyn Fn() + Send + Sync>>,
    ) -> io::Result<Self> {
        let workers = config.workers.max(1);
        let mut bound = Vec::with_capacity(config.listen.len());
        for listen in &config.listen {
            bound.push(socket::bind(
                listen,
                workers,
                config.layout,
                (config.recv_buffer, config.send_buffer),
            )?);
        }
        let total = bound.len() * workers;
        // WP8.4: one socket and one worker per proxy DHCP listener; their counters follow the
        // workers', the committer's stay last.
        let proxies = bind_proxies(config)?;
        let links: Vec<(SocketAddrV4, Option<LinkSender>)> = config
            .listen
            .iter()
            .zip(&bound)
            .map(|(listen, bound)| {
                (
                    SocketAddrV4::new(bound.local, bound.address.port()),
                    link_sender(listen),
                )
            })
            .collect();
        let listeners = config
            .listen
            .iter()
            .zip(&links)
            .map(|(listen, (address, link))| ListenerInfo {
                address: *address,
                mode: listen.mode,
                interface: listen.interface.clone(),
                workers,
                link_layer: link.is_some(),
            })
            .collect();
        // E32: the tables as large as the image needs, the settings their caps.
        let limits = Limits {
            pending: config.pending,
            offers: config.offers,
            probe_pending: config.conflict.pending,
            probe_cache: config.conflict.cache_entries,
        };
        let room = limits.room(sizing::leasable(&image));
        let conflict = ConflictSettings {
            pending: room.probe_pending,
            cache_entries: room.probe_cache,
            ..config.conflict.clone()
        };
        let shared = Arc::new(Shared {
            image: RwLock::new(Arc::new(image)),
            generation: AtomicU64::new(1),
            table,
            offers: OfferTable::with_capacity(room.offers),
            store,
            drive,
            pending: Mutex::new(Pending::new(room.pending)),
            in_flight: AtomicUsize::new(0),
            sockets: bound.iter().map(|b| Arc::clone(&b.sockets[0])).collect(),
            links,
            last_commit_us: AtomicU64::new(0),
            metrics: (0..=total + proxies.len())
                .map(|_| WorkerMetrics::default())
                .collect(),
            stop: AtomicBool::new(false),
            committer: Mutex::new(None),
            settings: config.engine,
            node: config.node,
            conflicts: Arc::new(Conflicts::new(&conflict)),
            limits,
        });
        let mut threads = Vec::with_capacity(total + 1);
        let committer = {
            let shared = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("dhcp-commit".to_owned())
                .spawn(move || commit_loop(&shared))?
        };
        *shared
            .committer
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(committer.thread().clone());
        threads.push(committer);
        // WP8.5: the dispatcher of the conflict probe, when a probe runs.
        if let Some(probe) = shared.conflicts.probe().cloned() {
            let mut hooks = ProbeHooks::new(Arc::clone(&shared));
            threads.push(
                std::thread::Builder::new()
                    .name("dhcp-probe".to_owned())
                    .spawn(move || {
                        let conflicts = Arc::clone(&hooks.shared.conflicts);
                        conflict::dispatch::run(&conflicts, &probe, &mut hooks);
                    })?,
            );
        }
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
                        .name(format!("dhcp-udp-{me}"))
                        .spawn(move || {
                            worker_loop(&shared, &socket, listener, me, local, mode);
                        })?,
                );
            }
        }
        // WP8.4: the proxy DHCP workers.
        spawn_proxies(&shared, &proxies, total, &mut threads)?;
        Ok(Self {
            shared,
            threads,
            locals: bound.iter().map(|b| b.address).collect(),
            listeners,
            proxies: proxies.iter().map(|p| p.address).collect(),
        })
    }

    /// What each listener is.
    pub fn listeners(&self) -> &[ListenerInfo] {
        &self.listeners
    }

    // WP8.4: the proxy DHCP listeners.
    /// The proxy DHCP listeners bound (the port the system chose for port 0).
    pub fn proxies(&self) -> &[SocketAddrV4] {
        &self.proxies
    }

    // WP7.5: the snapshot reset and the completion wake-up of the role.
    /// Replaces the image and, through `reset`, the lease table under the table's write
    /// guard, so that the workers see both or neither (a snapshot install). The fixed
    /// tables grow for the new image first (E32).
    pub fn swap(&self, image: ConfigImage, reset: impl FnOnce(&mut H::Table)) {
        self.fit(&image);
        let mut table = self.shared.table.write();
        reset(&mut table);
        *self
            .shared
            .image
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Arc::new(image);
        self.shared.generation.fetch_add(1, Ordering::Release);
    }

    /// The image the workers answer from.
    pub fn image(&self) -> Arc<ConfigImage> {
        Arc::clone(
            &self
                .shared
                .image
                .read()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    /// A function that wakes the committer, for a lease store that reports its
    /// completions from another thread.
    pub fn waker(&self) -> impl Fn() + Send + Sync + 'static {
        let shared = Arc::clone(&self.shared);
        move || shared.wake_committer()
    }

    /// The addresses bound, per listener (the port the system chose for port 0).
    pub fn local_addrs(&self) -> &[SocketAddrV4] {
        &self.locals
    }

    /// Swaps the configuration image; the fixed tables grow for it first (E32).
    pub fn set_image(&self, image: ConfigImage) {
        self.fit(&image);
        *self
            .shared
            .image
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Arc::new(image);
        self.shared.generation.fetch_add(1, Ordering::Release);
    }

    // E32: the fixed tables sized from the image.
    /// Grows the fixed tables to the room `image` needs ([`crate::sizing`]); called before
    /// the workers see the image, never by a worker.
    fn fit(&self, image: &ConfigImage) {
        let room = self.shared.limits.room(sizing::leasable(image));
        grow_pending(&self.shared.pending, room.pending);
        self.shared.offers.grow(room.offers);
        self.shared
            .conflicts
            .grow(room.probe_pending, room.probe_cache);
    }

    /// The room of the fixed tables now: the pending commits, the offers, the conflict
    /// probe's pending table and cache.
    pub fn room(&self) -> Room {
        let (probe_pending, probe_cache) = self.shared.conflicts.room();
        Room {
            pending: self
                .shared
                .pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .slots
                .len(),
            offers: self.shared.offers.capacity(),
            probe_pending,
            probe_cache,
        }
    }

    /// Runs `f` on the lease table (the feed applies rows here).
    pub fn with_table<R>(&self, f: impl FnOnce(&mut H::Table) -> R) -> R {
        f(&mut self.shared.table.write())
    }

    // WP8.5: conflict detection, for the role and the tests.
    /// Conflict detection: its switches, tables and counters.
    pub fn conflicts(&self) -> &Arc<Conflicts> {
        &self.shared.conflicts
    }

    /// The counters summed over the workers.
    pub fn metrics(&self) -> MetricsSnapshot {
        WorkerMetrics::total(&self.shared.metrics)
    }

    /// The last commit's time from hand-off to completion, once there was one.
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

    /// The offers held now.
    pub fn offers_held(&self) -> usize {
        self.shared.offers.live(Timestamp::now())
    }

    /// Stops the workers and the committer and waits for them.
    pub fn stop(mut self) {
        self.halt();
    }

    fn halt(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        self.shared.wake_committer();
        // WP8.5: the dispatcher looks at the stop flag when woken.
        self.shared.conflicts.wake();
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

impl<H: TableHandle> Drop for DhcpServer<H> {
    fn drop(&mut self) {
        self.halt();
    }
}

/// The link-layer socket of a direct listener with an interface, when it can be opened.
fn link_sender(listen: &Listen) -> Option<LinkSender> {
    if listen.mode != ListenMode::Direct {
        return None;
    }
    let interface = listen.interface.as_deref()?;
    match LinkSender::open(interface) {
        Ok(sender) => Some(sender),
        Err(error) => {
            tracing::info!(
                interface,
                %error,
                "the dhcp role answers clients without an address on this interface by broadcast"
            );
            None
        }
    }
}

fn send(
    socket: &UdpSocket,
    link: &(SocketAddrV4, Option<LinkSender>),
    dest: Destination,
    bytes: &[u8],
) -> io::Result<usize> {
    let target = match dest {
        Destination::Relay(address) | Destination::Client(address) => address,
        Destination::Link { addr, mac, port } => {
            if let (local, Some(sender)) = link
                && sender
                    .send((*local.ip(), local.port()), (mac, addr, port), bytes)
                    .is_ok()
            {
                return Ok(bytes.len());
            }
            SocketAddrV4::new(Ipv4Addr::BROADCAST, port)
        }
        Destination::Broadcast(port) => SocketAddrV4::new(Ipv4Addr::BROADCAST, port),
    };
    socket.send_to(bytes, target)
}

fn micros(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn worker_loop<H: TableHandle>(
    shared: &Shared<H>,
    socket: &UdpSocket,
    listener: usize,
    me: usize,
    local: Ipv4Addr,
    mode: ListenMode,
) {
    let metrics = &shared.metrics[me];
    let mut buf = vec![0u8; 4096];
    let mut scratch = Scratch::new();
    let mut seen = 0;
    let mut image = Arc::clone(&shared.image.read().unwrap_or_else(PoisonError::into_inner));
    while !shared.stop.load(Ordering::Relaxed) {
        // An error is a timeout to look at the stop flag, or on Windows the ICMP port
        // unreachable of an earlier reply, reported on a later receive.
        let Ok((len, SocketAddr::V4(source))) = socket.recv_from(&mut buf) else {
            continue;
        };
        let received = Instant::now();
        let answer = {
            // The table first, then the image: a swap holds the table's write guard while
            // it replaces both.
            let table = shared.table.read();
            let generation = shared.generation.load(Ordering::Acquire);
            if generation != seen {
                image = Arc::clone(&shared.image.read().unwrap_or_else(PoisonError::into_inner));
                seen = generation;
            }
            let ctx = Context {
                image: &image,
                leases: &*table,
                offers: &shared.offers,
                ownership: &SingleNode,
                allocator: &HashedAllocator,
                settings: &shared.settings,
                accepting: shared.store.accepting(),
                now: Timestamp::now(),
            };
            engine::handle(
                &ctx,
                &Received {
                    bytes: &buf[..len],
                    source,
                    local,
                    mode,
                },
                &mut scratch,
            )
        };
        metrics.count(&answer);
        // WP8.5: an OFFER of an address never leased to the client waits for the probe; a
        // DECLINE beyond the client's limit is dropped.
        let request = Received {
            bytes: &buf[..len],
            source,
            local,
            mode,
        };
        if conflict_step(
            shared,
            &image,
            &request,
            &answer,
            &scratch,
            (listener, me),
            received,
        ) {
            continue;
        }
        // End of the WP8.5 step.
        match answer.action {
            Action::Reply { kind, len, dest } => {
                if send(socket, &shared.links[listener], dest, &scratch.reply[..len]).is_ok()
                    && kind == MessageType::Offer
                {
                    metrics.exchange[0].record(micros(received));
                }
            }
            Action::CommitThenReply { len, dest, .. } => {
                hand_off(
                    shared,
                    &scratch,
                    answer.request,
                    (len, dest),
                    (listener, me),
                    received,
                );
            }
            Action::Commit => {
                let dest = Destination::Broadcast(shared.settings.client_port);
                hand_off(
                    shared,
                    &scratch,
                    answer.request,
                    (0, dest),
                    (listener, me),
                    received,
                );
            }
            Action::Drop(_) | Action::Ignore(_) => {}
        }
    }
}

// WP8.4: the proxy DHCP listeners and their workers.
/// Binds one socket per proxy DHCP listener.
fn bind_proxies(config: &ServerConfig) -> io::Result<Vec<socket::Bound>> {
    config
        .proxy
        .iter()
        .map(|address| {
            let listen = Listen {
                address: *address,
                mode: ListenMode::Relay,
                interface: None,
            };
            socket::bind(
                &listen,
                1,
                SocketLayout::Shared,
                (config.recv_buffer, config.send_buffer),
            )
        })
        .collect()
}

/// Starts one worker per proxy DHCP listener; their counters follow the `first` workers'.
fn spawn_proxies<H: TableHandle>(
    shared: &Arc<Shared<H>>,
    proxies: &[socket::Bound],
    first: usize,
    threads: &mut Vec<JoinHandle<()>>,
) -> io::Result<()> {
    for (offset, proxy) in proxies.iter().enumerate() {
        let socket = Arc::clone(&proxy.sockets[0]);
        let shared = Arc::clone(shared);
        let (local, me) = (proxy.local, first + offset);
        tracing::info!(listen = %proxy.address, "the dhcp role answers boot clients as a proxy DHCP server");
        threads.push(
            std::thread::Builder::new()
                .name(format!("dhcp-proxy-{offset}"))
                .spawn(move || proxy_loop(&shared, &socket, me, local))?,
        );
    }
    Ok(())
}

/// A proxy DHCP worker: boot replies without an address, nothing committed.
fn proxy_loop<H: TableHandle>(shared: &Shared<H>, socket: &UdpSocket, me: usize, local: Ipv4Addr) {
    let metrics = &shared.metrics[me];
    let mut buf = vec![0u8; 4096];
    let mut scratch = Scratch::new();
    let none = (SocketAddrV4::new(local, 0), None);
    while !shared.stop.load(Ordering::Relaxed) {
        let Ok((len, SocketAddr::V4(source))) = socket.recv_from(&mut buf) else {
            continue;
        };
        let image = Arc::clone(&shared.image.read().unwrap_or_else(PoisonError::into_inner));
        let answer = {
            let table = shared.table.read();
            let ctx = Context {
                image: &image,
                leases: &*table,
                offers: &shared.offers,
                ownership: &SingleNode,
                allocator: &HashedAllocator,
                settings: &shared.settings,
                accepting: shared.store.accepting(),
                now: Timestamp::now(),
            };
            engine::boot::proxy(
                &ctx,
                &Received {
                    bytes: &buf[..len],
                    source,
                    local,
                    mode: ListenMode::Relay,
                },
                &mut scratch,
            )
        };
        metrics.count(&answer);
        if let Action::Reply { len, dest, .. } = answer.action {
            let _ = send(socket, &none, dest, &scratch.reply[..len]);
        }
    }
}

/// Parks the reply under a ticket and hands the change to the store.
fn hand_off<H>(
    shared: &Shared<H>,
    scratch: &Scratch,
    request: Option<MessageType>,
    (len, dest): (usize, Destination),
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
    match shared.store.submit(&scratch.change, ticket) {
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

/// Frees a ticket's slot and returns it, when the ticket is current.
fn release<H>(shared: &Shared<H>, ticket: Ticket) -> Option<Slot> {
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

fn commit_loop<H: TableHandle>(shared: &Shared<H>) {
    let committer = shared.metrics.len() - 1;
    let mut done: Vec<Completion> = Vec::with_capacity(1_024);
    loop {
        if let Some(drive) = &shared.drive {
            drive();
        }
        done.clear();
        shared.store.completions(&mut done);
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
            if !shared.table.applies_commits() {
                let mut table = shared.table.write();
                let previous = table.lease(slot.change.vrf, slot.change.addr);
                table.apply(slot.change.to_lease(shared.node, previous.as_ref()));
            }
            let commit_us = micros(slot.submitted);
            shared.metrics[committer].commit.record(commit_us);
            shared
                .last_commit_us
                .store(commit_us.max(1), Ordering::Relaxed);
            if slot.len > 0
                && send(
                    &shared.sockets[slot.listener],
                    &shared.links[slot.listener],
                    slot.dest,
                    &slot.reply[..slot.len],
                )
                .is_ok()
            {
                shared.metrics[committer].exchange[1].record(micros(slot.received));
            }
        }
    }
}

// WP8.5: conflict detection on the worker's path and the dispatcher's hooks.
/// The identity no client has (every client identity starts with 0 or 1): the offer
/// table holds a conflict's address for it until the abandoned row has committed.
const CONFLICT_HOLDER: &[u8] = b"\xffconflict";

/// The ticket of a conflict's lease change: no reply waits for it, so the committer finds
/// no slot under it and sends nothing.
const CONFLICT_TICKET: Ticket = Ticket(u64::MAX);

/// The worker's step of conflict detection after the engine answered: an OFFER that needs
/// a probe is parked (true: the worker sends nothing now), a DECLINE beyond the client's
/// limit is dropped (true), an accepted one reported. Nothing here allocates.
fn conflict_step<H: TableHandle>(
    shared: &Shared<H>,
    image: &ConfigImage,
    request: &Received<'_>,
    answer: &engine::Answer,
    scratch: &Scratch,
    (listener, worker): (usize, usize),
    received: Instant,
) -> bool {
    let conflicts = &shared.conflicts;
    match answer.action {
        Action::Reply {
            kind: MessageType::Offer,
            len,
            dest,
        } if conflicts.enabled() => {
            let now = Timestamp::now();
            let reply = &scratch.reply[..len];
            let candidate = {
                let table = shared.table.read();
                rules::candidate(conflicts, image, &*table, request, reply, now)
            };
            candidate.is_some_and(|candidate| {
                conflicts.park(&Parking {
                    request: request.bytes,
                    source: request.source,
                    local: request.local,
                    mode: request.mode,
                    listener,
                    worker,
                    reply,
                    dest,
                    candidate,
                    received,
                })
            })
        }
        Action::Commit if answer.request == Some(MessageType::Decline) => {
            let mut identity = [0u8; tenko_core::dhcp::lease::MAX_IDENTITY];
            let Some(len) = rules::identity_of(request.bytes, &mut identity) else {
                return false;
            };
            if !conflicts.decline_allowed(&identity[..len], received) {
                shared.metrics[worker].retract(answer.request, DropReason::RateLimited);
                return true;
            }
            let mac = crate::v4::Message::parse(request.bytes)
                .ok()
                .and_then(|message| message.mac().ok());
            conflicts.declined(&Report {
                kind: ReportKind::Decline,
                vrf: scratch.change.vrf,
                prefix: scratch.change.scope,
                addr: scratch.change.addr,
                mac,
                at: Timestamp::now(),
            });
            false
        }
        _ => false,
    }
}

/// What the dispatcher of the conflict probe does through the server.
struct ProbeHooks<H> {
    shared: Arc<Shared<H>>,
    scratch: Box<Scratch>,
}

impl<H> ProbeHooks<H> {
    fn new(shared: Arc<Shared<H>>) -> Self {
        Self {
            shared,
            scratch: Scratch::new(),
        }
    }
}

impl<H: TableHandle> Hooks for ProbeHooks<H> {
    fn stopped(&self) -> bool {
        self.shared.stop.load(Ordering::Relaxed)
    }

    fn send(&mut self, parked: &Parked) {
        let shared = &self.shared;
        let listener = parked.listener;
        if send(
            &shared.sockets[listener],
            &shared.links[listener],
            parked.dest,
            parked.reply(),
        )
        .is_ok()
        {
            shared.metrics[parked.worker].exchange[0].record(micros(parked.received));
        }
    }

    fn mark(&mut self, parked: &Parked, mac: Option<[u8; 6]>) {
        let shared = &self.shared;
        let candidate = parked.candidate;
        let now = Timestamp::now();
        let after = |secs: u32| {
            now.checked_add(Duration::from_secs(u64::from(secs)))
                .unwrap_or(now)
        };
        // The client's offer gives way, and a holder no client matches keeps the address
        // from every client until the abandoned row is in the table.
        shared.offers.hold(
            candidate.prefix,
            candidate.addr,
            candidate.identity(),
            now,
            now,
        );
        shared.offers.hold(
            candidate.prefix,
            candidate.addr,
            CONFLICT_HOLDER,
            after(shared.settings.offer_secs),
            now,
        );
        let (htype, chaddr): (u8, &[u8]) = match &mac {
            Some(mac) => (1, mac),
            None => (0, &[]),
        };
        let change = PendingChange::new(
            tenko_core::dhcp::LeaseEventKind::Conflict,
            candidate.vrf,
            candidate.prefix,
            candidate.addr,
            htype,
            chaddr,
            None,
            tenko_core::dhcp::BindingState::Abandoned,
            now,
            after(shared.settings.decline_hold_secs),
        );
        match shared.store.submit(&change, CONFLICT_TICKET) {
            Ok(()) => {
                if !shared.table.applies_commits() {
                    // A table of the server's own (tests, benches): the row goes in now; the
                    // production table takes it from the lease store at its commit.
                    let mut table = shared.table.write();
                    let previous = table.lease(candidate.vrf, candidate.addr);
                    table.apply(change.to_lease(shared.node, previous.as_ref()));
                }
                shared.wake_committer();
            }
            Err(error) => tracing::debug!(
                addr = %candidate.addr,
                ?error,
                "the conflict's lease change was not taken; the offer table holds the address"
            ),
        }
    }

    fn rerun(&mut self, parked: &mut Parked) -> Rerun {
        let shared = Arc::clone(&self.shared);
        let table = shared.table.read();
        let image = Arc::clone(&shared.image.read().unwrap_or_else(PoisonError::into_inner));
        let now = Timestamp::now();
        let ctx = Context {
            image: &image,
            leases: &*table,
            offers: &shared.offers,
            ownership: &SingleNode,
            allocator: &HashedAllocator,
            settings: &shared.settings,
            accepting: shared.store.accepting(),
            now,
        };
        let received = Received {
            bytes: parked.request(),
            source: parked.source,
            local: parked.local,
            mode: parked.mode,
        };
        let answer = engine::handle(&ctx, &received, &mut self.scratch);
        match answer.action {
            Action::Reply {
                kind: MessageType::Offer,
                len,
                dest,
            } => {
                let candidate = rules::candidate(
                    &shared.conflicts,
                    &image,
                    &*table,
                    &received,
                    &self.scratch.reply[..len],
                    now,
                );
                drop(table);
                parked.set_reply(&self.scratch.reply[..len], dest);
                if let Some(candidate) = candidate {
                    parked.candidate = candidate;
                }
                Rerun::Offer {
                    probe: candidate.is_some(),
                }
            }
            Action::Drop(reason) => {
                shared.metrics[parked.worker].retract(answer.request, reason);
                Rerun::Nothing
            }
            _ => Rerun::Nothing,
        }
    }
}
