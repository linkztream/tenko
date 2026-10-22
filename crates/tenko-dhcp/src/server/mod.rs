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
//! WP7.5: the lease table is reached through a [`TableHandle`]: a table the server owns
//! (`RwLock<T>`, [`DhcpServer::start`]) or the role's [`SharedLeases`], which the
//! production lease store applies its commits to and the feed follows
//! ([`DhcpServer::start_with`]). A worker takes the table's read guard before it looks at
//! the image, so [`DhcpServer::swap`], which replaces both under the table's write guard,
//! is seen whole: no request is answered from a new image and an old table, or the
//! reverse.

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

use crate::{
    allocator::SingleNode,
    image::ConfigImage,
    lease::{LeaseTable, PendingChange, SharedLeases},
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
    /// How many commits may be in flight; a request beyond is dropped (`queue`).
    pub pending: usize,
    /// How many offers the offer table holds about.
    pub offers: usize,
    /// `SO_RCVBUF` (0 keeps the system's).
    pub recv_buffer: usize,
    /// `SO_SNDBUF` (0 keeps the system's).
    pub send_buffer: usize,
    /// The node that writes the leases.
    pub node: NodeId,
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

impl Pending {
    fn new(capacity: usize) -> Self {
        let now = Instant::now();
        let slot = Slot {
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
        let shared = Arc::new(Shared {
            image: RwLock::new(Arc::new(image)),
            generation: AtomicU64::new(1),
            table,
            offers: OfferTable::with_capacity(config.offers),
            store,
            drive,
            pending: Mutex::new(Pending::new(config.pending)),
            in_flight: AtomicUsize::new(0),
            sockets: bound.iter().map(|b| Arc::clone(&b.sockets[0])).collect(),
            links,
            last_commit_us: AtomicU64::new(0),
            metrics: (0..=total).map(|_| WorkerMetrics::default()).collect(),
            stop: AtomicBool::new(false),
            committer: Mutex::new(None),
            settings: config.engine,
            node: config.node,
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
        Ok(Self {
            shared,
            threads,
            locals: bound.iter().map(|b| b.address).collect(),
            listeners,
        })
    }

    /// What each listener is.
    pub fn listeners(&self) -> &[ListenerInfo] {
        &self.listeners
    }

    // WP7.5: the snapshot reset and the completion wake-up of the role.
    /// Replaces the image and, through `reset`, the lease table under the table's write
    /// guard, so that the workers see both or neither (a snapshot install).
    pub fn swap(&self, image: ConfigImage, reset: impl FnOnce(&mut H::Table)) {
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

    /// Swaps the configuration image.
    pub fn set_image(&self, image: ConfigImage) {
        *self
            .shared
            .image
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Arc::new(image);
        self.shared.generation.fetch_add(1, Ordering::Release);
    }

    /// Runs `f` on the lease table (the feed applies rows here).
    pub fn with_table<R>(&self, f: impl FnOnce(&mut H::Table) -> R) -> R {
        f(&mut self.shared.table.write())
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
                let previous = table.get(slot.change.vrf, slot.change.addr).cloned();
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
