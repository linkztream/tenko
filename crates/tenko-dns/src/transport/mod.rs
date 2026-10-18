//! The transports of the engine (ADR 0009, plan section 2.2): blocking UDP workers and
//! TCP on tokio, both calling the same [`Responder`](crate::respond::Responder).
//!
//! - [`udp`]: one blocking thread per worker. On Linux each worker owns its own socket bound
//!   with `SO_REUSEPORT` to the listen address, so the kernel spreads the clients over the
//!   workers by flow hash; on Windows (and wherever `SO_REUSEPORT` does not balance) the
//!   workers of an address share one socket. Each worker has its own receive buffer, its
//!   own [`Scratch`](crate::respond::Scratch) and its own counters. `recvmmsg` and UDP GSO
//!   are not used.
//! - [`tcp`]: RFC 7766 on the tokio runtime: length-prefixed messages, pipelined queries
//!   answered in order, an idle timeout, a cap on open connections per node and per client.
//!
//! Every listen address gets both transports, IPv4 and IPv6 alike (DNS-04); an IPv6
//! listener is IPv6-only so that `0.0.0.0` and `[::]` can be listened on side by side.

pub mod tcp;
pub mod udp;

use std::{
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
};

/// How the UDP workers of one listen address use sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketMode {
    /// Every worker has its own socket bound with `SO_REUSEPORT` (Linux).
    ReusePort,
    /// The workers share one socket (Windows, or `SO_REUSEPORT` switched off).
    Shared,
}

impl SocketMode {
    /// The mode's name for the health view.
    pub const fn as_str(self) -> &'static str {
        match self {
            SocketMode::ReusePort => "reuseport",
            SocketMode::Shared => "shared",
        }
    }

    /// The mode of this platform: `SO_REUSEPORT` on Linux, shared elsewhere.
    pub const fn platform_default() -> Self {
        if cfg!(target_os = "linux") {
            SocketMode::ReusePort
        } else {
            SocketMode::Shared
        }
    }
}

/// The counters of one UDP worker, on their own cache lines.
#[derive(Debug, Default)]
#[repr(align(128))]
pub struct WorkerCounters {
    /// Datagrams received.
    pub received: AtomicU64,
    /// Answers sent.
    pub sent: AtomicU64,
    /// Queries dropped (not a query, rate limited, no answer).
    pub dropped: AtomicU64,
    /// Queries handed to the forwarder.
    pub forwarded: AtomicU64,
    /// Receive errors (on Windows also the ICMP port unreachable of an earlier answer).
    pub recv_errors: AtomicU64,
    /// Send errors.
    pub send_errors: AtomicU64,
}

impl WorkerCounters {
    pub(crate) fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn read(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

/// One UDP worker as the health view shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpWorker {
    /// The worker's number, from 0.
    pub index: usize,
    /// The address its socket is bound to.
    pub listen: SocketAddr,
    /// Which socket of the address it reads: its own (reuseport) or the shared one (0).
    pub socket: usize,
    /// Datagrams received.
    pub received: u64,
    /// Answers sent.
    pub sent: u64,
    /// Queries dropped.
    pub dropped: u64,
    /// Queries forwarded.
    pub forwarded: u64,
    /// Receive errors.
    pub recv_errors: u64,
    /// Send errors.
    pub send_errors: u64,
}

/// The worker count and layout of a running server (ADR 0009: an operator sees uneven
/// `SO_REUSEPORT` spreading here); WP4.3 shows it in the node's health view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerLayout {
    /// How the UDP workers use sockets.
    pub mode: SocketMode,
    /// Workers per listen address.
    pub workers_per_address: usize,
    /// Every UDP worker.
    pub udp: Vec<UdpWorker>,
    /// The TCP listeners.
    pub tcp: Vec<SocketAddr>,
    /// Open TCP connections.
    pub tcp_open: usize,
    /// TCP connections refused by the per-node or per-client cap.
    pub tcp_refused: u64,
    /// The DoT and DoH listeners and their connections, when they run.
    pub tls: Option<Box<crate::tls::TlsLayout>>,
}

/// The fixed facts of one UDP worker, kept by the server for the layout.
#[derive(Debug)]
pub(crate) struct WorkerSlot {
    pub(crate) listen: SocketAddr,
    pub(crate) socket: usize,
    pub(crate) counters: std::sync::Arc<WorkerCounters>,
}

impl WorkerSlot {
    pub(crate) fn view(&self, index: usize) -> UdpWorker {
        let counters = &self.counters;
        UdpWorker {
            index,
            listen: self.listen,
            socket: self.socket,
            received: WorkerCounters::read(&counters.received),
            sent: WorkerCounters::read(&counters.sent),
            dropped: WorkerCounters::read(&counters.dropped),
            forwarded: WorkerCounters::read(&counters.forwarded),
            recv_errors: WorkerCounters::read(&counters.recv_errors),
            send_errors: WorkerCounters::read(&counters.send_errors),
        }
    }
}
