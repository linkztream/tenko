//! The DDNS queue (plan section 2.9, ADR 0020 point 5): names are written after the lease
//! commit, never inside it.
//!
//! When a committed lease gains, keeps or loses a name, the role enqueues a
//! [`DdnsRequest`] and answers the client; a DDNS worker (WP8.3) applies it as a change set
//! through the zone service with the RRset origin `dhcp`, retries with a backoff while the
//! store refuses (`[dhcp.ddns] retries`, `backoff_ms`), and records the outcome on the
//! lease row. On release and expiry the records go if their DHCID still matches. A full
//! queue drops the request and counts it; the next renewal enqueues it again.
//! [`MemDdnsQueue`] is the reference queue.

use std::{
    collections::VecDeque,
    net::Ipv4Addr,
    sync::{Mutex, PoisonError},
};

use tenko_core::{
    PrefixId, Timestamp, VrfId,
    dhcp::{ClientKey, DdnsPolicy},
};

/// Whether names are written or removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DdnsAction {
    /// Write the forward record, the PTR and the DHCID for the lease (on commit).
    Add,
    /// Remove them if the DHCID still matches (on release and expiry).
    Remove,
}

/// One DDNS job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdnsRequest {
    /// Write or remove.
    pub action: DdnsAction,
    /// The VRF.
    pub vrf: VrfId,
    /// The scope.
    pub scope: PrefixId,
    /// The address.
    pub addr: Ipv4Addr,
    /// The client (the DHCID is computed from it, RFC 4701).
    pub client: ClientKey,
    /// The name of option 81, as the client sent it.
    pub fqdn: Option<String>,
    /// The name of option 12.
    pub hostname: Option<String>,
    /// The flags of option 81 the client sent (S, O, E, N).
    pub fqdn_flags: Option<u8>,
    /// The scope's (or the policy's) DDNS settings.
    pub policy: DdnsPolicy,
    /// The lease time granted, for the TTL default.
    pub lease_secs: u32,
    /// When the lease ends.
    pub ends: Timestamp,
}

/// The queue is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the DDNS queue is full")]
pub struct QueueFull;

/// Where the role puts DDNS work.
pub trait DdnsQueue: Send + Sync {
    /// Adds a request.
    ///
    /// # Errors
    ///
    /// [`QueueFull`] when the queue holds its limit; the request is dropped and counted.
    fn enqueue(&self, request: DdnsRequest) -> Result<(), QueueFull>;

    /// The number of waiting requests (`tenko_dhcp_ddns_queue`).
    fn len(&self) -> usize;

    /// Whether no request waits.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The reference queue: bounded, first in first out.
#[derive(Debug)]
pub struct MemDdnsQueue {
    limit: usize,
    queue: Mutex<VecDeque<DdnsRequest>>,
}

impl MemDdnsQueue {
    /// A queue of at most `limit` requests.
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            queue: Mutex::new(VecDeque::new()),
        }
    }

    /// Takes every waiting request.
    pub fn drain(&self) -> Vec<DdnsRequest> {
        self.queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
            .collect()
    }
}

impl DdnsQueue for MemDdnsQueue {
    fn enqueue(&self, request: DdnsRequest) -> Result<(), QueueFull> {
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        if queue.len() >= self.limit {
            return Err(QueueFull);
        }
        queue.push_back(request);
        Ok(())
    }

    fn len(&self) -> usize {
        self.queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}
