//! The ring of fixed-size slots between the query path and the writer.

use std::net::{IpAddr, Ipv4Addr};

use tenko_core::dns::{BlockListId, QueryTransport, ViewId};

use crate::log::QueryLogEntry;

/// One entry, copied out of the query path without allocating.
#[derive(Clone, Copy)]
pub(crate) struct Slot {
    pub(crate) at_micros: u64,
    pub(crate) client: IpAddr,
    pub(crate) transport: QueryTransport,
    pub(crate) qname: [u8; 255],
    pub(crate) qname_len: u8,
    pub(crate) qtype: u16,
    pub(crate) rcode: u16,
    pub(crate) view: Option<ViewId>,
    pub(crate) blocked: Option<BlockListId>,
    pub(crate) cached: bool,
    pub(crate) duration_micros: u32,
}

impl Slot {
    pub(crate) const EMPTY: Slot = Slot {
        at_micros: 0,
        client: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        transport: QueryTransport::Udp,
        qname: [0; 255],
        qname_len: 0,
        qtype: 0,
        rcode: 0,
        view: None,
        blocked: None,
        cached: false,
        duration_micros: 0,
    };

    fn fill(&mut self, entry: &QueryLogEntry<'_>) {
        let len = entry.qname.len().min(self.qname.len());
        self.qname[..len].copy_from_slice(&entry.qname[..len]);
        self.qname_len = u8::try_from(len).unwrap_or(u8::MAX);
        self.at_micros = entry.at_micros;
        self.client = entry.client;
        self.transport = entry.transport;
        self.qtype = entry.qtype;
        self.rcode = entry.rcode;
        self.view = entry.view;
        self.blocked = entry.blocked;
        self.cached = entry.cached;
        self.duration_micros = entry.duration_micros;
    }

    /// The query name in wire form.
    pub(crate) fn qname(&self) -> &[u8] {
        &self.qname[..usize::from(self.qname_len)]
    }
}

/// Slots filled in order; the writer swaps a whole ring out and reads it in order.
pub(crate) struct Ring {
    slots: Box<[Slot]>,
    len: usize,
}

impl Ring {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            slots: vec![Slot::EMPTY; capacity.max(1)].into_boxed_slice(),
            len: 0,
        }
    }

    /// Copies an entry in; `false` when the ring is full.
    pub(crate) fn push(&mut self, entry: &QueryLogEntry<'_>) -> bool {
        let Some(slot) = self.slots.get_mut(self.len) else {
            return false;
        };
        slot.fill(entry);
        self.len += 1;
        true
    }

    /// The filled slots, oldest first.
    pub(crate) fn filled(&self) -> &[Slot] {
        &self.slots[..self.len]
    }

    /// Empties the ring (the slots keep their memory).
    pub(crate) fn clear(&mut self) {
        self.len = 0;
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn capacity(&self) -> usize {
        self.slots.len()
    }
}
