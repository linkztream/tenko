//! The pending table (plan section 2.7): DISCOVERs whose OFFER waits for a probe.
//!
//! A fixed set of slots made when the server starts, each with room for the request, the
//! OFFER built for it, where it goes, the candidate address and the deadline; a free list
//! and a queue of slots ready for the dispatcher, both with their full capacity reserved,
//! so that [`PendingTable::park`] on the worker copies into a slot and never allocates. A
//! request longer than a slot (more than [`REQUEST_CAPACITY`] octets) or a full table is
//! not parked: its OFFER goes out without a probe.

use std::{
    collections::VecDeque,
    net::{Ipv4Addr, SocketAddrV4},
    sync::{Mutex, MutexGuard, PoisonError},
    time::Instant,
};

use super::Candidate;
use crate::v4::engine::{Destination, ListenMode, REPLY_CAPACITY};

/// The longest request a slot keeps (an Ethernet MTU's payload).
pub const REQUEST_CAPACITY: usize = REPLY_CAPACITY;

/// What a worker parks.
#[derive(Debug, Clone, Copy)]
pub struct Parking<'a> {
    /// The request as received.
    pub request: &'a [u8],
    /// Where it came from.
    pub source: SocketAddrV4,
    /// The listener's address.
    pub local: Ipv4Addr,
    /// The listener's mode.
    pub mode: ListenMode,
    /// The listener.
    pub listener: usize,
    /// The worker (for its counters).
    pub worker: usize,
    /// The OFFER.
    pub reply: &'a [u8],
    /// Where the OFFER goes.
    pub dest: Destination,
    /// The address to probe.
    pub candidate: Candidate,
    /// When the request arrived.
    pub received: Instant,
}

/// One parked request, and the dispatcher's copy of it.
#[derive(Debug, Clone)]
pub struct Parked {
    used: bool,
    generation: u32,
    request: [u8; REQUEST_CAPACITY],
    request_len: usize,
    reply: [u8; REPLY_CAPACITY],
    reply_len: usize,
    /// Where the request came from.
    pub source: SocketAddrV4,
    /// The listener's address.
    pub local: Ipv4Addr,
    /// The listener's mode.
    pub mode: ListenMode,
    /// The listener.
    pub listener: usize,
    /// The worker.
    pub worker: usize,
    /// Where the OFFER goes.
    pub dest: Destination,
    /// The address to probe.
    pub candidate: Candidate,
    /// When the request arrived.
    pub received: Instant,
    /// When the OFFER goes out at the latest (the arrival plus the cap).
    pub deadline: Instant,
    /// Probes of further addresses after answers.
    pub attempts: u8,
}

impl Parked {
    /// An empty slot, on the heap.
    pub fn boxed() -> Box<Self> {
        Box::new(Self::empty())
    }

    fn empty() -> Self {
        let now = Instant::now();
        Self {
            used: false,
            generation: 0,
            request: [0; REQUEST_CAPACITY],
            request_len: 0,
            reply: [0; REPLY_CAPACITY],
            reply_len: 0,
            source: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            local: Ipv4Addr::UNSPECIFIED,
            mode: ListenMode::Relay,
            listener: 0,
            worker: 0,
            dest: Destination::Broadcast(68),
            candidate: Candidate::placeholder(),
            received: now,
            deadline: now,
            attempts: 0,
        }
    }

    /// The request.
    pub fn request(&self) -> &[u8] {
        &self.request[..self.request_len]
    }

    /// The OFFER.
    pub fn reply(&self) -> &[u8] {
        &self.reply[..self.reply_len]
    }

    /// Replaces the OFFER (the engine's answer after a conflict).
    pub fn set_reply(&mut self, reply: &[u8], dest: Destination) {
        let len = reply.len().min(REPLY_CAPACITY);
        self.reply[..len].copy_from_slice(&reply[..len]);
        self.reply_len = len;
        self.dest = dest;
    }

    fn fill(&mut self, parking: &Parking<'_>, deadline: Instant, attempts: u8) {
        self.request[..parking.request.len()].copy_from_slice(parking.request);
        self.request_len = parking.request.len();
        self.set_reply(parking.reply, parking.dest);
        self.source = parking.source;
        self.local = parking.local;
        self.mode = parking.mode;
        self.listener = parking.listener;
        self.worker = parking.worker;
        self.candidate = parking.candidate;
        self.received = parking.received;
        self.deadline = deadline;
        self.attempts = attempts;
    }

    /// This slot as a [`Parking`], to park it again.
    pub fn parking(&self) -> Parking<'_> {
        Parking {
            request: self.request(),
            source: self.source,
            local: self.local,
            mode: self.mode,
            listener: self.listener,
            worker: self.worker,
            reply: self.reply(),
            dest: self.dest,
            candidate: self.candidate,
            received: self.received,
        }
    }
}

/// A slot ready for its probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ready {
    /// The slot.
    pub index: u32,
    /// Its generation (a slot taken and parked again is another one).
    pub generation: u32,
    /// The address to probe.
    pub addr: Ipv4Addr,
    /// The OFFER's deadline.
    pub deadline: Instant,
}

struct Inner {
    slots: Box<[Parked]>,
    free: Vec<u32>,
    ready: VecDeque<u32>,
}

/// The parked requests.
pub struct PendingTable {
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for PendingTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingTable")
            .field("waiting", &self.waiting())
            .finish_non_exhaustive()
    }
}

impl PendingTable {
    /// A table of `capacity` slots (at least one).
    pub fn new(capacity: usize) -> Self {
        let capacity = u32::try_from(capacity.max(1)).unwrap_or(u32::MAX);
        Self {
            inner: Mutex::new(Inner {
                slots: vec![Parked::empty(); capacity as usize].into_boxed_slice(),
                free: (0..capacity).rev().collect(),
                ready: VecDeque::with_capacity(capacity as usize),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Parks a request until `deadline`; false when no slot is free or the request does
    /// not fit one.
    pub fn park(&self, parking: &Parking<'_>, deadline: Instant, attempts: u8) -> bool {
        if parking.request.len() > REQUEST_CAPACITY {
            return false;
        }
        let mut inner = self.lock();
        let Some(index) = inner.free.pop() else {
            return false;
        };
        let slot = &mut inner.slots[index as usize];
        slot.used = true;
        slot.generation = slot.generation.wrapping_add(1);
        slot.fill(parking, deadline, attempts);
        // The queue holds at most every slot, which its reserved capacity covers.
        inner.ready.push_back(index);
        true
    }

    /// The next slot ready for its probe.
    pub fn next_ready(&self) -> Option<Ready> {
        let mut inner = self.lock();
        while let Some(index) = inner.ready.pop_front() {
            let slot = &inner.slots[index as usize];
            if slot.used {
                return Some(Ready {
                    index,
                    generation: slot.generation,
                    addr: slot.candidate.addr,
                    deadline: slot.deadline,
                });
            }
        }
        None
    }

    /// Takes the slot of `ready` into `out` and frees it; false when the slot is no longer
    /// that one.
    pub fn take(&self, index: u32, generation: u32, out: &mut Parked) -> bool {
        let mut inner = self.lock();
        let Some(slot) = inner.slots.get_mut(index as usize) else {
            return false;
        };
        if !slot.used || slot.generation != generation {
            return false;
        }
        slot.used = false;
        out.clone_from(slot);
        inner.free.push(index);
        true
    }

    /// Parks the dispatcher's copy again for a probe of its new candidate.
    pub fn repark(&self, parked: &Parked) -> bool {
        self.park(
            &parked.parking(),
            parked.deadline,
            parked.attempts.saturating_add(1),
        )
    }

    // E32: the table grows with the image.
    /// The slots of the table.
    pub fn capacity(&self) -> usize {
        self.lock().slots.len()
    }

    /// Grows the table to `capacity` slots; a smaller one changes nothing. The new slots
    /// and queue are made outside the lock and the parked requests keep their index, so
    /// the dispatcher's `Ready` entries stay valid. Allocates: never on the DORA path.
    pub fn grow(&self, capacity: usize) {
        let capacity = u32::try_from(capacity.max(1)).unwrap_or(u32::MAX);
        if capacity as usize <= self.capacity() {
            return;
        }
        let mut slots = vec![Parked::empty(); capacity as usize].into_boxed_slice();
        let mut free: Vec<u32> = Vec::with_capacity(capacity as usize);
        let mut ready: VecDeque<u32> = VecDeque::with_capacity(capacity as usize);
        let old = {
            let mut inner = self.lock();
            let inner = &mut *inner;
            let held = inner.slots.len();
            if capacity as usize <= held {
                return;
            }
            for (new, old) in slots.iter_mut().zip(inner.slots.iter_mut()) {
                std::mem::swap(new, old);
            }
            free.extend((u32::try_from(held).unwrap_or(u32::MAX)..capacity).rev());
            free.extend_from_slice(&inner.free);
            ready.extend(inner.ready.drain(..));
            inner.free = free;
            inner.ready = ready;
            std::mem::replace(&mut inner.slots, slots)
        };
        drop(old);
    }

    /// The requests waiting now.
    pub fn waiting(&self) -> usize {
        let inner = self.lock();
        inner.slots.len() - inner.free.len()
    }

    /// Drops every parked request (the server stops; their OFFERs never leave).
    pub fn clear(&self) -> usize {
        let mut inner = self.lock();
        let inner = &mut *inner;
        let mut dropped = 0;
        for (index, slot) in inner.slots.iter_mut().enumerate() {
            if slot.used {
                slot.used = false;
                inner.free.push(u32::try_from(index).unwrap_or(u32::MAX));
                dropped += 1;
            }
        }
        inner.ready.clear();
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parking(request: &[u8]) -> Parking<'_> {
        Parking {
            request,
            source: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 67),
            local: Ipv4Addr::new(192, 0, 2, 10),
            mode: ListenMode::Relay,
            listener: 0,
            worker: 0,
            reply: request,
            dest: Destination::Broadcast(68),
            candidate: Candidate::placeholder(),
            received: Instant::now(),
        }
    }

    // E32: the table grows with the image.
    #[test]
    fn a_grown_table_keeps_its_parked_requests() {
        let table = PendingTable::new(2);
        let deadline = Instant::now();
        assert!(table.park(&parking(b"one"), deadline, 0));
        assert!(table.park(&parking(b"two"), deadline, 0));
        assert!(!table.park(&parking(b"three"), deadline, 0), "full");
        table.grow(4);
        assert_eq!(table.capacity(), 4);
        assert_eq!(table.waiting(), 2);
        assert!(table.park(&parking(b"three"), deadline, 0));
        assert!(table.park(&parking(b"four"), deadline, 0));
        assert!(!table.park(&parking(b"five"), deadline, 0), "full again");
        // The requests parked before the growth come out first, under their tickets.
        let mut out = Parked::boxed();
        for expected in [&b"one"[..], b"two", b"three", b"four"] {
            let ready = table.next_ready().expect("ready");
            assert!(table.take(ready.index, ready.generation, &mut out));
            assert_eq!(out.request(), expected);
        }
        assert_eq!(table.waiting(), 0);
        table.grow(1);
        assert_eq!(table.capacity(), 4, "it never shrinks");
    }
}
