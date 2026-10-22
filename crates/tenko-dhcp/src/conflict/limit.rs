//! The per-client DECLINE limit (plan section 2.7): a client may decline at most `limit`
//! addresses per window (`[dhcp.decline] limit` per `window_secs`, 3 per hour). Each
//! accepted DECLINE abandons an address for the hold time, so without the limit a broken
//! client that declines every address it is offered would drain its pool in minutes; with
//! it, a DECLINE beyond the limit is dropped (`tenko_dhcp_dropped_total{reason=
//! "rate_limited"}`) and the client keeps the lease it holds.
//!
//! The table is fixed at start: the client identity's hash, the start of its window and
//! the DECLINEs counted in it, in stripes with a bounded probe; a full window gives way to
//! the client whose window started first. A client pushed out early is counted from zero
//! again, which the table's size makes rare. Nothing allocates.

use std::{
    sync::{Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use super::hash_bytes;

const PROBE: usize = 8;
const STRIPES: usize = 16;

#[derive(Debug, Clone, Copy)]
struct Slot {
    key: u64,
    start: Option<Instant>,
    count: u32,
}

/// DECLINEs per client and window.
#[derive(Debug)]
pub struct DeclineLimit {
    stripes: Box<[Mutex<Box<[Slot]>>]>,
    per_stripe: usize,
    limit: u32,
    window: Duration,
}

impl DeclineLimit {
    /// A limit of `limit` per `window` for about `clients` clients at once (`limit` zero
    /// drops every DECLINE).
    pub fn new(clients: usize, limit: u32, window: Duration) -> Self {
        let per_stripe = (clients / STRIPES).max(16);
        let empty = Slot {
            key: 0,
            start: None,
            count: 0,
        };
        Self {
            stripes: (0..STRIPES)
                .map(|_| Mutex::new(vec![empty; per_stripe].into_boxed_slice()))
                .collect(),
            per_stripe,
            limit,
            window,
        }
    }

    fn lock(&self, stripe: usize) -> MutexGuard<'_, Box<[Slot]>> {
        self.stripes[stripe]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Counts a DECLINE of the client of `identity` at `now`; false when it is beyond the
    /// limit.
    pub fn allow(&self, identity: &[u8], now: Instant) -> bool {
        let key = hash_bytes(identity) | 1;
        #[allow(clippy::cast_possible_truncation, reason = "the low bits of a hash")]
        let (stripe, start) = (
            (key as usize) % STRIPES,
            ((key >> 32) as usize) % self.per_stripe,
        );
        let window = self.window;
        let mut slots = self.lock(stripe);
        let len = slots.len();
        let expired = |slot: &Slot| {
            slot.start
                .is_none_or(|began| now.saturating_duration_since(began) >= window)
        };
        let mut at = None;
        let mut oldest = start % len;
        for step in 0..PROBE.min(len) {
            let index = (start + step) % len;
            let slot = slots[index];
            if slot.key == key {
                at = Some(index);
                break;
            }
            if expired(&slot) {
                at.get_or_insert(index);
            } else if slot.start < slots[oldest].start {
                oldest = index;
            }
        }
        let index = at.unwrap_or(oldest);
        let slot = &mut slots[index];
        if slot.key != key || expired(slot) {
            *slot = Slot {
                key,
                start: Some(now),
                count: 0,
            };
        }
        if slot.count >= self.limit {
            return false;
        }
        slot.count += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_declines_at_most_the_limit_per_window() {
        let limit = DeclineLimit::new(64, 3, Duration::from_secs(3_600));
        let now = Instant::now();
        for _ in 0..3 {
            assert!(limit.allow(b"\x01broken", now));
        }
        assert!(!limit.allow(b"\x01broken", now + Duration::from_secs(10)));
        // Another client has its own count; the window's end starts a new one.
        assert!(limit.allow(b"\x01other", now));
        assert!(limit.allow(b"\x01broken", now + Duration::from_secs(3_600)));
    }

    #[test]
    fn a_zero_limit_drops_every_decline() {
        let limit = DeclineLimit::new(16, 0, Duration::from_secs(60));
        assert!(!limit.allow(b"a", Instant::now()));
    }
}
