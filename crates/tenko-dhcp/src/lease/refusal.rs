//! What the role does while the store refuses lease writes (P3-Q14, plan section 2.1): it
//! promises nothing it has not committed.
//!
//! - A renewal (or rebind, or INIT-REBOOT request) of a lease the client still holds is
//!   answered with an ACK for the time the lease has left: no extension, nothing written.
//! - Every other request is dropped (the client retries) and counted as
//!   `tenko_dhcp_dropped_total{reason="store_refused"}`; every refused write counts
//!   `tenko_dhcp_store_refused_total`.
//! - The health finding [`FINDING`] (`dhcp.role.store_refused`) is raised at the first
//!   refusal and cleared at the next commit.
//!
//! [`RefusalGate`] holds the state. It opens again for a trial after
//! [`RefusalGate::retry_after`]: [`RefusalGate::accepting`] turns true, the next change goes
//! to the store, and its commit clears the finding while a refusal closes the gate for
//! another interval. So no probe write is ever made, and a store that heals is used within
//! the interval. On one node the store refuses only on a disk failure or through the test
//! hook (`TENKO_TEST_REFUSE_WRITES_FILE`); in Phase 5 it is also the quorum-loss behaviour.

use std::{
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tenko_core::{
    Timestamp,
    dhcp::{LeaseEventKind, lease::MAX_IDENTITY},
};

use super::{LeaseTable, PendingChange, metrics};

/// The code of the health finding while the store refuses lease writes.
pub const FINDING: &str = "dhcp.role.store_refused";

/// The health finding while it is raised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// [`FINDING`].
    pub code: &'static str,
    /// When the store first refused.
    pub since: Timestamp,
    /// Refused writes since then.
    pub refused: u64,
    /// Renewals answered for their remaining time since then.
    pub answered: u64,
    /// Requests dropped since then.
    pub dropped: u64,
    /// The last error, in English.
    pub detail: String,
}

/// The answer to a request while the store refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhileRefused {
    /// ACK with this lease time: what the held lease has left. Nothing is written.
    Remaining {
        /// Seconds the lease has left.
        secs: u32,
    },
    /// No answer; counted.
    Drop,
}

#[derive(Debug, Default)]
struct Raised {
    since: Option<Timestamp>,
    detail: String,
}

/// The refusal state of one role.
#[derive(Debug)]
pub struct RefusalGate {
    origin: Instant,
    retry_after: Duration,
    refusing: AtomicBool,
    /// Milliseconds since `origin` of the last refusal.
    last_refusal_ms: AtomicU64,
    refused: AtomicU64,
    answered: AtomicU64,
    dropped: AtomicU64,
    raised: Mutex<Raised>,
}

impl Default for RefusalGate {
    fn default() -> Self {
        Self::new(Duration::from_secs(1))
    }
}

impl RefusalGate {
    /// A gate that tries the store again `retry_after` after a refusal.
    pub fn new(retry_after: Duration) -> Self {
        Self {
            origin: Instant::now(),
            retry_after,
            refusing: AtomicBool::new(false),
            last_refusal_ms: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            answered: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            raised: Mutex::new(Raised::default()),
        }
    }

    /// The interval after a refusal until the next trial.
    pub fn retry_after(&self) -> Duration {
        self.retry_after
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Whether lease writes go to the store now: always while it commits, and once per
    /// interval for a trial while it refuses. Neither allocates nor blocks.
    pub fn accepting(&self) -> bool {
        if !self.refusing.load(Ordering::Acquire) {
            return true;
        }
        let since = self.last_refusal_ms.load(Ordering::Acquire);
        let retry = u64::try_from(self.retry_after.as_millis()).unwrap_or(u64::MAX);
        self.elapsed_ms().saturating_sub(since) >= retry
    }

    /// Whether the finding is raised.
    pub fn refusing(&self) -> bool {
        self.refusing.load(Ordering::Acquire)
    }

    /// Records a refused write: counts it, raises the finding (first time) and closes the
    /// gate for an interval.
    pub fn refused(&self, detail: &str) {
        metrics::STORE_REFUSED.inc();
        self.refused.fetch_add(1, Ordering::Relaxed);
        self.last_refusal_ms
            .store(self.elapsed_ms(), Ordering::Release);
        let was = self.refusing.swap(true, Ordering::AcqRel);
        let mut raised = self.raised.lock().unwrap_or_else(PoisonError::into_inner);
        if !was || raised.since.is_none() {
            raised.since = Some(Timestamp::now());
            tracing::warn!(
                code = FINDING,
                "the store refuses lease writes ({detail}); renewals are answered for the time they have left, new requests are dropped"
            );
        }
        detail.clone_into(&mut raised.detail);
    }

    /// Records a commit: clears the finding when it was raised.
    pub fn committed(&self) {
        if self.refusing.swap(false, Ordering::AcqRel) {
            let mut raised = self.raised.lock().unwrap_or_else(PoisonError::into_inner);
            raised.since = None;
            raised.detail.clear();
            self.refused.store(0, Ordering::Relaxed);
            self.answered.store(0, Ordering::Relaxed);
            self.dropped.store(0, Ordering::Relaxed);
            tracing::info!(code = FINDING, "the store accepts lease writes again");
        }
    }

    /// The finding, while it is raised.
    pub fn finding(&self) -> Option<Finding> {
        if !self.refusing() {
            return None;
        }
        let raised = self.raised.lock().unwrap_or_else(PoisonError::into_inner);
        Some(Finding {
            code: FINDING,
            since: raised.since?,
            refused: self.refused.load(Ordering::Relaxed),
            answered: self.answered.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            detail: raised.detail.clone(),
        })
    }

    /// What to answer to `change` that the store did not take (the hand-off refused it, or
    /// its commit was refused): the remaining time of the lease the client holds at the
    /// address for a renewal, a rebind or a request of a held address; else a counted drop.
    /// Does not allocate.
    pub fn decide(
        &self,
        table: &dyn LeaseTable,
        change: &PendingChange,
        now: Timestamp,
    ) -> WhileRefused {
        let verdict = remaining(table, change, now);
        match verdict {
            WhileRefused::Remaining { .. } => {
                self.answered.fetch_add(1, Ordering::Relaxed);
            }
            WhileRefused::Drop => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                metrics::DropReason::StoreRefused.count();
            }
        }
        verdict
    }
}

/// The rule of [`RefusalGate::decide`], without the counting.
pub fn remaining(table: &dyn LeaseTable, change: &PendingChange, now: Timestamp) -> WhileRefused {
    if !matches!(
        change.kind,
        LeaseEventKind::Renewed | LeaseEventKind::Rebound | LeaseEventKind::Granted
    ) {
        return WhileRefused::Drop;
    }
    let Some(held) = table.get(change.vrf, change.addr) else {
        return WhileRefused::Drop;
    };
    let mut identity = [0u8; MAX_IDENTITY];
    let len = change.identity(&mut identity);
    let mut held_identity = [0u8; MAX_IDENTITY];
    let held_len = tenko_core::dhcp::write_identity(
        held.client.htype,
        &held.client.chaddr.0,
        held.client.client_id.as_ref().map(|id| id.0.as_slice()),
        &mut held_identity,
    );
    if held.scope != change.scope
        || held_identity[..held_len] != identity[..len]
        || !held.is_bound(now)
    {
        return WhileRefused::Drop;
    }
    let left = held.ends.saturating_since(now).as_secs();
    match u32::try_from(left) {
        Ok(0) => WhileRefused::Drop,
        Ok(secs) => WhileRefused::Remaining { secs },
        Err(_) => WhileRefused::Remaining { secs: u32::MAX },
    }
}
