//! The per-worker counters of the engine (OPS-21): relaxed atomics that a worker bumps
//! without allocating, summed over the workers when the metrics are read. The names and
//! labels are the families of [`crate::metrics`]; registering them with the process's
//! registry is the role's (WP7.5).

use std::sync::atomic::{AtomicU64, Ordering};

use super::{Action, Answer, DropReason};
use crate::{metrics::EXCHANGE_BUCKETS_US, v4::MessageType};

/// The message types counted, in the order of [`TYPE_LABELS`].
pub const TYPE_LABELS: [&str; 9] = [
    "discover", "request", "decline", "release", "inform", "offer", "ack", "nak", "other",
];

/// The outcomes counted, in the order of [`OUTCOME_LABELS`].
pub const OUTCOME_LABELS: [&str; 4] = ["answered", "nak", "dropped", "ignored"];

/// The drop reasons, in the order of [`DropReason`] and of the `reason` label.
pub const DROP_LABELS: [&str; 7] = [
    "malformed",
    "filtered",
    "no_scope",
    "pool_full",
    "queue",
    "store_refused",
    "rate_limited",
];

/// The steps of `tenko_dhcp_exchange_duration_seconds`.
pub const STEP_LABELS: [&str; 2] = ["offer", "ack"];

fn type_index(kind: Option<MessageType>) -> usize {
    match kind {
        Some(MessageType::Discover) => 0,
        Some(MessageType::Request) => 1,
        Some(MessageType::Decline) => 2,
        Some(MessageType::Release) => 3,
        Some(MessageType::Inform) => 4,
        Some(MessageType::Offer) => 5,
        Some(MessageType::Ack) => 6,
        Some(MessageType::Nak) => 7,
        Some(MessageType::Other(_)) | None => 8,
    }
}

/// A histogram over [`EXCHANGE_BUCKETS_US`] in microseconds.
#[derive(Debug, Default)]
pub struct Histogram {
    buckets: [AtomicU64; EXCHANGE_BUCKETS_US.len() + 1],
    sum_us: AtomicU64,
}

impl Histogram {
    /// Records one duration.
    pub fn record(&self, micros: u64) {
        let at = EXCHANGE_BUCKETS_US.partition_point(|bound| *bound < micros);
        self.buckets[at].fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(micros, Ordering::Relaxed);
    }

    /// The count per bucket (the last one above 1 s), and the sum in microseconds.
    pub fn read(&self) -> ([u64; EXCHANGE_BUCKETS_US.len() + 1], u64) {
        let mut out = [0; EXCHANGE_BUCKETS_US.len() + 1];
        for (value, bucket) in out.iter_mut().zip(&self.buckets) {
            *value = bucket.load(Ordering::Relaxed);
        }
        (out, self.sum_us.load(Ordering::Relaxed))
    }

    /// Adds another histogram's counts into `into`.
    fn add_into(&self, into: &mut ([u64; EXCHANGE_BUCKETS_US.len() + 1], u64)) {
        let (counts, sum) = self.read();
        for (total, count) in into.0.iter_mut().zip(counts) {
            *total += count;
        }
        into.1 += sum;
    }
}

/// One worker's counters.
#[derive(Debug, Default)]
pub struct WorkerMetrics {
    packets: [[AtomicU64; OUTCOME_LABELS.len()]; TYPE_LABELS.len()],
    dropped: [AtomicU64; DROP_LABELS.len()],
    naks: AtomicU64,
    declines: AtomicU64,
    store_refused: AtomicU64,
    /// DISCOVER to OFFER and REQUEST to ACK.
    pub exchange: [Histogram; 2],
    /// Hand-off to commit.
    pub commit: Histogram,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

impl WorkerMetrics {
    /// Counts an answer of the engine.
    pub fn count(&self, answer: &Answer) {
        let kind = type_index(answer.request);
        let outcome = match answer.action {
            Action::Reply {
                kind: MessageType::Nak,
                ..
            } => {
                bump(&self.naks);
                1
            }
            Action::Reply { .. } | Action::CommitThenReply { .. } | Action::Commit => 0,
            Action::Drop(reason) => {
                self.dropped(reason);
                2
            }
            Action::Ignore(_) => 3,
        };
        if answer.request == Some(MessageType::Decline) {
            bump(&self.declines);
        }
        bump(&self.packets[kind][outcome]);
    }

    /// Counts a drop the server decides (a full queue, a refusing store at the hand-off).
    pub fn dropped(&self, reason: DropReason) {
        if reason == DropReason::StoreRefused {
            bump(&self.store_refused);
        }
        bump(&self.dropped[reason as usize]);
    }

    /// Moves a counted answer to dropped: the hand-off after the engine failed.
    pub fn retract(&self, request: Option<MessageType>, reason: DropReason) {
        let kind = type_index(request);
        self.packets[kind][0].fetch_sub(1, Ordering::Relaxed);
        bump(&self.packets[kind][2]);
        self.dropped(reason);
    }

    /// The sum of `workers`.
    pub fn total<'a>(workers: impl IntoIterator<Item = &'a WorkerMetrics>) -> MetricsSnapshot {
        let mut out = MetricsSnapshot::default();
        for worker in workers {
            for (row, counters) in out.packets.iter_mut().zip(&worker.packets) {
                for (value, counter) in row.iter_mut().zip(counters) {
                    *value += counter.load(Ordering::Relaxed);
                }
            }
            for (value, counter) in out.dropped.iter_mut().zip(&worker.dropped) {
                *value += counter.load(Ordering::Relaxed);
            }
            out.naks += worker.naks.load(Ordering::Relaxed);
            out.declines += worker.declines.load(Ordering::Relaxed);
            out.store_refused += worker.store_refused.load(Ordering::Relaxed);
            for (total, histogram) in out.exchange.iter_mut().zip(&worker.exchange) {
                histogram.add_into(total);
            }
            worker.commit.add_into(&mut out.commit);
        }
        out
    }
}

/// The counters summed over the workers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// `tenko_dhcp_packets_total` by [`TYPE_LABELS`] and [`OUTCOME_LABELS`].
    pub packets: [[u64; OUTCOME_LABELS.len()]; TYPE_LABELS.len()],
    /// `tenko_dhcp_dropped_total` by [`DROP_LABELS`].
    pub dropped: [u64; DROP_LABELS.len()],
    /// `tenko_dhcp_naks_total`.
    pub naks: u64,
    /// `tenko_dhcp_declines_total`.
    pub declines: u64,
    /// `tenko_dhcp_store_refused_total`.
    pub store_refused: u64,
    /// `tenko_dhcp_exchange_duration_seconds` by [`STEP_LABELS`]: counts per bucket, sum.
    pub exchange: [([u64; EXCHANGE_BUCKETS_US.len() + 1], u64); 2],
    /// `tenko_dhcp_commit_duration_seconds`.
    pub commit: ([u64; EXCHANGE_BUCKETS_US.len() + 1], u64),
}

impl MetricsSnapshot {
    /// The packets of a type label and an outcome label.
    pub fn packets(&self, kind: &str, outcome: &str) -> u64 {
        let row = TYPE_LABELS.iter().position(|label| *label == kind);
        let column = OUTCOME_LABELS.iter().position(|label| *label == outcome);
        match (row, column) {
            (Some(row), Some(column)) => self.packets[row][column],
            _ => 0,
        }
    }

    /// The drops of a reason label.
    pub fn dropped(&self, reason: &str) -> u64 {
        DROP_LABELS
            .iter()
            .position(|label| *label == reason)
            .map_or(0, |at| self.dropped[at])
    }
}
