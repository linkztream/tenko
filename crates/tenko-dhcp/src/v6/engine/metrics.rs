//! The per-worker counters of the DHCPv6 engine (OPS-21): relaxed atomics, summed when the
//! metrics are read, under the families of [`crate::metrics`] with `family="v6"`. The drop
//! reasons are DHCPv4's ([`crate::v4::engine::metrics::DROP_LABELS`]); the steps of
//! `tenko_dhcp_exchange_duration_seconds` are `offer` (SOLICIT to ADVERTISE) and `ack`
//! (REQUEST, RENEW or REBIND to REPLY, and a rapid-commit SOLICIT to its REPLY).

use std::sync::atomic::{AtomicU64, Ordering};

use super::{Action6, Answer6};
use crate::{
    v4::engine::{
        DropReason,
        metrics::{DROP_LABELS, Histogram, OUTCOME_LABELS},
    },
    v6::MessageType,
};

/// The message types counted, in the order of the `type` label values.
pub const TYPE_LABELS: [&str; 9] = [
    "solicit",
    "request",
    "confirm",
    "renew",
    "rebind",
    "release",
    "decline",
    "information-request",
    "other",
];

fn type_index(kind: Option<MessageType>) -> usize {
    match kind {
        Some(MessageType::Solicit) => 0,
        Some(MessageType::Request) => 1,
        Some(MessageType::Confirm) => 2,
        Some(MessageType::Renew) => 3,
        Some(MessageType::Rebind) => 4,
        Some(MessageType::Release) => 5,
        Some(MessageType::Decline) => 6,
        Some(MessageType::InformationRequest) => 7,
        _ => 8,
    }
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// One worker's counters.
#[derive(Debug, Default)]
pub struct WorkerMetrics6 {
    packets: [[AtomicU64; OUTCOME_LABELS.len()]; TYPE_LABELS.len()],
    dropped: [AtomicU64; DROP_LABELS.len()],
    declines: AtomicU64,
    store_refused: AtomicU64,
    /// SOLICIT to ADVERTISE, and to REPLY.
    pub exchange: [Histogram; 2],
    /// Hand-off to commit.
    pub commit: Histogram,
}

impl WorkerMetrics6 {
    /// Counts an answer of the engine.
    pub fn count(&self, answer: &Answer6) {
        let kind = type_index(answer.request);
        let outcome = match answer.action {
            Action6::Reply { .. } | Action6::CommitThenReply { .. } => 0,
            Action6::Drop(reason) => {
                self.dropped(reason);
                2
            }
            Action6::Ignore(_) => 3,
        };
        if answer.request == Some(MessageType::Decline) {
            bump(&self.declines);
        }
        bump(&self.packets[kind][outcome]);
    }

    /// Counts a drop the server decides.
    pub fn dropped(&self, reason: DropReason) {
        if reason == DropReason::StoreRefused {
            bump(&self.store_refused);
        }
        bump(&self.dropped[reason as usize]);
    }

    /// Moves a counted answer to dropped.
    pub fn retract(&self, request: Option<MessageType>, reason: DropReason) {
        let kind = type_index(request);
        self.packets[kind][0].fetch_sub(1, Ordering::Relaxed);
        bump(&self.packets[kind][2]);
        self.dropped(reason);
    }

    /// The sum of `workers`.
    pub fn total<'a>(workers: impl IntoIterator<Item = &'a WorkerMetrics6>) -> Metrics6Snapshot {
        let mut out = Metrics6Snapshot::default();
        for worker in workers {
            for (row, counters) in out.packets.iter_mut().zip(&worker.packets) {
                for (value, counter) in row.iter_mut().zip(counters) {
                    *value += counter.load(Ordering::Relaxed);
                }
            }
            for (value, counter) in out.dropped.iter_mut().zip(&worker.dropped) {
                *value += counter.load(Ordering::Relaxed);
            }
            out.declines += worker.declines.load(Ordering::Relaxed);
            out.store_refused += worker.store_refused.load(Ordering::Relaxed);
            for (total, histogram) in out.exchange.iter_mut().zip(&worker.exchange) {
                add(histogram, total);
            }
            add(&worker.commit, &mut out.commit);
        }
        out
    }
}

fn add(
    histogram: &Histogram,
    into: &mut ([u64; crate::metrics::EXCHANGE_BUCKETS_US.len() + 1], u64),
) {
    let (counts, sum) = histogram.read();
    for (total, count) in into.0.iter_mut().zip(counts) {
        *total += count;
    }
    into.1 += sum;
}

/// The DHCPv6 counters summed over the workers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Metrics6Snapshot {
    /// `tenko_dhcp_packets_total{family="v6"}` by [`TYPE_LABELS`] and the outcomes.
    pub packets: [[u64; OUTCOME_LABELS.len()]; TYPE_LABELS.len()],
    /// The drops by reason.
    pub dropped: [u64; DROP_LABELS.len()],
    /// DECLINEs received.
    pub declines: u64,
    /// Changes the store refused.
    pub store_refused: u64,
    /// The exchange histograms.
    pub exchange: [([u64; crate::metrics::EXCHANGE_BUCKETS_US.len() + 1], u64); 2],
    /// The commit histogram.
    pub commit: ([u64; crate::metrics::EXCHANGE_BUCKETS_US.len() + 1], u64),
}

impl Metrics6Snapshot {
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
