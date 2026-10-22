//! The dispatcher: probes the parked offers and sends them (plan section 2.7).
//!
//! [`run`] is the body of one thread of the server with a single-threaded runtime of its
//! own, so that a probe's I/O (an ICMP datagram socket, a `ping.exe` child, the raw ARP
//! link) never runs on a worker. It takes the slots the workers park, starts a probe per
//! slot with the time left to the slot's deadline (the arrival plus the cap) and, as each
//! one ends:
//!
//! - nobody answered (or the cap cut the probe): the address enters the probe cache and the
//!   OFFER goes out;
//! - the probe cannot run, or the client's own MAC address answered: the OFFER goes out;
//! - another host answered: the address is marked ([`Hooks::mark`]), reported, and the
//!   engine runs again on the request ([`Hooks::rerun`]); the new OFFER is ran in turn
//!   with the time left, at most [`Conflicts::max_attempts`] times, else it goes out as it
//!   is. A reservation of the client that answers is offered all the same.
//!
//! When the server stops, the parked requests are dropped: their clients send their
//! DISCOVERs again.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use futures::{StreamExt as _, stream::FuturesUnordered};
use tenko_core::Timestamp;

use super::{
    Conflicts, Parked, ProbeHandle, Report, ReportKind, metrics::PROBE_DURATION, pending::Ready,
};
use crate::probe::ProbeOutcome;

/// How often the dispatcher looks at the stop flag while nothing happens.
const STOP_POLL: Duration = Duration::from_millis(100);

/// What the engine's second run gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rerun {
    /// A new OFFER is in the slot; `probe` says whether its address needs a probe (the
    /// slot's candidate is then that address).
    Offer {
        /// Whether to probe the new address.
        probe: bool,
    },
    /// No OFFER (the pool is full, the store refuses): nothing is sent.
    Nothing,
}

/// What the dispatcher asks of the server.
pub trait Hooks: Send {
    /// Whether the server stops.
    fn stopped(&self) -> bool;

    /// Sends the slot's OFFER out of its listener and records the exchange's time.
    fn send(&mut self, parked: &Parked);

    /// Marks the slot's candidate address as a conflict: held away from every client at
    /// once, and an abandoned lease row of kind `conflict` that names `mac` committed.
    fn mark(&mut self, parked: &Parked, mac: Option<[u8; 6]>);

    /// Runs the engine again on the slot's request after its address was marked; a new
    /// OFFER replaces the slot's.
    fn rerun(&mut self, parked: &mut Parked) -> Rerun;
}

/// Runs the dispatcher until the hooks say the server stops.
pub fn run(conflicts: &Arc<Conflicts>, probe: &ProbeHandle, hooks: &mut impl Hooks) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::warn!(%error, "the dhcp role's conflict probe could not start; offers go out unran");
            return;
        }
    };
    runtime.block_on(dispatch(conflicts, probe, hooks));
    let dropped = conflicts.pending().clear();
    if dropped > 0 {
        tracing::debug!(
            dropped,
            "offers waiting for the conflict probe were dropped at stop"
        );
    }
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

async fn dispatch(conflicts: &Arc<Conflicts>, probe: &ProbeHandle, hooks: &mut impl Hooks) {
    let mut probes = FuturesUnordered::new();
    let mut slot = Parked::boxed();
    loop {
        if hooks.stopped() {
            return;
        }
        while let Some(ready) = conflicts.pending().next_ready() {
            let remaining = ready.deadline.saturating_duration_since(Instant::now());
            let probe = probe.clone();
            probes.push(async move {
                let started = Instant::now();
                let outcome = if remaining.is_zero() {
                    None
                } else {
                    tokio::time::timeout(remaining, probe.probe(ready.addr, remaining))
                        .await
                        .ok()
                };
                (ready, outcome, !remaining.is_zero(), started.elapsed())
            });
        }
        tokio::select! {
            () = conflicts.woken() => {}
            Some((ready, outcome, ran, took)) = probes.next(), if !probes.is_empty() => {
                finish(conflicts, hooks, &mut slot, ready, outcome, ran, took);
            }
            () = tokio::time::sleep(STOP_POLL) => {}
        }
    }
}

fn finish(
    conflicts: &Conflicts,
    hooks: &mut impl Hooks,
    slot: &mut Parked,
    ready: Ready,
    outcome: Option<ProbeOutcome>,
    ran: bool,
    took: Duration,
) {
    if ran {
        PROBE_DURATION.observe(micros(took));
    }
    if !conflicts
        .pending()
        .take(ready.index, ready.generation, slot)
    {
        return;
    }
    let candidate = slot.candidate;
    let own = matches!(outcome, Some(ProbeOutcome::InUse { mac: Some(mac) }) if Some(mac) == candidate.mac);
    if ran {
        conflicts.count(outcome, own);
    }
    let report = |kind, mac| Report {
        kind,
        vrf: candidate.vrf,
        prefix: candidate.prefix,
        addr: candidate.addr,
        mac,
        at: Timestamp::now(),
    };
    match outcome {
        Some(ProbeOutcome::InUse { mac }) if !own => {
            if candidate.reserved {
                conflicts.count_reserved();
                conflicts.reports().push(&report(ReportKind::Reserved, mac));
                hooks.send(slot);
                return;
            }
            hooks.mark(slot, mac);
            conflicts.cache().forget(candidate.vrf, candidate.addr);
            conflicts.reports().push(&report(ReportKind::Conflict, mac));
            match hooks.rerun(slot) {
                Rerun::Offer { probe: true }
                    if slot.attempts < conflicts.max_attempts()
                        && Instant::now() < slot.deadline =>
                {
                    if !conflicts.pending().repark(slot) {
                        hooks.send(slot);
                    }
                }
                Rerun::Offer { .. } => hooks.send(slot),
                Rerun::Nothing => {}
            }
        }
        Some(ProbeOutcome::Clear) | None => {
            if ran {
                conflicts.clean(&candidate, Timestamp::now());
            }
            hooks.send(slot);
        }
        Some(ProbeOutcome::Unavailable | ProbeOutcome::InUse { .. }) => hooks.send(slot),
    }
}
