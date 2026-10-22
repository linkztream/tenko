//! What the workers and the dispatcher report to the role: the DECLINEs to audit and the
//! conflicts to log.
//!
//! The workers push into a [`ReportQueue`] whose capacity is reserved at start (a full
//! queue drops the report and counts it), so the DECLINE path does not allocate; the role's
//! [`run`] task drains it on the async side:
//!
//! - an accepted DECLINE writes the audit record `dhcp.decline` (the principal
//!   `system:dhcp`) with the address and the client's MAC address, in a batch of its own
//!   (the lease change is the committer's batch);
//! - a conflict a probe found is logged once, with the answering MAC address when ARP gave
//!   one; the abandoned lease row and its history row are the durable record.

use std::{
    collections::VecDeque,
    net::Ipv4Addr,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tenko_core::{
    MacAddr, PrefixId, Principal, SystemComponent, Timestamp, VrfId,
    audit::AuditDraft,
    dhcp::{audit, scope_object},
};
use tenko_store::{Store, WriteBatch};
use tokio_util::sync::CancellationToken;

use super::Conflicts;

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportKind {
    /// A client declined the address.
    Decline,
    /// A probe found the address in use; it is held for the decline hold time.
    Conflict,
    /// A probe found the client's reservation in use; it was offered all the same.
    Reserved,
}

/// One report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// What happened.
    pub kind: ReportKind,
    /// The VRF.
    pub vrf: VrfId,
    /// The scope.
    pub prefix: PrefixId,
    /// The address.
    pub addr: Ipv4Addr,
    /// The client's MAC address (a DECLINE), or the answering one (a conflict, when ARP
    /// gave it).
    pub mac: Option<[u8; 6]>,
    /// When.
    pub at: Timestamp,
}

/// The reports waiting for the role.
#[derive(Debug)]
pub struct ReportQueue {
    queue: Mutex<VecDeque<Report>>,
    capacity: usize,
    dropped: AtomicU64,
}

impl ReportQueue {
    /// A queue of `capacity` reports.
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            queue: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            dropped: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, VecDeque<Report>> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues a report; a full queue drops it and counts it. Never allocates.
    pub fn push(&self, report: &Report) {
        let mut queue = self.lock();
        if queue.len() >= self.capacity {
            drop(queue);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        queue.push_back(*report);
    }

    /// Moves the queued reports into `out`.
    pub fn drain(&self, out: &mut Vec<Report>) {
        out.extend(self.lock().drain(..));
    }

    /// Reports dropped because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// How often the role drains the queue.
const DRAIN_EVERY: Duration = Duration::from_millis(200);

/// The audit record of an accepted DECLINE.
pub fn decline_audit(report: &Report, hold_secs: u32) -> AuditDraft {
    let mut draft = AuditDraft::success(audit::DECLINE, vec![scope_object(report.prefix)])
        .with_context("addr", report.addr.to_string())
        .with_context("hold_secs", hold_secs.to_string());
    if let Some(mac) = report.mac {
        draft = draft.with_context("mac", MacAddr::new(mac).to_string());
    }
    draft
}

/// Drains the queue of `conflicts` until `stop`: audits the DECLINEs on `store` and logs
/// the conflicts.
pub async fn run(
    store: Arc<dyn Store>,
    conflicts: Arc<Conflicts>,
    hold_secs: u32,
    stop: CancellationToken,
) {
    let mut reports = Vec::with_capacity(64);
    loop {
        let stopping = tokio::select! {
            () = stop.cancelled() => true,
            () = tokio::time::sleep(DRAIN_EVERY) => false,
        };
        reports.clear();
        conflicts.reports().drain(&mut reports);
        for report in &reports {
            handle(store.as_ref(), report, hold_secs).await;
        }
        if stopping {
            return;
        }
    }
}

async fn handle(store: &dyn Store, report: &Report, hold_secs: u32) {
    let mac = report.mac.map(|mac| MacAddr::new(mac).to_string());
    match report.kind {
        ReportKind::Decline => {
            let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), report.at);
            batch.audit(decline_audit(report, hold_secs));
            if let Err(error) = store.propose(batch).await {
                tracing::warn!(addr = %report.addr, %error, "the audit record of a DHCP DECLINE was not written");
            }
            tracing::info!(addr = %report.addr, mac = mac.as_deref().unwrap_or("unknown"), hold_secs, "a DHCP client declined an address; it is held");
        }
        ReportKind::Conflict => tracing::warn!(
            addr = %report.addr,
            mac = mac.as_deref().unwrap_or("unknown (ICMP)"),
            hold_secs,
            "the conflict probe found an address in use before an offer; it is held and the next address is offered"
        ),
        ReportKind::Reserved => tracing::warn!(
            addr = %report.addr,
            mac = mac.as_deref().unwrap_or("unknown (ICMP)"),
            "the conflict probe found a reserved address in use; it is offered to its client all the same"
        ),
    }
}
