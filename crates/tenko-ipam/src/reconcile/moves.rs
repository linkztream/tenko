//! The observation step of moves (IPAM-19, ARCHITECTURE "Device move job" step 5): a move
//! job waits at `ipam.move.observe` until the device is seen at its new address. The step
//! is a manual task, so a person can still confirm it; the reconciler confirms it as
//! `system:reconciler` as soon as a current observation shows the new address in the
//! target VRF, from the interface's MAC address when the interface has one, reported
//! after the job started. A DHCP lease (the source `dhcp:<node>`, WP8.1) confirms it
//! anywhere in the target network when it comes from the interface's MAC address: a
//! reserved device gets the new address itself, a dynamic one an address of the pool.

use std::net::IpAddr;

use ipnet::IpNet;
use tenko_core::{
    InterfaceId, JobId, MacAddr, Timestamp, VrfId, codec::from_cbor, ipam::Interface,
    observe::ObservationSource,
};
use tenko_jobs::{
    Job, JobState, StepState,
    tables::{BY_STATE, JOBS},
};
use tenko_store::{KeyRange, ReadView, ReadViewExt};

use crate::{
    error::IpamResult,
    moves::{MOVE_JOB, MoveStepParams},
    tables::INTERFACES,
};

/// The step kind of the observation step.
const OBSERVE: &str = "ipam.move.observe";

/// A move job waiting at its observation step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WaitingMove {
    pub job: JobId,
    pub step: u16,
    pub vrf: VrfId,
    pub ip: IpAddr,
    /// The target network, where a lease of the MAC address confirms the move.
    pub cidr: IpNet,
    /// The MAC address of the moved interface; the sighting must come from it.
    pub mac: Option<MacAddr>,
    /// Sightings before this time do not count.
    pub since: Timestamp,
}

impl WaitingMove {
    /// Whether a sighting of `ip` in `vrf` from `mac` at `seen_at` confirms the move.
    pub(crate) fn confirmed_by(
        &self,
        vrf: Option<VrfId>,
        ip: IpAddr,
        mac: Option<MacAddr>,
        seen_at: Timestamp,
    ) -> bool {
        self.ip == ip
            && vrf == Some(self.vrf)
            && self.mac.is_none_or(|needed| mac == Some(needed))
            && seen_at >= self.since
    }

    /// Whether a report of `source` confirms the move: a sighting as
    /// [`confirmed_by`](Self::confirmed_by) says, or a DHCP lease of the interface's MAC
    /// address at any address of the target network.
    pub(crate) fn confirmed_by_source(
        &self,
        source: &ObservationSource,
        vrf: Option<VrfId>,
        ip: IpAddr,
        mac: Option<MacAddr>,
        seen_at: Timestamp,
    ) -> bool {
        if self.confirmed_by(vrf, ip, mac, seen_at) {
            return true;
        }
        matches!(source, ObservationSource::DhcpLease { .. })
            && self.mac.is_some_and(|needed| mac == Some(needed))
            && vrf == Some(self.vrf)
            && self.cidr.contains(&ip)
            && seen_at >= self.since
    }
}

fn waiting_step(job: &Job) -> Option<(u16, MoveStepParams)> {
    if job.spec.kind.as_str() != MOVE_JOB || job.state != JobState::Waiting {
        return None;
    }
    job.steps.iter().find_map(|record| {
        if record.kind.as_str() != OBSERVE
            || !matches!(record.state, StepState::WaitingForManual { .. })
        {
            return None;
        }
        let spec = job.spec.steps.get(usize::from(record.index))?;
        let params: MoveStepParams = from_cbor(&spec.params.0).ok()?;
        Some((record.index, params))
    })
}

/// Every move job waiting at its observation step.
pub(crate) fn waiting_moves(view: &dyn ReadView) -> IpamResult<Vec<WaitingMove>> {
    let rows = view.scan_typed(
        &BY_STATE,
        KeyRange::prefix(tenko_core::codec::encode_key(&(JobState::Waiting,))),
        usize::MAX,
        false,
    )?;
    let mut out = Vec::new();
    for ((_, id), (), _) in rows {
        let Some((job, _)) = view.get_typed(&JOBS, &id)? else {
            continue;
        };
        let Some((step, params)) = waiting_step(&job) else {
            continue;
        };
        let mac = match params.interface {
            Some(interface) => interface_mac(view, interface)?,
            None => None,
        };
        out.push(WaitingMove {
            job: id,
            step,
            vrf: params.vrf,
            ip: params.new_ip,
            cidr: params.cidr,
            mac,
            since: job.started.unwrap_or(job.created.at),
        });
    }
    Ok(out)
}

/// Whether any job waits at all (cheap check before building address observations).
pub(crate) fn any_waiting(view: &dyn ReadView) -> IpamResult<bool> {
    Ok(!view
        .scan_typed(
            &BY_STATE,
            KeyRange::prefix(tenko_core::codec::encode_key(&(JobState::Waiting,))),
            1,
            false,
        )?
        .is_empty())
}

fn interface_mac(view: &dyn ReadView, interface: InterfaceId) -> IpamResult<Option<MacAddr>> {
    Ok(view
        .get_typed(&INTERFACES, &interface)?
        .and_then(|(interface, _): (Interface, _)| interface.mac))
}
