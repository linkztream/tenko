//! The conflict observation (IPAM-23, plan section 2.8): what the `dhcp:<node>` source
//! knows of an address it found in use.
//!
//! A conflict is a lease row in state `abandoned`: written by a DECLINE (the client found
//! the address in use, without saying by whom) or by a probe that got an answer before an
//! offer (the row's hardware address is the answering MAC address when ARP gave one, else
//! empty). The fact is the source's address observation, `Observed::Address` with the
//! address, its VRF and the answering MAC address when known, valid until the hold ends.
//! It has the same subject as the lease fact of the address, so it replaces the decliner's
//! lease fact of the same source; IPAM's reconciler compares it with the other sources'
//! sightings and intent and raises the conflict (IPAM-23), never resolving it on its own.
//!
//! [`conflict_observation`] builds the value from the abandoned row; the observation hook
//! of the lease batch (WP8.1's, `ObservationHook`) writes it with the rules of
//! `observe::ingest`, so the fact is exactly as durable as the row.

use std::net::IpAddr;

use tenko_core::{
    MacAddr, NodeId, ObservationId, Timestamp,
    dhcp::{BindingState, Lease},
    observe::{Observation, ObservationSource, Observed},
};

/// The MAC address an abandoned row names: the answering host's when ARP gave it.
pub fn answering_mac(lease: &Lease) -> Option<MacAddr> {
    if lease.state != BindingState::Abandoned || lease.client.htype != 1 {
        return None;
    }
    let octets: [u8; 6] = lease.client.chaddr.0.as_slice().try_into().ok()?;
    Some(MacAddr::new(octets))
}

/// The conflict fact of an abandoned row of node `node`, or `None` for any other row.
pub fn conflict_observation(lease: &Lease, node: NodeId, now: Timestamp) -> Option<Observation> {
    (lease.state == BindingState::Abandoned).then(|| Observation {
        id: ObservationId::generate(),
        source: ObservationSource::DhcpLease { node },
        subject: Observed::Address {
            vrf: lease.vrf,
            ip: IpAddr::V4(lease.addr),
            mac: answering_mac(lease),
        },
        observed_at: lease.cltt,
        received_at: now,
        expires_at: Some(lease.ends),
    })
}
