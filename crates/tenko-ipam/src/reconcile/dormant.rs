//! Dormant claims: the addresses a stopped host is configured with.
//!
//! An inventory source that knows whether a host runs (the Proxmox VE connector for its
//! guests, `ObservedHost::power`) reports the configured addresses of a stopped guest too.
//! Such an address is not in use: the claim is **dormant**. The rule:
//!
//! - A dormant claim raises no conflict against a live claim (a running guest, a lease, a
//!   scan sighting): where a live claim of another device (or of a device without a MAC
//!   address) sees the same address, the dormant pair leaves [`Snapshot::seen`] for
//!   [`Snapshot::dormant`], so no rule reads it, and the views show it as configured on the
//!   stopped guest.
//! - A dormant claim alone at its address stays a sighting for every rule except the
//!   conflicts: two stopped guests on one address, or a stopped guest on an address that
//!   intent gives another device, are no conflict. A conflict needs two live claims.
//! - The address-taken conflict names the hosts of intent whose own claim on the address is
//!   only dormant (`dormant_hosts`), so the Discovery page preselects "Decommission" for
//!   them.
//!
//! A DNS record is never a sighting, so it neither overrides nor raises anything here.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use tenko_core::{MacAddr, VrfId};

use super::snapshot::{Intent, Placement, Seen, Snapshot};

/// Splits the pairs of the current facts into the pairs the rules see and the dormant
/// pairs that a live claim of another device on their address overrides.
pub(crate) fn split(pairs: Vec<Seen>) -> (Vec<Seen>, Vec<Seen>) {
    // (VRF, address) -> the devices of the live claims (`None`: a claim without a MAC).
    let mut live: BTreeMap<(VrfId, IpAddr), BTreeSet<Option<MacAddr>>> = BTreeMap::new();
    for pair in pairs.iter().filter(|pair| !pair.dormant) {
        if let Some(address) = address(pair) {
            live.entry(address).or_default().insert(pair.mac);
        }
    }
    pairs.into_iter().partition(|pair| {
        !pair.dormant
            || address(pair).is_none_or(|address| {
                !live
                    .get(&address)
                    .is_some_and(|devices| devices.iter().any(|device| *device != pair.mac))
            })
    })
}

/// The placed address of a pair.
fn address(pair: &Seen) -> Option<(VrfId, IpAddr)> {
    let ip = pair.ip?;
    let vrf = pair.placement?.vrf()?;
    Some((vrf, ip))
}

/// Whether a pair is a live claim: its host is not reported stopped.
pub(crate) fn live(pair: &Seen) -> bool {
    !pair.dormant
}

/// Whether every claim of `macs` on the address is dormant: none of them is seen live
/// there, and at least one is seen dormant (in the rules' pairs or overridden).
pub(crate) fn only_dormant(
    snapshot: &Snapshot,
    vrf: VrfId,
    ip: IpAddr,
    macs: &BTreeSet<MacAddr>,
) -> bool {
    let at = |pair: &&Seen| {
        pair.ip == Some(ip)
            && pair.placement.and_then(Placement::vrf) == Some(vrf)
            && pair.mac.is_some_and(|mac| macs.contains(&mac))
    };
    let live_claim = snapshot.seen.iter().filter(at).any(live);
    let dormant_claim = snapshot
        .seen
        .iter()
        .chain(snapshot.dormant.iter())
        .filter(at)
        .any(|pair| pair.dormant);
    !live_claim && dormant_claim
}

/// The MAC addresses whose live interfaces all belong to decommissioned hosts: the facts
/// that name them raise nothing.
pub(crate) fn decommissioned_macs(intent: &Intent) -> BTreeSet<MacAddr> {
    intent
        .interfaces_by_mac
        .iter()
        .filter(|(_, interfaces)| {
            interfaces.iter().all(|interface| {
                intent
                    .host_of(*interface)
                    .is_some_and(tenko_core::ipam::Host::is_decommissioned)
            })
        })
        .map(|(mac, _)| *mac)
        .collect()
}
