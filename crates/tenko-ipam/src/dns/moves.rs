//! The DNS part of a move (IPAM-19 step 3): what the move changes in the zones, for the
//! preview and for the step `ipam.move.dns`.
//!
//! The step is automatic when the device's name falls under a zone Tenko serves (and no
//! delegation inside it covers the name); otherwise it stays a task for a person. It
//! removes the A or AAAA record of the old address and its PTR and writes those of the new
//! address, through the actuator with the move treated as in flight. A name whose RRset
//! another origin holds stops the step with `ipam.move.dns_collision`.

use std::{collections::BTreeSet, net::IpAddr};

use tenko_core::{
    AddressId,
    dns::{DnsName, Rdata, RecordData, Rtype},
    ipam::{Address, Status},
};
use tenko_store::ReadView;

use super::{
    OrphanRule,
    plan::{self, DnsFinding, DnsPlan, MoveOverride, RecordChange, World, ZoneBatch},
};
use crate::error::IpamResult;

/// One address that moves.
#[derive(Debug, Clone)]
pub struct MovedAddress {
    /// The address now.
    pub old: Address,
    /// The identifier of the new address.
    pub new_id: AddressId,
    /// The new address.
    pub new_ip: IpAddr,
}

/// What a move changes in the zones for one address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MoveDnsChange {
    /// The zone Tenko serves for the name; none leaves the step to a person.
    pub zone: Option<DnsName>,
    /// The records removed, in presentation form.
    pub remove: Vec<String>,
    /// The records added.
    pub add: Vec<String>,
    /// Another origin holds the name or a PTR the move needs: why the step would stop.
    pub held: Vec<String>,
}

/// The zone Tenko serves for `name`, if any.
pub(crate) fn forward_zone(view: &dyn ReadView, world: &World, name: &DnsName) -> Option<DnsName> {
    world
        .zones
        .iter()
        .filter(|info| name.is_subdomain_of(&info.zone.name))
        .max_by_key(|info| info.zone.name.label_count())
        .filter(|info| !plan::delegated(view, &info.zone, name))
        .map(|info| info.zone.name.clone())
}

/// Whether a change concerns `name`: its own A or AAAA set, or a PTR set that points to it
/// before or after.
pub(crate) fn concerns(change: &RecordChange, name: &DnsName) -> bool {
    if &change.name == name {
        return matches!(change.rtype, Rtype::A | Rtype::AAAA);
    }
    change.rtype == Rtype::PTR
        && change
            .before
            .iter()
            .chain(&change.after)
            .any(|data| matches!(data, RecordData::Ptr { target } if target == name))
}

/// The batches of `planned` reduced to the changes that concern `name`.
pub(crate) fn batches_for(planned: &DnsPlan, name: &DnsName) -> Vec<ZoneBatch> {
    planned
        .batches
        .iter()
        .filter_map(|batch| {
            let changes: Vec<RecordChange> = batch
                .changes
                .iter()
                .filter(|change| concerns(change, name))
                .cloned()
                .collect();
            (!changes.is_empty()).then(|| ZoneBatch {
                zone: batch.zone,
                name: batch.name.clone(),
                changes,
            })
        })
        .collect()
}

/// The findings that would stop the DNS step of `name`.
pub(crate) fn held_for(planned: &DnsPlan, name: &DnsName) -> Vec<String> {
    planned
        .findings
        .iter()
        .filter_map(|finding| match finding {
            DnsFinding::Held {
                zone,
                name: owner,
                rtype,
                held_type,
                origin,
                wanted,
                ..
            } => {
                let ptr_to_name = *rtype == Rtype::PTR
                    && wanted
                        .iter()
                        .any(|data| matches!(data, RecordData::Ptr { target } if target == name));
                (owner == name || ptr_to_name).then(|| {
                    format!(
                        "{owner} {held_type} in {zone} belongs to the origin {}",
                        tenko_dns::zone::records::origin_name(*origin)
                    )
                })
            }
            _ => None,
        })
        .collect()
}

/// The records removed and added by the changes, in presentation form.
pub(crate) fn texts(batches: &[ZoneBatch]) -> (Vec<String>, Vec<String>) {
    let mut remove = Vec::new();
    let mut add = Vec::new();
    for change in batches.iter().flat_map(|batch| &batch.changes) {
        let before: BTreeSet<Rdata> = change.before.iter().map(Rdata::from_data).collect();
        let after: BTreeSet<Rdata> = change.after.iter().map(Rdata::from_data).collect();
        for data in &change.before {
            if !after.contains(&Rdata::from_data(data)) {
                remove.push(plan::record_text(&change.name, change.rtype, data));
            }
        }
        for data in &change.after {
            if !before.contains(&Rdata::from_data(data)) {
                add.push(plan::record_text(&change.name, change.rtype, data));
            }
        }
    }
    (remove, add)
}

/// What the moves change in the zones, one entry per moved address (the dry run of the
/// move preview): the new addresses are planned as if their DNS step had started.
///
/// # Errors
///
/// Store errors.
pub fn preview(view: &dyn ReadView, moved: &[MovedAddress]) -> IpamResult<Vec<MoveDnsChange>> {
    if moved.iter().all(|item| item.old.dns_name.is_none()) {
        return Ok(vec![MoveDnsChange::default(); moved.len()]);
    }
    let mut world = World::load(view)?;
    if world.zones.is_empty() {
        return Ok(vec![MoveDnsChange::default(); moved.len()]);
    }
    let mut overrides = plan::moves_in_flight(view, &[])?;
    for item in moved {
        let mut new = item.old.clone();
        new.id = item.new_id;
        new.ip = item.new_ip;
        new.status = Status::Planned;
        world.addresses.insert(new.id, new);
        overrides.push(MoveOverride {
            old: item.old.id,
            new: item.new_id,
        });
    }
    let planned = plan::plan_world(view, &world, &overrides, OrphanRule::Remove)?;
    Ok(moved
        .iter()
        .map(|item| {
            let Some(fqdn) = &item.old.dns_name else {
                return MoveDnsChange::default();
            };
            let name = DnsName::from(fqdn);
            let Some(zone) = forward_zone(view, &world, &name) else {
                return MoveDnsChange::default();
            };
            let (remove, add) = texts(&batches_for(&planned, &name));
            MoveDnsChange {
                zone: Some(zone),
                remove,
                add,
                held: held_for(&planned, &name),
            }
        })
        .collect())
}
