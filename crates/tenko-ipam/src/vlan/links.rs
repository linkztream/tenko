//! The prefixes of a VLAN (IPAM-03). A prefix names its VLAN (`Prefix::vlan`); linking and
//! unlinking is a change of the prefix (`PATCH /prefixes/{id}` with `vlan`).

use tenko_core::{
    ObjectRef, VlanId,
    ipam::{Prefix, Vlan},
};
use tenko_store::{KeyRange, ReadView, ReadViewExt};

use crate::{
    error::{IpamError, IpamResult},
    query,
    tables::PREFIXES,
};

/// The live prefixes linked to a VLAN, ordered by VRF and network; with `deleted`, the
/// soft-deleted ones too.
///
/// # Errors
///
/// 404 `ipam.not_found` for an unknown VLAN, or the store's errors.
pub fn vlan_prefixes(view: &dyn ReadView, vlan: VlanId, deleted: bool) -> IpamResult<Vec<Prefix>> {
    let _: Vlan = query::get(view, vlan).map_err(|error| {
        if error.is(crate::codes::NOT_FOUND) {
            IpamError::not_found(ObjectRef::from(vlan))
        } else {
            error
        }
    })?;
    let mut prefixes: Vec<Prefix> = view
        .scan_typed(&PREFIXES, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .map(|(_, mut prefix, revision): (_, Prefix, _)| {
            prefix.meta.revision = revision;
            prefix
        })
        .filter(|prefix| prefix.vlan == Some(vlan) && (deleted || !prefix.meta.is_deleted()))
        .collect();
    prefixes.sort_by_key(|p| (p.vrf, p.cidr));
    Ok(prefixes)
}
