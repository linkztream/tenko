//! Helpers for unit tests.

use tenko_core::{
    PrefixId, Principal, SystemComponent, VrfId,
    ipam::{AllocPolicy, Meta, Prefix, PrefixRole, Stamp, Status},
};

/// The principal of test writes.
pub(crate) fn principal() -> Principal {
    Principal::system(SystemComponent::Api)
}

/// A fixed stamp.
pub(crate) fn stamp() -> Stamp {
    Stamp::new("2026-10-09T12:00:00Z".parse().expect("time"), principal())
}

/// A network prefix in a new VRF.
pub(crate) fn prefix(cidr: &str) -> Prefix {
    Prefix {
        id: PrefixId::generate(),
        vrf: VrfId::generate(),
        cidr: cidr.parse().expect("cidr"),
        role: PrefixRole::Network,
        status: Status::Active,
        vlan: None,
        site: None,
        alarm: None,
        alloc: AllocPolicy::Lowest,
        meta: Meta::new(stamp()),
    }
}
