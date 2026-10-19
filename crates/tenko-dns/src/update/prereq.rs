//! The prerequisites of an update (RFC 2136 section 3.2).
//!
//! They are tested twice. First against the index at the revision the node serves
//! ([`IndexRecords`]), before the update waits for its zone: a client that sends its
//! updates one after the other sees each answered only once the index holds it, so the
//! next one's prerequisites see it too. Then, under the commit, against the store's view
//! with the changes of the updates before it in the same write ([`Records`] over the
//! planner's nodes, [`super::apply`]), which is what makes the update all or nothing.
//!
//! The answers: NXRRSET when an RRset that should exist does not or holds other records
//! (compared in canonical form, without duplicates and in any order), YXRRSET when one
//! that should not exist does, NXDOMAIN when a name should be in use and is not,
//! YXDOMAIN when it should not and is. A name is in use when it owns at least one record
//! of any type; an empty non-terminal is not in use, and wildcards do not apply.

use tenko_core::dns::{DnsName, Rdata, Rtype, ScopeName, ZoneId, ZoneKind};

use super::message::{Prerequisite, rcode};
use crate::index::{Index, Lookup, ScopeOf, ZoneView};

/// The records the prerequisites look at.
pub trait Records {
    /// The records of the RRset of `rtype` at exactly `name`, if it exists.
    fn rrset(&self, name: &DnsName, rtype: Rtype) -> Option<&[Rdata]>;

    /// Whether `name` owns at least one record.
    fn name_in_use(&self, name: &DnsName) -> bool;
}

/// A prerequisite that does not hold: the RCODE and the name it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unmet {
    /// NXRRSET, YXRRSET, NXDOMAIN or YXDOMAIN.
    pub rcode: u16,
    /// The name.
    pub name: DnsName,
}

impl Unmet {
    /// The text of the extended error.
    pub fn text(&self) -> String {
        let what = match self.rcode {
            rcode::NXRRSET => "the RRset does not exist as required",
            rcode::YXRRSET => "the RRset exists",
            rcode::NXDOMAIN => "the name is not in use",
            _ => "the name is in use",
        };
        format!("prerequisite: {what}: {}", self.name)
    }
}

/// Whether two record sets hold the same records (canonical form, any order).
fn same_records(a: &[Rdata], b: &[Rdata]) -> bool {
    let distinct = |set: &[Rdata]| {
        set.iter()
            .enumerate()
            .filter(|(index, data)| !set[..*index].contains(data))
            .count()
    };
    distinct(a) == distinct(b) && a.iter().all(|data| b.contains(data))
}

/// Tests `prerequisites` in order against `records`.
///
/// # Errors
///
/// The first prerequisite that does not hold.
pub fn check(prerequisites: &[Prerequisite], records: &impl Records) -> Result<(), Unmet> {
    for prerequisite in prerequisites {
        let holds = match prerequisite {
            Prerequisite::Exists { name, rtype } => records.rrset(name, *rtype).is_some(),
            Prerequisite::Equals { name, rtype, rdata } => records
                .rrset(name, *rtype)
                .is_some_and(|held| same_records(held, rdata)),
            Prerequisite::NotExists { name, rtype } => records.rrset(name, *rtype).is_none(),
            Prerequisite::NameInUse { name } => records.name_in_use(name),
            Prerequisite::NameNotInUse { name } => !records.name_in_use(name),
        };
        if !holds {
            let rcode = match prerequisite {
                Prerequisite::Exists { .. } | Prerequisite::Equals { .. } => rcode::NXRRSET,
                Prerequisite::NotExists { .. } => rcode::YXRRSET,
                Prerequisite::NameInUse { .. } => rcode::NXDOMAIN,
                Prerequisite::NameNotInUse { .. } => rcode::YXDOMAIN,
            };
            return Err(Unmet {
                rcode,
                name: prerequisite.name().clone(),
            });
        }
    }
    Ok(())
}

/// One scope of one zone, for the lookups of the index.
struct OneScope<'a> {
    zone: ZoneId,
    scope: &'a ScopeName,
}

impl ScopeOf for OneScope<'_> {
    fn scope_of(&self, zone: ZoneId) -> &ScopeName {
        if zone == self.zone {
            self.scope
        } else {
            &ScopeName::DEFAULT
        }
    }
}

/// The records of one scope of a zone in the index the node serves.
pub struct IndexRecords<'a, I: Index + ?Sized> {
    index: &'a I,
    zone: ZoneId,
    kind: ZoneKind,
    apex: Vec<u8>,
    scope: &'a ScopeName,
}

impl<'a, I: Index + ?Sized> IndexRecords<'a, I> {
    /// The records of `scope` of the zone `zone` at `apex` in `index`.
    pub fn new(
        index: &'a I,
        zone: ZoneId,
        kind: ZoneKind,
        apex: &DnsName,
        scope: &'a ScopeName,
    ) -> Self {
        Self {
            index,
            zone,
            kind,
            apex: apex.to_wire(),
            scope,
        }
    }

    fn view(&self) -> ZoneView<'_> {
        ZoneView {
            id: self.zone,
            kind: self.kind,
            apex: &self.apex,
            scope: self.scope,
        }
    }
}

impl<I: Index + ?Sized> Records for IndexRecords<'_, I> {
    fn rrset(&self, name: &DnsName, rtype: Rtype) -> Option<&[Rdata]> {
        let owner = name.to_wire();
        self.index
            .rrset_at(&self.view(), &owner, rtype)
            .map(|rrset| rrset.rdata)
    }

    fn name_in_use(&self, name: &DnsName) -> bool {
        let owner = name.to_wire();
        let scopes = OneScope {
            zone: self.zone,
            scope: self.scope,
        };
        match self.index.lookup(&scopes, &owner, Rtype::ANY) {
            Lookup::Answer {
                zone,
                rrset,
                wildcard: None,
            } if zone.id == self.zone => rrset.owner == owner.as_slice(),
            Lookup::Cname {
                zone,
                wildcard: None,
                ..
            } if zone.id == self.zone => true,
            Lookup::Delegation { zone, ns, .. } if zone.id == self.zone => {
                ns.owner == owner.as_slice()
                    || self
                        .index
                        .addresses(&scopes, &owner)
                        .iter()
                        .any(Option::is_some)
            }
            Lookup::Dname { zone, dname } if zone.id == self.zone => {
                dname.owner == owner.as_slice()
            }
            Lookup::Answer { zone, .. }
            | Lookup::Cname { zone, .. }
            | Lookup::Delegation { zone, .. }
            | Lookup::NoData { zone, .. }
            | Lookup::NxDomain { zone, .. }
            | Lookup::Dname { zone, .. }
                if zone.id != self.zone =>
            {
                // A zone of its own below the name: the delegation in this zone.
                self.index
                    .rrset_at(&self.view(), &owner, Rtype::NS)
                    .is_some()
            }
            _ => false,
        }
    }
}
