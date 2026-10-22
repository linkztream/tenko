//! What a DDNS request changes in the zones (plan section 2.9, ADR 0020 points 2 to 4):
//! the RFC 4703 conflict rules over the RRsets as the store holds them, planned without
//! writing.
//!
//! **Adding names.** At the forward name the server writes the A RRset and the DHCID
//! RRset (unless the client writes its A record itself, [`super::flags`]); in the reverse
//! zone Tenko keeps for the address, the PTR RRset. Who may replace what:
//!
//! | RRset there | Forward (A and DHCID) | PTR |
//! |---|---|---|
//! | none | written | written |
//! | `dhcp`, the DHCID matches the client | replaced | replaced |
//! | `dhcp`, another client's DHCID (or none) | refused (`protect`); taken over (`replace`, not under Hardened) | replaced: the address is this lease's |
//! | `ipam` | taken over only where the zone allows it (`Origin::may_replace`, `may_replace_ipam`), else skipped | the same |
//! | `manual`, `dynamic`, `transfer`, `dnssec`, `ad` | refused | refused |
//! | a CNAME at the name | refused | refused |
//!
//! A refused forward name gets no PTR either. Names the lease held before (another name,
//! another client at the address) are removed first, by the removal rules.
//!
//! **Removing names** (release, expiry, a new name, a new client): the A record of the
//! address goes, and the DHCID with it when no other address is left in the set, but only
//! while the DHCID at the name is still the client's; the PTR goes when it is a `dhcp` PTR
//! that points at the lease's forward name. Records of another origin are never touched.
//!
//! **Zones.** Only primary zones Tenko serves. The forward zone is the scope's (its
//! `forward_zone`, else the zone of the scope's domain name, option 15); the reverse zone
//! is the most specific primary zone whose apex is a reverse zone covering the address
//! (`tenko_ipam::dns::reverse`, RFC 2317 zones included). A zone takes DHCP updates only
//! where its update policy allows them ([`UpdatePolicy::dhcp_allowed`] with the profile's
//! default).
//!
//! [`UpdatePolicy::dhcp_allowed`]: tenko_core::dns::UpdatePolicy::dhcp_allowed

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
};

use tenko_core::{
    dhcp::{ClientKey, DdnsConflict, DdnsPolicy},
    dns::{
        DnsName, Origin, Rdata, RecordData, RrSet, RrSetKey, Rtype, ScopeName, Zone, ZoneId,
        ZoneKind, tables::RRSETS,
    },
    serde_util::HexBytes,
};
use tenko_dns::zone::{
    ZoneService, holds_data,
    records::{Change, Op},
};
use tenko_ipam::dns::reverse::{ReverseZone, classless_ptr_name, parse_zone, ptr_name};
use tenko_store::{ReadView, ReadViewExt as _, StoreError};

use super::{dhcid, flags, names, names::NameRefusal};

/// The DHCID record type.
pub const DHCID: Rtype = Rtype(dhcid::RTYPE);

/// What the profile says about DDNS (P3-Q6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DdnsProfile {
    /// Whether a zone whose update policy does not say takes DHCP updates (Home and Lab).
    pub allows_by_default: bool,
    /// Whether name protection holds whatever the scope says (Hardened).
    pub always_protect: bool,
}

impl DdnsProfile {
    /// Home: DHCP writes into the scope's zones.
    pub const HOME: Self = Self {
        allows_by_default: true,
        always_protect: false,
    };
    /// Standard: only where the zone allows it.
    pub const STANDARD: Self = Self {
        allows_by_default: false,
        always_protect: false,
    };
    /// Hardened: only where the zone allows it, and name protection cannot be switched off.
    pub const HARDENED: Self = Self {
        allows_by_default: false,
        always_protect: true,
    };
    /// Lab: as Home.
    pub const LAB: Self = Self::HOME;
}

/// The primary zones Tenko serves, read once per batch.
#[derive(Debug, Clone, Default)]
pub struct Zones {
    zones: Vec<Zone>,
}

impl Zones {
    /// The primary zones of `view`.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn read(view: &dyn ReadView) -> Result<Self, String> {
        let zones = ZoneService::zones(view)
            .map_err(|error| error.coded().detail.clone())?
            .into_iter()
            .map(|row| row.zone)
            .filter(|zone| zone.kind == ZoneKind::Primary && holds_data(zone.kind))
            .collect();
        Ok(Self { zones })
    }

    /// Zones given directly (tests).
    pub fn from_zones(zones: Vec<Zone>) -> Self {
        Self { zones }
    }

    /// The zone of an id.
    pub fn get(&self, id: ZoneId) -> Option<&Zone> {
        self.zones.iter().find(|zone| zone.id == id)
    }

    /// The zone whose apex is `name`.
    pub fn by_name(&self, name: &DnsName) -> Option<&Zone> {
        self.zones.iter().find(|zone| &zone.name == name)
    }

    /// The most specific zone that holds `name`.
    pub fn holding(&self, name: &DnsName) -> Option<&Zone> {
        self.zones
            .iter()
            .filter(|zone| name.is_subdomain_of(&zone.name))
            .max_by_key(|zone| zone.name.label_count())
    }

    /// The most specific reverse zone that covers `addr`, and the PTR name in it.
    pub fn reverse_for(&self, addr: Ipv4Addr) -> Option<(&Zone, DnsName)> {
        self.zones
            .iter()
            .filter_map(|zone| {
                let reverse = parse_zone(&zone.name)?;
                reverse
                    .net()
                    .contains(&IpAddr::V4(addr))
                    .then_some((zone, reverse))
            })
            .max_by_key(|(_, reverse)| reverse.net().prefix_len())
            .map(|(zone, reverse)| {
                let name = match reverse {
                    ReverseZone::Plain { .. } => ptr_name(IpAddr::V4(addr)),
                    ReverseZone::Classless { name, .. } => classless_ptr_name(addr, &name),
                };
                (zone, name)
            })
    }
}

/// One lease as the planner sees it.
#[derive(Debug, Clone)]
pub struct LeaseNames<'a> {
    /// The address.
    pub addr: Ipv4Addr,
    /// The client.
    pub client: &'a ClientKey,
    /// The name of option 81.
    pub fqdn: Option<&'a str>,
    /// The name of option 12.
    pub hostname: Option<&'a str>,
    /// The flags of option 81.
    pub fqdn_flags: Option<u8>,
    /// The scope's DDNS settings.
    pub policy: &'a DdnsPolicy,
    /// The zone of the scope's domain name (option 15), when it has one.
    pub domain: Option<DnsName>,
    /// The lease time, for the default TTL.
    pub lease_secs: u32,
}

/// What a lease should hold in the zones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Desired {
    /// The forward zone.
    pub zone: ZoneId,
    /// The forward name.
    pub name: DnsName,
    /// The DHCID of the client at the name.
    pub dhcid: Vec<u8>,
    /// Whether the server writes the A record and the DHCID.
    pub write_a: bool,
    /// The reverse zone and the PTR name, when a PTR is written.
    pub reverse: Option<(ZoneId, DnsName)>,
    /// The TTL of the records.
    pub ttl: u32,
}

/// Why a lease gets no names, as the outcome counts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    /// Nothing to write and nothing wrong: DDNS off, no name, IPAM manages the address.
    Quiet(Option<String>),
    /// A refusal the lease shows.
    Refused(String),
}

/// The names a lease should have, or why it has none. `ipam_named` says whether IPAM
/// names the address (a host with a DNS name: the DNS actuator writes its records).
///
/// # Errors
///
/// [`Skip`] when the lease gets no names: quietly, or refused with the reason it shows.
pub fn desired(
    lease: &LeaseNames<'_>,
    zones: &Zones,
    profile: DdnsProfile,
    ipam_named: bool,
) -> Result<Desired, Skip> {
    let policy = lease.policy;
    if !policy.enabled {
        return Err(Skip::Quiet(None));
    }
    if ipam_named {
        return Err(Skip::Quiet(Some(
            "IPAM manages the names of this address".to_owned(),
        )));
    }
    let zone = match policy.forward_zone {
        Some(id) => zones.get(id).ok_or_else(|| {
            Skip::Refused(format!(
                "the scope's forward zone {id} is not a primary zone Tenko serves"
            ))
        })?,
        None => lease
            .domain
            .as_ref()
            .and_then(|domain| zones.by_name(domain))
            .ok_or_else(|| {
                Skip::Quiet(Some(
                    "the scope names no forward zone Tenko serves".to_owned(),
                ))
            })?,
    };
    if !zone.update.dhcp_allowed(profile.allows_by_default) {
        return Err(Skip::Refused(format!(
            "the zone {} does not allow DHCP updates",
            zone.name
        )));
    }
    let name = match names::forward_name(lease.fqdn, lease.hostname, policy, &zone.name) {
        Ok(name) => name,
        Err(NameRefusal::NoName) => return Err(Skip::Quiet(None)),
        Err(refusal) => return Err(Skip::Refused(refusal.to_string())),
    };
    let reverse = if policy.reverse {
        zones
            .reverse_for(lease.addr)
            .filter(|(zone, _)| zone.update.dhcp_allowed(profile.allows_by_default))
            .map(|(zone, name)| (zone.id, name))
    } else {
        None
    };
    let ttl = policy.ttl.unwrap_or(lease.lease_secs / 3).max(1);
    Ok(Desired {
        zone: zone.id,
        dhcid: dhcid::dhcid(lease.client, &name),
        name,
        write_a: flags::server_writes_a(policy, lease.fqdn_flags),
        reverse,
        ttl,
    })
}

/// The names a lease wrote, as the worker remembers them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Written {
    /// The forward name (A and DHCID).
    pub forward: Option<DnsName>,
    /// The PTR name.
    pub reverse: Option<DnsName>,
    /// The DHCID at the forward name.
    pub dhcid: Option<Vec<u8>>,
}

/// The changes of one batch, by zone, with what each lease asked for.
#[derive(Debug, Default)]
pub struct Planner {
    /// What earlier requests of the batch did to a name: claimed with a DHCID, or removed.
    overlay: HashMap<(ZoneId, DnsName), Option<Vec<u8>>>,
}

/// The changes of one lease in one zone.
#[derive(Debug, Clone)]
pub struct ZoneChanges {
    /// The zone.
    pub zone: ZoneId,
    /// The changes, in order.
    pub changes: Vec<Change>,
}

/// The plan of one lease: changes per zone, the names it will hold when they apply, and
/// the refusal it shows.
#[derive(Debug, Clone, Default)]
pub struct LeasePlan {
    /// Removal changes, per zone.
    pub remove: Vec<ZoneChanges>,
    /// The forward changes (A and DHCID).
    pub forward: Option<ZoneChanges>,
    /// The PTR changes.
    pub reverse: Option<ZoneChanges>,
    /// What the lease holds once every change applied.
    pub holds: Written,
    /// What was refused, in English.
    pub refusal: Option<String>,
    /// Whether the plan removes names.
    pub removes: bool,
}

fn rrset(
    view: &dyn ReadView,
    zone: ZoneId,
    name: &DnsName,
    rtype: Rtype,
) -> Result<Option<RrSet>, StoreError> {
    let key = RrSetKey {
        zone,
        scope: ScopeName::DEFAULT,
        name: name.clone(),
        rtype,
    };
    Ok(view.get_typed(&RRSETS, &key)?.map(|(set, _)| set))
}

fn change(
    op: Op,
    name: &DnsName,
    rtype: Rtype,
    ttl: Option<u32>,
    records: Vec<RecordData>,
) -> Change {
    Change {
        op,
        scope: ScopeName::DEFAULT,
        name: name.clone(),
        rtype,
        ttl,
        records,
        take_over: false,
        origin: Origin::Dhcp,
    }
}

fn dhcid_record(data: &[u8]) -> RecordData {
    RecordData::Unknown {
        rtype: DHCID,
        data: HexBytes(data.to_vec()),
    }
}

fn holds(set: &RrSet, record: &RecordData) -> bool {
    let rdata = Rdata::from_data(record);
    set.rdata.contains(&rdata)
}

fn origin_name(origin: Origin) -> &'static str {
    tenko_dns::zone::records::origin_name(origin)
}

/// Whether DHCP may take over `existing` in `zone`: only `ipam` sets, where the zone
/// allows dynamic writers to replace them.
fn may_take_ipam(existing: Origin, zone: &Zone) -> bool {
    existing == Origin::Ipam && Origin::Dhcp.may_replace(Origin::Ipam, &zone.update)
}

impl Planner {
    /// A planner for one batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the DHCID at `name` is `dhcid`, counting the batch's earlier changes.
    fn dhcid_is(
        &self,
        view: &dyn ReadView,
        zone: ZoneId,
        name: &DnsName,
        dhcid: &[u8],
    ) -> Result<Option<bool>, StoreError> {
        if let Some(claimed) = self.overlay.get(&(zone, name.clone())) {
            return Ok(claimed.as_ref().map(|held| held == dhcid));
        }
        Ok(rrset(view, zone, name, DHCID)?
            .map(|set| set.origin == Origin::Dhcp && holds(&set, &dhcid_record(dhcid))))
    }

    /// The changes that remove what a lease at `addr` wrote.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn remove(
        &mut self,
        view: &dyn ReadView,
        zones: &Zones,
        addr: Ipv4Addr,
        written: &Written,
    ) -> Result<Vec<ZoneChanges>, StoreError> {
        let mut out = Vec::new();
        if let (Some(name), Some(dhcid)) = (&written.forward, &written.dhcid)
            && let Some(zone) = zones.holding(name)
            && self.dhcid_is(view, zone.id, name, dhcid)? == Some(true)
        {
            let a = RecordData::A { address: addr };
            let removed = self
                .overlay
                .get(&(zone.id, name.clone()))
                .is_some_and(Option::is_none);
            let set = if removed {
                None
            } else {
                rrset(view, zone.id, name, Rtype::A)?
            };
            let mut changes = Vec::new();
            match set {
                Some(set) if set.origin == Origin::Dhcp && holds(&set, &a) => {
                    if set.rdata.len() == 1 {
                        changes.push(change(Op::Delete, name, Rtype::A, None, Vec::new()));
                        changes.push(change(Op::Delete, name, DHCID, None, Vec::new()));
                    } else {
                        changes.push(change(Op::Remove, name, Rtype::A, None, vec![a]));
                    }
                }
                Some(_) => {}
                None => changes.push(change(Op::Delete, name, DHCID, None, Vec::new())),
            }
            if changes.iter().any(|c| c.rtype == DHCID) {
                self.overlay.insert((zone.id, name.clone()), None);
            }
            if !changes.is_empty() {
                out.push(ZoneChanges {
                    zone: zone.id,
                    changes,
                });
            }
        }
        if let Some(ptr) = &written.reverse
            && let Some(zone) = zones.holding(ptr)
            && let Some(set) = rrset(view, zone.id, ptr, Rtype::PTR)?
            && set.origin == Origin::Dhcp
        {
            let points_home = written.forward.as_ref().is_none_or(|target| {
                holds(
                    &set,
                    &RecordData::Ptr {
                        target: target.clone(),
                    },
                )
            });
            if points_home {
                let changes = vec![change(Op::Delete, ptr, Rtype::PTR, None, Vec::new())];
                match out.iter_mut().find(|zc| zc.zone == zone.id) {
                    Some(zc) => zc.changes.extend(changes),
                    None => out.push(ZoneChanges {
                        zone: zone.id,
                        changes,
                    }),
                }
            }
        }
        Ok(out)
    }

    /// The changes that give a lease at `addr` the names of `desired`. `conflict` is the
    /// scope's rule (already forced to `protect` under Hardened).
    ///
    /// # Errors
    ///
    /// The store's error.
    #[allow(
        clippy::too_many_lines,
        reason = "the rows of the conflict table, forward then reverse, read top to bottom"
    )]
    pub fn add(
        &mut self,
        view: &dyn ReadView,
        zones: &Zones,
        addr: Ipv4Addr,
        desired: &Desired,
        conflict: DdnsConflict,
    ) -> Result<LeasePlan, StoreError> {
        let mut plan = LeasePlan::default();
        let Some(zone) = zones.get(desired.zone) else {
            plan.refusal = Some("the forward zone is gone".to_owned());
            return Ok(plan);
        };
        let name = &desired.name;
        let key = (zone.id, name.clone());
        let removed = self.overlay.get(&key).is_some_and(Option::is_none);
        let read = |rtype| -> Result<Option<RrSet>, StoreError> {
            if removed && (rtype == Rtype::A || rtype == DHCID) {
                return Ok(None);
            }
            rrset(view, zone.id, name, rtype)
        };
        if let Some(cname) = read(Rtype::CNAME)? {
            plan.refusal = Some(format!(
                "{name} is an alias (CNAME of the origin {})",
                origin_name(cname.origin)
            ));
            return Ok(plan);
        }
        if desired.write_a {
            let a = read(Rtype::A)?;
            let ours = self.dhcid_is(view, zone.id, name, &desired.dhcid)?;
            let mut take_over = false;
            match a.as_ref().map(|set| set.origin) {
                None | Some(Origin::Dhcp) => {
                    // A DHCID that is not the client's, or a `dhcp` A without one,
                    // belongs to another client.
                    let foreign = match ours {
                        Some(mine) => !mine,
                        None => a.is_some(),
                    };
                    if foreign && conflict == DdnsConflict::Protect {
                        plan.refusal = Some(format!(
                            "name protection: {name} belongs to another client (RFC 4703)"
                        ));
                        return Ok(plan);
                    }
                }
                Some(origin) if may_take_ipam(origin, zone) => take_over = true,
                Some(Origin::Ipam) => {
                    plan.refusal = Some(format!(
                        "IPAM manages {name}, and the zone does not let DHCP replace it"
                    ));
                    return Ok(plan);
                }
                Some(origin) => {
                    plan.refusal = Some(format!(
                        "{name} belongs to the origin {}",
                        origin_name(origin)
                    ));
                    return Ok(plan);
                }
            }
            if let Some(set) = read(DHCID)?
                && set.origin != Origin::Dhcp
            {
                plan.refusal = Some(format!(
                    "the DHCID at {name} belongs to the origin {}",
                    origin_name(set.origin)
                ));
                return Ok(plan);
            }
            let mut a_set = change(
                Op::Set,
                name,
                Rtype::A,
                Some(desired.ttl),
                vec![RecordData::A { address: addr }],
            );
            a_set.take_over = take_over;
            let dhcid_set = change(
                Op::Set,
                name,
                DHCID,
                Some(desired.ttl),
                vec![dhcid_record(&desired.dhcid)],
            );
            plan.forward = Some(ZoneChanges {
                zone: zone.id,
                changes: vec![a_set, dhcid_set],
            });
            plan.holds.forward = Some(name.clone());
            plan.holds.dhcid = Some(desired.dhcid.clone());
            self.overlay.insert(key, Some(desired.dhcid.clone()));
        }
        if let Some((reverse, ptr)) = &desired.reverse
            && let Some(rzone) = zones.get(*reverse)
        {
            let existing = rrset(view, rzone.id, ptr, Rtype::PTR)?;
            let take_over = match existing.as_ref().map(|set| set.origin) {
                None | Some(Origin::Dhcp) => Some(false),
                Some(origin) if may_take_ipam(origin, rzone) => Some(true),
                Some(origin) => {
                    plan.refusal = Some(format!(
                        "the PTR {ptr} belongs to the origin {}",
                        origin_name(origin)
                    ));
                    None
                }
            };
            if let Some(take_over) = take_over {
                let mut set = change(
                    Op::Set,
                    ptr,
                    Rtype::PTR,
                    Some(desired.ttl),
                    vec![RecordData::Ptr {
                        target: name.clone(),
                    }],
                );
                set.take_over = take_over;
                plan.reverse = Some(ZoneChanges {
                    zone: rzone.id,
                    changes: vec![set],
                });
                plan.holds.reverse = Some(ptr.clone());
            }
        }
        Ok(plan)
    }
}
