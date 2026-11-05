//! What a DDNS request changes in the zones (plan section 2.9, ADR 0020 points 2 to 4):
//! the RFC 4703 conflict rules over the RRsets as the store holds them, planned without
//! writing.
//!
//! **Adding names.** At the forward name the server writes the A RRset and the DHCID
//! RRset (unless the client writes its A record itself, [`super::flags`]); in the reverse
//! zone Tenko keeps for the address, the PTR RRset. A name is one owner's whatever the
//! types of its records (RFC 4703 section 5): the planner reads every RRset at the
//! forward name, and the rows below apply to each of them, the DHCID aside. Who may
//! replace what:
//!
//! | RRset there | Forward (A and DHCID) | PTR |
//! |---|---|---|
//! | none | written | written |
//! | `dhcp`, the DHCID matches the client | replaced | replaced |
//! | `dhcp`, another client's DHCID (or none), of any type | refused (`protect`); taken over (`replace`, not under Hardened), the other client's records of other types deleted | replaced: the address is this lease's |
//! | `ipam`, of any type | taken over only where the zone allows it (`Origin::may_replace`, `may_replace_ipam`), else refused | the same |
//! | `manual`, `dynamic`, `transfer`, `dnssec`, `ad`, of any type | refused | refused |
//! | a CNAME at the name | refused | refused |
//! | a name IPAM gives an address, at any address | refused, unless the zone lets DHCP replace `ipam` data | the same |
//!
//! A refused forward name gets no PTR either. Names the lease held before (another name,
//! another client at the address) are removed first, by the removal rules. The zone
//! service checks the same rule once more at the write
//! ([`tenko_dns::zone::records`]): a `dhcp` change adds nothing at a name that holds data
//! of another origin unless a `dhcp` DHCID already stands there.
//!
//! **Removing names** (release, expiry, a new name, a new client): the A record of the
//! address goes, and the DHCID with it when no other address is left in the set, but only
//! while the DHCID at the name is still the client's; the PTR goes when it is a `dhcp` PTR
//! that points at the lease's forward name. Records of another origin are never touched.
//!
//! **Both families** (WP9.1). A DHCPv6 lease writes an AAAA record where a DHCPv4 lease
//! writes an A record, by the same rules, with the DHCID of its DUID (identifier type 2,
//! RFC 4701 section 3.3) and the PTR under `ip6.arpa`. A client whose DHCPv4 and DHCPv6
//! identities give the same DHCID (a DHCPv4 client that sends its DUID, RFC 4361) holds
//! one name for both; the DHCID goes with the last address record of either family.
//!
//! **Zones.** Only primary zones Tenko serves. The forward zone is the scope's (its
//! `forward_zone`, else the zone of the scope's domain name, option 15); the reverse zone
//! is the most specific primary zone whose apex is a reverse zone covering the address
//! (`tenko_ipam::dns::reverse`, RFC 2317 zones included). A zone takes DHCP updates only
//! where its update policy allows them ([`UpdatePolicy::dhcp_allowed`] with the profile's
//! default). A name is written into the zone that holds it: a name below the forward
//! zone's apex that lies in a child zone Tenko serves, or below a delegation (an NS set
//! between the name and the apex), is not the forward zone's and counts as a name outside
//! the zone (cut to its first label under the forward zone, or refused with
//! `refuse_foreign`). Removal looks for the client's DHCID in the zone that holds the
//! name first, then in the zones above it.
//!
//! [`UpdatePolicy::dhcp_allowed`]: tenko_core::dns::UpdatePolicy::dhcp_allowed

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
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
    records::{Change, Op, node_rrsets},
};
use tenko_ipam::{
    dns::reverse::{ReverseZone, classless_ptr_name, parse_zone, ptr_name},
    tables::ADDRESSES,
};
use tenko_store::{KeyRange, ReadView, ReadViewExt as _, StoreError};

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
        self.enclosing(name).next()
    }

    /// The zones that hold `name`, the most specific first.
    pub fn enclosing(&self, name: &DnsName) -> impl Iterator<Item = &Zone> {
        let mut zones: Vec<&Zone> = self
            .zones
            .iter()
            .filter(|zone| name.is_subdomain_of(&zone.name))
            .collect();
        zones.sort_by_key(|zone| std::cmp::Reverse(zone.name.label_count()));
        zones.into_iter()
    }

    /// The most specific reverse zone that covers `addr`, and the PTR name in it (an
    /// `in-addr.arpa` zone, RFC 2317 ones included, or an `ip6.arpa` zone).
    pub fn reverse_for(&self, addr: IpAddr) -> Option<(&Zone, DnsName)> {
        self.zones
            .iter()
            .filter_map(|zone| {
                let reverse = parse_zone(&zone.name)?;
                reverse.net().contains(&addr).then_some((zone, reverse))
            })
            .max_by_key(|(_, reverse)| reverse.net().prefix_len())
            .map(|(zone, reverse)| {
                let name = match (reverse, addr) {
                    (ReverseZone::Classless { name, .. }, IpAddr::V4(v4)) => {
                        classless_ptr_name(v4, &name)
                    }
                    _ => ptr_name(addr),
                };
                (zone, name)
            })
    }
}

/// One lease as the planner sees it.
#[derive(Debug, Clone)]
pub struct LeaseNames<'a> {
    /// The address: an A record for IPv4, AAAA for IPv6.
    pub addr: IpAddr,
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
    /// The store could not be read; the lease is tried again.
    Failed(String),
}

/// The delegation of `zone` that covers `name`: the owner of an NS set between the name
/// and the apex, both excluded (an NS set at the name itself is data of another origin
/// there, which [`Planner::add`] refuses).
fn delegation_above(
    view: &dyn ReadView,
    zone: &Zone,
    name: &DnsName,
) -> Result<Option<DnsName>, StoreError> {
    let mut current = name.parent();
    while let Some(owner) = current {
        if owner == zone.name || !owner.is_subdomain_of(&zone.name) {
            return Ok(None);
        }
        if rrset(view, zone.id, &owner, Rtype::NS)?.is_some() {
            return Ok(Some(owner));
        }
        current = owner.parent();
    }
    Ok(None)
}

/// Why `name`, below the apex of `zone`, is not the zone's to write: it lies in a child
/// zone Tenko serves, or below a delegation of the zone.
fn outside(
    view: &dyn ReadView,
    zones: &Zones,
    zone: &Zone,
    name: &DnsName,
) -> Result<Option<NameRefusal>, StoreError> {
    if let Some(holder) = zones.holding(name)
        && holder.id != zone.id
    {
        return Ok(Some(NameRefusal::OtherZone(
            name.as_str().to_owned(),
            holder.name.as_str().to_owned(),
        )));
    }
    Ok(delegation_above(view, zone, name)?
        .map(|cut| NameRefusal::Delegated(name.as_str().to_owned(), cut.as_str().to_owned())))
}

/// `name` held to the authority of `zone` (ADR 0020 points 3 and 6): a name that another
/// zone holds or that lies below a delegation is outside the forward zone, cut to its
/// first label under the zone (when that name is the zone's), or refused when the scope
/// says `refuse_foreign`.
fn in_authority(
    view: &dyn ReadView,
    zones: &Zones,
    zone: &Zone,
    policy: &DdnsPolicy,
    name: DnsName,
) -> Result<DnsName, Skip> {
    let failed = |error: StoreError| Skip::Failed(error.to_string());
    let Some(reason) = outside(view, zones, zone, &name).map_err(failed)? else {
        return Ok(name);
    };
    if !policy.refuse_foreign
        && let Some(label) = name.labels().next()
        && let Ok(cut) = names::under(&zone.name, label)
        && cut != name
        && outside(view, zones, zone, &cut).map_err(failed)?.is_none()
    {
        return Ok(cut);
    }
    Err(Skip::Refused(reason.to_string()))
}

/// The names a lease should have, or why it has none. `ipam_named` says whether IPAM
/// names the address (a host with a DNS name: the DNS actuator writes its records).
///
/// # Errors
///
/// [`Skip`] when the lease gets no names: quietly, refused with the reason it shows, or
/// failed when the store could not be read.
pub fn desired(
    view: &dyn ReadView,
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
    let name = in_authority(view, zones, zone, policy, name)?;
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
    /// The names IPAM gives its addresses, read once per batch when a name is first
    /// checked.
    ipam_names: Option<HashSet<DnsName>>,
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

// WP9.1: the address record of either family.
/// The address record of `addr` and its type.
fn address_record(addr: IpAddr) -> (Rtype, RecordData) {
    match addr {
        IpAddr::V4(address) => (Rtype::A, RecordData::A { address }),
        IpAddr::V6(address) => (Rtype::AAAA, RecordData::Aaaa { address }),
    }
}

/// The address record type of the other family.
fn other_family(rtype: Rtype) -> Rtype {
    if rtype == Rtype::A {
        Rtype::AAAA
    } else {
        Rtype::A
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

    /// Whether IPAM gives `name` to one of its addresses (an address object with that DNS
    /// name, at any address): the DNS actuator writes the name's records with the origin
    /// `ipam`, and the name is not a client's to take. The address objects are read once
    /// per batch.
    fn ipam_names(&mut self, view: &dyn ReadView, name: &DnsName) -> Result<bool, StoreError> {
        if self.ipam_names.is_none() {
            let names = view
                .scan_typed(&ADDRESSES, KeyRange::all(), usize::MAX, false)?
                .into_iter()
                .filter_map(|(_, address, _)| address.dns_name.as_ref().map(DnsName::from))
                .collect();
            self.ipam_names = Some(names);
        }
        Ok(self
            .ipam_names
            .get_or_insert_with(HashSet::new)
            .contains(name))
    }

    /// The zone that holds the client's DHCID at `name`: the most specific zone that holds
    /// the name first, then the zones above it (a name an earlier version wrote into a
    /// parent zone is still found and removed there).
    fn holder<'z>(
        &self,
        view: &dyn ReadView,
        zones: &'z Zones,
        name: &DnsName,
        dhcid: &[u8],
    ) -> Result<Option<&'z Zone>, StoreError> {
        for zone in zones.enclosing(name) {
            if self.dhcid_is(view, zone.id, name, dhcid)? == Some(true) {
                return Ok(Some(zone));
            }
        }
        Ok(None)
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
        addr: IpAddr,
        written: &Written,
    ) -> Result<Vec<ZoneChanges>, StoreError> {
        let mut out = Vec::new();
        if let (Some(name), Some(dhcid)) = (&written.forward, &written.dhcid)
            && let Some(zone) = self.holder(view, zones, name, dhcid)?
        {
            let (rtype, a) = address_record(addr);
            let removed = self
                .overlay
                .get(&(zone.id, name.clone()))
                .is_some_and(Option::is_none);
            let set = if removed {
                None
            } else {
                rrset(view, zone.id, name, rtype)?
            };
            // WP9.1: the DHCID stays while the client's records of the other family do.
            let other = if removed {
                None
            } else {
                rrset(view, zone.id, name, other_family(rtype))?
                    .filter(|set| set.origin == Origin::Dhcp)
            };
            let mut changes = Vec::new();
            match set {
                Some(set) if set.origin == Origin::Dhcp && holds(&set, &a) => {
                    if set.rdata.len() == 1 {
                        changes.push(change(Op::Delete, name, rtype, None, Vec::new()));
                        if other.is_none() {
                            changes.push(change(Op::Delete, name, DHCID, None, Vec::new()));
                        }
                    } else {
                        changes.push(change(Op::Remove, name, rtype, None, vec![a]));
                    }
                }
                None if other.is_none() => {
                    changes.push(change(Op::Delete, name, DHCID, None, Vec::new()));
                }
                Some(_) | None => {}
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
        addr: IpAddr,
        desired: &Desired,
        conflict: DdnsConflict,
    ) -> Result<LeasePlan, StoreError> {
        // WP9.1: A for an IPv4 lease, AAAA for an IPv6 one.
        let (address_type, address) = address_record(addr);
        let mut plan = LeasePlan::default();
        let Some(zone) = zones.get(desired.zone) else {
            plan.refusal = Some("the forward zone is gone".to_owned());
            return Ok(plan);
        };
        let name = &desired.name;
        let key = (zone.id, name.clone());
        // A removal earlier in the batch that took the DHCID took every `dhcp` record of
        // the name with it.
        let removed = self.overlay.get(&key).is_some_and(Option::is_none);
        let node: Vec<RrSet> = node_rrsets(view, zone.id, &ScopeName::DEFAULT, name)?
            .into_iter()
            .filter(|set| !(removed && set.origin == Origin::Dhcp))
            .collect();
        if let Some(cname) = node.iter().find(|set| set.rtype == Rtype::CNAME) {
            plan.refusal = Some(format!(
                "{name} is an alias (CNAME of the origin {})",
                origin_name(cname.origin)
            ));
            return Ok(plan);
        }
        if desired.write_a {
            if let Some(set) = node.iter().find(|set| set.rtype == DHCID)
                && set.origin != Origin::Dhcp
            {
                plan.refusal = Some(format!(
                    "the DHCID at {name} belongs to the origin {}",
                    origin_name(set.origin)
                ));
                return Ok(plan);
            }
            let ours = self.dhcid_is(view, zone.id, name, &desired.dhcid)?;
            // A DHCID that is not the client's (in the store, or claimed earlier in the
            // batch), or `dhcp` data of any type without one, belongs to another client.
            let foreign = match ours {
                Some(mine) => !mine,
                None => node
                    .iter()
                    .any(|set| set.origin == Origin::Dhcp && set.rtype != DHCID),
            };
            if foreign && conflict == DdnsConflict::Protect {
                plan.refusal = Some(format!(
                    "name protection: {name} belongs to another client (RFC 4703)"
                ));
                return Ok(plan);
            }
            let mut take_over = false;
            // Under `replace`, the other client's records of other types at the name.
            let mut displaced = Vec::new();
            // The name is one owner's whatever the types of its records (RFC 4703
            // section 5): every RRset at the name but the DHCID says who holds it.
            for set in node.iter().filter(|set| set.rtype != DHCID) {
                match set.origin {
                    Origin::Dhcp => {
                        if foreign && set.rtype != address_type {
                            displaced.push(change(Op::Delete, name, set.rtype, None, Vec::new()));
                        }
                    }
                    // The name is the client's (its DHCID stands there): data of another
                    // origin beside its records is not its to touch, and stops it only
                    // when it holds the type of its own record.
                    _ if ours == Some(true) && set.rtype != address_type => {}
                    origin if may_take_ipam(origin, zone) => {
                        take_over |= set.rtype == address_type;
                    }
                    Origin::Ipam => {
                        plan.refusal = Some(format!(
                            "IPAM manages {name}, and the zone does not let DHCP replace it"
                        ));
                        return Ok(plan);
                    }
                    origin => {
                        plan.refusal = Some(format!(
                            "{name} holds {} records of the origin {}",
                            set.rtype,
                            origin_name(origin)
                        ));
                        return Ok(plan);
                    }
                }
            }
            // A name IPAM gives one of its addresses is IPAM's to write, at whatever
            // address, before and after the DNS actuator wrote its records.
            if !may_take_ipam(Origin::Ipam, zone) && self.ipam_names(view, name)? {
                plan.refusal = Some(format!(
                    "IPAM manages {name}, and the zone does not let DHCP replace it"
                ));
                return Ok(plan);
            }
            let mut a_set = change(
                Op::Set,
                name,
                address_type,
                Some(desired.ttl),
                vec![address],
            );
            a_set.take_over = take_over;
            let dhcid_set = change(
                Op::Set,
                name,
                DHCID,
                Some(desired.ttl),
                vec![dhcid_record(&desired.dhcid)],
            );
            let mut changes = displaced;
            changes.push(a_set);
            changes.push(dhcid_set);
            plan.forward = Some(ZoneChanges {
                zone: zone.id,
                changes,
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tenko_core::{
        Principal, RequestCtx, SystemComponent,
        dns::{SerialPolicy, SoaDefaults, UpdatePolicy},
    };
    use tenko_dns::zone::{NewZone, ZoneConfig};
    use tenko_store::{MemStore, ReadConsistency, Store};

    use super::*;

    fn name(text: &str) -> DnsName {
        DnsName::new(text).expect("name")
    }

    fn cx() -> RequestCtx {
        RequestCtx::new(Principal::system(SystemComponent::Api))
    }

    fn new_zone(apex: &str) -> NewZone {
        NewZone {
            name: name(apex),
            kind: ZoneKind::Primary,
            tenant: None,
            scopes: Vec::new(),
            serial: SerialPolicy::Counter,
            soa: SoaDefaults::new(name("ns1.example.test"), name("hostmaster.example.test")),
            name_servers: vec![name("ns1.example.test")],
            transfer: tenko_core::dns::TransferPolicy::default(),
            update: UpdatePolicy::default(),
            dnssec: tenko_core::dns::DnssecPolicy::default(),
            source: None,
            description: None,
            reverse_of: None,
            catalog: false,
        }
    }

    fn record(owner: &str, origin: Origin, data: RecordData) -> Change {
        Change {
            op: Op::Set,
            scope: ScopeName::DEFAULT,
            name: name(owner),
            rtype: data.rtype(),
            ttl: Some(300),
            records: vec![data],
            take_over: false,
            origin,
        }
    }

    fn a(last: u8) -> RecordData {
        RecordData::A {
            address: std::net::Ipv4Addr::new(192, 0, 2, last),
        }
    }

    fn aaaa(last: u16) -> RecordData {
        RecordData::Aaaa {
            address: std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last),
        }
    }

    fn client(last: u8) -> ClientKey {
        ClientKey {
            htype: 1,
            chaddr: HexBytes(vec![0x00, 0x00, 0x5e, 0x00, 0x53, last]),
            client_id: None,
        }
    }

    fn wants(zone: ZoneId, owner: &str, dhcid: &[u8]) -> Desired {
        Desired {
            zone,
            name: name(owner),
            dhcid: dhcid.to_vec(),
            write_a: true,
            reverse: None,
            ttl: 300,
        }
    }

    /// A lab with the forward zone and the zones of `more`, and the service to write into
    /// them.
    struct Lab {
        store: Arc<dyn Store>,
        service: Arc<ZoneService>,
        forward: Zone,
    }

    impl Lab {
        async fn new() -> Self {
            let store: Arc<dyn Store> = Arc::new(MemStore::default());
            let service =
                ZoneService::with_direct_jobs(Arc::clone(&store), None, ZoneConfig::default());
            let forward = service
                .create(&cx(), new_zone("lan.example.test"))
                .await
                .expect("the forward zone")
                .zone;
            Self {
                store,
                service,
                forward,
            }
        }

        async fn create(&self, apex: &str) -> Zone {
            self.service
                .create(&cx(), new_zone(apex))
                .await
                .expect("zone")
                .zone
        }

        async fn write(&self, zone: ZoneId, changes: &[Change]) {
            self.service
                .change_records(&cx(), zone, changes, false)
                .await
                .expect("the records");
        }

        async fn view(&self) -> Arc<dyn ReadView> {
            self.store.read(ReadConsistency::Local).await.expect("view")
        }

        fn zones(&self) -> Zones {
            Zones::from_zones(vec![self.forward.clone()])
        }
    }

    fn refusal(plan: &LeasePlan) -> &str {
        plan.refusal.as_deref().unwrap_or("")
    }

    /// RFC 4703 section 5, ADR 0020 point 2: records of another origin at the name, of
    /// any type and either family, refuse the claim; `ipam` data gives way only where the
    /// zone lets DHCP replace it, and a name IPAM gives one of its addresses is refused
    /// before the actuator wrote anything.
    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the claims against each origin, read top to bottom"
    )]
    async fn data_of_another_origin_of_any_type_refuses_the_claim() {
        let lab = Lab::new().await;
        lab.write(
            lab.forward.id,
            &[
                record("nas.lan.example.test", Origin::Manual, a(9)),
                record("cam.lan.example.test", Origin::Manual, aaaa(9)),
                record(
                    "info.lan.example.test",
                    Origin::Manual,
                    RecordData::Txt {
                        strings: vec![tenko_core::dns::TextBytes(b"owner=ops".to_vec())],
                    },
                ),
                record("files.lan.example.test", Origin::Ipam, a(8)),
            ],
        )
        .await;
        let view = lab.view().await;
        let zones = lab.zones();
        let v4 = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 50));
        let v6 = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x50));
        let claim = |owner: &str, addr: IpAddr| {
            Planner::new().add(
                view.as_ref(),
                &zones,
                addr,
                &wants(lab.forward.id, owner, b"\x00\x02\x01\x01"),
                DdnsConflict::Replace,
            )
        };
        let plan = claim("nas.lan.example.test", v6).expect("plan");
        assert!(refusal(&plan).contains("holds A records of the origin manual"));
        assert!(plan.forward.is_none());
        let plan = claim("cam.lan.example.test", v4).expect("plan");
        assert!(refusal(&plan).contains("holds AAAA records of the origin manual"));
        let plan = claim("info.lan.example.test", v4).expect("plan");
        assert!(refusal(&plan).contains("holds TXT records of the origin manual"));
        let plan = claim("files.lan.example.test", v6).expect("plan");
        assert!(refusal(&plan).contains("IPAM manages files.lan.example.test"));

        // Where the zone lets DHCP replace ipam data, the AAAA goes beside the ipam A.
        let lenient = lab
            .service
            .update(
                &cx(),
                lab.forward.id,
                tenko_dns::zone::ZoneChange {
                    update: Some(UpdatePolicy {
                        may_replace_ipam: true,
                        ..UpdatePolicy::default()
                    }),
                    ..tenko_dns::zone::ZoneChange::default()
                },
                None,
            )
            .await
            .expect("the zone's policy")
            .zone;
        assert!(lenient.update.may_replace_ipam);
        let zones = Zones::from_zones(vec![lenient.clone()]);
        let plan = Planner::new()
            .add(
                view.as_ref(),
                &zones,
                v6,
                &wants(lenient.id, "files.lan.example.test", b"\x00\x02\x01\x01"),
                DdnsConflict::Protect,
            )
            .expect("plan");
        assert_eq!(plan.refusal, None);
        let forward = plan.forward.expect("the forward changes");
        assert_eq!(
            forward
                .changes
                .iter()
                .map(|change| (change.rtype, change.take_over))
                .collect::<Vec<_>>(),
            vec![(Rtype::AAAA, false), (DHCID, false)]
        );
        lab.write(lenient.id, &forward.changes).await;
    }

    /// Another client is refused under `protect` and, under `replace`, takes the name
    /// over with the records of both families; the holder of a name keeps updating it with
    /// its own DHCID, in either family and beside data an operator added later, which no
    /// client takes over.
    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one name through a take-over and the holder's updates"
    )]
    async fn the_holder_updates_and_replace_moves_the_name_across_families() {
        let lab = Lab::new().await;
        let owner = "phone.lan.example.test";
        let v4 = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 50));
        let v6 = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x50));
        let first = dhcid::dhcid(&client(1), &name(owner));
        let second = dhcid::dhcid(&client(2), &name(owner));
        let zones = lab.zones();
        let ops = |changes: &ZoneChanges| {
            changes
                .changes
                .iter()
                .map(|change| (change.op, change.rtype))
                .collect::<Vec<_>>()
        };
        let plan = Planner::new()
            .add(
                lab.view().await.as_ref(),
                &zones,
                v6,
                &wants(lab.forward.id, owner, &first),
                DdnsConflict::Protect,
            )
            .expect("plan");
        let forward = plan.forward.expect("the first claim");
        lab.write(lab.forward.id, &forward.changes).await;

        // Another client: refused under `protect`; under `replace` the name moves with
        // the first client's AAAA record.
        let view = lab.view().await;
        let plan = Planner::new()
            .add(
                view.as_ref(),
                &zones,
                v4,
                &wants(lab.forward.id, owner, &second),
                DdnsConflict::Protect,
            )
            .expect("plan");
        assert!(refusal(&plan).contains("name protection"));
        let plan = Planner::new()
            .add(
                view.as_ref(),
                &zones,
                v4,
                &wants(lab.forward.id, owner, &second),
                DdnsConflict::Replace,
            )
            .expect("plan");
        assert_eq!(plan.refusal, None);
        let forward = plan.forward.expect("the take-over");
        assert_eq!(
            ops(&forward),
            vec![
                (Op::Delete, Rtype::AAAA),
                (Op::Set, Rtype::A),
                (Op::Set, DHCID)
            ]
        );
        lab.write(lab.forward.id, &forward.changes).await;
        let view = lab.view().await;
        assert!(
            rrset(view.as_ref(), lab.forward.id, &name(owner), Rtype::AAAA)
                .expect("read")
                .is_none()
        );

        // An operator adds a TXT beside the holder's records: the holder's DHCPv6 side,
        // with the same DHCID (RFC 4361), is still written beside them.
        lab.write(
            lab.forward.id,
            &[record(
                owner,
                Origin::Manual,
                RecordData::Txt {
                    strings: vec![tenko_core::dns::TextBytes(b"asset=7".to_vec())],
                },
            )],
        )
        .await;
        let view = lab.view().await;
        let plan = Planner::new()
            .add(
                view.as_ref(),
                &zones,
                v6,
                &wants(lab.forward.id, owner, &second),
                DdnsConflict::Protect,
            )
            .expect("plan");
        assert_eq!(plan.refusal, None);
        let forward = plan.forward.expect("the holder's AAAA record");
        assert_eq!(
            ops(&forward),
            vec![(Op::Set, Rtype::AAAA), (Op::Set, DHCID)]
        );
        lab.write(lab.forward.id, &forward.changes).await;
        let view = lab.view().await;
        assert_eq!(
            rrset(view.as_ref(), lab.forward.id, &name(owner), Rtype::TXT)
                .expect("read")
                .map(|set| set.origin),
            Some(Origin::Manual),
            "the operator's record stays"
        );

        // The operator's record is nobody else's to take, `replace` or not.
        let plan = Planner::new()
            .add(
                view.as_ref(),
                &zones,
                v4,
                &wants(lab.forward.id, owner, &first),
                DdnsConflict::Replace,
            )
            .expect("plan");
        assert!(refusal(&plan).contains("holds TXT records of the origin manual"));
        assert!(plan.forward.is_none());
    }

    /// Two clients claiming one fresh name in one batch: the batch's own earlier claim
    /// counts as the DHCID at the name, so the second client is refused under `protect`
    /// and takes the name under `replace`.
    #[tokio::test]
    async fn two_claims_of_one_name_in_a_batch_are_one_clients() {
        let lab = Lab::new().await;
        let owner = "tv.lan.example.test";
        let addr = |last: u8| IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, last));
        let first = dhcid::dhcid(&client(1), &name(owner));
        let second = dhcid::dhcid(&client(2), &name(owner));
        let zones = lab.zones();
        let view = lab.view().await;
        let mut planner = Planner::new();
        let plan = planner
            .add(
                view.as_ref(),
                &zones,
                addr(50),
                &wants(lab.forward.id, owner, &first),
                DdnsConflict::Protect,
            )
            .expect("plan");
        assert_eq!(plan.refusal, None);
        assert!(plan.forward.is_some());
        let plan = planner
            .add(
                view.as_ref(),
                &zones,
                addr(51),
                &wants(lab.forward.id, owner, &second),
                DdnsConflict::Protect,
            )
            .expect("plan");
        assert!(refusal(&plan).contains("name protection"));
        assert!(plan.forward.is_none());
        let plan = planner
            .add(
                view.as_ref(),
                &zones,
                addr(51),
                &wants(lab.forward.id, owner, &second),
                DdnsConflict::Replace,
            )
            .expect("plan");
        assert_eq!(plan.refusal, None);
        assert!(plan.forward.is_some());
        // The first client, in the same batch again, is now the other one.
        let plan = planner
            .add(
                view.as_ref(),
                &zones,
                addr(50),
                &wants(lab.forward.id, owner, &first),
                DdnsConflict::Protect,
            )
            .expect("plan");
        assert!(refusal(&plan).contains("name protection"));
    }

    /// ADR 0020 points 3 and 6: a name that a child zone holds, or that lies below a
    /// delegation of the forward zone, is outside the forward zone (cut to its first
    /// label, or refused with `refuse_foreign`), and a removal finds the client's DHCID
    /// in the zone that holds the name, or above it.
    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the names of one zone, cut, refused and removed"
    )]
    async fn a_name_is_held_to_the_forward_zones_authority() {
        let lab = Lab::new().await;
        let child = lab.create("sub.lan.example.test").await;
        lab.write(
            lab.forward.id,
            &[record(
                "dl.lan.example.test",
                Origin::Manual,
                RecordData::Ns {
                    host: name("ns1.example.test"),
                },
            )],
        )
        .await;
        let zones = Zones::from_zones(vec![lab.forward.clone(), child.clone()]);
        let view = lab.view().await;
        let open = DdnsPolicy {
            enabled: true,
            forward_zone: Some(lab.forward.id),
            ..DdnsPolicy::default()
        };
        let strict = DdnsPolicy {
            refuse_foreign: true,
            ..open.clone()
        };
        let who = client(1);
        let wanted = |fqdn: &str, policy: &DdnsPolicy| {
            let lease = LeaseNames {
                addr: IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 50)),
                client: &who,
                fqdn: Some(fqdn),
                hostname: None,
                fqdn_flags: None,
                policy,
                domain: None,
                lease_secs: 3_600,
            };
            desired(view.as_ref(), &lease, &zones, DdnsProfile::HOME, false)
                .map(|want| want.name.as_str().to_owned())
        };
        assert_eq!(
            wanted("h.sub.lan.example.test", &open),
            Ok("h.lan.example.test".to_owned())
        );
        assert_eq!(
            wanted("h.sub.lan.example.test", &strict),
            Err(Skip::Refused(
                "the name h.sub.lan.example.test lies in the zone sub.lan.example.test, not in the scope's forward zone".to_owned()
            ))
        );
        // The child's apex itself cannot be cut to a name of the forward zone's.
        assert!(matches!(
            wanted("sub.lan.example.test", &open),
            Err(Skip::Refused(_))
        ));
        assert_eq!(
            wanted("h.dl.lan.example.test", &open),
            Ok("h.lan.example.test".to_owned())
        );
        assert_eq!(
            wanted("h.dl.lan.example.test", &strict),
            Err(Skip::Refused(
                "the name h.dl.lan.example.test lies below the delegation dl.lan.example.test"
                    .to_owned()
            ))
        );
        assert_eq!(
            wanted("h.lan.example.test", &strict),
            Ok("h.lan.example.test".to_owned())
        );

        // A name an earlier version wrote into the parent zone is removed from there.
        let owner = "old.sub.lan.example.test";
        let dhcid = dhcid::dhcid(&who, &name(owner));
        lab.write(
            lab.forward.id,
            &[
                record(owner, Origin::Dhcp, a(50)),
                record(owner, Origin::Dhcp, dhcid_record(&dhcid)),
            ],
        )
        .await;
        let view = lab.view().await;
        let removed = Planner::new()
            .remove(
                view.as_ref(),
                &zones,
                IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 50)),
                &Written {
                    forward: Some(name(owner)),
                    reverse: None,
                    dhcid: Some(dhcid),
                },
            )
            .expect("plan");
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].zone, lab.forward.id);
        assert_eq!(
            removed[0]
                .changes
                .iter()
                .map(|change| (change.op, change.rtype))
                .collect::<Vec<_>>(),
            vec![(Op::Delete, Rtype::A), (Op::Delete, DHCID)]
        );
    }
}
