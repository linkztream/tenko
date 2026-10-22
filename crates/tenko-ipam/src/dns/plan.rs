//! The planner (plan sections 2.5 and 2.6): from the intent and the zones in one read view
//! to the reverse zones to create or adopt, the RRset changes per zone and the findings.
//!
//! The planner is a pure function of the view; the actuator ([`super::DnsActuator`])
//! writes what it plans, the reconciler turns the findings into proposals, and the move
//! preview shows the part that concerns one device.
//!
//! # What an address gets
//!
//! An address is published when it is live, has a DNS name and is not `planned` (a move in
//! flight is the exception, see below). Its name gets an A or AAAA record in the zone
//! Tenko serves for it: the longest apex among the primary zones that the name falls
//! under, unless a delegation inside that zone covers the name. Its address gets a PTR
//! record to the name: in the RFC 2317 zone that covers it when Tenko serves one, else at
//! the plain reverse name in the longest reverse zone. Several addresses with one name give
//! one RRset with several records. A name without a zone is listed (a finding, once Tenko
//! serves any forward zone); its PTR is still written when Tenko serves the reverse zone.
//!
//! # Moves
//!
//! While a move job runs, its old address stays active and its new address is `planned`
//! until the cleanup. Once the job's automatic DNS step has started, the planner publishes
//! the new address in place of the old one, so the reconciler keeps what the step wrote;
//! when the job rolls back, its step's compensation and the planner both go back to the
//! old address.
//!
//! # Ownership
//!
//! Only RRsets of the origin `ipam` change. A wanted RRset that another origin holds with
//! other data is a finding and stays as it is; one that holds the same data is left alone.
//! An `ipam` RRset that nothing wants any more is deleted, or with the orphan rule
//! `propose` kept and listed.
//!
//! # The template of a reverse zone
//!
//! A new reverse zone copies its SOA values, serial policy and name servers from its
//! template: the longest reverse zone above it in Tenko, else the default zone of the
//! tenant (`dns.default_zone` on the tenant), else the tenant's first forward zone, else
//! one without a tenant, else the first forward zone. [`REVERSE_TEMPLATES`] keeps what a
//! reverse zone copied the last time. When the template's SOA values or name servers
//! change, or another zone becomes the template (the old one was deleted, or a default
//! zone was chosen), a reverse zone whose SOA values and name servers still equal the
//! copied ones follows in the same run; a zone that differs (an operator edited it) stays
//! as it is.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use serde::{Deserialize, Serialize};

use tenko_core::{
    AddressId, JobId, PrefixId, Revision, TenantId, VrfId,
    codec::{encode_key, from_cbor},
    dns::{
        DnsName, Origin, Rdata, RecordData, RrSet, RrSetKey, Rtype, ScopeName, SerialPolicy,
        SoaDefaults, Zone, ZoneId, ZoneKind,
        tables::{RRSETS, ZONES},
    },
    ipam::{Address, DnsReverse, Prefix, PrefixRole, Status, Tenant, Vrf},
    net::Fqdn,
    table::TableDef,
};
use tenko_jobs::{
    Job, JobState, StepState,
    tables::{BY_STATE, JOBS},
};
use tenko_store::{KeyRange, ReadView, ReadViewExt};

use super::{
    OrphanRule,
    reverse::{self, ReverseZone},
};
use crate::{
    error::IpamResult,
    moves::{MOVE_JOB, MoveStepParams, steps::DNS as DNS_STEP},
    tables::{ADDRESSES, PREFIXES, TENANTS, VRFS},
};

/// The most RRset changes in one batch (the zone service's limit).
pub const MAX_CHANGES: usize = 10_000;

// Backlog: the reverse-zone template.
/// What a reverse zone kept by IPAM copied from its template the last time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReverseTemplate {
    /// The template zone.
    pub template: ZoneId,
    /// Its apex.
    pub template_name: DnsName,
    /// The SOA values copied.
    pub soa: SoaDefaults,
    /// The name servers copied, sorted.
    pub name_servers: Vec<DnsName>,
}

/// The templates of the reverse zones, by zone (written by the actuator only).
pub static REVERSE_TEMPLATES: TableDef<ZoneId, ReverseTemplate> =
    TableDef::new("ipam.dns_reverse_templates");

/// The description of a reverse zone the actuator creates.
pub fn reverse_description(template: &DnsName) -> String {
    format!("Reverse zone kept by IPAM; SOA and name servers from {template}")
}

fn sorted(names: &[DnsName]) -> Vec<DnsName> {
    let mut names = names.to_vec();
    names.sort();
    names.dedup();
    names
}

/// Name of the default tenant.
const DEFAULT_TENANT: &str = "default";

/// A move whose DNS step has started: the planner publishes `new` instead of `old`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MoveOverride {
    /// The address that moves away.
    pub old: AddressId,
    /// The address it moves to.
    pub new: AddressId,
}

/// What the planner is told besides the view.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanOptions {
    /// What happens to an `ipam` RRset that nothing wants.
    pub orphans: OrphanRule,
    /// Moves to treat as in flight with their DNS step started, besides those the view's
    /// jobs show.
    pub moves: Vec<MoveOverride>,
    /// Move jobs whose DNS step the planner ignores (a step that undoes itself).
    pub ignore_jobs: Vec<JobId>,
}

/// A reverse zone to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneCreate {
    /// The apex.
    pub name: DnsName,
    /// The prefix it belongs to.
    pub prefix: PrefixId,
    /// The tenant of the prefix's VRF.
    pub tenant: Option<TenantId>,
    /// The serial policy, copied from the zone that lends the SOA values.
    pub serial: SerialPolicy,
    /// The SOA values, from the parent reverse zone or the tenant's forward zone.
    pub soa: SoaDefaults,
    /// The apex NS set, from the same zone.
    pub name_servers: Vec<DnsName>,
    /// The zone the SOA values and name servers come from.
    pub source: DnsName,
}

/// A reverse zone that follows its template: the SOA values and the name servers that
/// change, and the template it copied them from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneFollow {
    /// The zone.
    pub zone: ZoneId,
    /// Its apex.
    pub name: DnsName,
    /// The revision of the zone row the plan read; the update expects it.
    pub revision: Revision,
    /// The new SOA values, when they change.
    pub soa: Option<SoaDefaults>,
    /// The new name servers, when they change.
    pub name_servers: Option<Vec<DnsName>>,
    /// The origin of the apex NS set, kept by the change.
    pub ns_origin: Origin,
    /// The new description, when the zone still has the one the actuator gave it.
    pub description: Option<String>,
    /// What the zone copied after the change.
    pub stamp: ReverseTemplate,
}

/// An existing zone that becomes the reverse zone of a prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneAdopt {
    /// The zone.
    pub zone: ZoneId,
    /// Its apex.
    pub name: DnsName,
    /// The prefix.
    pub prefix: PrefixId,
}

/// The change of one RRset: `after` empty deletes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordChange {
    /// The owner.
    pub name: DnsName,
    /// The type.
    pub rtype: Rtype,
    /// The records now (empty when the RRset is new).
    pub before: Vec<RecordData>,
    /// The records after (empty to delete the RRset).
    pub after: Vec<RecordData>,
    /// The addresses behind the records after.
    pub addresses: Vec<AddressId>,
}

impl RecordChange {
    /// Whether the change deletes the RRset.
    pub fn is_delete(&self) -> bool {
        self.after.is_empty()
    }
}

/// The changes of one zone, in the order a batch applies them (per owner, deletions
/// first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneBatch {
    /// The zone.
    pub zone: ZoneId,
    /// Its apex.
    pub name: DnsName,
    /// The changes.
    pub changes: Vec<RecordChange>,
}

/// What the planner reports instead of writing (see [`super::findings`] for the rules).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsFinding {
    /// Names under no zone Tenko serves (or under a delegation inside one).
    NoZone {
        /// The names and their addresses.
        names: BTreeMap<Fqdn, Vec<AddressId>>,
    },
    /// A wanted RRset that another origin holds with other data.
    Held {
        /// The zone apex.
        zone: DnsName,
        /// The owner.
        name: DnsName,
        /// The type IPAM wants there.
        rtype: Rtype,
        /// The type that holds the name (the same type, or a CNAME, or data beside the
        /// CNAME IPAM wants).
        held_type: Rtype,
        /// Its origin.
        origin: Origin,
        /// What IPAM wants.
        wanted: Vec<RecordData>,
        /// The addresses behind it.
        addresses: Vec<AddressId>,
    },
    /// An `ipam` RRset that nothing wants (orphan rule `propose`).
    Orphaned {
        /// The zone apex.
        zone: DnsName,
        /// The owner.
        name: DnsName,
        /// The type.
        rtype: Rtype,
        /// Its records.
        records: Vec<RecordData>,
    },
    /// The RFC 2317 delegation to add in a parent zone Tenko does not serve.
    Delegation {
        /// The prefix.
        prefix: PrefixId,
        /// Its network.
        cidr: ipnet::IpNet,
        /// The RFC 2317 zone.
        zone: DnsName,
        /// The parent zone.
        parent: DnsName,
        /// The lines to add to the parent.
        lines: Vec<String>,
    },
    /// A reverse zone of a prefix that is gone or whose setting is `off`: it stays and is
    /// no longer kept.
    ReverseOrphaned {
        /// The zone.
        zone: ZoneId,
        /// Its apex.
        name: DnsName,
        /// The prefix it belonged to.
        prefix: PrefixId,
    },
    /// A managed prefix whose reverse zone cannot be created: no zone in Tenko lends the
    /// SOA values and name servers.
    NoNameServers {
        /// The prefix.
        prefix: PrefixId,
        /// Its network.
        cidr: ipnet::IpNet,
        /// The zones it would get.
        zones: Vec<DnsName>,
    },
}

/// The plan of one view.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsPlan {
    /// The revision of the view.
    pub revision: Revision,
    /// Reverse zones to create.
    pub create: Vec<ZoneCreate>,
    /// Zones to adopt as reverse zones of a prefix.
    pub adopt: Vec<ZoneAdopt>,
    /// RRset changes per zone, by apex.
    pub batches: Vec<ZoneBatch>,
    /// Findings.
    pub findings: Vec<DnsFinding>,
    /// Reverse zones that follow their template.
    pub follow: Vec<ZoneFollow>,
    /// Templates to record without a zone change: reverse zones in step with their
    /// template.
    pub stamps: Vec<(ZoneId, ReverseTemplate)>,
}

impl DnsPlan {
    /// Whether the plan writes nothing.
    pub fn is_empty(&self) -> bool {
        self.create.is_empty()
            && self.adopt.is_empty()
            && self.batches.is_empty()
            && self.follow.is_empty()
            && self.stamps.is_empty()
    }

    /// The RRset changes in all zones.
    pub fn change_count(&self) -> usize {
        self.batches.iter().map(|batch| batch.changes.len()).sum()
    }
}

// ----- loading -------------------------------------------------------------------------

/// A primary zone with what the planner needs of it.
#[derive(Debug, Clone)]
pub(crate) struct ZoneInfo {
    pub zone: Zone,
    /// The revision of the zone row.
    pub revision: Revision,
    /// The apex NS set of the default scope.
    pub name_servers: Vec<DnsName>,
    /// The origin of that NS set.
    pub ns_origin: Origin,
    /// Whether it holds `ipam` RRsets (the store's counters).
    pub has_ipam: bool,
    /// The network when the apex is a reverse zone name.
    pub reverse: Option<ReverseZone>,
}

/// The intent and the zones of one view.
#[derive(Debug, Default)]
pub(crate) struct World {
    pub zones: Vec<ZoneInfo>,
    pub prefixes: BTreeMap<PrefixId, Prefix>,
    pub vrf_tenant: BTreeMap<VrfId, TenantId>,
    pub default_tenant: Option<TenantId>,
    pub addresses: BTreeMap<AddressId, Address>,
    /// The default zone of each tenant that has one.
    pub tenant_default: BTreeMap<TenantId, ZoneId>,
    /// What each reverse zone copied from its template.
    pub templates: BTreeMap<ZoneId, ReverseTemplate>,
}

fn ns_set(view: &dyn ReadView, zone: &Zone) -> IpamResult<(Vec<DnsName>, Origin)> {
    let key = RrSetKey {
        zone: zone.id,
        scope: ScopeName::DEFAULT,
        name: zone.name.clone(),
        rtype: Rtype::NS,
    };
    let Some((rrset, _)) = view.get_typed(&RRSETS, &key)? else {
        return Ok((Vec::new(), Origin::Manual));
    };
    let hosts = rrset
        .records()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|record| match record {
            RecordData::Ns { host } => Some(host),
            _ => None,
        })
        .collect();
    Ok((hosts, rrset.origin))
}

impl World {
    pub(crate) fn load(view: &dyn ReadView) -> IpamResult<Self> {
        let mut world = World::default();
        for (_, zone, revision) in view.scan_typed(&ZONES, KeyRange::all(), usize::MAX, false)? {
            let zone: Zone = zone;
            if zone.kind != ZoneKind::Primary {
                continue;
            }
            let summary = tenko_dns::zone::ZoneService::summary(view, &zone)
                .map_err(|error| crate::IpamError::from_coded_error(error.into_coded()))?;
            let has_ipam = summary
                .origins
                .iter()
                .any(|(origin, count)| *origin == Origin::Ipam && *count > 0);
            let (name_servers, ns_origin) = ns_set(view, &zone)?;
            world.zones.push(ZoneInfo {
                revision,
                name_servers,
                ns_origin,
                has_ipam,
                reverse: reverse::parse_zone(&zone.name),
                zone,
            });
        }
        world.zones.sort_by(|a, b| a.zone.name.cmp(&b.zone.name));
        for (_, tenant, _) in view.scan_typed(&TENANTS, KeyRange::all(), usize::MAX, false)? {
            let tenant: Tenant = tenant;
            if tenant.meta.is_deleted() {
                continue;
            }
            if tenant.name.eq_ignore_ascii_case(DEFAULT_TENANT) {
                world.default_tenant = Some(tenant.id);
            }
            if let Some(zone) = tenant.dns.default_zone {
                world.tenant_default.insert(tenant.id, zone);
            }
        }
        for (zone, template, _) in
            view.scan_typed(&REVERSE_TEMPLATES, KeyRange::all(), usize::MAX, false)?
        {
            world.templates.insert(zone, template);
        }
        for (_, vrf, _) in view.scan_typed(&VRFS, KeyRange::all(), usize::MAX, false)? {
            let vrf: Vrf = vrf;
            if !vrf.meta.is_deleted() {
                world.vrf_tenant.insert(vrf.id, vrf.tenant);
            }
        }
        for (_, prefix, _) in view.scan_typed(&PREFIXES, KeyRange::all(), usize::MAX, false)? {
            let prefix: Prefix = prefix;
            if !prefix.meta.is_deleted() {
                world.prefixes.insert(prefix.id, prefix);
            }
        }
        for (_, address, _) in view.scan_typed(&ADDRESSES, KeyRange::all(), usize::MAX, false)? {
            let address: Address = address;
            if !address.meta.is_deleted() {
                world.addresses.insert(address.id, address);
            }
        }
        Ok(world)
    }

    fn zone(&self, id: ZoneId) -> Option<&ZoneInfo> {
        self.zones.iter().find(|info| info.zone.id == id)
    }

    fn zone_named(&self, name: &DnsName) -> Option<&ZoneInfo> {
        self.zones.iter().find(|info| &info.zone.name == name)
    }

    /// Whether the tenant of `vrf` has a forward zone in Tenko: a primary zone outside
    /// `arpa` of that tenant, or one without a tenant when the VRF belongs to the default
    /// tenant (or there is no default tenant).
    fn has_forward_zone(&self, vrf: VrfId) -> bool {
        let tenant = self.vrf_tenant.get(&vrf).copied();
        self.zones
            .iter()
            .filter(|info| is_forward(&info.zone.name))
            .any(|info| match info.zone.tenant {
                Some(owner) => Some(owner) == tenant,
                None => self.default_tenant.is_none() || tenant == self.default_tenant,
            })
    }

    /// The setting of a prefix in force: its own, else managed when its tenant has a
    /// forward zone (P2-Q11). Only network prefixes have reverse zones.
    pub(crate) fn effective(&self, prefix: &Prefix) -> DnsReverse {
        if prefix.role != PrefixRole::Network {
            return DnsReverse::Off;
        }
        prefix.dns_reverse.unwrap_or_else(|| {
            if self.has_forward_zone(prefix.vrf) {
                DnsReverse::Managed
            } else {
                DnsReverse::Off
            }
        })
    }

    /// The zone that lends a new reverse zone its SOA values and name servers (its
    /// template): the longest reverse zone above it, else the tenant's default zone, else
    /// the tenant's first forward zone, else the first forward zone without a tenant, else
    /// the first forward zone; always one with name servers.
    fn lender(&self, apex: &DnsName, vrf: VrfId) -> Option<&ZoneInfo> {
        let usable = |info: &&ZoneInfo| !info.name_servers.is_empty();
        let above = self
            .zones
            .iter()
            .filter(usable)
            .filter(|info| info.reverse.is_some() && apex.is_subdomain_of(&info.zone.name))
            .filter(|info| &info.zone.name != apex)
            .max_by_key(|info| info.zone.name.label_count());
        if above.is_some() {
            return above;
        }
        let tenant = self.vrf_tenant.get(&vrf).copied();
        let forward = || {
            self.zones
                .iter()
                .filter(usable)
                .filter(|info| is_forward(&info.zone.name))
        };
        // Backlog: the tenant's default zone comes first.
        let chosen = tenant
            .and_then(|tenant| self.tenant_default.get(&tenant))
            .and_then(|zone| forward().find(|info| info.zone.id == *zone));
        if chosen.is_some() {
            return chosen;
        }
        forward()
            .find(|info| info.zone.tenant.is_some() && info.zone.tenant == tenant)
            .or_else(|| forward().find(|info| info.zone.tenant.is_none()))
            .or_else(|| forward().next())
    }
}

/// The reverse zones that follow their template, and the templates to record for zones in
/// step with theirs (see the module documentation). Shorter apexes go first, so a zone
/// whose template is a reverse zone that follows in the same run takes its new values.
fn follow_templates(
    world: &World,
    frozen: &BTreeSet<ZoneId>,
) -> (Vec<ZoneFollow>, Vec<(ZoneId, ReverseTemplate)>) {
    let mut follow = Vec::new();
    let mut stamps = Vec::new();
    let mut planned: BTreeMap<ZoneId, (SoaDefaults, Vec<DnsName>)> = BTreeMap::new();
    let mut zones: Vec<&ZoneInfo> = world
        .zones
        .iter()
        .filter(|info| info.reverse.is_some() && !frozen.contains(&info.zone.id))
        .collect();
    zones.sort_by_key(|info| info.zone.name.label_count());
    for info in zones {
        let Some(prefix) = info
            .zone
            .reverse_of
            .and_then(|prefix| world.prefixes.get(&prefix))
        else {
            continue;
        };
        let Some(lender) = world.lender(&info.zone.name, prefix.vrf) else {
            continue;
        };
        let (soa, name_servers) = planned
            .get(&lender.zone.id)
            .cloned()
            .unwrap_or_else(|| (lender.zone.soa.clone(), sorted(&lender.name_servers)));
        let want = ReverseTemplate {
            template: lender.zone.id,
            template_name: lender.zone.name.clone(),
            soa,
            name_servers,
        };
        let current_ns = sorted(&info.name_servers);
        let stamp = world.templates.get(&info.zone.id);
        if info.zone.soa == want.soa && current_ns == want.name_servers {
            if stamp != Some(&want) {
                stamps.push((info.zone.id, want));
            }
            continue;
        }
        // A zone never recorded (kept before templates were, or adopted with other
        // values) does not follow.
        let Some(stamp) = stamp else {
            continue;
        };
        // Each part equals what the zone copied, or already the template's (a follow
        // that stopped half way); anything else is an operator's edit.
        let soa_kept = info.zone.soa == stamp.soa || info.zone.soa == want.soa;
        let ns_kept = current_ns == stamp.name_servers || current_ns == want.name_servers;
        if !soa_kept || !ns_kept {
            continue;
        }
        let description = (info.zone.description.as_deref()
            == Some(reverse_description(&stamp.template_name).as_str())
            && stamp.template_name != want.template_name)
            .then(|| reverse_description(&want.template_name));
        planned.insert(info.zone.id, (want.soa.clone(), want.name_servers.clone()));
        follow.push(ZoneFollow {
            zone: info.zone.id,
            name: info.zone.name.clone(),
            revision: info.revision,
            soa: (info.zone.soa != want.soa).then(|| want.soa.clone()),
            name_servers: (current_ns != want.name_servers).then(|| want.name_servers.clone()),
            ns_origin: info.ns_origin,
            description,
            stamp: want,
        });
    }
    (follow, stamps)
}

fn is_forward(name: &DnsName) -> bool {
    DnsName::new("arpa").is_ok_and(|arpa| !name.is_subdomain_of(&arpa))
}

/// The moves whose automatic DNS step has started, from the jobs of `view`.
pub(crate) fn moves_in_flight(
    view: &dyn ReadView,
    ignore: &[JobId],
) -> IpamResult<Vec<MoveOverride>> {
    let mut out = Vec::new();
    for state in [JobState::Running, JobState::Waiting] {
        let rows = view.scan_typed(
            &BY_STATE,
            KeyRange::prefix(encode_key(&(state,))),
            usize::MAX,
            false,
        )?;
        for ((_, id), (), _) in rows {
            if ignore.contains(&id) {
                continue;
            }
            let Some((job, _)) = view.get_typed(&JOBS, &id)? else {
                continue;
            };
            out.extend(dns_override(&job));
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn dns_override(job: &Job) -> Option<MoveOverride> {
    if job.spec.kind.as_str() != MOVE_JOB {
        return None;
    }
    job.steps.iter().find_map(|record| {
        if record.kind.as_str() != DNS_STEP
            || !matches!(record.state, StepState::Running | StepState::Done)
        {
            return None;
        }
        let spec = job.spec.steps.get(usize::from(record.index))?;
        let params: MoveStepParams = from_cbor(&spec.params.0).ok()?;
        params.dns.as_ref()?;
        Some(MoveOverride {
            old: params.address,
            new: params.new_address,
        })
    })
}

// ----- the plan ------------------------------------------------------------------------

/// What one RRset should hold.
#[derive(Debug, Default)]
struct Want {
    records: BTreeMap<Rdata, RecordData>,
    addresses: BTreeSet<AddressId>,
}

/// The wanted RRsets per zone, by owner and type.
type Wanted = BTreeMap<ZoneId, BTreeMap<(DnsName, Rtype), Want>>;

/// Plans the reverse zones and the records of `view` (see the module documentation).
///
/// # Errors
///
/// Store errors.
pub fn plan(view: &dyn ReadView, options: &PlanOptions) -> IpamResult<DnsPlan> {
    let world = World::load(view)?;
    let mut moves = moves_in_flight(view, &options.ignore_jobs)?;
    moves.extend(options.moves.iter().copied());
    plan_world(view, &world, &moves, options.orphans)
}

#[allow(
    clippy::too_many_lines,
    reason = "the steps of one plan read best in order"
)]
pub(crate) fn plan_world(
    view: &dyn ReadView,
    world: &World,
    moves: &[MoveOverride],
    orphans: OrphanRule,
) -> IpamResult<DnsPlan> {
    let mut out = DnsPlan {
        revision: view.revision(),
        ..DnsPlan::default()
    };

    // 1. Reverse zones of the managed prefixes, first owner by network.
    let mut prefixes: Vec<&Prefix> = world.prefixes.values().collect();
    prefixes.sort_by(|a, b| {
        (a.cidr.prefix_len(), a.cidr.network(), a.id).cmp(&(
            b.cidr.prefix_len(),
            b.cidr.network(),
            b.id,
        ))
    });
    let mut owners: BTreeMap<DnsName, (PrefixId, ReverseZone)> = BTreeMap::new();
    for prefix in &prefixes {
        if world.effective(prefix) != DnsReverse::Managed {
            continue;
        }
        for zone in reverse::zones_for(prefix.cidr) {
            owners
                .entry(zone.name().clone())
                .or_insert((prefix.id, zone));
        }
    }
    let mut no_servers: BTreeMap<PrefixId, Vec<DnsName>> = BTreeMap::new();
    for (name, (prefix_id, _)) in &owners {
        let Some(prefix) = world.prefixes.get(prefix_id) else {
            continue;
        };
        match world.zone_named(name) {
            Some(info) => {
                let taken = info
                    .zone
                    .reverse_of
                    .filter(|owner| owner != prefix_id)
                    .and_then(|owner| world.prefixes.get(&owner))
                    .is_some_and(|owner| {
                        world.effective(owner) == DnsReverse::Managed
                            && reverse::zones_for(owner.cidr)
                                .iter()
                                .any(|zone| zone.name() == name)
                    });
                if info.zone.reverse_of != Some(*prefix_id) && !taken {
                    out.adopt.push(ZoneAdopt {
                        zone: info.zone.id,
                        name: name.clone(),
                        prefix: *prefix_id,
                    });
                }
            }
            None => match world.lender(name, prefix.vrf) {
                Some(lender) => out.create.push(ZoneCreate {
                    name: name.clone(),
                    prefix: *prefix_id,
                    tenant: world.vrf_tenant.get(&prefix.vrf).copied(),
                    serial: lender.zone.serial,
                    soa: lender.zone.soa.clone(),
                    name_servers: sorted(&lender.name_servers),
                    source: lender.zone.name.clone(),
                }),
                None => no_servers.entry(*prefix_id).or_default().push(name.clone()),
            },
        }
    }
    for (prefix, zones) in no_servers {
        if let Some(prefix) = world.prefixes.get(&prefix) {
            out.findings.push(DnsFinding::NoNameServers {
                prefix: prefix.id,
                cidr: prefix.cidr,
                zones,
            });
        }
    }
    // A zone whose prefix is gone or off stays and is no longer kept.
    let mut frozen: BTreeSet<ZoneId> = BTreeSet::new();
    for info in &world.zones {
        let Some(owner) = info.zone.reverse_of else {
            continue;
        };
        let kept = owners
            .get(&info.zone.name)
            .is_some_and(|(prefix, _)| *prefix == owner)
            || out.adopt.iter().any(|adopt| adopt.zone == info.zone.id);
        let other_owner = owners.contains_key(&info.zone.name);
        if !kept && !other_owner {
            frozen.insert(info.zone.id);
            out.findings.push(DnsFinding::ReverseOrphaned {
                zone: info.zone.id,
                name: info.zone.name.clone(),
                prefix: owner,
            });
        }
    }
    (out.follow, out.stamps) = follow_templates(world, &frozen);
    let active: Vec<&ZoneInfo> = world
        .zones
        .iter()
        .filter(|info| !frozen.contains(&info.zone.id))
        .collect();
    let longest = |name: &DnsName| -> Option<&ZoneInfo> {
        active
            .iter()
            .copied()
            .filter(|info| name.is_subdomain_of(&info.zone.name))
            .max_by_key(|info| info.zone.name.label_count())
    };
    let classless: Vec<(&ZoneInfo, ipnet::Ipv4Net)> = active
        .iter()
        .filter_map(|info| match &info.reverse {
            Some(ReverseZone::Classless { net, .. }) => Some((*info, *net)),
            _ => None,
        })
        .collect();

    // 2. The wanted records.
    let suppressed: BTreeSet<AddressId> = moves.iter().map(|m| m.old).collect();
    let promoted: BTreeSet<AddressId> = moves.iter().map(|m| m.new).collect();
    let mut wanted: Wanted = BTreeMap::new();
    let mut no_zone: BTreeMap<Fqdn, Vec<AddressId>> = BTreeMap::new();
    for address in world.addresses.values() {
        let Some(fqdn) = &address.dns_name else {
            continue;
        };
        let published = if promoted.contains(&address.id) {
            true
        } else {
            address.status != Status::Planned && !suppressed.contains(&address.id)
        };
        if !published {
            continue;
        }
        let name = DnsName::from(fqdn);
        match longest(&name).filter(|info| !delegated(view, &info.zone, &name)) {
            Some(info) => {
                let (rtype, data) = match address.ip {
                    IpAddr::V4(ip) => (Rtype::A, RecordData::A { address: ip }),
                    IpAddr::V6(ip) => (Rtype::AAAA, RecordData::Aaaa { address: ip }),
                };
                want(
                    &mut wanted,
                    info.zone.id,
                    name.clone(),
                    rtype,
                    data,
                    address.id,
                );
            }
            None => no_zone.entry(fqdn.clone()).or_default().push(address.id),
        }
        let in_block = match address.ip {
            IpAddr::V4(ip) => classless
                .iter()
                .find(|(_, net)| net.contains(&ip))
                .map(|(info, _)| (*info, ip)),
            IpAddr::V6(_) => None,
        };
        let (zone, owner) = if let Some((info, ip)) = in_block {
            (Some(info), reverse::classless_ptr_name(ip, &info.zone.name))
        } else {
            let owner = reverse::ptr_name(address.ip);
            (longest(&owner), owner)
        };
        if let Some(info) = zone {
            want(
                &mut wanted,
                info.zone.id,
                owner,
                Rtype::PTR,
                RecordData::Ptr {
                    target: name.clone(),
                },
                address.id,
            );
        }
    }
    // Names without a zone are worth a word only once Tenko serves forward zones at all.
    let serves_forward = world.zones.iter().any(|info| is_forward(&info.zone.name));
    if !no_zone.is_empty() && serves_forward {
        out.findings.push(DnsFinding::NoZone { names: no_zone });
    }

    // RFC 2317: the delegation and the CNAME of every address in the parent, for the
    // classless zones of managed prefixes.
    for (name, (prefix_id, zone)) in &owners {
        let ReverseZone::Classless { net, parent, .. } = zone else {
            continue;
        };
        let servers = world
            .zone_named(name)
            .map(|info| info.name_servers.clone())
            .filter(|servers| !servers.is_empty())
            .or_else(|| {
                out.create
                    .iter()
                    .find(|create| &create.name == name)
                    .map(|create| create.name_servers.clone())
            })
            .unwrap_or_default();
        let parent_zone = longest(parent).filter(|info| &info.zone.name != name);
        match parent_zone {
            Some(info) if !servers.is_empty() => {
                for server in &servers {
                    want_glue(
                        &mut wanted,
                        info.zone.id,
                        name.clone(),
                        Rtype::NS,
                        RecordData::Ns {
                            host: server.clone(),
                        },
                    );
                }
                for ip in net.hosts_inclusive() {
                    let owner = reverse::ptr_name(IpAddr::V4(ip));
                    let target = reverse::classless_ptr_name(ip, name);
                    want_glue(
                        &mut wanted,
                        info.zone.id,
                        owner,
                        Rtype::CNAME,
                        RecordData::Cname { target },
                    );
                }
            }
            Some(_) => {}
            None => {
                if let Some(prefix) = world.prefixes.get(prefix_id) {
                    out.findings.push(DnsFinding::Delegation {
                        prefix: prefix.id,
                        cidr: prefix.cidr,
                        zone: name.clone(),
                        parent: parent.clone(),
                        lines: reverse::delegation_lines(zone, &servers),
                    });
                }
            }
        }
    }

    // 3. The diff per zone, against what the zones hold.
    let mut zones: BTreeSet<ZoneId> = wanted.keys().copied().collect();
    zones.extend(
        active
            .iter()
            .filter(|info| info.has_ipam)
            .map(|info| info.zone.id),
    );
    for zone_id in zones {
        let Some(info) = world.zone(zone_id) else {
            continue;
        };
        let wants = wanted.remove(&zone_id).unwrap_or_default();
        let (changes, findings) = diff_zone(view, info, &wants, orphans)?;
        out.findings.extend(findings);
        if !changes.is_empty() {
            out.batches.push(ZoneBatch {
                zone: zone_id,
                name: info.zone.name.clone(),
                changes,
            });
        }
    }
    out.batches.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Extends the classless coverage helper of `ipnet`: every address of the block.
trait HostsInclusive {
    fn hosts_inclusive(&self) -> Vec<std::net::Ipv4Addr>;
}

impl HostsInclusive for ipnet::Ipv4Net {
    fn hosts_inclusive(&self) -> Vec<std::net::Ipv4Addr> {
        let first = u32::from(self.network());
        let last = u32::from(self.broadcast());
        (first..=last).map(std::net::Ipv4Addr::from).collect()
    }
}

fn want(
    wanted: &mut Wanted,
    zone: ZoneId,
    name: DnsName,
    rtype: Rtype,
    data: RecordData,
    address: AddressId,
) {
    let entry = wanted
        .entry(zone)
        .or_default()
        .entry((name, rtype))
        .or_default();
    entry.records.insert(Rdata::from_data(&data), data);
    entry.addresses.insert(address);
}

fn want_glue(wanted: &mut Wanted, zone: ZoneId, name: DnsName, rtype: Rtype, data: RecordData) {
    let entry = wanted
        .entry(zone)
        .or_default()
        .entry((name, rtype))
        .or_default();
    entry.records.insert(Rdata::from_data(&data), data);
}

/// Whether a delegation inside `zone` covers `name`: an NS set at the name or at a name
/// between it and the apex.
pub(crate) fn delegated(view: &dyn ReadView, zone: &Zone, name: &DnsName) -> bool {
    let mut current = Some(name.clone());
    while let Some(owner) = current {
        if owner == zone.name {
            return false;
        }
        let key = RrSetKey {
            zone: zone.id,
            scope: ScopeName::DEFAULT,
            name: owner.clone(),
            rtype: Rtype::NS,
        };
        if view.get_typed(&RRSETS, &key).ok().flatten().is_some() {
            return true;
        }
        current = owner.parent();
    }
    false
}

/// The RRsets of one owner in the default scope.
fn node(view: &dyn ReadView, zone: ZoneId, name: &DnsName) -> IpamResult<Vec<RrSet>> {
    Ok(view
        .scan_typed(
            &RRSETS,
            KeyRange::prefix(encode_key(&(zone, ScopeName::DEFAULT, name.clone()))),
            usize::MAX,
            false,
        )?
        .into_iter()
        .map(|(_, rrset, _)| rrset)
        .filter(|rrset: &RrSet| &rrset.name == name)
        .collect())
}

/// The `ipam` RRsets of a zone's default scope.
fn ipam_rrsets(view: &dyn ReadView, zone: ZoneId) -> IpamResult<BTreeMap<(DnsName, Rtype), RrSet>> {
    Ok(view
        .scan_typed(
            &RRSETS,
            KeyRange::prefix(encode_key(&(zone, ScopeName::DEFAULT))),
            usize::MAX,
            false,
        )?
        .into_iter()
        .map(|(_, rrset, _)| rrset)
        .filter(|rrset: &RrSet| rrset.origin == Origin::Ipam)
        .map(|rrset| ((rrset.name.clone(), rrset.rtype), rrset))
        .collect())
}

/// Whether an RRset of `other` type beside one of `rtype` breaks the node rules.
fn clashes(rtype: Rtype, other: Rtype) -> bool {
    if rtype == other {
        return false;
    }
    let beside = |t: Rtype| t == Rtype::RRSIG || t == Rtype::NSEC;
    match (rtype, other) {
        (Rtype::CNAME, other) => !beside(other),
        (_, Rtype::CNAME) => !beside(rtype),
        (Rtype::NS, other) => {
            !matches!(other, Rtype::DS | Rtype::A | Rtype::AAAA) && !beside(other)
        }
        _ => false,
    }
}

fn records(rrset: &RrSet) -> Vec<RecordData> {
    rrset.records().unwrap_or_default()
}

fn same(rrset: &RrSet, want: &Want) -> bool {
    rrset.rdata.len() == want.records.len()
        && rrset
            .rdata
            .iter()
            .all(|data| want.records.contains_key(data))
}

fn diff_zone(
    view: &dyn ReadView,
    info: &ZoneInfo,
    wants: &BTreeMap<(DnsName, Rtype), Want>,
    orphans: OrphanRule,
) -> IpamResult<(Vec<RecordChange>, Vec<DnsFinding>)> {
    let zone = &info.zone;
    let mut stored = if info.has_ipam {
        ipam_rrsets(view, zone.id)?
    } else {
        BTreeMap::new()
    };
    let mut changes: Vec<RecordChange> = Vec::new();
    let mut findings = Vec::new();
    let mut forced: BTreeSet<(DnsName, Rtype)> = BTreeSet::new();
    let mut nodes: BTreeMap<DnsName, Vec<RrSet>> = BTreeMap::new();
    for ((name, rtype), want) in wants {
        if !nodes.contains_key(name) {
            nodes.insert(name.clone(), node(view, zone.id, name)?);
        }
        let here = nodes.get(name).map(Vec::as_slice).unwrap_or_default();
        let held = here.iter().find(|rrset| {
            rrset.origin != Origin::Ipam
                && (clashes(*rtype, rrset.rtype) || (rrset.rtype == *rtype && !same(rrset, want)))
        });
        if let Some(held) = held {
            findings.push(DnsFinding::Held {
                zone: zone.name.clone(),
                name: name.clone(),
                rtype: *rtype,
                held_type: held.rtype,
                origin: held.origin,
                wanted: want.records.values().cloned().collect(),
                addresses: want.addresses.iter().copied().collect(),
            });
            stored.remove(&(name.clone(), *rtype));
            continue;
        }
        // `ipam` RRsets that clash with what IPAM wants here are replaced, whatever the
        // orphan rule says.
        for other in here
            .iter()
            .filter(|rrset| rrset.origin == Origin::Ipam && clashes(*rtype, rrset.rtype))
        {
            forced.insert((name.clone(), other.rtype));
        }
        let existing = here.iter().find(|rrset| rrset.rtype == *rtype);
        stored.remove(&(name.clone(), *rtype));
        match existing {
            Some(rrset) if same(rrset, want) => {}
            Some(rrset) if rrset.origin != Origin::Ipam => {}
            existing => changes.push(RecordChange {
                name: name.clone(),
                rtype: *rtype,
                before: existing.map(records).unwrap_or_default(),
                after: want.records.values().cloned().collect(),
                addresses: want.addresses.iter().copied().collect(),
            }),
        }
    }
    for ((name, rtype), rrset) in stored {
        let remove = orphans == OrphanRule::Remove || forced.contains(&(name.clone(), rtype));
        if remove {
            changes.push(RecordChange {
                name,
                rtype,
                before: records(&rrset),
                after: Vec::new(),
                addresses: Vec::new(),
            });
        } else {
            findings.push(DnsFinding::Orphaned {
                zone: zone.name.clone(),
                name,
                rtype,
                records: records(&rrset),
            });
        }
    }
    changes.sort_by(|a, b| {
        (&a.name, !a.is_delete(), a.rtype).cmp(&(&b.name, !b.is_delete(), b.rtype))
    });
    Ok((changes, findings))
}

/// Splits the changes of a zone into batches of at most [`MAX_CHANGES`], never between the
/// changes of one owner unless one owner alone exceeds the limit.
pub fn chunks(changes: &[RecordChange]) -> Vec<&[RecordChange]> {
    let mut out = Vec::new();
    let mut start = 0;
    while start < changes.len() {
        let mut end = (start + MAX_CHANGES).min(changes.len());
        if end < changes.len() {
            let mut cut = end;
            while cut > start + 1 && changes[cut].name == changes[cut - 1].name {
                cut -= 1;
            }
            if cut > start + 1 {
                end = cut;
            }
        }
        out.push(&changes[start..end]);
        start = end;
    }
    out
}

/// The presentation text of a record, `www.example.test A 192.0.2.10`.
pub fn record_text(name: &DnsName, rtype: Rtype, data: &RecordData) -> String {
    let text = tenko_dns::zone::zonefile::presentation(rtype, &Rdata::from_data(data))
        .unwrap_or_else(|_| format!("{data:?}"));
    format!("{name} {rtype} {text}")
}
