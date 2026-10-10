//! Anchors of IPAM objects for scoped authorization (IAM-01, plan section 2.5, ADR 0015):
//! where an object sits among tenants, VRFs, sites and prefixes, kept in a derived index so
//! that authorization reads no table, and the check of a scoped principal's planned writes.
//!
//! # Anchors
//!
//! [`ScopeIndex`] follows the `ipam.*` primary tables in revision order (like the
//! [`PrefixTree`](crate::PrefixTree)) and answers [`Anchors`] from memory:
//!
//! | Object | Anchors |
//! |---|---|
//! | tenant | itself |
//! | VRF | itself and its tenant |
//! | site | itself and its ancestors |
//! | VLAN | its site and the site's ancestors |
//! | prefix | its chain (itself, then every enclosing live prefix), its VRF and tenant, and the site of the nearest prefix of the chain that names one |
//! | range, address | the chain of its prefix (the most specific prefix that holds it), as for the prefix |
//! | host | its tenant, its site, one chain per prefix of its live addresses, and the VRF when all of them share one |
//! | interface | the anchors of its host |
//! | job | the anchors of its targets merged ([`ScopeIndex::anchors_of_targets`]) |
//! | proposal | the chain of its subject address or network, merged with its objects |
//!
//! A merged object that has a part without prefix chains carries an empty chain, so a
//! write to it needs a rule that covers it whole: a prefix rule never admits a write to a
//! host that has an address outside the rule.
//!
//! # Writes
//!
//! A scoped principal's change is planned first, and every planned change is checked in
//! [`AnchorMode::All`] before and after it ([`ScopeIndex::check_plan`]): the object must lie
//! inside the scope where it is and where it goes, so nothing moves out of or into a scope
//! the principal does not hold. The anchors after the change come from an overlay of the
//! plan's objects on the index, so a host created with its interfaces or a prefix created
//! inside a new parent anchors correctly. Interfaces and addresses also need the right to
//! change their host. [`ScopeIndex::execute_checked`] plans, checks and applies with the
//! retries of [`IpamService::execute`], which it delegates to for principals without a
//! scoped reach.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::IpAddr,
    sync::{Arc, PoisonError, RwLock},
};

use arc_swap::ArcSwap;
use ipnet::IpNet;
use tenko_core::{
    Action, AddressId, AnchorMode, Anchors, Authorizer, Denied, DenyReason, HostId, InterfaceId,
    JobId, ObjectKind, ObjectRef, PrefixId, Principal, ProposalId, RangeId, RequestCtx, Revision,
    ScopeFilter, SiteId, TenantId, VlanId, VrfId,
};
use tenko_store::{
    AnchorResolver, ChangeSet, DerivedIndex, IndexImage, KeyRange, ReadConsistency, ReadView,
    ReadViewExt, StoreError, WatchFilter, downcast_image,
};

use crate::{
    Applied, IpamCommand, IpamError, IpamPlan, IpamService, PlanOptions,
    error::codes,
    history::ChangeAction,
    net::{Family, bounds, host_mask, ip_to_u128},
    object::IpamObject,
    observe::{ObservedFact, model::observed_ips},
    proposals::{IntentProposal, model::PROPOSALS},
    tables::{ADDRESSES, HOSTS, INTERFACES, PREFIXES, RANGES, SITES, VLANS, VRFS},
};

/// Longest site or prefix chain followed (a guard against cycles in damaged data).
const MAX_CHAIN: usize = 130;

/// A network within its family: the network value and the prefix length.
type NetKey = (u128, u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PrefixFacts {
    vrf: VrfId,
    net: IpNet,
    site: Option<SiteId>,
    live: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AddressFacts {
    id: AddressId,
    vrf: VrfId,
    prefix: PrefixId,
    interface: Option<InterfaceId>,
    live: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HostFacts {
    tenant: TenantId,
    site: Option<SiteId>,
    live: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InterfaceFacts {
    host: HostId,
    live: bool,
}

fn net_key(net: &IpNet) -> ((usize, NetKey), Family) {
    let family = Family::of_net(net);
    let (first, _) = bounds(net);
    ((family.index(), (first, net.prefix_len())), family)
}

/// What anchor computation reads: the index, or the index under a plan's changes.
trait Facts {
    fn tenant_of(&self, vrf: VrfId) -> Option<TenantId>;
    /// The parent of a site; `None` for a top-level or an unknown site.
    fn site_parent(&self, site: SiteId) -> Option<SiteId>;
    /// The site of a VLAN, if it has one.
    fn vlan_site(&self, vlan: VlanId) -> Option<SiteId>;
    fn prefix(&self, id: PrefixId) -> Option<PrefixFacts>;
    /// The nearest live prefix strictly enclosing `net` in its VRF, other than `except`.
    fn enclosing(&self, vrf: VrfId, net: &IpNet, except: PrefixId) -> Option<PrefixId>;
    /// The most specific live prefix of the VRF holding `ip`.
    fn containing(&self, vrf: VrfId, ip: IpAddr) -> Option<PrefixId>;
    fn range_prefix(&self, id: RangeId) -> Option<PrefixId>;
    fn address(&self, id: AddressId) -> Option<AddressFacts>;
    fn interface(&self, id: InterfaceId) -> Option<InterfaceFacts>;
    fn host(&self, id: HostId) -> Option<HostFacts>;
    /// The addresses of a host: the live ones on its live interfaces, or every one of them
    /// for a deleted host (the restore view).
    fn host_addresses(&self, id: HostId) -> Vec<AddressFacts>;
    /// Every VRF with a live prefix holding `ip`.
    fn vrfs_holding(&self, ip: IpAddr) -> Vec<VrfId>;
}

/// One built image of the index.
#[derive(Debug, Default)]
struct Image {
    revision: Revision,
    vrfs: HashMap<VrfId, TenantId>,
    sites: HashMap<SiteId, Option<SiteId>>,
    vlans: HashMap<VlanId, Option<SiteId>>,
    prefixes: HashMap<PrefixId, PrefixFacts>,
    /// Live prefixes per VRF and family, by network.
    nets: HashMap<(VrfId, usize), BTreeMap<NetKey, PrefixId>>,
    /// The parent of each live prefix that has one.
    parents: HashMap<PrefixId, PrefixId>,
    ranges: HashMap<RangeId, PrefixId>,
    addresses: HashMap<AddressId, AddressFacts>,
    interfaces: HashMap<InterfaceId, InterfaceFacts>,
    by_interface: HashMap<InterfaceId, BTreeSet<AddressId>>,
    by_host: HashMap<HostId, BTreeSet<InterfaceId>>,
    hosts: HashMap<HostId, HostFacts>,
}

impl Image {
    fn search(
        nets: Option<&BTreeMap<NetKey, PrefixId>>,
        family: Family,
        value: u128,
        lengths: impl Iterator<Item = u8>,
        except: PrefixId,
    ) -> Option<PrefixId> {
        let nets = nets?;
        lengths
            .filter_map(|len| nets.get(&(value & !host_mask(family, len), len)))
            .find(|id| **id != except)
            .copied()
    }

    fn set_prefix(
        &mut self,
        id: PrefixId,
        prefix: Option<PrefixFacts>,
        dirty: &mut HashSet<(VrfId, usize)>,
    ) {
        if let Some(old) = self.prefixes.remove(&id)
            && old.live
        {
            let ((family, key), _) = net_key(&old.net);
            if let Some(nets) = self.nets.get_mut(&(old.vrf, family))
                && nets.get(&key) == Some(&id)
            {
                nets.remove(&key);
            }
            dirty.insert((old.vrf, family));
            self.parents.remove(&id);
        }
        if let Some(prefix) = prefix {
            if prefix.live {
                let ((family, key), _) = net_key(&prefix.net);
                self.nets
                    .entry((prefix.vrf, family))
                    .or_default()
                    .insert(key, id);
                dirty.insert((prefix.vrf, family));
            }
            self.prefixes.insert(id, prefix);
        }
    }

    /// Recomputes the parents of every live prefix of one VRF and family.
    fn reparent(&mut self, vrf: VrfId, family_index: usize) {
        let Some(nets) = self.nets.get(&(vrf, family_index)) else {
            return;
        };
        let family = if family_index == 0 {
            Family::V4
        } else {
            Family::V6
        };
        let mut parents = Vec::with_capacity(nets.len());
        for ((value, len), id) in nets {
            let parent = Self::search(Some(nets), family, *value, (0..*len).rev(), *id);
            parents.push((*id, parent));
        }
        for (id, parent) in parents {
            match parent {
                Some(parent) => self.parents.insert(id, parent),
                None => self.parents.remove(&id),
            };
        }
    }

    fn set_address(&mut self, id: AddressId, address: Option<AddressFacts>) {
        if let Some(old) = self.addresses.remove(&id)
            && let Some(interface) = old.interface
            && let Some(set) = self.by_interface.get_mut(&interface)
        {
            set.remove(&id);
            if set.is_empty() {
                self.by_interface.remove(&interface);
            }
        }
        if let Some(address) = address {
            if let Some(interface) = address.interface {
                self.by_interface.entry(interface).or_default().insert(id);
            }
            self.addresses.insert(id, address);
        }
    }

    fn set_interface(&mut self, id: InterfaceId, interface: Option<InterfaceFacts>) {
        if let Some(old) = self.interfaces.remove(&id)
            && let Some(set) = self.by_host.get_mut(&old.host)
        {
            set.remove(&id);
            if set.is_empty() {
                self.by_host.remove(&old.host);
            }
        }
        if let Some(interface) = interface {
            self.by_host.entry(interface.host).or_default().insert(id);
            self.interfaces.insert(id, interface);
        }
    }

    fn load(
        &mut self,
        view: &dyn ReadView,
        object: ObjectRef,
        dirty: &mut HashSet<(VrfId, usize)>,
    ) -> Result<(), StoreError> {
        match object.kind {
            ObjectKind::Vrf => {
                let id = VrfId::from_uuid(object.id);
                match view.get_typed(&VRFS, &id)? {
                    Some((vrf, _)) => self.vrfs.insert(id, vrf.tenant),
                    None => self.vrfs.remove(&id),
                };
            }
            ObjectKind::Site => {
                let id = SiteId::from_uuid(object.id);
                match view.get_typed(&SITES, &id)? {
                    Some((site, _)) => self.sites.insert(id, site.parent),
                    None => self.sites.remove(&id),
                };
            }
            ObjectKind::Vlan => {
                let id = VlanId::from_uuid(object.id);
                match view.get_typed(&VLANS, &id)? {
                    Some((vlan, _)) => self.vlans.insert(id, vlan.site),
                    None => self.vlans.remove(&id),
                };
            }
            ObjectKind::Prefix => {
                let id = PrefixId::from_uuid(object.id);
                let facts = view
                    .get_typed(&PREFIXES, &id)?
                    .map(|(prefix, _)| PrefixFacts {
                        vrf: prefix.vrf,
                        net: prefix.cidr,
                        site: prefix.site,
                        live: !prefix.meta.is_deleted(),
                    });
                self.set_prefix(id, facts, dirty);
            }
            ObjectKind::Range => {
                let id = RangeId::from_uuid(object.id);
                match view.get_typed(&RANGES, &id)? {
                    Some((range, _)) => self.ranges.insert(id, range.prefix),
                    None => self.ranges.remove(&id),
                };
            }
            ObjectKind::Address => {
                let id = AddressId::from_uuid(object.id);
                let facts = view
                    .get_typed(&ADDRESSES, &id)?
                    .map(|(address, _)| AddressFacts {
                        id,
                        vrf: address.vrf,
                        prefix: address.prefix,
                        interface: address.interface,
                        live: !address.meta.is_deleted(),
                    });
                self.set_address(id, facts);
            }
            ObjectKind::Interface => {
                let id = InterfaceId::from_uuid(object.id);
                let facts =
                    view.get_typed(&INTERFACES, &id)?
                        .map(|(interface, _)| InterfaceFacts {
                            host: interface.host,
                            live: !interface.meta.is_deleted(),
                        });
                self.set_interface(id, facts);
            }
            ObjectKind::Host => {
                let id = HostId::from_uuid(object.id);
                match view.get_typed(&HOSTS, &id)? {
                    Some((host, _)) => self.hosts.insert(
                        id,
                        HostFacts {
                            tenant: host.tenant,
                            site: host.site,
                            live: !host.meta.is_deleted(),
                        },
                    ),
                    None => self.hosts.remove(&id),
                };
            }
            _ => {}
        }
        Ok(())
    }
}

/// The tables the index follows, with the kind of their objects.
fn tables() -> [(&'static tenko_core::TableName, ObjectKind); 8] {
    [
        (VRFS.name(), ObjectKind::Vrf),
        (SITES.name(), ObjectKind::Site),
        (VLANS.name(), ObjectKind::Vlan),
        (PREFIXES.name(), ObjectKind::Prefix),
        (RANGES.name(), ObjectKind::Range),
        (ADDRESSES.name(), ObjectKind::Address),
        (INTERFACES.name(), ObjectKind::Interface),
        (HOSTS.name(), ObjectKind::Host),
    ]
}

impl Facts for Image {
    fn tenant_of(&self, vrf: VrfId) -> Option<TenantId> {
        self.vrfs.get(&vrf).copied()
    }

    fn site_parent(&self, site: SiteId) -> Option<SiteId> {
        self.sites.get(&site).copied().flatten()
    }

    fn vlan_site(&self, vlan: VlanId) -> Option<SiteId> {
        self.vlans.get(&vlan).copied().flatten()
    }

    fn prefix(&self, id: PrefixId) -> Option<PrefixFacts> {
        self.prefixes.get(&id).copied()
    }

    fn enclosing(&self, vrf: VrfId, net: &IpNet, except: PrefixId) -> Option<PrefixId> {
        let ((family_index, (value, len)), family) = net_key(net);
        if self
            .prefixes
            .get(&except)
            .is_some_and(|facts| facts.live && facts.vrf == vrf && facts.net == *net)
        {
            return self.parents.get(&except).copied();
        }
        Self::search(
            self.nets.get(&(vrf, family_index)),
            family,
            value,
            (0..len).rev(),
            except,
        )
    }

    fn containing(&self, vrf: VrfId, ip: IpAddr) -> Option<PrefixId> {
        let family = Family::of(ip);
        Self::search(
            self.nets.get(&(vrf, family.index())),
            family,
            ip_to_u128(ip),
            (0..=family.bits()).rev(),
            PrefixId::from_uuid(uuid::Uuid::nil()),
        )
    }

    fn range_prefix(&self, id: RangeId) -> Option<PrefixId> {
        self.ranges.get(&id).copied()
    }

    fn address(&self, id: AddressId) -> Option<AddressFacts> {
        self.addresses.get(&id).copied()
    }

    fn interface(&self, id: InterfaceId) -> Option<InterfaceFacts> {
        self.interfaces.get(&id).copied()
    }

    fn host(&self, id: HostId) -> Option<HostFacts> {
        self.hosts.get(&id).copied()
    }

    fn host_addresses(&self, id: HostId) -> Vec<AddressFacts> {
        let all = self.hosts.get(&id).is_some_and(|host| !host.live);
        let mut out = Vec::new();
        for interface in self.by_host.get(&id).into_iter().flatten() {
            if !all && !self.interfaces.get(interface).is_some_and(|i| i.live) {
                continue;
            }
            for address in self.by_interface.get(interface).into_iter().flatten() {
                if let Some(facts) = self.addresses.get(address)
                    && (all || facts.live)
                {
                    out.push(*facts);
                }
            }
        }
        out
    }

    fn vrfs_holding(&self, ip: IpAddr) -> Vec<VrfId> {
        let family = Family::of(ip);
        let mut vrfs: Vec<VrfId> = self
            .nets
            .keys()
            .filter(|(_, index)| *index == family.index())
            .map(|(vrf, _)| *vrf)
            .filter(|vrf| self.containing(*vrf, ip).is_some())
            .collect();
        vrfs.sort();
        vrfs.dedup();
        vrfs
    }
}

// ----- anchor rules ---------------------------------------------------------------------

fn site_chain(facts: &dyn Facts, site: SiteId) -> Vec<SiteId> {
    let mut out = Vec::new();
    let mut next = Some(site);
    while let Some(current) = next {
        if out.contains(&current) || out.len() >= MAX_CHAIN {
            break;
        }
        out.push(current);
        next = facts.site_parent(current);
    }
    out
}

fn prefix_chain(facts: &dyn Facts, prefix: PrefixId) -> Vec<PrefixId> {
    let mut out = vec![prefix];
    let mut current = prefix;
    while out.len() < MAX_CHAIN {
        let Some(found) = facts.prefix(current) else {
            break;
        };
        match facts.enclosing(found.vrf, &found.net, current) {
            Some(parent) if !out.contains(&parent) => {
                out.push(parent);
                current = parent;
            }
            _ => break,
        }
    }
    out
}

/// The sites of a prefix chain: the site of its nearest prefix that names one.
fn chain_sites(facts: &dyn Facts, chain: &[PrefixId]) -> Vec<SiteId> {
    chain
        .iter()
        .find_map(|prefix| facts.prefix(*prefix).and_then(|found| found.site))
        .map(|site| site_chain(facts, site))
        .unwrap_or_default()
}

fn prefix_anchors(facts: &dyn Facts, object: ObjectRef, prefix: PrefixId) -> Anchors {
    let chain = prefix_chain(facts, prefix);
    let vrf = facts.prefix(prefix).map(|found| found.vrf);
    Anchors {
        object: Some(object),
        tenant: vrf.and_then(|vrf| facts.tenant_of(vrf)),
        vrf,
        sites: chain_sites(facts, &chain),
        prefixes: vec![chain],
    }
}

fn host_anchors(facts: &dyn Facts, object: ObjectRef, host: HostId) -> Anchors {
    let found = facts.host(host);
    let addresses = facts.host_addresses(host);
    let prefixes: BTreeSet<PrefixId> = addresses.iter().map(|address| address.prefix).collect();
    let vrfs: BTreeSet<VrfId> = addresses.iter().map(|address| address.vrf).collect();
    Anchors {
        object: Some(object),
        tenant: found.map(|host| host.tenant),
        vrf: if vrfs.len() == 1 {
            vrfs.into_iter().next()
        } else {
            None
        },
        sites: found
            .and_then(|host| host.site)
            .map(|site| site_chain(facts, site))
            .unwrap_or_default(),
        prefixes: prefixes
            .into_iter()
            .map(|prefix| prefix_chain(facts, prefix))
            .collect(),
    }
}

fn anchors_with(facts: &dyn Facts, object: ObjectRef) -> Anchors {
    let id = object.id;
    match object.kind {
        ObjectKind::Tenant => Anchors {
            tenant: Some(TenantId::from_uuid(id)),
            ..Anchors::of(object)
        },
        ObjectKind::Vrf => {
            let vrf = VrfId::from_uuid(id);
            Anchors {
                vrf: Some(vrf),
                tenant: facts.tenant_of(vrf),
                ..Anchors::of(object)
            }
        }
        ObjectKind::Site => Anchors {
            sites: site_chain(facts, SiteId::from_uuid(id)),
            ..Anchors::of(object)
        },
        ObjectKind::Vlan => Anchors {
            sites: facts
                .vlan_site(VlanId::from_uuid(id))
                .map(|site| site_chain(facts, site))
                .unwrap_or_default(),
            ..Anchors::of(object)
        },
        ObjectKind::Prefix => prefix_anchors(facts, object, PrefixId::from_uuid(id)),
        ObjectKind::Range => facts.range_prefix(RangeId::from_uuid(id)).map_or_else(
            || Anchors::of(object),
            |prefix| prefix_anchors(facts, object, prefix),
        ),
        ObjectKind::Address => facts.address(AddressId::from_uuid(id)).map_or_else(
            || Anchors::of(object),
            |address| prefix_anchors(facts, object, address.prefix),
        ),
        ObjectKind::Host => host_anchors(facts, object, HostId::from_uuid(id)),
        ObjectKind::Interface => facts.interface(InterfaceId::from_uuid(id)).map_or_else(
            || Anchors::of(object),
            |found| host_anchors(facts, object, found.host),
        ),
        _ => Anchors::of(object),
    }
}

/// Whether anchors place the object anywhere (a tenant, VRF, site or prefix).
fn anchored(anchors: &Anchors) -> bool {
    anchors.tenant.is_some()
        || anchors.vrf.is_some()
        || !anchors.sites.is_empty()
        || !anchors.prefixes.is_empty()
}

/// Merges the anchors of several parts into the anchors of one object: the tenant, VRF and
/// sites when every part shares them, every prefix chain, and an empty chain for a part
/// without chains, so that a write needs a rule covering the whole object.
pub fn merge(object: ObjectRef, parts: &[Anchors]) -> Anchors {
    let mut merged = Anchors::of(object);
    let Some(first) = parts.first() else {
        return merged;
    };
    if parts
        .iter()
        .all(|part| part.tenant.is_some() && part.tenant == first.tenant)
    {
        merged.tenant = first.tenant;
    }
    if parts
        .iter()
        .all(|part| part.vrf.is_some() && part.vrf == first.vrf)
    {
        merged.vrf = first.vrf;
    }
    if !first.sites.is_empty() && parts.iter().all(|part| part.sites == first.sites) {
        merged.sites.clone_from(&first.sites);
    }
    for part in parts {
        if part.prefixes.is_empty() {
            if !merged.prefixes.contains(&Vec::new()) {
                merged.prefixes.push(Vec::new());
            }
            continue;
        }
        for chain in &part.prefixes {
            if !merged.prefixes.contains(chain) {
                merged.prefixes.push(chain.clone());
            }
        }
    }
    merged
}

// ----- the overlay of a plan --------------------------------------------------------------

/// The index under the changes of a plan: the objects as the plan leaves them.
struct Overlay<'a> {
    base: &'a Image,
    objects: HashMap<ObjectRef, &'a IpamObject>,
    /// Live prefixes of the plan per VRF and family.
    nets: HashMap<(VrfId, usize), BTreeMap<NetKey, PrefixId>>,
}

impl<'a> Overlay<'a> {
    fn of(base: &'a Image, plan: &'a IpamPlan) -> Self {
        let mut objects: HashMap<ObjectRef, &'a IpamObject> = HashMap::new();
        for change in &plan.changes {
            if let Some(after) = &change.after {
                objects.insert(change.object, after);
            }
        }
        let mut nets: HashMap<(VrfId, usize), BTreeMap<NetKey, PrefixId>> = HashMap::new();
        for object in objects.values() {
            if let IpamObject::Prefix(prefix) = object
                && !prefix.meta.is_deleted()
            {
                let ((family, key), _) = net_key(&prefix.cidr);
                nets.entry((prefix.vrf, family))
                    .or_default()
                    .insert(key, prefix.id);
            }
        }
        Self {
            base,
            objects,
            nets,
        }
    }

    fn object(&self, object: ObjectRef) -> Option<&'a IpamObject> {
        self.objects.get(&object).copied()
    }

    /// Whether the plan changes a prefix, so its entry in the base no longer counts.
    fn changes_prefix(&self, id: PrefixId) -> bool {
        self.objects.contains_key(&ObjectRef::from(id))
    }

    fn search(
        &self,
        vrf: VrfId,
        family: Family,
        value: u128,
        lengths: impl Iterator<Item = u8>,
        except: PrefixId,
    ) -> Option<PrefixId> {
        let own = self.nets.get(&(vrf, family.index()));
        let base = self.base.nets.get(&(vrf, family.index()));
        for len in lengths {
            let key = (value & !host_mask(family, len), len);
            if let Some(id) = own.and_then(|nets| nets.get(&key))
                && *id != except
            {
                return Some(*id);
            }
            if let Some(id) = base.and_then(|nets| nets.get(&key))
                && *id != except
                && !self.changes_prefix(*id)
            {
                return Some(*id);
            }
        }
        None
    }
}

impl Facts for Overlay<'_> {
    fn tenant_of(&self, vrf: VrfId) -> Option<TenantId> {
        match self.object(ObjectRef::from(vrf)) {
            Some(IpamObject::Vrf(found)) => Some(found.tenant),
            _ => self.base.tenant_of(vrf),
        }
    }

    fn site_parent(&self, site: SiteId) -> Option<SiteId> {
        match self.object(ObjectRef::from(site)) {
            Some(IpamObject::Site(found)) => found.parent,
            _ => self.base.site_parent(site),
        }
    }

    fn vlan_site(&self, vlan: VlanId) -> Option<SiteId> {
        match self.object(ObjectRef::from(vlan)) {
            Some(IpamObject::Vlan(found)) => found.site,
            _ => self.base.vlan_site(vlan),
        }
    }

    fn prefix(&self, id: PrefixId) -> Option<PrefixFacts> {
        match self.object(ObjectRef::from(id)) {
            Some(IpamObject::Prefix(found)) => Some(PrefixFacts {
                vrf: found.vrf,
                net: found.cidr,
                site: found.site,
                live: !found.meta.is_deleted(),
            }),
            _ => self.base.prefix(id),
        }
    }

    fn enclosing(&self, vrf: VrfId, net: &IpNet, except: PrefixId) -> Option<PrefixId> {
        let ((_, (value, len)), family) = net_key(net);
        self.search(vrf, family, value, (0..len).rev(), except)
    }

    fn containing(&self, vrf: VrfId, ip: IpAddr) -> Option<PrefixId> {
        let family = Family::of(ip);
        self.search(
            vrf,
            family,
            ip_to_u128(ip),
            (0..=family.bits()).rev(),
            PrefixId::from_uuid(uuid::Uuid::nil()),
        )
    }

    fn range_prefix(&self, id: RangeId) -> Option<PrefixId> {
        match self.object(ObjectRef::from(id)) {
            Some(IpamObject::Range(found)) => Some(found.prefix),
            _ => self.base.range_prefix(id),
        }
    }

    fn address(&self, id: AddressId) -> Option<AddressFacts> {
        match self.object(ObjectRef::from(id)) {
            Some(IpamObject::Address(found)) => Some(AddressFacts {
                id,
                vrf: found.vrf,
                prefix: found.prefix,
                interface: found.interface,
                live: !found.meta.is_deleted(),
            }),
            _ => self.base.address(id),
        }
    }

    fn interface(&self, id: InterfaceId) -> Option<InterfaceFacts> {
        match self.object(ObjectRef::from(id)) {
            Some(IpamObject::Interface(found)) => Some(InterfaceFacts {
                host: found.host,
                live: !found.meta.is_deleted(),
            }),
            _ => self.base.interface(id),
        }
    }

    fn host(&self, id: HostId) -> Option<HostFacts> {
        match self.object(ObjectRef::from(id)) {
            Some(IpamObject::Host(found)) => Some(HostFacts {
                tenant: found.tenant,
                site: found.site,
                live: !found.meta.is_deleted(),
            }),
            _ => self.base.host(id),
        }
    }

    fn host_addresses(&self, id: HostId) -> Vec<AddressFacts> {
        let all = self.host(id).is_some_and(|host| !host.live);
        let mut interfaces: BTreeSet<InterfaceId> =
            self.base.by_host.get(&id).cloned().unwrap_or_default();
        let mut addresses: BTreeSet<AddressId> = BTreeSet::new();
        for object in self.objects.values() {
            match object {
                IpamObject::Interface(found) if found.host == id => {
                    interfaces.insert(found.id);
                }
                IpamObject::Address(found) if found.interface.is_some() => {
                    addresses.insert(found.id);
                }
                _ => {}
            }
        }
        let interfaces: BTreeSet<InterfaceId> = interfaces
            .into_iter()
            .filter(|interface| {
                self.interface(*interface)
                    .is_some_and(|found| found.host == id && (all || found.live))
            })
            .collect();
        for interface in &interfaces {
            addresses.extend(self.base.by_interface.get(interface).into_iter().flatten());
        }
        addresses
            .into_iter()
            .filter_map(|address| self.address(address))
            .filter(|address| {
                address
                    .interface
                    .is_some_and(|interface| interfaces.contains(&interface))
                    && (all || address.live)
            })
            .collect()
    }

    fn vrfs_holding(&self, ip: IpAddr) -> Vec<VrfId> {
        self.base.vrfs_holding(ip)
    }
}

// ----- the index ------------------------------------------------------------------------

/// The anchors index of IPAM objects (IAM-01). Register it with the store once; the
/// authorizer of `tenko-auth` finds anchors through it ([`AnchorResolver`]) and the API
/// routes filter lists and check planned writes with it.
pub struct ScopeIndex {
    image: ArcSwap<RwLock<Image>>,
}

impl std::fmt::Debug for ScopeIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScopeIndex")
            .field("revision", &self.revision())
            .finish_non_exhaustive()
    }
}

impl Default for ScopeIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// One image handed from `build` to `install`.
struct BuiltImage(RwLock<Image>);

impl IndexImage for BuiltImage {
    fn revision(&self) -> Revision {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .revision
    }

    fn memory_bytes(&self) -> usize {
        let image = self.0.read().unwrap_or_else(PoisonError::into_inner);
        (image.prefixes.len() * 3
            + image.addresses.len() * 2
            + image.interfaces.len() * 2
            + image.hosts.len()
            + image.sites.len()
            + image.vrfs.len()
            + image.vlans.len()
            + image.ranges.len())
            * 64
    }
}

impl ScopeIndex {
    /// An empty index; the store fills it on registration.
    pub fn new() -> Self {
        Self {
            image: ArcSwap::from_pointee(RwLock::new(Image::default())),
        }
    }

    /// The last revision built or applied.
    pub fn revision(&self) -> Revision {
        self.image
            .load()
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .revision
    }

    fn with<R>(&self, f: impl FnOnce(&Image) -> R) -> R {
        let image = self.image.load();
        let image = image.read().unwrap_or_else(PoisonError::into_inner);
        f(&image)
    }

    /// The anchors of an IPAM object from memory (tenants, VRFs, sites, VLANs, prefixes,
    /// ranges, addresses, hosts, interfaces); other kinds anchor to themselves only.
    pub fn anchors(&self, object: &ObjectRef) -> Anchors {
        self.with(|image| anchors_with(image, *object))
    }

    /// The anchors of an object that stands for its targets (a job): the targets' anchors
    /// merged ([`merge`]).
    pub fn anchors_of_targets(&self, object: ObjectRef, targets: &[ObjectRef]) -> Anchors {
        self.with(|image| {
            let parts: Vec<Anchors> = targets
                .iter()
                .map(|target| anchors_with(image, *target))
                .collect();
            merge(object, &parts)
        })
    }

    /// The anchors of an address in a VRF, or in every VRF that holds it when the VRF is
    /// not known (an observation that names only the address).
    pub fn anchors_of_ip(&self, object: ObjectRef, vrf: Option<VrfId>, ip: IpAddr) -> Anchors {
        self.with(|image| {
            let vrfs = match vrf {
                Some(vrf) => vec![vrf],
                None => image.vrfs_holding(ip),
            };
            let parts: Vec<Anchors> = vrfs
                .into_iter()
                .filter_map(|vrf| image.containing(vrf, ip))
                .map(|prefix| prefix_anchors(image, object, prefix))
                .collect();
            if parts.is_empty() {
                Anchors::of(object)
            } else {
                merge(object, &parts)
            }
        })
    }

    /// The anchors of an observed fact: the prefixes of the addresses it names (in its VRF
    /// when the source reports one). A fact that names no address (an attachment, a link,
    /// a vendor) has none and is visible to globally reaching principals only.
    pub fn anchors_of_fact(&self, fact: &ObservedFact) -> Anchors {
        let object = ObjectRef::new(ObjectKind::Observation, fact.observation.0);
        let parts: Vec<Anchors> = observed_ips(&fact.observed)
            .into_iter()
            .map(|ip| self.anchors_of_ip(object, fact.vrf(), ip))
            .filter(anchored)
            .collect();
        merge(object, &parts)
    }

    /// The anchors of a proposal: its subject prefix, or the prefix holding its subject
    /// address or network, merged with the anchors of its objects.
    pub fn anchors_of_proposal(&self, proposal: &IntentProposal) -> Anchors {
        let object = ObjectRef::from(proposal.id);
        let subject = &proposal.subject;
        self.with(|image| {
            let mut parts = Vec::new();
            let prefix = subject.prefix.or_else(|| {
                let vrf = subject.vrf?;
                match (subject.ip, subject.cidr) {
                    (Some(ip), _) => image.containing(vrf, ip),
                    (None, Some(cidr)) => image.containing(vrf, cidr.network()),
                    (None, None) => None,
                }
            });
            if let Some(prefix) = prefix {
                parts.push(prefix_anchors(image, object, prefix));
            }
            for target in &subject.objects {
                parts.push(anchors_with(image, *target));
            }
            if parts.is_empty() {
                Anchors::of(object)
            } else {
                merge(object, &parts)
            }
        })
    }

    /// Checks every change of a plan for `principal` (IAM-01): where the authorizer's
    /// scope for the change's action and kind is narrower than everything, the object must
    /// lie inside it before and after the change ([`AnchorMode::All`]), and an interface or
    /// an address needs the right to change its host before and after as well.
    ///
    /// # Errors
    ///
    /// [`Denied`] with `auth.forbidden` when no grant allows the change, or
    /// `auth.out_of_scope` for an object outside the scope.
    pub fn check_plan(
        &self,
        authorizer: &dyn Authorizer,
        principal: &Principal,
        plan: &IpamPlan,
    ) -> Result<(), Denied> {
        let image = self.image.load();
        let image = image.read().unwrap_or_else(PoisonError::into_inner);
        let overlay = Overlay::of(&image, plan);
        let mut filters: HashMap<(Action, ObjectKind), ScopeFilter> = HashMap::new();
        let mut filter = |action: Action, kind: ObjectKind| {
            filters
                .entry((action, kind))
                .or_insert_with(|| authorizer.scope(principal, action, kind))
                .clone()
        };
        let refuse = |action: Action, object: ObjectRef, reason: DenyReason| Denied {
            action,
            object,
            reason,
        };
        for change in &plan.changes {
            let action = match change.action {
                ChangeAction::Create => Action::Create,
                ChangeAction::Delete | ChangeAction::Remove => Action::Delete,
                _ => Action::Update,
            };
            let object = change.object;
            let scope = filter(action, object.kind);
            if matches!(scope, ScopeFilter::Nothing) {
                return Err(refuse(action, object, DenyReason::MissingPermission));
            }
            let mut hosts: BTreeSet<HostId> = BTreeSet::new();
            if change.before.is_some() {
                if !scope.is_all() && !scope.admits(&anchors_with(&*image, object), AnchorMode::All)
                {
                    return Err(refuse(action, object, DenyReason::OutOfScope));
                }
                hosts.extend(owning_host(&*image, change.before.as_ref()));
            }
            if change.after.is_some() {
                if !scope.is_all()
                    && !scope.admits(&anchors_with(&overlay, object), AnchorMode::All)
                {
                    return Err(refuse(action, object, DenyReason::OutOfScope));
                }
                hosts.extend(owning_host(&overlay, change.after.as_ref()));
            }
            // Binding an interface or an address changes its host too.
            for host in hosts {
                let host_ref = ObjectRef::from(host);
                if host_ref == object {
                    continue;
                }
                let scope = filter(Action::Update, ObjectKind::Host);
                if scope.is_all() {
                    continue;
                }
                if matches!(scope, ScopeFilter::Nothing) {
                    return Err(refuse(
                        Action::Update,
                        host_ref,
                        DenyReason::MissingPermission,
                    ));
                }
                let new_host = overlay.object(host_ref).is_some() && image.host(host).is_none();
                let before_ok =
                    new_host || scope.admits(&anchors_with(&*image, host_ref), AnchorMode::All);
                let after_ok = scope.admits(&anchors_with(&overlay, host_ref), AnchorMode::All);
                if !(before_ok && after_ok) {
                    return Err(refuse(Action::Update, host_ref, DenyReason::OutOfScope));
                }
            }
        }
        Ok(())
    }

    /// Whether `principal` reaches every IPAM kind for creates, changes and deletes
    /// without a scope, so its writes need no plan check.
    pub fn unrestricted(authorizer: &dyn Authorizer, principal: &Principal) -> bool {
        crate::object::IPAM_KINDS.into_iter().all(|kind| {
            [Action::Create, Action::Update, Action::Delete]
                .into_iter()
                .all(|action| {
                    !matches!(
                        authorizer.scope(principal, action, kind),
                        ScopeFilter::Only(_)
                    )
                })
        })
    }

    /// Plans `commands` without applying them and checks the plan for the principal of
    /// `cx` (the dry run of a scoped principal, API-09).
    ///
    /// # Errors
    ///
    /// [`ScopedWriteError::Ipam`] for a planning error, [`ScopedWriteError::Denied`] when
    /// the plan leaves the principal's scope.
    pub async fn preview_checked(
        &self,
        ipam: &IpamService,
        authorizer: &dyn Authorizer,
        commands: &[IpamCommand],
        cx: &RequestCtx,
        options: &PlanOptions,
    ) -> Result<IpamPlan, ScopedWriteError> {
        let plan = ipam.preview(commands, cx, options, None).await?;
        self.check_plan(authorizer, &cx.principal, &plan)?;
        Ok(plan)
    }

    /// Plans, checks and applies `commands` with the retries of
    /// [`IpamService::execute`]; a principal without a scoped reach goes through
    /// [`IpamService::execute`] itself.
    ///
    /// # Errors
    ///
    /// [`ScopedWriteError::Ipam`] for a planning or apply error (`ipam.contended` after too
    /// many stale plans), [`ScopedWriteError::Denied`] when a plan leaves the scope.
    pub async fn execute_checked(
        &self,
        ipam: &IpamService,
        authorizer: &dyn Authorizer,
        commands: &[IpamCommand],
        cx: &RequestCtx,
        options: &PlanOptions,
    ) -> Result<Applied, ScopedWriteError> {
        if Self::unrestricted(authorizer, &cx.principal) {
            return Ok(ipam.execute(commands, cx, options).await?);
        }
        let attempts = ipam.config().max_attempts;
        for attempt in 0..attempts {
            let consistency = if attempt == 0 {
                ReadConsistency::Local
            } else {
                ReadConsistency::Linearizable
            };
            let view = ipam
                .store()
                .read(consistency)
                .await
                .map_err(IpamError::from)?;
            let plan = ipam.plan(view.as_ref(), cx, options, commands)?;
            drop(view);
            self.check_plan(authorizer, &cx.principal, &plan)?;
            match ipam.apply(&plan, cx).await {
                Ok(mut applied) => {
                    applied.retries = attempt;
                    return Ok(applied);
                }
                Err(error) if error.is(codes::PLAN_STALE) => {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        5 * u64::from(attempt + 1),
                    ))
                    .await;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(IpamError::contended(attempts).into())
    }
}

/// The host an interface or an address belongs to, as `facts` see it.
fn owning_host(facts: &dyn Facts, object: Option<&IpamObject>) -> Option<HostId> {
    match object? {
        IpamObject::Interface(interface) => Some(interface.host),
        IpamObject::Address(address) => address
            .interface
            .and_then(|interface| facts.interface(interface))
            .map(|found| found.host),
        _ => None,
    }
}

/// Why a scoped write did not happen.
#[derive(Debug, Clone)]
pub enum ScopedWriteError {
    /// Authorization refused a planned change.
    Denied(Denied),
    /// Planning or applying failed.
    Ipam(IpamError),
}

impl From<Denied> for ScopedWriteError {
    fn from(denied: Denied) -> Self {
        Self::Denied(denied)
    }
}

impl From<IpamError> for ScopedWriteError {
    fn from(error: IpamError) -> Self {
        Self::Ipam(error)
    }
}

impl DerivedIndex for ScopeIndex {
    fn name(&self) -> &'static str {
        "ipam.scope"
    }

    fn filter(&self) -> WatchFilter {
        WatchFilter::tables(tables().iter().map(|(table, _)| (*table).clone()))
    }

    fn build(&self, view: &dyn ReadView) -> Result<Box<dyn IndexImage>, StoreError> {
        let mut image = Image {
            revision: view.revision(),
            ..Image::default()
        };
        for (id, vrf, _) in view.scan_typed(&VRFS, KeyRange::all(), usize::MAX, false)? {
            image.vrfs.insert(id, vrf.tenant);
        }
        for (id, site, _) in view.scan_typed(&SITES, KeyRange::all(), usize::MAX, false)? {
            image.sites.insert(id, site.parent);
        }
        for (id, vlan, _) in view.scan_typed(&VLANS, KeyRange::all(), usize::MAX, false)? {
            image.vlans.insert(id, vlan.site);
        }
        let mut dirty = HashSet::new();
        for (id, prefix, _) in view.scan_typed(&PREFIXES, KeyRange::all(), usize::MAX, false)? {
            image.set_prefix(
                id,
                Some(PrefixFacts {
                    vrf: prefix.vrf,
                    net: prefix.cidr,
                    site: prefix.site,
                    live: !prefix.meta.is_deleted(),
                }),
                &mut dirty,
            );
        }
        for (vrf, family) in dirty {
            image.reparent(vrf, family);
        }
        for (id, range, _) in view.scan_typed(&RANGES, KeyRange::all(), usize::MAX, false)? {
            image.ranges.insert(id, range.prefix);
        }
        for (id, address, _) in view.scan_typed(&ADDRESSES, KeyRange::all(), usize::MAX, false)? {
            image.set_address(
                id,
                Some(AddressFacts {
                    id,
                    vrf: address.vrf,
                    prefix: address.prefix,
                    interface: address.interface,
                    live: !address.meta.is_deleted(),
                }),
            );
        }
        for (id, interface, _) in
            view.scan_typed(&INTERFACES, KeyRange::all(), usize::MAX, false)?
        {
            image.set_interface(
                id,
                Some(InterfaceFacts {
                    host: interface.host,
                    live: !interface.meta.is_deleted(),
                }),
            );
        }
        for (id, host, _) in view.scan_typed(&HOSTS, KeyRange::all(), usize::MAX, false)? {
            image.hosts.insert(
                id,
                HostFacts {
                    tenant: host.tenant,
                    site: host.site,
                    live: !host.meta.is_deleted(),
                },
            );
        }
        Ok(Box::new(BuiltImage(RwLock::new(image))))
    }

    fn install(&self, image: Box<dyn IndexImage>) {
        if let Some(image) = downcast_image::<BuiltImage>(image) {
            let BuiltImage(image) = *image;
            self.image.store(Arc::new(image));
        }
    }

    fn apply(&self, changes: &ChangeSet, view: &dyn ReadView) {
        let image = self.image.load();
        let mut image = image.write().unwrap_or_else(PoisonError::into_inner);
        image.revision = changes.revision;
        let mut dirty = HashSet::new();
        let tables = tables();
        for change in &changes.changes {
            let Some((_, kind)) = tables.iter().find(|(table, _)| **table == change.table) else {
                continue;
            };
            let Ok(id) = tenko_core::codec::decode_key::<uuid::Uuid>(&change.key) else {
                continue;
            };
            if let Err(error) = image.load(view, ObjectRef::new(*kind, id), &mut dirty) {
                // Keep the previous state of this entry; the next build repairs it.
                tracing::error!(%error, revision = %changes.revision, "scope index update failed");
            }
        }
        for (vrf, family) in dirty {
            image.reparent(vrf, family);
        }
    }
}

impl AnchorResolver for ScopeIndex {
    fn anchors(&self, view: &dyn ReadView, object: &ObjectRef) -> Result<Anchors, StoreError> {
        match object.kind {
            ObjectKind::Job => Ok(
                match view.get_typed(&tenko_jobs::tables::JOBS, &JobId::from_uuid(object.id))? {
                    Some((job, _)) => self.anchors_of_targets(*object, &job.spec.targets),
                    None => Anchors::of(*object),
                },
            ),
            ObjectKind::Proposal => Ok(
                match view.get_typed(&PROPOSALS, &ProposalId::from_uuid(object.id))? {
                    Some((proposal, _)) => self.anchors_of_proposal(&proposal),
                    None => Anchors::of(*object),
                },
            ),
            _ => Ok(ScopeIndex::anchors(self, object)),
        }
    }
}
