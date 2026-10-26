//! The per-VRF prefix tree: a [`DerivedIndex`] over `ipam.prefixes`, `ipam.ranges` and
//! `ipam.addresses` (ADR 0002, ADR 0011 decision 8).
//!
//! # Design
//!
//! - **Image.** One [`TreeImage`] per build: per VRF and address family, a `BTreeMap` of
//!   live prefixes keyed by `(network, length)`, a `BTreeMap` of live addresses keyed by
//!   address and a `BTreeMap` of live ranges keyed by first address. Keys are numbers within
//!   the family, so ordering by `(network, length)` lists a prefix before everything inside
//!   it: a range scan from a prefix to its last address is a pre-order walk of its subtree.
//! - **Build aside, install atomically.** The store builds an image from a read view
//!   without blocking writers and swaps it in through an `ArcSwap`, so readers never see a
//!   cleared index (on registration, start and snapshot install).
//! - **Incremental updates.** [`DerivedIndex::apply`] reads each changed object from the
//!   view of its revision and moves it in place under the VRF's write lock; location maps by
//!   identifier find the old position. Prefixes whose utilization may have changed are
//!   marked for the alarm flush ([`crate::alarm::flush`]).
//! - **Readers** take the VRF's read lock for one query; writers of other VRFs never wait.
//!
//! # Queries
//!
//! Containment ([`PrefixTree::containing`]), children, the flattened tree with
//! utilization ([`PrefixTree::tree`]), utilization per prefix, and next free addresses and
//! prefixes ([`PrefixTree::next_free_addresses`], [`PrefixTree::next_free_prefix`]) with the
//! same rules as the planner, which verifies every candidate against its read view.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
    ops::Bound,
    sync::{
        Arc, Mutex, PoisonError, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use arc_swap::ArcSwap;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{
    AddressId, PrefixId, RangeId, Revision, SiteId, VlanId, VrfId,
    codec::decode_key,
    ipam::{Address, AllocPolicy, Prefix, PrefixRole, Range, RangeRole, Status, UtilizationAlarm},
};
use tenko_store::{
    ChangeSet, DerivedIndex, IndexImage, KeyRange, ReadView, ReadViewExt, StoreError, WatchFilter,
    downcast_image,
};
use tokio::sync::Notify;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    alarm::AlarmLevel,
    alloc::{first_free_block, first_free_lazy},
    net::{
        Family, bounds, host_bounds, host_capacity, host_mask, ip_to_u128, net_from, span,
        u128_to_ip,
    },
    tables::{ADDRESSES, PREFIXES, RANGES},
};

/// Utilization of one prefix, in addresses (IPAM-10).
///
/// One definition for every prefix: the meter ([`Utilization::permille`]) is the addresses
/// in use, `used + reserved`, of the usable addresses, `capacity`.
///
/// - `used`: the live address objects inside the prefix, each address once.
/// - `reserved`: the addresses held by ranges (DHCP pools, reserved and infrastructure
///   ranges) that are not address objects.
/// - `capacity`: the usable addresses. A network loses its network and broadcast address
///   (IPv4 up to /30) or its subnet-router anycast address (IPv6 up to /126); a supernet is
///   its whole size less those addresses of every network in its tree, since an address may
///   also lie directly in a supernet.
///
/// For a supernet `used` and `reserved` are the sums over its tree. How much of its space is
/// allocated to child prefixes is a separate figure, `covered` of `size`, and never part of
/// the meter, so an alarm on a supernet does not fire on allocation alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Utilization {
    /// Usable addresses.
    pub capacity: u128,
    /// Address objects inside the prefix.
    pub used: u128,
    /// Addresses held by ranges that are not address objects.
    pub reserved: u128,
    /// Usable addresses not in use.
    pub free: u128,
    /// Addresses allocated to child prefixes.
    pub covered: u128,
    /// Every address of the prefix.
    pub size: u128,
    /// Per range role: (size, address objects inside).
    pub by_role: BTreeMap<RangeRole, (u128, u128)>,
}

impl Utilization {
    /// Addresses in use: address objects plus the addresses ranges hold without one.
    pub fn in_use(&self) -> u128 {
        self.used.saturating_add(self.reserved)
    }

    /// `used + reserved` in tenths of a percent of the capacity, at most 1000.
    pub fn permille(&self) -> u16 {
        if self.capacity == 0 {
            return 0;
        }
        #[allow(clippy::cast_precision_loss)]
        let ratio = self.in_use() as f64 / self.capacity as f64;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let permille = (ratio * 1000.0).round().clamp(0.0, 1000.0) as u16;
        permille
    }

    /// The alarm level for thresholds (IPAM-10).
    pub fn level(&self, alarm: Option<UtilizationAlarm>) -> AlarmLevel {
        let Some(alarm) = alarm else {
            return AlarmLevel::Normal;
        };
        let permille = self.permille();
        if permille >= u16::from(alarm.crit_pct) * 10 {
            AlarmLevel::Critical
        } else if permille >= u16::from(alarm.warn_pct) * 10 {
            AlarmLevel::Warning
        } else {
            AlarmLevel::Normal
        }
    }

    /// The API shape.
    pub fn view(&self) -> UtilizationView {
        UtilizationView {
            capacity: self.capacity.to_string(),
            in_use: self.in_use().to_string(),
            used: self.used.to_string(),
            reserved: self.reserved.to_string(),
            free: self.free.to_string(),
            covered: self.covered.to_string(),
            size: self.size.to_string(),
            percent: f64::from(self.permille()) / 10.0,
            by_role: self
                .by_role
                .iter()
                .map(|(role, (size, used))| RoleUsage {
                    role: *role,
                    size: size.to_string(),
                    used: used.to_string(),
                })
                .collect(),
        }
    }
}

/// Utilization as the API shows it (see [`Utilization`]). Counts are decimal strings because
/// IPv6 sizes exceed JSON's exact integers. `percent` is `in_use` of `capacity` for every
/// prefix; for a supernet `in_use`, `used` and `reserved` are sums over its tree, and
/// `covered` of `size` is the space allocated to its child prefixes, a separate figure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct UtilizationView {
    /// Usable addresses: without the network and broadcast address of a network (IPv4 up to
    /// /30) or its subnet-router anycast address (IPv6 up to /126), and for a supernet
    /// without those of every network in its tree.
    #[schema(example = "254")]
    pub capacity: String,
    /// Addresses in use: `used + reserved`.
    #[schema(example = "112")]
    pub in_use: String,
    /// Address objects inside the prefix, each address once (for a supernet: in its whole
    /// tree).
    #[schema(example = "12")]
    pub used: String,
    /// Addresses held by ranges that are not address objects (for a supernet: the ranges
    /// of every network in its tree).
    #[schema(example = "100")]
    pub reserved: String,
    /// Usable addresses not in use.
    #[schema(example = "142")]
    pub free: String,
    /// Addresses allocated to child prefixes (the union of the direct children).
    #[schema(example = "0")]
    pub covered: String,
    /// Every address of the prefix, usable or not.
    #[schema(example = "256")]
    pub size: String,
    /// `in_use` as a percentage of `capacity`, one decimal: the meter and the alarm level.
    #[schema(example = 44.1)]
    pub percent: f64,
    /// Ranges per role (for a supernet: of every network in its tree).
    pub by_role: Vec<RoleUsage>,
}

/// The ranges of one role inside a network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RoleUsage {
    /// The role.
    pub role: RangeRole,
    /// Addresses in ranges of this role.
    pub size: String,
    /// Address objects inside them.
    pub used: String,
}

/// One prefix of the flattened tree (pre-order).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct TreeNode {
    /// The prefix.
    pub id: PrefixId,
    /// The most specific prefix containing it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<PrefixId>,
    /// Depth below the first level of the answer (0 for its top level).
    pub depth: u32,
    /// The network.
    #[schema(value_type = String, example = "192.0.2.0/24")]
    pub cidr: IpNet,
    /// Supernet or network.
    pub role: PrefixRole,
    /// Status.
    pub status: Status,
    /// VLAN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<VlanId>,
    /// Site.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<SiteId>,
    /// Description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Alarm thresholds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alarm: Option<UtilizationAlarm>,
    /// Alarm level now.
    pub level: AlarmLevel,
    /// Direct child prefixes.
    pub children: u32,
    /// Utilization.
    pub utilization: UtilizationView,
}

/// What the alarm flush needs to know about one prefix.
#[derive(Debug, Clone, PartialEq)]
pub struct AlarmState {
    /// The VRF.
    pub vrf: VrfId,
    /// The network.
    pub cidr: IpNet,
    /// Thresholds.
    pub alarm: Option<UtilizationAlarm>,
    /// Utilization now.
    pub utilization: Utilization,
    /// Level now.
    pub level: AlarmLevel,
}

#[derive(Debug, Clone)]
struct PrefixNode {
    id: PrefixId,
    cidr: IpNet,
    role: PrefixRole,
    status: Status,
    vlan: Option<VlanId>,
    site: Option<SiteId>,
    description: Option<String>,
    alarm: Option<UtilizationAlarm>,
    alloc: AllocPolicy,
}

#[derive(Debug, Clone)]
struct RangeNode {
    last: u128,
    role: RangeRole,
    prefix: PrefixId,
}

#[derive(Debug, Default)]
struct FamilyTree {
    prefixes: BTreeMap<(u128, u8), PrefixNode>,
    addresses: BTreeMap<u128, AddressId>,
    ranges: BTreeMap<(u128, RangeId), RangeNode>,
}

#[derive(Debug, Default)]
struct VrfTree {
    families: [FamilyTree; 2],
}

#[derive(Debug, Clone, Copy)]
struct PrefixLoc {
    vrf: VrfId,
    family: Family,
    net: u128,
    len: u8,
}

#[derive(Debug, Clone, Copy)]
struct AddrLoc {
    vrf: VrfId,
    family: Family,
    ip: u128,
}

#[derive(Debug, Clone, Copy)]
struct RangeLoc {
    vrf: VrfId,
    family: Family,
    first: u128,
}

#[derive(Debug, Default)]
struct Locations {
    prefixes: HashMap<PrefixId, PrefixLoc>,
    addresses: HashMap<AddressId, AddrLoc>,
    ranges: HashMap<RangeId, RangeLoc>,
}

/// One built image of the tree.
#[derive(Debug, Default)]
pub struct TreeImage {
    revision: AtomicU64,
    locations: Mutex<Locations>,
    vrfs: RwLock<HashMap<VrfId, Arc<RwLock<VrfTree>>>>,
}

impl IndexImage for TreeImage {
    fn revision(&self) -> Revision {
        Revision(self.revision.load(Ordering::Acquire))
    }

    fn memory_bytes(&self) -> usize {
        let locations = self
            .locations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        (locations.prefixes.len() * 3 + locations.addresses.len() * 2 + locations.ranges.len() * 2)
            * 64
    }
}

impl TreeImage {
    fn vrf(&self, vrf: VrfId) -> Option<Arc<RwLock<VrfTree>>> {
        self.vrfs
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&vrf)
            .cloned()
    }

    fn vrf_or_new(&self, vrf: VrfId) -> Arc<RwLock<VrfTree>> {
        if let Some(tree) = self.vrf(vrf) {
            return tree;
        }
        Arc::clone(
            self.vrfs
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(vrf)
                .or_default(),
        )
    }

    /// Removes the old position of a prefix and inserts the new one; returns the prefixes
    /// whose utilization may have changed.
    fn set_prefix(&self, id: PrefixId, prefix: Option<&Prefix>) -> Vec<PrefixId> {
        let mut dirty = vec![id];
        let mut locations = self
            .locations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(old) = locations.prefixes.remove(&id)
            && let Some(tree) = self.vrf(old.vrf)
        {
            let mut tree = tree.write().unwrap_or_else(PoisonError::into_inner);
            let family = &mut tree.families[old.family.index()];
            if family
                .prefixes
                .get(&(old.net, old.len))
                .is_some_and(|node| node.id == id)
            {
                family.prefixes.remove(&(old.net, old.len));
            }
            dirty.extend(family.alarmed_ancestors(old.family, old.net, old.len));
        }
        if let Some(prefix) = prefix.filter(|p| !p.meta.is_deleted()) {
            let family = Family::of_net(&prefix.cidr);
            let (net, _) = bounds(&prefix.cidr);
            let len = prefix.cidr.prefix_len();
            let tree = self.vrf_or_new(prefix.vrf);
            let mut tree = tree.write().unwrap_or_else(PoisonError::into_inner);
            let family_tree = &mut tree.families[family.index()];
            family_tree.prefixes.insert(
                (net, len),
                PrefixNode {
                    id,
                    cidr: prefix.cidr,
                    role: prefix.role,
                    status: prefix.status,
                    vlan: prefix.vlan,
                    site: prefix.site,
                    description: prefix.meta.description.clone(),
                    alarm: prefix.alarm,
                    alloc: prefix.alloc,
                },
            );
            dirty.extend(family_tree.alarmed_ancestors(family, net, len));
            locations.prefixes.insert(
                id,
                PrefixLoc {
                    vrf: prefix.vrf,
                    family,
                    net,
                    len,
                },
            );
        }
        dirty
    }

    fn set_address(&self, id: AddressId, address: Option<&Address>) -> Vec<PrefixId> {
        let mut dirty = Vec::new();
        let mut locations = self
            .locations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(old) = locations.addresses.remove(&id)
            && let Some(tree) = self.vrf(old.vrf)
        {
            let mut tree = tree.write().unwrap_or_else(PoisonError::into_inner);
            let family = &mut tree.families[old.family.index()];
            if family.addresses.get(&old.ip) == Some(&id) {
                family.addresses.remove(&old.ip);
            }
            dirty.extend(family.alarmed_containing(old.family, old.ip));
        }
        if let Some(address) = address.filter(|a| !a.meta.is_deleted()) {
            let family = Family::of(address.ip);
            let ip = ip_to_u128(address.ip);
            let tree = self.vrf_or_new(address.vrf);
            let mut tree = tree.write().unwrap_or_else(PoisonError::into_inner);
            let family_tree = &mut tree.families[family.index()];
            family_tree.addresses.insert(ip, id);
            dirty.extend(family_tree.alarmed_containing(family, ip));
            locations.addresses.insert(
                id,
                AddrLoc {
                    vrf: address.vrf,
                    family,
                    ip,
                },
            );
        }
        dirty
    }

    fn set_range(&self, id: RangeId, range: Option<&Range>, vrf: Option<VrfId>) -> Vec<PrefixId> {
        let mut dirty = Vec::new();
        let mut locations = self
            .locations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(old) = locations.ranges.remove(&id)
            && let Some(tree) = self.vrf(old.vrf)
        {
            let mut tree = tree.write().unwrap_or_else(PoisonError::into_inner);
            let family = &mut tree.families[old.family.index()];
            if let Some(node) = family.ranges.remove(&(old.first, id)) {
                dirty.push(node.prefix);
                // The supernets above count the range's addresses too.
                dirty.extend(family.alarmed_containing(old.family, old.first));
            }
        }
        if let (Some(range), Some(vrf)) = (range.filter(|r| !r.meta.is_deleted()), vrf) {
            let family = Family::of(range.first);
            let first = ip_to_u128(range.first);
            let tree = self.vrf_or_new(vrf);
            let mut tree = tree.write().unwrap_or_else(PoisonError::into_inner);
            let family_tree = &mut tree.families[family.index()];
            family_tree.ranges.insert(
                (first, id),
                RangeNode {
                    last: ip_to_u128(range.last),
                    role: range.role,
                    prefix: range.prefix,
                },
            );
            dirty.push(range.prefix);
            dirty.extend(family_tree.alarmed_containing(family, first));
            locations.ranges.insert(id, RangeLoc { vrf, family, first });
        }
        dirty
    }

    fn prefix_vrf(&self, prefix: PrefixId) -> Option<VrfId> {
        self.locations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .prefixes
            .get(&prefix)
            .map(|loc| loc.vrf)
    }
}

impl FamilyTree {
    /// Prefixes containing `ip` (most specific first) that have alarm thresholds.
    fn alarmed_containing(&self, family: Family, ip: u128) -> Vec<PrefixId> {
        (0..=family.bits())
            .rev()
            .filter_map(|len| {
                self.prefixes
                    .get(&(ip & !host_mask(family, len), len))
                    .filter(|node| node.alarm.is_some())
                    .map(|node| node.id)
            })
            .collect()
    }

    /// Prefixes strictly containing `(net, len)` that have alarm thresholds.
    fn alarmed_ancestors(&self, family: Family, net: u128, len: u8) -> Vec<PrefixId> {
        (0..len)
            .rev()
            .filter_map(|l| {
                self.prefixes
                    .get(&(net & !host_mask(family, l), l))
                    .filter(|node| node.alarm.is_some())
                    .map(|node| node.id)
            })
            .collect()
    }

    /// The most specific prefix containing `ip`.
    fn containing(&self, family: Family, ip: u128) -> Option<&PrefixNode> {
        (0..=family.bits())
            .rev()
            .find_map(|len| self.prefixes.get(&(ip & !host_mask(family, len), len)))
    }

    /// The most specific prefix strictly containing `(net, len)`.
    fn parent(&self, family: Family, net: u128, len: u8) -> Option<&PrefixNode> {
        (0..len)
            .rev()
            .find_map(|l| self.prefixes.get(&(net & !host_mask(family, l), l)))
    }

    /// Prefixes strictly inside `(net, len)`, in pre-order.
    fn descendants(
        &self,
        family: Family,
        net: u128,
        len: u8,
    ) -> impl Iterator<Item = (&(u128, u8), &PrefixNode)> {
        let last = net | host_mask(family, len);
        self.prefixes.range((
            Bound::Excluded((net, len)),
            Bound::Included((last, u8::MAX)),
        ))
    }

    /// The maximal child intervals of `(net, len)`.
    fn child_intervals(&self, family: Family, net: u128, len: u8) -> Vec<(u128, u128)> {
        let mut out: Vec<(u128, u128)> = Vec::new();
        for ((child, child_len), _) in self.descendants(family, net, len) {
            let end = *child | host_mask(family, *child_len);
            match out.last() {
                Some((_, last)) if *child <= *last => {}
                _ => out.push((*child, end)),
            }
        }
        out
    }

    fn count_addresses(&self, first: u128, last: u128) -> u128 {
        self.addresses.range(first..=last).count() as u128
    }

    /// The ranges of a prefix as `(first, last, role)`.
    fn ranges_of(&self, prefix: PrefixId, first: u128, last: u128) -> Vec<(u128, u128, RangeRole)> {
        self.ranges
            .range((
                Bound::Included((first, RangeId::from_uuid(Uuid::nil()))),
                Bound::Included((last, RangeId::from_uuid(Uuid::max()))),
            ))
            .filter(|(_, node)| node.prefix == prefix)
            .map(|((range_first, _), node)| (*range_first, node.last, node.role))
            .collect()
    }

    /// The addresses held by the ranges of a network that are not address objects, and the
    /// ranges per role as (size, address objects inside).
    fn range_usage(&self, node: &PrefixNode) -> (u128, BTreeMap<RangeRole, (u128, u128)>) {
        let (first, last) = bounds(&node.cidr);
        let mut reserved = 0u128;
        let mut by_role: BTreeMap<RangeRole, (u128, u128)> = BTreeMap::new();
        for (range_first, range_last, role) in self.ranges_of(node.id, first, last) {
            let size = span(range_first, range_last);
            let inside = self.count_addresses(range_first, range_last);
            reserved = reserved.saturating_add(size.saturating_sub(inside));
            let entry = by_role.entry(role).or_default();
            entry.0 = entry.0.saturating_add(size);
            entry.1 = entry.1.saturating_add(inside);
        }
        (reserved, by_role)
    }

    fn utilization(&self, family: Family, node: &PrefixNode) -> Utilization {
        let (first, last) = bounds(&node.cidr);
        let len = node.cidr.prefix_len();
        let size = span(first, last);
        let covered = self
            .child_intervals(family, first, len)
            .iter()
            .fold(0u128, |sum, (a, b)| sum.saturating_add(span(*a, *b)));
        // Addresses are keyed by address, so a count over the span counts each one once,
        // however deep below the prefix it lies.
        let used = self.count_addresses(first, last);
        let (capacity, reserved, by_role) = match node.role {
            PrefixRole::Network => {
                let (reserved, by_role) = self.range_usage(node);
                (host_capacity(&node.cidr), reserved, by_role)
            }
            PrefixRole::Supernet => {
                // Networks never contain prefixes, so the networks of the tree are disjoint
                // and the ranges of each one are counted once.
                let mut capacity = size;
                let mut reserved = 0u128;
                let mut by_role: BTreeMap<RangeRole, (u128, u128)> = BTreeMap::new();
                for (_, child) in self
                    .descendants(family, first, len)
                    .filter(|(_, child)| child.role == PrefixRole::Network)
                {
                    let (child_first, child_last) = bounds(&child.cidr);
                    let unusable =
                        span(child_first, child_last).saturating_sub(host_capacity(&child.cidr));
                    capacity = capacity.saturating_sub(unusable);
                    let (held, roles) = self.range_usage(child);
                    reserved = reserved.saturating_add(held);
                    for (role, (role_size, inside)) in roles {
                        let entry = by_role.entry(role).or_default();
                        entry.0 = entry.0.saturating_add(role_size);
                        entry.1 = entry.1.saturating_add(inside);
                    }
                }
                (capacity, reserved, by_role)
            }
        };
        Utilization {
            capacity,
            used,
            reserved,
            free: capacity.saturating_sub(used.saturating_add(reserved)),
            covered,
            size,
            by_role,
        }
    }
}

/// The prefix tree index. Register it with the store once
/// ([`Store::register_index`](tenko_store::Store::register_index)); the IPAM service does.
pub struct PrefixTree {
    image: ArcSwap<TreeImage>,
    dirty: Mutex<BTreeSet<PrefixId>>,
    changed: Notify,
}

impl std::fmt::Debug for PrefixTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrefixTree")
            .field("revision", &self.revision())
            .finish_non_exhaustive()
    }
}

impl Default for PrefixTree {
    fn default() -> Self {
        Self::new()
    }
}

impl PrefixTree {
    /// An empty tree; the store fills it on registration.
    pub fn new() -> Self {
        Self {
            image: ArcSwap::from_pointee(TreeImage::default()),
            dirty: Mutex::new(BTreeSet::new()),
            changed: Notify::new(),
        }
    }

    /// The last revision built or applied.
    pub fn revision(&self) -> Revision {
        self.image.load().revision()
    }

    /// Prefixes marked for the alarm flush since the last call.
    pub fn take_dirty(&self) -> BTreeSet<PrefixId> {
        std::mem::take(&mut *self.dirty.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Marks prefixes for the next alarm flush.
    pub fn mark_dirty(&self, prefixes: impl IntoIterator<Item = PrefixId>) {
        let mut dirty = self.dirty.lock().unwrap_or_else(PoisonError::into_inner);
        let before = dirty.len();
        dirty.extend(prefixes);
        if dirty.len() > before {
            self.changed.notify_one();
        }
    }

    /// Waits until prefixes are marked for the alarm flush.
    pub async fn changed(&self) {
        self.changed.notified().await;
    }

    fn with_family<R>(
        &self,
        vrf: VrfId,
        family: Family,
        f: impl FnOnce(&FamilyTree) -> R,
    ) -> Option<R> {
        let image = self.image.load();
        let tree = image.vrf(vrf)?;
        let tree = tree.read().unwrap_or_else(PoisonError::into_inner);
        Some(f(&tree.families[family.index()]))
    }

    fn locate(&self, prefix: PrefixId) -> Option<PrefixLoc> {
        self.image
            .load()
            .locations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .prefixes
            .get(&prefix)
            .copied()
    }

    /// The VRF and network of a live prefix.
    pub fn prefix(&self, prefix: PrefixId) -> Option<(VrfId, IpNet)> {
        let loc = self.locate(prefix)?;
        Some((loc.vrf, net_from(loc.family, loc.net, loc.len)))
    }

    /// The most specific live prefix of the VRF containing `ip`.
    pub fn containing(&self, vrf: VrfId, ip: IpAddr) -> Option<PrefixId> {
        let family = Family::of(ip);
        self.with_family(vrf, family, |tree| {
            tree.containing(family, ip_to_u128(ip)).map(|node| node.id)
        })
        .flatten()
    }

    /// The direct child prefixes of a prefix, in order.
    pub fn children(&self, prefix: PrefixId) -> Vec<PrefixId> {
        let Some(loc) = self.locate(prefix) else {
            return Vec::new();
        };
        self.with_family(loc.vrf, loc.family, |tree| {
            let mut out = Vec::new();
            let mut end: Option<u128> = None;
            for ((net, len), node) in tree.descendants(loc.family, loc.net, loc.len) {
                if end.is_some_and(|end| *net <= end) {
                    continue;
                }
                end = Some(*net | host_mask(loc.family, *len));
                out.push(node.id);
            }
            out
        })
        .unwrap_or_default()
    }

    /// Utilization of a live prefix.
    pub fn utilization(&self, prefix: PrefixId) -> Option<Utilization> {
        let loc = self.locate(prefix)?;
        self.with_family(loc.vrf, loc.family, |tree| {
            tree.prefixes
                .get(&(loc.net, loc.len))
                .map(|node| tree.utilization(loc.family, node))
        })
        .flatten()
    }

    /// Thresholds, utilization and level of a live prefix.
    pub fn alarm_state(&self, prefix: PrefixId) -> Option<AlarmState> {
        let loc = self.locate(prefix)?;
        self.with_family(loc.vrf, loc.family, |tree| {
            tree.prefixes.get(&(loc.net, loc.len)).map(|node| {
                let utilization = tree.utilization(loc.family, node);
                AlarmState {
                    vrf: loc.vrf,
                    cidr: node.cidr,
                    alarm: node.alarm,
                    level: utilization.level(node.alarm),
                    utilization,
                }
            })
        })
        .flatten()
    }

    /// The prefixes of a VRF in pre-order with depth, parent, child count, utilization and
    /// alarm level; only those inside `within` when given, and down to `max_depth` levels.
    pub fn tree(&self, vrf: VrfId, within: Option<IpNet>, max_depth: Option<u32>) -> Vec<TreeNode> {
        let families: Vec<Family> = match within {
            Some(net) => vec![Family::of_net(&net)],
            None => vec![Family::V4, Family::V6],
        };
        let mut out = Vec::new();
        for family in families {
            self.with_family(vrf, family, |tree| {
                collect_tree(tree, family, within, max_depth, &mut out);
            });
        }
        out
    }

    /// Up to `count` free addresses of a prefix by its allocation policy (or `policy`),
    /// outside its ranges and child prefixes, or inside one of its ranges.
    pub fn next_free_addresses(
        &self,
        prefix: PrefixId,
        policy: Option<AllocPolicy>,
        range: Option<RangeId>,
        count: usize,
    ) -> Vec<IpAddr> {
        let Some(loc) = self.locate(prefix) else {
            return Vec::new();
        };
        let range_loc = range.and_then(|id| {
            self.image
                .load()
                .locations
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .ranges
                .get(&id)
                .copied()
                .map(|loc| (id, loc))
        });
        self.with_family(loc.vrf, loc.family, |tree| {
            let Some(node) = tree.prefixes.get(&(loc.net, loc.len)) else {
                return Vec::new();
            };
            let policy = policy.unwrap_or(node.alloc);
            let (mut lo, mut hi) = match node.role {
                PrefixRole::Network => host_bounds(&node.cidr),
                PrefixRole::Supernet => bounds(&node.cidr),
            };
            let mut blocked = tree.child_intervals(loc.family, loc.net, loc.len);
            match (range, range_loc) {
                (Some(_), None) => return Vec::new(),
                (Some(_), Some((id, range_loc))) => {
                    let Some(range) = tree.ranges.get(&(range_loc.first, id)) else {
                        return Vec::new();
                    };
                    if range.prefix != node.id {
                        return Vec::new();
                    }
                    lo = lo.max(range_loc.first);
                    hi = hi.min(range.last);
                }
                (None, _) => {
                    let (first, last) = bounds(&node.cidr);
                    blocked.extend(
                        tree.ranges_of(node.id, first, last)
                            .into_iter()
                            .map(|(a, b, _)| (a, b)),
                    );
                }
            }
            let mut out = Vec::with_capacity(count);
            while out.len() < count {
                let Some(value) = first_free_lazy(lo, hi, blocked.clone(), &tree.addresses, policy)
                else {
                    break;
                };
                blocked.push((value, value));
                out.push(u128_to_ip(loc.family, value));
            }
            out
        })
        .unwrap_or_default()
    }

    /// The free child prefix of length `len` of a supernet by its allocation policy (or
    /// `policy`), avoiding child prefixes and addresses directly inside it.
    pub fn next_free_prefix(
        &self,
        parent: PrefixId,
        len: u8,
        policy: Option<AllocPolicy>,
    ) -> Option<IpNet> {
        let loc = self.locate(parent)?;
        self.with_family(loc.vrf, loc.family, |tree| {
            let node = tree.prefixes.get(&(loc.net, loc.len))?;
            if node.role != PrefixRole::Supernet || len <= loc.len || len > loc.family.bits() {
                return None;
            }
            let policy = policy.unwrap_or(node.alloc);
            let (first, last) = bounds(&node.cidr);
            let children = tree.child_intervals(loc.family, loc.net, loc.len);
            // Addresses directly in the supernet lie in the gaps between its children.
            let mut blocked = children.clone();
            let mut cursor = Some(first);
            for (a, b) in &children {
                if let Some(start) = cursor
                    && *a > start
                {
                    blocked.extend(tree.addresses.range(start..*a).map(|(ip, _)| (*ip, *ip)));
                }
                cursor = b.checked_add(1);
            }
            if let Some(start) = cursor
                && start <= last
            {
                blocked.extend(tree.addresses.range(start..=last).map(|(ip, _)| (*ip, *ip)));
            }
            first_free_block(loc.family, first, last, len, blocked, policy)
                .map(|start| net_from(loc.family, start, len))
        })
        .flatten()
    }

    fn apply_change(
        image: &TreeImage,
        change: &tenko_store::Change,
        view: &dyn ReadView,
    ) -> Result<Vec<PrefixId>, StoreError> {
        let table = &change.table;
        if table == PREFIXES.name() {
            let id: PrefixId = decode_key(&change.key)?;
            let prefix = if change.deleted {
                None
            } else {
                view.get_typed(&PREFIXES, &id)?.map(|(p, _)| p)
            };
            Ok(image.set_prefix(id, prefix.as_ref()))
        } else if table == ADDRESSES.name() {
            let id: AddressId = decode_key(&change.key)?;
            let address = if change.deleted {
                None
            } else {
                view.get_typed(&ADDRESSES, &id)?.map(|(a, _)| a)
            };
            Ok(image.set_address(id, address.as_ref()))
        } else if table == RANGES.name() {
            let id: RangeId = decode_key(&change.key)?;
            let range = if change.deleted {
                None
            } else {
                view.get_typed(&RANGES, &id)?.map(|(r, _)| r)
            };
            let vrf = match &range {
                Some(range) => match image.prefix_vrf(range.prefix) {
                    Some(vrf) => Some(vrf),
                    None => view
                        .get_typed(&PREFIXES, &range.prefix)?
                        .map(|(p, _)| p.vrf),
                },
                None => None,
            };
            Ok(image.set_range(id, range.as_ref(), vrf))
        } else {
            Ok(Vec::new())
        }
    }
}

fn collect_tree(
    tree: &FamilyTree,
    family: Family,
    within: Option<IpNet>,
    max_depth: Option<u32>,
    out: &mut Vec<TreeNode>,
) {
    let iter: Box<dyn Iterator<Item = (&(u128, u8), &PrefixNode)>> = match within {
        Some(net) => {
            let (first, last) = bounds(&net);
            Box::new(tree.prefixes.range((
                Bound::Included((first, net.prefix_len())),
                Bound::Included((last, u8::MAX)),
            )))
        }
        None => Box::new(tree.prefixes.iter()),
    };
    // Stack of (last address, index in `out` or usize::MAX when filtered by depth, id).
    let mut stack: Vec<(u128, usize, PrefixId)> = Vec::new();
    for ((net, len), node) in iter {
        while stack.last().is_some_and(|(end, _, _)| *end < *net) {
            stack.pop();
        }
        let depth = u32::try_from(stack.len()).unwrap_or(u32::MAX);
        let parent = match stack.last() {
            Some((_, _, id)) => Some(*id),
            None => tree.parent(family, *net, *len).map(|p| p.id),
        };
        if let Some((_, index, _)) = stack.last()
            && *index != usize::MAX
            && let Some(entry) = out.get_mut(*index)
        {
            entry.children += 1;
        }
        let index = if max_depth.is_none_or(|max| depth <= max) {
            let utilization = tree.utilization(family, node);
            out.push(TreeNode {
                id: node.id,
                parent,
                depth,
                cidr: node.cidr,
                role: node.role,
                status: node.status,
                vlan: node.vlan,
                site: node.site,
                description: node.description.clone(),
                alarm: node.alarm,
                level: utilization.level(node.alarm),
                children: 0,
                utilization: utilization.view(),
            });
            out.len() - 1
        } else {
            usize::MAX
        };
        stack.push((*net | host_mask(family, *len), index, node.id));
    }
}

impl DerivedIndex for PrefixTree {
    fn name(&self) -> &'static str {
        "ipam.prefix_tree"
    }

    fn filter(&self) -> WatchFilter {
        WatchFilter::tables([
            PREFIXES.name().clone(),
            RANGES.name().clone(),
            ADDRESSES.name().clone(),
        ])
    }

    fn build(&self, view: &dyn ReadView) -> Result<Box<dyn IndexImage>, StoreError> {
        let image = TreeImage::default();
        for (id, prefix, _) in view.scan_typed(&PREFIXES, KeyRange::all(), usize::MAX, false)? {
            image.set_prefix(id, Some(&prefix));
        }
        for (id, address, _) in view.scan_typed(&ADDRESSES, KeyRange::all(), usize::MAX, false)? {
            image.set_address(id, Some(&address));
        }
        for (id, range, _) in view.scan_typed(&RANGES, KeyRange::all(), usize::MAX, false)? {
            let vrf = image.prefix_vrf(range.prefix);
            image.set_range(id, Some(&range), vrf);
        }
        image.revision.store(view.revision().0, Ordering::Release);
        Ok(Box::new(image))
    }

    fn install(&self, image: Box<dyn IndexImage>) {
        let Some(image) = downcast_image::<TreeImage>(image) else {
            tracing::error!("prefix tree: install received a foreign image");
            return;
        };
        self.image.store(Arc::from(image));
        // Alarm levels may differ in the new image: re-check every prefix with thresholds.
        let alarmed: Vec<PrefixId> = self.alarmed_prefixes();
        self.mark_dirty(alarmed);
    }

    fn apply(&self, changes: &ChangeSet, view: &dyn ReadView) {
        let image = self.image.load();
        let mut dirty = Vec::new();
        for change in &changes.changes {
            match Self::apply_change(&image, change, view) {
                Ok(marked) => dirty.extend(marked),
                Err(error) => tracing::warn!(
                    %error,
                    revision = %changes.revision,
                    table = %change.table,
                    "prefix tree: change not applied"
                ),
            }
        }
        image.revision.store(changes.revision.0, Ordering::Release);
        self.mark_dirty(dirty);
    }
}

impl PrefixTree {
    fn alarmed_prefixes(&self) -> Vec<PrefixId> {
        let image = self.image.load();
        let vrfs: Vec<Arc<RwLock<VrfTree>>> = image
            .vrfs
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        let mut out = Vec::new();
        for tree in vrfs {
            let tree = tree.read().unwrap_or_else(PoisonError::into_inner);
            for family in &tree.families {
                out.extend(
                    family
                        .prefixes
                        .values()
                        .filter(|node| node.alarm.is_some())
                        .map(|node| node.id),
                );
            }
        }
        out
    }
}
