//! The production index (WP4.1): [`ZoneIndex`], what the engine answers from.
//!
//! # Layout
//!
//! Each scope of each zone is one name tree in two layers:
//!
//! - **The base** is built once from rows and never changes: every owner name (and every
//!   empty non-terminal) is stored once in one arena of wire names, its RRsets as runs of
//!   [`Rdata`] (the stored wire form the codec copies from, shared with the rows), and an
//!   open-addressing table of `u32` slots maps a name to its node. A lookup hashes the name
//!   once and compares it with the arena; it touches no allocation.
//! - **The overlay** holds the nodes that changed since the base was built: a small map
//!   from a name to its new node, or to a tombstone. A lookup reads the overlay first when
//!   it is not empty. When it grows past an eighth of the base (at least 1,024 nodes) the
//!   writer folds it into a new base.
//!
//! A [`ZoneIndex`] is immutable. [`ZoneIndex::apply`] returns a new index that shares every
//! base and every untouched zone with the old one and copies only the overlays it changes,
//! so the serving side swaps one pointer (an `ArcSwap`, as ADR 0002's index swap does) and
//! lookups are never blocked. Deltas are applied in revision order by one writer
//! ([`crate::catalog::CatalogHandle`]).
//!
//! # Lookup
//!
//! The zone is the one with the longest apex that encloses the name. Inside a scope the
//! exact name is tried first (the common case is one probe); otherwise the closest encloser
//! is found by walking up the name's ancestors. Zone cuts and DNAMEs are checked on the
//! existing ancestors from the apex down only in scopes that have any, so a zone without
//! delegations pays nothing for them. Wildcards are synthesized at the closest encloser
//! (RFC 4592). The semantics are those of the reference [`MemIndex`](crate::index::MemIndex),
//! and the tests hold the two against each other.
//!
//! RRsets of a zone that is not in the index (yet) are kept aside and join it when the
//! zone arrives; a zone that leaves puts its RRsets aside the same way.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap, hash_map::RandomState},
    hash::{BuildHasher, Hasher},
    ops::Bound,
    sync::Arc,
};

use tenko_core::{
    Revision,
    dns::{Rdata, RrSet, RrSetKey, Rtype, ScopeName, Zone, ZoneId, ZoneKind},
};

use crate::{
    feed::{Change, Delta, DnsData, FeedError},
    index::{Index, Lookup, RrSetView, ScopeOf, ZoneView, canonical_key},
    name::{self, MAX_NAME_LEN},
};

/// The overlay of a scope is folded into a new base when it holds more than this many
/// nodes and more than an eighth of the base.
const MIN_COMPACT: usize = 1024;

// ---------------------------------------------------------------------------------------
// Hashing

const MULTIPLIER: u64 = 0x517c_c1b7_2722_0a95;

fn fmix(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^ (h >> 33)
}

fn mix(state: u64, bytes: &[u8]) -> u64 {
    let mut h = state;
    let (words, rest) = bytes.as_chunks::<8>();
    for word in words {
        h = (h.rotate_left(5) ^ u64::from_le_bytes(*word)).wrapping_mul(MULTIPLIER);
    }
    if !rest.is_empty() {
        let mut word = [0u8; 8];
        word[..rest.len()].copy_from_slice(rest);
        h = (h.rotate_left(5) ^ u64::from_le_bytes(word)).wrapping_mul(MULTIPLIER);
    }
    h
}

/// A fast hash of wire names with a random seed per process. The tables hash names from
/// zone data, not from queries, so the speed of a multiply-rotate hash with a final
/// avalanche is worth more here than the flooding resistance of `SipHash`.
#[derive(Debug, Clone, Copy)]
struct Seeded(u64);

impl Seeded {
    fn new() -> Self {
        Self(RandomState::new().hash_one(0x7465_6e6b_6f00_u64))
    }

    fn hash(self, name: &[u8]) -> u64 {
        fmix(mix(self.0 ^ name.len() as u64, name))
    }
}

impl BuildHasher for Seeded {
    type Hasher = SeededHasher;

    fn build_hasher(&self) -> SeededHasher {
        SeededHasher(self.0)
    }
}

/// The streaming form of [`Seeded`] for the maps of the overlay and the apexes.
#[derive(Debug)]
struct SeededHasher(u64);

impl Hasher for SeededHasher {
    fn write(&mut self, bytes: &[u8]) {
        self.0 = mix(self.0, bytes);
    }

    fn finish(&self) -> u64 {
        fmix(self.0)
    }
}

type NameMap<V> = HashMap<Box<[u8]>, V, Seeded>;

// ---------------------------------------------------------------------------------------
// Canonical order (RFC 4034, section 6.1) without allocating

/// The start of each label of a wire name, leftmost first; returns the count.
fn label_starts(wire: &[u8], out: &mut [u8; 128]) -> usize {
    let mut count = 0;
    let mut pos = 0;
    while let Some(&len) = wire.get(pos) {
        if len == 0 || count == out.len() {
            break;
        }
        // A wire name is at most 255 octets, so a position fits a byte.
        out[count] = u8::try_from(pos).unwrap_or(u8::MAX);
        count += 1;
        pos += 1 + usize::from(len);
    }
    count
}

fn label_at(wire: &[u8], start: u8) -> &[u8] {
    let start = usize::from(start);
    let len = usize::from(wire[start]);
    wire.get(start + 1..start + 1 + len).unwrap_or_default()
}

/// Compares two lowercase wire names in the canonical order: label by label from the root.
pub fn canonical_cmp(a: &[u8], b: &[u8]) -> Ordering {
    let (mut starts_a, mut starts_b) = ([0u8; 128], [0u8; 128]);
    let count_a = label_starts(a, &mut starts_a);
    let count_b = label_starts(b, &mut starts_b);
    for index in 0..count_a.min(count_b) {
        let label_a = label_at(a, starts_a[count_a - 1 - index]);
        let label_b = label_at(b, starts_b[count_b - 1 - index]);
        match label_a.cmp(label_b) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    count_a.cmp(&count_b)
}

/// Writes the canonical key of [`canonical_key`] into a buffer; returns its length.
fn canonical_into(wire: &[u8], out: &mut [u8; MAX_NAME_LEN]) -> usize {
    let mut starts = [0u8; 128];
    let count = label_starts(wire, &mut starts);
    let mut len = 0;
    for index in (0..count).rev() {
        for &byte in label_at(wire, starts[index]) {
            if len < out.len() {
                out[len] = byte;
                len += 1;
            }
        }
        if len < out.len() {
            out[len] = 0;
            len += 1;
        }
    }
    len
}

// ---------------------------------------------------------------------------------------
// Nodes

/// An RRset of a node being built or changed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnedSet {
    rtype: Rtype,
    ttl: u32,
    rdata: Box<[Rdata]>,
}

/// A node of the overlay: its RRsets in type order and the number of its children.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct OwnedNode {
    sets: Vec<OwnedSet>,
    children: u32,
}

impl OwnedNode {
    fn exists(&self) -> bool {
        !self.sets.is_empty() || self.children > 0
    }

    fn put(&mut self, rtype: Rtype, value: Option<(u32, Box<[Rdata]>)>) {
        self.sets.retain(|set| set.rtype != rtype);
        if let Some((ttl, rdata)) = value {
            let at = self.sets.partition_point(|set| set.rtype < rtype);
            self.sets.insert(at, OwnedSet { rtype, ttl, rdata });
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct BaseNode {
    name: u32,
    sets: u32,
    children: u32,
    set_count: u16,
    name_len: u8,
}

#[derive(Debug, Clone, Copy)]
struct BaseSet {
    rtype: Rtype,
    count: u16,
    ttl: u32,
    rdata: u32,
}

/// The immutable layer of a scope: names in one arena, nodes, RRsets and record data in
/// flat vectors, a table of `u32` slots, and the NSEC owners in canonical order.
#[derive(Debug)]
struct Base {
    hash: Seeded,
    names: Vec<u8>,
    nodes: Vec<BaseNode>,
    sets: Vec<BaseSet>,
    rdata: Vec<Rdata>,
    slots: Box<[u32]>,
    nsec: Vec<u32>,
    // WP6.3: the NSEC3 owners in canonical order, which is hash order.
    nsec3: Vec<u32>,
}

/// A node of either layer.
#[derive(Debug, Clone, Copy)]
enum NodeRef<'a> {
    Base(&'a Base, &'a BaseNode),
    Owned(&'a [u8], &'a OwnedNode),
}

impl<'a> NodeRef<'a> {
    fn owner(self) -> &'a [u8] {
        match self {
            NodeRef::Base(base, node) => base.name_of(node),
            NodeRef::Owned(owner, _) => owner,
        }
    }

    fn children(self) -> u32 {
        match self {
            NodeRef::Base(_, node) => node.children,
            NodeRef::Owned(_, node) => node.children,
        }
    }

    fn set(self, index: usize) -> Option<RrSetView<'a>> {
        match self {
            NodeRef::Base(base, node) => {
                if index >= usize::from(node.set_count) {
                    return None;
                }
                let set = base.sets.get(node.sets as usize + index)?;
                let start = set.rdata as usize;
                Some(RrSetView {
                    owner: base.name_of(node),
                    rtype: set.rtype,
                    ttl: set.ttl,
                    rdata: base.rdata.get(start..start + usize::from(set.count))?,
                })
            }
            NodeRef::Owned(owner, node) => node.sets.get(index).map(|set| RrSetView {
                owner,
                rtype: set.rtype,
                ttl: set.ttl,
                rdata: &set.rdata,
            }),
        }
    }

    fn sets(self) -> impl Iterator<Item = RrSetView<'a>> {
        (0..).map_while(move |index| self.set(index))
    }

    fn get(self, rtype: Rtype) -> Option<RrSetView<'a>> {
        self.sets().find(|set| set.rtype == rtype)
    }

    fn first(self) -> Option<RrSetView<'a>> {
        self.set(0)
    }

    fn to_owned(self) -> OwnedNode {
        OwnedNode {
            sets: self
                .sets()
                .map(|set| OwnedSet {
                    rtype: set.rtype,
                    ttl: set.ttl,
                    rdata: set.rdata.into(),
                })
                .collect(),
            children: self.children(),
        }
    }

    /// A zone cut (NS below the apex) or a DNAME: something that changes the names below.
    fn is_guard(self, apex: bool) -> bool {
        self.sets()
            .any(|set| set.rtype == Rtype::DNAME || (!apex && set.rtype == Rtype::NS))
    }
}

/// What a base is built from: the nodes with their RRsets (empty non-terminals and the
/// child counts are derived).
type Rows = HashMap<Vec<u8>, Vec<OwnedSet>, Seeded>;

impl Base {
    /// Octets of the arrays and of the record data (see [`IndexStats::base_bytes`]).
    fn memory_bytes(&self) -> usize {
        use std::mem::size_of;
        self.names.capacity()
            + self.nodes.capacity() * size_of::<BaseNode>()
            + self.sets.capacity() * size_of::<BaseSet>()
            + self.rdata.capacity() * size_of::<Rdata>()
            + self
                .rdata
                .iter()
                .map(|rdata| rdata.as_bytes().len())
                .sum::<usize>()
            + self.slots.len() * size_of::<u32>()
            + self.nsec.capacity() * size_of::<u32>()
            + self.nsec3.capacity() * size_of::<u32>()
    }

    fn empty() -> Self {
        Self {
            hash: Seeded::new(),
            names: Vec::new(),
            nodes: Vec::new(),
            sets: Vec::new(),
            rdata: Vec::new(),
            slots: Box::new([0; 2]),
            nsec: Vec::new(),
            nsec3: Vec::new(),
        }
    }

    fn name_of(&self, node: &BaseNode) -> &[u8] {
        let start = node.name as usize;
        &self.names[start..start + usize::from(node.name_len)]
    }

    fn len(&self) -> usize {
        self.nodes.len()
    }

    fn find(&self, name: &[u8]) -> Option<&BaseNode> {
        if self.nodes.is_empty() {
            return None;
        }
        let mask = self.slots.len() - 1;
        // Truncation to the table size is the point.
        #[allow(clippy::cast_possible_truncation)]
        let mut slot = self.hash.hash(name) as usize & mask;
        loop {
            let entry = self.slots[slot];
            if entry == 0 {
                return None;
            }
            let node = &self.nodes[entry as usize - 1];
            if self.name_of(node) == name {
                return Some(node);
            }
            slot = (slot + 1) & mask;
        }
    }

    /// Builds a base for the zone at `apex` from its nodes with data.
    fn build(apex: &[u8], rows: Rows) -> Self {
        let hash = Seeded::new();
        let apex_labels = name::label_count(apex);
        let mut nodes: HashMap<Vec<u8>, OwnedNode, Seeded> =
            HashMap::with_capacity_and_hasher(rows.len() + rows.len() / 4, hash);
        let mut owners = Vec::with_capacity(rows.len());
        for (owner, mut sets) in rows {
            if sets.is_empty() || !name::is_within(&owner, apex) {
                continue;
            }
            sets.sort_by_key(|set| set.rtype);
            owners.push(owner.clone());
            nodes.insert(owner, OwnedNode { sets, children: 0 });
        }
        // Count children, creating the empty non-terminals on the way up.
        for owner in &owners {
            let mut child: &[u8] = owner;
            while child.len() > apex.len() && name::label_count(child) > apex_labels {
                let parent = name::suffix(child, 1);
                if let Some(node) = nodes.get_mut(parent) {
                    node.children += 1;
                    break;
                }
                nodes.insert(
                    parent.to_vec(),
                    OwnedNode {
                        sets: Vec::new(),
                        children: 1,
                    },
                );
                child = parent;
            }
        }
        Self::lay_out(hash, nodes)
    }

    fn lay_out(hash: Seeded, nodes: HashMap<Vec<u8>, OwnedNode, Seeded>) -> Self {
        let count = nodes.len();
        let mut base = Self {
            hash,
            names: Vec::with_capacity(nodes.keys().map(Vec::len).sum()),
            nodes: Vec::with_capacity(count),
            sets: Vec::with_capacity(nodes.values().map(|node| node.sets.len()).sum()),
            rdata: Vec::with_capacity(
                nodes
                    .values()
                    .flat_map(|node| node.sets.iter().map(|set| set.rdata.len()))
                    .sum(),
            ),
            slots: vec![0; (count * 2).next_power_of_two().max(2)].into_boxed_slice(),
            nsec: Vec::new(),
            nsec3: Vec::new(),
        };
        for (owner, node) in nodes {
            let index = base.nodes.len();
            let set_start = base.sets.len();
            for set in &node.sets {
                base.sets.push(BaseSet {
                    rtype: set.rtype,
                    count: u16::try_from(set.rdata.len()).unwrap_or(u16::MAX),
                    ttl: set.ttl,
                    rdata: to_u32(base.rdata.len()),
                });
                let take = set.rdata.len().min(usize::from(u16::MAX));
                base.rdata.extend_from_slice(&set.rdata[..take]);
            }
            if node.sets.iter().any(|set| set.rtype == Rtype::NSEC) {
                base.nsec.push(to_u32(index));
            }
            // WP6.3: the NSEC3 owners.
            if node.sets.iter().any(|set| set.rtype == Rtype::NSEC3) {
                base.nsec3.push(to_u32(index));
            }
            base.nodes.push(BaseNode {
                name: to_u32(base.names.len()),
                sets: to_u32(set_start),
                children: node.children,
                set_count: u16::try_from(node.sets.len()).unwrap_or(u16::MAX),
                name_len: u8::try_from(owner.len()).unwrap_or(u8::MAX),
            });
            base.names.extend_from_slice(&owner);
            let mask = base.slots.len() - 1;
            #[allow(clippy::cast_possible_truncation)]
            let mut slot = hash.hash(&owner) as usize & mask;
            while base.slots[slot] != 0 {
                slot = (slot + 1) & mask;
            }
            base.slots[slot] = to_u32(index + 1);
        }
        // WP6.3: both lists of denial owners in canonical order.
        let mut nsec = std::mem::take(&mut base.nsec);
        let mut nsec3 = std::mem::take(&mut base.nsec3);
        for list in [&mut nsec, &mut nsec3] {
            list.sort_by(|a, b| {
                canonical_cmp(
                    base.name_of(&base.nodes[*a as usize]),
                    base.name_of(&base.nodes[*b as usize]),
                )
            });
        }
        base.nsec = nsec;
        base.nsec3 = nsec3;
        base
    }
}

fn to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

// ---------------------------------------------------------------------------------------
// Scopes

#[derive(Debug, Clone, Default)]
struct Overlay {
    nodes: HashMap<Box<[u8]>, Option<OwnedNode>, Seeded>,
    /// NSEC owners by canonical key: `Some` adds an owner, `None` hides one of the base.
    nsec: BTreeMap<Vec<u8>, Option<Box<[u8]>>>,
    // WP6.3: the NSEC3 owners the same way.
    nsec3: BTreeMap<Vec<u8>, Option<Box<[u8]>>>,
}

impl Default for Seeded {
    fn default() -> Self {
        Self::new()
    }
}

/// One scope of one zone: the base, the overlay and the number of cuts and DNAMEs.
#[derive(Debug, Clone)]
struct ScopeTree {
    base: Arc<Base>,
    overlay: Arc<Overlay>,
    guards: usize,
}

impl ScopeTree {
    fn build(apex: &[u8], rows: Rows) -> Self {
        let base = Base::build(apex, rows);
        let mut tree = Self {
            base: Arc::new(base),
            overlay: Arc::new(Overlay::default()),
            guards: 0,
        };
        tree.guards = tree
            .base
            .nodes
            .iter()
            .filter(|node| {
                let owner = tree.base.name_of(node);
                NodeRef::Base(&tree.base, node).is_guard(owner == apex)
            })
            .count();
        tree
    }

    fn empty() -> Self {
        Self {
            base: Arc::new(Base::empty()),
            overlay: Arc::new(Overlay::default()),
            guards: 0,
        }
    }

    fn node(&self, name: &[u8]) -> Option<NodeRef<'_>> {
        if !self.overlay.nodes.is_empty()
            && let Some((owner, entry)) = self.overlay.nodes.get_key_value(name)
        {
            return entry.as_ref().map(|node| NodeRef::Owned(owner, node));
        }
        self.base
            .find(name)
            .map(|node| NodeRef::Base(&self.base, node))
    }

    /// Every node that holds data, from both layers.
    fn rows(&self) -> Rows {
        let mut rows: Rows = HashMap::with_hasher(Seeded::new());
        for node in &self.base.nodes {
            let owner = self.base.name_of(node);
            if node.set_count > 0 && !self.overlay.nodes.contains_key(owner) {
                rows.insert(
                    owner.to_vec(),
                    NodeRef::Base(&self.base, node).to_owned().sets,
                );
            }
        }
        for (owner, node) in &self.overlay.nodes {
            if let Some(node) = node
                && !node.sets.is_empty()
            {
                rows.insert(owner.to_vec(), node.sets.clone());
            }
        }
        rows
    }

    fn write(&mut self, owner: &[u8], node: Option<OwnedNode>) {
        let in_base = self.base.find(owner).is_some();
        let overlay = Arc::make_mut(&mut self.overlay);
        if node.is_none() && !in_base {
            overlay.nodes.remove(owner);
        } else {
            overlay.nodes.insert(owner.into(), node);
        }
    }

    /// Sets or removes one RRset of the zone at `apex`.
    fn put(&mut self, apex: &[u8], owner: &[u8], rtype: Rtype, value: Option<(u32, Box<[Rdata]>)>) {
        if !name::is_within(owner, apex) {
            return;
        }
        let before = self.node(owner);
        let existed = before.is_some();
        let is_apex = owner == apex;
        let guard_before = before.is_some_and(|node| node.is_guard(is_apex));
        let mut node = before.map(NodeRef::to_owned).unwrap_or_default();
        let nsec_before = node.sets.iter().any(|set| set.rtype == Rtype::NSEC);
        let hashed_before = node.sets.iter().any(|set| set.rtype == Rtype::NSEC3);
        node.put(rtype, value);
        let nsec_after = node.sets.iter().any(|set| set.rtype == Rtype::NSEC);
        let hashed_after = node.sets.iter().any(|set| set.rtype == Rtype::NSEC3);
        let exists = node.exists();
        let guard_after = exists && NodeRef::Owned(owner, &node).is_guard(is_apex);
        self.guards = self.guards + usize::from(guard_after) - usize::from(guard_before);
        if nsec_before != nsec_after {
            let overlay = Arc::make_mut(&mut self.overlay);
            overlay
                .nsec
                .insert(canonical_key(owner), nsec_after.then(|| owner.into()));
        }
        // WP6.3: the NSEC3 owners.
        if hashed_before != hashed_after {
            let overlay = Arc::make_mut(&mut self.overlay);
            overlay
                .nsec3
                .insert(canonical_key(owner), hashed_after.then(|| owner.into()));
        }
        self.write(owner, exists.then_some(node));
        if existed != exists && !is_apex {
            self.adjust_parents(apex, owner, exists);
        }
    }

    /// Counts a child that appeared (`added`) or went away below the parent of `owner`, up
    /// the ancestors whose existence changes with it.
    fn adjust_parents(&mut self, apex: &[u8], owner: &[u8], added: bool) {
        let mut child = owner;
        loop {
            let parent = name::suffix(child, 1);
            let before = self.node(parent);
            let existed = before.is_some();
            let mut node = before.map(NodeRef::to_owned).unwrap_or_default();
            node.children = if added {
                node.children + 1
            } else {
                node.children.saturating_sub(1)
            };
            let exists = node.exists();
            self.write(parent, exists.then_some(node));
            if existed == exists || parent == apex || parent.len() <= apex.len() {
                break;
            }
            child = parent;
        }
    }

    fn overlay_len(&self) -> usize {
        self.overlay.nodes.len()
    }

    fn wants_compaction(&self) -> bool {
        let pending = self.overlay_len();
        pending > MIN_COMPACT && pending > self.base.len() / 8
    }

    /// The NSEC RRset that covers or matches `name` in canonical order.
    fn covering_nsec(&self, name: &[u8]) -> Option<RrSetView<'_>> {
        // WP6.3: the search is shared with NSEC3.
        let owner = self.denial_owner(name, Rtype::NSEC)?;
        self.node(owner)?.get(Rtype::NSEC)
    }

    // WP6.3: the NSEC3 chain, and the search shared by both chains.

    /// The NSEC3 RRset whose owner matches or covers the hashed owner `name` in hash
    /// order; the last one covers the names before the first.
    fn covering_nsec3(&self, name: &[u8]) -> Option<RrSetView<'_>> {
        let owner = self
            .denial_owner(name, Rtype::NSEC3)
            .or_else(|| self.last_denial_owner(Rtype::NSEC3))?;
        self.node(owner)?.get(Rtype::NSEC3)
    }

    /// The owner list of the base and of the overlay of a denial type.
    fn denial_lists(&self, rtype: Rtype) -> (&[u32], &DenialOwners) {
        if rtype == Rtype::NSEC3 {
            (&self.base.nsec3, &self.overlay.nsec3)
        } else {
            (&self.base.nsec, &self.overlay.nsec)
        }
    }

    /// The denial owner of `rtype` at or before `name` in canonical order.
    fn denial_owner(&self, name: &[u8], rtype: Rtype) -> Option<&[u8]> {
        let (list, overlay_list) = self.denial_lists(rtype);
        let mut key = [0u8; MAX_NAME_LEN];
        let key_len = canonical_into(name, &mut key);
        let key = &key[..key_len];
        // The best owner of the overlay at or before the name.
        let overlay = overlay_list
            .range::<[u8], _>((Bound::Unbounded, Bound::Included(key)))
            .rev()
            .find_map(|(_, owner)| owner.as_deref());
        // The best owner of the base that the overlay does not override.
        let base = &self.base;
        let mut upper = list.partition_point(|index| {
            canonical_cmp(base.name_of(&base.nodes[*index as usize]), name) != Ordering::Greater
        });
        let mut base_owner = None;
        let mut scratch = [0u8; MAX_NAME_LEN];
        while upper > 0 {
            let owner = base.name_of(&base.nodes[list[upper - 1] as usize]);
            let len = canonical_into(owner, &mut scratch);
            if !overlay_list.contains_key(&scratch[..len]) {
                base_owner = Some(owner);
                break;
            }
            upper -= 1;
        }
        later(overlay, base_owner)
    }

    /// The last denial owner of `rtype` in canonical order.
    fn last_denial_owner(&self, rtype: Rtype) -> Option<&[u8]> {
        let (list, overlay_list) = self.denial_lists(rtype);
        let overlay = overlay_list
            .values()
            .rev()
            .find_map(|owner| owner.as_deref());
        let base = &self.base;
        let mut scratch = [0u8; MAX_NAME_LEN];
        let base_owner = list.iter().rev().find_map(|index| {
            let owner = base.name_of(&base.nodes[*index as usize]);
            let len = canonical_into(owner, &mut scratch);
            (!overlay_list.contains_key(&scratch[..len])).then_some(owner)
        });
        later(overlay, base_owner)
    }
}

// WP6.3: the overlay's owners of one denial type, and the later of two owners.

/// Denial owners of the overlay by canonical key: `Some` adds one, `None` hides one of the
/// base.
type DenialOwners = BTreeMap<Vec<u8>, Option<Box<[u8]>>>;

/// The later of two optional owners in canonical order.
fn later<'a>(a: Option<&'a [u8]>, b: Option<&'a [u8]>) -> Option<&'a [u8]> {
    match (a, b) {
        (Some(a), Some(b)) => Some(if canonical_cmp(a, b) == Ordering::Less {
            b
        } else {
            a
        }),
        (a, b) => a.or(b),
    }
}

// ---------------------------------------------------------------------------------------
// Zones

#[derive(Debug, Clone)]
struct ZoneEntry {
    id: ZoneId,
    kind: ZoneKind,
    apex: Box<[u8]>,
    labels: usize,
    scopes: Vec<(ScopeName, ScopeTree)>,
}

impl ZoneEntry {
    fn new(zone: &Zone) -> Self {
        let apex: Box<[u8]> = zone.name.to_wire().into();
        Self {
            id: zone.id,
            kind: zone.kind,
            labels: name::label_count(&apex),
            apex,
            scopes: Vec::new(),
        }
    }

    /// The scope a query sees: the one asked for, else the default scope.
    fn scope(&self, scope: &ScopeName) -> Option<(&ScopeName, &ScopeTree)> {
        let find = |wanted: &ScopeName| {
            self.scopes
                .iter()
                .find(|(name, _)| name == wanted)
                .map(|(name, tree)| (name, tree))
        };
        find(scope).or_else(|| find(&ScopeName::DEFAULT))
    }

    fn scope_mut(&mut self, scope: &ScopeName, create: bool) -> Option<&mut ScopeTree> {
        let index = match self.scopes.iter().position(|(name, _)| name == scope) {
            Some(index) => index,
            None if create => {
                self.scopes.push((scope.clone(), ScopeTree::empty()));
                self.scopes.len() - 1
            }
            None => return None,
        };
        Some(&mut self.scopes[index].1)
    }
}

/// The key of an RRset kept aside for a zone the index does not hold.
type AsideKey = (ZoneId, ScopeName, Box<[u8]>, Rtype);

/// RRsets kept aside, by zone, scope, owner and type.
type Aside = BTreeMap<AsideKey, (u32, Box<[Rdata]>)>;

/// The production index: one name tree per zone and scope, immutable, shared between
/// revisions.
#[derive(Debug, Clone)]
pub struct ZoneIndex {
    revision: Revision,
    apexes: NameMap<Arc<ZoneEntry>>,
    by_id: HashMap<ZoneId, Box<[u8]>>,
    min_labels: usize,
    max_labels: usize,
    aside: Arc<Aside>,
}

impl Default for ZoneIndex {
    fn default() -> Self {
        Self {
            revision: Revision::ZERO,
            apexes: HashMap::with_hasher(Seeded::new()),
            by_id: HashMap::new(),
            min_labels: 0,
            max_labels: 0,
            aside: Arc::new(BTreeMap::new()),
        }
    }
}

/// What the index holds, for the health view and the measurements.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IndexStats {
    /// Zones.
    pub zones: usize,
    /// Zone scopes with data.
    pub scopes: usize,
    /// Nodes of the bases, empty non-terminals included.
    pub base_nodes: usize,
    /// Nodes of the overlays (changed since their base was built).
    pub overlay_nodes: usize,
    /// RRsets of the bases.
    pub base_rrsets: usize,
    /// Records of the bases.
    pub base_records: usize,
    /// Octets of owner names in the bases.
    pub name_octets: usize,
    /// RRsets kept aside for zones the index does not hold.
    pub aside: usize,
    /// Octets the bases hold in their arrays and record data (M18): a lower bound of the
    /// index's memory, without the allocator's overhead per record data, the overlays and
    /// the view and forwarding tables.
    pub base_bytes: usize,
}

impl ZoneIndex {
    /// Builds the index from an image.
    pub fn build(data: &DnsData) -> Self {
        let mut index = Self {
            revision: data.revision,
            ..Self::default()
        };
        let mut staged: HashMap<(ZoneId, ScopeName), Rows> = HashMap::new();
        for zone in data.zones.values() {
            index.insert_entry(ZoneEntry::new(zone));
        }
        let aside = Arc::make_mut(&mut index.aside);
        for (key, rrset) in &data.rrsets {
            let owner = key.name.to_wire();
            if index.by_id.contains_key(&key.zone) {
                staged
                    .entry((key.zone, key.scope.clone()))
                    .or_insert_with(|| HashMap::with_hasher(Seeded::new()))
                    .entry(owner)
                    .or_default()
                    .push(owned_set(key.rtype, rrset));
            } else {
                aside.insert(
                    (key.zone, key.scope.clone(), owner.into(), key.rtype),
                    (rrset.ttl, rrset.rdata.clone().into()),
                );
            }
        }
        for ((zone, scope), rows) in staged {
            index.with_entry(zone, |entry| {
                let tree = ScopeTree::build(&entry.apex, rows);
                if tree.node(&entry.apex).is_some() {
                    entry.scopes.push((scope, tree));
                }
            });
        }
        index
    }

    /// The index after a delta, sharing everything the delta does not touch.
    ///
    /// # Errors
    ///
    /// [`FeedError::Gap`] when the delta does not start at this index's revision.
    pub fn apply(&self, delta: &Delta) -> Result<Self, FeedError> {
        if delta.from != self.revision || delta.to <= delta.from {
            return Err(FeedError::Gap {
                held: self.revision,
                from: delta.from,
            });
        }
        let mut next = self.clone();
        let mut touched: Vec<(ZoneId, ScopeName)> = Vec::new();
        for change in &delta.changes {
            match change {
                Change::Zone(id, zone) => next.put_zone(*id, zone.as_ref()),
                Change::RrSet(key, rrset)
                    if next.put_rrset(key, rrset.as_ref())
                        && !touched
                            .iter()
                            .any(|(zone, scope)| *zone == key.zone && *scope == key.scope) =>
                {
                    touched.push((key.zone, key.scope.clone()));
                }
                _ => {}
            }
        }
        for (zone, scope) in touched {
            next.with_entry(zone, |entry| {
                let apex = entry.apex.clone();
                if let Some(tree) = entry.scope_mut(&scope, false)
                    && tree.wants_compaction()
                {
                    *tree = ScopeTree::build(&apex, tree.rows());
                }
            });
        }
        next.revision = delta.to;
        Ok(next)
    }

    /// Counts what the index holds.
    pub fn stats(&self) -> IndexStats {
        let mut stats = IndexStats {
            zones: self.apexes.len(),
            aside: self.aside.len(),
            ..IndexStats::default()
        };
        for entry in self.apexes.values() {
            for (_, tree) in &entry.scopes {
                stats.scopes += 1;
                stats.base_nodes += tree.base.nodes.len();
                stats.overlay_nodes += tree.overlay_len();
                stats.base_rrsets += tree.base.sets.len();
                stats.base_records += tree.base.rdata.len();
                stats.name_octets += tree.base.names.len();
                stats.base_bytes += tree.base.memory_bytes();
            }
        }
        stats
    }

    fn insert_entry(&mut self, entry: ZoneEntry) {
        self.by_id.insert(entry.id, entry.apex.clone());
        self.apexes.insert(entry.apex.clone(), Arc::new(entry));
        self.update_labels();
    }

    fn update_labels(&mut self) {
        self.min_labels = self.apexes.values().map(|e| e.labels).min().unwrap_or(0);
        self.max_labels = self.apexes.values().map(|e| e.labels).max().unwrap_or(0);
    }

    fn with_entry(&mut self, zone: ZoneId, f: impl FnOnce(&mut ZoneEntry)) {
        if let Some(apex) = self.by_id.get(&zone)
            && let Some(entry) = self.apexes.get_mut(apex)
        {
            let entry = Arc::make_mut(entry);
            f(entry);
            entry
                .scopes
                .retain(|(_, tree)| tree.node(&entry.apex).is_some());
        }
    }

    fn put_zone(&mut self, id: ZoneId, zone: Option<&Zone>) {
        let wire = zone.map(|zone| zone.name.to_wire());
        match (self.by_id.get(&id), zone) {
            (Some(apex), Some(zone)) if Some(&apex[..]) == wire.as_deref() => {
                let kind = zone.kind;
                self.with_entry(id, |entry| entry.kind = kind);
                return;
            }
            (Some(_), _) => self.remove_zone(id),
            (None, _) => {}
        }
        let Some(zone) = zone else {
            return;
        };
        let mut entry = ZoneEntry::new(zone);
        let aside = Arc::make_mut(&mut self.aside);
        let keys: Vec<AsideKey> = aside
            .keys()
            .filter(|(zone, ..)| *zone == id)
            .cloned()
            .collect();
        let mut staged: HashMap<ScopeName, Rows> = HashMap::new();
        for key in keys {
            if let Some((ttl, rdata)) = aside.remove(&key) {
                let (_, scope, owner, rtype) = key;
                staged
                    .entry(scope)
                    .or_insert_with(|| HashMap::with_hasher(Seeded::new()))
                    .entry(owner.into_vec())
                    .or_default()
                    .push(OwnedSet { rtype, ttl, rdata });
            }
        }
        for (scope, rows) in staged {
            let tree = ScopeTree::build(&entry.apex, rows);
            if tree.node(&entry.apex).is_some() {
                entry.scopes.push((scope, tree));
            }
        }
        self.insert_entry(entry);
    }

    fn remove_zone(&mut self, id: ZoneId) {
        let Some(apex) = self.by_id.remove(&id) else {
            return;
        };
        let Some(entry) = self.apexes.remove(&apex) else {
            return;
        };
        let aside = Arc::make_mut(&mut self.aside);
        for (scope, tree) in &entry.scopes {
            for (owner, sets) in tree.rows() {
                for set in sets {
                    aside.insert(
                        (id, scope.clone(), owner.clone().into(), set.rtype),
                        (set.ttl, set.rdata),
                    );
                }
            }
        }
        self.update_labels();
    }

    /// Applies one RRset change; `true` when it went into a zone of the index.
    fn put_rrset(&mut self, key: &RrSetKey, rrset: Option<&RrSet>) -> bool {
        let owner = key.name.to_wire();
        let value = rrset.map(|rrset| (rrset.ttl, Box::<[Rdata]>::from(rrset.rdata.clone())));
        if !self.by_id.contains_key(&key.zone) {
            let aside = Arc::make_mut(&mut self.aside);
            let slot = (key.zone, key.scope.clone(), owner.into(), key.rtype);
            match value {
                Some(value) => aside.insert(slot, value),
                None => aside.remove(&slot),
            };
            return false;
        }
        self.with_entry(key.zone, |entry| {
            let apex = entry.apex.clone();
            if let Some(tree) = entry.scope_mut(&key.scope, value.is_some()) {
                tree.put(&apex, &owner, key.rtype, value);
            }
        });
        true
    }

    /// The zone with the longest apex that encloses `qname`.
    // WP6.3: a DS query at the apex of a zone is answered by its parent when the index
    // holds the parent (RFC 4035, section 3.1.4.1).
    fn zone_for(&self, qname: &[u8], qtype: Rtype) -> Option<&ZoneEntry> {
        let found = self.zone_of(qname)?;
        if qtype == Rtype::DS
            && &found.apex[..] == qname
            && name::label_count(qname) > 0
            && let Some(parent) = self.zone_of(name::suffix(qname, 1))
        {
            return Some(parent);
        }
        Some(found)
    }

    fn zone_of(&self, qname: &[u8]) -> Option<&ZoneEntry> {
        let labels = name::label_count(qname);
        if self.apexes.is_empty() || labels < self.min_labels {
            return None;
        }
        let first = labels.saturating_sub(self.max_labels);
        let last = labels - self.min_labels;
        (first..=last).find_map(|skip| {
            self.apexes
                .get(name::suffix(qname, skip))
                .map(AsRef::as_ref)
        })
    }

    fn entry(&self, id: ZoneId) -> Option<&ZoneEntry> {
        self.apexes.get(self.by_id.get(&id)?).map(AsRef::as_ref)
    }
}

// WP6.1: what zone transfers read from the index.
/// One RRset of a zone scope as a transfer copies it: the owner in lowercase wire form,
/// the type, the TTL and the records.
pub type ScopeRrSet = (Box<[u8]>, Rtype, u32, Box<[Rdata]>);

impl ZoneIndex {
    /// The zone whose apex encloses `qname` most closely, with its kind, whether or not the
    /// index holds data for it (a secondary zone before its first transfer or after it
    /// expired holds none).
    pub fn enclosing_zone(&self, qname: &[u8]) -> Option<(ZoneId, ZoneKind)> {
        self.zone_of(qname).map(|entry| (entry.id, entry.kind))
    }

    /// Every RRset of one scope of a zone in canonical order of the owners (RFC 4034
    /// section 6.1), the types of an owner in type order; `None` when the index holds no
    /// data for the scope. Copies the owners and shares the record data; for AXFR, off the
    /// query path.
    pub fn scope_rrsets(&self, zone: ZoneId, scope: &ScopeName) -> Option<Vec<ScopeRrSet>> {
        let entry = self.entry(zone)?;
        let (_, tree) = entry.scopes.iter().find(|(name, _)| name == scope)?;
        let mut owners: Vec<(Vec<u8>, Vec<OwnedSet>)> = tree.rows().into_iter().collect();
        owners.sort_by(|a, b| canonical_cmp(&a.0, &b.0));
        Some(
            owners
                .into_iter()
                .flat_map(|(owner, sets)| {
                    let owner: Box<[u8]> = owner.into();
                    sets.into_iter()
                        .map(move |set| (owner.clone(), set.rtype, set.ttl, set.rdata))
                })
                .collect(),
        )
    }
}

fn owned_set(rtype: Rtype, rrset: &RrSet) -> OwnedSet {
    OwnedSet {
        rtype,
        ttl: rrset.ttl,
        rdata: rrset.rdata.clone().into(),
    }
}

/// Writes `*.` and `encloser` into `buf` and returns the wildcard name.
fn wildcard_of<'b>(encloser: &[u8], buf: &'b mut [u8; MAX_NAME_LEN]) -> Option<&'b [u8]> {
    let len = encloser.len() + 2;
    if len > MAX_NAME_LEN {
        return None;
    }
    buf[0] = 1;
    buf[1] = b'*';
    buf[2..len].copy_from_slice(encloser);
    Some(&buf[..len])
}

fn answer<'a>(
    zone: ZoneView<'a>,
    soa: Option<RrSetView<'a>>,
    node: NodeRef<'a>,
    qtype: Rtype,
    wildcard: Option<&'a [u8]>,
) -> Lookup<'a> {
    let found = if qtype == Rtype::ANY {
        node.first()
    } else {
        node.get(qtype)
    };
    if let Some(rrset) = found {
        Lookup::Answer {
            zone,
            rrset,
            wildcard,
        }
    } else if let Some(cname) = node.get(Rtype::CNAME) {
        Lookup::Cname {
            zone,
            cname,
            wildcard,
        }
    } else {
        Lookup::NoData {
            zone,
            soa,
            wildcard,
        }
    }
}

/// The cut or DNAME on the way from the apex down to the closest encloser, if any.
fn guarded<'a>(
    tree: &'a ScopeTree,
    zone: ZoneView<'a>,
    entry: &ZoneEntry,
    qname: &[u8],
    encloser_labels: usize,
    exact: bool,
    qtype: Rtype,
) -> Option<Lookup<'a>> {
    let labels = name::label_count(qname);
    for depth in entry.labels..=encloser_labels {
        let current = name::suffix(qname, labels - depth);
        let node = tree.node(current)?;
        let at_name = exact && depth == labels;
        if depth > entry.labels
            && let Some(ns) = node.get(Rtype::NS)
            && !(at_name && qtype == Rtype::DS)
        {
            return Some(Lookup::Delegation {
                zone,
                ns,
                ds: node.get(Rtype::DS),
            });
        }
        if !at_name && let Some(dname) = node.get(Rtype::DNAME) {
            return Some(Lookup::Dname { zone, dname });
        }
    }
    None
}

impl Index for ZoneIndex {
    fn revision(&self) -> Revision {
        self.revision
    }

    fn lookup<'a>(&'a self, scopes: &dyn ScopeOf, qname: &[u8], qtype: Rtype) -> Lookup<'a> {
        let Some(entry) = self.zone_for(qname, qtype) else {
            return Lookup::NotAuthoritative;
        };
        let Some((scope, tree)) = entry.scope(scopes.scope_of(entry.id)) else {
            return Lookup::NotAuthoritative;
        };
        let zone = ZoneView {
            id: entry.id,
            kind: entry.kind,
            apex: &entry.apex,
            scope,
        };
        let soa = tree.node(&entry.apex).and_then(|apex| apex.get(Rtype::SOA));
        let labels = name::label_count(qname);
        let (encloser, encloser_labels, exact) = if let Some(node) = tree.node(qname) {
            (node, labels, true)
        } else {
            let found = (1..=labels - entry.labels).find_map(|skip| {
                tree.node(name::suffix(qname, skip))
                    .map(|node| (node, labels - skip))
            });
            let Some((node, depth)) = found else {
                return Lookup::NotAuthoritative;
            };
            (node, depth, false)
        };
        if tree.guards > 0
            && let Some(lookup) = guarded(tree, zone, entry, qname, encloser_labels, exact, qtype)
        {
            return lookup;
        }
        if exact {
            return answer(zone, soa, encloser, qtype, None);
        }
        let mut buf = [0u8; MAX_NAME_LEN];
        if let Some(wildcard) = wildcard_of(encloser.owner(), &mut buf)
            && let Some(node) = tree.node(wildcard)
        {
            return answer(zone, soa, node, qtype, Some(node.owner()));
        }
        Lookup::NxDomain {
            zone,
            soa,
            closest_encloser: encloser.owner(),
        }
    }

    fn addresses<'a>(&'a self, scopes: &dyn ScopeOf, name: &[u8]) -> [Option<RrSetView<'a>>; 2] {
        let node = self.zone_of(name).and_then(|entry| {
            entry
                .scope(scopes.scope_of(entry.id))
                .and_then(|(_, tree)| tree.node(name))
        });
        [
            node.and_then(|node| node.get(Rtype::A)),
            node.and_then(|node| node.get(Rtype::AAAA)),
        ]
    }

    fn covering_nsec<'a>(&'a self, zone: &ZoneView<'_>, name: &[u8]) -> Option<RrSetView<'a>> {
        let (_, tree) = self.entry(zone.id)?.scope(zone.scope)?;
        tree.covering_nsec(name)
    }

    // WP6.3: the RRset at a name and the NSEC3 chain.
    fn rrset_at<'a>(
        &'a self,
        zone: &ZoneView<'_>,
        owner: &[u8],
        rtype: Rtype,
    ) -> Option<RrSetView<'a>> {
        let (_, tree) = self.entry(zone.id)?.scope(zone.scope)?;
        tree.node(owner)?.get(rtype)
    }

    fn covering_nsec3<'a>(&'a self, zone: &ZoneView<'_>, hashed: &[u8]) -> Option<RrSetView<'a>> {
        let (_, tree) = self.entry(zone.id)?.scope(zone.scope)?;
        tree.covering_nsec3(hashed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in text.split('.').filter(|label| !label.is_empty()) {
            out.push(u8::try_from(label.len()).expect("label"));
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    #[test]
    fn canonical_order_matches_the_keys() {
        let names = [
            "example.test",
            "a.example.test",
            "aa.example.test",
            "b.a.example.test",
            "z.example.test",
            "test",
            "a.test",
            "*.example.test",
        ];
        for a in names {
            for b in names {
                let (wa, wb) = (wire(a), wire(b));
                assert_eq!(
                    canonical_cmp(&wa, &wb),
                    canonical_key(&wa).cmp(&canonical_key(&wb)),
                    "{a} {b}"
                );
                let mut buf = [0u8; MAX_NAME_LEN];
                let len = canonical_into(&wa, &mut buf);
                assert_eq!(&buf[..len], &canonical_key(&wa)[..]);
            }
        }
    }

    #[test]
    fn the_hash_spreads_similar_names() {
        let hash = Seeded::new();
        let mut buckets = [0u32; 64];
        for n in 0..64_000 {
            let name = wire(&format!("host-{n}.example.test"));
            #[allow(clippy::cast_possible_truncation)]
            let bucket = (hash.hash(&name) & 63) as usize;
            buckets[bucket] += 1;
        }
        assert!(
            buckets.iter().all(|&count| (800..1200).contains(&count)),
            "{buckets:?}"
        );
    }
}
