//! The authoritative index (plan sections 2.1 and 3.3): what the engine answers from.
//!
//! [`Index::lookup`] takes a query name in lowercase wire form and a type and says what the
//! zones hold: the RRset, a CNAME or DNAME to follow, a referral at a zone cut, or a
//! negative answer with the SOA and the closest encloser. Wildcards (RFC 4592) are
//! synthesized inside the lookup; CNAME chains are followed inside the index by
//! [`Index::resolve`]. Lookups read memory only and allocate nothing: the results borrow
//! the index.
//!
//! [`MemIndex`] is the reference implementation, built from a [`DnsData`] image with plain
//! maps. It is simple and correct rather than compact: the production index of WP4.1 is
//! tested against it.

use std::collections::{BTreeMap, HashMap};

use tenko_core::{
    Revision,
    dns::{Rdata, Rtype, ScopeName, ZoneId, ZoneKind},
};

use crate::{
    feed::DnsData,
    name::{self, MAX_NAME_LEN},
};

/// The longest CNAME chain [`Index::resolve`] follows (BIND and Unbound stop near here).
pub const MAX_CHAIN: usize = 8;

/// Which scope of a zone a query sees (DNS-20); chosen by the view.
pub trait ScopeOf {
    /// The scope of `zone` for this query.
    fn scope_of(&self, zone: ZoneId) -> &ScopeName;
}

/// The implicit default view: the default scope of every zone.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultScopes;

impl ScopeOf for DefaultScopes {
    fn scope_of(&self, _zone: ZoneId) -> &ScopeName {
        &ScopeName::DEFAULT
    }
}

/// The zone an answer comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneView<'a> {
    /// The zone.
    pub id: ZoneId,
    /// What the zone is.
    pub kind: ZoneKind,
    /// The apex in lowercase wire form.
    pub apex: &'a [u8],
    /// The scope the lookup used.
    pub scope: &'a ScopeName,
}

/// An RRset of the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RrSetView<'a> {
    /// The owner in lowercase wire form (`*.example.test` for a wildcard source).
    pub owner: &'a [u8],
    /// The type.
    pub rtype: Rtype,
    /// The TTL.
    pub ttl: u32,
    /// The data of each record.
    pub rdata: &'a [Rdata],
}

/// What the index holds for a name and a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup<'a> {
    /// No zone of the index encloses the name: not authoritative (REFUSED, or the
    /// forwarder).
    NotAuthoritative,
    /// The RRset of the name and type. `wildcard` names the wildcard owner it was
    /// synthesized from; the answer's owner is then the question name.
    Answer {
        /// The zone.
        zone: ZoneView<'a>,
        /// The RRset.
        rrset: RrSetView<'a>,
        /// The wildcard owner of a synthesized answer.
        wildcard: Option<&'a [u8]>,
    },
    /// The name owns a CNAME and the type is another: follow it.
    Cname {
        /// The zone.
        zone: ZoneView<'a>,
        /// The CNAME RRset.
        cname: RrSetView<'a>,
        /// The wildcard owner of a synthesized CNAME.
        wildcard: Option<&'a [u8]>,
    },
    /// A DNAME above the name redirects it (RFC 6672); the engine synthesizes the CNAME.
    Dname {
        /// The zone.
        zone: ZoneView<'a>,
        /// The DNAME RRset.
        dname: RrSetView<'a>,
    },
    /// The name is at or below a zone cut: refer to the child's servers. A query for DS
    /// at the cut itself is answered by the parent instead.
    Delegation {
        /// The parent zone.
        zone: ZoneView<'a>,
        /// The NS RRset at the cut.
        ns: RrSetView<'a>,
        /// The DS RRset at the cut, if signed.
        ds: Option<RrSetView<'a>>,
    },
    /// The name exists (possibly as an empty non-terminal or through a wildcard) but has
    /// no data of the type.
    NoData {
        /// The zone.
        zone: ZoneView<'a>,
        /// The SOA for the negative answer (RFC 2308); `None` for an incomplete zone.
        soa: Option<RrSetView<'a>>,
        /// The wildcard owner that matched, if any.
        wildcard: Option<&'a [u8]>,
    },
    /// The name does not exist.
    NxDomain {
        /// The zone.
        zone: ZoneView<'a>,
        /// The SOA for the negative answer; `None` for an incomplete zone.
        soa: Option<RrSetView<'a>>,
        /// The closest encloser (RFC 5155): the longest existing ancestor of the name.
        closest_encloser: &'a [u8],
    },
}

/// One step of a CNAME chain: the zone, the CNAME RRset and its wildcard source.
pub type ChainStep<'a> = (ZoneView<'a>, RrSetView<'a>, Option<&'a [u8]>);

/// A CNAME chain followed inside the index.
#[derive(Debug, Clone, Copy)]
pub struct Chain<'a> {
    steps: [Option<ChainStep<'a>>; MAX_CHAIN],
    len: usize,
    /// The chain is longer than [`MAX_CHAIN`] or loops: the engine answers SERVFAIL or
    /// stops with what it has.
    pub exhausted: bool,
}

impl Default for Chain<'_> {
    fn default() -> Self {
        Self {
            steps: [None; MAX_CHAIN],
            len: 0,
            exhausted: false,
        }
    }
}

impl<'a> Chain<'a> {
    /// The CNAME RRsets followed, in order, with their zone and wildcard source.
    pub fn steps(&self) -> impl Iterator<Item = ChainStep<'a>> + '_ {
        self.steps[..self.len].iter().flatten().copied()
    }

    /// How many CNAMEs were followed.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no CNAME was followed.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push(&mut self, step: ChainStep<'a>) -> bool {
        if self.len == MAX_CHAIN {
            self.exhausted = true;
            return false;
        }
        self.steps[self.len] = Some(step);
        self.len += 1;
        true
    }

    fn holds(&self, owner: &[u8]) -> bool {
        self.steps().any(|(_, rrset, _)| rrset.owner == owner)
    }
}

/// The authoritative data the engine answers from.
pub trait Index: Send + Sync {
    /// The store revision the index holds.
    fn revision(&self) -> Revision;

    /// What the zones hold for `qname` (lowercase wire form) and `qtype`, in the scopes
    /// `scopes` chooses. A query for ANY gets one RRset of the name (RFC 8482).
    fn lookup<'a>(&'a self, scopes: &dyn ScopeOf, qname: &[u8], qtype: Rtype) -> Lookup<'a>;

    /// The A and AAAA RRsets at exactly `name`, below a zone cut too: glue and the
    /// additional section.
    fn addresses<'a>(&'a self, scopes: &dyn ScopeOf, name: &[u8]) -> [Option<RrSetView<'a>>; 2];

    /// The NSEC RRset that covers or matches `name` in a zone (RFC 4034 canonical order),
    /// for negative answers of signed zones. `None` when the zone has no NSEC chain.
    fn covering_nsec<'a>(&'a self, zone: &ZoneView<'_>, name: &[u8]) -> Option<RrSetView<'a>>;

    /// Follows CNAMEs from `qname` inside the index: each CNAME RRset goes into `chain` and
    /// the lookup continues at its target, up to [`MAX_CHAIN`] steps or a loop. Returns
    /// the lookup of the last name; a target outside the zones ends the chain with
    /// [`Lookup::NotAuthoritative`].
    fn resolve<'a>(
        &'a self,
        scopes: &dyn ScopeOf,
        qname: &[u8],
        qtype: Rtype,
        chain: &mut Chain<'a>,
    ) -> Lookup<'a> {
        let mut lookup = self.lookup(scopes, qname, qtype);
        while let Lookup::Cname {
            zone,
            cname,
            wildcard,
        } = lookup
        {
            let Some(target) = cname.rdata.first().map(Rdata::as_bytes) else {
                break;
            };
            if chain.holds(cname.owner) || !chain.push((zone, cname, wildcard)) {
                chain.exhausted = true;
                break;
            }
            lookup = self.lookup(scopes, target, qtype);
        }
        lookup
    }
}

/// The RRsets of one owner name, in type order.
#[derive(Debug, Clone, Default)]
struct Node {
    owner: Box<[u8]>,
    rrsets: Vec<(Rtype, u32, Vec<Rdata>)>,
}

impl Node {
    fn get(&self, rtype: Rtype) -> Option<RrSetView<'_>> {
        self.rrsets
            .iter()
            .find(|(candidate, _, _)| *candidate == rtype)
            .map(|(rtype, ttl, rdata)| self.view(*rtype, *ttl, rdata))
    }

    fn view<'a>(&'a self, rtype: Rtype, ttl: u32, rdata: &'a [Rdata]) -> RrSetView<'a> {
        RrSetView {
            owner: &self.owner,
            rtype,
            ttl,
            rdata,
        }
    }

    fn first(&self) -> Option<RrSetView<'_>> {
        self.rrsets
            .first()
            .map(|(rtype, ttl, rdata)| self.view(*rtype, *ttl, rdata))
    }
}

/// One scope of one zone: its nodes by owner (with every empty non-terminal) and the
/// canonical order for NSEC.
#[derive(Debug, Default)]
struct ScopeData {
    nodes: HashMap<Box<[u8]>, Node>,
    canonical: BTreeMap<Vec<u8>, Box<[u8]>>,
}

#[derive(Debug)]
struct ZoneEntry {
    kind: ZoneKind,
    apex: Box<[u8]>,
    labels: usize,
    scopes: HashMap<ScopeName, ScopeData>,
}

/// The reference index: maps built from a [`DnsData`] image.
#[derive(Debug, Default)]
pub struct MemIndex {
    revision: Revision,
    zones: HashMap<ZoneId, ZoneEntry>,
    apexes: HashMap<Box<[u8]>, ZoneId>,
}

/// The RFC 4034 canonical order of a wire name as a byte string: the labels from the
/// root down, each followed by 0x00.
pub fn canonical_key(wire: &[u8]) -> Vec<u8> {
    let labels: Vec<&[u8]> = name::Labels::new(wire).collect();
    let mut out = Vec::with_capacity(wire.len());
    for label in labels.iter().rev() {
        out.extend(label.iter().map(u8::to_ascii_lowercase));
        out.push(0);
    }
    out
}

impl MemIndex {
    /// Builds the index from an image. RRsets of zones that are not in the image are
    /// left out.
    pub fn build(data: &DnsData) -> Self {
        let mut index = Self {
            revision: data.revision,
            ..Self::default()
        };
        for zone in data.zones.values() {
            let apex: Box<[u8]> = zone.name.to_wire().into();
            index.apexes.insert(apex.clone(), zone.id);
            index.zones.insert(
                zone.id,
                ZoneEntry {
                    kind: zone.kind,
                    labels: name::label_count(&apex),
                    apex,
                    scopes: HashMap::new(),
                },
            );
        }
        for rrset in data.rrsets.values() {
            let Some(entry) = index.zones.get_mut(&rrset.zone) else {
                continue;
            };
            let owner: Box<[u8]> = rrset.name.to_wire().into();
            let scope = entry.scopes.entry(rrset.scope.clone()).or_default();
            // The owner and every empty non-terminal between it and the apex.
            let mut skip = 0;
            loop {
                let ancestor = name::suffix(&owner, skip);
                if name::label_count(ancestor) < entry.labels {
                    break;
                }
                let node = scope.nodes.entry(ancestor.into()).or_insert_with(|| Node {
                    owner: ancestor.into(),
                    rrsets: Vec::new(),
                });
                if skip == 0 {
                    node.rrsets
                        .push((rrset.rtype, rrset.ttl, rrset.rdata.clone()));
                    node.rrsets.sort_by_key(|(rtype, _, _)| *rtype);
                }
                scope
                    .canonical
                    .entry(canonical_key(ancestor))
                    .or_insert_with(|| ancestor.into());
                if name::label_count(ancestor) == entry.labels {
                    break;
                }
                skip += 1;
            }
        }
        index
    }

    /// The zone with the longest apex that encloses `qname`.
    fn zone_of(&self, qname: &[u8]) -> Option<(ZoneId, &ZoneEntry)> {
        let labels = name::label_count(qname);
        (0..=labels).find_map(|skip| {
            let id = *self.apexes.get(name::suffix(qname, skip))?;
            Some((id, self.zones.get(&id)?))
        })
    }

    fn scope_data<'a>(
        entry: &'a ZoneEntry,
        scope: &ScopeName,
    ) -> Option<(&'a ScopeName, &'a ScopeData)> {
        entry
            .scopes
            .get_key_value(scope)
            .or_else(|| entry.scopes.get_key_value(&ScopeName::DEFAULT))
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

impl Index for MemIndex {
    fn revision(&self) -> Revision {
        self.revision
    }

    fn lookup<'a>(&'a self, scopes: &dyn ScopeOf, qname: &[u8], qtype: Rtype) -> Lookup<'a> {
        let Some((id, entry)) = self.zone_of(qname) else {
            return Lookup::NotAuthoritative;
        };
        let Some((scope, data)) = Self::scope_data(entry, scopes.scope_of(id)) else {
            return Lookup::NotAuthoritative;
        };
        let zone = ZoneView {
            id,
            kind: entry.kind,
            apex: &entry.apex,
            scope,
        };
        let soa = data
            .nodes
            .get(&entry.apex)
            .and_then(|apex| apex.get(Rtype::SOA));
        let labels = name::label_count(qname);
        // Walk down from below the apex to the name: cuts and DNAMEs first.
        let mut encloser: &[u8] = &entry.apex;
        for depth in entry.labels + 1..=labels {
            let current = name::suffix(qname, labels - depth);
            let Some(node) = data.nodes.get(current) else {
                break;
            };
            let at_name = depth == labels;
            if let Some(ns) = node.get(Rtype::NS)
                && !(at_name && qtype == Rtype::DS)
            {
                return Lookup::Delegation {
                    zone,
                    ns,
                    ds: node.get(Rtype::DS),
                };
            }
            if !at_name && let Some(dname) = node.get(Rtype::DNAME) {
                return Lookup::Dname { zone, dname };
            }
            encloser = &node.owner;
        }
        let answer = |node: &'a Node, wildcard: Option<&'a [u8]>| {
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
        };
        if let Some(node) = data.nodes.get(qname) {
            return answer(node, None);
        }
        // The name does not exist: a wildcard at the closest encloser, or NXDOMAIN.
        let mut buf = [0u8; MAX_NAME_LEN];
        if let Some(wildcard) = wildcard_of(encloser, &mut buf)
            && let Some(node) = data.nodes.get(wildcard)
        {
            return answer(node, Some(&node.owner));
        }
        Lookup::NxDomain {
            zone,
            soa,
            closest_encloser: encloser,
        }
    }

    fn addresses<'a>(&'a self, scopes: &dyn ScopeOf, name: &[u8]) -> [Option<RrSetView<'a>>; 2] {
        let Some((id, entry)) = self.zone_of(name) else {
            return [None, None];
        };
        let node =
            Self::scope_data(entry, scopes.scope_of(id)).and_then(|(_, data)| data.nodes.get(name));
        [
            node.and_then(|node| node.get(Rtype::A)),
            node.and_then(|node| node.get(Rtype::AAAA)),
        ]
    }

    fn covering_nsec<'a>(&'a self, zone: &ZoneView<'_>, name: &[u8]) -> Option<RrSetView<'a>> {
        let entry = self.zones.get(&zone.id)?;
        let (_, data) = Self::scope_data(entry, zone.scope)?;
        let key = canonical_key(name);
        data.canonical
            .range(..=key)
            .rev()
            .find_map(|(_, owner)| data.nodes.get(owner).and_then(|node| node.get(Rtype::NSEC)))
    }
}
