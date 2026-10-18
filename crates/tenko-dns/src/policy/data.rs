//! The policy's part of the serving catalog: the RPZ zones compiled from their RRsets and
//! the matchers of the newest version of every list, built from the rows of one revision
//! and kept current from the feed's deltas.
//!
//! A delta that touches no RPZ zone, no RRset of one, no list and no list version shares
//! everything with the catalog before it. A touched RPZ zone is compiled again from its
//! rows (the default scope); a new version builds the list's matcher (a list of a million
//! names in a few hundred milliseconds, on the writer's blocking thread, never on the query
//! path). A version that does not decode keeps the matcher the list had.

use std::{collections::BTreeMap, sync::Arc};

use ipnet::IpNet;
use tenko_core::dns::{
    BlockAction, BlockList, BlockListId, DnsName, ListKind, ListVersion, RrSet, Rtype, ScopeName,
    Zone, ZoneId, ZoneKind,
};

use super::{counters, rpz::RpzZone};
use crate::{
    feed::{Change, DnsData},
    lists::ListMatcher,
};

/// An RPZ zone with its counter.
#[derive(Debug, Clone)]
pub struct ActiveZone {
    /// The compiled zone.
    pub zone: Arc<RpzZone>,
    /// Its blocked counter.
    pub slot: u16,
}

/// A list the query path applies: enabled, with a version.
#[derive(Debug, Clone)]
pub struct ActiveList {
    /// The list.
    pub id: BlockListId,
    /// Its name, the label of its counter.
    pub name: Box<str>,
    /// What a blocked name answers.
    pub action: BlockAction,
    /// The clients it exempts.
    pub exempt: Box<[IpNet]>,
    /// The newest version's set.
    pub matcher: Arc<ListMatcher>,
    /// Its blocked counter.
    pub slot: u16,
}

impl ActiveList {
    /// Whether the list exempts `client` (canonical form).
    pub fn exempts(&self, client: std::net::IpAddr) -> bool {
        self.exempt.iter().any(|prefix| prefix.contains(&client))
    }
}

type RpzSets = BTreeMap<(DnsName, Rtype), RrSet>;

/// The compiled policy of one catalog revision.
#[derive(Debug, Clone, Default)]
pub struct PolicyData {
    rpz_rows: Arc<BTreeMap<ZoneId, Zone>>,
    rpz_sets: Arc<BTreeMap<ZoneId, Arc<RpzSets>>>,
    compiled: Arc<BTreeMap<ZoneId, ActiveZone>>,
    /// The RPZ zones by name: the order of a view that names none.
    zones: Arc<Vec<ActiveZone>>,
    list_rows: Arc<BTreeMap<BlockListId, BlockList>>,
    matchers: Arc<BTreeMap<BlockListId, (u64, Arc<ListMatcher>)>>,
    blocks: Arc<Vec<ActiveList>>,
    allows: Arc<Vec<ActiveList>>,
    /// The exempt prefixes of the enabled allow lists: clients the policy never blocks.
    exempt_all: Arc<Vec<IpNet>>,
}

fn matcher_of(version: &ListVersion) -> Option<Arc<ListMatcher>> {
    match ListMatcher::build(&version.compiled.0) {
        Ok(matcher) => Some(Arc::new(matcher)),
        Err(error) => {
            tracing::warn!(list = %version.list, version = version.revision, %error, "a block list version does not decode; the list keeps the version it had");
            None
        }
    }
}

impl PolicyData {
    /// The policy of an image.
    pub fn build(data: &DnsData) -> Self {
        let rpz_rows: BTreeMap<ZoneId, Zone> = data
            .zones
            .iter()
            .filter(|(_, zone)| zone.kind == ZoneKind::Rpz)
            .map(|(id, zone)| (*id, zone.clone()))
            .collect();
        let mut sets: BTreeMap<ZoneId, RpzSets> = BTreeMap::new();
        for set in data.rrsets.values() {
            if rpz_rows.contains_key(&set.zone) && set.scope == ScopeName::DEFAULT {
                sets.entry(set.zone)
                    .or_default()
                    .insert((set.name.clone(), set.rtype), set.clone());
            }
        }
        let mut newest: BTreeMap<BlockListId, &ListVersion> = BTreeMap::new();
        for ((id, revision), version) in &data.list_versions {
            if newest.get(id).is_none_or(|held| held.revision < *revision) {
                newest.insert(*id, version);
            }
        }
        let matchers = newest
            .into_iter()
            .filter_map(|(id, version)| {
                matcher_of(version).map(|matcher| (id, (version.revision, matcher)))
            })
            .collect();
        let mut policy = Self {
            rpz_rows: Arc::new(rpz_rows),
            rpz_sets: Arc::new(
                sets.into_iter()
                    .map(|(id, sets)| (id, Arc::new(sets)))
                    .collect(),
            ),
            compiled: Arc::default(),
            zones: Arc::default(),
            list_rows: Arc::new(data.lists.clone()),
            matchers: Arc::new(matchers),
            blocks: Arc::default(),
            allows: Arc::default(),
            exempt_all: Arc::default(),
        };
        let compiled = policy
            .rpz_rows
            .keys()
            .map(|id| (*id, policy.compile_zone(*id)))
            .filter_map(|(id, zone)| zone.map(|zone| (id, zone)))
            .collect();
        policy.compiled = Arc::new(compiled);
        policy.derive();
        policy
    }

    fn compile_zone(&self, id: ZoneId) -> Option<ActiveZone> {
        let zone = self.rpz_rows.get(&id)?;
        let empty = RpzSets::new();
        let sets = self.rpz_sets.get(&id).map_or(&empty, |sets| sets.as_ref());
        let compiled = RpzZone::compile(zone, sets.values());
        if compiled.skipped > 0 {
            tracing::info!(zone = %zone.name, skipped = compiled.skipped, "RPZ owners that are no trigger were skipped");
        }
        Some(ActiveZone {
            slot: counters::slot(zone.name.as_str()),
            zone: Arc::new(compiled),
        })
    }

    /// The lists and zones in their order of application, from the rows and matchers.
    fn derive(&mut self) {
        let mut zones: Vec<ActiveZone> = self.compiled.values().cloned().collect();
        zones.sort_by(|a, b| a.zone.name.cmp(&b.zone.name));
        self.zones = Arc::new(zones);
        let mut blocks = Vec::new();
        let mut allows = Vec::new();
        let mut exempt_all = Vec::new();
        let mut rows: Vec<&BlockList> = self
            .list_rows
            .values()
            .filter(|list| list.enabled)
            .collect();
        rows.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then(a.id.cmp(&b.id))
        });
        for list in rows {
            if list.kind == ListKind::Allow {
                exempt_all.extend(list.exempt.iter().copied());
            }
            let Some((_, matcher)) = self.matchers.get(&list.id) else {
                continue;
            };
            let active = ActiveList {
                id: list.id,
                name: list.name.as_str().into(),
                action: list.action.clone(),
                exempt: list.exempt.clone().into_boxed_slice(),
                matcher: Arc::clone(matcher),
                slot: counters::slot(&list.name),
            };
            match list.kind {
                ListKind::Block => blocks.push(active),
                ListKind::Allow => allows.push(active),
            }
        }
        self.blocks = Arc::new(blocks);
        self.allows = Arc::new(allows);
        self.exempt_all = Arc::new(exempt_all);
    }

    /// The policy after a delta's changes.
    #[must_use]
    pub fn apply(&self, changes: &[Change]) -> Self {
        let mut next = self.clone();
        let mut touched: Vec<ZoneId> = Vec::new();
        let mut lists = false;
        for change in changes {
            match change {
                Change::Zone(id, zone) => {
                    let was = next.rpz_rows.contains_key(id);
                    let is = zone.as_ref().is_some_and(|zone| zone.kind == ZoneKind::Rpz);
                    if was || is {
                        let rows = Arc::make_mut(&mut next.rpz_rows);
                        match zone {
                            Some(zone) if is => {
                                rows.insert(*id, zone.clone());
                            }
                            _ => {
                                rows.remove(id);
                                Arc::make_mut(&mut next.rpz_sets).remove(id);
                            }
                        }
                        touched.push(*id);
                    }
                }
                Change::RrSet(key, set) => {
                    if key.scope != ScopeName::DEFAULT || !next.rpz_rows.contains_key(&key.zone) {
                        continue;
                    }
                    let sets = Arc::make_mut(&mut next.rpz_sets);
                    let zone_sets = Arc::make_mut(sets.entry(key.zone).or_default());
                    match set {
                        Some(set) => zone_sets.insert((key.name.clone(), key.rtype), set.clone()),
                        None => zone_sets.remove(&(key.name.clone(), key.rtype)),
                    };
                    touched.push(key.zone);
                }
                Change::List(id, list) => {
                    lists = true;
                    let rows = Arc::make_mut(&mut next.list_rows);
                    if let Some(list) = list {
                        rows.insert(*id, list.clone())
                    } else {
                        Arc::make_mut(&mut next.matchers).remove(id);
                        rows.remove(id)
                    };
                }
                Change::ListVersion((id, revision), version) => {
                    lists = true;
                    let held = next.matchers.get(id).map(|(held, _)| *held);
                    match version {
                        Some(version) if held.is_none_or(|held| held <= *revision) => {
                            if let Some(matcher) = matcher_of(version) {
                                Arc::make_mut(&mut next.matchers).insert(*id, (*revision, matcher));
                            }
                        }
                        None if held == Some(*revision) => {
                            Arc::make_mut(&mut next.matchers).remove(id);
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        if touched.is_empty() && !lists {
            return next;
        }
        touched.sort_unstable();
        touched.dedup();
        if !touched.is_empty() {
            let compiled = Arc::make_mut(&mut next.compiled);
            for id in touched {
                compiled.remove(&id);
            }
            let missing: Vec<ZoneId> = next
                .rpz_rows
                .keys()
                .filter(|id| !next.compiled.contains_key(id))
                .copied()
                .collect();
            for id in missing {
                if let Some(zone) = next.compile_zone(id) {
                    Arc::make_mut(&mut next.compiled).insert(id, zone);
                }
            }
        }
        next.derive();
        next
    }

    /// Whether nothing is configured: no RPZ zone, no list with a version, no exemption.
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
            && self.blocks.is_empty()
            && self.allows.is_empty()
            && self.exempt_all.is_empty()
    }

    /// The RPZ zones by name.
    pub fn zones(&self) -> &[ActiveZone] {
        &self.zones
    }

    /// An RPZ zone by id.
    pub fn zone(&self, id: ZoneId) -> Option<&ActiveZone> {
        self.compiled.get(&id)
    }

    /// The enabled block lists with a version, by name.
    pub fn blocks(&self) -> &[ActiveList] {
        &self.blocks
    }

    /// The enabled allow lists with a version, by name.
    pub fn allows(&self) -> &[ActiveList] {
        &self.allows
    }

    /// The clients the enabled allow lists exempt from the whole policy.
    pub fn exempt_all(&self) -> &[IpNet] {
        &self.exempt_all
    }

    /// The version a list's matcher was built from.
    pub fn list_version(&self, id: BlockListId) -> Option<u64> {
        self.matchers.get(&id).map(|(revision, _)| *revision)
    }

    /// The names of the counted lists and zones: the enabled block lists and the RPZ zones.
    pub fn counted(&self) -> impl Iterator<Item = (&str, u16)> {
        self.blocks
            .iter()
            .map(|list| (&*list.name, list.slot))
            .chain(self.zones.iter().map(|zone| (&*zone.zone.name, zone.slot)))
    }

    /// Whether some RPZ zone or list looks at answers (every list does: CNAME targets).
    pub fn inspects_answers(&self) -> bool {
        !self.blocks.is_empty()
            || self
                .zones
                .iter()
                .any(|zone| zone.zone.has_answer_triggers() || zone.zone.triggers() > 0)
    }
}
