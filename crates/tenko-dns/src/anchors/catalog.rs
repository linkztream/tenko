//! The trust anchors as the validator reads them from the catalog's rows
//! ([`CatalogAnchors`]): a snapshot of `dns.trust_anchors` and `dns.ntas` rebuilt only
//! when those rows change (the catalog's `anchors_revision`), with a generation that
//! moves with it so that the validator drops the key sets it validated under the old
//! anchors. The forwarder's housekeeping calls [`CatalogAnchors::refresh`].

use std::{
    collections::HashMap,
    sync::{Arc, PoisonError, RwLock},
};

use tenko_core::{
    Revision, Timestamp,
    dns::{DnsName, NegativeTrustAnchor, TrustAnchor},
};

use crate::{catalog::Catalog, recursion::TrustAnchors};

#[derive(Debug, Default)]
struct Snapshot {
    anchors: HashMap<DnsName, Arc<TrustAnchor>>,
    ntas: Vec<NegativeTrustAnchor>,
    /// The key tags of the root's trusted keys, for the worker's sentinel check.
    root_tags: Vec<u16>,
    revision: Option<Revision>,
    generation: u64,
}

/// The catalog's trust anchors; see the module documentation.
#[derive(Debug, Default)]
pub struct CatalogAnchors {
    snapshot: RwLock<Snapshot>,
}

impl CatalogAnchors {
    /// No anchors yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes the rows of `catalog` when they changed since the last refresh; returns
    /// `None` when nothing changed, else the zones whose negative trust anchors came or
    /// went (the cached answers under them are stale).
    pub fn refresh(&self, catalog: &Catalog) -> Option<Vec<DnsName>> {
        let revision = catalog.anchors_revision();
        {
            let snapshot = self.snapshot.read().unwrap_or_else(PoisonError::into_inner);
            if snapshot.revision == Some(revision) {
                return None;
            }
        }
        let anchors: HashMap<DnsName, Arc<TrustAnchor>> = catalog
            .trust_anchors()
            .iter()
            .map(|(zone, anchor)| (zone.clone(), Arc::new(anchor.clone())))
            .collect();
        let ntas: Vec<NegativeTrustAnchor> = catalog.ntas().values().cloned().collect();
        let mut snapshot = self
            .snapshot
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let changed = snapshot.anchors.len() != anchors.len()
            || snapshot
                .anchors
                .iter()
                .any(|(zone, anchor)| anchors.get(zone).is_none_or(|other| **other != **anchor))
            || snapshot.ntas != ntas;
        snapshot.revision = Some(revision);
        if !changed {
            return None;
        }
        let mut nta_zones: Vec<DnsName> = snapshot
            .ntas
            .iter()
            .chain(ntas.iter())
            .filter(|nta| !snapshot.ntas.contains(nta) || !ntas.contains(nta))
            .map(|nta| nta.zone.clone())
            .collect();
        nta_zones.sort();
        nta_zones.dedup();
        snapshot.root_tags = anchors
            .get(&DnsName::root())
            .map(|anchor| anchor.trusted().map(|key| key.key_tag).collect())
            .unwrap_or_default();
        snapshot.anchors = anchors;
        snapshot.ntas = ntas;
        snapshot.generation += 1;
        Some(nta_zones)
    }

    /// The key tags of the root's trusted keys (the RFC 8509 sentinel and the RFC 8145
    /// signalling).
    pub fn root_tags(&self) -> Vec<u16> {
        self.snapshot
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .root_tags
            .clone()
    }

    /// Whether `tag` is a trusted root key's tag; allocates nothing (the worker's
    /// sentinel check on a cache hit).
    pub fn has_root_tag(&self, tag: u16) -> bool {
        self.snapshot
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .root_tags
            .contains(&tag)
    }

    /// The anchor rows, for the status.
    pub fn rows(&self) -> Vec<Arc<TrustAnchor>> {
        let snapshot = self.snapshot.read().unwrap_or_else(PoisonError::into_inner);
        let mut rows: Vec<Arc<TrustAnchor>> = snapshot.anchors.values().cloned().collect();
        rows.sort_by(|a, b| a.zone.as_str().cmp(b.zone.as_str()));
        rows
    }

    /// The negative trust anchors that have not expired at `now`, for the status.
    pub fn active_ntas(&self, now: Timestamp) -> Vec<NegativeTrustAnchor> {
        let snapshot = self.snapshot.read().unwrap_or_else(PoisonError::into_inner);
        snapshot
            .ntas
            .iter()
            .filter(|nta| now < nta.expires_at)
            .cloned()
            .collect()
    }
}

impl TrustAnchors for CatalogAnchors {
    fn closest(&self, name: &DnsName) -> Option<Arc<TrustAnchor>> {
        let snapshot = self.snapshot.read().unwrap_or_else(PoisonError::into_inner);
        let mut candidate = Some(name.clone());
        while let Some(zone) = candidate {
            if let Some(anchor) = snapshot.anchors.get(&zone) {
                return Some(Arc::clone(anchor));
            }
            candidate = zone.parent();
        }
        None
    }

    fn negative(&self, name: &DnsName, now: Timestamp) -> Option<NegativeTrustAnchor> {
        let snapshot = self.snapshot.read().unwrap_or_else(PoisonError::into_inner);
        snapshot
            .ntas
            .iter()
            .filter(|nta| nta.covers(name, now))
            .max_by_key(|nta| nta.zone.label_count())
            .cloned()
    }

    fn generation(&self) -> u64 {
        self.snapshot
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .generation
    }
}
