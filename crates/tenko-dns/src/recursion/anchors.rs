//! The trust anchors as the validator reads them ([`TrustAnchors`], fed from the rows
//! `dns.trust_anchors` and `dns.ntas` through the catalog by WP10.2) and the resolver the
//! leader's trust anchor service asks for a zone's DNSKEY set ([`AnchorResolver`]: in
//! process on the single node, a node of the installation in Phase 5; recursion plan
//! section 2.13). [`MemAnchors`] is the test oracle of both.

use std::{
    collections::HashMap,
    sync::{Arc, PoisonError, RwLock},
};

use tenko_core::{
    Timestamp,
    dns::{
        AnchorData, AnchorKey, AnchorSource, AnchorState, DnsName, ExtendedError,
        NegativeTrustAnchor, SecurityState, TrustAnchor,
    },
    serde_util::HexBytes,
};

use super::shipped;

/// The trust anchors and negative trust anchors the validator uses.
pub trait TrustAnchors: Send + Sync {
    /// The anchor of the closest zone at or above `name` (the root's at worst, when there
    /// is one).
    fn closest(&self, name: &DnsName) -> Option<Arc<TrustAnchor>>;

    /// The negative trust anchor that covers `name` at `now`, if any (RFC 7646).
    fn negative(&self, name: &DnsName, now: Timestamp) -> Option<NegativeTrustAnchor>;

    /// A number that changes whenever the anchors change, so that the validator can drop
    /// the key sets it validated with the old ones.
    fn generation(&self) -> u64;
}

/// A zone's DNSKEY set as the trust anchor service needs it (RFC 5011 section 2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnskeySet {
    /// The DNSKEY records' data.
    pub keys: Vec<Vec<u8>>,
    /// The validation state of the set against the current anchors.
    pub state: SecurityState,
    /// The TTL the set came with.
    pub ttl: u32,
    /// The original TTL of its RRSIG.
    pub original_ttl: u32,
    /// The earliest expiry of its signatures.
    pub signature_expiry: Option<Timestamp>,
}

/// Why the DNSKEY set could not be had.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AnchorError {
    /// No server of the zone answered.
    #[error("no server of the zone answered")]
    Unreachable,
    /// The answer did not validate.
    #[error("the DNSKEY set is bogus (extended error {})", .0.code())]
    Bogus(ExtendedError),
    /// The node runs no resolver (recursion off).
    #[error("the node runs no recursive resolver")]
    NoResolver,
}

/// The resolver the trust anchor service asks; see the module documentation.
#[async_trait::async_trait]
pub trait AnchorResolver: Send + Sync {
    /// The DNSKEY set of `zone`, validated with the current anchors, asked with CD clear
    /// and bypassing the answer cache.
    ///
    /// # Errors
    ///
    /// [`AnchorError`] when no server answered, the set is bogus or there is no resolver.
    async fn dnskeys(&self, zone: &DnsName) -> Result<DnskeySet, AnchorError>;
}

/// The root's trust anchor from the shipped IANA file: the keys valid at `now` as DS keys
/// in the state Valid, with the source `shipped` of `release`.
pub fn shipped_root(release: &str, now: Timestamp) -> TrustAnchor {
    let unix = i64::try_from(now.unix_nanos() / 1_000_000_000).unwrap_or(i64::MAX);
    let keys = shipped::valid_at(unix)
        .map(|anchor| {
            let mut rdata = anchor.key_tag.to_be_bytes().to_vec();
            rdata.extend_from_slice(&[anchor.algorithm, anchor.digest_type]);
            rdata.extend_from_slice(anchor.digest);
            AnchorKey {
                key_tag: anchor.key_tag,
                algorithm: anchor.algorithm,
                digest_type: Some(anchor.digest_type),
                data: AnchorData::Ds {
                    rdata: HexBytes(rdata),
                },
                state: AnchorState::Valid,
                source: AnchorSource::Shipped {
                    release: release.to_owned(),
                },
                added_at: now,
                state_since: now,
                last_seen: None,
            }
        })
        .collect();
    TrustAnchor {
        zone: DnsName::root(),
        keys,
        last_query: None,
        next_query: None,
    }
}

#[derive(Debug, Default)]
struct Inner {
    anchors: HashMap<DnsName, Arc<TrustAnchor>>,
    negative: Vec<NegativeTrustAnchor>,
    dnskeys: HashMap<DnsName, Result<DnskeySet, AnchorError>>,
    generation: u64,
}

/// The test oracle of [`TrustAnchors`] and [`AnchorResolver`]: anchors and negative trust
/// anchors set by hand, and DNSKEY sets scripted per zone.
#[derive(Debug, Default)]
pub struct MemAnchors {
    inner: RwLock<Inner>,
}

impl MemAnchors {
    /// No anchor.
    pub fn new() -> Self {
        Self::default()
    }

    /// The shipped root anchor ([`shipped_root`]).
    pub fn shipped(release: &str, now: Timestamp) -> Self {
        let anchors = Self::new();
        anchors.set(shipped_root(release, now));
        anchors
    }

    /// Sets the anchor of its zone.
    pub fn set(&self, anchor: TrustAnchor) {
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        inner.anchors.insert(anchor.zone.clone(), Arc::new(anchor));
        inner.generation += 1;
    }

    /// Removes the anchor of `zone`.
    pub fn remove(&self, zone: &DnsName) {
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        inner.anchors.remove(zone);
        inner.generation += 1;
    }

    /// Adds a negative trust anchor.
    pub fn add_negative(&self, anchor: NegativeTrustAnchor) {
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        inner.negative.push(anchor);
        inner.generation += 1;
    }

    /// Scripts the answer of [`AnchorResolver::dnskeys`] for `zone`.
    pub fn script_dnskeys(&self, zone: DnsName, answer: Result<DnskeySet, AnchorError>) {
        self.inner
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .dnskeys
            .insert(zone, answer);
    }
}

impl TrustAnchors for MemAnchors {
    fn closest(&self, name: &DnsName) -> Option<Arc<TrustAnchor>> {
        let inner = self.inner.read().unwrap_or_else(PoisonError::into_inner);
        let mut candidate = Some(name.clone());
        while let Some(zone) = candidate {
            if let Some(anchor) = inner.anchors.get(&zone) {
                return Some(Arc::clone(anchor));
            }
            candidate = zone.parent();
        }
        None
    }

    fn negative(&self, name: &DnsName, now: Timestamp) -> Option<NegativeTrustAnchor> {
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .negative
            .iter()
            .filter(|anchor| anchor.covers(name, now))
            .max_by_key(|anchor| anchor.zone.label_count())
            .cloned()
    }

    fn generation(&self) -> u64 {
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .generation
    }
}

#[async_trait::async_trait]
impl AnchorResolver for MemAnchors {
    async fn dnskeys(&self, zone: &DnsName) -> Result<DnskeySet, AnchorError> {
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .dnskeys
            .get(zone)
            .cloned()
            .unwrap_or(Err(AnchorError::Unreachable))
    }
}
