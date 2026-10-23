//! The resolver the trust anchor service asks in process ([`NodeResolver`], recursion
//! plan section 2.13): a zone's DNSKEY set through the node's own engine, bypassing the
//! answer cache, validated against the current anchors as RFC 5011 section 2.2 asks (the
//! set is signed by a key the anchor row trusts), with a revoked key kept in the set only
//! when its self-signature verifies (section 2.1). Phase 5 puts a node of the installation
//! behind the same trait.

use std::{sync::Arc, time::SystemTime};

use tenko_core::{
    Timestamp,
    dns::{AnchorData, DnsName, SecurityState},
};

use crate::{
    dnssec::crypto,
    recurse::{Engine, Outcome, Question, message},
    recursion::{AnchorError, AnchorResolver, Authority, DnskeySet, TrustAnchors, ValidationCaps},
    validate::{
        chain::DNSKEY,
        rrset::{Budget, Key, group, self_signed, verify},
    },
};

/// The in-process resolver; see the module documentation.
pub struct NodeResolver<A> {
    engine: Arc<Engine<A>>,
    anchors: Arc<dyn TrustAnchors>,
    caps: ValidationCaps,
}

impl<A> std::fmt::Debug for NodeResolver<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeResolver").finish_non_exhaustive()
    }
}

impl<A: Authority + 'static> NodeResolver<A> {
    /// A resolver over `engine` with `anchors`.
    pub fn new(
        engine: Arc<Engine<A>>,
        anchors: Arc<dyn TrustAnchors>,
        caps: ValidationCaps,
    ) -> Self {
        Self {
            engine,
            anchors,
            caps,
        }
    }
}

fn now32() -> u32 {
    let unix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    u32::try_from(unix.as_secs() % (1 << 32)).unwrap_or(0)
}

#[async_trait::async_trait]
impl<A: Authority + 'static> AnchorResolver for NodeResolver<A> {
    async fn dnskeys(&self, zone: &DnsName) -> Result<DnskeySet, AnchorError> {
        let wire = zone.to_wire();
        let resolved = self
            .engine
            .resolve(Question {
                qname: &wire,
                qtype: DNSKEY,
                qclass: 1,
                view: None,
            })
            .await;
        if resolved.outcome != Outcome::Answered {
            return Err(AnchorError::Unreachable);
        }
        let parsed = message::parse(&resolved.message).ok_or(AnchorError::Unreachable)?;
        let sets = group(&parsed.answer);
        let set = sets
            .iter()
            .find(|set| set.owner == wire.as_slice() && set.rtype == DNSKEY)
            .ok_or(AnchorError::Unreachable)?;
        let anchor = self.anchors.closest(zone);
        let trusted: Vec<AnchorData> = anchor
            .as_ref()
            .filter(|anchor| anchor.zone == *zone)
            .map(|anchor| anchor.trusted().map(|key| key.data.clone()).collect())
            .unwrap_or_default();
        // An anchor key names the DNSKEY as it was added; a revoked key carries the
        // REVOKE bit and signs the set under its new tag (RFC 5011 section 2.1), so the
        // comparison is made with the bit cleared as well.
        let accept = |key: &Key<'_>| {
            let mut cleared = key.data.to_vec();
            if let Some(flags_low) = cleared.get_mut(1) {
                *flags_low &= !0x80;
            }
            trusted.iter().any(|data| match data {
                AnchorData::Ds { rdata } => {
                    crypto::ds_matches(&wire, key.data, &rdata.0)
                        || crypto::ds_matches(&wire, &cleared, &rdata.0)
                }
                AnchorData::Dnskey { rdata } => rdata.0 == key.data || rdata.0 == cleared,
            })
        };
        let now = now32();
        let mut budget = Budget::default();
        let verified = verify(
            set,
            &wire,
            &set.records,
            &accept,
            now,
            &self.caps,
            &mut budget,
        )
        .or_else(|fault| {
            // A set signed only by a revoked anchor key: the revocation itself is what
            // the service must learn, so the self-signature counts.
            let revoked_anchor_signed = set.records.iter().any(|data| {
                Key::parse(data).is_some_and(|key| {
                    key.revoked()
                        && accept(&key)
                        && self_signed(set, &wire, data, now, &self.caps, &mut budget)
                })
            });
            if revoked_anchor_signed {
                Ok(crate::validate::rrset::Verified {
                    expiration: now,
                    original_ttl: set.ttl,
                    wildcard_labels: None,
                    key_tag: 0,
                })
            } else {
                Err(fault)
            }
        });
        let (state, signature_expiry, original_ttl) = match &verified {
            Ok(verified) => {
                let left = crate::dnssec::sign::seconds_until(verified.expiration, now).max(0);
                (
                    SecurityState::Secure,
                    Timestamp::now().checked_add(std::time::Duration::from_secs(
                        u64::try_from(left).unwrap_or(0),
                    )),
                    verified.original_ttl,
                )
            }
            Err(_) if trusted.is_empty() => (SecurityState::Indeterminate, None, set.ttl),
            Err(_) => (SecurityState::Bogus, None, set.ttl),
        };
        // A revoked key stays in the set only when it signed the set itself.
        let keys: Vec<Vec<u8>> = set
            .records
            .iter()
            .filter(|data| {
                Key::parse(data).is_some_and(|key| {
                    !key.revoked() || self_signed(set, &wire, data, now, &self.caps, &mut budget)
                })
            })
            .map(|data| data.to_vec())
            .collect();
        Ok(DnskeySet {
            keys,
            state,
            ttl: set.ttl,
            original_ttl,
            signature_expiry,
        })
    }
}
