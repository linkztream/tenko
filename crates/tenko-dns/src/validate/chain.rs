//! The chain walk (recursion plan section 2.3, RFC 4035 section 5): from the nearest trust
//! anchor at or above a zone, down one label at a time, asking the parent for DS and the
//! child for DNSKEY through the [`KeyFetch`] of the context, with every finding kept in
//! the [`KeyTable`] and mirrored into the infrastructure cache's DS slot where the zone
//! has a cut.
//!
//! At each name below the anchor the parent's DS answer decides: a DS set signed by the
//! parent's keys names the child's keys, which the child's DNSKEY set must be signed by
//! (secure); a DS set of unsupported algorithms or digests only makes the child insecure
//! (RFC 6840 section 5.2); a NODATA proven by the parent's NSEC or NSEC3 records makes
//! the child insecure when the name is a delegation (NS, no DS, no SOA, or an opt-out
//! span) and no cut at all otherwise (the parent's keys go on); anything else is bogus
//! with the extended error that names the fault. A name at or below a negative trust
//! anchor is insecure without a walk; a name no anchor covers is indeterminate.

use std::{
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use tenko_core::{
    Timestamp,
    dns::{AnchorData, DnsName, ExtendedError, TrustAnchor},
};

use crate::{
    dnssec::crypto,
    name,
    recurse::message::{self, Parsed, types},
    recursion::{
        BogusReason, ChainContext, DsState, ValidationCaps,
        validator::{FetchError, Fetched},
    },
};

use super::{
    keys::{BOGUS_HOLD, KeyTable, MAX_HOLD, ZoneState},
    nsec::{self, CutProof, Nsec, ProofFault},
    nsec3::{Chain, Nsec3},
    rrset::{Budget, Fault, Key, RrSet, Verified, group, verify},
};

/// The most sub-queries one client query's validation may make.
pub const MAX_FETCHES: u32 = 32;

/// The denial records of a parent's DS answer and their TTL.
type ParentDenials<'p> = (Vec<Nsec<'p>>, Vec<Nsec3<'p>>, u32);

/// The DNSKEY type.
pub const DNSKEY: u16 = 48;

/// The walk could not finish: a sub-query it needed was refused (the client set CD, or
/// the budget is spent), so the answer stays unvalidated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Incomplete;

/// The bogus reason and extended error of a verification fault.
pub fn fault_reason(fault: Fault) -> (BogusReason, ExtendedError) {
    let reason = match fault {
        Fault::NoSig => BogusReason::MissingRrsig,
        Fault::NoKey => BogusReason::MissingKey,
        Fault::Expired => BogusReason::Expired,
        Fault::NotYetValid => BogusReason::NotYetValid,
        Fault::Signature => BogusReason::Signature,
        Fault::Cap => BogusReason::Cap,
    };
    (reason, reason.ede())
}

/// The bogus reason that best fits an extended error read back from the infrastructure
/// cache.
fn reason_of(ede: ExtendedError) -> BogusReason {
    BogusReason::ALL
        .into_iter()
        .find(|reason| reason.ede() == ede)
        .unwrap_or(BogusReason::Signature)
}

/// The walk of one client query's validation.
pub struct Walker<'a> {
    ctx: &'a ChainContext<'a>,
    table: &'a Mutex<KeyTable>,
    caps: ValidationCaps,
    /// Seconds since 1970 modulo 2^32, for the signatures.
    pub now32: u32,
    now: Instant,
    now_ts: Timestamp,
    generation: u64,
    /// The costs so far.
    pub budget: Budget,
    /// The root's DNSKEY set failed on time: the clock is probably wrong (OPS-09).
    pub clock_fault: Option<bool>,
}

impl<'a> Walker<'a> {
    /// A walk in `ctx` over `table`.
    pub fn new(ctx: &'a ChainContext<'a>, table: &'a Mutex<KeyTable>) -> Self {
        let unix = ctx
            .now
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let now32 = u32::try_from(unix.as_secs() % (1 << 32)).unwrap_or(0);
        let now_ts = Timestamp::from_unix_nanos(i128::try_from(unix.as_nanos()).unwrap_or(0))
            .unwrap_or_else(|_| Timestamp::now());
        Self {
            ctx,
            table,
            caps: ctx.caps,
            now32,
            now: Instant::now(),
            now_ts,
            generation: ctx.anchors.generation(),
            budget: Budget::default(),
            clock_fault: None,
        }
    }

    /// The caps.
    pub fn caps(&self) -> ValidationCaps {
        self.caps
    }

    fn lock(&self) -> std::sync::MutexGuard<'a, KeyTable> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What is known about `zone`: the infrastructure cache's DS slot first, then the
    /// table.
    fn lookup(&self, zone: &[u8]) -> Option<ZoneState> {
        if let Ok((zone_name, _)) = DnsName::from_wire(zone)
            && let Some(cut) = self.ctx.infra.cut(&zone_name, self.now)
        {
            match cut.ds {
                DsState::Secure { keys, .. } => return Some(ZoneState::Secure(keys)),
                DsState::Insecure { .. } => return Some(ZoneState::Insecure),
                DsState::Bogus { ede, .. } => {
                    return Some(ZoneState::Bogus(reason_of(ede), ede));
                }
                DsState::Unknown => {}
            }
        }
        self.lock().get(zone, self.generation, self.now)
    }

    /// Remembers `state` for `zone` for `hold`.
    fn remember(&self, zone: &[u8], state: ZoneState, hold: Duration) {
        let hold = hold.min(MAX_HOLD);
        let until = self.now + hold;
        if let Ok((zone_name, _)) = DnsName::from_wire(zone) {
            let mirror = match &state {
                ZoneState::Secure(keys) => Some(DsState::Secure {
                    keys: Arc::clone(keys),
                    until,
                }),
                ZoneState::Insecure => Some(DsState::Insecure { until }),
                ZoneState::Bogus(_, ede) => Some(DsState::Bogus { ede: *ede, until }),
                ZoneState::NotACut | ZoneState::Indeterminate => None,
            };
            if let Some(ds) = mirror {
                self.ctx.infra.set_ds(&zone_name, ds);
            }
        }
        self.lock().put(zone, state, until, self.generation);
    }

    /// The seconds a verified RRset may be trusted for: the smaller of its TTL and what is
    /// left of its signature.
    fn hold_of(&self, ttl: u32, verified: &Verified) -> Duration {
        let left = crate::dnssec::sign::seconds_until(verified.expiration, self.now32).max(0);
        Duration::from_secs(u64::from(ttl).min(u64::try_from(left).unwrap_or(0)))
    }

    /// One sub-query.
    async fn fetch(&mut self, name: &[u8], rtype: u16) -> Result<Option<Parsed>, Incomplete> {
        if self.budget.fetches >= MAX_FETCHES {
            return Err(Incomplete);
        }
        self.budget.fetches += 1;
        let Ok((name, _)) = DnsName::from_wire(name) else {
            return Ok(None);
        };
        match self
            .ctx
            .fetch
            .fetch(&name, tenko_core::dns::Rtype(rtype))
            .await
        {
            Ok(Fetched { message, .. }) => Ok(message::parse(&message)),
            Err(FetchError::Budget) => Err(Incomplete),
            Err(FetchError::Unreachable) => Ok(None),
        }
    }

    /// The trusted keys of the anchor's zone: its DNSKEY set, signed by a key an anchor
    /// names.
    async fn anchor_keys(&mut self, anchor: &TrustAnchor) -> Result<ZoneState, Incomplete> {
        let zone = anchor.zone.to_wire();
        let Some(parsed) = self.fetch(&zone, DNSKEY).await? else {
            return Ok(ZoneState::Bogus(
                BogusReason::MissingKey,
                ExtendedError::DNSKEY_MISSING,
            ));
        };
        let sets = group(&parsed.answer);
        let Some(set) = sets
            .iter()
            .find(|set| set.owner == zone.as_slice() && set.rtype == DNSKEY)
        else {
            return Ok(ZoneState::Bogus(
                BogusReason::MissingKey,
                ExtendedError::DNSKEY_MISSING,
            ));
        };
        let trusted: Vec<&AnchorData> = anchor.trusted().map(|key| &key.data).collect();
        let accept = |key: &Key<'_>| {
            trusted.iter().any(|data| match data {
                AnchorData::Ds { rdata } => crypto::ds_matches(&zone, key.data, &rdata.0),
                AnchorData::Dnskey { rdata } => rdata.0 == key.data,
            })
        };
        let result = verify(
            set,
            &zone,
            &set.records,
            &accept,
            self.now32,
            &self.caps,
            &mut self.budget,
        );
        if anchor.zone.is_root() {
            self.clock_fault = Some(matches!(result, Err(Fault::Expired | Fault::NotYetValid)));
        }
        Ok(match result {
            Ok(verified) => {
                let state = ZoneState::Secure(key_set(set));
                self.remember(&zone, state.clone(), self.hold_of(set.ttl, &verified));
                state
            }
            Err(fault) => {
                let (reason, ede) = fault_reason(fault);
                let state = ZoneState::Bogus(reason, ede);
                self.remember(&zone, state.clone(), BOGUS_HOLD);
                state
            }
        })
    }

    /// The parent's NSEC and NSEC3 records of `parsed`, each verified with `keys` of
    /// `parent`; a record that fails makes the whole answer bogus.
    fn parent_denials<'p>(
        &mut self,
        parsed: &'p Parsed,
        parent: &[u8],
        keys: &[&[u8]],
    ) -> Result<ParentDenials<'p>, (BogusReason, ExtendedError)> {
        let sets = group(&parsed.authority);
        let mut plain = Vec::new();
        let mut hashed = Vec::new();
        let mut ttl = u32::MAX;
        // A parent's record without any signature (its SOA, say) marks an answer whose
        // signatures were stripped on the way: that, not a missing proof, is the fault.
        let mut stripped = false;
        for set in &sets {
            if set.rtype != types::NSEC && set.rtype != types::NSEC3 {
                if set.rtype != types::NS
                    && set.sigs.is_empty()
                    && crate::name::is_within(set.owner, parent)
                {
                    stripped = true;
                }
                continue;
            }
            if !set
                .sigs
                .iter()
                .any(|sig| sig.signer.eq_ignore_ascii_case(parent))
            {
                continue;
            }
            let verified = verify(
                set,
                parent,
                keys,
                &|_| true,
                self.now32,
                &self.caps,
                &mut self.budget,
            )
            .map_err(fault_reason)?;
            ttl = ttl.min(set.ttl).min(verified.original_ttl);
            for data in &set.records {
                match set.rtype {
                    types::NSEC => plain.extend(Nsec::parse(set.owner, data)),
                    _ => hashed.extend(Nsec3::parse(set.owner, data, parent)),
                }
            }
        }
        if plain.is_empty() && hashed.is_empty() && stripped {
            return Err(fault_reason(Fault::NoSig));
        }
        Ok((plain, hashed, if ttl == u32::MAX { 0 } else { ttl }))
    }

    /// One step down: what `child` is, given the keys of `parent`.
    async fn step(
        &mut self,
        child: &[u8],
        parent: &[u8],
        parent_keys: &Arc<[Vec<u8>]>,
    ) -> Result<(ZoneState, Duration), Incomplete> {
        let bogus =
            |reason: BogusReason, ede: ExtendedError| (ZoneState::Bogus(reason, ede), BOGUS_HOLD);
        let keys: Vec<&[u8]> = parent_keys.iter().map(Vec::as_slice).collect();
        let Some(ds_answer) = self.fetch(child, types::DS).await? else {
            return Ok(bogus(
                BogusReason::MissingKey,
                ExtendedError::DNSKEY_MISSING,
            ));
        };
        if ds_answer.rcode != 0 && ds_answer.rcode != 3 {
            return Ok(bogus(
                BogusReason::MissingKey,
                ExtendedError::DNSKEY_MISSING,
            ));
        }
        let answer_sets = group(&ds_answer.answer);
        if let Some(ds_set) = answer_sets
            .iter()
            .find(|set| set.owner == child && set.rtype == types::DS)
        {
            let verified = match verify(
                ds_set,
                parent,
                &keys,
                &|_| true,
                self.now32,
                &self.caps,
                &mut self.budget,
            ) {
                Ok(verified) => verified,
                Err(fault) => {
                    let (reason, ede) = fault_reason(fault);
                    return Ok(bogus(reason, ede));
                }
            };
            let supported: Vec<&[u8]> = ds_set
                .records
                .iter()
                .copied()
                .filter(|ds| {
                    ds.len() > 4
                        && crypto::supported_algorithm(ds[2])
                        && crypto::supported_digest(ds[3])
                })
                .collect();
            if supported.is_empty() {
                return Ok((ZoneState::Insecure, self.hold_of(ds_set.ttl, &verified)));
            }
            return self.child_keys(child, &supported).await;
        }
        // No DS: what the parent's denial records say.
        let (plain, hashed, ttl) = match self.parent_denials(&ds_answer, parent, &keys) {
            Ok(denials) => denials,
            Err((reason, ede)) => return Ok(bogus(reason, ede)),
        };
        let hold = Duration::from_secs(u64::from(ttl));
        if !plain.is_empty() {
            return Ok(match nsec::delegation(&plain, child, parent) {
                Some(CutProof::Insecure) => (ZoneState::Insecure, hold),
                Some(CutProof::NotACut) => (ZoneState::NotACut, hold),
                Some(CutProof::Bogus) | None => {
                    bogus(BogusReason::Nsec, ExtendedError::NSEC_MISSING)
                }
            });
        }
        if let Some(chain) = Chain::new(&hashed, parent) {
            if chain.iterations() > self.caps.nsec3_servfail_above {
                return Ok(bogus(
                    BogusReason::Nsec,
                    ExtendedError::UNSUPPORTED_NSEC3_ITERATIONS,
                ));
            }
            if chain.iterations() > self.caps.nsec3_insecure_above {
                return Ok((ZoneState::Insecure, hold));
            }
            self.budget.hashes = 0;
            let caps = self.caps;
            return Ok(match chain.delegation(child, &caps, &mut self.budget) {
                Ok(Some(CutProof::Insecure)) => (ZoneState::Insecure, hold),
                Ok(Some(CutProof::NotACut)) => (ZoneState::NotACut, hold),
                Ok(Some(CutProof::Bogus) | None) => {
                    bogus(BogusReason::Nsec, ExtendedError::NSEC_MISSING)
                }
                Err(ProofFault::Cap) => bogus(BogusReason::Cap, ExtendedError::DNSSEC_BOGUS),
                Err(_) => bogus(BogusReason::Nsec, ExtendedError::NSEC_MISSING),
            });
        }
        Ok(bogus(BogusReason::Nsec, ExtendedError::NSEC_MISSING))
    }

    /// The child's DNSKEY set, signed by a key the DS records `supported` name.
    async fn child_keys(
        &mut self,
        child: &[u8],
        supported: &[&[u8]],
    ) -> Result<(ZoneState, Duration), Incomplete> {
        let missing = (
            ZoneState::Bogus(BogusReason::MissingKey, ExtendedError::DNSKEY_MISSING),
            BOGUS_HOLD,
        );
        let Some(parsed) = self.fetch(child, DNSKEY).await? else {
            return Ok(missing);
        };
        let sets = group(&parsed.answer);
        let Some(set) = sets
            .iter()
            .find(|set| set.owner == child && set.rtype == DNSKEY)
        else {
            return Ok(missing);
        };
        let accept = |key: &Key<'_>| {
            supported
                .iter()
                .any(|ds| crypto::ds_matches(child, key.data, ds))
        };
        match verify(
            set,
            child,
            &set.records,
            &accept,
            self.now32,
            &self.caps,
            &mut self.budget,
        ) {
            Ok(verified) => Ok((
                ZoneState::Secure(key_set(set)),
                self.hold_of(set.ttl, &verified),
            )),
            Err(fault) => {
                let (reason, ede) = fault_reason(fault);
                Ok((ZoneState::Bogus(reason, ede), BOGUS_HOLD))
            }
        }
    }

    /// The state of `zone` (lowercase wire form): the keys that sign it, or why they
    /// cannot be had.
    ///
    /// # Errors
    ///
    /// [`Incomplete`] when a sub-query was refused.
    pub async fn keys_for(&mut self, zone: &[u8]) -> Result<ZoneState, Incomplete> {
        let Ok((zone_name, _)) = DnsName::from_wire(zone) else {
            return Ok(ZoneState::Bogus(
                BogusReason::Signature,
                ExtendedError::DNSSEC_BOGUS,
            ));
        };
        let Some(anchor) = self.ctx.anchors.closest(&zone_name) else {
            return Ok(ZoneState::Indeterminate);
        };
        if self.ctx.anchors.negative(&zone_name, self.now_ts).is_some() {
            return Ok(ZoneState::Insecure);
        }
        if anchor.trusted().next().is_none() {
            // Every anchor key is revoked or pending: nothing to start from.
            return Ok(ZoneState::Bogus(
                BogusReason::MissingKey,
                ExtendedError::DNSKEY_MISSING,
            ));
        }
        let anchor_zone = anchor.zone.to_wire();
        let mut current = match self.lookup(&anchor_zone) {
            Some(ZoneState::NotACut) | None => self.anchor_keys(&anchor).await?,
            Some(state) => state,
        };
        let mut parent: Vec<u8> = anchor_zone.clone();
        let labels = name::label_count(zone);
        let anchor_labels = name::label_count(&anchor_zone);
        for depth in anchor_labels + 1..=labels {
            let ZoneState::Secure(parent_keys) = &current else {
                return Ok(current);
            };
            let parent_keys = Arc::clone(parent_keys);
            let child = name::suffix(zone, labels - depth);
            let state = if let Some(state) = self.lookup(child) {
                state
            } else {
                let (state, hold) = self.step(child, &parent, &parent_keys).await?;
                self.remember(child, state.clone(), hold);
                state
            };
            match state {
                ZoneState::NotACut => {}
                other => {
                    current = other;
                    parent = child.to_vec();
                }
            }
        }
        Ok(current)
    }

    /// The state of the zone an unsigned RRset at `owner` lives in: the walk down every
    /// label of the owner, which ends secure when no cut on the way is insecure.
    ///
    /// # Errors
    ///
    /// [`Incomplete`] when a sub-query was refused.
    pub async fn state_at(&mut self, owner: &[u8]) -> Result<ZoneState, Incomplete> {
        self.keys_for(owner).await
    }
}

/// The DNSKEY records of a verified set as the key set of its zone.
fn key_set(set: &RrSet<'_>) -> Arc<[Vec<u8>]> {
    set.records
        .iter()
        .map(|data| data.to_vec())
        .collect::<Vec<_>>()
        .into()
}
