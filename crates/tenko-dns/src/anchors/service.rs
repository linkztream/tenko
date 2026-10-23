//! The leader service `dns.trust_anchors` (recursion plan section 2.4, RFC 5011): the
//! root's row from the shipped anchors, replaced at an upgrade where the stored set is
//! still a shipped set; the RFC 5011 state machine per anchor zone over the DNSKEY set the
//! node's own resolver returns ([`AnchorResolver`]); the expiry of negative trust
//! anchors (RFC 7646). Every state change is a row change with its audit record
//! (`dns.trust_anchor.state`, `dns.nta.expire`), fenced with the leader epoch.
//!
//! # The states (RFC 5011 section 4)
//!
//! A key seen with the SEP bit in a DNSKEY set signed by a trusted anchor enters
//! `AddPend`; after the add hold-down it is `Valid` when still there, gone when not. A `Valid`
//! key the set no longer holds is `Missing` (still trusted); seen again, `Valid`. A key with
//! the REVOKE bit that signed the set is `Revoked` (no longer trusted) and `Removed` after
//! the remove hold-down, then forgotten. The hold-downs are 30 days, or `[dns.recursion]
//! rfc5011_hold_down_secs` under the Lab profile ([`AnchorWiring`]). The active refresh
//! interval is half the signature validity, at least an hour, at most 15 days (section
//! 2.3); a query that fails is tried again after an hour.
//!
//! The resolver the service asks is wired in by the `dns` role when it starts
//! ([`AnchorWiring::set_resolver`]); a controller without the role keeps the rows and
//! expires negative trust anchors but runs no refresh.

use std::{
    sync::{
        Arc, Mutex, PoisonError, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tenko_core::{
    ObjectKind, ObjectRef, RequestCtx, SystemComponent, Timestamp,
    audit::AuditDraft,
    cluster::LeaderService,
    dns::{
        AnchorData, AnchorKey, AnchorSource, AnchorState, DnsName, NegativeTrustAnchor, NtaId,
        SecurityState, TrustAnchor, audit,
        tables::{NTAS, NTAS_BY_ZONE, TRUST_ANCHORS},
    },
};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, Store, WriteBatch, fence};
use tokio_util::sync::CancellationToken;

use crate::{
    dnssec::crypto,
    recursion::{AnchorResolver, DnskeySet, anchors::shipped_root, shipped},
    validate::rrset::Key,
};

/// The name of the service.
pub const SERVICE: &str = "dns.trust_anchors";

/// The hold-downs of RFC 5011 section 2.4.1: thirty days.
pub const HOLD_DOWN: Duration = Duration::from_secs(30 * 86_400);

/// The shortest active refresh interval (RFC 5011 section 2.3).
pub const REFRESH_MIN: Duration = Duration::from_secs(3600);

/// The longest active refresh interval.
pub const REFRESH_MAX: Duration = Duration::from_secs(15 * 86_400);

/// How long after a failed query the zone is asked again.
pub const RETRY: Duration = Duration::from_secs(3600);

/// What the `dns` role wires into the service when it starts.
#[derive(Default)]
pub struct AnchorWiring {
    resolver: RwLock<Option<Arc<dyn AnchorResolver>>>,
    hold_down_secs: AtomicU64,
}

impl std::fmt::Debug for AnchorWiring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnchorWiring")
            .field("resolver", &self.resolver().is_some())
            .field("hold_down", &self.hold_down())
            .finish()
    }
}

impl AnchorWiring {
    /// Nothing wired yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The resolver the service asks, and the hold-down in seconds (`None`: thirty days).
    pub fn set_resolver(&self, resolver: Arc<dyn AnchorResolver>, hold_down_secs: Option<u64>) {
        *self
            .resolver
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(resolver);
        self.hold_down_secs
            .store(hold_down_secs.unwrap_or(0), Ordering::Relaxed);
    }

    /// The resolver, when one is wired.
    pub fn resolver(&self) -> Option<Arc<dyn AnchorResolver>> {
        self.resolver
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The hold-down in force.
    pub fn hold_down(&self) -> Duration {
        match self.hold_down_secs.load(Ordering::Relaxed) {
            0 => HOLD_DOWN,
            secs => Duration::from_secs(secs),
        }
    }
}

/// The settings of the service.
#[derive(Debug, Clone)]
pub struct AnchorServiceConfig {
    /// The release that ships the anchors (the crate version).
    pub release: String,
    /// How often the service looks at the rows.
    pub tick: Duration,
}

impl Default for AnchorServiceConfig {
    fn default() -> Self {
        Self {
            release: String::new(),
            tick: Duration::from_secs(60),
        }
    }
}

/// What one pass did, for the log and the tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PassReport {
    /// Rows written.
    pub written: usize,
    /// Zones asked for their DNSKEY set.
    pub asked: usize,
    /// Negative trust anchors expired.
    pub expired: usize,
}

/// The service; see the module documentation.
pub struct AnchorService {
    store: Arc<dyn Store>,
    config: AnchorServiceConfig,
    wiring: Arc<AnchorWiring>,
    last: Mutex<PassReport>,
}

impl std::fmt::Debug for AnchorService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnchorService")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

fn ctx(now: Timestamp) -> RequestCtx {
    let mut ctx = RequestCtx::system(SystemComponent::Dns);
    ctx.now = now;
    ctx
}

fn target() -> Vec<ObjectRef> {
    vec![ObjectRef::singleton(ObjectKind::DnsKey)]
}

/// Whether `key` of a row is the DNSKEY `data` of the zone `zone` (wire form), the
/// REVOKE bit left out of the comparison (RFC 5011 section 2.1: a revoked key is the
/// same key with the bit set, under another key tag).
fn names(key: &AnchorKey, zone: &[u8], data: &[u8]) -> bool {
    let mut cleared = data.to_vec();
    if let Some(flags_low) = cleared.get_mut(1) {
        *flags_low &= !0x80;
    }
    match &key.data {
        AnchorData::Dnskey { rdata } => rdata.0 == cleared,
        AnchorData::Ds { rdata } => crypto::ds_matches(zone, &cleared, &rdata.0),
    }
}

/// The active refresh interval for a set whose signatures expire at `expiry` (RFC 5011
/// section 2.3): half the time left, within the bounds. A Lab hold-down shorter than the
/// real one scales the bounds with it (half the hold-down at most), so that a roll of
/// seconds is followed.
fn refresh_interval(
    now: Timestamp,
    expiry: Option<Timestamp>,
    ttl: u32,
    hold_down: Duration,
) -> Duration {
    let half_validity = expiry.map_or(REFRESH_MAX, |expiry| expiry.saturating_since(now) / 2);
    let half_ttl = Duration::from_secs(u64::from(ttl) / 2).max(REFRESH_MIN);
    let interval = half_validity.min(half_ttl).clamp(REFRESH_MIN, REFRESH_MAX);
    if hold_down < HOLD_DOWN {
        interval.min((hold_down / 2).max(Duration::from_secs(1)))
    } else {
        interval
    }
}

/// How long after a failed query the zone is asked again, under `hold_down`.
fn retry_interval(hold_down: Duration) -> Duration {
    if hold_down < HOLD_DOWN {
        (hold_down / 2).max(Duration::from_secs(1))
    } else {
        RETRY
    }
}

impl AnchorService {
    /// The service over `store` with `config` and `wiring`.
    pub fn new(
        store: Arc<dyn Store>,
        config: AnchorServiceConfig,
        wiring: Arc<AnchorWiring>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            config,
            wiring,
            last: Mutex::new(PassReport::default()),
        })
    }

    /// The wiring.
    pub fn wiring(&self) -> &Arc<AnchorWiring> {
        &self.wiring
    }

    /// What the last pass did.
    pub fn last_pass(&self) -> PassReport {
        *self.last.lock().unwrap_or_else(PoisonError::into_inner)
    }

    async fn propose(&self, mut batch: WriteBatch, epoch: Option<u64>) -> Result<(), String> {
        if let Some(epoch) = epoch {
            batch.preconditions.push(fence(epoch));
        }
        self.store
            .propose(batch)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// The root's row: created from the shipped anchors when absent, replaced by the
    /// current shipped set when every stored key is a shipped one of another release.
    async fn ensure_root(&self, epoch: Option<u64>, now: Timestamp) -> Result<usize, String> {
        let view = self
            .store
            .read(ReadConsistency::Local)
            .await
            .map_err(|error| error.to_string())?;
        let root = DnsName::root();
        let existing = view
            .get_typed(&TRUST_ANCHORS, &root)
            .map_err(|error| error.to_string())?;
        let shipped = shipped_root(&self.config.release, now);
        let (replace, revision) = match &existing {
            None => (true, None),
            Some((anchor, revision)) => {
                let all_shipped = anchor
                    .keys
                    .iter()
                    .all(|key| matches!(&key.source, AnchorSource::Shipped { release } if *release != self.config.release));
                let same_set = anchor.keys.len() == shipped.keys.len()
                    && anchor.keys.iter().all(|key| {
                        shipped
                            .keys
                            .iter()
                            .any(|other| other.key_tag == key.key_tag && other.data == key.data)
                    });
                (
                    all_shipped && !same_set && !shipped.keys.is_empty(),
                    Some(*revision),
                )
            }
        };
        if !replace || shipped.keys.is_empty() {
            return Ok(0);
        }
        let mut anchor = shipped;
        anchor.next_query = Some(now);
        let cx = ctx(now);
        let mut batch = WriteBatch::for_request(&cx);
        batch.expect_typed(&TRUST_ANCHORS, &root, revision);
        batch
            .put_typed(&TRUST_ANCHORS, &root, &anchor)
            .map_err(|error| error.to_string())?;
        batch.audit(
            AuditDraft::success(audit::TRUST_ANCHOR_ADD, target())
                .with_context("zone", ".")
                .with_context("source", "shipped")
                .with_context("release", self.config.release.clone())
                .with_context(
                    "key_tags",
                    anchor
                        .keys
                        .iter()
                        .map(|key| key.key_tag.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
        );
        self.propose(batch, epoch).await?;
        tracing::info!(
            release = %self.config.release,
            keys = anchor.keys.len(),
            "the root's trust anchor row holds the shipped anchors"
        );
        Ok(1)
    }

    /// Expires the negative trust anchors past their time.
    async fn expire_ntas(&self, epoch: Option<u64>, now: Timestamp) -> Result<usize, String> {
        let view = self
            .store
            .read(ReadConsistency::Local)
            .await
            .map_err(|error| error.to_string())?;
        let rows: Vec<(NtaId, NegativeTrustAnchor, _)> = view
            .scan_typed(&NTAS, KeyRange::all(), usize::MAX, false)
            .map_err(|error| error.to_string())?;
        let mut expired = 0;
        for (id, nta, revision) in rows {
            if now < nta.expires_at {
                continue;
            }
            let cx = ctx(now);
            let mut batch = WriteBatch::for_request(&cx);
            batch.expect_typed(&NTAS, &id, Some(revision));
            batch.delete_typed(&NTAS, &id);
            batch.delete_typed(&NTAS_BY_ZONE, &(nta.zone.clone(), id));
            batch.audit(
                AuditDraft::success(audit::NTA_EXPIRE, target())
                    .with_context("zone", nta.zone.to_string())
                    .with_context("id", id.to_string()),
            );
            self.propose(batch, epoch).await?;
            tracing::info!(zone = %nta.zone, "a negative trust anchor expired");
            expired += 1;
        }
        Ok(expired)
    }

    /// Applies RFC 5011 to `anchor` with the DNSKEY `set` at `now`; returns the changes
    /// as audit context lines, or nothing when the row stays.
    fn apply(
        anchor: &mut TrustAnchor,
        set: &DnskeySet,
        now: Timestamp,
        hold_down: Duration,
    ) -> Vec<(u16, AnchorState)> {
        let zone = anchor.zone.to_wire();
        let mut changes = Vec::new();
        let set_state =
            |key: &mut AnchorKey, state: AnchorState, changes: &mut Vec<(u16, AnchorState)>| {
                if key.state != state {
                    key.state = state;
                    key.state_since = now;
                    changes.push((key.key_tag, state));
                }
            };
        let keys: Vec<Key<'_>> = set
            .keys
            .iter()
            .filter_map(|data| Key::parse(data))
            .filter(|key| {
                key.flags & tenko_core::dns::recursion::DNSKEY_ZONE != 0 && key.protocol == 3
            })
            .collect();
        // The keys the row knows, seen or not.
        for key in &mut anchor.keys {
            let seen = keys
                .iter()
                .find(|candidate| names(key, &zone, candidate.data));
            match (seen, key.state) {
                (Some(candidate), _) if candidate.revoked() => {
                    key.last_seen = Some(now);
                    if matches!(
                        key.state,
                        AnchorState::Valid
                            | AnchorState::Missing
                            | AnchorState::AddPend
                            | AnchorState::Start
                    ) {
                        set_state(key, AnchorState::Revoked, &mut changes);
                    }
                }
                (Some(_), AnchorState::Missing) => {
                    key.last_seen = Some(now);
                    set_state(key, AnchorState::Valid, &mut changes);
                }
                (Some(_), AnchorState::AddPend | AnchorState::Start) => {
                    key.last_seen = Some(now);
                    if key.state == AnchorState::Start {
                        set_state(key, AnchorState::AddPend, &mut changes);
                    } else if now.saturating_since(key.state_since) >= hold_down {
                        set_state(key, AnchorState::Valid, &mut changes);
                    }
                }
                (Some(_), _) => key.last_seen = Some(now),
                (None, AnchorState::Valid) => set_state(key, AnchorState::Missing, &mut changes),
                (None, AnchorState::AddPend | AnchorState::Start) => {
                    // Not seen again: back to the start, which forgets it.
                    set_state(key, AnchorState::Removed, &mut changes);
                }
                (None, _) => {}
            }
            if key.state == AnchorState::Revoked
                && now.saturating_since(key.state_since) >= hold_down
            {
                set_state(key, AnchorState::Removed, &mut changes);
            }
        }
        // New keys with the secure entry point bit.
        for candidate in &keys {
            if candidate.revoked() || !candidate.sep() {
                continue;
            }
            if anchor
                .keys
                .iter()
                .any(|key| names(key, &zone, candidate.data))
            {
                continue;
            }
            if anchor.keys.len() >= tenko_core::dns::recursion::ANCHOR_KEYS_MAX {
                break;
            }
            anchor.keys.push(AnchorKey {
                key_tag: candidate.key_tag,
                algorithm: candidate.algorithm,
                digest_type: None,
                data: AnchorData::Dnskey {
                    rdata: tenko_core::serde_util::HexBytes(candidate.data.to_vec()),
                },
                state: AnchorState::AddPend,
                source: AnchorSource::Rfc5011,
                added_at: now,
                state_since: now,
                last_seen: Some(now),
            });
            changes.push((candidate.key_tag, AnchorState::AddPend));
        }
        // Removed keys are forgotten after another hold-down.
        let before = anchor.keys.len();
        anchor.keys.retain(|key| {
            key.state != AnchorState::Removed || now.saturating_since(key.state_since) < hold_down
        });
        if anchor.keys.len() != before {
            changes.push((0, AnchorState::Removed));
        }
        changes
    }

    /// The RFC 5011 refresh of the rows whose time has come.
    async fn refresh(&self, epoch: Option<u64>, now: Timestamp) -> Result<(usize, usize), String> {
        let Some(resolver) = self.wiring.resolver() else {
            return Ok((0, 0));
        };
        let hold_down = self.wiring.hold_down();
        let view = self
            .store
            .read(ReadConsistency::Local)
            .await
            .map_err(|error| error.to_string())?;
        let rows: Vec<(DnsName, TrustAnchor, _)> = view
            .scan_typed(&TRUST_ANCHORS, KeyRange::all(), usize::MAX, false)
            .map_err(|error| error.to_string())?;
        let (mut asked, mut written) = (0, 0);
        for (zone, mut anchor, revision) in rows {
            if anchor.next_query.is_some_and(|next| now < next) {
                continue;
            }
            asked += 1;
            anchor.last_query = Some(now);
            let outcome = resolver.dnskeys(&zone).await;
            let mut changes = Vec::new();
            match &outcome {
                Ok(set) if set.state == SecurityState::Secure => {
                    changes = Self::apply(&mut anchor, set, now, hold_down);
                    let interval = refresh_interval(now, set.signature_expiry, set.ttl, hold_down);
                    anchor.next_query = now.checked_add(interval);
                }
                Ok(set) => {
                    tracing::warn!(zone = %zone, state = %set.state, "the DNSKEY set did not validate with the current anchors");
                    anchor.next_query = now.checked_add(retry_interval(hold_down));
                }
                Err(error) => {
                    tracing::warn!(zone = %zone, %error, "the DNSKEY set could not be had");
                    anchor.next_query = now.checked_add(retry_interval(hold_down));
                }
            }
            let cx = ctx(now);
            let mut batch = WriteBatch::for_request(&cx);
            batch.expect_typed(&TRUST_ANCHORS, &zone, Some(revision));
            batch
                .put_typed(&TRUST_ANCHORS, &zone, &anchor)
                .map_err(|error| error.to_string())?;
            for (key_tag, state) in &changes {
                batch.audit(
                    AuditDraft::success(audit::TRUST_ANCHOR_STATE, target())
                        .with_context("zone", zone.to_string())
                        .with_context("key_tag", key_tag.to_string())
                        .with_context("state", state.as_str()),
                );
                tracing::info!(zone = %zone, key_tag, state = state.as_str(), "a trust anchor key changed its state");
            }
            self.propose(batch, epoch).await?;
            written += 1;
            if anchor.trusted().next().is_none() {
                tracing::error!(zone = %zone, "every trust anchor key of the zone is revoked or pending: the zone cannot be validated (dns.trust_anchor.stale)");
            }
        }
        Ok((asked, written))
    }

    /// One pass: the root row, the expiries, the refreshes.
    ///
    /// # Errors
    ///
    /// A store error as text.
    pub async fn pass(&self, epoch: Option<u64>) -> Result<PassReport, String> {
        let now = Timestamp::now();
        let mut report = PassReport::default();
        report.written += self.ensure_root(epoch, now).await?;
        report.expired = self.expire_ntas(epoch, now).await?;
        let (asked, written) = self.refresh(epoch, now).await?;
        report.asked = asked;
        report.written += written;
        *self.last.lock().unwrap_or_else(PoisonError::into_inner) = report;
        Ok(report)
    }

    /// The service as the supervisor runs it.
    pub fn leader_service(self: &Arc<Self>) -> Arc<dyn LeaderService> {
        Arc::new(Service(Arc::clone(self)))
    }
}

struct Service(Arc<AnchorService>);

#[async_trait::async_trait]
impl LeaderService for Service {
    fn name(&self) -> &'static str {
        SERVICE
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        loop {
            // A Lab hold-down of seconds brings the pace with it.
            let hold_down = self.0.wiring.hold_down();
            let pause = if hold_down < HOLD_DOWN {
                (hold_down / 4)
                    .max(Duration::from_secs(1))
                    .min(self.0.config.tick)
            } else {
                self.0.config.tick
            };
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                () = tokio::time::sleep(pause) => {}
            }
            self.0.pass(Some(epoch)).await?;
        }
    }
}

/// The shipped anchors' key tags, for the tests and the status.
pub fn shipped_tags() -> Vec<u16> {
    shipped::ROOT_ANCHORS
        .iter()
        .map(|anchor| anchor.key_tag)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(keys: Vec<Vec<u8>>, state: SecurityState) -> DnskeySet {
        DnskeySet {
            keys,
            state,
            ttl: 3600,
            original_ttl: 3600,
            signature_expiry: None,
        }
    }

    fn dnskey(flags: u16, seed: u8) -> Vec<u8> {
        let mut out = flags.to_be_bytes().to_vec();
        out.extend_from_slice(&[3, 15]);
        out.extend_from_slice(&[seed; 32]);
        out
    }

    fn row(data: &[u8], state: AnchorState, now: Timestamp) -> TrustAnchor {
        TrustAnchor {
            zone: DnsName::root(),
            keys: vec![AnchorKey {
                key_tag: crypto::key_tag(data),
                algorithm: 15,
                digest_type: None,
                data: AnchorData::Dnskey {
                    rdata: tenko_core::serde_util::HexBytes(data.to_vec()),
                },
                state,
                source: AnchorSource::Operator,
                added_at: now,
                state_since: now,
                last_seen: None,
            }],
            last_query: None,
            next_query: None,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines, reason = "one key's life, state by state")]
    fn the_state_machine_follows_rfc5011() {
        let now = Timestamp::now();
        let hold = Duration::from_secs(60);
        let old = dnskey(257, 1);
        let new = dnskey(257, 2);
        let zsk = dnskey(256, 3);
        // A new SEP key enters AddPend; a ZSK never does.
        let mut anchor = row(&old, AnchorState::Valid, now);
        let changes = AnchorService::apply(
            &mut anchor,
            &set(
                vec![old.clone(), new.clone(), zsk.clone()],
                SecurityState::Secure,
            ),
            now,
            hold,
        );
        assert_eq!(changes, vec![(crypto::key_tag(&new), AnchorState::AddPend)]);
        assert_eq!(anchor.keys.len(), 2);
        assert_eq!(anchor.keys[1].source, AnchorSource::Rfc5011);
        // Before the hold-down it stays; after it, Valid.
        let soon = now.checked_add(Duration::from_secs(30)).expect("time");
        assert_eq!(
            AnchorService::apply(
                &mut anchor,
                &set(vec![old.clone(), new.clone()], SecurityState::Secure),
                soon,
                hold
            ),
            vec![]
        );
        let later = now.checked_add(Duration::from_secs(61)).expect("time");
        let changes = AnchorService::apply(
            &mut anchor,
            &set(vec![old.clone(), new.clone()], SecurityState::Secure),
            later,
            hold,
        );
        assert_eq!(changes, vec![(crypto::key_tag(&new), AnchorState::Valid)]);
        // The old key revoked: Revoked at once, Removed after the hold-down, then gone.
        let mut revoked = old.clone();
        revoked[1] |= 0x80;
        let changes = AnchorService::apply(
            &mut anchor,
            &set(vec![revoked.clone(), new.clone()], SecurityState::Secure),
            later,
            hold,
        );
        assert_eq!(changes, vec![(crypto::key_tag(&old), AnchorState::Revoked)]);
        assert!(
            anchor
                .trusted()
                .any(|key| key.key_tag == crypto::key_tag(&new))
        );
        assert!(
            !anchor
                .trusted()
                .any(|key| key.key_tag == crypto::key_tag(&old))
        );
        let much_later = later.checked_add(Duration::from_secs(61)).expect("time");
        let changes = AnchorService::apply(
            &mut anchor,
            &set(vec![new.clone()], SecurityState::Secure),
            much_later,
            hold,
        );
        assert_eq!(changes, vec![(crypto::key_tag(&old), AnchorState::Removed)]);
        let gone = much_later
            .checked_add(Duration::from_secs(61))
            .expect("time");
        let changes = AnchorService::apply(
            &mut anchor,
            &set(vec![new.clone()], SecurityState::Secure),
            gone,
            hold,
        );
        assert_eq!(changes, vec![(0, AnchorState::Removed)]);
        assert_eq!(anchor.keys.len(), 1);
        // A Valid key that disappears is Missing and still trusted; back, Valid again.
        let changes = AnchorService::apply(
            &mut anchor,
            &set(vec![zsk.clone()], SecurityState::Secure),
            gone,
            hold,
        );
        assert_eq!(changes, vec![(crypto::key_tag(&new), AnchorState::Missing)]);
        assert!(anchor.trusted().next().is_some());
        let changes = AnchorService::apply(
            &mut anchor,
            &set(vec![new.clone()], SecurityState::Secure),
            gone,
            hold,
        );
        assert_eq!(changes, vec![(crypto::key_tag(&new), AnchorState::Valid)]);
        // An AddPend key that vanishes is forgotten.
        let other = dnskey(257, 4);
        AnchorService::apply(
            &mut anchor,
            &set(vec![new.clone(), other.clone()], SecurityState::Secure),
            gone,
            hold,
        );
        let changes = AnchorService::apply(
            &mut anchor,
            &set(vec![new.clone()], SecurityState::Secure),
            gone,
            hold,
        );
        assert_eq!(
            changes,
            vec![(crypto::key_tag(&other), AnchorState::Removed)]
        );
    }

    #[test]
    fn the_refresh_interval_is_half_the_validity_within_bounds() {
        let now = Timestamp::now();
        let expiry = now
            .checked_add(Duration::from_secs(10 * 86_400))
            .expect("time");
        assert_eq!(
            refresh_interval(now, Some(expiry), 86_400 * 20, HOLD_DOWN),
            Duration::from_secs(5 * 86_400)
        );
        assert_eq!(
            refresh_interval(now, Some(expiry), 60, HOLD_DOWN),
            REFRESH_MIN
        );
        let far = now
            .checked_add(Duration::from_secs(365 * 86_400))
            .expect("time");
        assert_eq!(
            refresh_interval(now, Some(far), 86_400 * 365, HOLD_DOWN),
            REFRESH_MAX
        );
        assert_eq!(
            refresh_interval(now, None, 172_800, HOLD_DOWN),
            Duration::from_secs(86_400)
        );
        // The Lab hold-down scales the pace with it.
        let lab = Duration::from_secs(20);
        assert_eq!(
            refresh_interval(now, Some(expiry), 86_400, lab),
            Duration::from_secs(10)
        );
        assert_eq!(retry_interval(lab), Duration::from_secs(10));
        assert_eq!(retry_interval(HOLD_DOWN), RETRY);
        assert!(shipped_tags().contains(&20326));
    }
}
