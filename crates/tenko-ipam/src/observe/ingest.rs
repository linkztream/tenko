//! Ingest: one batch of observations of one source becomes changes to that source's facts,
//! written as one batch (`system:reconciler`, audit action `ipam.observation.ingest`).
//!
//! # Rules
//!
//! - A subject seen for the first time is a new fact with one sighting.
//! - A known fact is written again only when its attributes changed, when it had expired,
//!   or when a refresh is due: the source's time passed the last sighting by the refresh
//!   interval, or the stored lifetime has less than half of a fresh one left (so a fact
//!   never lapses between two polls). Otherwise the report counts it as unchanged and
//!   nothing is written, which keeps a quiet network from rewriting its facts on every
//!   poll (R9).
//! - A sighting is counted at most once per refresh interval.
//! - A complete batch expires the facts of its source that it no longer reports: their
//!   `expires_at` becomes the receive time. Facts are never deleted here; retention
//!   purges them later ([`super::retention`]).
//! - Two observations of one subject in one batch: the later one (by source time, then by
//!   position) wins.
//! - Every fact write expects the revision it read; a concurrent writer makes the ingest
//!   read again and retry.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use tenko_core::{
    ObjectRef, Principal, SystemComponent, Timestamp,
    audit::{AuditAction, AuditDraft},
    codec::encode_key,
    observe::Observation,
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadView, ReadViewExt, Store, StoreError, WriteBatch,
};

use super::{
    ObserveConfig,
    model::{
        FactSubject, IngestBatch, IngestReport, ObservedFact, observed_ips, observed_macs,
        observed_name, source_connector, source_key,
    },
    tables::{BY_IP, BY_MAC, BY_NAME, FACTS},
};
use crate::error::{IpamError, IpamResult};

/// Audit action of an ingest that wrote something.
pub const INGEST_ACTION: &str = "ipam.observation.ingest";

/// Facts read per scan page.
const SCAN_PAGE: usize = 10_000;

/// Writes the facts of `batch` (see the module documentation) and reports what changed.
///
/// # Errors
///
/// Store errors, or `ipam.contended` when concurrent writers kept invalidating the batch.
pub async fn ingest(
    store: &Arc<dyn Store>,
    batch: &IngestBatch,
    config: &ObserveConfig,
) -> IpamResult<IngestReport> {
    let latest = latest_per_subject(&batch.observations);
    for attempt in 0..config.max_attempts.max(1) {
        let consistency = if attempt == 0 {
            ReadConsistency::Local
        } else {
            ReadConsistency::Linearizable
        };
        let view = store.read(consistency).await?;
        let (write, mut report) = plan_ingest(view.as_ref(), batch, &latest, config)?;
        drop(view);
        let Some(write) = write else {
            return Ok(report);
        };
        match store.propose(write).await {
            Ok(committed) => {
                report.revision = Some(committed.revision);
                return Ok(report);
            }
            Err(StoreError::PreconditionFailed(_)) => {
                tracing::debug!(attempt, "observation ingest stale; reading again");
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(IpamError::contended(config.max_attempts.max(1)))
}

/// The observation per (source key, subject key) that wins inside one batch.
fn latest_per_subject(observations: &[Observation]) -> BTreeMap<(String, String), &Observation> {
    let mut latest: BTreeMap<(String, String), &Observation> = BTreeMap::new();
    for observation in observations {
        let key = (
            source_key(&observation.source),
            FactSubject::of(&observation.subject).key(),
        );
        match latest.get(&key) {
            Some(existing) if existing.observed_at > observation.observed_at => {}
            _ => {
                latest.insert(key, observation);
            }
        }
    }
    latest
}

/// Every fact of one source.
fn facts_of(view: &dyn ReadView, source: &str) -> IpamResult<BTreeMap<String, ObservedFact>> {
    let prefix = encode_key(&(source.to_owned(),));
    let mut range = KeyRange::prefix(prefix.clone());
    let mut out = BTreeMap::new();
    loop {
        let rows = view.scan_typed(&FACTS, range.clone(), SCAN_PAGE, false)?;
        let full = rows.len() == SCAN_PAGE;
        let mut last = None;
        for ((_, subject), mut fact, revision) in rows {
            fact.revision = revision;
            last = Some(FACTS.key(&(source.to_owned(), subject.clone())));
            out.insert(subject, fact);
        }
        match (full, last) {
            (true, Some(last)) => range = KeyRange::prefix(prefix.clone()).after(last),
            _ => return Ok(out),
        }
    }
}

/// Whether a stored fact is due for a refresh write by a report at `observed_at` that
/// would live until `expires_at`. The lease facts of [`super::dhcp`] follow the same rule.
pub(crate) fn refresh_due(
    fact: &ObservedFact,
    observed_at: Timestamp,
    received_at: Timestamp,
    expires_at: Option<Timestamp>,
    refresh: Duration,
) -> bool {
    if observed_at.saturating_since(fact.last_seen) >= refresh {
        return true;
    }
    match (fact.expires_at, expires_at) {
        (Some(stored), Some(fresh)) => {
            let left = stored.saturating_since(received_at);
            let full = fresh.saturating_since(received_at);
            left < full / 2
        }
        (Some(_), None) => true,
        (None, _) => false,
    }
}

/// Index rows a fact needs.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct IndexRows {
    macs: BTreeSet<tenko_core::MacAddr>,
    ips: BTreeSet<std::net::IpAddr>,
    names: BTreeSet<String>,
}

impl IndexRows {
    pub(crate) fn of(observed: &tenko_core::observe::Observed) -> Self {
        Self {
            macs: observed_macs(observed).into_iter().collect(),
            ips: observed_ips(observed).into_iter().collect(),
            names: observed_name(observed)
                .map(|name| BTreeSet::from([name.to_ascii_lowercase()]))
                .unwrap_or_default(),
        }
    }

    /// Puts the rows of `self` missing from `before` and deletes the rows of `before`
    /// missing from `self`.
    pub(crate) fn write(
        &self,
        before: &IndexRows,
        source: &str,
        subject: &str,
        batch: &mut WriteBatch,
    ) -> IpamResult<()> {
        let key = |s: &str| (s.to_owned(), subject.to_owned());
        for mac in self.macs.difference(&before.macs) {
            let (a, b) = key(source);
            batch.put_typed(&BY_MAC, &(*mac, a, b), &())?;
        }
        for mac in before.macs.difference(&self.macs) {
            let (a, b) = key(source);
            batch.delete_typed(&BY_MAC, &(*mac, a, b));
        }
        for ip in self.ips.difference(&before.ips) {
            let (a, b) = key(source);
            batch.put_typed(&BY_IP, &(*ip, a, b), &())?;
        }
        for ip in before.ips.difference(&self.ips) {
            let (a, b) = key(source);
            batch.delete_typed(&BY_IP, &(*ip, a, b));
        }
        for name in self.names.difference(&before.names) {
            let (a, b) = key(source);
            batch.put_typed(&BY_NAME, &(name.clone(), a, b), &())?;
        }
        for name in before.names.difference(&self.names) {
            let (a, b) = key(source);
            batch.delete_typed(&BY_NAME, &(name.clone(), a, b));
        }
        Ok(())
    }
}

/// Deletes a fact and its index rows (retention).
pub(crate) fn delete_fact(fact: &ObservedFact, batch: &mut WriteBatch) {
    let rows = IndexRows::of(&fact.observed);
    let key = (fact.source_key.clone(), fact.subject_key.clone());
    for mac in &rows.macs {
        batch.delete_typed(&BY_MAC, &(*mac, key.0.clone(), key.1.clone()));
    }
    for ip in &rows.ips {
        batch.delete_typed(&BY_IP, &(*ip, key.0.clone(), key.1.clone()));
    }
    for name in &rows.names {
        batch.delete_typed(&BY_NAME, &(name.clone(), key.0.clone(), key.1.clone()));
    }
    batch.delete_typed(&FACTS, &key);
    batch.expect_typed(&FACTS, &key, Some(fact.revision));
}

/// The write of one ingest against `view`, or `None` when nothing changes.
#[allow(clippy::too_many_lines)] // One pass: new, changed, refreshed and gone facts.
fn plan_ingest(
    view: &dyn ReadView,
    batch: &IngestBatch,
    latest: &BTreeMap<(String, String), &Observation>,
    config: &ObserveConfig,
) -> IpamResult<(Option<WriteBatch>, IngestReport)> {
    let mut report = IngestReport::default();
    let mut write = WriteBatch::new(
        Principal::system(SystemComponent::Reconciler),
        batch.received_at,
    );
    let batch_source = source_key(&batch.source);
    let mut sources: BTreeSet<String> = latest.keys().map(|(source, _)| source.clone()).collect();
    if batch.complete {
        sources.insert(batch_source.clone());
    }
    let mut existing: BTreeMap<String, BTreeMap<String, ObservedFact>> = BTreeMap::new();
    for source in &sources {
        existing.insert(source.clone(), facts_of(view, source)?);
    }
    let received = batch.received_at;
    for ((source, subject_key), observation) in latest {
        if let FactSubject::Host { external_id } = FactSubject::of(&observation.subject)
            && external_id.trim().is_empty()
        {
            report.skipped += 1;
            continue;
        }
        let key = (source.clone(), subject_key.clone());
        let stored = existing
            .get(source)
            .and_then(|facts| facts.get(subject_key));
        let rows = IndexRows::of(&observation.subject);
        match stored {
            None => {
                let fact = ObservedFact {
                    source: observation.source.clone(),
                    source_key: source.clone(),
                    subject: FactSubject::of(&observation.subject),
                    subject_key: subject_key.clone(),
                    observed: observation.subject.clone(),
                    observation: observation.id,
                    first_seen: observation.observed_at,
                    last_seen: observation.observed_at,
                    received_at: received,
                    expires_at: observation.expires_at,
                    sightings: 1,
                    counted_at: Some(observation.observed_at),
                    revision: tenko_core::Revision::ZERO,
                };
                write.put_typed(&FACTS, &key, &fact)?;
                write.expect_typed(&FACTS, &key, None);
                rows.write(&IndexRows::default(), source, subject_key, &mut write)?;
                report.new += 1;
            }
            Some(old) => {
                let changed = old.observed != observation.subject;
                let revived = !old.is_current(received);
                let due = refresh_due(
                    old,
                    observation.observed_at,
                    received,
                    observation.expires_at,
                    config.refresh,
                );
                if !(changed || revived || due) {
                    report.unchanged += 1;
                    continue;
                }
                let counted_since = old.counted_at.unwrap_or(old.first_seen);
                let counts = revived
                    || observation.observed_at.saturating_since(counted_since) >= config.refresh;
                let mut fact = old.clone();
                fact.source = observation.source.clone();
                fact.observed = observation.subject.clone();
                if changed {
                    fact.observation = observation.id;
                }
                fact.first_seen = fact.first_seen.min(observation.observed_at);
                fact.last_seen = fact.last_seen.max(observation.observed_at);
                fact.received_at = received;
                fact.expires_at = observation.expires_at;
                if counts {
                    fact.sightings = fact.sightings.saturating_add(1);
                    fact.counted_at = Some(observation.observed_at);
                }
                fact.revision = tenko_core::Revision::ZERO;
                write.put_typed(&FACTS, &key, &fact)?;
                write.expect_typed(&FACTS, &key, Some(old.revision));
                rows.write(
                    &IndexRows::of(&old.observed),
                    source,
                    subject_key,
                    &mut write,
                )?;
                if changed {
                    report.changed += 1;
                } else {
                    report.refreshed += 1;
                }
            }
        }
    }
    if batch.complete
        && let Some(facts) = existing.get(&batch_source)
    {
        for (subject_key, old) in facts {
            if latest.contains_key(&(batch_source.clone(), subject_key.clone()))
                || !old.is_current(received)
            {
                continue;
            }
            let key = (batch_source.clone(), subject_key.clone());
            let mut fact = old.clone();
            fact.expires_at = Some(received);
            fact.received_at = received;
            fact.revision = tenko_core::Revision::ZERO;
            write.put_typed(&FACTS, &key, &fact)?;
            write.expect_typed(&FACTS, &key, Some(old.revision));
            report.gone += 1;
        }
    }
    if write.mutations.is_empty() {
        return Ok((None, report));
    }
    let objects: Vec<ObjectRef> = source_connector(&batch.source)
        .map(ObjectRef::from)
        .into_iter()
        .collect();
    write.audit(
        AuditDraft::success(AuditAction::from_static(INGEST_ACTION), objects)
            .with_context("source", batch_source)
            .with_context("new", report.new.to_string())
            .with_context("changed", report.changed.to_string())
            .with_context("refreshed", report.refreshed.to_string())
            .with_context("gone", report.gone.to_string()),
    );
    Ok((Some(write), report))
}

#[cfg(test)]
mod tests {
    use tenko_core::{
        ConnectorId, MacAddr, ObservationId,
        observe::{ObservationSource, Observed, ObservedHost},
    };
    use tenko_store::MemStore;

    use super::*;

    fn time(text: &str) -> Timestamp {
        text.parse().expect("time")
    }

    fn host(connector: ConnectorId, id: &str, ip: &str, at: &str) -> Observation {
        let at = time(at);
        Observation {
            id: ObservationId::generate(),
            source: ObservationSource::Inventory { connector },
            subject: Observed::Host(ObservedHost {
                external_id: id.to_owned(),
                name: Some(format!("vm-{id}")),
                macs: vec!["00:00:5e:00:53:01".parse::<MacAddr>().expect("mac")],
                ips: vec![ip.parse().expect("ip")],
                ..ObservedHost::default()
            }),
            observed_at: at,
            received_at: at,
            expires_at: at.checked_add(Duration::from_secs(900)),
        }
    }

    fn batch(connector: ConnectorId, observations: Vec<Observation>, at: &str) -> IngestBatch {
        IngestBatch {
            source: ObservationSource::Inventory { connector },
            observations,
            complete: true,
            received_at: time(at),
        }
    }

    #[tokio::test]
    async fn repeated_polls_write_only_changes_and_refreshes() {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let config = ObserveConfig::default();
        let connector = ConnectorId::generate();
        let first = ingest(
            &store,
            &batch(
                connector,
                vec![host(connector, "101", "192.0.2.10", "2026-10-10T08:00:00Z")],
                "2026-10-10T08:00:00Z",
            ),
            &config,
        )
        .await
        .expect("first");
        assert_eq!((first.new, first.unchanged), (1, 0));
        assert!(first.wrote());

        // One minute later, nothing changed: no write.
        let again = ingest(
            &store,
            &batch(
                connector,
                vec![host(connector, "101", "192.0.2.10", "2026-10-10T08:01:00Z")],
                "2026-10-10T08:01:00Z",
            ),
            &config,
        )
        .await
        .expect("again");
        assert_eq!((again.new, again.unchanged), (0, 1));
        assert!(!again.wrote());

        // A changed address is written at once.
        let changed = ingest(
            &store,
            &batch(
                connector,
                vec![host(connector, "101", "192.0.2.11", "2026-10-10T08:02:00Z")],
                "2026-10-10T08:02:00Z",
            ),
            &config,
        )
        .await
        .expect("changed");
        assert_eq!(changed.changed, 1);
        let view = store.read(ReadConsistency::Local).await.expect("view");
        assert!(
            view.get_typed(
                &BY_IP,
                &(
                    "192.0.2.10".parse().expect("ip"),
                    format!("inventory:{connector}"),
                    "host:101".to_owned()
                )
            )
            .expect("read")
            .is_none(),
            "the old address leaves the index"
        );

        // The complete batch without the host expires it.
        let gone = ingest(
            &store,
            &batch(connector, vec![], "2026-10-10T08:03:00Z"),
            &config,
        )
        .await
        .expect("gone");
        assert_eq!(gone.gone, 1);
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let (fact, _) = view
            .get_typed(
                &FACTS,
                &(format!("inventory:{connector}"), "host:101".to_owned()),
            )
            .expect("read")
            .expect("fact");
        assert!(!fact.is_current(time("2026-10-10T08:03:00Z")));
        assert_eq!(fact.sightings, 1);
    }
}
