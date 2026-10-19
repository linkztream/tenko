//! The zone service (WP4.2, plan sections 2.4 and 2.5, ADR 0017): zones, RRsets, access
//! lists and TSIG keys in the replicated store.
//!
//! The engine reads what this service writes and never writes itself. Every write is
//! planned against a read view, checked with the rules of the model and committed as one
//! batch with its audit record; a batch expects the versions it read, so a concurrent
//! change makes it stale and the service plans again ([`ZoneConfig::max_attempts`]).
//!
//! | Module | What |
//! |---|---|
//! | this module | [`ZoneService`]: zones (create, read, change, delete) and RRset reads |
//! | [`records`] | batch changes of RRsets with a dry run and a diff |
//! | [`serial`] | SOA serials per policy |
//! | [`journal`] | the IXFR journal of each zone scope, bounded by entries and days |
//! | [`zonefile`] | the zone file reader (`$ORIGIN`, `$TTL`, `$GENERATE`; `$INCLUDE` refused) and writer |
//! | [`export`] | the zone file export (MIG-15) |
//! | [`import`] | the zone file import: preview, then a background job in chunks |
//! | [`acl`] | access lists |
//! | [`keys`] | TSIG keys, the secret in the vault |
//! | [`jobs`] | the inline job of every change and the job runner stand-in |
//! | [`views`] | views, their positions and the scope rule (WP6.4) |
//! | [`secondary`] | secondary and catalog zones: transfers in as a leader service (WP6.1) |
//! | [`signing`] | the signing state, the writes of a signing pass, the rollover's start (WP6.3) |
//!
//! # Zones
//!
//! A primary or RPZ zone holds data: on creation each scope gets the apex SOA (from
//! [`SoaDefaults`] and the first serial of the policy) and the NS set of the name servers
//! given. A secondary zone is created empty and filled by zone transfers ([`secondary`]),
//! whose RRsets carry the origin `transfer` and are read-only to every other writer
//! (`dns.zone.secondary`); a stub or forward zone is a row only. A change of the SOA values rewrites the SOA of every scope with the next
//! serial; a new scope gets an SOA and a copy of the default scope's NS set; a removed
//! scope loses its RRsets and journal. Deleting a zone removes its RRsets and journal in
//! the same batch when they fit in one; a larger zone loses its row first (the engine stops
//! serving it) and the rest is purged in batches right after.
//!
//! The RRsets per origin of a zone are counted with store counters (added and removed per
//! zone and origin), so a zone list needs no scan of the records.

pub mod acl;
mod error;
pub mod export;
pub mod import;
pub mod jobs;
pub mod journal;
pub mod keys;
pub mod records;
// WP6.1: the leader service of secondary and catalog zones, and the read-only rule.
pub mod secondary;
pub mod serial;
// WP6.4: views and the scope rule.
pub mod views;
// WP6.3: the signer's entry points and the writes of a signing pass.
pub mod signing;
pub mod zonefile;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use tenko_core::{
    CounterKey, ObjectRef, PrefixId, RequestCtx, Revision, TenantId,
    audit::{AuditDraft, FieldChange},
    codec::key::encode_key,
    dns::{
        DnsName, DnssecPolicy, JournalEntry, JournalRecord, Origin, Rdata, RecordData, RrSet,
        Rtype, ScopeName, SecondarySource, SerialPolicy, SoaDefaults, TransferPolicy, UpdatePolicy,
        Zone, ZoneId, ZoneKind, ZoneScope, audit, check_apex,
        tables::{RRSETS, ZONES},
    },
    ipam::Stamp,
};
use tenko_store::{KeyRange, ReadConsistency, ReadView, ReadViewExt, Store, WriteBatch};
use tenko_vault::Vault;

pub use error::{ZoneError, ZoneResult};
pub use import::ImportStaging;
pub use jobs::{DirectJobs, Written, ZoneJobs};
pub use journal::JournalLimits;

/// Limits of the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneConfig {
    /// Changes in one batch.
    pub max_changes: usize,
    /// The journal bounds per zone scope.
    pub journal: JournalLimits,
    /// RRsets per batch of an import.
    pub import_chunk: usize,
    /// Plans before a contended write gives up.
    pub max_attempts: u32,
    /// The largest zone file an import takes, in bytes.
    pub max_zone_file_bytes: usize,
    /// Records one `$GENERATE` line may produce.
    pub max_generate: u32,
}

impl Default for ZoneConfig {
    fn default() -> Self {
        Self {
            max_changes: 10_000,
            journal: JournalLimits::default(),
            import_chunk: 5_000,
            max_attempts: 16,
            max_zone_file_bytes: 1 << 30,
            max_generate: 65_536,
        }
    }
}

/// A new zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewZone {
    /// The apex.
    pub name: DnsName,
    /// What the zone is.
    pub kind: ZoneKind,
    /// The owning tenant.
    pub tenant: Option<TenantId>,
    /// Scopes besides `default`.
    pub scopes: Vec<ZoneScope>,
    /// How the serial moves.
    pub serial: SerialPolicy,
    /// The SOA values.
    pub soa: SoaDefaults,
    /// The apex NS set of a primary or RPZ zone.
    pub name_servers: Vec<DnsName>,
    /// Zone transfers and NOTIFY.
    pub transfer: TransferPolicy,
    /// Dynamic updates.
    pub update: UpdatePolicy,
    /// Signing.
    pub dnssec: DnssecPolicy,
    /// The servers of a secondary, stub or forward zone.
    pub source: Option<SecondarySource>,
    /// Free text.
    pub description: Option<String>,
    /// The IPAM prefix whose reverse zone this is (plan section 2.6); set by the DNS
    /// actuator of IPAM, never by the API.
    pub reverse_of: Option<PrefixId>,
    // WP6.1: catalog zones.
    /// A catalog zone (RFC 9432, [`Zone::catalog`]).
    pub catalog: bool,
}

/// Changes to a zone; the name and the kind do not change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZoneChange {
    /// The scopes, `default` included.
    pub scopes: Option<Vec<ZoneScope>>,
    /// How the serial moves.
    pub serial: Option<SerialPolicy>,
    /// The SOA values.
    pub soa: Option<SoaDefaults>,
    /// Zone transfers and NOTIFY.
    pub transfer: Option<TransferPolicy>,
    /// Dynamic updates.
    pub update: Option<UpdatePolicy>,
    /// Signing.
    pub dnssec: Option<DnssecPolicy>,
    /// The servers of a secondary, stub or forward zone.
    pub source: Option<SecondarySource>,
    /// Free text; an empty string clears it.
    pub description: Option<String>,
    /// The IPAM prefix whose reverse zone this is; `Some(None)` clears it (the DNS actuator
    /// of IPAM adopts a zone with it, never the API).
    pub reverse_of: Option<Option<PrefixId>>,
    // WP6.1: catalog zones.
    /// Whether the zone is a catalog zone (RFC 9432).
    pub catalog: Option<bool>,
}

/// What a zone list shows besides the row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSummary {
    /// The SOA serial of the default scope, 0 for a zone without data.
    pub soa_serial: u32,
    /// RRsets in all scopes.
    pub rrsets: u64,
    /// RRsets per origin present, sorted by origin.
    pub origins: Vec<(Origin, u64)>,
}

/// A zone as read, with the revision of its row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneRow {
    /// The zone.
    pub zone: Zone,
    /// The revision of the row.
    pub revision: Revision,
}

/// What a zone write reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneWritten {
    /// The zone after the write.
    pub zone: Zone,
    /// The revision of the write.
    pub revision: Revision,
    /// The inline job; none when nothing changed.
    pub job: Option<tenko_core::JobId>,
}

const ORIGINS: [Origin; 7] = [
    Origin::Manual,
    Origin::Ipam,
    Origin::Dynamic,
    Origin::Dhcp,
    Origin::Ad,
    Origin::Transfer,
    // WP6.3: the signer's rows.
    Origin::Dnssec,
];

fn origin_index(origin: Origin) -> u8 {
    match origin {
        Origin::Manual => 0,
        Origin::Ipam => 1,
        Origin::Dynamic => 2,
        Origin::Dhcp => 3,
        Origin::Ad => 4,
        Origin::Transfer => 5,
        // WP6.3: the signer's rows.
        Origin::Dnssec => 6,
    }
}

fn origin_added(zone: ZoneId, origin: Origin) -> CounterKey {
    CounterKey::with("dns.rrsets.added", &(zone, origin_index(origin)))
}

fn origin_removed(zone: ZoneId, origin: Origin) -> CounterKey {
    CounterKey::with("dns.rrsets.removed", &(zone, origin_index(origin)))
}

/// The counter every zone create and delete bumps, so that two creates of one name cannot
/// both commit.
fn zone_names() -> CounterKey {
    CounterKey::new("dns.zones.names")
}

/// Adds the write of `new` over `old` (or a new RRset) to `batch`, with its counters.
///
/// # Errors
///
/// A codec error.
pub(crate) fn stage_put(
    batch: &mut WriteBatch,
    old: Option<&RrSet>,
    new: &RrSet,
) -> ZoneResult<()> {
    batch.put_typed(&RRSETS, &new.key(), new)?;
    match old {
        Some(old) if old.origin == new.origin => {}
        Some(old) => {
            batch.bump(origin_removed(old.zone, old.origin));
            batch.bump(origin_added(new.zone, new.origin));
        }
        None => {
            batch.bump(origin_added(new.zone, new.origin));
        }
    }
    Ok(())
}

/// Adds the deletion of `old` to `batch`, with its counter.
pub(crate) fn stage_delete(batch: &mut WriteBatch, old: &RrSet) {
    batch.delete_typed(&RRSETS, &old.key());
    batch.bump(origin_removed(old.zone, old.origin));
}

/// The key range of a zone's RRsets, of one scope, or of one owner name in a scope.
pub(crate) fn rrset_range(
    zone: ZoneId,
    scope: Option<&ScopeName>,
    name: Option<&DnsName>,
) -> KeyRange {
    let prefix = match (scope, name) {
        (Some(scope), Some(name)) => encode_key(&(zone, scope.clone(), name.clone())),
        (Some(scope), None) => encode_key(&(zone, scope.clone())),
        _ => encode_key(&zone),
    };
    KeyRange::prefix(prefix)
}

/// The RRsets of one owner name in a scope, with their revisions.
///
/// # Errors
///
/// The store's error.
pub(crate) fn node(
    view: &dyn ReadView,
    zone: ZoneId,
    scope: &ScopeName,
    name: &DnsName,
) -> ZoneResult<Vec<(RrSet, Revision)>> {
    Ok(view
        .scan_typed(
            &RRSETS,
            rrset_range(zone, Some(scope), Some(name)),
            usize::MAX,
            false,
        )?
        .into_iter()
        .map(|(_, rrset, revision)| (rrset, revision))
        .collect())
}

/// The SOA record data of a zone scope's SOA RRset.
pub(crate) fn soa_data(rrset: &RrSet) -> Option<RecordData> {
    rrset
        .records()
        .ok()
        .and_then(|records| records.into_iter().next())
        .filter(|data| matches!(data, RecordData::Soa { .. }))
}

/// The serial of an SOA RRset.
pub(crate) fn soa_serial(rrset: &RrSet) -> Option<u32> {
    match soa_data(rrset) {
        Some(RecordData::Soa { serial, .. }) => Some(serial),
        _ => None,
    }
}

/// The SOA RRset of a scope from its values and a serial.
pub(crate) fn soa_rrset(
    zone: &Zone,
    scope: &ScopeName,
    soa: &SoaDefaults,
    serial: u32,
    stamp: Stamp,
) -> RrSet {
    RrSet {
        zone: zone.id,
        scope: scope.clone(),
        name: zone.name.clone(),
        rtype: Rtype::SOA,
        ttl: soa.ttl,
        rdata: vec![Rdata::from_data(&RecordData::Soa {
            mname: soa.mname.clone(),
            rname: soa.rname.clone(),
            serial,
            refresh: soa.refresh,
            retry: soa.retry,
            expire: soa.expire,
            minimum: soa.minimum,
        })],
        origin: Origin::Manual,
        key: None,
        updated: stamp,
    }
}

/// The records of an RRset as journal records.
pub(crate) fn journal_records(rrset: &RrSet) -> impl Iterator<Item = JournalRecord> + '_ {
    rrset.rdata.iter().map(|rdata| JournalRecord {
        name: rrset.name.clone(),
        rtype: rrset.rtype,
        ttl: rrset.ttl,
        rdata: rdata.clone(),
    })
}

/// Whether a zone of this kind holds RRsets.
pub fn holds_data(kind: ZoneKind) -> bool {
    matches!(kind, ZoneKind::Primary | ZoneKind::Rpz)
}

/// The zone service. Cheap to share as `Arc<ZoneService>`.
pub struct ZoneService {
    store: Arc<dyn Store>,
    jobs: Arc<dyn ZoneJobs>,
    vault: Option<Arc<dyn Vault>>,
    staging: Arc<ImportStaging>,
    config: ZoneConfig,
    direct: Option<Arc<DirectJobs>>,
}

impl std::fmt::Debug for ZoneService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneService")
            .field("config", &self.config)
            .field("vault", &self.vault.is_some())
            .finish_non_exhaustive()
    }
}

/// Registers the step handlers of the zone service with the job engine: `dns.write` and
/// the steps of an import, which read the zone files staged in `staging`.
pub fn register_steps(engine: &mut tenko_jobs::JobEngine, staging: &Arc<ImportStaging>) {
    for handler in step_handlers(staging) {
        engine.register(handler);
    }
}

/// The step handlers of the zone service.
pub fn step_handlers(staging: &Arc<ImportStaging>) -> Vec<Arc<dyn tenko_jobs::StepHandler>> {
    let mut handlers: Vec<Arc<dyn tenko_jobs::StepHandler>> = vec![Arc::new(jobs::WriteStep)];
    handlers.extend(import::step_handlers(staging));
    handlers
}

impl ZoneService {
    /// The service over `store`, writing through `jobs`; TSIG keys need the `vault`. The
    /// import steps registered with the engine must share `staging` ([`register_steps`]).
    pub fn new(
        store: Arc<dyn Store>,
        jobs: Arc<dyn ZoneJobs>,
        vault: Option<Arc<dyn Vault>>,
        staging: Arc<ImportStaging>,
        config: ZoneConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            jobs,
            vault,
            staging,
            config,
            direct: None,
        })
    }

    /// A service that runs its jobs in place ([`DirectJobs`]), for tests and tools.
    pub fn with_direct_jobs(
        store: Arc<dyn Store>,
        vault: Option<Arc<dyn Vault>>,
        config: ZoneConfig,
    ) -> Arc<Self> {
        let staging = Arc::new(ImportStaging::default());
        let mut direct = DirectJobs::new(Arc::clone(&store));
        for handler in step_handlers(&staging) {
            direct.register(handler);
        }
        let direct = Arc::new(direct);
        Arc::new(Self {
            store,
            jobs: Arc::clone(&direct) as Arc<dyn ZoneJobs>,
            vault,
            staging,
            config,
            direct: Some(direct),
        })
    }

    /// The store.
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    /// The limits.
    pub fn config(&self) -> ZoneConfig {
        self.config
    }

    /// The job runner.
    pub fn jobs(&self) -> &Arc<dyn ZoneJobs> {
        &self.jobs
    }

    /// The in-place job runner of a service made with [`ZoneService::with_direct_jobs`],
    /// which keeps the background jobs it ran.
    pub fn direct_jobs(&self) -> Option<&Arc<DirectJobs>> {
        self.direct.as_ref()
    }

    /// A read view, at least at `at_least` when given (read-your-writes).
    ///
    /// # Errors
    ///
    /// The store's error.
    pub async fn view(&self, at_least: Option<Revision>) -> ZoneResult<Arc<dyn ReadView>> {
        let consistency = match at_least {
            Some(revision) => ReadConsistency::AtLeast(revision),
            None => ReadConsistency::Local,
        };
        Ok(self.store.read(consistency).await?)
    }

    async fn fresh_view(&self, attempt: u32) -> ZoneResult<Arc<dyn ReadView>> {
        let consistency = if attempt == 0 {
            ReadConsistency::Local
        } else {
            ReadConsistency::Linearizable
        };
        Ok(self.store.read(consistency).await?)
    }

    /// Plans with `plan` against fresh views and commits its batch as an inline job,
    /// planning again after a stale write. `plan` returns the batch, a summary line, the
    /// targets and its own result, or `None` when there is nothing to write.
    pub(crate) async fn execute<T, F>(
        &self,
        cx: &RequestCtx,
        mut plan: F,
    ) -> ZoneResult<(T, Option<Written>)>
    where
        F: FnMut(&dyn ReadView) -> ZoneResult<Planned<T>>,
    {
        let mut last = None;
        for attempt in 0..self.config.max_attempts {
            let view = self.fresh_view(attempt).await?;
            let planned = plan(view.as_ref())?;
            drop(view);
            let Some(write) = planned.write else {
                return Ok((planned.result, None));
            };
            match jobs::commit(
                self.jobs.as_ref(),
                cx,
                write.summary,
                write.targets,
                write.batch,
            )
            .await
            {
                Ok(written) => return Ok((planned.result, Some(written))),
                Err(error) if error.is_stale() => {
                    tracing::debug!(attempt, "zone write stale; planning again");
                    last = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last.unwrap_or_else(|| {
            ZoneError::new(
                "sys.store.precondition_failed",
                409,
                "the zone changed meanwhile",
            )
        }))
    }

    // ----- reads ------------------------------------------------------------------------

    /// A zone.
    ///
    /// # Errors
    ///
    /// `dns.zone.not_found`, or the store's error.
    pub fn zone(view: &dyn ReadView, id: ZoneId) -> ZoneResult<ZoneRow> {
        view.get_typed(&ZONES, &id)?
            .map(|(zone, revision)| ZoneRow { zone, revision })
            .ok_or_else(|| ZoneError::zone_not_found(id))
    }

    /// Every zone, by name.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn zones(view: &dyn ReadView) -> ZoneResult<Vec<ZoneRow>> {
        let mut zones: Vec<ZoneRow> = view
            .scan_typed(&ZONES, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, zone, revision)| ZoneRow { zone, revision })
            .collect();
        zones.sort_by(|a, b| {
            a.zone
                .name
                .as_str()
                .cmp(b.zone.name.as_str())
                .then(a.zone.id.cmp(&b.zone.id))
        });
        Ok(zones)
    }

    /// The zone whose apex is `name`.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn zone_by_name(view: &dyn ReadView, name: &DnsName) -> ZoneResult<Option<ZoneRow>> {
        Ok(Self::zones(view)?
            .into_iter()
            .find(|row| &row.zone.name == name))
    }

    /// The serial and the RRset counts of a zone.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn summary(view: &dyn ReadView, zone: &Zone) -> ZoneResult<ZoneSummary> {
        let mut origins = Vec::new();
        let mut rrsets = 0u64;
        for origin in ORIGINS {
            let added = view.counter(&origin_added(zone.id, origin))?;
            let removed = view.counter(&origin_removed(zone.id, origin))?;
            let count = added.saturating_sub(removed);
            if count > 0 {
                origins.push((origin, count));
                rrsets += count;
            }
        }
        let soa_serial = view
            .get_typed(
                &RRSETS,
                &tenko_core::dns::RrSetKey {
                    zone: zone.id,
                    scope: ScopeName::DEFAULT,
                    name: zone.name.clone(),
                    rtype: Rtype::SOA,
                },
            )?
            .and_then(|(rrset, _)| soa_serial(&rrset))
            .unwrap_or_default();
        Ok(ZoneSummary {
            soa_serial,
            rrsets,
            origins,
        })
    }

    /// The serial of a scope's SOA, if the scope has one.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn scope_serial(
        view: &dyn ReadView,
        zone: &Zone,
        scope: &ScopeName,
    ) -> ZoneResult<Option<u32>> {
        Ok(view
            .get_typed(
                &RRSETS,
                &tenko_core::dns::RrSetKey {
                    zone: zone.id,
                    scope: scope.clone(),
                    name: zone.name.clone(),
                    rtype: Rtype::SOA,
                },
            )?
            .and_then(|(rrset, _)| soa_serial(&rrset)))
    }

    // ----- zone writes ------------------------------------------------------------------

    /// Creates a zone; a primary or RPZ zone gets the apex SOA and NS set in every scope.
    ///
    /// # Errors
    ///
    /// `dns.zone.invalid`, `dns.zone.exists`, `dns.record.invalid` for a bad name server,
    /// or a store or job error.
    #[allow(clippy::too_many_lines, reason = "one plan of a new zone")]
    pub async fn create(&self, cx: &RequestCtx, new: NewZone) -> ZoneResult<ZoneWritten> {
        let id = ZoneId::generate();
        let stamp = Stamp::new(cx.now, cx.principal.clone());
        let mut scopes = vec![ZoneScope::default_scope()];
        scopes.extend(new.scopes.iter().cloned());
        let zone = Zone {
            id,
            name: new.name.clone(),
            kind: new.kind,
            tenant: new.tenant,
            scopes,
            serial: new.serial,
            soa: new.soa.clone(),
            transfer: new.transfer.clone(),
            update: new.update.clone(),
            dnssec: new.dnssec.clone(),
            source: new.source.clone(),
            reverse_of: new.reverse_of,
            catalog: new.catalog,
            description: clean_description(new.description.clone()),
            created: stamp.clone(),
            updated: stamp.clone(),
        };
        zone.validate()?;
        let apex_sets = if holds_data(zone.kind) {
            if new.name_servers.is_empty() {
                return Err(ZoneError::zone_invalid(
                    "name_servers",
                    "a primary or RPZ zone needs at least one name server",
                ));
            }
            let mut sets = Vec::new();
            for scope in &zone.scopes {
                let soa = soa_rrset(
                    &zone,
                    &scope.name,
                    &zone.soa,
                    serial::first(zone.serial, cx.now),
                    stamp.clone(),
                );
                let ns = ns_rrset(
                    &zone,
                    &scope.name,
                    &new.name_servers,
                    zone.soa.ttl,
                    stamp.clone(),
                )?;
                soa.check(&zone.name)?;
                ns.check(&zone.name)?;
                check_apex(&zone.name, [&soa, &ns])?;
                sets.push(soa);
                sets.push(ns);
            }
            sets
        } else {
            if !new.name_servers.is_empty() {
                return Err(ZoneError::zone_invalid(
                    "name_servers",
                    "only a primary or RPZ zone has an NS set of its own",
                ));
            }
            Vec::new()
        };
        let ((), written) = self
            .execute(cx, |view| {
                if Self::zone_by_name(view, &zone.name)?.is_some() {
                    return Err(ZoneError::new(
                        tenko_core::dns::codes::ZONE_EXISTS,
                        409,
                        format!("a zone {} exists", zone.name),
                    )
                    .param("name", zone.name.as_str()));
                }
                secondary::check_catalog_unique(view, &zone)?;
                let mut batch = WriteBatch::for_request(cx);
                stage_acl_refs(&mut batch, view, &zone)?;
                batch.expect_counter(zone_names(), view.counter(&zone_names())?);
                batch.bump(zone_names());
                batch.expect_typed(&ZONES, &zone.id, None);
                batch.put_typed(&ZONES, &zone.id, &zone)?;
                for rrset in &apex_sets {
                    stage_put(&mut batch, None, rrset)?;
                }
                batch.audit(
                    AuditDraft::success(audit::ZONE_CREATE, vec![ObjectRef::from(zone.id)])
                        .with_source_ip(cx.source_ip)
                        .with_context("name", zone.name.as_str())
                        .with_context("kind", kind_name(zone.kind)),
                );
                Ok(Planned::write(
                    (),
                    batch,
                    format!("create zone {}", zone.name),
                    vec![ObjectRef::from(zone.id)],
                ))
            })
            .await?;
        let written = written.ok_or_else(internal_nothing_written)?;
        Ok(ZoneWritten {
            zone,
            revision: written.revision,
            job: Some(written.job),
        })
    }

    /// Changes a zone. With `expect`, only the row at that revision changes.
    ///
    /// # Errors
    ///
    /// `dns.zone.not_found`, `dns.zone.invalid`, 412 when `expect` is stale, or a store
    /// or job error.
    #[allow(clippy::too_many_lines, reason = "one plan of a zone change")]
    pub async fn update(
        &self,
        cx: &RequestCtx,
        id: ZoneId,
        change: ZoneChange,
        expect: Option<Revision>,
    ) -> ZoneResult<ZoneWritten> {
        let limits = self.config.journal;
        let (zone, written) = self
            .execute(cx, |view| {
                let row = Self::zone(view, id)?;
                check_expect(expect, row.revision)?;
                let before = row.zone;
                let mut zone = before.clone();
                let stamp = Stamp::new(cx.now, cx.principal.clone());
                let mut fields = Vec::new();
                if let Some(scopes) = &change.scopes {
                    zone.scopes.clone_from(scopes);
                    fields.push("scopes");
                }
                if let Some(policy) = change.serial {
                    zone.serial = policy;
                    fields.push("serial");
                }
                if let Some(soa) = &change.soa {
                    zone.soa = soa.clone();
                    fields.push("soa");
                }
                if let Some(transfer) = &change.transfer {
                    zone.transfer = transfer.clone();
                    fields.push("transfer");
                }
                if let Some(update) = &change.update {
                    zone.update = update.clone();
                    fields.push("update");
                }
                if let Some(dnssec) = &change.dnssec {
                    zone.dnssec = dnssec.clone();
                    fields.push("dnssec");
                }
                if let Some(source) = &change.source {
                    zone.source = Some(source.clone());
                    fields.push("source");
                }
                if let Some(description) = &change.description {
                    zone.description = clean_description(Some(description.clone()));
                    fields.push("description");
                }
                if let Some(reverse_of) = change.reverse_of {
                    zone.reverse_of = reverse_of;
                    fields.push("reverse_of");
                }
                if let Some(catalog) = change.catalog {
                    zone.catalog = catalog;
                    fields.push("catalog");
                }
                zone.validate()?;
                secondary::check_catalog_unique(view, &zone)?;
                if zone == before {
                    return Ok(Planned::nothing(zone));
                }
                zone.updated = stamp.clone();
                let mut batch = WriteBatch::for_request(cx);
                stage_acl_refs(&mut batch, view, &zone)?;
                // WP6.4: a scope a view names is not removed.
                views::stage_zone_refs(&mut batch, view, &before, Some(&zone))?;
                batch.expect_typed(&ZONES, &id, Some(row.revision));
                batch.put_typed(&ZONES, &id, &zone)?;
                if holds_data(zone.kind) {
                    Self::stage_scope_changes(&mut batch, view, &before, &zone, &stamp, limits)?;
                }
                let mut draft = AuditDraft::success(audit::ZONE_UPDATE, vec![ObjectRef::from(id)])
                    .with_source_ip(cx.source_ip)
                    .with_context("name", zone.name.as_str());
                for field in &fields {
                    draft = draft.with_change(FieldChange {
                        object: None,
                        field: (*field).to_owned(),
                        old: None,
                        new: None,
                    });
                }
                batch.audit(draft);
                Ok(Planned::write(
                    zone.clone(),
                    batch,
                    format!("change zone {}", zone.name),
                    vec![ObjectRef::from(id)],
                ))
            })
            .await?;
        let view = self.view(written.map(|w| w.revision)).await?;
        let row = Self::zone(view.as_ref(), id)?;
        Ok(ZoneWritten {
            zone: if written.is_some() { row.zone } else { zone },
            revision: written.map_or(row.revision, |w| w.revision),
            job: written.map(|w| w.job),
        })
    }

    /// The SOA rewrites, new scopes and removed scopes of a zone change.
    fn stage_scope_changes(
        batch: &mut WriteBatch,
        view: &dyn ReadView,
        before: &Zone,
        zone: &Zone,
        stamp: &Stamp,
        limits: JournalLimits,
    ) -> ZoneResult<()> {
        let default_ns = view
            .get_typed(
                &RRSETS,
                &tenko_core::dns::RrSetKey {
                    zone: zone.id,
                    scope: ScopeName::DEFAULT,
                    name: zone.name.clone(),
                    rtype: Rtype::NS,
                },
            )?
            .map(|(rrset, _)| rrset);
        for scope in &zone.scopes {
            if before.has_scope(&scope.name) {
                if before.soa == zone.soa {
                    continue;
                }
                let key = tenko_core::dns::RrSetKey {
                    zone: zone.id,
                    scope: scope.name.clone(),
                    name: zone.name.clone(),
                    rtype: Rtype::SOA,
                };
                let Some((old, revision)) = view.get_typed(&RRSETS, &key)? else {
                    continue;
                };
                let current = soa_serial(&old).unwrap_or_default();
                let next = serial::next(zone.serial, current, stamp.at);
                let new = soa_rrset(zone, &scope.name, &zone.soa, next, stamp.clone());
                new.check(&zone.name)?;
                batch.expect_typed(&RRSETS, &key, Some(revision));
                stage_put(batch, Some(&old), &new)?;
                let entry = JournalEntry {
                    zone: zone.id,
                    scope: scope.name.clone(),
                    from_serial: current,
                    to_serial: next,
                    revision: view.revision(),
                    at: stamp.at,
                    removed: journal_records(&old).collect(),
                    added: journal_records(&new).collect(),
                };
                journal::stage_append(batch, view, limits, &entry)?;
            } else {
                let soa = soa_rrset(
                    zone,
                    &scope.name,
                    &zone.soa,
                    serial::first(zone.serial, stamp.at),
                    stamp.clone(),
                );
                stage_put(batch, None, &soa)?;
                if let Some(ns) = &default_ns {
                    let mut copy = ns.clone();
                    copy.scope = scope.name.clone();
                    copy.updated = stamp.clone();
                    stage_put(batch, None, &copy)?;
                }
            }
        }
        for scope in &before.scopes {
            if zone.has_scope(&scope.name) {
                continue;
            }
            let rows = view.scan_typed(
                &RRSETS,
                rrset_range(zone.id, Some(&scope.name), None),
                usize::MAX,
                false,
            )?;
            for (_, rrset, _) in &rows {
                stage_delete(batch, rrset);
            }
            journal::stage_reset(batch, view, zone.id, &scope.name)?;
        }
        Ok(())
    }

    /// Deletes a zone with its RRsets and journal.
    ///
    /// # Errors
    ///
    /// `dns.zone.not_found`, 412 when `expect` is stale, or a store or job error.
    pub async fn delete(
        &self,
        cx: &RequestCtx,
        id: ZoneId,
        expect: Option<Revision>,
    ) -> ZoneResult<Written> {
        let chunk = self.config.import_chunk;
        let (rest, written) = self
            .execute(cx, |view| {
                let row = Self::zone(view, id)?;
                check_expect(expect, row.revision)?;
                let zone = row.zone;
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&ZONES, &id, Some(row.revision));
                batch.delete_typed(&ZONES, &id);
                // WP6.4: a zone a view names is not deleted.
                views::stage_zone_refs(&mut batch, view, &zone, None)?;
                batch.expect_counter(zone_names(), view.counter(&zone_names())?);
                batch.bump(zone_names());
                let rows =
                    view.scan_typed(&RRSETS, rrset_range(id, None, None), chunk + 1, false)?;
                let complete = rows.len() <= chunk;
                for (_, rrset, _) in rows.iter().take(chunk) {
                    stage_delete(&mut batch, rrset);
                }
                for scope in &zone.scopes {
                    journal::stage_reset(&mut batch, view, id, &scope.name)?;
                }
                batch.audit(
                    AuditDraft::success(audit::ZONE_DELETE, vec![ObjectRef::from(id)])
                        .with_source_ip(cx.source_ip)
                        .with_context("name", zone.name.as_str()),
                );
                Ok(Planned::write(
                    !complete,
                    batch,
                    format!("delete zone {}", zone.name),
                    vec![ObjectRef::from(id)],
                ))
            })
            .await?;
        let written = written.ok_or_else(internal_nothing_written)?;
        if rest {
            self.purge(id).await?;
        }
        Ok(written)
    }

    /// Deletes the RRsets left of a deleted zone, in batches, as the DNS component.
    async fn purge(&self, id: ZoneId) -> ZoneResult<()> {
        let system = RequestCtx::system(tenko_core::SystemComponent::Dns);
        loop {
            let view = self.view(None).await?;
            if view.get_typed(&ZONES, &id)?.is_some() {
                return Ok(());
            }
            let rows = view.scan_typed(
                &RRSETS,
                rrset_range(id, None, None),
                self.config.import_chunk,
                false,
            )?;
            if rows.is_empty() {
                return Ok(());
            }
            let mut batch = WriteBatch::for_request(&system);
            for (_, rrset, _) in &rows {
                stage_delete(&mut batch, rrset);
            }
            self.store.propose(batch).await?;
        }
    }

    /// The RRsets of a zone scope in key order (canonical name order, then type), from
    /// after `after` (a store key of a previous page), filtered; at most `limit`, and the
    /// key to continue from when more may follow.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn rrsets(
        view: &dyn ReadView,
        zone: &Zone,
        filter: &RrSetFilter,
        after: Option<&[u8]>,
        limit: usize,
    ) -> ZoneResult<RrSetPage> {
        let mut out = Vec::new();
        let mut cursor = after.map(<[u8]>::to_vec);
        let step = limit.clamp(64, 4096);
        loop {
            let mut range = rrset_range(zone.id, Some(&filter.scope), None);
            if let Some(cursor) = &cursor {
                range = range.after(cursor.clone());
            }
            let rows = view.scan(RRSETS.name(), range, step, false)?;
            let exhausted = rows.len() < step;
            for (key, versioned) in rows {
                cursor = Some(key.to_vec());
                let rrset: RrSet = RRSETS.decode(&versioned.value)?;
                if filter.matches(zone, &rrset) {
                    out.push((rrset, versioned.revision));
                    if out.len() == limit {
                        return Ok((out, cursor));
                    }
                }
            }
            if exhausted {
                return Ok((out, None));
            }
        }
    }
}

/// A page of RRsets with their revisions, and the store key to continue after.
pub type RrSetPage = (Vec<(RrSet, Revision)>, Option<Vec<u8>>);

/// The filter of an RRset list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrSetFilter {
    /// The scope.
    pub scope: ScopeName,
    /// Owner names starting with this text, relative to the apex (`www`, `_ldap._tcp`;
    /// `@` is the apex).
    pub name: Option<String>,
    /// One type.
    pub rtype: Option<Rtype>,
    /// One origin; without it the rows of the signer (`dnssec`) are left out.
    pub origin: Option<Origin>,
}

impl RrSetFilter {
    /// Every RRset of a scope.
    pub fn scope(scope: ScopeName) -> Self {
        Self {
            scope,
            name: None,
            rtype: None,
            origin: None,
        }
    }

    fn matches(&self, zone: &Zone, rrset: &RrSet) -> bool {
        // WP6.3: the signer's rows show only when asked for (`?origin=dnssec`).
        if self.origin.is_none() && rrset.origin == Origin::Dnssec {
            return false;
        }
        if self.rtype.is_some_and(|rtype| rtype != rrset.rtype)
            || self.origin.is_some_and(|origin| origin != rrset.origin)
        {
            return false;
        }
        let Some(prefix) = &self.name else {
            return true;
        };
        let prefix = prefix.trim().trim_end_matches('.').to_ascii_lowercase();
        if prefix == "@" {
            return rrset.name == zone.name;
        }
        relative_name(&rrset.name, &zone.name).starts_with(&prefix)
            || rrset.name.as_str().starts_with(&prefix)
    }
}

/// A name relative to the apex: `@` for the apex itself.
pub fn relative_name(name: &DnsName, apex: &DnsName) -> String {
    if name == apex {
        return "@".to_owned();
    }
    if apex.is_root() {
        return name.as_str().to_owned();
    }
    name.as_str()
        .strip_suffix(apex.as_str())
        .and_then(|head| head.strip_suffix('.'))
        .map_or_else(|| name.as_str().to_owned(), ToOwned::to_owned)
}

/// What a plan wants written, with the result it reports.
pub(crate) struct Planned<T> {
    pub(crate) result: T,
    pub(crate) write: Option<PlannedWrite>,
}

pub(crate) struct PlannedWrite {
    pub(crate) batch: WriteBatch,
    pub(crate) summary: String,
    pub(crate) targets: Vec<ObjectRef>,
}

impl<T> Planned<T> {
    pub(crate) fn write(
        result: T,
        batch: WriteBatch,
        summary: String,
        targets: Vec<ObjectRef>,
    ) -> Self {
        Self {
            result,
            write: Some(PlannedWrite {
                batch,
                summary,
                targets,
            }),
        }
    }

    pub(crate) fn nothing(result: T) -> Self {
        Self {
            result,
            write: None,
        }
    }
}

fn ns_rrset(
    zone: &Zone,
    scope: &ScopeName,
    servers: &[DnsName],
    ttl: u32,
    stamp: Stamp,
) -> ZoneResult<RrSet> {
    let mut rdata: Vec<Rdata> = Vec::new();
    for host in servers {
        if host.is_root() || host.is_wildcard() {
            return Err(ZoneError::zone_invalid(
                "name_servers",
                "a name server is a host name",
            ));
        }
        let data = Rdata::from_data(&RecordData::Ns { host: host.clone() });
        if !rdata.contains(&data) {
            rdata.push(data);
        }
    }
    Ok(RrSet {
        zone: zone.id,
        scope: scope.clone(),
        name: zone.name.clone(),
        rtype: Rtype::NS,
        ttl,
        rdata,
        origin: Origin::Manual,
        key: None,
        updated: stamp,
    })
}

fn clean_description(description: Option<String>) -> Option<String> {
    description
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
}

fn kind_name(kind: ZoneKind) -> &'static str {
    match kind {
        ZoneKind::Primary => "primary",
        ZoneKind::Secondary => "secondary",
        ZoneKind::Stub => "stub",
        ZoneKind::Forward => "forward",
        ZoneKind::Rpz => "rpz",
    }
}

/// Checks that the access lists a zone names exist and makes the batch expect them, so a
/// list deleted meanwhile makes it stale.
fn stage_acl_refs(batch: &mut WriteBatch, view: &dyn ReadView, zone: &Zone) -> ZoneResult<()> {
    for (field, id) in zone
        .transfer
        .allow
        .iter()
        .map(|id| ("transfer.allow", id))
        .chain(zone.update.allowed.iter().map(|id| ("update.allowed", id)))
    {
        let Some((_, revision)) = view.get_typed(&tenko_core::dns::tables::ACLS, id)? else {
            return Err(
                ZoneError::zone_invalid(field, "the access list does not exist")
                    .param("acl", id.to_string()),
            );
        };
        batch.expect_typed(&tenko_core::dns::tables::ACLS, id, Some(revision));
    }
    Ok(())
}

/// 412 when the client's revision is not the row's.
pub(crate) fn check_expect(expect: Option<Revision>, current: Revision) -> ZoneResult<()> {
    match expect {
        Some(expect) if expect != current => Err(ZoneError::new(
            "sys.store.precondition_failed",
            412,
            format!(
                "the object changed since revision {}; it is at {}",
                expect.0, current.0
            ),
        )
        .param("expected", expect.0.to_string())
        .param("current", current.0.to_string())),
        _ => Ok(()),
    }
}

fn internal_nothing_written() -> ZoneError {
    ZoneError::new(
        tenko_core::error::codes::INTERNAL,
        500,
        "the write reported no commit",
    )
}
