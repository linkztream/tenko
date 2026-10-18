//! Secondary and catalog zones (WP6.1, plan section 2.4): the leader service
//! `dns.transfer` and the read-only rule.
//!
//! A zone of kind secondary is filled by zone transfers from the servers of its `source`,
//! tried in order. The service refreshes each zone on the timers of the SOA it holds:
//! after `refresh` seconds, after `retry` seconds while every primary fails, and it lets
//! the copy go after `expire` seconds without a successful refresh (the zone then answers
//! SERVFAIL until the next transfer). A NOTIFY from one of the primaries, or a request
//! through the API, refreshes the zone at once. A refresh asks for IXFR with the copy's
//! SOA and falls back to AXFR ([`crate::xfr::inbound`]); TSIG when the primary has a key,
//! TLS (XoT) when it says `xot`, to port 853 unless another port is set.
//!
//! The result is written as one change set through the store, signed with the leader's
//! epoch: the RRsets of the transfer replace the copy's with the origin `transfer`, the
//! SOA carries the serial as received, and the journal gets one entry with the change (the
//! journal is reset after a transfer that changes more than [`JOURNAL_MAX`] records or a
//! first transfer), so that the index of every node follows through the store and the zone
//! transfers on to its own secondaries with IXFR. A zone too large for one store batch is
//! written in chunks of [`CHUNK`] RRsets with the SOA last.
//!
//! The RRsets of a secondary zone are read-only for every other writer (409
//! `dns.zone.secondary`, [`check_writable`]); in a primary catalog zone only the members
//! Tenko writes are.
//!
//! Catalog zones (RFC 9432): a secondary catalog zone's members become secondary zones of
//! this installation with the catalog's primaries (described as members of the catalog,
//! which is how the service knows they are its own) and are deleted when they leave it. A
//! primary catalog zone lists every primary zone of its tenant whose `transfer.allow` is
//! not empty, catalog zones excepted; the service rewrites the list with a serial step
//! whenever the zones change, so its secondaries follow by IXFR and NOTIFY.
//!
//! The state of each zone (the serial held, each primary's last success and error, the
//! next refresh, the expiry) lives in the memory of the service on the leader. After a
//! restart the copy is taken as fresh from the time its SOA was last written and refreshed
//! at once.

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock, PoisonError},
    time::Duration,
};

use futures::StreamExt as _;
use tenko_core::Revision;
use tenko_core::{
    ObjectRef, RequestCtx, SystemComponent, Timestamp,
    audit::AuditDraft,
    cluster::LeaderService,
    dns::{
        DnsName, KeyMeta, KeyName, Origin, PrimaryServer, Rdata, RecordData, RrSet, RrSetKey,
        Rtype, ScopeName, Zone, ZoneId, ZoneKind, audit, codes,
        tables::{KEYS_META, RRSETS, ZONES},
    },
    ipam::Stamp,
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, WatchFilter, WriteBatch};
use tokio_util::sync::CancellationToken;

use super::{
    NewZone, ZoneError, ZoneResult, ZoneService, journal, records, rrset_range, stage_delete,
    stage_put,
};
use crate::{
    tsig::TsigKey,
    xfr::{
        NotifyHandler, catalog_zone,
        inbound::{self, FetchError, Fetched, Held, Limits, Primary},
        message::Record,
    },
};

/// Records a transfer may change and still get a journal entry; a larger change resets
/// the journal (its secondaries get AXFR).
pub const JOURNAL_MAX: usize = 10_000;

/// RRsets per batch of a transfer too large for one.
pub const CHUNK: usize = 20_000;

/// The text a member zone of a secondary catalog zone is described with.
pub const MEMBER_OF: &str = "Member of the catalog zone ";

/// The 409 of a write to records that come from transfers.
pub fn read_only(zone: &Zone) -> ZoneError {
    ZoneError::new(
        codes::ZONE_SECONDARY,
        409,
        format!(
            "the records of {} come from zone transfers and are read-only",
            zone.name
        ),
    )
    .param("zone", zone.name.as_str())
}

/// Refuses every write to the records of a secondary zone but the service's own.
///
/// # Errors
///
/// `dns.zone.secondary` for a secondary zone.
pub fn check_writable(zone: &Zone) -> ZoneResult<()> {
    if zone.kind == ZoneKind::Secondary {
        return Err(read_only(zone));
    }
    Ok(())
}

/// Refuses a second primary catalog zone in a tenant (or among the zones without one).
///
/// # Errors
///
/// `dns.zone.invalid` on the field `catalog`, or the store's error.
pub fn check_catalog_unique(view: &dyn ReadView, zone: &Zone) -> ZoneResult<()> {
    if !zone.catalog || zone.kind != ZoneKind::Primary {
        return Ok(());
    }
    let clash = view
        .scan_typed(&ZONES, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .any(|(_, other, _)| {
            other.id != zone.id
                && other.catalog
                && other.kind == ZoneKind::Primary
                && other.tenant == zone.tenant
        });
    if clash {
        return Err(ZoneError::zone_invalid(
            "catalog",
            "a tenant has at most one primary catalog zone",
        ));
    }
    Ok(())
}

impl ZoneService {
    /// The TSIG key of `meta` with its secret from the vault, for the transfer and NOTIFY
    /// paths (never shown to anyone).
    ///
    /// # Errors
    ///
    /// 503 without a vault, or the vault's error.
    pub async fn tsig_key(&self, meta: &KeyMeta) -> ZoneResult<TsigKey> {
        let vault = self.vault.as_ref().ok_or_else(|| {
            ZoneError::new(
                "vault.unavailable",
                503,
                "TSIG keys need the vault, which this server does not run",
            )
        })?;
        let cx = RequestCtx::system(SystemComponent::Dns);
        let secret = vault.get_system(&cx, meta.secret).await?;
        Ok(TsigKey::new(&meta.name, meta.algorithm, secret.expose()))
    }
}

/// The TSIG keys of the leader services, read from the store and the vault on first use
/// and again when a key's metadata changes.
pub struct KeyLoader {
    zones: Arc<ZoneService>,
    cache: Mutex<HashMap<KeyName, (KeyMeta, Arc<TsigKey>)>>,
}

impl std::fmt::Debug for KeyLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyLoader").finish_non_exhaustive()
    }
}

impl KeyLoader {
    /// A loader over the zone service.
    pub fn new(zones: Arc<ZoneService>) -> Self {
        Self {
            zones,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The key of a name, when it exists and its secret can be read.
    pub async fn key(&self, name: &KeyName) -> Option<Arc<TsigKey>> {
        let view = self.zones.view(None).await.ok()?;
        let (meta, _) = view.get_typed(&KEYS_META, name).ok()??;
        drop(view);
        if let Some((cached, key)) = self
            .cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name)
            && *cached == meta
        {
            return Some(Arc::clone(key));
        }
        match self.zones.tsig_key(&meta).await {
            Ok(key) => {
                let key = Arc::new(key);
                self.cache
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(name.clone(), (meta, Arc::clone(&key)));
                Some(key)
            }
            Err(error) => {
                tracing::warn!(key = %name, %error, "a TSIG key could not be read from the vault");
                None
            }
        }
    }
}

/// The settings of the service.
#[derive(Debug, Clone)]
pub struct SecondarySettings {
    /// The time limits of one transfer.
    pub limits: Limits,
    /// The CA of XoT primaries (`[dns] upstream_ca`); the system roots when absent.
    pub upstream_ca: Option<Vec<u8>>,
    /// Transfers at the same time.
    pub concurrency: usize,
    /// The longest sleep of the service between two looks.
    pub tick: Duration,
}

impl Default for SecondarySettings {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            upstream_ca: None,
            concurrency: 4,
            tick: Duration::from_secs(30),
        }
    }
}

/// The state of one primary of a zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimaryStatus {
    /// The address and port.
    pub address: SocketAddr,
    /// The last successful refresh from it.
    pub last_success: Option<Timestamp>,
    /// The stable code of its last failure, cleared by a success.
    pub last_error: Option<String>,
    /// What failed, in English.
    pub detail: Option<String>,
}

/// The transfer state of a zone, as the API shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferState {
    /// The serial held.
    pub serial: Option<u32>,
    /// Each primary.
    pub primaries: Vec<PrimaryStatus>,
    /// The next refresh.
    pub next_refresh: Option<Timestamp>,
    /// When the copy expires without a successful refresh.
    pub expires: Option<Timestamp>,
    /// A transfer is running.
    pub running: bool,
}

#[derive(Debug, Clone)]
struct ZoneState {
    serial: Option<u32>,
    primaries: Vec<PrimaryStatus>,
    next_refresh: Timestamp,
    expires: Option<Timestamp>,
    running: bool,
}

/// The SOA timers of a copy.
#[derive(Debug, Clone, Copy)]
struct Timers {
    refresh: u32,
    retry: u32,
    expire: u32,
}

impl Timers {
    const DEFAULT: Timers = Timers {
        refresh: 3600,
        retry: 600,
        expire: 1_209_600,
    };

    fn of(rdata: &Rdata) -> Self {
        match rdata.decode(Rtype::SOA) {
            Ok(RecordData::Soa {
                refresh,
                retry,
                expire,
                ..
            }) => Self {
                refresh: refresh.max(1),
                retry: retry.max(1),
                expire: expire.max(1),
            },
            _ => Self::DEFAULT,
        }
    }
}

fn after(at: Timestamp, seconds: u32) -> Timestamp {
    at.checked_add(Duration::from_secs(u64::from(seconds)))
        .unwrap_or(at)
}

/// The leader service `dns.transfer`. Cheap to clone; every clone is the same service.
#[derive(Clone)]
pub struct SecondaryService {
    inner: Arc<Inner>,
}

struct Inner {
    zones: Arc<ZoneService>,
    keys: Arc<KeyLoader>,
    settings: SecondarySettings,
    state: Mutex<HashMap<ZoneId, ZoneState>>,
    wake: tokio::sync::Notify,
    tls: OnceLock<Result<Arc<rustls::ClientConfig>, String>>,
}

impl std::fmt::Debug for SecondaryService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecondaryService")
            .field("settings", &self.inner.settings)
            .finish_non_exhaustive()
    }
}

/// What one refresh did.
enum Refreshed {
    /// The copy is current or was replaced: the new serial.
    Serial(u32),
    /// Every primary failed.
    Failed,
}

impl SecondaryService {
    /// The service over the zone service.
    pub fn new(zones: Arc<ZoneService>, keys: Arc<KeyLoader>, settings: SecondarySettings) -> Self {
        Self {
            inner: Arc::new(Inner {
                zones,
                keys,
                settings,
                state: Mutex::new(HashMap::new()),
                wake: tokio::sync::Notify::new(),
                tls: OnceLock::new(),
            }),
        }
    }

    /// The transfer state of a zone: the service's view on the leader, or what the store
    /// says when the service has not seen the zone.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn state(&self, view: &dyn ReadView, zone: &Zone) -> ZoneResult<TransferState> {
        if let Some(state) = self.inner.lock().get(&zone.id) {
            return Ok(TransferState {
                serial: state.serial,
                primaries: state.primaries.clone(),
                next_refresh: Some(state.next_refresh),
                expires: state.expires,
                running: state.running,
            });
        }
        let serial = ZoneService::scope_serial(view, zone, &ScopeName::DEFAULT)?;
        Ok(TransferState {
            serial,
            primaries: primaries_of(zone)
                .into_iter()
                .map(|address| PrimaryStatus {
                    address,
                    last_success: None,
                    last_error: None,
                    detail: None,
                })
                .collect(),
            next_refresh: None,
            expires: None,
            running: false,
        })
    }

    /// Refreshes a secondary zone now (the API's `POST .../transfer`), audited as
    /// `dns.transfer.trigger`.
    ///
    /// # Errors
    ///
    /// `dns.zone.not_found`, `dns.zone.invalid` for a zone that is not secondary, or the
    /// store's error.
    pub async fn trigger(&self, cx: &RequestCtx, id: ZoneId) -> ZoneResult<TransferState> {
        let view = self.inner.zones.view(None).await?;
        let zone = ZoneService::zone(view.as_ref(), id)?.zone;
        if zone.kind != ZoneKind::Secondary {
            return Err(ZoneError::new(
                codes::ZONE_INVALID,
                409,
                format!("{} is not a secondary zone", zone.name),
            )
            .param("field", "kind")
            .param("reason", "only a secondary zone is transferred in"));
        }
        let mut batch = WriteBatch::for_request(cx);
        batch.audit(
            AuditDraft::success(audit::TRANSFER_TRIGGER, vec![ObjectRef::from(id)])
                .with_source_ip(cx.source_ip)
                .with_context("zone", zone.name.as_str()),
        );
        self.inner.zones.store().propose(batch).await?;
        if let Some(state) = self.inner.lock().get_mut(&id) {
            state.next_refresh = Timestamp::now();
        }
        self.inner.wake.notify_one();
        self.state(view.as_ref(), &zone)
    }
}

/// The addresses of a zone's primaries, with 853 for XoT on the default port.
fn primaries_of(zone: &Zone) -> Vec<SocketAddr> {
    zone.source
        .as_ref()
        .map(|source| source.primaries.iter().map(primary_address).collect())
        .unwrap_or_default()
}

fn primary_address(primary: &PrimaryServer) -> SocketAddr {
    let port = if primary.xot && primary.port == 53 {
        853
    } else {
        primary.port
    };
    SocketAddr::new(primary.address, port)
}

impl NotifyHandler for SecondaryService {
    fn notified(&self, zone: ZoneId, from: std::net::IpAddr, serial: Option<u32>) {
        let mut state = self.inner.lock();
        if let Some(entry) = state.get_mut(&zone) {
            if serial.is_some_and(|serial| {
                entry
                    .serial
                    .is_some_and(|held| crate::xfr::out::serial_ge(held, serial))
            }) {
                tracing::debug!(%from, ?serial, "NOTIFY for a serial already held");
                return;
            }
            entry.next_refresh = Timestamp::now();
        }
        drop(state);
        self.inner.wake.notify_one();
    }
}

/// The RRsets of a zone's default scope, with their revisions.
fn scope_rrsets(
    view: &dyn ReadView,
    zone: ZoneId,
) -> ZoneResult<BTreeMap<(DnsName, Rtype), (RrSet, Revision)>> {
    Ok(view
        .scan_typed(
            &RRSETS,
            rrset_range(zone, Some(&ScopeName::DEFAULT), None),
            usize::MAX,
            false,
        )?
        .into_iter()
        .map(|(_, rrset, revision)| ((rrset.name.clone(), rrset.rtype), (rrset, revision)))
        .collect())
}

fn system() -> RequestCtx {
    RequestCtx::system(SystemComponent::Dns)
}

fn transfer_rrset(zone: &Zone, name: DnsName, rtype: Rtype, ttl: u32, stamp: &Stamp) -> RrSet {
    RrSet {
        zone: zone.id,
        scope: ScopeName::DEFAULT,
        name,
        rtype,
        ttl,
        rdata: Vec::new(),
        origin: Origin::Transfer,
        key: None,
        updated: stamp.clone(),
    }
}

/// The RRsets after a transfer, from the copy before it.
fn target(
    zone: &Zone,
    before: &BTreeMap<(DnsName, Rtype), (RrSet, Revision)>,
    fetched: &Fetched,
    stamp: &Stamp,
) -> Result<BTreeMap<(DnsName, Rtype), RrSet>, FetchError> {
    let mut after: BTreeMap<(DnsName, Rtype), RrSet> = BTreeMap::new();
    let add = |after: &mut BTreeMap<(DnsName, Rtype), RrSet>, record: &Record| {
        if record.class != 1 || !record.name.is_subdomain_of(&zone.name) {
            return;
        }
        let set = after
            .entry((record.name.clone(), record.rtype))
            .or_insert_with(|| {
                transfer_rrset(zone, record.name.clone(), record.rtype, record.ttl, stamp)
            });
        set.ttl = set.ttl.min(record.ttl);
        if !set.rdata.contains(&record.rdata) {
            set.rdata.push(record.rdata.clone());
        }
    };
    match fetched {
        Fetched::Current { .. } => {}
        Fetched::Full { records, .. } => {
            for record in records {
                add(&mut after, record);
            }
        }
        Fetched::Delta { steps, soa, .. } => {
            for ((name, rtype), (rrset, _)) in before {
                after.insert((name.clone(), *rtype), rrset.clone());
            }
            for step in steps {
                for record in step.removed.iter().skip(1) {
                    let key = (record.name.clone(), record.rtype);
                    if let Some(set) = after.get_mut(&key) {
                        set.rdata.retain(|rdata| *rdata != record.rdata);
                        if set.rdata.is_empty() {
                            after.remove(&key);
                        }
                    }
                }
                for record in step.added.iter().skip(1) {
                    let key = (record.name.clone(), record.rtype);
                    if let Some(set) = after.get_mut(&key) {
                        // An added record into an RRset of another TTL takes the new TTL.
                        set.ttl = record.ttl;
                    }
                    add(&mut after, record);
                }
            }
            after.remove(&(zone.name.clone(), Rtype::SOA));
            add(&mut after, soa);
        }
    }
    for set in after.values_mut() {
        set.origin = Origin::Transfer;
        set.updated = stamp.clone();
        set.check(&zone.name).map_err(|error| FetchError {
            code: codes::TRANSFER_FAILED,
            detail: format!("{} {}: {error}", set.name, set.rtype),
        })?;
    }
    if !after.contains_key(&(zone.name.clone(), Rtype::SOA)) {
        return Err(FetchError {
            code: codes::TRANSFER_FAILED,
            detail: "the transfer holds no SOA at the apex".to_owned(),
        });
    }
    Ok(after)
}

/// One RRset changed by a transfer: before and after.
type Change = (Option<(RrSet, Revision)>, Option<RrSet>);

fn diff(
    before: &BTreeMap<(DnsName, Rtype), (RrSet, Revision)>,
    after: &BTreeMap<(DnsName, Rtype), RrSet>,
) -> Vec<Change> {
    let mut out = Vec::new();
    for (key, (old, revision)) in before {
        match after.get(key) {
            Some(new) if same(old, new) => {}
            Some(new) => out.push((Some((old.clone(), *revision)), Some(new.clone()))),
            None => out.push((Some((old.clone(), *revision)), None)),
        }
    }
    for (key, new) in after {
        if !before.contains_key(key) {
            out.push((None, Some(new.clone())));
        }
    }
    out
}

fn same(a: &RrSet, b: &RrSet) -> bool {
    a.ttl == b.ttl
        && a.origin == b.origin
        && a.rdata.len() == b.rdata.len()
        && a.rdata.iter().all(|rdata| b.rdata.contains(rdata))
}

impl Inner {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<ZoneId, ZoneState>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn tls(&self) -> Result<Arc<rustls::ClientConfig>, String> {
        self.tls
            .get_or_init(|| {
                crate::upstream::TlsClient::new(self.settings.upstream_ca.as_deref())
                    .map(|client| client.dot())
            })
            .clone()
    }

    /// Brings the state in line with the zone rows: new secondary zones are due at once,
    /// gone ones are dropped; the primary catalog zones get their member lists.
    async fn reconcile(&self, epoch: u64) -> ZoneResult<()> {
        let view = self.zones.view(None).await?;
        let rows = ZoneService::zones(view.as_ref())?;
        let now = Timestamp::now();
        {
            let mut state = self.lock();
            state.retain(|id, _| {
                rows.iter()
                    .any(|row| row.zone.id == *id && row.zone.kind == ZoneKind::Secondary)
            });
            for row in &rows {
                let zone = &row.zone;
                if zone.kind != ZoneKind::Secondary {
                    continue;
                }
                let addresses = primaries_of(zone);
                if let Some(entry) = state.get_mut(&zone.id) {
                    if entry
                        .primaries
                        .iter()
                        .map(|p| p.address)
                        .ne(addresses.iter().copied())
                    {
                        entry.primaries = addresses
                            .iter()
                            .map(|address| PrimaryStatus {
                                address: *address,
                                last_success: None,
                                last_error: None,
                                detail: None,
                            })
                            .collect();
                        entry.next_refresh = now;
                    }
                    continue;
                }
                let soa = view
                    .get_typed(
                        &RRSETS,
                        &RrSetKey {
                            zone: zone.id,
                            scope: ScopeName::DEFAULT,
                            name: zone.name.clone(),
                            rtype: Rtype::SOA,
                        },
                    )?
                    .map(|(rrset, _)| rrset);
                let (serial, expires) = match &soa {
                    Some(soa) => (
                        super::soa_serial(soa),
                        soa.rdata
                            .first()
                            .map(|rdata| after(soa.updated.at, Timers::of(rdata).expire)),
                    ),
                    None => (None, None),
                };
                state.insert(
                    zone.id,
                    ZoneState {
                        serial,
                        primaries: addresses
                            .iter()
                            .map(|address| PrimaryStatus {
                                address: *address,
                                last_success: None,
                                last_error: None,
                                detail: None,
                            })
                            .collect(),
                        next_refresh: now,
                        expires,
                        running: false,
                    },
                );
            }
        }
        for row in rows
            .iter()
            .filter(|row| row.zone.catalog && row.zone.kind == ZoneKind::Primary)
        {
            if let Err(error) = self
                .write_catalog(view.as_ref(), &row.zone, &rows, epoch)
                .await
            {
                tracing::warn!(zone = %row.zone.name, %error, "the members of a catalog zone could not be written");
            }
        }
        Ok(())
    }

    /// Writes the member list of a primary catalog zone when it changed.
    async fn write_catalog(
        &self,
        view: &dyn ReadView,
        catalog: &Zone,
        rows: &[super::ZoneRow],
        epoch: u64,
    ) -> ZoneResult<()> {
        let members: Vec<(ZoneId, DnsName)> = rows
            .iter()
            .map(|row| &row.zone)
            .filter(|zone| {
                zone.kind == ZoneKind::Primary
                    && !zone.catalog
                    && zone.tenant == catalog.tenant
                    && !zone.transfer.allow.is_empty()
            })
            .map(|zone| (zone.id, zone.name.clone()))
            .collect();
        let cx = system();
        let stamp = Stamp::new(cx.now, cx.principal.clone());
        let mut desired: BTreeMap<(DnsName, Rtype), RrSet> = BTreeMap::new();
        for (name, rtype, rdata) in catalog_zone::generate(&catalog.name, &members) {
            let mut set = transfer_rrset(catalog, name.clone(), rtype, 0, &stamp);
            set.rdata = rdata;
            desired.insert((name, rtype), set);
        }
        let current: BTreeMap<(DnsName, Rtype), (RrSet, Revision)> =
            scope_rrsets(view, catalog.id)?
                .into_iter()
                .filter(|(_, (rrset, _))| rrset.origin == Origin::Transfer)
                .collect();
        let changes = diff(&current, &desired);
        if changes.is_empty() {
            return Ok(());
        }
        let mut batch = WriteBatch::for_request(&cx);
        batch.preconditions.push(tenko_store::fence(epoch));
        let mut diffs = Vec::new();
        for (old, new) in &changes {
            let key = old
                .as_ref()
                .map_or_else(|| new.as_ref().map(RrSet::key), |(old, _)| Some(old.key()));
            let Some(key) = key else { continue };
            batch.expect_typed(&RRSETS, &key, old.as_ref().map(|(_, revision)| *revision));
            match new {
                Some(new) => stage_put(&mut batch, old.as_ref().map(|(old, _)| old), new)?,
                None => {
                    if let Some((old, _)) = old {
                        stage_delete(&mut batch, old);
                    }
                }
            }
            diffs.push(records::Diff {
                key,
                before: old.as_ref().map(|(old, _)| old.clone()),
                after: new.clone(),
            });
        }
        let (removed, added) = records::journal_diff(diffs.iter());
        let step = records::stage_serial_step(
            &mut batch,
            view,
            catalog,
            &ScopeName::DEFAULT,
            &stamp,
            self.zones.config().journal,
            removed,
            added,
        )?;
        batch.audit(
            AuditDraft::success(audit::ZONE_TRANSFER_IN, vec![ObjectRef::from(catalog.id)])
                .with_context("zone", catalog.name.as_str())
                .with_context("kind", "catalog")
                .with_context("members", members.len().to_string())
                .with_context("serial", step.to.to_string()),
        );
        self.zones.store().propose(batch).await?;
        tracing::info!(zone = %catalog.name, members = members.len(), serial = step.to, "catalog zone members written");
        Ok(())
    }

    /// The zones due for a refresh, marked running.
    fn take_due(&self, limit: usize) -> Vec<ZoneId> {
        let now = Timestamp::now();
        let mut state = self.lock();
        let running = state.values().filter(|zone| zone.running).count();
        let mut due: Vec<(Timestamp, ZoneId)> = state
            .iter()
            .filter(|(_, zone)| !zone.running && zone.next_refresh <= now)
            .map(|(id, zone)| (zone.next_refresh, *id))
            .collect();
        due.sort();
        due.truncate(limit.saturating_sub(running));
        for (_, id) in &due {
            if let Some(zone) = state.get_mut(id) {
                zone.running = true;
            }
        }
        due.into_iter().map(|(_, id)| id).collect()
    }

    /// How long until the next zone is due, at most the tick.
    fn sleep(&self) -> Duration {
        let now = Timestamp::now();
        let state = self.lock();
        state
            .values()
            .filter(|zone| !zone.running)
            .map(|zone| {
                if zone.next_refresh <= now {
                    Duration::ZERO
                } else {
                    zone.next_refresh.saturating_since(now)
                }
            })
            .chain(
                state
                    .values()
                    .filter_map(|zone| zone.expires.map(|at| at.saturating_since(now))),
            )
            .min()
            .unwrap_or(self.settings.tick)
            .clamp(Duration::from_millis(50), self.settings.tick)
    }

    /// The copies past their expiry: their records go.
    async fn expire_due(&self, epoch: u64) {
        let now = Timestamp::now();
        let expired: Vec<ZoneId> = self
            .lock()
            .iter()
            .filter(|(_, zone)| {
                !zone.running && zone.serial.is_some() && zone.expires.is_some_and(|at| at <= now)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            match self.expire(id, epoch).await {
                Ok(()) => {
                    if let Some(zone) = self.lock().get_mut(&id) {
                        zone.serial = None;
                        zone.expires = None;
                    }
                }
                Err(error) => {
                    tracing::warn!(zone = %id, %error, "an expired zone could not be emptied");
                }
            }
        }
    }

    async fn expire(&self, id: ZoneId, epoch: u64) -> ZoneResult<()> {
        let cx = system();
        loop {
            let view = self.zones.view(None).await?;
            let zone = ZoneService::zone(view.as_ref(), id)?.zone;
            let rows = view.scan_typed(&RRSETS, rrset_range(id, None, None), CHUNK, false)?;
            let mut batch = WriteBatch::for_request(&cx);
            batch.preconditions.push(tenko_store::fence(epoch));
            let last = rows.len() < CHUNK;
            for (_, rrset, _) in &rows {
                stage_delete(&mut batch, rrset);
            }
            if last {
                for scope in &zone.scopes {
                    journal::stage_reset(&mut batch, view.as_ref(), id, &scope.name)?;
                }
                batch.audit(
                    AuditDraft::success(audit::ZONE_TRANSFER_IN, vec![ObjectRef::from(id)])
                        .with_context("zone", zone.name.as_str())
                        .with_context("kind", "expire"),
                );
            }
            drop(view);
            self.zones.store().propose(batch).await?;
            if last {
                tracing::warn!(zone = %zone.name, "the copy of a secondary zone expired; it answers SERVFAIL until the next transfer");
                return Ok(());
            }
        }
    }

    /// One refresh of a zone from its primaries in order.
    async fn refresh(self: Arc<Self>, id: ZoneId, epoch: u64) {
        let outcome = self.try_refresh(id, epoch).await;
        let now = Timestamp::now();
        let view = self.zones.view(None).await.ok();
        let timers = view
            .as_ref()
            .and_then(|view| {
                let zone = ZoneService::zone(view.as_ref(), id).ok()?.zone;
                let key = RrSetKey {
                    zone: id,
                    scope: ScopeName::DEFAULT,
                    name: zone.name,
                    rtype: Rtype::SOA,
                };
                let (soa, _) = view.get_typed(&RRSETS, &key).ok()??;
                soa.rdata.first().map(Timers::of)
            })
            .unwrap_or(Timers::DEFAULT);
        let mut state = self.lock();
        if let Some(zone) = state.get_mut(&id) {
            zone.running = false;
            match outcome {
                Some(Refreshed::Serial(serial)) => {
                    zone.serial = Some(serial);
                    zone.next_refresh = after(now, timers.refresh);
                    zone.expires = Some(after(now, timers.expire));
                }
                Some(Refreshed::Failed) | None => {
                    let retry = if zone.serial.is_some() {
                        timers.retry
                    } else {
                        timers.retry.min(60)
                    };
                    zone.next_refresh = after(now, retry);
                }
            }
        }
        drop(state);
        self.wake.notify_one();
    }

    fn set_primary(&self, id: ZoneId, address: SocketAddr, result: Result<(), &FetchError>) {
        let mut state = self.lock();
        let Some(zone) = state.get_mut(&id) else {
            return;
        };
        let Some(primary) = zone.primaries.iter_mut().find(|p| p.address == address) else {
            return;
        };
        match result {
            Ok(()) => {
                primary.last_success = Some(Timestamp::now());
                primary.last_error = None;
                primary.detail = None;
            }
            Err(error) => {
                primary.last_error = Some(error.code.to_owned());
                primary.detail = Some(error.detail.clone());
            }
        }
    }

    async fn try_refresh(&self, id: ZoneId, epoch: u64) -> Option<Refreshed> {
        let view = self.zones.view(None).await.ok()?;
        let zone = ZoneService::zone(view.as_ref(), id).ok()?.zone;
        let held = view
            .get_typed(
                &RRSETS,
                &RrSetKey {
                    zone: id,
                    scope: ScopeName::DEFAULT,
                    name: zone.name.clone(),
                    rtype: Rtype::SOA,
                },
            )
            .ok()
            .flatten()
            .and_then(|(soa, _)| {
                let rdata = soa.rdata.first()?.as_bytes().to_vec();
                Some(Held {
                    serial: crate::xfr::message::soa_serial(&rdata)?,
                    ttl: soa.ttl,
                    rdata,
                })
            });
        drop(view);
        let servers = zone
            .source
            .as_ref()
            .map(|source| source.primaries.clone())
            .unwrap_or_default();
        for server in &servers {
            let address = primary_address(server);
            let primary = match self.primary(server, address).await {
                Ok(primary) => primary,
                Err(error) => {
                    self.set_primary(id, address, Err(&error));
                    continue;
                }
            };
            let fetched = match inbound::fetch(
                &primary,
                &zone.name,
                held.as_ref(),
                self.settings.limits,
            )
            .await
            {
                Ok(fetched) => fetched,
                Err(error) => {
                    tracing::info!(zone = %zone.name, %address, %error, "a zone transfer failed");
                    self.set_primary(id, address, Err(&error));
                    continue;
                }
            };
            if let Fetched::Current { serial } = fetched {
                self.set_primary(id, address, Ok(()));
                return Some(Refreshed::Serial(
                    held.as_ref().map_or(serial, |held| held.serial),
                ));
            }
            match self
                .apply(&zone, held.as_ref(), &fetched, address, epoch)
                .await
            {
                Ok(serial) => {
                    self.set_primary(id, address, Ok(()));
                    if zone.catalog
                        && let Err(error) = self.sync_members(&zone).await
                    {
                        tracing::warn!(zone = %zone.name, %error, "the members of a catalog zone could not be followed");
                    }
                    return Some(Refreshed::Serial(serial));
                }
                Err(error) => {
                    tracing::warn!(zone = %zone.name, %address, %error, "a zone transfer could not be written");
                    self.set_primary(id, address, Err(&error));
                }
            }
        }
        Some(Refreshed::Failed)
    }

    async fn primary(
        &self,
        server: &PrimaryServer,
        address: SocketAddr,
    ) -> Result<Primary, FetchError> {
        let key = match &server.key {
            Some(name) => Some(self.keys.key(name).await.ok_or_else(|| FetchError {
                code: codes::TRANSFER_TSIG,
                detail: format!("the TSIG key {name} is unknown or cannot be read"),
            })?),
            None => None,
        };
        let tls = if server.xot {
            let config = self.tls().map_err(|detail| FetchError {
                code: codes::TRANSFER_FAILED,
                detail,
            })?;
            let name = server
                .tls_name
                .clone()
                .unwrap_or_else(|| server.address.to_string());
            Some((config, name))
        } else {
            None
        };
        Ok(Primary { address, key, tls })
    }

    /// Writes a transfer's result: one batch when it fits, else chunks with the SOA last.
    #[allow(
        clippy::too_many_lines,
        reason = "the diff, the chunks, the journal and the audit of one transfer in order"
    )]
    async fn apply(
        &self,
        zone: &Zone,
        held: Option<&Held>,
        fetched: &Fetched,
        address: SocketAddr,
        epoch: u64,
    ) -> Result<u32, FetchError> {
        let store_error = |error: ZoneError| FetchError {
            code: codes::TRANSFER_FAILED,
            detail: format!("the store refused the transfer: {error}"),
        };
        let cx = system();
        let stamp = Stamp::new(cx.now, cx.principal.clone());
        let view = self.zones.view(None).await.map_err(store_error)?;
        let before = scope_rrsets(view.as_ref(), zone.id).map_err(store_error)?;
        let after = target(zone, &before, fetched, &stamp)?;
        let serial = after
            .get(&(zone.name.clone(), Rtype::SOA))
            .and_then(super::soa_serial)
            .unwrap_or_default();
        let changes = diff(&before, &after);
        let kind = match fetched {
            Fetched::Delta { .. } => "ixfr",
            _ => "axfr",
        };
        let changed_records: usize = changes
            .iter()
            .map(|(old, new)| {
                old.as_ref().map_or(0, |(old, _)| old.rdata.len())
                    + new.as_ref().map_or(0, |new| new.rdata.len())
            })
            .sum();
        let (soa_change, others): (Vec<Change>, Vec<Change>) =
            changes.into_iter().partition(|(old, new)| {
                old.as_ref()
                    .is_some_and(|(old, _)| old.rtype == Rtype::SOA && old.name == zone.name)
                    || new
                        .as_ref()
                        .is_some_and(|new| new.rtype == Rtype::SOA && new.name == zone.name)
            });
        let chunks: Vec<&[Change]> = if others.len() + soa_change.len() <= CHUNK {
            vec![]
        } else {
            others.chunks(CHUNK).collect()
        };
        for chunk in &chunks {
            let mut batch = WriteBatch::for_request(&cx);
            batch.preconditions.push(tenko_store::fence(epoch));
            stage_changes(&mut batch, chunk).map_err(store_error)?;
            self.zones
                .store()
                .propose(batch)
                .await
                .map_err(|error| store_error(error.into()))?;
        }
        let mut batch = WriteBatch::for_request(&cx);
        batch.preconditions.push(tenko_store::fence(epoch));
        if chunks.is_empty() {
            stage_changes(&mut batch, &others).map_err(store_error)?;
        }
        stage_changes(&mut batch, &soa_change).map_err(store_error)?;
        let from = held.map(|held| held.serial);
        let journaled = match from {
            Some(from) if chunks.is_empty() && changed_records <= JOURNAL_MAX => {
                let diffs: Vec<records::Diff> = others
                    .iter()
                    .filter_map(|(old, new)| {
                        let key = old
                            .as_ref()
                            .map(|(old, _)| old.key())
                            .or_else(|| new.as_ref().map(RrSet::key))?;
                        Some(records::Diff {
                            key,
                            before: old.as_ref().map(|(old, _)| old.clone()),
                            after: new.clone(),
                        })
                    })
                    .collect();
                let (removed, added) = records::journal_diff(diffs.iter());
                let old_soa = before
                    .get(&(zone.name.clone(), Rtype::SOA))
                    .map(|(soa, _)| soa);
                let new_soa = after.get(&(zone.name.clone(), Rtype::SOA));
                let mut journal_removed: Vec<_> = old_soa
                    .into_iter()
                    .flat_map(super::journal_records)
                    .collect();
                journal_removed.extend(removed);
                let mut journal_added: Vec<_> = new_soa
                    .into_iter()
                    .flat_map(super::journal_records)
                    .collect();
                journal_added.extend(added);
                journal::stage_append(
                    &mut batch,
                    view.as_ref(),
                    self.zones.config().journal,
                    &tenko_core::dns::JournalEntry {
                        zone: zone.id,
                        scope: ScopeName::DEFAULT,
                        from_serial: from,
                        to_serial: serial,
                        revision: view.revision(),
                        at: stamp.at,
                        removed: journal_removed,
                        added: journal_added,
                    },
                )
                .map_err(store_error)?;
                true
            }
            _ => {
                journal::stage_reset(&mut batch, view.as_ref(), zone.id, &ScopeName::DEFAULT)
                    .map_err(store_error)?;
                false
            }
        };
        drop(view);
        let mut draft =
            AuditDraft::success(audit::ZONE_TRANSFER_IN, vec![ObjectRef::from(zone.id)])
                .with_context("zone", zone.name.as_str())
                .with_context("kind", kind)
                .with_context("primary", address.to_string())
                .with_context("serial", serial.to_string())
                .with_context("records", changed_records.to_string())
                .with_context("journal", if journaled { "entry" } else { "reset" });
        if let Some(from) = from {
            draft = draft.with_context("from_serial", from.to_string());
        }
        batch.audit(draft);
        self.zones
            .store()
            .propose(batch)
            .await
            .map_err(|error| store_error(error.into()))?;
        tracing::info!(zone = %zone.name, %address, kind, serial, records = changed_records, "zone transferred in");
        Ok(serial)
    }

    /// Creates the secondary zones of a catalog's new members and deletes those of members
    /// that left it.
    async fn sync_members(&self, catalog: &Zone) -> ZoneResult<()> {
        let view = self.zones.view(None).await?;
        let rrsets = scope_rrsets(view.as_ref(), catalog.id)?;
        let members = catalog_zone::members(
            &catalog.name,
            rrsets.values().flat_map(|(rrset, _)| {
                rrset
                    .rdata
                    .iter()
                    .map(move |rdata| (&rrset.name, rrset.rtype, rdata))
            }),
        )
        .map_err(|error| ZoneError::new(codes::TRANSFER_FAILED, 422, error.to_string()))?;
        let rows = ZoneService::zones(view.as_ref())?;
        drop(view);
        let marker = format!("{MEMBER_OF}{}", catalog.name);
        let cx = system();
        for member in &members {
            if rows.iter().any(|row| &row.zone.name == member) {
                continue;
            }
            let created = self
                .zones
                .create(
                    &cx,
                    NewZone {
                        name: member.clone(),
                        kind: ZoneKind::Secondary,
                        tenant: catalog.tenant,
                        scopes: Vec::new(),
                        serial: tenko_core::dns::SerialPolicy::default(),
                        soa: catalog.soa.clone(),
                        name_servers: Vec::new(),
                        transfer: tenko_core::dns::TransferPolicy::default(),
                        update: tenko_core::dns::UpdatePolicy::default(),
                        dnssec: tenko_core::dns::DnssecPolicy::default(),
                        source: catalog.source.clone(),
                        description: Some(marker.clone()),
                        reverse_of: None,
                        catalog: false,
                    },
                )
                .await;
            match created {
                Ok(written) => {
                    tracing::info!(zone = %member, catalog = %catalog.name, id = %written.zone.id, "catalog member zone created");
                }
                Err(error) => {
                    tracing::warn!(zone = %member, %error, "a catalog member zone could not be created");
                }
            }
        }
        for row in &rows {
            let zone = &row.zone;
            if zone.kind == ZoneKind::Secondary
                && zone.description.as_deref() == Some(marker.as_str())
                && !members.contains(&zone.name)
            {
                match self.zones.delete(&cx, zone.id, None).await {
                    Ok(_) => {
                        tracing::info!(zone = %zone.name, catalog = %catalog.name, "catalog member zone deleted");
                    }
                    Err(error) => {
                        tracing::warn!(zone = %zone.name, %error, "a catalog member zone could not be deleted");
                    }
                }
            }
        }
        Ok(())
    }
}

fn stage_changes(batch: &mut WriteBatch, changes: &[Change]) -> ZoneResult<()> {
    for (old, new) in changes {
        match (old, new) {
            (Some((old, revision)), Some(new)) => {
                batch.expect_typed(&RRSETS, &old.key(), Some(*revision));
                stage_put(batch, Some(old), new)?;
            }
            (Some((old, revision)), None) => {
                batch.expect_typed(&RRSETS, &old.key(), Some(*revision));
                stage_delete(batch, old);
            }
            (None, Some(new)) => {
                batch.expect_typed(&RRSETS, &new.key(), None);
                stage_put(batch, None, new)?;
            }
            (None, None) => {}
        }
    }
    Ok(())
}

#[async_trait::async_trait]
impl LeaderService for SecondaryService {
    fn name(&self) -> &'static str {
        "dns.transfer"
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        let inner = Arc::clone(&self.inner);
        let filter = || WatchFilter::tables([ZONES.name().clone()]);
        let mut stream = inner.zones.store().watch(None, filter()).ok();
        let mut running = tokio::task::JoinSet::new();
        let mut reconcile = true;
        let mut reconciled = std::time::Instant::now();
        loop {
            if reconcile || reconciled.elapsed() >= inner.settings.tick {
                if let Err(error) = inner.reconcile(epoch).await {
                    tracing::warn!(%error, "the secondary zones could not be read");
                }
                reconcile = false;
                reconciled = std::time::Instant::now();
            }
            for id in inner.take_due(inner.settings.concurrency) {
                running.spawn(Arc::clone(&inner).refresh(id, epoch));
            }
            inner.expire_due(epoch).await;
            let sleep = inner.sleep();
            let changed = async {
                match &mut stream {
                    Some(stream) => matches!(stream.next().await, Some(Ok(_))),
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                () = stop.cancelled() => {
                    running.abort_all();
                    inner.lock().values_mut().for_each(|zone| zone.running = false);
                    return Ok(());
                }
                () = inner.wake.notified() => {}
                alive = changed => {
                    reconcile = true;
                    if !alive {
                        stream = inner.zones.store().watch(None, filter()).ok();
                    }
                }
                Some(_) = running.join_next(), if !running.is_empty() => {}
                () = tokio::time::sleep(sleep) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests;
