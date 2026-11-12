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
//! The expiry counts from the last successful refresh, a transfer written or a copy found
//! current, and that time is stored per zone (`dns.transfer_state`, [`TransferStamp`]): a
//! restart or a change of leader reads it, so neither shortens a copy's life. A copy
//! without a stamp for its serial (written before the stamp existed, or restored without
//! it) cannot tell how old it is: it counts as refreshed when the term starts, once (the
//! stamp is written then), so it is never let go for want of a stamp. The rest of each
//! zone's state (each primary's last success and error, the next refresh) lives in the
//! memory of the service on the leader, rebuilt at each term start; every zone is
//! refreshed at once then. A primary's SOA whose expire is shorter than its refresh plus
//! retry is read with expire raised to that sum (RFC 1912 section 2.2), so the copy cannot
//! expire before its next refresh.
//!
//! At each term start and every hour the service also removes the records of zones that
//! no longer exist, which a delete cut short leaves behind.

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock, PoisonError},
    time::Duration,
};

use tenko_core::Revision;
use tenko_core::{
    ObjectRef, RequestCtx, SystemComponent, Timestamp,
    audit::AuditDraft,
    cluster::LeaderService,
    dns::{
        DnsName, KeyMeta, KeyName, Origin, PrimaryServer, Rdata, RecordData, RrSet, RrSetKey,
        Rtype, ScopeName, TransferStamp, Zone, ZoneId, ZoneKind, audit, codes,
        tables::{KEYS_META, RRSETS, TRANSFER_STATE, ZONES},
    },
    ipam::Stamp,
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, WatchFilter, WriteBatch};
use tokio::task::{JoinError, JoinSet};
use tokio_util::sync::CancellationToken;

use super::{
    NewZone, ZoneError, ZoneResult, ZoneService, follow::Follow, journal, records, rrset_range,
    stage_delete, stage_put,
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

/// Members a secondary catalog zone may have; a catalog with more changes nothing until it
/// is back under the bound.
pub const CATALOG_MEMBERS_MAX: usize = 10_000;

/// The stable code of a transfer whose serial is older than the copy's (RFC 1982): it is
/// not applied, unless an operator asks for the transfer through the API.
pub const TRANSFER_OLDER_SERIAL: &str = inbound::OLDER_SERIAL;

/// The first pause after a refresh that an unsigned NOTIFY started, before another unsigned
/// NOTIFY may start one.
pub const NOTIFY_QUIET_MIN: Duration = Duration::from_secs(2);

/// The longest pause: it doubles from [`NOTIFY_QUIET_MIN`] while unsigned NOTIFY messages
/// bring nothing new, and returns to it when a refresh brings a new serial.
pub const NOTIFY_QUIET_MAX: Duration = Duration::from_secs(300);

/// How often the leader looks for the records of zones that no longer exist.
pub const ORPHAN_SWEEP: Duration = Duration::from_secs(3600);

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
    /// A refresh asked for while a transfer ran.
    requested: Option<Requested>,
    /// The backoff from unsigned NOTIFY messages.
    backoff: Backoff,
    /// An operator asked for the refresh through the API: it applies a transfer whose
    /// serial is older than the copy's.
    forced: bool,
}

/// The backoff from unsigned NOTIFY messages (RFC 1996 section 3.10: their source is not
/// authenticated).
#[derive(Debug, Clone)]
struct Backoff {
    /// Unsigned NOTIFY messages start no refresh before this time.
    quiet_until: Option<Timestamp>,
    /// The pause after the next refresh an unsigned NOTIFY starts.
    quiet: Duration,
    /// The coming (or running) refresh was asked for by unsigned NOTIFY messages only.
    by_unsigned: bool,
    /// The request kept while a transfer ran came from unsigned NOTIFY messages only.
    requested_unsigned: bool,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            quiet_until: None,
            quiet: NOTIFY_QUIET_MIN,
            by_unsigned: false,
            requested_unsigned: false,
        }
    }
}

/// A refresh asked for while a transfer of the zone ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Requested {
    /// NOTIFY messages up to this serial (the highest one announced).
    Serial(u32),
    /// A request without a serial: a NOTIFY without SOA, or the API.
    Any,
}

impl ZoneState {
    /// The state of a zone the service starts to follow.
    fn new(serial: Option<u32>, primaries: Vec<PrimaryStatus>, expires: Option<Timestamp>) -> Self {
        Self {
            serial,
            primaries,
            next_refresh: Timestamp::now(),
            expires,
            running: false,
            requested: None,
            backoff: Backoff::default(),
            forced: false,
        }
    }

    /// A signed NOTIFY or a request through the API: the zone is due now. While a transfer
    /// runs it may already have read the primary's old copy, so the request is kept and the
    /// zone refreshed once more when it ends (RFC 1996 section 4.4).
    fn request(&mut self, serial: Option<u32>, now: Timestamp) {
        self.backoff.by_unsigned = false;
        self.backoff.requested_unsigned = false;
        self.keep(serial, now);
    }

    /// An unsigned NOTIFY: like [`ZoneState::request`], but it starts no refresh before
    /// the quiet time that the last one it started left. It is never dropped: while a
    /// transfer runs it is kept, and while the quiet time lasts the zone is due when it
    /// ends.
    fn request_unsigned(&mut self, serial: Option<u32>, now: Timestamp) {
        let at = self.backoff.quiet_until.map_or(now, |quiet| quiet.max(now));
        if self.running {
            if self.requested.is_none() {
                self.backoff.requested_unsigned = true;
            }
            let next = self.next_refresh;
            self.keep(serial, now);
            self.next_refresh = next;
        } else {
            if self.next_refresh > now {
                self.backoff.by_unsigned = true;
            }
            self.next_refresh = self.next_refresh.min(at);
        }
    }

    /// An operator's request through the API: due now, and it may apply an older serial.
    fn force(&mut self, now: Timestamp) {
        self.forced = true;
        self.request(None, now);
    }

    /// Keeps a request while a transfer runs; makes the zone due now otherwise.
    fn keep(&mut self, serial: Option<u32>, now: Timestamp) {
        self.next_refresh = now;
        if self.running {
            self.requested = Some(match (self.requested, serial) {
                (Some(Requested::Serial(kept)), Some(serial))
                    if crate::xfr::out::serial_ge(kept, serial) =>
                {
                    Requested::Serial(kept)
                }
                (Some(Requested::Any), _) | (_, None) => Requested::Any,
                (_, Some(serial)) => Requested::Serial(serial),
            });
        }
    }

    /// The end of a transfer: the next refresh after the SOA's timers, or at once when a
    /// request came while it ran that the serial reached does not cover (after the quiet
    /// time when unsigned NOTIFY messages alone asked for it).
    fn finish(&mut self, outcome: Option<Refreshed>, now: Timestamp, timers: Timers) {
        self.running = false;
        let moved = matches!(outcome, Some(Refreshed::Serial { serial, .. }) if self.serial != Some(serial));
        if moved {
            self.backoff.quiet = NOTIFY_QUIET_MIN;
        } else if self.backoff.by_unsigned {
            self.backoff.quiet = (self.backoff.quiet * 2).min(NOTIFY_QUIET_MAX);
        }
        if self.backoff.by_unsigned || moved {
            self.backoff.quiet_until = now.checked_add(self.backoff.quiet);
        }
        self.backoff.by_unsigned = false;
        match outcome {
            Some(Refreshed::Serial { serial, at }) => {
                self.serial = Some(serial);
                self.next_refresh = after(now, timers.refresh);
                // From the stored stamp, so that a restart computes the same expiry.
                self.expires = Some(after(at, timers.expire));
            }
            Some(Refreshed::Failed) | None => {
                let retry = if self.serial.is_some() {
                    timers.retry
                } else {
                    timers.retry.min(60)
                };
                self.next_refresh = after(now, retry);
            }
        }
        if let Some(requested) = self.requested.take() {
            let covered = match requested {
                Requested::Serial(wanted) => self
                    .serial
                    .is_some_and(|held| crate::xfr::out::serial_ge(held, wanted)),
                Requested::Any => false,
            };
            if !covered {
                let timer = self.next_refresh;
                self.next_refresh = now;
                if self.backoff.requested_unsigned {
                    self.backoff.by_unsigned = true;
                    if let Some(quiet) = self.backoff.quiet_until {
                        // After the pause, or on the timer when that comes sooner.
                        self.next_refresh = timer.min(quiet.max(now));
                    }
                }
            }
        }
        self.backoff.requested_unsigned = false;
    }
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

    /// The timers of an SOA, and the expire it gave when that was raised to refresh plus
    /// retry.
    fn read(rdata: &Rdata) -> (Self, Option<u32>) {
        let Ok(RecordData::Soa {
            refresh,
            retry,
            expire,
            ..
        }) = rdata.decode(Rtype::SOA)
        else {
            return (Self::DEFAULT, None);
        };
        let (refresh, retry) = (refresh.max(1), retry.max(1));
        let least = refresh.saturating_add(retry);
        let timers = Self {
            refresh,
            retry,
            expire: expire.max(least),
        };
        (timers, (expire < least).then_some(expire))
    }

    /// Says that the SOA of `zone` gave the expire `given`, raised to these timers.
    fn log_raised(self, zone: &DnsName, given: u32) {
        tracing::info!(%zone, given, expire = self.expire, refresh = self.refresh, retry = self.retry, "the primary's SOA expires before its next refresh; the copy keeps it for refresh plus retry");
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
#[derive(Debug, Clone, Copy)]
enum Refreshed {
    /// The copy is current or was replaced: its serial, and the time stored as its last
    /// successful refresh.
    Serial { serial: u32, at: Timestamp },
    /// Every primary failed.
    Failed,
}

/// The copy of a secondary zone in the store: its SOA and its stamp.
#[derive(Debug, Clone, Copy)]
struct HeldCopy {
    serial: u32,
    timers: Timers,
    /// The last successful refresh, when the stamp is that of this serial.
    refreshed: Option<Timestamp>,
    /// The expire the SOA gave, when it was raised to refresh plus retry.
    given_expire: Option<u32>,
}

impl HeldCopy {
    fn expires(&self) -> Option<Timestamp> {
        self.refreshed.map(|at| after(at, self.timers.expire))
    }
}

/// The copy a secondary zone holds, if any.
fn held_copy(view: &dyn ReadView, zone: &Zone) -> ZoneResult<Option<HeldCopy>> {
    let Some((soa, _)) = view.get_typed(&RRSETS, &soa_key(zone))? else {
        return Ok(None);
    };
    let (Some(serial), Some(rdata)) = (super::soa_serial(&soa), soa.rdata.first()) else {
        return Ok(None);
    };
    let (timers, given_expire) = Timers::read(rdata);
    let refreshed = view
        .get_typed(&TRANSFER_STATE, &zone.id)?
        .filter(|(stamp, _)| stamp.serial == serial)
        .map(|(stamp, _)| stamp.refreshed);
    Ok(Some(HeldCopy {
        serial,
        timers,
        refreshed,
        given_expire,
    }))
}

fn soa_key(zone: &Zone) -> RrSetKey {
    RrSetKey {
        zone: zone.id,
        scope: ScopeName::DEFAULT,
        name: zone.name.clone(),
        rtype: Rtype::SOA,
    }
}

/// Stores `at` as the last successful refresh of the copy at `serial`.
fn stage_stamp(batch: &mut WriteBatch, zone: ZoneId, serial: u32, at: Timestamp) -> ZoneResult<()> {
    let stamp = TransferStamp {
        zone,
        serial,
        refreshed: at,
    };
    batch.put_typed(&TRANSFER_STATE, &zone, &stamp)?;
    Ok(())
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
        let held = held_copy(view, zone)?;
        Ok(TransferState {
            serial: held.map(|held| held.serial),
            primaries: statuses(zone),
            next_refresh: None,
            expires: held.and_then(|held| held.expires()),
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
            state.force(Timestamp::now());
        }
        self.inner.wake.notify_one();
        self.state(view.as_ref(), &zone)
    }
}

/// Each primary of a zone, with no refresh seen yet.
fn statuses(zone: &Zone) -> Vec<PrimaryStatus> {
    primaries_of(zone)
        .into_iter()
        .map(|address| PrimaryStatus {
            address,
            last_success: None,
            last_error: None,
            detail: None,
        })
        .collect()
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
    fn notified(&self, zone: ZoneId, from: std::net::IpAddr, serial: Option<u32>, signed: bool) {
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
            if signed {
                entry.request(serial, Timestamp::now());
            } else {
                entry.request_unsigned(serial, Timestamp::now());
            }
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
        principal: None,
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
    /// gone ones are dropped; the primary catalog zones get their member lists. The store is
    /// read before the state's lock is taken, because the NOTIFY path takes that lock on a
    /// UDP worker, which must not wait.
    async fn reconcile(&self, epoch: u64) -> ZoneResult<()> {
        let view = self.zones.view(None).await?;
        let rows = ZoneService::zones(view.as_ref())?;
        let secondaries: Vec<&Zone> = rows
            .iter()
            .map(|row| &row.zone)
            .filter(|zone| zone.kind == ZoneKind::Secondary)
            .collect();
        let known: Vec<ZoneId> = self.lock().keys().copied().collect();
        let now = Timestamp::now();
        let mut fresh = Vec::new();
        let mut unstamped = Vec::new();
        for zone in secondaries.iter().filter(|zone| !known.contains(&zone.id)) {
            let held = held_copy(view.as_ref(), zone)?;
            if let Some(held) = held
                && let Some(given) = held.given_expire
            {
                held.timers.log_raised(&zone.name, given);
            }
            let expires = held.map(|held| {
                held.expires().unwrap_or_else(|| {
                    unstamped.push((zone.id, held.serial));
                    after(now, held.timers.expire)
                })
            });
            let state = ZoneState::new(held.map(|held| held.serial), statuses(zone), expires);
            fresh.push((zone.id, state));
        }
        if !unstamped.is_empty() {
            self.stamp_unknown(&unstamped, now, epoch).await;
        }
        {
            let mut state = self.lock();
            state.retain(|id, _| secondaries.iter().any(|zone| zone.id == *id));
            for zone in &secondaries {
                let Some(entry) = state.get_mut(&zone.id) else {
                    continue;
                };
                if entry
                    .primaries
                    .iter()
                    .map(|p| p.address)
                    .ne(primaries_of(zone))
                {
                    entry.primaries = statuses(zone);
                    entry.next_refresh = now;
                }
            }
            for (id, entry) in fresh {
                state.entry(id).or_insert(entry);
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

    /// How long until the next zone is due or expires, at most the tick. A zone whose
    /// refresh runs is left out: its end wakes the loop.
    fn sleep(&self) -> Duration {
        let now = Timestamp::now();
        self.lock()
            .values()
            .filter(|zone| !zone.running)
            .flat_map(|zone| [Some(zone.next_refresh), zone.expires])
            .flatten()
            .map(|at| at.saturating_since(now))
            .min()
            .unwrap_or(self.settings.tick)
            .clamp(Duration::from_millis(50), self.settings.tick)
    }

    /// The copies past their expiry: their records go. A copy whose refresh runs is left to
    /// the refresh's outcome.
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
                batch.delete_typed(&TRANSFER_STATE, &id);
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

    /// Stores the term start as the last refresh of copies that have no stamp for their
    /// serial, so that the grace they get is given once.
    async fn stamp_unknown(&self, copies: &[(ZoneId, u32)], at: Timestamp, epoch: u64) {
        tracing::info!(
            zones = copies.len(),
            "secondary copies without a record of their last refresh count as refreshed now"
        );
        let cx = system();
        for chunk in copies.chunks(CHUNK) {
            let mut batch = WriteBatch::for_request(&cx);
            batch.preconditions.push(tenko_store::fence(epoch));
            for (zone, serial) in chunk {
                if let Err(error) = stage_stamp(&mut batch, *zone, *serial, at) {
                    tracing::warn!(%zone, %error, "the refresh record of a secondary copy could not be staged");
                }
            }
            if let Err(error) = self.zones.store().propose_background(batch).await {
                tracing::warn!(%error, "the refresh records of secondary copies could not be written; they count from the next term start");
            }
        }
    }

    /// The end of a zone's refresh: its state moves by the outcome (`None` when the refresh
    /// could not run or panicked) and the timers of the SOA it holds now.
    async fn finish(&self, id: ZoneId, outcome: Option<Refreshed>) {
        let timers = match self.zones.view(None).await {
            Ok(view) => ZoneService::zone(view.as_ref(), id)
                .ok()
                .and_then(|row| held_copy(view.as_ref(), &row.zone).ok().flatten()),
            Err(_) => None,
        }
        .map_or(Timers::DEFAULT, |held| held.timers);
        if let Some(zone) = self.lock().get_mut(&id) {
            zone.finish(outcome, Timestamp::now(), timers);
        }
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

    /// The start of a term. The state of an earlier term is stale (another leader may have
    /// refreshed since): the term reads every zone from the store again.
    fn begin(&self) {
        self.lock().clear();
    }

    /// One look of the term: expiry first, so that a copy past it goes before a new refresh
    /// of it could start; then the refreshes that are due.
    async fn pass(self: &Arc<Self>, epoch: u64, refreshes: &mut Refreshes) {
        self.expire_due(epoch).await;
        for id in self.take_due(self.settings.concurrency) {
            refreshes.spawn(self, id, epoch);
        }
    }

    /// Removes the records of zones that no longer exist (a delete whose purge failed or
    /// was cut short).
    async fn sweep(&self) {
        match self.zones.purge_orphans().await {
            Ok(0) => {}
            Ok(zones) => {
                tracing::info!(zones, "the records left by deleted zones were removed");
            }
            Err(error) => {
                tracing::warn!(%error, "the records left by deleted zones could not be removed; the next sweep tries again");
            }
        }
    }

    /// Records that the copy at `serial` was found current now: the stamp alone, in the
    /// background class (no RRset changes, and nobody waits on it).
    async fn confirm(&self, id: ZoneId, serial: u32, epoch: u64) -> Result<Timestamp, FetchError> {
        let failed = |error: &dyn std::fmt::Display| FetchError {
            code: codes::TRANSFER_FAILED,
            detail: format!("the store refused the record of the refresh: {error}"),
        };
        let cx = system();
        let mut batch = WriteBatch::for_request(&cx);
        batch.preconditions.push(tenko_store::fence(epoch));
        stage_stamp(&mut batch, id, serial, cx.now).map_err(|error| failed(&error))?;
        self.zones
            .store()
            .propose_background(batch)
            .await
            .map_err(|error| failed(&error))?;
        Ok(cx.now)
    }

    async fn try_refresh(&self, id: ZoneId, epoch: u64) -> Option<Refreshed> {
        let view = self.zones.view(None).await.ok()?;
        let zone = ZoneService::zone(view.as_ref(), id).ok()?.zone;
        let forced = self
            .lock()
            .get_mut(&id)
            .is_some_and(|zone| std::mem::take(&mut zone.forced));
        // One deadline for the whole refresh, whichever primaries it tries.
        let deadline = tokio::time::Instant::now() + self.settings.limits.deadline;
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
            let fetched = match self
                .fetch(&primary, &zone.name, held.as_ref(), forced, deadline)
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
                let serial = held.as_ref().map_or(serial, |held| held.serial);
                match self.confirm(id, serial, epoch).await {
                    Ok(at) => {
                        self.set_primary(id, address, Ok(()));
                        return Some(Refreshed::Serial { serial, at });
                    }
                    Err(error) => {
                        tracing::warn!(zone = %zone.name, %address, %error, "a current copy could not be recorded as refreshed");
                        self.set_primary(id, address, Err(&error));
                        continue;
                    }
                }
            }
            if let Err(error) = older_serial(held.as_ref(), &fetched, forced) {
                tracing::warn!(zone = %zone.name, %address, %error, "a zone transfer was not applied");
                self.set_primary(id, address, Err(&error));
                continue;
            }
            match self
                .apply(&zone, held.as_ref(), &fetched, address, epoch)
                .await
            {
                Ok((serial, at)) => {
                    self.set_primary(id, address, Ok(()));
                    if zone.catalog
                        && let Err(error) = self.sync_members(&zone).await
                    {
                        tracing::warn!(zone = %zone.name, %error, "the members of a catalog zone could not be followed");
                    }
                    return Some(Refreshed::Serial { serial, at });
                }
                Err(error) => {
                    tracing::warn!(zone = %zone.name, %address, %error, "a zone transfer could not be written");
                    self.set_primary(id, address, Err(&error));
                }
            }
        }
        Some(Refreshed::Failed)
    }

    /// One transfer from `primary` within `deadline`. "Transfer now" (`forced`) takes a
    /// primary whose serial went back: its IXFR answer is the older SOA alone, so the zone
    /// is then asked for whole.
    async fn fetch(
        &self,
        primary: &Primary,
        apex: &DnsName,
        held: Option<&Held>,
        forced: bool,
        deadline: tokio::time::Instant,
    ) -> Result<Fetched, FetchError> {
        let limits = self.settings.limits;
        let result = inbound::fetch_until(primary, apex, held, limits, deadline).await;
        if forced && matches!(&result, Err(error) if error.code == inbound::OLDER_SERIAL) {
            return inbound::fetch_until(primary, apex, None, limits, deadline).await;
        }
        result
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
    ) -> Result<(u32, Timestamp), FetchError> {
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
        if held.is_none_or(|held| held.serial != serial)
            && let Some(rdata) = after
                .get(&(zone.name.clone(), Rtype::SOA))
                .and_then(|soa| soa.rdata.first())
            && let (timers, Some(given)) = Timers::read(rdata)
        {
            timers.log_raised(&zone.name, given);
        }
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
        stage_stamp(&mut batch, zone.id, serial, stamp.at).map_err(store_error)?;
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
        Ok((serial, stamp.at))
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
        let members = admit_members(catalog, members, &rows, CATALOG_MEMBERS_MAX)
            .map_err(|detail| ZoneError::new(codes::TRANSFER_FAILED, 422, detail))?;
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

/// Refuses a transfer that would take the copy back to an older serial (RFC 1982), a
/// replayed or stale answer, unless an operator asked for it (`forced`). The same serial is
/// applied: it is the same version, sent again.
fn older_serial(held: Option<&Held>, fetched: &Fetched, forced: bool) -> Result<(), FetchError> {
    let (Some(held), Some(serial)) = (held, fetched.serial()) else {
        return Ok(());
    };
    if forced || crate::xfr::out::serial_ge(serial, held.serial) {
        return Ok(());
    }
    Err(inbound::older(serial, held.serial))
}

/// The members of a catalog that may become zones (RFC 9432 section 7: a consumer
/// restricts what a catalog may add): not the root or a top-level domain, not the catalog
/// itself or a name below it, not a name at, below or above a zone of another tenant, not
/// a name below a zone of the same tenant that is not one of this catalog's members; at
/// most [`CATALOG_MEMBERS_MAX`].
///
/// # Errors
///
/// A catalog with more members than the bound: nothing is created or deleted.
fn admit_members(
    catalog: &Zone,
    members: Vec<DnsName>,
    rows: &[super::ZoneRow],
    max: usize,
) -> Result<Vec<DnsName>, String> {
    let marker = format!("{MEMBER_OF}{}", catalog.name);
    if members.len() > max {
        return Err(format!(
            "the catalog lists {} members, more than the bound of {max}; its member zones are left as they are",
            members.len()
        ));
    }
    Ok(members
        .into_iter()
        .filter(|member| {
            let refused = if member.is_root() {
                Some("the root")
            } else if member.label_count() < 2 {
                Some("a top-level domain")
            } else if *member == catalog.name || member.is_subdomain_of(&catalog.name) {
                Some("the catalog zone itself or a name below it")
            } else if rows.iter().any(|row| {
                // A root zone holds every name; it says nothing about a member.
                !row.zone.name.is_root()
                    && row.zone.tenant != catalog.tenant
                    && (member.is_subdomain_of(&row.zone.name)
                        || row.zone.name.is_subdomain_of(member))
            }) {
                Some("a name at, below or above a zone of another tenant")
            } else if rows.iter().any(|row| {
                !row.zone.name.is_root()
                    && row.zone.tenant == catalog.tenant
                    && row.zone.description.as_deref() != Some(marker.as_str())
                    && row.zone.name != *member
                    && member.is_subdomain_of(&row.zone.name)
            }) {
                Some("a name below a zone of the tenant that the catalog does not hold")
            } else {
                None
            };
            if let Some(reason) = refused {
                tracing::warn!(catalog = %catalog.name, %member, "a catalog member was not added: {reason}");
            }
            refused.is_none()
        })
        .collect())
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

/// The refreshes that run, each with its zone, so that a refresh that panics still ends
/// and frees its zone and its slot.
#[derive(Default)]
struct Refreshes {
    set: JoinSet<(ZoneId, Option<Refreshed>)>,
    zones: HashMap<tokio::task::Id, ZoneId>,
}

impl Refreshes {
    fn spawn(&mut self, inner: &Arc<Inner>, id: ZoneId, epoch: u64) {
        let inner = Arc::clone(inner);
        let task = self
            .set
            .spawn(async move { (id, inner.try_refresh(id, epoch).await) });
        self.zones.insert(task.id(), id);
    }

    fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// The next refresh to end, with its zone and outcome; no outcome when it panicked.
    /// Cancel-safe.
    async fn next(&mut self) -> Option<(ZoneId, Option<Refreshed>)> {
        loop {
            match self.set.join_next_with_id().await? {
                Ok((task, (id, outcome))) => {
                    self.zones.remove(&task);
                    return Some((id, outcome));
                }
                Err(error) => {
                    if let Some(id) = self.ended(&error) {
                        return Some((id, None));
                    }
                }
            }
        }
    }

    fn ended(&mut self, error: &JoinError) -> Option<ZoneId> {
        let id = self.zones.remove(&error.id())?;
        if error.is_panic() {
            tracing::error!(zone = %id, "a refresh of a secondary zone panicked; the zone is retried on its timer");
        }
        Some(id)
    }

    fn abort(&mut self) {
        self.set.abort_all();
        self.zones.clear();
    }
}

#[async_trait::async_trait]
impl LeaderService for SecondaryService {
    fn name(&self) -> &'static str {
        "dns.transfer"
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        let inner = Arc::clone(&self.inner);
        inner.begin();
        let mut follow = Follow::new(
            Arc::clone(inner.zones.store()),
            WatchFilter::tables([ZONES.name().clone()]),
            "the secondary zones",
        );
        let mut refreshes = Refreshes::default();
        let mut reconcile = false;
        let mut reconciled = std::time::Instant::now();
        let mut swept: Option<std::time::Instant> = None;
        loop {
            if swept.is_none_or(|at| at.elapsed() >= ORPHAN_SWEEP) {
                inner.sweep().await;
                swept = Some(std::time::Instant::now());
            }
            if reconcile || reconciled.elapsed() >= inner.settings.tick {
                if let Err(error) = inner.reconcile(epoch).await {
                    tracing::warn!(%error, "the secondary zones could not be read");
                }
                reconcile = false;
                reconciled = std::time::Instant::now();
            }
            inner.pass(epoch, &mut refreshes).await;
            let sleep = inner.sleep();
            tokio::select! {
                () = stop.cancelled() => break,
                () = inner.wake.notified() => {}
                _ = follow.next() => reconcile = true,
                Some((id, outcome)) = refreshes.next(), if !refreshes.is_empty() => {
                    inner.finish(id, outcome).await;
                }
                () = tokio::time::sleep(sleep) => {}
            }
        }
        refreshes.abort();
        inner.lock().clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod role_tests;
