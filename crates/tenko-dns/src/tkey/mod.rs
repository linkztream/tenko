//! TKEY for GSS-TSIG (RFC 2930, RFC 3645; DNS-28, CON-03; identity plan section 3.3):
//! the negotiation of security contexts with Kerberos inside SPNEGO, the context table of
//! the node with its bounds, and the handle through which the node's Kerberos keys reach
//! the acceptor.
//!
//! | Module | What |
//! |---|---|
//! | [`context`] | a security context: the identity, the MIC keys, the sequence window |
//! | [`wire`] | the TKEY query and answer on the wire |
//! | [`refusals`] | the acceptor's refusals, aggregated per source before a finding |
//!
//! **Where.** The query path recognizes a TKEY query by the type of its question and hands
//! it to the update path ([`crate::update::UpdatePath`]) off the worker, after the same
//! admission an UPDATE passes: the parse, the cookie where the profile requires one, the
//! rate limiter, and the update path's bounds in flight per node and per client. There
//! [`Tkey::answer`] runs it. Over UDP, whose source can be spoofed, every TKEY query is
//! answered with TC before any work, so that negotiations run over TCP. A node without
//! keys answers REFUSED without touching the acceptor.
//!
//! **Modes.** Mode 3 (GSS-API negotiation) and mode 5 (deletion, signed by the context it
//! deletes) are taken over TCP (UDP answers TC); every other mode is answered BADMODE, an
//! algorithm other than `gss-tsig` BADALG, a key name in use (an established context, a negotiation
//! from another client, a TSIG key) BADNAME. A refused negotiation is answered with the
//! TKEY error BADKEY and no token.
//!
//! **The table.** Per node, in memory, keyed by the key name in lowercase wire form:
//! negotiations in flight and established contexts. A negotiation is dropped when it is
//! not complete within [`NEGOTIATION_TIMEOUT_SECS`]; at most
//! [`GssSettings::per_client_max`] are in flight from one client (an IPv4 address or an
//! IPv6 /64), and one more is refused before any Kerberos work, counted as `limit`; at
//! [`GssSettings::negotiating_max`] on the node the oldest negotiation waiting for its next
//! leg leaves for the new one (counted as `limit`), so that legs which prove nothing
//! cannot hold every place. A negotiation completed after the keys were cleared or
//! replaced, or after its place was given up, keeps no context. An
//! established context expires at the earlier of the ticket's end and
//! [`GssSettings::context_max_secs`] after its establishment; when
//! [`GssSettings::contexts_max`] are held, the expired ones go and then the one idle
//! longest. Contexts are neither stored nor replicated: a restart drops them and the
//! clients negotiate again (BADKEY on the old context).
//!
//! **The seam with the account's lifecycle.** The keys of the account arrive through a
//! [`KeyHandle`]: the controller's watcher of the vault secret `dns.krb` calls
//! [`KeyHandle::install`] with the account's realm, its SPNs and its key set when the
//! secret appears or changes, and [`KeyHandle::clear`] when it goes. An install with the
//! same realm and SPNs replaces the keys and keeps the replay cache; another realm or SPN
//! list starts a new acceptor. A clear drops the acceptor and every context.
//!
//! Metrics: `tenko_dns_tkey_total{outcome}`, `tenko_dns_gss_contexts{state}` and
//! `tenko_dns_gss_establish_seconds` ([`crate::metrics`]). Audit: `dns.gss.refuse` at most
//! once a minute per client, with the reason; never a token or a key.

pub mod context;
pub mod refusals;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod wire;

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError, RwLock},
    time::Instant,
};

use tenko_core::{
    audit::AuditDraft,
    dns::{PrincipalName, QueryTransport, Realm, audit, codes, findings},
};
use tenko_krb::{
    acceptor::{Acceptor, Clock, Config, Context, KrbTime, Negotiation, Service, Step},
    keys::KeySet,
};

pub use self::{
    context::{ContextParts, GssContext, GssIdentity, Role},
    refusals::GssFinding,
};
use self::{
    refusals::{Refusals, Source},
    wire::{TkeyAnswer, TkeyQuery, error, mode},
};
use crate::{
    authoritative::rcode,
    metrics::{GSS_CONTEXT_GAUGE, GSS_ESTABLISH_HISTOGRAM, TKEY_COUNTER, TKEY_OUTCOMES},
    rate::limiter::prefix_bits,
    respond::Conn,
    tsig::{self, GSS_TSIG, KeySource, Keyring, MacKey, Signer},
    wire::{MAX_MESSAGE_LEN, SERVER_UDP_PAYLOAD},
    xfr::TransferAudit,
};

/// Seconds a negotiation may take before it is dropped (identity plan section 3.3).
pub const NEGOTIATION_TIMEOUT_SECS: u64 = 30;

/// How often the established contexts are swept for expired ones, at most.
const SWEEP_SECS: u64 = 60;

/// The bounds of the context table and the acceptor's skew (`[dns.gss]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GssSettings {
    /// Seconds an established context lives at most.
    pub context_max_secs: u64,
    /// Established contexts on the node at most.
    pub contexts_max: usize,
    /// Negotiations in flight on the node at most.
    pub negotiating_max: usize,
    /// Negotiations in flight from one client at most.
    pub per_client_max: usize,
    /// Seconds of clock skew the acceptor allows.
    pub skew_secs: u64,
}

impl Default for GssSettings {
    /// The defaults of the Standard profile.
    fn default() -> Self {
        Self {
            context_max_secs: 3_600,
            contexts_max: 10_000,
            negotiating_max: 1_000,
            per_client_max: 32,
            skew_secs: 300,
        }
    }
}

/// The system clock, for the acceptor and the table.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> KrbTime {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        KrbTime::from_unix_nanos(i128::try_from(nanos).unwrap_or(i128::MAX))
    }
}

/// The TKEY handler's part of the node's status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GssReport {
    /// Negotiations in flight.
    pub negotiating: u64,
    /// Established contexts.
    pub established: u64,
    /// Negotiations refused in the last hour (a refusal of the acceptor, a bound, a name in
    /// use).
    pub refused_last_hour: u64,
    /// The findings the refusals raise.
    pub findings: Vec<GssFinding>,
}

/// Why a key set was not installed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InstallError {
    /// No SPN, or one that is not `service/host` without a realm.
    #[error("invalid service principal name {0:?}: write service/host without a realm")]
    Spn(String),
    /// The key set holds no key.
    #[error("the key set holds no key; clear the acceptor instead")]
    NoKeys,
}

struct Installed {
    realm: Realm,
    spns: Vec<String>,
    service: Arc<Service>,
}

struct Negotiating {
    /// `None` while a leg is being stepped.
    negotiation: Option<Negotiation>,
    source: Source,
    started: u64,
    arrived: Instant,
    /// The order of admission, oldest first.
    order: u64,
}

#[derive(Default)]
struct Table {
    established: HashMap<Box<[u8]>, Arc<GssContext>>,
    negotiating: HashMap<Box<[u8]>, Negotiating>,
    per_source: HashMap<Source, usize>,
    swept: u64,
    admitted: u64,
}

impl Table {
    fn gauges(&self) {
        GSS_CONTEXT_GAUGE.set_total(0, self.negotiating.len() as u64);
        GSS_CONTEXT_GAUGE.set_total(1, self.established.len() as u64);
    }

    fn release(&mut self, source: Source) {
        if let Some(count) = self.per_source.get_mut(&source) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_source.remove(&source);
            }
        }
    }

    fn remove_negotiation(&mut self, name: &[u8]) -> Option<Negotiating> {
        let removed = self.negotiating.remove(name)?;
        self.release(removed.source);
        Some(removed)
    }

    fn drop_stale_negotiations(&mut self, now: u64) {
        let stale: Vec<Box<[u8]>> = self
            .negotiating
            .iter()
            .filter(|(_, n)| now.saturating_sub(n.started) >= NEGOTIATION_TIMEOUT_SECS)
            .map(|(name, _)| name.clone())
            .collect();
        for name in stale {
            self.remove_negotiation(&name);
        }
    }

    fn sweep(&mut self, now: u64) {
        if now.saturating_sub(self.swept) < SWEEP_SECS {
            return;
        }
        self.swept = now;
        self.established.retain(|_, context| !context.expired(now));
    }

    fn insert(&mut self, context: Arc<GssContext>, max: usize, now: u64) {
        if self.established.len() >= max {
            self.established.retain(|_, held| !held.expired(now));
        }
        while self.established.len() >= max.max(1) {
            let Some(idle) = self
                .established
                .iter()
                .min_by_key(|(_, held)| held.last_used())
                .map(|(name, _)| name.clone())
            else {
                break;
            };
            self.established.remove(&idle);
        }
        self.established
            .insert(Box::from(context.name_wire()), context);
    }
}

/// The TKEY handler and the GSS-TSIG contexts of a node.
pub struct Tkey {
    settings: GssSettings,
    clock: Arc<dyn Clock>,
    acceptor: RwLock<Option<Installed>>,
    table: Mutex<Table>,
    refusals: Mutex<Refusals>,
    /// Refused negotiations per minute of the last hour: (minute, count).
    minutes: Mutex<[(u64, u64); 60]>,
}

impl std::fmt::Debug for Tkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tkey")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

/// The handle through which the account's keys reach the acceptor of the node (the seam
/// with the account's lifecycle; see the module documentation). Cloning it is cheap.
#[derive(Clone)]
pub struct KeyHandle(Arc<Tkey>);

impl std::fmt::Debug for KeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("KeyHandle").finish_non_exhaustive()
    }
}

impl KeyHandle {
    /// Installs the account's key set with its realm and SPNs (`DNS/<fqdn>`, written
    /// `service/host`), or replaces the one installed: with the same realm and SPNs only
    /// the keys change and the replay cache stays; otherwise a new acceptor starts, which
    /// takes authenticators from after this moment only. Established contexts stay until
    /// they expire.
    ///
    /// # Errors
    ///
    /// [`InstallError`] for an SPN that is not `service/host` or an empty key set; what
    /// was installed before stays.
    pub fn install(&self, realm: Realm, spns: &[String], keys: KeySet) -> Result<(), InstallError> {
        self.0.install(realm, spns, keys)
    }

    /// Removes the keys: TKEY is answered REFUSED from now on, and every negotiation and
    /// established context is dropped.
    pub fn clear(&self) {
        self.0.clear();
    }

    /// The realm and SPNs installed, if any.
    pub fn installed(&self) -> Option<(Realm, Vec<String>)> {
        self.0.installed()
    }
}

// WP13.2: the seam with the account's lifecycle: its watcher installs the keys here.
impl crate::zone::kerberos::KeySink for KeyHandle {
    fn install(&self, realm: Realm, spns: &[String], keys: KeySet) -> Result<(), String> {
        KeyHandle::install(self, realm, spns, keys).map_err(|error| error.to_string())
    }

    fn clear(&self) {
        KeyHandle::clear(self);
    }

    fn installed(&self) -> Option<(Realm, Vec<String>)> {
        KeyHandle::installed(self)
    }
}
// WP13.2: end.

fn source_of(client: IpAddr) -> Source {
    prefix_bits(client, 32, 64)
}

fn count(outcome: &str) {
    if let Some(index) = TKEY_OUTCOMES.iter().position(|known| *known == outcome) {
        TKEY_COUNTER.inc(u16::try_from(index).unwrap_or(0));
    }
}

fn valid_spn(spn: &str) -> bool {
    let mut parts = spn.split('/');
    let service = parts.next().unwrap_or_default();
    let host = parts.next().unwrap_or_default();
    parts.next().is_none()
        && !service.is_empty()
        && !host.is_empty()
        && !spn.contains('@')
        && spn.bytes().all(|b| b.is_ascii_graphic())
}

/// The TKEY record of an answer before it is written.
struct ReplyRecord {
    mode: u16,
    error: u16,
    expiration: u32,
    key: Vec<u8>,
}

/// What a TKEY answer carries.
struct Reply {
    rcode: u8,
    tkey: Option<ReplyRecord>,
    signer: Option<Signer>,
}

impl Reply {
    fn rcode(rcode: u16) -> Self {
        Self {
            rcode: u8::try_from(rcode & 0x0f).unwrap_or(2),
            tkey: None,
            signer: None,
        }
    }

    fn error(mode: u16, error: u16) -> Self {
        Self {
            rcode: 0,
            tkey: Some(ReplyRecord {
                mode,
                error,
                expiration: 0,
                key: Vec::new(),
            }),
            signer: None,
        }
    }

    fn ok(mode: u16, expiration: u32, key: Vec<u8>, signer: Option<Signer>) -> Self {
        Self {
            rcode: 0,
            tkey: Some(ReplyRecord {
                mode,
                error: 0,
                expiration,
                key,
            }),
            signer,
        }
    }
}

impl Tkey {
    /// A handler with `settings` on the system clock.
    pub fn new(settings: GssSettings) -> Arc<Self> {
        Self::with_clock(settings, Arc::new(SystemClock))
    }

    /// A handler with `settings` on `clock` (tests replay recorded exchanges).
    pub fn with_clock(settings: GssSettings, clock: Arc<dyn Clock>) -> Arc<Self> {
        Arc::new(Self {
            settings,
            clock,
            acceptor: RwLock::new(None),
            table: Mutex::new(Table::default()),
            refusals: Mutex::new(Refusals::default()),
            minutes: Mutex::new([(0, 0); 60]),
        })
    }

    /// The handle for the account's keys.
    pub fn handle(self: &Arc<Self>) -> KeyHandle {
        KeyHandle(Arc::clone(self))
    }

    /// The settings.
    pub fn settings(&self) -> &GssSettings {
        &self.settings
    }

    fn now(&self) -> u64 {
        u64::try_from(self.clock.now().secs).unwrap_or(0)
    }

    fn table(&self) -> std::sync::MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn install(&self, realm: Realm, spns: &[String], keys: KeySet) -> Result<(), InstallError> {
        if spns.is_empty() {
            return Err(InstallError::Spn(String::new()));
        }
        if let Some(bad) = spns.iter().find(|spn| !valid_spn(spn)) {
            return Err(InstallError::Spn(bad.clone()));
        }
        if keys.is_empty() {
            return Err(InstallError::NoKeys);
        }
        let mut acceptor = self
            .acceptor
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(installed) = acceptor.as_ref()
            && installed.realm == realm
            && installed.spns == spns
        {
            installed.service.set_keys(keys);
            return Ok(());
        }
        let names: Vec<&str> = spns.iter().map(String::as_str).collect();
        let mut config = Config::new(realm.clone(), &names);
        config.max_skew_secs = i64::try_from(self.settings.skew_secs).unwrap_or(i64::MAX);
        let service = Service::new(config, keys, Arc::clone(&self.clock));
        *acceptor = Some(Installed {
            realm,
            spns: spns.to_vec(),
            service,
        });
        Ok(())
    }

    fn clear(&self) {
        *self
            .acceptor
            .write()
            .unwrap_or_else(PoisonError::into_inner) = None;
        let mut table = self.table();
        table.established.clear();
        table.negotiating.clear();
        table.per_source.clear();
        table.gauges();
    }

    fn installed(&self) -> Option<(Realm, Vec<String>)> {
        self.acceptor
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|installed| (installed.realm.clone(), installed.spns.clone()))
    }

    fn service(&self) -> Option<Arc<Service>> {
        self.acceptor
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|installed| Arc::clone(&installed.service))
    }

    /// The established context of a key name in lowercase wire form, when it is held and
    /// has not expired; marks it used. Allocates nothing.
    pub fn context(&self, name: &[u8]) -> Option<Arc<GssContext>> {
        let now = self.now();
        let mut table = self.table();
        let context = table.established.get(name)?;
        if context.expired(now) {
            table.established.remove(name);
            table.gauges();
            return None;
        }
        context.touch(now);
        Some(Arc::clone(context))
    }

    /// The negotiations in flight and the established contexts.
    pub fn counts(&self) -> (usize, usize) {
        let table = self.table();
        (table.negotiating.len(), table.established.len())
    }

    /// The findings the acceptor's refusals raise now ([`refusals`]).
    /// What the node's status reports: the contexts, the negotiations refused in the last
    /// hour, and the findings of [`Tkey::findings`].
    pub fn report(&self) -> GssReport {
        let now = self.now();
        let minute = now / 60;
        let refused_last_hour = self
            .minutes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(at, _)| minute.saturating_sub(*at) < 60)
            .map(|(_, count)| count)
            .sum();
        let (negotiating, established) = self.counts();
        GssReport {
            negotiating: negotiating as u64,
            established: established as u64,
            refused_last_hour,
            findings: self.findings(),
        }
    }

    fn note_refusal(&self) {
        let minute = self.now() / 60;
        let mut minutes = self.minutes.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = &mut minutes[usize::try_from(minute % 60).unwrap_or(0)];
        if slot.0 == minute {
            slot.1 += 1;
        } else {
            *slot = (minute, 1);
        }
    }

    /// The findings the acceptor's refusals raise now ([`refusals`]).
    pub fn findings(&self) -> Vec<GssFinding> {
        let now = self.now();
        self.refusals
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .findings(now)
    }

    fn refuse(
        &self,
        conn: &Conn,
        audit_to: &dyn TransferAudit,
        outcome: &str,
        finding: Option<&'static str>,
        reason: &str,
        principal: Option<&PrincipalName>,
    ) {
        count(outcome);
        self.note_refusal();
        let client = conn.client.ip();
        if let Some(finding) = finding {
            self.refusals
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .record(finding, source_of(client), self.now());
        }
        tracing::debug!(client = %conn.client, %reason, "a TKEY negotiation was refused");
        if audit_to.refusal_due(client) {
            let mut draft = AuditDraft::denied(audit::GSS_REFUSE, Vec::new())
                .with_source_ip(Some(client))
                .with_context("client", client.to_string())
                .with_context("code", codes::GSS_REFUSED)
                .with_context("reason", reason);
            if let Some(principal) = principal {
                draft = draft.with_context("principal", principal.to_string());
            }
            audit_to.record(draft);
        }
    }

    /// Answers one TKEY query from `conn`: the octets of the answer, or `None` for no
    /// answer. `hmac` is the node's TSIG keyring (a key name in use there is BADNAME);
    /// refusals are audited through `audit`.
    pub fn answer(
        &self,
        request: &[u8],
        conn: &Conn,
        hmac: &Keyring,
        audit: &dyn TransferAudit,
    ) -> Option<Vec<u8>> {
        let query = match wire::parse(request) {
            Ok(query) => query,
            Err(wire::TkeyFormError::NotTkey) => return None,
            Err(_) => {
                let mut out = Vec::with_capacity(crate::wire::HEADER_LEN);
                return crate::wire::write_formerr(request, &mut out).then_some(out);
            }
        };
        // Over UDP every TKEY query is answered with TC before any work, so that the
        // negotiation runs over TCP, whose source address cannot be spoofed (Windows and
        // nsupdate send TKEY over TCP anyway).
        if conn.transport == QueryTransport::Udp {
            let mut out = Vec::with_capacity(crate::wire::HEADER_LEN + query.question_end);
            return wire::write_truncated(request, &query, &mut out).then_some(out);
        }
        let max_len = MAX_MESSAGE_LEN;
        let now = self.now();
        let reply = if wire_eq(query.algorithm, GSS_TSIG) {
            match self.service() {
                None => Reply::rcode(rcode::REFUSED),
                Some(service) => match query.mode {
                    mode::GSSAPI => self.negotiate(&service, &query, conn, hmac, audit, now),
                    mode::DELETE => self.delete(request, &query, now),
                    other => {
                        count("token");
                        Reply::error(other, error::BADMODE)
                    }
                },
            }
        } else {
            count("token");
            Reply::error(query.mode, error::BADALG)
        };
        self.write(request, &query, reply, now, max_len)
    }

    /// Admits a leg of the negotiation named by `query` from `source`: the next leg of a
    /// negotiation in flight, or a new one under the bounds, reserved in the table.
    fn admit(
        &self,
        service: &Arc<Service>,
        name: &[u8],
        source: Source,
        hmac: &Keyring,
        now: u64,
    ) -> Result<(Negotiation, Instant), Admission> {
        let mut table = self.table();
        table.drop_stale_negotiations(now);
        table.sweep(now);
        if table.established.contains_key(name) || hmac.get(name).is_some() {
            return Err(Admission::NameInUse);
        }
        if let Some(pending) = table.negotiating.get_mut(name) {
            if pending.source != source {
                return Err(Admission::NameInUse);
            }
            let arrived = pending.arrived;
            return pending
                .negotiation
                .take()
                .map(|negotiation| (negotiation, arrived))
                .ok_or(Admission::Busy);
        }
        let from_source = table.per_source.get(&source).copied().unwrap_or(0);
        if from_source >= self.settings.per_client_max {
            return Err(Admission::Limit);
        }
        // At the node's bound the oldest negotiation waiting for its next leg leaves: a
        // negotiation that proves nothing (a Continue answer needs no valid ticket) cannot
        // hold a place for 30 s, and a client completes its legs within a round trip.
        if table.negotiating.len() >= self.settings.negotiating_max {
            let oldest = table
                .negotiating
                .iter()
                .filter(|(_, pending)| pending.negotiation.is_some())
                .min_by_key(|(_, pending)| pending.order)
                .map(|(name, _)| name.clone());
            let Some(oldest) = oldest else {
                return Err(Admission::Limit);
            };
            table.remove_negotiation(&oldest);
            count("limit");
        }
        *table.per_source.entry(source).or_insert(0) += 1;
        let arrived = Instant::now();
        table.admitted += 1;
        let order = table.admitted;
        table.negotiating.insert(
            Box::from(name),
            Negotiating {
                negotiation: None,
                source,
                started: now,
                arrived,
                order,
            },
        );
        table.gauges();
        Ok((service.negotiation(), arrived))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the parts of one negotiation leg"
    )]
    fn negotiate(
        &self,
        service: &Arc<Service>,
        query: &TkeyQuery<'_>,
        conn: &Conn,
        hmac: &Keyring,
        audit: &dyn TransferAudit,
        now: u64,
    ) -> Reply {
        let name = query.name.as_wire();
        if query.signed {
            count("token");
            return Reply::rcode(rcode::FORMERR);
        }
        let (mut negotiation, arrived) =
            match self.admit(service, name, source_of(conn.client.ip()), hmac, now) {
                Ok(admitted) => admitted,
                Err(Admission::NameInUse) => {
                    self.refuse(conn, audit, "token", None, "the key name is in use", None);
                    return Reply::error(mode::GSSAPI, error::BADNAME);
                }
                Err(Admission::Busy) => {
                    count("token");
                    return Reply::error(mode::GSSAPI, error::BADKEY);
                }
                Err(Admission::Limit) => {
                    let reason = "the node's negotiations are at their bound";
                    let finding = Some(findings::GSS_CONTEXT_LIMIT);
                    self.refuse(conn, audit, "limit", finding, reason, None);
                    return Reply::error(mode::GSSAPI, error::BADKEY);
                }
            };
        // The Kerberos work, outside the lock.
        match negotiation.step(query.key) {
            Ok(Step::Continue(token)) => {
                if let Some(pending) = self.table().negotiating.get_mut(name) {
                    pending.negotiation = Some(negotiation);
                }
                count("continue");
                Reply::ok(mode::GSSAPI, 0, token, None)
            }
            Ok(Step::Established { token, context }) => {
                self.established(service, query, conn, audit, &context, token, arrived, now)
            }
            Err(refusal) => {
                let mut table = self.table();
                table.remove_negotiation(name);
                table.gauges();
                drop(table);
                self.refuse(
                    conn,
                    audit,
                    refusal.outcome(),
                    refusal.finding(),
                    &refusal.to_string(),
                    None,
                );
                Reply::error(mode::GSSAPI, error::BADKEY)
            }
        }
    }

    /// Puts the context of a completed negotiation into the table; its answer is signed
    /// with it.
    #[allow(
        clippy::too_many_arguments,
        reason = "the parts of one completed negotiation"
    )]
    fn established(
        &self,
        service: &Arc<Service>,
        query: &TkeyQuery<'_>,
        conn: &Conn,
        audit: &dyn TransferAudit,
        context: &Context,
        token: Vec<u8>,
        arrived: Instant,
        now: u64,
    ) -> Reply {
        let name = query.name.as_wire();
        // The keys may have been cleared or replaced, or the place given up, while the
        // leg was stepped: then the context is not kept.
        let current = self.service().is_some_and(|now| Arc::ptr_eq(&now, service));
        let mut table = self.table();
        let reserved = table.remove_negotiation(name).is_some();
        if !reserved || !current {
            table.gauges();
            drop(table);
            count("token");
            return Reply::error(mode::GSSAPI, error::BADKEY);
        }
        let Ok(keys) = context.mic_keys() else {
            table.gauges();
            drop(table);
            let reason = "the MIC keys could not be derived";
            self.refuse(conn, audit, "token", None, reason, Some(&context.client));
            return Reply::error(mode::GSSAPI, error::BADKEY);
        };
        let ticket_end = u64::try_from(context.expires).unwrap_or(0);
        let expires = ticket_end.min(now.saturating_add(self.settings.context_max_secs));
        let gss = Arc::new(GssContext::new(ContextParts {
            name: query.name.clone(),
            identity: GssIdentity {
                principal: context.client.clone(),
                sid: context.user_sid().cloned(),
                groups: context.group_sids(),
            },
            keys,
            role: Role::Acceptor,
            send_seq: u64::from(context.acceptor_seq),
            receive_seq: u64::from(context.initiator_seq),
            client: conn.client.ip(),
            established: now,
            expires,
        }));
        table.insert(Arc::clone(&gss), self.settings.contexts_max, now);
        table.gauges();
        drop(table);
        count("established");
        let micros = u64::try_from(arrived.elapsed().as_micros()).unwrap_or(u64::MAX);
        GSS_ESTABLISH_HISTOGRAM.observe(micros);
        // The first signed message of the context covers no request MAC.
        Reply::ok(
            mode::GSSAPI,
            u32::try_from(expires).unwrap_or(u32::MAX),
            token,
            Some(Signer::request(MacKey::Gss(gss))),
        )
    }

    /// Mode 5: deletes the context that signs the query.
    fn delete(&self, request: &[u8], query: &TkeyQuery<'_>, now: u64) -> Reply {
        let name = query.name.as_wire();
        let Ok(Some(view)) = tsig::find(request) else {
            count("token");
            return Reply::error(mode::DELETE, error::BADKEY);
        };
        let Ok(verified) = tsig::verify_request(&Contexts(self), request, &view, now) else {
            count("token");
            return Reply::rcode(rcode::NOTAUTH);
        };
        if verified.key.name_wire() != name {
            count("token");
            return Reply::error(mode::DELETE, error::BADKEY);
        }
        let mut table = self.table();
        table.established.remove(name);
        table.gauges();
        drop(table);
        count("deleted");
        Reply::ok(
            mode::DELETE,
            0,
            Vec::new(),
            Some(Signer::answer(verified.key, verified.mac)),
        )
    }
}

/// Why a negotiation leg was not admitted.
enum Admission {
    /// The name is an established context, a TSIG key, or another client's negotiation.
    NameInUse,
    /// A leg of the same negotiation is being stepped right now.
    Busy,
    /// The node's or the client's bound.
    Limit,
}

impl Tkey {
    /// Writes the answer of `reply` and signs it when it carries a signer. An answer that
    /// cannot be signed is SERVFAIL, and a context it would have established is dropped.
    fn write(
        &self,
        request: &[u8],
        query: &TkeyQuery<'_>,
        reply: Reply,
        now: u64,
        max_len: usize,
    ) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(512);
        let now32 = u32::try_from(now).unwrap_or(u32::MAX);
        let record = reply.tkey.as_ref().map(|record| TkeyAnswer {
            algorithm: GSS_TSIG,
            inception: if record.error == 0 { now32 } else { 0 },
            expiration: record.expiration,
            mode: record.mode,
            error: record.error,
            key: &record.key,
        });
        let written = wire::write_answer(
            request,
            query,
            reply.rcode,
            record.as_ref(),
            SERVER_UDP_PAYLOAD,
            max_len,
            &mut out,
        );
        if !written {
            return None;
        }
        if let Some(mut signer) = reply.signer
            && !signer.sign(&mut out, now, 0, &[], max_len)
        {
            let mut table = self.table();
            table.established.remove(query.name.as_wire());
            table.gauges();
            drop(table);
            let mut failed = Vec::with_capacity(crate::wire::HEADER_LEN + query.question_end);
            return wire::write_header_answer(request, rcode::SERVFAIL, &mut failed)
                .then_some(failed);
        }
        Some(out)
    }
}

fn wire_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// The GSS-TSIG contexts of a node as a key source.
struct Contexts<'a>(&'a Tkey);

impl KeySource for Contexts<'_> {
    fn find(&self, name: &[u8], _algorithm: &[u8]) -> Option<MacKey> {
        self.0.context(name).map(MacKey::Gss)
    }
}

/// The keys of the update path: the TSIG keyring, and the node's GSS-TSIG contexts for a
/// record whose algorithm is `gss-tsig` (an unknown context is counted as
/// `unknown_context`).
#[derive(Debug, Clone, Copy)]
pub struct UpdateKeys<'a> {
    /// The TSIG keys.
    pub hmac: &'a Keyring,
    /// The contexts, on a node that takes GSS-TSIG.
    pub gss: Option<&'a Tkey>,
}

impl KeySource for UpdateKeys<'_> {
    fn find(&self, name: &[u8], algorithm: &[u8]) -> Option<MacKey> {
        if wire_eq(algorithm, GSS_TSIG) {
            let found = self.gss.and_then(|gss| gss.context(name)).map(MacKey::Gss);
            if found.is_none() {
                count("unknown_context");
            }
            return found;
        }
        self.hmac.find(name, algorithm)
    }
}

#[cfg(test)]
mod tests;
