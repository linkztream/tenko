//! Dynamic updates (RFC 2136, RFC 3007; WP6.2, DNS-11, TGL-09, plan sections 2.4 and 2.5).
//!
//! | Module | What |
//! |---|---|
//! | [`message`] | the UPDATE message: the parser with the format rules, the answer writer |
//! | [`policy`] | who may update: the access lists, TSIG, the profile defaults of TGL-09 |
//! | [`prereq`] | the prerequisites of section 3.2, against the index and under the commit |
//! | [`apply`] | the change set: section 3.4 with the origin rules, one write per group |
//!
//! The listeners hand an UPDATE to the path off the query path: the responder answers it
//! [`crate::respond::Reply::Forward`], and [`crate::respond::Responder::forward`] gives it
//! to the [`UpdateSink`] with the transport's reply path. An ordinary query costs one
//! octet compare and allocates nothing more. The path then, on the runtime:
//!
//! 1. reads the TSIG record and verifies it (BADKEY, BADSIG, BADTIME are answered NOTAUTH
//!    with the TSIG error, a truncated MAC FORMERR), then parses the message (FORMERR,
//!    NOTZONE, NOTAUTH for a class other than IN); every later answer to a signed request
//!    is signed;
//! 2. finds the zone among the zones the node serves (NOTAUTH when it does not) and checks
//!    the policy (REFUSED with an extended error, audited as `dns.update.refuse` at most
//!    once a minute per client);
//! 3. tests the prerequisites against the index in the scope the client's view chooses;
//! 4. queues the update for its zone: one task per zone takes what waits, up to
//!    [`UpdateSettings::max_group`] updates, and plans them as one change set through the
//!    zone service ([`apply`]), so that updates are serialised per zone and a burst costs
//!    one commit, not one per update (risk R52);
//! 5. answers NOERROR only once the index the node answers from holds the commit (waiting
//!    at most [`UpdateSettings::index_wait`], then SERVFAIL with the extended error "Not
//!    Ready" and a log line), and SERVFAIL when the store refuses the write (no quorum, a
//!    refused batch), with nothing written.
//!
//! On the single node of Phase 2 the change set is a function call into the zone service;
//! in Phase 5 a `dns` node without a controller sends the same change set over the cluster
//! channel (`Dns.Update`) and waits for its delta (ADR 0017), and nothing else changes.
//!
//! Metrics: `tenko_dns_updates_total{outcome}` and `tenko_dns_update_duration_seconds`
//! (from the arrival of the message to its answer), registered by the role.

pub mod apply;
pub mod message;
pub mod policy;
pub mod prereq;

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use tenko_core::{
    ObjectRef, RequestCtx, SystemComponent,
    audit::AuditDraft,
    dns::{KeyName, QueryTransport, Rtype, ScopeName, Zone, ZoneId, audit},
    metrics::{CounterVec, Desc, Histogram, Registry},
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use self::{
    apply::{Item, Outcome},
    message::{AnswerEdns, ParseError, UpdateMessage, ede, rcode},
    policy::ProfileCell,
    prereq::IndexRecords,
};
use crate::{
    catalog::{CatalogHandle, ViewQuery, ViewScopes},
    index::ScopeOf as _,
    respond::{Conn, ReplyPath},
    tsig::{self, Signer, Verified},
    wire::{self, CLASSIC_UDP_LEN, MAX_MESSAGE_LEN, SERVER_UDP_PAYLOAD},
    xfr::{Directory, TransferAudit, out::unix_now},
    zone::ZoneService,
};

/// An UPDATE handed over by a listener.
#[derive(Debug)]
pub struct UpdateQuery {
    /// The message's octets.
    pub message: Vec<u8>,
    /// Where it came from.
    pub conn: Conn,
    /// Where the answer goes.
    pub reply: ReplyPath,
    /// When it arrived.
    pub at: Instant,
}

/// The update path the responder hands UPDATE messages to (`server::Hooks::updates`).
/// `submit` runs on a listener's thread (a UDP worker): it must not block.
pub trait UpdateSink: Send + Sync {
    /// Takes one UPDATE.
    fn submit(&self, query: UpdateQuery);
}

/// The limits of the update path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateSettings {
    /// How long an applied update waits for the index to hold its commit before it is
    /// answered SERVFAIL ("Not Ready").
    pub index_wait: Duration,
    /// The most updates of one zone planned and committed together.
    pub max_group: usize,
    /// The most updates waiting for one zone; beyond it an update is answered SERVFAIL.
    pub queue: usize,
    /// How long the task of a zone without updates stays.
    pub idle: Duration,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            index_wait: Duration::from_secs(2),
            max_group: 256,
            queue: 4096,
            idle: Duration::from_secs(300),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Metrics

/// Duration buckets in microseconds: 1 ms to 5 s.
pub const UPDATE_BUCKETS_US: &[u64] = &[
    1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 2_000_000,
    5_000_000,
];

/// `tenko_dns_updates_total{outcome}`: dynamic updates by outcome.
pub const UPDATES: Desc =
    Desc::counter("tenko_dns_updates", "DNS dynamic updates (RFC 2136)").labels(&["outcome"]);

/// `tenko_dns_update_duration_seconds`: from the arrival of an update to its answer.
pub const UPDATE_DURATION: Desc = Desc::histogram(
    "tenko_dns_update_duration_seconds",
    "Duration of DNS dynamic updates from arrival to answer",
    UPDATE_BUCKETS_US,
    1_000_000,
);

/// The `outcome` label values, in the order of [`MetricOutcome`].
pub const OUTCOMES: [&str; 6] = [
    "ok",
    "prerequisite",
    "refused",
    "notauth",
    "formerr",
    "failed",
];

/// An outcome of the update counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MetricOutcome {
    /// Applied (NOERROR).
    Ok = 0,
    /// A prerequisite did not hold.
    Prerequisite = 1,
    /// Refused by the policy or the origin rules.
    Refused = 2,
    /// Not authoritative, or the TSIG did not verify.
    NotAuth = 3,
    /// Malformed, or a name outside the zone.
    FormErr = 4,
    /// SERVFAIL: the store refused, the index did not follow, a rule broke, the queue.
    Failed = 5,
}

/// [`UPDATES`].
pub static UPDATE_COUNTER: CounterVec = CounterVec::fixed(
    UPDATES,
    &[
        &["ok"],
        &["prerequisite"],
        &["refused"],
        &["notauth"],
        &["formerr"],
        &["failed"],
    ],
);

/// [`UPDATE_DURATION`].
pub static UPDATE_LATENCY: Histogram = Histogram::new(UPDATE_DURATION);

/// Registers the update families with `registry`.
pub fn register_metrics(registry: &Registry) {
    UPDATE_COUNTER.add(0, 0);
    registry.register(&UPDATE_COUNTER);
    registry.register(&UPDATE_LATENCY);
}

fn outcome_of(code: u16) -> MetricOutcome {
    match code {
        rcode::NOERROR => MetricOutcome::Ok,
        rcode::NXDOMAIN | rcode::YXDOMAIN | rcode::YXRRSET | rcode::NXRRSET => {
            MetricOutcome::Prerequisite
        }
        rcode::REFUSED => MetricOutcome::Refused,
        rcode::NOTAUTH => MetricOutcome::NotAuth,
        rcode::FORMERR | rcode::NOTZONE | rcode::NOTIMP => MetricOutcome::FormErr,
        _ => MetricOutcome::Failed,
    }
}

// ---------------------------------------------------------------------------------------
// The path

/// The answer of one update: the RCODE and the extended error.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Answer {
    rcode: u16,
    error: Option<(u16, String)>,
}

impl Answer {
    fn ok() -> Self {
        Self {
            rcode: rcode::NOERROR,
            error: None,
        }
    }

    fn with(rcode: u16, code: u16, text: impl Into<String>) -> Self {
        Self {
            rcode,
            error: Some((code, text.into())),
        }
    }
}

/// An update waiting for its zone.
struct Pending {
    message: UpdateMessage,
    scope: ScopeName,
    key: Option<KeyName>,
    client: IpAddr,
    done: oneshot::Sender<Answer>,
}

/// The update path of a node: the zones and keys from the directory, the index and the
/// access lists from the catalog, the writes through the zone service.
pub struct UpdatePath {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for UpdatePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdatePath")
            .field("settings", &self.inner.settings)
            .finish_non_exhaustive()
    }
}

struct Inner {
    catalog: CatalogHandle,
    directory: Arc<Directory>,
    zones: Arc<ZoneService>,
    profile: Arc<ProfileCell>,
    audit: Arc<dyn TransferAudit>,
    runtime: tokio::runtime::Handle,
    settings: UpdateSettings,
    queues: Mutex<HashMap<ZoneId, mpsc::Sender<Pending>>>,
    stop: CancellationToken,
}

impl UpdatePath {
    /// The update path over `catalog` (the index and the access lists), `directory` (the
    /// zones and the TSIG keys) and `zones` (the writes), under the profile in `profile`,
    /// auditing refusals through `audit`; its tasks run on the current runtime until
    /// `stop`.
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime.
    pub fn new(
        catalog: CatalogHandle,
        directory: Arc<Directory>,
        zones: Arc<ZoneService>,
        profile: Arc<ProfileCell>,
        audit: Arc<dyn TransferAudit>,
        stop: CancellationToken,
    ) -> Self {
        Self::with_settings(
            catalog,
            directory,
            zones,
            profile,
            audit,
            stop,
            UpdateSettings::default(),
        )
    }

    /// The same with other limits.
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime.
    pub fn with_settings(
        catalog: CatalogHandle,
        directory: Arc<Directory>,
        zones: Arc<ZoneService>,
        profile: Arc<ProfileCell>,
        audit: Arc<dyn TransferAudit>,
        stop: CancellationToken,
        settings: UpdateSettings,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                catalog,
                directory,
                zones,
                profile,
                audit,
                runtime: tokio::runtime::Handle::current(),
                settings,
                queues: Mutex::new(HashMap::new()),
                stop,
            }),
        }
    }

    /// Answers one UPDATE: the octets of the answer, or `None` for no answer. What
    /// [`UpdateSink::submit`] runs for each message, for tests and tools.
    pub async fn answer(&self, message: &[u8], conn: &Conn) -> Option<Vec<u8>> {
        Arc::clone(&self.inner).answer(message, conn).await
    }
}

impl UpdateSink for UpdatePath {
    fn submit(&self, query: UpdateQuery) {
        let inner = Arc::clone(&self.inner);
        self.inner.runtime.spawn(async move {
            let UpdateQuery {
                message,
                conn,
                reply,
                at,
            } = query;
            let answer = inner.answer(&message, &conn).await;
            if let Some(answer) = answer {
                match reply {
                    ReplyPath::Udp(socket) => {
                        let _ = socket.send_to(&answer, conn.client);
                    }
                    ReplyPath::Tcp(sender) => {
                        let _ = sender.send(answer).await;
                    }
                }
            }
            let micros = u64::try_from(at.elapsed().as_micros()).unwrap_or(u64::MAX);
            UPDATE_LATENCY.observe(micros);
        });
    }
}

/// The largest answer the transport takes.
fn max_len(conn: &Conn, edns: Option<u16>) -> usize {
    match conn.transport {
        QueryTransport::Udp => edns.map_or(CLASSIC_UDP_LEN, usize::from),
        _ => MAX_MESSAGE_LEN,
    }
}

/// Writes and signs an answer.
fn finish(
    request: &[u8],
    zone_end: Option<usize>,
    edns: Option<u16>,
    answer: &Answer,
    signed: Option<&Verified>,
    conn: &Conn,
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(512);
    let edns_out = edns.map(|_| AnswerEdns {
        udp_size: SERVER_UDP_PAYLOAD,
        error: answer
            .error
            .as_ref()
            .map(|(code, text)| (*code, text.as_str())),
    });
    if !message::write_answer(request, zone_end, answer.rcode, edns_out, &mut out) {
        return None;
    }
    if let Some(verified) = signed {
        let mut chain = Signer::answer(Arc::clone(&verified.key), verified.mac);
        chain.sign(&mut out, unix_now(), 0, &[], max_len(conn, edns));
    }
    UPDATE_COUNTER.inc(outcome_of(answer.rcode) as u16);
    Some(out)
}

impl Inner {
    async fn answer(self: Arc<Self>, request: &[u8], conn: &Conn) -> Option<Vec<u8>> {
        let header = wire::parse_header(request)?;
        if header.qr {
            return None;
        }
        let zone_end =
            wire::questions_end(request, header.qdcount.min(1)).filter(|_| header.qdcount == 1);
        // TSIG first: an answer to a signed request is signed.
        let now = unix_now();
        let signed = match tsig::find(request) {
            Err(_) => {
                let answer = Answer::with(rcode::FORMERR, ede::OTHER, "malformed TSIG record");
                return finish(request, zone_end, None, &answer, None, conn);
            }
            Ok(None) => None,
            Ok(Some(view)) => {
                match tsig::verify_request(self.directory.keys(), request, &view, now) {
                    Ok(verified) => Some(verified),
                    Err(refused) => {
                        let code = if refused.error == tsig::TsigError::Truncated {
                            rcode::FORMERR
                        } else {
                            rcode::NOTAUTH
                        };
                        let mut out = Vec::with_capacity(512);
                        if !message::write_answer(request, zone_end, code, None, &mut out) {
                            return None;
                        }
                        tsig::refusal_tsig(&mut out, &refused, &view, now, MAX_MESSAGE_LEN);
                        UPDATE_COUNTER.inc(outcome_of(code) as u16);
                        tracing::debug!(client = %conn.client, error = %refused.error, "dynamic update with a TSIG that does not verify");
                        return Some(out);
                    }
                }
            }
        };
        let message = match message::parse(request) {
            Ok(message) => message,
            Err(ParseError::NotUpdate) => return None,
            Err(error) => {
                let answer = Answer::with(
                    error.rcode().unwrap_or(rcode::FORMERR),
                    ede::OTHER,
                    error.to_string(),
                );
                let edns = edns_of(request);
                return finish(
                    request,
                    error.zone_end(),
                    edns,
                    &answer,
                    signed.as_ref(),
                    conn,
                );
            }
        };
        let key = signed.as_ref().and_then(|verified| verified.key.name());
        let answer = self.decide(message.clone(), key, conn).await;
        finish(
            request,
            Some(message.zone_end),
            message.edns,
            &answer,
            signed.as_ref(),
            conn,
        )
    }

    /// The zone, the policy, the prerequisites against the index, then the zone's queue.
    async fn decide(
        self: &Arc<Self>,
        message: UpdateMessage,
        key: Option<KeyName>,
        conn: &Conn,
    ) -> Answer {
        let client = conn.client.ip();
        let zones = self.directory.zones();
        let Some(zone) = zones.by_apex(&message.zone.to_wire()).cloned() else {
            return Answer::with(
                rcode::NOTAUTH,
                ede::NOT_AUTHORITATIVE,
                format!("{} is not a zone of this server", message.zone),
            );
        };
        drop(zones);
        let profile = self.profile.get();
        let scope = {
            let catalog = self.catalog.load();
            if let Err(reason) =
                policy::check(&zone, |id| catalog.acl(id), profile, client, key.as_ref())
            {
                self.refused(&zone, client, key.as_ref(), reason);
                return Answer::with(rcode::REFUSED, ede::PROHIBITED, reason);
            }
            let apex = zone.name.to_wire();
            let view = catalog.views().select(&ViewQuery {
                client,
                local: conn.local.ip(),
                transport: conn.transport,
                qtype: Rtype::SOA,
                minute_of_day: u16::try_from((unix_now() % 86_400) / 60).unwrap_or(0),
                qname: &apex,
            });
            let scope = ViewScopes::new(view, client).scope_of(zone.id).clone();
            let records =
                IndexRecords::new(catalog.index(), zone.id, zone.kind, &zone.name, &scope);
            if let Err(unmet) = prereq::check(&message.prerequisites, &records) {
                return Answer::with(unmet.rcode, ede::OTHER, unmet.text());
            }
            scope
        };
        let (done, wait) = oneshot::channel();
        let pending = Pending {
            message,
            scope,
            key,
            client,
            done,
        };
        if let Err(answer) = self.enqueue(zone.id, pending) {
            return answer;
        }
        wait.await.unwrap_or_else(|_| {
            Answer::with(rcode::SERVFAIL, ede::OTHER, "the update path is stopping")
        })
    }

    /// Audits a refusal, at most once a minute per client.
    fn refused(&self, zone: &Zone, client: IpAddr, key: Option<&KeyName>, reason: &str) {
        if !self.audit.refusal_due(client) {
            return;
        }
        self.audit.record(
            AuditDraft::denied(audit::UPDATE_REFUSE, vec![ObjectRef::from(zone.id)])
                .with_source_ip(Some(client))
                .with_context("zone", zone.name.as_str())
                .with_context("client", client.to_string())
                .with_context("key", key.map_or("none", KeyName::as_str))
                .with_context("code", tenko_core::dns::codes::UPDATE_REFUSED)
                .with_context("reason", reason),
        );
    }

    /// Hands an update to the task of its zone, starting the task when there is none.
    fn enqueue(self: &Arc<Self>, zone: ZoneId, pending: Pending) -> Result<(), Answer> {
        let mut queues = self.queues.lock().unwrap_or_else(PoisonError::into_inner);
        let sender = match queues.get(&zone) {
            Some(sender) if !sender.is_closed() => sender.clone(),
            _ => {
                let (sender, receiver) = mpsc::channel(self.settings.queue.max(1));
                queues.insert(zone, sender.clone());
                self.runtime
                    .spawn(Arc::clone(self).zone_task(zone, receiver));
                sender
            }
        };
        // Sent under the lock: the task leaves only while it holds the lock and nothing
        // waits, so no update is sent to a task that left.
        sender.try_send(pending).map_err(|_| {
            Answer::with(
                rcode::SERVFAIL,
                ede::OTHER,
                "the zone's update queue is full",
            )
        })
    }

    /// The task of one zone: takes what waits, up to the group size, and commits it as one
    /// change set; leaves after a while without updates.
    async fn zone_task(self: Arc<Self>, zone: ZoneId, mut receiver: mpsc::Receiver<Pending>) {
        loop {
            let first = tokio::select! {
                () = self.stop.cancelled() => return,
                next = receiver.recv() => match next {
                    Some(pending) => pending,
                    None => return,
                },
                () = tokio::time::sleep(self.settings.idle) => {
                    let mut queues = self.queues.lock().unwrap_or_else(PoisonError::into_inner);
                    if receiver.is_empty() {
                        queues.remove(&zone);
                        return;
                    }
                    continue;
                }
            };
            let mut group = vec![first];
            while group.len() < self.settings.max_group {
                match receiver.try_recv() {
                    Ok(pending) => group.push(pending),
                    Err(_) => break,
                }
            }
            self.run_group(zone, group).await;
        }
    }

    /// Plans and commits a group, waits for the index, answers every update.
    async fn run_group(&self, zone: ZoneId, group: Vec<Pending>) {
        let items: Vec<Item<'_>> = group
            .iter()
            .map(|pending| Item {
                message: &pending.message,
                scope: pending.scope.clone(),
                key: pending.key.clone(),
                client: pending.client,
            })
            .collect();
        let profile = self.profile.get();
        let admit = |zone: &Zone, item: &Item<'_>| {
            let catalog = self.catalog.load();
            policy::check(
                zone,
                |id| catalog.acl(id),
                profile,
                item.client,
                item.key.as_ref(),
            )
        };
        let cx = RequestCtx::system(SystemComponent::Dns);
        let limits = self.zones.config().journal;
        let result = self
            .zones
            .execute(&cx, |view| {
                apply::plan(view, zone, &items, &admit, &cx, limits)
            })
            .await;
        let answers: Vec<Answer> = match result {
            Ok((outcomes, written)) => {
                let ready = match &written {
                    Some(written) => self.reach(written.revision.0).await,
                    None => true,
                };
                if !ready {
                    tracing::warn!(
                        zone = %zone,
                        revision = written.as_ref().map_or(0, |written| written.revision.0),
                        "a dynamic update was committed, but the index did not hold it within {} ms; answered SERVFAIL",
                        self.settings.index_wait.as_millis()
                    );
                }
                let directory = self.directory.zones();
                let row = directory.by_id(zone).cloned();
                drop(directory);
                outcomes
                    .into_iter()
                    .zip(&items)
                    .map(|(outcome, item)| self.answer_of(outcome, ready, row.as_deref(), item))
                    .collect()
            }
            Err(error) => {
                tracing::warn!(zone = %zone, code = %error.coded().code, %error, "the store refused a dynamic update; answered SERVFAIL");
                let text = format!("the store refused the write ({})", error.coded().code);
                items
                    .iter()
                    .map(|_| Answer::with(rcode::SERVFAIL, ede::OTHER, text.clone()))
                    .collect()
            }
        };
        for (pending, answer) in group.into_iter().zip(answers) {
            let _ = pending.done.send(answer);
        }
    }

    fn answer_of(
        &self,
        outcome: Outcome,
        ready: bool,
        zone: Option<&Zone>,
        item: &Item<'_>,
    ) -> Answer {
        match outcome {
            Outcome::Applied { .. } if ready => Answer::ok(),
            Outcome::Applied { .. } => Answer::with(
                rcode::SERVFAIL,
                ede::NOT_READY,
                "the update is committed; the server does not answer from it yet",
            ),
            Outcome::Unmet(unmet) => Answer::with(unmet.rcode, ede::OTHER, unmet.text()),
            Outcome::Refused(reason) => {
                if let Some(zone) = zone {
                    self.refused(zone, item.client, item.key.as_ref(), &reason);
                }
                Answer::with(rcode::REFUSED, ede::PROHIBITED, reason)
            }
            Outcome::Failed(reason) => Answer::with(rcode::SERVFAIL, ede::OTHER, reason),
            Outcome::NotAuth(reason) => {
                Answer::with(rcode::NOTAUTH, ede::NOT_AUTHORITATIVE, reason)
            }
        }
    }

    /// Waits until the index serves at least `revision`, at most the bound.
    async fn reach(&self, revision: u64) -> bool {
        let deadline = tokio::time::Instant::now() + self.settings.index_wait;
        loop {
            if self.catalog.revision().0 >= revision {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}

/// The requester's EDNS UDP size of a message that did not parse as an UPDATE, when its
/// OPT record can be found.
fn edns_of(request: &[u8]) -> Option<u16> {
    let header = wire::parse_header(request)?;
    let mut pos = wire::questions_end(request, header.qdcount)?;
    let records =
        usize::from(header.ancount) + usize::from(header.nscount) + usize::from(header.arcount);
    for _ in 0..records {
        let record = wire::read_record(request, pos)?;
        if record.rtype == wire::TYPE_OPT {
            return Some(record.class.max(512));
        }
        pos = record.end();
    }
    None
}

/// The address a listener saw, for tests that call the path directly.
pub fn conn(client: SocketAddr, local: SocketAddr, transport: QueryTransport) -> Conn {
    Conn {
        client,
        local,
        transport,
    }
}
