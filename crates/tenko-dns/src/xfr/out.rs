//! AXFR and IXFR out, NOTIFY in and signed SOA queries on the role's listeners (RFC 5936,
//! RFC 1995, RFC 1996, RFC 9103).
//!
//! A transfer, and the signed SOA query of a secondary, is answered for a zone the node
//! serves when [`access::transfer`] admits it: the zone's `transfer.allow` access lists
//! (none means nobody, a deny in any list wins) with the client's address and its TSIG key,
//! a key one of the lists names with `require_tsig`, TLS that this node ended itself with
//! `xot`, and the floor of the security profile on top (TGL-10). The scope is the one the
//! client's view chooses from its address, the local address and the transport the request
//! came on, as for its queries.
//!
//! - AXFR streams the scope from the index: the SOA, every other RRset in canonical order,
//!   the SOA again, in messages of at most 16 KiB, each signed in the MAC chain.
//! - IXFR answers the single SOA when the client's serial is current, the deltas from the
//!   journal when its serial is in it (only the change, M19), and the zone in AXFR form
//!   when it is not or the journal was reset. Over UDP an IXFR is answered with the SOA
//!   only, which tells the client to come back over TCP (RFC 1995 section 2).
//! - A NOTIFY for a secondary zone from one of its primaries ([`access::notify`]: signed
//!   when the primary has a key, and always under Hardened) is acknowledged and handed to
//!   the secondary service.
//! - An SOA query signed with TSIG, a secondary's refresh check, is answered and signed
//!   after the same check as a transfer, from the scope of the client's view.
//!
//! Every transfer is audited as `dns.zone.transfer_out` with the client, the key and the
//! serials; refusals are audited and logged with their reason, at most once a minute per
//! client and a bounded number a minute in all ([`TransferAudit::refusal_due`]).

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use tenko_core::{
    ObjectRef,
    audit::AuditDraft,
    dns::{JournalEntry, KeyName, Rtype, Zone, audit},
};
use tokio::sync::mpsc;

use super::{
    Directory, JournalSource, Kind, MetricKind, NotifyHandler, Outcome, TransferAudit,
    TransferSink,
    access::{self, Refusal},
    classify, count, count_bytes,
    message::{
        self, MAX_TRANSFER_MESSAGE, MessageWriter, TransferRequest, read_request, short_answer,
    },
};
use crate::{
    catalog::{Catalog, CatalogHandle, ViewQuery, ViewScopes},
    index::{Index, Lookup, ScopeOf},
    respond::Conn,
    tsig::{self, Signer, TsigView, Verified},
    update::policy::{ProfileCell, UpdateProfile},
    wire::MAX_MESSAGE_LEN,
};

/// Seconds since 1970.
pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Whether serial `a` is at or after serial `b` (RFC 1982).
pub fn serial_ge(a: u32, b: u32) -> bool {
    a == b || a.wrapping_sub(b) < 0x8000_0000
}

/// The transfer path of a node: answers from the catalog, the directory and the journal.
pub struct XfrOut {
    catalog: CatalogHandle,
    directory: Arc<Directory>,
    journal: Arc<dyn JournalSource>,
    audit: Arc<dyn TransferAudit>,
    notify: Option<Arc<dyn NotifyHandler>>,
    profile: Arc<ProfileCell>,
    site: Arc<access::Site>,
    message_limit: usize,
}

impl std::fmt::Debug for XfrOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XfrOut")
            .field("notify", &self.notify.is_some())
            .field("profile", &self.profile.get())
            .field("message_limit", &self.message_limit)
            .finish_non_exhaustive()
    }
}

/// How a request was signed.
enum Signed {
    /// Not signed.
    No,
    /// Signed and verified.
    Yes(Verified),
}

impl Signed {
    fn key_name(&self) -> Option<KeyName> {
        match self {
            Signed::No => None,
            Signed::Yes(verified) => verified.key.name(),
        }
    }

    fn signer(&self) -> Option<Signer> {
        match self {
            Signed::No => None,
            Signed::Yes(verified) => Some(Signer::answer(verified.key.clone(), verified.mac)),
        }
    }
}

/// The outcome of the first look at a request: an answer of one message, or a transfer
/// to stream.
enum First {
    /// Send this one message (already signed).
    Reply(Vec<u8>),
    /// Send nothing.
    Drop,
    /// Stream a transfer.
    Transfer(Box<Plan>),
}

/// A transfer the access checks admitted.
struct Plan {
    request: TransferRequest,
    message: Vec<u8>,
    zone: Arc<Zone>,
    catalog: Arc<Catalog>,
    conn: Conn,
    signed: Signed,
    kind: Kind,
}

/// Why `conn` may not transfer `zone` under `profile` ([`access::transfer`] over the lists
/// of `catalog`).
fn refusal(
    zone: &Zone,
    catalog: &Catalog,
    profile: UpdateProfile,
    site: &access::Site,
    conn: &Conn,
    key: Option<&KeyName>,
    tls: bool,
) -> Result<(), Refusal> {
    let lists: Vec<_> = zone
        .transfer
        .allow
        .iter()
        .filter_map(|id| catalog.acl(*id))
        .collect();
    access::transfer(zone, &lists, profile, site, conn.client.ip(), key, tls)
}

impl XfrOut {
    /// The transfer path over `catalog` (records), `directory` (zones and keys) and
    /// `journal` (deltas), auditing through `audit`; NOTIFY messages go to `notify`.
    pub fn new(
        catalog: CatalogHandle,
        directory: Arc<Directory>,
        journal: Arc<dyn JournalSource>,
        audit: Arc<dyn TransferAudit>,
        notify: Option<Arc<dyn NotifyHandler>>,
    ) -> Self {
        Self {
            catalog,
            directory,
            journal,
            audit,
            notify,
            profile: Arc::new(ProfileCell::new(UpdateProfile::default())),
            site: Arc::new(access::Site::default()),
            message_limit: MAX_TRANSFER_MESSAGE,
        }
    }

    /// The same path under the security profile `profile` holds (TGL-10): the role shares
    /// the cell of the update path, which follows the settings. Without it the path
    /// follows Standard.
    #[must_use]
    pub fn with_profile(mut self, profile: Arc<ProfileCell>) -> Self {
        self.profile = profile;
        self
    }

    /// The same path with the site of the Hardened XoT rule that `site` holds (the
    /// security setting `transfer_site`, kept current by the role). Without it the path
    /// uses the default ranges.
    #[must_use]
    pub fn with_site(mut self, site: Arc<access::Site>) -> Self {
        self.site = site;
        self
    }

    /// The same path with another message size (tests).
    #[must_use]
    pub fn with_message_limit(mut self, limit: usize) -> Self {
        self.message_limit = limit.clamp(512, MAX_MESSAGE_LEN);
        self
    }

    /// A signed answer of one message.
    fn reply(mut answer: Vec<u8>, signed: &Signed) -> Vec<u8> {
        if let Some(mut signer) = signed.signer() {
            signer.sign(&mut answer, unix_now(), 0, &[], MAX_MESSAGE_LEN);
        }
        answer
    }

    /// The first look at a message: parse, TSIG, the zone, the access checks.
    fn first(&self, message: &[u8], conn: &Conn, tls: bool) -> First {
        let Some(kind) = classify(message) else {
            return First::Drop;
        };
        let Some(request) = read_request(message) else {
            let mut out = Vec::new();
            return if crate::wire::write_formerr(message, &mut out) {
                First::Reply(out)
            } else {
                First::Drop
            };
        };
        let now = unix_now();
        let signed = match tsig::find(message) {
            Err(_) => return First::Reply(short_answer(message, &request, 1)),
            Ok(None) => Signed::No,
            Ok(Some(view)) => {
                match tsig::verify_request(self.directory.keys(), message, &view, now) {
                    Ok(verified) => Signed::Yes(verified),
                    Err(refused) => {
                        return First::Reply(Self::tsig_refusal(
                            message, &request, &refused, &view, now,
                        ));
                    }
                }
            }
        };
        if request.question.qclass != message::CLASS_IN {
            return First::Reply(Self::reply(short_answer(message, &request, 5), &signed));
        }
        if kind == Kind::Notify {
            return self.notify_in(message, &request, conn, &signed);
        }
        let zones = self.directory.zones();
        let Some(zone) = zones.by_apex(request.question.name.as_wire()).cloned() else {
            return First::Reply(Self::reply(short_answer(message, &request, 9), &signed));
        };
        drop(zones);
        let catalog = self.catalog.load_full();
        let key = signed.key_name();
        if let Err(refused) = refusal(
            &zone,
            &catalog,
            self.profile.get(),
            &self.site,
            conn,
            key.as_ref(),
            tls,
        ) {
            match kind {
                Kind::Ixfr => count(MetricKind::IxfrOut, Outcome::Refused),
                Kind::Axfr => count(MetricKind::AxfrOut, Outcome::Refused),
                Kind::SignedSoa | Kind::Notify => {}
            }
            self.refused(&zone, conn, kind, key.as_ref(), refused);
            return First::Reply(Self::reply(short_answer(message, &request, 5), &signed));
        }
        if kind == Kind::SignedSoa {
            return Self::signed_soa(message, &request, &zone, &catalog, conn, &signed);
        }
        First::Transfer(Box::new(Plan {
            request,
            message: message.to_vec(),
            zone,
            catalog,
            conn: *conn,
            signed,
            kind,
        }))
    }

    /// Audits and logs a refusal when one of `conn`'s is due (at most once a minute per
    /// client and a bounded number a minute in all).
    fn refused(
        &self,
        zone: &Zone,
        conn: &Conn,
        kind: Kind,
        key: Option<&KeyName>,
        refused: Refusal,
    ) {
        let client = conn.client.ip();
        if !self.audit.refusal_due(client) {
            return;
        }
        tracing::warn!(
            zone = %zone.name,
            %client,
            kind = kind_name(kind),
            key = key.map_or("none", KeyName::as_str),
            code = refused.code,
            "a zone transfer was refused: {}",
            refused.reason
        );
        self.audit.record(
            AuditDraft::denied(audit::ZONE_TRANSFER_OUT, vec![ObjectRef::from(zone.id)])
                .with_source_ip(Some(client))
                .with_context("zone", zone.name.as_str())
                .with_context("kind", kind_name(kind))
                .with_context("key", key.map_or("none", KeyName::as_str))
                .with_context("code", refused.code)
                .with_context("reason", refused.reason),
        );
    }

    /// The NOTAUTH answer of a request whose TSIG did not verify.
    fn tsig_refusal(
        message: &[u8],
        request: &TransferRequest,
        refused: &tsig::Refused,
        view: &TsigView<'_>,
        now: u64,
    ) -> Vec<u8> {
        let rcode = if refused.error == tsig::TsigError::Truncated {
            1
        } else {
            9
        };
        let mut out = short_answer(message, request, rcode);
        tsig::refusal_tsig(&mut out, refused, view, now, MAX_MESSAGE_LEN);
        out
    }

    /// A NOTIFY: acknowledged when [`access::notify`] accepts it, signed when the request
    /// was.
    fn notify_in(
        &self,
        message: &[u8],
        request: &TransferRequest,
        conn: &Conn,
        signed: &Signed,
    ) -> First {
        let from = conn.client.ip();
        let key = signed.key_name();
        let zones = self.directory.zones();
        let Some(zone) = zones.by_apex(request.question.name.as_wire()) else {
            count(MetricKind::NotifyIn, Outcome::Refused);
            tracing::debug!(%from, "a NOTIFY for a zone this node does not hold was refused");
            return First::Reply(Self::reply(short_answer(message, request, 5), signed));
        };
        let (id, authenticated) = match access::notify(zone, self.profile.get(), from, key.as_ref())
        {
            Ok(accepted) => accepted,
            Err(refused) => {
                count(MetricKind::NotifyIn, Outcome::Refused);
                // From a primary's own address the refusal is worth an operator's look; from
                // anywhere else it is noise, and spoofable, so it stays at debug.
                let from_primary = !matches!(
                    refused.code,
                    access::codes::NOT_SECONDARY | access::codes::NOT_A_PRIMARY
                );
                if from_primary && self.audit.refusal_due(from) {
                    tracing::warn!(zone = %zone.name, %from, code = refused.code, "a NOTIFY was refused: {}", refused.reason);
                } else {
                    tracing::debug!(zone = %zone.name, %from, code = refused.code, "a NOTIFY was refused: {}", refused.reason);
                }
                return First::Reply(Self::reply(short_answer(message, request, 5), signed));
            }
        };
        drop(zones);
        count(MetricKind::NotifyIn, Outcome::Ok);
        if let Some(handler) = &self.notify {
            handler.notified(id, from, request.serial, authenticated);
        }
        First::Reply(Self::reply(short_answer(message, request, 0), signed))
    }

    /// A signed SOA query the access checks admitted: the SOA of the zone in the scope of
    /// the client's view, signed.
    fn signed_soa(
        message: &[u8],
        request: &TransferRequest,
        zone: &Zone,
        catalog: &Catalog,
        conn: &Conn,
        signed: &Signed,
    ) -> First {
        let scopes = scope_for(catalog, conn, request);
        let Some((ttl, rdata)) = soa_in(catalog, zone, &scopes) else {
            // A secondary zone before its first transfer, or expired.
            return First::Reply(Self::reply(short_answer(message, request, 2), signed));
        };
        let mut writer = MessageWriter::new(message, request, MAX_MESSAGE_LEN);
        writer.push(
            request.question.name.as_wire(),
            message::TYPE_SOA,
            ttl,
            &rdata,
        );
        First::Reply(Self::reply(writer.take(), signed))
    }

    /// Streams an admitted transfer into `sink`.
    #[allow(
        clippy::too_many_lines,
        reason = "one transfer from its first SOA to its audit record reads better whole"
    )]
    async fn transfer(self: Arc<Self>, plan: Plan, sink: mpsc::Sender<Vec<u8>>) {
        let Plan {
            request,
            message,
            zone,
            catalog,
            conn,
            signed,
            kind,
        } = plan;
        let client = conn.client.ip();
        let conn_scope = scope_for(&catalog, &conn, &request);
        let scope = conn_scope.scope_of(zone.id).clone();
        let Some((soa_ttl, soa)) = soa_in(&catalog, &zone, &conn_scope) else {
            // A secondary zone before its first transfer, or expired.
            let _ = sink
                .send(Self::reply(short_answer(&message, &request, 2), &signed))
                .await;
            return;
        };
        let current = message::soa_serial(&soa).unwrap_or_default();
        let mut stream = Stream {
            writer: MessageWriter::new(&message, &request, self.message_limit),
            signer: signed.signer(),
            sink,
            messages: 0,
            records: 0,
            bytes: 0,
        };
        let apex = zone.name.to_wire();
        let mut answered = "axfr";
        let mut from_serial = None;
        let result = if kind == Kind::Ixfr
            && let Some(client_serial) = request.serial
        {
            from_serial = Some(client_serial);
            if serial_ge(client_serial, current) {
                answered = "ixfr";
                stream.push(&apex, Rtype::SOA.0, soa_ttl, &soa).await
            } else {
                match self.journal.entries(zone.id, &scope).await {
                    Ok(entries) => match chain(&entries, client_serial, current) {
                        Some(steps) => {
                            answered = "ixfr";
                            stream_ixfr(&mut stream, &apex, soa_ttl, &soa, &steps).await
                        }
                        None => {
                            stream_axfr(&mut stream, &catalog, &zone, &scope, &apex, soa_ttl, &soa)
                                .await
                        }
                    },
                    Err(error) => {
                        tracing::warn!(zone = %zone.name, %error, "the journal could not be read; answering in AXFR form");
                        stream_axfr(&mut stream, &catalog, &zone, &scope, &apex, soa_ttl, &soa)
                            .await
                    }
                }
            }
        } else {
            stream_axfr(&mut stream, &catalog, &zone, &scope, &apex, soa_ttl, &soa).await
        };
        let ok = match result {
            Ok(()) => stream.flush().await.is_ok(),
            Err(()) => false,
        };
        let metric = if answered == "ixfr" {
            MetricKind::IxfrOut
        } else {
            MetricKind::AxfrOut
        };
        count_bytes(false, stream.bytes);
        let key = signed.key_name();
        let mut draft = if ok {
            count(
                metric,
                if stream.records == 1 {
                    Outcome::Current
                } else {
                    Outcome::Ok
                },
            );
            AuditDraft::success(audit::ZONE_TRANSFER_OUT, vec![ObjectRef::from(zone.id)])
        } else {
            count(metric, Outcome::Failed);
            AuditDraft::failed(
                audit::ZONE_TRANSFER_OUT,
                vec![ObjectRef::from(zone.id)],
                &tenko_core::dns::DnsError::new(
                    tenko_core::dns::codes::TRANSFER_FAILED,
                    500,
                    "the transfer ended before its last message",
                ),
            )
        };
        draft = draft
            .with_source_ip(Some(client))
            .with_context("zone", zone.name.as_str())
            .with_context("kind", answered)
            .with_context("requested", kind_name(kind))
            .with_context("key", key.as_ref().map_or("none", KeyName::as_str))
            .with_context("serial", current.to_string())
            .with_context("records", stream.records.to_string())
            .with_context("messages", stream.messages.to_string());
        if let Some(from) = from_serial {
            draft = draft.with_context("from_serial", from.to_string());
        }
        self.audit.record(draft);
    }
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Axfr => "axfr",
        Kind::Ixfr => "ixfr",
        Kind::Notify => "notify",
        Kind::SignedSoa => "soa",
    }
}

/// The scopes the view of `conn` chooses: its client, the local address and the transport
/// the request came on, as for a query.
fn scope_for<'a>(catalog: &'a Catalog, conn: &Conn, request: &TransferRequest) -> ViewScopes<'a> {
    let client = conn.client.ip();
    let view = catalog.views().select(&ViewQuery {
        client,
        local: conn.local.ip(),
        transport: conn.transport,
        qtype: Rtype(request.question.qtype),
        minute_of_day: u16::try_from((unix_now() % 86_400) / 60).unwrap_or(0),
        qname: request.question.name.as_wire(),
    });
    ViewScopes::new(view, client)
}

/// The SOA (TTL and data) of a zone in the scopes `scopes` chooses, when the index holds
/// the zone's data.
fn soa_in(catalog: &Catalog, zone: &Zone, scopes: &dyn ScopeOf) -> Option<(u32, Vec<u8>)> {
    let apex = zone.name.to_wire();
    match catalog.index().lookup(scopes, &apex, Rtype::SOA) {
        Lookup::Answer {
            zone: found, rrset, ..
        } if found.id == zone.id && found.apex == apex.as_slice() => rrset
            .rdata
            .first()
            .map(|rdata| (rrset.ttl, rdata.as_bytes().to_vec())),
        _ => None,
    }
}

/// The journal steps from `from` to `to`, oldest first, when the journal holds every one.
pub fn chain(entries: &[JournalEntry], from: u32, to: u32) -> Option<Vec<&JournalEntry>> {
    let mut steps = Vec::new();
    let mut at = from;
    for entry in entries {
        if entry.from_serial == at && entry.to_serial != at {
            steps.push(entry);
            at = entry.to_serial;
            if at == to {
                return Some(steps);
            }
        }
    }
    None
}

/// The messages of a transfer as they are written: signed and sent one by one.
struct Stream {
    writer: MessageWriter,
    signer: Option<Signer>,
    sink: mpsc::Sender<Vec<u8>>,
    messages: usize,
    records: usize,
    bytes: usize,
}

impl Stream {
    /// Adds a record, sending the current message first when it is full.
    async fn push(&mut self, owner: &[u8], rtype: u16, ttl: u32, rdata: &[u8]) -> Result<(), ()> {
        if self.writer.push(owner, rtype, ttl, rdata) {
            self.records += 1;
            return Ok(());
        }
        if self.writer.is_empty() {
            // A record larger than a message.
            return Err(());
        }
        self.flush().await?;
        if self.writer.push(owner, rtype, ttl, rdata) {
            self.records += 1;
            Ok(())
        } else {
            Err(())
        }
    }

    /// Signs and sends the current message.
    async fn flush(&mut self) -> Result<(), ()> {
        if self.writer.is_empty() {
            return Ok(());
        }
        let mut message = self.writer.take();
        if let Some(signer) = &mut self.signer
            && !signer.sign(&mut message, unix_now(), 0, &[], MAX_MESSAGE_LEN)
        {
            return Err(());
        }
        self.messages += 1;
        self.bytes += message.len();
        self.sink.send(message).await.map_err(|_| ())
    }
}

/// The zone in AXFR form: the SOA, every other RRset, the SOA.
async fn stream_axfr(
    stream: &mut Stream,
    catalog: &Catalog,
    zone: &Zone,
    scope: &tenko_core::dns::ScopeName,
    apex: &[u8],
    soa_ttl: u32,
    soa: &[u8],
) -> Result<(), ()> {
    let rrsets = catalog.index().scope_rrsets(zone.id, scope).ok_or(())?;
    stream.push(apex, Rtype::SOA.0, soa_ttl, soa).await?;
    for (owner, rtype, ttl, rdata) in &rrsets {
        if *rtype == Rtype::SOA && owner.as_ref() == apex {
            continue;
        }
        for record in rdata {
            stream.push(owner, rtype.0, *ttl, record.as_bytes()).await?;
        }
    }
    stream.push(apex, Rtype::SOA.0, soa_ttl, soa).await
}

/// The deltas in IXFR form (RFC 1995 section 4): the current SOA, then per step the old
/// SOA, the records removed, the new SOA and the records added, then the current SOA.
async fn stream_ixfr(
    stream: &mut Stream,
    apex: &[u8],
    soa_ttl: u32,
    soa: &[u8],
    steps: &[&JournalEntry],
) -> Result<(), ()> {
    stream.push(apex, Rtype::SOA.0, soa_ttl, soa).await?;
    for step in steps {
        for record in step.removed.iter().chain(step.added.iter()) {
            stream
                .push(
                    &record.name.to_wire(),
                    record.rtype.0,
                    record.ttl,
                    record.rdata.as_bytes(),
                )
                .await?;
        }
    }
    stream.push(apex, Rtype::SOA.0, soa_ttl, soa).await
}

impl TransferSink for XfrOut {
    fn datagram(&self, message: &[u8], conn: &Conn, out: &mut Vec<u8>) -> bool {
        match self.first(message, conn, false) {
            First::Reply(answer) => {
                *out = answer;
                true
            }
            First::Drop => false,
            First::Transfer(plan) => {
                // UDP: AXFR is refused; IXFR is answered with the current SOA only, which
                // sends the client to TCP (RFC 1995 section 2).
                let Plan {
                    request,
                    message,
                    zone,
                    catalog,
                    conn,
                    signed,
                    kind,
                } = *plan;
                if kind == Kind::Axfr {
                    *out = Self::reply(short_answer(&message, &request, 5), &signed);
                    return true;
                }
                let scopes = scope_for(&catalog, &conn, &request);
                let Some((ttl, soa)) = soa_in(&catalog, &zone, &scopes) else {
                    *out = Self::reply(short_answer(&message, &request, 2), &signed);
                    return true;
                };
                let mut writer = MessageWriter::new(&message, &request, 512 + message::TSIG_ROOM);
                writer.push(&zone.name.to_wire(), message::TYPE_SOA, ttl, &soa);
                count(MetricKind::IxfrOut, Outcome::Current);
                *out = Self::reply(writer.take(), &signed);
                true
            }
        }
    }

    fn stream(self: Arc<Self>, message: Vec<u8>, conn: Conn, tls: bool) -> mpsc::Receiver<Vec<u8>> {
        let (sender, receiver) = mpsc::channel(4);
        let this = self;
        tokio::spawn(async move {
            match this.first(&message, &conn, tls) {
                First::Reply(answer) => {
                    let _ = sender.send(answer).await;
                }
                First::Drop => {}
                First::Transfer(plan) => this.transfer(*plan, sender).await,
            }
        });
        receiver
    }
}

#[cfg(test)]
mod tests;
