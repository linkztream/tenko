//! Zone transfers and NOTIFY (WP6.1; RFC 5936, RFC 1995, RFC 1996, RFC 9103, RFC 9432).
//!
//! | Module | What |
//! |---|---|
//! | [`message`] | the messages of transfers and NOTIFY: the writer and the reader |
//! | [`out`] | AXFR and IXFR out on the role's TCP and DoT listeners, IXFR over UDP, NOTIFY in |
//! | [`notify`] | NOTIFY out from the leader when a serial changes, with retries |
//! | [`inbound`] | the transfer client: SOA check, IXFR with the AXFR fallback, TSIG, XoT |
//! | [`catalog_zone`] | the members of a catalog zone (RFC 9432), read and written |
//!
//! The listeners of the `dns` role hand a message to the transfer path ([`TransferSink`])
//! before the resolver sees it when [`classify`] says it is one: an AXFR or IXFR query or a
//! NOTIFY. Over TCP and DoT the path answers with a stream of messages the connection
//! writes in order; over UDP it answers an IXFR with the SOA only (RFC 1995 section 2) and
//! a NOTIFY with its acknowledgement. The path reads the zone rows and the TSIG keys from a
//! [`Directory`] kept current from the store, the records from the index, and the IXFR
//! deltas from the journal through [`JournalSource`]; it writes nothing but its audit
//! records ([`TransferAudit`]). A NOTIFY for a secondary zone reaches the leader's
//! secondary service through [`NotifyHandler`], which refreshes the zone and writes the
//! result through the store like every other change (plan section 2.4).

pub mod catalog_zone;
#[path = "in.rs"]
pub mod inbound;
pub mod message;
pub mod notify;
pub mod out;

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use futures::StreamExt as _;
use tenko_core::{
    RequestCtx, SystemComponent,
    audit::AuditDraft,
    dns::{
        JournalEntry, KeyMeta, KeyName, ScopeName, Zone, ZoneId,
        tables::{JOURNAL, KEYS_META, ZONES},
    },
    metrics::{CounterVec, Desc, Registry},
};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, Store, WatchFilter, WriteBatch};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    respond::Conn,
    tsig::{Keyring, TsigKey},
    wire::{self, HEADER_LEN},
    zone::ZoneService,
};

/// What a message on the transfer path asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A full transfer (RFC 5936).
    Axfr,
    /// An incremental transfer (RFC 1995).
    Ixfr,
    /// A NOTIFY (RFC 1996).
    Notify,
    /// A query for an SOA signed with TSIG: a secondary's refresh check, answered and
    /// signed by the transfer path (the resolver refuses signed queries).
    SignedSoa,
}

/// What a message is for the transfer path, from its header and question type only; no
/// allocation. `None` for everything the resolver answers.
pub fn classify(message: &[u8]) -> Option<Kind> {
    let header = wire::parse_header(message)?;
    if header.qr || header.qdcount != 1 {
        return None;
    }
    if header.opcode == message::OPCODE_NOTIFY {
        return Some(Kind::Notify);
    }
    if header.opcode != message::OPCODE_QUERY {
        return None;
    }
    let end = wire::skip_name(message, HEADER_LEN)?;
    let qtype = u16::from_be_bytes([*message.get(end)?, *message.get(end + 1)?]);
    match qtype {
        message::TYPE_AXFR => Some(Kind::Axfr),
        message::TYPE_IXFR => Some(Kind::Ixfr),
        message::TYPE_SOA if header.arcount > 0 => {
            matches!(crate::tsig::find(message), Ok(Some(_))).then_some(Kind::SignedSoa)
        }
        _ => None,
    }
}

/// The transfer path the listeners hand messages to (`server::Hooks::transfers`).
pub trait TransferSink: Send + Sync {
    /// Answers a message of [`classify`] that came over UDP into `out`; `false` sends
    /// nothing. Runs on a UDP worker: it must not block.
    fn datagram(&self, message: &[u8], conn: &Conn, out: &mut Vec<u8>) -> bool;

    /// Answers a message of [`classify`] that came over TCP or DoT (`tls` when this node
    /// ended TLS itself: XoT, RFC 9103) with the messages of the answer, in order; the
    /// connection writes each as it arrives and goes on reading when the channel closes.
    fn stream(self: Arc<Self>, message: Vec<u8>, conn: Conn, tls: bool) -> mpsc::Receiver<Vec<u8>>;
}

/// Where a NOTIFY for a secondary zone goes: the leader's secondary service.
pub trait NotifyHandler: Send + Sync {
    /// A primary of `zone` at `from` says its serial is now `serial` (when it said).
    fn notified(&self, zone: ZoneId, from: IpAddr, serial: Option<u32>);
}

/// The audit records of transfers out, written off the transfer path.
pub trait TransferAudit: Send + Sync {
    /// Records one transfer, or one refusal.
    fn record(&self, draft: AuditDraft);

    /// Whether a refusal of `client` is recorded now (a scan must not fill the log).
    fn refusal_due(&self, client: IpAddr) -> bool {
        let _ = client;
        true
    }
}

/// The journal entries an IXFR answer is built from.
#[async_trait::async_trait]
pub trait JournalSource: Send + Sync {
    /// The entries of a zone scope, oldest first.
    async fn entries(&self, zone: ZoneId, scope: &ScopeName) -> Result<Vec<JournalEntry>, String>;
}

/// The journal in the store of this process (Phase 2: the role runs in the controller's
/// process; a `dns` node of Phase 5 reads its node-sync copy of `dns.journal`).
#[derive(Clone)]
pub struct StoreJournal {
    store: Arc<dyn Store>,
}

impl StoreJournal {
    /// The journal of `store`.
    pub fn new(store: Arc<dyn Store>) -> Self {
        Self { store }
    }
}

#[async_trait::async_trait]
impl JournalSource for StoreJournal {
    async fn entries(&self, zone: ZoneId, scope: &ScopeName) -> Result<Vec<JournalEntry>, String> {
        let view = self
            .store
            .read(ReadConsistency::Local)
            .await
            .map_err(|error| error.to_string())?;
        let range = KeyRange::prefix(tenko_core::codec::key::encode_key(&(zone, scope.clone())));
        Ok(view
            .scan_typed(&JOURNAL, range, usize::MAX, false)
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|(_, entry, _)| entry)
            .collect())
    }
}

/// Audit records written to the store of this process as the DNS component, refusals at
/// most once a minute per client so that a scan cannot fill the audit log.
pub struct StoreAudit {
    store: Arc<dyn Store>,
    refusals: Mutex<HashMap<IpAddr, Instant>>,
}

impl StoreAudit {
    /// Records into `store`.
    pub fn new(store: Arc<dyn Store>) -> Self {
        Self {
            store,
            refusals: Mutex::new(HashMap::new()),
        }
    }

    fn due(&self, client: IpAddr) -> bool {
        let mut seen = self.refusals.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        seen.retain(|_, at| now.duration_since(*at) < Duration::from_secs(60));
        if seen.len() > 4096 || seen.contains_key(&client) {
            return false;
        }
        seen.insert(client, now);
        true
    }
}

impl TransferAudit for StoreAudit {
    fn record(&self, draft: AuditDraft) {
        let store = Arc::clone(&self.store);
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        runtime.spawn(async move {
            let cx = RequestCtx::system(SystemComponent::Dns);
            let mut batch = WriteBatch::for_request(&cx);
            batch.audit(draft);
            if let Err(error) = store.propose(batch).await {
                tracing::warn!(%error, "the audit record of a zone transfer could not be written");
            }
        });
    }

    fn refusal_due(&self, client: IpAddr) -> bool {
        self.due(client)
    }
}

/// The zone rows and TSIG keys the transfer path reads, swapped whole.
#[derive(Debug, Default)]
pub struct Directory {
    zones: ArcSwap<ZoneTable>,
    keys: Keyring,
}

/// The zones by apex in lowercase wire form and by id.
#[derive(Debug, Default)]
pub struct ZoneTable {
    by_apex: HashMap<Box<[u8]>, Arc<Zone>>,
    by_id: HashMap<ZoneId, Arc<Zone>>,
}

impl ZoneTable {
    /// The table of `zones`.
    pub fn new(zones: impl IntoIterator<Item = Zone>) -> Self {
        let mut table = Self::default();
        for zone in zones {
            let zone = Arc::new(zone);
            table
                .by_apex
                .insert(zone.name.to_wire().into(), Arc::clone(&zone));
            table.by_id.insert(zone.id, zone);
        }
        table
    }

    /// The zone whose apex is `apex` (lowercase wire form).
    pub fn by_apex(&self, apex: &[u8]) -> Option<&Arc<Zone>> {
        self.by_apex.get(apex)
    }

    /// The zone of an id.
    pub fn by_id(&self, id: ZoneId) -> Option<&Arc<Zone>> {
        self.by_id.get(&id)
    }
}

impl Directory {
    /// A directory of `zones` and `keys` (tests and tools; the role follows the store).
    pub fn new(
        zones: impl IntoIterator<Item = Zone>,
        keys: impl IntoIterator<Item = TsigKey>,
    ) -> Self {
        let directory = Self::default();
        directory.zones.store(Arc::new(ZoneTable::new(zones)));
        directory.keys.replace(keys);
        directory
    }

    /// The zones.
    pub fn zones(&self) -> arc_swap::Guard<Arc<ZoneTable>> {
        self.zones.load()
    }

    /// The TSIG keys.
    pub fn keys(&self) -> &Keyring {
        &self.keys
    }

    /// Reads the zones and the keys again: the keys' secrets come from the vault through
    /// the zone service, reused from `cache` while a key's secret reference is unchanged.
    ///
    /// # Errors
    ///
    /// The store's or the vault's error as text.
    pub async fn load(
        &self,
        zones: &ZoneService,
        cache: &mut HashMap<KeyName, (KeyMeta, Arc<TsigKey>)>,
    ) -> Result<(), String> {
        let view = zones.view(None).await.map_err(|error| error.to_string())?;
        let rows: Vec<Zone> = view
            .scan_typed(&ZONES, KeyRange::all(), usize::MAX, false)
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|(_, zone, _)| zone)
            .collect();
        let metas: Vec<KeyMeta> = view
            .scan_typed(&KEYS_META, KeyRange::all(), usize::MAX, false)
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|(_, key, _)| key)
            .collect();
        drop(view);
        cache.retain(|name, (meta, _)| metas.iter().any(|m| &m.name == name && m == meta));
        for meta in &metas {
            if cache.contains_key(&meta.name) {
                continue;
            }
            match zones.tsig_key(meta).await {
                Ok(key) => {
                    cache.insert(meta.name.clone(), (meta.clone(), Arc::new(key)));
                }
                Err(error) => {
                    tracing::warn!(key = %meta.name, %error, "a TSIG key could not be read from the vault");
                }
            }
        }
        self.zones.store(Arc::new(ZoneTable::new(rows)));
        self.keys
            .replace_shared(cache.values().map(|(_, key)| Arc::clone(key)));
        Ok(())
    }

    /// Keeps the directory current until `stop`: read at once, then again after every
    /// change of the zones or keys and at least every 30 seconds.
    pub async fn follow(self: Arc<Self>, zones: Arc<ZoneService>, stop: CancellationToken) {
        let mut cache = HashMap::new();
        let filter = || WatchFilter::tables([ZONES.name().clone(), KEYS_META.name().clone()]);
        let mut stream = zones.store().watch(None, filter()).ok();
        loop {
            if let Err(error) = self.load(&zones, &mut cache).await {
                tracing::warn!(%error, "the zones and keys of the transfer path could not be read");
            }
            let changed = async {
                match &mut stream {
                    Some(stream) => matches!(stream.next().await, Some(Ok(_))),
                    None => false,
                }
            };
            let alive = tokio::select! {
                () = stop.cancelled() => return,
                alive = changed => alive,
                () = tokio::time::sleep(Duration::from_secs(30)) => true,
            };
            if !alive {
                stream = zones.store().watch(None, filter()).ok();
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// Metrics

/// `tenko_dns_xfr_total{kind,outcome}`: transfers and NOTIFY messages by kind and outcome.
pub const XFR: Desc = Desc::counter("tenko_dns_xfr", "DNS zone transfers and NOTIFY messages")
    .labels(&["kind", "outcome"]);

/// `tenko_dns_xfr_bytes_total{direction}`: octets of transfer messages.
pub const XFR_BYTES: Desc = Desc::counter(
    "tenko_dns_xfr_bytes",
    "Octets of DNS zone transfer messages",
)
.labels(&["direction"]);

/// The `kind` label values, in the order of [`MetricKind`].
pub const KINDS: [&str; 6] = [
    "axfr_out",
    "ixfr_out",
    "axfr_in",
    "ixfr_in",
    "notify_out",
    "notify_in",
];

/// The `outcome` label values, in the order of [`Outcome`].
pub const OUTCOMES: [&str; 4] = ["ok", "current", "refused", "failed"];

/// A kind of the transfer counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MetricKind {
    /// AXFR answered (an IXFR answered in AXFR form counts here).
    AxfrOut = 0,
    /// IXFR answered with a delta or the SOA.
    IxfrOut = 1,
    /// AXFR received.
    AxfrIn = 2,
    /// IXFR received.
    IxfrIn = 3,
    /// NOTIFY sent.
    NotifyOut = 4,
    /// NOTIFY received.
    NotifyIn = 5,
}

/// An outcome of the transfer counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Outcome {
    /// Done.
    Ok = 0,
    /// The copy was current; nothing moved.
    Current = 1,
    /// Refused (access lists, TSIG, the other side).
    Refused = 2,
    /// Failed (no answer, a malformed answer).
    Failed = 3,
}

static SERIES: [[&str; 2]; 24] = {
    let mut rows = [["", ""]; 24];
    let mut kind = 0;
    while kind < 6 {
        let mut outcome = 0;
        while outcome < 4 {
            rows[kind * 4 + outcome] = [KINDS[kind], OUTCOMES[outcome]];
            outcome += 1;
        }
        kind += 1;
    }
    rows
};

/// [`XFR`].
pub static XFR_COUNTER: CounterVec = CounterVec::new(XFR);

/// [`XFR_BYTES`] by direction: 0 out, 1 in.
pub static XFR_BYTES_COUNTER: CounterVec = CounterVec::fixed(XFR_BYTES, &[&["out"], &["in"]]);

/// Counts one transfer or NOTIFY.
pub fn count(kind: MetricKind, outcome: Outcome) {
    XFR_COUNTER.inc(kind as u16 * 4 + outcome as u16);
}

/// Counts octets of transfer messages: `inbound` for received ones.
pub fn count_bytes(inbound: bool, bytes: usize) {
    XFR_BYTES_COUNTER.add(u16::from(inbound), u64::try_from(bytes).unwrap_or(u64::MAX));
}

/// Seals the transfer families.
pub fn seal_metrics() {
    let series: Vec<&[&str]> = SERIES.iter().map(|row| &row[..]).collect();
    XFR_COUNTER.seal(&series);
    XFR_BYTES_COUNTER.add(0, 0);
}

/// Seals the transfer families and registers them with `registry`.
pub fn register_metrics(registry: &Registry) {
    seal_metrics();
    registry.register(&XFR_COUNTER);
    registry.register(&XFR_BYTES_COUNTER);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::write_query;

    #[test]
    fn the_transfer_path_takes_axfr_ixfr_and_notify_only() {
        let mut out = Vec::new();
        write_query(&mut out, 1, "example.test", 252, None);
        assert_eq!(classify(&out), Some(Kind::Axfr));
        write_query(&mut out, 1, "example.test", 251, None);
        assert_eq!(classify(&out), Some(Kind::Ixfr));
        write_query(&mut out, 1, "example.test", 1, None);
        assert_eq!(classify(&out), None);
        message::write_request(
            &mut out,
            1,
            message::OPCODE_NOTIFY,
            b"\x04test\x00",
            6,
            None,
        );
        assert_eq!(classify(&out), Some(Kind::Notify));
        out[2] |= 0x80;
        assert_eq!(classify(&out), None, "a response is not for the path");
        assert_eq!(classify(&[0; 3]), None);
    }

    #[test]
    fn the_transfer_families_encode() {
        let registry = Registry::new();
        register_metrics(&registry);
        count(MetricKind::IxfrOut, Outcome::Ok);
        count_bytes(false, 512);
        let mut text = String::new();
        tenko_core::metrics::encode(&registry.snapshot(), &mut text);
        tenko_core::metrics::check(&text).expect("valid OpenMetrics");
        assert!(text.contains("tenko_dns_xfr_total{kind=\"ixfr_out\",outcome=\"ok\"}"));
        assert!(text.contains("tenko_dns_xfr_bytes_total{direction=\"out\"}"));
    }
}
