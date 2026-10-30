//! The write cost of a DNS update (WP9.6, ADR 0030): what the store batches of ONE logical
//! update carry, counted on a recording store over a memory store. Two paths are measured:
//! a dynamic update (RFC 2136, the path the DHCP role's DDNS worker and a TSIG client use)
//! that adds or deletes one A record, and a zone edit through the zone service
//! (`ZoneService::change_records`, the path of the API) that replaces one RRset. The zone is
//! warm: it holds 300 A records besides its SOA and NS, so rows that scale with the size of
//! the zone would show up. Each case runs on an unsigned zone, and the edit and the add also
//! on a signed zone, where the signer's incremental pass follows the update and its batches
//! are counted with the update's.
//!
//! For each case the batches proposed, the mutations (rows) grouped by table, the CBOR
//! bytes of the batches as the store encodes them into a Raft entry and the `payload_size`
//! of the batches are printed on one `WRITE COST dns` line (`--no-capture` shows them). The
//! rows and the bytes fail above a cap written here: the value measured on 2026-10-30 when
//! the cap was set plus a margin of 25 %, so a change that costs store work per update has
//! to raise the cap in the same commit, visibly.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock, PoisonError},
};

use tenko_core::{
    JobId, RequestCtx, SystemComponent,
    audit::AuditDraft,
    dns::{
        AclEntry, Denial, DnsName, DnssecAlgorithm, DnssecMode, DnssecPolicy, Origin,
        QueryTransport, RecordData, Rtype, ScopeName, SerialPolicy, SoaDefaults, UpdatePolicy,
        ZoneId, ZoneKind,
    },
};
use tenko_dns::{
    catalog::{self, CatalogHandle},
    dnssec::{Signer, SignerConfig, Trigger, rollover},
    respond::Conn,
    store_feed,
    update::{
        UpdatePath, UpdateSettings,
        message::{CLASS_IN, CLASS_NONE, push_record, rcode, write_request},
        policy::{ProfileCell, UpdateProfile},
    },
    wire,
    xfr::{Directory, TransferAudit},
    zone::{
        DirectJobs, ImportStaging, NewZone, ZoneChange, ZoneConfig, ZoneJobs, ZoneService,
        acl::NewAcl,
        records::{Change, Op},
    },
};
use tenko_jobs::{Job, JobError, JobSpec};
use tenko_store::{
    ChangeStream, Committed, DerivedIndex, Leadership, MemStore, MemStoreConfig, Mutation,
    ReadConsistency, ReadView, Store, StoreError, StoreStatus, WatchFilter, WriteBatch,
};
use tenko_vault::MemVault;
use tokio_util::sync::CancellationToken;

/// Rows (mutations) of the batches of one dynamic update that adds a record to an unsigned
/// zone, and their CBOR bytes. Measured on 2026-10-30.
const MEASURED_ADD_ROWS: f64 = 5.0;
const CAP_ADD_ROWS: f64 = 1.25 * MEASURED_ADD_ROWS;
const MEASURED_ADD_BYTES: f64 = 1_825.0;
const CAP_ADD_BYTES: f64 = 1.25 * MEASURED_ADD_BYTES;
/// The same for a dynamic update that deletes a record from an unsigned zone.
const MEASURED_DELETE_ROWS: f64 = 5.0;
const CAP_DELETE_ROWS: f64 = 1.25 * MEASURED_DELETE_ROWS;
const MEASURED_DELETE_BYTES: f64 = 1_644.0;
const CAP_DELETE_BYTES: f64 = 1.25 * MEASURED_DELETE_BYTES;
/// The same for a zone edit that replaces one RRset of an unsigned zone.
const MEASURED_EDIT_ROWS: f64 = 4.0;
const CAP_EDIT_ROWS: f64 = 1.25 * MEASURED_EDIT_ROWS;
const MEASURED_EDIT_BYTES: f64 = 1_728.0;
const CAP_EDIT_BYTES: f64 = 1.25 * MEASURED_EDIT_BYTES;
/// The same for a dynamic update that adds a record to a signed zone, with the signer's
/// incremental pass that follows it.
const MEASURED_SIGNED_ADD_ROWS: f64 = 16.0;
const CAP_SIGNED_ADD_ROWS: f64 = 1.25 * MEASURED_SIGNED_ADD_ROWS;
const MEASURED_SIGNED_ADD_BYTES: f64 = 8_020.0;
const CAP_SIGNED_ADD_BYTES: f64 = 1.25 * MEASURED_SIGNED_ADD_BYTES;
/// The same for a zone edit that replaces one RRset of a signed zone, with the signer's pass.
const MEASURED_SIGNED_EDIT_ROWS: f64 = 10.0;
const CAP_SIGNED_EDIT_ROWS: f64 = 1.25 * MEASURED_SIGNED_EDIT_ROWS;
const MEASURED_SIGNED_EDIT_BYTES: f64 = 5_958.0;
const CAP_SIGNED_EDIT_BYTES: f64 = 1.25 * MEASURED_SIGNED_EDIT_BYTES;

/// A records the warm zone holds.
const WARM_RECORDS: usize = 300;
const ZONE: &str = "example.test";

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn cx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Dns)
}

/// What one proposed batch carried.
struct BatchStat {
    /// Mutations by table (a counter bump under `bump:<name>`).
    tables: BTreeMap<String, usize>,
    /// Key and value octets by table.
    table_octets: BTreeMap<String, usize>,
    rows: usize,
    audits: usize,
    bytes: usize,
    payload: usize,
}

/// A store that records what each batch it is handed writes, over a memory store.
struct Recording {
    inner: Arc<MemStore>,
    batches: Mutex<Vec<BatchStat>>,
}

impl Recording {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(MemStore::new(MemStoreConfig::default())),
            batches: Mutex::new(Vec::new()),
        })
    }

    fn take(&self) -> Vec<BatchStat> {
        std::mem::take(&mut *self.batches.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

#[async_trait::async_trait]
impl Store for Recording {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        let bytes = tenko_core::codec::to_cbor(&batch).map_or(0, |encoded| encoded.len());
        let mut tables = BTreeMap::new();
        let mut table_octets = BTreeMap::new();
        for mutation in &batch.mutations {
            let (table, octets) = match mutation {
                Mutation::Put { table, key, value } => {
                    (table.as_str().to_owned(), key.len() + value.len())
                }
                Mutation::Delete { table, key } => (table.as_str().to_owned(), key.len()),
                Mutation::Bump { counter } => (format!("bump:{}", counter.name().as_str()), 0),
            };
            *tables.entry(table.clone()).or_insert(0) += 1;
            *table_octets.entry(table).or_insert(0) += octets;
        }
        let stat = BatchStat {
            tables,
            table_octets,
            rows: batch.mutations.len(),
            audits: batch.audit.len(),
            bytes,
            payload: batch.payload_size(),
        };
        self.batches
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(stat);
        self.inner.propose(batch).await
    }

    async fn read(&self, consistency: ReadConsistency) -> Result<Arc<dyn ReadView>, StoreError> {
        self.inner.read(consistency).await
    }

    fn watch(
        &self,
        from: Option<tenko_core::Revision>,
        filter: WatchFilter,
    ) -> Result<ChangeStream, StoreError> {
        self.inner.watch(from, filter)
    }

    fn register_index(&self, index: Arc<dyn DerivedIndex>) -> Result<(), StoreError> {
        self.inner.register_index(index)
    }

    fn status(&self) -> StoreStatus {
        self.inner.status()
    }

    fn leadership(&self) -> tokio::sync::watch::Receiver<Option<Leadership>> {
        self.inner.leadership()
    }
}

/// The figures of the batches of one logical update.
#[derive(Default)]
struct Cost {
    batches: usize,
    rows: usize,
    audits: usize,
    bytes: usize,
    payload: usize,
    tables: BTreeMap<String, usize>,
    table_octets: BTreeMap<String, usize>,
}

impl Cost {
    fn of(batches: &[BatchStat]) -> Self {
        let mut cost = Self {
            batches: batches.len(),
            ..Self::default()
        };
        for batch in batches {
            cost.rows += batch.rows;
            cost.audits += batch.audits;
            cost.bytes += batch.bytes;
            cost.payload += batch.payload;
            for (table, rows) in &batch.tables {
                *cost.tables.entry(table.clone()).or_insert(0) += rows;
            }
            for (table, octets) in &batch.table_octets {
                *cost.table_octets.entry(table.clone()).or_insert(0) += octets;
            }
        }
        cost
    }

    /// The sum of two costs.
    fn plus(self, other: Self) -> Self {
        let mut tables = self.tables;
        for (table, rows) in other.tables {
            *tables.entry(table).or_insert(0) += rows;
        }
        let mut table_octets = self.table_octets;
        for (table, octets) in other.table_octets {
            *table_octets.entry(table).or_insert(0) += octets;
        }
        Self {
            batches: self.batches + other.batches,
            rows: self.rows + other.rows,
            audits: self.audits + other.audits,
            bytes: self.bytes + other.bytes,
            payload: self.payload + other.payload,
            tables,
            table_octets,
        }
    }

    fn print(&self, case: &str) {
        let tables: Vec<String> = self
            .tables
            .iter()
            .map(|(table, rows)| format!("{table}: {rows}"))
            .collect();
        let octets: Vec<String> = self
            .table_octets
            .iter()
            .map(|(table, octets)| format!("{table}: {octets}"))
            .collect();
        eprintln!(
            "WRITE COST dns {case}: batches={} rows={} audit={} bytes={} payload={} tables={{{}}}",
            self.batches,
            self.rows,
            self.audits,
            self.bytes,
            self.payload,
            tables.join(", ")
        );
        eprintln!(
            "WRITE COST dns {case}: key and value octets by table {{{}}}",
            octets.join(", ")
        );
    }

    #[allow(clippy::cast_precision_loss, reason = "test figures")]
    fn check(&self, case: &str, cap_rows: f64, cap_bytes: f64) {
        assert!(
            self.rows as f64 <= cap_rows,
            "{case}: {} rows, cap {cap_rows}",
            self.rows
        );
        assert!(
            self.bytes as f64 <= cap_bytes,
            "{case}: {} bytes, cap {cap_bytes}",
            self.bytes
        );
    }
}

/// Jobs run in place by a runner set after the signer exists.
#[derive(Default)]
struct LateJobs(OnceLock<Arc<DirectJobs>>);

#[async_trait::async_trait]
impl ZoneJobs for LateJobs {
    async fn run_inline(&self, spec: JobSpec, cx: &RequestCtx) -> Result<Job, JobError> {
        self.0.get().expect("runner").run_inline(spec, cx).await
    }

    async fn submit(&self, spec: JobSpec, cx: &RequestCtx) -> Result<JobId, JobError> {
        self.0.get().expect("runner").submit(spec, cx).await
    }
}

struct Refusals;

impl TransferAudit for Refusals {
    fn record(&self, _draft: AuditDraft) {}
}

struct Lab {
    recording: Arc<Recording>,
    zones: Arc<ZoneService>,
    signer: Arc<Signer>,
    path: UpdatePath,
    zone: ZoneId,
    stop: CancellationToken,
    /// Keeps the catalog alive for the index the update path waits for.
    _catalog: CatalogHandle,
}

impl Drop for Lab {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

fn a(address: &str) -> RecordData {
    RecordData::A {
        address: address.parse().expect("address"),
    }
}

fn set(owner: &str, records: Vec<RecordData>, origin: Origin) -> Change {
    Change {
        op: Op::Set,
        scope: ScopeName::DEFAULT,
        name: name(owner),
        rtype: Rtype::A,
        ttl: Some(300),
        records,
        take_over: false,
        origin,
    }
}

/// `example.test` with `WARM_RECORDS` A records `h000..` and updates allowed from
/// 192.0.2.0/24 without TSIG; signed with ECDSA P-256 and NSEC when `with_dnssec`. The
/// recording is empty when the lab is returned.
#[allow(clippy::too_many_lines, reason = "the whole fixture in one place")]
async fn warm_lab(with_dnssec: bool) -> Lab {
    let recording = Recording::new();
    let store: Arc<dyn Store> = Arc::clone(&recording) as Arc<dyn Store>;
    let vault = Arc::new(MemVault::with_store(Arc::clone(&recording.inner)));
    let late = Arc::new(LateJobs::default());
    let staging = Arc::new(ImportStaging::default());
    let zones = ZoneService::new(
        Arc::clone(&store),
        Arc::clone(&late) as Arc<dyn ZoneJobs>,
        Some(Arc::clone(&vault) as Arc<dyn tenko_vault::Vault>),
        Arc::clone(&staging),
        ZoneConfig::default(),
    );
    let signer = Signer::new(
        Arc::clone(&zones),
        vault as Arc<dyn tenko_vault::Vault>,
        SignerConfig::default(),
    );
    let mut direct = DirectJobs::new(Arc::clone(&store));
    for handler in tenko_dns::zone::step_handlers(&staging) {
        direct.register(handler);
    }
    for handler in rollover::step_handlers(&signer) {
        direct.register(handler);
    }
    assert!(late.0.set(Arc::new(direct)).is_ok());
    let (office, _) = zones
        .create_acl(
            &cx(),
            NewAcl {
                name: "lan".to_owned(),
                entries: vec![AclEntry::Prefix {
                    prefix: "192.0.2.0/24".parse().expect("prefix"),
                    deny: false,
                }],
                description: None,
            },
        )
        .await
        .expect("acl");
    let written = zones
        .create(
            &cx(),
            NewZone {
                name: name(ZONE),
                kind: ZoneKind::Primary,
                tenant: None,
                scopes: Vec::new(),
                serial: SerialPolicy::Counter,
                soa: SoaDefaults::new(name("ns1.example.test"), name("hostmaster.example.test")),
                name_servers: vec![name("ns1.example.test")],
                transfer: tenko_core::dns::TransferPolicy::default(),
                update: UpdatePolicy {
                    allowed: vec![office.id],
                    require_tsig: false,
                    may_replace_ipam: false,
                    dhcp: None,
                },
                dnssec: DnssecPolicy::default(),
                source: None,
                description: None,
                reverse_of: None,
                catalog: false,
            },
        )
        .await
        .expect("zone");
    let zone = written.zone.id;
    let mut changes = vec![set(
        "ns1.example.test",
        vec![a("192.0.2.1")],
        Origin::Manual,
    )];
    for k in 0..WARM_RECORDS {
        let address = format!("198.51.100.{}", k % 250 + 1);
        changes.push(set(
            &format!("h{k:03}.example.test"),
            vec![a(&address)],
            Origin::Manual,
        ));
    }
    for chunk in changes.chunks(100) {
        zones
            .change_records(&cx(), zone, chunk, false)
            .await
            .expect("records");
    }
    if with_dnssec {
        zones
            .update(
                &cx(),
                zone,
                ZoneChange {
                    dnssec: Some(DnssecPolicy {
                        mode: DnssecMode::Online,
                        algorithm: DnssecAlgorithm::EcdsaP256Sha256,
                        denial: Denial::Nsec,
                        ..DnssecPolicy::default()
                    }),
                    ..ZoneChange::default()
                },
                None,
            )
            .await
            .expect("policy");
        signer
            .sync(zone, Trigger::full(false))
            .await
            .expect("signed");
    }
    let mut feed = store_feed::register(Arc::clone(&store)).expect("feed");
    let catalog = catalog::initial(&mut feed).await.expect("catalog");
    let stop = CancellationToken::new();
    tokio::spawn(catalog::follow(feed, catalog.clone(), stop.child_token()));
    let directory = Arc::new(Directory::default());
    directory
        .load(&zones, &mut HashMap::new())
        .await
        .expect("directory");
    let path = UpdatePath::with_settings(
        catalog.clone(),
        directory,
        Arc::clone(&zones),
        Arc::new(ProfileCell::new(UpdateProfile::Standard)),
        Arc::new(Refusals) as Arc<dyn TransferAudit>,
        stop.child_token(),
        UpdateSettings::default(),
    );
    recording.take();
    Lab {
        recording,
        zones,
        signer,
        path,
        zone,
        stop,
        _catalog: catalog,
    }
}

impl Lab {
    /// Sends one update that adds (`add`) or deletes the A record `owner` -> `data`; the
    /// answer must be NOERROR.
    async fn dynamic(&self, owner: &str, data: [u8; 4], add: bool) {
        let (class, ttl) = if add {
            (CLASS_IN, 120)
        } else {
            (CLASS_NONE, 0)
        };
        let mut update = Vec::new();
        push_record(&mut update, &name(owner).to_wire(), 1, class, ttl, &data);
        let mut message = Vec::new();
        write_request(
            &mut message,
            0x2136,
            &name(ZONE).to_wire(),
            (0, &[]),
            (1, &update),
        );
        let conn = Conn {
            client: SocketAddr::new("192.0.2.10".parse().expect("address"), 40_000),
            local: "192.0.2.53:53".parse().expect("local"),
            transport: QueryTransport::Udp,
        };
        let answer = self.path.answer(&message, &conn).await.expect("an answer");
        let header = wire::parse_header(&answer).expect("header");
        assert_eq!(
            u16::from(header.rcode),
            rcode::NOERROR,
            "the update applies"
        );
    }

    /// The incremental signing pass for the changed `owner` and the apex SOA.
    async fn sign(&self, owner: &str) {
        let dirty: HashSet<(DnsName, Rtype)> = [(name(owner), Rtype::A), (name(ZONE), Rtype::SOA)]
            .into_iter()
            .collect();
        let report = self
            .signer
            .sync(
                self.zone,
                Trigger {
                    changed: HashMap::from([(ScopeName::DEFAULT, dirty)]),
                    ..Trigger::default()
                },
            )
            .await
            .expect("pass");
        assert!(!report.full && report.rows > 0, "{report:?}");
    }

    /// The zone edit: the RRset `owner` A gets one other address.
    async fn edit(&self, owner: &str, address: &str) {
        self.zones
            .change_records(
                &cx(),
                self.zone,
                &[set(owner, vec![a(address)], Origin::Manual)],
                false,
            )
            .await
            .expect("edit");
    }

    /// The batches proposed since the last call, as a cost.
    fn cost(&self) -> Cost {
        Cost::of(&self.recording.take())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dynamic_update_that_adds_a_record_stays_within_its_caps() {
    let lab = warm_lab(false).await;
    lab.dynamic("new.example.test", [192, 0, 2, 9], true).await;
    let cost = lab.cost();
    cost.print("ddns add, unsigned zone");
    cost.check("ddns add", CAP_ADD_ROWS, CAP_ADD_BYTES);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dynamic_update_that_deletes_a_record_stays_within_its_caps() {
    let lab = warm_lab(false).await;
    lab.dynamic("h007.example.test", [198, 51, 100, 8], false)
        .await;
    let cost = lab.cost();
    cost.print("ddns delete, unsigned zone");
    cost.check("ddns delete", CAP_DELETE_ROWS, CAP_DELETE_BYTES);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_zone_edit_of_one_rrset_stays_within_its_caps() {
    let lab = warm_lab(false).await;
    lab.edit("h007.example.test", "192.0.2.77").await;
    let cost = lab.cost();
    cost.print("zone edit, unsigned zone");
    cost.check("zone edit", CAP_EDIT_ROWS, CAP_EDIT_BYTES);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dynamic_update_in_a_signed_zone_stays_within_its_caps() {
    let lab = warm_lab(true).await;
    lab.dynamic("new.example.test", [192, 0, 2, 9], true).await;
    let update = lab.cost();
    lab.sign("new.example.test").await;
    let pass = lab.cost();
    update.print("ddns add, signed zone, update");
    pass.print("ddns add, signed zone, signer pass");
    let total = update.plus(pass);
    total.print("ddns add, signed zone, total");
    total.check("signed ddns add", CAP_SIGNED_ADD_ROWS, CAP_SIGNED_ADD_BYTES);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_zone_edit_in_a_signed_zone_stays_within_its_caps() {
    let lab = warm_lab(true).await;
    lab.edit("h007.example.test", "192.0.2.77").await;
    let update = lab.cost();
    lab.sign("h007.example.test").await;
    let pass = lab.cost();
    update.print("zone edit, signed zone, edit");
    pass.print("zone edit, signed zone, signer pass");
    let total = update.plus(pass);
    total.print("zone edit, signed zone, total");
    total.check(
        "signed zone edit",
        CAP_SIGNED_EDIT_ROWS,
        CAP_SIGNED_EDIT_BYTES,
    );
}
