//! Dynamic updates (WP6.2, RFC 2136) through the update path over a zone service on an
//! in-memory store, the store feed and the catalog the node answers from: every
//! operation, every prerequisite, TSIG and the access lists, the origin rules, the answer
//! once the index holds the commit, SERVFAIL when the store refuses the write and when the
//! index does not follow. The listeners are left out: the tests call what the update sink
//! runs for each message.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tenko_core::{
    RequestCtx, SystemComponent,
    audit::AuditDraft,
    dns::{
        AclEntry, DnsName, Origin, QueryTransport, RecordData, Rtype, ScopeName, SerialPolicy,
        SoaDefaults, TsigAlgorithm, UpdatePolicy, Zone, ZoneKind,
    },
};
use tenko_dns::{
    catalog::{self, CatalogHandle},
    index::{DefaultScopes, Index as _, Lookup},
    respond::Conn,
    store_feed,
    tsig::{self, Signer, TsigKey, Verifier},
    update::{
        UpdatePath, UpdateSettings,
        message::{CLASS_ANY, CLASS_IN, CLASS_NONE, TYPE_ANY, push_record, rcode, write_request},
        policy::{ProfileCell, UpdateProfile},
    },
    wire::{self, MAX_MESSAGE_LEN},
    xfr::{Directory, TransferAudit},
    zone::{
        NewZone, ZoneChange, ZoneConfig, ZoneService,
        acl::NewAcl,
        keys::NewKey,
        records::{Change, Op},
    },
};
use tenko_store::{
    ChangeStream, Committed, DerivedIndex, Leadership, MemStore, ReadConsistency, ReadView, Store,
    StoreError, StoreStatus, WatchFilter, WriteBatch,
};
use tenko_vault::MemVault;
use tokio_util::sync::CancellationToken;

const KEY: &str = "update.example.test";
const ZONE: &str = "example.test";

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn cx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Dns)
}

fn wire_name(text: &str) -> Vec<u8> {
    name(text).to_wire()
}

/// A store that refuses every write while it is closed, as a store without quorum does.
#[derive(Debug)]
struct Gate {
    inner: Arc<MemStore>,
    closed: AtomicBool,
}

#[async_trait::async_trait]
impl Store for Gate {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(StoreError::NoQuorum);
        }
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

#[derive(Default)]
struct Refusals(Mutex<Vec<AuditDraft>>);

impl TransferAudit for Refusals {
    fn record(&self, draft: AuditDraft) {
        self.0.lock().expect("refusals").push(draft);
    }
}

struct Lab {
    store: Arc<Gate>,
    zones: Arc<ZoneService>,
    catalog: CatalogHandle,
    directory: Arc<Directory>,
    path: UpdatePath,
    zone: Zone,
    key: Arc<TsigKey>,
    refusals: Arc<Refusals>,
    stop: CancellationToken,
}

impl Drop for Lab {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

fn client(address: &str) -> Conn {
    Conn {
        client: SocketAddr::new(address.parse().expect("address"), 40_000),
        local: "192.0.2.53:53".parse().expect("local"),
        transport: QueryTransport::Udp,
    }
}

/// `example.test` with `www A 192.0.2.1`, `mail MX 10 Mail.example.test` and an `ipam`
/// RRset `host A 192.0.2.50`; updates allowed from the access list `updaters` (a deny for
/// 203.0.113.0/24, then the key) and `lan` (192.0.2.0/24), with `require_tsig`.
#[allow(clippy::too_many_lines, reason = "the whole fixture in one place")]
async fn lab_with(follow: bool, settings: UpdateSettings, profile: UpdateProfile) -> Lab {
    let memory = Arc::new(MemStore::default());
    let store = Arc::new(Gate {
        inner: Arc::clone(&memory),
        closed: AtomicBool::new(false),
    });
    let vault = Arc::new(MemVault::with_store(Arc::clone(&memory)));
    let zones = ZoneService::with_direct_jobs(
        Arc::clone(&store) as Arc<dyn Store>,
        Some(vault as Arc<dyn tenko_vault::Vault>),
        ZoneConfig::default(),
    );
    let created = zones
        .create_key(
            &cx(),
            NewKey {
                name: name(KEY),
                algorithm: TsigAlgorithm::HmacSha256,
                secret: None,
                description: None,
            },
        )
        .await
        .expect("key");
    let secret = domain::utils::base64::decode::<Vec<u8>>(created.secret.as_str()).expect("base64");
    let key = Arc::new(TsigKey::new(&name(KEY), TsigAlgorithm::HmacSha256, &secret));
    let (updaters, _) = zones
        .create_acl(
            &cx(),
            NewAcl {
                name: "updaters".to_owned(),
                entries: vec![
                    AclEntry::Prefix {
                        prefix: "203.0.113.0/24".parse().expect("prefix"),
                        deny: true,
                    },
                    AclEntry::Key {
                        name: name(KEY),
                        deny: false,
                    },
                ],
                description: None,
            },
        )
        .await
        .expect("acl");
    let (lan, _) = zones
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
                    allowed: vec![updaters.id, lan.id],
                    require_tsig: true,
                    may_replace_ipam: false,
                },
                dnssec: tenko_core::dns::DnssecPolicy::default(),
                source: None,
                description: None,
                reverse_of: None,
                catalog: false,
            },
        )
        .await
        .expect("zone");
    let zone = written.zone;
    let set = |owner: &str, rtype: Rtype, records: Vec<RecordData>, origin: Origin| Change {
        op: Op::Set,
        scope: ScopeName::DEFAULT,
        name: name(owner),
        rtype,
        ttl: Some(300),
        records,
        take_over: false,
        origin,
    };
    zones
        .change_records(
            &cx(),
            zone.id,
            &[
                set(
                    "www.example.test",
                    Rtype::A,
                    vec![RecordData::A {
                        address: "192.0.2.1".parse().expect("a"),
                    }],
                    Origin::Manual,
                ),
                set(
                    "mail.example.test",
                    Rtype::MX,
                    vec![RecordData::Mx {
                        preference: 10,
                        exchange: name("mail.example.test"),
                    }],
                    Origin::Manual,
                ),
            ],
            false,
        )
        .await
        .expect("records");
    zones
        .change_records(
            &cx(),
            zone.id,
            &[set(
                "host.example.test",
                Rtype::A,
                vec![RecordData::A {
                    address: "192.0.2.50".parse().expect("a"),
                }],
                Origin::Ipam,
            )],
            false,
        )
        .await
        .expect("ipam");
    let feed_store = Arc::clone(&store) as Arc<dyn Store>;
    let mut feed = store_feed::register(feed_store).expect("feed");
    let catalog = catalog::initial(&mut feed).await.expect("catalog");
    let stop = CancellationToken::new();
    if follow {
        tokio::spawn(catalog::follow(feed, catalog.clone(), stop.child_token()));
    }
    let directory = Arc::new(Directory::default());
    directory
        .load(&zones, &mut HashMap::new())
        .await
        .expect("directory");
    let refusals = Arc::new(Refusals::default());
    let path = UpdatePath::with_settings(
        catalog.clone(),
        Arc::clone(&directory),
        Arc::clone(&zones),
        Arc::new(ProfileCell::new(profile)),
        Arc::clone(&refusals) as Arc<dyn TransferAudit>,
        stop.child_token(),
        settings,
    );
    Lab {
        store,
        zones,
        catalog,
        directory,
        path,
        zone,
        key,
        refusals,
        stop,
    }
}

async fn lab() -> Lab {
    lab_with(true, UpdateSettings::default(), UpdateProfile::Standard).await
}

/// One RFC 2136 message under construction.
#[derive(Default)]
struct Msg {
    prereq: (u16, Vec<u8>),
    update: (u16, Vec<u8>),
}

impl Msg {
    fn pre(mut self, owner: &str, rtype: u16, class: u16, data: &[u8]) -> Self {
        push_record(&mut self.prereq.1, &wire_name(owner), rtype, class, 0, data);
        self.prereq.0 += 1;
        self
    }

    fn add(mut self, owner: &str, rtype: u16, ttl: u32, data: &[u8]) -> Self {
        push_record(
            &mut self.update.1,
            &wire_name(owner),
            rtype,
            CLASS_IN,
            ttl,
            data,
        );
        self.update.0 += 1;
        self
    }

    fn delete_rrset(mut self, owner: &str, rtype: u16) -> Self {
        push_record(
            &mut self.update.1,
            &wire_name(owner),
            rtype,
            CLASS_ANY,
            0,
            &[],
        );
        self.update.0 += 1;
        self
    }

    fn delete_name(self, owner: &str) -> Self {
        self.delete_rrset(owner, TYPE_ANY)
    }

    fn delete_record(mut self, owner: &str, rtype: u16, data: &[u8]) -> Self {
        push_record(
            &mut self.update.1,
            &wire_name(owner),
            rtype,
            CLASS_NONE,
            0,
            data,
        );
        self.update.0 += 1;
        self
    }

    fn bytes(&self, id: u16) -> Vec<u8> {
        let mut out = Vec::new();
        write_request(
            &mut out,
            id,
            &wire_name(ZONE),
            (self.prereq.0, &self.prereq.1),
            (self.update.0, &self.update.1),
        );
        out
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// What came back: the RCODE, the TSIG error when the answer carries one, the extended
/// error text.
#[derive(Debug)]
struct Got {
    rcode: u16,
    tsig_error: Option<u16>,
    text: Option<String>,
}

fn read(answer: &[u8]) -> Got {
    let header = wire::parse_header(answer).expect("header");
    assert!(header.qr);
    assert_eq!(header.opcode, 5);
    let tsig_error = tsig::find(answer).expect("tsig").map(|view| view.error);
    let mut text = None;
    let mut pos = wire::questions_end(answer, header.qdcount).expect("zone");
    for _ in 0..header.arcount {
        let record = wire::read_record(answer, pos).expect("record");
        if record.rtype == wire::TYPE_OPT {
            for (code, value) in wire::options(record.data(answer)) {
                if code == wire::OPTION_EXTENDED_ERROR && value.len() >= 2 {
                    text = Some(String::from_utf8_lossy(&value[2..]).into_owned());
                }
            }
        }
        pos = record.end();
    }
    Got {
        rcode: u16::from(header.rcode),
        tsig_error,
        text,
    }
}

impl Lab {
    /// Sends `msg` signed with the lab's key from `from`, with EDNS, and checks the
    /// answer's signature.
    async fn signed(&self, msg: &Msg, from: &str) -> Got {
        self.send(msg, from, Some(&self.key)).await
    }

    async fn send(&self, msg: &Msg, from: &str, key: Option<&Arc<TsigKey>>) -> Got {
        let mut message = msg.bytes(0x2136);
        // EDNS, so that the answer carries the extended error.
        message.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        message[11] = 1;
        let mut signer = key.map(|key| Signer::request(Arc::clone(key)));
        if let Some(signer) = &mut signer {
            assert!(signer.sign(&mut message, now(), 0, &[], MAX_MESSAGE_LEN));
        }
        let answer = self
            .path
            .answer(&message, &client(from))
            .await
            .expect("an answer");
        let got = read(&answer);
        if let (Some(signer), None | Some(0)) = (&signer, got.tsig_error) {
            let mut verifier = Verifier::new(
                Arc::clone(signer.key()),
                signer.last_mac().expect("request MAC"),
            );
            verifier
                .verify(&answer, now())
                .expect("the answer is signed");
        }
        got
    }

    /// The A records the index serves at `owner`.
    fn served(&self, owner: &str, rtype: Rtype) -> Vec<Vec<u8>> {
        let catalog = self.catalog.load();
        match catalog
            .index()
            .lookup(&DefaultScopes, &wire_name(owner), rtype)
        {
            Lookup::Answer { rrset, .. } => rrset
                .rdata
                .iter()
                .map(|rdata| rdata.as_bytes().to_vec())
                .collect(),
            _ => Vec::new(),
        }
    }

    async fn rrset(&self, owner: &str, rtype: Rtype) -> Option<tenko_core::dns::RrSet> {
        let view = self.zones.view(None).await.expect("view");
        let key = tenko_core::dns::RrSetKey {
            zone: self.zone.id,
            scope: ScopeName::DEFAULT,
            name: name(owner),
            rtype,
        };
        tenko_store::ReadViewExt::get_typed(view.as_ref(), &tenko_core::dns::tables::RRSETS, &key)
            .expect("read")
            .map(|(rrset, _)| rrset)
    }

    async fn serial(&self) -> u32 {
        let rrset = self.rrset(ZONE, Rtype::SOA).await.expect("soa");
        match rrset.records().expect("records").remove(0) {
            RecordData::Soa { serial, .. } => serial,
            _ => 0,
        }
    }

    async fn audit_actions(&self) -> Vec<String> {
        let view = self.zones.view(None).await.expect("view");
        tenko_store::ReadViewExt::scan_typed(
            view.as_ref(),
            &tenko_store::tables::AUDIT,
            tenko_store::KeyRange::all(),
            usize::MAX,
            false,
        )
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record.draft.action.as_str().to_owned())
        .collect()
    }
}

const A_9: [u8; 4] = [192, 0, 2, 9];
const A_10: [u8; 4] = [192, 0, 2, 10];

/// DNS-11: an update is answered once the index serves it.
#[tokio::test]
async fn an_add_is_answered_once_the_index_serves_it() {
    let lab = lab().await;
    let before = lab.serial().await;
    let got = lab
        .signed(
            &Msg::default().add("new.example.test", 1, 120, &A_9),
            "192.0.2.10",
        )
        .await;
    assert_eq!(got.rcode, 0, "{got:?}");
    assert_eq!(lab.served("new.example.test", Rtype::A), vec![A_9.to_vec()]);
    let rrset = lab
        .rrset("new.example.test", Rtype::A)
        .await
        .expect("rrset");
    assert_eq!((rrset.origin, rrset.ttl), (Origin::Dynamic, 120));
    assert_eq!(rrset.key.as_ref().map(DnsName::as_str), Some(KEY));
    assert_eq!(lab.serial().await, before + 1);
    assert!(
        lab.audit_actions()
            .await
            .iter()
            .any(|action| action == "dns.update.apply")
    );
}

#[tokio::test]
async fn replace_and_the_three_deletions() {
    let lab = lab().await;
    // Replace: delete the RRset and add in one update; the manual RRset becomes dynamic.
    let got = lab
        .signed(
            &Msg::default()
                .delete_rrset("www.example.test", 1)
                .add("www.example.test", 1, 300, &A_9)
                .add("www.example.test", 1, 300, &A_10),
            "192.0.2.10",
        )
        .await;
    assert_eq!(got.rcode, 0, "{got:?}");
    let mut served = lab.served("www.example.test", Rtype::A);
    served.sort();
    assert_eq!(served, vec![A_9.to_vec(), A_10.to_vec()]);
    // Delete one record.
    let got = lab
        .signed(
            &Msg::default().delete_record("www.example.test", 1, &A_9),
            "192.0.2.10",
        )
        .await;
    assert_eq!(got.rcode, 0);
    assert_eq!(
        lab.served("www.example.test", Rtype::A),
        vec![A_10.to_vec()]
    );
    // Delete a name.
    let got = lab
        .signed(
            &Msg::default().delete_name("www.example.test"),
            "192.0.2.10",
        )
        .await;
    assert_eq!(got.rcode, 0);
    assert_eq!(
        lab.served("www.example.test", Rtype::A),
        Vec::<Vec<u8>>::new()
    );
    // The apex keeps its SOA and NS through a deletion of the name and of the NS set.
    let got = lab
        .signed(
            &Msg::default().delete_name(ZONE).delete_rrset(ZONE, 2),
            "192.0.2.10",
        )
        .await;
    assert_eq!(got.rcode, 0);
    assert!(lab.rrset(ZONE, Rtype::SOA).await.is_some());
    assert!(lab.rrset(ZONE, Rtype::NS).await.is_some());
}

#[tokio::test]
async fn each_prerequisite_is_tested() {
    let lab = lab().await;
    let www = "www.example.test";
    let nothing = "nothing.example.test";
    let mx = b"\x00\x0a\x04MAIL\x07Example\x04TEST\x00";
    let cases: [(Msg, u16); 10] = [
        (Msg::default().pre(www, 1, CLASS_ANY, &[]), 0),
        (
            Msg::default().pre(nothing, 1, CLASS_ANY, &[]),
            rcode::NXRRSET,
        ),
        (Msg::default().pre(www, 1, CLASS_NONE, &[]), rcode::YXRRSET),
        (Msg::default().pre(nothing, 1, CLASS_NONE, &[]), 0),
        (Msg::default().pre(www, TYPE_ANY, CLASS_ANY, &[]), 0),
        (
            Msg::default().pre(nothing, TYPE_ANY, CLASS_ANY, &[]),
            rcode::NXDOMAIN,
        ),
        (
            Msg::default().pre(www, TYPE_ANY, CLASS_NONE, &[]),
            rcode::YXDOMAIN,
        ),
        (Msg::default().pre(nothing, TYPE_ANY, CLASS_NONE, &[]), 0),
        // Value dependent, compared in canonical form: the exchange in another case.
        (Msg::default().pre("mail.example.test", 15, CLASS_IN, mx), 0),
        (
            Msg::default()
                .pre(www, 1, CLASS_IN, &[192, 0, 2, 1])
                .pre(www, 1, CLASS_IN, &A_9),
            rcode::NXRRSET,
        ),
    ];
    for (index, (msg, want)) in cases.iter().enumerate() {
        let got = lab.signed(msg, "192.0.2.10").await;
        assert_eq!(got.rcode, *want, "case {index}: {got:?}");
        if *want != 0 {
            assert!(
                got.text
                    .as_deref()
                    .is_some_and(|text| text.starts_with("prerequisite"))
            );
        }
    }
    // A prerequisite that does not hold leaves the update unapplied.
    let got = lab
        .signed(
            &Msg::default()
                .pre(nothing, TYPE_ANY, CLASS_ANY, &[])
                .add(nothing, 1, 60, &A_9),
            "192.0.2.10",
        )
        .await;
    assert_eq!(got.rcode, rcode::NXDOMAIN);
    assert!(lab.rrset(nothing, Rtype::A).await.is_none());
}

/// DNS-11: TSIG and the access lists decide.
#[tokio::test]
async fn the_key_and_the_access_lists_decide() {
    let lab = lab().await;
    let add = Msg::default().add("new.example.test", 1, 60, &A_9);
    // Unsigned: the zone requires TSIG.
    let got = lab.send(&add, "192.0.2.10", None).await;
    assert_eq!(got.rcode, rcode::REFUSED);
    assert_eq!(
        got.text.as_deref(),
        Some("the zone's updates need a TSIG key")
    );
    // Signed, but from an address the first entry of `updaters` denies and `lan` does
    // not hold.
    let got = lab.signed(&add, "203.0.113.5").await;
    assert_eq!(got.rcode, rcode::REFUSED);
    assert_eq!(
        got.text.as_deref(),
        Some("the client is not in the zone's update access lists")
    );
    // An unknown key: NOTAUTH with BADKEY.
    let stranger = Arc::new(TsigKey::new(
        &name("stranger.example.test"),
        TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef",
    ));
    let got = lab.send(&add, "192.0.2.10", Some(&stranger)).await;
    assert_eq!((got.rcode, got.tsig_error), (rcode::NOTAUTH, Some(17)));
    // The right name with the wrong secret: BADSIG.
    let forged = Arc::new(TsigKey::new(
        &name(KEY),
        TsigAlgorithm::HmacSha256,
        b"not the secret of the key at all",
    ));
    let got = lab.send(&add, "192.0.2.10", Some(&forged)).await;
    assert_eq!((got.rcode, got.tsig_error), (rcode::NOTAUTH, Some(16)));
    assert!(lab.rrset("new.example.test", Rtype::A).await.is_none());
    let refusals = lab.refusals.0.lock().expect("refusals");
    assert!(
        refusals
            .iter()
            .all(|draft| draft.action.as_str() == "dns.update.refuse")
    );
    assert!(!refusals.is_empty());
}

/// TGL-09: the Lab profile takes unsigned updates from the lists.
#[tokio::test]
async fn the_lab_profile_takes_unsigned_updates_from_the_lists() {
    let lab = lab_with(true, UpdateSettings::default(), UpdateProfile::Lab).await;
    let got = lab
        .send(
            &Msg::default().add("lab.example.test", 1, 60, &A_9),
            "192.0.2.10",
            None,
        )
        .await;
    assert_eq!(got.rcode, 0, "{got:?}");
    let rrset = lab
        .rrset("lab.example.test", Rtype::A)
        .await
        .expect("rrset");
    assert_eq!((rrset.origin, rrset.key), (Origin::Dynamic, None));
    let got = lab
        .send(
            &Msg::default().add("lab.example.test", 1, 60, &A_10),
            "198.51.100.7",
            None,
        )
        .await;
    assert_eq!(got.rcode, rcode::REFUSED, "outside the lists");
}

#[tokio::test]
async fn an_ipam_rrset_is_replaced_only_when_the_zone_allows_it() {
    let lab = lab().await;
    let msg = Msg::default()
        .add("new.example.test", 1, 60, &A_9)
        .delete_rrset("host.example.test", 1);
    let got = lab.signed(&msg, "192.0.2.10").await;
    assert_eq!(got.rcode, rcode::REFUSED);
    assert!(
        got.text
            .as_deref()
            .is_some_and(|text| text.starts_with("host.example.test A belongs to IPAM")),
        "{got:?}"
    );
    assert!(
        lab.rrset("new.example.test", Rtype::A).await.is_none(),
        "all or nothing"
    );
    let row = lab.zone.clone();
    lab.zones
        .update(
            &cx(),
            row.id,
            ZoneChange {
                update: Some(UpdatePolicy {
                    may_replace_ipam: true,
                    ..row.update.clone()
                }),
                ..ZoneChange::default()
            },
            None,
        )
        .await
        .expect("policy");
    lab.directory
        .load(&lab.zones, &mut HashMap::new())
        .await
        .expect("directory");
    let got = lab.signed(&msg, "192.0.2.10").await;
    assert_eq!(got.rcode, 0, "{got:?}");
    assert!(lab.rrset("host.example.test", Rtype::A).await.is_none());
}

#[tokio::test]
async fn a_write_the_store_refuses_is_servfail_and_writes_nothing() {
    let lab = lab().await;
    let before = lab.serial().await;
    lab.store.closed.store(true, Ordering::SeqCst);
    let got = lab
        .signed(
            &Msg::default().add("new.example.test", 1, 60, &A_9),
            "192.0.2.10",
        )
        .await;
    assert_eq!(got.rcode, rcode::SERVFAIL);
    assert!(
        got.text
            .as_deref()
            .is_some_and(|text| text.contains("sys.store.no_quorum")),
        "{got:?}"
    );
    lab.store.closed.store(false, Ordering::SeqCst);
    assert!(lab.rrset("new.example.test", Rtype::A).await.is_none());
    assert_eq!(lab.serial().await, before);
    let got = lab
        .signed(
            &Msg::default().add("new.example.test", 1, 60, &A_9),
            "192.0.2.10",
        )
        .await;
    assert_eq!(
        got.rcode, 0,
        "the client retries once the store writes again"
    );
}

#[tokio::test]
async fn an_index_that_does_not_follow_answers_not_ready() {
    let settings = UpdateSettings {
        index_wait: Duration::from_millis(50),
        ..UpdateSettings::default()
    };
    let lab = lab_with(false, settings, UpdateProfile::Standard).await;
    let got = lab
        .signed(
            &Msg::default().add("new.example.test", 1, 60, &A_9),
            "192.0.2.10",
        )
        .await;
    assert_eq!(got.rcode, rcode::SERVFAIL);
    assert!(
        lab.rrset("new.example.test", Rtype::A).await.is_some(),
        "committed"
    );
}

#[tokio::test]
async fn the_format_answers() {
    let lab = lab().await;
    let mut other = Vec::new();
    write_request(&mut other, 1, &wire_name("other.test"), (0, &[]), (0, &[]));
    let answer = lab
        .path
        .answer(&other, &client("192.0.2.10"))
        .await
        .expect("answer");
    assert_eq!(read(&answer).rcode, rcode::NOTAUTH);
    let mut outside = Vec::new();
    push_record(
        &mut outside,
        &wire_name("www.other.test"),
        1,
        CLASS_IN,
        60,
        &A_9,
    );
    let mut message = Vec::new();
    write_request(&mut message, 1, &wire_name(ZONE), (0, &[]), (1, &outside));
    let answer = lab
        .path
        .answer(&message, &client("192.0.2.10"))
        .await
        .expect("answer");
    assert_eq!(read(&answer).rcode, rcode::NOTZONE);
    message.truncate(message.len() - 2);
    let answer = lab
        .path
        .answer(&message, &client("192.0.2.10"))
        .await
        .expect("answer");
    assert_eq!(read(&answer).rcode, rcode::FORMERR);
    message[2] |= 0x80;
    assert!(
        lab.path
            .answer(&message, &client("192.0.2.10"))
            .await
            .is_none(),
        "a response"
    );
}

#[tokio::test]
async fn concurrent_updates_of_one_zone_all_land() {
    let lab = Arc::new(lab().await);
    let before = lab.serial().await;
    let mut tasks = Vec::new();
    for index in 0..64u8 {
        let lab = Arc::clone(&lab);
        tasks.push(tokio::spawn(async move {
            let owner = format!("h{index}.example.test");
            lab.signed(
                &Msg::default().add(&owner, 1, 60, &[192, 0, 2, index]),
                "192.0.2.10",
            )
            .await
            .rcode
        }));
    }
    for task in tasks {
        assert_eq!(task.await.expect("task"), 0);
    }
    for index in 0..64u8 {
        let owner = format!("h{index}.example.test");
        assert_eq!(lab.served(&owner, Rtype::A), vec![vec![192, 0, 2, index]]);
    }
    let steps = lab.serial().await - before;
    assert!(
        (1..=64).contains(&steps),
        "one serial step per commit: {steps}"
    );
}

#[tokio::test]
async fn cname_rules_and_the_soa_are_kept() {
    let lab = lab().await;
    // A CNAME at a name that holds data is ignored, data beside a CNAME too.
    let got = lab
        .signed(
            &Msg::default()
                .add("www.example.test", 5, 60, &wire_name("mail.example.test"))
                .add("alias.example.test", 5, 60, &wire_name("www.example.test"))
                .add("alias.example.test", 1, 60, &A_9)
                .add(ZONE, 6, 60, &[0; 22]),
            "192.0.2.10",
        )
        .await;
    assert_eq!(got.rcode, 0, "{got:?}");
    assert!(lab.rrset("www.example.test", Rtype::CNAME).await.is_none());
    assert!(
        lab.rrset("alias.example.test", Rtype::CNAME)
            .await
            .is_some()
    );
    assert!(lab.rrset("alias.example.test", Rtype::A).await.is_none());
}
