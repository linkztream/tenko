//! GSS-TSIG on the update path (WP13.2; DNS-28, TGL-09; identity plan sections 3.3 to
//! 3.6): TKEY through the update path, updates signed on a context, the principal's policy,
//! the ownership table of section 3.6 with `dns.name_owners`, the refusals of E43 (unknown
//! and expired contexts, a skewed signature, a replay), over a zone service on an
//! in-memory store and the catalog the node answers from.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use tenko_core::{
    RequestCtx, SystemComponent,
    audit::AuditDraft,
    dns::{
        AclEntry, DnsName, KerberosUpdate, NameOwner, NameOwnerKey, Origin, OwnerSource, Ownership,
        PrincipalName, QueryTransport, Realm, RecordData, Rtype, ScopeName, SerialPolicy, Sid,
        SoaDefaults, TsigAlgorithm, UpdatePolicy, Zone, ZoneKind, tables::NAME_OWNERS,
    },
    timestamp::Timestamp,
};
use tenko_dns::{
    catalog::{self, CatalogHandle},
    respond::Conn,
    store_feed,
    tkey::{
        GssContext, GssSettings, Tkey,
        testing::{Initiator, SPN, key, key_set, pair, realm},
        wire::{self as tkey_wire, answer_record, mode},
    },
    tsig::{self, GSS_TSIG, MacKey, Signer, TsigKey, Verifier},
    update::{
        UpdatePath, UpdateSettings,
        message::{CLASS_ANY, CLASS_IN, TYPE_ANY, push_record, write_request},
        policy::{ProfileCell, UpdateProfile},
    },
    wire::{self, MAX_MESSAGE_LEN},
    xfr::{Directory, TransferAudit},
    zone::{
        NewZone, ZoneConfig, ZoneService,
        acl::NewAcl,
        keys::NewKey,
        records::{Change, Op},
    },
};
use tenko_store::{MemStore, ReadViewExt as _, Store, WriteBatch};
use tenko_vault::MemVault;
use tokio_util::sync::CancellationToken;

const ZONE: &str = "corp.example.test";
const KEY: &str = "update.corp.example.test";
const DOMAIN: &str = "S-1-5-21-1000-2000-3000";

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn cx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Dns)
}

fn sid(rid: u32) -> Sid {
    Sid::parse(&format!("{DOMAIN}-{rid}")).expect("sid")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

#[derive(Default)]
struct Audit(Mutex<Vec<AuditDraft>>);

impl TransferAudit for Audit {
    fn record(&self, draft: AuditDraft) {
        self.0.lock().expect("audit").push(draft);
    }
}

/// A principal of the tests and the two sides of its context.
struct Who {
    client: Arc<GssContext>,
    from: &'static str,
}

struct Lab {
    memory: Arc<MemStore>,
    zones: Arc<ZoneService>,
    path: UpdatePath,
    tkey: Arc<Tkey>,
    zone: Zone,
    hmac: Arc<TsigKey>,
    catalog: CatalogHandle,
    stop: CancellationToken,
    names: Mutex<u32>,
}

impl Drop for Lab {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

fn conn(from: &str) -> Conn {
    Conn {
        client: SocketAddr::new(from.parse().expect("address"), 40_000),
        local: "192.0.2.53:53".parse().expect("local"),
        transport: QueryTransport::Tcp,
    }
}

/// `corp.example.test`, secure only with ownership on: the list `ad-corp` takes every
/// principal of `CORP.EXAMPLE.TEST` and the TSIG key; Domain Admins (512) and Domain
/// Controllers (516) are privileged, group 1101 is `DnsUpdateProxy`. Records: `www` manual,
/// `host` from IPAM, `legacy` imported from AD without an owner, `old` dynamic without an
/// owner (written by TSIG before ownership).
#[allow(clippy::too_many_lines, reason = "the whole fixture in one place")]
async fn lab_with(ownership: Ownership, profile: UpdateProfile) -> Lab {
    let memory = Arc::new(MemStore::default());
    let vault = Arc::new(MemVault::with_store(Arc::clone(&memory)));
    let zones = ZoneService::with_direct_jobs(
        Arc::clone(&memory) as Arc<dyn Store>,
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
    let secret = tenko_dns::zone::encoding::base64_decode(created.secret.as_str()).expect("b64");
    let hmac = Arc::new(TsigKey::new(&name(KEY), TsigAlgorithm::HmacSha256, &secret));
    let (list, _) = zones
        .create_acl(
            &cx(),
            NewAcl {
                name: "ad-corp".to_owned(),
                entries: vec![
                    AclEntry::Kerberos {
                        realm: realm(),
                        principal: None,
                        from: None,
                        deny: false,
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
    let mut kerberos = KerberosUpdate::for_realm(realm());
    kerberos.ownership = ownership;
    kerberos.privileged = vec![sid(512), sid(516)];
    kerberos.update_proxy = Some(sid(1101));
    let written = zones
        .create(
            &cx(),
            NewZone {
                name: name(ZONE),
                kind: ZoneKind::Primary,
                tenant: None,
                scopes: Vec::new(),
                serial: SerialPolicy::Counter,
                soa: SoaDefaults::new(
                    name("ns1.corp.example.test"),
                    name("hostmaster.corp.example.test"),
                ),
                name_servers: vec![name("ns1.corp.example.test")],
                transfer: tenko_core::dns::TransferPolicy::default(),
                update: UpdatePolicy {
                    allowed: vec![list.id],
                    require_tsig: true,
                    may_replace_ipam: false,
                    dhcp: None,
                    kerberos: Some(kerberos),
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
    let a = |owner: &str, last: u8, origin: Origin| Change {
        op: Op::Set,
        scope: ScopeName::DEFAULT,
        name: name(owner),
        rtype: Rtype::A,
        ttl: Some(300),
        records: vec![RecordData::A {
            address: std::net::Ipv4Addr::new(192, 0, 2, last),
        }],
        take_over: false,
        origin,
    };
    for change in [
        a("www.corp.example.test", 1, Origin::Manual),
        a("host.corp.example.test", 50, Origin::Ipam),
        a("legacy.corp.example.test", 60, Origin::Ad),
        a("old.corp.example.test", 70, Origin::Dynamic),
    ] {
        zones
            .change_records(&cx(), zone.id, &[change], false)
            .await
            .expect("records");
    }
    let mut feed = store_feed::register(Arc::clone(&memory) as Arc<dyn Store>).expect("feed");
    let catalog = catalog::initial(&mut feed).await.expect("catalog");
    let stop = CancellationToken::new();
    tokio::spawn(catalog::follow(feed, catalog.clone(), stop.child_token()));
    let directory = Arc::new(Directory::default());
    directory
        .load(&zones, &mut HashMap::new())
        .await
        .expect("directory");
    let tkey = Tkey::new(GssSettings::default());
    let path = UpdatePath::with_settings(
        catalog.clone(),
        directory,
        Arc::clone(&zones),
        Arc::new(ProfileCell::new(profile)),
        Arc::new(Audit::default()) as Arc<dyn TransferAudit>,
        stop.child_token(),
        UpdateSettings::default(),
    )
    .with_gss(Arc::clone(&tkey));
    Lab {
        memory,
        zones,
        path,
        tkey,
        zone,
        hmac,
        catalog,
        stop,
        names: Mutex::new(0),
    }
}

async fn lab() -> Lab {
    lab_with(Ownership::Windows, UpdateProfile::Standard).await
}

/// An update under construction.
#[derive(Default)]
struct Msg {
    update: (u16, Vec<u8>),
}

impl Msg {
    fn add_a(mut self, owner: &str, last: u8) -> Self {
        push_record(
            &mut self.update.1,
            &name(owner).to_wire(),
            1,
            CLASS_IN,
            300,
            &[192, 0, 2, last],
        );
        self.update.0 += 1;
        self
    }

    fn add_srv(mut self, owner: &str) -> Self {
        let mut data = vec![0, 0, 0, 100, 1, 133];
        data.extend_from_slice(&name("dc01.corp.example.test").to_wire());
        push_record(
            &mut self.update.1,
            &name(owner).to_wire(),
            33,
            CLASS_IN,
            600,
            &data,
        );
        self.update.0 += 1;
        self
    }

    fn delete_name(mut self, owner: &str) -> Self {
        push_record(
            &mut self.update.1,
            &name(owner).to_wire(),
            TYPE_ANY,
            CLASS_ANY,
            0,
            &[],
        );
        self.update.0 += 1;
        self
    }

    fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_request(
            &mut out,
            0x2136,
            &name(ZONE).to_wire(),
            (0, &[]),
            (self.update.0, &self.update.1),
        );
        out
    }
}

/// What came back.
#[derive(Debug, PartialEq, Eq)]
struct Got {
    rcode: u8,
    tsig_error: Option<u16>,
}

fn read(answer: &[u8]) -> Got {
    let header = wire::parse_header(answer).expect("header");
    Got {
        rcode: header.rcode,
        tsig_error: tsig::find(answer).expect("tsig").map(|view| view.error),
    }
}

const NOERROR: Got = Got {
    rcode: 0,
    tsig_error: Some(0),
};
const REFUSED: Got = Got {
    rcode: 5,
    tsig_error: Some(0),
};

impl Lab {
    /// A principal with its context adopted by the node.
    fn who(&self, principal: &str, sid: Option<Sid>, groups: Vec<Sid>, from: &'static str) -> Who {
        let mut count = self.names.lock().expect("names");
        *count += 1;
        let label = format!("ctx-{count}");
        let mut key_name = vec![u8::try_from(label.len()).expect("short")];
        key_name.extend_from_slice(label.as_bytes());
        key_name.extend_from_slice(&name(ZONE).to_wire());
        let address: IpAddr = from.parse().expect("address");
        let (acceptor, client) = pair(&key_name, principal, sid, groups, address, now());
        self.tkey.adopt(acceptor);
        Who { client, from }
    }

    /// Sends `msg` signed by `who` and checks the answer's signature.
    async fn gss(&self, who: &Who, msg: &Msg) -> Got {
        let mut message = msg.bytes();
        let mut signer = Signer::request(MacKey::Gss(Arc::clone(&who.client)));
        assert!(signer.sign(&mut message, now(), 0, &[], MAX_MESSAGE_LEN));
        let answer = self
            .path
            .answer(&message, &conn(who.from))
            .await
            .expect("an answer");
        let got = read(&answer);
        if got.tsig_error == Some(0) {
            let mut verifier = Verifier::new(
                MacKey::Gss(Arc::clone(&who.client)),
                signer.last_mac().expect("mac"),
            );
            verifier
                .verify(&answer, now())
                .expect("the answer is signed with the context");
        }
        got
    }

    async fn tsig(&self, msg: &Msg) -> Got {
        let mut message = msg.bytes();
        let mut signer = Signer::request(Arc::clone(&self.hmac));
        assert!(signer.sign(&mut message, now(), 0, &[], MAX_MESSAGE_LEN));
        read(
            &self
                .path
                .answer(&message, &conn("192.0.2.200"))
                .await
                .expect("an answer"),
        )
    }

    async fn owner(&self, owner: &str) -> Option<NameOwner> {
        let view = self.zones.view(None).await.expect("view");
        view.get_typed(
            &NAME_OWNERS,
            &NameOwnerKey {
                zone: self.zone.id,
                scope: ScopeName::DEFAULT,
                name: name(owner),
            },
        )
        .expect("read")
        .map(|(owner, _)| owner)
    }

    async fn rrset(&self, owner: &str, rtype: Rtype) -> Option<tenko_core::dns::RrSet> {
        let view = self.zones.view(None).await.expect("view");
        view.get_typed(
            &tenko_core::dns::tables::RRSETS,
            &tenko_core::dns::RrSetKey {
                zone: self.zone.id,
                scope: ScopeName::DEFAULT,
                name: name(owner),
                rtype,
            },
        )
        .expect("read")
        .map(|(rrset, _)| rrset)
    }

    async fn audit(&self) -> Vec<AuditDraft> {
        let view = self.zones.view(None).await.expect("view");
        view.scan_typed(
            &tenko_store::tables::AUDIT,
            tenko_store::KeyRange::all(),
            usize::MAX,
            false,
        )
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record.draft)
        .collect()
    }

    async fn set_hold(&self, owner: &str, until: Timestamp) {
        let mut row = self.owner(owner).await.expect("an owner");
        row.hold_until = Some(until);
        let mut batch = WriteBatch::for_request(&cx());
        batch
            .put_typed(
                &NAME_OWNERS,
                &NameOwnerKey {
                    zone: self.zone.id,
                    scope: ScopeName::DEFAULT,
                    name: name(owner),
                },
                &row,
            )
            .expect("encode");
        self.memory.propose(batch).await.expect("write");
    }
}

fn context_of(draft: &AuditDraft, key: &str) -> Option<String> {
    draft.details.context.get(key).cloned()
}

/// DNS-28: an update signed with GSS-TSIG is verified on the node's context, applied, and
/// answered signed with the context; the RRset records the principal, the name gets its
/// creator as owner, and the audit record carries the principal, its SID and the decision.
#[tokio::test]
async fn dns_28_a_gss_tsig_update_records_its_principal_and_owner() {
    let lab = lab().await;
    let alice = lab.who(
        "pc01$@CORP.EXAMPLE.TEST",
        Some(sid(1001)),
        vec![sid(515)],
        "192.0.2.21",
    );
    assert_eq!(
        lab.gss(&alice, &Msg::default().add_a("pc01.corp.example.test", 21))
            .await,
        NOERROR
    );
    let rrset = lab
        .rrset("pc01.corp.example.test", Rtype::A)
        .await
        .expect("written");
    assert_eq!(rrset.origin, Origin::Dynamic);
    assert_eq!(rrset.key, None);
    assert_eq!(
        rrset.principal,
        Some(PrincipalName::parse("pc01$@CORP.EXAMPLE.TEST").expect("principal"))
    );
    let owner = lab.owner("pc01.corp.example.test").await.expect("an owner");
    assert_eq!(owner.sid, Some(sid(1001)));
    assert_eq!(owner.hold_until, None);
    let applied = lab
        .audit()
        .await
        .into_iter()
        .find(|draft| draft.action.as_str() == "dns.update.apply")
        .expect("audited");
    assert_eq!(
        context_of(&applied, "principal").as_deref(),
        Some("pc01$@CORP.EXAMPLE.TEST")
    );
    assert_eq!(context_of(&applied, "sid"), Some(sid(1001).to_string()));
    assert_eq!(context_of(&applied, "ownership").as_deref(), Some("owner"));
    assert_eq!(context_of(&applied, "key"), None);
}

/// DNS-28, E46: the rows of the ownership table of section 3.6 that need no imported owner
/// SIDs from a Windows source: a new name, an owned name, the owner, a privileged group, a member of
/// `DnsUpdateProxy`, the locator names, a record of IPAM, a manual record, a TSIG update.
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the table of section 3.6 in one sequence"
)]
async fn dns_28_e46_the_ownership_table() {
    let lab = lab().await;
    let alice = lab.who(
        "pc01$@CORP.EXAMPLE.TEST",
        Some(sid(1001)),
        vec![sid(515)],
        "192.0.2.21",
    );
    let bob = lab.who(
        "pc02$@CORP.EXAMPLE.TEST",
        Some(sid(1002)),
        vec![sid(515)],
        "192.0.2.22",
    );
    let dc = lab.who(
        "dc01$@CORP.EXAMPLE.TEST",
        Some(sid(1000)),
        vec![sid(516)],
        "192.0.2.2",
    );
    let proxy = lab.who(
        "dhcp$@CORP.EXAMPLE.TEST",
        Some(sid(1003)),
        vec![sid(1101)],
        "192.0.2.3",
    );
    // A new name: the creator owns it.
    let pc01 = "pc01.corp.example.test";
    assert_eq!(
        lab.gss(&alice, &Msg::default().add_a(pc01, 21)).await,
        NOERROR
    );
    // An owned name: another principal is refused, the owner and a privileged one pass.
    assert_eq!(
        lab.gss(&bob, &Msg::default().add_a(pc01, 22)).await,
        REFUSED
    );
    assert_eq!(
        lab.gss(&alice, &Msg::default().add_a(pc01, 23)).await,
        NOERROR
    );
    assert_eq!(lab.gss(&dc, &Msg::default().add_a(pc01, 24)).await, NOERROR);
    assert_eq!(
        lab.owner(pc01).await.expect("owner").sid,
        Some(sid(1001)),
        "kept"
    );
    // TSIG does not change an owned name, and takes no ownership elsewhere.
    assert_eq!(lab.tsig(&Msg::default().add_a(pc01, 25)).await, REFUSED);
    assert_eq!(
        lab.tsig(&Msg::default().add_a("printer.corp.example.test", 26))
            .await,
        NOERROR
    );
    assert_eq!(lab.owner("printer.corp.example.test").await, None);
    // Dynamic records without an owner: the next principal becomes the owner.
    assert_eq!(
        lab.gss(&bob, &Msg::default().add_a("old.corp.example.test", 71))
            .await,
        NOERROR
    );
    assert_eq!(
        lab.owner("old.corp.example.test").await.expect("owner").sid,
        Some(sid(1002))
    );
    // DnsUpdateProxy leaves a new name unowned; the next principal owns it.
    let pc09 = "pc09.corp.example.test";
    assert_eq!(
        lab.gss(&proxy, &Msg::default().add_a(pc09, 90)).await,
        NOERROR
    );
    assert_eq!(lab.owner(pc09).await, None);
    assert_eq!(
        lab.gss(&bob, &Msg::default().add_a(pc09, 91)).await,
        NOERROR
    );
    assert_eq!(lab.owner(pc09).await.expect("owner").sid, Some(sid(1002)));
    // Locator names: privileged principals only, and no owner kept.
    let ldap = "_ldap._tcp.corp.example.test";
    assert_eq!(
        lab.gss(&alice, &Msg::default().add_srv(ldap)).await,
        REFUSED
    );
    assert_eq!(lab.gss(&dc, &Msg::default().add_srv(ldap)).await, NOERROR);
    assert_eq!(lab.owner(ldap).await, None);
    assert_eq!(
        lab.gss(&alice, &Msg::default().add_a(ZONE, 99)).await,
        REFUSED,
        "the apex"
    );
    // A record of IPAM: the origin rule refuses it, for a privileged principal too.
    assert_eq!(
        lab.gss(&dc, &Msg::default().add_a("host.corp.example.test", 51))
            .await,
        REFUSED
    );
    // A manual record: privileged principals only.
    assert_eq!(
        lab.gss(&alice, &Msg::default().add_a("www.corp.example.test", 2))
            .await,
        REFUSED
    );
    assert_eq!(
        lab.gss(&dc, &Msg::default().add_a("www.corp.example.test", 2))
            .await,
        NOERROR
    );
    // WP13.4: a privileged principal that writes a name without an owner owns it, as the
    // creator does on Windows; another principal cannot take it afterwards.
    let www = lab.owner("www.corp.example.test").await.expect("owned");
    assert_eq!(www.sid, Some(sid(1000)));
    assert_eq!(
        lab.gss(&bob, &Msg::default().add_a("www.corp.example.test", 3))
            .await,
        REFUSED
    );
}

/// DNS-28, E46: a record imported from AD without an owner is claimed only by the host it
/// names (or changed by a privileged principal); the claimant becomes the owner.
#[tokio::test]
async fn dns_28_e46_an_imported_name_is_claimed_by_its_own_host() {
    let lab = lab().await;
    let bob = lab.who(
        "pc02$@CORP.EXAMPLE.TEST",
        Some(sid(1002)),
        vec![sid(515)],
        "192.0.2.22",
    );
    let legacy = lab.who(
        "LEGACY$@CORP.EXAMPLE.TEST",
        Some(sid(1004)),
        vec![sid(515)],
        "192.0.2.60",
    );
    let name = "legacy.corp.example.test";
    assert_eq!(
        lab.gss(&bob, &Msg::default().add_a(name, 61)).await,
        REFUSED
    );
    assert_eq!(
        lab.gss(&legacy, &Msg::default().add_a(name, 61)).await,
        NOERROR
    );
    let owner = lab.owner(name).await.expect("claimed");
    assert_eq!(owner.sid, Some(sid(1004)));
    let applied = lab
        .audit()
        .await
        .into_iter()
        .rfind(|draft| draft.action.as_str() == "dns.update.apply")
        .expect("audited");
    assert_eq!(
        context_of(&applied, "ownership").as_deref(),
        Some("claimed")
    );
}

/// DNS-28, E46: a name whose last record went keeps its owner for the hold: another
/// principal is refused within it, the owner may come back (the hold ends), and once the
/// hold has passed the name is new again.
#[tokio::test]
async fn dns_28_e46_a_removed_name_is_held_for_its_owner() {
    let lab = lab().await;
    let alice = lab.who(
        "pc01$@CORP.EXAMPLE.TEST",
        Some(sid(1001)),
        vec![sid(515)],
        "192.0.2.21",
    );
    let bob = lab.who(
        "pc02$@CORP.EXAMPLE.TEST",
        Some(sid(1002)),
        vec![sid(515)],
        "192.0.2.22",
    );
    let pc01 = "pc01.corp.example.test";
    assert_eq!(
        lab.gss(&alice, &Msg::default().add_a(pc01, 21)).await,
        NOERROR
    );
    assert_eq!(
        lab.gss(&alice, &Msg::default().delete_name(pc01)).await,
        NOERROR
    );
    let held = lab.owner(pc01).await.expect("held");
    let until = held.hold_until.expect("a hold");
    let days = until.unix_nanos() - held.since.unix_nanos();
    assert!(
        days >= 14 * 86_400 * 1_000_000_000,
        "fourteen days by default"
    );
    assert_eq!(
        lab.gss(&bob, &Msg::default().add_a(pc01, 22)).await,
        REFUSED,
        "within the hold"
    );
    assert_eq!(
        lab.tsig(&Msg::default().add_a(pc01, 22)).await,
        REFUSED,
        "TSIG too"
    );
    assert_eq!(
        lab.gss(&alice, &Msg::default().add_a(pc01, 23)).await,
        NOERROR,
        "the owner"
    );
    assert_eq!(
        lab.owner(pc01).await.expect("owner").hold_until,
        None,
        "the hold ended"
    );
    // After the hold the name is new again.
    assert_eq!(
        lab.gss(&alice, &Msg::default().delete_name(pc01)).await,
        NOERROR
    );
    let past = Timestamp::now()
        .checked_sub(Duration::from_secs(60))
        .expect("a past time");
    lab.set_hold(pc01, past).await;
    assert_eq!(
        lab.gss(&bob, &Msg::default().add_a(pc01, 24)).await,
        NOERROR,
        "after the hold"
    );
    assert_eq!(lab.owner(pc01).await.expect("owner").sid, Some(sid(1002)));
}

/// DNS-28: an MIT principal (no PAC, no SID) owns by name; with `ownership = none` a zone
/// keeps no owners, unless the Hardened profile is in force.
#[tokio::test]
async fn dns_28_ownership_by_name_and_the_profiles() {
    let lab = lab().await;
    let carol = lab.who("carol@CORP.EXAMPLE.TEST", None, Vec::new(), "192.0.2.30");
    let dave = lab.who("dave@CORP.EXAMPLE.TEST", None, Vec::new(), "192.0.2.31");
    let ws = "ws.corp.example.test";
    assert_eq!(
        lab.gss(&carol, &Msg::default().add_a(ws, 30)).await,
        NOERROR
    );
    assert_eq!(lab.gss(&dave, &Msg::default().add_a(ws, 31)).await, REFUSED);
    assert_eq!(
        lab.gss(&carol, &Msg::default().add_a(ws, 32)).await,
        NOERROR
    );
    let off = lab_with(Ownership::None, UpdateProfile::Standard).await;
    let carol = off.who("carol@CORP.EXAMPLE.TEST", None, Vec::new(), "192.0.2.30");
    let dave = off.who("dave@CORP.EXAMPLE.TEST", None, Vec::new(), "192.0.2.31");
    assert_eq!(
        off.gss(&carol, &Msg::default().add_a(ws, 30)).await,
        NOERROR
    );
    assert_eq!(off.owner(ws).await, None);
    assert_eq!(off.gss(&dave, &Msg::default().add_a(ws, 31)).await, NOERROR);
    let hardened = lab_with(Ownership::None, UpdateProfile::Hardened).await;
    let carol = hardened.who("carol@CORP.EXAMPLE.TEST", None, Vec::new(), "192.0.2.30");
    let dave = hardened.who("dave@CORP.EXAMPLE.TEST", None, Vec::new(), "192.0.2.31");
    assert_eq!(
        hardened.gss(&carol, &Msg::default().add_a(ws, 30)).await,
        NOERROR
    );
    assert_eq!(
        hardened.gss(&dave, &Msg::default().add_a(ws, 31)).await,
        REFUSED,
        "Hardened keeps ownership"
    );
}

/// DNS-28, TGL-09: the principal's realm must be the zone's; an unsigned update is refused
/// in a zone that requires a signature.
#[tokio::test]
async fn dns_28_the_policy_checks_the_principal() {
    let lab = lab().await;
    let eve = lab.who("eve@OTHER.EXAMPLE.TEST", None, Vec::new(), "192.0.2.40");
    assert_eq!(
        lab.gss(&eve, &Msg::default().add_a("eve.corp.example.test", 40))
            .await,
        REFUSED
    );
    let unsigned = Msg::default().add_a("anon.corp.example.test", 41).bytes();
    let answer = lab
        .path
        .answer(&unsigned, &conn("192.0.2.41"))
        .await
        .expect("answer");
    assert_eq!(wire::parse_header(&answer).expect("header").rcode, 5);
}

/// DNS-28, E43: an update on an unknown or expired context is NOTAUTH with BADKEY, a skewed
/// signature NOTAUTH with BADTIME, and a replayed signed update NOTAUTH with BADSIG.
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the four refusals of E43 in one place"
)]
async fn dns_28_e43_unknown_expired_skewed_and_replayed() {
    let lab = lab().await;
    let msg = Msg::default().add_a("pc05.corp.example.test", 50);
    // Unknown: the client's side of a context the node never held.
    let (_, stranger) = pair(
        b"\x07unknown\x04corp\x07example\x04test\x00",
        "pc05$@CORP.EXAMPLE.TEST",
        None,
        Vec::new(),
        "192.0.2.50".parse().expect("address"),
        now(),
    );
    let mut message = msg.bytes();
    assert!(Signer::request(MacKey::Gss(stranger)).sign(
        &mut message,
        now(),
        0,
        &[],
        MAX_MESSAGE_LEN
    ));
    let answer = lab
        .path
        .answer(&message, &conn("192.0.2.50"))
        .await
        .expect("answer");
    assert_eq!(
        read(&answer),
        Got {
            rcode: 9,
            tsig_error: Some(17)
        }
    );
    // Expired: a context whose hour has passed.
    let (acceptor, client) = pair(
        b"\x07expired\x04corp\x07example\x04test\x00",
        "pc05$@CORP.EXAMPLE.TEST",
        None,
        Vec::new(),
        "192.0.2.50".parse().expect("address"),
        now() - 7_200,
    );
    lab.tkey.adopt(acceptor);
    let mut message = msg.bytes();
    assert!(Signer::request(MacKey::Gss(client)).sign(
        &mut message,
        now(),
        0,
        &[],
        MAX_MESSAGE_LEN
    ));
    let answer = lab
        .path
        .answer(&message, &conn("192.0.2.50"))
        .await
        .expect("answer");
    assert_eq!(
        read(&answer),
        Got {
            rcode: 9,
            tsig_error: Some(17)
        }
    );
    // Skewed: signed 400 s ago.
    let pc05 = lab.who("pc05$@CORP.EXAMPLE.TEST", None, Vec::new(), "192.0.2.50");
    let mut message = msg.bytes();
    assert!(Signer::request(MacKey::Gss(Arc::clone(&pc05.client))).sign(
        &mut message,
        now() - 400,
        0,
        &[],
        MAX_MESSAGE_LEN
    ));
    let answer = lab
        .path
        .answer(&message, &conn("192.0.2.50"))
        .await
        .expect("answer");
    assert_eq!(
        read(&answer),
        Got {
            rcode: 9,
            tsig_error: Some(18)
        }
    );
    // Replayed: the same signed update twice.
    let mut message = msg.bytes();
    assert!(Signer::request(MacKey::Gss(Arc::clone(&pc05.client))).sign(
        &mut message,
        now(),
        0,
        &[],
        MAX_MESSAGE_LEN
    ));
    let first = lab
        .path
        .answer(&message, &conn("192.0.2.50"))
        .await
        .expect("answer");
    assert_eq!(read(&first).rcode, 0);
    let again = lab
        .path
        .answer(&message, &conn("192.0.2.50"))
        .await
        .expect("answer");
    assert_eq!(
        read(&again),
        Got {
            rcode: 9,
            tsig_error: Some(16)
        }
    );
}

/// DNS-28, E43 in process: a TKEY negotiation through the update path establishes a
/// context with the account's keys, and an update signed on it is applied; a path whose
/// node holds no keys answers TKEY REFUSED.
#[tokio::test]
async fn dns_28_e43_tkey_then_a_signed_update_through_the_update_path() {
    let lab = lab().await;
    let mut query = Vec::new();
    let key_name = b"\x0bpc07-tkey-1\x04corp\x07example\x04test\x00";
    let service_key = key(tenko_core::dns::EncryptionType::Aes256CtsHmacSha1, 0x77);
    let mut init = Initiator::new(
        service_key.clone(),
        5,
        "pc07$",
        i64::try_from(now()).expect("now"),
    );
    tkey_wire::write_query(
        &mut query,
        1,
        key_name,
        GSS_TSIG,
        mode::GSSAPI,
        &init.spnego_token(),
        0,
    );
    let answer = lab
        .path
        .answer(&query, &conn("192.0.2.70"))
        .await
        .expect("answer");
    assert_eq!(
        wire::parse_header(&answer).expect("header").rcode,
        5,
        "no keys yet"
    );
    lab.tkey
        .handle()
        .install(realm(), &[SPN.to_owned()], key_set(&service_key, 5))
        .expect("install");
    init.now += 1;
    init.cusec += 1;
    tkey_wire::write_query(
        &mut query,
        2,
        key_name,
        GSS_TSIG,
        mode::GSSAPI,
        &init.spnego_token(),
        0,
    );
    let answer = lab
        .path
        .answer(&query, &conn("192.0.2.70"))
        .await
        .expect("answer");
    let (_, error, token) = answer_record(&answer).expect("parses").expect("record");
    assert_eq!(error, 0);
    let client = init.finish(key_name, token, "192.0.2.53".parse().expect("server"));
    let pc07 = Who {
        client,
        from: "192.0.2.70",
    };
    assert_eq!(
        lab.gss(&pc07, &Msg::default().add_a("pc07.corp.example.test", 77))
            .await,
        NOERROR
    );
    assert!(lab.catalog.revision().0 > 0);
    let realm_of = Realm::new("CORP.EXAMPLE.TEST").expect("realm");
    assert_eq!(
        lab.tkey.handle().installed().map(|(realm, _)| realm),
        Some(realm_of)
    );
}

/// DNS-28, E46 (review): a name owned by a SID is not taken over by a ticket of the same
/// name without a PAC (a recreated account, `PA-PAC-REQUEST` false); a wildcard name is
/// for privileged principals only; an owner left without a hold on a name whose records
/// went outside the update path is stale, and the name is new again.
#[tokio::test]
async fn dns_28_e46_sid_owners_wildcards_and_stale_owners() {
    let lab = lab().await;
    let alice = lab.who(
        "pc01$@CORP.EXAMPLE.TEST",
        Some(sid(1001)),
        vec![sid(515)],
        "192.0.2.21",
    );
    let no_pac = lab.who("pc01$@CORP.EXAMPLE.TEST", None, Vec::new(), "192.0.2.21");
    let bob = lab.who(
        "pc02$@CORP.EXAMPLE.TEST",
        Some(sid(1002)),
        vec![sid(515)],
        "192.0.2.22",
    );
    let dc = lab.who(
        "dc01$@CORP.EXAMPLE.TEST",
        Some(sid(1000)),
        vec![sid(516)],
        "192.0.2.2",
    );
    let pc01 = "pc01.corp.example.test";
    assert_eq!(
        lab.gss(&alice, &Msg::default().add_a(pc01, 21)).await,
        NOERROR
    );
    assert_eq!(
        lab.gss(&no_pac, &Msg::default().add_a(pc01, 29)).await,
        REFUSED,
        "no SID"
    );
    let wildcard = "*.corp.example.test";
    assert_eq!(
        lab.gss(&bob, &Msg::default().add_a(wildcard, 66)).await,
        REFUSED
    );
    assert_eq!(
        lab.gss(&dc, &Msg::default().add_a(wildcard, 66)).await,
        NOERROR
    );
    assert_eq!(lab.owner(wildcard).await, None);
    // An owner row without a hold on a name without records: stale.
    let gone = "gone.corp.example.test";
    lab.put_owner(
        gone,
        NameOwner {
            sid: Some(sid(1001)),
            principal: PrincipalName::parse("pc01$@CORP.EXAMPLE.TEST").expect("principal"),
            since: Timestamp::now(),
            hold_until: None,
            how: OwnerSource::Created,
        },
    )
    .await;
    assert_eq!(
        lab.gss(&bob, &Msg::default().add_a(gone, 70)).await,
        NOERROR
    );
    assert_eq!(lab.owner(gone).await.expect("owner").sid, Some(sid(1002)));
}

// WP13.4: the remaining rows of E46.

/// The Windows file of the E46 table: `srv01` static (no aging mark), `ws05` and `ws06`
/// dynamic (`[AGE:n]`), `mixed` with one dynamic and one static record, `txt01` an aged
/// record of a type no client registers for itself, and a WINS record, which is a loss.
const WINDOWS_FILE: &str = "\
;  Database file corp.example.test.dns for corp.example.test zone.
@                       [AGE:0] 3600 WINS L1 C900 ( 192.0.2.9 )
srv01                   1200    A       192.0.2.10
ws05                    [AGE:3660412]   1200    A       192.0.2.15
ws06                    [AGE:3660413]   1200    A       192.0.2.16
mixed                   [AGE:3660414]   1200    A       192.0.2.17
                        1200    A       192.0.2.18
txt01                   [AGE:3660415]   1200    TXT     \"an aged record of another type\"
";

/// Who acts in a row of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Actor {
    /// PC01$, a member computer (SID 1001).
    Pc01,
    /// PC02$, another member computer (1002).
    Pc02,
    /// PC07$, the computer an administrator hands names to (1007).
    Pc07,
    /// DC01$, a domain controller (1000, Domain Controllers).
    Dc,
    /// An administrator (1500, Domain Admins).
    Admin,
    /// WS05$ (1005), the host a Windows file's dynamic record names.
    Ws05,
    /// WS06$ (1006), the owner a migration adapter read.
    Ws06,
    /// A rebuilt WS06$ under a new account (1099): the same name, another SID.
    Ws06Rebuilt,
    /// SRV01$ (1010), whose record is static in the file.
    Srv01,
    /// The TSIG key of the list.
    Tsig,
}

/// What a row does.
enum Do {
    /// A signed update.
    Update(Actor, Msg),
    /// An administrator's release through the zone service.
    Release(&'static str),
    /// An administrator's assignment to PC07$ with its SID.
    Assign(&'static str),
    /// An administrator's assignment that the zone service refuses with this code.
    AssignRefused(&'static str, &'static str),
    /// A migration adapter's owner (MIG-06): WS06$ with its SID.
    ImportOwner(&'static str),
    /// An administrator adds a manual AAAA record through the API.
    Manual(&'static str),
}

/// One row: what is done, the answer, and the owner of the name after it (by RID and how).
struct Row {
    what: &'static str,
    name: &'static str,
    action: Do,
    expect: Option<Got>,
    owner: Option<(u32, OwnerSource)>,
}

/// DNS-28, MIG-06, E46: the rows WP13.4 adds to the table of
/// section 3.6, in one sequence on one zone: a controller's own name, a refresh, the
/// static records beside an owner's, the Windows file's import marking, the owner of the
/// Windows adapter, release and assignment.
#[tokio::test]
#[allow(clippy::too_many_lines, reason = "the table is the test")]
async fn dns_28_e46_the_remaining_rows() {
    let lab = lab().await;
    // The Windows file first: the preview lists what it would mark `ad` and what it keeps
    // `manual`, and the import carries the approval of that list.
    let request = |approval| tenko_dns::zone::import::ImportRequest {
        zone: lab.zone.id,
        scope: ScopeName::DEFAULT,
        text: WINDOWS_FILE.to_owned(),
        replace: false,
        dialect: tenko_dns::zone::zonefile::Dialect::Windows,
        claim: tenko_dns::zone::import::ClaimRequest {
            approval,
            ..Default::default()
        },
    };
    let preview = lab
        .zones
        .preview_import(&cx(), &request(None))
        .await
        .expect("preview");
    assert_eq!(preview.claimable, 2, "ws05 and ws06; mixed stays manual");
    let listed: Vec<(&str, &str)> = preview
        .claimable_names
        .iter()
        .map(|entry| (entry.name.as_str(), entry.claimant.as_str()))
        .collect();
    assert_eq!(
        listed,
        [
            ("ws05.corp.example.test", "WS05$"),
            ("ws06.corp.example.test", "WS06$")
        ]
    );
    assert_eq!(
        preview.held_back, 1,
        "mixed: a static record beside the aged one"
    );
    assert_eq!(preview.lost, 1, "the WINS record");
    let digest = preview
        .claimable_digest
        .as_deref()
        .expect("a digest")
        .parse()
        .expect("the digest reads");
    let (job, _) = lab
        .zones
        .start_import(&cx(), request(Some(digest)))
        .await
        .expect("import");
    let direct = lab.zones.direct_jobs().expect("direct jobs");
    let report =
        tenko_dns::zone::import::report_of(&direct.job(job).expect("job")).expect("report");
    assert_eq!(report.claimable, 2);
    assert_eq!(
        lab.rrset("txt01.corp.example.test", Rtype::TXT)
            .await
            .expect("imported")
            .origin,
        Origin::Manual,
        "only A, AAAA and PTR records become claimable"
    );
    for (owner, origin) in [
        ("srv01.corp.example.test", Origin::Manual),
        ("ws05.corp.example.test", Origin::Ad),
        ("ws06.corp.example.test", Origin::Ad),
        ("mixed.corp.example.test", Origin::Manual),
    ] {
        assert_eq!(
            lab.rrset(owner, Rtype::A).await.expect("imported").origin,
            origin,
            "{owner}"
        );
    }
    let who = |actor: Actor| -> Option<Who> {
        let (principal, rid, groups): (&str, u32, Vec<Sid>) = match actor {
            Actor::Pc01 => ("pc01$@CORP.EXAMPLE.TEST", 1001, vec![sid(515)]),
            Actor::Pc02 => ("pc02$@CORP.EXAMPLE.TEST", 1002, vec![sid(515)]),
            Actor::Pc07 => ("pc07$@CORP.EXAMPLE.TEST", 1007, vec![sid(515)]),
            Actor::Dc => ("dc01$@CORP.EXAMPLE.TEST", 1000, vec![sid(516)]),
            Actor::Admin => ("administrator@CORP.EXAMPLE.TEST", 1500, vec![sid(512)]),
            Actor::Ws05 => ("WS05$@CORP.EXAMPLE.TEST", 1005, vec![sid(515)]),
            Actor::Ws06 => ("WS06$@CORP.EXAMPLE.TEST", 1006, vec![sid(515)]),
            Actor::Ws06Rebuilt => ("WS06$@CORP.EXAMPLE.TEST", 1099, vec![sid(515)]),
            Actor::Srv01 => ("SRV01$@CORP.EXAMPLE.TEST", 1010, vec![sid(515)]),
            Actor::Tsig => return None,
        };
        Some(lab.who(principal, Some(sid(rid)), groups, "192.0.2.30"))
    };
    let pc01 = "pc01.corp.example.test";
    let dc01 = "dc01.corp.example.test";
    let ws05 = "ws05.corp.example.test";
    let ws06 = "ws06.corp.example.test";
    let spare = "spare.corp.example.test";
    let created = OwnerSource::Created;
    let rows = vec![
        Row {
            what: "a controller creates its host name and owns it",
            name: dc01,
            action: Do::Update(Actor::Dc, Msg::default().add_a(dc01, 2)),
            expect: Some(NOERROR),
            owner: Some((1000, created)),
        },
        Row {
            what: "a member computer cannot take a controller's name",
            name: dc01,
            action: Do::Update(Actor::Pc02, Msg::default().add_a(dc01, 66)),
            expect: Some(REFUSED),
            owner: Some((1000, created)),
        },
        Row {
            what: "TSIG cannot either",
            name: dc01,
            action: Do::Update(Actor::Tsig, Msg::default().add_a(dc01, 66)),
            expect: Some(REFUSED),
            owner: Some((1000, created)),
        },
        Row {
            what: "a Domain Admin changes it, the owner stays",
            name: dc01,
            action: Do::Update(Actor::Admin, Msg::default().add_a(dc01, 3)),
            expect: Some(NOERROR),
            owner: Some((1000, created)),
        },
        Row {
            what: "a member creates its own name",
            name: pc01,
            action: Do::Update(Actor::Pc01, Msg::default().add_a(pc01, 21)),
            expect: Some(NOERROR),
            owner: Some((1001, created)),
        },
        Row {
            what: "an administrator adds a manual record beside it",
            name: pc01,
            action: Do::Manual(pc01),
            expect: None,
            owner: Some((1001, created)),
        },
        Row {
            what: "a refresh (the same data again) keeps the owner",
            name: pc01,
            action: Do::Update(Actor::Pc01, Msg::default().add_a(pc01, 21)),
            expect: Some(NOERROR),
            owner: Some((1001, created)),
        },
        Row {
            what: "the owner cannot delete the manual record beside its own",
            name: pc01,
            action: Do::Update(Actor::Pc01, Msg::default().delete_name(pc01)),
            expect: Some(REFUSED),
            owner: Some((1001, created)),
        },
        Row {
            what: "a static record of the Windows file is not claimable by its host",
            name: "srv01.corp.example.test",
            action: Do::Update(
                Actor::Srv01,
                Msg::default().add_a("srv01.corp.example.test", 11),
            ),
            expect: Some(REFUSED),
            owner: None,
        },
        Row {
            what: "another host cannot claim a dynamic record of the file",
            name: ws05,
            action: Do::Update(Actor::Pc02, Msg::default().add_a(ws05, 66)),
            expect: Some(REFUSED),
            owner: None,
        },
        Row {
            what: "its own host claims it",
            name: ws05,
            action: Do::Update(Actor::Ws05, Msg::default().add_a(ws05, 15)),
            expect: Some(NOERROR),
            owner: Some((1005, OwnerSource::Claimed)),
        },
        Row {
            what: "the Windows adapter's owner (MIG-06) is written as imported",
            name: ws06,
            action: Do::ImportOwner(ws06),
            expect: None,
            owner: Some((1006, OwnerSource::Imported)),
        },
        Row {
            what: "a rebuilt account of the same name is refused (the SID decides)",
            name: ws06,
            action: Do::Update(Actor::Ws06Rebuilt, Msg::default().add_a(ws06, 16)),
            expect: Some(REFUSED),
            owner: Some((1006, OwnerSource::Imported)),
        },
        Row {
            what: "the imported owner refreshes its record",
            name: ws06,
            action: Do::Update(Actor::Ws06, Msg::default().add_a(ws06, 16)),
            expect: Some(NOERROR),
            owner: Some((1006, OwnerSource::Imported)),
        },
        Row {
            what: "an administrator releases the claimed name",
            name: ws05,
            action: Do::Release(ws05),
            expect: None,
            owner: None,
        },
        Row {
            what: "a released name is not open to any principal",
            name: ws05,
            action: Do::Update(Actor::Pc02, Msg::default().add_a(ws05, 66)),
            expect: Some(REFUSED),
            owner: None,
        },
        Row {
            what: "its own host claims it again",
            name: ws05,
            action: Do::Update(Actor::Ws05, Msg::default().add_a(ws05, 15)),
            expect: Some(NOERROR),
            owner: Some((1005, OwnerSource::Claimed)),
        },
        Row {
            what: "a name holding a manual record is not given an owner",
            name: pc01,
            action: Do::AssignRefused(pc01, "dns.owner.protected"),
            expect: None,
            owner: Some((1001, created)),
        },
        Row {
            what: "an administrator hands the claimed name to PC07$",
            name: ws05,
            action: Do::Assign(ws05),
            expect: None,
            owner: Some((1007, OwnerSource::Assigned)),
        },
        Row {
            what: "the old owner is refused",
            name: ws05,
            action: Do::Update(Actor::Ws05, Msg::default().add_a(ws05, 25)),
            expect: Some(REFUSED),
            owner: Some((1007, OwnerSource::Assigned)),
        },
        Row {
            what: "the new owner changes it",
            name: ws05,
            action: Do::Update(Actor::Pc07, Msg::default().add_a(ws05, 27)),
            expect: Some(NOERROR),
            owner: Some((1007, OwnerSource::Assigned)),
        },
        Row {
            what: "a name without records is held for the principal it is assigned to",
            name: spare,
            action: Do::Assign(spare),
            expect: None,
            owner: Some((1007, OwnerSource::Assigned)),
        },
        Row {
            what: "another principal cannot create it within the hold",
            name: spare,
            action: Do::Update(Actor::Pc02, Msg::default().add_a(spare, 66)),
            expect: Some(REFUSED),
            owner: Some((1007, OwnerSource::Assigned)),
        },
        Row {
            what: "the assigned principal creates it",
            name: spare,
            action: Do::Update(Actor::Pc07, Msg::default().add_a(spare, 77)),
            expect: Some(NOERROR),
            owner: Some((1007, OwnerSource::Assigned)),
        },
    ];
    for row in rows {
        let got = match row.action {
            Do::Update(actor, msg) => Some(match who(actor) {
                Some(who) => lab.gss(&who, &msg).await,
                None => lab.tsig(&msg).await,
            }),
            Do::Manual(owner) => {
                lab.zones
                    .change_records(
                        &cx(),
                        lab.zone.id,
                        &[Change {
                            op: Op::Set,
                            scope: ScopeName::DEFAULT,
                            name: name(owner),
                            rtype: Rtype::AAAA,
                            ttl: Some(300),
                            records: vec![RecordData::Aaaa {
                                address: "2001:db8::1".parse().expect("address"),
                            }],
                            take_over: false,
                            origin: Origin::Manual,
                        }],
                        false,
                    )
                    .await
                    .expect(row.what);
                None
            }
            Do::Release(owner) => {
                lab.zones
                    .release_owner(&cx(), lab.zone.id, &ScopeName::DEFAULT, &name(owner), None)
                    .await
                    .expect(row.what);
                assert_eq!(
                    lab.rrset(owner, Rtype::A).await.expect("records").origin,
                    Origin::Ad,
                    "{}: the records are claimable again",
                    row.what
                );
                None
            }
            Do::Assign(owner) => {
                lab.zones
                    .assign_owner(
                        &cx(),
                        lab.zone.id,
                        &tenko_dns::zone::ownership::OwnerAssignment {
                            scope: ScopeName::DEFAULT,
                            name: name(owner),
                            principal: PrincipalName::parse("pc07$@CORP.EXAMPLE.TEST")
                                .expect("principal"),
                            sid: Some(sid(1007)),
                            expect: None,
                        },
                    )
                    .await
                    .expect(row.what);
                None
            }
            Do::AssignRefused(owner, code) => {
                let error = lab
                    .zones
                    .assign_owner(
                        &cx(),
                        lab.zone.id,
                        &tenko_dns::zone::ownership::OwnerAssignment {
                            scope: ScopeName::DEFAULT,
                            name: name(owner),
                            principal: PrincipalName::parse("pc07$@CORP.EXAMPLE.TEST")
                                .expect("principal"),
                            sid: Some(sid(1007)),
                            expect: None,
                        },
                    )
                    .await
                    .expect_err(row.what);
                assert!(error.is(code), "{}: {error:?}", row.what);
                None
            }
            Do::ImportOwner(owner) => {
                let imported = lab
                    .zones
                    .import_owners(
                        &cx(),
                        lab.zone.id,
                        &ScopeName::DEFAULT,
                        &[
                            tenko_dns::zone::ownership::ImportedOwner {
                                name: name(owner),
                                principal: PrincipalName::parse("WS06$@CORP.EXAMPLE.TEST")
                                    .expect("principal"),
                                sid: Some(sid(1006)),
                            },
                            tenko_dns::zone::ownership::ImportedOwner {
                                name: name("_ldap._tcp.corp.example.test"),
                                principal: PrincipalName::parse("dc01$@CORP.EXAMPLE.TEST")
                                    .expect("principal"),
                                sid: Some(sid(1000)),
                            },
                        ],
                    )
                    .await
                    .expect(row.what);
                assert_eq!(
                    (imported.written, imported.skipped),
                    (1, 1),
                    "a locator name keeps no owner"
                );
                None
            }
        };
        assert_eq!(got, row.expect, "{}", row.what);
        let owner = lab.owner(row.name).await;
        assert_eq!(
            owner.as_ref().map(|owner| (owner.sid.clone(), owner.how)),
            row.owner.map(|(rid, how)| (Some(sid(rid)), how)),
            "{}",
            row.what
        );
    }
    // The manual AAAA beside pc01 is still there, and still manual.
    assert_eq!(
        lab.rrset(pc01, Rtype::AAAA).await.expect("kept").origin,
        Origin::Manual
    );
}

impl Lab {
    async fn put_owner(&self, owner: &str, row: NameOwner) {
        let mut batch = WriteBatch::for_request(&cx());
        batch
            .put_typed(
                &NAME_OWNERS,
                &NameOwnerKey {
                    zone: self.zone.id,
                    scope: ScopeName::DEFAULT,
                    name: name(owner),
                },
                &row,
            )
            .expect("encode");
        self.memory.propose(batch).await.expect("write");
    }
}
