//! The transfer path out (WP6.1): AXFR and IXFR from the index and the journal, the
//! access lists and TSIG, IXFR over UDP, NOTIFY in. The listeners are left out: the tests
//! call the path the TCP, DoT and UDP listeners call.

mod support;

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use tenko_core::{
    Revision, Timestamp,
    audit::AuditDraft,
    dns::{
        Acl, AclEntry, AclId, JournalEntry, JournalRecord, MatchRule, PrimaryServer,
        QueryTransport, Rdata, RrSet, Rtype, ScopeName, ScopeWeight, SecondarySource,
        TransferPolicy, TsigAlgorithm, View, ViewId, Zone, ZoneId, ZoneKind,
    },
};
use tenko_dns::{
    DnsData,
    catalog::{Catalog, CatalogHandle},
    respond::Conn,
    tsig::{Signer, TsigKey, Verifier},
    update::policy::{ProfileCell, UpdateProfile},
    wire::{self, MAX_MESSAGE_LEN},
    xfr::{
        Directory, JournalSource, NotifyHandler, TransferAudit, TransferSink,
        message::{
            OPCODE_NOTIFY, OPCODE_QUERY, Record, TYPE_AXFR, TYPE_IXFR, TYPE_SOA, read_answer,
            soa_serial, write_request,
        },
        out::XfrOut,
    },
};

use support::{a, name, rrset, soa, stamp, txt, zone};

const KEY: &str = "transfer.example.test";
const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

fn key() -> TsigKey {
    TsigKey::new(&name(KEY), TsigAlgorithm::HmacSha256, SECRET)
}

#[derive(Default)]
struct Journal(BTreeMap<u32, JournalEntry>);

#[async_trait::async_trait]
impl JournalSource for Journal {
    async fn entries(
        &self,
        _zone: ZoneId,
        _scope: &ScopeName,
    ) -> Result<Vec<JournalEntry>, String> {
        Ok(self.0.values().cloned().collect())
    }
}

#[derive(Default)]
struct Audit(Mutex<Vec<AuditDraft>>);

impl TransferAudit for Audit {
    fn record(&self, draft: AuditDraft) {
        self.0.lock().expect("audit").push(draft);
    }
}

#[derive(Default)]
struct Notified(Mutex<Vec<(ZoneId, IpAddr, Option<u32>)>>);

impl NotifyHandler for Notified {
    fn notified(&self, zone: ZoneId, from: IpAddr, serial: Option<u32>, _signed: bool) {
        self.0.lock().expect("notified").push((zone, from, serial));
    }
}

struct Lab {
    zone: Zone,
    secondary: Zone,
    path: Arc<XfrOut>,
    audit: Arc<Audit>,
    notified: Arc<Notified>,
}

fn soa_at(apex: &str, serial: u32) -> tenko_core::dns::RecordData {
    let mut data = soa(apex, 60);
    if let tenko_core::dns::RecordData::Soa { serial: s, .. } = &mut data {
        *s = serial;
    }
    data
}

/// `example.test` at serial 3 with 200 names, transfers allowed to loopback with the key
/// (`require_tsig` as given); journal steps 1 to 2 and 2 to 3. And a secondary zone
/// `secondary.test` whose primary is 192.0.2.53 with the key.
#[allow(clippy::too_many_lines, reason = "the whole fixture in one place")]
fn lab(require_tsig: bool, xot: bool, limit: usize) -> Lab {
    let acl = Acl {
        id: AclId::generate(),
        name: "transfers".to_owned(),
        entries: vec![
            AclEntry::Key {
                name: name(KEY),
                deny: false,
            },
            AclEntry::Prefix {
                prefix: "127.0.0.0/8".parse().expect("prefix"),
                deny: false,
            },
        ],
        description: None,
    };
    let mut zone = zone("example.test");
    zone.transfer = TransferPolicy {
        allow: vec![acl.id],
        notify: Vec::new(),
        require_tsig,
        xot,
    };
    let mut secondary = support::zone("secondary.test");
    secondary.kind = ZoneKind::Secondary;
    secondary.source = Some(SecondarySource {
        primaries: vec![PrimaryServer {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
            port: 53,
            key: Some(name(KEY)),
            xot: false,
            tls_name: None,
        }],
    });
    let scope = ScopeName::DEFAULT;
    let mut data = DnsData::at(Revision(10));
    let mut put = |set: RrSet| {
        data.rrsets.insert(set.key(), set);
    };
    put(rrset(
        &zone,
        &scope,
        "example.test",
        &[soa_at("example.test", 3)],
    ));
    put(rrset(
        &zone,
        &scope,
        "example.test",
        &[support::ns("ns1.example.test")],
    ));
    put(rrset(&zone, &scope, "ns1.example.test", &[a(53)]));
    for index in 0..200u8 {
        let owner = format!("host{index}.example.test");
        put(rrset(&zone, &scope, &owner, &[a(index)]));
        put(rrset(&zone, &scope, &owner, &[txt(&"x".repeat(60))]));
    }
    data.zones.insert(zone.id, zone.clone());
    data.zones.insert(secondary.id, secondary.clone());
    data.acls.insert(acl.id, acl);
    let handle = CatalogHandle::new(Catalog::build(&data));
    let directory = Arc::new(Directory::new([zone.clone(), secondary.clone()], [key()]));
    let record = |owner: &str, data: &tenko_core::dns::RecordData| JournalRecord {
        name: name(owner),
        rtype: data.rtype(),
        ttl: 300,
        rdata: Rdata::from_data(data),
    };
    let step = |from: u32, to: u32, removed: Vec<JournalRecord>, added: Vec<JournalRecord>| {
        let mut all_removed = vec![record("example.test", &soa_at("example.test", from))];
        all_removed.extend(removed);
        let mut all_added = vec![record("example.test", &soa_at("example.test", to))];
        all_added.extend(added);
        JournalEntry {
            zone: zone.id,
            scope: ScopeName::DEFAULT,
            from_serial: from,
            to_serial: to,
            revision: Revision(u64::from(to)),
            at: Timestamp::now(),
            removed: all_removed,
            added: all_added,
        }
    };
    let mut journal = Journal::default();
    journal.0.insert(
        1,
        step(1, 2, vec![], vec![record("new.example.test", &a(77))]),
    );
    journal.0.insert(
        2,
        step(
            2,
            3,
            vec![record("new.example.test", &a(77))],
            vec![record("new.example.test", &a(78))],
        ),
    );
    let audit = Arc::new(Audit::default());
    let notified = Arc::new(Notified::default());
    let path = Arc::new(
        XfrOut::new(
            handle,
            directory,
            Arc::new(journal),
            Arc::clone(&audit) as Arc<dyn TransferAudit>,
            Some(Arc::clone(&notified) as Arc<dyn NotifyHandler>),
        )
        .with_message_limit(limit),
    );
    let _ = stamp();
    Lab {
        zone,
        secondary,
        path,
        audit,
        notified,
    }
}

fn conn(client: [u8; 4], transport: QueryTransport) -> Conn {
    Conn {
        client: SocketAddr::from((client, 40_000)),
        local: SocketAddr::from(([127, 0, 0, 1], 53)),
        transport,
    }
}

/// A request for the zone, signed with the key when `signed`; returns it with the verifier
/// of its answers.
fn request(qtype: u16, serial: Option<u32>, signed: bool) -> (Vec<u8>, Option<Verifier>) {
    let mut out = Vec::new();
    let soa_data = serial.map(|serial| Rdata::from_data(&soa_at("example.test", serial)));
    write_request(
        &mut out,
        0x4242,
        OPCODE_QUERY,
        &name("example.test").to_wire(),
        qtype,
        soa_data.as_ref().map(|rdata| (60, rdata.as_bytes())),
    );
    if !signed {
        return (out, None);
    }
    let key = Arc::new(key());
    let mut request_signer = Signer::request(Arc::clone(&key));
    assert!(request_signer.sign(&mut out, now(), 0, &[], MAX_MESSAGE_LEN));
    let mac = request_signer.last_mac().expect("mac");
    (out, Some(Verifier::new(key, mac)))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs()
}

async fn collect(path: &Arc<XfrOut>, message: Vec<u8>, conn: Conn, tls: bool) -> Vec<Vec<u8>> {
    let mut receiver = Arc::clone(path).stream(message, conn, tls);
    let mut messages = Vec::new();
    while let Some(message) = receiver.recv().await {
        messages.push(message);
    }
    messages
}

fn records(messages: &[Vec<u8>]) -> Vec<Record> {
    messages
        .iter()
        .flat_map(|message| read_answer(message).expect("answer").answers)
        .collect()
}

fn rcode(message: &[u8]) -> u8 {
    wire::parse_header(message).expect("header").rcode
}

#[tokio::test]
async fn an_axfr_streams_the_zone_signed_in_messages_of_the_limit() {
    let lab = lab(true, false, 2048);
    let (message, verifier) = request(TYPE_AXFR, None, true);
    let messages = collect(
        &lab.path,
        message,
        conn([127, 0, 0, 1], QueryTransport::Tcp),
        false,
    )
    .await;
    assert!(messages.len() > 5, "{} messages", messages.len());
    assert!(messages.iter().all(|message| message.len() <= 2048));
    let mut verifier = verifier.expect("signed");
    for message in &messages {
        verifier.verify(message, now()).expect("the MAC chain");
    }
    assert!(verifier.complete());
    let all = records(&messages);
    // SOA, NS, ns1 A, 200 x (A, TXT), SOA.
    assert_eq!(all.len(), 1 + 1 + 1 + 400 + 1);
    assert_eq!(all.first().map(|r| r.rtype), Some(Rtype::SOA));
    assert_eq!(all.last().map(|r| r.rtype), Some(Rtype::SOA));
    assert_eq!(all.iter().filter(|r| r.rtype == Rtype::SOA).count(), 2);
    let audit = lab.audit.0.lock().expect("audit");
    assert_eq!(audit.len(), 1);
    let _ = &lab.zone;
}

#[tokio::test]
async fn without_the_key_or_from_elsewhere_the_transfer_is_refused() {
    let lab = lab(true, false, 16 * 1024);
    let (unsigned, _) = request(TYPE_AXFR, None, false);
    let answer = collect(
        &lab.path,
        unsigned.clone(),
        conn([127, 0, 0, 1], QueryTransport::Tcp),
        false,
    )
    .await;
    assert_eq!(answer.len(), 1);
    assert_eq!(rcode(&answer[0]), 5, "REFUSED without TSIG");
    // Signed with the key but from outside the list's prefixes: the key entry matches.
    let (signed, _) = request(TYPE_AXFR, None, true);
    let answer = collect(
        &lab.path,
        signed,
        conn([198, 51, 100, 7], QueryTransport::Tcp),
        false,
    )
    .await;
    assert!(answer.len() > 1, "the key entry allows it");
    // Without require_tsig, loopback may transfer unsigned; a client elsewhere may not.
    let open = lab_open();
    let answer = collect(
        &open.path,
        unsigned.clone(),
        conn([127, 0, 0, 1], QueryTransport::Tcp),
        false,
    )
    .await;
    assert!(!answer.is_empty() && rcode(&answer[0]) == 0);
    let answer = collect(
        &open.path,
        unsigned,
        conn([198, 51, 100, 7], QueryTransport::Tcp),
        false,
    )
    .await;
    assert_eq!(rcode(&answer[0]), 5);
    // A wrong key: NOTAUTH with BADKEY.
    let mut forged = Vec::new();
    write_request(
        &mut forged,
        1,
        OPCODE_QUERY,
        &name("example.test").to_wire(),
        TYPE_AXFR,
        None,
    );
    let other = Arc::new(TsigKey::new(
        &name("other.example.test"),
        TsigAlgorithm::HmacSha256,
        SECRET,
    ));
    assert!(Signer::request(other).sign(&mut forged, now(), 0, &[], MAX_MESSAGE_LEN));
    let answer = collect(
        &lab.path,
        forged,
        conn([127, 0, 0, 1], QueryTransport::Tcp),
        false,
    )
    .await;
    assert_eq!(rcode(&answer[0]), 9);
    let tsig = tenko_dns::tsig::find(&answer[0])
        .expect("parse")
        .expect("tsig");
    assert_eq!(tsig.error, tenko_dns::tsig::error::BADKEY);
}

fn lab_open() -> Lab {
    lab(false, false, 16 * 1024)
}

#[tokio::test]
async fn an_xot_zone_transfers_over_tls_only() {
    let lab = lab(false, true, 16 * 1024);
    let (message, _) = request(TYPE_AXFR, None, false);
    let plain = collect(
        &lab.path,
        message.clone(),
        conn([127, 0, 0, 1], QueryTransport::Tcp),
        false,
    )
    .await;
    assert_eq!(rcode(&plain[0]), 5);
    let tls = collect(
        &lab.path,
        message,
        conn([127, 0, 0, 1], QueryTransport::Dot),
        true,
    )
    .await;
    assert!(!tls.is_empty() && rcode(&tls[0]) == 0);
    assert!(records(&tls).len() > 400);
}

#[tokio::test]
async fn an_ixfr_sends_the_delta_the_soa_or_the_zone() {
    let lab = lab_open();
    let client = conn([127, 0, 0, 1], QueryTransport::Tcp);
    // From serial 1: both steps.
    let (message, _) = request(TYPE_IXFR, Some(1), false);
    let delta = records(&collect(&lab.path, message, client, false).await);
    let serials: Vec<Option<u32>> = delta
        .iter()
        .filter(|record| record.rtype == Rtype::SOA)
        .map(|record| soa_serial(record.rdata.as_bytes()))
        .collect();
    assert_eq!(
        serials,
        vec![Some(3), Some(1), Some(2), Some(2), Some(3), Some(3)]
    );
    assert_eq!(delta.len(), 6 + 3, "three changed records and six SOAs");
    // Current: the SOA alone.
    let (message, _) = request(TYPE_IXFR, Some(3), false);
    let current = records(&collect(&lab.path, message, client, false).await);
    assert_eq!(current.len(), 1);
    // A serial the journal does not hold: the zone in AXFR form.
    let (message, _) = request(TYPE_IXFR, Some(0), false);
    let full = records(&collect(&lab.path, message, client, false).await);
    assert_eq!(full.len(), 404);
}

#[tokio::test]
async fn an_ixfr_over_udp_is_the_soa_only_and_axfr_is_refused() {
    let lab = lab_open();
    let udp = conn([127, 0, 0, 1], QueryTransport::Udp);
    let (message, _) = request(TYPE_IXFR, Some(1), false);
    let mut out = Vec::new();
    assert!(lab.path.datagram(&message, &udp, &mut out));
    let answer = read_answer(&out).expect("answer");
    assert_eq!(answer.answers.len(), 1);
    assert_eq!(answer.answers[0].rtype, Rtype::SOA);
    let (message, _) = request(TYPE_AXFR, None, false);
    assert!(lab.path.datagram(&message, &udp, &mut out));
    assert_eq!(rcode(&out), 5);
}

#[tokio::test]
async fn a_notify_from_the_primary_with_its_key_reaches_the_service() {
    let lab = lab_open();
    let apex = lab.secondary.name.to_wire();
    let serial = Rdata::from_data(&soa_at("secondary.test", 9));
    let mut message = Vec::new();
    write_request(
        &mut message,
        7,
        OPCODE_NOTIFY,
        &apex,
        TYPE_SOA,
        Some((60, serial.as_bytes())),
    );
    let unsigned = message.clone();
    let key = Arc::new(key());
    let mut signer = Signer::request(Arc::clone(&key));
    assert!(signer.sign(&mut message, now(), 0, &[], MAX_MESSAGE_LEN));
    let mut out = Vec::new();
    // From another address: refused.
    assert!(lab.path.datagram(
        &message,
        &conn([192, 0, 2, 99], QueryTransport::Udp),
        &mut out
    ));
    assert_eq!(rcode(&out), 5);
    // From the primary without its key: refused.
    assert!(lab.path.datagram(
        &unsigned,
        &conn([192, 0, 2, 53], QueryTransport::Udp),
        &mut out
    ));
    assert_eq!(rcode(&out), 5);
    assert!(lab.notified.0.lock().expect("notified").is_empty());
    // From the primary, signed: acknowledged, signed, handed on.
    assert!(lab.path.datagram(
        &message,
        &conn([192, 0, 2, 53], QueryTransport::Udp),
        &mut out
    ));
    let header = wire::parse_header(&out).expect("header");
    assert_eq!(
        (header.qr, header.opcode, header.rcode),
        (true, OPCODE_NOTIFY, 0)
    );
    let mut verifier = Verifier::new(key, signer.last_mac().expect("mac"));
    verifier
        .verify(&out, now())
        .expect("a signed acknowledgment");
    assert_eq!(
        lab.notified.0.lock().expect("notified").as_slice(),
        &[(
            lab.secondary.id,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
            Some(9)
        )]
    );
}

/// The view lab: `example.test` with an `internal` scope (serial 7, the name
/// `secret.example.test`) beside the default one (serial 3, `public.example.test`); the
/// view `listener` maps the zone to `internal` for queries to 127.0.0.1, the view `xot`
/// for queries over DoT. Transfers are allowed to loopback and to the key; a second key,
/// `update.example.test`, is known to the node but named by no list.
fn view_lab(profile: UpdateProfile) -> Arc<XfrOut> {
    let acl = Acl {
        id: AclId::generate(),
        name: "transfers".to_owned(),
        entries: vec![
            AclEntry::Key {
                name: name(KEY),
                deny: false,
            },
            AclEntry::Prefix {
                prefix: "127.0.0.0/8".parse().expect("prefix"),
                deny: false,
            },
        ],
        description: None,
    };
    let mut zone = zone("example.test");
    zone.transfer = TransferPolicy {
        allow: vec![acl.id],
        notify: Vec::new(),
        require_tsig: false,
        xot: false,
    };
    let internal = support::internal();
    let mut data = DnsData::at(Revision(10));
    for (scope, serial, owner) in [
        (ScopeName::DEFAULT, 3, "public.example.test"),
        (internal.clone(), 7, "secret.example.test"),
    ] {
        for set in [
            rrset(
                &zone,
                &scope,
                "example.test",
                &[soa_at("example.test", serial)],
            ),
            rrset(
                &zone,
                &scope,
                "example.test",
                &[support::ns("ns1.example.test")],
            ),
            rrset(&zone, &scope, owner, &[a(9)]),
        ] {
            data.rrsets.insert(set.key(), set);
        }
    }
    let to_internal = ScopeWeight {
        zone: zone.id,
        scope: internal,
        weight: 1,
    };
    for (view_name, order, rule) in [
        (
            "xot",
            0,
            MatchRule::Transport {
                transports: vec![QueryTransport::Dot],
            },
        ),
        (
            "listener",
            1,
            MatchRule::Interface {
                addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            },
        ),
    ] {
        let view = View {
            id: ViewId::generate(),
            name: view_name.to_owned(),
            rules: vec![rule],
            scope_map: vec![to_internal.clone()],
            order,
            recursion: None,
            resolution: None,
            description: None,
        };
        data.views.insert(view.id, view);
    }
    data.zones.insert(zone.id, zone.clone());
    data.acls.insert(acl.id, acl);
    let update_key = TsigKey::new(
        &name("update.example.test"),
        TsigAlgorithm::HmacSha256,
        SECRET,
    );
    Arc::new(
        XfrOut::new(
            CatalogHandle::new(Catalog::build(&data)),
            Arc::new(Directory::new([zone], [key(), update_key])),
            Arc::new(Journal::default()),
            Arc::new(Audit::default()) as Arc<dyn TransferAudit>,
            None,
        )
        .with_profile(Arc::new(ProfileCell::new(profile))),
    )
}

fn conn_at(client: [u8; 4], local: [u8; 4], transport: QueryTransport) -> Conn {
    Conn {
        client: SocketAddr::from((client, 40_000)),
        local: SocketAddr::from((local, 53)),
        transport,
    }
}

fn owners(messages: &[Vec<u8>]) -> Vec<String> {
    records(messages)
        .iter()
        .map(|record| record.name.to_string())
        .collect()
}

/// A transfer serves the scope that the view of its own connection chooses: the local
/// address and the transport it came on, as a query does, not the client address.
#[tokio::test]
async fn a_transfer_serves_the_scope_of_the_view_of_its_own_connection() {
    let path = view_lab(UpdateProfile::Standard);
    let (message, _) = request(TYPE_AXFR, None, false);
    let on_loopback = collect(
        &path,
        message.clone(),
        conn_at([127, 0, 0, 1], [127, 0, 0, 1], QueryTransport::Tcp),
        false,
    )
    .await;
    assert!(
        owners(&on_loopback)
            .iter()
            .any(|owner| owner.starts_with("secret."))
    );
    let on_public = collect(
        &path,
        message.clone(),
        conn_at([127, 0, 0, 1], [203, 0, 113, 53], QueryTransport::Tcp),
        false,
    )
    .await;
    let public = owners(&on_public);
    assert!(public.iter().any(|owner| owner.starts_with("public.")));
    assert!(
        !public.iter().any(|owner| owner.starts_with("secret.")),
        "the view of the listener must not apply to another local address: {public:?}"
    );
    let over_dot = collect(
        &path,
        message,
        conn_at([127, 0, 0, 1], [203, 0, 113, 53], QueryTransport::Dot),
        true,
    )
    .await;
    assert!(
        owners(&over_dot)
            .iter()
            .any(|owner| owner.starts_with("secret.")),
        "the transport view applies to XoT"
    );
}

fn signed_soa(key_name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    write_request(
        &mut out,
        0x5151,
        OPCODE_QUERY,
        &name("example.test").to_wire(),
        TYPE_SOA,
        None,
    );
    let key = Arc::new(TsigKey::new(
        &name(key_name),
        TsigAlgorithm::HmacSha256,
        SECRET,
    ));
    assert!(Signer::request(key).sign(&mut out, now(), 0, &[], MAX_MESSAGE_LEN));
    out
}

/// A signed SOA query passes the same check as a transfer, and answers from the scope of
/// the view of the client.
#[tokio::test]
async fn a_signed_soa_query_passes_the_transfer_check_and_follows_the_view() {
    let path = view_lab(UpdateProfile::Standard);
    let mut out = Vec::new();
    // Any valid key of the node is not enough: the lists must allow the client.
    assert!(path.datagram(
        &signed_soa("update.example.test"),
        &conn_at([198, 51, 100, 7], [203, 0, 113, 53], QueryTransport::Udp),
        &mut out
    ));
    assert_eq!(rcode(&out), 5, "REFUSED for a key no list names");
    let serial_of = |out: &[u8]| {
        let answer = read_answer(out).expect("answer");
        assert_eq!(answer.answers.len(), 1);
        soa_serial(answer.answers[0].rdata.as_bytes())
    };
    assert!(path.datagram(
        &signed_soa(KEY),
        &conn_at([198, 51, 100, 7], [203, 0, 113, 53], QueryTransport::Udp),
        &mut out
    ));
    assert_eq!(serial_of(&out), Some(3), "the default scope");
    assert!(path.datagram(
        &signed_soa(KEY),
        &conn_at([198, 51, 100, 7], [127, 0, 0, 1], QueryTransport::Udp),
        &mut out
    ));
    assert_eq!(
        serial_of(&out),
        Some(7),
        "the scope of the view of the listener"
    );
}

/// TGL-10 under Hardened: whatever the zone stores, a transfer needs TSIG, and a client
/// outside the site needs XoT.
#[tokio::test]
async fn under_hardened_a_transfer_needs_tsig_and_off_site_xot() {
    let path = view_lab(UpdateProfile::Hardened);
    let (unsigned, _) = request(TYPE_AXFR, None, false);
    let answer = collect(
        &path,
        unsigned.clone(),
        conn_at([127, 0, 0, 1], [127, 0, 0, 1], QueryTransport::Tcp),
        false,
    )
    .await;
    assert_eq!(
        rcode(&answer[0]),
        5,
        "unsigned, although the zone allows it"
    );
    let (signed, _) = request(TYPE_AXFR, None, true);
    let answer = collect(
        &path,
        signed.clone(),
        conn_at([127, 0, 0, 1], [127, 0, 0, 1], QueryTransport::Tcp),
        false,
    )
    .await;
    assert_eq!(rcode(&answer[0]), 0, "signed inside the site");
    let answer = collect(
        &path,
        signed.clone(),
        conn_at([198, 51, 100, 7], [203, 0, 113, 53], QueryTransport::Tcp),
        false,
    )
    .await;
    assert_eq!(rcode(&answer[0]), 5, "off-site over plain TCP");
    let answer = collect(
        &path,
        signed,
        conn_at([198, 51, 100, 7], [203, 0, 113, 53], QueryTransport::Dot),
        true,
    )
    .await;
    assert_eq!(rcode(&answer[0]), 0, "off-site over XoT");
    // Under Standard the zone's settings apply.
    let standard = view_lab(UpdateProfile::Standard);
    let answer = collect(
        &standard,
        unsigned,
        conn_at([127, 0, 0, 1], [127, 0, 0, 1], QueryTransport::Tcp),
        false,
    )
    .await;
    assert_eq!(rcode(&answer[0]), 0);
}

/// A refusal is audited with the stable code and the reason.
#[tokio::test]
async fn a_refusal_is_audited_with_its_code_and_reason() {
    let lab = lab(true, false, 16 * 1024);
    let (unsigned, _) = request(TYPE_AXFR, None, false);
    let _ = collect(
        &lab.path,
        unsigned,
        conn([127, 0, 0, 1], QueryTransport::Tcp),
        false,
    )
    .await;
    let audit = lab.audit.0.lock().expect("audit");
    let draft = format!("{:?}", audit.last().expect("a refusal record"));
    assert!(draft.contains("unsigned"), "{draft}");
    assert!(draft.contains("need a TSIG key"), "{draft}");
}
