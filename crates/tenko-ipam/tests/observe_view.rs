//! Reads of the observation layer over `MemStore`: the fact list (filters, sorting, paging)
//! and the computed view of one subject across sources, with the matching intent.

mod common;

use std::{net::IpAddr, sync::Arc, time::Duration};

use common::{address, host, prefix, run, service, vrf};
use tenko_core::{
    AddressId, ConnectorId, MacAddr, NodeId, ObjectRef, ObservationId, Principal, SystemComponent,
    Timestamp, VrfId,
    ipam::AssignmentMode,
    observe::{
        Endpoint, LinkKind, Observation, ObservationSource, Observed, ObservedHost, ProbeMethod,
    },
};
use tenko_ipam::{
    IpamCommand, IpamError, codes,
    observe::{
        IngestBatch, IngestReport, IntentSighting, ObserveConfig, ingest,
        tables::LAST_SEEN,
        view::{FactQuery, SubjectQuery, list_facts, subject_view},
    },
};
use tenko_store::{MemStore, ReadConsistency, ReadView, Store, WriteBatch};

fn time(text: &str) -> Timestamp {
    format!("2026-10-10T{text}Z").parse().expect("time")
}

fn mac(last: u8) -> MacAddr {
    format!("00:00:5e:00:53:{last:02x}").parse().expect("mac")
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("ip address")
}

fn inventory(connector: ConnectorId) -> ObservationSource {
    ObservationSource::Inventory { connector }
}

fn controller(connector: ConnectorId) -> ObservationSource {
    ObservationSource::NetworkController { connector }
}

fn probe(method: ProbeMethod) -> ObservationSource {
    ObservationSource::Probe {
        node: NodeId(1),
        method,
    }
}

/// An observation seen at `at` (a time of day on 2026-10-10) that lives for 15 minutes.
fn observation(source: &ObservationSource, subject: Observed, at: &str) -> Observation {
    let at = time(at);
    Observation {
        id: ObservationId::generate(),
        source: source.clone(),
        subject,
        observed_at: at,
        received_at: at,
        expires_at: at.checked_add(Duration::from_secs(900)),
    }
}

/// An inventory host.
fn host_subject(
    external_id: &str,
    name: Option<&str>,
    macs: &[u8],
    ips: &[&str],
    extra: impl FnOnce(&mut ObservedHost),
) -> Observed {
    let mut host = ObservedHost {
        external_id: external_id.to_owned(),
        name: name.map(str::to_owned),
        macs: macs.iter().map(|last| mac(*last)).collect(),
        ips: ips.iter().map(|text| ip(text)).collect(),
        ..ObservedHost::default()
    };
    extra(&mut host);
    Observed::Host(host)
}

fn attachment(
    client: u8,
    device: &str,
    port: Option<&str>,
    ssid: Option<&str>,
    vlan: u16,
) -> Observed {
    Observed::Attachment {
        mac: mac(client),
        device: device.to_owned(),
        port: port.map(str::to_owned),
        ssid: ssid.map(str::to_owned),
        vlan: Some(vlan),
    }
}

fn mem() -> Arc<dyn Store> {
    Arc::new(MemStore::default())
}

async fn push(
    store: &Arc<dyn Store>,
    source: &ObservationSource,
    observations: Vec<Observation>,
    complete: bool,
    at: &str,
) -> IngestReport {
    let batch = IngestBatch {
        source: source.clone(),
        observations,
        complete,
        received_at: time(at),
    };
    ingest(store, &batch, &ObserveConfig::default())
        .await
        .expect("ingest")
}

async fn read(store: &Arc<dyn Store>) -> Arc<dyn ReadView> {
    store.read(ReadConsistency::Local).await.expect("view")
}

fn sorted(mut keys: Vec<String>) -> Vec<String> {
    keys.sort();
    keys
}

fn assert_empty<T: std::fmt::Debug>(items: &[T]) {
    assert!(items.is_empty(), "expected nothing, found {items:?}");
}

fn assert_coded(error: &IpamError, code: &str, status: u16, name: Option<&str>) {
    assert_eq!(error.code_str(), code, "{error:?}");
    assert_eq!(error.coded().status, status);
    if let Some(name) = name {
        assert_eq!(
            error.coded().params.get("name").map(String::as_str),
            Some(name)
        );
    }
}

/// A set of sources and facts that every filter test reads.
struct Fixture {
    store: Arc<dyn Store>,
    /// Connector A: an inventory and a network controller.
    a: ConnectorId,
    /// Connector B: an inventory.
    b: ConnectorId,
    /// The VRF the probe reports.
    vrf: VrfId,
}

const LINK_KEY: &str = "link:ap-hall||sw-core|uplink1|uplink";

impl Fixture {
    /// Nine facts:
    ///
    /// | Source | Subject | Seen |
    /// |---|---|---|
    /// | inventory A | host 101 (mac 1 and 2, 192.0.2.10 and 2001:db8::10) | 08:00 |
    /// | inventory A | host 102 (mac 3, 198.51.100.20) | 08:01 |
    /// | network controller A | attachment of mac 1, attachment of mac 3 | 08:02, 08:03 |
    /// | inventory B | host ha (mac 4, 192.0.2.30) | 08:04 |
    /// | probe arp, tcp_syn, os_fingerprint | address, services, OS of 192.0.2.10 | 08:05 |
    /// | network controller A | link | 08:06 |
    #[allow(clippy::too_many_lines)] // One source after the other.
    async fn new() -> Self {
        let store = mem();
        let fixture = Fixture {
            store,
            a: ConnectorId::generate(),
            b: ConnectorId::generate(),
            vrf: VrfId::generate(),
        };
        let inv_a = inventory(fixture.a);
        let ctl_a = controller(fixture.a);
        let inv_b = inventory(fixture.b);
        let web = host_subject(
            "101",
            Some("Web01.Example.Test"),
            &[1, 2],
            &["192.0.2.10", "2001:db8::10"],
            |host| {
                host.os = Some("Debian 13".to_owned());
                host.platform = Some("qemu".to_owned());
                host.parent = Some("pve1".to_owned());
                host.tags = vec!["prod".to_owned(), "web".to_owned()];
            },
        );
        let db = host_subject(
            "102",
            Some("db01.example.test"),
            &[3],
            &["198.51.100.20"],
            |host| {
                host.os = Some("Alpine 3.22".to_owned());
                host.platform = Some("lxc".to_owned());
                host.parent = Some("pve2".to_owned());
                host.tags = vec!["lab".to_owned()];
            },
        );
        push(
            &fixture.store,
            &inv_a,
            vec![
                observation(&inv_a, web, "08:00:00"),
                observation(&inv_a, db, "08:01:00"),
            ],
            true,
            "08:01:00",
        )
        .await;
        let link = Observed::Link {
            a: Endpoint {
                device: "sw-core".to_owned(),
                port: Some("uplink1".to_owned()),
            },
            b: Endpoint {
                device: "ap-hall".to_owned(),
                port: None,
            },
            kind: LinkKind::Uplink,
        };
        push(
            &fixture.store,
            &ctl_a,
            vec![
                observation(
                    &ctl_a,
                    attachment(1, "sw-core", Some("Gi1/0/12"), None, 20),
                    "08:02:00",
                ),
                observation(
                    &ctl_a,
                    attachment(3, "ap-hall", None, Some("IoT-Net"), 30),
                    "08:03:00",
                ),
                observation(&ctl_a, link, "08:06:00"),
            ],
            false,
            "08:06:00",
        )
        .await;
        let home = host_subject(
            "ha",
            Some("hub01.example.org"),
            &[4],
            &["192.0.2.30"],
            |host| host.platform = Some("esphome".to_owned()),
        );
        push(
            &fixture.store,
            &inv_b,
            vec![observation(&inv_b, home, "08:04:00")],
            true,
            "08:04:00",
        )
        .await;
        let arp = probe(ProbeMethod::Arp);
        let syn = probe(ProbeMethod::TcpSyn);
        let os = probe(ProbeMethod::OsFingerprint);
        let address = Observed::Address {
            vrf: fixture.vrf,
            ip: ip("192.0.2.10"),
            mac: Some(mac(1)),
        };
        let services = Observed::Services {
            ip: ip("192.0.2.10"),
            open_tcp: vec![443, 22, 443],
            tls_tcp: vec![443],
        };
        let guess = Observed::Os {
            ip: ip("192.0.2.10"),
            guess: "Linux 6.x".to_owned(),
            confidence: 80,
        };
        for (source, subject) in [(arp, address), (syn, services), (os, guess)] {
            push(
                &fixture.store,
                &source,
                vec![observation(&source, subject, "08:05:00")],
                false,
                "08:05:00",
            )
            .await;
        }
        fixture
    }

    fn address_key(&self) -> String {
        format!("address:{}/192.0.2.10", self.vrf)
    }

    /// The subject keys of the facts a query returns, in order, read at 08:12.
    async fn keys(&self, query: FactQuery) -> Vec<String> {
        self.keys_at(query, "08:12:00").await
    }

    async fn keys_at(&self, query: FactQuery, now: &str) -> Vec<String> {
        let view = read(&self.store).await;
        let query = FactQuery {
            limit: Some(1_000),
            ..query
        };
        list_facts(view.as_ref(), None, &query, time(now))
            .expect("list")
            .items
            .into_iter()
            .map(|fact| fact.subject_key)
            .collect()
    }
}

/// Every page of a query, as the subject keys per page.
fn walk(view: &dyn ReadView, base: &FactQuery, limit: usize, now: Timestamp) -> Vec<Vec<String>> {
    let mut pages = Vec::new();
    let mut cursor = None;
    loop {
        let query = FactQuery {
            limit: Some(limit),
            cursor: cursor.take(),
            ..base.clone()
        };
        let page = list_facts(view, None, &query, now).expect("page");
        pages.push(
            page.items
                .into_iter()
                .map(|fact| fact.subject_key)
                .collect(),
        );
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return pages,
        }
        assert!(pages.len() < 50, "the cursor does not advance");
    }
}

#[tokio::test]
async fn pages_cover_every_fact_once_in_every_order() {
    let store = mem();
    let connector = ConnectorId::generate();
    let inv = inventory(connector);
    // vm4 and vm5 share a time, so the fact key breaks the tie.
    let seen = [
        ("vm1", "08:01:00"),
        ("vm2", "08:02:00"),
        ("vm3", "08:03:00"),
        ("vm4", "08:04:00"),
        ("vm5", "08:04:00"),
        ("vm6", "08:06:00"),
        ("vm7", "08:07:00"),
    ];
    let observations = seen
        .iter()
        .map(|(id, at)| observation(&inv, host_subject(id, Some(id), &[], &[], |_| {}), at))
        .collect();
    push(&store, &inv, observations, true, "08:07:00").await;
    let view = read(&store).await;
    let now = time("08:10:00");

    let newest_first =
        ["vm7", "vm6", "vm4", "vm5", "vm3", "vm2", "vm1"].map(|id| format!("host:{id}"));
    let base = FactQuery::default();
    let all = walk(view.as_ref(), &base, 1_000, now);
    assert_eq!(
        all,
        vec![newest_first.to_vec()],
        "-last_seen is the default"
    );

    for limit in [1, 2, 3, 6, 7, 8] {
        let pages = walk(view.as_ref(), &base, limit, now);
        let flat: Vec<String> = pages.iter().flatten().cloned().collect();
        assert_eq!(
            flat, newest_first,
            "limit {limit}: no gaps and no duplicates"
        );
        assert_eq!(pages.len(), 7_usize.div_ceil(limit), "limit {limit}");
        assert!(pages.iter().all(|page| page.len() <= limit));
    }
    let pages = walk(view.as_ref(), &base, 3, now);
    assert_eq!(pages.iter().map(Vec::len).collect::<Vec<_>>(), [3, 3, 1]);

    // The same walk under other orders.
    for (sort, expected) in [
        ("subject", ["vm1", "vm2", "vm3", "vm4", "vm5", "vm6", "vm7"]),
        (
            "-subject",
            ["vm7", "vm6", "vm5", "vm4", "vm3", "vm2", "vm1"],
        ),
        (
            "last_seen",
            ["vm1", "vm2", "vm3", "vm4", "vm5", "vm6", "vm7"],
        ),
    ] {
        let base = FactQuery {
            sort: vec![sort.to_owned()],
            ..FactQuery::default()
        };
        let flat: Vec<String> = walk(view.as_ref(), &base, 3, now)
            .into_iter()
            .flatten()
            .collect();
        let expected: Vec<String> = expected.map(|id| format!("host:{id}")).to_vec();
        assert_eq!(flat, expected, "sort {sort}");
    }

    // The last page has no cursor, and a page that ends exactly at the end has none either.
    let page = list_facts(
        view.as_ref(),
        None,
        &FactQuery {
            limit: Some(7),
            ..FactQuery::default()
        },
        now,
    )
    .expect("page");
    assert_eq!(page.items.len(), 7);
    assert_eq!(page.next_cursor, None);
}

#[tokio::test]
async fn a_cursor_stays_valid_when_facts_arrive_elsewhere() {
    let store = mem();
    let connector = ConnectorId::generate();
    let inv = inventory(connector);
    let observations = ["a", "b", "c", "d"]
        .iter()
        .map(|id| observation(&inv, host_subject(id, None, &[], &[], |_| {}), "08:00:00"))
        .collect();
    push(&store, &inv, observations, true, "08:00:00").await;
    let now = time("08:05:00");
    let base = FactQuery {
        sort: vec!["subject".to_owned()],
        limit: Some(2),
        ..FactQuery::default()
    };
    let first = list_facts(read(&store).await.as_ref(), None, &base, now).expect("first");
    let cursor = first.next_cursor.clone().expect("more");
    // A fact that sorts before the cursor, and one after it.
    let extra = ["0", "e"]
        .iter()
        .map(|id| observation(&inv, host_subject(id, None, &[], &[], |_| {}), "08:01:00"))
        .collect();
    push(&store, &inv, extra, false, "08:01:00").await;
    let second = list_facts(
        read(&store).await.as_ref(),
        None,
        &FactQuery {
            cursor: Some(cursor),
            ..base
        },
        now,
    )
    .expect("second");
    let keys: Vec<&str> = second
        .items
        .iter()
        .map(|f| f.subject_key.as_str())
        .collect();
    assert_eq!(keys, ["host:c", "host:d"]);
    let last = list_facts(
        read(&store).await.as_ref(),
        None,
        &FactQuery {
            cursor: second.next_cursor,
            sort: vec!["subject".to_owned()],
            limit: Some(2),
            ..FactQuery::default()
        },
        now,
    )
    .expect("last");
    assert_eq!(last.items.len(), 1);
    assert_eq!(last.items[0].subject_key, "host:e");
}

#[tokio::test]
async fn sort_orders_by_time_source_and_subject() {
    let fixture = Fixture::new().await;
    let by = |sort: &[&str]| FactQuery {
        sort: sort.iter().map(|s| (*s).to_owned()).collect(),
        ..FactQuery::default()
    };

    // Seen at 08:00 (host 101) to 08:06 (the link); the probe facts share 08:05, and the
    // fact key (source, then subject) breaks that tie in both directions.
    let at_0805 = [
        fixture.address_key(),
        "os:192.0.2.10".to_owned(),
        "services:192.0.2.10".to_owned(),
    ];
    let mut ascending = vec![
        "host:101".to_owned(),
        "host:102".to_owned(),
        format!("attachment:{}", mac(1)),
        format!("attachment:{}", mac(3)),
        "host:ha".to_owned(),
    ];
    ascending.extend(at_0805.iter().cloned());
    ascending.push(LINK_KEY.to_owned());
    let mut descending = vec![LINK_KEY.to_owned()];
    descending.extend(at_0805);
    descending.extend(ascending[..5].iter().rev().cloned());

    assert_eq!(fixture.keys(by(&["last_seen"])).await, ascending);
    assert_eq!(fixture.keys(by(&["+last_seen"])).await, ascending);
    assert_eq!(fixture.keys(by(&["-last_seen"])).await, descending);
    assert_eq!(
        fixture.keys(FactQuery::default()).await,
        descending,
        "-last_seen is the default"
    );
    // Every fact was seen once, so the first sighting orders like the last one.
    assert_eq!(fixture.keys(by(&["first_seen"])).await, ascending);
    assert_eq!(fixture.keys(by(&["-first_seen"])).await, descending);

    // Source, then subject descending, in one string and in two.
    let view = read(&fixture.store).await;
    let facts = list_facts(
        view.as_ref(),
        None,
        &FactQuery {
            limit: Some(1_000),
            ..FactQuery::default()
        },
        time("08:12:00"),
    )
    .expect("list")
    .items;
    let mut expected: Vec<(String, String)> = facts
        .iter()
        .map(|f| (f.source_key.clone(), f.subject_key.clone()))
        .collect();
    expected.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)));
    let expected: Vec<String> = expected.into_iter().map(|(_, subject)| subject).collect();
    assert_eq!(fixture.keys(by(&["source,-subject"])).await, expected);
    assert_eq!(fixture.keys(by(&["source", "-subject"])).await, expected);
    assert_eq!(fixture.keys(by(&[" +source , -subject "])).await, expected);
}

#[tokio::test]
async fn filter_by_source_key_and_connector() {
    let fixture = Fixture::new().await;
    let source = |text: String| FactQuery {
        source: Some(text),
        ..FactQuery::default()
    };
    // A source key matches one source.
    assert_eq!(
        sorted(
            fixture
                .keys(source(format!("inventory:{}", fixture.a)))
                .await
        ),
        ["host:101", "host:102"]
    );
    assert_eq!(
        sorted(
            fixture
                .keys(source(format!("network_controller:{}", fixture.a)))
                .await
        ),
        sorted(vec![
            format!("attachment:{}", mac(1)),
            format!("attachment:{}", mac(3)),
            LINK_KEY.to_owned(),
        ])
    );
    assert_eq!(
        fixture.keys(source("probe:1:arp".to_owned())).await,
        [fixture.address_key()]
    );
    // A connector id matches the inventory and the network controller of the connector.
    assert_eq!(fixture.keys(source(fixture.a.to_string())).await.len(), 5);
    assert_eq!(
        fixture.keys(source(fixture.b.to_string())).await,
        ["host:ha"]
    );
    assert_empty(
        &fixture
            .keys(source(ConnectorId::generate().to_string()))
            .await,
    );
    assert_empty(&fixture.keys(source("inventory:nothing".to_owned())).await);
}

#[tokio::test]
async fn filter_by_subject_type() {
    let fixture = Fixture::new().await;
    let kind = |text: &str| FactQuery {
        subject_type: Some(text.to_owned()),
        ..FactQuery::default()
    };
    assert_eq!(
        sorted(fixture.keys(kind("host")).await),
        ["host:101", "host:102", "host:ha"]
    );
    assert_eq!(fixture.keys(kind("attachment")).await.len(), 2);
    assert_eq!(fixture.keys(kind("address")).await, [fixture.address_key()]);
    assert_eq!(
        fixture.keys(kind("services")).await,
        ["services:192.0.2.10"]
    );
    assert_eq!(fixture.keys(kind("os")).await, ["os:192.0.2.10"]);
    assert_eq!(fixture.keys(kind("link")).await, [LINK_KEY]);

    let view = read(&fixture.store).await;
    let error =
        list_facts(view.as_ref(), None, &kind("router"), time("08:12:00")).expect_err("type");
    assert_coded(&error, codes::INVALID_FILTER, 400, Some("type"));
    let error = list_facts(view.as_ref(), None, &kind("Host"), time("08:12:00")).expect_err("case");
    assert_coded(&error, codes::INVALID_FILTER, 400, Some("type"));
}

#[tokio::test]
async fn filter_by_mac_ip_and_network() {
    let fixture = Fixture::new().await;
    let with_mac = |last: u8| FactQuery {
        mac: Some(mac(last)),
        ..FactQuery::default()
    };
    assert_eq!(
        sorted(fixture.keys(with_mac(1)).await),
        sorted(vec![
            "host:101".to_owned(),
            format!("attachment:{}", mac(1)),
            fixture.address_key(),
        ])
    );
    assert_eq!(fixture.keys(with_mac(2)).await, ["host:101"]);
    assert_empty(&fixture.keys(with_mac(9)).await);

    let with_ip = |text: &str| FactQuery {
        ip: Some(ip(text)),
        ..FactQuery::default()
    };
    assert_eq!(
        sorted(fixture.keys(with_ip("192.0.2.10")).await),
        sorted(vec![
            "host:101".to_owned(),
            fixture.address_key(),
            "services:192.0.2.10".to_owned(),
            "os:192.0.2.10".to_owned(),
        ])
    );
    assert_eq!(fixture.keys(with_ip("2001:db8::10")).await, ["host:101"]);
    assert_empty(&fixture.keys(with_ip("192.0.2.11")).await);

    let within = |text: &str| FactQuery {
        within: Some(text.parse().expect("network")),
        ..FactQuery::default()
    };
    assert_eq!(
        sorted(fixture.keys(within("192.0.2.0/24")).await),
        sorted(vec![
            "host:101".to_owned(),
            "host:ha".to_owned(),
            fixture.address_key(),
            "services:192.0.2.10".to_owned(),
            "os:192.0.2.10".to_owned(),
        ])
    );
    assert_eq!(fixture.keys(within("192.0.2.30/32")).await, ["host:ha"]);
    assert_eq!(fixture.keys(within("198.51.100.0/24")).await, ["host:102"]);
    // The family matters: an IPv6 network holds no IPv4 address, and 0.0.0.0/0 no IPv6 one.
    assert_eq!(fixture.keys(within("2001:db8::/32")).await, ["host:101"]);
    assert_eq!(fixture.keys(within("2001:db8:1::/48")).await.len(), 0);
    assert_eq!(fixture.keys(within("0.0.0.0/0")).await.len(), 6);
    assert_eq!(fixture.keys(within("::/0")).await, ["host:101"]);
}

#[tokio::test]
async fn filter_by_text() {
    let fixture = Fixture::new().await;
    let text = |q: &str| FactQuery {
        q: Some(q.to_owned()),
        ..FactQuery::default()
    };
    // The name, without case, and trimmed.
    assert_eq!(fixture.keys(text("web01")).await, ["host:101"]);
    assert_eq!(fixture.keys(text("  WEB01.example  ")).await, ["host:101"]);
    // OS, platform, parent, tag and external id of a host.
    assert_eq!(fixture.keys(text("debian")).await, ["host:101"]);
    assert_eq!(fixture.keys(text("LXC")).await, ["host:102"]);
    assert_eq!(fixture.keys(text("pve2")).await, ["host:102"]);
    assert_eq!(fixture.keys(text("prod")).await, ["host:101"]);
    assert_eq!(fixture.keys(text("esphome")).await, ["host:ha"]);
    assert_eq!(fixture.keys(text("host:ha")).await, ["host:ha"]);
    // The device, port and SSID of an attachment.
    assert_eq!(
        fixture.keys(text("gi1/0/12")).await,
        [format!("attachment:{}", mac(1))]
    );
    assert_eq!(
        fixture.keys(text("iot-net")).await,
        [format!("attachment:{}", mac(3))]
    );
    assert_eq!(
        sorted(fixture.keys(text("sw-core")).await),
        sorted(vec![format!("attachment:{}", mac(1)), LINK_KEY.to_owned()]),
        "the device of an attachment, and the endpoint in the key of a link"
    );
    // The guess of an OS fact, and the address in a subject key.
    assert_eq!(fixture.keys(text("linux 6")).await, ["os:192.0.2.10"]);
    assert_eq!(
        sorted(fixture.keys(text("services:")).await),
        ["services:192.0.2.10"]
    );
    // An empty text matches everything, an unknown one nothing, and a text does not match
    // across two attributes.
    assert_eq!(fixture.keys(text("  ")).await.len(), 9);
    assert_empty(&fixture.keys(text("no such thing")).await);
    assert_empty(&fixture.keys(text("qemu pve1")).await);
}

#[tokio::test]
async fn filters_combine() {
    let fixture = Fixture::new().await;
    let query = FactQuery {
        subject_type: Some("host".to_owned()),
        within: Some("192.0.2.0/24".parse().expect("network")),
        source: Some(fixture.a.to_string()),
        current: Some(true),
        ..FactQuery::default()
    };
    assert_eq!(fixture.keys(query).await, ["host:101"]);
    let query = FactQuery {
        subject_type: Some("attachment".to_owned()),
        mac: Some(mac(3)),
        q: Some("iot".to_owned()),
        ..FactQuery::default()
    };
    assert_eq!(
        fixture.keys(query).await,
        [format!("attachment:{}", mac(3))]
    );
}

#[tokio::test]
async fn filter_by_current_follows_expiry_and_time() {
    let fixture = Fixture::new().await;
    let current = |flag: bool| FactQuery {
        current: Some(flag),
        ..FactQuery::default()
    };
    // Everything is current at 08:12 and nothing is expired.
    assert_eq!(fixture.keys(current(true)).await.len(), 9);
    assert_empty(&fixture.keys(current(false)).await);

    // An empty complete batch of inventory A expires its two hosts at once.
    let report = push(
        &fixture.store,
        &inventory(fixture.a),
        vec![],
        true,
        "08:10:00",
    )
    .await;
    assert_eq!(report.gone, 2);
    assert_eq!(
        sorted(fixture.keys(current(false)).await),
        ["host:101", "host:102"]
    );
    assert_eq!(fixture.keys(current(true)).await.len(), 7);
    assert_eq!(
        fixture.keys(FactQuery::default()).await.len(),
        9,
        "expired facts stay in the list"
    );

    // Facts that nobody refreshed lapse with time: nothing is current at 09:00.
    assert_eq!(fixture.keys_at(current(true), "09:00:00").await.len(), 0);
    assert_eq!(fixture.keys_at(current(false), "09:00:00").await.len(), 9);
    // At 08:17:30 the attachment of MAC 1 (seen 08:02, valid until 08:17) has lapsed while the
    // other unrefreshed facts, seen 08:03 or later, live on; the two hosts of inventory A
    // stay expired.
    let still = fixture.keys_at(current(true), "08:17:30").await;
    assert_eq!(
        sorted(still),
        sorted(vec![
            format!("attachment:{}", mac(3)),
            "host:ha".to_owned(),
            fixture.address_key(),
            "services:192.0.2.10".to_owned(),
            "os:192.0.2.10".to_owned(),
            LINK_KEY.to_owned(),
        ])
    );
}

#[tokio::test]
async fn items_carry_their_revision_and_the_page_the_view_revision() {
    let store = mem();
    let connector = ConnectorId::generate();
    let inv = inventory(connector);
    let first = push(
        &store,
        &inv,
        vec![observation(
            &inv,
            host_subject("1", None, &[], &[], |_| {}),
            "08:00:00",
        )],
        false,
        "08:00:00",
    )
    .await;
    let second = push(
        &store,
        &inv,
        vec![observation(
            &inv,
            host_subject("2", None, &[], &[], |_| {}),
            "08:01:00",
        )],
        false,
        "08:01:00",
    )
    .await;
    let view = read(&store).await;
    let page = list_facts(
        view.as_ref(),
        None,
        &FactQuery {
            sort: vec!["subject".to_owned()],
            ..FactQuery::default()
        },
        time("08:05:00"),
    )
    .expect("page");
    assert_eq!(page.revision, view.revision());
    let revisions: Vec<_> = page.items.iter().map(|fact| fact.revision).collect();
    assert_eq!(
        revisions,
        [
            first.revision.expect("first"),
            second.revision.expect("second")
        ]
    );
    assert!(page.items[0].revision < page.items[1].revision);
}

#[tokio::test]
async fn invalid_parameters_are_refused() {
    let fixture = Fixture::new().await;
    let view = read(&fixture.store).await;
    let now = time("08:12:00");

    let error = list_facts(
        view.as_ref(),
        None,
        &FactQuery {
            sort: vec!["name".to_owned()],
            ..FactQuery::default()
        },
        now,
    )
    .expect_err("sort");
    assert_coded(&error, codes::INVALID_FILTER, 400, Some("sort"));
    let error = list_facts(
        view.as_ref(),
        None,
        &FactQuery {
            sort: vec!["last_seen,-bogus".to_owned()],
            ..FactQuery::default()
        },
        now,
    )
    .expect_err("second field");
    assert_coded(&error, codes::INVALID_FILTER, 400, Some("sort"));

    for cursor in ["zz", "abc", "not hex at all"] {
        let error = list_facts(
            view.as_ref(),
            None,
            &FactQuery {
                cursor: Some(cursor.to_owned()),
                ..FactQuery::default()
            },
            now,
        )
        .expect_err("cursor");
        assert_coded(&error, codes::INVALID_CURSOR, 400, None);
    }

    for limit in [0, 1_001, usize::MAX] {
        let error = list_facts(
            view.as_ref(),
            None,
            &FactQuery {
                limit: Some(limit),
                ..FactQuery::default()
            },
            now,
        )
        .expect_err("limit");
        assert_coded(&error, codes::INVALID_FILTER, 400, Some("limit"));
    }
    for limit in [1, 1_000] {
        list_facts(
            view.as_ref(),
            None,
            &FactQuery {
                limit: Some(limit),
                ..FactQuery::default()
            },
            now,
        )
        .expect("limit in range");
    }
    // A valid hex string that is no sort key of ours is still a valid cursor: it just
    // starts after everything it is smaller than.
    let page = list_facts(
        view.as_ref(),
        None,
        &FactQuery {
            cursor: Some("ff".to_owned()),
            ..FactQuery::default()
        },
        now,
    )
    .expect("cursor");
    assert_empty(&page.items);
}

fn subject(text: &str) -> SubjectQuery {
    text.parse().expect("subject")
}

#[tokio::test]
async fn a_mac_collects_the_facts_of_every_source() {
    let fixture = Fixture::new().await;
    let view = read(&fixture.store).await;
    let result = subject_view(
        view.as_ref(),
        None,
        &subject("00-00-5E-00-53-01"),
        time("08:12:00"),
    )
    .expect("view");
    assert_eq!(result.subject, format!("mac:{}", mac(1)));
    assert_eq!(result.revision, view.revision());

    // Newest sighting first: the probe address (08:05), the attachment (08:02), the host.
    let keys: Vec<(&str, &str)> = result
        .facts
        .iter()
        .map(|f| (f.source_key.as_str(), f.subject_key.as_str()))
        .collect();
    assert_eq!(
        keys,
        [
            ("probe:1:arp", fixture.address_key().as_str()),
            (
                format!("network_controller:{}", fixture.a).as_str(),
                format!("attachment:{}", mac(1)).as_str()
            ),
            (format!("inventory:{}", fixture.a).as_str(), "host:101"),
        ]
    );
    assert!(result.facts.iter().all(|fact| fact.revision.0 > 0));

    let summary = &result.summary;
    assert!(summary.current);
    assert_eq!(
        summary.sources,
        sorted(vec![
            format!("inventory:{}", fixture.a),
            format!("network_controller:{}", fixture.a),
            "probe:1:arp".to_owned(),
        ])
    );
    assert_eq!(summary.first_seen, Some(time("08:00:00")));
    assert_eq!(summary.last_seen, Some(time("08:05:00")));
    assert_eq!(summary.macs, [mac(1), mac(2)]);
    assert_eq!(summary.ips, [ip("192.0.2.10"), ip("2001:db8::10")]);
    assert_eq!(summary.names, ["Web01.Example.Test"]);
    assert_eq!(summary.os, ["Debian 13"]);
    assert_eq!(summary.platforms, ["qemu"]);
    assert_eq!(summary.parents, ["pve1"]);
    assert_eq!(summary.tags, ["prod", "web"]);
    assert!(
        summary.open_tcp.is_empty(),
        "the services fact names no MAC"
    );
    assert_eq!(summary.attachments.len(), 1);
    let attached = &summary.attachments[0];
    assert_eq!(attached.source, format!("network_controller:{}", fixture.a));
    assert_eq!(attached.mac, mac(1));
    assert_eq!(attached.device, "sw-core");
    assert_eq!(attached.port.as_deref(), Some("Gi1/0/12"));
    assert_eq!(attached.ssid, None);
    assert_eq!(attached.vlan, Some(20));
    assert_eq!(attached.last_seen, time("08:02:00"));

    // No intent matches, so there is nothing to show.
    assert_eq!(
        result.intent,
        tenko_ipam::observe::view::IntentMatch::default()
    );
    assert_empty(&result.sightings);
}

#[tokio::test]
async fn an_ip_collects_services_and_os_guesses() {
    let fixture = Fixture::new().await;
    let view = read(&fixture.store).await;
    let result = subject_view(
        view.as_ref(),
        None,
        &subject("192.0.2.10"),
        time("08:12:00"),
    )
    .expect("view");
    assert_eq!(result.subject, "ip:192.0.2.10");
    let mut keys: Vec<String> = result.facts.iter().map(|f| f.subject_key.clone()).collect();
    keys.sort();
    assert_eq!(
        keys,
        sorted(vec![
            "host:101".to_owned(),
            fixture.address_key(),
            "services:192.0.2.10".to_owned(),
            "os:192.0.2.10".to_owned(),
        ])
    );
    let summary = &result.summary;
    assert_eq!(summary.open_tcp, [22, 443], "sorted, without duplicates");
    assert_eq!(summary.tls_tcp, [443]);
    assert_eq!(summary.os, ["Debian 13", "Linux 6.x"]);
    assert_eq!(summary.macs, [mac(1), mac(2)]);
    assert_empty(&summary.attachments);
    assert_eq!(summary.sources.len(), 4);

    // An IPv6 address finds only the host that names it.
    let result = subject_view(
        view.as_ref(),
        None,
        &subject("2001:db8::10"),
        time("08:12:00"),
    )
    .expect("view");
    assert_eq!(result.subject, "ip:2001:db8::10");
    assert_eq!(result.facts.len(), 1);
    assert_eq!(result.summary.ips, [ip("192.0.2.10"), ip("2001:db8::10")]);
}

#[tokio::test]
async fn a_name_is_compared_without_case_and_not_as_a_prefix() {
    let fixture = Fixture::new().await;
    let inv_b = inventory(fixture.b);
    let longer = host_subject("web01x", Some("web01.example.tests"), &[7], &[], |_| {});
    push(
        &fixture.store,
        &inv_b,
        vec![
            observation(&inv_b, longer, "08:07:00"),
            observation(
                &inv_b,
                host_subject(
                    "ha",
                    Some("hub01.example.org"),
                    &[4],
                    &["192.0.2.30"],
                    |_| {},
                ),
                "08:08:00",
            ),
        ],
        false,
        "08:08:00",
    )
    .await;
    let view = read(&fixture.store).await;
    let result = subject_view(
        view.as_ref(),
        None,
        &subject("WEB01.Example.TEST"),
        time("08:12:00"),
    )
    .expect("view");
    assert_eq!(result.subject, "name:web01.example.test");
    assert_eq!(result.facts.len(), 1);
    assert_eq!(result.facts[0].subject_key, "host:101");
    assert_eq!(result.summary.names, ["Web01.Example.Test"]);
    assert_eq!(result.summary.macs, [mac(1), mac(2)]);

    let longer = subject_view(
        view.as_ref(),
        None,
        &subject("web01.example.tests"),
        time("08:12:00"),
    )
    .expect("view");
    assert_eq!(longer.facts.len(), 1);
    assert_eq!(longer.facts[0].subject_key, "host:web01x");
}

#[tokio::test]
async fn current_facts_come_first_and_the_summary_follows_them() {
    let store = mem();
    let connector = ConnectorId::generate();
    let inv = inventory(connector);
    let ctl = controller(connector);
    let named = |ips: &[&str]| {
        host_subject("101", Some("web01.example.test"), &[1, 2], ips, |host| {
            host.os = Some("Debian 13".to_owned());
            host.platform = Some("qemu".to_owned());
            host.parent = Some("pve1".to_owned());
            host.tags = vec!["prod".to_owned()];
        })
    };
    push(
        &store,
        &inv,
        vec![observation(&inv, named(&["192.0.2.10"]), "08:00:00")],
        true,
        "08:00:00",
    )
    .await;
    push(
        &store,
        &ctl,
        vec![observation(
            &ctl,
            attachment(1, "sw1", Some("p3"), None, 20),
            "08:05:00",
        )],
        false,
        "08:05:00",
    )
    .await;
    // The host changes its address at 08:10: first seen 08:00, last seen 08:10.
    let report = push(
        &store,
        &inv,
        vec![observation(&inv, named(&["192.0.2.11"]), "08:10:00")],
        true,
        "08:10:00",
    )
    .await;
    assert_eq!(report.changed, 1);
    let at_mac = subject("00:00:5e:00:53:01");
    let keys = |facts: &[tenko_ipam::observe::ObservedFact]| -> Vec<String> {
        facts.iter().map(|f| f.subject_key.clone()).collect()
    };

    // Both current: the host was seen last.
    let view = read(&store).await;
    let result = subject_view(view.as_ref(), None, &at_mac, time("08:11:00")).expect("view");
    assert_eq!(
        keys(&result.facts),
        ["host:101", &format!("attachment:{}", mac(1))]
    );
    assert!(result.summary.current);
    assert_eq!(
        result.summary.ips,
        [ip("192.0.2.11")],
        "the address it has now"
    );
    assert_eq!(result.summary.sources.len(), 2);

    // The inventory stops reporting the host: it expires, the attachment is still current
    // and comes first although the host was seen later.
    let report = push(&store, &inv, vec![], true, "08:12:00").await;
    assert_eq!(report.gone, 1);
    let view = read(&store).await;
    let result = subject_view(view.as_ref(), None, &at_mac, time("08:13:00")).expect("view");
    assert_eq!(
        keys(&result.facts),
        [&format!("attachment:{}", mac(1)), "host:101"]
    );
    let summary = &result.summary;
    assert!(summary.current);
    assert_eq!(summary.sources, [format!("network_controller:{connector}")]);
    assert_eq!(summary.macs, [mac(1)], "only the current attachment counts");
    assert_empty(&summary.ips);
    assert!(summary.names.is_empty() && summary.os.is_empty() && summary.tags.is_empty());
    assert!(summary.platforms.is_empty() && summary.parents.is_empty());
    assert_eq!(summary.attachments.len(), 1);
    assert_eq!(
        summary.first_seen,
        Some(time("08:00:00")),
        "over every fact"
    );
    assert_eq!(summary.last_seen, Some(time("08:10:00")), "over every fact");

    // Later still, the attachment lapses too: nothing is current and every fact counts.
    let result = subject_view(view.as_ref(), None, &at_mac, time("09:00:00")).expect("view");
    let summary = &result.summary;
    assert!(!summary.current);
    assert_empty(&summary.sources);
    assert_eq!(summary.macs, [mac(1), mac(2)]);
    assert_eq!(summary.ips, [ip("192.0.2.11")]);
    assert_eq!(summary.names, ["web01.example.test"]);
    assert_eq!(summary.os, ["Debian 13"]);
    assert_eq!(summary.platforms, ["qemu"]);
    assert_eq!(summary.parents, ["pve1"]);
    assert_eq!(summary.tags, ["prod"]);
    assert_eq!(summary.attachments.len(), 1);
    // Both are expired; the newest sighting is first.
    assert_eq!(
        keys(&result.facts),
        ["host:101", &format!("attachment:{}", mac(1))]
    );
}

/// Writes the last sighting of an intent object the way the reconciler does.
async fn sighted(store: &MemStore, object: ObjectRef, at: &str) {
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Reconciler), time(at));
    batch
        .put_typed(
            &LAST_SEEN,
            &object,
            &IntentSighting {
                at: time(at),
                source: "inventory:test".to_owned(),
                observation: ObservationId::generate(),
            },
        )
        .expect("put");
    store.propose(batch).await.expect("propose");
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One check after the other, each reporting what broke.
async fn intent_matches_by_mac_ip_and_name_and_skips_deleted_objects() {
    let (service, mem_store) = service();
    let store: Arc<dyn Store> = Arc::new(mem_store.clone());

    // Intent: host web01 with eth0 (mac 1) and 192.0.2.10 in the default VRF, the same
    // address in a second VRF, and host db01 with eth0 (mac 33).
    let (web, web_eth0) = host(
        "web01.example.test",
        AssignmentMode::Static,
        Some("00-00-5E-00-53-01"),
    );
    let web_id = web.id.expect("id");
    let (db, db_eth0) = host(
        "db01.example.test",
        AssignmentMode::Static,
        Some("00-00-5E-00-53-21"),
    );
    let db_id = db.id.expect("id");
    let mut web_address = address(None, "192.0.2.10");
    web_address.interface = Some(web_eth0);
    let web_address_id: AddressId = web_address.id.expect("id");
    let lab = vrf("lab");
    let lab_id = lab.id.expect("id");
    let lab_address = address(Some(lab_id), "192.0.2.10");
    let lab_address_id: AddressId = lab_address.id.expect("id");
    let other_address = address(None, "192.0.2.99");
    let other_address_id: AddressId = other_address.id.expect("id");
    run(
        &service,
        vec![
            IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24")),
            IpamCommand::CreateVrf(lab),
            IpamCommand::CreatePrefix(prefix(Some(lab_id), "192.0.2.0/24")),
            IpamCommand::CreateHost(web),
            IpamCommand::CreateHost(db),
            IpamCommand::CreateAddress(web_address),
            IpamCommand::CreateAddress(lab_address),
            IpamCommand::CreateAddress(other_address),
        ],
    )
    .await;

    // Observations: the inventory sees web01 by name, MAC and address, and db01 by name with
    // a MAC that no interface has.
    let connector = ConnectorId::generate();
    let inv = inventory(connector);
    push(
        &store,
        &inv,
        vec![
            observation(
                &inv,
                host_subject(
                    "101",
                    Some("Web01.Example.Test"),
                    &[1],
                    &["192.0.2.10"],
                    |_| {},
                ),
                "08:00:00",
            ),
            observation(
                &inv,
                host_subject(
                    "102",
                    Some("db01.example.test"),
                    &[34],
                    &["198.51.100.21"],
                    |_| {},
                ),
                "08:00:00",
            ),
        ],
        true,
        "08:00:00",
    )
    .await;

    // Sightings of the matching objects, and of an address that does not match.
    sighted(&mem_store, ObjectRef::from(web_address_id), "08:01:00").await;
    sighted(&mem_store, ObjectRef::from(lab_address_id), "08:02:00").await;
    sighted(&mem_store, ObjectRef::from(web_eth0), "08:03:00").await;
    sighted(&mem_store, ObjectRef::from(other_address_id), "08:04:00").await;
    sighted(&mem_store, ObjectRef::from(db_eth0), "08:05:00").await;

    let now = time("08:10:00");
    let view = read(&store).await;
    let by_mac =
        subject_view(view.as_ref(), None, &subject("00:00:5e:00:53:01"), now).expect("view");
    assert_eq!(by_mac.intent.hosts, [web_id]);
    assert_eq!(by_mac.intent.interfaces, [web_eth0]);
    let mut addresses = vec![web_address_id, lab_address_id];
    addresses.sort();
    assert_eq!(by_mac.intent.addresses, addresses, "one per VRF, sorted");
    assert_eq!(by_mac.intent.vrfs.len(), 2);
    assert!(by_mac.intent.vrfs.contains(&lab_id));
    let objects: Vec<ObjectRef> = by_mac.sightings.iter().map(|s| s.object).collect();
    let mut expected: Vec<ObjectRef> = vec![
        ObjectRef::from(web_address_id),
        ObjectRef::from(lab_address_id),
        ObjectRef::from(web_eth0),
    ];
    expected.sort();
    assert_eq!(
        objects, expected,
        "ordered by object, without the unrelated address"
    );
    let seen_at = |object: ObjectRef| {
        by_mac
            .sightings
            .iter()
            .find(|s| s.object == object)
            .map(|s| s.sighting.at)
    };
    assert_eq!(seen_at(ObjectRef::from(web_eth0)), Some(time("08:03:00")));
    assert_eq!(
        seen_at(ObjectRef::from(web_address_id)),
        Some(time("08:01:00"))
    );

    // The same objects by address (the interface is found through the MAC of the host fact),
    // and by name.
    let by_ip = subject_view(view.as_ref(), None, &subject("192.0.2.10"), now).expect("view");
    assert_eq!(by_ip.intent, by_mac.intent);
    let by_name =
        subject_view(view.as_ref(), None, &subject("web01.example.test"), now).expect("view");
    assert_eq!(by_name.intent, by_mac.intent);
    assert_eq!(by_name.sightings, by_mac.sightings);

    // A name finds the host and its interfaces even when no MAC of the observation matches;
    // the unrelated MAC and address find nothing.
    let db_view =
        subject_view(view.as_ref(), None, &subject("DB01.example.test"), now).expect("view");
    assert_eq!(db_view.intent.hosts, [db_id]);
    assert_eq!(db_view.intent.interfaces, [db_eth0]);
    assert_empty(&db_view.intent.addresses);
    assert_empty(&db_view.intent.vrfs);
    assert_eq!(db_view.sightings.len(), 1);
    assert_eq!(db_view.sightings[0].object, ObjectRef::from(db_eth0));

    // Deleted objects do not match: the address of the second VRF, and host db01 with its
    // interface.
    run(
        &service,
        vec![
            IpamCommand::Delete {
                object: ObjectRef::from(lab_address_id),
                expected: None,
                cascade: false,
            },
            IpamCommand::Delete {
                object: ObjectRef::from(db_id),
                expected: None,
                cascade: true,
            },
        ],
    )
    .await;
    let view = read(&store).await;
    let by_mac =
        subject_view(view.as_ref(), None, &subject("00:00:5e:00:53:01"), now).expect("view");
    assert_eq!(by_mac.intent.addresses, [web_address_id]);
    assert_eq!(by_mac.intent.vrfs.len(), 1);
    assert_eq!(by_mac.sightings.len(), 2);
    let db_view =
        subject_view(view.as_ref(), None, &subject("db01.example.test"), now).expect("view");
    assert_empty(&db_view.intent.hosts);
    assert_empty(&db_view.intent.interfaces);
    assert_empty(&db_view.sightings);
}

#[tokio::test]
async fn an_interface_of_another_mac_does_not_match() {
    let (service, mem_store) = service();
    let store: Arc<dyn Store> = Arc::new(mem_store.clone());
    let (web, interface) = host(
        "web01.example.test",
        AssignmentMode::Static,
        Some("00-00-5E-00-53-02"),
    );
    let web_id = web.id.expect("id");
    run(&service, vec![IpamCommand::CreateHost(web)]).await;
    let connector = ConnectorId::generate();
    let inv = inventory(connector);
    push(
        &store,
        &inv,
        vec![observation(
            &inv,
            host_subject(
                "1",
                Some("other.example.test"),
                &[1],
                &["198.51.100.5"],
                |_| {},
            ),
            "08:00:00",
        )],
        true,
        "08:00:00",
    )
    .await;
    let view = read(&store).await;
    let result = subject_view(
        view.as_ref(),
        None,
        &subject("00:00:5e:00:53:01"),
        time("08:05:00"),
    )
    .expect("view");
    assert_empty(&result.intent.hosts);
    assert_empty(&result.intent.interfaces);
    // The host with the MAC 02 is found by its own MAC if some source names it.
    push(
        &store,
        &inv,
        vec![observation(
            &inv,
            host_subject("2", Some("web01.example.test"), &[2], &[], |_| {}),
            "08:06:00",
        )],
        false,
        "08:06:00",
    )
    .await;
    let view = read(&store).await;
    let result = subject_view(
        view.as_ref(),
        None,
        &subject("00:00:5e:00:53:02"),
        time("08:07:00"),
    )
    .expect("view");
    assert_eq!(result.intent.hosts, [web_id]);
    assert_eq!(result.intent.interfaces, [interface]);
}

#[tokio::test]
async fn an_unknown_subject_is_not_found() {
    let fixture = Fixture::new().await;
    let view = read(&fixture.store).await;
    for text in [
        "00:00:5e:00:53:99",
        "203.0.113.7",
        "2001:db8:ffff::1",
        "nobody.example.test",
    ] {
        let error =
            subject_view(view.as_ref(), None, &subject(text), time("08:12:00")).expect_err(text);
        assert_coded(&error, codes::NOT_FOUND, 404, None);
        let params = &error.coded().params;
        assert_eq!(
            params.get("kind").map(String::as_str),
            Some("observation"),
            "{text}"
        );
        assert_eq!(
            params.get("subject").map(String::as_str),
            Some(subject(text).to_string().as_str()),
            "{text}"
        );
        assert!(params.contains_key("revision"));
    }
    // An empty store has nothing to show either.
    let empty = mem();
    let view = read(&empty).await;
    let error = subject_view(view.as_ref(), None, &subject("192.0.2.1"), time("08:12:00"))
        .expect_err("empty");
    assert_coded(&error, codes::NOT_FOUND, 404, None);
    let page =
        list_facts(view.as_ref(), None, &FactQuery::default(), time("08:12:00")).expect("list");
    assert_empty(&page.items);
    assert_eq!(page.next_cursor, None);
}

#[tokio::test]
async fn probe_names_and_vendors_join_the_view_of_their_device() {
    let store = mem();
    let vrf = VrfId::generate();
    let arp = probe(ProbeMethod::Arp);
    let rdns = probe(ProbeMethod::ReverseDns);
    let tcp = probe(ProbeMethod::TcpConnect);
    let batches = [
        (
            arp.clone(),
            vec![
                Observed::Address {
                    vrf,
                    ip: ip("192.0.2.40"),
                    mac: Some(mac(40)),
                },
                Observed::Vendor {
                    mac: mac(40),
                    vendor: "ICANN, IANA Department".to_owned(),
                },
            ],
        ),
        (
            rdns,
            vec![Observed::Name {
                ip: ip("192.0.2.40"),
                name: "Printer.Example.Test".to_owned(),
                placeholder: false,
            }],
        ),
        (
            tcp,
            vec![Observed::Services {
                ip: ip("192.0.2.40"),
                open_tcp: vec![443, 631],
                tls_tcp: vec![443],
            }],
        ),
    ];
    for (source, subjects) in batches {
        let observations = subjects
            .into_iter()
            .map(|subject| observation(&source, subject, "08:05:00"))
            .collect();
        push(&store, &source, observations, true, "08:05:00").await;
    }
    let view = read(&store).await;
    // The name finds the device; a name fact is indexed like an inventory name.
    let by_name = subject_view(
        view.as_ref(),
        None,
        &subject("printer.example.test"),
        time("08:06:00"),
    )
    .expect("view by name");
    assert_eq!(by_name.facts.len(), 1);
    assert_eq!(by_name.facts[0].subject_key, "name:192.0.2.40");
    let by_ip = subject_view(
        view.as_ref(),
        None,
        &subject("192.0.2.40"),
        time("08:06:00"),
    )
    .expect("view by address");
    let summary = &by_ip.summary;
    assert_eq!(summary.names, ["Printer.Example.Test"]);
    assert_eq!(summary.open_tcp, [443, 631]);
    assert_eq!(summary.tls_tcp, [443]);
    let by_mac = subject_view(
        view.as_ref(),
        None,
        &subject("00:00:5e:00:53:28"),
        time("08:06:00"),
    )
    .expect("view by MAC");
    assert_eq!(by_mac.summary.vendors, ["ICANN, IANA Department"]);
    let vendors = list_facts(
        view.as_ref(),
        None,
        &FactQuery {
            subject_type: Some("vendor".to_owned()),
            ..FactQuery::default()
        },
        time("08:06:00"),
    )
    .expect("list");
    assert_eq!(vendors.items.len(), 1);
}

/// A bound lease row of `address` to the MAC `00:00:5e:00:53:<client>`, granted at 08:00
/// and last renewed at 08:10, ending at 09:00.
fn lease_row(address: &str, client: u8, vrf: VrfId) -> tenko_core::dhcp::Lease {
    use tenko_core::dhcp::{BindingState, ClientKey, DdnsState, Lease};
    Lease {
        addr: address.parse().expect("address"),
        vrf,
        scope: tenko_core::PrefixId::generate(),
        client: ClientKey {
            htype: 1,
            chaddr: tenko_core::serde_util::HexBytes(mac(client).octets().to_vec()),
            client_id: None,
        },
        state: BindingState::Active,
        cltt: time("08:10:00"),
        ends: time("09:00:00"),
        tstp: None,
        tsfp: None,
        atsfp: None,
        node: NodeId(1),
        share: None,
        hostname: Some("printer".to_owned()),
        fqdn: None,
        fqdn_flags: None,
        ddns_policy: None,
        ddns: DdnsState::default(),
        fingerprint: None,
        relay: None,
        observed_at: None,
        granted: Some(time("08:00:00")),
    }
}

#[tokio::test]
async fn the_fact_list_presents_the_lease_rows_and_reads_no_stored_lease_fact() {
    use tenko_core::dhcp::tables::LEASES;
    use tenko_ipam::observe::{ObservedFact, dhcp::LeaseFacts, model::FactSubject, tables::FACTS};

    let store = mem();
    let vrf = VrfId::generate();
    let lease = lease_row("192.0.2.40", 0x40, vrf);
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), time("08:10:00"));
    batch
        .put_typed(&LEASES, &(vrf, lease.addr), &lease)
        .expect("lease");
    // A fact row of the lease source, as an older version wrote them: it is never read.
    let stale = ObservedFact {
        source: ObservationSource::DhcpLease { node: NodeId(1) },
        source_key: "dhcp:1".to_owned(),
        subject: FactSubject::Address {
            vrf,
            ip: ip("192.0.2.41"),
        },
        subject_key: format!("address:{vrf}/192.0.2.41"),
        observed: Observed::Address {
            vrf,
            ip: ip("192.0.2.41"),
            mac: Some(mac(0x41)),
        },
        observation: ObservationId::generate(),
        first_seen: time("08:00:00"),
        last_seen: time("08:10:00"),
        received_at: time("08:10:00"),
        expires_at: Some(time("09:00:00")),
        sightings: 1,
        counted_at: Some(time("08:00:00")),
        revision: tenko_core::Revision::ZERO,
    };
    batch
        .put_typed(
            &FACTS,
            &(stale.source_key.clone(), stale.subject_key.clone()),
            &stale,
        )
        .expect("stale fact");
    store.propose(batch).await.expect("commit");

    let leases = LeaseFacts::new(ObserveConfig::default());
    let view = read(&store).await;
    leases.ensure(view.as_ref()).expect("lease view");
    let query = FactQuery {
        source: Some("dhcp:1".to_owned()),
        sort: vec!["subject".to_owned()],
        ..FactQuery::default()
    };
    let page =
        list_facts(view.as_ref(), Some(&leases), &query, time("08:30:00")).expect("with leases");
    let keys: Vec<&str> = page
        .items
        .iter()
        .map(|fact| fact.subject_key.as_str())
        .collect();
    assert_eq!(
        keys,
        [
            format!("address:{vrf}/192.0.2.40").as_str(),
            "name:192.0.2.40"
        ],
        "the lease row gives its address and name facts; the stored row is not read"
    );
    let address = &page.items[0];
    assert_eq!(address.source_key, "dhcp:1");
    assert_eq!(address.first_seen, time("08:00:00"), "the grant time");
    assert_eq!(address.last_seen, time("08:10:00"), "the last transaction");
    assert_eq!(address.expires_at, Some(time("09:00:00")), "the end");
    assert_eq!(
        address.observed,
        Observed::Address {
            vrf,
            ip: ip("192.0.2.40"),
            mac: Some(mac(0x40)),
        }
    );
    // The id is derived from the row, so a second view of the same row names it alike.
    let again = LeaseFacts::new(ObserveConfig::default());
    again.ensure(view.as_ref()).expect("second view");
    let second =
        list_facts(view.as_ref(), Some(&again), &query, time("08:30:00")).expect("second page");
    assert_eq!(second.items[0].observation, address.observation);

    // Without the lease view the list holds the stored facts of other sources only.
    let none = list_facts(view.as_ref(), None, &query, time("08:30:00")).expect("without");
    assert_empty(&none.items);

    // After its end the binding's facts are expired, not gone.
    let current = FactQuery {
        current: Some(true),
        ..query.clone()
    };
    let late = list_facts(view.as_ref(), Some(&leases), &current, time("09:30:00")).expect("late");
    assert_empty(&late.items);
}
