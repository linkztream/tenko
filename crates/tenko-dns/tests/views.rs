//! Views, scopes and weights (DNS-20, WP6.4) through the catalog, the responder and the
//! forwarder, without the API: what the view table compiled from `dns.views` rows does to
//! the answers.
//!
//! - Two views with `ClientSubnet` rules on one zone with two scopes answer each client
//!   from its view's scope; a client no view matches gets the default scope (the implicit
//!   default view); the first view in order wins.
//! - The `Transport`, `Interface`, `Qtype`, `Qname` and `TimeOfDay` rules select.
//! - A weighted scope pair (700 and 300) splits clients within 5 percentage points of the
//!   configured share, and each client keeps its scope (the choice is a hash of the client
//!   address, so one client sees one answer set).
//! - A cached answer of one view never reaches a client of another: the cache key carries
//!   the view.
//! - The catalog follows view rows through the feed's deltas: a new view, a new order and a
//!   deleted view take effect on the next query.

mod support;

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use support::{
    a,
    answer::{Answer, decode, query},
    name, ns, rrset, rrset_ttl, soa, zone,
};
use tenko_core::{
    Revision,
    dns::{
        MatchRule, QueryTransport, RecordData, Rtype, ScopeName, ScopeWeight, View, ViewId, Zone,
        ZoneScope,
    },
};
use tenko_dns::{
    DnsData, DomainCodec, Request,
    authoritative::Authoritative,
    catalog::{Catalog, CatalogHandle, ViewQuery},
    codec::Codec,
    cookie::CookieSecret,
    feed::{Change, Delta},
    forward::{ForwardSettings, Forwarder, RecursionDefault, RecursionPolicy},
    pool::UpstreamSpec,
    respond::{
        Clock, Conn, ForwardQuery, ForwardSink, Intake, IntakeQuery, Reply, ReplyPath, Responder,
        Scratch,
    },
    wire,
};
use tokio_util::sync::CancellationToken;

const A: u16 = 1;
const AAAA: u16 = 28;

fn scope(text: &str) -> ScopeName {
    ScopeName::new(text).expect("scope")
}

/// `example.test` with three scopes: `www` is 192.0.2.1 in the default scope, 192.0.2.10
/// in `inside` and 192.0.2.20 in `outside`.
fn split_zone() -> (Zone, DnsData) {
    let mut zone = zone("example.test");
    zone.scopes = vec![
        ZoneScope::default_scope(),
        ZoneScope {
            name: scope("inside"),
            description: None,
        },
        ZoneScope {
            name: scope("outside"),
            description: None,
        },
    ];
    let mut image = DnsData::at(Revision(2));
    for (scope_name, last) in [
        (ScopeName::DEFAULT, 1),
        (scope("inside"), 10),
        (scope("outside"), 20),
    ] {
        for rrset in [
            rrset_ttl(
                &zone,
                &scope_name,
                "example.test",
                3600,
                &[soa("example.test", 60)],
            ),
            rrset(
                &zone,
                &scope_name,
                "example.test",
                &[ns("ns1.example.test")],
            ),
            rrset(&zone, &scope_name, "ns1.example.test", &[a(53)]),
            rrset(&zone, &scope_name, "www.example.test", &[a(last)]),
            rrset(
                &zone,
                &scope_name,
                "www.example.test",
                &[RecordData::Aaaa {
                    address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, u16::from(last)),
                }],
            ),
        ] {
            image.rrsets.insert(rrset.key(), rrset);
        }
    }
    image.zones.insert(zone.id, zone.clone());
    (zone, image)
}

fn view(name: &str, order: u32, rules: Vec<MatchRule>, scope_map: Vec<ScopeWeight>) -> View {
    View {
        id: ViewId::generate(),
        name: name.to_owned(),
        rules,
        scope_map,
        order,
        recursion: None,
        resolution: None,
        description: None,
    }
}

fn weight(zone: &Zone, scope_name: &str, weight: u16) -> ScopeWeight {
    ScopeWeight {
        zone: zone.id,
        scope: scope(scope_name),
        weight,
    }
}

fn subnet(prefixes: &[&str]) -> MatchRule {
    MatchRule::ClientSubnet {
        prefixes: prefixes
            .iter()
            .map(|prefix| prefix.parse().expect("prefix"))
            .collect(),
    }
}

fn with_views(image: &DnsData, views: &[View]) -> DnsData {
    let mut image = image.clone();
    for view in views {
        image.views.insert(view.id, view.clone());
    }
    image
}

/// A responder over a catalog, asked from any client, local address and transport.
struct Engine {
    responder: Responder<Authoritative>,
    scratch: Scratch,
    clock: Clock,
}

impl Engine {
    fn new(image: &DnsData) -> Self {
        let catalog = CatalogHandle::new(Catalog::build(image));
        Self {
            responder: Responder::new(
                Authoritative::new(catalog),
                CookieSecret::with_secret([3; 16]),
            )
            .with_metrics(false),
            scratch: Scratch::new(),
            clock: Clock::now(),
        }
    }

    fn ask_on(
        &mut self,
        qname: &str,
        qtype: u16,
        client: &str,
        local: &str,
        transport: QueryTransport,
    ) -> Answer {
        let conn = Conn {
            client: SocketAddr::new(client.parse().expect("client"), 40000),
            local: SocketAddr::new(local.parse().expect("local"), 53),
            transport,
        };
        let bytes = query(qname, qtype).bytes(0x4242);
        let reply = self.responder.respond(
            &bytes,
            &conn,
            &self.clock,
            Instant::now(),
            &mut self.scratch,
        );
        assert_eq!(reply, Reply::Send, "{qname} from {client}");
        decode(&self.scratch.out)
    }

    /// The last octet of the one A record (or the last group of the one AAAA record) of
    /// `www.example.test` for `client`.
    fn www(&mut self, client: &str) -> u8 {
        self.www_on(client, "192.0.2.53", QueryTransport::Udp, A)
    }

    fn www_on(&mut self, client: &str, local: &str, transport: QueryTransport, qtype: u16) -> u8 {
        let answer = self.ask_on("www.example.test", qtype, client, local, transport);
        assert_eq!(answer.answers.len(), 1, "{client}: {answer:?}");
        *answer.answers[0].rdata.last().expect("rdata")
    }
}

#[test]
fn client_subnet_views_on_one_zone_answer_from_their_scopes() {
    let (zone, image) = split_zone();
    let inside = view(
        "inside",
        1,
        vec![subnet(&["192.0.2.0/24", "2001:db8:1::/48"])],
        vec![weight(&zone, "inside", 1)],
    );
    let outside = view(
        "outside",
        2,
        vec![subnet(&["0.0.0.0/0", "::/0"])],
        vec![weight(&zone, "outside", 1)],
    );
    // No view: every client is in the implicit default view.
    let mut plain = Engine::new(&image);
    assert_eq!(plain.www("192.0.2.7"), 1);
    assert_eq!(plain.www("203.0.113.7"), 1);

    let mut engine = Engine::new(&with_views(&image, &[inside.clone(), outside.clone()]));
    assert_eq!(engine.www("192.0.2.7"), 10, "inside");
    assert_eq!(
        engine.www("::ffff:192.0.2.7"),
        10,
        "a mapped address is its IPv4 address"
    );
    assert_eq!(engine.www("2001:db8:1::7"), 10, "inside over IPv6");
    assert_eq!(engine.www("203.0.113.7"), 20, "outside");
    assert_eq!(engine.www("2001:db8:2::7"), 20, "outside over IPv6");

    // The first match wins: with `outside` first, it takes every client.
    let mut first = outside.clone();
    first.order = 0;
    let mut engine = Engine::new(&with_views(&image, &[inside.clone(), first]));
    assert_eq!(engine.www("192.0.2.7"), 20);

    // A view that does not map the zone sees its default scope.
    let unmapped = view(
        "unmapped",
        1,
        vec![subnet(&["198.51.100.0/24"])],
        Vec::new(),
    );
    let mut engine = Engine::new(&with_views(&image, &[unmapped, outside]));
    assert_eq!(engine.www("198.51.100.7"), 1);
    assert_eq!(engine.www("203.0.113.7"), 20);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one scenario per test kind, read top to bottom"
)]
fn the_transport_interface_qtype_qname_and_time_rules_select() {
    let (zone, image) = split_zone();
    let dot = view(
        "dot",
        1,
        vec![MatchRule::Transport {
            transports: vec![QueryTransport::Dot, QueryTransport::Doh],
        }],
        vec![weight(&zone, "inside", 1)],
    );
    let interface = view(
        "second address",
        2,
        vec![MatchRule::Interface {
            addresses: vec!["192.0.2.54".parse().expect("address")],
        }],
        vec![weight(&zone, "outside", 1)],
    );
    let mut engine = Engine::new(&with_views(&image, &[dot, interface]));
    let client = "203.0.113.7";
    assert_eq!(
        engine.www_on(client, "192.0.2.53", QueryTransport::Udp, A),
        1
    );
    assert_eq!(
        engine.www_on(client, "192.0.2.53", QueryTransport::Tcp, A),
        1
    );
    assert_eq!(
        engine.www_on(client, "192.0.2.53", QueryTransport::Dot, A),
        10
    );
    assert_eq!(
        engine.www_on(client, "192.0.2.53", QueryTransport::Doh, A),
        10
    );
    assert_eq!(
        engine.www_on(client, "192.0.2.54", QueryTransport::Udp, A),
        20
    );
    assert_eq!(
        engine.www_on(client, "192.0.2.54", QueryTransport::Dot, A),
        10,
        "the first view in order"
    );

    // All rules of a view must hold: AAAA from 198.51.100.0/24 only.
    let both = view(
        "aaaa from the lab",
        1,
        vec![
            subnet(&["198.51.100.0/24"]),
            MatchRule::Qtype {
                types: vec![Rtype::AAAA],
            },
        ],
        vec![weight(&zone, "inside", 1)],
    );
    let mut engine = Engine::new(&with_views(&image, &[both]));
    assert_eq!(
        engine.www_on("198.51.100.7", "192.0.2.53", QueryTransport::Udp, AAAA),
        10
    );
    assert_eq!(
        engine.www_on("198.51.100.7", "192.0.2.53", QueryTransport::Udp, A),
        1
    );
    assert_eq!(
        engine.www_on("203.0.113.7", "192.0.2.53", QueryTransport::Udp, AAAA),
        1
    );

    // The name and the time of day through the view table itself.
    let qname = view(
        "names",
        1,
        vec![MatchRule::Qname {
            suffixes: vec![name("www.example.test")],
        }],
        Vec::new(),
    );
    let night = view(
        "night",
        2,
        vec![MatchRule::TimeOfDay {
            from_minute: 22 * 60,
            to_minute: 6 * 60,
        }],
        Vec::new(),
    );
    let catalog = Catalog::build(&with_views(&image, &[qname.clone(), night.clone()]));
    let select = |name_text: &str, minute: u16| {
        let wire_name = support::wire(name_text);
        catalog
            .views()
            .select(&ViewQuery {
                client: "203.0.113.7".parse().expect("client"),
                local: "192.0.2.53".parse().expect("local"),
                transport: QueryTransport::Udp,
                qtype: Rtype::A,
                minute_of_day: minute,
                qname: &wire_name,
            })
            .map(tenko_dns::catalog::CompiledView::id)
    };
    assert_eq!(select("www.example.test", 12 * 60), Some(qname.id));
    assert_eq!(
        select("a.www.example.test", 12 * 60),
        Some(qname.id),
        "below the suffix"
    );
    assert_eq!(select("mail.example.test", 12 * 60), None);
    assert_eq!(
        select("mail.example.test", 23 * 60),
        Some(night.id),
        "wraps midnight"
    );
    assert_eq!(select("mail.example.test", 5 * 60), Some(night.id));
    assert_eq!(select("mail.example.test", 6 * 60 + 1), None);
}

/// The share of `clients` that get `inside` (192.0.2.10 for `www`), and checks that each
/// client gets the same scope when it asks again.
fn inside_share(engine: &mut Engine, clients: &[String]) -> f64 {
    let mut inside = 0usize;
    for client in clients {
        let first = engine.www(client);
        assert!(first == 10 || first == 20, "{client}: {first}");
        assert_eq!(engine.www(client), first, "{client} keeps its scope");
        if first == 10 {
            inside += 1;
        }
    }
    #[allow(clippy::cast_precision_loss, reason = "test counts")]
    let share = inside as f64 / clients.len() as f64;
    share
}

#[test]
fn a_weighted_scope_pair_splits_clients_as_configured_and_each_client_keeps_its_scope() {
    let (zone, image) = split_zone();
    let weighted = view(
        "weighted",
        1,
        Vec::new(),
        vec![weight(&zone, "inside", 700), weight(&zone, "outside", 300)],
    );
    let data = with_views(&image, &[weighted]);
    let mut engine = Engine::new(&data);
    // 10,000 IPv6 clients of the documentation prefix and the 762 IPv4 addresses of the
    // three documentation ranges.
    let v6: Vec<String> = (1..=10_000u32)
        .map(|n| {
            let address = Ipv6Addr::new(
                0x2001,
                0xdb8,
                u16::try_from(n >> 8).expect("fits"),
                0,
                0,
                0,
                0,
                u16::try_from(n & 0xff).expect("fits") + 1,
            );
            address.to_string()
        })
        .collect();
    let v4: Vec<String> = [[192, 0, 2], [198, 51, 100], [203, 0, 113]]
        .iter()
        .flat_map(|net| {
            (1..=254u8).map(move |host| Ipv4Addr::new(net[0], net[1], net[2], host).to_string())
        })
        .collect();
    let share_v6 = inside_share(&mut engine, &v6);
    let share_v4 = inside_share(&mut engine, &v4);
    eprintln!(
        "weighted 700/300: inside share {share_v6:.4} of 10000 IPv6 clients, {share_v4:.4} of 762 IPv4 clients"
    );
    assert!((share_v6 - 0.7).abs() <= 0.05, "IPv6 share {share_v6}");
    assert!((share_v4 - 0.7).abs() <= 0.05, "IPv4 share {share_v4}");

    // A new catalog of the same rows (another node, a restart) keeps every client's scope.
    let mut again = Engine::new(&data);
    for client in v6.iter().step_by(97).chain(v4.iter().step_by(13)) {
        assert_eq!(again.www(client), engine.www(client), "{client}");
    }

    // Three scopes: 500, 300, 200 (the default scope named in the map).
    let three = view(
        "three",
        1,
        Vec::new(),
        vec![
            ScopeWeight {
                zone: zone.id,
                scope: ScopeName::DEFAULT,
                weight: 200,
            },
            weight(&zone, "inside", 500),
            weight(&zone, "outside", 300),
        ],
    );
    let mut engine = Engine::new(&with_views(&image, &[three]));
    let mut counts = [0usize; 3];
    for client in &v6 {
        match engine.www(client) {
            1 => counts[0] += 1,
            10 => counts[1] += 1,
            20 => counts[2] += 1,
            other => panic!("{client}: {other}"),
        }
    }
    eprintln!("weighted 200/500/300: {counts:?} of 10000");
    for (count, expected) in counts.iter().zip([0.2, 0.5, 0.3]) {
        #[allow(clippy::cast_precision_loss, reason = "test counts")]
        let share = *count as f64 / 10_000.0;
        assert!((share - expected).abs() <= 0.05, "{counts:?}");
    }
}

/// An upstream in the test that answers every A query with 203.0.113.N, N counting up from
/// 1 with each query it answers, so a second upstream answer differs from the first.
fn counting_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind the upstream");
    let address = socket.local_addr().expect("address");
    let seen = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&seen);
    let next = AtomicU8::new(1);
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((len, from)) = socket.recv_from(&mut buf) {
            let query = &buf[..len];
            let Some(end) = wire::questions_end(query, 1) else {
                continue;
            };
            count.fetch_add(1, Ordering::Relaxed);
            let mut answer = Vec::with_capacity(end + 16);
            answer.extend_from_slice(&query[..2]);
            answer.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
            answer.extend_from_slice(&query[wire::HEADER_LEN..end]);
            answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            answer.extend_from_slice(&[203, 0, 113, next.fetch_add(1, Ordering::Relaxed)]);
            let _ = socket.send_to(&answer, from);
        }
    });
    (address, seen)
}

fn forward_query(id: u16) -> Vec<u8> {
    let mut out = Vec::new();
    wire::write_query(&mut out, id, "www.example.net", A, Some(1232));
    out[2] |= 0x01;
    out
}

/// What the forwarder answers on the query path for a client of `view`: the cache's answer,
/// or `None` when it would forward.
fn from_cache(forwarder: &Forwarder, view: Option<ViewId>) -> Option<Vec<u8>> {
    let message = forward_query(7);
    let mut request = Request::default();
    DomainCodec::new()
        .parse(&message, &mut request)
        .expect("parses");
    let mut out = Vec::with_capacity(65_535);
    let intake = forwarder.intake(
        &IntakeQuery {
            message: &message,
            request: &request,
            client: "127.0.0.1:40000".parse().expect("client"),
            transport: QueryTransport::Udp,
            view,
            rule: None,
            max_len: 1232,
            udp_size: wire::SERVER_UDP_PAYLOAD,
            cookie: None,
            now: Instant::now(),
        },
        &mut out,
    );
    match intake {
        Intake::Answered { .. } | Intake::Synthesised { .. } => Some(out),
        Intake::Forward => None,
        Intake::Refuse { ede } => panic!("refused with {ede}"),
    }
}

/// Forwards one query for a client of `view` and waits for the answer.
async fn forwarded(forwarder: &Arc<Forwarder>, view: Option<ViewId>) -> Vec<u8> {
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind a client");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    forwarder.submit(ForwardQuery {
        message: forward_query(9),
        client: client.local_addr().expect("address"),
        transport: QueryTransport::Udp,
        view,
        rule: None,
        cookie: None,
        reply: ReplyPath::Udp(Arc::new(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind the node"),
        )),
    });
    tokio::task::spawn_blocking(move || {
        let mut buf = vec![0u8; 65_535];
        let (len, _) = client.recv_from(&mut buf).expect("an answer");
        buf.truncate(len);
        buf
    })
    .await
    .expect("joins")
}

fn last_address_octet(answer: &[u8]) -> u8 {
    let end = wire::questions_end(answer, 1).expect("question");
    let record = wire::read_record(answer, end).expect("record");
    *answer[record.rdata..record.rdata + 4]
        .last()
        .expect("an address")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cached_answer_of_one_view_never_reaches_a_client_of_another() {
    let (upstream, asked) = counting_upstream();
    let (zone, image) = split_zone();
    let inside = view(
        "inside",
        1,
        vec![subnet(&["192.0.2.0/24"])],
        vec![weight(&zone, "inside", 1)],
    );
    let outside = view("outside", 2, Vec::new(), vec![weight(&zone, "outside", 1)]);
    let data = with_views(&image, &[inside.clone(), outside.clone()]);
    let stop = CancellationToken::new();
    let (forwarder, _task) = Forwarder::start(
        ForwardSettings {
            upstreams: vec![UpstreamSpec {
                address: upstream,
                transport: tenko_core::dns::ForwardTransport::Plain,
                tcp_only: false,
                tls_name: None,
                path: None,
            }],
            timeout: Duration::from_millis(500),
            metrics: false,
            ..ForwardSettings::default()
        },
        CatalogHandle::new(Catalog::build(&data)),
        None,
        Arc::new(RecursionPolicy::new(RecursionDefault::Anyone)),
        stop.clone(),
    );

    // The inside view asks first: the upstream answers .1 and the cache keeps it for that
    // view only.
    let first = forwarded(&forwarder, Some(inside.id)).await;
    assert_eq!(last_address_octet(&first), 1);
    let cached = from_cache(&forwarder, Some(inside.id)).expect("the inside view's cache");
    assert_eq!(last_address_octet(&cached), 1);
    assert!(
        from_cache(&forwarder, Some(outside.id)).is_none(),
        "no entry for outside"
    );
    assert!(
        from_cache(&forwarder, None).is_none(),
        "no entry for the default view"
    );
    assert_eq!(asked.load(Ordering::Relaxed), 1);

    // The outside view asks the upstream itself and gets its own answer and entry.
    let second = forwarded(&forwarder, Some(outside.id)).await;
    assert_eq!(last_address_octet(&second), 2);
    assert_eq!(asked.load(Ordering::Relaxed), 2);
    assert_eq!(
        last_address_octet(&from_cache(&forwarder, Some(outside.id)).expect("outside's entry")),
        2
    );
    assert_eq!(
        last_address_octet(&from_cache(&forwarder, Some(inside.id)).expect("inside's entry")),
        1,
        "each view keeps its own answer"
    );
    stop.cancel();
}

#[test]
fn the_catalog_follows_view_rows_through_the_feed() {
    let (zone, image) = split_zone();
    let catalog = Catalog::build(&image);
    let delta = |from: u64, changes: Vec<Change>| Delta {
        from: Revision(from),
        to: Revision(from + 1),
        changes,
    };
    let pick = |catalog: &Catalog, client: &str| {
        let wire_name = support::wire("www.example.test");
        catalog
            .views()
            .select(&ViewQuery {
                client: client.parse().expect("client"),
                local: "192.0.2.53".parse().expect("local"),
                transport: QueryTransport::Udp,
                qtype: Rtype::A,
                minute_of_day: 0,
                qname: &wire_name,
            })
            .map(tenko_dns::catalog::CompiledView::id)
    };
    assert!(catalog.views().is_empty());
    let inside = view(
        "inside",
        1,
        vec![subnet(&["192.0.2.0/24"])],
        vec![weight(&zone, "inside", 1)],
    );
    let all = view("all", 2, Vec::new(), vec![weight(&zone, "outside", 1)]);
    let next = catalog
        .apply(&delta(
            2,
            vec![
                Change::View(inside.id, Some(inside.clone())),
                Change::View(all.id, Some(all.clone())),
            ],
        ))
        .expect("delta");
    assert_eq!(next.views().len(), 2);
    assert_eq!(pick(&next, "192.0.2.7"), Some(inside.id));
    assert_eq!(pick(&next, "203.0.113.7"), Some(all.id));
    // A new order: `all` first takes every client.
    let mut moved = all.clone();
    moved.order = 1;
    let mut pushed = inside.clone();
    pushed.order = 2;
    let next = next
        .apply(&delta(
            3,
            vec![
                Change::View(all.id, Some(moved)),
                Change::View(inside.id, Some(pushed)),
            ],
        ))
        .expect("delta");
    assert_eq!(pick(&next, "192.0.2.7"), Some(all.id));
    // Deleted: the implicit default view again.
    let next = next
        .apply(&delta(
            4,
            vec![Change::View(all.id, None), Change::View(inside.id, None)],
        ))
        .expect("delta");
    assert!(next.views().is_empty());
    assert_eq!(pick(&next, "192.0.2.7"), None);
    assert!(next.view(inside.id).is_none());
}
