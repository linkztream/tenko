//! The methods that talk to the network, against listeners on loopback that answer with
//! recorded messages: `tcp_connect` with its TLS hint, `reverse_dns`, `mdns` and `llmnr`.
//! Nothing here leaves the host.

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use tenko_cluster::probe::SightingSubject;
use tenko_scan::{
    config::TcpTargets,
    limit::{PaceLimits, Pacer},
    method::{Cancel, Method, RunContext},
    methods::{names::NameQuery, rdns::ReverseDns, tcp::TcpConnect},
    scope::Scope,
    sys::RecordedSystem,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "fixtures", "dns", name]
        .iter()
        .collect();
    let text = std::fs::read_to_string(&path).expect("fixture");
    text.lines()
        .flat_map(|line| line.split('#').next().unwrap_or("").split_whitespace())
        .map(|token| u8::from_str_radix(token, 16).expect("hex"))
        .collect()
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("ip")
}

fn context(prefixes: &[&str], known: &[&str]) -> RunContext {
    let prefixes: Vec<String> = prefixes.iter().map(|p| (*p).to_owned()).collect();
    RunContext {
        scope: Arc::new(Scope::parse(&prefixes, &[], 256).expect("scope")),
        narrowed: false,
        known: known.iter().map(|text| ip(text)).collect(),
        pacer: Arc::new(Pacer::new(PaceLimits {
            per_second: None,
            per_host_interval: Duration::ZERO,
            concurrency: 8,
        })),
        cancel: Cancel::never(),
    }
}

/// A TCP listener that answers every connection with `answer` and closes.
async fn listener(answer: &'static [u8]) -> u16 {
    let socket = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = socket.local_addr().expect("addr").port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = socket.accept().await {
            tokio::spawn(async move {
                let mut hello = [0u8; 512];
                let _ =
                    tokio::time::timeout(Duration::from_millis(200), stream.read(&mut hello)).await;
                let _ = stream.write_all(answer).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test]
async fn tcp_connect_reports_open_ports_and_which_speak_tls() {
    // A recorded ServerHello head and an SSH banner.
    let tls = listener(&[0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x56]).await;
    let plain = listener(b"SSH-2.0-Example\r\n").await;
    let closed = {
        let socket = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        socket.local_addr().expect("addr").port()
    };
    let method = TcpConnect::new(
        vec![tls, plain, closed],
        Duration::from_millis(800),
        true,
        TcpTargets::Known,
    );
    let output = method
        .run(&context(&["127.0.0.1/32"], &["127.0.0.1"]))
        .await
        .expect("run");
    assert!(output.covered_all);
    assert_eq!(output.probes, 3);
    let mut open = vec![tls, plain];
    open.sort_unstable();
    assert_eq!(
        output
            .found
            .iter()
            .map(|f| f.subject.clone())
            .collect::<Vec<_>>(),
        [SightingSubject::Services {
            ip: ip("127.0.0.1"),
            open_tcp: open,
            tls_tcp: vec![tls],
        }]
    );
}

#[tokio::test]
async fn tcp_connect_never_leaves_the_scope() {
    let port = listener(b"").await;
    let method = TcpConnect::new(
        vec![port],
        Duration::from_millis(300),
        false,
        TcpTargets::Known,
    );
    let output = method
        .run(&context(&["192.0.2.0/24"], &["127.0.0.1"]))
        .await
        .expect("run");
    assert_eq!(output.probes, 0, "127.0.0.1 is known but outside the scope");
    assert_eq!(output.found, Vec::new());
}

/// A UDP responder: for every datagram, `answer` builds the reply from the query.
async fn responder(answer: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let address = socket.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 9000];
        while let Ok((len, from)) = socket.recv_from(&mut buffer).await {
            if let Some(reply) = answer(&buffer[..len]) {
                let _ = socket.send_to(&reply, from).await;
            }
        }
    });
    address
}

/// The recorded answer with the id of the query.
fn with_id(mut answer: Vec<u8>, query: &[u8]) -> Vec<u8> {
    answer[..2].copy_from_slice(&query[..2]);
    answer
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test]
async fn reverse_dns_names_the_known_addresses() {
    let server = responder(|query| Some(with_id(fixture("dns_reverse_resolver.hex"), query))).await;
    let method = ReverseDns::new(
        vec![server],
        Duration::from_millis(800),
        Arc::new(RecordedSystem::new()),
    );
    let output = method
        .run(&context(
            &["198.51.100.0/24"],
            &["198.51.100.7", "198.51.100.8", "192.0.2.9"],
        ))
        .await
        .expect("run");
    assert!(output.covered_all, "{:?}", output.notes);
    assert_eq!(output.probes, 2, "192.0.2.9 is outside the scope");
    assert_eq!(
        output
            .found
            .iter()
            .map(|f| f.subject.clone())
            .collect::<Vec<_>>(),
        [SightingSubject::Name {
            ip: ip("198.51.100.7"),
            name: "gw.example.net".to_owned(),
        }],
        "198.51.100.8 has no PTR record in the answer"
    );
}

#[tokio::test]
async fn reverse_dns_without_answers_is_partial() {
    let silent = responder(|_| None).await;
    let method = ReverseDns::new(
        vec![silent],
        Duration::from_millis(100),
        Arc::new(RecordedSystem::new()),
    );
    let output = method
        .run(&context(&["198.51.100.0/24"], &["198.51.100.7"]))
        .await
        .expect("run");
    assert!(!output.covered_all);
    assert_eq!(output.found, Vec::new());
    assert!(output.notes[0].contains("no answer"), "{:?}", output.notes);
}

#[tokio::test]
async fn reverse_dns_reads_the_system_resolvers() {
    let system = RecordedSystem::new().file("/etc/resolv.conf", "").command(
        "powershell.exe -NoProfile -NonInteractive -Command (Get-DnsClientServerAddress \
             -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses }).ServerAddresses",
        0,
        "",
    );
    let method = ReverseDns::new(Vec::new(), Duration::from_millis(100), Arc::new(system));
    let error = method
        .run(&context(&["198.51.100.0/24"], &["198.51.100.7"]))
        .await
        .expect_err("no resolver");
    assert_eq!(error.code(), "scan.unavailable");
}

#[tokio::test]
async fn mdns_browses_asks_each_service_type_and_reports_the_printer() {
    let responder = responder(|query| {
        if contains(query, b"\x09_services\x07_dns-sd") {
            Some(fixture("mdns_services_browse.hex"))
        } else if contains(query, b"\x04_ipp\x04_tcp") {
            Some(fixture("mdns_printer.hex"))
        } else if contains(query, b"in-addr") {
            Some(with_id(fixture("mdns_reverse_ptr.hex"), query))
        } else {
            None
        }
    })
    .await;
    let method = NameQuery::mdns(
        responder,
        responder.port(),
        Duration::from_millis(600),
        false,
    );
    let output = method
        .run(&context(&["192.0.2.0/24", "127.0.0.1/32"], &["127.0.0.1"]))
        .await
        .expect("run");
    assert!(output.covered_all);
    let subjects: Vec<SightingSubject> = output.found.iter().map(|f| f.subject.clone()).collect();
    let printer = ip("192.0.2.40");
    assert!(subjects.contains(&SightingSubject::Address {
        ip: printer,
        mac: None
    }));
    assert!(subjects.contains(&SightingSubject::Name {
        ip: printer,
        name: "printer.local".to_owned()
    }));
    assert!(subjects.contains(&SightingSubject::Services {
        ip: printer,
        open_tcp: vec![631],
        tls_tcp: Vec::new()
    }));
    // The browse, three service types, one reverse query.
    assert_eq!(output.probes, 5);
}

#[tokio::test]
async fn llmnr_asks_the_known_addresses_for_their_names() {
    let responder = responder(|query| Some(with_id(fixture("llmnr_a.hex"), query))).await;
    let method = NameQuery::llmnr(responder.port(), Duration::from_millis(400));
    let output = method
        .run(&context(&["192.0.2.0/24", "127.0.0.1/32"], &["127.0.0.1"]))
        .await
        .expect("run");
    assert!(output.covered_all);
    let subjects: Vec<SightingSubject> = output.found.iter().map(|f| f.subject.clone()).collect();
    assert!(subjects.contains(&SightingSubject::Name {
        ip: ip("192.0.2.50"),
        name: "fileserver".to_owned()
    }));
    assert!(subjects.contains(&SightingSubject::Address {
        ip: ip("192.0.2.50"),
        mac: None
    }));
    assert_eq!(output.probes, 1);
}
