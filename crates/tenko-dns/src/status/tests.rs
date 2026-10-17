//! Tests of the local node: the report and the commands.

use std::net::{Ipv4Addr, SocketAddr};

use super::*;
use crate::{
    catalog::{Catalog, CatalogHandle},
    querylog::{LogSettings, LogWriter},
    server::{Hooks, ServerConfig},
    transport::udp::UdpSettings,
};

async fn server() -> Server {
    let config = ServerConfig {
        listen: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 0))],
        udp: UdpSettings {
            workers: 2,
            ..UdpSettings::default()
        },
        ..ServerConfig::default()
    };
    Server::start_authoritative(
        config,
        CatalogHandle::new(Catalog::default()),
        Hooks::default(),
    )
    .await
    .expect("server")
}

#[tokio::test]
async fn the_report_names_the_listeners_and_stops_serving_after_the_stop() {
    let node = LocalNode::new(
        NodeId(1),
        server().await,
        FeedProgress::default(),
        None,
        None,
    );
    let status = node.status();
    assert!(status.serving);
    assert_eq!(status.node, NodeId(1));
    assert_eq!(
        (status.zones, status.rrsets, status.cache_entries),
        (0, 0, 0)
    );
    let udp: Vec<&Listener> = status
        .listeners
        .iter()
        .filter(|listener| listener.transport == QueryTransport::Udp)
        .collect();
    assert_eq!(udp.len(), 1);
    assert_eq!(udp[0].workers, 2);
    assert_ne!(udp[0].address.port(), 0);
    assert!(
        status
            .listeners
            .iter()
            .any(|listener| listener.transport == QueryTransport::Tcp)
    );
    node.take_server().expect("the server").stop().await;
    let stopped = node.status();
    assert!(!stopped.serving);
    assert_eq!(stopped.listeners, []);
}

#[tokio::test]
async fn the_commands_answer_in_place() {
    let node = LocalNode::new(
        NodeId(1),
        server().await,
        FeedProgress::default(),
        None,
        None,
    );
    let flush = node.execute(CACHE_FLUSH, &[]);
    assert_eq!(flush.outcome, Outcome::Done);
    assert!(flush.detail.contains("no cache"), "{}", flush.detail);
    let stats = node.execute(STATS, &[]);
    assert_eq!(stats.outcome, Outcome::Done);
    assert!(stats.detail.contains("2 UDP worker(s)"), "{}", stats.detail);
    assert!(matches!(
        stats.output,
        Output::Stats(DnsStats {
            layout: Some(_),
            ..
        })
    ));
    let log = node.execute(LOG_READ, &[]);
    assert_eq!(log.outcome, Outcome::Rejected);
    assert!(log.detail.contains("off"), "{}", log.detail);
    let unknown = node.execute("scan.run", &[]);
    assert_eq!(unknown.outcome, Outcome::Rejected);
    node.take_server().expect("the server").stop().await;
}

#[tokio::test]
async fn the_log_is_read_through_the_command() {
    let dir = std::env::temp_dir().join(format!("tenko-status-{}", uuid::Uuid::now_v7()));
    let writer = LogWriter::start(LogSettings {
        dir: dir.clone(),
        days: 1,
        size_mb: 16,
        sample: 1,
        pseudonymise: false,
    })
    .expect("log");
    let qname = tenko_core::dns::DnsName::new("www.example.test")
        .expect("name")
        .to_wire();
    writer.sink().record(&crate::log::QueryLogEntry {
        at_micros: 1_792_000_000_000_000,
        client: Ipv4Addr::LOCALHOST.into(),
        transport: QueryTransport::Tcp,
        qname: &qname,
        qtype: 28,
        rcode: 3,
        view: None,
        blocked: None,
        cached: false,
        duration_micros: 9,
    });
    let sink = writer.sink();
    writer.stop();
    let node = LocalNode::new(
        NodeId(1),
        server().await,
        FeedProgress::default(),
        None,
        Some((sink, dir.clone())),
    );
    let args = tenko_core::codec::to_cbor(&LogReadArgs {
        cursor: None,
        limit: 10,
        qname: None,
    })
    .expect("args");
    let read = node.execute(LOG_READ, &args);
    assert_eq!(read.outcome, Outcome::Done, "{}", read.detail);
    let Output::Log(page) = read.output else {
        panic!("a page");
    };
    assert_eq!(page.lines.len(), 1);
    assert_eq!(page.lines[0].qname, "www.example.test");
    assert_eq!(page.lines[0].rcode, 3);
    assert_eq!(page.lines[0].transport, QueryTransport::Tcp);
    let bad = node.execute(LOG_READ, b"not cbor");
    assert_eq!(bad.outcome, Outcome::Rejected);
    node.take_server().expect("the server").stop().await;
    let _ = std::fs::remove_dir_all(dir);
}
