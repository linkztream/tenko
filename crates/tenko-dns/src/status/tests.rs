//! Tests of the local node: the report and the commands.

use crate::log::QueryLogSink as _;
use std::net::{Ipv4Addr, SocketAddr};

use super::*;
use crate::{
    catalog::{Catalog, CatalogHandle},
    querylog::{ClientField, LogSettings, LogWriter},
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
        &stats.output,
        Output::Stats(stats) if matches!(**stats, DnsStats { layout: Some(_), .. })
    ));
    let log = node.execute(LOG_READ, &[]);
    assert_eq!(log.outcome, Outcome::Rejected);
    assert!(log.detail.contains("off"), "{}", log.detail);
    assert_eq!(node.execute(LOG_STOP, &[]).outcome, Outcome::Rejected);
    let unknown = node.execute("scan.run", &[]);
    assert_eq!(unknown.outcome, Outcome::Rejected);
    node.take_server().expect("the server").stop().await;
}

#[tokio::test]
async fn the_log_is_read_through_the_command() {
    let dir = std::env::temp_dir().join(format!("tenko-status-{}", uuid::Uuid::now_v7()));
    let writer = LogWriter::start(LogSettings {
        days: 1,
        size_mb: 16,
        client: ClientField::Address,
        ..LogSettings::new(dir.clone())
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
        ..LogReadArgs::default()
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
    assert_eq!(page.lines[0].client.as_deref(), Some("127.0.0.1"));
    let bad = node.execute(LOG_READ, b"not cbor");
    assert_eq!(bad.outcome, Outcome::Rejected);
    let filtered = |args: LogReadArgs| {
        node.execute(LOG_READ, &tenko_core::codec::to_cbor(&args).expect("args"))
    };
    let unknown_client = filtered(LogReadArgs {
        limit: 10,
        client: Some("somebody".to_owned()),
        ..LogReadArgs::default()
    });
    assert_eq!(unknown_client.outcome, Outcome::Rejected);
    assert!(
        unknown_client.detail.contains("client"),
        "{}",
        unknown_client.detail
    );
    let Output::Log(other) = filtered(LogReadArgs {
        limit: 10,
        rcode: Some(0),
        ..LogReadArgs::default()
    })
    .output
    else {
        panic!("a page");
    };
    assert_eq!(other.lines, Vec::new());

    let stop = node.execute(LOG_STOP, &[]);
    assert_eq!(stop.outcome, Outcome::Done, "{}", stop.detail);
    assert!(dir.join(crate::querylog::STOPPED_MARKER).exists());
    let stats = node.execute(STATS, &[]);
    assert!(
        stats.detail.contains("query log (stopped)"),
        "{}",
        stats.detail
    );
    assert!(node.status().log.expect("log figures").stopped);
    let start = node.execute(LOG_START, &[]);
    assert_eq!(start.outcome, Outcome::Done, "{}", start.detail);
    assert!(!node.status().log.expect("log figures").stopped);
    node.take_server().expect("the server").stop().await;
    let _ = std::fs::remove_dir_all(dir);
}
