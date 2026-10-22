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

// cache-browse: the listing through the command.
#[tokio::test]
async fn the_cache_is_listed_through_the_command() {
    use crate::{
        cache::CacheKey,
        forward::{ForwardSettings, RecursionDefault, RecursionPolicy},
    };
    let bare = LocalNode::new(
        NodeId(1),
        server().await,
        FeedProgress::default(),
        None,
        None,
    );
    let empty = bare.execute(CACHE_LIST, &[]);
    assert_eq!(empty.outcome, Outcome::Done);
    assert!(empty.detail.contains("no cache"), "{}", empty.detail);
    assert_eq!(empty.output, Output::Cache(Box::default()));
    for args in [
        CacheListArgs {
            suffix: Some("not a name".to_owned()),
            ..CacheListArgs::default()
        },
        CacheListArgs {
            view: Some("lan".to_owned()),
            ..CacheListArgs::default()
        },
        CacheListArgs {
            cursor: Some("zz".to_owned()),
            ..CacheListArgs::default()
        },
    ] {
        let encoded = tenko_core::codec::to_cbor(&args).expect("cbor");
        let result = bare.execute(CACHE_LIST, &encoded);
        assert_eq!(result.outcome, Outcome::Rejected, "{args:?}");
    }
    bare.take_server().expect("the server").stop().await;

    let stop = tokio_util::sync::CancellationToken::new();
    let catalog = CatalogHandle::new(Catalog::default());
    let (forwarder, _task) = Forwarder::start(
        ForwardSettings {
            cache: Some(crate::cache::CacheSettings::default()),
            ..ForwardSettings::default()
        },
        catalog,
        None,
        Arc::new(RecursionPolicy::new(RecursionDefault::KnownPrefixes)),
        stop.clone(),
    );
    let cache = forwarder.cache().expect("a cache");
    let now = std::time::Instant::now();
    for name in ["www.example.test", "api.example.test", "www.example.net"] {
        let qname = DnsName::new(name).expect("name").to_wire();
        let mut answer = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        answer.extend_from_slice(&qname);
        answer.extend_from_slice(&[0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4]);
        answer.extend_from_slice(&[192, 0, 2, 1]);
        let key = CacheKey::new(None, &qname, 1, 1);
        assert!(cache.insert(&key, &answer, now, None));
    }
    let node = LocalNode::new(
        NodeId(1),
        server().await,
        FeedProgress::default(),
        Some(forwarder),
        None,
    );
    let args = CacheListArgs {
        suffix: Some("example.test".to_owned()),
        limit: 1,
        ..CacheListArgs::default()
    };
    let first = node.execute(
        CACHE_LIST,
        &tenko_core::codec::to_cbor(&args).expect("cbor"),
    );
    assert_eq!(first.outcome, Outcome::Done, "{}", first.detail);
    let Output::Cache(page) = first.output else {
        panic!("not a page: {:?}", first.output);
    };
    assert_eq!(page.entries[0].name.as_str(), "api.example.test");
    let next = CacheListArgs {
        cursor: page.next.map(|cursor| cursor.encode()),
        ..args
    };
    let second = node.execute(
        CACHE_LIST,
        &tenko_core::codec::to_cbor(&next).expect("cbor"),
    );
    let Output::Cache(page) = second.output else {
        panic!("not a page: {:?}", second.output);
    };
    assert_eq!(page.entries[0].name.as_str(), "www.example.test");
    assert!(page.next.is_none());
    stop.cancel();
    node.take_server().expect("the server").stop().await;
}
