//! The server on real sockets: UDP workers on IPv4 and IPv6, TCP with pipelining, the idle
//! timeout and the per-client cap, the worker layout, a delta from the feed seen by the
//! next query, and a graceful stop.

mod support;

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream, UdpSocket},
    time::{Duration, Instant},
};

use support::{
    a,
    answer::{Answer, decode, query},
    ports::{loopback, start_on_free_port},
    rrset, soa, zone,
};
use tenko_core::{
    Revision,
    dns::{RrSet, ScopeName, Zone},
};
use tenko_dns::{
    DnsData, MemFeed,
    authoritative::rcode,
    catalog::{self, CatalogHandle},
    feed::Change,
    server::{Hooks, Server, ServerConfig},
    transport::{SocketMode, tcp::TcpSettings, udp::UdpSettings},
};
use tokio_util::sync::CancellationToken;

fn image() -> (DnsData, Zone) {
    let parent = zone("example.test");
    let mut image = DnsData::at(Revision(1));
    let rows: Vec<RrSet> = vec![
        rrset(
            &parent,
            &ScopeName::DEFAULT,
            "example.test",
            &[soa("example.test", 300)],
        ),
        rrset(&parent, &ScopeName::DEFAULT, "www.example.test", &[a(1)]),
    ];
    for row in rows {
        image.rrsets.insert(row.key(), row);
    }
    image.zones.insert(parent.id, parent.clone());
    (image, parent)
}

fn config(listen: Vec<SocketAddr>, tcp: TcpSettings) -> ServerConfig {
    ServerConfig {
        listen,
        udp: UdpSettings {
            workers: 2,
            mode: SocketMode::platform_default(),
            recv_buffer: 0,
            send_buffer: 0,
        },
        tcp: Some(tcp),
        metrics: true,
        cookies: tenko_dns::cookie::CookieMode::On,
        edns_udp_size: 1232,
        tls: None,
    }
}

fn udp_ask(server: SocketAddr, qname: &str) -> Option<Answer> {
    let local: SocketAddr = if server.is_ipv6() {
        "[::1]:0".parse().expect("address")
    } else {
        "127.0.0.1:0".parse().expect("address")
    };
    let socket = UdpSocket::bind(local).expect("bind");
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("timeout");
    socket
        .send_to(&query(qname, 1).bytes(0x0101), server)
        .expect("send");
    let mut buf = [0u8; 2048];
    let (len, _) = socket.recv_from(&mut buf).ok()?;
    Some(decode(&buf[..len]))
}

fn tcp_frames(stream: &mut TcpStream, count: usize) -> Vec<Answer> {
    let mut answers = Vec::new();
    for _ in 0..count {
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).expect("length");
        let mut message = vec![0u8; usize::from(u16::from_be_bytes(len))];
        stream.read_exact(&mut message).expect("message");
        answers.push(decode(&message));
    }
    answers
}

fn closed(stream: &mut TcpStream) -> bool {
    let mut byte = [0u8; 1];
    matches!(stream.read(&mut byte), Ok(0) | Err(_))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines, reason = "one server through its whole life")]
async fn udp_and_tcp_answer_and_the_server_stops() {
    let (image, _) = image();
    let handle = CatalogHandle::new(tenko_dns::catalog::Catalog::build(&image));
    let ipv6 = UdpSocket::bind("[::1]:0").is_ok();
    let settings = TcpSettings {
        max_connections: 100,
        per_client: 2,
        idle: Duration::from_millis(400),
    };
    let server = start_on_free_port(|port| config(loopback(port, ipv6), settings), &handle).await;
    let udp = server.udp_addresses().to_vec();
    let tcp = server.tcp_addresses().to_vec();
    assert_eq!(udp.len(), tcp.len());
    assert_eq!(udp[0].port(), tcp[0].port(), "UDP and TCP share the port");
    let v4 = udp[0];
    let answers = tokio::task::spawn_blocking(move || {
        let www = udp_ask(v4, "www.example.test").expect("an answer");
        let nx = udp_ask(v4, "nohost.example.test").expect("an answer");
        (www, nx)
    })
    .await
    .expect("join");
    assert_eq!(
        (answers.0.rcode, answers.0.answers.len()),
        (rcode::NOERROR, 1)
    );
    assert_eq!(answers.1.rcode, rcode::NXDOMAIN);
    if ipv6 {
        let v6 = udp[1];
        let answer = tokio::task::spawn_blocking(move || udp_ask(v6, "www.example.test"))
            .await
            .expect("join")
            .expect("an answer over IPv6");
        assert_eq!(answer.answers.len(), 1);
    }
    // A worker counts an answer after it has left, so the client can hold both
    // answers a moment before the counters say so: they are waited for, briefly.
    let began = std::time::Instant::now();
    let layout = loop {
        let layout = server.layout();
        let received: u64 = layout.udp.iter().map(|worker| worker.received).sum();
        let sent: u64 = layout.udp.iter().map(|worker| worker.sent).sum();
        if received >= 2 && sent == received {
            break layout;
        }
        assert!(
            began.elapsed() < std::time::Duration::from_secs(5),
            "the workers' counters did not settle: {layout:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    assert_eq!(layout.workers_per_address, 2);
    assert_eq!(layout.udp.len(), 2 * udp.len());

    let tcp_v4 = tcp[0];
    tokio::task::spawn_blocking(move || {
        // Pipelining: five queries in one write, five answers in order.
        let mut stream = TcpStream::connect(tcp_v4).expect("connect");
        let mut batch = Vec::new();
        for (index, qname) in [
            "www.example.test",
            "a.example.test",
            "www.example.test",
            "example.test",
            "www.example.test",
        ]
        .iter()
        .enumerate()
        {
            let message = query(qname, 1).bytes(u16::try_from(index).expect("id"));
            batch.extend_from_slice(&u16::try_from(message.len()).expect("len").to_be_bytes());
            batch.extend_from_slice(&message);
        }
        stream.write_all(&batch).expect("write");
        let answers = tcp_frames(&mut stream, 5);
        let ids: Vec<u16> = answers.iter().map(|answer| answer.header.id).collect();
        assert_eq!(ids, [0, 1, 2, 3, 4]);
        assert_eq!(answers[1].rcode, rcode::NXDOMAIN);
        // The per-client cap: a third connection from the same address is closed at once.
        let mut second = TcpStream::connect(tcp_v4).expect("connect");
        let mut third = TcpStream::connect(tcp_v4).expect("connect");
        third
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        assert!(closed(&mut third), "over the per-client cap");
        // The idle timeout closes a quiet connection.
        second
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let started = Instant::now();
        assert!(closed(&mut second));
        assert!(started.elapsed() >= Duration::from_millis(300));
        // A cut message closes the connection too.
        let mut cut = TcpStream::connect(tcp_v4).expect("connect");
        cut.write_all(&[0, 40, 1, 2]).expect("write");
        cut.set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        assert!(closed(&mut cut));
    })
    .await
    .expect("join");
    assert!(server.layout().tcp_refused >= 1);

    server.stop().await;
    let gone = tokio::task::spawn_blocking(move || udp_ask(v4, "www.example.test"))
        .await
        .expect("join");
    assert!(gone.is_none(), "no answer after the stop");
    assert!(
        TcpStream::connect(tcp_v4).is_err() || {
            let mut stream = TcpStream::connect(tcp_v4).expect("connect");
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("timeout");
            closed(&mut stream)
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delta_from_the_feed_is_answered_by_the_running_server() {
    let (image, parent) = image();
    let (mut feed, writer) = MemFeed::new(image);
    let handle = catalog::initial(&mut feed).await.expect("image");
    let server = start_on_free_port(
        |port| config(loopback(port, false), TcpSettings::default()),
        &handle,
    )
    .await;
    let stop = CancellationToken::new();
    let follower = tokio::spawn(catalog::follow(feed, handle.clone(), stop.clone()));
    let address = server.udp_addresses()[0];
    let before = tokio::task::spawn_blocking(move || udp_ask(address, "new.example.test"))
        .await
        .expect("join")
        .expect("answer");
    assert_eq!(before.rcode, rcode::NXDOMAIN);
    let added = rrset(&parent, &ScopeName::DEFAULT, "new.example.test", &[a(42)]);
    let revision = writer.publish(vec![Change::RrSet(added.key(), Some(added))]);
    let deadline = Instant::now() + Duration::from_secs(5);
    while handle.revision() < revision && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(handle.revision(), revision);
    let after = tokio::task::spawn_blocking(move || udp_ask(address, "new.example.test"))
        .await
        .expect("join")
        .expect("answer");
    assert_eq!(after.answers[0].rdata, [192, 0, 2, 42]);
    // A reset swaps a whole new catalog.
    writer.reset(DnsData::at(Revision(50)));
    let deadline = Instant::now() + Duration::from_secs(5);
    while handle.revision() != Revision(50) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let empty = tokio::task::spawn_blocking(move || udp_ask(address, "www.example.test"))
        .await
        .expect("join")
        .expect("answer");
    assert_eq!(empty.rcode, rcode::REFUSED, "no zone after the reset");
    stop.cancel();
    follower.await.expect("join").expect("follow");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_port_in_use_fails_the_start() {
    let (image, _) = image();
    let taken = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let address = taken.local_addr().expect("address");
    let handle = CatalogHandle::new(tenko_dns::catalog::Catalog::build(&image));
    let result = Server::start_authoritative(
        config(vec![address], TcpSettings::default()),
        handle.clone(),
        Hooks::default(),
    )
    .await;
    assert!(result.is_err());
    let mut empty = config(Vec::new(), TcpSettings::default());
    assert!(
        Server::start_authoritative(empty.clone(), handle.clone(), Hooks::default())
            .await
            .is_err()
    );
    empty.listen = vec!["127.0.0.1:0".parse().expect("address")];
    empty.udp.workers = 0;
    assert!(
        Server::start_authoritative(empty, handle, Hooks::default())
            .await
            .is_err()
    );
}
