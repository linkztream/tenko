//! The listeners and workers over loopback (WP7.3): a relay-mode listener, the DORA path,
//! a renewal and a release through the in-memory store, the ACK sent only after the commit
//! and the lease table updated from it, and the store-refusal drop of P3-Q14.

mod engine_world;

use std::{
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    sync::Arc,
    time::{Duration, Instant},
};

use engine_world::{Ask, World, ip};
use tenko_core::{NodeId, dhcp::BindingState};
use tenko_dhcp::{
    lease::LeaseTable,
    server::{DhcpServer, Listen, ServerConfig, SocketLayout},
    store::{LeaseStore, MemLeaseStore},
    v4::{Message, MessageType, engine::ListenMode},
};

const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;

fn relayed(kind: MessageType, client: u8) -> Ask {
    let mut ask = Ask::new(kind, client);
    ask.giaddr = Some(LOOPBACK);
    ask.subnet = Some(ip("192.0.2.0"));
    ask
}

fn exchange(relay: &UdpSocket, server: SocketAddrV4, ask: &Ask) -> Option<Vec<u8>> {
    relay.send_to(&ask.bytes(), server).expect("send");
    let mut buf = [0u8; 1500];
    match relay.recv_from(&mut buf) {
        Ok((len, _)) => Some(buf[..len].to_vec()),
        Err(_) => None,
    }
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < Duration::from_secs(5), "{what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one exchange after another over the same server"
)]
fn a_relay_listener_runs_dora_renew_and_release_through_the_store() {
    let relay = UdpSocket::bind(SocketAddrV4::new(LOOPBACK, 0)).expect("bind");
    relay
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("timeout");
    let relay_port = relay.local_addr().expect("addr").port();
    let world = World::new();
    let store = Arc::new(MemLeaseStore::with_capacity(NodeId(1), 1_024));
    let mut config = ServerConfig {
        listen: vec![Listen {
            address: SocketAddrV4::new(LOOPBACK, 0),
            mode: ListenMode::Relay,
            interface: None,
        }],
        workers: 2,
        layout: SocketLayout::Shared,
        node: NodeId(1),
        ..ServerConfig::default()
    };
    config.engine.relay_port = relay_port;
    let driven = Arc::clone(&store);
    let server = DhcpServer::start(
        &config,
        world.image.clone(),
        world.leases.clone(),
        Arc::clone(&store) as Arc<dyn LeaseStore>,
        Some(Box::new(move || {
            driven.commit();
        })),
    )
    .expect("start");
    let address = server.local_addrs()[0];

    // DISCOVER and OFFER.
    let offer = exchange(&relay, address, &relayed(MessageType::Discover, 0x30)).expect("offer");
    let offer = Message::parse(&offer).expect("parse");
    assert_eq!(offer.message_type().expect("53"), Some(MessageType::Offer));
    let addr = offer.yiaddr();
    assert_eq!(addr.octets()[..3], [192, 0, 2]);
    assert_eq!(offer.server_identifier().expect("54"), Some(LOOPBACK));
    assert!(store.leases().is_empty(), "a DISCOVER writes nothing");

    // REQUEST and ACK: the ACK comes after the commit, and the table holds the row.
    let mut request = relayed(MessageType::Request, 0x30);
    request.requested = Some(addr);
    request.server_id = Some(LOOPBACK);
    let ack = exchange(&relay, address, &request).expect("ack");
    let ack = Message::parse(&ack).expect("parse");
    assert_eq!(ack.message_type().expect("53"), Some(MessageType::Ack));
    assert_eq!(ack.yiaddr(), addr);
    let committed = store.leases();
    let row = committed
        .values()
        .find(|lease| lease.addr == addr)
        .expect("committed");
    assert_eq!(row.state, BindingState::Active);
    wait_for("the table takes the commit", || {
        server.with_table(|table| table.get(row.vrf, addr).is_some_and(|l| l == row))
    });

    // A renewal through the relay moves the end.
    let mut renew = relayed(MessageType::Request, 0x30);
    renew.ciaddr = Some(addr);
    let first_end = row.ends;
    std::thread::sleep(Duration::from_millis(1_100));
    let renewed = exchange(&relay, address, &renew).expect("renewal ack");
    assert_eq!(
        Message::parse(&renewed)
            .expect("parse")
            .message_type()
            .expect("53"),
        Some(MessageType::Ack)
    );
    let vrf = row.vrf;
    wait_for("the renewal is applied", || {
        server.with_table(|table| table.get(vrf, addr).is_some_and(|l| l.ends > first_end))
    });

    // A release is committed without a reply.
    let mut release = relayed(MessageType::Release, 0x30);
    release.ciaddr = Some(addr);
    release.server_id = Some(LOOPBACK);
    assert!(
        exchange(&relay, address, &release).is_none(),
        "no reply to a release"
    );
    wait_for("the release is committed", || {
        store
            .leases()
            .values()
            .any(|lease| lease.addr == addr && lease.state == BindingState::Released)
    });

    // While the store refuses, a new lease is dropped and counted.
    store.set_refusing(true);
    let mut refused = relayed(MessageType::Request, 0x31);
    refused.requested = Some(ip("192.0.2.170"));
    refused.server_id = Some(LOOPBACK);
    assert!(exchange(&relay, address, &refused).is_none());
    store.set_refusing(false);

    let metrics = server.metrics();
    assert_eq!(metrics.packets("discover", "answered"), 1);
    assert_eq!(metrics.packets("request", "answered"), 2);
    assert_eq!(metrics.packets("release", "answered"), 1);
    assert_eq!(metrics.dropped("store_refused"), 1);
    assert_eq!(metrics.store_refused, 1);
    assert_eq!(
        metrics.exchange[0].0.iter().sum::<u64>(),
        1,
        "one offer timed"
    );
    assert_eq!(
        metrics.exchange[1].0.iter().sum::<u64>(),
        2,
        "two acks timed"
    );
    assert_eq!(metrics.commit.0.iter().sum::<u64>(), 3, "three commits");
    assert_eq!(server.in_flight(), 0);
    server.stop();
}
