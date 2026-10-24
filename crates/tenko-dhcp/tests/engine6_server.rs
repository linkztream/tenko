//! The DHCPv6 listener on loopback: a relay agent's RELAY-FORW gets its RELAY-REPL, a
//! REQUEST's REPLY leaves only after the commit, and a refusing store sends no REPLY.

mod engine6_world;

use std::{
    net::{Ipv6Addr, SocketAddrV6, UdpSocket},
    sync::Arc,
    time::Duration,
};

use engine6_world::{
    SERVER_DUID, addresses, client_options, duid_ll, ia_na, mac, message, relayed,
};
use tenko_core::{NodeId, PrefixId, Timestamp};
use tenko_dhcp::{
    v4::engine::ListenMode,
    v6::{
        Message, MessageType, code,
        engine::Engine6Settings,
        lease::{Lease6Index, Lease6Table, SharedLeases6, store::MemLease6Store},
        server::{Dhcp6Server, Listen6, Server6Config},
    },
};

fn relay_socket() -> UdpSocket {
    let socket = UdpSocket::bind("[::1]:0").expect("a relay socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    socket
}

fn start(store: Arc<MemLease6Store>, relay_port: u16) -> (Dhcp6Server, SharedLeases6) {
    let (first, second) = (PrefixId::generate(), PrefixId::generate());
    let image = engine6_world::image(first, second, |_, _, _| {});
    let table = SharedLeases6::new(Lease6Index::new());
    let config = Server6Config {
        listen: vec![Listen6 {
            address: SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0),
            mode: ListenMode::Relay,
            interface: None,
        }],
        workers: 2,
        engine: Engine6Settings {
            relay_port,
            ..Engine6Settings::default()
        },
        node: NodeId(1),
        server_duid: SERVER_DUID.to_vec(),
        pending: 16,
        offers: 64,
        ..Server6Config::default()
    };
    let drive_store = Arc::clone(&store);
    let server = Dhcp6Server::start(
        &config,
        Arc::new(image),
        table.clone(),
        store,
        false,
        Some(Box::new(move || {
            drive_store.commit(Timestamp::now());
        })),
    )
    .expect("the server starts");
    (server, table)
}

fn exchange(relay: &UdpSocket, server: SocketAddrV6, bytes: &[u8]) -> Option<Vec<u8>> {
    relay.send_to(bytes, server).expect("send");
    let mut buf = [0u8; 2048];
    relay
        .recv_from(&mut buf)
        .ok()
        .map(|(len, _)| buf[..len].to_vec())
}

#[test]
fn a_relayed_exchange_on_loopback_commits_before_the_reply() {
    let relay = relay_socket();
    let port = relay.local_addr().expect("addr").port();
    let store = Arc::new(MemLease6Store::with_capacity(NodeId(1), 16));
    let (server, table) = start(Arc::clone(&store), port);
    let target = server.local_addrs()[0];
    let duid = duid_ll(mac(0x31));
    let link = engine6_world::LINK1;
    let peer: Ipv6Addr = "fe80::200:5eff:fe00:5331".parse().expect("peer");
    let solicit = message(MessageType::Solicit, 1, |b| {
        client_options(b, &duid);
        ia_na(b, 1, None);
    });
    let advertise = exchange(
        &relay,
        target,
        &relayed(&solicit, &[(link, peer, Some(b"eth1"))], None),
    )
    .expect("an advertise");
    let outer = Message::parse(&advertise).expect("parses");
    assert_eq!(outer.kind(), MessageType::RelayRepl);
    assert_eq!(outer.interface_id().expect("walk"), Some(&b"eth1"[..]));
    let offered = addresses(&advertise)[0].1;
    assert_eq!(table.read().len(), 0);
    let request = message(MessageType::Request, 2, |b| {
        client_options(b, &duid);
        b.option(code::SERVERID, &SERVER_DUID).expect("sid");
        ia_na(b, 1, Some(offered));
    });
    let reply = exchange(
        &relay,
        target,
        &relayed(&request, &[(link, peer, None)], None),
    )
    .expect("a reply");
    assert_eq!(addresses(&reply)[0].1, offered);
    // The row was committed (and applied) before the REPLY was sent.
    assert!(store.rows().values().any(|lease| lease.addr6() == offered));
    let held = table
        .read()
        .get(tenko_core::VrfId(uuid::Uuid::nil()), offered)
        .cloned();
    assert!(held.is_some_and(|lease| lease.duid.as_bytes() == duid));
    let metrics = server.metrics();
    assert_eq!(metrics.packets("solicit", "answered"), 1);
    assert_eq!(metrics.packets("request", "answered"), 1);
    // A refusing store: the REQUEST gets no REPLY.
    store.set_refusing(true);
    let again = message(MessageType::Request, 3, |b| {
        client_options(b, &duid_ll(mac(0x32)));
        b.option(code::SERVERID, &SERVER_DUID).expect("sid");
        ia_na(b, 1, None);
    });
    assert!(
        exchange(
            &relay,
            target,
            &relayed(&again, &[(link, peer, None)], None)
        )
        .is_none()
    );
    server.stop();
}
