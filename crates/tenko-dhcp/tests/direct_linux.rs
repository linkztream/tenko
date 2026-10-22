//! Direct mode on Linux (WP7.5, `docs/dhcp.md` section 10.3), with root: a veth pair, the
//! listener bound to one end with `SO_BINDTODEVICE`, a client's DISCOVER broadcast as a raw
//! frame from the other end without the broadcast flag, and the OFFER expected as a
//! link-layer unicast to the client's hardware address through the listener's `AF_PACKET`
//! socket, with `yiaddr` as the IP destination.
//!
//! The test changes the host's interfaces, so it is ignored unless asked for:
//! `TENKO_TEST_DIRECT_VETH=1 cargo test -p tenko-dhcp --test direct_linux -- --ignored`
//! as root (in WSL: `wsl -u root`). It creates `tdhcp0` (192.0.2.1/24) and `tdhcp1` (the
//! client, MAC 00:00:5e:00:53:31, no address) and removes them at the end.

#![cfg(target_os = "linux")]

mod engine_world;

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

use engine_world::{Ask, World, ip, mac};
use pnet_datalink::{Channel, Config};
use tenko_core::NodeId;
use tenko_dhcp::{
    server::{
        DhcpServer, Listen, ServerConfig, SocketLayout,
        link::{Framing, HEADERS, frame},
    },
    store::{LeaseStore, MemLeaseStore},
    v4::{Message, MessageType, engine::ListenMode},
};

const SERVER_SIDE: &str = "tdhcp0";
const CLIENT_SIDE: &str = "tdhcp1";
const CLIENT: u8 = 0x31;

fn ip_command(args: &[&str]) {
    let status = Command::new("ip").args(args).status().expect("ip");
    assert!(status.success(), "ip {args:?}");
}

/// Removes the pair when the test ends, also on a failure.
struct Pair;

impl Pair {
    fn create() -> Self {
        let _ = Command::new("ip")
            .args(["link", "del", SERVER_SIDE])
            .stderr(std::process::Stdio::null())
            .status();
        ip_command(&[
            "link",
            "add",
            SERVER_SIDE,
            "type",
            "veth",
            "peer",
            "name",
            CLIENT_SIDE,
        ]);
        let client = mac(CLIENT)
            .iter()
            .map(|octet| format!("{octet:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        ip_command(&["link", "set", CLIENT_SIDE, "address", &client]);
        ip_command(&["addr", "add", "192.0.2.1/24", "dev", SERVER_SIDE]);
        ip_command(&["link", "set", SERVER_SIDE, "up"]);
        ip_command(&["link", "set", CLIENT_SIDE, "up"]);
        Self
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "del", SERVER_SIDE])
            .stderr(std::process::Stdio::null())
            .status();
    }
}

#[test]
#[ignore = "needs root and changes the host's interfaces; set TENKO_TEST_DIRECT_VETH=1"]
#[allow(
    clippy::too_many_lines,
    reason = "one exchange on the link, read top to bottom"
)]
fn a_direct_listener_answers_a_client_without_an_address_at_the_link_layer() {
    if std::env::var_os("TENKO_TEST_DIRECT_VETH").is_none() {
        eprintln!("TENKO_TEST_DIRECT_VETH is not set; nothing to do");
        return;
    }
    let _pair = Pair::create();
    let world = World::new();
    let store = Arc::new(MemLeaseStore::with_capacity(NodeId(1), 64));
    let config = ServerConfig {
        listen: vec![Listen {
            address: SocketAddrV4::new(ip("192.0.2.1"), 67),
            mode: ListenMode::Direct,
            interface: Some(SERVER_SIDE.to_owned()),
        }],
        workers: 2,
        layout: SocketLayout::ReusePort,
        node: NodeId(1),
        ..ServerConfig::default()
    };
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
    assert!(
        server.listeners()[0].link_layer,
        "the listener opened its link-layer socket"
    );

    // The client side: a raw channel on the other end of the pair.
    let native = pnet_datalink::interfaces()
        .into_iter()
        .find(|candidate| candidate.name == CLIENT_SIDE)
        .expect("the client side");
    let Channel::Ethernet(mut tx, mut rx) = pnet_datalink::channel(
        &native,
        Config {
            read_timeout: Some(Duration::from_millis(100)),
            promiscuous: false,
            ..Config::default()
        },
    )
    .expect("a raw channel") else {
        panic!("not an Ethernet channel");
    };
    // A client on the link: no relay, no address, no broadcast flag.
    let mut ask = Ask::new(MessageType::Discover, CLIENT);
    ask.giaddr = None;
    let discover = ask.bytes();
    let framing = Framing {
        source_mac: mac(CLIENT),
        source: Ipv4Addr::UNSPECIFIED,
        source_port: 68,
        dest_mac: [0xff; 6],
        dest: Ipv4Addr::BROADCAST,
        dest_port: 67,
    };
    let mut out = vec![0u8; HEADERS + discover.len()];
    let len = frame(&framing, &discover, &mut out).expect("frame");

    let start = Instant::now();
    let mut sent_at: Option<Instant> = None;
    let mut sent = 0u64;
    let mut seen = Vec::new();
    let offer = loop {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "no unicast OFFER arrived at the client's hardware address; the server counted {:?}, \
             the client saw {seen:?}",
            server.metrics(),
        );
        if sent_at.is_none_or(|at| at.elapsed() > Duration::from_millis(500)) {
            tx.send_to(&out[..len], None)
                .expect("a send")
                .expect("sent");
            sent_at = Some(Instant::now());
            sent += 1;
        }
        let Ok(received) = rx.next() else {
            continue;
        };
        // The IPv4 frames on the link, for the message of a failure.
        if seen.len() < 8 && received.len() > HEADERS && received[12..14] == [0x08, 0x00] {
            seen.push((
                received[0..6].to_vec(),
                received[26..34].to_vec(),
                received[34..38].to_vec(),
            ));
        }
        // Ethernet to the client's MAC, IPv4, UDP to port 68.
        if received.len() > HEADERS
            && received[0..6] == mac(CLIENT)
            && received[12..14] == [0x08, 0x00]
            && received[23] == 17
            && received[36..38] == 68u16.to_be_bytes()
        {
            break received.to_vec();
        }
    };
    let message = Message::parse(&offer[HEADERS..]).expect("a DHCP message");
    assert_eq!(
        message.message_type().expect("53"),
        Some(MessageType::Offer)
    );
    let yiaddr = message.yiaddr();
    assert_eq!(yiaddr.octets()[..3], [192, 0, 2]);
    assert_eq!(
        &offer[30..34],
        &yiaddr.octets(),
        "the IP destination is yiaddr"
    );
    assert_eq!(
        &offer[26..30],
        &[192, 0, 2, 1],
        "from the listener's address"
    );
    // One answer per DISCOVER: a broadcast reaches every socket of a reuse-port group, so
    // the direct listener has one socket for its workers.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        server.metrics().packets("discover", "answered"),
        sent,
        "each DISCOVER answered once"
    );
    server.stop();
}

#[test]
#[ignore = "needs root and changes the host's interfaces; set TENKO_TEST_DIRECT_VETH=1"]
fn the_link_sender_reaches_the_other_end_of_the_pair() {
    if std::env::var_os("TENKO_TEST_DIRECT_VETH").is_none() {
        return;
    }
    let _pair = Pair::create();
    let sender = tenko_dhcp::server::LinkSender::open(SERVER_SIDE).expect("a sender");
    let native = pnet_datalink::interfaces()
        .into_iter()
        .find(|candidate| candidate.name == CLIENT_SIDE)
        .expect("the client side");
    let Channel::Ethernet(_tx, mut rx) = pnet_datalink::channel(
        &native,
        Config {
            read_timeout: Some(Duration::from_millis(100)),
            promiscuous: false,
            ..Config::default()
        },
    )
    .expect("a raw channel") else {
        panic!("not an Ethernet channel");
    };
    let payload = [0x42u8; 300];
    let start = Instant::now();
    let mut sends = 0;
    loop {
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "nothing arrived after {sends} send(s)"
        );
        sender
            .send(
                (ip("192.0.2.1"), 67),
                (mac(CLIENT), ip("192.0.2.150"), 68),
                &payload,
            )
            .expect("sent");
        sends += 1;
        if let Ok(frame) = rx.next()
            && frame.len() == HEADERS + payload.len()
            && frame[0..6] == mac(CLIENT)
        {
            assert_eq!(&frame[HEADERS..], &payload[..]);
            break;
        }
    }
}
