//! The engine and a client a move job moves (ADR 0027, `docs/moves.md` section 5): the
//! short lease at the renewal of a marked lease, with its own T1 and T2, and none without
//! the marker, for another client or past the marker's end; the activity the role notes for
//! the job; and why no NAK at T1 helps a moved client.

mod engine_world;

use std::net::SocketAddrV4;

use engine_world::{Ask, World, at, ip, mac, t0};
use tenko_core::{
    JobId, MacAddr, PrefixId, VrfId,
    dhcp::{MovingClient, MovingLease},
};
use tenko_dhcp::{
    moving::Activity,
    v4::{
        Message, MessageType,
        engine::{Action, Answer, Destination, Scratch},
    },
};

/// The marker of a move job for client `k` and its lease of 192.0.2.110, active for ten
/// minutes after `t0`, with scope B (198.51.100.0/24) as the target.
fn marker(world_vrf: VrfId, job: JobId, k: u8, target: Option<PrefixId>) -> MovingClient {
    MovingClient {
        job,
        mac: MacAddr::new(mac(k)),
        lease: Some(MovingLease {
            vrf: world_vrf,
            addr: ip("192.0.2.110"),
        }),
        short_secs: 120,
        target,
        until: at(600),
        extended: false,
    }
}

/// The world with `moving` in its image (client :10 holds 192.0.2.110 for an hour); the
/// rows get the VRF and the prefix of scope B.
fn world(moving: impl FnOnce(VrfId, PrefixId) -> Vec<MovingClient>) -> World {
    World::moving(moving)
}

/// The renewal of client :10, unicast from its address (RENEWING).
fn renewal() -> Ask {
    let mut ask = Ask::new(MessageType::Request, 0x10);
    ask.giaddr = None;
    ask.ciaddr = Some(ip("192.0.2.110"));
    ask
}

fn ack(answer: &Answer, scratch: &Scratch) -> (u32, u32, u32) {
    let Action::CommitThenReply {
        kind: MessageType::Ack,
        len,
        ..
    } = answer.action
    else {
        panic!("not an ACK after the commit: {answer:?}");
    };
    let reply = Message::parse(&scratch.reply[..len]).expect("a reply");
    (
        reply.lease_time().expect("51").expect("a lease time"),
        reply.renewal_time().expect("58").expect("T1"),
        reply.rebinding_time().expect("59").expect("T2"),
    )
}

#[test]
fn a_marked_lease_renews_with_the_short_lease_and_its_own_t1_and_t2() {
    let job = JobId::generate();
    let world = world(|vrf, target| vec![marker(vrf, job, 0x10, Some(target))]);
    let mut scratch = Scratch::new();
    let answer = world.run(&renewal().bytes(), at(30), &mut scratch);
    // 120 s, T1 at half and T2 at seven eighths, derived as for any grant.
    assert_eq!(ack(&answer, &scratch), (120, 60, 105));
    assert_eq!(scratch.change.ends, at(150));
}

#[test]
fn an_unmarked_lease_another_client_and_an_ended_marker_renew_as_usual() {
    let job = JobId::generate();
    let mut scratch = Scratch::new();
    // No marker: the pool's day.
    let plain = World::new();
    let answer = plain.run(&renewal().bytes(), at(30), &mut scratch);
    assert_eq!(ack(&answer, &scratch), (86_400, 43_200, 75_600));
    // A marker of another client for the same address.
    let other = world(|vrf, target| vec![marker(vrf, job, 0x11, Some(target))]);
    let answer = other.run(&renewal().bytes(), at(30), &mut scratch);
    assert_eq!(ack(&answer, &scratch).0, 86_400);
    // A marker past its end (its job is no longer active): ignored.
    let ended = world(|vrf, target| vec![marker(vrf, job, 0x10, Some(target))]);
    let answer = ended.run(&renewal().bytes(), at(601), &mut scratch);
    assert_eq!(ack(&answer, &scratch).0, 86_400);
    // A marker without the old lease ("move now") only follows the client.
    let followed = world(|vrf, target| {
        vec![MovingClient {
            lease: None,
            ..marker(vrf, job, 0x10, Some(target))
        }]
    });
    let answer = followed.run(&renewal().bytes(), at(30), &mut scratch);
    assert_eq!(ack(&answer, &scratch).0, 86_400);
    assert_eq!(
        followed
            .image
            .moving()
            .activity(job, &mac(0x10))
            .and_then(|seen| seen.last),
        Some(at(30))
    );
}

#[test]
fn the_rebinding_on_the_new_network_is_refused_and_noted_as_the_reconnection() {
    let job = JobId::generate();
    let world = world(|vrf, target| vec![marker(vrf, job, 0x10, Some(target))]);
    let mut scratch = Scratch::new();
    // The renewal on the old network is activity, not a reconnection.
    world.run(&renewal().bytes(), at(30), &mut scratch);
    assert_eq!(
        world.image.moving().activity(job, &mac(0x10)),
        Some(Activity {
            last: Some(at(30)),
            on_target: None
        })
    );
    // At T2 of the short lease the client broadcasts; the relay of the new network adds
    // its giaddr, which selects scope B, the move's target.
    let mut rebind = Ask::new(MessageType::Request, 0x10);
    rebind.giaddr = Some(ip("198.51.100.1"));
    rebind.ciaddr = Some(ip("192.0.2.110"));
    let answer = world.run(&rebind.bytes(), at(135), &mut scratch);
    match answer.action {
        Action::Reply {
            kind: MessageType::Nak,
            dest,
            ..
        } => assert_eq!(
            dest,
            Destination::Relay(SocketAddrV4::new(ip("198.51.100.1"), 67))
        ),
        other => panic!("not a NAK: {other:?}"),
    }
    assert_eq!(
        world.image.moving().activity(job, &mac(0x10)),
        Some(Activity {
            last: Some(at(135)),
            on_target: Some(at(135))
        })
    );
    // The DISCOVER that follows on the new network is noted too.
    let discover = {
        let mut ask = Ask::new(MessageType::Discover, 0x10);
        ask.giaddr = Some(ip("198.51.100.1"));
        ask
    };
    world.run(&discover.bytes(), at(136), &mut scratch);
    assert_eq!(
        world
            .image
            .moving()
            .activity(job, &mac(0x10))
            .and_then(|seen| seen.on_target),
        Some(at(136))
    );
}

/// Why the move job never waits for a NAK at T1 (`docs/moves.md` section 5): a moved
/// client's unicast renewal at T1 never leaves it (it cannot reach its old gateway), and
/// if it did, the server would select the old scope by `ciaddr` and acknowledge it. The
/// only NAK of a unicast renewal without `giaddr` goes out as a broadcast on the server's
/// own link, which the moved client is not on. A move that wants the client back sooner
/// shortens its lease before the network changes instead.
#[test]
fn no_nak_at_t1_reaches_a_moved_client_a_unicast_renewal_is_nakked_by_broadcast_on_the_servers_link()
 {
    let world = World::new();
    let mut scratch = Scratch::new();
    // The client's own renewal of its old address is acknowledged to that address.
    let own = world.run(&renewal().bytes(), t0(), &mut scratch);
    assert!(
        matches!(
            own.action,
            Action::CommitThenReply {
                kind: MessageType::Ack,
                dest: Destination::Client(addr),
                ..
            } if addr == SocketAddrV4::new(ip("192.0.2.110"), 68)
        ),
        "{own:?}"
    );
    // A unicast renewal the server refuses: the NAK is a broadcast on the server's link.
    let mut other = renewal();
    other.client = 0x32;
    let refused = world.run(&other.bytes(), t0(), &mut scratch);
    assert!(
        matches!(
            refused.action,
            Action::Reply {
                kind: MessageType::Nak,
                dest: Destination::Broadcast(68),
                ..
            }
        ),
        "{refused:?}"
    );
}
