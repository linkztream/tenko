//! Conflict detection and DECLINE (WP8.5, plan section 2.7, DHCP-06, TGL-16) through the
//! listeners and workers over loopback, with a fake probe that answers at once, late or
//! never:
//!
//! - an OFFER of an address never leased to the client waits for the probe, in the pending
//!   table and not in a worker, and goes out when nobody answered or at the cap;
//! - an answer marks the address (abandoned for the hold time, with the answering MAC
//!   address) and the next address is offered; the client's own MAC address is no conflict;
//!   a reservation that answers is offered all the same;
//! - the probe cache; the rules of when (renewals, the client's lease, its previous address,
//!   a reservation in use are never probed); no probe, or the setting off, offers at once;
//! - a DECLINE abandons the address for the hold time, is reported for its audit record,
//!   and a client beyond its limit is dropped and keeps its lease;
//! - M35's first half: the offer delay for new addresses stays at most the cap with a probe
//!   that never answers, and renewals are not delayed (`m35_offer_delay_and_renewals`
//!   prints the figures; run it with `--release --no-capture` for the results file).
//!
//! Documentation addresses (RFC 5737) and MACs (RFC 7042) only.

mod engine_world;

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    sync::{Arc, Mutex, PoisonError, RwLock},
    time::{Duration, Instant},
};

use engine_world::{Ask, World, ip, mac};
use tenko_core::{
    NodeId, Timestamp,
    dhcp::{BindingState, LeaseEventKind},
};
use tenko_dhcp::{
    conflict::{ConflictSettings, DynProbe, ProbeHandle, ReportKind, TIMER_TICK},
    lease::{LeaseTable, MemLeaseTable, PendingChange},
    probe::{ConflictProbe, NoProbe, ProbeOutcome},
    server::{DhcpServer, Listen, ServerConfig, SocketLayout},
    store::{LeaseStore, MemLeaseStore},
    v4::{Message, MessageType, engine::ListenMode},
};

const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;
const CAP: Duration = Duration::from_millis(300);
/// What the timers of the platform add to the cap (Windows ticks at about 15.6 ms).
const SLACK: Duration = Duration::from_millis(60);
/// The earliest an offer cut by the cap arrives.
const AT_THE_CAP: Duration = Duration::from_millis(295).saturating_sub(TIMER_TICK);

/// How the fake probe answers one address.
#[derive(Debug, Clone, Copy)]
enum Answer {
    /// Never: the cap ends the probe.
    Never,
    /// Nobody, after a while.
    Clear(Duration),
    /// A host, after a while.
    InUse(Duration, Option<[u8; 6]>),
}

type Rule = Box<dyn Fn(Ipv4Addr, usize) -> Answer + Send + Sync>;

/// A probe whose answers a rule decides: by address and by the number of the call.
struct Fake {
    rule: Rule,
    calls: Mutex<Vec<Ipv4Addr>>,
}

impl Fake {
    fn new(rule: impl Fn(Ipv4Addr, usize) -> Answer + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            rule: Box::new(rule),
            calls: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<Ipv4Addr> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl ConflictProbe for Fake {
    fn available(&self) -> bool {
        true
    }

    fn probe(
        &self,
        addr: Ipv4Addr,
        _timeout: Duration,
    ) -> impl Future<Output = ProbeOutcome> + Send {
        let answer = {
            let mut calls = self.calls.lock().unwrap_or_else(PoisonError::into_inner);
            calls.push(addr);
            (self.rule)(addr, calls.len() - 1)
        };
        async move {
            match answer {
                Answer::Never => std::future::pending().await,
                Answer::Clear(after) => {
                    tokio::time::sleep(after).await;
                    ProbeOutcome::Clear
                }
                Answer::InUse(after, mac) => {
                    tokio::time::sleep(after).await;
                    ProbeOutcome::InUse { mac }
                }
            }
        }
    }
}

/// A squatter's MAC address.
const SQUATTER: [u8; 6] = [0x00, 0x00, 0x5e, 0x00, 0x53, 0xee];

/// A server over the world's image with the fake probe (or none), and a relay socket.
struct Lab {
    server: DhcpServer<RwLock<MemLeaseTable>>,
    store: Arc<MemLeaseStore>,
    relay: UdpSocket,
    address: SocketAddrV4,
    vrf: tenko_core::VrfId,
}

fn lab_with(
    probe: Option<Arc<dyn DynProbe>>,
    prepare: impl FnOnce(&mut World),
    tune: impl FnOnce(&mut ServerConfig),
) -> Lab {
    let relay = UdpSocket::bind(SocketAddrV4::new(LOOPBACK, 0)).expect("bind");
    relay
        .set_read_timeout(Some(Duration::from_millis(1_500)))
        .expect("timeout");
    let relay_port = relay.local_addr().expect("addr").port();
    let mut world = World::new();
    // The world's leases are at its fixed time; the server runs on the clock.
    world.leases = MemLeaseTable::default();
    prepare(&mut world);
    let store = Arc::new(MemLeaseStore::with_capacity(NodeId(1), 4_096));
    let mut config = ServerConfig {
        listen: vec![Listen {
            address: SocketAddrV4::new(LOOPBACK, 0),
            mode: ListenMode::Relay,
            interface: None,
        }],
        workers: 1,
        layout: SocketLayout::Shared,
        node: NodeId(1),
        conflict: ConflictSettings {
            probe: probe.map(ProbeHandle::shared),
            cap: CAP,
            ..ConflictSettings::default()
        },
        ..ServerConfig::default()
    };
    config.engine.relay_port = relay_port;
    tune(&mut config);
    let driven = Arc::clone(&store);
    let vrf = world.vrf;
    let server = DhcpServer::start(
        &config,
        world.image.clone(),
        world.leases,
        Arc::clone(&store) as Arc<dyn LeaseStore>,
        Some(Box::new(move || {
            driven.commit();
        })),
    )
    .expect("start");
    let address = server.local_addrs()[0];
    Lab {
        server,
        store,
        relay,
        address,
        vrf,
    }
}

fn lab(probe: Option<Arc<dyn DynProbe>>) -> Lab {
    lab_with(probe, |_| {}, |_| {})
}

/// A request of client `k` relayed from loopback into scope A (option 118).
fn relayed(kind: MessageType, client: u8) -> Ask {
    let mut ask = Ask::new(kind, client);
    ask.giaddr = Some(LOOPBACK);
    ask.subnet = Some(ip("192.0.2.0"));
    ask
}

/// Gives client `k` (with option 61) a lease of `addr` in `state` ending `secs` from now.
fn lease_now(world: &mut World, k: u8, addr: Ipv4Addr, state: BindingState, secs: i64) {
    let scope = world.scope_of(addr).prefix;
    let mut id = vec![1];
    id.extend(mac(k));
    let now = Timestamp::now();
    let ends = if secs >= 0 {
        now.checked_add(Duration::from_secs(secs.unsigned_abs()))
            .expect("time")
    } else {
        Timestamp::from_unix_nanos(
            now.unix_nanos() - i128::from(secs.unsigned_abs()) * 1_000_000_000,
        )
        .expect("time")
    };
    let change = PendingChange::new(
        LeaseEventKind::Granted,
        world.vrf,
        scope,
        addr,
        1,
        &mac(k),
        Some(&id),
        state,
        now,
        ends,
    );
    world.leases.apply(change.to_lease(NodeId(1), None));
}

impl Lab {
    /// Sends `ask` and waits for one reply; the reply and the time it took.
    fn exchange(&self, ask: &Ask) -> Option<(Message<'static>, Duration)> {
        let started = Instant::now();
        self.relay
            .send_to(&ask.bytes(), self.address)
            .expect("send");
        let mut buf = [0u8; 1500];
        let (len, _) = self.relay.recv_from(&mut buf).ok()?;
        let took = started.elapsed();
        let bytes: &'static [u8] = Box::leak(buf[..len].to_vec().into_boxed_slice());
        Some((Message::parse(bytes).expect("parse"), took))
    }

    fn offer(&self, client: u8) -> (Ipv4Addr, Duration) {
        let (offer, took) = self
            .exchange(&relayed(MessageType::Discover, client))
            .expect("an offer");
        assert_eq!(offer.message_type().expect("53"), Some(MessageType::Offer));
        (offer.yiaddr(), took)
    }

    fn ack(&self, client: u8, addr: Ipv4Addr) -> Duration {
        let mut request = relayed(MessageType::Request, client);
        request.requested = Some(addr);
        request.server_id = Some(LOOPBACK);
        let (ack, took) = self.exchange(&request).expect("an ack");
        assert_eq!(ack.message_type().expect("53"), Some(MessageType::Ack));
        assert_eq!(ack.yiaddr(), addr);
        took
    }

    fn renew(&self, client: u8, addr: Ipv4Addr) -> Duration {
        let mut renew = relayed(MessageType::Request, client);
        renew.ciaddr = Some(addr);
        let (ack, took) = self.exchange(&renew).expect("a renewal ack");
        assert_eq!(ack.message_type().expect("53"), Some(MessageType::Ack));
        took
    }

    fn decline(&self, client: u8, addr: Ipv4Addr) {
        let mut decline = relayed(MessageType::Decline, client);
        decline.requested = Some(addr);
        decline.server_id = Some(LOOPBACK);
        self.relay
            .send_to(&decline.bytes(), self.address)
            .expect("send");
    }

    fn row(&self, addr: Ipv4Addr) -> Option<tenko_core::dhcp::Lease> {
        self.server
            .with_table(|table| table.get(self.vrf, addr).cloned())
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
fn an_offer_waits_for_the_probe_and_goes_out_when_nobody_answered() {
    let fake = Fake::new(|_, _| Answer::Clear(Duration::from_millis(40)));
    let lab = lab(Some(fake.clone()));
    let (addr, took) = lab.offer(0x30);
    assert_eq!(fake.calls(), vec![addr]);
    assert!(took >= Duration::from_millis(35), "{took:?}");
    assert!(took < CAP, "the offer went out on the answer: {took:?}");
    let stats = lab.server.conflicts().stats();
    assert_eq!((stats.parked, stats.clear, stats.conflicts), (1, 1, 0));
    // The same client asks again: the cache lets the offer through at once.
    let (again, quick) = lab.offer(0x30);
    assert_eq!(again, addr);
    assert_eq!(fake.calls().len(), 1, "a clean address is not probed again");
    assert!(quick < Duration::from_millis(30), "{quick:?}");
    assert_eq!(lab.server.conflicts().stats().cached, 1);
    lab.server.stop();
}

#[test]
fn the_cap_sends_the_offer_when_the_probe_never_or_late_answers() {
    for answer in [
        Answer::Never,
        Answer::InUse(Duration::from_secs(2), Some(SQUATTER)),
    ] {
        let fake = Fake::new(move |_, _| answer);
        let lab = lab(Some(fake.clone()));
        let (addr, took) = lab.offer(0x31);
        assert_eq!(fake.calls(), vec![addr], "{answer:?}");
        assert!(took >= AT_THE_CAP, "{answer:?}: {took:?}");
        assert!(took <= CAP + SLACK, "{answer:?}: {took:?}");
        let stats = lab.server.conflicts().stats();
        assert_eq!((stats.capped, stats.conflicts), (1, 0), "{answer:?}");
        assert!(lab.row(addr).is_none(), "a late answer marks nothing");
        lab.server.stop();
    }
}

#[test]
fn an_answer_marks_the_address_and_the_next_one_is_offered() {
    // The first address answers at once with a MAC address; the next is clean.
    let fake = Fake::new(|_, call| {
        if call == 0 {
            Answer::InUse(Duration::ZERO, Some(SQUATTER))
        } else {
            Answer::Clear(Duration::from_millis(5))
        }
    });
    let lab = lab(Some(fake.clone()));
    let (addr, took) = lab.offer(0x32);
    let calls = fake.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    let squatted = calls[0];
    assert_ne!(addr, squatted, "the next address is offered");
    assert_eq!(calls[1], addr);
    assert!(took < CAP, "{took:?}");
    // The squatted address is abandoned for the hold time, with the answering MAC.
    let row = lab.row(squatted).expect("the conflict's row");
    assert_eq!(row.state, BindingState::Abandoned);
    assert_eq!(row.client.chaddr.0, SQUATTER.to_vec());
    let held = row.ends.saturating_since(row.cltt);
    assert!(
        held >= Duration::from_secs(86_399) && held <= Duration::from_secs(86_401),
        "{held:?}"
    );
    wait_for("the conflict is committed", || {
        lab.store
            .history()
            .iter()
            .any(|event| event.addr == squatted && event.kind == LeaseEventKind::Conflict)
    });
    let observation =
        tenko_dhcp::conflict::observation::conflict_observation(&row, NodeId(1), Timestamp::now())
            .expect("a conflict fact");
    assert!(matches!(
        observation.subject,
        tenko_core::observe::Observed::Address { mac: Some(mac), .. } if mac.octets() == SQUATTER
    ));
    // Nobody else is offered it, and the client completes its exchange on the new one.
    lab.ack(0x32, addr);
    for client in 0x40..0x48 {
        let (other, _) = lab.offer(client);
        assert_ne!(other, squatted);
    }
    let stats = lab.server.conflicts().stats();
    assert_eq!(stats.conflicts, 1);
    let mut reports = Vec::new();
    lab.server.conflicts().reports().drain(&mut reports);
    assert!(
        reports
            .iter()
            .any(|report| report.kind == ReportKind::Conflict && report.addr == squatted)
    );
    lab.server.stop();
}

#[test]
fn every_answering_address_is_skipped_until_the_cap() {
    // Every address answers: the server probes three further addresses after the first and
    // then offers the next one unprobed, at most at the cap.
    let fake = Fake::new(|_, _| Answer::InUse(Duration::from_millis(10), None));
    let lab = lab(Some(fake.clone()));
    let (addr, took) = lab.offer(0x33);
    let calls = fake.calls();
    assert_eq!(calls.len(), 4, "the first probe and three more: {calls:?}");
    assert!(!calls.contains(&addr), "{calls:?} {addr}");
    assert!(took <= CAP + SLACK, "{took:?}");
    assert_eq!(lab.server.conflicts().stats().conflicts, 4);
    lab.server.stop();
}

#[test]
fn the_clients_own_mac_is_no_conflict() {
    let fake = Fake::new(|_, _| Answer::InUse(Duration::ZERO, Some(mac(0x34))));
    let lab = lab(Some(fake.clone()));
    let (addr, _) = lab.offer(0x34);
    assert_eq!(fake.calls(), vec![addr]);
    assert!(lab.row(addr).is_none());
    let stats = lab.server.conflicts().stats();
    assert_eq!((stats.own, stats.conflicts), (1, 0));
    lab.server.stop();
}

#[test]
fn renewals_leases_previous_addresses_and_reservations_in_use_are_never_probed() {
    let fake = Fake::new(|_, _| Answer::Never);
    let bound = ip("192.0.2.150");
    let previous = ip("192.0.2.151");
    let lab = lab_with(
        Some(fake.clone()),
        |world| {
            lease_now(world, 0x35, bound, BindingState::Active, 3_600);
            lease_now(world, 0x36, previous, BindingState::Expired, -60);
        },
        |_| {},
    );
    // A renewal of a bound lease.
    let took = lab.renew(0x35, bound);
    assert!(took < Duration::from_millis(100), "{took:?}");
    // A DISCOVER of the client that holds a lease: its lease, at once.
    let (addr, took) = lab.offer(0x35);
    assert_eq!(addr, bound);
    assert!(took < Duration::from_millis(100), "{took:?}");
    // The client's previous address, asked for again.
    let mut discover = relayed(MessageType::Discover, 0x36);
    discover.requested = Some(previous);
    let (offer, took) = lab.exchange(&discover).expect("an offer");
    assert_eq!(offer.yiaddr(), previous);
    assert!(took < Duration::from_millis(100), "{took:?}");
    assert!(fake.calls().is_empty(), "{:?}", fake.calls());
    assert_eq!(lab.server.conflicts().stats().parked, 0);
    lab.server.stop();
}

#[test]
fn a_reservation_is_probed_until_its_owner_uses_it_and_offered_even_when_it_answers() {
    // Client :20 has the reservation 192.0.2.20 in the world, not yet used.
    let reserved = ip("192.0.2.20");
    let fake = Fake::new(|_, _| Answer::InUse(Duration::ZERO, Some(SQUATTER)));
    let lab = lab_with(Some(fake.clone()), |_| {}, |_| {});
    let mut discover = relayed(MessageType::Discover, 0x20);
    discover.with_id = false;
    let (offer, _) = lab.exchange(&discover).expect("an offer");
    assert_eq!(
        offer.yiaddr(),
        reserved,
        "a reservation is offered all the same"
    );
    assert_eq!(fake.calls(), vec![reserved]);
    assert!(
        lab.row(reserved).is_none(),
        "a reservation is not abandoned"
    );
    assert_eq!(lab.server.conflicts().stats().reserved, 1);
    lab.server.stop();

    // Once the owner holds it, it is never probed.
    let fake = Fake::new(|_, _| Answer::Never);
    let lab = lab_with(
        Some(fake.clone()),
        |world| {
            let scope = world.scope_of(reserved).prefix;
            let now = Timestamp::now();
            let change = PendingChange::new(
                LeaseEventKind::Granted,
                world.vrf,
                scope,
                reserved,
                1,
                &mac(0x20),
                None,
                BindingState::Active,
                now,
                now.checked_add(Duration::from_secs(600)).expect("time"),
            );
            world.leases.apply(change.to_lease(NodeId(1), None));
        },
        |_| {},
    );
    let (offer, took) = lab.exchange(&discover).expect("an offer");
    assert_eq!(offer.yiaddr(), reserved);
    assert!(took < Duration::from_millis(100), "{took:?}");
    assert_eq!(fake.calls(), Vec::<Ipv4Addr>::new());
    lab.server.stop();
}

#[test]
fn without_a_probe_or_with_the_setting_off_offers_go_out_at_once() {
    let none = lab(None);
    assert!(!none.server.conflicts().available());
    let (_, took) = none.offer(0x37);
    assert!(took < Duration::from_millis(100), "{took:?}");
    none.server.stop();

    let unavailable = lab(Some(Arc::new(NoProbe)));
    assert!(!unavailable.server.conflicts().enabled());
    let (_, took) = unavailable.offer(0x37);
    assert!(took < Duration::from_millis(100), "{took:?}");
    unavailable.server.stop();

    let fake = Fake::new(|_, _| Answer::Never);
    let off = lab(Some(fake.clone()));
    off.server.conflicts().set_setting(Some(false));
    let (_, took) = off.offer(0x38);
    assert!(took < Duration::from_millis(100), "{took:?}");
    assert_eq!(fake.calls(), Vec::<Ipv4Addr>::new());
    // The profile's default (Lab: off) holds while the setting is unset.
    off.server.conflicts().set_setting(None);
    off.server.conflicts().set_profile_default(false);
    assert!(!off.server.conflicts().enabled());
    off.server.conflicts().set_profile_default(true);
    assert!(off.server.conflicts().enabled());
    off.server.stop();
}

#[test]
fn a_full_pending_table_offers_without_a_probe() {
    let fake = Fake::new(|_, _| Answer::Never);
    let lab = lab_with(
        Some(fake.clone()),
        |_| {},
        |config| config.conflict.pending = 1,
    );
    lab.relay
        .send_to(&relayed(MessageType::Discover, 0x39).bytes(), lab.address)
        .expect("send");
    // The second DISCOVER finds the only slot taken.
    let (_, took) = lab.offer(0x3a);
    assert!(took < Duration::from_millis(100), "{took:?}");
    assert_eq!(lab.server.conflicts().stats().unparked, 1);
    lab.server.stop();
}

#[test]
fn a_decline_holds_the_address_and_a_client_beyond_its_limit_is_dropped() {
    let fake = Fake::new(|_, _| Answer::Clear(Duration::ZERO));
    let lab = lab_with(
        Some(fake.clone()),
        |_| {},
        |config| config.conflict.decline_limit = 2,
    );
    let mut declined = Vec::new();
    for round in 0..3 {
        let (addr, _) = lab.offer(0x3b);
        lab.ack(0x3b, addr);
        wait_for("the lease is in the table", || {
            lab.row(addr)
                .is_some_and(|row| row.state == BindingState::Active)
        });
        lab.decline(0x3b, addr);
        if round < 2 {
            wait_for("the decline holds the address", || {
                lab.row(addr)
                    .is_some_and(|row| row.state == BindingState::Abandoned)
            });
            let row = lab.row(addr).expect("row");
            let held = row.ends.saturating_since(row.cltt);
            assert!(held >= Duration::from_secs(86_399), "{held:?}");
            assert!(!declined.contains(&addr));
            declined.push(addr);
        } else {
            // The third DECLINE within the window is dropped: the client keeps its lease.
            std::thread::sleep(Duration::from_millis(200));
            assert_eq!(
                lab.row(addr).map(|row| row.state),
                Some(BindingState::Active)
            );
        }
    }
    let metrics = lab.server.metrics();
    assert_eq!(metrics.dropped("rate_limited"), 1);
    assert_eq!(metrics.declines, 3);
    let stats = lab.server.conflicts().stats();
    assert_eq!((stats.declines, stats.limited), (2, 1));
    let mut reports = Vec::new();
    lab.server.conflicts().reports().drain(&mut reports);
    let audited: Vec<Ipv4Addr> = reports
        .iter()
        .filter(|report| report.kind == ReportKind::Decline)
        .map(|report| report.addr)
        .collect();
    assert_eq!(audited, declined);
    assert!(
        reports
            .iter()
            .all(|report| report.mac == Some(mac(0x3b)) || report.kind != ReportKind::Decline)
    );
    let draft = tenko_dhcp::conflict::report::decline_audit(&reports[0], 86_400);
    assert_eq!(draft.action, tenko_core::dhcp::audit::DECLINE);
    assert_eq!(
        draft.details.context.get("addr"),
        Some(&declined[0].to_string())
    );
    lab.server.stop();
}

#[test]
fn the_lease_batch_takes_a_decline_of_the_holder_and_a_conflict_only_of_a_free_address() {
    // The production committer refuses a change that would take an address another client
    // holds; a DECLINE's change belongs to no client and must still end the decliner's
    // binding, while a conflict never takes another client's binding.
    use tenko_dhcp::lease::batch::held_by_other;
    let world = World::new();
    let addr = ip("192.0.2.150");
    let scope = world.scope_of(addr).prefix;
    let now = Timestamp::now();
    let later = now.checked_add(Duration::from_secs(3_600)).expect("time");
    let bound = PendingChange::new(
        LeaseEventKind::Granted,
        world.vrf,
        scope,
        addr,
        1,
        &mac(0x3c),
        None,
        BindingState::Active,
        now,
        later,
    )
    .to_lease(NodeId(1), None);
    let change = |kind, htype, chaddr: &[u8]| {
        PendingChange::new(
            kind,
            world.vrf,
            scope,
            addr,
            htype,
            chaddr,
            None,
            BindingState::Abandoned,
            now,
            later,
        )
    };
    let declined = change(LeaseEventKind::Declined, 0, &[]);
    assert!(!held_by_other(&declined, Some(&bound), now));
    // A conflict never takes a declined address before its hold ends.
    let abandoned = declined.to_lease(NodeId(1), Some(&bound));
    let conflict = change(LeaseEventKind::Conflict, 1, &SQUATTER);
    assert!(held_by_other(&conflict, Some(&abandoned), now));
    let conflict = change(LeaseEventKind::Conflict, 1, &SQUATTER);
    assert!(held_by_other(&conflict, Some(&bound), now));
    assert!(!held_by_other(&conflict, None, now));
}

#[test]
fn offers_wait_in_the_table_and_not_in_a_worker() {
    // One worker, 40 DISCOVERs at once, a probe that never answers: every offer arrives at
    // about the cap, not one cap after another.
    let fake = Fake::new(|_, _| Answer::Never);
    let lab = lab(Some(fake.clone()));
    let started = Instant::now();
    // Client :66 is the world's denied MAC address, so the clients start above it.
    for client in 0x70..0x98 {
        lab.relay
            .send_to(&relayed(MessageType::Discover, client).bytes(), lab.address)
            .expect("send");
    }
    let mut seen = HashMap::new();
    let mut buf = [0u8; 1500];
    while seen.len() < 40 {
        let Ok((len, _)) = lab.relay.recv_from(&mut buf) else {
            panic!(
                "{} offers of 40; {:?}, {:?}, {} probes",
                seen.len(),
                lab.server.conflicts().stats(),
                lab.server.metrics().dropped,
                fake.calls().len()
            );
        };
        let message = Message::parse(&buf[..len]).expect("parse");
        seen.insert(message.xid(), started.elapsed());
    }
    let last = seen.values().max().copied().unwrap_or_default();
    assert!(last <= CAP + SLACK * 2, "{last:?}");
    assert_eq!(fake.calls().len(), 40);
    lab.server.stop();
}

fn percentile(sorted: &[Duration], q: f64) -> Duration {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "an index into a short list"
    )]
    let at = ((sorted.len() as f64 - 1.0) * q).round() as usize;
    sorted[at]
}

#[test]
fn m35_offer_delay_and_renewals() {
    // M35's first half: a probe that never answers, new clients one after another (25, or
    // TENKO_M35_CLIENTS up to 90, the pool's size), then their renewals; the same renewals
    // without conflict detection as the baseline.
    let count: u8 = std::env::var("TENKO_M35_CLIENTS")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(25)
        .clamp(1, 90);
    let fake = Fake::new(|_, _| Answer::Never);
    let lab = lab(Some(fake.clone()));
    let clients: Vec<u8> = (0x80..0x80 + count).collect();
    let mut offers = Vec::new();
    let mut leases = Vec::new();
    for client in &clients {
        let (addr, took) = lab.offer(*client);
        offers.push(took);
        lab.ack(*client, addr);
        leases.push((*client, addr));
    }
    let mut renewals: Vec<Duration> = leases
        .iter()
        .map(|(client, addr)| lab.renew(*client, *addr))
        .collect();
    assert_eq!(
        fake.calls().len(),
        clients.len(),
        "every new address probed once"
    );
    lab.server.stop();

    let baseline = lab_with(None, |_| {}, |_| {});
    let mut plain = Vec::new();
    for client in &clients {
        let (addr, _) = baseline.offer(*client);
        baseline.ack(*client, addr);
        plain.push(baseline.renew(*client, addr));
    }
    baseline.server.stop();

    offers.sort_unstable();
    renewals.sort_unstable();
    plain.sort_unstable();
    println!(
        "M35 offer delay, new addresses, probe never answers, cap {} ms: n={} min {:?} p50 {:?} p99 {:?} max {:?}",
        CAP.as_millis(),
        offers.len(),
        offers[0],
        percentile(&offers, 0.5),
        percentile(&offers, 0.99),
        offers[offers.len() - 1]
    );
    println!(
        "M35 renewals with conflict detection: n={} p50 {:?} p99 {:?} max {:?}; without: p50 {:?} p99 {:?} max {:?}",
        renewals.len(),
        percentile(&renewals, 0.5),
        percentile(&renewals, 0.99),
        renewals[renewals.len() - 1],
        percentile(&plain, 0.5),
        percentile(&plain, 0.99),
        plain[plain.len() - 1]
    );
    assert!(offers[offers.len() - 1] <= CAP + SLACK, "{offers:?}");
    assert!(offers[0] >= AT_THE_CAP, "{offers:?}");
    assert!(
        renewals[renewals.len() - 1] < Duration::from_millis(100),
        "renewals are not probed: {renewals:?}"
    );
}

#[test]
fn the_scan_probe_finds_a_host_that_answers_and_clears_one_that_does_not() {
    // The production probe over ICMP on this host: loopback answers; an address of
    // TEST-NET-1 (RFC 5737) does not. A host without ICMP has no probe.
    let probe = tenko_dhcp::conflict::scan::ScanProbe::detect();
    if !ConflictProbe::available(&probe) {
        eprintln!("no probe on this host: {}", probe.describe());
        return;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let answer = probe.probe(LOOPBACK, Duration::from_secs(1)).await;
        assert!(
            matches!(
                answer,
                ProbeOutcome::InUse { .. } | ProbeOutcome::Unavailable
            ),
            "{answer:?}"
        );
        let started = Instant::now();
        let quiet = tokio::time::timeout(
            CAP + Duration::from_secs(2),
            probe.probe(ip("192.0.2.254"), CAP),
        )
        .await
        .expect("the probe ends");
        assert!(
            matches!(quiet, ProbeOutcome::Clear | ProbeOutcome::Unavailable),
            "{quiet:?}"
        );
        eprintln!(
            "scan probe ({}): loopback {answer:?}, TEST-NET {quiet:?} in {:?}",
            probe.describe(),
            started.elapsed()
        );
    });
}

/// The client of M35's lab half and E27's conflict rows (`bench/phase3-dhcp/results/
/// 2026-10-22-m35-conflict-probe.md`): a relay agent on the node in front of `tenko serve`
/// with the `dhcp` and `probe` roles, ignored unless `TENKO_LAB_SERVER` names the listener.
///
/// `TENKO_LAB_SERVER` (the listener, `127.0.0.1:16767`), `TENKO_LAB_RELAY_PORT` (the
/// server's `[dhcp] relay_port`), `TENKO_LAB_SUBNET` (option 118, the scope's network),
/// `TENKO_LAB_SQUATTERS` (the squatted addresses, comma-separated) and `TENKO_LAB_CLIENTS`
/// (how many new clients run DISCOVER, OFFER, REQUEST and ACK, at most 200). Each client is
/// timed from its DISCOVER to the OFFER; then each renews and the renewal is timed. The
/// test fails when an OFFER names a squatted address. It prints the figures; the operator
/// checks the abandoned rows through `GET /dhcp/leases`.
#[test]
#[ignore = "the lab run of M35: needs a tenko server with the dhcp and probe roles"]
fn lab_m35_squatters_are_skipped() {
    let Ok(server) = std::env::var("TENKO_LAB_SERVER") else {
        return;
    };
    let server: SocketAddrV4 = server.parse().expect("TENKO_LAB_SERVER");
    let env = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name}"));
    let relay_port: u16 = env("TENKO_LAB_RELAY_PORT").parse().expect("a port");
    let subnet: Ipv4Addr = env("TENKO_LAB_SUBNET").parse().expect("an address");
    let squatters: Vec<Ipv4Addr> = env("TENKO_LAB_SQUATTERS")
        .split(',')
        .map(|text| text.trim().parse().expect("an address"))
        .collect();
    let count: u8 = env("TENKO_LAB_CLIENTS").parse().expect("a count");
    let relay = UdpSocket::bind(SocketAddrV4::new(*server.ip(), relay_port)).expect("bind");
    relay
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let ask = |kind, client| {
        let mut ask = Ask::new(kind, client);
        ask.giaddr = Some(*server.ip());
        ask.subnet = Some(subnet);
        ask
    };
    let exchange = |ask: &Ask, want: MessageType| -> Option<(Ipv4Addr, Duration)> {
        let started = Instant::now();
        relay.send_to(&ask.bytes(), server).expect("send");
        let mut buf = [0u8; 1500];
        loop {
            let (len, _) = relay.recv_from(&mut buf).ok()?;
            let message = Message::parse(&buf[..len]).ok()?;
            if message.xid() == 0x5e00_5300 | u32::from(ask.client)
                && message.message_type().ok()? == Some(want)
            {
                return Some((message.yiaddr(), started.elapsed()));
            }
        }
    };
    let mut offers = Vec::new();
    let mut leases = Vec::new();
    let mut squatted = 0;
    for client in 1..=count {
        let Some((addr, took)) = exchange(&ask(MessageType::Discover, client), MessageType::Offer)
        else {
            println!("client {client}: no offer");
            continue;
        };
        if squatters.contains(&addr) {
            squatted += 1;
        }
        println!("client {client}: offer {addr} after {took:?}");
        offers.push(took);
        let mut request = ask(MessageType::Request, client);
        request.requested = Some(addr);
        request.server_id = Some(*server.ip());
        if exchange(&request, MessageType::Ack).is_some() {
            leases.push((client, addr));
        }
    }
    let mut renewals = Vec::new();
    for (client, addr) in &leases {
        let mut renew = ask(MessageType::Request, *client);
        renew.ciaddr = Some(*addr);
        if let Some((_, took)) = exchange(&renew, MessageType::Ack) {
            renewals.push(took);
        }
    }
    // The first client declines its address (E27: a DECLINE quarantines it).
    if let Some((client, addr)) = leases.first() {
        let mut decline = ask(MessageType::Decline, *client);
        decline.requested = Some(*addr);
        decline.server_id = Some(*server.ip());
        relay.send_to(&decline.bytes(), server).expect("send");
        println!("client {client}: declined {addr}");
    }
    offers.sort_unstable();
    renewals.sort_unstable();
    if !offers.is_empty() && !renewals.is_empty() {
        println!(
            "offers n={} min {:?} p50 {:?} p99 {:?} max {:?}; renewals n={} p50 {:?} p99 {:?} max {:?}; offers of squatted addresses {squatted}",
            offers.len(),
            offers[0],
            percentile(&offers, 0.5),
            percentile(&offers, 0.99),
            offers[offers.len() - 1],
            renewals.len(),
            percentile(&renewals, 0.5),
            percentile(&renewals, 0.99),
            renewals[renewals.len() - 1],
        );
    }
    assert_eq!(squatted, 0, "an offer named a squatted address");
}
