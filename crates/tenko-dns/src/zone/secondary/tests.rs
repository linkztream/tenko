use std::net::Ipv4Addr;

use tenko_core::{
    Principal,
    dns::{RecordData, SerialPolicy, SoaDefaults, TransferPolicy, UpdatePolicy, ZoneScope},
};

use super::*;
use crate::xfr::inbound::Step;

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn stamp() -> Stamp {
    Stamp::new(Timestamp::now(), Principal::system(SystemComponent::Dns))
}

fn secondary() -> Zone {
    Zone {
        id: ZoneId::generate(),
        name: name("example.test"),
        kind: ZoneKind::Secondary,
        tenant: None,
        scopes: vec![ZoneScope::default_scope()],
        serial: SerialPolicy::default(),
        soa: SoaDefaults::new(name("ns.example.test"), name("hostmaster.example.test")),
        transfer: TransferPolicy::default(),
        update: UpdatePolicy::default(),
        dnssec: tenko_core::dns::DnssecPolicy::default(),
        source: None,
        reverse_of: None,
        catalog: false,
        description: None,
        created: stamp(),
        updated: stamp(),
    }
}

fn soa(serial: u32) -> RecordData {
    RecordData::Soa {
        mname: name("ns.example.test"),
        rname: name("hostmaster.example.test"),
        serial,
        refresh: 60,
        retry: 10,
        expire: 3600,
        minimum: 5,
    }
}

fn record(owner: &str, ttl: u32, data: &RecordData) -> Record {
    Record {
        name: name(owner),
        rtype: data.rtype(),
        class: 1,
        ttl,
        rdata: Rdata::from_data(data),
    }
}

fn a(last: u8) -> RecordData {
    RecordData::A {
        address: Ipv4Addr::new(192, 0, 2, last),
    }
}

fn full(serial: u32, hosts: &[u8]) -> Fetched {
    let mut records = vec![
        record("example.test", 60, &soa(serial)),
        record(
            "example.test",
            60,
            &RecordData::Ns {
                host: name("ns.example.test"),
            },
        ),
    ];
    for host in hosts {
        records.push(record("www.example.test", 300, &a(*host)));
    }
    Fetched::Full { records, bytes: 0 }
}

fn copy_of(zone: &Zone, fetched: &Fetched) -> BTreeMap<(DnsName, Rtype), (RrSet, Revision)> {
    target(zone, &BTreeMap::new(), fetched, &stamp())
        .expect("a copy")
        .into_iter()
        .map(|(key, set)| (key, (set, Revision(1))))
        .collect()
}

#[test]
fn an_axfr_becomes_rrsets_of_the_origin_transfer() {
    let zone = secondary();
    let after = target(&zone, &BTreeMap::new(), &full(7, &[1, 2, 2]), &stamp()).expect("target");
    assert_eq!(after.len(), 3, "SOA, NS and one A set");
    let www = &after[&(name("www.example.test"), Rtype::A)];
    assert_eq!(www.rdata.len(), 2, "a duplicate record counts once");
    assert!(after.values().all(|set| set.origin == Origin::Transfer));
    assert_eq!(
        super::super::soa_serial(&after[&(name("example.test"), Rtype::SOA)]),
        Some(7)
    );
    // A transfer without the apex SOA is refused; a record outside the zone is left out.
    let Fetched::Full { mut records, .. } = full(7, &[1]) else {
        unreachable!()
    };
    records.push(record("www.other.test", 300, &a(9)));
    let outside = target(
        &zone,
        &BTreeMap::new(),
        &Fetched::Full {
            records: records.clone(),
            bytes: 0,
        },
        &stamp(),
    )
    .expect("target");
    assert!(!outside.contains_key(&(name("www.other.test"), Rtype::A)));
    records.remove(0);
    let error = target(
        &zone,
        &BTreeMap::new(),
        &Fetched::Full { records, bytes: 0 },
        &stamp(),
    )
    .expect_err("no SOA");
    assert_eq!(error.code, codes::TRANSFER_FAILED);
}

#[test]
fn an_ixfr_applies_its_steps_to_the_copy() {
    let zone = secondary();
    let before = copy_of(&zone, &full(7, &[1, 2]));
    let delta = Fetched::Delta {
        steps: vec![
            Step {
                removed: vec![
                    record("example.test", 60, &soa(7)),
                    record("www.example.test", 300, &a(1)),
                ],
                added: vec![
                    record("example.test", 60, &soa(8)),
                    record("mail.example.test", 300, &a(25)),
                ],
            },
            Step {
                removed: vec![record("example.test", 60, &soa(8))],
                added: vec![
                    record("example.test", 60, &soa(9)),
                    record("www.example.test", 300, &a(3)),
                ],
            },
        ],
        soa: record("example.test", 60, &soa(9)),
        bytes: 0,
    };
    let after = target(&zone, &before, &delta, &stamp()).expect("target");
    let www: Vec<&Rdata> = after[&(name("www.example.test"), Rtype::A)]
        .rdata
        .iter()
        .collect();
    assert_eq!(
        www,
        vec![&Rdata::from_data(&a(2)), &Rdata::from_data(&a(3))]
    );
    assert!(after.contains_key(&(name("mail.example.test"), Rtype::A)));
    assert_eq!(
        super::super::soa_serial(&after[&(name("example.test"), Rtype::SOA)]),
        Some(9)
    );
    // The diff holds the changed sets only: the SOA, www and mail.
    let changes = diff(&before, &after);
    assert_eq!(changes.len(), 3);
    assert!(changes.iter().any(|(old, new)| {
        old.is_none()
            && new
                .as_ref()
                .is_some_and(|set| set.name == name("mail.example.test"))
    }));
}

#[test]
fn removing_the_last_record_drops_the_rrset() {
    let zone = secondary();
    let before = copy_of(&zone, &full(7, &[1]));
    let delta = Fetched::Delta {
        steps: vec![Step {
            removed: vec![
                record("example.test", 60, &soa(7)),
                record("www.example.test", 300, &a(1)),
            ],
            added: vec![record("example.test", 60, &soa(8))],
        }],
        soa: record("example.test", 60, &soa(8)),
        bytes: 0,
    };
    let after = target(&zone, &before, &delta, &stamp()).expect("target");
    assert!(!after.contains_key(&(name("www.example.test"), Rtype::A)));
    let changes = diff(&before, &after);
    assert!(
        changes.iter().any(|(old, new)| new.is_none()
            && old.as_ref().is_some_and(|(set, _)| set.rtype == Rtype::A))
    );
}

#[test]
fn a_secondary_zone_is_read_only_and_a_primary_is_not() {
    let mut zone = secondary();
    let error = check_writable(&zone).expect_err("read-only");
    assert!(error.is(codes::ZONE_SECONDARY), "{error:?}");
    assert_eq!(error.coded().status, 409);
    zone.kind = ZoneKind::Primary;
    assert!(check_writable(&zone).is_ok());
}

#[test]
fn the_soa_timers_of_a_copy_read_from_its_soa() {
    let timers = Timers::of(&Rdata::from_data(&soa(1)));
    assert_eq!(
        (timers.refresh, timers.retry, timers.expire),
        (60, 10, 3600)
    );
    let fallback = Timers::of(&Rdata::from_data(&a(1)));
    assert_eq!(fallback.refresh, Timers::DEFAULT.refresh);
    let at = Timestamp::now();
    assert_eq!(after(at, 60).saturating_since(at), Duration::from_secs(60));
}

#[test]
fn xot_on_the_default_port_goes_to_853() {
    let mut server = PrimaryServer {
        address: std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
        port: 53,
        key: None,
        xot: true,
        tls_name: None,
    };
    assert_eq!(primary_address(&server).port(), 853);
    server.port = 8530;
    assert_eq!(primary_address(&server).port(), 8530);
    server.xot = false;
    server.port = 53;
    assert_eq!(primary_address(&server).port(), 53);
}

fn held(serial: u32) -> ZoneState {
    ZoneState::new(Some(serial), Vec::new(), None)
}

const TIMERS: Timers = Timers {
    refresh: 3600,
    retry: 600,
    expire: 86_400,
};

/// RFC 1996 section 4.4: a NOTIFY that arrives while a transfer runs is not lost; the
/// zone is refreshed again once the transfer ends, unless it ended at the serial the
/// NOTIFY announced or a later one.
#[test]
fn a_notify_during_a_running_transfer_refreshes_the_zone_again() {
    let now = Timestamp::now();
    let mut zone = held(1);
    zone.running = true;
    zone.request(Some(2), now);
    zone.finish(Some(Refreshed::Serial(1)), now, TIMERS);
    assert!(!zone.running);
    assert!(zone.next_refresh <= now, "the NOTIFY for serial 2 was lost");
    assert_eq!(zone.requested, None);
    // That refresh reaches serial 2: the refresh timer applies.
    zone.running = true;
    zone.finish(Some(Refreshed::Serial(2)), now, TIMERS);
    assert_eq!(zone.next_refresh, after(now, TIMERS.refresh));
}

#[test]
fn a_notify_the_running_transfer_covers_needs_no_second_refresh() {
    let now = Timestamp::now();
    let mut zone = held(1);
    zone.running = true;
    zone.request(Some(2), now);
    zone.request(Some(3), now);
    zone.finish(Some(Refreshed::Serial(3)), now, TIMERS);
    assert_eq!(zone.next_refresh, after(now, TIMERS.refresh));
    // A request without a serial (the API, a NOTIFY without SOA) always refreshes again.
    zone.running = true;
    zone.request(None, now);
    zone.request(Some(3), now);
    zone.finish(Some(Refreshed::Serial(3)), now, TIMERS);
    assert!(zone.next_refresh <= now);
    // A failed transfer retries on its own timer, or at once when a NOTIFY came.
    zone.running = true;
    zone.finish(Some(Refreshed::Failed), now, TIMERS);
    assert_eq!(zone.next_refresh, after(now, TIMERS.retry));
    zone.running = true;
    zone.request(Some(4), now);
    zone.finish(None, now, TIMERS);
    assert!(zone.next_refresh <= now);
}

#[test]
fn a_request_while_idle_makes_the_zone_due_without_a_second_refresh() {
    let now = Timestamp::now();
    let mut zone = held(1);
    zone.next_refresh = after(now, 3600);
    zone.request(Some(2), now);
    assert!(zone.next_refresh <= now);
    assert_eq!(zone.requested, None);
}

/// RFC 1996 section 3.10: an unsigned NOTIFY may be spoofed. The first refreshes at once;
/// one that brought nothing new leaves a pause, doubled each time up to the bound, during
/// which a further unsigned NOTIFY waits instead of refreshing back to back. It is never
/// dropped: the zone is due when the pause ends.
#[test]
fn unsigned_notify_messages_that_bring_nothing_back_off() {
    let now = Timestamp::now();
    let mut zone = held(1);
    zone.next_refresh = after(now, 3600);
    zone.request_unsigned(None, now);
    assert!(zone.next_refresh <= now, "the first one refreshes at once");
    let mut pause = NOTIFY_QUIET_MIN;
    for _ in 0..12 {
        zone.running = true;
        zone.finish(Some(Refreshed::Serial(1)), now, TIMERS);
        pause = (pause * 2).min(NOTIFY_QUIET_MAX);
        assert_eq!(zone.next_refresh, after(now, TIMERS.refresh));
        zone.request_unsigned(None, now);
        let due = now.checked_add(pause).expect("time");
        assert_eq!(zone.next_refresh, due, "kept for the end of the pause");
    }
    assert_eq!(pause, NOTIFY_QUIET_MAX, "the pause has its bound");
    // A refresh that brings a new serial ends the backoff.
    zone.running = true;
    zone.finish(Some(Refreshed::Serial(2)), now, TIMERS);
    zone.request_unsigned(Some(3), now);
    assert_eq!(
        zone.next_refresh,
        now.checked_add(NOTIFY_QUIET_MIN).expect("time")
    );
    // A signed NOTIFY, or the API, is not held back.
    zone.request(Some(3), now);
    assert!(zone.next_refresh <= now);
}

/// An unsigned NOTIFY during a running transfer is kept (RFC 1996 section 4.4) and the
/// zone refreshed once more when the pause allows; a signed one in the same transfer
/// refreshes at once.
#[test]
fn an_unsigned_notify_during_a_transfer_is_kept_for_the_end_of_the_pause() {
    let now = Timestamp::now();
    let mut zone = held(1);
    let quiet = now.checked_add(Duration::from_secs(40)).expect("time");
    zone.backoff.quiet_until = Some(quiet);
    zone.running = true;
    zone.request_unsigned(Some(2), now);
    zone.finish(Some(Refreshed::Serial(1)), now, TIMERS);
    assert_eq!(zone.next_refresh, quiet, "not lost, not at once");
    zone.running = true;
    zone.request_unsigned(Some(2), now);
    zone.request(Some(2), now);
    zone.finish(Some(Refreshed::Serial(1)), now, TIMERS);
    assert!(zone.next_refresh <= now, "a signed NOTIFY came as well");
}

fn fetched(serial: u32) -> Fetched {
    full(serial, &[1])
}

fn held_soa(serial: u32) -> Held {
    Held {
        serial,
        ttl: 60,
        rdata: Rdata::from_data(&soa(serial)).as_bytes().to_vec(),
    }
}

/// RFC 1982: a transfer with an older serial than the copy's is not applied, unless an
/// operator asked for it through the API.
#[test]
fn a_transfer_with_an_older_serial_is_not_applied() {
    let held = held_soa(10);
    let error = older_serial(Some(&held), &fetched(5), false).expect_err("older");
    assert_eq!(error.code, TRANSFER_OLDER_SERIAL);
    assert!(error.detail.contains("serial 5"), "{}", error.detail);
    assert_eq!(
        older_serial(Some(&held), &fetched(5), true),
        Ok(()),
        "forced"
    );
    assert_eq!(
        older_serial(Some(&held), &fetched(10), false),
        Ok(()),
        "the same serial"
    );
    assert_eq!(older_serial(Some(&held), &fetched(11), false), Ok(()));
    assert_eq!(
        older_serial(None, &fetched(5), false),
        Ok(()),
        "no copy yet"
    );
    // Across the wrap: 1 comes after 4,294,967,295.
    let wrap = held_soa(u32::MAX);
    assert_eq!(older_serial(Some(&wrap), &fetched(1), false), Ok(()));
    assert!(older_serial(Some(&held_soa(1)), &fetched(u32::MAX), false).is_err());
}

/// The API's "Transfer now" takes the forced flag with it; the next refresh consumes it.
#[test]
fn transfer_now_forces_the_next_refresh_only() {
    let now = Timestamp::now();
    let mut zone = held(1);
    zone.force(now);
    assert!(zone.forced && zone.next_refresh <= now);
    assert!(std::mem::take(&mut zone.forced));
    assert!(!zone.forced);
}

fn row(zone: Zone) -> super::super::ZoneRow {
    super::super::ZoneRow {
        zone,
        revision: Revision(1),
    }
}

/// RFC 9432 section 7: a catalog adds no root, no zone at or below another tenant's zone,
/// not itself, and no more than the bound.
#[test]
fn a_catalog_adds_only_names_it_may() {
    let mut catalog = secondary();
    catalog.name = name("catalog.example.test");
    catalog.catalog = true;
    let mut foreign = secondary();
    foreign.name = name("other.example.net");
    foreign.tenant = Some(tenko_core::id::TenantId::generate());
    let mut own = secondary();
    own.name = name("own.example.test");
    let rows = [row(foreign), row(own)];
    let members = vec![
        DnsName::root(),
        name("catalog.example.test"),
        name("other.example.net"),
        name("deep.other.example.net"),
        name("member.example.test"),
        name("sub.own.example.test"),
    ];
    let admitted = admit_members(&catalog, members.clone(), &rows, 100).expect("under the bound");
    // `sub.own.example.test` lies below a zone of the tenant that the catalog does not hold.
    assert_eq!(admitted, vec![name("member.example.test")]);
    assert!(
        admit_members(&catalog, members, &rows, 5).is_err(),
        "over the bound"
    );
    // A top-level domain, a name below the catalog, the parent of another tenant's zone.
    let more = vec![
        name("test"),
        name("x.catalog.example.test"),
        name("example.net"),
    ];
    assert_eq!(admit_members(&catalog, more, &rows, 100), Ok(Vec::new()));
}

/// A name below one of the catalog's own member zones may be a member too.
#[test]
fn a_catalog_may_add_below_its_own_members() {
    let mut catalog = secondary();
    catalog.name = name("catalog.example.test");
    catalog.catalog = true;
    let mut member = secondary();
    member.name = name("held.example.test");
    member.description = Some(format!("{MEMBER_OF}catalog.example.test"));
    let rows = [row(member)];
    assert_eq!(
        admit_members(&catalog, vec![name("sub.held.example.test")], &rows, 100),
        Ok(vec![name("sub.held.example.test")])
    );
}

/// A kept unsigned NOTIFY never puts the refresh later than the SOA timers would.
#[test]
fn a_kept_unsigned_notify_keeps_a_sooner_timer() {
    let now = Timestamp::now();
    let mut zone = held(1);
    zone.backoff.quiet_until = Some(now.checked_add(Duration::from_secs(300)).expect("time"));
    zone.running = true;
    zone.request_unsigned(Some(2), now);
    let short = Timers {
        refresh: 60,
        retry: 60,
        expire: 86_400,
    };
    zone.finish(Some(Refreshed::Serial(1)), now, short);
    assert_eq!(zone.next_refresh, after(now, 60));
}

/// The refresh state machine under random sequences of NOTIFY messages (signed and not),
/// API requests, transfers and their outcomes: a request is never lost. A request made
/// while no transfer runs makes the zone due within the pause bound, and the refresh that
/// starts next answers it; a request made while a transfer runs that the transfer's serial
/// does not cover makes the zone due again within the bound when it ends.
#[test]
fn no_request_is_lost_under_random_sequences() {
    let mut seed: u64 = 0x5eed_1234_abcd_0001;
    let mut next = move || {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        seed >> 33
    };
    let base = Timestamp::now();
    let bound = |now: Timestamp| now.checked_add(NOTIFY_QUIET_MAX).expect("time");
    for _ in 0..2_000 {
        let mut zone = held(1);
        zone.next_refresh = after(base, 3600);
        let mut now = base;
        // The serial a request asked for that no transfer has reached yet; None asks for
        // any refresh.
        let mut pending: Option<Option<u32>> = None;
        for _ in 0..40 {
            now = now
                .checked_add(Duration::from_millis(next() % 5_000))
                .expect("time");
            let serial = (next() % 3 != 0).then(|| u32::try_from(next() % 8).unwrap_or(0));
            match next() % 6 {
                0 => {
                    zone.request(serial, now);
                    pending = Some(serial);
                }
                1 | 2 => {
                    zone.request_unsigned(serial, now);
                    pending = Some(serial);
                }
                3 => {
                    zone.force(now);
                    pending = Some(None);
                }
                4 if !zone.running && zone.next_refresh <= now => {
                    // The refresh that starts answers every request made so far.
                    zone.running = true;
                    pending = None;
                }
                5 if zone.running => {
                    let reached = u32::try_from(next() % 8).unwrap_or(0);
                    let outcome = match next() % 3 {
                        0 => Some(Refreshed::Failed),
                        1 => None,
                        _ => Some(Refreshed::Serial(reached)),
                    };
                    zone.finish(outcome, now, TIMERS);
                    let covered = |asked: Option<u32>| {
                        asked.is_some_and(|asked| {
                            zone.serial
                                .is_some_and(|held| crate::xfr::out::serial_ge(held, asked))
                        })
                    };
                    if let Some(asked) = pending {
                        if covered(asked) {
                            pending = None;
                        } else {
                            assert!(
                                zone.next_refresh <= bound(now),
                                "a request was lost at the end of a transfer"
                            );
                        }
                    }
                }
                _ => {}
            }
            if pending.is_some() && !zone.running {
                assert!(
                    zone.next_refresh <= bound(now),
                    "a pending request waits past the bound"
                );
            }
        }
    }
}

/// A root zone (of this tenant or another) holds every name, and says nothing about a
/// member: it refuses none.
#[test]
fn a_root_zone_does_not_refuse_every_member() {
    let mut catalog = secondary();
    catalog.name = name("catalog.example.test");
    catalog.catalog = true;
    let mut root = secondary();
    root.name = DnsName::root();
    let mut foreign_root = secondary();
    foreign_root.name = DnsName::root();
    foreign_root.tenant = Some(tenko_core::id::TenantId::generate());
    let rows = [row(root), row(foreign_root)];
    assert_eq!(
        admit_members(&catalog, vec![name("member.example.test")], &rows, 100),
        Ok(vec![name("member.example.test")])
    );
}
