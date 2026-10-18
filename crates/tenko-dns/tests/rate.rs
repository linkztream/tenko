//! Response rate limiting and the per-client query limit: the token buckets of
//! `Limiter` driven by simulated time (every call passes an `Instant` built from one start),
//! the keys RRL counts by, the client prefixes it groups by, the slip, the exemptions and the
//! limiter that admits everything.
//!
//! The counters are process-wide statics, so the tests compare deltas, and every test holds
//! one lock while it runs so that the tests of one process (plain `cargo test` uses threads,
//! nextest one process each) never see each other's counts.
//!
//! Test data stays inside the documentation ranges (IPv4 192.0.2.0/24, 198.51.100.0/24 and
//! 203.0.113.0/24, IPv6 `2001:db8::/32`) and names under `example.test`.

use std::{
    net::IpAddr,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use tenko_dns::rate::{
    RateDecision, RateLimiter, ResponseKey, ResponseKind, Unlimited,
    limiter::{
        CLIENT_LIMITED_COUNTER, ClientLimit, LimitSettings, Limiter, RRL_DROPPED_COUNTER,
        RRL_SLIPPED_COUNTER, RrlSettings,
    },
};

const SEND: RateDecision = RateDecision::Send;
const SLIP: RateDecision = RateDecision::Slip;
const DROP: RateDecision = RateDecision::Drop;

static SERIAL: Mutex<()> = Mutex::new(());

/// A limiter, the instant its simulated clock starts at, and the lock on the counters.
struct Rig {
    limiter: Limiter,
    start: Instant,
    _serial: MutexGuard<'static, ()>,
}

impl Rig {
    fn new(settings: LimitSettings) -> Self {
        Self::build(settings, None)
    }

    fn with_known(
        settings: LimitSettings,
        known: Arc<dyn Fn(IpAddr) -> bool + Send + Sync>,
    ) -> Self {
        Self::build(settings, Some(known))
    }

    fn build(
        settings: LimitSettings,
        known: Option<Arc<dyn Fn(IpAddr) -> bool + Send + Sync>>,
    ) -> Self {
        let serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        let mut limiter = Limiter::new(settings);
        if let Some(known) = known {
            limiter = limiter.with_known_exempt(known);
        }
        // Taken after the limiter, so that no instant of the test lies before its clock.
        let start = Instant::now();
        Self {
            limiter,
            start,
            _serial: serial,
        }
    }

    fn at(&self, millis: u64) -> Instant {
        self.start + Duration::from_millis(millis)
    }

    fn response(&self, client: IpAddr, key: &ResponseKey<'_>, millis: u64) -> RateDecision {
        self.limiter.admit_response(client, key, self.at(millis))
    }

    fn query(&self, client: IpAddr, millis: u64) -> bool {
        self.limiter.admit_query(client, self.at(millis))
    }

    /// `count` identical responses at one instant.
    fn flood(
        &self,
        client: IpAddr,
        key: &ResponseKey<'_>,
        count: usize,
        millis: u64,
    ) -> Vec<RateDecision> {
        (0..count)
            .map(|_| self.response(client, key, millis))
            .collect()
    }
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

/// The lowercase wire form of a name in text.
fn wire(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.').filter(|label| !label.is_empty()) {
        out.push(u8::try_from(label.len()).expect("label length"));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn key(kind: ResponseKind, name: &[u8], qtype: u16) -> ResponseKey<'_> {
    ResponseKey {
        kind,
        name,
        qtype,
        udp: true,
    }
}

fn answer(name: &[u8]) -> ResponseKey<'_> {
    key(ResponseKind::Answer, name, 1)
}

fn rrl_only(rrl: RrlSettings) -> LimitSettings {
    LimitSettings {
        rrl: Some(rrl),
        // Many slots, so that two keys of a test never meet in one slot.
        table: 1 << 18,
        ..LimitSettings::default()
    }
}

fn per_client(queries_per_second: u32, burst: u32) -> LimitSettings {
    LimitSettings {
        client: Some(ClientLimit {
            queries_per_second,
            burst,
        }),
        table: 1 << 18,
        ..LimitSettings::default()
    }
}

/// How many of `decisions` are `Send`, `Slip` and `Drop`.
fn tally(decisions: &[RateDecision]) -> (usize, usize, usize) {
    let count = |wanted| decisions.iter().filter(|got| **got == wanted).count();
    (count(SEND), count(SLIP), count(DROP))
}

fn dropped(kind: ResponseKind) -> u64 {
    RRL_DROPPED_COUNTER.get(kind.index())
}

fn slipped() -> u64 {
    RRL_SLIPPED_COUNTER.get()
}

fn limited() -> u64 {
    CLIENT_LIMITED_COUNTER.get()
}

fn delta(before: u64, after: u64) -> usize {
    usize::try_from(after - before).expect("fits")
}

// ---- The reflection pattern ----

const VICTIM: &str = "198.51.100.7";

#[test]
fn a_reflection_flood_is_limited_to_the_rate_and_slips_every_second_response() {
    let rig = Rig::new(rrl_only(RrlSettings {
        responses_per_second: 5,
        slip: 2,
        ..RrlSettings::default()
    }));
    let name = wire("victim.example.test");
    let key = answer(&name);
    let (dropped_before, slipped_before) = (dropped(ResponseKind::Answer), slipped());

    let decisions = rig.flood(ip(VICTIM), &key, 1_000, 0);

    assert!(decisions[..5].iter().all(|decision| *decision == SEND));
    for (at, decision) in decisions[5..].iter().enumerate() {
        let expected = if at % 2 == 0 { DROP } else { SLIP };
        assert_eq!(*decision, expected, "limited response {}", at + 1);
    }
    assert_eq!(tally(&decisions), (5, 497, 498));
    assert_eq!(delta(dropped_before, dropped(ResponseKind::Answer)), 498);
    assert_eq!(delta(slipped_before, slipped()), 497);
}

#[test]
fn a_flood_spread_over_a_second_gets_only_the_first_seconds_tokens_through() {
    let rig = Rig::new(rrl_only(RrlSettings {
        responses_per_second: 5,
        ..RrlSettings::default()
    }));
    let name = wire("victim.example.test");
    let key = answer(&name);
    let (dropped_before, slipped_before) = (dropped(ResponseKind::Answer), slipped());

    let decisions: Vec<RateDecision> = (0..1_000)
        .map(|millis| rig.response(ip(VICTIM), &key, millis))
        .collect();

    let (sent, slips, drops) = tally(&decisions);
    // The bucket holds a second of tokens at the start. A limited response takes a token
    // too, so the debt grows a thousand times faster than the bucket fills and nothing more
    // gets through.
    assert_eq!(sent, 5);
    assert_eq!(sent + slips + drops, 1_000);
    assert_eq!(delta(dropped_before, dropped(ResponseKind::Answer)), drops);
    assert_eq!(delta(slipped_before, slipped()), slips);
}

#[test]
fn the_other_addresses_of_the_victims_prefix_share_its_bucket() {
    let rig = Rig::new(rrl_only(RrlSettings {
        responses_per_second: 5,
        ..RrlSettings::default()
    }));
    let name = wire("victim.example.test");
    let key = answer(&name);
    rig.flood(ip(VICTIM), &key, 100, 0);

    for neighbour in ["198.51.100.8", "198.51.100.200", "198.51.100.255"] {
        assert_ne!(
            rig.response(ip(neighbour), &key, 0),
            SEND,
            "{neighbour} is in the /24 of the victim"
        );
    }
    for other in ["198.51.101.7", "203.0.113.9", "192.0.2.7"] {
        assert_eq!(
            rig.response(ip(other), &key, 0),
            SEND,
            "{other} is in another /24"
        );
    }
}

#[test]
fn the_flood_does_not_touch_other_responses_to_the_same_prefix() {
    let rig = Rig::new(rrl_only(RrlSettings {
        responses_per_second: 5,
        ..RrlSettings::default()
    }));
    let name = wire("victim.example.test");
    rig.flood(ip(VICTIM), &answer(&name), 100, 0);

    let other = wire("quiet.example.test");
    assert_eq!(rig.response(ip(VICTIM), &answer(&other), 0), SEND);
}

// ---- Normal clients ----

#[test]
fn a_normal_client_asking_four_names_a_second_is_never_limited() {
    let rig = Rig::new(rrl_only(RrlSettings {
        responses_per_second: 5,
        ..RrlSettings::default()
    }));
    let names: Vec<Vec<u8>> = (0..4)
        .map(|i| wire(&format!("name{i}.example.test")))
        .collect();
    let before = (dropped(ResponseKind::Answer), slipped());

    for second in 0..10 {
        for (at, name) in names.iter().enumerate() {
            let millis = second * 1_000 + u64::try_from(at).expect("small") * 250;
            assert_eq!(
                rig.response(ip("203.0.113.9"), &answer(name), millis),
                SEND,
                "second {second}, name {at}"
            );
        }
    }
    assert_eq!((dropped(ResponseKind::Answer), slipped()), before);
}

#[test]
fn a_client_asking_one_name_three_times_a_second_under_a_rate_of_five_is_never_limited() {
    let rig = Rig::new(rrl_only(RrlSettings {
        responses_per_second: 5,
        ..RrlSettings::default()
    }));
    let name = wire("steady.example.test");
    for second in 0..10 {
        for burst in 0..3 {
            let millis = second * 1_000 + burst * 333;
            assert_eq!(
                rig.response(ip("203.0.113.9"), &answer(&name), millis),
                SEND,
                "second {second}, query {burst}"
            );
        }
    }
}

#[test]
fn a_client_asking_above_the_rate_is_cut_off_once_its_first_second_is_used() {
    let rig = Rig::new(rrl_only(RrlSettings {
        responses_per_second: 5,
        slip: 0,
        ..RrlSettings::default()
    }));
    let name = wire("greedy.example.test");
    // Ten a second against a rate of five: every response takes a token, limited ones too,
    // so the balance only falls (by half a token a response) and never recovers.
    let decisions: Vec<RateDecision> = (0..200)
        .map(|at| rig.response(ip("203.0.113.9"), &answer(&name), at * 100))
        .collect();
    let (sent, slips, drops) = tally(&decisions);
    assert_eq!(slips, 0);
    assert!((9..=10).contains(&sent), "{sent} sent");
    assert_eq!(drops, 200 - sent);
}

// ---- The bucket refills ----

#[test]
fn a_limited_client_stays_limited_inside_the_window() {
    let rig = Rig::new(rrl_only(RrlSettings {
        responses_per_second: 5,
        window_secs: 15,
        ..RrlSettings::default()
    }));
    let name = wire("victim.example.test");
    let key = answer(&name);
    rig.flood(ip(VICTIM), &key, 1_000, 0);

    for millis in [1_000, 5_000, 10_000, 14_000] {
        assert_ne!(
            rig.response(ip(VICTIM), &key, millis),
            SEND,
            "{millis} ms after the flood"
        );
    }
}

#[test]
fn the_bucket_refills_after_the_window_and_a_second_of_silence() {
    let rig = Rig::new(rrl_only(RrlSettings {
        responses_per_second: 5,
        slip: 2,
        window_secs: 15,
        ..RrlSettings::default()
    }));
    let name = wire("victim.example.test");
    let key = answer(&name);
    rig.flood(ip(VICTIM), &key, 1_000, 0);

    let later = rig.flood(ip(VICTIM), &key, 10, 16_000);

    assert_eq!(
        tally(&later),
        (5, 2, 3),
        "a second's worth, then limited again"
    );
    assert!(later[..5].iter().all(|decision| *decision == SEND));
    assert_eq!(
        later[5], DROP,
        "the slip count starts again after a response was sent"
    );
}

#[test]
fn a_shorter_window_recovers_sooner() {
    let rig = Rig::new(rrl_only(RrlSettings {
        responses_per_second: 5,
        window_secs: 2,
        ..RrlSettings::default()
    }));
    let name = wire("victim.example.test");
    let key = answer(&name);
    rig.flood(ip(VICTIM), &key, 1_000, 0);

    assert_ne!(rig.response(ip(VICTIM), &key, 1_000), SEND);
    assert_eq!(rig.response(ip(VICTIM), &key, 3_000), SEND);
}

#[test]
fn a_flood_that_never_stops_gets_nothing_through_after_the_first_second() {
    let rig = Rig::new(rrl_only(RrlSettings {
        responses_per_second: 5,
        window_secs: 15,
        ..RrlSettings::default()
    }));
    let name = wire("victim.example.test");
    let key = answer(&name);
    // A thousand a second for a minute: the debt stays at its floor.
    let mut sent = 0;
    for second in 0..60 {
        let decisions = rig.flood(ip(VICTIM), &key, 1_000, second * 1_000);
        sent += tally(&decisions).0;
    }
    // Each burst puts the key back at its debt floor, and a second of silence repays far
    // less than the debt.
    assert_eq!(sent, 5);
}

// ---- The keys ----

fn keyed(errors: u32, responses: u32) -> Rig {
    Rig::new(rrl_only(RrlSettings {
        responses_per_second: responses,
        errors_per_second: errors,
        slip: 0,
        ..RrlSettings::default()
    }))
}

#[test]
fn nxdomain_responses_are_keyed_by_the_zone_at_the_error_rate() {
    let rig = keyed(3, 50);
    let zone = wire("example.test");
    let client = ip("203.0.113.9");
    let nx_before = dropped(ResponseKind::NxDomain);
    // Many random names below one zone reach RRL as the one zone name; the query type is
    // not part of the key.
    let decisions: Vec<RateDecision> = (0..100)
        .map(|at| rig.response(client, &key(ResponseKind::NxDomain, &zone, 1 + at % 3), 0))
        .collect();
    assert_eq!(tally(&decisions), (3, 0, 97), "errors_per_second, not 50");
    assert_eq!(delta(nx_before, dropped(ResponseKind::NxDomain)), 97);

    let other_zone = wire("other.test");
    assert_eq!(
        rig.response(client, &key(ResponseKind::NxDomain, &other_zone, 1), 0),
        SEND,
        "another zone has a bucket of its own"
    );
}

#[test]
fn answers_are_keyed_by_the_query_name_and_type() {
    let rig = keyed(9, 2);
    let client = ip("203.0.113.9");
    let first = wire("one.example.test");
    let second = wire("two.example.test");

    let same = rig.flood(client, &key(ResponseKind::Answer, &first, 1), 5, 0);
    assert_eq!(tally(&same), (2, 0, 3), "responses_per_second");
    for (name, qtype) in [(&first, 28), (&second, 1), (&second, 28)] {
        let decisions = rig.flood(client, &key(ResponseKind::Answer, name, qtype), 2, 0);
        assert_eq!(
            tally(&decisions),
            (2, 0, 0),
            "{qtype} of another name or type"
        );
    }
}

#[test]
fn nodata_is_counted_apart_from_answers_for_the_same_name_and_type() {
    let rig = keyed(9, 2);
    let client = ip("203.0.113.9");
    let name = wire("one.example.test");
    rig.flood(client, &key(ResponseKind::Answer, &name, 1), 5, 0);

    let nodata = rig.flood(client, &key(ResponseKind::NoData, &name, 1), 3, 0);
    assert_eq!(
        tally(&nodata),
        (2, 0, 1),
        "its own bucket at the response rate"
    );
}

#[test]
fn referrals_are_keyed_by_the_zone_at_the_response_rate() {
    let rig = keyed(9, 2);
    let client = ip("203.0.113.9");
    let zone = wire("example.test");
    let decisions: Vec<RateDecision> = (1..=6)
        .map(|qtype| rig.response(client, &key(ResponseKind::Referral, &zone, qtype), 0))
        .collect();
    assert_eq!(tally(&decisions), (2, 0, 4));
}

#[test]
fn errors_are_keyed_by_the_kind_alone() {
    let rig = keyed(3, 50);
    let client = ip("203.0.113.9");
    let decisions: Vec<RateDecision> = (0..20)
        .map(|at| {
            let name = wire(&format!("n{at}.example.test"));
            rig.response(client, &key(ResponseKind::Error, &name, 1 + at % 5), 0)
        })
        .collect();
    assert_eq!(
        tally(&decisions),
        (3, 0, 17),
        "one bucket at errors_per_second"
    );

    let zone = wire("example.test");
    assert_eq!(
        rig.response(client, &key(ResponseKind::NxDomain, &zone, 1), 0),
        SEND,
        "NXDOMAIN does not share the bucket of errors"
    );
}

#[test]
fn tcp_responses_are_never_limited() {
    let rig = keyed(1, 1);
    let name = wire("victim.example.test");
    let before = (dropped(ResponseKind::Answer), slipped());
    for kind in [
        ResponseKind::Answer,
        ResponseKind::NoData,
        ResponseKind::NxDomain,
        ResponseKind::Referral,
        ResponseKind::Error,
    ] {
        let tcp = ResponseKey {
            kind,
            name: &name,
            qtype: 1,
            udp: false,
        };
        let decisions = rig.flood(ip(VICTIM), &tcp, 1_000, 0);
        assert_eq!(tally(&decisions), (1_000, 0, 0), "{kind:?}");
    }
    assert_eq!((dropped(ResponseKind::Answer), slipped()), before);
}

#[test]
fn tcp_responses_do_not_use_up_the_udp_bucket() {
    let rig = keyed(1, 2);
    let name = wire("victim.example.test");
    let tcp = ResponseKey {
        udp: false,
        ..answer(&name)
    };
    rig.flood(ip(VICTIM), &tcp, 1_000, 0);
    assert_eq!(
        tally(&rig.flood(ip(VICTIM), &answer(&name), 3, 0)),
        (2, 0, 1)
    );
}

#[test]
fn a_slip_of_zero_never_slips() {
    let rig = Rig::new(rrl_only(RrlSettings {
        responses_per_second: 5,
        slip: 0,
        ..RrlSettings::default()
    }));
    let name = wire("victim.example.test");
    let before = (dropped(ResponseKind::Answer), slipped());
    let decisions = rig.flood(ip(VICTIM), &answer(&name), 1_000, 0);
    assert_eq!(tally(&decisions), (5, 0, 995));
    assert_eq!(delta(before.0, dropped(ResponseKind::Answer)), 995);
    assert_eq!(delta(before.1, slipped()), 0);
}

#[test]
fn a_slip_of_one_always_slips() {
    let rig = Rig::new(rrl_only(RrlSettings {
        responses_per_second: 5,
        slip: 1,
        ..RrlSettings::default()
    }));
    let name = wire("victim.example.test");
    let before = (dropped(ResponseKind::Answer), slipped());
    let decisions = rig.flood(ip(VICTIM), &answer(&name), 1_000, 0);
    assert_eq!(tally(&decisions), (5, 995, 0));
    assert_eq!(delta(before.0, dropped(ResponseKind::Answer)), 0);
    assert_eq!(delta(before.1, slipped()), 995);
}

#[test]
fn a_slip_of_three_slips_every_third_limited_response() {
    let rig = Rig::new(rrl_only(RrlSettings {
        responses_per_second: 1,
        slip: 3,
        ..RrlSettings::default()
    }));
    let name = wire("victim.example.test");
    let decisions = rig.flood(ip(VICTIM), &answer(&name), 7, 0);
    assert_eq!(decisions, [SEND, DROP, DROP, SLIP, DROP, DROP, SLIP]);
}

#[test]
fn the_dropped_counter_is_kept_per_kind() {
    let rig = keyed(1, 1);
    let client = ip("203.0.113.9");
    let name = wire("count.example.test");
    let kinds = [
        ResponseKind::Answer,
        ResponseKind::NoData,
        ResponseKind::NxDomain,
        ResponseKind::Referral,
        ResponseKind::Error,
    ];
    for kind in kinds {
        let before: Vec<u64> = kinds.iter().map(|kind| dropped(*kind)).collect();
        let first = rig.response(client, &key(kind, &name, 1), 0);
        let second = rig.response(client, &key(kind, &name, 1), 0);
        assert_eq!((first, second), (SEND, DROP), "{kind:?}");
        for (at, other) in kinds.iter().enumerate() {
            let expected = usize::from(*other == kind);
            assert_eq!(
                delta(before[at], dropped(*other)),
                expected,
                "{} after a drop of {}",
                other.as_str(),
                kind.as_str()
            );
        }
    }
}

#[test]
fn the_kinds_have_their_label_values_and_series() {
    let kinds = [
        (ResponseKind::Answer, "answer", 0),
        (ResponseKind::NoData, "nodata", 1),
        (ResponseKind::NxDomain, "nxdomain", 2),
        (ResponseKind::Referral, "referral", 3),
        (ResponseKind::Error, "error", 4),
    ];
    for (kind, label, index) in kinds {
        assert_eq!(kind.as_str(), label);
        assert_eq!(kind.index(), index);
    }
}

#[test]
fn the_default_settings_are_the_documented_ones() {
    assert_eq!(
        RrlSettings::default(),
        RrlSettings {
            responses_per_second: 10,
            errors_per_second: 5,
            window_secs: 15,
            slip: 2,
            ipv4_prefix: 24,
            ipv6_prefix: 56,
        }
    );
    let settings = LimitSettings::default();
    assert!(settings.rrl.is_none() && settings.client.is_none() && settings.exempt.is_empty());
    assert_eq!(settings.table, 65_536);
}

// ---- Grouping by prefix ----

#[test]
fn ipv6_clients_of_one_56_share_a_bucket() {
    let rig = keyed(9, 3);
    let name = wire("victim.example.test");
    let key = answer(&name);
    assert_eq!(
        tally(&rig.flood(ip("2001:db8:0:100::1"), &key, 3, 0)),
        (3, 0, 0)
    );
    // The fourth group differs in its low byte and in the interface part only.
    for same in [
        "2001:db8:0:1ff:aaaa::5",
        "2001:db8:0:100::2",
        "2001:db8:0:180::ffff",
    ] {
        assert_eq!(rig.response(ip(same), &key, 0), DROP, "{same}");
    }
    for other in [
        "2001:db8:0:200::1",
        "2001:db8:0:0::1",
        "2001:db8:1:100::1",
        "2001:db9:0:100::1",
    ] {
        assert_eq!(
            rig.response(ip(other), &key, 0),
            SEND,
            "{other} is in another /56"
        );
    }
}

#[test]
fn the_prefix_lengths_can_be_changed() {
    let rig = Rig::new(rrl_only(RrlSettings {
        responses_per_second: 1,
        slip: 0,
        ipv4_prefix: 32,
        ipv6_prefix: 64,
        ..RrlSettings::default()
    }));
    let name = wire("victim.example.test");
    let key = answer(&name);
    assert_eq!(rig.response(ip("198.51.100.7"), &key, 0), SEND);
    assert_eq!(
        rig.response(ip("198.51.100.8"), &key, 0),
        SEND,
        "a /32 of its own"
    );
    assert_eq!(rig.response(ip("198.51.100.7"), &key, 0), DROP);
    assert_eq!(rig.response(ip("2001:db8:0:100::1"), &key, 0), SEND);
    assert_eq!(
        rig.response(ip("2001:db8:0:101::1"), &key, 0),
        SEND,
        "a /64 of its own"
    );
    assert_eq!(rig.response(ip("2001:db8:0:100::9"), &key, 0), DROP);
}

#[test]
fn an_ipv4_mapped_ipv6_address_is_grouped_as_ipv4() {
    let rig = keyed(9, 2);
    let name = wire("victim.example.test");
    let key = answer(&name);
    assert_eq!(tally(&rig.flood(ip("198.51.100.7"), &key, 2, 0)), (2, 0, 0));
    assert_eq!(rig.response(ip("::ffff:198.51.100.99"), &key, 0), DROP);
}

#[test]
fn an_ipv4_and_an_ipv6_client_never_share_a_bucket() {
    let rig = keyed(9, 1);
    let name = wire("victim.example.test");
    let key = answer(&name);
    assert_eq!(rig.response(ip("0.0.0.1"), &key, 0), SEND);
    assert_eq!(rig.response(ip("::1"), &key, 0), SEND);
    assert_eq!(rig.response(ip("0.0.0.1"), &key, 0), DROP);
    assert_eq!(rig.response(ip("::1"), &key, 0), DROP);
}

// ---- Exemptions ----

fn exempting() -> LimitSettings {
    LimitSettings {
        rrl: Some(RrlSettings {
            responses_per_second: 1,
            slip: 0,
            ..RrlSettings::default()
        }),
        client: Some(ClientLimit {
            queries_per_second: 1,
            burst: 0,
        }),
        exempt: vec![
            "198.51.100.0/24".parse().expect("prefix"),
            "2001:db8:e::/48".parse().expect("prefix"),
        ],
        table: 1 << 18,
    }
}

#[test]
fn a_client_in_the_exempt_prefixes_is_never_limited() {
    let rig = Rig::new(exempting());
    let name = wire("victim.example.test");
    let key = answer(&name);
    let before = (dropped(ResponseKind::Answer), slipped(), limited());
    for exempt in ["198.51.100.77", "2001:db8:e:1::5", "::ffff:198.51.100.77"] {
        let decisions = rig.flood(ip(exempt), &key, 1_000, 0);
        assert_eq!(tally(&decisions), (1_000, 0, 0), "{exempt} responses");
        assert!(
            (0..1_000).all(|_| rig.query(ip(exempt), 0)),
            "{exempt} queries"
        );
    }
    assert_eq!(
        (dropped(ResponseKind::Answer), slipped(), limited()),
        before
    );

    let outside = ip("198.51.101.77");
    assert_eq!(tally(&rig.flood(outside, &key, 5, 0)), (1, 0, 4));
    assert!(rig.query(outside, 0));
    assert!(!rig.query(outside, 0));
}

#[test]
fn a_client_the_known_prefixes_accept_is_never_limited() {
    let known = ip("203.0.113.9");
    let rig = Rig::with_known(exempting(), Arc::new(move |client| client == known));
    let name = wire("victim.example.test");
    let key = answer(&name);

    assert_eq!(tally(&rig.flood(known, &key, 1_000, 0)), (1_000, 0, 0));
    assert!((0..1_000).all(|_| rig.query(known, 0)));

    let stranger = ip("203.0.113.10");
    assert_eq!(tally(&rig.flood(stranger, &key, 5, 0)), (1, 0, 4));
    assert!(rig.query(stranger, 0));
    assert!(!rig.query(stranger, 0));
}

#[test]
fn the_known_closure_is_asked_with_the_canonical_address() {
    let known = ip("203.0.113.9");
    let rig = Rig::with_known(exempting(), Arc::new(move |client| client == known));
    let name = wire("victim.example.test");
    let mapped = ip("::ffff:203.0.113.9");
    assert_eq!(
        tally(&rig.flood(mapped, &answer(&name), 100, 0)),
        (100, 0, 0)
    );
}

// ---- The per-client limit ----

#[test]
fn a_client_may_send_the_rate_plus_the_burst_at_once() {
    let rig = Rig::new(per_client(10, 5));
    let before = limited();

    let admitted: Vec<bool> = (0..100).map(|_| rig.query(ip("203.0.113.9"), 0)).collect();

    assert_eq!(admitted.iter().filter(|admitted| **admitted).count(), 15);
    assert!(admitted[..15].iter().all(|admitted| *admitted));
    assert_eq!(delta(before, limited()), 85);
}

#[test]
fn a_limited_client_is_admitted_again_as_time_passes() {
    let rig = Rig::new(per_client(10, 5));
    let client = ip("203.0.113.9");
    for _ in 0..100 {
        rig.query(client, 0);
    }

    assert!(!rig.query(client, 50), "half a token is not enough");
    assert!(rig.query(client, 150), "one token every 100 ms");
    assert!(!rig.query(client, 150));
    let admitted = (0..30).filter(|_| rig.query(client, 1_200)).count();
    assert_eq!(admitted, 10, "a second's worth of tokens");
}

#[test]
fn a_client_that_stays_silent_gets_its_burst_back_but_no_more() {
    let rig = Rig::new(per_client(10, 5));
    let client = ip("203.0.113.9");
    for _ in 0..100 {
        rig.query(client, 0);
    }
    let admitted = (0..100).filter(|_| rig.query(client, 60_000)).count();
    assert_eq!(admitted, 15);
}

#[test]
fn a_steady_client_under_the_rate_is_never_limited() {
    let rig = Rig::new(per_client(10, 5));
    let before = limited();
    for at in 0..1_000 {
        assert!(rig.query(ip("203.0.113.9"), at * 100), "query {at}");
    }
    assert_eq!(limited(), before);
}

#[test]
fn clients_are_limited_one_by_one_for_ipv4() {
    let rig = Rig::new(per_client(10, 5));
    for _ in 0..100 {
        rig.query(ip("198.51.100.7"), 0);
    }
    assert!(!rig.query(ip("198.51.100.7"), 0));
    assert!(
        rig.query(ip("198.51.100.8"), 0),
        "the neighbour has its own budget"
    );
}

#[test]
fn an_ipv6_client_is_grouped_by_its_64() {
    let rig = Rig::new(per_client(10, 5));
    for _ in 0..100 {
        rig.query(ip("2001:db8:5:5::1"), 0);
    }
    assert!(!rig.query(ip("2001:db8:5:5:ffff::2"), 0), "the same /64");
    assert!(!rig.query(ip("2001:db8:5:5::9999"), 0), "the same /64");
    assert!(rig.query(ip("2001:db8:5:6::1"), 0), "another /64");
    assert!(rig.query(ip("2001:db8:6:5::1"), 0), "another /64");
}

#[test]
fn without_a_client_limit_every_query_is_admitted() {
    let rig = Rig::new(rrl_only(RrlSettings::default()));
    let before = limited();
    assert!((0..10_000).all(|_| rig.query(ip("203.0.113.9"), 0)));
    assert_eq!(limited(), before);
}

#[test]
fn without_rrl_every_response_is_sent() {
    let rig = Rig::new(per_client(1, 0));
    let name = wire("victim.example.test");
    let decisions = rig.flood(ip(VICTIM), &answer(&name), 10_000, 0);
    assert_eq!(tally(&decisions), (10_000, 0, 0));
}

#[test]
fn rrl_and_the_client_limit_count_separately() {
    let rig = Rig::new(LimitSettings {
        rrl: Some(RrlSettings {
            responses_per_second: 5,
            slip: 0,
            ..RrlSettings::default()
        }),
        client: Some(ClientLimit {
            queries_per_second: 10,
            burst: 5,
        }),
        table: 1 << 18,
        ..LimitSettings::default()
    });
    let client = ip(VICTIM);
    let name = wire("victim.example.test");
    let admitted = (0..100).filter(|_| rig.query(client, 0)).count();
    assert_eq!(admitted, 15);
    assert_eq!(
        tally(&rig.flood(client, &answer(&name), 100, 0)),
        (5, 0, 95)
    );
}

// ---- Unlimited ----

#[test]
fn unlimited_admits_everything() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let unlimited = Unlimited;
    let now = Instant::now();
    let name = wire("victim.example.test");
    let before = (dropped(ResponseKind::Answer), slipped(), limited());
    for _ in 0..10_000 {
        assert!(unlimited.admit_query(ip(VICTIM), now));
        assert_eq!(
            unlimited.admit_response(ip(VICTIM), &answer(&name), now),
            SEND
        );
    }
    assert_eq!(
        (dropped(ResponseKind::Answer), slipped(), limited()),
        before
    );
}

#[test]
fn a_limiter_without_settings_admits_everything_like_unlimited() {
    let rig = Rig::new(LimitSettings::default());
    let name = wire("victim.example.test");
    assert!((0..1_000).all(|_| rig.query(ip(VICTIM), 0)));
    assert_eq!(
        tally(&rig.flood(ip(VICTIM), &answer(&name), 1_000, 0)),
        (1_000, 0, 0)
    );
}

#[test]
fn the_limiters_work_behind_the_trait_object() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let limiters: Vec<Arc<dyn RateLimiter>> = vec![
        Arc::new(Unlimited),
        Arc::new(Limiter::new(LimitSettings::default())),
    ];
    let now = Instant::now();
    for limiter in limiters {
        assert!(limiter.admit_query(ip(VICTIM), now));
    }
}
