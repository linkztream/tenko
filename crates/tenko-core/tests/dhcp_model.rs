//! Property tests of the DHCP model (`tenko_core::dhcp`): option data in wire and typed form,
//! option owners, MAC patterns and filters, lease times, client identities, option merging,
//! the reservation check, and the encodings of the rows of the `dhcp` tables.

use std::{
    collections::BTreeSet,
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use ipnet::{Ipv4Net, Ipv6Net};
use proptest::prelude::*;
use serde::{Serialize, de::DeserializeOwned};
use tenko_core::{
    NodeId, Timestamp,
    codec::{decode_key, encode_key, from_cbor, to_cbor},
    dhcp::{
        AddressRange, BindingState, Class, Condition, DdnsConflict, DdnsPolicy, DdnsState,
        DhcpSettings, Filter, FilterKind, FilterVerdict, Fingerprint, Join, Lease, LeaseTimes,
        MacPattern, Match, OptionData, OptionKind, OptionOwner, OptionSet, OptionSpace,
        OptionValue, Policy, PolicyAction, PoolShare, RelayInfo, ReservationCandidate,
        ReservationWarning, Scope, StaticRoute, Term, check_reservations, filter_verdict,
        lease::{ClientKey, MAX_CHADDR, MAX_CLIENT_ID, MAX_IDENTITY},
        merge, write_identity,
    },
    dns::{DnsName, ZoneId},
    id::{HostId, InterfaceId, PrefixId, RangeId, VrfId},
    ipam::Stamp,
    principal::{Principal, SystemComponent},
    serde_util::HexBytes,
};
use uuid::Uuid;

// ---------------------------------------------------------------------------------------
// Building blocks

fn id<T: Debug>(make: fn(Uuid) -> T) -> impl Strategy<Value = T> {
    any::<u128>().prop_map(move |n| make(Uuid::from_u128(n)))
}

fn timestamp() -> impl Strategy<Value = Timestamp> {
    (0i64..4_000_000_000, 0u32..1_000_000_000).prop_map(|(secs, nanos)| {
        Timestamp::from_unix_nanos(i128::from(secs) * 1_000_000_000 + i128::from(nanos))
            .expect("in range")
    })
}

fn stamp() -> impl Strategy<Value = Stamp> {
    timestamp().prop_map(|at| Stamp::new(at, Principal::system(SystemComponent::Dhcp)))
}

fn hex(max: usize) -> impl Strategy<Value = HexBytes> {
    prop::collection::vec(any::<u8>(), 0..=max).prop_map(HexBytes)
}

fn text() -> impl Strategy<Value = String> {
    "[a-z0-9 .-]{1,20}"
}

fn maybe<T: Debug>(strategy: impl Strategy<Value = T>) -> impl Strategy<Value = Option<T>> {
    prop::option::of(strategy)
}

fn ipv4() -> impl Strategy<Value = Ipv4Addr> {
    any::<[u8; 4]>().prop_map(Ipv4Addr::from)
}

fn ipv6() -> impl Strategy<Value = Ipv6Addr> {
    any::<[u8; 16]>().prop_map(Ipv6Addr::from)
}

fn ip() -> impl Strategy<Value = IpAddr> {
    prop_oneof![ipv4().prop_map(IpAddr::V4), ipv6().prop_map(IpAddr::V6)]
}

fn dns_name() -> impl Strategy<Value = DnsName> {
    prop::collection::vec("[a-z0-9]{1,10}", 1..=4)
        .prop_map(|labels| DnsName::new(&labels.join(".")).expect("valid name"))
}

// ---------------------------------------------------------------------------------------
// Option data

/// Every kind with the array flags it admits, and typed data that encodes to it.
fn option_case() -> impl Strategy<Value = (OptionKind, bool, OptionData)> {
    // A scalar list: one value, or one to eight when the option is an array.
    fn list<T: Debug + Clone + 'static>(
        element: impl Strategy<Value = T> + 'static,
    ) -> impl Strategy<Value = (bool, Vec<T>)> {
        let element = element.boxed();
        prop_oneof![
            element.clone().prop_map(|one| (false, vec![one])),
            prop::collection::vec(element, 1..=8).prop_map(|many| (true, many)),
        ]
    }

    let route = (ipv4(), 0u8..=32, ipv4()).prop_map(|(addr, width, router)| StaticRoute {
        destination: Ipv4Net::new(addr, width).expect("width").trunc(),
        router,
    });
    prop_oneof![
        list(ipv4()).prop_map(|(array, values)| (
            OptionKind::Ipv4Address,
            array,
            OptionData::Ipv4 { values }
        )),
        list(ipv6()).prop_map(|(array, values)| (
            OptionKind::Ipv6Address,
            array,
            OptionData::Ipv6 { values }
        )),
        // A prefix is its network address (the model refuses bits beyond the length).
        list(
            (ipv6(), 0u8..=128)
                .prop_map(|(addr, len)| { Ipv6Net::new(addr, len).expect("length").trunc() })
        )
        .prop_map(|(array, values)| (
            OptionKind::Ipv6Prefix,
            array,
            OptionData::Ipv6Prefix { values }
        )),
        list(any::<u8>().prop_map(u32::from)).prop_map(|(array, values)| (
            OptionKind::U8,
            array,
            OptionData::Unsigned(values)
        )),
        list(any::<u16>().prop_map(u32::from)).prop_map(|(array, values)| (
            OptionKind::U16,
            array,
            OptionData::Unsigned(values)
        )),
        list(any::<u32>()).prop_map(|(array, values)| (
            OptionKind::U32,
            array,
            OptionData::Unsigned(values)
        )),
        any::<i32>().prop_map(|value| (OptionKind::I32, false, OptionData::Signed(value))),
        list(any::<bool>()).prop_map(|(array, values)| (
            OptionKind::Bool,
            array,
            OptionData::Bool(values)
        )),
        "[^\\x00]{1,40}".prop_map(|value| (OptionKind::String, false, OptionData::Text(value))),
        list(dns_name()).prop_map(|(array, values)| (
            OptionKind::Fqdn,
            array,
            OptionData::Names(values)
        )),
        prop::collection::vec(route, 1..=6).prop_map(|routes| (
            OptionKind::ClasslessRoutes,
            false,
            OptionData::Routes(routes)
        )),
        hex(64).prop_map(|bytes| (OptionKind::Binary, false, OptionData::Binary(bytes))),
        Just((OptionKind::Empty, false, OptionData::Empty)),
    ]
}

const KINDS: [OptionKind; 13] = [
    OptionKind::Ipv4Address,
    OptionKind::Ipv6Address,
    OptionKind::Ipv6Prefix,
    OptionKind::U8,
    OptionKind::U16,
    OptionKind::U32,
    OptionKind::I32,
    OptionKind::Bool,
    OptionKind::String,
    OptionKind::Fqdn,
    OptionKind::ClasslessRoutes,
    OptionKind::Binary,
    OptionKind::Empty,
];

fn kind() -> impl Strategy<Value = OptionKind> {
    prop::sample::select(KINDS.to_vec())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn option_data_round_trips_through_the_wire_form((kind, array, data) in option_case()) {
        prop_assert!(!array || kind.may_repeat());
        let wire = data.encode(kind, array).expect("generated data encodes");
        prop_assert!(kind.check(array, &wire).is_ok());
        prop_assert_eq!(OptionData::decode(kind, array, &wire).expect("decodes"), data.clone());
        // The typed view is the same through an option value.
        let value = OptionValue::v4(224, wire);
        prop_assert_eq!(value.typed(kind, array).expect("typed"), data);
    }

    #[test]
    fn checking_and_decoding_never_panic(
        kind in kind(),
        array in any::<bool>(),
        data in prop::collection::vec(any::<u8>(), 0..300),
    ) {
        let checked = kind.check(array, &data);
        let decoded = OptionData::decode(kind, array, &data);
        prop_assert_eq!(checked.is_ok(), decoded.is_ok());
        if let Ok(typed) = decoded {
            // What decodes encodes again, to data that decodes to the same view.
            if let Ok(wire) = typed.encode(kind, array) {
                prop_assert_eq!(OptionData::decode(kind, array, &wire).expect("again"), typed);
            }
        }
    }

    /// The same, with data shaped like the wire form of the structured kinds, so that the
    /// checks go past their first octet.
    #[test]
    fn structured_data_checks_agree_with_decoding(
        kind in prop::sample::select(vec![OptionKind::Fqdn, OptionKind::ClasslessRoutes, OptionKind::Ipv6Prefix]),
        array in any::<bool>(),
        chunks in prop::collection::vec(
            prop_oneof![
                prop::collection::vec(any::<u8>(), 0..=8),
                prop::collection::vec(0u8..=40, 1..=7),
                (0u8..=5, prop::collection::vec(b'a'..=b'z', 0..=5)).prop_map(|(len, mut label)| {
                    label.truncate(usize::from(len));
                    let mut out = vec![u8::try_from(label.len()).expect("short")];
                    out.extend(label);
                    out
                }),
            ],
            0..=6,
        ),
    ) {
        let data: Vec<u8> = chunks.concat();
        let checked = kind.check(array, &data);
        let decoded = OptionData::decode(kind, array, &data);
        prop_assert_eq!(checked.is_ok(), decoded.is_ok());
    }
}

/// The root alone and a label that is no DNS label are refused by the check as by the
/// decoding (found by the property above: `[0]` and `[1, b' ', 0]`).
#[test]
fn fqdn_check_is_ok_exactly_when_decode_is_ok() {
    for data in [vec![0u8], vec![1, b' ', 0]] {
        for array in [false, true] {
            assert_eq!(
                OptionKind::Fqdn.check(array, &data).is_ok(),
                OptionData::decode(OptionKind::Fqdn, array, &data).is_ok(),
                "{data:?} array {array}"
            );
        }
    }
}

/// A classless route's destination bits after its width are cleared when it is decoded, as
/// the encoding clears them (found by `checking_and_decoding_never_panic` on 2026-10-22:
/// `0.0.0.1/25` decoded with the bit, encoded again without it).
#[test]
fn a_route_reads_with_the_bits_after_its_width_cleared() {
    let data = [9u8, 0, 0, 0, 0, 0, 0, 25, 0, 0, 0, 1, 0, 0, 0, 0];
    assert!(OptionKind::ClasslessRoutes.check(false, &data).is_ok());
    let typed = OptionData::decode(OptionKind::ClasslessRoutes, false, &data).expect("decodes");
    let OptionData::Routes(routes) = &typed else {
        panic!("routes, not {typed:?}");
    };
    assert_eq!(routes[1].destination, "0.0.0.0/25".parse().expect("a net"));
    let wire = typed
        .encode(OptionKind::ClasslessRoutes, false)
        .expect("encodes");
    assert_eq!(
        OptionData::decode(OptionKind::ClasslessRoutes, false, &wire).expect("again"),
        typed
    );
}

/// An IPv6 prefix is its network address and its length: one with bits set beyond its
/// length is refused by the check, the decoding and the encoding alike, so that what is
/// stored reads back as written (found by `checking_and_decoding_never_panic`: the list
/// `[::/0, ::/0, ::1/0]` decoded, encoded again as `[::/0, ::/0, ::/0]`).
#[test]
fn an_ipv6_prefix_with_bits_beyond_its_length_is_refused() {
    let mut found = vec![0u8; 51];
    found[50] = 1;
    let host_bits = |len: u8, last: u8| {
        let mut data = vec![len];
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        data.extend_from_slice(&[0; 11]);
        data.push(last);
        data
    };
    for (data, array) in [
        (found, true),
        (host_bits(64, 1), false),
        (host_bits(127, 1), false),
        (host_bits(0, 0), false),
    ] {
        assert!(
            OptionKind::Ipv6Prefix.check(array, &data).is_err(),
            "{data:?}"
        );
        assert!(
            OptionData::decode(OptionKind::Ipv6Prefix, array, &data).is_err(),
            "{data:?}"
        );
    }
    let typed = |text: &str| OptionData::Ipv6Prefix {
        values: vec![text.parse().expect("a prefix")],
    };
    assert!(
        typed("::1/0")
            .encode(OptionKind::Ipv6Prefix, false)
            .is_err()
    );
    assert!(
        typed("2001:db8::1/64")
            .encode(OptionKind::Ipv6Prefix, false)
            .is_err()
    );
    // The network address of every length passes and reads back as it was.
    for (text, last) in [
        ("2001:db8::/32", 0),
        ("2001:db8::1/128", 1),
        ("2001:db8::/64", 0),
    ] {
        let data = typed(text)
            .encode(OptionKind::Ipv6Prefix, false)
            .expect("encodes");
        assert_eq!(data.last(), Some(&last));
        assert!(OptionKind::Ipv6Prefix.check(false, &data).is_ok());
        assert_eq!(
            OptionData::decode(OptionKind::Ipv6Prefix, false, &data).expect("decodes"),
            typed(text)
        );
    }
}

/// An `i32` option holds one value: the kind does not repeat, so a list is refused by the
/// check and the decoding alike rather than cut to its first value (found by the property
/// above: `[0, 0, 0, 1, 0, 0, 0, 2]` decoded to `Signed(1)`).
#[test]
fn an_i32_option_holds_one_value() {
    let wire = [0u8, 0, 0, 1, 0, 0, 0, 2];
    assert!(!OptionKind::I32.may_repeat());
    assert!(OptionKind::I32.check(true, &wire).is_err());
    assert!(OptionData::decode(OptionKind::I32, true, &wire).is_err());
    let typed = OptionData::decode(OptionKind::I32, false, &wire[..4]).expect("decodes");
    assert_eq!(
        typed.encode(OptionKind::I32, false).expect("encodes"),
        &wire[..4]
    );
}

// ---------------------------------------------------------------------------------------
// Option owners

fn owner() -> impl Strategy<Value = OptionOwner> {
    prop_oneof![
        Just(OptionOwner::Server),
        id(tenko_core::dhcp::SharedNetworkId::from_uuid).prop_map(OptionOwner::SharedNetwork),
        id(PrefixId::from_uuid).prop_map(OptionOwner::Scope),
        id(RangeId::from_uuid).prop_map(OptionOwner::Pool),
        id(tenko_core::dhcp::PolicyId::from_uuid).prop_map(OptionOwner::Policy),
        id(InterfaceId::from_uuid).prop_map(OptionOwner::Host),
    ]
}

/// Checks the CBOR and the JSON round trip of a row.
fn round_trips<T: Serialize + DeserializeOwned + PartialEq + Debug>(
    value: &T,
) -> Result<(), TestCaseError> {
    let cbor = to_cbor(value).expect("cbor");
    prop_assert_eq!(&from_cbor::<T>(&cbor).expect("from cbor"), value);
    let json = serde_json::to_string(value).expect("json");
    prop_assert_eq!(&serde_json::from_str::<T>(&json).expect("from json"), value);
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn option_owners_round_trip_in_every_form(owner in owner()) {
        prop_assert_eq!(OptionOwner::from_path(&owner.to_path()).expect("path"), owner);
        prop_assert_eq!(decode_key::<OptionOwner>(&encode_key(&owner)).expect("key"), owner);
        round_trips(&owner)?;
    }

    #[test]
    fn option_owner_keys_group_by_level(a in owner(), b in owner()) {
        // The tag leads the key, so the keys of one level are adjacent.
        if a.level() < b.level() {
            prop_assert!(encode_key(&a) < encode_key(&b));
        }
    }

    #[test]
    fn owner_paths_that_are_not_owners_are_refused(text in "[a-z_:0-9-]{0,50}") {
        if let Ok(parsed) = OptionOwner::from_path(&text) {
            prop_assert_eq!(parsed.to_path(), text);
        }
    }
}

// ---------------------------------------------------------------------------------------
// MAC patterns and filters

type Positions = [Option<u8>; 6];

fn pattern_text(positions: &Positions) -> String {
    positions
        .iter()
        .map(|position| position.map_or_else(|| "*".to_owned(), |octet| format!("{octet:02x}")))
        .collect::<Vec<_>>()
        .join(":")
}

fn naive_match(positions: &Positions, mac: [u8; 6]) -> bool {
    positions
        .iter()
        .zip(mac)
        .all(|(position, octet)| position.is_none_or(|expected| expected == octet))
}

/// Patterns and addresses from a small alphabet of octets, so that matches are common.
fn small_positions() -> impl Strategy<Value = Positions> {
    prop::array::uniform6(maybe(0u8..3))
}

fn small_mac() -> impl Strategy<Value = [u8; 6]> {
    prop::array::uniform6(0u8..3)
}

fn filter(mac: MacPattern, kind: FilterKind) -> Filter {
    let stamp = Stamp::new(
        "2026-10-22T12:00:00Z".parse().expect("time"),
        Principal::system(SystemComponent::Dhcp),
    );
    Filter {
        id: tenko_core::dhcp::FilterId::generate(),
        mac,
        kind,
        note: None,
        created: stamp.clone(),
        updated: stamp,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn mac_patterns_round_trip_and_match_octet_by_octet(
        positions in prop::array::uniform6(maybe(any::<u8>())),
        steps in prop::array::uniform6((any::<u8>(), any::<bool>())),
    ) {
        let text = pattern_text(&positions);
        let pattern = MacPattern::new(&text).expect("generated patterns parse");
        prop_assert_eq!(pattern.to_string(), text.clone());
        prop_assert_eq!(MacPattern::new(&pattern.to_string()).expect("again"), pattern);
        prop_assert_eq!(text.parse::<MacPattern>().expect("from_str"), pattern);
        prop_assert_eq!(pattern.is_exact(), positions.iter().all(Option::is_some));
        // Upper case and dashes are the same pattern.
        let loud = text.to_ascii_uppercase().replace(':', "-");
        prop_assert_eq!(MacPattern::new(&loud).expect("loud"), pattern);
        // An address that follows the pattern where `follow` says so.
        let mut mac = [0u8; 6];
        for (index, (octet, follow)) in steps.iter().enumerate() {
            mac[index] = match positions[index] {
                Some(expected) if *follow => expected,
                _ => *octet,
            };
        }
        prop_assert_eq!(pattern.matches(&mac), naive_match(&positions, mac));
        // Every pattern matches the address it was written from.
        let from: [u8; 6] = std::array::from_fn(|i| positions[i].unwrap_or(steps[i].0));
        prop_assert!(pattern.matches(&from));
        round_trips(&pattern)?;
    }

    #[test]
    fn an_exact_pattern_matches_one_address(mac in any::<[u8; 6]>(), other in any::<[u8; 6]>(), near in 0usize..6) {
        let pattern = MacPattern::exact(mac);
        prop_assert!(pattern.is_exact());
        prop_assert!(pattern.matches(&mac));
        prop_assert_eq!(pattern.matches(&other), other == mac);
        let mut nudged = mac;
        nudged[near] = nudged[near].wrapping_add(1);
        prop_assert!(!pattern.matches(&nudged));
        prop_assert_eq!(MacPattern::new(&pattern.to_string()).expect("text"), pattern);
    }

    #[test]
    fn short_patterns_end_in_a_wildcard(octets in prop::collection::vec(any::<u8>(), 0..=5)) {
        let mut parts: Vec<String> = octets.iter().map(|octet| format!("{octet:02x}")).collect();
        parts.push("*".to_owned());
        let pattern = MacPattern::new(&parts.join(":")).expect("a prefix pattern");
        let mut mac = [0xaau8; 6];
        mac[..octets.len()].copy_from_slice(&octets);
        prop_assert!(pattern.matches(&mac));
        if let Some(first) = octets.first() {
            mac[0] = first.wrapping_add(1);
            prop_assert!(!pattern.matches(&mac));
        }
        // A prefix without the closing wildcard is no pattern.
        if octets.len() < 6 && !octets.is_empty() {
            let open: Vec<String> = octets.iter().map(|octet| format!("{octet:02x}")).collect();
            prop_assert!(MacPattern::new(&open.join(":")).is_err());
        }
    }

    #[test]
    fn parsing_a_pattern_never_panics(text in ".{0,24}", close in "[0-9a-fA-F:*-]{0,24}") {
        for text in [text, close] {
            if let Ok(pattern) = MacPattern::new(&text) {
                prop_assert_eq!(MacPattern::new(&pattern.to_string()).expect("again"), pattern);
            }
        }
    }

    #[test]
    fn filters_deny_before_they_allow(
        entries in prop::collection::vec((small_positions(), any::<bool>()), 0..=8),
        mac in small_mac(),
    ) {
        let filters: Vec<Filter> = entries
            .iter()
            .map(|(positions, deny)| {
                let pattern = MacPattern::new(&pattern_text(positions)).expect("pattern");
                filter(pattern, if *deny { FilterKind::Deny } else { FilterKind::Allow })
            })
            .collect();
        let denied = entries.iter().any(|(positions, deny)| *deny && naive_match(positions, mac));
        let allowed = entries.iter().any(|(positions, deny)| !*deny && naive_match(positions, mac));
        let expected = if denied {
            FilterVerdict::Denied
        } else if allowed {
            FilterVerdict::Allowed
        } else {
            FilterVerdict::Unlisted
        };
        prop_assert_eq!(filter_verdict(&filters, &mac), expected);
        // The order of the entries does not matter.
        let mut reversed = filters;
        reversed.reverse();
        prop_assert_eq!(filter_verdict(&reversed, &mac), expected);
    }
}

/// Octets are two hexadecimal digits: a sign is refused (found by the property above:
/// `u8::from_str_radix` takes a leading plus).
#[test]
fn mac_pattern_octets_are_hexadecimal_digits() {
    assert!(MacPattern::new("+f:00:5e:00:53:01").is_err());
}

// ---------------------------------------------------------------------------------------
// Lease times

/// Times that pass `validate`, with and without explicit T1 and T2.
fn lease_times() -> impl Strategy<Value = LeaseTimes> {
    (8u32..200_000)
        .prop_flat_map(|default_secs| {
            let timers = prop_oneof![
                2 => Just((None, None)),
                1 => (1..default_secs / 2).prop_map(|t1| (Some(t1), None)),
                1 => (default_secs / 2 + 1..default_secs).prop_map(|t2| (None, Some(t2))),
                2 => (1..default_secs / 2, default_secs / 2 + 1..default_secs)
                    .prop_map(|(t1, t2)| (Some(t1), Some(t2))),
            ];
            (
                Just(default_secs),
                1..=default_secs,
                default_secs..=default_secs + 100_000,
                timers,
            )
        })
        .prop_map(
            |(default_secs, min_secs, max_secs, (t1_secs, t2_secs))| LeaseTimes {
                default_secs,
                min_secs,
                max_secs,
                t1_secs,
                t2_secs,
            },
        )
        .prop_filter("passes validate", |times| times.validate("lease").is_ok())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn grants_stay_between_min_and_max(times in lease_times(), asked in any::<u32>(), spot in any::<u32>()) {
        for requested in [asked, 0, 1, times.min_secs, times.max_secs, u32::MAX] {
            let granted = times.grant(Some(requested));
            prop_assert!(times.min_secs <= granted && granted <= times.max_secs);
            if (times.min_secs..=times.max_secs).contains(&requested) {
                prop_assert_eq!(granted, requested);
            }
        }
        prop_assert_eq!(times.grant(None), times.default_secs);
        // T1 <= T2 <= the grant, for every grant in range.
        let span = times.max_secs - times.min_secs + 1;
        for granted in [times.min_secs, times.default_secs, times.max_secs, times.min_secs + spot % span] {
            let (t1, t2) = times.renewal_times(granted);
            prop_assert!(t1 <= t2, "{t1} {t2} for {granted} of {times:?}");
            prop_assert!(t2 <= granted, "{t2} for {granted} of {times:?}");
        }
        round_trips(&times)?;
    }

    #[test]
    fn fixed_times_validate_and_grant_one_value(secs in 1u32..=31_536_000, asked in any::<Option<u32>>()) {
        let times = LeaseTimes::fixed(secs);
        prop_assert!(times.validate("lease").is_ok());
        prop_assert_eq!(times.grant(asked), secs);
        let (t1, t2) = times.renewal_times(secs);
        prop_assert!(t1 <= t2 && t2 <= secs);
    }
}

// ---------------------------------------------------------------------------------------
// Client identities

fn small_key() -> impl Strategy<Value = ClientKey> {
    (
        0u8..3,
        prop::collection::vec(0u8..2, 0..=4),
        maybe(prop::collection::vec(0u8..2, 0..=3)),
    )
        .prop_map(|(htype, chaddr, client_id)| ClientKey {
            htype,
            chaddr: HexBytes(chaddr),
            client_id: client_id.map(HexBytes),
        })
}

fn client_key() -> impl Strategy<Value = ClientKey> {
    (any::<u8>(), hex(MAX_CHADDR), maybe(hex(MAX_CLIENT_ID))).prop_map(
        |(htype, chaddr, client_id)| ClientKey {
            htype,
            chaddr,
            client_id,
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn identity_is_what_write_identity_writes(key in client_key()) {
        let mut out = [0u8; MAX_IDENTITY];
        let len = write_identity(
            key.htype,
            &key.chaddr.0,
            key.client_id.as_ref().map(|id| id.0.as_slice()),
            &mut out,
        );
        prop_assert_eq!(key.identity(), out[..len].to_vec());
        prop_assert!(len <= MAX_IDENTITY);
        match &key.client_id {
            Some(id) => {
                prop_assert_eq!(key.identity(), [&[1u8][..], &id.0].concat());
            }
            None => {
                prop_assert_eq!(key.identity(), [&[0u8, key.htype][..], &key.chaddr.0].concat());
            }
        }
        round_trips(&key)?;
    }

    #[test]
    fn a_client_identifier_replaces_the_hardware_address(
        id in hex(MAX_CLIENT_ID),
        (htype_a, chaddr_a) in (any::<u8>(), hex(MAX_CHADDR)),
        (htype_b, chaddr_b) in (any::<u8>(), hex(MAX_CHADDR)),
    ) {
        let with = |htype, chaddr| ClientKey { htype, chaddr, client_id: Some(id.clone()) };
        prop_assert_eq!(with(htype_a, chaddr_a).identity(), with(htype_b, chaddr_b).identity());
    }

    #[test]
    fn identities_without_a_client_identifier_follow_the_hardware(a in small_key(), b in small_key()) {
        let (a, b) = (
            ClientKey { client_id: None, ..a },
            ClientKey { client_id: None, ..b },
        );
        prop_assert_eq!(
            a.identity() == b.identity(),
            (a.htype, &a.chaddr) == (b.htype, &b.chaddr)
        );
    }

    #[test]
    fn the_two_kinds_of_identity_never_meet(a in small_key(), b in small_key()) {
        let with = ClientKey { client_id: Some(a.client_id.clone().unwrap_or_default()), ..a };
        let without = ClientKey { client_id: None, ..b };
        prop_assert_ne!(with.identity(), without.identity());
    }

    #[test]
    fn long_inputs_are_cut_to_their_maxima(
        chaddr in prop::collection::vec(any::<u8>(), MAX_CHADDR..=40),
        id in prop::collection::vec(any::<u8>(), MAX_CLIENT_ID..=300),
    ) {
        let mut out = [0u8; MAX_IDENTITY];
        let len = write_identity(1, &chaddr, None, &mut out);
        prop_assert_eq!(len, 2 + MAX_CHADDR);
        let len = write_identity(1, &chaddr, Some(&id), &mut out);
        prop_assert_eq!(len, MAX_IDENTITY);
        prop_assert_eq!(&out[1..], &id[..MAX_CLIENT_ID]);
    }
}

// ---------------------------------------------------------------------------------------
// Merging option sets

fn option_value() -> impl Strategy<Value = OptionValue> {
    (
        prop::sample::select(vec!["dhcp4", "dhcp6", "vendor-a"]),
        1u16..6,
        prop::collection::vec(any::<u8>(), 0..=4),
    )
        .prop_map(|(space, code, data)| OptionValue {
            space: OptionSpace::new(space).expect("space"),
            code,
            data: HexBytes(data),
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn merging_lets_the_last_set_win_and_keeps_the_first_order(
        sets in prop::collection::vec(prop::collection::vec(option_value(), 0..=6), 0..=5),
    ) {
        let merged = merge(sets.iter().map(Vec::as_slice));
        // No code twice.
        let keys: BTreeSet<_> = merged.iter().map(|v| (v.space.clone(), v.code)).collect();
        prop_assert_eq!(keys.len(), merged.len());
        // The model: first appearance orders, the last value wins.
        let mut model: Vec<OptionValue> = Vec::new();
        for value in sets.iter().flatten() {
            match model.iter_mut().find(|held| held.space == value.space && held.code == value.code) {
                Some(held) => held.data = value.data.clone(),
                None => model.push(value.clone()),
            }
        }
        prop_assert_eq!(&merged, &model);
        // Merging the merge with nothing, or by itself, changes nothing.
        prop_assert_eq!(merge([merged.as_slice()]), merged.clone());
        prop_assert_eq!(merge([merged.as_slice(), merged.as_slice()]), merged);
    }
}

// ---------------------------------------------------------------------------------------
// The reservation check

type Candidate = (u8, Option<u8>, u8);

fn candidates() -> impl Strategy<Value = Vec<ReservationCandidate>> {
    // (scope, identity, address), over small alphabets so that collisions are common; every
    // candidate is a host of its own.
    prop::collection::vec((0u8..2, maybe(0u8..4), 1u8..5), 0..=6).prop_map(
        |rows: Vec<Candidate>| {
            rows.into_iter()
                .enumerate()
                .map(|(index, (scope, identity, address))| ReservationCandidate {
                    host: HostId::from_uuid(Uuid::from_u128(index as u128 + 1)),
                    scope: PrefixId::from_uuid(Uuid::from_u128(u128::from(scope) + 1000)),
                    address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, address)),
                    identity: identity.map(|octet| vec![0, 1, octet]),
                })
                .collect()
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn reservations_warn_exactly_when_they_collide(candidates in candidates()) {
        let warnings = check_reservations(&candidates);
        let identified = candidates.iter().all(|c| c.identity.is_some());
        let addresses: BTreeSet<_> = candidates.iter().map(|c| c.address).collect();
        let clients: BTreeSet<_> = candidates
            .iter()
            .filter_map(|c| c.identity.clone().map(|identity| (c.scope, identity)))
            .collect();
        let clean = identified
            && addresses.len() == candidates.len()
            && clients.len() == candidates.len();
        prop_assert_eq!(warnings.is_empty(), clean, "{:?}", warnings);

        // Each kind of warning counts what the model counts.
        let count = |wanted: fn(&ReservationWarning) -> bool| warnings.iter().filter(|w| wanted(w)).count();
        prop_assert_eq!(
            count(|w| matches!(w, ReservationWarning::NoIdentity { .. })),
            candidates.iter().filter(|c| c.identity.is_none()).count()
        );
        let shared_addresses = addresses
            .iter()
            .filter(|address| candidates.iter().filter(|c| &c.address == *address).count() > 1)
            .count();
        prop_assert_eq!(
            count(|w| matches!(w, ReservationWarning::AddressCollision { .. })),
            shared_addresses
        );
        let shared_clients = clients
            .iter()
            .filter(|(scope, identity)| {
                candidates
                    .iter()
                    .filter(|c| &c.scope == scope && c.identity.as_ref() == Some(identity))
                    .count()
                    > 1
            })
            .count();
        prop_assert_eq!(
            count(|w| matches!(w, ReservationWarning::ClientCollision { .. })),
            shared_clients
        );
        // A host listed twice collides with no one.
        let doubled: Vec<ReservationCandidate> =
            candidates.iter().chain(candidates.iter()).cloned().collect();
        prop_assert_eq!(check_reservations(&doubled), warnings);
    }
}

// ---------------------------------------------------------------------------------------
// Encodings of the rows

fn lease_state() -> impl Strategy<Value = BindingState> {
    prop::sample::select(vec![
        BindingState::Free,
        BindingState::Active,
        BindingState::Expired,
        BindingState::Released,
        BindingState::Abandoned,
        BindingState::Reset,
        BindingState::Backup,
    ])
}

fn ddns_policy() -> impl Strategy<Value = DdnsPolicy> {
    (
        any::<bool>(),
        maybe(id(ZoneId::from_uuid)),
        any::<bool>(),
        maybe(any::<u32>()),
        prop::sample::select(vec![DdnsConflict::Protect, DdnsConflict::Replace]),
        (any::<bool>(), any::<bool>(), any::<bool>()),
    )
        .prop_map(
            |(enabled, forward_zone, reverse, ttl, conflict, (a, legacy, foreign))| DdnsPolicy {
                enabled,
                forward_zone,
                reverse,
                ttl,
                conflict,
                client_may_update_a: a,
                legacy_clients: legacy,
                refuse_foreign: foreign,
            },
        )
}

/// Times as the model stores them, not necessarily valid ones.
fn any_lease_times() -> impl Strategy<Value = LeaseTimes> {
    (
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        maybe(any::<u32>()),
        maybe(any::<u32>()),
    )
        .prop_map(
            |(default_secs, min_secs, max_secs, t1_secs, t2_secs)| LeaseTimes {
                default_secs,
                min_secs,
                max_secs,
                t1_secs,
                t2_secs,
            },
        )
}

fn ddns_state() -> impl Strategy<Value = DdnsState> {
    (
        maybe(dns_name()),
        maybe(dns_name()),
        maybe(hex(32)),
        maybe(text()),
        maybe(timestamp()),
    )
        .prop_map(|(forward, reverse, dhcid, last_error, updated)| DdnsState {
            forward,
            reverse,
            dhcid,
            last_error,
            updated,
        })
}

fn fingerprint() -> impl Strategy<Value = Fingerprint> {
    (
        hex(20),
        maybe(text()),
        any::<bool>(),
        any::<bool>(),
        maybe(any::<u16>()),
    )
        .prop_map(
            |(parameters, vendor_class, user_class, client_fqdn, architecture)| Fingerprint {
                parameters,
                vendor_class,
                user_class,
                client_fqdn,
                architecture,
            },
        )
}

fn relay() -> impl Strategy<Value = RelayInfo> {
    (
        ipv4(),
        maybe(hex(16)),
        maybe(hex(16)),
        maybe(ipv4()),
        maybe(ipv4()),
        hex(40),
    )
        .prop_map(
            |(giaddr, circuit_id, remote_id, link_selection, server_id_override, raw)| RelayInfo {
                giaddr,
                circuit_id,
                remote_id,
                link_selection,
                server_id_override,
                raw,
            },
        )
}

fn lease() -> impl Strategy<Value = Lease> {
    let times = (
        timestamp(),
        timestamp(),
        maybe(timestamp()),
        maybe(timestamp()),
        maybe(timestamp()),
    );
    let names = (maybe(text()), maybe(text()));
    let attachments = (maybe(fingerprint()), maybe(relay()), maybe(timestamp()));
    (
        ipv4(),
        (id(VrfId::from_uuid), id(PrefixId::from_uuid)),
        client_key(),
        lease_state(),
        times,
        (
            any::<u64>(),
            maybe(prop::sample::select(vec![
                PoolShare::Primary,
                PoolShare::Secondary,
            ])),
        ),
        names,
        ddns_state(),
        attachments,
    )
        .prop_map(
            |(
                addr,
                (vrf, scope),
                client,
                state,
                (cltt, ends, tstp, tsfp, atsfp),
                (node, share),
                (hostname, fqdn),
                ddns,
                (fingerprint, relay, observed_at),
            )| Lease {
                addr,
                vrf,
                scope,
                client,
                state,
                cltt,
                ends,
                tstp,
                tsfp,
                atsfp,
                node: NodeId(node),
                share,
                hostname,
                fqdn,
                fqdn_flags: None,
                ddns_policy: None,
                ddns,
                fingerprint,
                relay,
                observed_at,
            },
        )
}

fn matcher() -> impl Strategy<Value = Match> {
    prop_oneof![
        (text(), any::<bool>()).prop_map(|(value, prefix)| Match::VendorClass { value, prefix }),
        text().prop_map(|value| Match::UserClass { value }),
        prop::array::uniform6(maybe(any::<u8>())).prop_map(|positions| Match::Mac {
            pattern: MacPattern::new(&pattern_text(&positions)).expect("pattern"),
        }),
        hex(20).prop_map(|value| Match::ClientId { value }),
        hex(20).prop_map(|value| Match::CircuitId { value }),
        hex(20).prop_map(|value| Match::RemoteId { value }),
        any::<u16>().prop_map(|code| Match::Architecture { code }),
        (text(), any::<bool>()).prop_map(|(value, prefix)| Match::HostName { value, prefix }),
    ]
}

fn term() -> impl Strategy<Value = Term> {
    prop_oneof![
        id(tenko_core::dhcp::ClassId::from_uuid).prop_map(Term::Class),
        id(tenko_core::dhcp::ClassId::from_uuid).prop_map(Term::NotClass),
        matcher().prop_map(Term::Match),
        matcher().prop_map(Term::NotMatch),
    ]
}

fn policy() -> impl Strategy<Value = Policy> {
    let action = (
        maybe((ip(), ip()).prop_map(|(first, last)| AddressRange { first, last })),
        maybe(any_lease_times()),
        maybe(ddns_policy()),
    )
        .prop_map(|(range, lease, ddns)| PolicyAction { range, lease, ddns });
    (
        id(tenko_core::dhcp::PolicyId::from_uuid),
        text(),
        maybe(id(PrefixId::from_uuid)),
        (any::<u32>(), any::<bool>()),
        (
            prop::sample::select(vec![Join::And, Join::Or]),
            prop::collection::vec(term(), 1..=6),
        ),
        action,
        maybe(text()),
        (stamp(), stamp()),
    )
        .prop_map(
            |(
                id,
                name,
                scope,
                (order, enabled),
                (join, terms),
                action,
                description,
                (created, updated),
            )| {
                Policy {
                    id,
                    name,
                    scope,
                    order,
                    enabled,
                    condition: Condition { join, terms },
                    action,
                    description,
                    created,
                    updated,
                }
            },
        )
}

fn class() -> impl Strategy<Value = Class> {
    (
        id(tenko_core::dhcp::ClassId::from_uuid),
        text(),
        prop::collection::vec(matcher(), 0..=6),
        maybe(text()),
        (stamp(), stamp()),
    )
        .prop_map(
            |(id, name, matches, description, (created, updated))| Class {
                id,
                name,
                matches,
                description,
                created,
                updated,
            },
        )
}

fn filter_row() -> impl Strategy<Value = Filter> {
    (
        id(tenko_core::dhcp::FilterId::from_uuid),
        prop::array::uniform6(maybe(any::<u8>())),
        prop::sample::select(vec![FilterKind::Allow, FilterKind::Deny]),
        maybe(text()),
        (stamp(), stamp()),
    )
        .prop_map(|(id, positions, kind, note, (created, updated))| Filter {
            id,
            mac: MacPattern::new(&pattern_text(&positions)).expect("pattern"),
            kind,
            note,
            created,
            updated,
        })
}

fn option_set() -> impl Strategy<Value = OptionSet> {
    (
        owner(),
        prop::collection::vec(
            (option_value(), prop::collection::vec(any::<u8>(), 0..=300)).prop_map(
                |(mut value, long)| {
                    if value.code == 5 {
                        value.data = HexBytes(long);
                    }
                    value
                },
            ),
            0..=8,
        ),
        stamp(),
    )
        .prop_map(|(owner, values, updated)| OptionSet {
            owner,
            values,
            updated,
        })
}

fn settings() -> impl Strategy<Value = DhcpSettings> {
    (
        any_lease_times(),
        any::<bool>(),
        ddns_policy(),
        maybe(any::<bool>()),
        maybe(any::<u32>()),
        maybe(stamp()),
    )
        .prop_map(
            |(lease, authoritative, ddns, conflict_detection, history_days, updated)| {
                DhcpSettings {
                    lease,
                    authoritative,
                    ddns,
                    conflict_detection,
                    history_days,
                    updated,
                }
            },
        )
}

fn scope() -> impl Strategy<Value = Scope> {
    (
        id(PrefixId::from_uuid),
        (any::<bool>(), any::<bool>()),
        maybe(any_lease_times()),
        maybe(any::<bool>()),
        maybe(ip()),
        ddns_policy(),
        maybe(id(tenko_core::dhcp::SharedNetworkId::from_uuid)),
        prop::collection::vec(id(tenko_core::dhcp::ClassId::from_uuid), 0..=4),
        maybe(text()),
        (stamp(), stamp()),
    )
        .prop_map(
            |(
                prefix,
                (enabled, restricted),
                lease,
                authoritative,
                server_id,
                ddns,
                shared_network,
                classes,
                description,
                (created, updated),
            )| Scope {
                v6: None,
                prefix,
                enabled,
                lease,
                authoritative,
                server_id,
                ddns,
                shared_network,
                restricted,
                classes,
                description,
                created,
                updated,
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn leases_round_trip(lease in lease()) {
        round_trips(&lease)?;
    }

    #[test]
    fn leases_without_the_optional_parts_round_trip(lease in lease()) {
        let bare = Lease {
            client: ClientKey { client_id: None, ..lease.client.clone() },
            relay: None,
            fingerprint: None,
            ..lease
        };
        round_trips(&bare)?;
    }

    #[test]
    fn policies_round_trip(policy in policy()) {
        round_trips(&policy)?;
    }

    #[test]
    fn classes_round_trip(class in class()) {
        round_trips(&class)?;
    }

    #[test]
    fn filters_round_trip(filter in filter_row()) {
        round_trips(&filter)?;
    }

    #[test]
    fn option_sets_round_trip(set in option_set()) {
        round_trips(&set)?;
    }

    #[test]
    fn settings_round_trip(settings in settings()) {
        round_trips(&settings)?;
    }

    #[test]
    fn scopes_round_trip(scope in scope()) {
        round_trips(&scope)?;
    }
}
