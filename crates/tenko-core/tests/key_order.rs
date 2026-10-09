//! Property tests of the order-preserving key encoding.
//!
//! For every type that implements `KeyCodec` (primitives, strings and bytes, UUID-based
//! identifiers, IP addresses and networks, options, the domain types of `tenko-core` and
//! composite tuples) the suite proves, over generated pairs of values `a` and `b`:
//!
//! - order: `a.cmp(&b)` equals the byte-wise comparison of `encode_key(&a)` and
//!   `encode_key(&b)`, so `a < b` exactly when the keys sort that way and `a == b` exactly
//!   when the keys are equal;
//! - round trip: `decode_key::<T>(&encode_key(&a)) == Ok(a)`;
//! - self-delimiting: two concatenated keys decode one after the other, no proper prefix of
//!   a key decodes, and a key followed by a byte is rejected as trailing input;
//! - composability: `(a, u16::MAX)` and `(b, 0)` still sort like the tuples, which only
//!   holds when no key is a prefix of another and no suffix can reorder two keys.
//!
//! Test data stays inside the documentation ranges (IPv4 192.0.2.0/24, 198.51.100.0/24 and
//! 203.0.113.0/24, IPv6 `2001:db8::/32`, MAC addresses 00-00-5E-00-53-xx, DNS names under
//! `example.test`). Deterministic regression tests cover the tricky layouts: a string that
//! is a prefix of another followed by components that start with `0xFF`, `None` against
//! `Some`, IPv4 against IPv6, negative against positive integers, and the rejection of
//! trailing, truncated and malformed input.

use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use bytes::Bytes;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use proptest::{array::uniform6, prelude::*, strategy::ValueTree, test_runner::TestRunner};
use tenko_core::{
    AddressId, ApiTokenId, AuditSeq, ConnectorId, CounterKey, CustomFieldId, HostId,
    IdempotencyKey, ImportId, InterfaceId, JobId, MacAddr, NodeId, ObjectKind, ObjectRef,
    ObservationId, PrefixId, ProposalId, RangeId, RequestId, Revision, SecretId, SessionId, SiteId,
    TableName, TenantId, Timestamp, UserId, VlanId, VrfId,
    codec::{KeyCodec, KeyError, decode_key, encode_key, prefix_successor},
    names::NAMESPACES,
    net::{Duid, Fqdn, HostName},
};
use uuid::Uuid;

/// Nanoseconds of 0001-01-01T00:00:00Z, the earliest supported timestamp.
const MIN_NANOS: i128 = -62_135_596_800 * 1_000_000_000;
/// Nanoseconds of 9999-12-31T23:59:59.999999999Z, the latest supported timestamp.
const MAX_NANOS: i128 = 253_402_300_800 * 1_000_000_000 - 1;

type Pair<T> = (T, T);

// ---------------------------------------------------------------------------------------
// The generic checks
// ---------------------------------------------------------------------------------------

/// Proves order, round trip and self-delimitation for one pair of values.
fn check<T: KeyCodec + Ord + Debug + Clone>(a: &T, b: &T) {
    let key_a = encode_key(a);
    let key_b = encode_key(b);

    // Order, equality and round trip.
    assert_eq!(
        a.cmp(b),
        key_a.cmp(&key_b),
        "order of {a:?} and {b:?} differs from the order of their keys {:02x?} and {:02x?}",
        &key_a[..],
        &key_b[..],
    );
    assert_eq!(a == b, key_a == key_b, "equality of {a:?} and {b:?}");
    assert_eq!(
        decode_key::<T>(&key_a),
        Ok(a.clone()),
        "round trip of {a:?}"
    );
    assert_eq!(
        decode_key::<T>(&key_b),
        Ok(b.clone()),
        "round trip of {b:?}"
    );

    // Self-delimiting: two keys back to back decode one after the other.
    let mut joined = Vec::new();
    a.encode_key(&mut joined);
    b.encode_key(&mut joined);
    let mut input = joined.as_slice();
    assert_eq!(
        T::decode_key(&mut input),
        Ok(a.clone()),
        "first of {a:?}, {b:?}"
    );
    assert_eq!(
        T::decode_key(&mut input),
        Ok(b.clone()),
        "second of {a:?}, {b:?}"
    );
    assert!(input.is_empty(), "bytes left after {a:?}, {b:?}");

    // Prefix-free: no proper prefix of a key is a key, and trailing input is rejected.
    for (value, key) in [(a, &key_a), (b, &key_b)] {
        for len in 0..key.len() {
            assert!(
                decode_key::<T>(&key[..len]).is_err(),
                "the first {len} bytes of the key of {value:?} decoded"
            );
        }
        let mut trailing = key.to_vec();
        trailing.push(0x00);
        assert_eq!(
            decode_key::<T>(&trailing),
            Err(KeyError::Trailing(1)),
            "trailing byte after the key of {value:?}"
        );
    }

    // Composable: a trailing component cannot reorder two keys. The extreme suffixes
    // (largest after `a`, smallest after `b`) are the ones that expose a key that is a
    // prefix of another or whose terminator sorts above a following byte.
    let left = (a.clone(), u16::MAX);
    let right = (b.clone(), 0_u16);
    assert_eq!(
        left.cmp(&right),
        encode_key(&left).cmp(&encode_key(&right)),
        "order of ({a:?}, MAX) and ({b:?}, 0)"
    );
    let forward = (a.clone(), b.clone());
    let backward = (b.clone(), a.clone());
    assert_eq!(
        forward.cmp(&backward),
        encode_key(&forward).cmp(&encode_key(&backward)),
        "order of ({a:?}, {b:?}) and ({b:?}, {a:?})"
    );
    assert_eq!(decode_key::<(T, T)>(&encode_key(&forward)), Ok(forward));
}

// ---------------------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------------------

/// Two independent values, or (one time in five) the same value twice.
fn pairs<T: Debug + Clone + 'static>(strategy: BoxedStrategy<T>) -> BoxedStrategy<Pair<T>> {
    prop_oneof![
        4 => (strategy.clone(), strategy.clone()),
        1 => strategy.prop_map(|a| (a.clone(), a)),
    ]
    .boxed()
}

/// Pairs of 2-tuples whose components tie independently, so that shared leading components
/// (and with them the interesting suffix comparisons) are common.
fn zip2<A, B>(a: BoxedStrategy<Pair<A>>, b: BoxedStrategy<Pair<B>>) -> BoxedStrategy<Pair<(A, B)>>
where
    A: Debug + 'static,
    B: Debug + 'static,
{
    (a, b)
        .prop_map(|((a1, a2), (b1, b2))| ((a1, b1), (a2, b2)))
        .boxed()
}

/// Pairs of 3-tuples, see [`zip2`].
fn zip3<A, B, C>(
    a: BoxedStrategy<Pair<A>>,
    b: BoxedStrategy<Pair<B>>,
    c: BoxedStrategy<Pair<C>>,
) -> BoxedStrategy<Pair<(A, B, C)>>
where
    A: Debug + 'static,
    B: Debug + 'static,
    C: Debug + 'static,
{
    (a, b, c)
        .prop_map(|((a1, a2), (b1, b2), (c1, c2))| ((a1, b1, c1), (a2, b2, c2)))
        .boxed()
}

/// Pairs of 4-tuples, see [`zip2`].
fn zip4<A, B, C, D>(
    a: BoxedStrategy<Pair<A>>,
    b: BoxedStrategy<Pair<B>>,
    c: BoxedStrategy<Pair<C>>,
    d: BoxedStrategy<Pair<D>>,
) -> BoxedStrategy<Pair<(A, B, C, D)>>
where
    A: Debug + 'static,
    B: Debug + 'static,
    C: Debug + 'static,
    D: Debug + 'static,
{
    (a, b, c, d)
        .prop_map(|((a1, a2), (b1, b2), (c1, c2), (d1, d2))| ((a1, b1, c1, d1), (a2, b2, c2, d2)))
        .boxed()
}

/// A byte that is often one of the escape and terminator bytes.
fn byte() -> BoxedStrategy<u8> {
    prop_oneof![
        Just(0x00_u8),
        Just(0x01_u8),
        Just(0xFF_u8),
        Just(0xFE_u8),
        any::<u8>(),
    ]
    .boxed()
}

/// Byte strings biased towards `0x00`, `0x01` and `0xFF`, mostly short so that prefixes
/// of one another are common.
fn byte_vecs() -> BoxedStrategy<Vec<u8>> {
    prop_oneof![
        8 => prop::collection::vec(byte(), 0..=6),
        1 => prop::collection::vec(byte(), 0..=40),
    ]
    .boxed()
}

fn bytes_values() -> BoxedStrategy<Bytes> {
    byte_vecs().prop_map(Bytes::from).boxed()
}

/// Strings with embedded NUL, `U+0001`, `U+00FF` (UTF-8 `0xC3 0xBF`) and the highest scalar
/// value (`0xF4 0x8F 0xBF 0xBF`), mostly short, plus fully arbitrary strings.
fn strings() -> BoxedStrategy<String> {
    let alphabet = vec![
        '\0',
        '\u{1}',
        '\u{7f}',
        '\u{ff}',
        'a',
        'b',
        ' ',
        '\u{10ffff}',
    ];
    prop_oneof![
        3 => "[\\x00\\x01\\xff a-z]{0,8}",
        3 => prop::collection::vec(prop::sample::select(alphabet), 0..=6)
            .prop_map(|chars| chars.into_iter().collect::<String>()),
        1 => any::<String>(),
    ]
    .boxed()
}

fn arbitrary_strings() -> BoxedStrategy<String> {
    any::<String>().boxed()
}

fn edge_u16() -> BoxedStrategy<u16> {
    prop_oneof![
        2 => any::<u16>(),
        1 => prop::sample::select(vec![0_u16, 1, 0xFF, 0x100, 0x101, 0xFFFE, 0xFFFF]),
    ]
    .boxed()
}

macro_rules! edge_ints {
    ($($name:ident: $ty:ty => [$($value:expr),+ $(,)?]),+ $(,)?) => {$(
        fn $name() -> BoxedStrategy<$ty> {
            prop_oneof![
                3 => any::<$ty>(),
                2 => prop::sample::select(vec![$($value),+]),
            ]
            .boxed()
        }
    )+};
}

edge_ints! {
    edge_u8: u8 => [0, 1, 0x7F, 0x80, 0xFE, 0xFF],
    edge_u32: u32 => [0, 1, 0xFF, 0x100, 0xFFFF, 0x1_0000, 0xFFFF_FFFE, 0xFFFF_FFFF],
    edge_u64: u64 => [
        0, 1, 0xFF, 0x100, 0xFFFF_FFFF, 0x1_0000_0000, u64::MAX - 1, u64::MAX,
    ],
    edge_u128: u128 => [
        0, 1, 0xFF, 0x100, u128::from(u64::MAX), u128::from(u64::MAX) + 1, u128::MAX - 1,
        u128::MAX,
    ],
    edge_i64: i64 => [
        i64::MIN, i64::MIN + 1, -0x1_0000_0000, -0x100, -0xFF, -1, 0, 1, 0xFF, 0x100,
        i64::MAX - 1, i64::MAX,
    ],
    edge_i128: i128 => [
        i128::MIN, i128::MIN + 1, i128::from(i64::MIN) - 1, -0x100, -1, 0, 1,
        i128::from(i64::MAX) + 1, i128::MAX - 1, i128::MAX,
    ],
}

fn uuids() -> BoxedStrategy<Uuid> {
    prop_oneof![
        1 => any::<[u8; 16]>(),
        1 => proptest::array::uniform16(byte()),
    ]
    .prop_map(Uuid::from_bytes)
    .boxed()
}

/// IPv4 addresses inside 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24.
fn ipv4_addrs() -> BoxedStrategy<Ipv4Addr> {
    (
        prop::sample::select(vec![[192_u8, 0, 2], [198, 51, 100], [203, 0, 113]]),
        byte(),
    )
        .prop_map(|([a, b, c], d)| Ipv4Addr::new(a, b, c, d))
        .boxed()
}

/// IPv6 addresses inside `2001:db8::/32`.
fn ipv6_addrs() -> BoxedStrategy<Ipv6Addr> {
    let segment = prop_oneof![
        Just(0_u16),
        Just(1_u16),
        Just(0xFFFF_u16),
        Just(0x00FF_u16),
        any::<u16>(),
    ];
    uniform6(segment)
        .prop_map(|s| Ipv6Addr::new(0x2001, 0x0db8, s[0], s[1], s[2], s[3], s[4], s[5]))
        .boxed()
}

fn ip_addrs() -> BoxedStrategy<IpAddr> {
    prop_oneof![
        ipv4_addrs().prop_map(IpAddr::V4),
        ipv6_addrs().prop_map(IpAddr::V6),
    ]
    .boxed()
}

/// Prefix lengths 24 to 32.
fn ipv4_prefix_lens() -> BoxedStrategy<u8> {
    prop_oneof![Just(24_u8), Just(32_u8), 24_u8..=32].boxed()
}

/// Prefix lengths 32 to 128.
fn ipv6_prefix_lens() -> BoxedStrategy<u8> {
    prop_oneof![Just(32_u8), Just(64_u8), Just(128_u8), 32_u8..=128].boxed()
}

/// Networks keep their host bits (`192.0.2.5/24` is a valid `Ipv4Net`), which exercises
/// the full address-then-length layout.
fn ipv4_net_pairs() -> BoxedStrategy<Pair<Ipv4Net>> {
    zip2(pairs(ipv4_addrs()), pairs(ipv4_prefix_lens()))
        .prop_map(|((a1, l1), (a2, l2))| {
            (
                Ipv4Net::new(a1, l1).expect("prefix length"),
                Ipv4Net::new(a2, l2).expect("prefix length"),
            )
        })
        .boxed()
}

fn ipv6_net_pairs() -> BoxedStrategy<Pair<Ipv6Net>> {
    zip2(pairs(ipv6_addrs()), pairs(ipv6_prefix_lens()))
        .prop_map(|((a1, l1), (a2, l2))| {
            (
                Ipv6Net::new(a1, l1).expect("prefix length"),
                Ipv6Net::new(a2, l2).expect("prefix length"),
            )
        })
        .boxed()
}

fn ip_nets() -> BoxedStrategy<IpNet> {
    prop_oneof![
        ipv4_net_pairs().prop_map(|(net, _)| IpNet::V4(net)),
        ipv6_net_pairs().prop_map(|(net, _)| IpNet::V6(net)),
    ]
    .boxed()
}

/// Timestamps across years 1 to 9999: the whole range, around the epoch (both signs, with
/// sub-second and whole-second steps), and at both ends of the range.
fn timestamps() -> BoxedStrategy<Timestamp> {
    prop_oneof![
        4 => MIN_NANOS..=MAX_NANOS,
        3 => -3_000_000_000_i128..3_000_000_000,
        2 => -5_i128..5,
        1 => MIN_NANOS..MIN_NANOS + 3_000_000_000,
        1 => MAX_NANOS - 3_000_000_000..=MAX_NANOS,
        2 => prop::sample::select(vec![MIN_NANOS, -1_000_000_000, -1, 0, 1, 1_000_000_000, MAX_NANOS]),
    ]
    .prop_map(|nanos| Timestamp::from_unix_nanos(nanos).expect("inside years 1 to 9999"))
    .boxed()
}

/// MAC addresses 00-00-5E-00-53-00 to 00-00-5E-00-53-FF.
fn mac_addrs() -> BoxedStrategy<MacAddr> {
    byte()
        .prop_map(|last| MacAddr::new([0x00, 0x00, 0x5E, 0x00, 0x53, last]))
        .boxed()
}

/// `<labels>.example.test` with one to three labels from a small alphabet, so that names
/// share prefixes and differ around `.`, `-` and `_`.
fn dns_names() -> BoxedStrategy<String> {
    let label = "[a-c0-9_]([a-c0-9_-]{0,3}[a-c0-9_])?";
    prop::collection::vec(label, 1..=3)
        .prop_map(|labels| format!("{}.example.test", labels.join(".")))
        .boxed()
}

fn fqdns() -> BoxedStrategy<Fqdn> {
    dns_names()
        .prop_map(|name| Fqdn::new(&name).expect("valid DNS name"))
        .boxed()
}

fn host_names() -> BoxedStrategy<HostName> {
    dns_names()
        .prop_map(|name| HostName::new(&name).expect("valid host name"))
        .boxed()
}

fn duids() -> BoxedStrategy<Duid> {
    prop_oneof![
        9 => prop::collection::vec(byte(), 2..=5),
        1 => prop::collection::vec(byte(), 2..=130),
    ]
    .prop_map(|bytes| Duid::new(bytes).expect("2 to 130 bytes"))
    .boxed()
}

fn object_kinds() -> BoxedStrategy<ObjectKind> {
    prop::sample::select(ObjectKind::ALL.to_vec()).boxed()
}

fn object_refs() -> BoxedStrategy<ObjectRef> {
    (object_kinds(), uuids())
        .prop_map(|(kind, id)| ObjectRef::new(kind, id))
        .boxed()
}

/// Valid namespaced names: a known namespace plus up to three short segments over a small
/// alphabet (`-` sorts below `.`, `_` above the digits), or one long segment.
fn table_names() -> BoxedStrategy<TableName> {
    let namespace = prop::sample::select(NAMESPACES.to_vec());
    prop_oneof![
        8 => (namespace.clone(), prop::collection::vec("[a-c0-9_-]{1,3}", 1..=3))
            .prop_map(|(ns, segments)| format!("{ns}.{}", segments.join("."))),
        1 => (namespace, "[a-z0-9_-]{1,100}").prop_map(|(ns, segment)| format!("{ns}.{segment}")),
    ]
    .prop_map(|name| TableName::new(name).expect("valid namespaced name"))
    .boxed()
}

/// A counter key whose qualifier is empty, the key encoding of a typed qualifier, or
/// arbitrary raw bytes (built through the serde form, the fields are private).
fn counter_keys() -> BoxedStrategy<CounterKey> {
    let name = prop::sample::select(vec![
        "ipam.tree",
        "ipam.tree-2",
        "ipam.tree.v2",
        "ipam.tre",
        "sys.journal",
    ]);
    prop_oneof![
        1 => name.clone().prop_map(CounterKey::new),
        2 => (name.clone(), byte_vecs()).prop_map(|(name, qualifier)| CounterKey::with(name, &qualifier)),
        1 => (name.clone(), uuids()).prop_map(|(name, id)| CounterKey::with(name, &id)),
        1 => (name.clone(), edge_u16()).prop_map(|(name, id)| CounterKey::with(name, &id)),
        3 => (name, byte_vecs()).prop_map(|(name, qualifier)| {
            serde_json::from_value(serde_json::json!({ "name": name, "qualifier": qualifier }))
                .expect("counter key")
        }),
    ]
    .boxed()
}

/// Visible ASCII, 1 to 255 characters: short strings over a small alphabet that includes
/// the boundaries `!` and `~`, short strings over the whole range, and long strings.
fn idempotency_keys() -> BoxedStrategy<IdempotencyKey> {
    prop_oneof![
        3 => "[!#a-b~]{1,4}",
        3 => "[!-~]{1,8}",
        1 => "[!-~]{1,255}",
    ]
    .prop_map(|key| IdempotencyKey::new(key).expect("visible ASCII"))
    .boxed()
}

// ---------------------------------------------------------------------------------------
// Properties of single types
// ---------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn u8_keys((a, b) in pairs(edge_u8())) {
        check(&a, &b);
    }

    #[test]
    fn u16_keys((a, b) in pairs(edge_u16())) {
        check(&a, &b);
    }

    #[test]
    fn u32_keys((a, b) in pairs(edge_u32())) {
        check(&a, &b);
    }

    #[test]
    fn u64_keys((a, b) in pairs(edge_u64())) {
        check(&a, &b);
    }

    #[test]
    fn u128_keys((a, b) in pairs(edge_u128())) {
        check(&a, &b);
    }

    #[test]
    fn i64_keys((a, b) in pairs(edge_i64())) {
        check(&a, &b);
    }

    #[test]
    fn i128_keys((a, b) in pairs(edge_i128())) {
        check(&a, &b);
    }

    #[test]
    fn bool_keys(a in any::<bool>(), b in any::<bool>()) {
        check(&a, &b);
    }

    #[test]
    fn string_keys((a, b) in pairs(strings())) {
        check(&a, &b);
    }

    #[test]
    fn arbitrary_string_keys((a, b) in pairs(arbitrary_strings())) {
        check(&a, &b);
    }

    #[test]
    fn byte_vec_keys((a, b) in pairs(byte_vecs())) {
        check(&a, &b);
    }

    #[test]
    fn bytes_keys((a, b) in pairs(bytes_values())) {
        check(&a, &b);
    }

    #[test]
    fn uuid_keys((a, b) in pairs(uuids())) {
        check(&a, &b);
    }

    #[test]
    fn ipv4_addr_keys((a, b) in pairs(ipv4_addrs())) {
        check(&a, &b);
    }

    #[test]
    fn ipv6_addr_keys((a, b) in pairs(ipv6_addrs())) {
        check(&a, &b);
    }

    #[test]
    fn ip_addr_keys((a, b) in pairs(ip_addrs())) {
        check(&a, &b);
    }

    #[test]
    fn ipv4_net_keys((a, b) in ipv4_net_pairs()) {
        check(&a, &b);
    }

    #[test]
    fn ipv6_net_keys((a, b) in ipv6_net_pairs()) {
        check(&a, &b);
    }

    #[test]
    fn ip_net_keys((a, b) in pairs(ip_nets())) {
        check(&a, &b);
    }

    #[test]
    fn option_u32_keys((a, b) in pairs(proptest::option::of(edge_u32()).boxed())) {
        check(&a, &b);
    }

    #[test]
    fn option_string_keys((a, b) in pairs(proptest::option::of(strings()).boxed())) {
        check(&a, &b);
    }

    #[test]
    fn host_id_keys((a, b) in pairs(uuids().prop_map(HostId::from_uuid).boxed())) {
        check(&a, &b);
    }

    #[test]
    fn node_id_keys((a, b) in pairs(edge_u64().prop_map(NodeId).boxed())) {
        check(&a, &b);
    }

    #[test]
    fn revision_keys((a, b) in pairs(edge_u64().prop_map(Revision).boxed())) {
        check(&a, &b);
    }

    #[test]
    fn audit_seq_keys((a, b) in pairs(edge_u64().prop_map(AuditSeq).boxed())) {
        check(&a, &b);
    }

    #[test]
    fn timestamp_keys((a, b) in pairs(timestamps())) {
        check(&a, &b);
    }

    #[test]
    fn mac_addr_keys((a, b) in pairs(mac_addrs())) {
        check(&a, &b);
    }

    #[test]
    fn fqdn_keys((a, b) in pairs(fqdns())) {
        check(&a, &b);
    }

    #[test]
    fn host_name_keys((a, b) in pairs(host_names())) {
        check(&a, &b);
    }

    #[test]
    fn duid_keys((a, b) in pairs(duids())) {
        check(&a, &b);
    }

    #[test]
    fn object_kind_keys((a, b) in pairs(object_kinds())) {
        check(&a, &b);
    }

    #[test]
    fn object_ref_keys((a, b) in pairs(object_refs())) {
        check(&a, &b);
    }

    #[test]
    fn table_name_keys((a, b) in pairs(table_names())) {
        check(&a, &b);
    }

    #[test]
    fn counter_key_keys((a, b) in pairs(counter_keys())) {
        check(&a, &b);
    }

    #[test]
    fn idempotency_key_keys((a, b) in pairs(idempotency_keys())) {
        check(&a, &b);
    }

    /// Every `id_type!` identifier shares one macro-generated encoding; check each type
    /// anyway so a hand-written replacement cannot slip in.
    #[test]
    fn every_identifier_type_keys((a, b) in pairs(uuids())) {
        macro_rules! check_ids {
            ($($id:ident),+) => {$(
                check(&$id::from_uuid(a), &$id::from_uuid(b));
            )+};
        }
        check_ids!(
            AddressId, ApiTokenId, ConnectorId, CustomFieldId, HostId, ImportId, InterfaceId,
            JobId, ObservationId, PrefixId, ProposalId, RangeId, RequestId, SecretId, SessionId,
            SiteId, TenantId, UserId, VlanId, VrfId
        );
    }
}

// ---------------------------------------------------------------------------------------
// Properties of composite keys
// ---------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(768))]

    #[test]
    fn string_u16_keys((a, b) in zip2(pairs(strings()), pairs(edge_u16()))) {
        check(&a, &b);
    }

    #[test]
    fn byte_vec_pair_keys((a, b) in zip2(pairs(byte_vecs()), pairs(byte_vecs()))) {
        check(&a, &b);
    }

    #[test]
    fn vrf_id_ip_addr_keys(
        (a, b) in zip2(pairs(uuids().prop_map(VrfId::from_uuid).boxed()), pairs(ip_addrs())),
    ) {
        check(&a, &b);
    }

    #[test]
    fn option_string_u8_ip_net_keys(
        (a, b) in zip3(
            pairs(proptest::option::of(strings()).boxed()),
            pairs(edge_u8()),
            pairs(ip_nets()),
        ),
    ) {
        check(&a, &b);
    }

    #[test]
    fn table_name_bytes_keys((a, b) in zip2(pairs(table_names()), pairs(bytes_values()))) {
        check(&a, &b);
    }

    #[test]
    fn u64_string_ip_addr_mac_addr_keys(
        (a, b) in zip4(pairs(edge_u64()), pairs(strings()), pairs(ip_addrs()), pairs(mac_addrs())),
    ) {
        check(&a, &b);
    }

    #[test]
    fn string_triple_keys((a, b) in zip3(pairs(strings()), pairs(strings()), pairs(strings()))) {
        check(&a, &b);
    }

    /// The widest tuple the codec supports.
    #[test]
    fn six_component_keys(
        (a, b) in pairs(
            (
                edge_u8(),
                strings(),
                proptest::option::of(edge_u32()),
                ip_addrs(),
                byte_vecs(),
                any::<bool>(),
            )
                .boxed(),
        ),
    ) {
        check(&a, &b);
    }

    /// A key and the key of an extended tuple compare by their shared leading component
    /// first: with the timestamp first, the order is chronological.
    #[test]
    fn timestamp_first_composites_sort_chronologically(
        (a, b) in zip3(pairs(timestamps()), pairs(uuids()), pairs(byte_vecs())),
    ) {
        check(&a, &b);
        if a.0 != b.0 {
            prop_assert_eq!(a.0 < b.0, encode_key(&a) < encode_key(&b));
        }
    }
}

// ---------------------------------------------------------------------------------------
// Prefix successors
// ---------------------------------------------------------------------------------------

/// Short byte strings over a few bytes that matter for `prefix_successor`.
fn successor_bytes(max_len: usize) -> BoxedStrategy<Vec<u8>> {
    prop::collection::vec(
        prop_oneof![
            Just(0x00_u8),
            Just(0x01_u8),
            Just(0x7F_u8),
            Just(0xFE_u8),
            Just(0xFF_u8),
        ],
        0..=max_len,
    )
    .boxed()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// `prefix_successor(p)` is greater than `p ++ suffix` for every suffix, and not greater
    /// than any key that is greater than `p` without starting with it.
    #[test]
    fn prefix_successor_bounds_exactly_the_keys_with_the_prefix(
        prefix in successor_bytes(4),
        suffix in successor_bytes(4),
        other in successor_bytes(6),
    ) {
        let mut extended = prefix.clone();
        extended.extend_from_slice(&suffix);
        if let Some(end) = prefix_successor(&prefix) {
            prop_assert!(end > prefix, "{end:02x?} is not above {prefix:02x?}");
            prop_assert!(!end.starts_with(&prefix));
            prop_assert!(
                extended < end,
                "{extended:02x?} (prefix {prefix:02x?}) is not below {end:02x?}"
            );
            if !other.starts_with(&prefix) && other > prefix {
                prop_assert!(
                    end <= other,
                    "{end:02x?} is above {other:02x?}, which does not start with {prefix:02x?}"
                );
            }
        } else {
            // No upper bound exists only when every string above the prefix starts with
            // it: the prefix is empty or all 0xFF.
            prop_assert!(prefix.iter().all(|&byte| byte == 0xFF));
            prop_assert!(other.starts_with(&prefix) || other <= prefix);
        }
    }

    /// A prefix scan over the encoding of a leading component selects exactly the composite
    /// keys with that component, however its bytes relate to those of other components.
    #[test]
    fn prefix_scan_selects_exactly_the_leading_component(
        ((a, x), (b, y)) in zip2(pairs(strings()), pairs(edge_u16())),
    ) {
        let start = encode_key(&a);
        let end = Bytes::from(prefix_successor(&start).expect("string keys end in 0x01"));
        let in_scan = |key: &Bytes| *key >= start && *key < end;
        prop_assert!(in_scan(&encode_key(&(a.clone(), x))));
        prop_assert_eq!(in_scan(&encode_key(&(b.clone(), y))), a == b);
    }

    /// The same for a two-component leading prefix of a longer key.
    #[test]
    fn prefix_scan_selects_exactly_the_leading_components(
        ((lead, other), (addr, tail)) in (
            pairs((strings(), edge_u8()).boxed()),
            (ip_addrs(), byte_vecs()),
        ),
    ) {
        let start = encode_key(&lead);
        let end = Bytes::from(prefix_successor(&start).expect("a string terminator is not 0xFF"));
        let in_scan = |key: &Bytes| *key >= start && *key < end;
        let same = other == lead;
        prop_assert!(in_scan(&encode_key(&(lead.0, lead.1, addr, tail.clone()))));
        prop_assert_eq!(in_scan(&encode_key(&(other.0, other.1, addr, tail))), same);
    }
}

// ---------------------------------------------------------------------------------------
// The generators themselves
// ---------------------------------------------------------------------------------------

/// Draws `count` values from a strategy with a fixed seed.
fn sample<T: Debug>(strategy: &BoxedStrategy<T>, count: usize) -> Vec<T> {
    let mut runner = TestRunner::deterministic();
    (0..count)
        .map(|_| {
            strategy
                .new_tree(&mut runner)
                .expect("value tree")
                .current()
        })
        .collect()
}

#[test]
fn generated_network_data_stays_inside_the_documentation_ranges() {
    let blocks = [[192_u8, 0, 2], [198, 51, 100], [203, 0, 113]];
    for addr in sample(&ipv4_addrs(), 2000) {
        assert!(
            blocks.contains(&addr.octets()[..3].try_into().expect("three octets")),
            "{addr}"
        );
    }
    for net in sample(&ipv4_net_pairs(), 2000)
        .into_iter()
        .flat_map(|(a, b)| [a, b])
    {
        assert!(
            blocks.contains(&net.addr().octets()[..3].try_into().expect("three octets")),
            "{net}"
        );
        assert!((24..=32).contains(&net.prefix_len()), "{net}");
    }
    for addr in sample(&ipv6_addrs(), 2000) {
        assert_eq!(addr.segments()[..2], [0x2001, 0x0db8], "{addr}");
    }
    for net in sample(&ipv6_net_pairs(), 2000)
        .into_iter()
        .flat_map(|(a, b)| [a, b])
    {
        assert_eq!(net.addr().segments()[..2], [0x2001, 0x0db8], "{net}");
        assert!((32..=128).contains(&net.prefix_len()), "{net}");
    }
    for mac in sample(&mac_addrs(), 2000) {
        assert_eq!(mac.octets()[..5], [0x00, 0x00, 0x5E, 0x00, 0x53], "{mac}");
    }
    for name in sample(&dns_names(), 2000) {
        assert!(name.ends_with(".example.test"), "{name}");
    }
}

#[test]
fn generators_reach_the_cases_that_break_naive_encodings() {
    // Strings: NUL, U+00FF, the highest scalar value, proper prefixes, equal values.
    let texts = sample(&pairs(strings()), 4000);
    let any_text =
        |predicate: &dyn Fn(&str) -> bool| texts.iter().any(|(a, b)| predicate(a) || predicate(b));
    assert!(any_text(&|s| s.contains('\0')));
    assert!(any_text(&|s| s.contains('\u{1}')));
    assert!(any_text(&|s| s.contains('\u{ff}')));
    assert!(any_text(&|s| s.contains('\u{10ffff}')));
    assert!(any_text(&str::is_empty));
    assert!(
        texts
            .iter()
            .any(|(a, b)| a != b && b.starts_with(a.as_str()))
    );
    assert!(
        texts
            .iter()
            .any(|(a, b)| a != b && b.starts_with(&format!("{a}\0")))
    );
    assert!(texts.iter().any(|(a, b)| a == b));

    // Byte strings: the three special bytes, proper prefixes, equal values.
    let blobs = sample(&pairs(byte_vecs()), 4000);
    for special in [0x00_u8, 0x01, 0xFF] {
        assert!(
            blobs.iter().any(|(a, _)| a.contains(&special)),
            "{special:#04x}"
        );
    }
    assert!(blobs.iter().any(|(a, b)| a != b && b.starts_with(a)));
    assert!(
        blobs
            .iter()
            .any(|(a, b)| a != b && b.starts_with(&[a.as_slice(), &[0x00]].concat()))
    );
    assert!(blobs.iter().any(|(a, b)| a == b));

    // Timestamps: both signs, both ends of the range, ties.
    let times = sample(&pairs(timestamps()), 4000);
    let nanos: Vec<i128> = times
        .iter()
        .flat_map(|(a, b)| [a.unix_nanos(), b.unix_nanos()])
        .collect();
    assert!(nanos.iter().any(|&n| n < 0));
    assert!(nanos.iter().any(|&n| n > 0));
    assert!(nanos.contains(&0));
    assert!(nanos.iter().any(|&n| n < MIN_NANOS + 3_000_000_000));
    assert!(nanos.iter().any(|&n| n > MAX_NANOS - 3_000_000_000));
    assert!(times.iter().any(|(a, b)| a == b));

    // Options and addresses of both families.
    let options = sample(&pairs(proptest::option::of(edge_u32()).boxed()), 1000);
    assert!(options.iter().any(|(a, b)| a.is_none() && b.is_some()));
    assert!(options.iter().any(|(a, b)| a.is_some() && b.is_none()));
    let addrs = sample(&pairs(ip_addrs()), 1000);
    assert!(addrs.iter().any(|(a, b)| a.is_ipv4() && b.is_ipv6()));
    assert!(addrs.iter().any(|(a, b)| a.is_ipv6() && b.is_ipv4()));
}

// ---------------------------------------------------------------------------------------
// Deterministic regression tests
// ---------------------------------------------------------------------------------------

/// Asserts `smaller < larger` for the values and for their keys.
fn assert_strictly_ordered<T: KeyCodec + Ord + Debug + Clone>(smaller: &T, larger: &T) {
    assert!(smaller < larger, "{smaller:?} is not below {larger:?}");
    assert!(
        encode_key(smaller) < encode_key(larger),
        "key of {smaller:?} is not below key of {larger:?}"
    );
    check(smaller, larger);
}

#[test]
fn a_string_sorts_before_its_extensions_whatever_follows_it() {
    // The case a single-byte terminator gets wrong: the extension starts with the bytes
    // that the following component of the shorter key can start with.
    assert_strictly_ordered(
        &("a".to_owned(), 0xFFFF_u16),
        &("a\0\x01".to_owned(), 0_u16),
    );
    assert_strictly_ordered(&("a".to_owned(), 0xFFFF_u16), &("a\0".to_owned(), 0_u16));
    assert_strictly_ordered(&("a".to_owned(), 0xFFFF_u16), &("a\x01".to_owned(), 0_u16));
    assert_strictly_ordered(
        &("a".to_owned(), 0xFFFF_u16),
        &("a\u{ff}".to_owned(), 0_u16),
    );
    assert_strictly_ordered(&("a".to_owned(), u16::MAX), &("aa".to_owned(), 0_u16));
    assert_strictly_ordered(&(String::new(), u16::MAX), &("\0".to_owned(), 0_u16));
    assert_strictly_ordered(&("a\0".to_owned(), u16::MAX), &("a\0\0".to_owned(), 0_u16));
    // Several string components in a row.
    assert_strictly_ordered(
        &("a".to_owned(), "\u{ff}".to_owned(), "z".to_owned()),
        &("a".to_owned(), "\u{ff}\0".to_owned(), String::new()),
    );
    assert_strictly_ordered(
        &("a".to_owned(), "\u{ff}\u{ff}".to_owned(), "z".to_owned()),
        &("a\0".to_owned(), String::new(), String::new()),
    );
}

#[test]
fn a_byte_string_sorts_before_its_extensions_whatever_follows_it() {
    let tail = vec![0xFF_u8; 3];
    for extension in [
        vec![0xAA, 0x00],
        vec![0xAA, 0x00, 0x00],
        vec![0xAA, 0x00, 0x01],
        vec![0xAA, 0x00, 0xFF],
        vec![0xAA, 0x01],
        vec![0xAA, 0xFF],
    ] {
        assert_strictly_ordered(
            &(vec![0xAA_u8], tail.clone()),
            &(extension.clone(), Vec::new()),
        );
        assert_strictly_ordered(
            &(Bytes::from_static(&[0xAA]), tail.clone()),
            &(Bytes::from(extension), Vec::new()),
        );
    }
    assert_strictly_ordered(
        &(Vec::<u8>::new(), tail.clone()),
        &(vec![0x00_u8], Vec::new()),
    );
    assert_strictly_ordered(&(vec![0x00_u8], tail), &(vec![0x00_u8, 0x00], Vec::new()));
}

#[test]
fn strings_and_byte_strings_compare_bytewise() {
    let ordered: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0x00, 0x00],
        vec![0x00, 0x01],
        vec![0x00, 0xFF],
        vec![0x01],
        vec![0x7F],
        vec![0xFE, 0xFF],
        vec![0xFF],
        vec![0xFF, 0x00],
        vec![0xFF, 0xFF],
    ];
    for pair in ordered.windows(2) {
        assert_strictly_ordered(&pair[0], &pair[1]);
        assert_strictly_ordered(&Bytes::from(pair[0].clone()), &Bytes::from(pair[1].clone()));
    }
    let strings = [
        "",
        "\0",
        "\0\0",
        "\0\u{1}",
        "\u{1}",
        "a",
        "a\0",
        "a\u{1}",
        "a\u{ff}",
        "b",
        "\u{ff}",
        "\u{10ffff}",
    ];
    for pair in strings.windows(2) {
        assert_strictly_ordered(&pair[0].to_owned(), &pair[1].to_owned());
    }
}

#[test]
fn none_sorts_before_some_whatever_follows() {
    assert_strictly_ordered(&(None::<u8>, u64::MAX), &(Some(0_u8), 0_u64));
    assert_strictly_ordered(&(None::<String>, u16::MAX), &(Some(String::new()), 0_u16));
    assert_strictly_ordered(
        &(None::<String>, "\u{ff}".to_owned()),
        &(Some(String::new()), String::new()),
    );
    assert_strictly_ordered(
        &(
            None::<String>,
            0xFF_u8,
            "203.0.113.255/32".parse::<IpNet>().expect("net"),
        ),
        &(
            Some(String::new()),
            0_u8,
            "192.0.2.0/24".parse::<IpNet>().expect("net"),
        ),
    );
    assert_strictly_ordered(&None::<u32>, &Some(0_u32));
    assert_strictly_ordered(&Some(0_u32), &Some(1_u32));
    assert_strictly_ordered(&Some(u32::MAX - 1), &Some(u32::MAX));
    assert_strictly_ordered(&None::<String>, &Some(String::new()));
    assert_strictly_ordered(&Some(String::new()), &Some("\0".to_owned()));
    // `None` is a single byte, so it also sorts first as the middle component.
    assert_strictly_ordered(
        &(1_u8, None::<u64>, "z".to_owned()),
        &(1_u8, Some(0_u64), String::new()),
    );
}

#[test]
fn ipv4_sorts_before_ipv6() {
    let v4_high: IpAddr = "203.0.113.255".parse().expect("address");
    let v6_low: IpAddr = "2001:db8::".parse().expect("address");
    assert_strictly_ordered(&v4_high, &v6_low);
    assert_strictly_ordered(
        &"192.0.2.0".parse::<IpAddr>().expect("address"),
        &"192.0.2.1".parse::<IpAddr>().expect("address"),
    );
    assert_strictly_ordered(
        &"2001:db8::".parse::<IpAddr>().expect("address"),
        &"2001:db8::1".parse::<IpAddr>().expect("address"),
    );

    let net_v4_high: IpNet = "203.0.113.255/32".parse().expect("net");
    let net_v6_low: IpNet = "2001:db8::/32".parse().expect("net");
    assert_strictly_ordered(&net_v4_high, &net_v6_low);
    assert_strictly_ordered(
        &"192.0.2.0/24".parse::<IpNet>().expect("net"),
        &"192.0.2.0/25".parse::<IpNet>().expect("net"),
    );
    assert_strictly_ordered(
        &"192.0.2.0/25".parse::<IpNet>().expect("net"),
        &"192.0.2.128/25".parse::<IpNet>().expect("net"),
    );

    // The family byte decides before whatever follows.
    assert_strictly_ordered(&(v4_high, u16::MAX), &(v6_low, 0_u16));
    assert_strictly_ordered(&(net_v4_high, u16::MAX), &(net_v6_low, 0_u16));
    assert_eq!(encode_key(&v4_high).len(), 5);
    assert_eq!(encode_key(&v6_low).len(), 17);
}

#[test]
fn negative_integers_sort_before_positive_ones() {
    let signed_64 = [
        i64::MIN,
        i64::MIN + 1,
        -0x100,
        -1,
        0,
        1,
        0x100,
        i64::MAX - 1,
        i64::MAX,
    ];
    for pair in signed_64.windows(2) {
        assert_strictly_ordered(&pair[0], &pair[1]);
        assert_strictly_ordered(&(pair[0], u16::MAX), &(pair[1], 0_u16));
    }
    let signed_128 = [
        i128::MIN,
        i128::from(i64::MIN) - 1,
        -1,
        0,
        1,
        i128::from(i64::MAX) + 1,
        i128::MAX,
    ];
    for pair in signed_128.windows(2) {
        assert_strictly_ordered(&pair[0], &pair[1]);
    }
    // Timestamps before the epoch sort before timestamps after it.
    let nanos = [
        MIN_NANOS,
        -1_000_000_001,
        -1_000_000_000,
        -1,
        0,
        1,
        999_999_999,
        1_000_000_000,
        MAX_NANOS,
    ];
    for pair in nanos.windows(2) {
        let earlier = Timestamp::from_unix_nanos(pair[0]).expect("timestamp");
        let later = Timestamp::from_unix_nanos(pair[1]).expect("timestamp");
        assert_strictly_ordered(&earlier, &later);
    }
}

#[test]
fn timestamp_range_matches_the_generator_bounds() {
    assert!(Timestamp::from_unix_nanos(MIN_NANOS).is_ok());
    assert!(Timestamp::from_unix_nanos(MIN_NANOS - 1).is_err());
    assert!(Timestamp::from_unix_nanos(MAX_NANOS).is_ok());
    assert!(Timestamp::from_unix_nanos(MAX_NANOS + 1).is_err());
}

#[test]
fn every_object_kind_orders_by_name_like_its_key() {
    for &a in ObjectKind::ALL {
        for &b in ObjectKind::ALL {
            check(&a, &b);
            assert_eq!(a.cmp(&b), a.as_str().cmp(b.as_str()));
            check(&ObjectRef::singleton(a), &ObjectRef::singleton(b));
        }
    }
}

#[test]
fn decode_rejects_trailing_bytes() {
    assert_eq!(decode_key::<()>(&[]), Ok(()));
    assert_eq!(decode_key::<()>(&[0]), Err(KeyError::Trailing(1)));
    assert_eq!(decode_key::<u8>(&[1, 2]), Err(KeyError::Trailing(1)));
    assert_eq!(decode_key::<u64>(&[0; 10]), Err(KeyError::Trailing(2)));
    assert_eq!(decode_key::<bool>(&[1, 0]), Err(KeyError::Trailing(1)));

    // After the terminator of a byte string, whatever the extra bytes are.
    for extra in [
        &[0x00_u8][..],
        &[0x01],
        &[0xFF],
        &[0x00, 0x01],
        &[0x61, 0x62, 0x63],
    ] {
        let mut key = encode_key(&"abc".to_owned()).to_vec();
        key.extend_from_slice(extra);
        assert_eq!(
            decode_key::<String>(&key),
            Err(KeyError::Trailing(extra.len()))
        );
        let mut key = encode_key(&vec![0x61_u8, 0x00]).to_vec();
        key.extend_from_slice(extra);
        assert_eq!(
            decode_key::<Vec<u8>>(&key),
            Err(KeyError::Trailing(extra.len()))
        );
        let mut key = encode_key(&Bytes::new()).to_vec();
        key.extend_from_slice(extra);
        assert_eq!(
            decode_key::<Bytes>(&key),
            Err(KeyError::Trailing(extra.len()))
        );
    }

    // After a complete composite and after the last component of an option.
    let mut key = encode_key(&("a".to_owned(), 7_u16)).to_vec();
    key.push(0);
    assert_eq!(
        decode_key::<(String, u16)>(&key),
        Err(KeyError::Trailing(1))
    );
    let mut key = encode_key(&None::<u32>).to_vec();
    key.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(decode_key::<Option<u32>>(&key), Err(KeyError::Trailing(4)));
    let mut key = encode_key(&"192.0.2.1".parse::<IpAddr>().expect("address")).to_vec();
    key.push(0);
    assert_eq!(decode_key::<IpAddr>(&key), Err(KeyError::Trailing(1)));
}

#[test]
fn decode_rejects_truncated_input() {
    // Strings and byte strings need their terminator, and an escape needs its second byte.
    for input in [
        &b""[..],
        b"abc",
        b"abc\x00",
        b"abc\x00\xff",
        b"\x00",
        b"\x00\xff",
        b"\x00\xff\x00",
        b"\xff",
    ] {
        assert_eq!(
            decode_key::<String>(input),
            Err(KeyError::Truncated),
            "{input:02x?}"
        );
        assert_eq!(
            decode_key::<Vec<u8>>(input),
            Err(KeyError::Truncated),
            "{input:02x?}"
        );
        assert_eq!(
            decode_key::<Bytes>(input),
            Err(KeyError::Truncated),
            "{input:02x?}"
        );
    }

    // Fixed-width integers, addresses, identifiers and MAC addresses.
    assert_eq!(decode_key::<u8>(&[]), Err(KeyError::Truncated));
    assert_eq!(decode_key::<u16>(&[1]), Err(KeyError::Truncated));
    assert_eq!(decode_key::<u128>(&[0; 15]), Err(KeyError::Truncated));
    assert_eq!(decode_key::<i64>(&[0x80; 7]), Err(KeyError::Truncated));
    assert_eq!(
        decode_key::<Ipv4Addr>(&[192, 0, 2]),
        Err(KeyError::Truncated)
    );
    assert_eq!(
        decode_key::<Ipv6Addr>(&[0x20; 15]),
        Err(KeyError::Truncated)
    );
    assert_eq!(decode_key::<Uuid>(&[0; 15]), Err(KeyError::Truncated));
    assert_eq!(decode_key::<HostId>(&[0; 15]), Err(KeyError::Truncated));
    assert_eq!(
        decode_key::<MacAddr>(&[0, 0, 0x5E, 0, 0x53]),
        Err(KeyError::Truncated)
    );
    assert_eq!(
        decode_key::<Timestamp>(&[0x80; 15]),
        Err(KeyError::Truncated)
    );

    // The family byte, the prefix length and the option payload can each be missing.
    assert_eq!(decode_key::<IpAddr>(&[]), Err(KeyError::Truncated));
    assert_eq!(
        decode_key::<IpAddr>(&[0x04, 192, 0, 2]),
        Err(KeyError::Truncated)
    );
    assert_eq!(
        decode_key::<Ipv4Net>(&[192, 0, 2, 0]),
        Err(KeyError::Truncated)
    );
    assert_eq!(
        decode_key::<IpNet>(&[0x04, 192, 0, 2, 0]),
        Err(KeyError::Truncated)
    );
    assert_eq!(decode_key::<Option<u32>>(&[]), Err(KeyError::Truncated));
    assert_eq!(
        decode_key::<Option<u32>>(&[0x01, 0, 0, 0]),
        Err(KeyError::Truncated)
    );

    // Every proper prefix of composite keys, including those that end between components.
    let composite = encode_key(&(
        Some("a\0b".to_owned()),
        7_u16,
        "2001:db8::1/64".parse::<IpNet>().expect("net"),
    ));
    for len in 0..composite.len() {
        assert_eq!(
            decode_key::<(Option<String>, u16, IpNet)>(&composite[..len]),
            Err(KeyError::Truncated),
            "first {len} bytes"
        );
    }
    assert!(decode_key::<(Option<String>, u16, IpNet)>(&composite).is_ok());
}

#[test]
fn decode_rejects_malformed_escapes() {
    // `0x00` must be followed by `0x01` (terminator) or `0xFF` (escaped NUL); anything
    // else, at any position, is malformed.
    for second in 0..=u8::MAX {
        let input = [0x61, 0x00, second, 0x00, 0x01];
        if second == 0x01 {
            assert_eq!(decode_key::<String>(&input), Err(KeyError::Trailing(2)));
        } else if second == 0xFF {
            assert_eq!(decode_key::<String>(&input).as_deref(), Ok("a\0"));
            assert_eq!(decode_key::<Vec<u8>>(&input), Ok(vec![0x61, 0x00]));
            assert_eq!(
                decode_key::<Bytes>(&input),
                Ok(Bytes::from_static(&[0x61, 0x00]))
            );
        } else {
            assert!(
                matches!(decode_key::<String>(&input), Err(KeyError::Invalid(_))),
                "{second:#04x}"
            );
            assert!(
                matches!(decode_key::<Vec<u8>>(&input), Err(KeyError::Invalid(_))),
                "{second:#04x}"
            );
            assert!(
                matches!(decode_key::<Bytes>(&input), Err(KeyError::Invalid(_))),
                "{second:#04x}"
            );
            // Inside composites the failure is the same, and it is reported before any
            // later component is looked at.
            assert!(matches!(
                decode_key::<(String, u16)>(&[0x61, 0x00, second, 0x00, 0x01, 0, 7]),
                Err(KeyError::Invalid(_))
            ));
            assert!(matches!(
                decode_key::<Option<String>>(&[0x01, 0x00, second, 0x00, 0x01]),
                Err(KeyError::Invalid(_))
            ));
            assert!(matches!(
                decode_key::<Duid>(&[0x00, second, 0x00, 0x01]),
                Err(KeyError::Invalid(_))
            ));
        }
    }
    // A lone `0x00` or `0x00 0xFF` at the end is truncated, not malformed.
    assert_eq!(decode_key::<String>(&[0x00]), Err(KeyError::Truncated));
    assert_eq!(
        decode_key::<String>(&[0x00, 0xFF]),
        Err(KeyError::Truncated)
    );
}

#[test]
fn decode_rejects_malformed_values() {
    fn invalid<T: KeyCodec + Debug>(input: &[u8]) {
        assert!(
            matches!(decode_key::<T>(input), Err(KeyError::Invalid(_))),
            "{input:02x?} decoded as {:?}",
            decode_key::<T>(input)
        );
    }

    invalid::<bool>(&[2]);
    invalid::<Option<u8>>(&[2, 0]);
    invalid::<IpAddr>(&[0x05, 192, 0, 2, 1]);
    invalid::<IpNet>(&[0x00, 192, 0, 2, 0, 24]);
    invalid::<Ipv4Net>(&[192, 0, 2, 0, 33]);
    invalid::<Ipv6Net>(&[&[0x20, 0x01, 0x0d, 0xb8][..], &[0; 12], &[129]].concat());
    invalid::<IpNet>(&[&[0x06, 0x20, 0x01, 0x0d, 0xb8][..], &[0; 12], &[200]].concat());
    // Not UTF-8.
    invalid::<String>(&[0xFF, 0x00, 0x01]);
    invalid::<String>(&[0xC3, 0x00, 0x01]);
    // Values that their type refuses.
    invalid::<ObjectKind>(&encode_key(&"nope".to_owned()));
    invalid::<TableName>(&encode_key(&"nope".to_owned()));
    invalid::<TableName>(&encode_key(&"ipam.UPPER".to_owned()));
    invalid::<TableName>(&encode_key(&"dns.zones".to_owned()));
    invalid::<IdempotencyKey>(&encode_key(&String::new()));
    invalid::<IdempotencyKey>(&encode_key(&"has space".to_owned()));
    invalid::<Fqdn>(&encode_key(&"single".to_owned()));
    invalid::<Fqdn>(&encode_key(&"-bad.example.test".to_owned()));
    invalid::<HostName>(&encode_key(&"bad..example.test".to_owned()));
    invalid::<Duid>(&encode_key(&vec![0x01_u8]));
    invalid::<Duid>(&encode_key(&vec![0x01_u8; 131]));
    invalid::<Timestamp>(&encode_key(&(MIN_NANOS - 1)));
    invalid::<Timestamp>(&encode_key(&(MAX_NANOS + 1)));
    invalid::<Timestamp>(&encode_key(&i128::MIN));
    invalid::<Timestamp>(&encode_key(&i128::MAX));
    invalid::<CounterKey>(&encode_key(&("nope".to_owned(), Vec::<u8>::new())));

    // The limits themselves are accepted.
    assert!(decode_key::<Timestamp>(&encode_key(&MIN_NANOS)).is_ok());
    assert!(decode_key::<Timestamp>(&encode_key(&MAX_NANOS)).is_ok());
    assert!(decode_key::<Duid>(&encode_key(&vec![0x01_u8; 2])).is_ok());
    assert!(decode_key::<Duid>(&encode_key(&vec![0x01_u8; 130])).is_ok());
    assert!(decode_key::<Ipv4Net>(&[192, 0, 2, 0, 32]).is_ok());
    assert!(decode_key::<Ipv4Net>(&[192, 0, 2, 0, 0]).is_ok());
}

#[test]
fn prefix_successor_edge_cases() {
    assert_eq!(prefix_successor(&[]), None);
    assert_eq!(prefix_successor(&[0xFF]), None);
    assert_eq!(prefix_successor(&[0xFF, 0xFF, 0xFF]), None);
    assert_eq!(prefix_successor(&[0x00]), Some(vec![0x01]));
    assert_eq!(prefix_successor(&[0x61, 0xFF]), Some(vec![0x62]));
    assert_eq!(
        prefix_successor(&[0x61, 0xFE, 0xFF]),
        Some(vec![0x61, 0xFF])
    );
    // The end of the scan over every key of a string is the key of the next possible
    // string at the same depth: terminator 0x00 0x01 becomes 0x00 0x02.
    assert_eq!(
        prefix_successor(&encode_key(&"a".to_owned())),
        Some(vec![0x61, 0x00, 0x02])
    );
}
