//! Property tests of the DNS model (`tenko_core::dns`): name normalization and its
//! encodings, the wire form of record data, TXT splitting (DNS-24), and decoders that never
//! panic on arbitrary input.

use std::net::{Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use tenko_core::{
    codec::{decode_key, encode_key},
    dns::{DnsName, Rdata, RecordData, Rtype, ScopeName, SvcParam, TextBytes, split_txt},
    serde_util::HexBytes,
};

/// One label from the allowed characters, 1 to 20 long, mixed case.
fn label() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_/-]{1,20}"
}

/// A name of 1 to 5 labels, optionally a wildcard, optionally with a trailing dot.
fn name_text() -> impl Strategy<Value = String> {
    (
        any::<bool>(),
        prop::collection::vec(label(), 1..=5),
        any::<bool>(),
    )
        .prop_map(|(wildcard, labels, dot)| {
            let mut text = labels.join(".");
            if wildcard {
                text = format!("*.{text}");
            }
            if dot {
                text.push('.');
            }
            text
        })
}

fn name() -> impl Strategy<Value = DnsName> {
    name_text().prop_map(|text| DnsName::new(&text).expect("generated names are valid"))
}

fn hex(max: usize) -> impl Strategy<Value = HexBytes> {
    prop::collection::vec(any::<u8>(), 0..=max).prop_map(HexBytes)
}

/// Known record types with valid data, plus RFC 3597 data of private-use types.
fn record_data() -> impl Strategy<Value = RecordData> {
    let types = prop::collection::vec(
        prop::sample::select(vec![
            Rtype::A,
            Rtype::NS,
            Rtype::MX,
            Rtype::TXT,
            Rtype::AAAA,
            Rtype::RRSIG,
            Rtype::NSEC,
            Rtype::CAA,
            Rtype(1234),
            Rtype(65280),
        ]),
        0..6,
    );
    prop_oneof![
        any::<[u8; 4]>().prop_map(|o| RecordData::A {
            address: Ipv4Addr::from(o)
        }),
        any::<[u8; 16]>().prop_map(|o| RecordData::Aaaa {
            address: Ipv6Addr::from(o)
        }),
        name().prop_map(|target| RecordData::Cname { target }),
        (any::<u16>(), name()).prop_map(|(preference, exchange)| RecordData::Mx {
            preference,
            exchange
        }),
        (any::<u16>(), any::<u16>(), any::<u16>(), name()).prop_map(
            |(priority, weight, port, target)| RecordData::Srv {
                priority,
                weight,
                port,
                target
            }
        ),
        prop::collection::vec(prop::collection::vec(any::<u8>(), 0..=255), 1..4).prop_map(
            |strings| RecordData::Txt {
                strings: strings.into_iter().map(TextBytes).collect()
            }
        ),
        (
            any::<u8>(),
            "[a-z0-9]{1,15}",
            prop::collection::vec(any::<u8>(), 0..40)
        )
            .prop_map(|(flags, tag, value)| RecordData::Caa {
                flags,
                tag,
                value: TextBytes(value)
            }),
        (any::<u16>(), any::<u8>(), any::<u8>(), hex(64)).prop_map(
            |(key_tag, algorithm, digest_type, digest)| RecordData::Ds {
                key_tag,
                algorithm,
                digest_type,
                digest
            }
        ),
        (name(), types.clone()).prop_map(|(next, types)| RecordData::Nsec { next, types }),
        (
            any::<u16>(),
            hex(32),
            hex(32).prop_filter("non-empty", |h| !h.0.is_empty()),
            types
        )
            .prop_map(|(iterations, salt, next_hashed, types)| RecordData::Nsec3 {
                hash_algorithm: 1,
                flags: 0,
                iterations,
                salt,
                next_hashed,
                types
            }),
        (
            any::<u16>(),
            name(),
            prop::collection::btree_map(any::<u16>(), hex(16), 0..4)
        )
            .prop_map(|(priority, target, params)| RecordData::Https {
                priority,
                target,
                params: params
                    .into_iter()
                    .map(|(key, value)| SvcParam { key, value })
                    .collect()
            }),
        (65280u16..=65534, hex(64)).prop_map(|(rtype, data)| RecordData::Unknown {
            rtype: Rtype(rtype),
            data
        }),
    ]
}

/// Sorts and deduplicates the type bitmaps, which the wire form stores as a set.
fn canonical(mut data: RecordData) -> RecordData {
    if let RecordData::Nsec { types, .. } | RecordData::Nsec3 { types, .. } = &mut data {
        types.sort();
        types.dedup();
    }
    data
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn normalization_is_idempotent_and_encodings_round_trip(text in name_text()) {
        let name = DnsName::new(&text).expect("valid");
        prop_assert_eq!(DnsName::new(name.as_str()).expect("again"), name.clone());
        prop_assert!(name.as_str().bytes().all(|b| !b.is_ascii_uppercase()));
        prop_assert!(!name.as_str().ends_with('.'));
        let wire = name.to_wire();
        prop_assert_eq!(wire.len(), name.wire_len());
        prop_assert_eq!(DnsName::from_wire(&wire).expect("wire"), (name.clone(), wire.len()));
        prop_assert_eq!(decode_key::<DnsName>(&encode_key(&name)).expect("key"), name.clone());
        let json = serde_json::to_string(&name).expect("json");
        prop_assert_eq!(serde_json::from_str::<DnsName>(&json).expect("json"), name);
    }

    #[test]
    fn a_child_sorts_inside_its_parents_key_range(parent in name(), child in label()) {
        prop_assume!(!parent.is_wildcard());
        let Ok(below) = parent.child(&child.to_ascii_lowercase()) else {
            return Ok(());
        };
        prop_assert!(below.is_subdomain_of(&parent));
        let parent_key = encode_key(&parent);
        let below_key = encode_key(&below);
        prop_assert!(parent_key < below_key);
        let mut prefix = Vec::new();
        tenko_core::codec::key::encode_bytes(&parent.subtree_prefix(), &mut prefix);
        // The escaped prefix without its terminator is a prefix of every key below.
        prop_assert!(below_key.starts_with(&prefix[..prefix.len() - 2]));
    }

    #[test]
    fn record_data_round_trips_through_the_wire_form(data in record_data()) {
        let data = canonical(data);
        data.validate().expect("generated data is valid");
        let rdata = Rdata::from_data(&data);
        prop_assert_eq!(rdata.decode(data.rtype()).expect("decode"), data.clone());
        prop_assert_eq!(Rdata::from_wire(data.rtype(), rdata.as_bytes()).expect("wire"), rdata);
        let json = serde_json::to_value(&data).expect("json");
        prop_assert_eq!(serde_json::from_value::<RecordData>(json).expect("json"), data);
    }

    #[test]
    fn decoders_never_panic(rtype in any::<u16>(), wire in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = RecordData::from_wire(Rtype(rtype), &wire);
        let _ = DnsName::from_wire(&wire);
        if let Ok(data) = RecordData::from_wire(Rtype(rtype), &wire) {
            // Whatever decodes writes back to bytes that decode to the same value.
            let again = Rdata::from_data(&data);
            prop_assert_eq!(again.decode(Rtype(rtype)).expect("again"), data);
        }
    }

    #[test]
    fn txt_splitting_keeps_every_octet(text in ".{0,800}") {
        let parts = split_txt(text.as_bytes());
        prop_assert!(!parts.is_empty());
        prop_assert!(parts.iter().all(|part| part.0.len() <= 255));
        let joined: Vec<u8> = parts.iter().flat_map(|part| part.0.clone()).collect();
        prop_assert_eq!(&joined, &text.as_bytes().to_vec());
        // Valid UTF-8 is never cut inside a character.
        prop_assert!(parts.iter().all(|part| std::str::from_utf8(&part.0).is_ok()));
        let data = RecordData::txt(&text);
        data.validate().expect("split TXT is valid");
    }

    #[test]
    fn text_escapes_round_trip(bytes in prop::collection::vec(any::<u8>(), 0..100)) {
        let text = TextBytes(bytes);
        prop_assert_eq!(TextBytes::parse(&text.to_string()).expect("parse"), text);
    }

    #[test]
    fn scope_names_round_trip(text in "[a-z0-9][a-z0-9_-]{0,62}") {
        let scope = ScopeName::new(&text).expect("valid");
        prop_assert_eq!(decode_key::<ScopeName>(&encode_key(&scope)).expect("key"), scope);
    }
}
