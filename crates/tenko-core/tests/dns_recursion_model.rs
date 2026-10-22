//! The recursive resolver's model (recursion plan section 3.1, WP10.0): trust anchors,
//! negative trust anchors, the resolution modes and the security states with their
//! rendering, with unit and property tests.

use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use proptest::prelude::*;
use tenko_core::{
    Coded, Timestamp,
    codec::{from_cbor, to_cbor},
    dns::{
        AnchorData, AnchorKey, AnchorSource, AnchorState, ClientFlags, DnsName, ExtendedError,
        ForwardRule, ForwardRuleId, ForwardTransport, NegativeTrustAnchor, NtaId, ResolutionMode,
        RuleMode, SecurityState, TrustAnchor, Upstream, codes, recursion,
    },
    principal::{Principal, SystemComponent},
    serde_util::HexBytes,
};

fn at(text: &str) -> Timestamp {
    text.parse().expect("time")
}

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

/// The root KSK-2017's DS (key tag 20326, RSASHA256, SHA-256) as RFC 7958 publishes it.
fn ds_20326() -> Vec<u8> {
    let digest = "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d";
    let mut rdata = vec![0x4f, 0x66, 8, 2];
    rdata.extend(
        (0..digest.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&digest[index..index + 2], 16).expect("hex")),
    );
    rdata
}

fn ds_key() -> AnchorKey {
    AnchorKey {
        key_tag: 20326,
        algorithm: 8,
        digest_type: Some(2),
        data: AnchorData::Ds {
            rdata: HexBytes(ds_20326()),
        },
        state: AnchorState::Valid,
        source: AnchorSource::Shipped {
            release: "0.0.2".to_owned(),
        },
        added_at: at("2026-10-22T00:00:00Z"),
        state_since: at("2026-10-22T00:00:00Z"),
        last_seen: None,
    }
}

fn dnskey_rdata(flags: u16, algorithm: u8, key: &[u8]) -> Vec<u8> {
    let mut rdata = flags.to_be_bytes().to_vec();
    rdata.extend_from_slice(&[3, algorithm]);
    rdata.extend_from_slice(key);
    rdata
}

fn dnskey_key(flags: u16, key: &[u8]) -> AnchorKey {
    let rdata = dnskey_rdata(flags, 13, key);
    AnchorKey {
        key_tag: recursion::key_tag(&rdata),
        algorithm: 13,
        digest_type: None,
        data: AnchorData::Dnskey {
            rdata: HexBytes(rdata),
        },
        state: AnchorState::Valid,
        source: AnchorSource::Operator,
        added_at: at("2026-10-22T00:00:00Z"),
        state_since: at("2026-10-22T00:00:00Z"),
        last_seen: Some(at("2026-10-22T01:00:00Z")),
    }
}

fn root_anchor() -> TrustAnchor {
    TrustAnchor {
        zone: DnsName::root(),
        keys: vec![ds_key()],
        last_query: None,
        next_query: None,
    }
}

fn nta() -> NegativeTrustAnchor {
    NegativeTrustAnchor {
        id: NtaId::generate(),
        zone: name("bogus.example.test"),
        expires_at: at("2026-10-23T00:00:00Z"),
        reason: "The zone's operator lost its keys; ticket 42".to_owned(),
        created_by: Principal::system(SystemComponent::Dns),
        created_at: at("2026-10-22T00:00:00Z"),
    }
}

fn code<E: Coded>(error: &E) -> &'static str {
    error.code()
}

#[test]
fn a_shipped_root_anchor_validates_and_round_trips() {
    let anchor = root_anchor();
    anchor.validate(false).expect("valid");
    assert_eq!(
        from_cbor::<TrustAnchor>(&to_cbor(&anchor).expect("cbor")).expect("cbor"),
        anchor
    );
    let json = serde_json::to_value(&anchor).expect("json");
    assert_eq!(json["zone"], ".");
    assert_eq!(json["keys"][0]["state"], "valid");
    assert_eq!(json["keys"][0]["source"]["kind"], "shipped");
    assert_eq!(json["keys"][0]["data"]["kind"], "ds");
    assert!(json.get("last_query").is_none());
    assert_eq!(
        serde_json::from_value::<TrustAnchor>(json).expect("json"),
        anchor
    );
}

#[test]
fn anchor_keys_must_agree_with_their_material() {
    let mut key = ds_key();
    key.key_tag = 20327;
    assert_eq!(
        code(&key.validate().expect_err("tag")),
        codes::TRUST_ANCHOR_INVALID
    );
    let mut key = ds_key();
    key.digest_type = None;
    assert!(key.validate().is_err(), "a DS names its digest type");
    let mut key = ds_key();
    if let AnchorData::Ds { rdata } = &mut key.data {
        rdata.0.pop();
    }
    assert!(key.validate().is_err(), "a SHA-256 digest is 32 octets");
    let mut key = ds_key();
    key.state_since = at("2026-10-21T00:00:00Z");
    assert!(key.validate().is_err(), "state before addition");

    dnskey_key(257, &[7; 64]).validate().expect("a KSK");
    dnskey_key(256, &[7; 64])
        .validate()
        .expect("a ZSK is a zone key too");
    assert!(
        dnskey_key(1, &[7; 64]).validate().is_err(),
        "no zone key bit"
    );
    let mut key = dnskey_key(257, &[7; 64]);
    key.digest_type = Some(2);
    assert!(key.validate().is_err(), "a DNSKEY has no digest type");
    let mut key = dnskey_key(257, &[7; 64]);
    key.key_tag ^= 1;
    assert!(key.validate().is_err(), "the key tag is computed");
}

#[test]
fn trust_anchor_rows_follow_their_rules() {
    let mut anchor = root_anchor();
    anchor.keys.push(ds_key());
    assert!(anchor.validate(false).is_err(), "a key twice");
    anchor.keys.pop();
    anchor.keys[0].state = AnchorState::Revoked;
    assert!(
        anchor.validate(false).is_err(),
        "the root keeps a trusted key"
    );
    anchor.validate(true).expect("the Lab profile may");
    anchor.keys.clear();
    assert!(anchor.validate(true).is_err(), "at least one key");
    let private = TrustAnchor {
        zone: name("corp.example.test"),
        keys: vec![{
            let mut key = dnskey_key(257, &[9; 64]);
            key.state = AnchorState::AddPend;
            key
        }],
        last_query: Some(at("2026-10-22T00:00:00Z")),
        next_query: Some(at("2026-10-21T00:00:00Z")),
    };
    assert!(private.validate(false).is_err(), "next before last");
    let private = TrustAnchor {
        next_query: Some(at("2026-10-23T00:00:00Z")),
        ..private
    };
    private
        .validate(false)
        .expect("a private zone needs no trusted key yet");
    assert_eq!(private.trusted().count(), 0);
    assert!(AnchorState::Missing.trusted() && !AnchorState::AddPend.trusted());
}

#[test]
fn negative_trust_anchors_are_bounded() {
    let anchor = nta();
    anchor.validate().expect("valid");
    let json = serde_json::to_value(&anchor).expect("json");
    assert_eq!(
        serde_json::from_value::<NegativeTrustAnchor>(json).expect("json"),
        anchor
    );
    assert!(anchor.covers(&name("www.bogus.example.test"), at("2026-10-22T12:00:00Z")));
    assert!(anchor.covers(&name("bogus.example.test"), at("2026-10-22T12:00:00Z")));
    assert!(!anchor.covers(&name("example.test"), at("2026-10-22T12:00:00Z")));
    assert!(!anchor.covers(&name("bogus.example.test"), at("2026-10-23T00:00:00Z")));

    let root = NegativeTrustAnchor {
        zone: DnsName::root(),
        ..nta()
    };
    assert_eq!(
        code(&root.validate().expect_err("root")),
        codes::NTA_INVALID
    );
    let long = NegativeTrustAnchor {
        expires_at: at("2026-10-29T00:00:01Z"),
        ..nta()
    };
    assert!(long.validate().is_err(), "over seven days");
    let week = NegativeTrustAnchor {
        expires_at: at("2026-10-29T00:00:00Z"),
        ..nta()
    };
    week.validate().expect("exactly seven days");
    for reason in ["", "   ", "line\nbreak"] {
        let bad = NegativeTrustAnchor {
            reason: reason.to_owned(),
            ..nta()
        };
        assert!(bad.validate().is_err(), "{reason:?}");
    }
    let bad = NegativeTrustAnchor {
        reason: "x".repeat(501),
        ..nta()
    };
    assert!(bad.validate().is_err());

    let now = at("2026-10-22T00:00:00Z");
    assert_eq!(
        NegativeTrustAnchor::expiry_for(now, None, false).expect("default"),
        at("2026-10-29T00:00:00Z")
    );
    assert_eq!(
        code(&NegativeTrustAnchor::expiry_for(now, None, true).expect_err("Hardened")),
        codes::NTA_INVALID
    );
    assert!(NegativeTrustAnchor::expiry_for(now, Some(now), false).is_err());
    assert!(NegativeTrustAnchor::expiry_for(now, Some(at("2026-10-30T00:00:00Z")), false).is_err());
}

fn rule(mode: RuleMode) -> ForwardRule {
    ForwardRule {
        id: ForwardRuleId::generate(),
        suffix: name("corp.example.test"),
        upstreams: Vec::new(),
        transport: ForwardTransport::Plain,
        tls_name: None,
        view: None,
        mode,
        validate: true,
        description: None,
    }
}

#[test]
fn recurse_rules_name_no_upstream() {
    rule(RuleMode::Recurse).validate().expect("recurse");
    assert_eq!(
        code(&rule(RuleMode::Forward).validate().expect_err("no upstream")),
        codes::FORWARDER_INVALID
    );
    let upstream = Upstream {
        address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        port: None,
        path: None,
    };
    let mut recurse = rule(RuleMode::Recurse);
    recurse.upstreams.push(upstream.clone());
    assert!(recurse.validate().is_err(), "upstreams");
    let mut recurse = rule(RuleMode::Recurse);
    recurse.transport = ForwardTransport::Dot;
    assert!(recurse.validate().is_err(), "transport");
    let mut recurse = rule(RuleMode::Recurse);
    recurse.tls_name = Some("resolver.example.net".to_owned());
    assert!(recurse.validate().is_err(), "tls_name");
    let mut recurse = rule(RuleMode::Recurse);
    recurse.validate = false;
    assert!(recurse.validate().is_err(), "validate");
    let mut forward = rule(RuleMode::Forward);
    forward.upstreams.push(upstream);
    forward.validate = false;
    forward
        .validate()
        .expect("a forward rule may trust its upstream");

    // A Phase 2 row decodes with the defaults.
    let json = serde_json::json!({
        "id": ForwardRuleId::generate(),
        "suffix": ".",
        "upstreams": [{"address": "192.0.2.1"}],
    });
    let old: ForwardRule = serde_json::from_value(json).expect("old row");
    assert_eq!(old.mode, RuleMode::Forward);
    assert!(old.validate);
    let json = serde_json::to_value(rule(RuleMode::Recurse)).expect("json");
    assert_eq!(json["mode"], "recurse");
    assert_eq!(json["validate"], true);
}

#[test]
fn resolution_modes_parse() {
    for mode in ResolutionMode::ALL {
        assert_eq!(
            mode.as_str().parse::<ResolutionMode>().expect("parse"),
            mode
        );
        assert_eq!(
            serde_json::to_value(mode).expect("json"),
            serde_json::Value::String(mode.to_string())
        );
    }
    assert!("default".parse::<ResolutionMode>().is_err());
}

#[test]
fn security_states_render_as_the_plan_says() {
    let plain = ClientFlags::default();
    let dnssec = ClientFlags {
        dnssec_ok: true,
        ..plain
    };
    let ad = ClientFlags { ad: true, ..plain };
    let cd = ClientFlags { cd: true, ..dnssec };

    let secure = SecurityState::Secure.render(plain, None);
    assert!(!secure.ad && !secure.dnssec_records && !secure.servfail);
    assert!(SecurityState::Secure.render(dnssec, None).ad);
    assert!(SecurityState::Secure.render(dnssec, None).dnssec_records);
    assert!(SecurityState::Secure.render(ad, None).ad);
    assert!(!SecurityState::Insecure.render(dnssec, None).ad);
    assert!(!SecurityState::Unvalidated.render(dnssec, None).ad);

    let bogus = SecurityState::Bogus.render(dnssec, Some(ExtendedError::SIGNATURE_EXPIRED));
    assert!(bogus.servfail && !bogus.ad && !bogus.dnssec_records);
    assert_eq!(bogus.ede, Some(ExtendedError::SIGNATURE_EXPIRED));
    assert_eq!(
        SecurityState::Bogus.render(plain, None).ede,
        Some(ExtendedError::DNSSEC_BOGUS)
    );
    let checked_off = SecurityState::Bogus.render(cd, None);
    assert!(!checked_off.servfail && !checked_off.ad && checked_off.dnssec_records);

    let indeterminate = SecurityState::Indeterminate.render(dnssec, None);
    assert!(!indeterminate.servfail && !indeterminate.ad);
    assert_eq!(indeterminate.ede, Some(ExtendedError::DNSSEC_INDETERMINATE));
}

#[test]
fn extended_errors_are_named() {
    for ede in ExtendedError::NAMED {
        assert!(ede.name().is_some(), "{ede:?}");
    }
    assert!(
        ExtendedError::NAMED
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert_eq!(ExtendedError::DNSSEC_BOGUS.code(), 6);
    assert_eq!(ExtendedError::NO_REACHABLE_AUTHORITY.code(), 22);
    assert_eq!(ExtendedError::UNSUPPORTED_NSEC3_ITERATIONS.code(), 27);
    assert_eq!(ExtendedError(4).name(), None);
    assert_eq!(serde_json::to_value(ExtendedError(9)).expect("json"), 9);
}

fn state() -> impl Strategy<Value = SecurityState> {
    prop::sample::select(SecurityState::ALL.to_vec())
}

fn anchor_state() -> impl Strategy<Value = AnchorState> {
    prop::sample::select(AnchorState::ALL.to_vec())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn rendering_invariants_hold(
        state in state(),
        dnssec_ok: bool,
        ad: bool,
        cd: bool,
        ede in prop::option::of(0u16..30),
    ) {
        let client = ClientFlags { dnssec_ok, ad, cd };
        let rendering = state.render(client, ede.map(ExtendedError));
        prop_assert_eq!(rendering.servfail, state == SecurityState::Bogus && !cd);
        prop_assert!(!rendering.ad || state == SecurityState::Secure);
        prop_assert_eq!(rendering.ad, state == SecurityState::Secure && (ad || dnssec_ok));
        prop_assert!(!rendering.dnssec_records || dnssec_ok);
        prop_assert!(!rendering.servfail || rendering.ede.is_some());
        prop_assert_eq!(SecurityState::from_u8(state.to_u8()), state);
    }

    #[test]
    fn dnskey_anchors_round_trip(
        flags in prop::sample::select(vec![256u16, 257, 385]),
        key in prop::collection::vec(any::<u8>(), 1..300),
        state in anchor_state(),
        hours in 0u64..10_000,
    ) {
        let mut anchor_key = dnskey_key(flags, &key);
        anchor_key.state = state;
        anchor_key.state_since = anchor_key
            .added_at
            .checked_add(Duration::from_secs(hours * 3600))
            .expect("time");
        prop_assert!(anchor_key.validate().is_ok());
        let anchor = TrustAnchor {
            zone: name("corp.example.test"),
            keys: vec![anchor_key],
            last_query: None,
            next_query: None,
        };
        prop_assert!(anchor.validate(false).is_ok());
        let decoded: TrustAnchor = from_cbor(&to_cbor(&anchor).expect("cbor")).expect("cbor");
        prop_assert_eq!(&decoded, &anchor);
        let json = serde_json::to_value(&anchor).expect("json");
        let decoded: TrustAnchor = serde_json::from_value(json).expect("json");
        prop_assert_eq!(decoded, anchor);
    }

    #[test]
    fn nta_expiries_stay_within_a_week(secs in 0u64..(14 * 86_400), required: bool) {
        let now = at("2026-10-22T00:00:00Z");
        let requested = now.checked_add(Duration::from_secs(secs)).expect("time");
        let result = NegativeTrustAnchor::expiry_for(now, Some(requested), required);
        prop_assert_eq!(result.is_ok(), secs > 0 && secs <= recursion::NTA_MAX_SECS);
        if let Ok(expires_at) = result {
            let anchor = NegativeTrustAnchor { expires_at, created_at: now, ..nta() };
            prop_assert!(anchor.validate().is_ok());
            let decoded: NegativeTrustAnchor =
                from_cbor(&to_cbor(&anchor).expect("cbor")).expect("cbor");
            prop_assert_eq!(decoded, anchor);
        }
    }
}
