//! The identity model of secure updates (identity plan section 4.1, WP13.0): realms,
//! principal names and SIDs with their parsing, the Kerberos part of the update policy,
//! the access list entry, the name owners and the account metadata, with unit and property
//! tests; and the proof that an RRset written by 0.0.11 decodes with the new cold field.

use std::net::{IpAddr, Ipv4Addr};

use proptest::prelude::*;
use tenko_core::{
    Coded, Timestamp,
    codec::{decode_key, encode_key, from_cbor, to_cbor},
    dns::{
        Acl, AclEntry, AclId, DnsName, KerberosUpdate, KrbAccount, NameOwner, NameOwnerKey, Origin,
        Ownership, PrincipalName, Realm, RrSet, ScopeName, Sid, UpdatePolicy, WindowsUpdateMode,
        ZoneId, codes, identity, tables,
    },
};

fn realm() -> Realm {
    Realm::new("CORP.EXAMPLE.TEST").expect("realm")
}

fn principal(text: &str) -> PrincipalName {
    PrincipalName::parse(text).expect("principal")
}

fn sid(text: &str) -> Sid {
    Sid::parse(text).expect("sid")
}

/// The CBOR bytes of an RRset as 0.0.11 wrote them (`tests/fixtures/rrset-0.0.11.cbor.hex`,
/// captured from the 0.0.11 code: a dynamic A record with its TSIG key).
fn rrset_0_0_11() -> Vec<u8> {
    let hex = include_str!("fixtures/rrset-0.0.11.cbor.hex");
    let hex = hex.trim();
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn an_rrset_of_0_0_11_decodes_without_a_principal_and_writes_the_same_bytes() {
    let bytes = rrset_0_0_11();
    let rrset: RrSet = from_cbor(&bytes).expect("a 0.0.11 RRset decodes");
    assert_eq!(rrset.name.as_str(), "host01.corp.example.test");
    assert_eq!(rrset.origin, Origin::Dynamic);
    assert_eq!(
        rrset.key.as_ref().map(DnsName::as_str),
        Some("update.corp.example.test")
    );
    assert_eq!(rrset.principal, None, "the cold field is absent");
    // Written back, the row is byte for byte what 0.0.11 wrote: a 0.0.11 binary reads it
    // unchanged, so the data format does not move for the field.
    assert_eq!(to_cbor(&rrset).expect("cbor"), bytes);
    // With a principal the row gains one key; a 0.0.11 binary ignores it.
    let mut signed = rrset.clone();
    signed.principal = Some(principal("HOST01$@CORP.EXAMPLE.TEST"));
    let with = to_cbor(&signed).expect("cbor");
    assert!(with.len() > bytes.len());
    assert_eq!(from_cbor::<RrSet>(&with).expect("cbor"), signed);
    let json = serde_json::to_value(&signed).expect("json");
    assert_eq!(json["principal"], "HOST01$@CORP.EXAMPLE.TEST");
}

#[test]
fn the_update_policy_of_0_0_11_decodes_and_the_windows_modes_follow_the_fields() {
    let old = serde_json::json!({
        "allowed": [],
        "require_tsig": true,
        "may_replace_ipam": false
    });
    let policy: UpdatePolicy = serde_json::from_value(old).expect("json");
    assert_eq!(policy.kerberos, None);
    assert_eq!(policy.windows_mode(), WindowsUpdateMode::None);
    let json = serde_json::to_value(&policy).expect("json");
    assert!(json.get("kerberos").is_none(), "absent when unset");
    assert_eq!(
        from_cbor::<UpdatePolicy>(&to_cbor(&policy).expect("cbor")).expect("cbor"),
        policy
    );

    let list = AclId::generate();
    let tsig = UpdatePolicy {
        allowed: vec![list],
        ..UpdatePolicy::default()
    };
    assert_eq!(tsig.windows_mode(), WindowsUpdateMode::Tsig);
    let secure = UpdatePolicy {
        allowed: vec![list],
        kerberos: Some(KerberosUpdate::for_realm(realm())),
        ..UpdatePolicy::default()
    };
    assert_eq!(secure.windows_mode(), WindowsUpdateMode::SecureOnly);
    let both = UpdatePolicy {
        require_tsig: false,
        ..secure.clone()
    };
    assert_eq!(both.windows_mode(), WindowsUpdateMode::NonsecureAndSecure);
    assert_eq!(
        serde_json::to_value(WindowsUpdateMode::NonsecureAndSecure).expect("json"),
        "nonsecure_and_secure"
    );
    let json = serde_json::to_value(&secure).expect("json");
    assert_eq!(json["kerberos"]["realms"][0], "CORP.EXAMPLE.TEST");
    assert_eq!(json["kerberos"]["ownership"], "windows");
    assert_eq!(json["kerberos"]["owner_hold_days"], 14);
}

#[test]
fn a_kerberos_entry_decides_signed_requests_and_passes_others_by() {
    let client: IpAddr = "192.0.2.10".parse().expect("address");
    let outside: IpAddr = "198.51.100.10".parse().expect("address");
    let acl = Acl {
        id: AclId::generate(),
        name: "ad-corp".to_owned(),
        entries: vec![
            AclEntry::Kerberos {
                realm: realm(),
                principal: Some("dc*$".to_owned()),
                from: None,
                deny: true,
            },
            AclEntry::Kerberos {
                realm: realm(),
                principal: Some("*$".to_owned()),
                from: Some("192.0.2.0/24".parse().expect("prefix")),
                deny: false,
            },
        ],
        description: None,
    };
    for entry in &acl.entries {
        entry.validate().expect("valid");
    }
    let computer = principal("WS01$@CORP.EXAMPLE.TEST");
    let controller = principal("DC01$@CORP.EXAMPLE.TEST");
    let user = principal("alex@CORP.EXAMPLE.TEST");
    let other = principal("WS01$@OTHER.EXAMPLE.TEST");
    assert!(acl.allows_principal(client, &computer));
    assert!(!acl.allows_principal(outside, &computer), "outside `from`");
    assert!(
        !acl.allows_principal(client, &controller),
        "the deny entry first"
    );
    assert!(!acl.allows_principal(client, &user), "not a computer");
    assert!(!acl.allows_principal(client, &other), "another realm");
    // Without a principal the entries match nothing: a TSIG or unsigned request is refused
    // by a list of Kerberos entries alone.
    assert!(!acl.allows(client, None));
    assert!(!acl.allows(client, Some(&DnsName::new("k.example.test").expect("name"))));
    let bad = AclEntry::Kerberos {
        realm: realm(),
        principal: Some("a@b".to_owned()),
        from: None,
        deny: false,
    };
    assert!(bad.validate().is_err());

    // The entry round-trips in JSON and CBOR with its prefix as text.
    let json = serde_json::to_value(&acl).expect("json");
    assert_eq!(json["entries"][0]["kind"], "kerberos");
    assert_eq!(json["entries"][0]["realm"], "CORP.EXAMPLE.TEST");
    assert!(json["entries"][0].get("from").is_none());
    assert_eq!(json["entries"][1]["from"], "192.0.2.0/24");
    let back: Acl = serde_json::from_value(json).expect("json");
    assert_eq!(back, acl);
    assert_eq!(
        from_cbor::<Acl>(&to_cbor(&acl).expect("cbor")).expect("cbor"),
        acl
    );
    // A realm in lower case folds; the API reads what Windows administrators type.
    let lower: AclEntry = serde_json::from_value(serde_json::json!({
        "kind": "kerberos", "realm": "corp.example.test"
    }))
    .expect("json");
    assert_eq!(
        lower,
        AclEntry::Kerberos {
            realm: realm(),
            principal: None,
            from: None,
            deny: false
        }
    );
}

#[test]
fn name_owner_keys_order_by_zone_scope_and_name_and_the_tables_are_declared() {
    let zone = ZoneId::generate();
    let key = NameOwnerKey {
        zone,
        scope: ScopeName::DEFAULT,
        name: DnsName::new("ws01.corp.example.test").expect("name"),
    };
    let bytes = encode_key(&key);
    assert_eq!(decode_key::<NameOwnerKey>(&bytes).expect("decodes"), key);
    let later = NameOwnerKey {
        name: DnsName::new("ws02.corp.example.test").expect("name"),
        ..key.clone()
    };
    assert!(encode_key(&key) < encode_key(&later));
    let realm_key = encode_key(&realm());
    assert_eq!(decode_key::<Realm>(&realm_key).expect("decodes"), realm());
    assert_eq!(tables::NAME_OWNERS.name().as_str(), "dns.name_owners");
    assert_eq!(tables::KRB_ACCOUNTS.name().as_str(), "dns.krb_accounts");
    let node: Vec<&str> = tables::NODE_TABLES
        .iter()
        .map(tenko_core::names::TableName::as_str)
        .collect();
    assert!(node.contains(&"dns.name_owners") && node.contains(&"dns.krb_accounts"));
    let owner = NameOwner {
        sid: Some(sid("S-1-5-21-1004336348-1177238915-682003330-1200")),
        principal: principal("WS01$@CORP.EXAMPLE.TEST"),
        since: "2026-10-25T12:00:00Z".parse().expect("time"),
        hold_until: None,
    };
    let encoded = tables::NAME_OWNERS.encode(&owner).expect("cbor");
    assert_eq!(tables::NAME_OWNERS.decode(&encoded).expect("cbor"), owner);
    assert_eq!(tenko_core::dns::KRB_PURPOSE, "krb");
    for code in [
        codes::KRB_ACCOUNT_NOT_FOUND,
        codes::KRB_ACCOUNT_INVALID,
        codes::KRB_KEYTAB_INVALID,
        codes::GSS_REFUSED,
    ] {
        assert!(codes::ALL.contains(&code), "{code}");
    }
    let error = KrbAccount {
        realm: realm(),
        name: String::new(),
        spns: vec!["DNS/ns1.corp.example.test".to_owned()],
        kdcs: Vec::new(),
        owned: true,
        rotation_days: 30,
        versions: Vec::new(),
        last_rotation: None,
        last_check: None,
    }
    .validate()
    .expect_err("an empty name");
    assert_eq!(error.code(), codes::KRB_ACCOUNT_INVALID);
    assert_eq!(error.http_status(), 400);
}

fn realm_text() -> impl Strategy<Value = String> {
    "[A-Za-z0-9.-]{1,40}"
}

fn component() -> impl Strategy<Value = String> {
    // Printable text with the characters the escapes cover, and a few others.
    proptest::collection::vec(
        prop_oneof![
            Just('/'),
            Just('@'),
            Just('\\'),
            Just('\n'),
            Just('$'),
            any::<char>().prop_filter("printable", |ch| !ch.is_control()),
        ],
        1..24,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn realms_are_case_insensitive_and_round_trip(text in realm_text()) {
        let upper = Realm::new(&text.to_ascii_uppercase()).expect("realm");
        let lower = Realm::new(&text.to_ascii_lowercase()).expect("realm");
        prop_assert_eq!(&upper, &lower);
        prop_assert_eq!(upper.as_str(), text.to_ascii_uppercase());
        prop_assert_eq!(upper.domain(), text.to_ascii_lowercase());
        let json = serde_json::to_string(&upper).expect("json");
        prop_assert_eq!(serde_json::from_str::<Realm>(&json).expect("json"), upper.clone());
        prop_assert_eq!(decode_key::<Realm>(&encode_key(&upper)).expect("key"), upper);
    }

    #[test]
    fn principal_names_round_trip_through_their_string_form(
        components in proptest::collection::vec(component(), 1..=8),
        realm in realm_text(),
    ) {
        let realm = Realm::new(&realm).expect("realm");
        let principal = PrincipalName::new(components.clone(), realm.clone()).expect("principal");
        let text = principal.to_string();
        let back = PrincipalName::parse(&text).expect("the string form parses");
        prop_assert_eq!(&back, &principal);
        prop_assert_eq!(back.components(), components.as_slice());
        prop_assert_eq!(back.realm(), &realm);
        prop_assert_eq!(
            from_cbor::<PrincipalName>(&to_cbor(&principal).expect("cbor")).expect("cbor"),
            principal.clone()
        );
        // The pattern of the name itself always matches, and `*` does.
        prop_assert!(identity::principal_matches(&principal.without_realm(), &principal));
        prop_assert!(identity::principal_matches("*", &principal));
        // A computer account is one component ending in `$`.
        prop_assert_eq!(
            principal.is_computer(),
            components.len() == 1 && components[0].ends_with('$')
        );
    }

    #[test]
    fn sids_round_trip_through_text_and_bytes(
        authority in 0_u64..(1 << 48),
        subs in proptest::collection::vec(any::<u32>(), 0..=15),
    ) {
        let sid = Sid::new(authority, subs.clone()).expect("sid");
        let text = sid.to_string();
        prop_assert!(text.starts_with("S-1-"));
        prop_assert_eq!(Sid::parse(&text).expect("parses"), sid.clone());
        prop_assert_eq!(Sid::from_bytes(&sid.to_bytes()).expect("packs"), sid.clone());
        prop_assert_eq!(sid.rid(), subs.last().copied());
        prop_assert_eq!(sid.parent().map(|parent| parent.sub_authorities().len()), subs.len().checked_sub(1));
        let json = serde_json::to_string(&sid).expect("json");
        prop_assert_eq!(serde_json::from_str::<Sid>(&json).expect("json"), sid);
    }

    #[test]
    fn a_name_owner_matches_itself_whatever_the_sid(
        subs in proptest::collection::vec(any::<u32>(), 1..=5),
        with_sid in any::<bool>(),
    ) {
        let own = Sid::new(5, subs).expect("sid");
        let principal = principal("WS01$@CORP.EXAMPLE.TEST");
        let owner = NameOwner {
            sid: with_sid.then(|| own.clone()),
            principal: principal.clone(),
            since: "2026-10-25T12:00:00Z".parse::<Timestamp>().expect("time"),
            hold_until: None,
        };
        prop_assert!(owner.is_owner(&principal, Some(&own)));
        prop_assert!(owner.is_owner(&principal, None));
        let _ = Ownership::default();
        let _ = Ipv4Addr::LOCALHOST;
    }
}
