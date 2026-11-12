//! The parts of the claim plan that read text: the digest, the cursor, the address a
//! reverse name stands for, the rule's bounds and its line in the audit record.

use super::*;

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

#[test]
fn a_digest_reads_back_and_refuses_anything_else() {
    let digest = ClaimDigest([0xab; 32]);
    let text = digest.to_string();
    assert_eq!(text.len(), 64);
    assert_eq!(text.parse::<ClaimDigest>().expect("reads"), digest);
    assert_eq!(
        text.to_uppercase().parse::<ClaimDigest>().expect("reads"),
        digest
    );
    for bad in [
        "",
        "ab",
        &text[1..],
        &format!("{text}0"),
        &text.replace('a', "g"),
    ] {
        let error = bad.parse::<ClaimDigest>().expect_err(bad);
        assert!(error.is(CLAIMABLE_INVALID), "{bad}");
    }
}

#[test]
fn the_digest_covers_the_file_the_zone_the_scope_and_the_set() {
    let zone = ZoneId::generate();
    let set: BTreeSet<(DnsName, Rtype)> = [(name("pc01.example.test"), Rtype::A)].into();
    let base = digest_of(zone, &ScopeName::DEFAULT, "text", &set);
    assert_eq!(base, digest_of(zone, &ScopeName::DEFAULT, "text", &set));
    assert_ne!(base, digest_of(zone, &ScopeName::DEFAULT, "text ", &set));
    assert_ne!(
        base,
        digest_of(ZoneId::generate(), &ScopeName::DEFAULT, "text", &set)
    );
    let scope = ScopeName::new("lab").expect("scope");
    assert_ne!(base, digest_of(zone, &scope, "text", &set));
    let more: BTreeSet<(DnsName, Rtype)> = [
        (name("pc01.example.test"), Rtype::A),
        (name("pc01.example.test"), Rtype::AAAA),
    ]
    .into();
    assert_ne!(base, digest_of(zone, &ScopeName::DEFAULT, "text", &more));
    assert_ne!(
        base,
        digest_of(zone, &ScopeName::DEFAULT, "text", &BTreeSet::new())
    );
}

#[test]
fn a_cursor_reads_back() {
    let text = cursor(&name("pc01.example.test"), Rtype::AAAA);
    assert_eq!(
        parse_cursor(&text).expect("reads"),
        (name("pc01.example.test"), Rtype::AAAA)
    );
    for bad in ["", "pc01.example.test", "pc01.example.test A", "a b 1x"] {
        let error = parse_cursor(bad).expect_err(bad);
        assert!(error.is(CLAIMABLE_INVALID), "{bad}: {error:?}");
    }
}

#[test]
fn a_reverse_name_stands_for_an_address() {
    assert_eq!(
        reverse_address(&name("21.2.0.192.in-addr.arpa")),
        Some("192.0.2.21".parse().expect("address"))
    );
    let six = "1.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
    assert_eq!(
        reverse_address(&name(six)),
        Some("2001:db8::21".parse().expect("address"))
    );
    for partial in [
        "2.0.192.in-addr.arpa",
        "300.2.0.192.in-addr.arpa",
        "0/26.2.0.192.in-addr.arpa",
        "8.b.d.0.1.0.0.2.ip6.arpa",
        "pc01.example.test",
    ] {
        assert_eq!(reverse_address(&name(partial)), None, "{partial}");
    }
}

#[test]
fn the_bounds_of_a_claim_request() {
    let ok = ClaimRequest::default();
    assert!(ok.check().is_ok());
    assert!(ok.is_empty());
    let too_many = |request: ClaimRequest, field: &str| {
        let error = request.check().expect_err(field);
        assert!(error.is(CLAIMABLE_INVALID), "{field}");
        assert_eq!(
            error.coded().params.get("field").map(String::as_str),
            Some(field)
        );
    };
    too_many(
        ClaimRequest {
            rule: ClaimRule {
                under: vec![name("example.test"); MAX_RULE_NAMES + 1],
                ..ClaimRule::default()
            },
            ..ClaimRequest::default()
        },
        "under",
    );
    too_many(
        ClaimRequest {
            rule: ClaimRule {
                within: vec!["192.0.2.0/24".parse().expect("net"); MAX_RULE_PREFIXES + 1],
                ..ClaimRule::default()
            },
            ..ClaimRequest::default()
        },
        "within",
    );
    too_many(
        ClaimRequest {
            rule: ClaimRule {
                except: vec![name("example.test"); MAX_RULE_EXCEPT + 1],
                ..ClaimRule::default()
            },
            ..ClaimRequest::default()
        },
        "except",
    );
    too_many(
        ClaimRequest {
            limit: Some(0),
            ..ClaimRequest::default()
        },
        "limit",
    );
    too_many(
        ClaimRequest {
            reserved_hosts: vec!["tenko1".to_owned(); MAX_RESERVED_HOSTS + 1],
            ..ClaimRequest::default()
        },
        "reserved_hosts",
    );
}

#[test]
fn the_rule_in_one_line() {
    assert_eq!(ClaimRule::default().describe(), "every candidate");
    let rule = ClaimRule {
        under: vec![name("corp.example.test")],
        within: vec!["192.0.2.0/24".parse().expect("net")],
        except: vec![name("a.corp.example.test"), name("b.corp.example.test")],
    };
    assert_eq!(
        rule.describe(),
        "under corp.example.test; within 192.0.2.0/24; except 2 name(s)"
    );
}

#[test]
fn the_address_tree() {
    for inside in [
        "21.2.0.192.in-addr.arpa",
        "2.0.192.in-addr.arpa",
        "0/26.2.0.192.in-addr.arpa",
        "8.b.d.0.1.0.0.2.ip6.arpa",
    ] {
        assert!(is_address_tree(&name(inside)), "{inside}");
    }
    for outside in [
        "in-addr.arpa",
        "ip6.arpa",
        "arpa",
        "wpad.corp.example.test",
        "in-addr.arpa.example.test",
    ] {
        assert!(!is_address_tree(&name(outside)), "{outside}");
    }
}
