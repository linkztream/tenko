//! The compiled matcher: each kind of match, the facts of a message, AND and OR with
//! negation, the order of scope and server policies, the first match per action, and the
//! admission of scopes, pools and policy ranges.

use std::net::{IpAddr, Ipv4Addr};

use ipnet::Ipv4Net;
use tenko_core::{
    PrefixId, RangeId, VrfId,
    dhcp::{
        AddressRange, Class, ClassId, Condition, DdnsPolicy, Join, LeaseTimes, MacPattern, Match,
        OptionValue, Policy, PolicyAction, PolicyId, Term,
    },
    ipam::Stamp,
    principal::{Principal, SystemComponent},
    serde_util::HexBytes,
};

use super::{Facts, Matcher, Test};
use crate::{
    image::{PoolImage, ScopeImage},
    v4::{BOOTREQUEST, Message, MessageBuilder, MessageType, code},
};

fn stamp() -> Stamp {
    Stamp::new(
        "2026-10-22T12:00:00Z".parse().expect("time"),
        Principal::system(SystemComponent::Dhcp),
    )
}

const MAC: [u8; 6] = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x21];

fn ip(text: &str) -> Ipv4Addr {
    text.parse().expect("an address")
}

/// A DISCOVER with options 12, 60, 61, 77, 82 (circuit-id and remote-id) and 93.
fn request(vendor: &[u8], user: &[u8], arch: u16) -> Vec<u8> {
    let mut buf = [0u8; 1024];
    let mut builder = MessageBuilder::new(&mut buf, 1024).expect("builder");
    builder.op(BOOTREQUEST).htype(1).hlen(6).xid(7);
    builder.chaddr(&MAC).expect("chaddr");
    builder.message_type(MessageType::Discover).expect("53");
    let mut id = vec![1];
    id.extend(MAC);
    builder.option(code::CLIENT_IDENTIFIER, &id).expect("61");
    builder.option(code::HOST_NAME, b"Lab-PC-07").expect("12");
    builder
        .option(code::VENDOR_CLASS_IDENTIFIER, vendor)
        .expect("60");
    builder.option(code::USER_CLASS, user).expect("77");
    builder
        .option(code::CLIENT_ARCHITECTURE, &arch.to_be_bytes())
        .expect("93");
    builder
        .relay_agent_info(&[1, 3, b'l', b'a', b'n', 2, 2, 0xab, 0xcd])
        .expect("82");
    let len = builder.finish().expect("finish");
    buf[..len].to_vec()
}

fn class(name: &str, matches: Vec<Match>) -> Class {
    Class {
        id: ClassId::generate(),
        name: name.to_owned(),
        matches,
        description: None,
        created: stamp(),
        updated: stamp(),
    }
}

fn policy(scope: Option<PrefixId>, order: u32, join: Join, terms: Vec<Term>) -> Policy {
    Policy {
        id: PolicyId::generate(),
        name: format!("policy-{order}"),
        scope,
        order,
        enabled: true,
        condition: Condition { join, terms },
        action: PolicyAction::default(),
        description: None,
        created: stamp(),
        updated: stamp(),
    }
}

fn scope(prefix: PrefixId, classes: Vec<ClassId>, pools: Vec<PoolImage>) -> ScopeImage {
    ScopeImage {
        prefix,
        vrf: VrfId::generate(),
        network: "192.0.2.0/24".parse::<Ipv4Net>().expect("net"),
        authoritative: true,
        restricted: false,
        server_id: None,
        lease: LeaseTimes::default(),
        shared_network: None,
        pools,
        excluded: Vec::new(),
        options: Vec::new(),
        classes,
        ddns: DdnsPolicy::default(),
    }
}

fn pool(first: &str, last: &str, classes: Vec<ClassId>) -> PoolImage {
    PoolImage {
        range: RangeId::generate(),
        first: ip(first),
        last: ip(last),
        lease: LeaseTimes::default(),
        classes,
        options: Vec::new(),
    }
}

#[test]
fn the_facts_of_a_message_borrow_every_field_a_class_tests() {
    let bytes = request(b"PXEClient:Arch:00007:UNDI:003016", b"iPXE", 7);
    let message = Message::parse(&bytes).expect("parse");
    let facts = Facts::of(&message);
    assert_eq!(facts.mac, Some(MAC));
    assert_eq!(facts.client_id.map(<[u8]>::len), Some(7));
    assert_eq!(
        facts.vendor_class,
        Some(&b"PXEClient:Arch:00007:UNDI:003016"[..])
    );
    assert_eq!(facts.user_class, Some(&b"iPXE"[..]));
    assert_eq!(facts.circuit_id, Some(&b"lan"[..]));
    assert_eq!(facts.remote_id, Some(&[0xab, 0xcd][..]));
    assert_eq!(facts.architecture(), Some(7));
    assert!(facts.has_architecture(7) && !facts.has_architecture(0));
    assert_eq!(facts.host_name, Some(&b"Lab-PC-07"[..]));
}

#[test]
fn every_kind_of_match_holds_for_its_field_only() {
    let bytes = request(
        b"MSFT 5.0",
        &[4, b'l', b'a', b'b', b'1', 3, b'o', b'p', b's'],
        0,
    );
    let message = Message::parse(&bytes).expect("parse");
    let facts = Facts::of(&message);
    let holds = |item: Match| Test::compile(&item).holds(&facts);
    let text = |value: &str| value.to_owned();
    assert!(holds(Match::VendorClass {
        value: text("MSFT 5.0"),
        prefix: false
    }));
    assert!(!holds(Match::VendorClass {
        value: text("MSFT"),
        prefix: false
    }));
    assert!(holds(Match::VendorClass {
        value: text("MSFT"),
        prefix: true
    }));
    // RFC 3004: one of the length-prefixed classes, or the whole value as sent.
    assert!(holds(Match::UserClass { value: text("ops") }));
    assert!(holds(Match::UserClass {
        value: text("lab1")
    }));
    assert!(!holds(Match::UserClass { value: text("op") }));
    assert!(holds(Match::Mac {
        pattern: MacPattern::new("00:00:5e:00:53:*").expect("pattern")
    }));
    assert!(!holds(Match::Mac {
        pattern: MacPattern::new("00:00:5e:00:54:*").expect("pattern")
    }));
    let mut id = vec![1];
    id.extend(MAC);
    assert!(holds(Match::ClientId {
        value: HexBytes(id.clone())
    }));
    assert!(!holds(Match::ClientId {
        value: HexBytes(id[1..].to_vec())
    }));
    assert!(holds(Match::CircuitId {
        value: HexBytes(b"lan".to_vec())
    }));
    assert!(holds(Match::RemoteId {
        value: HexBytes(vec![0xab, 0xcd])
    }));
    assert!(!holds(Match::RemoteId {
        value: HexBytes(b"lan".to_vec())
    }));
    assert!(holds(Match::Architecture { code: 0 }));
    assert!(!holds(Match::Architecture { code: 7 }));
    assert!(holds(Match::HostName {
        value: text("lab-pc-07"),
        prefix: false
    }));
    assert!(holds(Match::HostName {
        value: text("LAB-PC"),
        prefix: true
    }));
    assert!(!holds(Match::HostName {
        value: text("lab-pc"),
        prefix: false
    }));
}

#[test]
fn a_plain_user_class_matches_as_sent() {
    // iPXE sends option 77 as the plain string "iPXE", which is not RFC 3004's form.
    let bytes = request(b"PXEClient:Arch:00000:UNDI:002001", b"iPXE", 0);
    let message = Message::parse(&bytes).expect("parse");
    let facts = Facts::of(&message);
    assert!(
        Test::compile(&Match::UserClass {
            value: "iPXE".to_owned()
        })
        .holds(&facts)
    );
    assert!(
        !Test::compile(&Match::UserClass {
            value: "PXE".to_owned()
        })
        .holds(&facts)
    );
}

#[test]
fn conditions_join_terms_with_and_or_and_negation() {
    let prefix = PrefixId::generate();
    let uefi = class("uefi", vec![Match::Architecture { code: 7 }]);
    let ipxe = class(
        "ipxe",
        vec![Match::UserClass {
            value: "iPXE".to_owned(),
        }],
    );
    let gone = ClassId::generate();
    let mut policies = vec![
        // 1: uefi AND NOT ipxe: false for an iPXE client.
        policy(
            Some(prefix),
            1,
            Join::And,
            vec![Term::Class(uefi.id), Term::NotClass(ipxe.id)],
        ),
        // 2: a class the image lacks, OR a vendor prefix: true.
        policy(
            Some(prefix),
            2,
            Join::Or,
            vec![
                Term::Class(gone),
                Term::Match(Match::VendorClass {
                    value: "PXEClient".to_owned(),
                    prefix: true,
                }),
            ],
        ),
        // 3: NOT a missing class AND NOT a host name: true.
        policy(
            Some(prefix),
            3,
            Join::And,
            vec![
                Term::NotClass(gone),
                Term::NotMatch(Match::HostName {
                    value: "other".to_owned(),
                    prefix: false,
                }),
            ],
        ),
        // 4: disabled.
        policy(Some(prefix), 4, Join::Or, vec![Term::Class(uefi.id)]),
        // 5: the server's, after the scope's.
        policy(None, 0, Join::Or, vec![Term::Class(ipxe.id)]),
    ];
    policies[3].enabled = false;
    let scopes = [scope(prefix, Vec::new(), Vec::new())];
    let matcher = Matcher::compile(&[uefi, ipxe], &policies, &scopes, |_| Vec::new());
    let bytes = request(b"PXEClient:Arch:00007:UNDI:003016", b"iPXE", 7);
    let message = Message::parse(&bytes).expect("parse");
    let decision = matcher.decide(prefix, Facts::of(&message));
    let found: Vec<PolicyId> = decision.matched().map(|rule| rule.id).collect();
    assert_eq!(found, vec![policies[1].id, policies[2].id, policies[4].id]);
    // Another scope sees the server's policy only.
    let other = matcher.decide(PrefixId::generate(), Facts::of(&message));
    let found: Vec<PolicyId> = other.matched().map(|rule| rule.id).collect();
    assert_eq!(found, vec![policies[4].id]);
}

#[test]
fn the_first_matching_policy_wins_per_action_and_per_option() {
    let prefix = PrefixId::generate();
    let any = || {
        vec![Term::Match(Match::Mac {
            pattern: MacPattern::new("00:00:5e:*").expect("pattern"),
        })]
    };
    let mut first = policy(Some(prefix), 1, Join::Or, any());
    first.action.lease = Some(LeaseTimes::fixed(600));
    let mut second = policy(Some(prefix), 2, Join::Or, any());
    second.action.lease = Some(LeaseTimes::fixed(60));
    second.action.range = Some(AddressRange {
        first: IpAddr::V4(ip("192.0.2.200")),
        last: IpAddr::V4(ip("192.0.2.209")),
    });
    second.action.ddns = Some(DdnsPolicy {
        enabled: true,
        ..DdnsPolicy::default()
    });
    let (a, b) = (first.id, second.id);
    let scopes = [scope(prefix, Vec::new(), Vec::new())];
    let matcher = Matcher::compile(&[], &[first, second], &scopes, |id| {
        if id == a {
            vec![OptionValue::v4(code::BOOTFILE_NAME, b"first.efi".to_vec())]
        } else if id == b {
            vec![
                OptionValue::v4(code::BOOTFILE_NAME, b"second.efi".to_vec()),
                OptionValue::v4(code::TFTP_SERVER_NAME, b"192.0.2.5".to_vec()),
            ]
        } else {
            Vec::new()
        }
    });
    let bytes = request(b"PXEClient", b"x", 0);
    let message = Message::parse(&bytes).expect("parse");
    let decision = matcher.decide(prefix, Facts::of(&message));
    assert_eq!(decision.lease().map(|times| times.default_secs), Some(600));
    assert_eq!(
        decision.range(),
        Some((ip("192.0.2.200"), ip("192.0.2.209")))
    );
    assert!(decision.ddns().is_some_and(|ddns| ddns.enabled));
    assert_eq!(
        decision.option(code::BOOTFILE_NAME),
        Some(&b"first.efi"[..])
    );
    assert_eq!(
        decision.option(code::TFTP_SERVER_NAME),
        Some(&b"192.0.2.5"[..])
    );
    assert_eq!(decision.option(code::DOMAIN_NAME), None);
}

#[test]
fn scopes_pools_and_policy_ranges_admit_their_clients_only() {
    let prefix = PrefixId::generate();
    let printers = class(
        "printers",
        vec![Match::VendorClass {
            value: "Printer".to_owned(),
            prefix: true,
        }],
    );
    let pxe = class(
        "pxe",
        vec![Match::VendorClass {
            value: "PXEClient".to_owned(),
            prefix: true,
        }],
    );
    let mut ranged = policy(Some(prefix), 1, Join::Or, vec![Term::Class(printers.id)]);
    ranged.action.range = Some(AddressRange {
        first: IpAddr::V4(ip("192.0.2.40")),
        last: IpAddr::V4(ip("192.0.2.49")),
    });
    let pools = vec![
        pool("192.0.2.10", "192.0.2.99", Vec::new()),
        pool("192.0.2.150", "192.0.2.199", vec![pxe.id]),
    ];
    let open = scope(prefix, Vec::new(), pools.clone());
    let closed = scope(PrefixId::generate(), vec![pxe.id], pools);
    let scopes = [open.clone(), closed.clone()];
    let matcher = Matcher::compile(&[printers, pxe], &[ranged], &scopes, |_| Vec::new());
    let printer = request(b"Printer-7", b"x", 0);
    let printer = Message::parse(&printer).expect("parse");
    let printer = matcher.decide(prefix, Facts::of(&printer));
    let laptop = request(b"MSFT 5.0", b"x", 0);
    let laptop = Message::parse(&laptop).expect("parse");
    let laptop = matcher.decide(prefix, Facts::of(&laptop));
    let boot = request(b"PXEClient:Arch:00000", b"x", 0);
    let boot = Message::parse(&boot).expect("parse");
    let boot = matcher.decide(prefix, Facts::of(&boot));
    // The printer is confined to its policy's range.
    assert!(printer.admits(&open, ip("192.0.2.45")));
    assert!(!printer.admits(&open, ip("192.0.2.20")));
    assert!(printer.admits_pool(&open, &open.pools[0]));
    assert!(!printer.admits_pool(&open, &open.pools[1]));
    // The policy's range is kept from the others.
    assert!(!laptop.admits(&open, ip("192.0.2.45")));
    assert!(laptop.admits(&open, ip("192.0.2.20")));
    // The second pool admits the PXE class only.
    assert!(!laptop.admits(&open, ip("192.0.2.160")));
    assert!(boot.admits(&open, ip("192.0.2.160")));
    assert!(!laptop.admits_pool(&open, &open.pools[1]));
    // The closed scope admits the PXE class only.
    assert!(boot.admits_scope(&closed) && !laptop.admits_scope(&closed));
    assert!(!laptop.admits(&closed, ip("192.0.2.20")));
    // Without classes and policies nothing is restricted.
    let empty = Matcher::default();
    assert!(empty.is_empty());
    let message = request(b"Printer-7", b"x", 0);
    let message = Message::parse(&message).expect("parse");
    let nothing = empty.decide(prefix, Facts::of(&message));
    assert!(nothing.is_empty() && nothing.admits(&open, ip("192.0.2.45")));
}
