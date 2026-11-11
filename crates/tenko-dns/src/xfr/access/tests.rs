use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tenko_core::dns::{
    AclId, DnsName, PrimaryServer, SecondarySource, SoaDefaults, TransferPolicy, ZoneScope,
};

use super::*;

pub(crate) fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

pub(crate) fn zone(apex: &str) -> Zone {
    let stamp = tenko_core::ipam::Stamp::new(
        "2026-11-11T12:00:00Z".parse().expect("time"),
        tenko_core::Principal::system(tenko_core::SystemComponent::Dns),
    );
    Zone {
        id: ZoneId::generate(),
        name: name(apex),
        kind: ZoneKind::Primary,
        tenant: None,
        scopes: vec![ZoneScope::default_scope()],
        serial: tenko_core::dns::SerialPolicy::default(),
        soa: SoaDefaults::new(
            name(&format!("ns1.{apex}")),
            name(&format!("hostmaster.{apex}")),
        ),
        transfer: TransferPolicy::default(),
        update: tenko_core::dns::UpdatePolicy::default(),
        dnssec: tenko_core::dns::DnssecPolicy::default(),
        source: None,
        reverse_of: None,
        catalog: false,
        description: None,
        created: stamp.clone(),
        updated: stamp,
    }
}

pub(crate) fn list(entries: Vec<AclEntry>) -> Acl {
    Acl {
        id: AclId::generate(),
        name: "secondaries".to_owned(),
        entries,
        description: None,
    }
}

fn key() -> KeyName {
    name("transfer.example.test")
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// A zone with one list that allows `any` and names the key, `require_tsig` and `xot` as
/// given.
fn open(require_tsig: bool, xot: bool) -> (Zone, Acl) {
    let acl = list(vec![
        AclEntry::Key {
            name: key(),
            deny: false,
        },
        AclEntry::Any { deny: false },
    ]);
    let mut zone = zone("example.test");
    zone.transfer = TransferPolicy {
        allow: vec![acl.id],
        notify: Vec::new(),
        require_tsig,
        xot,
    };
    (zone, acl)
}

#[test]
fn the_site_is_the_private_shared_unique_local_loopback_and_link_local_ranges() {
    let site = Site::default();
    for inside in [
        v4(10, 1, 2, 3),
        v4(172, 31, 0, 1),
        v4(192, 168, 1, 1),
        v4(100, 64, 0, 1),
        v4(127, 0, 0, 1),
        v4(169, 254, 9, 9),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        "fd00::1".parse().expect("ula"),
        "fe80::1".parse().expect("link-local"),
        IpAddr::V6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped()),
    ] {
        assert!(site.contains(inside), "{inside} is inside the site");
    }
    for outside in [
        v4(192, 0, 2, 7),
        v4(198, 51, 100, 1),
        v4(172, 32, 0, 1),
        "2001:db8::1".parse().expect("documentation"),
    ] {
        assert!(!site.contains(outside), "{outside} leaves the site");
    }
    assert!(site.contains_network(&"10.20.0.0/16".parse().expect("net")));
    assert!(!site.contains_network(&"0.0.0.0/0".parse().expect("net")));
}

/// The site is the administrator's list (`transfer_site`): a network added counts as
/// inside, a default range removed does not, and an empty list makes every client leave
/// the site, so that under Hardened every transfer needs XoT.
#[test]
fn the_site_follows_the_setting() {
    let (zone, acl) = open(true, false);
    let lists = [&acl];
    let hardened = UpdateProfile::Hardened;
    let site = Site::of(&["203.0.113.0/24".to_owned()]);
    let listed = v4(203, 0, 113, 9);
    let private = v4(10, 0, 0, 7);
    assert!(site.contains(listed) && !site.contains(private));
    assert_eq!(
        transfer(&zone, &lists, hardened, &site, listed, Some(&key()), false),
        Ok(())
    );
    assert_eq!(
        transfer(&zone, &lists, hardened, &site, private, Some(&key()), false)
            .map_err(|refusal| refusal.code),
        Err(codes::PROFILE_XOT)
    );
    site.set(Vec::new());
    assert!(
        !site.contains(v4(127, 0, 0, 1)),
        "an empty site holds nothing"
    );
    assert_eq!(
        transfer(&zone, &lists, hardened, &site, listed, Some(&key()), true),
        Ok(()),
        "over XoT"
    );
}

/// TGL-10 under Hardened: the profile's floor holds whatever the zone stores (TSIG always,
/// XoT for clients outside the site); under the other profiles the zone's settings apply.
#[test]
fn the_hardened_floor_holds_whatever_the_zone_stores() {
    let site = Site::default();
    let (zone, acl) = open(false, false);
    let lists = [&acl];
    let public = v4(198, 51, 100, 7);
    let private = v4(10, 0, 0, 7);
    for profile in [
        UpdateProfile::Home,
        UpdateProfile::Standard,
        UpdateProfile::Lab,
    ] {
        assert_eq!(
            transfer(&zone, &lists, profile, &site, public, None, false),
            Ok(())
        );
    }
    let hardened = UpdateProfile::Hardened;
    let refused =
        transfer(&zone, &lists, hardened, &site, private, None, false).expect_err("unsigned");
    assert_eq!(refused.code, codes::PROFILE_UNSIGNED);
    assert_eq!(
        transfer(&zone, &lists, hardened, &site, private, Some(&key()), false),
        Ok(()),
        "signed, inside the site, over TCP"
    );
    let refused = transfer(&zone, &lists, hardened, &site, public, Some(&key()), false)
        .expect_err("off-site");
    assert_eq!(refused.code, codes::PROFILE_XOT);
    assert_eq!(
        transfer(&zone, &lists, hardened, &site, public, Some(&key()), true),
        Ok(()),
        "signed over XoT"
    );
    // A key the lists do not name is refused under the floor too.
    let other = name("other.example.test");
    let refused = transfer(&zone, &lists, hardened, &site, private, Some(&other), true)
        .expect_err("not named");
    assert_eq!(refused.code, codes::KEY_NOT_NAMED);
    // The zone's own `xot` is stricter than the floor and holds inside the site as well.
    let (strict, acl) = open(true, true);
    let refused = transfer(
        &strict,
        &[&acl],
        hardened,
        &site,
        private,
        Some(&key()),
        false,
    )
    .expect_err("xot");
    assert_eq!(refused.code, codes::XOT);
    assert_eq!(
        effective(&zone, hardened),
        Effective {
            tsig: Rule::Profile,
            xot: Rule::Profile
        }
    );
    assert_eq!(
        effective(&strict, hardened),
        Effective {
            tsig: Rule::Zone,
            xot: Rule::Zone
        }
    );
    assert_eq!(
        effective(&zone, UpdateProfile::Standard),
        Effective {
            tsig: Rule::Off,
            xot: Rule::Off
        }
    );
}

/// Deny wins across the transfer lists (owner decision of 2026-11-06).
#[test]
fn a_deny_in_any_transfer_list_wins() {
    let site = Site::default();
    let deny = list(vec![AclEntry::Prefix {
        prefix: "192.0.2.66/32".parse().expect("prefix"),
        deny: true,
    }]);
    let allow = list(vec![AclEntry::Prefix {
        prefix: "192.0.2.0/24".parse().expect("prefix"),
        deny: false,
    }]);
    let mut zone = zone("example.test");
    zone.transfer = TransferPolicy {
        allow: vec![deny.id, allow.id],
        notify: Vec::new(),
        require_tsig: false,
        xot: false,
    };
    let lists = [&deny, &allow];
    let standard = UpdateProfile::Standard;
    let refused = transfer(
        &zone,
        &lists,
        standard,
        &site,
        v4(192, 0, 2, 66),
        None,
        false,
    )
    .expect_err("the deny wins");
    assert_eq!(refused.code, codes::NOT_ALLOWED);
    assert_eq!(
        transfer(
            &zone,
            &lists,
            standard,
            &site,
            v4(192, 0, 2, 7),
            None,
            false
        ),
        Ok(())
    );
    let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 66).to_ipv6_mapped());
    assert!(
        transfer(&zone, &lists, standard, &site, mapped, None, false).is_err(),
        "a mapped address is the same client"
    );
    zone.transfer.allow.clear();
    let refused =
        transfer(&zone, &[], standard, &site, v4(192, 0, 2, 7), None, false).expect_err("no list");
    assert_eq!(refused.code, codes::NO_ACCESS_LIST);
}

#[test]
fn a_notify_comes_from_a_primary_and_under_hardened_is_signed() {
    let mut zone = zone("secondary.test");
    zone.kind = ZoneKind::Secondary;
    zone.source = Some(SecondarySource {
        primaries: vec![
            PrimaryServer {
                address: v4(192, 0, 2, 53),
                port: 53,
                key: None,
                xot: false,
                tls_name: None,
            },
            PrimaryServer {
                address: v4(192, 0, 2, 54),
                port: 53,
                key: Some(key()),
                xot: false,
                tls_name: None,
            },
        ],
    });
    let standard = UpdateProfile::Standard;
    let hardened = UpdateProfile::Hardened;
    assert_eq!(
        notify(&zone, standard, v4(192, 0, 2, 53), None),
        Ok((zone.id, false))
    );
    // A key of the node is not the primary's key: unsigned for the backoff.
    assert_eq!(
        notify(&zone, standard, v4(192, 0, 2, 53), Some(&key())),
        Ok((zone.id, false))
    );
    assert_eq!(
        notify(&zone, hardened, v4(192, 0, 2, 53), None).map_err(|r| r.code),
        Err(codes::PROFILE_NOTIFY_UNSIGNED)
    );
    assert_eq!(
        notify(&zone, standard, v4(192, 0, 2, 54), None).map_err(|r| r.code),
        Err(codes::NOTIFY_KEY)
    );
    assert_eq!(
        notify(&zone, hardened, v4(192, 0, 2, 54), Some(&key())),
        Ok((zone.id, true))
    );
    assert_eq!(
        notify(&zone, standard, v4(192, 0, 2, 99), None).map_err(|r| r.code),
        Err(codes::NOT_A_PRIMARY)
    );
    zone.kind = ZoneKind::Primary;
    assert_eq!(
        notify(&zone, standard, v4(192, 0, 2, 53), None).map_err(|r| r.code),
        Err(codes::NOT_SECONDARY)
    );
}
