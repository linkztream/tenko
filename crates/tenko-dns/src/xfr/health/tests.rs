use std::{collections::HashMap, net::IpAddr};

use tenko_core::dns::{AclId, PrimaryServer, SecondarySource, TransferPolicy};

use super::*;
use crate::xfr::access::Site;
use crate::xfr::access::tests::{list, name, zone};

fn codes(found: &[Finding]) -> Vec<(&'static str, String)> {
    found
        .iter()
        .map(|finding| {
            (
                finding.code,
                finding
                    .params
                    .get("rule")
                    .or(finding.params.get("field"))
                    .cloned()
                    .unwrap_or_default(),
            )
        })
        .collect()
}

fn assert_none(found: &[Finding]) {
    assert_eq!(codes(found), Vec::<(&'static str, String)>::new());
}

#[test]
fn a_zone_weaker_than_the_profile_is_a_finding_and_under_hardened_a_refusal() {
    let any = list(vec![AclEntry::Any { deny: false }]);
    let lists: HashMap<AclId, Acl> = HashMap::from([(any.id, any.clone())]);
    let mut zone = zone("example.test");
    zone.transfer = TransferPolicy {
        allow: vec![any.id],
        notify: Vec::new(),
        require_tsig: false,
        xot: false,
    };
    let acl = |id: AclId| lists.get(&id);
    let standard = findings(&zone, acl, UpdateProfile::Standard, &Site::default());
    assert_eq!(
        codes(&standard),
        vec![(WEAKER_THAN_PROFILE, "tsig".to_owned())]
    );
    assert!(standard[0].detail.contains("Hardened profile would refuse"));
    let hardened = findings(&zone, acl, UpdateProfile::Hardened, &Site::default());
    assert_eq!(
        codes(&hardened),
        vec![
            (PROFILE_REFUSES, "tsig".to_owned()),
            (PROFILE_REFUSES, "xot".to_owned())
        ]
    );
    // TSIG on and lists inside the site: nothing to report under Hardened.
    let inside = list(vec![AclEntry::Prefix {
        prefix: "10.0.0.0/8".parse().expect("prefix"),
        deny: false,
    }]);
    let lists: HashMap<AclId, Acl> = HashMap::from([(inside.id, inside.clone())]);
    zone.transfer.allow = vec![inside.id];
    zone.transfer.require_tsig = true;
    assert_none(&findings(
        &zone,
        |id| lists.get(&id),
        UpdateProfile::Hardened,
        &Site::default(),
    ));
    // No access list: the zone transfers to nobody, which is never a finding.
    zone.transfer.allow.clear();
    zone.transfer.require_tsig = false;
    assert_none(&findings(
        &zone,
        |id| lists.get(&id),
        UpdateProfile::Hardened,
        &Site::default(),
    ));
}

#[test]
fn a_hardened_secondary_whose_primary_has_no_key_is_a_finding() {
    let mut zone = zone("secondary.test");
    zone.kind = ZoneKind::Secondary;
    zone.source = Some(SecondarySource {
        primaries: vec![PrimaryServer {
            address: IpAddr::from([192, 0, 2, 53]),
            port: 53,
            key: None,
            xot: false,
            tls_name: None,
        }],
    });
    let none = |_: AclId| None;
    assert_eq!(
        codes(&findings(
            &zone,
            none,
            UpdateProfile::Hardened,
            &Site::default()
        )),
        vec![(PROFILE_REFUSES, "notify".to_owned())]
    );
    assert_none(&findings(
        &zone,
        none,
        UpdateProfile::Standard,
        &Site::default(),
    ));
    zone.source.as_mut().expect("source").primaries[0].key = Some(name("k.example.test"));
    assert_none(&findings(
        &zone,
        none,
        UpdateProfile::Hardened,
        &Site::default(),
    ));
}

#[test]
fn a_deny_that_overrides_another_lists_allow_is_named_with_both_entries() {
    let mut deny = list(vec![AclEntry::Prefix {
        prefix: "192.0.2.66/32".parse().expect("prefix"),
        deny: true,
    }]);
    deny.name = "blocked".to_owned();
    let mut allow = list(vec![AclEntry::Prefix {
        prefix: "192.0.2.0/24".parse().expect("prefix"),
        deny: false,
    }]);
    allow.name = "lan".to_owned();
    let mut elsewhere = list(vec![AclEntry::Prefix {
        prefix: "10.0.0.0/8".parse().expect("prefix"),
        deny: false,
    }]);
    elsewhere.name = "office".to_owned();
    let lists: HashMap<AclId, Acl> = [&deny, &allow, &elsewhere]
        .into_iter()
        .map(|acl| (acl.id, acl.clone()))
        .collect();
    let mut zone = zone("example.test");
    zone.transfer.allow = vec![deny.id, allow.id];
    zone.update.allowed = vec![allow.id, deny.id];
    let found = findings(
        &zone,
        |id| lists.get(&id),
        UpdateProfile::Standard,
        &Site::default(),
    );
    assert_eq!(
        codes(&found),
        vec![
            (DENY_WINS, "transfer".to_owned()),
            (DENY_WINS, "update".to_owned())
        ]
    );
    let params = &found[0].params;
    assert_eq!(params["deny_list"], "blocked");
    assert_eq!(params["deny_entry"], "192.0.2.66/32");
    assert_eq!(params["allow_list"], "lan");
    assert_eq!(params["allow_entry"], "192.0.2.0/24");
    assert!(
        found[0].detail.contains("stands while"),
        "{}",
        found[0].detail
    );
    // A deny that overlaps no allow of another list changes nothing.
    zone.transfer.allow = vec![deny.id, elsewhere.id];
    zone.update.allowed = vec![elsewhere.id];
    assert_none(&findings(
        &zone,
        |id| lists.get(&id),
        UpdateProfile::Standard,
        &Site::default(),
    ));
    // A deny its own list shadows never decides: an earlier entry matches all it matches.
    let mut shadowed = list(vec![
        AclEntry::Any { deny: false },
        AclEntry::Prefix {
            prefix: "192.0.2.66/32".parse().expect("prefix"),
            deny: true,
        },
    ]);
    shadowed.name = "shadowed".to_owned();
    let lists: HashMap<AclId, Acl> = [&shadowed, &allow]
        .into_iter()
        .map(|acl| (acl.id, acl.clone()))
        .collect();
    zone.transfer.allow = vec![shadowed.id, allow.id];
    zone.update.allowed.clear();
    assert_none(&findings(
        &zone,
        |id| lists.get(&id),
        UpdateProfile::Standard,
        &Site::default(),
    ));
    // Two different keys never match one request.
    let key_deny = list(vec![AclEntry::Key {
        name: name("a.example.test"),
        deny: true,
    }]);
    let key_allow = list(vec![AclEntry::Key {
        name: name("b.example.test"),
        deny: false,
    }]);
    let lists: HashMap<AclId, Acl> = [&key_deny, &key_allow]
        .into_iter()
        .map(|acl| (acl.id, acl.clone()))
        .collect();
    zone.transfer.allow = vec![key_deny.id, key_allow.id];
    assert_none(&findings(
        &zone,
        |id| lists.get(&id),
        UpdateProfile::Standard,
        &Site::default(),
    ));
}
