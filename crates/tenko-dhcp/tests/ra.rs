//! The router advertisement check of DHCP-10 (WP9.2): `evaluate` and `RaWatch` against a
//! hand-built DHCPv6 image. Each finding has its case and its counter-case: flags off on a
//! link with a scope, M on, O only with and without address pools, M on a link without a
//! scope, the node's own networks as the link's mapping to a scope, routers whose flags are
//! combined, the forgetting of what is stale, the limits of the watch and the report of a check
//! that cannot run. Documentation addresses (RFC 3849) and MACs (RFC 7042) only.

mod engine6_world;

use std::net::Ipv6Addr;
use std::time::Duration;

use engine6_world::scope;
use ipnet::Ipv6Net;
use tenko_core::{PrefixId, Timestamp};
use tenko_dhcp::{
    ra::{
        FLAGS_OFF, MANAGED_WITHOUT_SCOPE, MAX_HEARD, MAX_ROUTERS, OTHER_ONLY, RaCheck, RaHeard,
        RaWatch, STALE, UNCHECKED, evaluate,
    },
    v6::image::Image6,
};

// ---------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------

fn net(text: &str) -> Ipv6Net {
    text.parse().expect("a network")
}

fn ip(text: &str) -> Ipv6Addr {
    text.parse().expect("an address")
}

/// A moment `secs` seconds after the epoch plus a fixed offset.
fn at(secs: u64) -> Timestamp {
    Timestamp::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_000_000 + secs))
        .expect("a timestamp")
}

/// The router with the documentation MAC 00:00:5e:00:53:`last`, by its link-local address.
fn router(last: u8) -> Ipv6Addr {
    ip(&format!("fe80::200:5eff:fe00:53{last:02x}"))
}

/// A scope of `network` with one address pool.
fn scope_of(network: &str) -> tenko_dhcp::v6::image::Scope6Image {
    let base = network.split("::").next().expect("a network");
    scope(
        PrefixId::generate(),
        network,
        &format!("{base}::100"),
        &format!("{base}::1ff"),
    )
}

/// A scope of `network` without an address pool: only delegation could be served from it.
fn scope_without_pools(network: &str) -> tenko_dhcp::v6::image::Scope6Image {
    let mut scope = scope_of(network);
    scope.pools.clear();
    scope
}

fn image(scopes: Vec<tenko_dhcp::v6::image::Scope6Image>) -> Image6 {
    let mut image = Image6::default();
    for scope in scopes {
        image.add_scope(scope);
    }
    image
}

/// One advertisement of router `last` on interface `index` (named `eth<index>`).
fn heard(
    index: u32,
    last: u8,
    managed: bool,
    other: bool,
    prefixes: &[&str],
    when: Timestamp,
) -> RaHeard {
    RaHeard {
        interface: index,
        name: format!("eth{index}"),
        router: router(last),
        managed,
        other,
        router_lifetime: 1800,
        prefixes: prefixes.iter().map(|text| net(text)).collect(),
        networks: Vec::new(),
        at: when,
    }
}

fn with_networks(mut entry: RaHeard, networks: &[&str]) -> RaHeard {
    entry.networks = networks.iter().map(|text| net(text)).collect();
    entry
}

fn param<'a>(finding: &'a tenko_dhcp::ra::RaFinding, key: &str) -> &'a str {
    finding
        .params
        .get(key)
        .unwrap_or_else(|| panic!("no parameter {key}: {:?}", finding.params))
}

// ---------------------------------------------------------------------------------------
// evaluate: the findings
// ---------------------------------------------------------------------------------------

#[test]
fn the_codes_are_the_stable_names_of_the_health_rows() {
    assert_eq!(FLAGS_OFF, "dhcp.ra.flags_off");
    assert_eq!(OTHER_ONLY, "dhcp.ra.other_only");
    assert_eq!(MANAGED_WITHOUT_SCOPE, "dhcp.ra.managed_without_scope");
    assert_eq!(UNCHECKED, "dhcp.ra.unchecked");
}

#[test]
fn flags_off_on_a_link_with_a_scope_is_found() {
    let image = image(vec![scope_of("2001:db8:1::/64")]);
    let entries = [heard(2, 1, false, false, &["2001:db8:1::/64"], at(10))];
    let (links, findings) = evaluate(&image, &entries);

    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.code, FLAGS_OFF);
    assert_eq!(finding.interface, "eth2");
    assert_eq!(param(finding, "interface"), "eth2");
    assert_eq!(param(finding, "routers"), "fe80::200:5eff:fe00:5301");
    assert_eq!(param(finding, "scopes"), "2001:db8:1::/64");
    assert_eq!(finding.params.len(), 3);
    assert!(finding.detail.contains("eth2"));
    assert!(finding.detail.contains("2001:db8:1::/64"));
    assert!(finding.detail.contains("fe80::200:5eff:fe00:5301"));

    assert_eq!(links.len(), 1);
    assert_eq!(links[0].interface, "eth2");
    assert_eq!(links[0].routers, vec![router(1)]);
    assert!(!links[0].managed && !links[0].other);
    assert_eq!(links[0].prefixes, vec![net("2001:db8:1::/64")]);
    assert_eq!(links[0].scopes, vec![net("2001:db8:1::/64")]);
    assert_eq!(links[0].seen, at(10));
}

#[test]
fn flags_off_on_a_link_without_a_scope_is_nothing() {
    let image = image(vec![scope_of("2001:db8:1::/64")]);
    let entries = [heard(2, 1, false, false, &["2001:db8:9::/64"], at(10))];
    let (links, findings) = evaluate(&image, &entries);
    assert_eq!(findings.len(), 0);
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].scopes.len(), 0);
}

#[test]
fn the_m_flag_with_a_scope_is_no_finding() {
    let image = image(vec![scope_of("2001:db8:1::/64")]);
    let entries = [heard(2, 1, true, false, &["2001:db8:1::/64"], at(10))];
    let (links, findings) = evaluate(&image, &entries);
    assert!(findings.is_empty(), "{findings:?}");
    assert!(links[0].managed && !links[0].other);
    assert_eq!(links[0].scopes, vec![net("2001:db8:1::/64")]);
}

#[test]
fn m_and_o_together_with_a_scope_are_no_finding() {
    let image = image(vec![scope_of("2001:db8:1::/64")]);
    let entries = [heard(2, 1, true, true, &["2001:db8:1::/64"], at(10))];
    let (_, findings) = evaluate(&image, &entries);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn o_without_m_while_a_scope_has_pools_is_found() {
    let image = image(vec![scope_of("2001:db8:1::/64")]);
    let entries = [heard(3, 7, false, true, &["2001:db8:1::/64"], at(10))];
    let (links, findings) = evaluate(&image, &entries);

    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.code, OTHER_ONLY);
    assert_eq!(finding.interface, "eth3");
    assert_eq!(param(finding, "interface"), "eth3");
    assert_eq!(param(finding, "routers"), "fe80::200:5eff:fe00:5307");
    assert_eq!(param(finding, "scopes"), "2001:db8:1::/64");
    assert_eq!(finding.params.len(), 3);
    assert!(finding.detail.contains("O flag"));
    assert!(links[0].other && !links[0].managed);
}

#[test]
fn o_without_m_while_no_scope_has_pools_is_no_finding() {
    // Stateless DHCPv6 is what such a scope serves: other configuration, no addresses.
    let image = image(vec![scope_without_pools("2001:db8:1::/64")]);
    let entries = [heard(3, 7, false, true, &["2001:db8:1::/64"], at(10))];
    let (links, findings) = evaluate(&image, &entries);
    assert!(findings.is_empty(), "{findings:?}");
    assert_eq!(links[0].scopes, vec![net("2001:db8:1::/64")]);
}

#[test]
fn o_without_m_is_found_when_any_one_of_the_link_scopes_has_pools() {
    let image = image(vec![
        scope_without_pools("2001:db8:1::/64"),
        scope_of("2001:db8:2::/64"),
    ]);
    let entries = [heard(
        3,
        7,
        false,
        true,
        &["2001:db8:1::/64", "2001:db8:2::/64"],
        at(10),
    )];
    let (_, findings) = evaluate(&image, &entries);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, OTHER_ONLY);
    assert_eq!(
        param(&findings[0], "scopes"),
        "2001:db8:1::/64, 2001:db8:2::/64"
    );
}

#[test]
fn m_on_a_link_without_a_scope_is_found_with_the_advertised_prefixes() {
    let image = image(vec![scope_of("2001:db8:1::/64")]);
    let entries = [heard(
        4,
        9,
        true,
        false,
        &["2001:db8:9::/64", "2001:db8:a::/64"],
        at(10),
    )];
    let (links, findings) = evaluate(&image, &entries);

    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.code, MANAGED_WITHOUT_SCOPE);
    assert_eq!(finding.interface, "eth4");
    assert_eq!(param(finding, "interface"), "eth4");
    assert_eq!(param(finding, "routers"), "fe80::200:5eff:fe00:5309");
    assert_eq!(
        param(finding, "prefixes"),
        "2001:db8:9::/64, 2001:db8:a::/64"
    );
    assert_eq!(finding.params.len(), 3);
    assert!(!finding.params.contains_key("scopes"));
    assert_eq!(links[0].scopes.len(), 0);
}

#[test]
fn m_on_a_link_without_a_scope_and_without_prefixes_names_the_nodes_networks() {
    let image = image(vec![scope_of("2001:db8:1::/64")]);
    // The node's own address is given with its host part; the finding shows the network.
    let entries = [with_networks(
        heard(4, 9, true, false, &[], at(10)),
        &["2001:db8:9::5/64"],
    )];
    let (_, findings) = evaluate(&image, &entries);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, MANAGED_WITHOUT_SCOPE);
    assert_eq!(param(&findings[0], "prefixes"), "2001:db8:9::/64");
}

#[test]
fn m_without_a_scope_and_without_any_network_is_still_found() {
    let image = image(Vec::new());
    let entries = [heard(4, 9, true, true, &[], at(10))];
    let (_, findings) = evaluate(&image, &entries);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, MANAGED_WITHOUT_SCOPE);
    assert_eq!(param(&findings[0], "prefixes"), "");
}

#[test]
fn o_only_without_a_scope_is_no_finding() {
    let image = image(vec![scope_of("2001:db8:1::/64")]);
    let entries = [heard(4, 9, false, true, &["2001:db8:9::/64"], at(10))];
    let (_, findings) = evaluate(&image, &entries);
    assert!(findings.is_empty(), "{findings:?}");
}

// ---------------------------------------------------------------------------------------
// evaluate: which scopes belong to a link
// ---------------------------------------------------------------------------------------

#[test]
fn the_nodes_own_network_maps_a_link_to_a_scope() {
    // The router advertises no prefix (a link that uses a manually configured prefix), but
    // the node has 2001:db8:1::10/64 on the link, which is the scope's network.
    let image = image(vec![scope_of("2001:db8:1::/64")]);
    let entries = [with_networks(
        heard(2, 1, false, false, &[], at(10)),
        &["2001:db8:1::10/64"],
    )];
    let (links, findings) = evaluate(&image, &entries);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, FLAGS_OFF);
    assert_eq!(param(&findings[0], "scopes"), "2001:db8:1::/64");
    assert_eq!(links[0].prefixes.len(), 0);
    assert_eq!(links[0].scopes, vec![net("2001:db8:1::/64")]);
}

#[test]
fn the_nodes_own_network_prevents_a_managed_without_scope_finding() {
    let image = image(vec![scope_of("2001:db8:1::/64")]);
    let entries = [with_networks(
        heard(2, 1, true, false, &["2001:db8:9::/64"], at(10)),
        &["2001:db8:1::10/64"],
    )];
    let (links, findings) = evaluate(&image, &entries);
    assert!(findings.is_empty(), "{findings:?}");
    assert_eq!(links[0].scopes, vec![net("2001:db8:1::/64")]);
}

#[test]
fn a_scope_that_contains_or_is_contained_by_a_prefix_belongs_to_the_link() {
    let image = image(vec![
        scope_of("2001:db8:1::/64"),
        scope_of("2001:db8:2::/64"),
    ]);
    // A /56 around the first scope, a /80 inside the second.
    let entries = [heard(
        2,
        1,
        false,
        false,
        &["2001:db8:1::/56", "2001:db8:2::/80"],
        at(10),
    )];
    let (links, findings) = evaluate(&image, &entries);
    assert_eq!(findings.len(), 1);
    assert_eq!(
        param(&findings[0], "scopes"),
        "2001:db8:1::/64, 2001:db8:2::/64"
    );
    assert_eq!(
        links[0].scopes,
        vec![net("2001:db8:1::/64"), net("2001:db8:2::/64")]
    );
}

#[test]
fn a_neighbouring_network_is_not_an_overlap() {
    let image = image(vec![scope_of("2001:db8:1::/64")]);
    for prefix in ["2001:db8:2::/64", "2001:db8:0:1::/64", "2001:db9:1::/64"] {
        let entries = [heard(2, 1, false, false, &[prefix], at(10))];
        let (links, findings) = evaluate(&image, &entries);
        assert!(findings.is_empty(), "{prefix}: {findings:?}");
        assert!(links[0].scopes.is_empty(), "{prefix}");
    }
}

#[test]
fn an_empty_image_gives_links_without_scopes_and_only_the_m_finding() {
    let image = image(Vec::new());
    let entries = [
        heard(2, 1, false, false, &["2001:db8:1::/64"], at(10)),
        heard(3, 2, false, true, &["2001:db8:2::/64"], at(10)),
        heard(4, 3, true, false, &["2001:db8:3::/64"], at(10)),
    ];
    let (links, findings) = evaluate(&image, &entries);
    assert_eq!(links.len(), 3);
    assert!(links.iter().all(|link| link.scopes.is_empty()));
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, MANAGED_WITHOUT_SCOPE);
    assert_eq!(findings[0].interface, "eth4");
}

// ---------------------------------------------------------------------------------------
// evaluate: several routers and several links
// ---------------------------------------------------------------------------------------

#[test]
fn the_flags_of_a_link_are_the_or_over_its_routers() {
    let image = image(vec![scope_of("2001:db8:1::/64")]);
    // Two routers on one link: one sets M, the other neither.
    let entries = [
        heard(2, 1, false, false, &["2001:db8:1::/64"], at(10)),
        heard(2, 2, true, false, &["2001:db8:1::/64"], at(20)),
    ];
    let (links, findings) = evaluate(&image, &entries);
    assert!(findings.is_empty(), "{findings:?}");
    assert_eq!(links.len(), 1);
    assert!(links[0].managed && !links[0].other);
    assert_eq!(links[0].routers, vec![router(1), router(2)]);
    // The prefix both advertise is listed once, and the last advertisement is the link's.
    assert_eq!(links[0].prefixes, vec![net("2001:db8:1::/64")]);
    assert_eq!(links[0].seen, at(20));

    // M from one router and O from the other make a link with both.
    let entries = [
        heard(2, 1, true, false, &["2001:db8:1::/64"], at(10)),
        heard(2, 2, false, true, &["2001:db8:1::/64"], at(20)),
    ];
    let (links, findings) = evaluate(&image, &entries);
    assert_eq!(findings.len(), 0);
    assert!(links[0].managed && links[0].other);
}

#[test]
fn two_routers_that_both_set_nothing_are_named_together_in_order() {
    let image = image(vec![scope_of("2001:db8:1::/64")]);
    // Given in the opposite order of their addresses.
    let entries = [
        heard(2, 0x0b, false, false, &["2001:db8:1::/64"], at(10)),
        heard(2, 0x0a, false, false, &["2001:db8:1::/64"], at(10)),
    ];
    let (links, findings) = evaluate(&image, &entries);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, FLAGS_OFF);
    assert_eq!(
        param(&findings[0], "routers"),
        "fe80::200:5eff:fe00:530a, fe80::200:5eff:fe00:530b"
    );
    assert_eq!(links[0].routers, vec![router(0x0a), router(0x0b)]);
}

#[test]
fn the_prefixes_of_all_routers_of_a_link_decide_its_scopes() {
    let image = image(vec![
        scope_of("2001:db8:1::/64"),
        scope_of("2001:db8:2::/64"),
    ]);
    let entries = [
        heard(2, 1, false, false, &["2001:db8:1::/64"], at(10)),
        heard(2, 2, false, false, &["2001:db8:2::/64"], at(10)),
    ];
    let (links, findings) = evaluate(&image, &entries);
    assert_eq!(findings.len(), 1);
    assert_eq!(
        param(&findings[0], "scopes"),
        "2001:db8:1::/64, 2001:db8:2::/64"
    );
    assert_eq!(
        links[0].prefixes,
        vec![net("2001:db8:1::/64"), net("2001:db8:2::/64")]
    );
}

#[test]
fn links_are_judged_one_by_one_and_listed_by_interface_index() {
    let image = image(vec![
        scope_of("2001:db8:1::/64"),
        scope_of("2001:db8:2::/64"),
        scope_of("2001:db8:3::/64"),
    ]);
    let entries = [
        // Index 9: M and a scope.
        heard(9, 3, true, false, &["2001:db8:3::/64"], at(30)),
        // Index 2: neither flag and a scope.
        heard(2, 1, false, false, &["2001:db8:1::/64"], at(10)),
        // Index 5: O only and a scope with pools.
        heard(5, 2, false, true, &["2001:db8:2::/64"], at(20)),
        // Index 7: neither flag and no scope.
        heard(7, 4, false, false, &["2001:db8:7::/64"], at(40)),
    ];
    let (links, findings) = evaluate(&image, &entries);
    let order: Vec<&str> = links.iter().map(|link| link.interface.as_str()).collect();
    assert_eq!(order, ["eth2", "eth5", "eth7", "eth9"]);
    let found: Vec<(&str, &str)> = findings
        .iter()
        .map(|finding| (finding.code, finding.interface.as_str()))
        .collect();
    assert_eq!(found, [(FLAGS_OFF, "eth2"), (OTHER_ONLY, "eth5")]);
}

#[test]
fn the_result_does_not_depend_on_the_order_of_what_was_heard() {
    let image = image(vec![
        scope_of("2001:db8:1::/64"),
        scope_of("2001:db8:2::/64"),
    ]);
    let entries = vec![
        heard(2, 1, false, false, &["2001:db8:1::/64"], at(10)),
        heard(2, 2, false, false, &["2001:db8:1::/64"], at(15)),
        heard(3, 3, false, true, &["2001:db8:2::/64"], at(20)),
        heard(4, 4, true, false, &["2001:db8:4::/64"], at(30)),
    ];
    let (links, findings) = evaluate(&image, &entries);
    let reversed: Vec<_> = entries.iter().rev().cloned().collect();
    let (links_back, findings_back) = evaluate(&image, &reversed);
    assert_eq!(links, links_back);
    assert_eq!(findings, findings_back);
    assert_eq!(findings.len(), 3);
}

#[test]
fn nothing_heard_gives_nothing() {
    let image = image(vec![scope_of("2001:db8:1::/64")]);
    let (links, findings) = evaluate(&image, &[]);
    assert_eq!(links.len() + findings.len(), 0);
}

// ---------------------------------------------------------------------------------------
// RaWatch
// ---------------------------------------------------------------------------------------

#[test]
fn a_new_watch_is_off_and_empty() {
    let watch = RaWatch::new();
    assert_eq!(watch.check(), RaCheck::Off);
    assert_eq!(RaCheck::default(), RaCheck::Off);
    assert_eq!(watch.heard(at(0)).len(), 0);
    let report = watch.report(None, at(0));
    assert_eq!(report.check, RaCheck::Off);
    assert_eq!(report.links.len() + report.findings.len(), 0);
}

#[test]
fn the_check_has_a_word_for_each_state() {
    assert_eq!(RaCheck::Off.as_str(), "off");
    assert_eq!(
        RaCheck::Unavailable("why".to_owned()).as_str(),
        "unavailable"
    );
    assert_eq!(RaCheck::Watching.as_str(), "watching");
    let watch = RaWatch::new();
    watch.set_check(RaCheck::Watching);
    assert_eq!(watch.check(), RaCheck::Watching);
    watch.set_check(RaCheck::Unavailable("no socket".to_owned()));
    assert_eq!(watch.check(), RaCheck::Unavailable("no socket".to_owned()));
}

#[test]
fn a_later_advertisement_of_a_router_replaces_its_earlier_one() {
    let watch = RaWatch::new();
    watch.record(heard(2, 1, false, false, &["2001:db8:1::/64"], at(10)));
    watch.record(heard(2, 1, true, false, &["2001:db8:1::/64"], at(20)));
    let held = watch.heard(at(30));
    assert_eq!(held.len(), 1);
    assert!(held[0].managed);
    assert_eq!(held[0].at, at(20));
    // The same router on another link is another entry.
    watch.record(heard(3, 1, false, false, &[], at(25)));
    assert_eq!(watch.heard(at(30)).len(), 2);
}

#[test]
fn a_reading_is_forgotten_when_it_is_as_old_as_the_stale_time() {
    let watch = RaWatch::new();
    watch.record(heard(2, 1, false, false, &["2001:db8:1::/64"], at(0)));
    let just_before = at(0)
        .checked_add(
            STALE
                .checked_sub(Duration::from_secs(1))
                .expect("a second less"),
        )
        .expect("time");
    assert_eq!(watch.heard(just_before).len(), 1);
    let at_stale = at(0).checked_add(STALE).expect("time");
    assert_eq!(watch.heard(at_stale).len(), 0);
    // It is gone for good, not only hidden from the one call.
    assert_eq!(watch.heard(at(1)).len(), 0);
}

#[test]
fn a_fresh_advertisement_keeps_a_router_and_a_stale_one_goes_alone() {
    let watch = RaWatch::new();
    watch.record(heard(2, 1, false, false, &[], at(0)));
    watch.record(heard(2, 2, false, false, &[], at(0)));
    // Router 1 is heard again 40 minutes later.
    watch.record(heard(2, 1, false, false, &[], at(2_400)));
    // At 70 minutes router 2 is 70 minutes old and router 1 is 30.
    let held = watch.heard(at(4_200));
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].router, router(1));
}

#[test]
fn a_stale_reading_gives_no_finding_and_no_link() {
    let image = image(vec![scope_of("2001:db8:1::/64")]);
    let watch = RaWatch::new();
    watch.set_check(RaCheck::Watching);
    watch.record(heard(2, 1, false, false, &["2001:db8:1::/64"], at(0)));

    let fresh = watch.report(Some(&image), at(60));
    assert_eq!(fresh.check, RaCheck::Watching);
    assert_eq!(fresh.links.len(), 1);
    assert_eq!(fresh.findings.len(), 1);
    assert_eq!(fresh.findings[0].code, FLAGS_OFF);

    let stale = watch.report(Some(&image), at(0).checked_add(STALE).expect("time"));
    assert_eq!(stale.links.len(), 0);
    assert_eq!(stale.findings.len(), 0);
}

#[test]
fn the_per_link_limit_forgets_the_oldest_router_of_that_link() {
    let watch = RaWatch::new();
    // The limit's worth of routers on link 2, the first heard first; one router on link 3.
    for last in 0..MAX_ROUTERS {
        let last = u8::try_from(last).expect("a small number");
        watch.record(heard(2, last, false, false, &[], at(u64::from(last) + 10)));
    }
    watch.record(heard(3, 0, false, false, &[], at(5)));
    assert_eq!(watch.heard(at(100)).len(), MAX_ROUTERS + 1);

    // A router heard again is not new: nothing is evicted.
    watch.record(heard(2, 3, true, false, &[], at(50)));
    assert_eq!(watch.heard(at(100)).len(), MAX_ROUTERS + 1);

    // One more router on link 2 pushes out router 0, the oldest of that link, and leaves
    // link 3's router (older still) alone.
    let extra = u8::try_from(MAX_ROUTERS).expect("a small number");
    watch.record(heard(2, extra, false, false, &[], at(60)));
    let held = watch.heard(at(100));
    assert_eq!(held.len(), MAX_ROUTERS + 1);
    let on_link2: Vec<Ipv6Addr> = held
        .iter()
        .filter(|entry| entry.interface == 2)
        .map(|entry| entry.router)
        .collect();
    assert_eq!(on_link2.len(), MAX_ROUTERS);
    assert!(!on_link2.contains(&router(0)));
    assert!(on_link2.contains(&router(extra)));
    assert!(on_link2.contains(&router(1)));
    assert!(held.iter().any(|entry| entry.interface == 3));
}

#[test]
fn the_oldest_is_the_one_heard_longest_ago_not_the_first_recorded() {
    let watch = RaWatch::new();
    for last in 0..MAX_ROUTERS {
        let last = u8::try_from(last).expect("a small number");
        watch.record(heard(2, last, false, false, &[], at(u64::from(last) + 10)));
    }
    // Router 0 speaks again, so router 1 is now the oldest.
    watch.record(heard(2, 0, false, false, &[], at(500)));
    let extra = u8::try_from(MAX_ROUTERS).expect("a small number");
    watch.record(heard(2, extra, false, false, &[], at(600)));
    let routers: Vec<Ipv6Addr> = watch.heard(at(700)).iter().map(|e| e.router).collect();
    assert!(routers.contains(&router(0)));
    assert!(!routers.contains(&router(1)));
}

#[test]
fn the_overall_limit_forgets_the_oldest_router_of_all_links() {
    let watch = RaWatch::new();
    // MAX_HEARD routers on links of the limit per link each, the first heard first.
    let per_link = u32::try_from(MAX_ROUTERS).expect("small");
    let links = u32::try_from(MAX_HEARD / MAX_ROUTERS).expect("small");
    let mut count = 0u64;
    for link in 0..links {
        for last in 0..per_link {
            let when = at(count);
            count += 1;
            let mut entry = heard(link + 1, 0, false, false, &[], when);
            entry.router = ip(&format!("fe80::{:x}:{:x}", link + 1, last + 1));
            watch.record(entry);
        }
    }
    assert_eq!(count, u64::try_from(MAX_HEARD).expect("small"));
    let now = at(count + 10);
    assert_eq!(watch.heard(now).len(), MAX_HEARD);

    // A router on a new link: the oldest of all (link 1, the first) makes room.
    let mut entry = heard(links + 1, 0, false, false, &[], at(count));
    entry.router = ip("fe80::ffff:1");
    watch.record(entry);
    let held = watch.heard(now);
    assert_eq!(held.len(), MAX_HEARD);
    assert!(held.iter().any(|entry| entry.router == ip("fe80::ffff:1")));
    assert!(!held.iter().any(|entry| entry.router == ip("fe80::1:1")));
    assert!(held.iter().any(|entry| entry.router == ip("fe80::1:2")));

    // A router heard again at the limit is not new and evicts nothing.
    let mut again = heard(2, 0, true, false, &[], at(count + 1));
    again.router = ip("fe80::2:1");
    watch.record(again);
    assert_eq!(watch.heard(now).len(), MAX_HEARD);
}

#[test]
fn a_host_sending_from_many_addresses_cannot_grow_the_watch() {
    let watch = RaWatch::new();
    for n in 0..5_000u64 {
        let mut entry = heard(2, 0, false, false, &[], at(n % 3_000));
        entry.router = ip(&format!("fe80::{:x}", n + 1));
        watch.record(entry);
    }
    assert!(watch.heard(at(3_000)).len() <= MAX_ROUTERS);
}

// ---------------------------------------------------------------------------------------
// RaWatch::report
// ---------------------------------------------------------------------------------------

#[test]
fn without_an_image_there_are_no_links_and_no_findings() {
    let watch = RaWatch::new();
    watch.set_check(RaCheck::Watching);
    watch.record(heard(2, 1, true, false, &["2001:db8:9::/64"], at(10)));
    let report = watch.report(None, at(20));
    assert_eq!(report.check, RaCheck::Watching);
    assert_eq!(report.links.len(), 0);
    assert_eq!(report.findings.len(), 0);

    // Not even an unavailable check says anything without an image: there is no scope.
    watch.set_check(RaCheck::Unavailable("no socket".to_owned()));
    let report = watch.report(None, at(20));
    assert_eq!(report.findings.len(), 0);
}

#[test]
fn an_unavailable_check_with_scopes_is_the_unchecked_finding() {
    let image = image(vec![scope_of("2001:db8:1::/64")]);
    let watch = RaWatch::new();
    watch.set_check(RaCheck::Unavailable(
        "a raw socket needs CAP_NET_RAW".to_owned(),
    ));
    let report = watch.report(Some(&image), at(20));
    assert_eq!(
        report.check,
        RaCheck::Unavailable("a raw socket needs CAP_NET_RAW".to_owned())
    );
    assert_eq!(report.links.len(), 0);
    assert_eq!(report.findings.len(), 1);
    let finding = &report.findings[0];
    assert_eq!(finding.code, UNCHECKED);
    assert_eq!(finding.interface, "");
    assert_eq!(param(finding, "reason"), "a raw socket needs CAP_NET_RAW");
    assert_eq!(finding.params.len(), 1);
    assert!(finding.detail.contains("a raw socket needs CAP_NET_RAW"));
}

#[test]
fn an_unavailable_check_without_scopes_says_nothing() {
    let watch = RaWatch::new();
    watch.set_check(RaCheck::Unavailable("no socket".to_owned()));
    let report = watch.report(Some(&Image6::default()), at(20));
    assert_eq!(report.findings.len(), 0);
    assert_eq!(report.check.as_str(), "unavailable");
}

#[test]
fn a_check_that_is_off_or_watching_is_never_unchecked() {
    let image = image(vec![scope_of("2001:db8:1::/64")]);
    let watch = RaWatch::new();
    assert_eq!(watch.report(Some(&image), at(20)).findings.len(), 0);
    watch.set_check(RaCheck::Watching);
    let report = watch.report(Some(&image), at(20));
    assert_eq!(report.findings.len(), 0);
    assert_eq!(report.links.len(), 0);
}

#[test]
fn the_report_carries_the_findings_of_what_was_heard_and_the_unchecked_one_last() {
    let image = image(vec![scope_of("2001:db8:1::/64")]);
    let watch = RaWatch::new();
    watch.set_check(RaCheck::Unavailable("lost".to_owned()));
    watch.record(heard(2, 1, false, false, &["2001:db8:1::/64"], at(10)));
    let report = watch.report(Some(&image), at(20));
    let codes: Vec<&str> = report.findings.iter().map(|finding| finding.code).collect();
    assert_eq!(codes, [FLAGS_OFF, UNCHECKED]);
    assert_eq!(report.links.len(), 1);
}
