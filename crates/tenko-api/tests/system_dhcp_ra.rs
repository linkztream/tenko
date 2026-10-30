//! The health rows of the router advertisement check of DHCP-10 (WP9.2) in the system
//! status: `dhcp_role_warnings` turns the findings of the dhcp role's report into warnings
//! that carry the node and the finding's own parameters, and the diagnostics give the rows
//! their severity (the two informational ones, the others warnings).

use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::time::Duration;

use ipnet::Ipv6Net;
use tenko_api::{
    dto::system::{FindingSeverity, StatusWarning},
    routes::system::{DHCP_ROLE_NOT_SERVING, dhcp_role_warnings, diagnostics::severity_of},
};
use tenko_core::{NodeId, Revision, Timestamp, dhcp::BindingState};
use tenko_dhcp::{
    ra::{
        FLAGS_OFF, MANAGED_WITHOUT_SCOPE, OTHER_ONLY, RaCheck, RaFinding, RaHeard, RaReport,
        RaWatch, UNCHECKED,
    },
    role::DhcpStatus,
    v6::image::Image6,
};

/// The status of a serving dhcp role on node 7 with nothing else to report, `ra` as given.
fn status(ra: RaReport) -> DhcpStatus {
    let none = [
        (BindingState::Free, 0),
        (BindingState::Active, 0),
        (BindingState::Expired, 0),
        (BindingState::Released, 0),
        (BindingState::Abandoned, 0),
        (BindingState::Reset, 0),
        (BindingState::Backup, 0),
    ];
    DhcpStatus {
        node: NodeId(7),
        serving: true,
        accepting: true,
        refusal: None,
        derived: None,
        probe: true,
        probe_expected: false,
        listeners: Vec::new(),
        scopes: 0,
        leases: none,
        last_commit: None,
        revision: Revision::ZERO,
        lag: 0,
        started: Timestamp::UNIX_EPOCH,
        installs: 0,
        proxies: Vec::new(),
        listeners6: Vec::new(),
        scopes6: 0,
        leases6: none,
        ra,
        server_duid: None,
    }
}

fn finding(
    code: &'static str,
    interface: &str,
    detail: &str,
    params: &[(&str, &str)],
) -> RaFinding {
    RaFinding {
        code,
        interface: interface.to_owned(),
        detail: detail.to_owned(),
        params: params
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect(),
    }
}

fn report(findings: Vec<RaFinding>) -> RaReport {
    RaReport {
        check: RaCheck::Watching,
        links: Vec::new(),
        findings,
    }
}

fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

#[test]
fn a_serving_role_without_findings_has_no_warnings() {
    assert_eq!(dhcp_role_warnings(&status(RaReport::default())).len(), 0);
    assert_eq!(dhcp_role_warnings(&status(report(Vec::new()))).len(), 0);
}

#[test]
fn a_finding_becomes_a_warning_with_the_node_and_its_own_parameters() {
    let flags_off = finding(
        FLAGS_OFF,
        "eth2",
        "the router advertisements on eth2 set neither M nor O",
        &[
            ("interface", "eth2"),
            ("routers", "fe80::200:5eff:fe00:5301"),
            ("scopes", "2001:db8:1::/64"),
        ],
    );
    let warnings = dhcp_role_warnings(&status(report(vec![flags_off.clone()])));
    assert_eq!(
        warnings,
        vec![StatusWarning {
            code: "dhcp.ra.flags_off".to_owned(),
            detail: flags_off.detail.clone(),
            params: params(&[
                ("node", "7"),
                ("interface", "eth2"),
                ("routers", "fe80::200:5eff:fe00:5301"),
                ("scopes", "2001:db8:1::/64"),
            ]),
        }]
    );
}

#[test]
fn every_finding_is_a_warning_in_the_order_of_the_report() {
    let findings = vec![
        finding(
            FLAGS_OFF,
            "eth2",
            "flags off",
            &[("interface", "eth2"), ("scopes", "2001:db8:1::/64")],
        ),
        finding(
            OTHER_ONLY,
            "eth3",
            "other only",
            &[("interface", "eth3"), ("scopes", "2001:db8:2::/64")],
        ),
        finding(
            MANAGED_WITHOUT_SCOPE,
            "eth4",
            "managed without a scope",
            &[("interface", "eth4"), ("prefixes", "2001:db8:9::/64")],
        ),
        finding(UNCHECKED, "", "not checked", &[("reason", "no socket")]),
    ];
    let warnings = dhcp_role_warnings(&status(report(findings.clone())));
    assert_eq!(warnings.len(), 4);
    for (warning, finding) in warnings.iter().zip(&findings) {
        assert_eq!(warning.code, finding.code);
        assert_eq!(warning.detail, finding.detail);
        // The node first, then what the finding says; nothing else is added.
        let mut expected = finding.params.clone();
        expected.insert("node".to_owned(), "7".to_owned());
        assert_eq!(warning.params, expected, "{}", finding.code);
    }
    assert_eq!(
        warnings[3].params,
        params(&[("node", "7"), ("reason", "no socket")])
    );
}

#[test]
fn the_check_state_alone_raises_no_warning() {
    for check in [
        RaCheck::Off,
        RaCheck::Watching,
        RaCheck::Unavailable("no socket".to_owned()),
    ] {
        let ra = RaReport {
            check,
            links: Vec::new(),
            findings: Vec::new(),
        };
        assert_eq!(dhcp_role_warnings(&status(ra)).len(), 0);
    }
}

#[test]
fn the_router_advertisement_warnings_follow_the_role_warnings() {
    let mut role = status(report(vec![finding(
        FLAGS_OFF,
        "eth2",
        "flags off",
        &[("interface", "eth2")],
    )]));
    role.serving = false;
    role.probe_expected = true;
    role.probe = false;
    let codes: Vec<String> = dhcp_role_warnings(&role)
        .into_iter()
        .map(|warning| warning.code)
        .collect();
    assert_eq!(
        codes,
        [
            DHCP_ROLE_NOT_SERVING,
            "dhcp.probe.missing",
            "dhcp.ra.flags_off"
        ]
    );
}

#[test]
fn a_finding_of_the_real_check_reaches_the_status_as_a_warning() {
    // A router on eth4 sets M and the node serves no DHCPv6 scope: the check says so, and the
    // status carries it with the node.
    let watch = RaWatch::new();
    watch.set_check(RaCheck::Watching);
    let now = Timestamp::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_000_000))
        .expect("a timestamp");
    watch.record(RaHeard {
        interface: 4,
        name: "eth4".to_owned(),
        router: "fe80::200:5eff:fe00:5309"
            .parse::<Ipv6Addr>()
            .expect("address"),
        managed: true,
        other: false,
        router_lifetime: 1800,
        prefixes: vec!["2001:db8:9::/64".parse::<Ipv6Net>().expect("network")],
        networks: Vec::new(),
        at: now,
    });
    let ra = watch.report(Some(&Image6::default()), now);
    assert_eq!(ra.findings.len(), 1);

    let warnings = dhcp_role_warnings(&status(ra));
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].code, MANAGED_WITHOUT_SCOPE);
    assert_eq!(warnings[0].params["node"], "7");
    assert_eq!(warnings[0].params["interface"], "eth4");
    assert_eq!(warnings[0].params["routers"], "fe80::200:5eff:fe00:5309");
    assert_eq!(warnings[0].params["prefixes"], "2001:db8:9::/64");
    assert!(warnings[0].detail.contains("eth4"));
}

#[test]
fn the_diagnostics_give_the_rows_their_severity() {
    // Stateless DHCPv6 may be meant, and a check that cannot run is no fault of the network.
    assert_eq!(severity_of("dhcp.ra.other_only"), FindingSeverity::Info);
    assert_eq!(severity_of("dhcp.ra.unchecked"), FindingSeverity::Info);
    assert_eq!(severity_of("dhcp.ra.flags_off"), FindingSeverity::Warning);
    assert_eq!(
        severity_of("dhcp.ra.managed_without_scope"),
        FindingSeverity::Warning
    );
    // The constants the check exports are those codes.
    assert_eq!(severity_of(OTHER_ONLY), FindingSeverity::Info);
    assert_eq!(severity_of(UNCHECKED), FindingSeverity::Info);
    assert_eq!(severity_of(FLAGS_OFF), FindingSeverity::Warning);
    assert_eq!(severity_of(MANAGED_WITHOUT_SCOPE), FindingSeverity::Warning);
    // The role's own failures stay errors.
    assert_eq!(severity_of(DHCP_ROLE_NOT_SERVING), FindingSeverity::Error);
}
