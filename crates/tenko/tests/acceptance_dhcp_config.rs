//! Acceptance of the DHCP configuration (WP7.4) through the real binary: one node with the
//! DHCP module on (the default set of modules), its IPAM network and pool made through the
//! API, and the DHCP configuration made, read and removed with `tenko dhcp ...` in
//! separate processes.
//!
//! - A scope for the network, an exclusion, a pool's lease times, options at the server
//!   and scope levels from `CODE=HEXDATA`, a custom definition, a class and a MAC filter
//!   are created with the command line and read back with it, as tables and as JSON.
//! - The effective options of a client show each option with the level that set it.
//! - IPAM refuses to delete the prefix while the scope exists; after `scope delete` it
//!   goes.
//! - The errors of the API come back as the exit status of a server problem with the code.

mod serve_support;

use serde_json::{Value, json};
use serve_support::{Node, api::Api, wait_for_setup_token};

#[test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
fn the_dhcp_configuration_round_trips_through_the_command_line() {
    let mut node = Node::new();
    let mut server = node.start();
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);
    node.login().assert_code(0);

    // The network and its pool, through IPAM.
    let prefix = api
        .post("/prefixes", &json!({ "cidr": "192.0.2.0/24" }))
        .expect(201)["item"]["id"]
        .as_str()
        .expect("a prefix id")
        .to_owned();
    let pool = api
        .post(
            &format!("/prefixes/{prefix}/ranges"),
            &json!({ "first": "192.0.2.100", "last": "192.0.2.199", "role": "dhcp_pool" }),
        )
        .expect(201)["item"]["id"]
        .as_str()
        .expect("a range id")
        .to_owned();

    // The scope.
    let created = node.client(&[
        "dhcp",
        "scope",
        "create",
        &prefix,
        "--lease-default",
        "3600",
        "--lease-min",
        "600",
        "--lease-max",
        "7200",
        "--description",
        "office",
        "--json",
    ]);
    created.assert_code(0);
    assert_eq!(created.json()["cidr"], "192.0.2.0/24");
    assert_eq!(created.json()["lease"]["default_secs"], 3600);
    node.client(&["dhcp", "scope", "list"])
        .assert_code(0)
        .assert_stdout_contains("NETWORK")
        .assert_stdout_contains("192.0.2.0/24");
    node.client(&["dhcp", "scope", "create", &prefix])
        .assert_code(5)
        .assert_stderr_contains("dhcp.scope.exists");
    node.client(&["dhcp", "scope", "set", &prefix, "--restricted"])
        .assert_code(0);
    assert_eq!(
        node.client(&["dhcp", "scope", "show", &prefix, "--json"])
            .json()["restricted"],
        true
    );

    // An exclusion and the pool's lease times.
    let exclusion = node.client(&[
        "dhcp",
        "exclusion",
        "add",
        &prefix,
        "192.0.2.190",
        "192.0.2.199",
        "--json",
    ]);
    exclusion.assert_code(0);
    let exclusion_id = exclusion.json()["id"].as_str().expect("an id").to_owned();
    node.client(&["dhcp", "exclusion", "list", &prefix])
        .assert_code(0)
        .assert_stdout_contains("192.0.2.190");
    node.client(&[
        "dhcp",
        "pool",
        "set",
        &pool,
        "--lease-default",
        "1800",
        "--lease-min",
        "900",
        "--lease-max",
        "3600",
    ])
    .assert_code(0);
    let pools = node.client(&["dhcp", "pool", "list", "--json"]);
    pools.assert_code(0);
    let items = pools.json()["items"].as_array().expect("items").clone();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["size"], 90);
    assert_eq!(items[0]["settings"]["lease"]["default_secs"], 1800);
    let figures = node.client(&["dhcp", "scope", "utilization", &prefix, "--json"]);
    figures.assert_code(0);
    assert_eq!(figures.json()["pool_size"], 90);

    // Options at two levels and a custom definition.
    node.client(&[
        "dhcp",
        "option",
        "set",
        "server",
        "6=c0000235",
        "42=c000027b",
    ])
    .assert_code(0);
    node.client(&[
        "dhcp",
        "option",
        "set",
        &format!("scope:{prefix}"),
        "3=c0000201",
        "6=c0000236c0000237",
    ])
    .assert_code(0);
    node.client(&["dhcp", "option", "set", "server", "51=00000e10"])
        .assert_code(5)
        .assert_stderr_contains("dhcp.option.code_reserved");
    node.client(&[
        "dhcp",
        "option",
        "define",
        "--code",
        "224",
        "--name",
        "site-flag",
        "--kind",
        "u16",
    ])
    .assert_code(0);
    node.client(&["dhcp", "option", "defs"])
        .assert_code(0)
        .assert_stdout_contains("site-flag");
    node.client(&["dhcp", "option", "catalog"])
        .assert_code(0)
        .assert_stdout_contains("domain-name-servers");
    let shown = node.client(&[
        "dhcp",
        "option",
        "show",
        &format!("scope:{prefix}"),
        "--json",
    ]);
    shown.assert_code(0);
    assert_eq!(
        shown.json()["values"][1]["typed"],
        json!({ "ipv4": { "values": ["192.0.2.54", "192.0.2.55"] } })
    );
    let effective = node.client(&[
        "dhcp",
        "scope",
        "options",
        &prefix,
        "--mac",
        "00:00:5e:00:53:01",
        "--json",
    ]);
    effective.assert_code(0);
    let levels: Vec<(u64, String)> = effective.json()["options"]
        .as_array()
        .expect("options")
        .iter()
        .map(|option: &Value| {
            (
                option["value"]["code"].as_u64().expect("code"),
                option["level"].as_str().expect("level").to_owned(),
            )
        })
        .collect();
    assert_eq!(
        levels,
        [
            (6, "scope".to_owned()),
            (42, "server".to_owned()),
            (3, "scope".to_owned())
        ]
    );

    // A class and a filter.
    node.client(&[
        "dhcp",
        "class",
        "create",
        "pxe",
        "--match",
        r#"{"vendor_class": {"value": "PXEClient", "prefix": true}}"#,
    ])
    .assert_code(0);
    node.client(&["dhcp", "class", "list"])
        .assert_code(0)
        .assert_stdout_contains("pxe");
    node.client(&["dhcp", "filter", "add", "00:00:5e:00:53:*", "--deny"])
        .assert_code(0);
    node.client(&["dhcp", "filter", "add", "00:00:5e:00:53:*", "--allow"])
        .assert_code(5)
        .assert_stderr_contains("dhcp.filter.exists");
    node.client(&["dhcp", "filter", "list"])
        .assert_code(0)
        .assert_stdout_contains("00:00:5e:00:53:*");

    // The settings.
    node.client(&["dhcp", "settings", "set", "--history-days", "14"])
        .assert_code(0);
    let settings = node.client(&["dhcp", "settings", "show", "--json"]);
    settings.assert_code(0);
    assert_eq!(settings.json()["effective_history_days"], 14);

    // The prefix stays while the scope exists, and goes after it.
    let refused = api.delete(&format!("/prefixes/{prefix}?cascade=true"), None);
    assert_eq!(refused.status, 409, "{}", refused.json());
    assert_eq!(refused.code().as_deref(), Some("dhcp.scope.attached"));
    node.client(&["dhcp", "exclusion", "delete", &prefix, &exclusion_id])
        .assert_code(0);
    node.client(&["dhcp", "scope", "delete", &prefix])
        .assert_code(0)
        .assert_stdout_contains("deleted the scope");
    node.client(&["dhcp", "scope", "show", &prefix])
        .assert_code(5)
        .assert_stderr_contains("dhcp.scope.not_found");
    let gone = api.delete(&format!("/prefixes/{prefix}?cascade=true"), None);
    assert_eq!(gone.status, 200, "{}", gone.json());

    // The lease routes are later packages' and say so.
    node.client(&["dhcp", "lease", "list"])
        .assert_code(5)
        .assert_stderr_contains("sys.not_implemented");
    server.stop().assert_graceful_shutdown();
}
