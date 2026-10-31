//! The delegation pools and delegated prefixes through the routes (WP9.4, the `IA_PD` half):
//! `GET /dhcp/pools` with the pool's role, delegated length, size in prefixes and bound
//! prefixes; the `pd` block of the utilization; the kind filter and the prefix-aware address
//! filter of `GET /dhcp/leases`; the link from a delegated prefix to its router's address
//! lease; and the history's MAC filter over the link-layer address of a DHCPv6 client with
//! a DUID-EN behind an RFC 6939 relay. The dhcp role runs on the test's in-memory store
//! without listeners, its tables loaded from the rows written before it starts.

mod dhcp_support;

use std::{sync::Arc, time::Duration};

use dhcp_support::{App, Reply, send};
use serde_json::{Value, json};
use tenko_api::routes::dhcp::DhcpNodeSlot;
use tenko_core::{
    NodeId, PrefixId, Principal, SystemComponent, Timestamp, VrfId,
    dhcp::{BindingState, DdnsState, Lease6, Lease6Event, Lease6Kind, LeaseEventKind, tables},
    net::Duid,
    serde_util::HexBytes,
};
use tenko_dhcp::{
    lease::CommitSettings,
    role::{DhcpNode, Role, RoleSettings},
    server::ServerConfig,
    v6::server::Server6Config,
};
use tenko_store::{Store, WriteBatch};

/// The router's MAC address, which its relay sends in option 79 (RFC 6939).
const MAC: [u8; 6] = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x21];
/// The router's DUID-EN, which names no MAC address.
const ROUTER: &str = "0002000000090c0c0c0c21";
/// Another client's DUID-EN.
const OTHER: &str = "0002000000090c0c0c0c22";

fn later(seconds: u64) -> Timestamp {
    Timestamp::now()
        .checked_add(Duration::from_secs(seconds))
        .expect("time")
}

fn earlier(seconds: i128) -> Timestamp {
    Timestamp::from_unix_nanos(Timestamp::now().unix_nanos() - seconds * 1_000_000_000)
        .expect("time")
}

fn lease6(vrf: VrfId, scope: PrefixId, addr: &str, len: u8, duid: &str, mac: bool) -> Lease6 {
    Lease6 {
        addr: addr.parse().expect("address"),
        prefix_len: len,
        kind: if len == 128 {
            Lease6Kind::Na
        } else {
            Lease6Kind::Pd
        },
        vrf,
        scope,
        iaid: 1,
        duid: duid.parse::<Duid>().expect("duid"),
        link_layer: mac.then(|| HexBytes(MAC.to_vec())),
        link_layer_type: mac.then_some(1),
        state: BindingState::Active,
        cltt: Timestamp::now(),
        ends: later(3_600),
        preferred_ends: later(2_250),
        node: NodeId(1),
        fqdn: None,
        fqdn_flags: None,
        relay: None,
        observed_at: None,
        granted: None,
        ddns: DdnsState::default(),
    }
}

struct World {
    app: App,
    router: axum::Router,
    role: Role,
    link: String,
    delegation: String,
    pool: String,
}

impl World {
    async fn get(&self, path: &str) -> Reply {
        send(&self.router, "GET", path, None, &[]).await
    }
}

/// A link `2001:db8:1::/64` with an address pool and a delegation network
/// `2001:db8:180::/48` with the pool `2001:db8:180:100::/56` at /60, each with a scope; the
/// router's address on the link and two delegated prefixes (its own and another
/// client's), the router's history rows; then the role.
async fn world() -> World {
    let app = App::new();
    let link = app.prefix("2001:db8:1::/64").await;
    app.range(&link, "2001:db8:1::100", "2001:db8:1::2ff", "dhcp_pool")
        .await;
    let delegation = app.prefix("2001:db8:180::/48").await;
    let reply = app
        .send(
            "POST",
            &format!("/prefixes/{delegation}/ranges"),
            Some(json!({
                "first": "2001:db8:180:100::",
                "last": "2001:db8:180:1ff:ffff:ffff:ffff:ffff",
                "role": "dhcp_pd_pool",
                "delegated_len": 60,
            })),
        )
        .await;
    reply.assert_status(201);
    let pool = reply.body["item"]["id"].as_str().expect("id").to_owned();
    for prefix in [&link, &delegation] {
        app.send("POST", "/dhcp/scopes", Some(json!({ "prefix": prefix })))
            .await
            .assert_status(201);
    }
    let item = app.get(&format!("/dhcp/scopes/{link}")).await;
    let vrf: VrfId = serde_json::from_value(item.body["vrf"].clone()).expect("vrf");
    let link_scope: PrefixId = link.parse().expect("prefix");
    let pd_scope: PrefixId = delegation.parse().expect("prefix");

    let address = lease6(vrf, link_scope, "2001:db8:1::100", 128, ROUTER, true);
    let prefix = lease6(vrf, pd_scope, "2001:db8:180:110::", 60, ROUTER, true);
    let other = lease6(vrf, pd_scope, "2001:db8:180:120::", 60, OTHER, false);
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
    for lease in [&address, &prefix, &other] {
        batch
            .put_typed(&tables::LEASES6, &(vrf, lease.addr6()), lease)
            .expect("lease");
    }
    let (t1, t2) = (earlier(200), earlier(100));
    batch
        .put_typed(
            &tables::HISTORY6,
            &(t1, vrf, address.addr6()),
            &Lease6Event::of(&address, LeaseEventKind::Granted, t1),
        )
        .expect("history");
    batch
        .put_typed(
            &tables::HISTORY6,
            &(t2, vrf, prefix.addr6()),
            &Lease6Event::of(&prefix, LeaseEventKind::Granted, t2),
        )
        .expect("history");
    app.store.propose(batch).await.expect("rows");

    let role = Role::start(
        Arc::clone(&app.store) as Arc<dyn Store>,
        NodeId(1),
        RoleSettings {
            server: ServerConfig::default(),
            commit: CommitSettings::default(),
            probe: false,
            probe_expected: false,
            server6: Server6Config::default(),
        },
    )
    .await
    .expect("role");
    let slot = DhcpNodeSlot::default();
    slot.set(role.node() as Arc<dyn DhcpNode>);
    let router = app.router.clone().layer(axum::Extension(slot));
    World {
        app,
        router,
        role,
        link,
        delegation,
        pool,
    }
}

fn addrs(reply: &Reply) -> Vec<String> {
    reply
        .items()
        .iter()
        .map(|item| item["addr"].as_str().expect("addr").to_owned())
        .collect()
}

#[tokio::test]
async fn a_delegation_pool_counts_prefixes() {
    let world = world().await;
    let pools = world
        .get(&format!("/dhcp/pools?scope={}", world.delegation))
        .await;
    pools.assert_status(200);
    let items = pools.items();
    assert_eq!(items.len(), 1, "{}", pools.body);
    assert_eq!(items[0]["range"], json!(world.pool));
    assert_eq!(items[0]["role"], "dhcp_pd_pool");
    assert_eq!(items[0]["delegated_len"], 60);
    assert_eq!(items[0]["size"], 16, "a /56 holds sixteen /60s");
    assert_eq!(items[0]["leased"], 2);
    let one = world.get(&format!("/dhcp/pools/{}", world.pool)).await;
    one.assert_status(200);
    assert_eq!(one.body["role"], "dhcp_pd_pool");

    // An address pool says its role and no delegated length.
    let link = world
        .get(&format!("/dhcp/pools?scope={}", world.link))
        .await;
    assert_eq!(link.items()[0]["role"], "dhcp_pool");
    assert!(link.items()[0].get("delegated_len").is_none());

    // The utilization's `pd` block counts the same prefixes; the address figures leave
    // them out.
    let figures = world
        .get(&format!("/dhcp/scopes/{}/utilization", world.delegation))
        .await;
    figures.assert_status(200);
    assert_eq!(figures.body["family"], "v6");
    assert_eq!(figures.body["leased"], 0);
    assert_eq!(figures.body["pd"]["pools"], 1);
    assert_eq!(figures.body["pd"]["pool_size"], 16);
    assert_eq!(figures.body["pd"]["leased"], 2);
    assert_eq!(figures.body["pd"]["free"], 14);
    assert_eq!(figures.body["pd"]["utilization"], 0.125);
    let link = world
        .get(&format!("/dhcp/scopes/{}/utilization", world.link))
        .await;
    assert!(link.body.get("pd").is_none(), "{}", link.body);

    // An exclusion that touches one prefix takes that prefix out.
    world
        .app
        .send(
            "POST",
            &format!("/dhcp/scopes/{}/exclusions", world.delegation),
            Some(json!({ "first": "2001:db8:180:1f0::5", "last": "2001:db8:180:1f0::5" })),
        )
        .await
        .assert_status(201);
    let pools = world
        .get(&format!("/dhcp/pools?scope={}", world.delegation))
        .await;
    assert_eq!(pools.items()[0]["size"], 15);
    let figures = world
        .get(&format!("/dhcp/scopes/{}/utilization", world.delegation))
        .await;
    assert_eq!(figures.body["pd"]["pool_size"], 15);
    assert_eq!(figures.body["pd"]["free"], 13);
    world.role.stop().await;
}

#[tokio::test]
async fn the_lease_list_filters_by_kind_and_by_prefix() {
    let world = world().await;
    let all = world.get("/dhcp/leases").await;
    all.assert_status(200);
    assert_eq!(
        addrs(&all),
        [
            "2001:db8:1::100",
            "2001:db8:180:110::",
            "2001:db8:180:120::"
        ]
    );
    let items = all.items();
    assert_eq!(items[1]["kind"], "pd");
    assert_eq!(items[1]["prefix_len"], 60);
    // The router's prefix names its address lease by the DUID; the other client has none,
    // and an address lease names none.
    assert_eq!(items[1]["address_lease"]["addr"], "2001:db8:1::100");
    assert_eq!(items[1]["address_lease"]["family"], "v6");
    assert_eq!(items[1]["address_lease"]["state"], "active");
    assert!(items[2].get("address_lease").is_none());
    assert!(items[0].get("address_lease").is_none());

    let pd = world.get("/dhcp/leases?kind=pd").await;
    assert_eq!(addrs(&pd), ["2001:db8:180:110::", "2001:db8:180:120::"]);
    let na = world.get("/dhcp/leases?kind=na").await;
    assert_eq!(addrs(&na), ["2001:db8:1::100"]);

    // An address inside a delegated prefix finds the prefix that holds it.
    let inside = world.get("/dhcp/leases?addr=2001:db8:180:11a::1").await;
    assert_eq!(addrs(&inside), ["2001:db8:180:110::"]);
    // A prefix finds the leases inside it, delegated prefixes and addresses alike.
    let net = world.get("/dhcp/leases?addr=2001:db8:180::/48").await;
    assert_eq!(addrs(&net), ["2001:db8:180:110::", "2001:db8:180:120::"]);
    let link = world.get("/dhcp/leases?addr=2001:db8:1::/64").await;
    assert_eq!(addrs(&link), ["2001:db8:1::100"]);
    // A shorter prefix inside a delegated prefix finds it as well.
    let part = world.get("/dhcp/leases?addr=2001:db8:180:118::/62").await;
    assert_eq!(addrs(&part), ["2001:db8:180:110::"]);
    // Text that starts an address works as before.
    let text = world.get("/dhcp/leases?addr=2001:db8:180:12").await;
    assert_eq!(addrs(&text), ["2001:db8:180:120::"]);
    world.role.stop().await;
}

#[tokio::test]
async fn the_history_finds_a_relayed_duid_en_client_by_its_mac_address() {
    let world = world().await;
    let all = world.get("/dhcp/history").await;
    all.assert_status(200);
    let items = all.items();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["prefix_len"], 60);
    assert_eq!(
        items[0]["mac"], "00:00:5e:00:53:21",
        "from the relay's option 79"
    );
    let by_mac = world.get("/dhcp/history?mac=00:00:5e:00:53:21").await;
    assert_eq!(by_mac.items().len(), 2, "{}", by_mac.body);
    let other = world.get("/dhcp/history?mac=00:00:5e:00:53:22").await;
    assert_eq!(other.items().len(), 0);
    world.role.stop().await;
}

#[tokio::test]
async fn the_node_report_says_the_ra_check_is_off_without_a_probe() {
    let world = world().await;
    let report = world.get("/nodes/1/dhcp").await;
    report.assert_status(200);
    assert_eq!(report.body["ra"]["check"], "off");
    assert_eq!(report.body["ra"]["links"], Value::Array(Vec::new()));
    assert_eq!(report.body["ra"]["findings"], Value::Array(Vec::new()));
    assert!(report.body["ra"].get("reason").is_none());
    // No DHCPv6 listener, so no DHCPv6 server and no DUID to report.
    assert!(report.body.get("server_duid").is_none(), "{}", report.body);
    world.role.stop().await;
}
