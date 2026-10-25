//! The lease, history, utilization and node routes over both families (WP9.4): the dhcp
//! role runs on the test's in-memory store without listeners, its tables loaded from the
//! DHCPv4 and DHCPv6 rows written before it starts, and the routes answer through it.

mod dhcp_support;

use std::{sync::Arc, time::Duration};

use dhcp_support::{App, Reply, send};
use serde_json::{Value, json};
use tenko_api::routes::dhcp::DhcpNodeSlot;
use tenko_core::{
    NodeId, PrefixId, Principal, SystemComponent, Timestamp, VrfId,
    dhcp::{
        BindingState, ClientKey, DdnsState, Lease, Lease6, Lease6Event, Lease6Kind, LeaseEvent,
        LeaseEventKind, tables,
    },
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

const MAC: [u8; 6] = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01];
/// A DUID-LL of hardware type 1 over [`MAC`].
const DUID_LL: &str = "0003000100005e005301";
/// A DUID-EN, which names no MAC address.
const DUID_EN: &str = "0002000000090c0c0c0c";

fn later(seconds: u64) -> Timestamp {
    Timestamp::now()
        .checked_add(Duration::from_secs(seconds))
        .expect("time")
}

fn earlier(seconds: i128) -> Timestamp {
    Timestamp::from_unix_nanos(Timestamp::now().unix_nanos() - seconds * 1_000_000_000)
        .expect("time")
}

fn lease4(vrf: VrfId, scope: PrefixId, addr: &str) -> Lease {
    Lease {
        addr: addr.parse().expect("address"),
        vrf,
        scope,
        client: ClientKey {
            htype: 1,
            chaddr: HexBytes(MAC.to_vec()),
            client_id: None,
        },
        state: BindingState::Active,
        cltt: Timestamp::now(),
        ends: later(3_600),
        tstp: None,
        tsfp: None,
        atsfp: None,
        node: NodeId(1),
        share: None,
        hostname: Some("laptop".to_owned()),
        fqdn: None,
        fqdn_flags: None,
        ddns_policy: None,
        ddns: DdnsState::default(),
        fingerprint: None,
        relay: None,
        observed_at: None,
    }
}

fn lease6(vrf: VrfId, scope: PrefixId, addr: &str, duid: &str, mac: bool) -> Lease6 {
    Lease6 {
        addr: addr.parse().expect("address"),
        prefix_len: 128,
        kind: Lease6Kind::Na,
        vrf,
        scope,
        iaid: 7,
        duid: duid.parse::<Duid>().expect("duid"),
        link_layer: mac.then(|| HexBytes(MAC.to_vec())),
        link_layer_type: mac.then_some(1),
        state: BindingState::Active,
        cltt: Timestamp::now(),
        ends: later(3_600),
        preferred_ends: later(2_250),
        node: NodeId(1),
        fqdn: Some("laptop.example.net".to_owned()),
        fqdn_flags: None,
        relay: None,
        observed_at: None,
        ddns: DdnsState::default(),
    }
}

struct World {
    app: App,
    router: axum::Router,
    role: Role,
    v4: String,
    v6: String,
}

impl World {
    async fn get(&self, path: &str) -> Reply {
        send(&self.router, "GET", path, None, &[]).await
    }

    async fn post(&self, path: &str, body: Value) -> Reply {
        send(&self.router, "POST", path, Some(body), &[]).await
    }

    async fn put(&self, path: &str, body: Value) -> Reply {
        send(&self.router, "PUT", path, Some(body), &[]).await
    }
}

/// A DHCPv4 scope and a DHCPv6 scope with a pool each; one DHCPv4 lease and two DHCPv6
/// leases (one of the same MAC address, one with a DUID-EN), three history rows; then the
/// role, started on the store.
async fn world() -> World {
    let app = App::new();
    let v4 = app.prefix("192.0.2.0/24").await;
    app.range(&v4, "192.0.2.100", "192.0.2.199", "dhcp_pool")
        .await;
    let v6 = app.prefix("2001:db8:1::/64").await;
    app.range(&v6, "2001:db8:1::100", "2001:db8:1::2ff", "dhcp_pool")
        .await;
    for prefix in [&v4, &v6] {
        app.send("POST", "/dhcp/scopes", Some(json!({ "prefix": prefix })))
            .await
            .assert_status(201);
    }
    let item = app.get(&format!("/dhcp/scopes/{v4}")).await;
    let vrf: VrfId = serde_json::from_value(item.body["vrf"].clone()).expect("vrf");
    let scope4: PrefixId = v4.parse().expect("prefix");
    let scope6: PrefixId = v6.parse().expect("prefix");

    let near = lease6(vrf, scope6, "2001:db8:1::100", DUID_LL, true);
    let far = lease6(vrf, scope6, "2001:db8:1::101", DUID_EN, false);
    let v4_lease = lease4(vrf, scope4, "192.0.2.100");
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
    batch
        .put_typed(&tables::LEASES, &(vrf, v4_lease.addr), &v4_lease)
        .expect("lease");
    for lease in [&near, &far] {
        batch
            .put_typed(&tables::LEASES6, &(vrf, lease.addr6()), lease)
            .expect("lease");
    }
    let (t1, t2, t3) = (earlier(300), earlier(200), earlier(100));
    batch
        .put_typed(
            &tables::HISTORY,
            &(t1, vrf, v4_lease.addr),
            &LeaseEvent::of(&v4_lease, LeaseEventKind::Granted, t1),
        )
        .expect("history");
    batch
        .put_typed(
            &tables::HISTORY6,
            &(t2, vrf, near.addr6()),
            &Lease6Event::of(&near, LeaseEventKind::Granted, t2),
        )
        .expect("history");
    batch
        .put_typed(
            &tables::HISTORY6,
            &(t3, vrf, near.addr6()),
            &Lease6Event::of(&near, LeaseEventKind::Renewed, t3),
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
        v4,
        v6,
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
async fn the_lease_list_holds_both_families_with_their_correlation() {
    let world = world().await;
    let all = world.get("/dhcp/leases").await;
    all.assert_status(200);
    assert_eq!(
        addrs(&all),
        ["192.0.2.100", "2001:db8:1::100", "2001:db8:1::101"]
    );
    let items = all.items();
    assert_eq!(items[0]["family"], "v4");
    assert_eq!(items[0]["client"]["chaddr"], "00005e005301");
    assert_eq!(items[0]["mac"], "00:00:5e:00:53:01");
    assert_eq!(items[0]["peer"]["addr"], "2001:db8:1::100");
    assert_eq!(items[0]["peer"]["family"], "v6");
    assert_eq!(items[1]["family"], "v6");
    assert_eq!(items[1]["kind"], "na");
    assert_eq!(items[1]["duid"], DUID_LL);
    assert_eq!(items[1]["iaid"], 7);
    assert_eq!(items[1]["mac"], "00:00:5e:00:53:01");
    assert_eq!(items[1]["peer"]["addr"], "192.0.2.100");
    assert_eq!(items[1]["peer"]["state"], "active");
    assert!(items[1].get("client").is_none());
    assert!(items[2].get("mac").is_none() && items[2].get("peer").is_none());

    // The filters: the family, the DUID, the MAC address of both families, the name.
    let v6 = world.get("/dhcp/leases?family=v6").await;
    assert_eq!(addrs(&v6), ["2001:db8:1::100", "2001:db8:1::101"]);
    let v4 = world.get("/dhcp/leases?family=v4").await;
    assert_eq!(addrs(&v4), ["192.0.2.100"]);
    let duid = world
        .get(&format!(
            "/dhcp/leases?duid={}",
            "00:02:00:00:00:09:0c:0c:0c:0c"
        ))
        .await;
    assert_eq!(addrs(&duid), ["2001:db8:1::101"]);
    let mac = world.get("/dhcp/leases?mac=00:00:5e:00:53:01").await;
    assert_eq!(addrs(&mac), ["192.0.2.100", "2001:db8:1::100"]);
    let name = world.get("/dhcp/leases?name=example.net").await;
    assert_eq!(addrs(&name), ["2001:db8:1::100", "2001:db8:1::101"]);
    let scoped = world.get(&format!("/dhcp/leases?scope={}", world.v6)).await;
    assert_eq!(scoped.items().len(), 2);
    world
        .get("/dhcp/leases?duid=zz")
        .await
        .assert_problem(400, "sys.invalid_value");

    // One lease by address in either family.
    let one = world.get("/dhcp/leases/2001:db8:1::100").await;
    one.assert_status(200);
    assert_eq!(one.body["family"], "v6");
    assert!(one.body["preferred_ends"].is_string());
    world
        .get("/dhcp/leases/2001:db8:1::999")
        .await
        .assert_problem(404, "dhcp.lease.not_found");
    world.role.stop().await;
}

#[tokio::test]
async fn pages_go_through_the_dhcpv4_part_then_the_dhcpv6_part() {
    let world = world().await;
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..4 {
        let path = match &cursor {
            Some(cursor) => format!("/dhcp/leases?limit=1&cursor={cursor}"),
            None => "/dhcp/leases?limit=1".to_owned(),
        };
        let page = world.get(&path).await;
        page.assert_status(200);
        seen.extend(addrs(&page));
        cursor = page.body["next_cursor"].as_str().map(str::to_owned);
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(seen, ["192.0.2.100", "2001:db8:1::100", "2001:db8:1::101"]);
    // A page that ends with the last DHCPv4 lease continues with the first DHCPv6 one.
    let two = world.get("/dhcp/leases?limit=2").await;
    assert_eq!(addrs(&two), ["192.0.2.100", "2001:db8:1::100"]);
    let rest = world
        .get(&format!(
            "/dhcp/leases?limit=2&cursor={}",
            two.text("next_cursor")
        ))
        .await;
    assert_eq!(addrs(&rest), ["2001:db8:1::101"]);
    assert_eq!(rest.body["next_cursor"], Value::Null);
    world
        .get("/dhcp/leases?cursor=not-a-cursor")
        .await
        .assert_problem(400, "sys.invalid_cursor");
    world.role.stop().await;
}

#[tokio::test]
async fn the_history_merges_both_tables_newest_first() {
    let world = world().await;
    let all = world.get("/dhcp/history").await;
    all.assert_status(200);
    let kinds: Vec<(String, String)> = all
        .items()
        .iter()
        .map(|item| {
            (
                item["family"].as_str().expect("family").to_owned(),
                item["kind"].as_str().expect("kind").to_owned(),
            )
        })
        .collect();
    assert_eq!(
        kinds,
        [
            ("v6".to_owned(), "renewed".to_owned()),
            ("v6".to_owned(), "granted".to_owned()),
            ("v4".to_owned(), "granted".to_owned()),
        ]
    );
    let items = all.items();
    assert_eq!(items[0]["duid"], DUID_LL);
    assert_eq!(items[0]["mac"], "00:00:5e:00:53:01", "from the DUID-LL");
    assert_eq!(items[2]["mac"], "00:00:5e:00:53:01");

    let v4 = world.get("/dhcp/history?family=v4").await;
    assert_eq!(v4.items().len(), 1);
    let by_addr = world.get("/dhcp/history?addr=2001:db8:1::100").await;
    assert_eq!(by_addr.items().len(), 2);
    let by_mac = world.get("/dhcp/history?mac=00:00:5e:00:53:01").await;
    assert_eq!(by_mac.items().len(), 3);
    let by_duid = world.get(&format!("/dhcp/history?duid={DUID_EN}")).await;
    assert_eq!(by_duid.items().len(), 0);

    // Pages of one keep the merged order.
    let mut order = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..5 {
        let path = match &cursor {
            Some(cursor) => format!("/dhcp/history?limit=1&cursor={cursor}"),
            None => "/dhcp/history?limit=1".to_owned(),
        };
        let page = world.get(&path).await;
        page.assert_status(200);
        order.extend(
            page.items()
                .iter()
                .map(|item| item["kind"].as_str().expect("kind").to_owned()),
        );
        cursor = page.body["next_cursor"].as_str().map(str::to_owned);
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(order, ["renewed", "granted", "granted"]);
    world.role.stop().await;
}

#[tokio::test]
async fn a_dhcpv6_scope_counts_its_leases() {
    let world = world().await;
    let figures = world
        .get(&format!("/dhcp/scopes/{}/utilization", world.v6))
        .await;
    figures.assert_status(200);
    assert_eq!(figures.body["family"], "v6");
    assert_eq!(figures.body["pool_size"], 512);
    assert_eq!(figures.body["leased"], 2);
    assert_eq!(figures.body["free"], 510);
    let v4 = world
        .get(&format!("/dhcp/scopes/{}/utilization", world.v4))
        .await;
    assert_eq!(v4.body["family"], "v4");
    assert_eq!(v4.body["leased"], 1);
    let scope = world.get(&format!("/dhcp/scopes/{}", world.v6)).await;
    assert_eq!(scope.body["leases"], 2);
    assert_eq!(scope.body["family"], "v6");

    // A /64 pool reads its size as a power of two.
    let wide = world.app.prefix("2001:db8:2::/64").await;
    world
        .app
        .range(
            &wide,
            "2001:db8:2::",
            "2001:db8:2::ffff:ffff:ffff:ffff",
            "dhcp_pool",
        )
        .await;
    world
        .post("/dhcp/scopes", json!({ "prefix": wide }))
        .await
        .assert_status(201);
    let big = world.get(&format!("/dhcp/scopes/{wide}/utilization")).await;
    big.assert_status(200);
    assert_eq!(big.body["pool_bits"], 63, "{}", big.body);
    world.role.stop().await;
}

#[tokio::test]
async fn the_node_report_carries_the_dhcpv6_side() {
    let world = world().await;
    let report = world.get("/nodes/1/dhcp").await;
    report.assert_status(200);
    assert_eq!(report.body["listeners6"], json!([]));
    assert_eq!(report.body["scopes6"], 1);
    let active = report.body["leases6"]
        .as_array()
        .expect("counts")
        .iter()
        .find(|count| count["state"] == "active")
        .expect("active")["count"]
        .clone();
    assert_eq!(active, 2);
    let node = world.get("/nodes/1/dhcp/leases?family=v6").await;
    assert_eq!(node.items().len(), 2);
    let history = world.get("/nodes/1/dhcp/history?family=v6").await;
    assert_eq!(history.items().len(), 2);
    world.role.stop().await;
}

#[tokio::test]
async fn a_dhcpv6_lease_is_released_and_audited() {
    let world = world().await;
    let released = world
        .post(
            "/dhcp/leases/2001:db8:1::100/release",
            json!({ "reason": "retired" }),
        )
        .await;
    released.assert_status(200);
    assert_eq!(released.body["family"], "v6");
    assert_eq!(released.body["state"], "released");
    world
        .post("/dhcp/leases/2001:db8:1::100/release", json!({}))
        .await
        .assert_problem(409, "dhcp.lease.state");
    world
        .post("/dhcp/leases/2001:db8:1::999/release", json!({}))
        .await
        .assert_problem(404, "dhcp.lease.not_found");
    let node = world
        .post("/nodes/1/dhcp/leases/2001:db8:1::101/release", json!({}))
        .await;
    node.assert_status(202);
    let history = world.get("/dhcp/history?addr=2001:db8:1::100").await;
    assert_eq!(history.items()[0]["kind"], "reclaimed");
    let actions = world.app.audit_actions().await;
    assert_eq!(
        actions
            .iter()
            .filter(|action| *action == "dhcp.lease.release")
            .count(),
        4,
        "{actions:?}"
    );
    assert!(actions.iter().any(|action| action == "dhcp.lease.read"));
    world.role.stop().await;
}

#[tokio::test]
async fn the_catalog_serves_the_dhcpv6_options_and_sets_take_them_typed() {
    let world = world().await;
    let v6 = world.get("/dhcp/option-catalog?space=dhcp6").await;
    v6.assert_status(200);
    let entries = v6.body.as_array().expect("entries").clone();
    assert!(entries.iter().all(|entry| entry["space"] == "dhcp6"));
    let dns = entries
        .iter()
        .find(|entry| entry["code"] == 23)
        .expect("option 23");
    assert_eq!(dns["name"], "dns-servers");
    assert_eq!(dns["kind"], "ipv6_address");
    assert_eq!(dns["server_managed"], false);
    assert!(
        entries
            .iter()
            .any(|entry| entry["code"] == 14 && entry["server_managed"] == true)
    );
    let both = world.get("/dhcp/option-catalog").await;
    let spaces: Vec<&str> = both
        .body
        .as_array()
        .expect("entries")
        .iter()
        .map(|entry| entry["space"].as_str().expect("space"))
        .collect();
    assert!(spaces.contains(&"dhcp4") && spaces.contains(&"dhcp6"));
    assert_eq!(spaces[0], "dhcp4");
    world
        .get("/dhcp/option-catalog?space=dhcp5")
        .await
        .assert_problem(400, "sys.invalid_query");

    let path = format!("/dhcp/option-sets/scope:{}", world.v6);
    let set = world
        .put(
            &path,
            json!({ "values": [
                { "space": "dhcp6", "code": 23, "typed": { "ipv6": { "values": ["2001:db8::53"] } } },
                { "space": "dhcp6", "code": 24, "typed": { "names": ["example.net"] } }
            ] }),
        )
        .await;
    set.assert_status(200);
    let values = set.body["values"].as_array().expect("values").clone();
    assert_eq!(values[0]["name"], "dns-servers");
    assert_eq!(values[0]["typed"]["ipv6"]["values"][0], "2001:db8::53");
    assert_eq!(values[1]["name"], "domain-search");
    world
        .put(
            &path,
            json!({ "values": [{ "space": "dhcp6", "code": 1, "data": "0001" }] }),
        )
        .await
        .assert_problem(409, "dhcp.option.code_reserved");
    world.role.stop().await;
}
