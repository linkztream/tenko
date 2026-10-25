//! Tests of the reserve routes (DHCP-01, IPAM-18, IPAM-23): what they write, in one batch with one
//! audit record, and what they refuse without writing anything.

use std::sync::Arc;

use serde_json::{Value, json};
use tenko_core::{
    Action, ObjectKind, PrefixId, Principal, SystemComponent, Timestamp,
    audit::AuditRecord,
    dhcp::{DdnsPolicy, LeaseTimes, Scope, tables::SCOPES},
    ipam::{RangeRole, Stamp},
};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, WriteBatch, tables};

use super::super::tenancy::testkit::{Api, Policy, Reply};
use crate::state::AppState;

/// The API with the network `192.0.2.0/24` and, when `scope`, a DHCP scope on it.
async fn network(scope: bool) -> (Api, PrefixId) {
    let api = Api::new();
    let prefix = api.make_prefix(None, "192.0.2.0/24").await;
    if scope {
        add_scope(&api, prefix).await;
    }
    (api, prefix)
}

/// Writes a scope row for the prefix, as the DHCP configuration service would.
async fn add_scope(api: &Api, prefix: PrefixId) {
    let now = Timestamp::now();
    let stamp = Stamp::new(now, Principal::system(SystemComponent::Dhcp));
    let scope = Scope {
        v6: None,
        prefix,
        enabled: false,
        lease: Some(LeaseTimes::fixed(3_600)),
        authoritative: None,
        server_id: None,
        ddns: DdnsPolicy::default(),
        shared_network: None,
        restricted: false,
        classes: Vec::new(),
        description: None,
        created: stamp.clone(),
        updated: stamp,
    };
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
    batch.put_typed(&SCOPES, &prefix, &scope).expect("scope");
    api.store().propose(batch).await.expect("commit");
}

fn id_of(value: &Value) -> String {
    value["id"].as_str().expect("id").to_owned()
}

/// Creates an address and returns its identifier.
async fn address(api: &Api, body: &Value) -> String {
    id_of(&api.create("/addresses", body).await)
}

/// Creates a host with one interface and returns the host and the interface.
async fn host(api: &Api, name: &str, mode: &str, interface: &Value) -> (String, String) {
    let body = json!({ "name": name, "mode": mode, "interfaces": [interface] });
    let host = id_of(&api.create("/hosts", &body).await);
    let interfaces = api.get(&format!("/hosts/{host}/interfaces")).await.ids();
    (host, interfaces[0].clone())
}

/// The audit records, oldest first.
async fn audit(api: &Api) -> Vec<AuditRecord> {
    let view = api
        .store()
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    view.scan_typed(&tables::AUDIT, KeyRange::all(), usize::MAX, false)
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record)
        .collect()
}

/// How many audit records there are.
async fn audit_count(api: &Api) -> usize {
    audit(api).await.len()
}

async fn reserve(api: &Api, address: &str, body: &Value) -> Reply {
    api.post(&format!("/addresses/{address}/reserve"), body)
        .await
}

#[tokio::test]
async fn an_unbound_address_gets_a_new_reserved_host_in_one_batch_and_one_audit_record() {
    let (api, prefix) = network(true).await;
    let id = address(&api, &json!({ "ip": "192.0.2.20" })).await;
    let before = audit_count(&api).await;
    let reply = reserve(
        &api,
        &id,
        &json!({ "new_host": "printer01", "mac": "02:00:5e:10:00:01" }),
    )
    .await;
    reply.assert_json(200);
    let body = &reply.body;
    assert_eq!(body["dry_run"], false);
    assert_eq!(body["unchanged"], false);
    assert_eq!(body["scope"], prefix.to_string());
    assert_eq!(body["host"]["name"], "printer01");
    assert_eq!(body["host"]["mode"], "reserved");
    assert_eq!(body["interface"]["name"], "eth0");
    assert_eq!(body["interface"]["mac"], "02:00:5e:10:00:01");
    assert_eq!(body["address"]["interface"], body["interface"]["id"]);
    assert_eq!(body["address"]["status"], "active");

    // One batch: every row carries the one revision; one audit record names them all.
    let revision = body["revision"].as_u64().expect("revision");
    for object in ["host", "interface", "address"] {
        assert_eq!(body[object]["meta"]["revision"], revision, "{object}");
    }
    let records = audit(&api).await;
    assert_eq!(records.len(), before + 1);
    let record = records.last().expect("record");
    assert_eq!(record.draft.action.as_str(), "ipam.address.reserve");
    let kinds: Vec<ObjectKind> = record.draft.objects.iter().map(|o| o.kind).collect();
    assert!(kinds.contains(&ObjectKind::Host), "{kinds:?}");
    assert!(kinds.contains(&ObjectKind::Interface), "{kinds:?}");
    assert!(kinds.contains(&ObjectKind::Address), "{kinds:?}");
    assert!(
        record
            .draft
            .details
            .changes
            .iter()
            .all(|change| change.object.is_some()),
        "every change names its object"
    );
}

#[tokio::test]
async fn an_existing_static_host_becomes_reserved_and_its_interface_gets_the_identity() {
    let (api, _) = network(true).await;
    let (host_id, interface) = host(&api, "nas01", "static", &json!({ "name": "lan" })).await;
    let id = address(
        &api,
        &json!({ "ip": "192.0.2.21", "interface": interface, "status": "planned" }),
    )
    .await;
    let reply = reserve(
        &api,
        &id,
        &json!({ "mac": "02:00:5e:10:00:02", "client_id": "01:02:00:5e:10:00:02" }),
    )
    .await;
    reply.assert_json(200);
    assert_eq!(reply.body["host"]["id"], host_id);
    assert_eq!(reply.body["host"]["mode"], "reserved");
    assert_eq!(reply.body["interface"]["id"], interface);
    assert_eq!(reply.body["interface"]["mac"], "02:00:5e:10:00:02");
    assert_eq!(reply.body["interface"]["client_id"], "0102005e100002");
    // A planned address stays planned.
    assert_eq!(reply.body["address"]["status"], "planned");
}

#[tokio::test]
async fn a_request_that_finds_the_reservation_in_place_changes_nothing() {
    let (api, _) = network(true).await;
    let id = address(&api, &json!({ "ip": "192.0.2.22" })).await;
    let body = json!({ "new_host": "cam01", "mac": "02:00:5e:10:00:03" });
    reserve(&api, &id, &body).await.assert_json(200);
    let before = audit_count(&api).await;
    let again = reserve(&api, &id, &json!({ "mac": "02:00:5e:10:00:03" })).await;
    again.assert_json(200);
    assert_eq!(again.body["unchanged"], true);
    assert_eq!(again.body["job_id"], Value::Null);
    assert_eq!(audit_count(&api).await, before);
}

#[tokio::test]
async fn a_prefix_without_a_scope_is_refused_and_nothing_is_written() {
    let (api, _) = network(false).await;
    let (host_id, interface) = host(&api, "nas02", "static", &json!({ "name": "lan" })).await;
    let id = address(&api, &json!({ "ip": "192.0.2.23", "interface": interface })).await;
    let before = audit_count(&api).await;
    reserve(&api, &id, &json!({ "mac": "02:00:5e:10:00:04" }))
        .await
        .assert_problem(404, "dhcp.scope.not_found");
    assert_eq!(audit_count(&api).await, before);
    let host = api.get(&format!("/hosts/{host_id}")).await;
    assert_eq!(host.body["mode"], "static");
    let interface = api.get(&format!("/interfaces/{interface}")).await;
    assert_eq!(interface.body["mac"], Value::Null);
}

#[tokio::test]
async fn an_interface_without_identity_is_refused_with_no_identity() {
    let (api, _) = network(true).await;
    let (host_id, interface) = host(&api, "nas03", "static", &json!({ "name": "lan" })).await;
    let id = address(&api, &json!({ "ip": "192.0.2.24", "interface": interface })).await;
    let before = audit_count(&api).await;
    let reply = reserve(&api, &id, &json!({})).await;
    reply.assert_problem(409, "dhcp.reservation.no_identity");
    assert_eq!(reply.body["params"]["host"], host_id);
    assert_eq!(audit_count(&api).await, before);
    assert_eq!(
        api.get(&format!("/hosts/{host_id}")).await.body["mode"],
        "static"
    );
}

#[tokio::test]
async fn a_client_another_reserved_host_presents_in_the_scope_is_a_409() {
    let (api, _) = network(true).await;
    let (other, other_interface) = host(
        &api,
        "phone01",
        "reserved",
        &json!({ "name": "wlan", "mac": "02:00:5e:10:00:05" }),
    )
    .await;
    address(
        &api,
        &json!({ "ip": "192.0.2.25", "interface": other_interface }),
    )
    .await;
    let id = address(&api, &json!({ "ip": "192.0.2.26" })).await;
    let before = audit_count(&api).await;
    let reply = reserve(
        &api,
        &id,
        &json!({ "new_host": "phone02", "mac": "02:00:5e:10:00:05" }),
    )
    .await;
    reply.assert_problem(409, "dhcp.reservation.conflict");
    assert!(
        reply.body["params"]["hosts"]
            .as_str()
            .is_some_and(|hosts| hosts.contains(&other)),
        "{}",
        reply.body
    );
    // Nothing of the plan was written: no host phone02.
    assert_eq!(audit_count(&api).await, before);
    let hosts = api.get("/hosts?q=phone02").await;
    hosts.assert_no_items();

    // The same MAC address keyed by a client identifier is another client.
    reserve(
        &api,
        &id,
        &json!({ "new_host": "phone02", "mac": "02:00:5e:10:00:05", "client_id": "ff00aa" }),
    )
    .await
    .assert_json(200);
}

#[tokio::test]
async fn an_address_another_reserved_host_holds_is_a_409() {
    let (api, _) = network(true).await;
    let (_, interface) = host(
        &api,
        "tv01",
        "reserved",
        &json!({ "name": "lan", "mac": "02:00:5e:10:00:06" }),
    )
    .await;
    let id = address(&api, &json!({ "ip": "192.0.2.27", "interface": interface })).await;
    let reply = reserve(
        &api,
        &id,
        &json!({ "new_host": "tv02", "mac": "02:00:5e:10:00:07" }),
    )
    .await;
    reply.assert_problem(409, "dhcp.reservation.conflict");
    assert_eq!(reply.body["params"]["address"], "192.0.2.27");
}

#[tokio::test]
async fn an_address_inside_a_dhcp_pool_is_refused_and_nothing_is_written() {
    let (api, prefix) = network(true).await;
    api.make_range(prefix, "192.0.2.100", "192.0.2.199", RangeRole::DhcpPool)
        .await;
    let (host_id, interface) = host(&api, "nas04", "static", &json!({ "name": "lan" })).await;
    let id = address(
        &api,
        &json!({ "ip": "192.0.2.150", "interface": interface }),
    )
    .await;
    let before = audit_count(&api).await;
    reserve(&api, &id, &json!({ "mac": "02:00:5e:10:00:08" }))
        .await
        .assert_problem(409, "ipam.address.in_dhcp_pool");
    assert_eq!(audit_count(&api).await, before);
    assert_eq!(
        api.get(&format!("/hosts/{host_id}")).await.body["mode"],
        "static"
    );
}

#[tokio::test]
async fn the_value_route_creates_an_address_ipam_does_not_hold() {
    let (api, prefix) = network(true).await;
    let reply = api
        .post(
            "/addresses/reserve",
            &json!({
                "ip": "192.0.2.30",
                "new_host": "laptop01",
                "mac": "02:00:5e:10:00:09",
                "status": "planned"
            }),
        )
        .await;
    reply.assert_json(200);
    assert_eq!(reply.body["address"]["ip"], "192.0.2.30");
    assert_eq!(reply.body["address"]["status"], "planned");
    assert_eq!(reply.body["scope"], prefix.to_string());
    assert_eq!(reply.body["host"]["mode"], "reserved");

    // An address it holds is used as it is.
    let again = api
        .post(
            "/addresses/reserve",
            &json!({ "ip": "192.0.2.30", "mac": "02:00:5e:10:00:09" }),
        )
        .await;
    again.assert_json(200);
    assert_eq!(again.body["address"]["id"], reply.body["address"]["id"]);
    assert_eq!(again.body["unchanged"], true);
}

#[tokio::test]
async fn a_dry_run_answers_the_plan_and_writes_nothing() {
    let (api, _) = network(true).await;
    let id = address(&api, &json!({ "ip": "192.0.2.31" })).await;
    let before = audit_count(&api).await;
    let reply = api
        .post(
            &format!("/addresses/{id}/reserve?dry_run=true"),
            &json!({ "new_host": "nas05", "mac": "02:00:5e:10:00:0a" }),
        )
        .await;
    reply.assert_json(200);
    assert_eq!(reply.body["dry_run"], true);
    assert_eq!(reply.body["revision"], Value::Null);
    assert_eq!(reply.body["host"]["mode"], "reserved");
    assert!(reply.body["plan"].is_object());
    assert_eq!(audit_count(&api).await, before);
    api.get("/hosts?q=nas05").await.assert_no_items();
}

#[tokio::test]
async fn malformed_requests_are_400() {
    let (api, _) = network(true).await;
    let id = address(&api, &json!({ "ip": "192.0.2.32" })).await;
    for body in [
        // An unbound address and no host named.
        json!({ "mac": "02:00:5e:10:00:0b" }),
        // An existing and a new host.
        json!({ "host": super::super::tenancy::testkit::unknown_id(), "new_host": "x01" }),
        // A status that makes no reservation.
        json!({ "new_host": "x01", "mac": "02:00:5e:10:00:0b", "status": "deprecated" }),
        // The address by value on the identifier route.
        json!({ "ip": "192.0.2.33", "new_host": "x01" }),
    ] {
        reserve(&api, &id, &body)
            .await
            .assert_problem(400, "ipam.validation");
    }
    api.post("/addresses/reserve", &json!({ "new_host": "x01" }))
        .await
        .assert_problem(400, "ipam.validation");
}

#[tokio::test]
async fn the_route_asks_for_the_ipam_writes_it_makes_and_nothing_else() {
    let (owner, _) = network(true).await;
    let (host_id, _) = host(&owner, "nas06", "static", &json!({ "name": "lan" })).await;
    let id = address(&owner, &json!({ "ip": "192.0.2.34" })).await;
    let body = json!({ "host": host_id, "mac": "02:00:5e:10:00:0c" });

    // A reader is refused before anything is written.
    let reader = owner.sibling(AppState {
        authorizer: Some(Policy::new(true, false) as Arc<dyn tenko_core::Authorizer>),
        ..AppState::default()
    });
    reserve(&reader, &id, &body)
        .await
        .assert_problem(403, "auth.forbidden");
    assert_eq!(
        owner.get(&format!("/hosts/{host_id}")).await.body["mode"],
        "static"
    );

    // A writer is asked exactly for the updates of the host, the interface and the address.
    let policy = Policy::new(true, true);
    let writer = owner.sibling(AppState {
        authorizer: Some(Arc::clone(&policy) as Arc<dyn tenko_core::Authorizer>),
        ..AppState::default()
    });
    reserve(&writer, &id, &body).await.assert_json(200);
    let asked: Vec<(Action, ObjectKind)> = policy
        .asked()
        .iter()
        .filter(|(action, _)| *action != Action::Read)
        .map(|(action, object)| (*action, object.kind))
        .collect();
    assert_eq!(
        asked,
        [
            (Action::Update, ObjectKind::Host),
            (Action::Update, ObjectKind::Interface),
            (Action::Update, ObjectKind::Address),
        ]
    );
}
