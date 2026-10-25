//! Route tests of the host lifecycle: decommission and reinstate, the hosts list filter, the
//! rights they need and their audit records. Test data lives in the documentation ranges
//! (`192.0.2.0/24`, MACs `00-00-5E-00-53-xx`, names under `example.test`).

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{Request, header},
};
use serde_json::{Value, json};
use tenko_core::{
    Action, Authorizer, Denied, DenyReason, ObjectKind, ObjectRef, Principal, RequestCtx,
    ScopeFilter, SystemComponent, audit::AuditRecord,
};
use tenko_ipam::{IpamCommand, IpamService, PlanOptions, command::PrefixInput};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadViewExt, Store, tables::AUDIT};
use tower::ServiceExt;
use utoipa_axum::router::OpenApiRouter;

use super::super::{
    addresses, common, hosts,
    tenancy::testkit::{Reply, ip4, label, unknown_id},
};
use crate::{API_BASE, state::AppState};

fn mac(n: usize) -> String {
    format!("00-00-5E-00-53-{n:02X}")
}

/// The routes of the lifecycle and of the areas it reads and changes, over `state`.
fn router(state: AppState) -> Router {
    let area = hosts::routes()
        .merge(addresses::routes())
        .merge(super::routes())
        .merge(common::routes());
    let (router, _) = OpenApiRouter::<AppState>::new()
        .nest(API_BASE, area)
        .split_for_parts();
    router.with_state(state)
}

/// An authorizer that allows everything except the listed actions and records every
/// question.
struct Deny {
    actions: Vec<Action>,
    asked: Mutex<Vec<(Action, ObjectRef)>>,
}

impl Deny {
    fn new(actions: Vec<Action>) -> Arc<Self> {
        Arc::new(Self {
            actions,
            asked: Mutex::new(Vec::new()),
        })
    }

    fn asked(&self) -> Vec<(Action, ObjectRef)> {
        self.asked.lock().expect("lock").clone()
    }
}

impl Authorizer for Deny {
    fn check(
        &self,
        _principal: &Principal,
        action: Action,
        object: &ObjectRef,
    ) -> Result<(), Denied> {
        self.asked.lock().expect("lock").push((action, *object));
        if self.actions.contains(&action) {
            Err(Denied {
                action,
                object: *object,
                reason: DenyReason::MissingPermission,
            })
        } else {
            Ok(())
        }
    }

    fn scope(&self, _principal: &Principal, _action: Action, _kind: ObjectKind) -> ScopeFilter {
        ScopeFilter::All
    }
}

/// The routes over one IPAM service, with the network 192.0.2.0/24 in the default VRF.
struct Lab {
    router: Router,
    service: Arc<IpamService>,
}

/// A host with one interface and two addresses (one with a DNS name).
struct Server {
    host: String,
    interface: String,
    named: String,
    bare: String,
}

impl Lab {
    async fn new() -> Self {
        let store = Arc::new(MemStore::default()) as Arc<dyn Store>;
        let service = IpamService::with_direct_jobs(store).expect("service");
        let lab = Self {
            router: router(AppState::default()).layer(Extension(Arc::clone(&service))),
            service,
        };
        let input = PrefixInput {
            id: None,
            vrf: None,
            cidr: "192.0.2.0/24".parse().expect("cidr"),
            role: None,
            status: None,
            vlan: None,
            site: None,
            alarm: None,
            alloc: None,
            tags: BTreeSet::new(),
            custom: BTreeMap::new(),
            description: None,
        };
        lab.service
            .execute(
                &[IpamCommand::CreatePrefix(input)],
                &RequestCtx::system(SystemComponent::Api),
                &PlanOptions::default(),
            )
            .await
            .expect("the network");
        lab
    }

    /// The same service and store behind another router.
    fn checked_by(&self, authorizer: Arc<dyn Authorizer>) -> Self {
        let state = AppState {
            authorizer: Some(authorizer),
            ..AppState::default()
        };
        Self {
            router: router(state).layer(Extension(Arc::clone(&self.service))),
            service: Arc::clone(&self.service),
        }
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&Value>,
    ) -> Reply {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("{API_BASE}{path}"));
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let body = match body {
            Some(value) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        let response = self
            .router
            .clone()
            .oneshot(builder.body(body).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let text_of = |name| {
            response
                .headers()
                .get(name)
                .map(|value| value.to_str().expect("header text").to_owned())
        };
        let content_type = text_of(header::CONTENT_TYPE).unwrap_or_default();
        let etag = text_of(header::ETAG);
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        Reply {
            status,
            content_type,
            etag,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        }
    }

    async fn get(&self, path: &str) -> Reply {
        self.send("GET", path, &[], None).await
    }

    async fn post(&self, path: &str, body: &Value) -> Reply {
        self.send("POST", path, &[], Some(body)).await
    }

    /// `POST /hosts/{id}/decommission`.
    async fn decommission(&self, host: &str, body: &Value) -> Reply {
        self.post(&format!("/hosts/{host}/decommission"), body)
            .await
    }

    /// `POST /hosts/{id}/reinstate`.
    async fn reinstate(&self, host: &str) -> Reply {
        self.send("POST", &format!("/hosts/{host}/reinstate"), &[], None)
            .await
    }

    /// Creates a host with one interface `eth0` and returns the identifiers.
    async fn make_host(&self, n: usize) -> (String, String) {
        let body = json!({
            "name": label("host", n),
            "interfaces": [{ "name": "eth0", "mac": mac(n) }],
        });
        let reply = self.post("/hosts", &body).await;
        reply.assert_write(201);
        let host = reply.item_id();
        let interfaces = self.get(&format!("/hosts/{host}/interfaces")).await;
        interfaces.assert_json(200);
        (host, interfaces.ids().remove(0))
    }

    /// Assigns an address of 192.0.2.0/24 to an interface, with a DNS name when given.
    async fn make_address(&self, interface: &str, host_part: usize, name: Option<&str>) -> String {
        let mut body = json!({ "ip": ip4(host_part), "interface": interface });
        if let Some(name) = name {
            body["dns_name"] = json!(name);
        }
        let reply = self.post("/addresses", &body).await;
        reply.assert_write(201);
        reply.item_id()
    }

    /// A host `host-01` with the addresses 192.0.2.10 (named) and 192.0.2.11.
    async fn server(&self) -> Server {
        let (host, interface) = self.make_host(1).await;
        let named = self
            .make_address(&interface, 10, Some("app01.example.test"))
            .await;
        let bare = self.make_address(&interface, 11, None).await;
        Server {
            host,
            interface,
            named,
            bare,
        }
    }

    /// The address as the API shows it.
    async fn address(&self, id: &str) -> Value {
        let reply = self.get(&format!("/addresses/{id}")).await;
        reply.assert_json(200);
        reply.body
    }

    /// The host as the API shows it.
    async fn host(&self, id: &str) -> Value {
        let reply = self.get(&format!("/hosts/{id}")).await;
        reply.assert_json(200);
        reply.body
    }

    /// The actions of the audit records, oldest first.
    async fn audit_actions(&self) -> Vec<String> {
        let view = self
            .service
            .store()
            .read(ReadConsistency::Linearizable)
            .await
            .expect("view");
        view.scan_typed(&AUDIT, KeyRange::all(), usize::MAX, false)
            .expect("audit")
            .into_iter()
            .map(|(_, record, _): (_, AuditRecord, _)| record.draft.action.as_str().to_owned())
            .collect()
    }
}

fn count(actions: &[String], action: &str) -> usize {
    actions
        .iter()
        .filter(|each| each.as_str() == action)
        .count()
}

/// The identifiers of the hosts that a list path answers.
async fn ids_at(lab: &Lab, path: &str) -> Vec<String> {
    let reply = lab.get(path).await;
    reply.assert_json(200);
    reply.ids()
}

// ----- decommission ---------------------------------------------------------------------

#[tokio::test]
async fn a_decommission_answers_200_with_the_record_and_releases_the_addresses() {
    let lab = Lab::new().await;
    let server = lab.server().await;
    let reply = lab
        .decommission(
            &server.host,
            &json!({ "reason": "replaced by a new guest", "keep_dns": false }),
        )
        .await;
    reply.assert_write(200);
    assert_eq!(reply.item_id(), server.host);
    let record = &reply.item()["decommissioned"];
    assert_eq!(record["reason"], "replaced by a new guest");
    assert_eq!(record["kept_dns"], false);
    assert!(record["at"].is_string(), "{record}");
    let released = record["released"].as_array().expect("released");
    assert_eq!(released.len(), 2, "{record}");
    let find = |id: &str| {
        released
            .iter()
            .find(|each| each["address"] == id)
            .unwrap_or_else(|| panic!("{id} in {released:?}"))
    };
    assert_eq!(find(&server.named)["interface"], server.interface);
    assert_eq!(find(&server.named)["dns_name"], "app01.example.test");
    assert_eq!(find(&server.bare)["interface"], server.interface);
    assert_eq!(find(&server.bare)["dns_name"], Value::Null);

    // The addresses are unassigned and the named one lost its DNS name.
    let named = lab.address(&server.named).await;
    assert_eq!(named["interface"], Value::Null, "{named}");
    assert_eq!(named["dns_name"], Value::Null, "{named}");
    let bare = lab.address(&server.bare).await;
    assert_eq!(bare["interface"], Value::Null, "{bare}");
    assert_eq!(named["meta"]["deleted"], Value::Null);

    // The host reads as decommissioned and its etag is the one of the write.
    let read = lab.get(&format!("/hosts/{}", server.host)).await;
    read.assert_json(200);
    assert_eq!(read.body["decommissioned"], *record);
    assert_eq!(read.etag, reply.etag);
}

#[tokio::test]
async fn a_decommission_with_keep_dns_keeps_the_names() {
    let lab = Lab::new().await;
    let server = lab.server().await;
    let reply = lab
        .decommission(&server.host, &json!({ "keep_dns": true }))
        .await;
    reply.assert_write(200);
    let record = &reply.item()["decommissioned"];
    assert_eq!(record["kept_dns"], true);
    assert_eq!(record["reason"], Value::Null);
    let released = record["released"].as_array().expect("released");
    assert_eq!(released.len(), 2);
    assert!(
        released.iter().all(|each| each["dns_name"].is_null()),
        "{record}"
    );
    let named = lab.address(&server.named).await;
    assert_eq!(named["interface"], Value::Null);
    assert_eq!(named["dns_name"], "app01.example.test");
}

#[tokio::test]
async fn a_decommission_with_an_empty_body_uses_the_defaults() {
    let lab = Lab::new().await;
    let server = lab.server().await;
    let reply = lab.decommission(&server.host, &json!({})).await;
    reply.assert_write(200);
    let record = &reply.item()["decommissioned"];
    assert_eq!(record["kept_dns"], false);
    assert_eq!(record["reason"], Value::Null);
    assert_eq!(lab.address(&server.named).await["dns_name"], Value::Null);
}

#[tokio::test]
async fn a_decommission_with_a_bad_body_is_a_400_problem() {
    let lab = Lab::new().await;
    let server = lab.server().await;
    let too_long = lab
        .decommission(&server.host, &json!({ "reason": "x".repeat(1_025) }))
        .await;
    too_long.assert_problem(400, "ipam.validation");
    for body in [
        json!({ "reason": 5 }),
        json!({ "keep_dns": "yes" }),
        json!({ "colour": "red" }),
    ] {
        lab.decommission(&server.host, &body)
            .await
            .assert_problem(400, "sys.invalid_request");
    }
    lab.post(
        &format!("/hosts/{}/decommission?colour=red", server.host),
        &json!({}),
    )
    .await
    .assert_problem(400, "sys.invalid_query");
    assert_eq!(lab.host(&server.host).await["decommissioned"], Value::Null);
    assert_eq!(
        lab.address(&server.named).await["interface"],
        server.interface
    );
}

#[tokio::test]
async fn a_second_decommission_and_a_reinstatement_of_an_active_host_are_409_problems() {
    let lab = Lab::new().await;
    let server = lab.server().await;
    let reinstate = lab.reinstate(&server.host).await;
    reinstate.assert_problem(409, "ipam.host.not_decommissioned");
    assert_eq!(reinstate.body["params"]["host"], label("host", 1));

    lab.decommission(&server.host, &json!({}))
        .await
        .assert_write(200);
    let twice = lab.decommission(&server.host, &json!({})).await;
    twice.assert_problem(409, "ipam.host.decommissioned");
    assert_eq!(twice.body["params"]["host"], label("host", 1));
}

#[tokio::test]
async fn an_unknown_host_is_a_404_problem_and_a_bad_identifier_a_400() {
    let lab = Lab::new().await;
    let id = unknown_id();
    let decommission = lab.decommission(&id, &json!({})).await;
    decommission.assert_problem(404, "ipam.not_found");
    assert_eq!(decommission.body["params"]["id"], id);
    lab.reinstate(&id)
        .await
        .assert_problem(404, "ipam.not_found");
    lab.decommission("not-a-uuid", &json!({}))
        .await
        .assert_problem(400, "sys.invalid_request");
    lab.reinstate("not-a-uuid")
        .await
        .assert_problem(400, "sys.invalid_request");
}

#[tokio::test]
async fn a_deleted_host_cannot_be_decommissioned_or_reinstated() {
    let lab = Lab::new().await;
    let (host, _) = lab.make_host(1).await;
    lab.send("DELETE", &format!("/hosts/{host}"), &[], None)
        .await
        .assert_write(200);
    lab.decommission(&host, &json!({}))
        .await
        .assert_problem(409, "ipam.object_deleted");
    lab.reinstate(&host)
        .await
        .assert_problem(409, "ipam.object_deleted");
}

#[tokio::test]
async fn a_stale_if_match_is_a_412_problem_and_a_current_one_is_accepted() {
    let lab = Lab::new().await;
    let server = lab.server().await;
    let path = format!("/hosts/{}", server.host);
    let stale = lab.get(&path).await.etag.expect("etag");
    lab.send(
        "PATCH",
        &path,
        &[],
        Some(&json!({ "description": "moved to rack 2" })),
    )
    .await
    .assert_write(200);

    let refused = lab
        .send(
            "POST",
            &format!("{path}/decommission"),
            &[("if-match", &stale)],
            Some(&json!({})),
        )
        .await;
    refused.assert_problem(412, "ipam.revision_mismatch");
    assert_eq!(lab.host(&server.host).await["decommissioned"], Value::Null);

    let current = lab.get(&path).await.etag.expect("etag");
    let done = lab
        .send(
            "POST",
            &format!("{path}/decommission"),
            &[("if-match", &current)],
            Some(&json!({})),
        )
        .await;
    done.assert_write(200);

    // The same for the way back.
    let current = done.etag.clone().expect("etag");
    lab.send(
        "PATCH",
        &path,
        &[],
        Some(&json!({ "description": "again" })),
    )
    .await
    .assert_write(200);
    lab.send(
        "POST",
        &format!("{path}/reinstate"),
        &[("if-match", &current)],
        None,
    )
    .await
    .assert_problem(412, "ipam.revision_mismatch");
    let current = lab.get(&path).await.etag.expect("etag");
    lab.send(
        "POST",
        &format!("{path}/reinstate"),
        &[("if-match", &current)],
        None,
    )
    .await
    .assert_write(200);
}

#[tokio::test]
async fn a_dry_run_writes_nothing() {
    let lab = Lab::new().await;
    let server = lab.server().await;
    let revision = lab.get("/hosts").await.body["revision"].clone();
    let audit = lab.audit_actions().await.len();

    let dry = lab
        .post(
            &format!("/hosts/{}/decommission?dry_run=true", server.host),
            &json!({ "reason": "preview" }),
        )
        .await;
    dry.assert_dry_run();
    assert!(
        dry.item()["decommissioned"].is_object(),
        "the item as it would be: {}",
        dry.body
    );
    let lines = dry.summary_lines();
    assert!(!lines.is_empty(), "{lines:?}");
    let changes = dry.body["plan"]["changes"].as_array().expect("changes");
    assert_eq!(
        changes.len(),
        3,
        "the host and its two addresses: {changes:?}"
    );

    assert_eq!(lab.host(&server.host).await["decommissioned"], Value::Null);
    assert_eq!(
        lab.address(&server.named).await["interface"],
        server.interface
    );
    assert_eq!(lab.get("/hosts").await.body["revision"], revision);
    assert_eq!(lab.audit_actions().await.len(), audit);

    // And the dry run of a reinstatement.
    lab.decommission(&server.host, &json!({}))
        .await
        .assert_write(200);
    let dry = lab
        .send(
            "POST",
            &format!("/hosts/{}/reinstate?dry_run=true", server.host),
            &[],
            None,
        )
        .await;
    dry.assert_dry_run();
    assert!(
        lab.host(&server.host).await["decommissioned"].is_object(),
        "still decommissioned"
    );
    assert_eq!(lab.address(&server.bare).await["interface"], Value::Null);
}

// ----- the list filter ------------------------------------------------------------------

#[tokio::test]
async fn the_hosts_list_hides_a_decommissioned_host_unless_asked() {
    let lab = Lab::new().await;
    let (kept, _) = lab.make_host(1).await;
    let (gone, _) = lab.make_host(2).await;
    assert_eq!(
        ids_at(&lab, "/hosts").await,
        [kept.clone(), gone.clone()],
        "both are active"
    );
    lab.decommission(&gone, &json!({})).await.assert_write(200);

    assert_eq!(ids_at(&lab, "/hosts").await, [kept.as_str()]);
    assert_eq!(
        ids_at(&lab, "/hosts?lifecycle=active").await,
        [kept.as_str()]
    );
    assert_eq!(
        ids_at(&lab, "/hosts?lifecycle=decommissioned").await,
        [gone.as_str()]
    );
    assert_eq!(
        ids_at(&lab, "/hosts?lifecycle=all").await,
        [kept.clone(), gone.clone()]
    );
    // Other filters still apply.
    assert_eq!(
        ids_at(&lab, "/hosts?lifecycle=decommissioned&mode=static").await,
        [gone.as_str()]
    );
    lab.get("/hosts?lifecycle=decommissioned&mode=dynamic")
        .await
        .assert_json(200)
        .assert_no_items();
    // A decommissioned host is still there to read.
    lab.get(&format!("/hosts/{gone}")).await.assert_json(200);

    let bad = lab.get("/hosts?lifecycle=retired").await;
    bad.assert_problem(400, "sys.invalid_query");
    assert_eq!(bad.body["params"]["parameter"], "lifecycle");

    lab.reinstate(&gone).await.assert_write(200);
    assert_eq!(
        ids_at(&lab, "/hosts").await,
        [kept.clone(), gone.clone()],
        "back in the default list"
    );
    lab.get("/hosts?lifecycle=decommissioned")
        .await
        .assert_json(200)
        .assert_no_items();
}

// ----- reinstate ------------------------------------------------------------------------

#[tokio::test]
async fn a_reinstatement_binds_the_addresses_again_and_restores_the_names() {
    let lab = Lab::new().await;
    let server = lab.server().await;
    lab.decommission(&server.host, &json!({}))
        .await
        .assert_write(200);

    let reply = lab.reinstate(&server.host).await;
    reply.assert_write(200);
    assert_eq!(reply.item_id(), server.host);
    assert_eq!(reply.item()["decommissioned"], Value::Null);
    assert_eq!(reply.body["warnings"], json!([]));

    let named = lab.address(&server.named).await;
    assert_eq!(named["interface"], server.interface, "{named}");
    assert_eq!(named["dns_name"], "app01.example.test", "{named}");
    let bare = lab.address(&server.bare).await;
    assert_eq!(bare["interface"], server.interface, "{bare}");
    assert_eq!(bare["dns_name"], Value::Null);
}

#[tokio::test]
async fn a_reinstatement_warns_about_an_address_that_is_gone_or_taken() {
    let lab = Lab::new().await;
    let server = lab.server().await;
    let (_, other_interface) = lab.make_host(2).await;
    lab.decommission(&server.host, &json!({}))
        .await
        .assert_write(200);
    // Another host takes one address in the meantime and the other one is deleted.
    lab.send(
        "PATCH",
        &format!("/addresses/{}", server.named),
        &[],
        Some(&json!({ "interface": other_interface })),
    )
    .await
    .assert_write(200);
    lab.send("DELETE", &format!("/addresses/{}", server.bare), &[], None)
        .await
        .assert_write(200);

    let reply = lab.reinstate(&server.host).await;
    reply.assert_write(200);
    assert_eq!(reply.item()["decommissioned"], Value::Null);
    let warnings = reply.body["warnings"].as_array().expect("warnings");
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(
        warnings
            .iter()
            .all(|warning| warning["code"] == "ipam.host.reinstate_skipped"
                && warning["requires_ack"] == false),
        "{warnings:?}"
    );
    let cause = |address: &str| {
        warnings
            .iter()
            .find(|warning| warning["params"]["address"] == address)
            .map(|warning| warning["params"]["cause"].clone())
    };
    assert_eq!(cause(&server.named), Some(json!("assigned")));
    assert_eq!(cause(&server.bare), Some(json!("deleted")));
    let assigned = warnings
        .iter()
        .find(|warning| warning["params"]["address"] == server.named)
        .expect("warning");
    assert_eq!(assigned["params"]["ip"], "192.0.2.10");
    assert_eq!(
        lab.address(&server.named).await["interface"],
        other_interface,
        "the address stays where it went"
    );
}

// ----- rights and audit -----------------------------------------------------------------

#[tokio::test]
async fn deleting_the_host_is_the_right_both_routes_need() {
    let lab = Lab::new().await;
    let server = lab.server().await;
    // May update and create, may not delete.
    let guard = Deny::new(vec![Action::Delete]);
    let guarded = lab.checked_by(guard.clone());

    guarded
        .decommission(&server.host, &json!({}))
        .await
        .assert_problem(403, "auth.forbidden");
    guarded
        .reinstate(&server.host)
        .await
        .assert_problem(403, "auth.forbidden");
    assert_eq!(
        guard.asked(),
        [
            (
                Action::Delete,
                ObjectRef::from(server.host.parse::<tenko_core::HostId>().expect("id"))
            ),
            (
                Action::Delete,
                ObjectRef::from(server.host.parse::<tenko_core::HostId>().expect("id"))
            ),
        ]
    );
    assert_eq!(lab.host(&server.host).await["decommissioned"], Value::Null);
    assert_eq!(
        lab.address(&server.named).await["interface"],
        server.interface,
        "nothing was changed"
    );

    // A principal that may delete but not update decommissions: it is the delete right.
    let deleter = lab.checked_by(Deny::new(vec![Action::Update, Action::Create]));
    deleter
        .decommission(&server.host, &json!({}))
        .await
        .assert_write(200);
    // A refused reinstatement leaves the host decommissioned.
    guarded
        .reinstate(&server.host)
        .await
        .assert_problem(403, "auth.forbidden");
    assert!(lab.host(&server.host).await["decommissioned"].is_object());
    deleter.reinstate(&server.host).await.assert_write(200);
}

#[tokio::test]
async fn the_audit_records_the_lifecycle_actions_beside_the_address_updates() {
    let lab = Lab::new().await;
    let server = lab.server().await;
    let before = lab.audit_actions().await;
    assert_eq!(count(&before, "ipam.host.decommission"), 0);

    lab.decommission(&server.host, &json!({}))
        .await
        .assert_write(200);
    let after = lab.audit_actions().await;
    assert_eq!(count(&after, "ipam.host.decommission"), 1, "{after:?}");
    assert_eq!(
        count(&after, "ipam.address.update") - count(&before, "ipam.address.update"),
        2,
        "the address changes stay address updates: {after:?}"
    );
    assert_eq!(count(&after, "ipam.host.reinstate"), 0);

    lab.reinstate(&server.host).await.assert_write(200);
    let end = lab.audit_actions().await;
    assert_eq!(count(&end, "ipam.host.decommission"), 1, "{end:?}");
    assert_eq!(count(&end, "ipam.host.reinstate"), 1, "{end:?}");
    assert_eq!(
        count(&end, "ipam.address.update") - count(&after, "ipam.address.update"),
        2,
        "{end:?}"
    );
}

// ----- bulk -----------------------------------------------------------------------------

#[tokio::test]
async fn a_bulk_change_decommissions_and_reinstates_hosts() {
    let lab = Lab::new().await;
    let server = lab.server().await;
    let (second, second_interface) = lab.make_host(2).await;
    let second_address = lab.make_address(&second_interface, 20, None).await;

    let reply = lab
        .post(
            "/hosts/bulk",
            &json!({ "operations": [
                { "op": "decommission_host", "args": { "host": server.host, "reason": "bulk" } },
                { "op": "decommission_host", "args": { "host": second, "keep_dns": true } },
            ] }),
        )
        .await;
    reply.assert_json(200);
    assert_eq!(reply.body["dry_run"], false, "{}", reply.body);
    let results = reply.body["results"].as_array().expect("results");
    assert_eq!(results.len(), 2, "{}", reply.body);
    assert_eq!(results[0]["id"], server.host);
    assert_eq!(results[1]["id"], second);
    for host in [&server.host, &second] {
        assert!(lab.host(host).await["decommissioned"].is_object());
    }
    assert_eq!(lab.address(&server.named).await["interface"], Value::Null);
    assert_eq!(lab.address(&second_address).await["interface"], Value::Null);
    assert_eq!(
        lab.host(&server.host).await["decommissioned"]["reason"],
        "bulk"
    );
    assert_eq!(lab.host(&second).await["decommissioned"]["kept_dns"], true);

    let back = lab
        .post(
            "/hosts/bulk",
            &json!({ "operations": [
                { "op": "reinstate_host", "args": { "host": server.host } },
                { "op": "reinstate_host", "args": { "host": second } },
            ] }),
        )
        .await;
    back.assert_json(200);
    assert_eq!(back.body["warnings"], json!([]));
    for host in [&server.host, &second] {
        assert_eq!(lab.host(host).await["decommissioned"], Value::Null);
    }
    assert_eq!(
        lab.address(&server.named).await["interface"],
        server.interface
    );
    assert_eq!(
        lab.address(&second_address).await["interface"],
        second_interface
    );
}

#[tokio::test]
async fn a_bulk_change_is_all_or_nothing() {
    let lab = Lab::new().await;
    let server = lab.server().await;
    // The second operation fails (the host is decommissioned by the first), so the first
    // does not apply either.
    let reply = lab
        .post(
            "/hosts/bulk",
            &json!({ "operations": [
                { "op": "decommission_host", "args": { "host": server.host } },
                { "op": "decommission_host", "args": { "host": server.host } },
            ] }),
        )
        .await;
    reply.assert_problem(409, "ipam.host.decommissioned");
    assert_eq!(lab.host(&server.host).await["decommissioned"], Value::Null);
    assert_eq!(
        lab.address(&server.named).await["interface"],
        server.interface
    );
}

#[tokio::test]
async fn a_bulk_decommission_needs_the_right_to_delete_the_host() {
    let lab = Lab::new().await;
    let server = lab.server().await;
    let guard = Deny::new(vec![Action::Delete]);
    let guarded = lab.checked_by(guard.clone());
    for operation in [
        json!({ "op": "decommission_host", "args": { "host": server.host } }),
        json!({ "op": "reinstate_host", "args": { "host": server.host } }),
    ] {
        guarded
            .post("/hosts/bulk", &json!({ "operations": [operation] }))
            .await
            .assert_problem(403, "auth.forbidden");
    }
    assert!(
        guard
            .asked()
            .iter()
            .all(|(action, _)| *action == Action::Delete),
        "{:?}",
        guard.asked()
    );
    assert_eq!(lab.host(&server.host).await["decommissioned"], Value::Null);

    // Allowed to delete: the same request works.
    let allowed = lab.checked_by(Deny::new(vec![Action::Update]));
    allowed
        .post(
            "/hosts/bulk",
            &json!({ "operations": [
                { "op": "decommission_host", "args": { "host": server.host } },
            ] }),
        )
        .await
        .assert_json(200);
    assert!(lab.host(&server.host).await["decommissioned"].is_object());
}
