//! Route tests of "keep both": the proposals the reconciler opens for two guests on one
//! address, kept as intended through `POST /proposals/{id}/keep`. Test data lives in the
//! documentation ranges (`192.0.2.0/24`, MACs `00-00-5E-00-53-xx`).

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{Request, header},
};
use serde_json::{Value, json};
use tenko_core::{
    Action, Authorizer, ConnectorId, Denied, DenyReason, ObjectKind, ObjectRef, ObservationId,
    Principal, RequestCtx, ScopeFilter, SystemComponent, Timestamp,
    audit::AuditRecord,
    observe::{Observation, ObservationSource, Observed, ObservedHost, PowerState},
};
use tenko_ipam::{
    IpamCommand, IpamService, PlanOptions,
    command::PrefixInput,
    observe::IngestBatch,
    reconcile::{ReconcileReport, Reconciler, ReconcilerConfig},
};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadViewExt, Store, tables::AUDIT};
use tower::ServiceExt;
use utoipa_axum::router::OpenApiRouter;

use super::super::{proposals, tenancy::testkit::Reply};
use crate::{API_BASE, state::AppState};

const TWIN_A_MAC: &str = "00-00-5E-00-53-41";
const TWIN_B_MAC: &str = "00-00-5E-00-53-42";
const WEB_MAC: &str = "00-00-5E-00-53-01";

/// The routes of the proposals area and of the keep route, over `state`.
fn router(state: AppState) -> Router {
    let (router, _) = OpenApiRouter::<AppState>::new()
        .nest(API_BASE, proposals::routes().merge(super::routes()))
        .split_for_parts();
    router.with_state(state)
}

/// An authorizer that allows everything except the listed actions and records every
/// question.
struct Deny {
    actions: Vec<Action>,
    asked: Mutex<Vec<(Action, ObjectRef)>>,
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

/// The proposals routes over one IPAM service and one reconciler, with the network
/// 192.0.2.0/24 in the default VRF.
struct Lab {
    router: Router,
    service: Arc<IpamService>,
    reconciler: Arc<Reconciler>,
    connector: ConnectorId,
}

/// An inventory guest with a MAC address and an address, in a power state.
fn guest(id: &str, mac: &str, ip: &str, power: PowerState) -> ObservedHost {
    ObservedHost {
        external_id: id.to_owned(),
        name: Some(id.to_owned()),
        macs: vec![mac.parse().expect("mac")],
        ips: vec![ip.parse().expect("ip")],
        os: Some("Linux 6.x".to_owned()),
        platform: Some("qemu".to_owned()),
        parent: Some("pve1".to_owned()),
        tags: Vec::new(),
        power: Some(power),
    }
}

impl Lab {
    async fn new() -> Self {
        let store = Arc::new(MemStore::default()) as Arc<dyn Store>;
        let service = IpamService::with_direct_jobs(store).expect("service");
        let reconciler =
            Reconciler::new(Arc::clone(&service), ReconcilerConfig::default()).expect("reconciler");
        let lab = Self {
            router: Router::new(),
            service,
            reconciler,
            connector: ConnectorId::generate(),
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
        lab.behind(AppState::default())
    }

    /// The same service and reconciler behind a router with `state`.
    fn behind(self, state: AppState) -> Self {
        Self {
            router: router(state)
                .layer(Extension(Arc::clone(&self.service)))
                .layer(Extension(Arc::clone(&self.reconciler))),
            ..self
        }
    }

    /// The same lab with `actions` denied to every request.
    fn denying(&self, actions: Vec<Action>) -> (Self, Arc<Deny>) {
        let deny = Arc::new(Deny {
            actions,
            asked: Mutex::new(Vec::new()),
        });
        let lab = Self {
            router: Router::new(),
            service: Arc::clone(&self.service),
            reconciler: Arc::clone(&self.reconciler),
            connector: self.connector,
        }
        .behind(AppState {
            authorizer: Some(Arc::clone(&deny) as Arc<dyn Authorizer>),
            ..AppState::default()
        });
        (lab, deny)
    }

    /// One complete inventory poll of the connector, seen now.
    async fn poll(&self, hosts: Vec<ObservedHost>) {
        let when = Timestamp::now();
        let source = ObservationSource::Inventory {
            connector: self.connector,
        };
        let observations = hosts
            .into_iter()
            .map(|host| Observation {
                id: ObservationId::generate(),
                source: source.clone(),
                subject: Observed::Host(host),
                observed_at: when,
                received_at: when,
                expires_at: when.checked_add(Duration::from_secs(900)),
            })
            .collect();
        self.reconciler
            .ingest(IngestBatch {
                source,
                observations,
                complete: true,
                received_at: when,
            })
            .await
            .expect("ingest");
    }

    /// A run of the reconciler, now.
    async fn reconcile(&self) -> ReconcileReport {
        self.reconciler
            .reconcile(Timestamp::now())
            .await
            .expect("reconcile")
    }

    /// Two running guests on 192.0.2.40 and one run: the identifier of the conflict.
    async fn twins(&self) -> String {
        self.poll(vec![
            guest("twin-a", TWIN_A_MAC, "192.0.2.40", PowerState::Running),
            guest("twin-b", TWIN_B_MAC, "192.0.2.40", PowerState::Running),
        ])
        .await;
        self.reconcile().await;
        let list = self.get("/proposals?state=open&kind=conflict").await;
        list.assert_json(200);
        assert_eq!(list.items().len(), 1, "{}", list.body);
        assert_eq!(
            list.items()[0]["rule"],
            "ipam.reconcile.conflict_shared_address"
        );
        list.ids().remove(0)
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

    /// `POST /proposals/{id}/keep` with a body.
    async fn keep(&self, id: &str, body: &Value) -> Reply {
        self.send("POST", &format!("/proposals/{id}/keep"), &[], Some(body))
            .await
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

#[tokio::test]
async fn keeping_a_shared_address_conflict_closes_it_as_rejected_and_audits_the_keep() {
    let lab = Lab::new().await;
    let id = lab.twins().await;
    let reply = lab.keep(&id, &json!({ "reason": "fallback guest" })).await;
    reply.assert_json(200);
    let body = &reply.body;
    assert_eq!(body["proposal"]["id"], id, "{body}");
    assert_eq!(body["proposal"]["state"], "rejected", "{body}");
    assert_eq!(body["proposal"]["reason"], "fallback guest", "{body}");
    assert_eq!(body["dry_run"], false);
    assert!(body["revision"].as_u64().is_some(), "{body}");
    assert!(body["job_id"].is_string(), "{body}");
    let revision = body["proposal"]["revision"].as_u64().expect("revision");
    assert_eq!(
        reply.etag.as_deref(),
        Some(format!("\"{revision}\"").as_str())
    );

    let read = lab.get(&format!("/proposals/{id}")).await;
    read.assert_json(200);
    assert_eq!(read.body["state"], "rejected");
    assert_eq!(read.etag, reply.etag);
    lab.get("/proposals?state=open&kind=conflict")
        .await
        .assert_json(200)
        .assert_no_items();

    let actions = lab.audit_actions().await;
    assert_eq!(
        actions
            .iter()
            .filter(|action| action.as_str() == "ipam.proposal.keep")
            .count(),
        1,
        "{actions:?}"
    );
    assert!(
        !actions
            .iter()
            .any(|action| action == "ipam.proposal.reject"),
        "{actions:?}"
    );

    // The exception holds: the same two devices raise it no more.
    let report = lab.reconcile().await;
    assert_eq!((report.opened, report.suppressed), (0, 1), "{report:?}");
    lab.get("/proposals?state=open&kind=conflict")
        .await
        .assert_json(200)
        .assert_no_items();
}

#[tokio::test]
async fn a_body_without_a_reason_keeps_the_conflict_too() {
    let lab = Lab::new().await;
    let id = lab.twins().await;
    let reply = lab.keep(&id, &json!({})).await;
    reply.assert_json(200);
    assert_eq!(reply.body["proposal"]["state"], "rejected");
    assert_eq!(reply.body["proposal"]["reason"], Value::Null);
}

#[tokio::test]
async fn a_proposal_that_is_not_an_address_conflict_cannot_be_kept() {
    let lab = Lab::new().await;
    lab.poll(vec![guest(
        "web01",
        WEB_MAC,
        "192.0.2.10",
        PowerState::Running,
    )])
    .await;
    lab.reconcile().await;
    let list = lab.get("/proposals?state=open&kind=discovered_host").await;
    assert_eq!(list.items().len(), 1, "{}", list.body);
    let id = list.ids().remove(0);

    let reply = lab.keep(&id, &json!({})).await;
    reply.assert_problem(409, "ipam.proposal.not_keepable");
    assert_eq!(reply.body["params"]["id"], id);
    assert_eq!(
        reply.body["params"]["rule"],
        "ipam.reconcile.discovered_mac"
    );
    let read = lab.get(&format!("/proposals/{id}")).await;
    assert_eq!(read.body["state"], "open", "it stays open");
}

#[tokio::test]
async fn a_conflict_that_is_decided_already_is_a_409_and_an_unknown_proposal_a_404() {
    let lab = Lab::new().await;
    let id = lab.twins().await;
    lab.keep(&id, &json!({})).await.assert_json(200);
    lab.keep(&id, &json!({}))
        .await
        .assert_problem(409, "ipam.proposal.not_open");
    lab.keep(&tenko_core::ProposalId::generate().to_string(), &json!({}))
        .await
        .assert_problem(404, "ipam.proposal.not_found");
    lab.keep("not-a-uuid", &json!({}))
        .await
        .assert_problem(400, "sys.invalid_request");
}

#[tokio::test]
async fn a_stale_if_match_is_a_412_and_a_current_one_is_accepted() {
    let lab = Lab::new().await;
    let id = lab.twins().await;
    let path = format!("/proposals/{id}/keep");
    lab.send("POST", &path, &[("if-match", "\"1\"")], Some(&json!({})))
        .await
        .assert_problem(412, "ipam.proposal.revision_mismatch");
    assert_eq!(
        lab.get(&format!("/proposals/{id}")).await.body["state"],
        "open"
    );
    let current = lab
        .get(&format!("/proposals/{id}"))
        .await
        .etag
        .expect("etag");
    lab.send("POST", &path, &[("if-match", &current)], Some(&json!({})))
        .await
        .assert_json(200);
}

#[tokio::test]
async fn a_bad_reason_or_body_is_a_400_problem() {
    let lab = Lab::new().await;
    let id = lab.twins().await;
    lab.keep(&id, &json!({ "reason": "x".repeat(1_025) }))
        .await
        .assert_problem(400, "ipam.validation");
    lab.keep(&id, &json!({ "reason": 5 }))
        .await
        .assert_problem(400, "sys.invalid_request");
    lab.send(
        "POST",
        &format!("/proposals/{id}/keep?colour=red"),
        &[],
        Some(&json!({})),
    )
    .await
    .assert_problem(400, "sys.invalid_query");
    assert_eq!(
        lab.get(&format!("/proposals/{id}")).await.body["state"],
        "open"
    );
}

#[tokio::test]
async fn keeping_needs_the_right_to_approve_proposals() {
    let lab = Lab::new().await;
    let id = lab.twins().await;
    let (denied, deny) = lab.denying(vec![Action::Approve]);
    denied
        .keep(&id, &json!({}))
        .await
        .assert_problem(403, "auth.forbidden");
    let asked = deny.asked.lock().expect("lock").clone();
    assert_eq!(
        asked,
        [(
            Action::Approve,
            ObjectRef::from(id.parse::<tenko_core::ProposalId>().expect("id"))
        )]
    );
    assert_eq!(
        lab.get(&format!("/proposals/{id}")).await.body["state"],
        "open",
        "nothing changed"
    );

    // Approving is the right, and no other: a principal that may do the rest may keep.
    let (allowed, _) = lab.denying(vec![Action::Delete, Action::Update, Action::Create]);
    allowed.keep(&id, &json!({})).await.assert_json(200);
}

#[tokio::test]
async fn a_stopped_guest_on_the_address_raises_nothing_to_keep() {
    let lab = Lab::new().await;
    lab.poll(vec![
        guest("twin-a", TWIN_A_MAC, "192.0.2.40", PowerState::Running),
        guest("twin-b", TWIN_B_MAC, "192.0.2.40", PowerState::Stopped),
    ])
    .await;
    lab.reconcile().await;
    lab.get("/proposals?kind=conflict")
        .await
        .assert_json(200)
        .assert_no_items();
}
