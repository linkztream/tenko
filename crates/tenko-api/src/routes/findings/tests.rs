//! Tests of the findings routes: the counts equal the open proposals of the Discovery
//! list, a change of a source reaches the index and the live topic, the filters and paging,
//! and a principal sees only the findings whose source it may read.

use std::{sync::Arc, time::Duration};

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::Request,
};
use futures::StreamExt;
use serde_json::Value;
use tenko_core::{
    Action, AuthStrength, Authorizer, ConnectorId, Denied, DenyReason, ObjectKind, ObjectRef,
    ObservationId, Principal, RequestCtx, ScopeFilter, SessionId, SystemComponent, Timestamp,
    UserId,
    observe::{Observation, ObservationSource, Observed, ObservedHost},
};
use tenko_ipam::{
    IpamCommand, IpamService, PlanOptions,
    command::PrefixInput,
    findings::FindingsConfig,
    observe::IngestBatch,
    proposals,
    reconcile::{Reconciler, ReconcilerConfig},
};
use tenko_store::Store;
use tokio::sync::watch;
use tower::ServiceExt;
use utoipa_axum::router::OpenApiRouter;

use crate::{API_BASE, dto::events::TopicSet, findings::FindingsService, state::AppState};

/// The findings and proposals routes over one IPAM service, one reconciler and one findings
/// service, with the network 192.0.2.0/24.
struct Lab {
    store: Arc<dyn Store>,
    state: AppState,
    service: Arc<IpamService>,
    reconciler: Arc<Reconciler>,
    findings: Arc<FindingsService>,
    connector: ConnectorId,
    _stop: watch::Sender<bool>,
}

fn person() -> RequestCtx {
    RequestCtx::new(Principal::User {
        id: UserId::generate(),
        session: SessionId::generate(),
        strength: AuthStrength::Passkey,
    })
}

fn device(id: &str, mac: &str, ip: &str) -> ObservedHost {
    ObservedHost {
        external_id: id.to_owned(),
        name: Some(format!("vm{id}")),
        name_placeholder: false,
        macs: vec![mac.parse().expect("mac")],
        ips: vec![ip.parse().expect("ip")],
        os: None,
        platform: None,
        parent: None,
        tags: Vec::new(),
        power: None,
    }
}

impl Lab {
    async fn new() -> Self {
        Self::with(AppState::default()).await
    }

    async fn with(state: AppState) -> Self {
        let store = Arc::clone(&state.store);
        let service = IpamService::with_direct_jobs(Arc::clone(&store)).expect("service");
        let reconciler =
            Reconciler::new(Arc::clone(&service), ReconcilerConfig::default()).expect("reconciler");
        let findings = FindingsService::new(
            Arc::clone(&store),
            FindingsConfig::default(),
            true,
            state.events().clone(),
        );
        let (stop, stopped) = watch::channel(false);
        findings.spawn(stopped);
        let lab = Self {
            store,
            state,
            service,
            reconciler,
            findings,
            connector: ConnectorId::generate(),
            _stop: stop,
        };
        lab.service
            .execute(
                &[IpamCommand::CreatePrefix(
                    serde_json::from_value::<PrefixInput>(serde_json::json!({
                        "cidr": "192.0.2.0/24",
                        "role": "network",
                    }))
                    .expect("prefix"),
                )],
                &person(),
                &PlanOptions::default(),
            )
            .await
            .expect("prefix");
        lab
    }

    fn router(&self) -> Router {
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(
                API_BASE,
                super::routes().merge(super::super::proposals::routes()),
            )
            .split_for_parts();
        router
            .with_state(self.state.clone())
            .layer(Extension(Arc::clone(&self.service)))
            .layer(Extension(Arc::clone(&self.reconciler)))
            .layer(Extension(Arc::clone(&self.findings)))
    }

    async fn get(&self, path: &str) -> (u16, Value) {
        let response = self
            .router()
            .oneshot(
                Request::builder()
                    .uri(format!("{API_BASE}{path}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

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
        self.reconciler
            .reconcile(Timestamp::now())
            .await
            .expect("reconcile");
    }

    /// Waits until the index has applied the store's newest revision.
    async fn settle(&self) {
        let newest = self.store.status().revision;
        for _ in 0..500 {
            if self.findings.index().revision() >= newest {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the findings index did not reach revision {newest}");
    }
}

/// IPAM-15: the Discovery badge and the Discovery list count the same.
#[tokio::test]
async fn the_counts_equal_the_open_proposals_of_the_discovery_list() {
    let lab = Lab::new().await;
    lab.poll(vec![
        device("1", "00:00:5e:00:53:01", "192.0.2.11"),
        device("2", "00:00:5e:00:53:02", "192.0.2.12"),
        device("3", "00:00:5e:00:53:03", "192.0.2.13"),
    ])
    .await;
    lab.settle().await;
    let (status, open) = lab.get("/proposals?state=open").await;
    assert_eq!(status, 200, "{open}");
    let discovery = open["items"].as_array().expect("items").len();
    assert_eq!(discovery, 3);
    let (status, counts) = lab.get("/findings/counts").await;
    assert_eq!(status, 200, "{counts}");
    assert_eq!(counts["sources"]["proposal"], discovery);
    let area = &counts["areas"]["discovery"];
    assert_eq!(
        area["act"].as_u64().expect("act") + area["review"].as_u64().expect("review"),
        u64::try_from(discovery).expect("count"),
        "the Discovery badge counts what the Discovery list shows: {counts}"
    );
    assert_eq!(counts["problems"], discovery);

    // The list, filtered and paged; one finding by its identifier.
    let (status, page) = lab.get("/findings?source=proposal&limit=2").await;
    assert_eq!(status, 200, "{page}");
    assert_eq!(page["items"].as_array().expect("items").len(), 2);
    let cursor = page["next_cursor"].as_str().expect("cursor").to_owned();
    let (_, rest) = lab
        .get(&format!(
            "/findings?source=proposal&limit=2&cursor={cursor}"
        ))
        .await;
    assert_eq!(rest["items"].as_array().expect("items").len(), 1);
    let first = page["items"][0].clone();
    assert_eq!(first["kind"], "unknown_device");
    assert_eq!(first["severity"], "review");
    assert_eq!(first["action"], "adopt");
    assert_eq!(first["area"], "discovery");
    let id = first["id"].as_str().expect("id");
    let (status, one) = lab.get(&format!("/findings/{id}")).await;
    assert_eq!(status, 200);
    assert_eq!(one, first);
    let (status, missing) = lab.get("/findings/proposal:nothing").await;
    assert_eq!(status, 404);
    assert_eq!(missing["code"], "findings.not_found");
    let (status, _) = lab.get("/findings?q=192.0.2.12").await;
    assert_eq!(status, 200);
    let (_, by_text) = lab.get("/findings?q=192.0.2.12").await;
    assert_eq!(by_text["items"].as_array().expect("items").len(), 1);
    let (status, bad) = lab.get("/findings?severity=urgent").await;
    assert_eq!(status, 400, "{bad}");
    let (status, bad) = lab.get("/findings?colour=red").await;
    assert_eq!(status, 400, "{bad}");
}

/// IPAM-15, API-05: a decision reaches the index and the topic `findings`.
#[tokio::test]
async fn a_decision_on_a_proposal_reaches_the_counts_and_the_findings_topic() {
    let lab = Lab::new().await;
    lab.poll(vec![
        device("1", "00:00:5e:00:53:01", "192.0.2.11"),
        device("2", "00:00:5e:00:53:02", "192.0.2.12"),
    ])
    .await;
    lab.settle().await;
    let (_, open) = lab.get("/proposals?state=open").await;
    let id: tenko_core::ProposalId =
        serde_json::from_value(open["items"][0]["id"].clone()).expect("id");
    let mut stream = Box::pin(
        crate::sse::event_stream(
            lab.state.events(),
            lab.store.as_ref(),
            None,
            TopicSet::parse("findings").expect("topics"),
            Principal::system(SystemComponent::Api),
        )
        .await,
    );
    proposals::reject(&lab.service, id, None, &person(), None)
        .await
        .expect("reject");
    let frame = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let bytes = stream.next().await.expect("open").expect("frame");
            let text = String::from_utf8_lossy(&bytes).into_owned();
            if text.contains(&id.to_string()) {
                return text;
            }
        }
    })
    .await
    .expect("a findings event names the proposal");
    assert!(frame.starts_with("event: findings\n"), "{frame}");
    assert!(frame.contains("findings.changed"), "{frame}");
    // The event goes out after the index applied the change: a read now sees it.
    let (_, counts) = lab.get("/findings/counts").await;
    assert_eq!(counts["sources"]["proposal"], 1, "{counts}");
}

/// Allows everything except reading proposals or the system: an authorizer that
/// answers no scope for those kinds.
struct NoProposals;

impl Authorizer for NoProposals {
    fn check(
        &self,
        _principal: &Principal,
        action: Action,
        object: &ObjectRef,
    ) -> Result<(), Denied> {
        match object.kind {
            ObjectKind::Proposal | ObjectKind::System => Err(Denied {
                action,
                object: *object,
                reason: DenyReason::MissingPermission,
            }),
            _ => Ok(()),
        }
    }

    fn scope(&self, _principal: &Principal, _action: Action, kind: ObjectKind) -> ScopeFilter {
        match kind {
            ObjectKind::Proposal | ObjectKind::System => ScopeFilter::Nothing,
            _ => ScopeFilter::All,
        }
    }
}

/// IAM-01: the findings follow the read rights of their sources.
#[tokio::test]
async fn a_principal_counts_only_the_findings_whose_source_it_may_read() {
    let lab = Lab::with(AppState {
        authorizer: Some(Arc::new(NoProposals)),
        ..AppState::default()
    })
    .await;
    lab.poll(vec![device("1", "00:00:5e:00:53:01", "192.0.2.11")])
        .await;
    lab.settle().await;
    assert_eq!(lab.findings.index().counts().sources.proposal, 1);
    let (status, counts) = lab.get("/findings/counts").await;
    assert_eq!(status, 200, "{counts}");
    assert_eq!(counts["sources"]["proposal"], 0, "{counts}");
    let (_, page) = lab.get("/findings?source=proposal").await;
    assert_eq!(page["items"], Value::Array(Vec::new()));
}

#[tokio::test]
async fn without_the_service_the_routes_answer_unavailable() {
    let (router, _) = OpenApiRouter::<AppState>::new()
        .nest(API_BASE, super::routes())
        .split_for_parts();
    let response = router
        .with_state(AppState::default())
        .oneshot(
            Request::builder()
                .uri(format!("{API_BASE}/findings/counts"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status().as_u16(), 503);
}
