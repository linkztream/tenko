//! Observations: what the sources see, read-only.
//!
//! Area: observations. Owner: WP2.4. Requirements: IPAM-12, IPAM-13, IPAM-17.
//!
//! The observation layer keeps what connectors, probes and (later) the DNS and DHCP engines
//! report apart from intent (ADR 0005 decision 2). One source's knowledge of one subject is
//! a **fact**; facts of different sources are never merged. These endpoints list the facts
//! and compute the picture of one subject across sources. Nothing here writes: observations
//! reach intent only through proposals ([`super::proposals`]).
//!
//! [`super::common`] documents the conventions every IPAM endpoint follows: the IPAM service
//! as a request extension (503 `ipam.unavailable` without it), the list parameters, and the
//! authorization checks.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /observations` | 200 page of facts | 400 `sys.invalid_query`, `sys.invalid_cursor`, 503 |
//! | `GET /observations/{subject}` | 200 subject view | 400 `ipam.validation`, 403, 404 `ipam.not_found`, 503 |
//!
//! # The list
//!
//! `GET /observations` takes the filters `source` (a source key such as
//! `inventory:<connector>`, or a connector identifier, which matches the inventory and the
//! network controller source of that connector), `type` (`host`, `address`, `attachment`,
//! `services`, `os` or `link`), `mac`, `ip`, `within` (a network: facts that name an
//! address inside it), `q` (text over the subject, name, OS, platform, parent, tags and
//! attachment device), `current` (`true`: only facts that count as current now, `false`:
//! only expired ones) and `sort` (`last_seen`, `first_seen`, `source`, `subject`; `-` in
//! front for descending; `-last_seen` by default). The answer is a page of facts; the cursor
//! is bound to the query like every other list.
//!
//! # One subject
//!
//! `GET /observations/{subject}` names a MAC address (`00-00-5E-00-53-01` or
//! `00:00:5e:00:53:01`), an IP address or a name (compared without case). The answer lists
//! every fact that names the subject, the picture across sources (MAC addresses, IP
//! addresses, names, operating systems, attachments, open ports), the intent objects that
//! match and the last sightings of the matching addresses and interfaces. A subject that no
//! fact names is a 404 `ipam.not_found`; one that cannot be a subject (empty, with control
//! characters, over 253 characters) is a 400 `ipam.validation`.
//!
//! # Authorization
//!
//! With an [`Authorizer`](tenko_core::Authorizer) in the state, a list is empty when the
//! principal may not read observations at all, and a subject needs [`Action::Read`] on the
//! kind (403 otherwise).

use std::net::IpAddr;

use axum::{Json, extract::State};
use tenko_core::{Action, MacAddr, ObjectKind, Revision, Timestamp};
use tenko_ipam::observe::{
    ObservedFact,
    view::{FactQuery, SORTS, SubjectQuery, SubjectView, list_facts, subject_view},
};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::common::{Ipam, IpamPath, ReadParams, authorize, may_read_kind, new_of};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{Filters, PageParams, SortKey, encode_cursor},
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// The routes of the area.
pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_observations))
        .routes(routes!(get_observation))
}

/// The subject types a fact can have (`FactSubject::type_name`).
const SUBJECT_TYPES: [&str; 6] = ["host", "address", "attachment", "services", "os", "link"];

/// The `type` filter, or 400 `sys.invalid_query` for an unknown type.
fn subject_type(filters: &Filters) -> Result<Option<String>, ApiError> {
    filters
        .get("type")?
        .map(|raw| {
            let lower = raw.to_ascii_lowercase();
            if SUBJECT_TYPES.contains(&lower.as_str()) {
                Ok(lower)
            } else {
                Err(ApiError::invalid_query(
                    "type",
                    format!(
                        "`{raw}` is not a subject type; allowed: {}",
                        SUBJECT_TYPES.join(", ")
                    ),
                ))
            }
        })
        .transpose()
}

/// Lists facts, newest sighting first unless `sort` says otherwise.
#[utoipa::path(
    get,
    path = "/observations",
    tag = "observations",
    operation_id = "list_observations",
    summary = "List observed facts",
    params(
        PageParams,
        ("source" = Option<String>, Query, description = "Only facts of this source: a source key such as `inventory:<connector>`, or a connector identifier (which matches the inventory and the network controller source of the connector)."),
        ("type" = Option<String>, Query, description = "Only facts about this kind of subject: `host`, `address`, `attachment`, `services`, `os` or `link`."),
        ("mac" = Option<String>, Query, description = "Only facts that name this MAC address (`00-00-5E-00-53-01` or `00:00:5e:00:53:01`)."),
        ("ip" = Option<String>, Query, description = "Only facts that name this IP address."),
        ("within" = Option<String>, Query, description = "Only facts that name an IP address inside this network, such as `192.0.2.0/24`."),
        ("q" = Option<String>, Query, description = "Case-insensitive text search over the subject, the name, the operating system, the platform, the parent, the tags and the attachment device."),
        ("current" = Option<bool>, Query, description = "`true`: only facts that count as current now; `false`: only expired facts."),
        ("sort" = Option<String>, Query, description = "Sort order: comma-separated fields, `-` in front for descending. Fields: `last_seen` (the default, newest first), `first_seen`, `source`, `subject`.")
    ),
    responses(
        (status = 200, description = "A page of facts", body = Page<ObservedFact>),
        (status = 400, description = "Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_observations(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
) -> Result<Json<Page<ObservedFact>>, ApiError> {
    filters.only(&[
        "source", "type", "mac", "ip", "within", "q", "current", "sort",
    ])?;
    let page = filters.page()?;
    let scope = filters.scope("ipam.obs.facts");
    let query = FactQuery {
        source: filters.get("source")?.map(str::to_owned),
        subject_type: subject_type(&filters)?,
        mac: filters.parse::<MacAddr>("mac")?,
        ip: filters.parse::<IpAddr>("ip")?,
        within: filters.cidr("within")?,
        q: filters.get("q")?.map(str::to_owned),
        current: filters.boolean("current")?,
        sort: filters
            .sort(SORTS, &[SortKey::desc("last_seen")])?
            .into_iter()
            .map(|key| {
                if key.descending {
                    format!("-{}", key.field)
                } else {
                    key.field.to_owned()
                }
            })
            .collect(),
        limit: Some(page.limit()?),
        cursor: page.cursor::<String>(scope)?,
    };
    let view = ipam.view(page.at_least.map(Revision)).await?;
    if !may_read_kind(&app, &cx, ObjectKind::Observation) {
        return Ok(Json(Page::new(Vec::new(), None, view.revision())));
    }
    let facts = list_facts(view.as_ref(), &query, Timestamp::now())?;
    Ok(Json(Page::new(
        facts.items,
        facts
            .next_cursor
            .map(|cursor| encode_cursor(scope, &cursor)),
        facts.revision,
    )))
}

/// Shows one subject across every source.
#[utoipa::path(
    get,
    path = "/observations/{subject}",
    tag = "observations",
    operation_id = "get_observation",
    summary = "Get the picture of one subject across sources",
    params(
        ("subject" = String, Path, description = "A MAC address (`00-00-5E-00-53-01` or `00:00:5e:00:53:01`), an IP address or a name (compared without case)."),
        ReadParams
    ),
    responses(
        (status = 200, description = "The facts that name the subject, the picture across sources, the intent objects that match and their last sightings", body = SubjectView),
        (status = 400, description = "The subject is not a MAC address, an IP address or a name (`ipam.validation`), or a parameter is unknown (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not read observations", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No source has observed the subject (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_observation(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(subject): IpamPath<String>,
    filters: Filters,
) -> Result<Json<SubjectView>, ApiError> {
    filters.only(&[])?;
    let at_least = filters.page()?.at_least.map(Revision);
    authorize(&app, &cx, Action::Read, new_of(ObjectKind::Observation))?;
    let subject: SubjectQuery = subject.parse()?;
    let view = ipam.view(at_least).await?;
    Ok(Json(subject_view(
        view.as_ref(),
        &subject,
        Timestamp::now(),
    )?))
}

/// Route tests of the observations area, driven through the router over a fresh in-memory
/// store. Test data stays in the documentation ranges (192.0.2.0/24, MAC addresses
/// 00-00-5E-00-53-xx and names under `example.test`).
#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::Arc,
        time::Duration,
    };

    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        http::{Request, header},
    };
    use serde_json::Value;
    use tenko_core::{
        AuthStrength, Authorizer, ConnectorId, ObservationId, Principal, RequestCtx, SessionId,
        UserId,
        ipam::AssignmentMode,
        observe::{Observation, ObservationSource, Observed, ObservedHost},
    };
    use tenko_ipam::{
        IpamCommand, IpamService, PlanOptions,
        command::{AddressInput, HostInput, InterfaceInput, PrefixInput},
        observe::IngestBatch,
        reconcile::{Reconciler, ReconcilerConfig},
    };
    use tenko_store::{MemStore, Store};
    use tower::ServiceExt;

    use super::super::tenancy::testkit::{Policy, Reply};
    use super::*;
    use crate::API_BASE;

    const WEB_MAC: &str = "00-00-5E-00-53-01";
    const DB_MAC: &str = "00-00-5E-00-53-02";
    const OLD_MAC: &str = "00-00-5E-00-53-03";

    // ----- harness ---------------------------------------------------------------------

    /// The routes of the area under the API base, over `state`.
    fn router(state: AppState) -> Router {
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        router.with_state(state)
    }

    /// The observation routes over one IPAM service. Intent: the network 192.0.2.0/24 and
    /// the host `web01` with the MAC address 00-00-5E-00-53-01 and the address 192.0.2.10.
    /// Facts: two inventory hosts and a client attachment of one connector, seen now, and
    /// an inventory host of another connector last seen long ago (expired).
    struct Lab {
        router: Router,
        service: Arc<IpamService>,
        /// The connector of the current facts.
        connector: ConnectorId,
    }

    impl Lab {
        async fn new() -> Self {
            Self::with_state(AppState::default()).await
        }

        async fn with_state(state: AppState) -> Self {
            let store: Arc<dyn Store> = Arc::new(MemStore::default());
            let service = IpamService::with_direct_jobs(store).expect("service");
            let reconciler = Reconciler::new(Arc::clone(&service), ReconcilerConfig::default())
                .expect("reconciler");
            let lab = Self {
                router: router(state).layer(Extension(Arc::clone(&service))),
                service,
                connector: ConnectorId::generate(),
            };
            lab.make_intent().await;
            let now = Timestamp::now();
            let inventory = ObservationSource::Inventory {
                connector: lab.connector,
            };
            let controller = ObservationSource::NetworkController {
                connector: lab.connector,
            };
            ingest(
                &reconciler,
                &inventory,
                now,
                vec![
                    Observed::Host(vm("qemu/101", "web01", WEB_MAC, "192.0.2.10")),
                    Observed::Host(vm("qemu/102", "db01", DB_MAC, "192.0.2.11")),
                ],
            )
            .await;
            ingest(
                &reconciler,
                &controller,
                now,
                vec![Observed::Attachment {
                    mac: WEB_MAC.parse().expect("mac"),
                    device: "switch-1".to_owned(),
                    port: Some("3".to_owned()),
                    ssid: None,
                    vlan: Some(20),
                }],
            )
            .await;
            let long_ago: Timestamp = "2020-01-01T00:00:00Z".parse().expect("time");
            ingest(
                &reconciler,
                &ObservationSource::Inventory {
                    connector: ConnectorId::generate(),
                },
                long_ago,
                vec![Observed::Host(vm(
                    "lxc/201",
                    "old01",
                    OLD_MAC,
                    "192.0.2.12",
                ))],
            )
            .await;
            lab
        }

        /// The same facts behind another router.
        fn behind(&self, router: Router) -> Self {
            Self {
                router,
                service: Arc::clone(&self.service),
                connector: self.connector,
            }
        }

        /// The same facts, checked by `authorizer`.
        fn checked_by(&self, authorizer: Arc<dyn Authorizer>) -> Self {
            self.behind(
                router(AppState {
                    authorizer: Some(authorizer),
                    ..AppState::default()
                })
                .layer(Extension(Arc::clone(&self.service))),
            )
        }

        /// A server without IPAM.
        fn without_ipam(&self) -> Self {
            self.behind(router(AppState::default()))
        }

        async fn make_intent(&self) {
            let cx = RequestCtx::new(Principal::User {
                id: UserId::generate(),
                session: SessionId::generate(),
                strength: AuthStrength::Passkey,
            });
            let interface = tenko_core::InterfaceId::generate();
            let commands = vec![
                IpamCommand::CreatePrefix(PrefixInput {
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
                }),
                IpamCommand::CreateHost(HostInput {
                    id: None,
                    tenant: None,
                    name: "web01".parse().expect("name"),
                    mode: Some(AssignmentMode::Static),
                    lock: None,
                    site: None,
                    interfaces: vec![InterfaceInput {
                        id: Some(interface),
                        host: None,
                        name: "eth0".to_owned(),
                        mac: Some(WEB_MAC.parse().expect("mac")),
                        duid: None,
                        client_id: None,
                        tags: BTreeSet::new(),
                        custom: BTreeMap::new(),
                        description: None,
                    }],
                    tags: BTreeSet::new(),
                    custom: BTreeMap::new(),
                    description: None,
                }),
                IpamCommand::CreateAddress(AddressInput {
                    id: None,
                    vrf: None,
                    ip: "192.0.2.10".parse().expect("ip"),
                    status: None,
                    interface: Some(interface),
                    dns_name: None,
                    tags: BTreeSet::new(),
                    custom: BTreeMap::new(),
                    description: None,
                }),
            ];
            self.service
                .execute(&commands, &cx, &PlanOptions::default())
                .await
                .expect("intent");
        }

        async fn get(&self, path: &str) -> Reply {
            let request = Request::builder()
                .method("GET")
                .uri(format!("{API_BASE}{path}"))
                .body(Body::empty())
                .expect("request");
            let response = self
                .router
                .clone()
                .oneshot(request)
                .await
                .expect("response");
            let status = response.status();
            let content_type = response
                .headers()
                .get(header::CONTENT_TYPE)
                .map(|value| value.to_str().expect("text").to_owned())
                .unwrap_or_default();
            let etag = response
                .headers()
                .get(header::ETAG)
                .map(|value| value.to_str().expect("text").to_owned());
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

        /// The subject keys of the facts a list answers, in order.
        async fn keys(&self, query: &str) -> Vec<String> {
            let reply = self.get(&format!("/observations{query}")).await;
            reply.assert_json(200);
            reply.texts("subject_key")
        }

        /// Walks a list page by page and returns the pages.
        async fn pages(&self, path: &str, limit: usize) -> Vec<Reply> {
            let separator = if path.contains('?') { '&' } else { '?' };
            let mut next = format!("{path}{separator}limit={limit}");
            let mut pages = Vec::new();
            loop {
                assert!(pages.len() < 50, "the cursor never ends");
                let reply = self.get(&next).await;
                reply.assert_json(200);
                assert!(reply.items().len() <= limit, "{}", reply.body);
                let cursor = reply.body["next_cursor"].as_str().map(str::to_owned);
                pages.push(reply);
                match cursor {
                    Some(cursor) => {
                        next = format!("{path}{separator}limit={limit}&cursor={cursor}");
                    }
                    None => return pages,
                }
            }
        }
    }

    /// One complete poll of `source` that reports `subjects` as seen at `when`.
    async fn ingest(
        reconciler: &Reconciler,
        source: &ObservationSource,
        when: Timestamp,
        subjects: Vec<Observed>,
    ) {
        let observations = subjects
            .into_iter()
            .map(|subject| Observation {
                id: ObservationId::generate(),
                source: source.clone(),
                subject,
                observed_at: when,
                received_at: when,
                expires_at: when.checked_add(Duration::from_secs(900)),
            })
            .collect();
        reconciler
            .ingest(IngestBatch {
                source: source.clone(),
                observations,
                complete: true,
                received_at: when,
            })
            .await
            .expect("ingest");
    }

    /// An inventory host with one MAC address and one address.
    fn vm(id: &str, name: &str, mac: &str, ip: &str) -> ObservedHost {
        ObservedHost {
            external_id: id.to_owned(),
            name: Some(name.to_owned()),
            macs: vec![mac.parse().expect("mac")],
            ips: vec![ip.parse().expect("ip")],
            os: Some("Linux 6.x".to_owned()),
            platform: Some("qemu".to_owned()),
            parent: Some("pve1".to_owned()),
            tags: Vec::new(),
        }
    }

    // ----- the list --------------------------------------------------------------------

    #[tokio::test]
    async fn the_list_answers_every_fact_newest_sighting_first() {
        let lab = Lab::new().await;
        let reply = lab.get("/observations").await;
        reply.assert_json(200);
        assert_eq!(reply.items().len(), 4, "{}", reply.body);
        assert_eq!(reply.body["next_cursor"], Value::Null);
        assert!(reply.body["revision"].as_u64().is_some(), "{}", reply.body);
        let keys = reply.texts("subject_key");
        assert_eq!(keys.last().map(String::as_str), Some("host:lxc/201"));
        let first = &reply.items()[0];
        assert!(first["source_key"].is_string(), "{first}");
        assert!(first["observed"]["type"].is_string(), "{first}");
        assert!(first["last_seen"].is_string(), "{first}");
        assert_eq!(first["sightings"], 1);

        let oldest_first = lab.keys("?sort=last_seen").await;
        assert_eq!(oldest_first[0], "host:lxc/201");
        let by_subject = lab.keys("?sort=subject").await;
        let mut sorted = by_subject.clone();
        sorted.sort();
        assert_eq!(by_subject, sorted);
        let by_subject_down = lab.keys("?sort=-subject").await;
        sorted.reverse();
        assert_eq!(by_subject_down, sorted);
        lab.keys("?sort=source,-first_seen").await;
        lab.get(&format!(
            "/observations?at_least={}",
            reply.body["revision"].as_u64().expect("revision")
        ))
        .await
        .assert_json(200);
    }

    #[tokio::test]
    async fn the_list_filters_by_type_mac_address_source_text_and_currency() {
        let lab = Lab::new().await;
        let connector = lab.connector;

        assert_eq!(lab.keys("?type=host").await.len(), 3);
        assert_eq!(lab.keys("?type=Attachment").await.len(), 1);
        for kind in ["address", "services", "os", "link"] {
            assert_eq!(lab.keys(&format!("?type={kind}")).await.len(), 0, "{kind}");
        }

        // A MAC address in either spelling: the inventory host and the attachment.
        for mac in [WEB_MAC, "00:00:5e:00:53:01"] {
            let keys = lab.keys(&format!("?mac={mac}")).await;
            assert_eq!(keys.len(), 2, "{mac}: {keys:?}");
            assert!(keys.contains(&"host:qemu/101".to_owned()), "{keys:?}");
            assert!(
                keys.iter().any(|key| key.starts_with("attachment:")),
                "{keys:?}"
            );
        }
        assert_eq!(lab.keys("?mac=00-00-5E-00-53-99").await.len(), 0);
        assert_eq!(lab.keys("?ip=192.0.2.11").await, ["host:qemu/102"]);
        assert_eq!(lab.keys("?within=192.0.2.8/29").await.len(), 3);
        assert_eq!(lab.keys("?within=192.0.2.0/29").await.len(), 0);
        assert_eq!(lab.keys("?within=192.0.2.11").await, ["host:qemu/102"]);

        // Current facts and expired ones.
        assert_eq!(lab.keys("?current=true").await.len(), 3);
        assert_eq!(lab.keys("?current=false").await, ["host:lxc/201"]);
        assert_eq!(lab.keys("?current=false&type=attachment").await.len(), 0);

        // A source key, or a connector, which matches both of its sources.
        assert_eq!(
            lab.keys(&format!("?source=inventory:{connector}"))
                .await
                .len(),
            2
        );
        assert_eq!(
            lab.keys(&format!("?source=network_controller:{connector}"))
                .await
                .len(),
            1
        );
        assert_eq!(lab.keys(&format!("?source={connector}")).await.len(), 3);
        assert_eq!(lab.keys("?source=inventory:nobody").await.len(), 0);

        // Text, without case.
        assert_eq!(lab.keys("?q=DB01").await, ["host:qemu/102"]);
        assert_eq!(lab.keys("?q=pve1").await.len(), 3);
        assert_eq!(lab.keys("?q=Switch-1").await.len(), 1);
        assert_eq!(lab.keys("?q=nothing-like-this").await.len(), 0);

        // Filters combine.
        assert_eq!(
            lab.keys("?type=host&current=true&within=192.0.2.0/24")
                .await
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn the_list_pages_with_a_cursor_bound_to_its_query() {
        let lab = Lab::new().await;
        let whole = lab.get("/observations?sort=subject").await;
        let pages = lab.pages("/observations?sort=subject", 1).await;
        assert_eq!(pages.len(), 4);
        let walked: Vec<String> = pages
            .iter()
            .flat_map(|page| page.texts("subject_key"))
            .collect();
        assert_eq!(walked, whole.texts("subject_key"));
        assert_eq!(pages[3].body["next_cursor"], Value::Null);

        // Pages of the filtered list.
        let hosts = lab.pages("/observations?type=host&current=true", 1).await;
        assert_eq!(hosts.len(), 2);

        let cursor = pages[0].body["next_cursor"].as_str().expect("cursor");
        lab.get(&format!("/observations?sort=-subject&cursor={cursor}"))
            .await
            .assert_problem(400, "sys.invalid_cursor");
        lab.get(&format!(
            "/observations?sort=subject&type=host&cursor={cursor}"
        ))
        .await
        .assert_problem(400, "sys.invalid_cursor");
        lab.get("/observations?cursor=garbage")
            .await
            .assert_problem(400, "sys.invalid_cursor");
        lab.get(&format!("/observations?sort=subject&cursor={cursor}"))
            .await
            .assert_json(200);
    }

    #[tokio::test]
    async fn bad_list_parameters_answer_problem_details() {
        let lab = Lab::new().await;
        for path in [
            "/observations?bogus=1",
            "/observations?type=nope",
            "/observations?mac=zz",
            "/observations?mac=00-00-5E-00-53",
            "/observations?ip=300.1.1.1",
            "/observations?within=192.0.2.1/24",
            "/observations?within=nowhere",
            "/observations?current=maybe",
            "/observations?sort=nope",
            "/observations?sort=subject,-subject",
            "/observations?limit=0",
            "/observations?limit=1001",
            "/observations?source=a&source=b",
            "/observations?at_least=soon",
        ] {
            lab.get(path).await.assert_problem(400, "sys.invalid_query");
        }
    }

    // ----- one subject -----------------------------------------------------------------

    #[tokio::test]
    async fn a_mac_address_shows_its_facts_across_sources_and_the_intent_that_matches() {
        let lab = Lab::new().await;
        for subject in [WEB_MAC, "00:00:5e:00:53:01", "00-00-5e-00-53-01"] {
            let reply = lab.get(&format!("/observations/{subject}")).await;
            reply.assert_json(200);
            let body = &reply.body;
            assert!(
                body["subject"]
                    .as_str()
                    .expect("subject")
                    .starts_with("mac:"),
                "{body}"
            );
            assert_eq!(body["facts"].as_array().expect("facts").len(), 2, "{body}");
            let summary = &body["summary"];
            assert_eq!(summary["current"], true, "{body}");
            assert_eq!(
                summary["sources"].as_array().expect("sources").len(),
                2,
                "{body}"
            );
            assert_eq!(summary["macs"].as_array().expect("macs").len(), 1, "{body}");
            assert_eq!(summary["names"][0], "web01", "{body}");
            assert_eq!(summary["ips"][0], "192.0.2.10", "{body}");
            assert_eq!(summary["attachments"][0]["device"], "switch-1", "{body}");
            assert_eq!(summary["attachments"][0]["port"], "3", "{body}");
            assert_eq!(summary["attachments"][0]["vlan"], 20, "{body}");
            assert_eq!(
                body["intent"]["hosts"].as_array().expect("hosts").len(),
                1,
                "{body}"
            );
            assert_eq!(
                body["intent"]["interfaces"]
                    .as_array()
                    .expect("interfaces")
                    .len(),
                1,
                "{body}"
            );
            assert!(body["revision"].as_u64().is_some(), "{body}");
        }
    }

    #[tokio::test]
    async fn an_address_and_a_name_find_their_facts_and_a_name_ignores_case() {
        let lab = Lab::new().await;
        let by_ip = lab.get("/observations/192.0.2.10").await;
        by_ip.assert_json(200);
        assert!(
            by_ip.body["subject"]
                .as_str()
                .expect("subject")
                .starts_with("ip:")
        );
        assert_eq!(by_ip.body["facts"].as_array().expect("facts").len(), 1);
        assert_eq!(
            by_ip.body["intent"]["addresses"]
                .as_array()
                .expect("addresses")
                .len(),
            1,
            "{}",
            by_ip.body
        );
        for name in ["db01", "DB01"] {
            let by_name = lab.get(&format!("/observations/{name}")).await;
            by_name.assert_json(200);
            assert_eq!(by_name.body["subject"], "name:db01");
            assert_eq!(by_name.body["facts"].as_array().expect("facts").len(), 1);
            assert_eq!(by_name.body["summary"]["macs"][0], "00:00:5e:00:53:02");
        }
        // A subject that only an expired fact names is still known, but not current.
        let old = lab.get(&format!("/observations/{OLD_MAC}")).await;
        old.assert_json(200);
        assert_eq!(old.body["summary"]["current"], false, "{}", old.body);
        lab.get(&format!("/observations/{DB_MAC}?at_least=1"))
            .await
            .assert_json(200);
    }

    #[tokio::test]
    async fn an_unknown_or_unusable_subject_is_refused() {
        let lab = Lab::new().await;
        for subject in ["00-00-5E-00-53-99", "192.0.2.99", "nobody", "2001:db8::1"] {
            let reply = lab.get(&format!("/observations/{subject}")).await;
            reply.assert_problem(404, "ipam.not_found");
            assert_eq!(
                reply.body["params"]["kind"], "observation",
                "{}",
                reply.body
            );
        }
        for subject in ["%01", "%20", "%09%0A", &"n".repeat(254)] {
            lab.get(&format!("/observations/{subject}"))
                .await
                .assert_problem(400, "ipam.validation");
        }
        lab.get("/observations/db01?bogus=1")
            .await
            .assert_problem(400, "sys.invalid_query");
        lab.get("/observations/db01?at_least=soon")
            .await
            .assert_problem(400, "sys.invalid_query");
        // The longest usable name is a name like any other.
        lab.get(&format!("/observations/{}", "n".repeat(253)))
            .await
            .assert_problem(404, "ipam.not_found");
    }

    // ----- authorization and availability ----------------------------------------------

    #[tokio::test]
    async fn a_reader_sees_observations_and_a_principal_that_reads_none_sees_none() {
        let lab = Lab::new().await;
        let reader = Policy::new(true, false);
        let reading = lab.checked_by(Arc::clone(&reader) as Arc<dyn Authorizer>);
        assert_eq!(reading.get("/observations").await.items().len(), 4);
        reading.get("/observations/db01").await.assert_json(200);
        assert!(
            reader
                .asked()
                .contains(&(Action::Read, new_of(ObjectKind::Observation))),
            "{:?}",
            reader.asked()
        );

        let blind = lab.checked_by(Policy::new(false, false));
        let empty = blind.get("/observations").await;
        empty.assert_json(200).assert_no_items();
        assert_eq!(empty.body["next_cursor"], Value::Null);
        assert!(empty.body["revision"].as_u64().is_some(), "{}", empty.body);
        blind
            .get("/observations/db01")
            .await
            .assert_problem(403, "auth.forbidden");
        // The refusal does not tell whether the subject exists.
        blind
            .get("/observations/nobody")
            .await
            .assert_problem(403, "auth.forbidden");
    }

    #[tokio::test]
    async fn without_ipam_the_observations_are_unavailable() {
        let lab = Lab::new().await.without_ipam();
        lab.get("/observations")
            .await
            .assert_problem(503, "ipam.unavailable");
        lab.get("/observations/db01")
            .await
            .assert_problem(503, "ipam.unavailable");
    }

    // ----- the document ----------------------------------------------------------------

    #[test]
    fn the_operations_are_documented() {
        let (_, document) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        let list = document.paths.paths["/api/v1/observations"]
            .get
            .as_ref()
            .expect("get");
        let one = document.paths.paths["/api/v1/observations/{subject}"]
            .get
            .as_ref()
            .expect("get");
        for (operation, id, statuses) in [
            (list, "list_observations", &["200", "400", "503"][..]),
            (
                one,
                "get_observation",
                &["200", "400", "403", "404", "503"][..],
            ),
        ] {
            assert_eq!(operation.operation_id.as_deref(), Some(id));
            assert_eq!(
                operation.tags.as_deref(),
                Some(&["observations".to_owned()][..])
            );
            for status in statuses {
                assert!(
                    operation.responses.responses.contains_key(*status),
                    "{id} documents {status}"
                );
            }
        }
        let names: Vec<&str> = list
            .parameters
            .iter()
            .flatten()
            .filter_map(|parameter| match parameter {
                utoipa::openapi::RefOr::T(parameter) => Some(parameter.name.as_str()),
                utoipa::openapi::RefOr::Ref(_) => None,
            })
            .collect();
        for name in [
            "limit", "cursor", "at_least", "source", "type", "mac", "ip", "within", "q", "current",
            "sort",
        ] {
            assert!(names.contains(&name), "{name} is documented: {names:?}");
        }
    }
}
