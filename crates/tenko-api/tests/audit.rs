//! The audit endpoints over an in-memory store: the paged and filtered log, one record by
//! sequence number and the verification of the hash chain.
//!
//! The log holds 30 records written through the store, one batch each, so that record `n`
//! was committed at revision `n`. The expectations come from the list of entries the log
//! was seeded with, never from the server's own filter code.

use std::{collections::BTreeSet, net::IpAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::Value;
use tenko_api::state::AppState;
use tenko_core::{
    Action, AddressId, ApiTokenId, AuthFailure, AuthStrength, Authenticator, Authorizer,
    Credentials, Denied, DenyReason, HostId, JobId, ObjectKind, ObjectRef, PrefixId, Principal,
    ScopeFilter, SessionId, SystemComponent, Timestamp, UserId,
    audit::{AuditDraft, AuditOutcome},
    auth::AuthFuture,
};
use tenko_store::{MemStore, Store, WriteBatch};
use tower::ServiceExt;

const PROBLEM_JSON: &str = "application/problem+json";
const RECORDS: usize = 30;
const ACTIONS: [&str; 6] = [
    "ipam.prefix.create",
    "ipam.prefix.update",
    "ipam.address.create",
    "auth.login.password",
    "jobs.cancel",
    "ipam.prefix.delete",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Success,
    Denied,
    Failed,
}

/// One record as it was seeded; the record's sequence number is its index plus one.
struct Entry {
    principal: Principal,
    action: &'static str,
    objects: Vec<ObjectRef>,
    outcome: Outcome,
    at: Timestamp,
}

/// Minute `minute` after 2026-10-09T12:00:00Z.
fn at(minute: usize) -> Timestamp {
    let base: Timestamp = "2026-10-09T12:00:00Z".parse().expect("time");
    let seconds = 60 * u64::try_from(minute).expect("small");
    base.checked_add(Duration::from_secs(seconds))
        .expect("in range")
}

fn seq_of(index: usize) -> u64 {
    u64::try_from(index).expect("small") + 1
}

/// Thirty entries with five principals, six actions, objects of four kinds and all three
/// outcomes, one minute apart.
fn entries() -> Vec<Entry> {
    let alice = UserId::generate();
    let principals = [
        Principal::system(SystemComponent::Api),
        Principal::system(SystemComponent::Ipam),
        Principal::User {
            id: alice,
            session: SessionId::generate(),
            strength: AuthStrength::Passkey,
        },
        Principal::User {
            id: UserId::generate(),
            session: SessionId::generate(),
            strength: AuthStrength::Password,
        },
        Principal::Token {
            id: ApiTokenId::generate(),
            owner: alice,
        },
    ];
    let prefixes: Vec<ObjectRef> = (0..4).map(|_| PrefixId::generate().into()).collect();
    let host: ObjectRef = HostId::generate().into();
    (0..RECORDS)
        .map(|index| {
            let action = ACTIONS[index % ACTIONS.len()];
            let mut objects = match action {
                "ipam.address.create" => vec![AddressId::generate().into()],
                "jobs.cancel" => vec![JobId::generate().into()],
                "auth.login.password" => vec![],
                _ => vec![prefixes[index % prefixes.len()]],
            };
            if index % 7 == 0 {
                objects.push(host);
            }
            let outcome = if index % 5 == 4 {
                Outcome::Failed
            } else if index % 3 == 2 {
                Outcome::Denied
            } else {
                Outcome::Success
            };
            Entry {
                principal: principals[index % principals.len()].clone(),
                action,
                objects,
                outcome,
                at: at(index),
            }
        })
        .collect()
}

fn draft(entry: &Entry) -> AuditDraft {
    let action = entry.action.parse().expect("action");
    let draft = AuditDraft::success(action, entry.objects.clone());
    match entry.outcome {
        Outcome::Success => draft,
        Outcome::Denied => AuditDraft {
            outcome: AuditOutcome::Denied,
            ..draft
        },
        Outcome::Failed => AuditDraft {
            outcome: AuditOutcome::Failed {
                code: "ipam.prefix.overlap".into(),
            },
            ..draft
        },
    }
}

async fn seeded_store(entries: &[Entry]) -> Arc<MemStore> {
    let store = Arc::new(MemStore::default());
    for entry in entries {
        let mut batch = WriteBatch::new(entry.principal.clone(), entry.at);
        batch.audit(draft(entry));
        store.propose(batch).await.expect("propose");
    }
    store
}

fn router(store: Arc<MemStore>) -> Router {
    tenko_api::api(AppState::new(store)).0
}

/// The log of 30 records behind the router, with the entries it was seeded from.
async fn log() -> (Router, Vec<Entry>) {
    let entries = entries();
    let store = seeded_store(&entries).await;
    (router(store), entries)
}

struct Reply {
    status: StatusCode,
    content_type: String,
    body: Value,
}

/// `GET /api/v1{path}`.
async fn get(router: &Router, path: &str) -> Reply {
    let request = Request::builder()
        .method("GET")
        .uri(format!("/api/v1{path}"))
        .body(Body::empty())
        .expect("request");
    let response = router.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|value| value.to_str().expect("text").to_owned())
        .unwrap_or_default();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body = serde_json::from_slice(&bytes).expect("JSON body");
    Reply {
        status,
        content_type,
        body,
    }
}

/// Asserts a problem document with the given status and code, served as problem details.
fn assert_problem(reply: &Reply, status: u16, code: &str, context: &str) {
    assert_eq!(reply.status.as_u16(), status, "{context}: {}", reply.body);
    assert_eq!(reply.content_type, PROBLEM_JSON, "{context}");
    assert_eq!(reply.body["type"], "about:blank", "{context}");
    assert_eq!(reply.body["status"], status, "{context}");
    assert_eq!(reply.body["code"], code, "{context}");
}

fn assert_ok(reply: &Reply, context: &str) {
    assert_eq!(reply.status, StatusCode::OK, "{context}: {}", reply.body);
    assert_eq!(reply.content_type, "application/json", "{context}");
}

fn seqs(page: &Value) -> Vec<u64> {
    page["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["seq"].as_u64().expect("seq"))
        .collect()
}

/// Reads pages with `limit` until `next_cursor` is null; returns the sequence numbers of
/// each page. `query` holds the filters and the order.
async fn walk(router: &Router, query: &str, limit: usize) -> Vec<Vec<u64>> {
    let mut pages = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut path = format!("/audit?limit={limit}");
        if !query.is_empty() {
            path.push('&');
            path.push_str(query);
        }
        if let Some(cursor) = &cursor {
            path.push_str("&cursor=");
            path.push_str(cursor);
        }
        let reply = get(router, &path).await;
        assert_ok(&reply, &path);
        pages.push(seqs(&reply.body));
        match reply.body["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => return pages,
        }
        assert!(pages.len() <= 100, "{path}: the cursors do not end");
    }
}

/// The sequence numbers of the entries that satisfy `keep`, ascending.
fn expected(entries: &[Entry], keep: impl Fn(&Entry) -> bool) -> Vec<u64> {
    entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| keep(entry))
        .map(|(index, _)| seq_of(index))
        .collect()
}

fn reversed(mut values: Vec<u64>) -> Vec<u64> {
    values.reverse();
    values
}

#[tokio::test]
async fn the_default_page_lists_the_newest_records_first() {
    let (router, entries) = log().await;
    let reply = get(&router, "/audit").await;
    assert_ok(&reply, "/audit");
    assert_eq!(seqs(&reply.body), reversed((1..=30).collect()));
    assert_eq!(reply.body["next_cursor"], Value::Null);
    assert_eq!(reply.body["revision"], 30);
    let newest = &reply.body["items"][0];
    assert_eq!(newest["draft"]["action"], entries[29].action);
    assert_eq!(newest["revision"], 30);
    assert_eq!(newest["hash"].as_str().map(str::len), Some(64));
}

#[tokio::test]
async fn limit_and_cursor_page_through_the_log_in_both_orders() {
    let (router, _) = log().await;
    let ascending: Vec<u64> = (1..=30).collect();
    for (query, want) in [
        ("", reversed(ascending.clone())),
        ("order=desc", reversed(ascending.clone())),
        ("order=asc", ascending),
    ] {
        for limit in [1, 7, 10, 29, 30, 31] {
            let pages = walk(&router, query, limit).await;
            let all: Vec<u64> = pages.iter().flatten().copied().collect();
            assert_eq!(all, want, "{query} limit {limit}");
            assert_eq!(
                pages.len(),
                RECORDS.div_ceil(limit),
                "{query} limit {limit}"
            );
            assert!(
                pages.iter().all(|page| page.len() <= limit),
                "{query} limit {limit}"
            );
            let (last, full) = pages.split_last().expect("a page");
            assert!(full.iter().all(|page| page.len() == limit));
            assert_ne!(last.len(), 0, "{query} limit {limit}");
        }
    }
}

#[tokio::test]
async fn the_last_page_has_no_cursor_and_a_middle_page_has_one() {
    let (router, _) = log().await;
    let first = get(&router, "/audit?limit=10&order=asc").await;
    assert_eq!(seqs(&first.body), (1..=10).collect::<Vec<u64>>());
    assert!(first.body["next_cursor"].is_string());
    let cursor = first.body["next_cursor"].as_str().expect("cursor");

    // The page size may change between pages; the cursor stays valid.
    let second = get(
        &router,
        &format!("/audit?limit=25&order=asc&cursor={cursor}"),
    )
    .await;
    assert_ok(&second, "second page");
    assert_eq!(seqs(&second.body), (11..=30).collect::<Vec<u64>>());
    assert_eq!(second.body["next_cursor"], Value::Null);
}

type Keep = Box<dyn Fn(&Entry) -> bool>;

fn case(query: impl Into<String>, keep: impl Fn(&Entry) -> bool + 'static) -> (String, Keep) {
    (query.into(), Box::new(keep))
}

/// Filters with the predicate over the seeded entries that selects the same records.
fn filter_cases(entries: &[Entry]) -> Vec<(String, Keep)> {
    let alice = entries[2].principal.subject();
    let token = entries[4].principal.subject();
    let a_prefix = entries[1].objects[0];
    let the_host = entries[0].objects[1];
    let tagged = |reference: ObjectRef| format!("{}:{}", reference.kind, reference.id);
    let (from, to) = (at(10).to_rfc3339(), at(20).to_rfc3339());
    let alice_again = alice.clone();
    vec![
        case("principal=system:ipam", |e| {
            e.principal == Principal::system(SystemComponent::Ipam)
        }),
        case(format!("principal={alice}"), move |e| {
            e.principal.subject() == alice
        }),
        case(format!("principal={token}"), move |e| {
            e.principal.subject() == token
        }),
        case("action=ipam.prefix.create", |e| {
            e.action == "ipam.prefix.create"
        }),
        case("action=jobs.cancel", |e| e.action == "jobs.cancel"),
        case("action=ipam.", |e| e.action.starts_with("ipam.")),
        case("action=ipam.prefix.", |e| {
            e.action.starts_with("ipam.prefix.")
        }),
        case("action=auth.", |e| e.action.starts_with("auth.")),
        case("object=prefix", |e| {
            e.objects.iter().any(|o| o.kind == ObjectKind::Prefix)
        }),
        case("object=host", |e| {
            e.objects.iter().any(|o| o.kind == ObjectKind::Host)
        }),
        case("object=address", |e| {
            e.objects.iter().any(|o| o.kind == ObjectKind::Address)
        }),
        case("object=job", |e| {
            e.objects.iter().any(|o| o.kind == ObjectKind::Job)
        }),
        case(format!("object={}", tagged(a_prefix)), move |e| {
            e.objects.contains(&a_prefix)
        }),
        case(format!("object={}", tagged(the_host)), move |e| {
            e.objects.contains(&the_host)
        }),
        case("outcome=success", |e| e.outcome == Outcome::Success),
        case("outcome=denied", |e| e.outcome == Outcome::Denied),
        case("outcome=failed", |e| e.outcome == Outcome::Failed),
        case(format!("from={from}"), |e| e.at >= at(10)),
        case(format!("to={to}"), |e| e.at < at(20)),
        case(format!("from={from}&to={to}"), |e| {
            e.at >= at(10) && e.at < at(20)
        }),
        case(format!("principal={alice_again}&object=prefix"), move |e| {
            e.principal.subject() == alice_again
                && e.objects.iter().any(|o| o.kind == ObjectKind::Prefix)
        }),
        case(
            format!(
                "action=ipam.&outcome=success&from={}&to={}",
                at(5).to_rfc3339(),
                at(25).to_rfc3339()
            ),
            |e| {
                e.action.starts_with("ipam.")
                    && e.outcome == Outcome::Success
                    && e.at >= at(5)
                    && e.at < at(25)
            },
        ),
    ]
}

#[tokio::test]
async fn every_filter_selects_the_matching_records_in_both_orders() {
    let (router, entries) = log().await;
    for (query, keep) in filter_cases(&entries) {
        let want = expected(&entries, keep);
        assert!(
            !want.is_empty() && want.len() < RECORDS,
            "{query} selects {} of {RECORDS}: not a useful case",
            want.len()
        );
        let asc = get(&router, &format!("/audit?{query}&order=asc")).await;
        assert_ok(&asc, &query);
        assert_eq!(seqs(&asc.body), want, "{query} ascending");
        assert_eq!(asc.body["next_cursor"], Value::Null, "{query}");
        let desc = get(&router, &format!("/audit?{query}")).await;
        assert_ok(&desc, &query);
        assert_eq!(seqs(&desc.body), reversed(want), "{query} descending");
    }
}

#[tokio::test]
async fn filtered_lists_page_through_their_matches() {
    let (router, entries) = log().await;
    for (query, keep) in filter_cases(&entries) {
        let want = expected(&entries, keep);
        for limit in [1, 2, 3] {
            let pages = walk(&router, &format!("{query}&order=asc"), limit).await;
            let all: Vec<u64> = pages.iter().flatten().copied().collect();
            assert_eq!(all, want, "{query} limit {limit}");
            // Every page but the last is full. The last one may be empty when rows that do
            // not match follow the final match: the scan only knows it is done at the end
            // of the log.
            let (last, full) = pages.split_last().expect("a page");
            assert!(full.iter().all(|page| page.len() == limit), "{query}");
            assert!(last.len() <= limit, "{query}");
            assert!(pages.len() >= want.len().div_ceil(limit), "{query}");
            let pages = walk(&router, &query, limit).await;
            let all: Vec<u64> = pages.iter().flatten().copied().collect();
            assert_eq!(
                all,
                reversed(want.clone()),
                "{query} limit {limit} descending"
            );
        }
    }
}

#[tokio::test]
async fn a_filter_that_matches_nothing_is_an_empty_last_page() {
    let (router, _) = log().await;
    for query in [
        "object=prefix:00000000-0000-0000-0000-000000000000",
        "from=2030-01-01T00:00:00Z",
        "to=2026-10-09T12:00:00Z",
        "principal=user:00000000-0000-0000-0000-000000000000",
        "action=scan.",
    ] {
        let reply = get(&router, &format!("/audit?{query}")).await;
        assert_ok(&reply, query);
        assert_eq!(reply.body["items"], Value::Array(Vec::new()), "{query}");
        assert_eq!(reply.body["next_cursor"], Value::Null, "{query}");
        assert_eq!(reply.body["revision"], 30, "{query}");
    }
}

#[tokio::test]
async fn read_your_writes_is_met_by_an_already_applied_revision() {
    let (router, _) = log().await;
    let reply = get(&router, "/audit?at_least=30&limit=1").await;
    assert_ok(&reply, "at_least");
    assert_eq!(seqs(&reply.body), [30]);
}

#[tokio::test]
async fn a_cursor_belongs_to_its_query() {
    let (router, _) = log().await;
    let first = get(&router, "/audit?limit=5&outcome=success").await;
    let cursor = first.body["next_cursor"]
        .as_str()
        .expect("cursor")
        .to_owned();

    // The same query continues.
    let same = get(
        &router,
        &format!("/audit?limit=5&outcome=success&cursor={cursor}"),
    )
    .await;
    assert_ok(&same, "same query");
    assert!(
        seqs(&same.body)
            .iter()
            .all(|seq| seq < &seqs(&first.body)[4])
    );

    // Any other filter, or none, or the other order refuses it.
    for other in [
        "limit=5&outcome=denied",
        "limit=5",
        "limit=5&outcome=success&order=asc",
        "limit=5&outcome=success&action=ipam.",
        "limit=5&outcome=success&principal=system:api",
    ] {
        let reply = get(&router, &format!("/audit?{other}&cursor={cursor}")).await;
        assert_problem(&reply, 400, "sys.invalid_cursor", other);
    }

    for garbage in ["not-a-cursor", "e30", "AAAA", "%00"] {
        let reply = get(&router, &format!("/audit?cursor={garbage}")).await;
        assert_problem(&reply, 400, "sys.invalid_cursor", garbage);
    }
}

#[tokio::test]
async fn malformed_queries_are_problem_details_naming_the_parameter() {
    let (router, _) = log().await;
    let uuid = "00000000-0000-0000-0000-000000000000";
    let cases = [
        ("limit=0".to_owned(), "limit"),
        ("limit=1001".to_owned(), "limit"),
        ("limit=many".to_owned(), "limit"),
        ("limit=1&limit=2".to_owned(), "limit"),
        ("at_least=soon".to_owned(), "at_least"),
        ("outcome=ok".to_owned(), "outcome"),
        ("outcome=success&outcome=failed".to_owned(), "outcome"),
        ("order=sideways".to_owned(), "order"),
        ("order=ASC".to_owned(), "order"),
        ("from=yesterday".to_owned(), "from"),
        ("to=2026-10-09".to_owned(), "to"),
        ("object=lease".to_owned(), "object"),
        ("object=prefix:not-a-uuid".to_owned(), "object"),
        (format!("object=lease:{uuid}"), "object"),
        ("action=nope.".to_owned(), "action"),
        ("action=ipam".to_owned(), "action"),
        ("principal=a&principal=b".to_owned(), "principal"),
        ("colour=blue".to_owned(), "colour"),
    ];
    for (query, parameter) in cases {
        let reply = get(&router, &format!("/audit?{query}")).await;
        assert_problem(&reply, 400, "sys.invalid_query", &query);
        assert_eq!(reply.body["params"]["parameter"], parameter, "{query}");
        assert_eq!(reply.body["errors"][0]["field"], parameter, "{query}");
    }
}

#[tokio::test]
async fn one_record_by_sequence_number() {
    let (router, entries) = log().await;
    let listed = get(&router, "/audit?order=asc&limit=30").await;
    let reply = get(&router, "/audit/7").await;
    assert_ok(&reply, "/audit/7");
    assert_eq!(reply.body, listed.body["items"][6]);
    assert_eq!(reply.body["seq"], 7);
    assert_eq!(reply.body["revision"], 7);
    assert_eq!(reply.body["at"], entries[6].at.to_rfc3339());
    assert_eq!(reply.body["draft"]["action"], entries[6].action);
    assert_eq!(
        reply.body["principal"],
        serde_json::to_value(&entries[6].principal).expect("principal")
    );

    // Records chain to their predecessor.
    let previous = get(&router, "/audit/6").await;
    assert_eq!(reply.body["prev"], previous.body["hash"]);
    let first = get(&router, "/audit/1").await;
    assert_eq!(first.body["prev"], "0".repeat(64));
    let newest = get(&router, "/audit/30").await;
    assert_ok(&newest, "/audit/30");
}

#[tokio::test]
async fn unknown_sequence_numbers_are_not_found() {
    let (router, _) = log().await;
    for seq in ["31", "1000", "18446744073709551615"] {
        let reply = get(&router, &format!("/audit/{seq}")).await;
        assert_problem(&reply, 404, "sys.audit.not_found", seq);
        assert_eq!(reply.body["params"]["seq"], seq, "{seq}");
    }
}

#[tokio::test]
async fn malformed_sequence_numbers_are_bad_requests() {
    let (router, _) = log().await;
    for seq in [
        "0",
        "00",
        "-1",
        "%2B1",
        "1.5",
        "abc",
        "0x10",
        "18446744073709551616",
        "%FF",
    ] {
        let reply = get(&router, &format!("/audit/{seq}")).await;
        assert_problem(&reply, 400, "sys.invalid_query", seq);
        assert_eq!(reply.body["params"]["parameter"], "seq", "{seq}");
    }
}

#[tokio::test]
async fn the_chain_of_a_seeded_log_verifies() {
    let (router, _) = log().await;
    let newest = get(&router, "/audit/30").await;
    let reply = get(&router, "/audit/verify").await;
    assert_ok(&reply, "/audit/verify");
    assert_eq!(reply.body["intact"], true);
    assert_eq!(reply.body["checked"], 30);
    assert_eq!(reply.body["head"]["seq"], 30);
    assert_eq!(reply.body["head"]["hash"], newest.body["hash"]);
    assert_eq!(reply.body["store_head"], 30);
    assert_eq!(reply.body["first_break"], Value::Null);
    assert_eq!(reply.body["revision"], 30);
}

#[tokio::test]
async fn an_empty_log_is_intact() {
    let router = router(Arc::new(MemStore::default()));
    let reply = get(&router, "/audit/verify").await;
    assert_ok(&reply, "/audit/verify");
    assert_eq!(reply.body["intact"], true);
    assert_eq!(reply.body["checked"], 0);
    assert_eq!(reply.body["head"]["seq"], 0);
    assert_eq!(reply.body["head"]["hash"], "0".repeat(64));
    assert_eq!(reply.body["store_head"], 0);
    assert_eq!(reply.body["first_break"], Value::Null);

    let list = get(&router, "/audit").await;
    assert_ok(&list, "/audit");
    assert_eq!(list.body["items"], Value::Array(Vec::new()));
    assert_eq!(list.body["next_cursor"], Value::Null);
    let one = get(&router, "/audit/1").await;
    assert_problem(&one, 404, "sys.audit.not_found", "/audit/1");
}

/// Allows exactly `Read` on the system object when open, nothing when closed.
struct Gate {
    open: bool,
}

impl Authorizer for Gate {
    fn check(
        &self,
        _principal: &Principal,
        action: Action,
        object: &ObjectRef,
    ) -> Result<(), Denied> {
        if self.open && action == Action::Read && object.kind == ObjectKind::System {
            Ok(())
        } else {
            Err(Denied {
                action,
                object: *object,
                reason: DenyReason::MissingPermission,
            })
        }
    }

    fn scope(&self, _principal: &Principal, _action: Action, _kind: ObjectKind) -> ScopeFilter {
        if self.open {
            ScopeFilter::All
        } else {
            ScopeFilter::Nothing
        }
    }
}

/// Refuses every request as unauthenticated.
struct Anonymous;

impl Authenticator for Anonymous {
    fn authenticate<'a>(
        &'a self,
        _credentials: &'a Credentials,
        _source_ip: Option<IpAddr>,
        _now: Timestamp,
    ) -> AuthFuture<'a> {
        Box::pin(async { Err(AuthFailure::Missing) })
    }
}

#[tokio::test]
async fn the_log_needs_read_access_to_the_system() {
    let entries = entries();
    let store = seeded_store(&entries).await;
    let paths = ["/audit", "/audit/7", "/audit/verify", "/audit/999"];

    let mut state = AppState::new(store.clone());
    state.authorizer = Some(Arc::new(Gate { open: false }));
    let closed = tenko_api::api(state).0;
    for path in paths {
        let reply = get(&closed, path).await;
        assert_problem(&reply, 403, "auth.forbidden", path);
    }
    // A bad request is judged after the permission: no hint about the log without it.
    let reply = get(&closed, "/audit?limit=0").await;
    assert_problem(&reply, 403, "auth.forbidden", "/audit?limit=0");

    let mut state = AppState::new(store.clone());
    state.authorizer = Some(Arc::new(Gate { open: true }));
    let open = tenko_api::api(state).0;
    for path in ["/audit", "/audit/7", "/audit/verify"] {
        assert_ok(&get(&open, path).await, path);
    }
    assert_problem(
        &get(&open, "/audit/999").await,
        404,
        "sys.audit.not_found",
        "/audit/999",
    );

    let mut state = AppState::new(store);
    state.auth = Some(Arc::new(Anonymous));
    let anonymous = tenko_api::api(state).0;
    for path in paths {
        let reply = get(&anonymous, path).await;
        assert_problem(&reply, 401, "auth.unauthenticated", path);
    }
}

#[test]
fn the_document_describes_the_audit_endpoints() {
    let document = serde_json::to_value(tenko_api::openapi()).expect("document");
    let paths = &document["paths"];

    let list = &paths["/api/v1/audit"]["get"];
    assert_eq!(list["operationId"], "list_audit");
    assert_eq!(list["tags"][0], "audit");
    let names: BTreeSet<&str> = list["parameters"]
        .as_array()
        .expect("parameters")
        .iter()
        .map(|parameter| {
            assert_eq!(parameter["in"], "query");
            parameter["name"].as_str().expect("name")
        })
        .collect();
    let want: BTreeSet<&str> = [
        "limit",
        "cursor",
        "at_least",
        "principal",
        "action",
        "object",
        "outcome",
        "from",
        "to",
        "order",
    ]
    .into_iter()
    .collect();
    assert_eq!(names, want);

    let verify = &paths["/api/v1/audit/verify"]["get"];
    assert_eq!(verify["operationId"], "verify_audit");
    let record = &paths["/api/v1/audit/{seq}"]["get"];
    assert_eq!(record["operationId"], "get_audit_record");
    assert_eq!(record["parameters"][0]["name"], "seq");
    assert_eq!(record["parameters"][0]["in"], "path");

    for (operation, statuses) in [
        (list, &["200", "400", "401", "403"][..]),
        (verify, &["200", "401", "403"][..]),
        (record, &["200", "400", "401", "403", "404"][..]),
    ] {
        for status in statuses {
            let response = &operation["responses"][*status];
            assert!(response.is_object(), "{operation} lacks {status}");
            let media = if *status == "200" {
                "application/json"
            } else {
                PROBLEM_JSON
            };
            assert!(response["content"][media].is_object(), "{status}: {media}");
        }
    }
    let schemas = &document["components"]["schemas"];
    for name in ["AuditRecord", "AuditVerifyReport", "AuditBreak"] {
        assert!(schemas[name].is_object(), "{name}");
    }
}
