//! The block list and allow list operations through the router: the rows, the fetch and
//! upload routes and the compile job behind them, over the zone service on an in-memory
//! store. The source of a URL list is a fake fetcher; no test reaches a network.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use serde_json::{Value, json};
use tenko_api::{routes::dns::ListUploadLimit, state::AppState};
use tenko_core::dns::{BlockListId, tables::LIST_VERSIONS};
use tenko_dns::{
    lists::{CompileStep, FetchFailure, Fetched, ListFetcher, ListStaging},
    zone::{DirectJobs, ImportStaging, ZoneConfig, ZoneJobs, ZoneService},
};
use tenko_jobs::JobState;
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadViewExt, Store};
use tower::ServiceExt;

const API: &str = "/api/v1";
const PROBLEM_JSON: &str = "application/problem+json";
const MISSING: &str = "0190d1c2-0000-7000-8000-0000000000ff";
const HOSTS: &str = "# a hosts file\n127.0.0.1 localhost\n0.0.0.0 ads.example.test\n\
                     0.0.0.0 tracker.example.test\n0.0.0.0 ADS.example.test\n";
const HOSTS_NEXT: &str = "0.0.0.0 ads.example.test\n0.0.0.0 tracker.example.test\n\
                          0.0.0.0 metrics.example.test\n";
const DOMAINS: &str = "ads.example.test\nsub.ads.example.test\nTracker.example.test\n";
const URL: &str = "https://lists.example.test/hosts.txt";

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

impl Reply {
    fn etag(&self) -> String {
        self.headers
            .get(header::ETAG)
            .expect("etag")
            .to_str()
            .expect("text")
            .to_owned()
    }

    fn id(&self) -> String {
        self.body["id"].as_str().expect("id").to_owned()
    }

    #[track_caller]
    fn assert_problem(&self, status: u16, code: &str) {
        assert_eq!(self.status.as_u16(), status, "{}", self.body);
        assert_eq!(
            self.headers
                .get(header::CONTENT_TYPE)
                .map(axum::http::HeaderValue::as_bytes),
            Some(PROBLEM_JSON.as_bytes())
        );
        assert_eq!(self.body["code"], code, "{}", self.body);
    }

    /// A `dns.list.invalid` problem of 400 naming `field`.
    #[track_caller]
    fn assert_invalid(&self, field: &str) {
        self.assert_problem(400, "dns.list.invalid");
        assert_eq!(self.body["params"]["field"], field, "{}", self.body);
    }

    /// A 202 with the job and its `Location`; returns the job id.
    #[track_caller]
    fn job(&self) -> String {
        assert_eq!(self.status, StatusCode::ACCEPTED, "{}", self.body);
        let job = self.body["job_id"].as_str().expect("job_id").to_owned();
        let location = self
            .headers
            .get(header::LOCATION)
            .expect("location")
            .to_str()
            .expect("text");
        assert_eq!(location, format!("{API}/jobs/{job}"));
        job
    }
}

/// What the fake fetcher serves, and what it was asked.
struct Source {
    body: String,
    etag: String,
    failure: Option<String>,
    calls: Vec<(String, Option<String>)>,
}

/// A [`ListFetcher`] over a fixed text with an entity tag: it answers `NotModified` to the
/// tag it serves, and it can be switched to fail.
struct FakeFetcher {
    source: Mutex<Source>,
}

impl FakeFetcher {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            source: Mutex::new(Source {
                body: HOSTS.to_owned(),
                etag: "\"v1\"".to_owned(),
                failure: None,
                calls: Vec::new(),
            }),
        })
    }

    fn with<T>(&self, change: impl FnOnce(&mut Source) -> T) -> T {
        change(&mut self.source.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn serve(&self, body: &str, etag: &str) {
        self.with(|source| {
            body.clone_into(&mut source.body);
            etag.clone_into(&mut source.etag);
        });
    }

    fn fail(&self, detail: Option<&str>) {
        self.with(|source| source.failure = detail.map(str::to_owned));
    }

    fn calls(&self) -> Vec<(String, Option<String>)> {
        self.with(|source| source.calls.clone())
    }

    fn answer(&self, url: &str, etag: Option<&str>) -> Result<Fetched, FetchFailure> {
        self.with(|source| {
            source.calls.push((url.to_owned(), etag.map(str::to_owned)));
            if let Some(detail) = &source.failure {
                return Err(FetchFailure {
                    detail: detail.clone(),
                });
            }
            if etag == Some(source.etag.as_str()) {
                return Ok(Fetched::NotModified);
            }
            Ok(Fetched::Changed {
                body: source.body.clone().into_bytes(),
                etag: Some(source.etag.clone()),
            })
        })
    }
}

// The expansion of `#[async_trait]`: this crate has no dependency on the macro.
impl ListFetcher for FakeFetcher {
    fn fetch<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        url: &'life1 str,
        etag: Option<&'life2 str>,
    ) -> Pin<Box<dyn Future<Output = Result<Fetched, FetchFailure>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(std::future::ready(self.answer(url, etag)))
    }
}

struct App {
    router: Router,
    store: Arc<MemStore>,
    fetcher: Arc<FakeFetcher>,
    jobs: Arc<DirectJobs>,
}

/// The router over a zone service whose job runner also runs the compile step. `upload` is
/// the upload limit to hand in, `staging` whether the list staging is handed in at all.
fn build(upload: Option<usize>, staging: bool) -> App {
    let store = Arc::new(MemStore::default());
    let fetcher = FakeFetcher::new();
    let import_staging = Arc::new(ImportStaging::default());
    let list_staging = Arc::new(ListStaging::default());
    let mut direct = DirectJobs::new(Arc::clone(&store) as Arc<dyn Store>);
    for handler in tenko_dns::zone::step_handlers(&import_staging) {
        direct.register(handler);
    }
    direct.register(Arc::new(CompileStep::new(
        Some(Arc::clone(&fetcher) as Arc<dyn ListFetcher>),
        Arc::clone(&list_staging),
    )));
    let jobs = Arc::new(direct);
    let service = ZoneService::new(
        Arc::clone(&store) as Arc<dyn Store>,
        Arc::clone(&jobs) as Arc<dyn ZoneJobs>,
        None,
        import_staging,
        ZoneConfig::default(),
    );
    let (router, _) = tenko_api::api(AppState::default());
    let mut router = router.layer(axum::Extension(service));
    if staging {
        router = router.layer(axum::Extension(list_staging));
    }
    if let Some(limit) = upload {
        router = router.layer(axum::Extension(ListUploadLimit(limit)));
    }
    App {
        router,
        store,
        fetcher,
        jobs,
    }
}

fn app() -> App {
    build(None, true)
}

async fn run(router: &Router, request: Request<Body>) -> Reply {
    let response = router.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("JSON")
    };
    Reply {
        status,
        headers,
        body,
    }
}

async fn send(router: &Router, method: &str, path: &str, body: Option<Value>) -> Reply {
    send_with(router, method, path, body, &[]).await
}

async fn send_with(
    router: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    extra: &[(&str, &str)],
) -> Reply {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("{API}{path}"));
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    let request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .expect("request");
    run(router, request).await
}

/// `PUT /dns/lists/{id}/file` with a plain text body; `declare` adds a `Content-Length`.
async fn upload(router: &Router, id: &str, text: &str, declare: bool) -> Reply {
    let mut builder = Request::builder()
        .method("PUT")
        .uri(format!("{API}/dns/lists/{id}/file"))
        .header(header::CONTENT_TYPE, "text/plain");
    if declare {
        builder = builder.header(header::CONTENT_LENGTH, text.len());
    }
    let request = builder.body(Body::from(text.to_owned())).expect("request");
    run(router, request).await
}

async fn create(router: &Router, body: Value) -> Reply {
    send(router, "POST", "/dns/lists", Some(body)).await
}

fn url_list(name: &str) -> Value {
    json!({
        "name": name,
        "source": {"kind": "url", "url": URL},
        "format": "hosts"
    })
}

fn upload_list(name: &str) -> Value {
    json!({"name": name, "source": {"kind": "upload"}, "format": "domains"})
}

async fn created(router: &Router, body: Value) -> Reply {
    let reply = create(router, body).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    reply
}

fn list_path(id: &str) -> String {
    format!("/dns/lists/{id}")
}

async fn read(router: &Router, id: &str) -> Reply {
    let reply = send(router, "GET", &list_path(id), None).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    reply
}

async fn fetch(router: &Router, id: &str) -> Reply {
    send(router, "POST", &format!("/dns/lists/{id}/fetch"), None).await
}

/// The audit actions in the store, in order.
async fn audit_actions(store: &MemStore) -> Vec<String> {
    let view = store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(
        &tenko_store::tables::AUDIT,
        KeyRange::all(),
        usize::MAX,
        false,
    )
    .expect("audit")
    .into_iter()
    .map(|(_, record, _)| record.draft.action.as_str().to_owned())
    .collect()
}

/// The revisions of the `dns.list_versions` rows of one list.
async fn version_rows(store: &MemStore, id: &str) -> Vec<u64> {
    let id: BlockListId = id.parse().expect("list id");
    let view = store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(&LIST_VERSIONS, KeyRange::all(), usize::MAX, false)
        .expect("versions")
        .into_iter()
        .filter(|(key, _, _)| key.0 == id)
        .map(|(key, _, _)| key.1)
        .collect()
}

#[tokio::test]
async fn a_list_is_created_read_and_listed_by_name() {
    let App { router, .. } = app();
    let block = created(
        &router,
        json!({
            "name": "ads-and-trackers",
            "source": {"kind": "url", "url": URL},
            "format": "hosts",
            "interval_hours": 12,
            "action": {"kind": "redirect", "address": "192.0.2.80"},
            "description": "  public ads  "
        }),
    )
    .await;
    assert_eq!(block.body["name"], "ads-and-trackers");
    assert_eq!(block.body["kind"], "block");
    assert_eq!(block.body["source"], json!({"kind": "url", "url": URL}));
    assert_eq!(block.body["format"], "hosts");
    assert_eq!(block.body["interval_hours"], 12);
    assert_eq!(
        block.body["action"],
        json!({"kind": "redirect", "address": "192.0.2.80"})
    );
    assert_eq!(block.body["description"], "public ads");
    assert!(block.body["revision"].is_number(), "{}", block.body);
    assert!(block.body.get("version").is_none(), "{}", block.body);
    assert!(block.body.get("last_error").is_none(), "{}", block.body);
    assert!(block.body.get("last_checked").is_none(), "{}", block.body);
    let etag = block.etag();

    let got = read(&router, &block.id()).await;
    assert_eq!(got.etag(), etag);
    assert_eq!(got.body, block.body);

    let allow = created(
        &router,
        json!({
            "name": "Trusted",
            "kind": "allow",
            "source": {"kind": "upload"},
            "format": "domains",
            "exempt": ["192.0.2.5/24", "192.0.2.10", "2001:db8::/32"]
        }),
    )
    .await;
    assert_eq!(allow.body["kind"], "allow");
    assert_eq!(allow.body["source"], json!({"kind": "upload"}));
    assert_eq!(
        allow.body["exempt"],
        json!(["192.0.2.0/24", "192.0.2.10/32", "2001:db8::/32"])
    );
    created(&router, upload_list("zeta")).await;

    let list = send(&router, "GET", "/dns/lists", None).await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.body);
    let names: Vec<&str> = list.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, ["ads-and-trackers", "Trusted", "zeta"]);
    assert!(list.body["next_cursor"].is_null());

    let mut seen = Vec::new();
    let mut path = "/dns/lists?limit=1".to_owned();
    for _ in 0..3 {
        let page = send(&router, "GET", &path, None).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        let items = page.body["items"].as_array().expect("items");
        assert_eq!(items.len(), 1);
        seen.push(items[0]["name"].as_str().expect("name").to_owned());
        match page.body["next_cursor"].as_str() {
            Some(cursor) => path = format!("/dns/lists?limit=1&cursor={cursor}"),
            None => break,
        }
    }
    assert_eq!(seen, ["ads-and-trackers", "Trusted", "zeta"]);
}

#[tokio::test]
async fn a_list_takes_its_defaults() {
    let App { router, .. } = app();
    let list = created(&router, url_list("defaults")).await;
    assert_eq!(list.body["kind"], "block");
    assert_eq!(list.body["action"], json!({"kind": "nxdomain"}));
    assert_eq!(list.body["interval_hours"], 24);
    assert_eq!(list.body["enabled"], true);
    assert!(list.body.get("exempt").is_none(), "{}", list.body);
    assert!(list.body.get("description").is_none(), "{}", list.body);

    let off = created(
        &router,
        json!({
            "name": "off",
            "source": {"kind": "upload"},
            "format": "domains",
            "action": {"kind": "nodata"},
            "enabled": false
        }),
    )
    .await;
    assert_eq!(off.body["enabled"], false);
    assert_eq!(off.body["action"], json!({"kind": "nodata"}));
}

#[tokio::test]
async fn an_invalid_list_is_refused_with_the_field() {
    let App { router, .. } = app();

    let mut bad_url = url_list("bad-url");
    bad_url["source"] = json!({"kind": "url", "url": "ftp://lists.example.test/hosts.txt"});
    create(&router, bad_url).await.assert_invalid("source.url");

    let mut zero = url_list("zero");
    zero["interval_hours"] = json!(0);
    create(&router, zero).await.assert_invalid("interval_hours");

    let mut long = url_list("long");
    long["interval_hours"] = json!(169);
    create(&router, long).await.assert_invalid("interval_hours");

    let mut exempt = url_list("exempt");
    exempt["exempt"] = json!(["192.0.2.0/24", "not-a-prefix"]);
    create(&router, exempt).await.assert_invalid("exempt");
    let mut wide = url_list("wide");
    wide["exempt"] = json!(["192.0.2.0/33"]);
    create(&router, wide).await.assert_invalid("exempt");

    create(&router, url_list("")).await.assert_invalid("name");

    created(&router, url_list("Ads")).await;
    create(&router, url_list("ads"))
        .await
        .assert_invalid("name");
    create(&router, url_list("ADS"))
        .await
        .assert_invalid("name");

    let list = send(&router, "GET", "/dns/lists", None).await;
    assert_eq!(list.body["items"].as_array().expect("items").len(), 1);
}

#[tokio::test]
async fn a_fetch_writes_the_version_and_a_second_one_finds_it_unchanged() {
    let App {
        router,
        store,
        fetcher,
        jobs,
    } = app();
    let list = created(&router, url_list("hosts")).await;
    let id = list.id();
    assert_eq!(version_rows(&store, &id).await, Vec::<u64>::new());

    let started = fetch(&router, &id).await;
    let job = started.job();
    let finished = jobs.job(job.parse().expect("job id")).expect("job ran");
    assert_eq!(finished.state, JobState::Succeeded, "{finished:?}");

    let first = read(&router, &id).await;
    let version = &first.body["version"];
    assert_eq!(version["revision"], 1, "{}", first.body);
    assert_eq!(version["entries"], 2, "{}", first.body);
    assert_eq!(version["etag"], "\"v1\"");
    assert!(version["bytes"].as_u64().expect("bytes") > 0);
    assert!(version["fetched"].is_string(), "{}", first.body);
    assert!(first.body.get("last_error").is_none(), "{}", first.body);
    assert!(first.body["last_checked"].is_string(), "{}", first.body);
    // The fetch changes no part of the row: its entity tag is the one of the create.
    assert_eq!(first.etag(), list.etag());
    assert_eq!(version_rows(&store, &id).await, [1]);
    assert_eq!(fetcher.calls(), [(URL.to_owned(), None)]);

    // The same entity tag: the source answers "not modified" and nothing is written.
    let again = fetch(&router, &id).await;
    let job = again.job();
    let finished = jobs.job(job.parse().expect("job id")).expect("job ran");
    assert_eq!(finished.state, JobState::Succeeded, "{finished:?}");
    assert_eq!(
        fetcher.calls()[1],
        (URL.to_owned(), Some("\"v1\"".to_owned()))
    );
    let second = read(&router, &id).await;
    assert_eq!(second.body["version"], first.body["version"]);
    assert_eq!(version_rows(&store, &id).await, [1]);
    assert!(second.body["last_checked"].is_string(), "{}", second.body);

    // A changed source writes revision 2 and removes the one before.
    fetcher.serve(HOSTS_NEXT, "\"v2\"");
    fetch(&router, &id).await.job();
    let third = read(&router, &id).await;
    assert_eq!(third.body["version"]["revision"], 2, "{}", third.body);
    assert_eq!(third.body["version"]["entries"], 3, "{}", third.body);
    assert_eq!(third.body["version"]["etag"], "\"v2\"");
    assert_eq!(version_rows(&store, &id).await, [2]);
}

#[tokio::test]
async fn a_failed_fetch_keeps_the_version_and_shows_its_error() {
    let App {
        router,
        store,
        fetcher,
        jobs,
    } = app();
    let id = created(&router, url_list("hosts")).await.id();
    fetch(&router, &id).await.job();
    let before = read(&router, &id).await;
    assert_eq!(before.body["version"]["revision"], 1, "{}", before.body);

    fetcher.fail(Some("the server answered 503 (test)"));
    let job = fetch(&router, &id).await.job();
    // The request is accepted; the job it started ends rolled back.
    let finished = jobs.job(job.parse().expect("job id")).expect("job ran");
    assert_ne!(finished.state, JobState::Succeeded, "{finished:?}");
    assert_eq!(
        finished.error.expect("job error").code,
        "dns.list.fetch_failed"
    );

    let after = read(&router, &id).await;
    assert_eq!(after.body["version"], before.body["version"]);
    assert_eq!(after.body["last_error"], "dns.list.fetch_failed");
    assert_eq!(
        after.body["last_error_detail"],
        "the server answered 503 (test)"
    );
    assert!(after.body["last_checked"].is_string(), "{}", after.body);
    assert_eq!(version_rows(&store, &id).await, [1]);

    // The next attempt that succeeds clears the error.
    fetcher.fail(None);
    fetch(&router, &id).await.job();
    let cleared = read(&router, &id).await;
    assert!(cleared.body.get("last_error").is_none(), "{}", cleared.body);
    assert!(
        cleared.body.get("last_error_detail").is_none(),
        "{}",
        cleared.body
    );
    assert_eq!(cleared.body["version"], before.body["version"]);

    // A list that never fetched successfully shows the error and no version.
    fetcher.fail(Some("no route (test)"));
    let fresh = created(&router, url_list("fresh")).await.id();
    fetch(&router, &fresh).await.job();
    let shown = read(&router, &fresh).await;
    assert!(shown.body.get("version").is_none(), "{}", shown.body);
    assert_eq!(shown.body["last_error"], "dns.list.fetch_failed");
    assert_eq!(shown.body["last_error_detail"], "no route (test)");
}

#[tokio::test]
async fn a_fetch_of_an_uploaded_or_unknown_list_is_refused() {
    let App { router, .. } = app();
    let id = created(&router, upload_list("uploaded")).await.id();
    let refused = fetch(&router, &id).await;
    refused.assert_problem(409, "dns.list.invalid");
    assert_eq!(
        refused.body["params"]["field"], "source",
        "{}",
        refused.body
    );

    fetch(&router, MISSING)
        .await
        .assert_problem(404, "dns.list.not_found");
    fetch(&router, "not-an-id")
        .await
        .assert_problem(400, "sys.invalid_request");
}

#[tokio::test]
async fn an_upload_compiles_the_file_into_a_version() {
    let App {
        router,
        store,
        jobs,
        ..
    } = app();
    let id = created(&router, upload_list("uploaded")).await.id();

    let started = upload(&router, &id, DOMAINS, false).await;
    let job = started.job();
    let finished = jobs.job(job.parse().expect("job id")).expect("job ran");
    assert_eq!(finished.state, JobState::Succeeded, "{finished:?}");

    // `sub.ads.example.test` lies under `ads.example.test`.
    let first = read(&router, &id).await;
    assert_eq!(first.body["version"]["revision"], 1, "{}", first.body);
    assert_eq!(first.body["version"]["entries"], 2, "{}", first.body);
    assert!(
        first.body["version"].get("etag").is_none(),
        "{}",
        first.body
    );
    assert!(first.body["last_checked"].is_string(), "{}", first.body);
    assert_eq!(version_rows(&store, &id).await, [1]);

    upload(&router, &id, "other.example.test\n", true)
        .await
        .job();
    let second = read(&router, &id).await;
    assert_eq!(second.body["version"]["revision"], 2, "{}", second.body);
    assert_eq!(second.body["version"]["entries"], 1, "{}", second.body);
    assert_eq!(version_rows(&store, &id).await, [2]);

    // Lines that hold no name are skipped, never an error.
    upload(
        &router,
        &id,
        "# nothing but a comment\nhttps://x.test/y\n",
        false,
    )
    .await
    .job();
    let empty = read(&router, &id).await;
    assert_eq!(empty.body["version"]["revision"], 3, "{}", empty.body);
    assert_eq!(empty.body["version"]["entries"], 0, "{}", empty.body);
}

#[tokio::test]
async fn an_upload_to_a_url_or_unknown_list_is_refused() {
    let App {
        router,
        store,
        fetcher,
        ..
    } = app();
    let id = created(&router, url_list("hosts")).await.id();
    let refused = upload(&router, &id, DOMAINS, false).await;
    refused.assert_problem(409, "dns.list.invalid");
    assert_eq!(
        refused.body["params"]["field"], "source",
        "{}",
        refused.body
    );
    assert_eq!(version_rows(&store, &id).await, Vec::<u64>::new());
    assert_eq!(fetcher.calls(), Vec::<(String, Option<String>)>::new());

    upload(&router, MISSING, DOMAINS, false)
        .await
        .assert_problem(404, "dns.list.not_found");
    upload(&router, "not-an-id", DOMAINS, false)
        .await
        .assert_problem(400, "sys.invalid_request");
}

#[tokio::test]
async fn a_file_over_the_limit_is_refused() {
    let App { router, store, .. } = build(Some(4 * 1024), true);
    let id = created(&router, upload_list("uploaded")).await.id();
    let big = "ads.example.test\n".repeat(400);
    assert!(big.len() > 4 * 1024);

    // With and without a declared length.
    upload(&router, &id, &big, true)
        .await
        .assert_problem(413, "sys.body_too_large");
    upload(&router, &id, &big, false)
        .await
        .assert_problem(413, "sys.body_too_large");
    assert_eq!(version_rows(&store, &id).await, Vec::<u64>::new());
    let after = read(&router, &id).await;
    assert!(after.body.get("version").is_none(), "{}", after.body);

    // A file within the limit is taken.
    upload(&router, &id, "ads.example.test\n", true).await.job();
    let ok = read(&router, &id).await;
    assert_eq!(ok.body["version"]["entries"], 1, "{}", ok.body);
}

#[tokio::test]
async fn a_list_is_changed_with_its_etag() {
    let App { router, .. } = app();
    let list = created(&router, url_list("hosts")).await;
    let id = list.id();
    let path = list_path(&id);
    let etag = list.etag();

    let patched = send_with(
        &router,
        "PATCH",
        &path,
        Some(json!({
            "exempt": ["192.0.2.0/24", "2001:db8::10"],
            "kind": "allow",
            "enabled": false,
            "description": "first"
        })),
        &[("if-match", &etag)],
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.body);
    assert_eq!(patched.body["kind"], "allow");
    assert_eq!(patched.body["enabled"], false);
    assert_eq!(
        patched.body["exempt"],
        json!(["192.0.2.0/24", "2001:db8::10/128"])
    );
    assert_eq!(patched.body["description"], "first");
    assert_eq!(patched.body["name"], "hosts");
    assert_ne!(patched.etag(), etag);
    assert_eq!(read(&router, &id).await.body, patched.body);

    // The stale revision is refused.
    send_with(
        &router,
        "PATCH",
        &path,
        Some(json!({"enabled": true})),
        &[("if-match", &etag)],
    )
    .await
    .assert_problem(412, "sys.store.precondition_failed");
    assert_eq!(read(&router, &id).await.body["enabled"], false);

    // The exempt prefixes are replaced whole; an empty description clears it.
    let cleared = send(
        &router,
        "PATCH",
        &path,
        Some(json!({"exempt": [], "description": "", "kind": "block", "enabled": true})),
    )
    .await;
    assert_eq!(cleared.status, StatusCode::OK, "{}", cleared.body);
    assert!(cleared.body.get("exempt").is_none(), "{}", cleared.body);
    assert!(
        cleared.body.get("description").is_none(),
        "{}",
        cleared.body
    );
    assert_eq!(cleared.body["kind"], "block");
    assert_eq!(cleared.body["enabled"], true);

    // A change that changes nothing keeps the revision.
    let same = send(&router, "PATCH", &path, Some(json!({"enabled": true}))).await;
    assert_eq!(same.status, StatusCode::OK, "{}", same.body);
    assert_eq!(same.etag(), cleared.etag());

    send(&router, "PATCH", &path, Some(json!({"exempt": ["bad"]})))
        .await
        .assert_invalid("exempt");
    send(&router, "PATCH", &path, Some(json!({"interval_hours": 0})))
        .await
        .assert_invalid("interval_hours");
    created(&router, url_list("other")).await;
    send(&router, "PATCH", &path, Some(json!({"name": "OTHER"})))
        .await
        .assert_invalid("name");
    send(
        &router,
        "PATCH",
        &format!("/dns/lists/{MISSING}"),
        Some(json!({"enabled": true})),
    )
    .await
    .assert_problem(404, "dns.list.not_found");
    send(
        &router,
        "PATCH",
        "/dns/lists/not-an-id",
        Some(json!({"enabled": true})),
    )
    .await
    .assert_problem(400, "sys.invalid_request");
}

#[tokio::test]
async fn a_new_source_or_format_drops_the_versions() {
    let App {
        router,
        store,
        fetcher,
        ..
    } = app();
    let id = created(&router, url_list("hosts")).await.id();
    let path = list_path(&id);
    fetch(&router, &id).await.job();
    assert_eq!(read(&router, &id).await.body["version"]["revision"], 1);

    // Settings that do not touch the names keep the version.
    for change in [
        json!({"enabled": false}),
        json!({"interval_hours": 6}),
        json!({"action": {"kind": "nodata"}}),
        json!({"kind": "allow"}),
    ] {
        let kept = send(&router, "PATCH", &path, Some(change)).await;
        assert_eq!(kept.status, StatusCode::OK, "{}", kept.body);
        assert_eq!(kept.body["version"]["revision"], 1, "{}", kept.body);
    }
    assert_eq!(version_rows(&store, &id).await, [1]);

    // A new format drops it.
    let format = send(&router, "PATCH", &path, Some(json!({"format": "domains"}))).await;
    assert_eq!(format.status, StatusCode::OK, "{}", format.body);
    assert!(format.body.get("version").is_none(), "{}", format.body);
    assert_eq!(version_rows(&store, &id).await, Vec::<u64>::new());

    // The next fetch writes the first version again; a new source drops it again.
    fetcher.serve(HOSTS_NEXT, "\"v9\"");
    fetch(&router, &id).await.job();
    let fetched = read(&router, &id).await;
    assert_eq!(fetched.body["version"]["revision"], 1, "{}", fetched.body);
    assert_eq!(fetched.body["version"]["etag"], "\"v9\"");
    let source = send(
        &router,
        "PATCH",
        &path,
        Some(json!({"source": {"kind": "url", "url": "https://lists.example.test/other.txt"}})),
    )
    .await;
    assert_eq!(source.status, StatusCode::OK, "{}", source.body);
    assert!(source.body.get("version").is_none(), "{}", source.body);
    assert_eq!(
        source.body["source"]["url"],
        "https://lists.example.test/other.txt"
    );
    assert_eq!(version_rows(&store, &id).await, Vec::<u64>::new());
    assert!(read(&router, &id).await.body.get("version").is_none());

    // The same source and format again is no change.
    fetch(&router, &id).await.job();
    let again = send(
        &router,
        "PATCH",
        &path,
        Some(json!({"source": {"kind": "url", "url": "https://lists.example.test/other.txt"}, "format": "domains"})),
    )
    .await;
    assert_eq!(again.body["version"]["revision"], 1, "{}", again.body);

    // An uploaded list drops its version the same way.
    let uploaded = created(&router, upload_list("uploaded")).await.id();
    upload(&router, &uploaded, DOMAINS, false).await.job();
    assert_eq!(
        read(&router, &uploaded).await.body["version"]["revision"],
        1
    );
    let hosts = send(
        &router,
        "PATCH",
        &list_path(&uploaded),
        Some(json!({"format": "hosts"})),
    )
    .await;
    assert!(hosts.body.get("version").is_none(), "{}", hosts.body);
    assert_eq!(version_rows(&store, &uploaded).await, Vec::<u64>::new());
}

#[tokio::test]
async fn a_deleted_list_is_gone_with_its_versions() {
    let App { router, store, .. } = app();
    let list = created(&router, url_list("hosts")).await;
    let id = list.id();
    let path = list_path(&id);
    fetch(&router, &id).await.job();
    assert_eq!(version_rows(&store, &id).await, [1]);

    // A stale `If-Match` refuses the delete.
    let etag = read(&router, &id).await.etag();
    send(
        &router,
        "PATCH",
        &path,
        Some(json!({"description": "changed"})),
    )
    .await;
    send_with(&router, "DELETE", &path, None, &[("if-match", &etag)])
        .await
        .assert_problem(412, "sys.store.precondition_failed");
    assert_eq!(version_rows(&store, &id).await, [1]);

    let deleted = send(&router, "DELETE", &path, None).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    send(&router, "GET", &path, None)
        .await
        .assert_problem(404, "dns.list.not_found");
    send(&router, "DELETE", &path, None)
        .await
        .assert_problem(404, "dns.list.not_found");
    assert_eq!(version_rows(&store, &id).await, Vec::<u64>::new());
    fetch(&router, &id)
        .await
        .assert_problem(404, "dns.list.not_found");
    let list = send(&router, "GET", "/dns/lists", None).await;
    assert_eq!(list.body["items"], json!([]));
}

#[tokio::test]
async fn every_change_is_audited_in_order() {
    let App { router, store, .. } = app();
    let url = created(&router, url_list("hosts")).await.id();
    let file = created(&router, upload_list("uploaded")).await.id();
    fetch(&router, &url).await.job();
    upload(&router, &file, DOMAINS, false).await.job();
    let patched = send(
        &router,
        "PATCH",
        &list_path(&url),
        Some(json!({"description": "named"})),
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.body);
    let deleted = send(&router, "DELETE", &list_path(&url), None).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);

    let actions = audit_actions(&store).await;
    let lists: Vec<&str> = actions
        .iter()
        .map(String::as_str)
        .filter(|action| action.starts_with("dns.list."))
        .collect();
    // The record of the fetch or the upload is written before its job, so it precedes the
    // compile record.
    assert_eq!(
        lists,
        [
            "dns.list.create",
            "dns.list.create",
            "dns.list.fetch",
            "dns.list.compile",
            "dns.list.upload",
            "dns.list.compile",
            "dns.list.update",
            "dns.list.delete"
        ],
        "{actions:?}"
    );
}

#[tokio::test]
async fn a_fetch_that_found_nothing_new_writes_no_compile_record() {
    let App { router, store, .. } = app();
    let id = created(&router, url_list("hosts")).await.id();
    fetch(&router, &id).await.job();
    fetch(&router, &id).await.job();
    let actions = audit_actions(&store).await;
    let count = |name: &str| actions.iter().filter(|action| *action == name).count();
    assert_eq!(count("dns.list.fetch"), 2, "{actions:?}");
    assert_eq!(count("dns.list.compile"), 1, "{actions:?}");
}

#[tokio::test]
async fn without_the_zone_service_the_module_is_disabled() {
    let (bare, _) = tenko_api::api(AppState::default());
    let path = format!("/dns/lists/{MISSING}");
    send(&bare, "GET", "/dns/lists", None)
        .await
        .assert_problem(409, "dns.module.disabled");
    create(&bare, url_list("hosts"))
        .await
        .assert_problem(409, "dns.module.disabled");
    send(&bare, "GET", &path, None)
        .await
        .assert_problem(409, "dns.module.disabled");
    send(&bare, "PATCH", &path, Some(json!({"enabled": true})))
        .await
        .assert_problem(409, "dns.module.disabled");
    send(&bare, "DELETE", &path, None)
        .await
        .assert_problem(409, "dns.module.disabled");
    fetch(&bare, MISSING)
        .await
        .assert_problem(409, "dns.module.disabled");
    upload(&bare, MISSING, DOMAINS, false)
        .await
        .assert_problem(409, "dns.module.disabled");
}

#[tokio::test]
async fn without_the_list_staging_the_jobs_are_disabled() {
    let App { router, .. } = build(None, false);
    let url = created(&router, url_list("hosts")).await.id();
    let file = created(&router, upload_list("uploaded")).await.id();
    fetch(&router, &url)
        .await
        .assert_problem(409, "dns.module.disabled");
    upload(&router, &file, DOMAINS, false)
        .await
        .assert_problem(409, "dns.module.disabled");
    // The rows are still served.
    assert_eq!(read(&router, &url).await.body["name"], "hosts");
}
