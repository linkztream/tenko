//! The API client against a real server on loopback, and against a stub that records the
//! requests it receives.
//!
//! The live tests start the full server with plain HTTP (the Lab profile) and drive it through
//! `tenko_api::client`. The stub tests pin what the client puts on the wire (headers, query,
//! body) and how it maps answers the real server never gives (a proxy's error page, a body
//! that is not UTF-8, a redirect, a reply that never comes).
#![cfg(all(feature = "server", feature = "client"))]

use std::{fmt::Write as _, net::SocketAddr, time::Duration};

use serde_json::{Value, json};
use tenko_api::{
    RunningServer, ServerConfig,
    client::{Client, ClientConfig, ClientError},
    dto::{Page, SortOrder, audit::AuditQuery, system::TlsMode as StatusTlsMode},
    problem::{ProblemDetails, codes},
    state::AppState,
};
use tenko_cluster::ca::{CertSource, TlsMaterial, TlsMode, TlsPolicy, TlsService, TrustedProxies};
use tenko_core::{
    AuditSeq, Principal, Revision, SystemComponent, Timestamp,
    audit::{AuditAction, AuditDraft, AuditRecord, Digest},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(10);
const PROBLEM_JSON: &str = "application/problem+json";

// ---------------------------------------------------------------------------------------
// The real server
// ---------------------------------------------------------------------------------------

/// Plain HTTP from every source, the simplest way to reach the server.
fn lab_config() -> ServerConfig {
    let mode = TlsMode::ReverseProxy {
        trusted_proxies: TrustedProxies::default(),
        proxy_protocol: false,
        public_host: "ddi.example.org".to_owned(),
    };
    let tls = TlsService::new(mode, TlsPolicy::default()).expect("tls service");
    let mut config = ServerConfig::new(
        vec!["127.0.0.1:0".parse().expect("address")],
        tls,
        TlsPolicy::default(),
    );
    config.lab_plain_http = true;
    config
}

/// A running server and a client for it.
struct Live {
    server: RunningServer,
    client: Client,
}

impl Live {
    async fn start() -> Self {
        let server = tenko_api::start(lab_config(), AppState::default())
            .await
            .expect("the server starts");
        let client = Client::new(ClientConfig::new(format!(
            "http://{}",
            server.local_addrs()[0]
        )))
        .expect("client");
        Self { server, client }
    }

    async fn finish(self) {
        self.server.shutdown();
        timeout(WAIT, self.server.wait())
            .await
            .expect("shutdown in time")
            .expect("clean shutdown");
    }
}

fn problem_of(error: ClientError) -> ProblemDetails {
    match error {
        ClientError::Problem(problem) => problem,
        other => panic!("expected problem details, got {other:?}"),
    }
}

#[tokio::test]
async fn health_and_ready() {
    let live = Live::start().await;
    assert!(live.client.base_url().starts_with("http://127.0.0.1:"));

    let health = live.client.health().await.expect("health");
    assert_eq!(health.status, "ok");
    assert_eq!(health.version, tenko_api::version());

    let ready = live.client.ready().await.expect("ready");
    assert_eq!(ready.status, "ready");
    live.finish().await;
}

#[tokio::test]
async fn clones_work_from_spawned_tasks() {
    let live = Live::start().await;
    let tasks: Vec<_> = (0..4)
        .map(|_| {
            let client = live.client.clone();
            tokio::spawn(async move {
                let refused = client
                    .post::<_, Value>("/health", &json!({}), None)
                    .await
                    .expect_err("health is read-only");
                (client.health().await, refused)
            })
        })
        .collect();
    for task in tasks {
        let (health, refused) = task.await.expect("task");
        assert_eq!(health.expect("health").status, "ok");
        assert_eq!(problem_of(refused).status, 405);
    }
    live.finish().await;
}

#[tokio::test]
async fn system_status_reports_plain_http() {
    let live = Live::start().await;
    let status = live.client.system_status().await.expect("status");
    assert_eq!(status.version, tenko_api::version());
    assert_eq!(
        status.tls.expect("a listener runs").mode,
        StatusTlsMode::Plain
    );
    assert!(
        status
            .warnings
            .iter()
            .any(|warning| warning.code == "sys.tls.plain_http"),
        "{:?}",
        status.warnings
    );
    live.finish().await;
}

#[tokio::test]
async fn openapi_document() {
    let live = Live::start().await;
    let document = live.client.openapi().await.expect("openapi");
    assert_eq!(document["info"]["title"], "Tenko DDI API");
    assert!(document["paths"]["/api/v1/audit/verify"].is_object());
    live.finish().await;
}

#[tokio::test]
async fn metrics_are_text_that_ends_with_eof() {
    let live = Live::start().await;
    live.client.health().await.expect("some traffic");
    let metrics = live.client.metrics().await.expect("metrics");
    assert!(metrics.ends_with("# EOF\n"), "{metrics:?}");
    live.finish().await;
}

#[tokio::test]
async fn audit_on_an_empty_store() {
    let live = Live::start().await;
    let page = live
        .client
        .audit(&AuditQuery::default())
        .await
        .expect("audit page");
    assert_eq!(page.items, Vec::new());
    assert_eq!(page.next_cursor, None);

    let all = live
        .client
        .audit_all(&AuditQuery {
            limit: Some(10),
            ..AuditQuery::default()
        })
        .await
        .expect("all records");
    assert_eq!(all, Vec::new());

    let report = live.client.audit_verify().await.expect("verify");
    assert!(report.intact);
    assert_eq!(report.checked, 0);
    assert!(report.first_break.is_none());

    let missing = problem_of(
        live.client
            .audit_record(AuditSeq(1))
            .await
            .expect_err("no such record"),
    );
    assert_eq!(missing.status, 404);
    assert_eq!(missing.code, codes::AUDIT_NOT_FOUND);
    live.finish().await;
}

#[tokio::test]
async fn unknown_routes_are_problem_details() {
    let live = Live::start().await;
    let error = live
        .client
        .get::<Value>("/nope")
        .await
        .expect_err("no such route");
    let problem = error.problem().expect("problem details");
    assert_eq!(problem.status, 404);
    assert_eq!(problem.code, codes::ROUTE_NOT_FOUND);
    assert!(
        problem.detail.contains("/api/v1/nope"),
        "{}",
        problem.detail
    );
    assert!(error.to_string().starts_with("sys.route_not_found (404)"));
    live.finish().await;
}

#[tokio::test]
async fn a_wrong_method_is_problem_details() {
    let live = Live::start().await;
    let problem = problem_of(
        live.client
            .post::<_, Value>("/health", &json!({}), None)
            .await
            .expect_err("health is read-only"),
    );
    assert_eq!(problem.status, 405);
    assert_eq!(problem.code, codes::METHOD_NOT_ALLOWED);
    live.finish().await;
}

#[tokio::test]
async fn a_token_does_not_disturb_open_endpoints() {
    let live = Live::start().await;
    let mut config = ClientConfig::new(live.client.base_url());
    config.token = Some("tk_0000000000000000".to_owned());
    let client = Client::new(config).expect("client");
    assert_eq!(client.health().await.expect("health").status, "ok");
    live.finish().await;
}

#[tokio::test]
async fn a_closed_port_is_a_transport_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("address");
    drop(listener);
    let client = Client::new(ClientConfig::new(format!("http://{addr}"))).expect("client");
    let error = client.health().await.expect_err("nothing listens");
    assert!(matches!(error, ClientError::Transport(_)), "{error:?}");
    assert!(error.to_string().starts_with("request failed:"), "{error}");
}

// ---------------------------------------------------------------------------------------
// Configuration errors
// ---------------------------------------------------------------------------------------

#[test]
fn an_invalid_base_url_is_an_invalid_config() {
    for url in [
        "",
        "not a url",
        "ddi.example.org",
        "ftp://ddi.example.org",
        "https://",
    ] {
        let error = Client::new(ClientConfig::new(url)).expect_err(url);
        assert!(
            matches!(error, ClientError::InvalidConfig(_)),
            "{url}: {error:?}"
        );
        assert!(error.problem().is_none());
    }
}

#[test]
fn a_garbage_root_ca_is_an_invalid_config() {
    for pem in [
        &b"this is not a certificate"[..],
        b"",
        b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    ] {
        let mut config = ClientConfig::new("https://ddi.example.org");
        config.root_ca_pem = Some(pem.to_vec());
        let error = Client::new(config).expect_err("garbage");
        assert!(matches!(error, ClientError::InvalidConfig(_)), "{error:?}");
    }
}

#[test]
fn debug_output_never_contains_the_token() {
    let token = "tk_f00dfeedf00dfeed";
    let mut config = ClientConfig::new("https://ddi.example.org");
    config.token = Some(token.to_owned());
    assert!(!format!("{config:?}").contains(token));
    let client = Client::new(config).expect("client");
    let debug = format!("{client:?}");
    assert!(!debug.contains(token), "{debug}");
    assert!(!format!("{:?}", client.clone()).contains(token));
    assert!(debug.contains("ddi.example.org"), "{debug}");
}

#[test]
fn the_default_timeout_is_thirty_seconds() {
    assert_eq!(
        ClientConfig::new("https://ddi.example.org").timeout,
        Duration::from_secs(30)
    );
}

#[tokio::test]
async fn bad_paths_and_headers_are_refused_before_anything_is_sent() {
    // Nothing listens on this address; a request that reached the network would fail with
    // a transport error instead.
    let client = Client::new(ClientConfig::new("http://127.0.0.1:9")).expect("client");
    for path in ["health", "", "/../x"] {
        let error = client.get::<Value>(path).await.expect_err(path);
        assert!(
            matches!(error, ClientError::InvalidConfig(_)),
            "{path}: {error:?}"
        );
    }
    let error = client
        .post::<_, Value>("/things", &json!({}), Some("two\nlines"))
        .await
        .expect_err("a key with a line break");
    assert!(matches!(error, ClientError::InvalidConfig(_)), "{error:?}");
}

// ---------------------------------------------------------------------------------------
// HTTPS with the internal CA
// ---------------------------------------------------------------------------------------

/// A test CA, its PEM, and a server certificate for 127.0.0.1.
fn loopback_pki() -> (String, TlsMaterial) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Tenko test CA");
    let ca_key = rcgen::KeyPair::generate().expect("key");
    let issuer = rcgen::CertifiedIssuer::self_signed(params, ca_key).expect("CA");

    let key = rcgen::KeyPair::generate().expect("key");
    let leaf = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()])
        .expect("params")
        .signed_by(&key, &issuer)
        .expect("leaf");
    let material = TlsMaterial::from_pem(
        leaf.pem().as_bytes(),
        key.serialize_pem().as_bytes(),
        CertSource::Inline,
    )
    .expect("material");
    (issuer.as_ref().pem(), material)
}

#[tokio::test]
async fn the_root_ca_makes_the_internal_ca_trusted() {
    let (root_pem, material) = loopback_pki();
    let tls = TlsService::new(TlsMode::InternalCa, TlsPolicy::default()).expect("tls service");
    tls.install(material);
    let config = ServerConfig::new(
        vec!["127.0.0.1:0".parse().expect("address")],
        tls,
        TlsPolicy::default(),
    );
    let server = tenko_api::start(config, AppState::default())
        .await
        .expect("the server starts");
    let base_url = format!("https://{}", server.local_addrs()[0]);

    let mut trusting = ClientConfig::new(&base_url);
    trusting.root_ca_pem = Some(root_pem.into_bytes());
    let trusting = Client::new(trusting).expect("client");
    let status = trusting.system_status().await.expect("status over TLS");
    assert_eq!(
        status.tls.expect("listener").mode,
        StatusTlsMode::InternalCa
    );

    // Without the root, the certificate is rejected, and the error says why.
    let default = Client::new(ClientConfig::new(&base_url)).expect("client");
    let error = default.health().await.expect_err("unknown issuer");
    assert!(matches!(error, ClientError::Transport(_)), "{error:?}");
    assert!(
        error
            .to_string()
            .to_ascii_lowercase()
            .contains("certificate"),
        "{error}"
    );

    server.shutdown();
    timeout(WAIT, server.wait())
        .await
        .expect("shutdown in time")
        .expect("clean shutdown");
}

// ---------------------------------------------------------------------------------------
// A stub server that records requests
// ---------------------------------------------------------------------------------------

/// One request as the stub received it.
#[derive(Debug)]
struct Recorded {
    line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Recorded {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("JSON request body")
    }
}

/// A server on loopback that answers the n-th connection with the n-th canned reply and
/// records what it received.
struct Stub {
    addr: SocketAddr,
    task: JoinHandle<Vec<Recorded>>,
}

impl Stub {
    async fn serve(replies: Vec<Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        let task = tokio::spawn(async move {
            let mut seen = Vec::new();
            for reply in replies {
                let (mut stream, _) = listener.accept().await.expect("accept");
                seen.push(read_request(&mut stream).await);
                stream.write_all(&reply).await.expect("write the reply");
                let _ = stream.shutdown().await;
            }
            seen
        });
        Self { addr, task }
    }

    fn client(&self) -> Client {
        Client::new(ClientConfig::new(format!("http://{}", self.addr))).expect("client")
    }

    fn client_with_token(&self, token: &str) -> Client {
        let mut config = ClientConfig::new(format!("http://{}", self.addr));
        config.token = Some(token.to_owned());
        Client::new(config).expect("client")
    }

    async fn requests(self) -> Vec<Recorded> {
        timeout(WAIT, self.task)
            .await
            .expect("the stub saw every request")
            .expect("stub task")
    }
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> Recorded {
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 1024];
    let head_end = loop {
        if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        let read = stream.read(&mut chunk).await.expect("read the request");
        assert!(read > 0, "the client closed before the request head ended");
        raw.extend_from_slice(&chunk[..read]);
    };
    let head = std::str::from_utf8(&raw[..head_end]).expect("ASCII head");
    let mut lines = head.split("\r\n");
    let line = lines.next().expect("request line").to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .map_or(0, |(_, value)| value.parse().expect("content length"));
    while raw.len() < head_end + length {
        let read = stream.read(&mut chunk).await.expect("read the body");
        assert!(read > 0, "the client closed before the body ended");
        raw.extend_from_slice(&chunk[..read]);
    }
    Recorded {
        line,
        headers,
        body: raw[head_end..head_end + length].to_vec(),
    }
}

/// A complete HTTP/1.1 reply that closes the connection.
fn reply(status: &str, content_type: Option<&str>, body: impl AsRef<[u8]>) -> Vec<u8> {
    let body = body.as_ref();
    let mut head = format!("HTTP/1.1 {status}\r\n");
    if let Some(content_type) = content_type {
        write!(head, "content-type: {content_type}\r\n").expect("write to a string");
    }
    write!(
        head,
        "content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )
    .expect("write to a string");
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn json_reply(status: &str, body: &Value) -> Vec<u8> {
    reply(status, Some("application/json"), body.to_string())
}

fn record(seq: u64) -> AuditRecord {
    AuditRecord::seal(
        AuditSeq(seq),
        Revision(seq),
        Timestamp::from_unix_nanos(i128::from(seq) * 1_000_000_000).expect("timestamp"),
        Principal::system(SystemComponent::Api),
        None,
        AuditDraft::success(AuditAction::from_static("sys.setup.complete"), vec![]),
        Digest::ZERO,
    )
    .expect("sealed record")
}

fn page_reply(records: &[u64], next_cursor: Option<&str>) -> Vec<u8> {
    let page = Page::new(
        records.iter().copied().map(record).collect(),
        next_cursor.map(str::to_owned),
        Revision(9),
    );
    json_reply("200 OK", &serde_json::to_value(page).expect("page"))
}

#[tokio::test]
async fn every_request_identifies_the_client_and_the_token() {
    let stub = Stub::serve(vec![json_reply(
        "200 OK",
        &json!({ "status": "ok", "version": "0.0.1" }),
    )])
    .await;
    stub.client_with_token("tk_example_token")
        .health()
        .await
        .expect("health");
    let requests = stub.requests().await;
    let request = &requests[0];
    assert_eq!(request.line, "GET /api/v1/health HTTP/1.1");
    assert_eq!(
        request.header("authorization"),
        Some("Bearer tk_example_token")
    );
    assert_eq!(request.header("accept"), Some("application/json"));
    assert_eq!(
        request.header("user-agent"),
        Some(format!("tenko/{}", tenko_api::version()).as_str())
    );
    assert!(request.header("idempotency-key").is_none());
    assert!(request.header("if-match").is_none());
}

#[tokio::test]
async fn no_token_means_no_authorization_header() {
    let stub = Stub::serve(vec![json_reply(
        "200 OK",
        &json!({ "status": "ok", "version": "0.0.1" }),
    )])
    .await;
    stub.client().health().await.expect("health");
    let requests = stub.requests().await;
    assert!(requests[0].header("authorization").is_none());
}

#[tokio::test]
async fn post_sends_the_body_and_the_idempotency_key() {
    let stub = Stub::serve(vec![
        json_reply("201 Created", &json!({ "id": 7 })),
        json_reply("201 Created", &json!({ "id": 8 })),
    ])
    .await;
    let client = stub.client();
    let body = json!({ "cidr": "192.0.2.0/24", "description": "documentation range" });

    let created: Value = client
        .post("/prefixes", &body, Some("import-0001"))
        .await
        .expect("created");
    assert_eq!(created["id"], 7);
    let created: Value = client
        .post("/prefixes", &body, None)
        .await
        .expect("created");
    assert_eq!(created["id"], 8);

    let requests = stub.requests().await;
    assert_eq!(requests[0].line, "POST /api/v1/prefixes HTTP/1.1");
    assert_eq!(requests[0].header("idempotency-key"), Some("import-0001"));
    assert_eq!(requests[0].header("content-type"), Some("application/json"));
    assert_eq!(requests[0].header("accept"), Some("application/json"));
    assert_eq!(requests[0].json(), body);
    assert_eq!(requests[1].line, "POST /api/v1/prefixes HTTP/1.1");
    assert!(requests[1].header("idempotency-key").is_none());
}

#[tokio::test]
async fn patch_and_delete_send_if_match_with_the_revision_in_quotes() {
    let stub = Stub::serve(vec![
        json_reply("200 OK", &json!({ "revision": 8 })),
        reply("204 No Content", None, ""),
        reply("204 No Content", None, ""),
        json_reply("200 OK", &json!({ "revision": 9 })),
    ])
    .await;
    let client = stub.client();

    let updated: Value = client
        .patch(
            "/prefixes/p1",
            &json!({ "description": "edited" }),
            Some(Revision(7)),
        )
        .await
        .expect("patched");
    assert_eq!(updated["revision"], 8);
    client
        .delete("/prefixes/p1", Some(Revision(8)))
        .await
        .expect("deleted");
    client.delete("/prefixes/p2", None).await.expect("deleted");
    let _: Value = client
        .patch("/prefixes/p3", &json!({}), None)
        .await
        .expect("patched");

    let requests = stub.requests().await;
    assert_eq!(requests[0].line, "PATCH /api/v1/prefixes/p1 HTTP/1.1");
    assert_eq!(requests[0].header("if-match"), Some("\"7\""));
    assert_eq!(requests[0].json(), json!({ "description": "edited" }));
    assert_eq!(requests[1].line, "DELETE /api/v1/prefixes/p1 HTTP/1.1");
    assert_eq!(requests[1].header("if-match"), Some("\"8\""));
    assert_eq!(requests[1].body, Vec::<u8>::new());
    assert_eq!(requests[2].line, "DELETE /api/v1/prefixes/p2 HTTP/1.1");
    assert!(requests[2].header("if-match").is_none());
    assert!(requests[3].header("if-match").is_none());
}

#[tokio::test]
async fn an_empty_answer_decodes_as_unit() {
    let stub = Stub::serve(vec![reply("204 No Content", None, "")]).await;
    let () = stub
        .client()
        .post("/auth/logout", &json!({}), None)
        .await
        .expect("no content");
    stub.requests().await;
}

#[tokio::test]
async fn get_query_encodes_the_parameters() {
    let stub = Stub::serve(vec![page_reply(&[], None)]).await;
    let query = AuditQuery {
        limit: Some(5),
        action: Some("ipam.".to_owned()),
        outcome: Some("denied".to_owned()),
        from: Some(Timestamp::from_unix_nanos(0).expect("timestamp")),
        order: Some(SortOrder::Asc),
        ..AuditQuery::default()
    };
    let page = stub.client().audit(&query).await.expect("page");
    assert_eq!(page.items, Vec::new());
    assert_eq!(page.revision, Revision(9));

    let requests = stub.requests().await;
    assert_eq!(
        requests[0].line,
        "GET /api/v1/audit?limit=5&action=ipam.&outcome=denied&from=1970-01-01T00%3A00%3A00Z&order=asc HTTP/1.1"
    );
}

#[tokio::test]
async fn an_empty_query_adds_no_question_mark() {
    let stub = Stub::serve(vec![page_reply(&[], None)]).await;
    stub.client()
        .audit(&AuditQuery::default())
        .await
        .expect("page");
    assert_eq!(stub.requests().await[0].line, "GET /api/v1/audit HTTP/1.1");
}

#[tokio::test]
async fn audit_all_follows_the_cursors() {
    let stub = Stub::serve(vec![
        page_reply(&[1, 2], Some("c1")),
        page_reply(&[3], Some("c2")),
        page_reply(&[4], None),
    ])
    .await;
    let records = stub
        .client()
        .audit_all(&AuditQuery {
            principal: Some("system:api".to_owned()),
            ..AuditQuery::default()
        })
        .await
        .expect("all records");
    assert_eq!(
        records
            .iter()
            .map(|record| record.seq.get())
            .collect::<Vec<_>>(),
        [1, 2, 3, 4]
    );

    let lines: Vec<String> = stub
        .requests()
        .await
        .into_iter()
        .map(|request| request.line)
        .collect();
    assert_eq!(
        lines,
        [
            "GET /api/v1/audit?limit=1000&principal=system%3Aapi HTTP/1.1",
            "GET /api/v1/audit?limit=1000&cursor=c1&principal=system%3Aapi HTTP/1.1",
            "GET /api/v1/audit?limit=1000&cursor=c2&principal=system%3Aapi HTTP/1.1",
        ]
    );
}

#[tokio::test]
async fn audit_all_keeps_the_callers_page_size_and_start() {
    let stub = Stub::serve(vec![page_reply(&[5], None)]).await;
    let records = stub
        .client()
        .audit_all(&AuditQuery {
            limit: Some(50),
            cursor: Some("start".to_owned()),
            ..AuditQuery::default()
        })
        .await
        .expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(
        stub.requests().await[0].line,
        "GET /api/v1/audit?limit=50&cursor=start HTTP/1.1"
    );
}

#[tokio::test]
async fn audit_all_gives_up_on_a_cursor_that_does_not_advance() {
    let stub = Stub::serve(vec![
        page_reply(&[1], Some("stuck")),
        page_reply(&[2], Some("stuck")),
    ])
    .await;
    let error = stub
        .client()
        .audit_all(&AuditQuery::default())
        .await
        .expect_err("a loop");
    assert!(matches!(error, ClientError::Decode(_)), "{error:?}");
    stub.requests().await;
}

#[tokio::test]
async fn audit_record_asks_for_the_sequence_number() {
    let stub = Stub::serve(vec![json_reply(
        "200 OK",
        &serde_json::to_value(record(42)).expect("record"),
    )])
    .await;
    let found = stub
        .client()
        .audit_record(AuditSeq(42))
        .await
        .expect("record");
    assert_eq!(found, record(42));
    assert_eq!(
        stub.requests().await[0].line,
        "GET /api/v1/audit/42 HTTP/1.1"
    );
}

#[tokio::test]
async fn problem_answers_become_problem_errors() {
    let document = json!({
        "type": "about:blank",
        "status": 409,
        "code": "ipam.prefix.overlap",
        "title": "Prefix overlaps an existing prefix in the VRF",
        "detail": "192.0.2.0/25 overlaps 192.0.2.0/24",
        "params": { "cidr": "192.0.2.0/24" },
        "errors": [{ "field": "cidr", "code": "ipam.prefix.overlap" }]
    });
    let stub = Stub::serve(vec![reply(
        "409 Conflict",
        Some("application/problem+json; charset=utf-8"),
        document.to_string(),
    )])
    .await;
    let error = stub
        .client()
        .post::<_, Value>("/prefixes", &json!({}), None)
        .await
        .expect_err("conflict");
    let problem = error.problem().expect("problem details");
    assert_eq!(problem.status, 409);
    assert_eq!(problem.code, "ipam.prefix.overlap");
    assert_eq!(problem.params["cidr"], "192.0.2.0/24");
    assert_eq!(problem.errors.len(), 1);
    assert_eq!(
        error.to_string(),
        "ipam.prefix.overlap (409): 192.0.2.0/25 overlaps 192.0.2.0/24"
    );
    stub.requests().await;
}

#[tokio::test]
async fn other_error_answers_keep_the_first_two_kib_of_the_body() {
    let page = format!("<html>{}</html>", "x".repeat(5000));
    let stub = Stub::serve(vec![
        reply("502 Bad Gateway", Some("text/html"), &page),
        reply("503 Service Unavailable", None, ""),
    ])
    .await;
    let client = stub.client();

    let error = client.health().await.expect_err("bad gateway");
    let ClientError::UnexpectedStatus { status, body } = &error else {
        panic!("expected an unexpected status, got {error:?}");
    };
    assert_eq!(*status, 502);
    assert_eq!(body.len(), 2048);
    assert!(page.starts_with(body.as_str()));
    assert!(error.problem().is_none());

    let error = client.health().await.expect_err("unavailable");
    assert!(
        matches!(&error, ClientError::UnexpectedStatus { status: 503, body } if body.is_empty()),
        "{error:?}"
    );
    assert_eq!(error.to_string(), "unexpected HTTP status 503");
    stub.requests().await;
}

#[tokio::test]
async fn a_problem_content_type_without_a_problem_document_is_an_unexpected_status() {
    let stub = Stub::serve(vec![
        reply("500 Internal Server Error", Some(PROBLEM_JSON), "not json"),
        reply(
            "500 Internal Server Error",
            Some(PROBLEM_JSON),
            r#"{"status":500}"#,
        ),
        // Plain JSON with the right members is not problem details either.
        reply(
            "500 Internal Server Error",
            Some("application/json"),
            r#"{"type":"about:blank","status":500,"code":"x","title":"t","detail":"d"}"#,
        ),
    ])
    .await;
    let client = stub.client();
    for expected in [
        "not json",
        r#"{"status":500}"#,
        r#"{"type":"about:blank","status":500,"code":"x","title":"t","detail":"d"}"#,
    ] {
        let error = client.health().await.expect_err("server error");
        assert!(
            matches!(&error, ClientError::UnexpectedStatus { status: 500, body } if body == expected),
            "{error:?}"
        );
    }
    stub.requests().await;
}

#[tokio::test]
async fn a_success_that_does_not_fit_is_a_decode_error() {
    let stub = Stub::serve(vec![
        json_reply("200 OK", &json!({ "status": 1 })),
        reply("200 OK", Some("text/html"), "<html>login</html>"),
        reply("200 OK", None, ""),
    ])
    .await;
    let client = stub.client();
    for _ in 0..3 {
        let error = client.health().await.expect_err("not a health document");
        assert!(
            matches!(&error, ClientError::Decode(reason) if reason.starts_with("GET /health")),
            "{error:?}"
        );
        assert!(error.to_string().starts_with("cannot use the response:"));
    }
    stub.requests().await;
}

#[tokio::test]
async fn redirects_are_reported_not_followed() {
    let stub = Stub::serve(vec![Vec::from(
        "HTTP/1.1 301 Moved Permanently\r\nlocation: https://198.51.100.7/api/v1/health\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            .as_bytes(),
    )])
    .await;
    let error = stub
        .client_with_token("tk_example_token")
        .health()
        .await
        .expect_err("a redirect");
    assert!(
        matches!(error, ClientError::UnexpectedStatus { status: 301, .. }),
        "{error:?}"
    );
    // Exactly one request was made: the stub only has one reply to give.
    assert_eq!(stub.requests().await.len(), 1);
}

#[tokio::test]
async fn text_answers_are_returned_as_text() {
    let csv = "id,cidr\r\n1,192.0.2.0/24\r\n2,198.51.100.0/24\r\n";
    let stub = Stub::serve(vec![
        reply("200 OK", Some("text/csv; charset=utf-8"), csv),
        reply("200 OK", Some("text/csv"), [0xff_u8, 0xfe, b'x']),
    ])
    .await;
    let client = stub.client();
    assert_eq!(
        client.get_text("/export/prefixes.csv").await.expect("csv"),
        csv
    );
    let error = client
        .get_text("/export/prefixes.csv")
        .await
        .expect_err("not UTF-8");
    assert!(matches!(error, ClientError::Decode(_)), "{error:?}");

    let requests = stub.requests().await;
    assert_eq!(requests[0].line, "GET /api/v1/export/prefixes.csv HTTP/1.1");
    assert_eq!(requests[0].header("accept"), Some("*/*"));
}

#[tokio::test]
async fn text_errors_are_still_problem_details() {
    let document = json!({
        "type": "about:blank",
        "status": 403,
        "code": "iam.forbidden",
        "title": "Forbidden",
        "detail": "the token lacks the metrics scope"
    });
    let stub = Stub::serve(vec![reply(
        "403 Forbidden",
        Some(PROBLEM_JSON),
        document.to_string(),
    )])
    .await;
    let error = stub.client().metrics().await.expect_err("forbidden");
    assert_eq!(problem_of(error).code, "iam.forbidden");
    stub.requests().await;
}

#[tokio::test]
async fn a_server_that_never_answers_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("address");
    let held = tokio::spawn(async move {
        // Accept and say nothing until the test is over.
        let (stream, _) = listener.accept().await.expect("accept");
        tokio::time::sleep(WAIT).await;
        drop(stream);
    });
    let mut config = ClientConfig::new(format!("http://{addr}"));
    config.timeout = Duration::from_millis(300);
    let client = Client::new(config).expect("client");
    let error = client.health().await.expect_err("timeout");
    match &error {
        ClientError::Transport(source) => assert!(source.is_timeout(), "{source:?}"),
        other => panic!("expected a transport error, got {other:?}"),
    }
    held.abort();
}
