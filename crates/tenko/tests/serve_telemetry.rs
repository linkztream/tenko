//! Traces over OTLP (OPS-05) against the real binary: `tenko serve` with
//! `[telemetry] otlp_endpoint` pointing at the test collector of
//! `serve_support::otlp` on loopback.
//!
//! - With the endpoint, a setup, a prefix and a read export the spans of the catalogue
//!   (`docs/observability.md` section 8) with the resource of the node; the graceful stop
//!   flushes them; no attribute carries the setup token, the password, the session cookie
//!   or the prefix; the health probes produce no span.
//! - Without the endpoint nothing reaches the collector and the server logs no telemetry
//!   line.
//! - With `sampling_ratio = 0.0` the server runs as usual and exports no span.

mod serve_support;

use std::time::Duration;

use opentelemetry_proto::tonic::trace::v1::Span;
use serde_json::json;
use serve_support::{
    Node, PASSWORD,
    api::Api,
    otlp::{Receiver, all_texts, attribute, span_attribute},
    wait_for_setup_token,
};

const PREFIX: &str = "192.0.2.0/24";

/// How long the spans may take to arrive after the server stopped.
const ARRIVAL: Duration = Duration::from_secs(10);

/// What the tests do on a running node: setup, one prefix, one read. Returns the setup
/// token, the session secret and the outcome of the graceful stop.
fn exercise(node: &mut Node) -> (String, String, serve_support::Outcome) {
    let mut server = node.start();
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(node);
    api.setup(&token);
    let created = api.post("/prefixes", &json!({ "cidr": PREFIX }));
    assert!(
        matches!(created.status, 201 | 202),
        "creating the prefix: HTTP {}: {}",
        created.status,
        created.text
    );
    api.get("/prefixes").expect(200);
    // The secret of the session, without the cookie's name.
    let cookie = api.cookie().expect("a session cookie");
    let cookie = cookie
        .strip_prefix("tenko_session=")
        .unwrap_or(cookie)
        .to_owned();
    let outcome = server.stop();
    outcome.assert_graceful_shutdown();
    (token, cookie, outcome)
}

fn named<'a>(spans: &'a [Span], name: &str) -> Vec<&'a Span> {
    spans.iter().filter(|span| span.name == name).collect()
}

#[test]
fn spans_reach_the_collector_and_carry_no_data() {
    let receiver = Receiver::start();
    let mut node = Node::new().with_config(&receiver.config(1.0));
    let (token, cookie, outcome) = exercise(&mut node);
    outcome.assert_stderr_contains("telemetry: traces are exported over OTLP");
    outcome.assert_stderr_contains("telemetry: the OTLP traces were flushed");
    assert!(
        receiver.wait_for("http.server.request", ARRIVAL),
        "no request span arrived\n{}",
        outcome.diagnostics()
    );
    println!("spans received per name: {:?}", receiver.counts());
    check_resource(&receiver);
    let spans = receiver.spans();
    let create = check_requests(&spans);
    check_write_and_step(&spans, create);
    check_privacy(&spans, &[&token, PASSWORD, &cookie, PREFIX, "192.0.2.0"]);
}

/// The resource names the service and the node.
fn check_resource(receiver: &Receiver) {
    let resources = receiver.resource_spans();
    let resource = resources
        .first()
        .and_then(|spans| spans.resource.as_ref())
        .expect("a resource");
    assert_eq!(
        attribute(&resource.attributes, "service.name").as_deref(),
        Some("tenko")
    );
    let instance = attribute(&resource.attributes, "service.instance.id");
    assert!(
        instance.as_deref().is_some_and(|id| !id.is_empty()),
        "service.instance.id: {instance:?}"
    );
    assert!(attribute(&resource.attributes, "service.version").is_some());
}

/// The request spans: `POST /api/v1/prefixes` with its attributes, no probe. Returns the
/// span of the create.
fn check_requests(spans: &[Span]) -> &Span {
    let requests = named(spans, "http.server.request");
    let create = requests
        .iter()
        .find(|span| {
            span_attribute(span, "http.route").as_deref() == Some("/api/v1/prefixes")
                && span_attribute(span, "http.request.method").as_deref() == Some("POST")
        })
        .unwrap_or_else(|| panic!("no span of POST /api/v1/prefixes in {requests:#?}"));
    let status = span_attribute(create, "http.response.status_code");
    assert!(
        matches!(status.as_deref(), Some("201" | "202")),
        "status: {status:?}"
    );
    assert_eq!(
        span_attribute(create, "tenko.route_class").as_deref(),
        Some("prefixes")
    );
    assert_eq!(
        span_attribute(create, "url.scheme").as_deref(),
        Some("https")
    );
    assert_eq!(
        span_attribute(create, "network.protocol.version").as_deref(),
        Some("1.1")
    );
    assert!(
        create.parent_span_id.is_empty(),
        "a request span is the root of its trace"
    );

    // The probes of the start and of the harness are not traced.
    for span in &requests {
        let route = span_attribute(span, "http.route").unwrap_or_default();
        assert!(
            !route.starts_with("/api/v1/health") && route != "/api/v1/metrics",
            "a probe or scrape was traced: {route}"
        );
    }
    create
}

/// The write of the prefix and the step of its job.
fn check_write_and_step(spans: &[Span], create: &Span) {
    // The write of the prefix is a child of its request, on the leader (this node).
    let proposals = named(spans, "tenko.store.propose");
    let propose = proposals
        .iter()
        .find(|span| span.parent_span_id == create.span_id && span.trace_id == create.trace_id)
        .unwrap_or_else(|| {
            panic!("no tenko.store.propose under the request span in {proposals:#?}")
        });
    assert_eq!(
        span_attribute(propose, "tenko.store.outcome").as_deref(),
        Some("ok")
    );
    assert_eq!(
        span_attribute(propose, "tenko.store.forwarded").as_deref(),
        Some("false")
    );
    assert!(span_attribute(propose, "tenko.store.revision").is_some());
    assert!(span_attribute(propose, "tenko.store.batch_bytes").is_some());
    assert!(
        named(spans, "tenko.store.coalesce")
            .iter()
            .any(|span| span.parent_span_id == propose.span_id),
        "no tenko.store.coalesce under the proposal"
    );

    // The step of the prefix's job is the root of a trace of its own.
    let steps = named(spans, "tenko.job.step");
    let step = steps
        .iter()
        .find(|span| span_attribute(span, "tenko.job.kind").as_deref() == Some("ipam.edit"))
        .unwrap_or_else(|| panic!("no tenko.job.step of ipam.edit in {steps:#?}"));
    assert!(
        step.parent_span_id.is_empty(),
        "a job step is the root of its trace"
    );
    assert_ne!(step.trace_id, create.trace_id);
    assert_eq!(
        span_attribute(step, "tenko.job.outcome").as_deref(),
        Some("ok")
    );
    assert!(span_attribute(step, "tenko.job.id").is_some());
}

/// No attribute carries a secret or a value from the data.
fn check_privacy(spans: &[Span], forbidden: &[&str]) {
    for span in spans {
        for text in all_texts(span) {
            for secret in forbidden {
                assert!(
                    !text.contains(secret),
                    "span {} carries `{text}`, which contains a secret or data",
                    span.name
                );
            }
        }
    }
}

#[test]
fn without_an_endpoint_nothing_is_exported() {
    let receiver = Receiver::start();
    let mut node = Node::new();
    let (_, _, outcome) = exercise(&mut node);
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        receiver.resource_spans().is_empty(),
        "spans arrived without an endpoint: {:?}",
        receiver.counts()
    );
    for needle in ["tenko::telemetry", "telemetry:", "OTLP"] {
        assert!(
            !outcome.stderr.contains(needle),
            "a telemetry line was logged without an endpoint ({needle})\n{}",
            outcome.diagnostics()
        );
    }
}

#[test]
fn sampling_ratio_zero_exports_nothing() {
    let receiver = Receiver::start();
    let mut node = Node::new().with_config(&receiver.config(0.0));
    let (_, _, outcome) = exercise(&mut node);
    outcome.assert_stderr_contains("telemetry: traces are exported over OTLP");
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        receiver.spans().is_empty(),
        "spans arrived with sampling_ratio = 0.0: {:?}",
        receiver.counts()
    );
}
