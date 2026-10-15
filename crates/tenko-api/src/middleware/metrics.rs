//! Request metrics and the process counters of the HTTP server, on the metrics core
//! (`tenko_core::metrics`, OPS-05, OPS-21).
//!
//! - `tenko_http_requests_total{route,method,status}`: the series are sealed at start from
//!   the OpenAPI document, one row per operation (its path template and method) plus the
//!   rows `ui` (the web UI) and `other` (an API path that matched no documented operation)
//!   for every method label, times the status labels of [`STATUS_LABELS`]. A request is
//!   counted by an index computed from its matched template (looked up in the
//!   [`RouteTable`] built at start), its method and its status: no allocation, no lock.
//! - `tenko_http_request_duration_seconds{class}`: the time from the request to the
//!   response head, per route class (the first path segment after `/api/v1/`, sealed from
//!   the document, plus `ui` and `other`).
//! - The process counters ([`Event`]): `tenko_http_refused{reason}`,
//!   `tenko_http_idempotent_replays` and `tenko_http_connections{outcome}`.
//!
//! The two request families are sealed with at most [`API_SHARDS`] (eight) shards instead of
//! the core's default of one per logical CPU (up to 32): the API serves thousands of requests
//! per second at most, on a few worker threads, so eight stripes keep the updates free of
//! contention, and the request series table is the largest allocation of the process (series
//! times shards times 8 bytes, about 0.4 MiB at eight shards against 1.5 MiB at 32). The hot
//! families of later phases (DNS, DHCP) keep the default.
//!
//! The families are process-wide statics; every [`Metrics`] registers them with its own
//! [`Registry`], together with the gauges of `routes::metrics`.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::OnceLock,
    time::Duration,
};

use axum::http::Method;
use tenko_core::metrics::{CounterVec, Desc, HistogramVec, Registry};

use crate::API_BASE;

/// Route label of responses served by the web UI.
pub(crate) const UI_ROUTE: &str = "ui";
/// Route and class label of API requests that matched no documented operation.
pub(crate) const OTHER_ROUTE: &str = "other";

/// Method labels; a method not listed shares `OTHER`.
const METHOD_LABELS: [&str; 8] = [
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "OTHER",
];

/// Status labels: the codes the server answers, and `other` for any other.
pub(crate) const STATUS_LABELS: [&str; 23] = [
    "200", "201", "202", "204", "303", "304", "400", "401", "403", "404", "405", "409", "410",
    "412", "413", "415", "422", "428", "429", "500", "501", "503", "other",
];

/// The most shards of the request families (see the module documentation).
pub(crate) const API_SHARDS: usize = 8;

/// Bucket bounds of the request duration, in microseconds: 250 µs to 10 s.
const DURATION_BOUNDS: [u64; 15] = [
    250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000,
    2_500_000, 5_000_000, 10_000_000,
];

/// HTTP requests by route template, method and status.
static HTTP_REQUESTS: CounterVec = CounterVec::new(
    Desc::counter(
        "tenko_http_requests",
        "HTTP requests by route template, method and status.",
    )
    .labels(&["route", "method", "status"]),
)
.sparse();

/// Request duration by route class.
static HTTP_DURATION: HistogramVec = HistogramVec::new(
    Desc::histogram(
        "tenko_http_request_duration_seconds",
        "Time from the request to the response head, by route class (the first path segment after /api/v1/).",
        &DURATION_BOUNDS,
        1_000_000,
    )
    .labels(&["class"]),
)
.sparse();

/// Requests refused before the handler.
static HTTP_REFUSED: CounterVec = CounterVec::fixed(
    Desc::counter(
        "tenko_http_refused",
        "Requests refused before the handler, by reason.",
    )
    .labels(&["reason"]),
    &[&["rate_limit_ip"], &["rate_limit_principal"], &["csrf"]],
);

/// Responses replayed for a repeated `Idempotency-Key`.
static HTTP_REPLAYS: CounterVec = CounterVec::fixed(
    Desc::counter(
        "tenko_http_idempotent_replays",
        "Responses replayed for a repeated Idempotency-Key.",
    ),
    &[&[]],
);

/// Connections by outcome.
static HTTP_CONNECTIONS: CounterVec = CounterVec::fixed(
    Desc::counter(
        "tenko_http_connections",
        "Connections of the API listener by outcome.",
    )
    .labels(&["outcome"]),
    &[
        &["accepted"],
        &["over_limit"],
        &["proxy_only"],
        &["tls_failed"],
        &["proxy_header_failed"],
    ],
);

/// A counter that refusals and connection events bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event {
    RateLimitedIp,
    RateLimitedPrincipal,
    CsrfRejected,
    IdempotentReplay,
    ConnectionAccepted,
    ConnectionOverLimit,
    ProxyOnlyRefused,
    TlsHandshakeFailed,
    ProxyHeaderFailed,
}

impl Event {
    /// The family and series of the event.
    const fn series(self) -> (&'static CounterVec, u16) {
        match self {
            Event::RateLimitedIp => (&HTTP_REFUSED, 0),
            Event::RateLimitedPrincipal => (&HTTP_REFUSED, 1),
            Event::CsrfRejected => (&HTTP_REFUSED, 2),
            Event::IdempotentReplay => (&HTTP_REPLAYS, 0),
            Event::ConnectionAccepted => (&HTTP_CONNECTIONS, 0),
            Event::ConnectionOverLimit => (&HTTP_CONNECTIONS, 1),
            Event::ProxyOnlyRefused => (&HTTP_CONNECTIONS, 2),
            Event::TlsHandshakeFailed => (&HTTP_CONNECTIONS, 3),
            Event::ProxyHeaderFailed => (&HTTP_CONNECTIONS, 4),
        }
    }
}

/// The row of a request in `tenko_http_requests_total`: its route and method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RouteRow(u16);

/// The series of the request families, sealed once from the OpenAPI document.
#[derive(Debug)]
pub(crate) struct RouteTable {
    /// The row of each documented method of each path template, by method label index.
    by_template: HashMap<Box<str>, [Option<u16>; METHOD_LABELS.len()]>,
    /// The class series of each row.
    classes: Vec<u16>,
    /// The route label of each row (the path template, `ui` or `other`), for the request
    /// span of `middleware::trace`.
    routes: Vec<Box<str>>,
    /// The class labels, by class series.
    class_names: Vec<Box<str>>,
    /// The first row of `ui`; one row per method label.
    ui: u16,
    /// The first row of `other`; one row per method label.
    other: u16,
}

impl RouteTable {
    /// The table of this process: the first call seals the request families from `document`,
    /// the OpenAPI document of the router the server builds (so no other copy of the
    /// document is built or kept); later calls return the same table.
    pub(crate) fn get_or_seal(document: &utoipa::openapi::OpenApi) -> &'static RouteTable {
        static TABLE: OnceLock<RouteTable> = OnceLock::new();
        TABLE.get_or_init(|| RouteTable::seal(document))
    }

    /// The table sealed from the whole API (tests).
    #[cfg(test)]
    pub(crate) fn get() -> &'static RouteTable {
        Self::get_or_seal(&crate::openapi())
    }

    /// Builds the table from `document` and seals the request families with it.
    fn seal(document: &utoipa::openapi::OpenApi) -> Self {
        let mut operations: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (path, item) in &document.paths.paths {
            let methods = [
                item.get.is_some(),
                item.head.is_some(),
                item.post.is_some(),
                item.put.is_some(),
                item.patch.is_some(),
                item.delete.is_some(),
                item.options.is_some(),
            ];
            let present: Vec<usize> = methods
                .iter()
                .enumerate()
                .filter_map(|(index, present)| present.then_some(index))
                .collect();
            if !present.is_empty() {
                operations.insert(path.as_str(), present);
            }
        }
        let class_names: BTreeSet<&str> = operations
            .keys()
            .map(|path| class_of(path))
            .chain([UI_ROUTE, OTHER_ROUTE])
            .collect();
        let class_names: Vec<&str> = class_names.into_iter().collect();
        let class_index = |name: &str| {
            let index = class_names
                .iter()
                .position(|class| *class == name)
                .unwrap_or_default();
            u16::try_from(index).expect("fewer than 65,536 classes")
        };

        let mut rows: Vec<(&str, &str)> = Vec::new();
        let mut classes = Vec::new();
        let mut by_template = HashMap::new();
        for (path, methods) in &operations {
            let mut slots = [None; METHOD_LABELS.len()];
            for method in methods {
                slots[*method] = Some(u16::try_from(rows.len()).expect("few rows"));
                rows.push((*path, METHOD_LABELS[*method]));
                classes.push(class_index(class_of(path)));
            }
            by_template.insert(Box::<str>::from(*path), slots);
        }
        let mut fixed_rows = |route: &'static str| {
            let first = u16::try_from(rows.len()).expect("few rows");
            for method in METHOD_LABELS {
                rows.push((route, method));
                classes.push(class_index(route));
            }
            first
        };
        let ui = fixed_rows(UI_ROUTE);
        let other = fixed_rows(OTHER_ROUTE);
        let routes = rows
            .iter()
            .map(|(route, _)| Box::<str>::from(*route))
            .collect();

        let mut series: Vec<[&str; 3]> = Vec::with_capacity(rows.len() * STATUS_LABELS.len());
        for (route, method) in &rows {
            for status in STATUS_LABELS {
                series.push([route, method, status]);
            }
        }
        let series: Vec<&[&str]> = series.iter().map(<[&str; 3]>::as_slice).collect();
        let shards = tenko_core::metrics::default_shards().min(API_SHARDS);
        HTTP_REQUESTS.seal_with_shards(&series, shards);
        let class_series: Vec<[&str; 1]> = class_names.iter().map(|class| [*class]).collect();
        let class_series: Vec<&[&str]> = class_series.iter().map(<[&str; 1]>::as_slice).collect();
        HTTP_DURATION.seal_with_shards(&class_series, shards);
        Self {
            by_template,
            classes,
            routes,
            class_names: class_names
                .iter()
                .map(|name| Box::<str>::from(*name))
                .collect(),
            ui,
            other,
        }
    }

    /// The route label of a row: its path template, `ui` or `other`.
    pub(crate) fn route_of(&self, row: RouteRow) -> &str {
        self.routes
            .get(usize::from(row.0))
            .map_or(OTHER_ROUTE, |route| route)
    }

    /// The class label of a row.
    pub(crate) fn class_of_row(&self, row: RouteRow) -> &str {
        self.classes
            .get(usize::from(row.0))
            .and_then(|class| self.class_names.get(usize::from(*class)))
            .map_or(OTHER_ROUTE, |name| name)
    }

    /// The row of a request: its matched path template (`None` when no route matched) and
    /// its method. A template or method the document does not list is `other`.
    pub(crate) fn row(&self, template: Option<&str>, method: &Method) -> RouteRow {
        let method = method_index(method);
        let documented = template
            .and_then(|template| self.by_template.get(template))
            .and_then(|slots| slots[method]);
        documented.map_or_else(|| self.other(method), RouteRow)
    }

    /// The `ui` row of a method.
    pub(crate) fn ui_row(&self, method: &Method) -> RouteRow {
        RouteRow(self.ui + method_offset(method))
    }

    /// The `other` row of a method.
    pub(crate) fn other_row(&self, method: &Method) -> RouteRow {
        self.other(method_index(method))
    }

    fn other(&self, method: usize) -> RouteRow {
        RouteRow(self.other + u16::try_from(method).unwrap_or_default())
    }

    /// Counts a finished request: its row, its status and how long it took.
    pub(crate) fn record(&self, row: RouteRow, status: u16, elapsed: Duration) {
        let series = usize::from(row.0) * STATUS_LABELS.len() + status_index(status);
        if let Ok(series) = u16::try_from(series) {
            HTTP_REQUESTS.inc(series);
        }
        if let Some(class) = self.classes.get(usize::from(row.0)) {
            HTTP_DURATION.observe(
                *class,
                u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            );
        }
    }

    /// The number of request series and their bytes (all shards).
    #[cfg(test)]
    pub(crate) fn footprint() -> (usize, usize) {
        (
            HTTP_REQUESTS.len() + HTTP_DURATION.len(),
            HTTP_REQUESTS.bytes() + HTTP_DURATION.bytes(),
        )
    }
}

/// The class of a path template: its first segment after the API base.
fn class_of(template: &str) -> &str {
    template
        .strip_prefix(API_BASE)
        .and_then(|rest| rest.strip_prefix('/'))
        .and_then(|rest| rest.split('/').next())
        .filter(|segment| !segment.is_empty())
        .unwrap_or(OTHER_ROUTE)
}

/// The index of a method label.
fn method_index(method: &Method) -> usize {
    match *method {
        Method::GET => 0,
        Method::HEAD => 1,
        Method::POST => 2,
        Method::PUT => 3,
        Method::PATCH => 4,
        Method::DELETE => 5,
        Method::OPTIONS => 6,
        _ => 7,
    }
}

fn method_offset(method: &Method) -> u16 {
    u16::try_from(method_index(method)).unwrap_or_default()
}

/// The index of a status label.
fn status_index(status: u16) -> usize {
    match status {
        200 => 0,
        201 => 1,
        202 => 2,
        204 => 3,
        303 => 4,
        304 => 5,
        400 => 6,
        401 => 7,
        403 => 8,
        404 => 9,
        405 => 10,
        409 => 11,
        410 => 12,
        412 => 13,
        413 => 14,
        415 => 15,
        422 => 16,
        428 => 17,
        429 => 18,
        500 => 19,
        501 => 20,
        503 => 21,
        _ => 22,
    }
}

/// The metrics of an API state: a registry with the request families, the process
/// counters and the platform gauges of `GET /metrics`.
#[derive(Debug)]
pub(crate) struct Metrics {
    registry: Registry,
}

impl Default for Metrics {
    fn default() -> Self {
        let registry = Registry::new();
        registry.register(&HTTP_REQUESTS);
        registry.register(&HTTP_DURATION);
        registry.register(&HTTP_REFUSED);
        registry.register(&HTTP_REPLAYS);
        registry.register(&HTTP_CONNECTIONS);
        crate::routes::metrics::register(&registry);
        Self { registry }
    }
}

impl Metrics {
    /// The registry.
    pub(crate) fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Bumps an event counter. The counters are process-wide statics; the method stays on
    /// the state so that the call sites read as before.
    #[allow(clippy::unused_self)]
    pub(crate) fn count(&self, event: Event) {
        let (family, series) = event.series();
        family.inc(series);
    }

    /// The value of an event counter (tests).
    #[cfg(test)]
    #[allow(clippy::unused_self)]
    pub(crate) fn get(&self, event: Event) -> u64 {
        let (family, series) = event.series();
        family.get(series)
    }
}

/// Requests counted for a route, method and status label (tests).
#[cfg(test)]
pub(crate) fn requests_for(route: &str, method: &str, status: &str) -> u64 {
    use tenko_core::metrics::{Collect as _, Value};
    let mut series = Vec::new();
    HTTP_REQUESTS.collect(&mut series);
    series
        .iter()
        .filter(|series| series.labels.matches(&[route, method, status]))
        .map(|series| match series.value {
            Value::Counter(total) => total,
            _ => 0,
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt as _;

    use super::*;
    use crate::{middleware::HttpConfig, state::AppState, ui::UiSource};

    fn render(metrics: &Metrics) -> String {
        let mut text = String::new();
        tenko_core::metrics::encode(&metrics.registry().snapshot(), &mut text);
        text
    }

    #[test]
    fn renders_openmetrics_text() {
        let metrics = Metrics::default();
        let routes = RouteTable::get();
        let health = routes.row(Some("/api/v1/health"), &Method::GET);
        routes.record(health, 200, Duration::from_micros(300));
        routes.record(health, 200, Duration::from_micros(300));
        let prefix = routes.row(Some("/api/v1/prefixes/{id}"), &Method::PATCH);
        routes.record(prefix, 409, Duration::from_millis(30));
        let odd = routes.row(
            Some("odd\"route"),
            &Method::from_bytes(b"BREW").expect("method"),
        );
        routes.record(odd, 418, Duration::from_secs(20));
        metrics.count(Event::RateLimitedIp);
        let text = render(&metrics);
        assert!(text.contains(
            "tenko_http_requests_total{route=\"/api/v1/health\",method=\"GET\",status=\"200\"} 2\n"
        ));
        assert!(
            text.contains("route=\"/api/v1/prefixes/{id}\",method=\"PATCH\",status=\"409\"} 1")
        );
        assert!(text.contains("route=\"other\",method=\"OTHER\",status=\"other\"} 1"));
        assert!(text.contains("tenko_http_refused_total{reason=\"rate_limit_ip\"} 1\n"));
        assert!(text.contains("tenko_http_idempotent_replays_total 0\n"));
        assert!(text.contains(
            "tenko_http_request_duration_seconds_bucket{class=\"health\",le=\"0.0005\"} 2\n"
        ));
        assert!(text.contains(
            "tenko_http_request_duration_seconds_bucket{class=\"prefixes\",le=\"0.05\"} 1\n"
        ));
        assert!(text.contains(
            "tenko_http_request_duration_seconds_bucket{class=\"other\",le=\"10.0\"} 0\n"
        ));
        assert!(text.contains("tenko_http_request_duration_seconds_count{class=\"other\"} 1\n"));
        assert!(text.contains("# UNIT tenko_http_request_duration_seconds seconds\n"));
        assert!(text.ends_with("# EOF\n"));
        assert_eq!(requests_for("/api/v1/health", "GET", "200"), 2);
        assert_eq!(metrics.get(Event::RateLimitedIp), 1);
    }

    #[test]
    fn every_documented_operation_has_a_row_and_classes_follow_the_first_segment() {
        let routes = RouteTable::get();
        let document = crate::openapi();
        let mut operations = 0;
        for (path, item) in &document.paths.paths {
            for (method, present) in [
                (Method::GET, item.get.is_some()),
                (Method::POST, item.post.is_some()),
                (Method::PUT, item.put.is_some()),
                (Method::PATCH, item.patch.is_some()),
                (Method::DELETE, item.delete.is_some()),
            ] {
                if present {
                    operations += 1;
                    assert_ne!(
                        routes.row(Some(path), &method),
                        routes.other_row(&method),
                        "{method} {path}"
                    );
                }
            }
        }
        assert!((1..=API_SHARDS).contains(&HTTP_REQUESTS.shards()));
        assert_eq!(HTTP_DURATION.shards(), HTTP_REQUESTS.shards());
        let (series, _) = RouteTable::footprint();
        // One row per operation plus eight `ui` and eight `other` rows, times the status
        // labels, plus one duration series per class.
        assert!(series > (operations + 16) * STATUS_LABELS.len());
        assert_eq!(class_of("/api/v1/prefixes/{id}/next-free"), "prefixes");
        assert_eq!(class_of("/api/v1/metrics"), "metrics");
        assert_eq!(class_of("/somewhere"), OTHER_ROUTE);
    }

    #[test]
    fn a_row_names_its_route_template_and_class() {
        let routes = RouteTable::get();
        let row = routes.row(Some("/api/v1/prefixes/{id}"), &Method::GET);
        assert_eq!(routes.route_of(row), "/api/v1/prefixes/{id}");
        assert_eq!(routes.class_of_row(row), "prefixes");
        let other = routes.other_row(&Method::GET);
        assert_eq!(routes.route_of(other), OTHER_ROUTE);
        assert_eq!(routes.class_of_row(other), OTHER_ROUTE);
        let ui = routes.ui_row(&Method::GET);
        assert_eq!(routes.route_of(ui), UI_ROUTE);
        assert_eq!(routes.class_of_row(ui), UI_ROUTE);
    }

    #[tokio::test]
    async fn a_request_to_an_unknown_route_counts_under_other() {
        let state = AppState::default();
        let app = crate::server::app(state.clone(), &HttpConfig::default(), &UiSource::Embedded)
            .expect("the app");
        for (method, path) in [
            ("GET", "/api/v1/no-such-area"),
            ("GET", "/api/v1/no-such-area"),
            ("PUT", "/api/v1/health"),
        ] {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .expect("request");
            let response = app.clone().oneshot(request).await.expect("response");
            assert!(response.status().is_client_error(), "{method} {path}");
        }
        assert_eq!(requests_for(OTHER_ROUTE, "GET", "404"), 2);
        assert_eq!(requests_for(OTHER_ROUTE, "PUT", "405"), 1);
        let text = crate::routes::metrics::render_metrics(&state);
        assert!(
            text.contains(
                "tenko_http_requests_total{route=\"other\",method=\"GET\",status=\"404\"} 2\n"
            ),
            "{text}"
        );
        assert!(text.contains("tenko_http_request_duration_seconds_count{class=\"other\"} 3\n"));
        tenko_core::metrics::check(&text).unwrap_or_else(|error| panic!("{error}\n{text}"));
    }
}
