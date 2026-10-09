//! Request counters and the text exposition of `GET /metrics` (`OpenMetrics`, OPS-05).
//!
//! The counters are the platform's own: HTTP requests by route template, method and status,
//! refusals by rate limit, CSRF guard and listener rules, idempotent replays, connections,
//! and the event hub. Store and TLS gauges are read at scrape time. The cost budget and the
//! data-plane counters of OPS-21 arrive with `tenko-core::metrics` in Slice 3.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    sync::{
        PoisonError, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

/// Route label of responses served by the web UI.
pub(crate) const UI_ROUTE: &str = "ui";
/// Route label of API requests that matched no route.
pub(crate) const UNMATCHED_ROUTE: &str = "unmatched";

/// A gauge or counter read at scrape time.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Sample {
    name: &'static str,
    help: &'static str,
    counter: bool,
    value: f64,
}

impl Sample {
    /// A gauge.
    pub(crate) const fn gauge(name: &'static str, help: &'static str, value: f64) -> Self {
        Self {
            name,
            help,
            counter: false,
            value,
        }
    }

    /// A counter; the sample gets the `_total` suffix.
    pub(crate) const fn counter(name: &'static str, help: &'static str, value: f64) -> Self {
        Self {
            name,
            help,
            counter: true,
            value,
        }
    }
}

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
    const ALL: [Event; 9] = [
        Event::RateLimitedIp,
        Event::RateLimitedPrincipal,
        Event::CsrfRejected,
        Event::IdempotentReplay,
        Event::ConnectionAccepted,
        Event::ConnectionOverLimit,
        Event::ProxyOnlyRefused,
        Event::TlsHandshakeFailed,
        Event::ProxyHeaderFailed,
    ];

    /// Metric family and label of the event.
    const fn family(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Event::RateLimitedIp => ("tenko_http_refused", "reason", "rate_limit_ip"),
            Event::RateLimitedPrincipal => ("tenko_http_refused", "reason", "rate_limit_principal"),
            Event::CsrfRejected => ("tenko_http_refused", "reason", "csrf"),
            Event::IdempotentReplay => ("tenko_http_idempotent_replays", "", ""),
            Event::ConnectionAccepted => ("tenko_http_connections", "outcome", "accepted"),
            Event::ConnectionOverLimit => ("tenko_http_connections", "outcome", "over_limit"),
            Event::ProxyOnlyRefused => ("tenko_http_connections", "outcome", "proxy_only"),
            Event::TlsHandshakeFailed => ("tenko_http_connections", "outcome", "tls_failed"),
            Event::ProxyHeaderFailed => {
                ("tenko_http_connections", "outcome", "proxy_header_failed")
            }
        }
    }
}

/// Request counters; shared by the middleware and `GET /metrics`.
#[derive(Debug, Default)]
pub(crate) struct Metrics {
    requests: RwLock<BTreeMap<(String, &'static str, u16), AtomicU64>>,
    events: [AtomicU64; 9],
}

impl Metrics {
    /// Counts one finished request.
    pub(crate) fn request(&self, route: &str, method: &axum::http::Method, status: u16) {
        let method = method_label(method);
        {
            let requests = self.requests.read().unwrap_or_else(PoisonError::into_inner);
            if let Some(counter) = requests.get(&(route.to_owned(), method, status)) {
                counter.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        let mut requests = self
            .requests
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        requests
            .entry((route.to_owned(), method, status))
            .or_default()
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Bumps an event counter.
    pub(crate) fn count(&self, event: Event) {
        let index = Event::ALL
            .iter()
            .position(|candidate| *candidate == event)
            .unwrap_or_default();
        self.events[index].fetch_add(1, Ordering::Relaxed);
    }

    /// The value of an event counter.
    pub(crate) fn get(&self, event: Event) -> u64 {
        let index = Event::ALL
            .iter()
            .position(|candidate| *candidate == event)
            .unwrap_or_default();
        self.events[index].load(Ordering::Relaxed)
    }

    /// Requests counted for a route, method and status (tests).
    #[cfg(test)]
    pub(crate) fn requests_for(&self, route: &str, method: &str, status: u16) -> u64 {
        let requests = self.requests.read().unwrap_or_else(PoisonError::into_inner);
        requests
            .iter()
            .filter(|((r, m, s), _)| r == route && *m == method && *s == status)
            .map(|(_, counter)| counter.load(Ordering::Relaxed))
            .sum()
    }

    /// Renders the counters in the `OpenMetrics` text format, followed by `samples` and the
    /// `# EOF` marker.
    pub(crate) fn render(&self, samples: &[Sample]) -> String {
        let mut out = String::with_capacity(4_096);
        let _ = writeln!(out, "# TYPE tenko_http_requests counter");
        let _ = writeln!(
            out,
            "# HELP tenko_http_requests HTTP requests by route template, method and status."
        );
        {
            let requests = self.requests.read().unwrap_or_else(PoisonError::into_inner);
            for ((route, method, status), counter) in requests.iter() {
                let _ = writeln!(
                    out,
                    "tenko_http_requests_total{{route=\"{}\",method=\"{method}\",status=\"{status}\"}} {}",
                    escape(route),
                    counter.load(Ordering::Relaxed)
                );
            }
        }
        let mut families: BTreeMap<&str, Vec<(Event, &str, &str)>> = BTreeMap::new();
        for event in Event::ALL {
            let (family, label, value) = event.family();
            families
                .entry(family)
                .or_default()
                .push((event, label, value));
        }
        for (family, events) in families {
            let _ = writeln!(out, "# TYPE {family} counter");
            for (event, label, value) in events {
                let count = self.get(event);
                if label.is_empty() {
                    let _ = writeln!(out, "{family}_total {count}");
                } else {
                    let _ = writeln!(out, "{family}_total{{{label}=\"{value}\"}} {count}");
                }
            }
        }
        for sample in samples {
            let (kind, suffix) = if sample.counter {
                ("counter", "_total")
            } else {
                ("gauge", "")
            };
            let name = sample.name;
            let _ = writeln!(out, "# TYPE {name} {kind}");
            let _ = writeln!(out, "# HELP {name} {}", sample.help);
            let _ = writeln!(out, "{name}{suffix} {}", sample.value);
        }
        out.push_str("# EOF\n");
        out
    }
}

/// A bounded label for the method (unknown methods share one label).
fn method_label(method: &axum::http::Method) -> &'static str {
    use axum::http::Method;
    match *method {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::OPTIONS => "OPTIONS",
        _ => "OTHER",
    }
}

/// Escapes a label value (backslash, double quote, line feed).
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use axum::http::Method;

    use super::*;

    #[test]
    fn renders_openmetrics_text() {
        let metrics = Metrics::default();
        metrics.request("/api/v1/health", &Method::GET, 200);
        metrics.request("/api/v1/health", &Method::GET, 200);
        metrics.request("/api/v1/prefixes/{id}", &Method::PATCH, 409);
        metrics.request(
            "odd\"route",
            &Method::from_bytes(b"BREW").expect("method"),
            418,
        );
        metrics.count(Event::RateLimitedIp);
        let text = metrics.render(&[
            Sample::gauge("tenko_store_revision", "Last applied revision.", 7.0),
            Sample::counter("tenko_sse_events", "Events.", 3.0),
        ]);
        assert!(text.contains(
            "tenko_http_requests_total{route=\"/api/v1/health\",method=\"GET\",status=\"200\"} 2\n"
        ));
        assert!(
            text.contains("route=\"/api/v1/prefixes/{id}\",method=\"PATCH\",status=\"409\"} 1")
        );
        assert!(text.contains("route=\"odd\\\"route\",method=\"OTHER\""));
        assert!(text.contains("tenko_http_refused_total{reason=\"rate_limit_ip\"} 1\n"));
        assert!(text.contains("tenko_http_idempotent_replays_total 0\n"));
        assert!(text.contains("# TYPE tenko_store_revision gauge\n"));
        assert!(text.contains("\ntenko_store_revision 7\n"));
        assert!(text.contains("# TYPE tenko_sse_events counter\n"));
        assert!(text.contains("\ntenko_sse_events_total 3\n"));
        assert!(text.ends_with("# EOF\n"));
        assert_eq!(metrics.requests_for("/api/v1/health", "GET", 200), 2);
    }
}
