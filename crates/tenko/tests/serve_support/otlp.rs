//! A test OTLP collector: a gRPC `TraceService` on a free loopback port that keeps every
//! `ResourceSpans` it receives, for the trace tests of `tenko serve`. It runs on a runtime of
//! its own, so the synchronous tests can read what arrived at any time. No trace leaves the
//! machine.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex, PoisonError},
    thread,
    time::{Duration, Instant},
};

use opentelemetry_proto::tonic::{
    collector::trace::v1::{
        ExportTraceServiceRequest, ExportTraceServiceResponse,
        trace_service_server::{TraceService, TraceServiceServer},
    },
    common::v1::{AnyValue, KeyValue, any_value::Value},
    trace::v1::{ResourceSpans, Span},
};

type Received = Arc<Mutex<Vec<ResourceSpans>>>;

struct Collector {
    received: Received,
}

#[tonic::async_trait]
impl TraceService for Collector {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        let spans = request.into_inner().resource_spans;
        self.received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(spans);
        Ok(tonic::Response::new(ExportTraceServiceResponse {
            partial_success: None,
        }))
    }
}

/// A running test collector. Dropping it stops the server.
pub struct Receiver {
    addr: SocketAddr,
    received: Received,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl Receiver {
    /// Starts the collector on a free port of `127.0.0.1`.
    pub fn start() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("a runtime for the collector");
        let received = Received::default();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .expect("a loopback port for the collector");
        let addr = listener.local_addr().expect("the collector's address");
        let service = TraceServiceServer::new(Collector {
            received: Arc::clone(&received),
        });
        runtime.spawn(async move {
            let incoming = tonic::transport::server::TcpIncoming::from(listener);
            let _ = tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
                })
                .await;
        });
        Self {
            addr,
            received,
            stop: Some(stop),
            runtime: Some(runtime),
        }
    }

    /// The endpoint for `[telemetry] otlp_endpoint`.
    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The `[telemetry]` section that sends the traces here with `sampling_ratio`.
    pub fn config(&self, sampling_ratio: f64) -> String {
        format!(
            "[telemetry]\notlp_endpoint = \"{}\"\nsampling_ratio = {sampling_ratio:?}\n",
            self.endpoint()
        )
    }

    /// Everything received so far.
    pub fn resource_spans(&self) -> Vec<ResourceSpans> {
        self.received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Every span received so far.
    pub fn spans(&self) -> Vec<Span> {
        self.resource_spans()
            .into_iter()
            .flat_map(|resource| resource.scope_spans)
            .flat_map(|scope| scope.spans)
            .collect()
    }

    /// Waits until a span named `name` arrived, at most `timeout`; true when it did.
    pub fn wait_for(&self, name: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.spans().iter().any(|span| span.name == name) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// The number of spans per name.
    pub fn counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for span in self.spans() {
            *counts.entry(span.name).or_insert(0) += 1;
        }
        counts
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(Duration::from_secs(2));
        }
    }
}

/// The value of attribute `key` as text (strings as they are, other scalars formatted).
pub fn attribute(attributes: &[KeyValue], key: &str) -> Option<String> {
    attributes
        .iter()
        .find(|attribute| attribute.key == key)
        .and_then(|attribute| attribute.value.as_ref())
        .and_then(text)
}

/// The value of a span attribute as text.
pub fn span_attribute(span: &Span, key: &str) -> Option<String> {
    attribute(&span.attributes, key)
}

/// Every text an attribute value holds, arrays and maps included.
pub fn texts(value: &AnyValue, out: &mut Vec<String>) {
    match &value.value {
        Some(Value::ArrayValue(array)) => {
            for value in &array.values {
                texts(value, out);
            }
        }
        Some(Value::KvlistValue(list)) => {
            for entry in &list.values {
                out.push(entry.key.clone());
                if let Some(value) = &entry.value {
                    texts(value, out);
                }
            }
        }
        _ => out.extend(text(value)),
    }
}

/// Every attribute key and value of a span, its events and links, as text.
pub fn all_texts(span: &Span) -> Vec<String> {
    let mut out = vec![span.name.clone()];
    let mut push = |attributes: &[KeyValue]| {
        for attribute in attributes {
            out.push(attribute.key.clone());
            if let Some(value) = &attribute.value {
                texts(value, &mut out);
            }
        }
    };
    push(&span.attributes);
    for event in &span.events {
        push(&event.attributes);
    }
    for link in &span.links {
        push(&link.attributes);
    }
    if let Some(status) = &span.status {
        out.push(status.message.clone());
    }
    for event in &span.events {
        out.push(event.name.clone());
    }
    out
}

fn text(value: &AnyValue) -> Option<String> {
    match value.value.as_ref()? {
        Value::StringValue(text) => Some(text.clone()),
        Value::BoolValue(flag) => Some(flag.to_string()),
        Value::IntValue(number) => Some(number.to_string()),
        Value::DoubleValue(number) => Some(number.to_string()),
        Value::BytesValue(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
        Value::StringValueStrindex(index) => Some(index.to_string()),
        Value::ArrayValue(_) | Value::KvlistValue(_) => None,
    }
}
