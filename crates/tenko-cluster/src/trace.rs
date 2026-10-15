//! The trace context of the controller-to-controller calls (OPS-05): the W3C `traceparent`
//! and `tracestate` in the gRPC metadata, and the spans of both sides.
//!
//! - The caller wraps a call in [`rpc`] (span `tenko.cluster.rpc`) and puts the context into
//!   the request with [`inject`] inside it.
//! - The callee opens [`span_for`] (span `tenko.cluster.request`) with the parent taken from
//!   the metadata, and runs the handler in it with [`serve`]. The cluster port is mutual TLS
//!   only, so every caller is a node of this installation and its context is trusted.
//! - Both spans carry `rpc.system = grpc`, `rpc.service`, `rpc.method`,
//!   `tenko.cluster.peer` (the other controller's node id, when known) and
//!   `rpc.grpc.status_code`, nothing from the messages.
//!
//! Traced: the `Cluster` service (except `TransferKek`, the key-generation exchange) and
//! `Metrics.Snapshot`. Not traced: the `Raft` service (its heartbeats every few hundred
//! milliseconds would drown everything else) and the node services.
//!
//! The propagator is the process-wide one of `opentelemetry::global`, which `tenko serve`
//! sets when traces are on; without it, or without a sampled span, nothing is injected and
//! the spans are disabled callsites.

use std::future::Future;

use opentelemetry::{
    propagation::{Extractor, Injector},
    trace::TraceContextExt as _,
};
use tenko_core::NodeId;
use tonic::{
    Request, Status,
    metadata::{KeyRef, MetadataKey, MetadataMap, MetadataValue},
};
use tracing::{Instrument as _, Span, field::Empty};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

use crate::mtls::PeerInfo;

/// `rpc.service` of the `Cluster` service.
pub const CLUSTER: &str = "tenko.cluster.v1.Cluster";
/// `rpc.service` of the `Metrics` service.
pub const METRICS: &str = "tenko.cluster.v1.Metrics";

/// Writes the propagator's fields into gRPC metadata.
struct MetadataInjector<'a>(&'a mut MetadataMap);

impl Injector for MetadataInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(key), Ok(value)) = (
            MetadataKey::from_bytes(key.as_bytes()),
            MetadataValue::try_from(value.as_str()),
        ) {
            self.0.insert(key, value);
        }
    }
}

/// Reads the propagator's fields from gRPC metadata.
struct MetadataExtractor<'a>(&'a MetadataMap);

impl Extractor for MetadataExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0
            .keys()
            .filter_map(|key| match key {
                KeyRef::Ascii(key) => Some(key.as_str()),
                KeyRef::Binary(_) => None,
            })
            .collect()
    }
}

/// Puts the context of the current span into the request's metadata. Without a current
/// span, or without a propagator, the metadata stays as it is.
pub fn inject<T>(request: &mut Request<T>) {
    let span = Span::current();
    if span.is_disabled() {
        return;
    }
    let context = span.context();
    if !context.span().span_context().is_valid() {
        return;
    }
    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&context, &mut MetadataInjector(request.metadata_mut()));
    });
}

/// The server span of a traced call, its parent the context in the request's metadata (a
/// root when there is none).
pub fn span_for<T>(request: &Request<T>, service: &str, method: &str) -> Span {
    let span = tracing::info_span!(
        parent: None,
        "tenko.cluster.request",
        otel.kind = "server",
        otel.status_code = Empty,
        rpc.system = "grpc",
        rpc.service = service,
        rpc.method = method,
        tenko.cluster.peer = Empty,
        rpc.grpc.status_code = Empty,
    );
    if span.is_disabled() {
        return span;
    }
    if let Some(peer) = request.extensions().get::<PeerInfo>() {
        span.record("tenko.cluster.peer", peer.identity.node.0);
    }
    let parent = opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.extract(&MetadataExtractor(request.metadata()))
    });
    if parent.span().span_context().is_valid() {
        let _ = span.set_parent(parent);
    }
    span
}

/// Runs a handler in its server span and records the status it answers.
///
/// # Errors
///
/// The status of the handler.
pub async fn serve<R>(
    span: Span,
    handler: impl Future<Output = Result<R, Status>>,
) -> Result<R, Status> {
    let result = handler.instrument(span.clone()).await;
    record_status(&span, &result);
    result
}

/// Runs a call to controller `peer` in the client span `tenko.cluster.rpc` and records the
/// status it got. The call builds its request inside, and puts the context into it with
/// [`inject`].
///
/// # Errors
///
/// The status of the call.
pub async fn rpc<R>(
    peer: Option<NodeId>,
    service: &'static str,
    method: &'static str,
    call: impl Future<Output = Result<R, Status>>,
) -> Result<R, Status> {
    let span = tracing::info_span!(
        "tenko.cluster.rpc",
        otel.kind = "client",
        otel.status_code = Empty,
        rpc.system = "grpc",
        rpc.service = service,
        rpc.method = method,
        tenko.cluster.peer = Empty,
        rpc.grpc.status_code = Empty,
    );
    if span.is_disabled() {
        return call.await;
    }
    if let Some(peer) = peer {
        span.record("tenko.cluster.peer", peer.0);
    }
    let result = call.instrument(span.clone()).await;
    record_status(&span, &result);
    result
}

fn record_status<R>(span: &Span, result: &Result<R, Status>) {
    let code = match result {
        Ok(_) => tonic::Code::Ok,
        Err(status) => status.code(),
    };
    span.record("rpc.grpc.status_code", i32::from(code));
    if !matches!(
        code,
        tonic::Code::Ok
            | tonic::Code::NotFound
            | tonic::Code::AlreadyExists
            | tonic::Code::FailedPrecondition
            | tonic::Code::InvalidArgument
            | tonic::Code::PermissionDenied
            | tonic::Code::Unauthenticated
    ) {
        span.record("otel.status_code", "error");
    }
}

#[cfg(test)]
mod tests {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_sdk::{
        propagation::TraceContextPropagator,
        trace::{InMemorySpanExporter, SdkTracerProvider},
    };
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

    #[test]
    fn inject_without_a_current_span_adds_nothing() {
        opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
        let mut request = Request::new(());
        inject(&mut request);
        assert!(request.metadata().is_empty(), "{:?}", request.metadata());
    }

    #[test]
    fn inject_inside_a_span_carries_its_context() {
        opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test")));
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("caller");
            let _entered = span.enter();
            let mut request = Request::new(());
            inject(&mut request);
            let traceparent = request
                .metadata()
                .get("traceparent")
                .and_then(|value| value.to_str().ok())
                .expect("a traceparent")
                .to_owned();
            let ids = span.context().span().span_context().clone();
            assert_eq!(
                traceparent,
                format!("00-{}-{}-01", ids.trace_id(), ids.span_id())
            );
        });
    }
}
