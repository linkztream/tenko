//! Traces over OpenTelemetry (OPS-05): the `tracing` spans of the server exported to an OTLP
//! collector over gRPC, when `[telemetry] otlp_endpoint` is set.
//!
//! [`layer`] builds the layer that [`logging::Layers::extra`] composes into the subscriber,
//! together with the [`Telemetry`] that owns the tracer provider and flushes it at shutdown.
//! Without an endpoint it returns `None` and builds nothing: no provider, no exporter, no
//! thread and no task, so the spans of the code cost a disabled callsite check each.
//!
//! With an endpoint:
//!
//! - The resource names the process: `service.name = tenko`, `service.version` and
//!   `service.instance.id` (the node id).
//! - The sampler is `ParentBased(TraceIdRatioBased(sampling_ratio))`: the root of a trace
//!   decides, its children follow.
//! - Finished spans go through the SDK's batch span processor (its own thread; an export at
//!   most every 5 s or every 512 spans) to the OTLP gRPC exporter (timeout 10 s). The
//!   exporter's channel runs on the tokio runtime of the server, so the layer is built inside
//!   it and the provider is shut down inside it ([`Telemetry::shutdown`]).
//! - The global propagator is the W3C trace context (`traceparent`, `tracestate`), which
//!   `tenko-cluster` and `tenko-connect` use to carry the context in gRPC metadata.
//! - Only spans of Tenko's own crates are exported, never log events: the span catalogue of
//!   `docs/observability.md` section 8 is the whole content, and log messages (which may name
//!   objects) do not leave the process this way.

use std::time::Duration;

use opentelemetry::{KeyValue, trace::TracerProvider as _};
use opentelemetry_otlp::{WithExportConfig as _, WithTonicConfig as _};
use opentelemetry_sdk::{
    Resource,
    propagation::TraceContextPropagator,
    trace::{Sampler, SdkTracerProvider},
};
use opentelemetry_semantic_conventions::resource::{SERVICE_INSTANCE_ID, SERVICE_VERSION};
use tenko_core::NodeId;
use tracing_subscriber::{Layer as _, Registry, filter::filter_fn};

use crate::{config::TelemetrySection, logging};

/// The `service.name` of the resource.
pub const SERVICE: &str = "tenko";

/// The name of the tracer (the instrumentation scope).
const TRACER: &str = "tenko";

/// How long an export to the collector may take.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the flush at shutdown may take.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// The log target of this module's lines.
const TARGET: &str = "tenko::telemetry";

/// The tracer provider of a server with traces on. Dropping it without
/// [`Telemetry::shutdown`] loses the spans not exported yet.
#[derive(Debug)]
pub struct Telemetry {
    provider: SdkTracerProvider,
    /// The endpoint without credentials, for the log.
    endpoint: String,
    sampling_ratio: f64,
}

impl Telemetry {
    /// Logs that traces are on, once the subscriber is installed.
    pub fn log_start(&self) {
        tracing::info!(
            target: TARGET,
            endpoint = %self.endpoint,
            sampling_ratio = self.sampling_ratio,
            "telemetry: traces are exported over OTLP"
        );
    }

    /// Exports the spans still queued and shuts the provider down, at most 5 s. Runs inside
    /// the server's runtime, which the exporter's channel needs; the blocking flush runs on a
    /// blocking thread so the runtime's workers stay free to drive it.
    pub async fn shutdown(self) {
        let provider = self.provider;
        let flushed =
            tokio::task::spawn_blocking(move || provider.shutdown_with_timeout(SHUTDOWN_TIMEOUT))
                .await;
        match flushed {
            Ok(Ok(())) => tracing::info!(target: TARGET, "telemetry: the OTLP traces were flushed"),
            Ok(Err(error)) => tracing::info!(
                target: TARGET,
                %error,
                "telemetry: the OTLP traces were not all flushed; spans still queued are dropped"
            ),
            Err(error) => tracing::info!(
                target: TARGET,
                %error,
                "telemetry: the flush of the OTLP traces did not finish"
            ),
        }
    }
}

/// The trace layer of `[telemetry]` and its provider, or `None` when no endpoint is set.
///
/// Call it inside the tokio runtime that will run the server (the exporter's channel spawns
/// its tasks there), before the subscriber is installed.
///
/// # Errors
///
/// The exporter cannot be built for the endpoint.
pub fn layer(
    section: &TelemetrySection,
    node_id: NodeId,
    version: &str,
) -> anyhow::Result<Option<(logging::BoxedLayer, Telemetry)>> {
    let Some(endpoint) = section.otlp_endpoint.as_deref() else {
        return Ok(None);
    };
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .with_timeout(EXPORT_TIMEOUT)
        .with_tls_config(tonic::transport::ClientTlsConfig::new().with_native_roots())
        .build()
        .map_err(|error| {
            anyhow::anyhow!(
                "telemetry.otlp_endpoint `{}`: {error}",
                without_userinfo(endpoint)
            )
        })?;
    let resource = Resource::builder()
        .with_service_name(SERVICE)
        .with_attributes([
            KeyValue::new(SERVICE_VERSION, version.to_owned()),
            KeyValue::new(SERVICE_INSTANCE_ID, node_id.to_string()),
        ])
        .build();
    let provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            section.sampling_ratio,
        ))))
        .with_batch_exporter(exporter)
        .build();
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
    let layer = tracing_opentelemetry::layer::<Registry>()
        .with_tracer(provider.tracer(TRACER))
        .with_threads(false)
        .with_filter(filter_fn(|metadata| {
            metadata.is_span() && metadata.target().starts_with("tenko")
        }))
        .boxed();
    let telemetry = Telemetry {
        provider,
        endpoint: without_userinfo(endpoint),
        sampling_ratio: section.sampling_ratio,
    };
    Ok(Some((layer, telemetry)))
}

/// The endpoint without a `user:password@` part, for the log.
fn without_userinfo(endpoint: &str) -> String {
    let Some((scheme, rest)) = endpoint.split_once("://") else {
        return endpoint.to_owned();
    };
    let authority_end = rest.find('/').unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
        Some(at) => format!("{scheme}://{}", &rest[at + 1..]),
        None => endpoint.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_endpoint_builds_nothing() {
        let section = TelemetrySection::default();
        let built = layer(&section, NodeId(1), "0.0.1").expect("no error");
        assert!(built.is_none());
    }

    #[test]
    fn the_log_line_hides_credentials_of_the_endpoint() {
        assert_eq!(
            without_userinfo("https://user:secret@collector.example.test:4317"),
            "https://collector.example.test:4317"
        );
        assert_eq!(
            without_userinfo("http://127.0.0.1:4317"),
            "http://127.0.0.1:4317"
        );
        assert_eq!(
            without_userinfo("http://192.0.2.10:4317/a@b"),
            "http://192.0.2.10:4317/a@b"
        );
    }

    #[tokio::test]
    async fn an_endpoint_builds_the_layer_and_shuts_down() {
        let section = TelemetrySection {
            otlp_endpoint: Some("http://127.0.0.1:9".to_owned()),
            sampling_ratio: 1.0,
        };
        let (_layer, telemetry) = layer(&section, NodeId(7), "0.0.1")
            .expect("the exporter builds")
            .expect("a layer");
        telemetry.shutdown().await;
    }
}
