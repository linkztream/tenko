//! Typed calls to a running plugin: every call carries the per-launch token and has a
//! timeout; answers are converted into the domain types and errors into
//! [`ConnectorError`]s.

use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use opentelemetry::{propagation::Injector, trace::TraceContextExt as _};
use tenko_core::{
    Coded, Timestamp,
    ir::{Ir, LossReport},
};
use tonic::{
    Request, Status,
    metadata::{MetadataKey, MetadataMap, MetadataValue},
    transport::Channel,
};
use tracing::{Instrument as _, Span, field::Empty};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

use crate::{
    ActuatorIntent, ActuatorPlan, ActuatorReceipt, CallContext, ConnectorError, Cursor,
    HealthReport, InventoryBatch, L2Change, L2Plan, L2Receipt, MigrationScope, TopologySnapshot,
    WebhookRequest, WriteMode, convert,
    proto::v1,
    status::{ERROR_CODE, TOKEN_METADATA, from_status},
};

/// Largest message the host accepts or sends, in bytes.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Most pages one poll follows before the host stops (a plugin that never ends a paging
/// sequence).
pub const MAX_PAGES: usize = 1_000;

/// Most migration items one read accepts.
pub const MAX_ITEMS: usize = 1_000_000;

/// `rpc.service` of the services of the plugin protocol.
const PLUGIN: &str = "tenko.connect.v1.Plugin";
const INVENTORY: &str = "tenko.connect.v1.Inventory";
const NETWORK: &str = "tenko.connect.v1.NetworkController";
const ACTUATOR: &str = "tenko.connect.v1.Actuator";
const MIGRATION: &str = "tenko.connect.v1.Migration";

/// A connection to one running plugin. Cheap to clone.
///
/// Every call runs in a span `tenko.connector.call` (OPS-05) with `rpc.system`,
/// `rpc.service`, `rpc.method`, `tenko.connector.instance` (when the client knows its
/// instance, [`PluginClient::with_instance`]), `rpc.grpc.status_code` and
/// `tenko.connector.outcome` (`ok` or the error code); the span's context goes to the plugin
/// as `traceparent` and `tracestate` in the metadata, through the process-wide propagator.
#[derive(Clone)]
pub struct PluginClient {
    channel: Channel,
    token: Arc<MetadataValue<tonic::metadata::Ascii>>,
    /// The connector instance id, for the spans.
    instance: Option<Arc<str>>,
}

impl std::fmt::Debug for PluginClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginClient").finish_non_exhaustive()
    }
}

/// An inventory poll that followed every page: the hosts of all pages, the last cursor,
/// and the warnings of lenient conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolledInventory {
    /// The pages merged into one batch (`more` is false).
    pub batch: InventoryBatch,
    /// Hosts or values the host dropped, in English.
    pub warnings: Vec<String>,
    /// How many pages were read.
    pub pages: usize,
}

impl PluginClient {
    /// A client over an open channel with the per-launch token.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::Protocol`] when the token is not valid metadata text.
    pub fn new(channel: Channel, token: &str) -> Result<Self, ConnectorError> {
        let token = MetadataValue::try_from(token)
            .map_err(|_| ConnectorError::protocol("the token is not valid metadata"))?;
        Ok(Self {
            channel,
            token: Arc::new(token),
            instance: None,
        })
    }

    /// The same client, naming connector instance `instance` in its spans.
    #[must_use]
    pub fn with_instance(mut self, instance: impl std::fmt::Display) -> Self {
        self.instance = Some(Arc::from(instance.to_string()));
        self
    }

    /// A request with the token and the timeout, and the span of the call with its context
    /// in the metadata.
    pub(crate) fn traced<T>(
        &self,
        service: &'static str,
        method: &'static str,
        message: T,
        timeout: Duration,
    ) -> (Request<T>, Span) {
        let mut request = self.request(message, timeout);
        let span = tracing::info_span!(
            "tenko.connector.call",
            otel.kind = "client",
            otel.status_code = Empty,
            rpc.system = "grpc",
            rpc.service = service,
            rpc.method = method,
            tenko.connector.instance = Empty,
            rpc.grpc.status_code = Empty,
            tenko.connector.outcome = Empty,
        );
        if !span.is_disabled() {
            if let Some(instance) = &self.instance {
                span.record("tenko.connector.instance", &**instance);
            }
            inject(&span, request.metadata_mut());
        }
        (request, span)
    }

    /// The channel, for raw calls of the conformance suite.
    pub(crate) fn channel(&self) -> Channel {
        self.channel.clone()
    }

    /// A request with the token and the timeout, for raw calls of the conformance suite.
    pub(crate) fn authorized<T>(&self, message: T, timeout: Duration) -> Request<T> {
        self.request(message, timeout)
    }

    fn request<T>(&self, message: T, timeout: Duration) -> Request<T> {
        let mut request = Request::new(message);
        request
            .metadata_mut()
            .insert(TOKEN_METADATA, (*self.token).clone());
        request.set_timeout(timeout);
        request
    }

    fn plugin(&self) -> v1::plugin_client::PluginClient<Channel> {
        v1::plugin_client::PluginClient::new(self.channel.clone())
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_MESSAGE_BYTES)
    }

    fn inventory(&self) -> v1::inventory_client::InventoryClient<Channel> {
        v1::inventory_client::InventoryClient::new(self.channel.clone())
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_MESSAGE_BYTES)
    }

    fn network(&self) -> v1::network_controller_client::NetworkControllerClient<Channel> {
        v1::network_controller_client::NetworkControllerClient::new(self.channel.clone())
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_MESSAGE_BYTES)
    }

    fn actuator(&self) -> v1::actuator_client::ActuatorClient<Channel> {
        v1::actuator_client::ActuatorClient::new(self.channel.clone())
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_MESSAGE_BYTES)
    }

    fn migration(&self) -> v1::migration_client::MigrationClient<Channel> {
        v1::migration_client::MigrationClient::new(self.channel.clone())
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_MESSAGE_BYTES)
    }

    /// Liveness: the plugin answers with its name and version.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::Timeout`] or the plugin's error.
    pub async fn ping(&self, timeout: Duration) -> Result<v1::PingResponse, ConnectorError> {
        let (request, span) = self.traced(PLUGIN, "Ping", v1::PingRequest {}, timeout);
        call(span, timeout, self.plugin().ping(request)).await
    }

    /// Remote health.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::Timeout`], the plugin's error, or [`ConnectorError::Protocol`]
    /// for an answer that does not convert.
    pub async fn check(
        &self,
        ctx: &CallContext,
        timeout: Duration,
    ) -> Result<HealthReport, ConnectorError> {
        let (request, span) = self.traced(
            PLUGIN,
            "Check",
            v1::CheckRequest {
                context: Some(convert::context_to_proto(ctx)),
            },
            timeout,
        );
        let response = call(span, timeout, self.plugin().check(request)).await?;
        Ok(convert::health_from_proto(response, Timestamp::now())?)
    }

    /// Asks the plugin to exit.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::Timeout`] or the plugin's error.
    pub async fn shutdown(&self, timeout: Duration) -> Result<(), ConnectorError> {
        let (request, span) = self.traced(PLUGIN, "Shutdown", v1::ShutdownRequest {}, timeout);
        call(span, timeout, self.plugin().shutdown(request)).await?;
        Ok(())
    }

    /// One poll call (one page), converted leniently.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::Timeout`] or the plugin's error.
    pub async fn poll_page(
        &self,
        ctx: &CallContext,
        cursor: Option<&Cursor>,
        timeout: Duration,
    ) -> Result<(InventoryBatch, Vec<String>), ConnectorError> {
        let (request, span) = self.traced(
            INVENTORY,
            "Poll",
            v1::PollRequest {
                context: Some(convert::context_to_proto(ctx)),
                cursor: cursor.map(|cursor| cursor.0.clone()),
            },
            timeout,
        );
        let response = call(span, timeout, self.inventory().poll(request)).await?;
        Ok(convert::batch_from_proto(response, Timestamp::now()))
    }

    /// Polls and follows every page (`more`), each page with its own timeout, at most
    /// [`MAX_PAGES`] pages.
    ///
    /// # Errors
    ///
    /// The error of any page, or [`ConnectorError::Protocol`] for a paging sequence that
    /// does not end or repeats a cursor.
    pub async fn poll(
        &self,
        ctx: &CallContext,
        cursor: Option<Cursor>,
        timeout: Duration,
    ) -> Result<PolledInventory, ConnectorError> {
        let (mut batch, mut warnings) = self.poll_page(ctx, cursor.as_ref(), timeout).await?;
        let mut pages = 1;
        let mut seen = std::collections::HashSet::new();
        while batch.more {
            let Some(next) = batch.cursor.clone() else {
                return Err(ConnectorError::protocol(
                    "the plugin announced another page without a cursor",
                ));
            };
            if !seen.insert(next.0.clone()) {
                return Err(ConnectorError::protocol(format!(
                    "the plugin repeated the cursor `{}`",
                    next.0.chars().take(64).collect::<String>()
                )));
            }
            if pages >= MAX_PAGES {
                return Err(ConnectorError::protocol(format!(
                    "the plugin returned more than {MAX_PAGES} pages"
                )));
            }
            let (page, page_warnings) = self.poll_page(ctx, Some(&next), timeout).await?;
            pages += 1;
            warnings.extend(page_warnings);
            batch.hosts.extend(page.hosts);
            batch.vendors.extend(page.vendors);
            batch.complete = page.complete;
            batch.cursor = page.cursor;
            batch.more = page.more;
            batch.observed_at = batch.observed_at.max(page.observed_at);
        }
        Ok(PolledInventory {
            batch,
            warnings,
            pages,
        })
    }

    /// Hands a webhook call to the plugin.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::Timeout`] or the plugin's error.
    pub async fn webhook(
        &self,
        ctx: &CallContext,
        webhook: &WebhookRequest,
        timeout: Duration,
    ) -> Result<Option<(InventoryBatch, Vec<String>)>, ConnectorError> {
        let (request, span) = self.traced(
            INVENTORY,
            "HandleWebhook",
            v1::WebhookRequest {
                context: Some(convert::context_to_proto(ctx)),
                headers: webhook
                    .headers
                    .iter()
                    .map(|(name, value)| v1::Header {
                        name: name.clone(),
                        value: value.clone(),
                    })
                    .collect(),
                body: webhook.body.to_vec(),
            },
            timeout,
        );
        let response = call(span, timeout, self.inventory().handle_webhook(request)).await?;
        Ok(response
            .batch
            .map(|batch| convert::batch_from_proto(batch, Timestamp::now())))
    }

    /// The topology of a network controller.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::Timeout`], the plugin's error, or [`ConnectorError::Protocol`]
    /// for a topology that does not convert.
    pub async fn topology(
        &self,
        ctx: &CallContext,
        timeout: Duration,
    ) -> Result<TopologySnapshot, ConnectorError> {
        let (request, span) = self.traced(
            NETWORK,
            "Topology",
            v1::TopologyRequest {
                context: Some(convert::context_to_proto(ctx)),
            },
            timeout,
        );
        let response = call(span, timeout, self.network().topology(request)).await?;
        Ok(convert::topology_from_proto(response.topology)?)
    }

    /// Plans an L2 change (no write).
    ///
    /// # Errors
    ///
    /// As [`topology`](PluginClient::topology).
    pub async fn plan(
        &self,
        ctx: &CallContext,
        change: &L2Change,
        timeout: Duration,
    ) -> Result<L2Plan, ConnectorError> {
        let (request, span) = self.traced(
            NETWORK,
            "Plan",
            v1::L2PlanRequest {
                context: Some(convert::context_to_proto(ctx)),
                change: Some(convert::change_to_proto(change)),
            },
            timeout,
        );
        let response = call(span, timeout, self.network().plan(request)).await?;
        Ok(convert::plan_from_proto("plan", response.plan)?)
    }

    /// Applies an L2 plan.
    ///
    /// # Errors
    ///
    /// As [`topology`](PluginClient::topology).
    pub async fn apply(
        &self,
        ctx: &CallContext,
        plan: &L2Plan,
        mode: WriteMode,
        timeout: Duration,
    ) -> Result<L2Receipt, ConnectorError> {
        let (request, span) = self.traced(
            NETWORK,
            "Apply",
            v1::L2ApplyRequest {
                context: Some(convert::context_to_proto(ctx)),
                plan: Some(convert::plan_to_proto(plan)),
                mode: convert::mode_to_proto(mode),
            },
            timeout,
        );
        let response = call(span, timeout, self.network().apply(request)).await?;
        Ok(convert::receipt_from_proto("receipt", response.receipt)?)
    }

    /// Reverts an applied L2 change.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::Timeout`] or the plugin's error.
    pub async fn revert(
        &self,
        ctx: &CallContext,
        receipt: &L2Receipt,
        timeout: Duration,
    ) -> Result<(), ConnectorError> {
        let (request, span) = self.traced(
            NETWORK,
            "Revert",
            v1::L2RevertRequest {
                context: Some(convert::context_to_proto(ctx)),
                receipt: Some(convert::receipt_to_proto(receipt)),
            },
            timeout,
        );
        call(span, timeout, self.network().revert(request)).await?;
        Ok(())
    }

    /// Plans an actuation (no write).
    ///
    /// # Errors
    ///
    /// As [`topology`](PluginClient::topology).
    pub async fn actuator_plan(
        &self,
        ctx: &CallContext,
        intent: &ActuatorIntent,
        timeout: Duration,
    ) -> Result<ActuatorPlan, ConnectorError> {
        let (request, span) = self.traced(
            ACTUATOR,
            "Plan",
            v1::ActuatorPlanRequest {
                context: Some(convert::context_to_proto(ctx)),
                intent: Some(convert::intent_to_proto(intent)),
            },
            timeout,
        );
        let response = call(span, timeout, self.actuator().plan(request)).await?;
        Ok(convert::actuator_plan_from_proto("plan", response.plan)?)
    }

    /// Applies an actuation plan.
    ///
    /// # Errors
    ///
    /// As [`topology`](PluginClient::topology).
    pub async fn actuator_apply(
        &self,
        ctx: &CallContext,
        plan: &ActuatorPlan,
        mode: WriteMode,
        timeout: Duration,
    ) -> Result<ActuatorReceipt, ConnectorError> {
        let (request, span) = self.traced(
            ACTUATOR,
            "Apply",
            v1::ActuatorApplyRequest {
                context: Some(convert::context_to_proto(ctx)),
                plan: Some(convert::actuator_plan_to_proto(plan)),
                mode: convert::mode_to_proto(mode),
            },
            timeout,
        );
        let response = call(span, timeout, self.actuator().apply(request)).await?;
        Ok(convert::actuator_receipt_from_proto(
            "receipt",
            response.receipt,
        )?)
    }

    /// Reverts an actuation.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::Timeout`] or the plugin's error.
    pub async fn actuator_revert(
        &self,
        ctx: &CallContext,
        receipt: &ActuatorReceipt,
        timeout: Duration,
    ) -> Result<(), ConnectorError> {
        let (request, span) = self.traced(
            ACTUATOR,
            "Revert",
            v1::ActuatorRevertRequest {
                context: Some(convert::context_to_proto(ctx)),
                receipt: Some(convert::actuator_receipt_to_proto(receipt)),
            },
            timeout,
        );
        call(span, timeout, self.actuator().revert(request)).await?;
        Ok(())
    }

    /// Reads a migration source into IR and a loss report. `timeout` bounds the whole
    /// stream.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::Timeout`], the plugin's error, or [`ConnectorError::Protocol`]
    /// for more than [`MAX_ITEMS`] items.
    pub async fn migration_read(
        &self,
        ctx: &CallContext,
        scope: &MigrationScope,
        timeout: Duration,
    ) -> Result<(Ir, LossReport), ConnectorError> {
        let (request, span) = self.traced(
            MIGRATION,
            "Read",
            v1::MigrationReadRequest {
                context: Some(convert::context_to_proto(ctx)),
                scope: Some(convert::scope_to_proto(scope)),
            },
            timeout,
        );
        let mut client = self.migration();
        let traced = span.clone();
        let read = async move {
            let mut stream = client
                .read(request)
                .await
                .map_err(|status| map_status(&status, timeout))?
                .into_inner();
            let mut assembler = convert::IrAssembler::new();
            let mut count = 0usize;
            while let Some(item) = stream.next().await {
                let item = item.map_err(|status| map_status(&status, timeout))?;
                count += 1;
                if count > MAX_ITEMS {
                    return Err(ConnectorError::protocol(format!(
                        "the plugin streamed more than {MAX_ITEMS} items"
                    )));
                }
                assembler.push(item);
            }
            Ok(assembler.finish())
        };
        let result = tokio::time::timeout(timeout, read.instrument(traced))
            .await
            .map_err(|_| ConnectorError::Timeout(timeout))
            .and_then(|read| read);
        let code = match &result {
            Ok(_) => tonic::Code::Ok,
            Err(ConnectorError::Timeout(_)) => tonic::Code::DeadlineExceeded,
            Err(_) => tonic::Code::Unknown,
        };
        record(&span, code, result.as_ref().err());
        result
    }
}

/// Runs one unary call in its span with a timeout, maps the error and records the outcome.
async fn call<T>(
    span: Span,
    timeout: Duration,
    call: impl std::future::Future<Output = Result<tonic::Response<T>, Status>>,
) -> Result<T, ConnectorError> {
    let (code, result) = match tokio::time::timeout(timeout, call)
        .instrument(span.clone())
        .await
    {
        Err(_) => (
            tonic::Code::DeadlineExceeded,
            Err(ConnectorError::Timeout(timeout)),
        ),
        Ok(Err(status)) => (status.code(), Err(map_status(&status, timeout))),
        Ok(Ok(response)) => (tonic::Code::Ok, Ok(response.into_inner())),
    };
    record(&span, code, result.as_ref().err());
    result
}

/// Records the status and the outcome of a call on its span.
fn record(span: &Span, code: tonic::Code, error: Option<&ConnectorError>) {
    if span.is_disabled() {
        return;
    }
    span.record("rpc.grpc.status_code", i32::from(code));
    match error {
        None => span.record("tenko.connector.outcome", "ok"),
        Some(error) => {
            span.record("otel.status_code", "error");
            span.record("tenko.connector.outcome", Coded::code(error))
        }
    };
}

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

/// Puts the context of `span` into `metadata` (W3C `traceparent` and `tracestate`), when
/// it belongs to a trace.
fn inject(span: &Span, metadata: &mut MetadataMap) {
    let context = span.context();
    if !context.span().span_context().is_valid() {
        return;
    }
    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&context, &mut MetadataInjector(metadata));
    });
}

/// A status from the transport (the connection to the plugin failed) is
/// [`ConnectorError::PluginUnavailable`]; a deadline that passed on either side is
/// [`ConnectorError::Timeout`]; a status the plugin sent follows the protocol's error
/// convention.
pub(crate) fn map_status(status: &Status, timeout: Duration) -> ConnectorError {
    let coded = status.metadata().get(ERROR_CODE).is_some();
    if !coded {
        let timed_out = status.code() == tonic::Code::DeadlineExceeded
            || (status.code() == tonic::Code::Cancelled
                && status.message().contains("Timeout expired"));
        if timed_out {
            return ConnectorError::Timeout(timeout);
        }
        if std::error::Error::source(status).is_some() {
            return ConnectorError::PluginUnavailable(format!(
                "the connection to the plugin failed: {}",
                status.message()
            ));
        }
        if status.code() == tonic::Code::Cancelled {
            return ConnectorError::PluginFailed(format!(
                "the plugin cancelled the call: {}",
                status.message()
            ));
        }
    }
    from_status(status)
}
