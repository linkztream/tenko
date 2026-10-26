//! The gRPC services of the SDK: adapters from the server traits of the protocol to the traits a
//! plugin implements.

use std::{pin::Pin, sync::Arc};

use futures::Stream;
use tokio::sync::Notify;
use tonic::{Request, Response, Status};

use crate::{
    Actuator, Connector, Cursor, InventorySource, MigrationSource, NetworkController,
    WebhookRequest, convert,
    proto::v1,
    status::{malformed, to_status},
};

fn failed(error: &crate::ConnectorError) -> Status {
    to_status(error)
}

/// `Plugin`: ping, check, shutdown.
pub(super) struct PluginService {
    pub(super) name: String,
    pub(super) version: String,
    pub(super) connector: Arc<dyn Connector>,
    pub(super) shutdown: Arc<Notify>,
}

#[tonic::async_trait]
impl v1::plugin_server::Plugin for PluginService {
    async fn ping(
        &self,
        _request: Request<v1::PingRequest>,
    ) -> Result<Response<v1::PingResponse>, Status> {
        Ok(Response::new(v1::PingResponse {
            name: self.name.clone(),
            version: self.version.clone(),
        }))
    }

    async fn check(
        &self,
        request: Request<v1::CheckRequest>,
    ) -> Result<Response<v1::CheckResponse>, Status> {
        let ctx = convert::context_from_proto(request.into_inner().context).map_err(malformed)?;
        let report = self.connector.check(&ctx).await.map_err(|e| failed(&e))?;
        Ok(Response::new(convert::health_to_proto(&report)))
    }

    async fn shutdown(
        &self,
        _request: Request<v1::ShutdownRequest>,
    ) -> Result<Response<v1::ShutdownResponse>, Status> {
        // A stored permit: the serve loop sees it even when it is not waiting yet.
        self.shutdown.notify_one();
        Ok(Response::new(v1::ShutdownResponse {}))
    }
}

/// `Inventory`: poll and webhooks.
pub(super) struct InventoryService {
    pub(super) source: Arc<dyn InventorySource>,
    /// Whether the manifest declares `webhook`.
    pub(super) webhooks: bool,
}

#[tonic::async_trait]
impl v1::inventory_server::Inventory for InventoryService {
    async fn poll(
        &self,
        request: Request<v1::PollRequest>,
    ) -> Result<Response<v1::PollResponse>, Status> {
        let request = request.into_inner();
        let ctx = convert::context_from_proto(request.context).map_err(malformed)?;
        let cursor = request
            .cursor
            .filter(|cursor| !cursor.is_empty())
            .map(Cursor);
        let batch = self
            .source
            .poll(&ctx, cursor)
            .await
            .map_err(|e| failed(&e))?;
        Ok(Response::new(convert::batch_to_proto(&batch)))
    }

    async fn handle_webhook(
        &self,
        request: Request<v1::WebhookRequest>,
    ) -> Result<Response<v1::WebhookResponse>, Status> {
        if !self.webhooks {
            return Err(failed(&crate::ConnectorError::Unsupported));
        }
        let request = request.into_inner();
        let ctx = convert::context_from_proto(request.context).map_err(malformed)?;
        let webhook = WebhookRequest {
            headers: request
                .headers
                .into_iter()
                .map(|header| (header.name.to_ascii_lowercase(), header.value))
                .collect(),
            body: request.body.into(),
        };
        let batch = self
            .source
            .webhook(&ctx, webhook)
            .await
            .map_err(|e| failed(&e))?;
        Ok(Response::new(v1::WebhookResponse {
            batch: batch.as_ref().map(convert::batch_to_proto),
        }))
    }
}

/// `NetworkController`: topology, plan, apply, revert. A port bounce or a client kick the
/// manifest does not declare (`port_bounce`, `client_kick`) is answered with `UNIMPLEMENTED`
/// before the plugin sees it.
pub(super) struct NetworkService {
    pub(super) controller: Arc<dyn NetworkController>,
    pub(super) declared: Vec<crate::Capability>,
}

impl NetworkService {
    /// Refuses a change whose capability the manifest does not declare.
    fn declared(&self, change: &crate::L2Change) -> Result<(), Status> {
        match change.capability() {
            Some(capability) if !self.declared.contains(&capability) => {
                Err(failed(&crate::ConnectorError::Unsupported))
            }
            _ => Ok(()),
        }
    }
}

#[tonic::async_trait]
impl v1::network_controller_server::NetworkController for NetworkService {
    async fn topology(
        &self,
        request: Request<v1::TopologyRequest>,
    ) -> Result<Response<v1::TopologyResponse>, Status> {
        let ctx = convert::context_from_proto(request.into_inner().context).map_err(malformed)?;
        let topology = self
            .controller
            .topology(&ctx)
            .await
            .map_err(|e| failed(&e))?;
        Ok(Response::new(v1::TopologyResponse {
            topology: Some(convert::topology_to_proto(&topology)),
        }))
    }

    async fn plan(
        &self,
        request: Request<v1::L2PlanRequest>,
    ) -> Result<Response<v1::L2PlanResponse>, Status> {
        let request = request.into_inner();
        let ctx = convert::context_from_proto(request.context).map_err(malformed)?;
        let change = convert::change_from_proto("change", request.change).map_err(malformed)?;
        self.declared(&change)?;
        let plan = self
            .controller
            .plan(&ctx, &change)
            .await
            .map_err(|e| failed(&e))?;
        Ok(Response::new(v1::L2PlanResponse {
            plan: Some(convert::plan_to_proto(&plan)),
        }))
    }

    async fn apply(
        &self,
        request: Request<v1::L2ApplyRequest>,
    ) -> Result<Response<v1::L2ApplyResponse>, Status> {
        let request = request.into_inner();
        let ctx = convert::context_from_proto(request.context).map_err(malformed)?;
        let plan = convert::plan_from_proto("plan", request.plan).map_err(malformed)?;
        self.declared(&plan.change)?;
        let mode = convert::mode_from_proto(request.mode);
        let receipt = self
            .controller
            .apply(&ctx, &plan, mode)
            .await
            .map_err(|e| failed(&e))?;
        Ok(Response::new(v1::L2ApplyResponse {
            receipt: Some(convert::receipt_to_proto(&receipt)),
        }))
    }

    async fn revert(
        &self,
        request: Request<v1::L2RevertRequest>,
    ) -> Result<Response<v1::L2RevertResponse>, Status> {
        let request = request.into_inner();
        let ctx = convert::context_from_proto(request.context).map_err(malformed)?;
        let receipt = convert::receipt_from_proto("receipt", request.receipt).map_err(malformed)?;
        self.declared(&receipt.plan.change)?;
        self.controller
            .revert(&ctx, &receipt)
            .await
            .map_err(|e| failed(&e))?;
        Ok(Response::new(v1::L2RevertResponse {}))
    }
}

/// `Actuator`: plan, apply, revert.
pub(super) struct ActuatorService(pub(super) Arc<dyn Actuator>);

#[tonic::async_trait]
impl v1::actuator_server::Actuator for ActuatorService {
    async fn plan(
        &self,
        request: Request<v1::ActuatorPlanRequest>,
    ) -> Result<Response<v1::ActuatorPlanResponse>, Status> {
        let request = request.into_inner();
        let ctx = convert::context_from_proto(request.context).map_err(malformed)?;
        let intent = convert::intent_from_proto("intent", request.intent).map_err(malformed)?;
        let plan = self.0.plan(&ctx, &intent).await.map_err(|e| failed(&e))?;
        Ok(Response::new(v1::ActuatorPlanResponse {
            plan: Some(convert::actuator_plan_to_proto(&plan)),
        }))
    }

    async fn apply(
        &self,
        request: Request<v1::ActuatorApplyRequest>,
    ) -> Result<Response<v1::ActuatorApplyResponse>, Status> {
        let request = request.into_inner();
        let ctx = convert::context_from_proto(request.context).map_err(malformed)?;
        let plan = convert::actuator_plan_from_proto("plan", request.plan).map_err(malformed)?;
        let mode = convert::mode_from_proto(request.mode);
        let receipt = self
            .0
            .apply(&ctx, &plan, mode)
            .await
            .map_err(|e| failed(&e))?;
        Ok(Response::new(v1::ActuatorApplyResponse {
            receipt: Some(convert::actuator_receipt_to_proto(&receipt)),
        }))
    }

    async fn revert(
        &self,
        request: Request<v1::ActuatorRevertRequest>,
    ) -> Result<Response<v1::ActuatorRevertResponse>, Status> {
        let request = request.into_inner();
        let ctx = convert::context_from_proto(request.context).map_err(malformed)?;
        let receipt =
            convert::actuator_receipt_from_proto("receipt", request.receipt).map_err(malformed)?;
        self.0
            .revert(&ctx, &receipt)
            .await
            .map_err(|e| failed(&e))?;
        Ok(Response::new(v1::ActuatorRevertResponse {}))
    }
}

/// `Migration`: read.
pub(super) struct MigrationService(pub(super) Arc<dyn MigrationSource>);

type ItemStream = Pin<Box<dyn Stream<Item = Result<v1::MigrationItem, Status>> + Send>>;

#[tonic::async_trait]
impl v1::migration_server::Migration for MigrationService {
    type ReadStream = ItemStream;

    async fn read(
        &self,
        request: Request<v1::MigrationReadRequest>,
    ) -> Result<Response<Self::ReadStream>, Status> {
        let request = request.into_inner();
        let ctx = convert::context_from_proto(request.context).map_err(malformed)?;
        let scope = convert::scope_from_proto(request.scope).map_err(malformed)?;
        let (ir, loss) = self.0.read(&ctx, &scope).await.map_err(|e| failed(&e))?;
        let items = convert::ir_to_items(&ir, &loss);
        Ok(Response::new(Box::pin(futures::stream::iter(
            items.into_iter().map(Ok),
        ))))
    }
}
