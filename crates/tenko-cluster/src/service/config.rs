//! The `Config` service: configuration sync to nodes, the secrets their configuration
//! names, a node's offer of its own configuration and its report of what it applies
//! (OPS-28, SCAN-05). The work is done in [`crate::node_sync`]; this file authenticates the
//! caller and maps the answers.

use std::pin::Pin;

use futures::Stream;
use tenko_core::{Role, Timestamp};
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};

use crate::{
    error::ClusterError,
    node_sync::{codes, secrets, source, tables::tables_for},
    probe::{ProbeScope, record_scope},
    proto::v1,
    server::{ClusterService, peer_of, status_of},
};

type DeltaStream = Pin<Box<dyn Stream<Item = Result<v1::ConfigDelta, Status>> + Send>>;

/// Most purposes in one `Secrets` request.
const MAX_PURPOSES: usize = 16;

#[tonic::async_trait]
impl v1::config_server::Config for ClusterService {
    type WatchStream = DeltaStream;

    async fn watch(
        &self,
        request: Request<v1::WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let peer = peer_of(&request)?;
        let record = self.authenticate(&peer).await?;
        let from = request.into_inner().from_revision;
        let (tx, mut rx) = mpsc::channel(4);
        let sync = self.registry.node_sync().clone();
        tokio::spawn(source::serve_watch(
            sync,
            record.id,
            record.roles.clone(),
            from,
            tx,
        ));
        let stream: DeltaStream = Box::pin(futures::stream::poll_fn(move |cx| rx.poll_recv(cx)));
        Ok(Response::new(stream))
    }

    async fn secrets(
        &self,
        request: Request<v1::SecretsRequest>,
    ) -> Result<Response<v1::SecretsResponse>, Status> {
        let peer = peer_of(&request)?;
        let record = self.authenticate(&peer).await?;
        let purposes = request.into_inner().purposes;
        if purposes.len() > MAX_PURPOSES {
            return Err(status_of(&ClusterError::new(
                codes::SECRETS_PURPOSE,
                400,
                format!("at most {MAX_PURPOSES} purposes per request"),
            )));
        }
        let values = secrets::resolve(self.registry.node_sync(), &record, &purposes)
            .await
            .map_err(|error| status_of(&error))?;
        if !values.is_empty() {
            tracing::info!(node = %record.id, count = values.len(), "secrets handed to a node");
        }
        Ok(Response::new(v1::SecretsResponse {
            secrets: values
                .iter()
                .map(secrets::NodeSecretValue::to_proto)
                .collect(),
        }))
    }

    async fn offer(
        &self,
        request: Request<v1::OfferRequest>,
    ) -> Result<Response<v1::OfferResponse>, Status> {
        let peer = peer_of(&request)?;
        let record = self.authenticate(&peer).await?;
        let offer = request.into_inner();
        if !tables_for(&record.roles)
            .iter()
            .any(|table| table.as_str() == offer.table)
        {
            return Err(status_of(&ClusterError::new(
                codes::CONFIG_KIND,
                403,
                format!(
                    "node {} has no role that uses the configuration `{}`",
                    record.id,
                    offer.table.chars().take(64).collect::<String>()
                ),
            )));
        }
        let handler = self
            .registry
            .node_sync()
            .offer_handler(&offer.table)
            .ok_or_else(|| {
                status_of(&ClusterError::new(
                    codes::CONFIG_KIND,
                    503,
                    "this controller does not take configuration offers yet; try again later",
                ))
            })?;
        let accepted = handler
            .offer(&record, &offer.encoding, &offer.payload)
            .await
            .map_err(|error| status_of(&error))?;
        let detail = if accepted {
            tracing::info!(node = %record.id, table = %offer.table, "a node's own configuration became its initial one");
            "the configuration is kept as the node's initial one".to_owned()
        } else {
            "the controllers hold a configuration for the node already; it wins".to_owned()
        };
        Ok(Response::new(v1::OfferResponse { accepted, detail }))
    }

    async fn report(
        &self,
        request: Request<v1::ConfigReport>,
    ) -> Result<Response<v1::ConfigReportResponse>, Status> {
        let peer = peer_of(&request)?;
        let record = self.authenticate(&peer).await?;
        let report = request.into_inner();
        if let Some(probe) = &report.probe
            && record.roles.contains(&Role::Probe)
        {
            let scope = ProbeScope::from_report(record.id, &report, probe, Timestamp::now());
            record_scope(self.registry.node_sync().store().as_ref(), record.id, scope)
                .await
                .map_err(|error| status_of(&error))?;
        }
        Ok(Response::new(v1::ConfigReportResponse {}))
    }
}
