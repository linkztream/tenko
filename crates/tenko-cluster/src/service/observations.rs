//! The `Observations` service: probe batches into the controller's reconciler.

use std::{collections::HashMap, sync::PoisonError};

use tenko_core::{NodeId, Role, Timestamp};
use tonic::{Request, Response, Status};

use crate::{
    error::ClusterError,
    probe::{IngestCounts, ProbeBatch},
    proto::v1,
    server::{ClusterService, peer_of, status_of},
};

#[tonic::async_trait]
impl v1::observations_server::Observations for ClusterService {
    async fn ingest(
        &self,
        request: Request<v1::IngestRequest>,
    ) -> Result<Response<v1::IngestResponse>, Status> {
        let peer = peer_of(&request)?;
        let record = self.authenticate(&peer).await?;
        let node = peer.identity.node;
        if !record.roles.contains(&Role::Probe) {
            return Err(status_of(&ClusterError::new(
                "cluster.node.role",
                403,
                format!("node {node} does not have the role probe"),
            )));
        }
        let request = request.into_inner();
        let epoch = request.epoch.clone();
        let sequence = request.sequence;
        let duplicate = self
            .lock_ingested()
            .get(&node)
            .is_some_and(|(last_epoch, last)| *last_epoch == epoch && sequence <= *last);
        if duplicate {
            return Ok(Response::new(v1::IngestResponse {
                sequence,
                duplicate: true,
                ..v1::IngestResponse::default()
            }));
        }
        let (batch, skipped) =
            ProbeBatch::from_request(request).map_err(|error| status_of(&error))?;
        let vrf = batch.vrf.or(record.vrf);
        let counts: IngestCounts = self
            .sink
            .ingest(node, vrf, batch)
            .await
            .map_err(|error| status_of(&error))?;
        self.lock_ingested().insert(node, (epoch, sequence));
        if let Err(error) = self.registry.touch(node, Timestamp::now(), false).await {
            tracing::debug!(node = %node, %error, "last_seen could not be written");
        }
        Ok(Response::new(v1::IngestResponse {
            sequence,
            duplicate: false,
            new: counts.new,
            changed: counts.changed,
            refreshed: counts.refreshed,
            unchanged: counts.unchanged,
            gone: counts.gone,
            skipped: counts.skipped.saturating_add(skipped),
        }))
    }
}

impl ClusterService {
    fn lock_ingested(&self) -> std::sync::MutexGuard<'_, HashMap<NodeId, (String, u64)>> {
        self.ingested.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
