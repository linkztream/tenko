//! The `Observations` service: probe batches into the controller's reconciler.
//!
//! A batch is recognised as sent before by its (epoch, sequence) against the node's ingest
//! cursor in the store (`cluster.ingest_cursors`), which every controller reads and
//! writes, so a resend after a lost answer is not ingested twice even when it reaches
//! another controller; a per-process copy answers repeats on the same controller without a
//! read. A controller that cannot write refuses the batch with `cluster.no_quorum`, and the
//! node keeps it and tries the next controller.

use std::{collections::HashMap, sync::PoisonError};

use tenko_core::{NodeId, Role, Timestamp};
use tonic::{Request, Response, Status};

use crate::{
    error::ClusterError,
    node_sync::{codes, cursors},
    probe::{IngestCounts, ProbeBatch, run_of},
    proto::v1,
    server::{ClusterService, peer_of, status_of},
};

/// The code of a store that cannot write, as a component reports it.
const STORE_NO_QUORUM: &str = "sys.store.no_quorum";

fn no_quorum() -> ClusterError {
    ClusterError::new(
        codes::NO_QUORUM,
        503,
        "this controller is cut off from the cluster and cannot take observations; try another one",
    )
}

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
        let store = std::sync::Arc::clone(self.registry.node_sync().store());
        if !store.status().quorum.accepts_writes() {
            return Err(status_of(&no_quorum()));
        }
        let request = request.into_inner();
        let epoch = request.epoch.clone();
        let sequence = request.sequence;
        let run = run_of(&request);
        let seen_here = self
            .lock_ingested()
            .get(&node)
            .is_some_and(|(last_epoch, last)| *last_epoch == epoch && sequence <= *last);
        let duplicate = seen_here
            || cursors::seen_anywhere(store.as_ref(), node, &epoch, sequence)
                .await
                .map_err(|error| status_of(&error))?;
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
        let result = run.map(|command| (command, batch.clone()));
        let counts: IngestCounts = self.sink.ingest(node, vrf, batch).await.map_err(|error| {
            if error.code() == STORE_NO_QUORUM {
                status_of(&no_quorum())
            } else {
                status_of(&error)
            }
        })?;
        let run = result.as_ref().map(|(command, batch)| (*command, batch));
        if let Err(error) = cursors::record(store.as_ref(), node, &epoch, sequence, run).await {
            tracing::warn!(node = %node, sequence, code = %error.code(), "the ingest cursor could not be written: {}", error.detail());
        }
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
