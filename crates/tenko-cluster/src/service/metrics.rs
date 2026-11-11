//! The `Metrics` service: one controller's newest metrics sample and the history of its
//! dashboard figures for the other controllers (see [`crate::metrics`]). The caller holds a
//! controller certificate; the answers come from the source the server set on the node
//! registry.

use tenko_core::{Role, Timestamp};
use tonic::{Request, Response, Status};

use crate::{
    error::ClusterError,
    proto::v1,
    server::{ClusterService, peer_of, status_of},
    trace,
};

fn unavailable() -> Status {
    status_of(&ClusterError::new(
        "cluster.metrics.unavailable",
        503,
        "this controller has no metrics sample yet; try again in a second",
    ))
}

impl ClusterService {
    /// Admits a caller of the `Metrics` service: a controller, and when it has a node record
    /// (every controller that joined), one whose record names the role and holds the
    /// certificate; the first controller's own certificate has none (the TLS handshake
    /// verified it).
    async fn admit_controller<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let peer = peer_of(request)?;
        let node = peer.identity.node;
        if !peer.identity.roles.contains(Role::Controller) {
            return Err(status_of(&ClusterError::new(
                "cluster.peer.not_controller",
                403,
                format!(
                    "node {node} is not a controller; only controllers read the metrics of a controller"
                ),
            )));
        }
        if let Some((record, _)) = self
            .registry
            .record(node)
            .await
            .map_err(|error| status_of(&error))?
            && (!record.roles.contains(&Role::Controller)
                || !record.holds(&peer.identity.serial, Timestamp::now()))
        {
            return Err(status_of(&ClusterError::new(
                "cluster.node.certificate_unknown",
                403,
                "the certificate is not one this controller was issued, or it expired",
            )));
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl v1::metrics_server::Metrics for ClusterService {
    async fn snapshot(
        &self,
        request: Request<v1::SnapshotRequest>,
    ) -> Result<Response<v1::MetricsSnapshot>, Status> {
        let span = trace::span_for(&request, trace::METRICS, "Snapshot");
        trace::serve(span, async move {
            self.admit_controller(&request).await?;
            let source = self.registry.metrics_source().ok_or_else(unavailable)?;
            let sample = source.current().await.ok_or_else(unavailable)?;
            Ok(Response::new(sample.to_proto()))
        })
        .await
    }

    // WP18.0: the history of the dashboard's figures.
    async fn history(
        &self,
        request: Request<v1::HistoryRequest>,
    ) -> Result<Response<v1::MetricsHistory>, Status> {
        let span = trace::span_for(&request, trace::METRICS, "History");
        trace::serve(span, async move {
            self.admit_controller(&request).await?;
            let source = self.registry.metrics_source().ok_or_else(unavailable)?;
            // A source without a history answers as a build before it: the caller combines
            // this controller as a missing one.
            let history = source.history().await.ok_or_else(|| {
                Status::unimplemented("this controller keeps no history of its metrics")
            })?;
            Ok(Response::new(history.to_proto()))
        })
        .await
    }
}
