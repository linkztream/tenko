//! The `Handshake` service: version negotiation (OPS-08). `Hello` and the fields it had
//! in protocol 1.0 are frozen across majors; `capabilities` and `endpoints` are new fields
//! that stay empty until the controller cluster fills them.

use tenko_core::Timestamp;
use tonic::{Request, Response, Status, metadata::MetadataValue};

use crate::{
    error::ClusterError,
    probe::timestamp_to_proto,
    proto::v1,
    server::{ClusterService, MAJORS_METADATA, peer_of, status_of},
    version,
};

#[tonic::async_trait]
impl v1::handshake_server::Handshake for ClusterService {
    async fn hello(
        &self,
        request: Request<v1::HelloRequest>,
    ) -> Result<Response<v1::HelloResponse>, Status> {
        let peer = peer_of(&request)?;
        self.authenticate(&peer).await?;
        let node = peer.identity.node;
        let hello = request.into_inner();
        let ours = &self.registry.config().majors;
        match version::negotiate(ours, &hello.majors) {
            Ok(major) => {
                if let Err(error) = self
                    .registry
                    .hello_ok(node, &hello.majors, major, &hello.version)
                    .await
                {
                    tracing::warn!(node = %node, %error, "the handshake could not be recorded");
                }
                Ok(Response::new(v1::HelloResponse {
                    major,
                    majors: ours.clone(),
                    version: crate::version().to_owned(),
                    node_id: node.0,
                    heartbeat_secs: self.registry.config().heartbeat_secs,
                    server_time: Some(timestamp_to_proto(Timestamp::now())),
                    capabilities: Vec::new(),
                    endpoints: self.registry.cluster_endpoints().await,
                }))
            }
            Err(mismatch) => {
                let now = Timestamp::now();
                if let Err(error) = self
                    .registry
                    .hello_mismatch(node, &mismatch, &hello.version, now)
                    .await
                {
                    tracing::warn!(node = %node, %error, "the refused handshake could not be recorded");
                }
                let error = ClusterError::new(
                    "cluster.protocol.unsupported",
                    409,
                    mismatch.detail("the controller", "the node"),
                );
                let mut status = status_of(&error);
                if let Ok(value) = MetadataValue::try_from(version::format_majors(ours)) {
                    status.metadata_mut().insert(MAJORS_METADATA, value);
                }
                Err(status)
            }
        }
    }
}
