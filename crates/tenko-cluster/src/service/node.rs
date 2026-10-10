//! The `Node` service: the heartbeat stream of a connected node and certificate renewal.

use std::{pin::Pin, sync::Arc};

use futures::Stream;
use tenko_core::Timestamp;
use tokio::sync::mpsc;
use tonic::{Request, Response, Status, Streaming};

use crate::{
    model::ConnectionView,
    probe::{timestamp_from_proto, timestamp_to_proto},
    proto::v1,
    server::{ClusterService, peer_of, status_of},
};

type DirectiveStream = Pin<Box<dyn Stream<Item = Result<v1::Directive, Status>> + Send>>;

#[tonic::async_trait]
impl v1::node_server::Node for ClusterService {
    type HeartbeatStream = DirectiveStream;

    async fn heartbeat(
        &self,
        request: Request<Streaming<v1::Beat>>,
    ) -> Result<Response<Self::HeartbeatStream>, Status> {
        let peer = peer_of(&request)?;
        self.authenticate(&peer).await?;
        let node = peer.identity.node;
        let mut inbound = request.into_inner();
        let (push, mut directives) = mpsc::channel(16);
        let now = Timestamp::now();
        let view = ConnectionView {
            since: now,
            peer: peer.remote,
            major: 0,
            version: String::new(),
            last_beat: None,
            buffered_batches: 0,
            buffered_bytes: 0,
            dropped_batches: 0,
            certificate_not_after: Some(peer.identity.not_after),
        };
        let guard = self.registry.sessions().open(node, view, push.clone());
        if let Err(error) = self.registry.touch(node, now, true).await {
            tracing::warn!(node = %node, %error, "last_seen could not be written");
        }
        tracing::info!(node = %node, peer = ?peer.remote, "node connected");
        let registry = Arc::clone(&self.registry);
        let renew_before = i64::from(registry.ca().policy().renew_before_days);
        tokio::spawn(async move {
            loop {
                let beat = match inbound.message().await {
                    Ok(Some(beat)) => beat,
                    Ok(None) => break,
                    Err(status) => {
                        tracing::debug!(node = %node, %status, "heartbeat stream ended");
                        break;
                    }
                };
                let now = Timestamp::now();
                let not_after = beat
                    .certificate_not_after
                    .as_ref()
                    .and_then(timestamp_from_proto);
                guard.update(|view| {
                    view.major = beat.major;
                    view.version.clone_from(&beat.version);
                    view.last_beat = Some(now);
                    view.buffered_batches = beat.buffered_batches;
                    view.buffered_bytes = beat.buffered_bytes;
                    view.dropped_batches = beat.dropped_batches;
                    if not_after.is_some() {
                        view.certificate_not_after = not_after;
                    }
                });
                if let Err(error) = registry.touch(node, now, false).await {
                    tracing::debug!(node = %node, %error, "last_seen could not be written");
                }
                let expires = not_after.unwrap_or(peer.identity.not_after);
                let renew = (expires.0 - now.0).whole_days() < renew_before;
                let directive = v1::Directive {
                    sequence: beat.sequence,
                    server_time: Some(timestamp_to_proto(now)),
                    renew,
                    revoked: false,
                    detail: String::new(),
                };
                if push.send(Ok(directive)).await.is_err() {
                    break;
                }
            }
            drop(guard);
            if let Err(error) = registry.touch(node, Timestamp::now(), true).await {
                tracing::debug!(node = %node, %error, "last_seen could not be written");
            }
            tracing::info!(node = %node, "node disconnected");
        });
        let stream: DirectiveStream =
            Box::pin(futures::stream::poll_fn(move |cx| directives.poll_recv(cx)));
        Ok(Response::new(stream))
    }

    async fn renew(
        &self,
        request: Request<v1::RenewRequest>,
    ) -> Result<Response<v1::RenewResponse>, Status> {
        let peer = peer_of(&request)?;
        self.authenticate(&peer).await?;
        let csr = request.into_inner().csr;
        let issued = self
            .registry
            .renew(
                peer.identity.node,
                &peer.identity.serial,
                &csr,
                Timestamp::now(),
            )
            .await
            .map_err(|error| status_of(&error))?;
        Ok(Response::new(v1::RenewResponse {
            certificate_pem: issued.chain_pem(),
            not_after: Some(timestamp_to_proto(issued.info.not_after)),
        }))
    }
}
