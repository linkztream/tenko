//! The `Node` service: the heartbeat stream of a connected node and certificate renewal.

use std::{pin::Pin, sync::Arc};

use futures::Stream;
use tenko_core::{NodeId, Timestamp};
use tokio::sync::mpsc;
use tonic::{Request, Response, Status, Streaming};

use crate::{
    model::ConnectionView,
    mtls::PeerInfo,
    probe::{timestamp_from_proto, timestamp_to_proto},
    proto::v1,
    registry::NodeRegistry,
    server::{ClusterService, peer_of, status_of},
    session::SessionGuard,
};

type DirectiveStream = Pin<Box<dyn Stream<Item = Result<v1::Directive, Status>> + Send>>;

/// The answer stream of a long-lived call of a node: the items of `inner`, while the node
/// still holds the certificate of its connection. Every
/// [`Timings::stream_recheck`](crate::registry::Timings::stream_recheck) the
/// record is checked again; when the check fails the stream ends with the refusal a new
/// call would get, and `inner`'s sender sees its receiver closed.
pub(super) fn rechecked<T: Send + 'static>(
    registry: Arc<NodeRegistry>,
    node: NodeId,
    serial: String,
    mut inner: mpsc::Receiver<Result<T, Status>>,
) -> Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>> {
    let (tx, mut rx) = mpsc::channel(1);
    tokio::spawn(async move {
        let every = registry.timings().stream_recheck;
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The check runs while the task waits for an item and while it waits for room to
        // hand one on, so a client that stops reading does not hold it off.
        let check = async |tx: &mpsc::Sender<Result<T, Status>>| -> bool {
            match registry.authenticate(node, &serial, Timestamp::now()).await {
                Ok(_) => true,
                Err(error) => {
                    tracing::info!(node = %node, code = %error.code(), "ended a stream of a node that no longer holds its certificate");
                    // Best effort: a client that reads gets the refusal, one that does not
                    // sees the stream end.
                    let _ = tx.try_send(Err(status_of(&error)));
                    false
                }
            }
        };
        loop {
            let item = tokio::select! {
                () = tx.closed() => return,
                item = inner.recv() => item,
                _ = tick.tick() => {
                    if check(&tx).await {
                        continue;
                    }
                    return;
                }
            };
            let Some(item) = item else { return };
            loop {
                tokio::select! {
                    permit = tx.reserve() => {
                        let Ok(permit) = permit else { return };
                        permit.send(item);
                        break;
                    }
                    _ = tick.tick() => {
                        if !check(&tx).await {
                            return;
                        }
                    }
                }
            }
        }
    });
    Box::pin(futures::stream::poll_fn(move |cx| rx.poll_recv(cx)))
}

#[tonic::async_trait]
impl v1::node_server::Node for ClusterService {
    type HeartbeatStream = DirectiveStream;

    async fn heartbeat(
        &self,
        request: Request<Streaming<v1::Beat>>,
    ) -> Result<Response<Self::HeartbeatStream>, Status> {
        let peer = peer_of(&request)?;
        let record = self.authenticate(&peer).await?;
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
            controller: Some(self.registry.config().local_node),
        };
        let guard = self
            .registry
            .sessions()
            .open(node, view.clone(), push.clone());
        if let Err(error) = self.registry.record_connection(node, &view).await {
            tracing::debug!(node = %node, %error, "the connection record could not be written");
        }
        if let Err(error) = self.registry.touch(node, now, true).await {
            tracing::warn!(node = %node, %error, "last_seen could not be written");
        }
        tracing::info!(node = %node, peer = ?peer.remote, "node connected");
        // A connection with the newest certificate proves the node holds it: the
        // certificates a renewal replaced retire.
        if record.certificate.serial == peer.identity.serial
            && self.registry.retirable(&record, now)
            && let Err(error) = self
                .registry
                .retire_replaced(node, record.certificate.not_after, now)
                .await
        {
            tracing::debug!(node = %node, %error, "the replaced certificates could not be retired");
        }
        let registry = Arc::clone(&self.registry);
        tokio::spawn(async move {
            follow_beats(&registry, &peer, &guard, &mut inbound, &push).await;
            drop(guard);
            if registry.sessions().view(node).is_none()
                && let Err(error) = registry.clear_connection(node).await
            {
                tracing::debug!(node = %node, %error, "the connection record could not be removed");
            }
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

/// Answers the beats of one heartbeat stream until it ends, the answer stream closes, or
/// the node no longer holds the certificate of its connection.
async fn follow_beats(
    registry: &NodeRegistry,
    peer: &PeerInfo,
    guard: &SessionGuard,
    inbound: &mut Streaming<v1::Beat>,
    push: &mpsc::Sender<Result<v1::Directive, Status>>,
) {
    let node = peer.identity.node;
    let renew_before = i64::from(registry.ca().policy().renew_before_days);
    let recheck = registry.timings().stream_recheck;
    let mut checked = std::time::Instant::now();
    // The newer certificate the node said it holds, once its proof was taken: it is
    // offered again at most once per check interval until it is.
    let mut proven: Option<Timestamp> = None;
    let mut offered: Option<std::time::Instant> = None;
    // When this stream last asked the node to renew: at most once per
    // [`RENEW_INTERVAL`](crate::registry::RENEW_INTERVAL), the pace the controller accepts.
    let mut asked: Option<std::time::Instant> = None;
    loop {
        let beat = match inbound.message().await {
            Ok(Some(beat)) => beat,
            Ok(None) => return,
            Err(status) => {
                tracing::debug!(node = %node, %status, "heartbeat stream ended");
                return;
            }
        };
        let now = Timestamp::now();
        // The stream answers only beats, so checking the record on a beat is enough:
        // without beats it carries nothing.
        if checked.elapsed() >= recheck {
            checked = std::time::Instant::now();
            if let Err(error) = registry
                .authenticate(node, &peer.identity.serial, now)
                .await
            {
                tracing::info!(node = %node, code = %error.code(), "ended the heartbeat stream of a node that no longer holds its certificate");
                let _ = push.send(Err(status_of(&error))).await;
                return;
            }
        }
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
        // The node renewed over this connection and says it holds the new certificate:
        // the replaced ones retire.
        if let Some(held) = not_after
            && held > peer.identity.not_after
            && proven != Some(held)
            && offered.is_none_or(|at| at.elapsed() >= recheck)
        {
            offered = Some(std::time::Instant::now());
            match registry.retire_replaced(node, held, now).await {
                Ok(true) => proven = Some(held),
                Ok(false) => {}
                Err(error) => {
                    tracing::debug!(node = %node, %error, "the replaced certificates could not be retired");
                }
            }
        }
        let expires = not_after.unwrap_or(peer.identity.not_after);
        let due = (expires.0 - now.0).whole_days() < renew_before;
        let renew = due && asked.is_none_or(|at| at.elapsed() >= crate::registry::RENEW_INTERVAL);
        if renew {
            asked = Some(std::time::Instant::now());
        }
        let directive = v1::Directive {
            sequence: beat.sequence,
            server_time: Some(timestamp_to_proto(now)),
            renew,
            revoked: false,
            detail: String::new(),
        };
        if push.send(Ok(directive)).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tenko_core::{RequestCtx, SystemComponent};
    use tenko_store::Store;

    use super::*;
    use crate::{
        ca::{CaPolicy, InternalCa},
        registry::{RegistryConfig, Timings},
    };

    /// A client that stops reading does not keep the check from running: the stream ends,
    /// and its producer sees the end, once the node no longer holds its certificate.
    #[tokio::test]
    async fn a_stream_nobody_reads_still_ends_when_the_check_fails() {
        let store = Arc::new(tenko_store::mem::MemStore::default());
        let vault = tenko_vault::MemVault::with_store(store.clone());
        let ca = InternalCa::load_or_init(
            &*store,
            &vault,
            &RequestCtx::system(SystemComponent::Cluster),
            CaPolicy::default(),
        )
        .await
        .expect("CA");
        let registry = NodeRegistry::new(
            store as Arc<dyn Store>,
            Arc::new(ca),
            RegistryConfig::new(NodeId(1)),
        );
        registry.set_timings(Timings {
            stream_recheck: Duration::from_millis(50),
            ..Timings::default()
        });
        let (producer, inner) = mpsc::channel::<Result<u32, Status>>(8);
        for n in 0..4 {
            producer.send(Ok(n)).await.expect("item");
        }
        // No node 4242 is enrolled; the stream is never read.
        let _unread = rechecked(registry, NodeId(4242), "00".to_owned(), inner);
        tokio::time::timeout(Duration::from_secs(5), producer.closed())
            .await
            .expect("the stream ended although nobody read it");
    }
}
