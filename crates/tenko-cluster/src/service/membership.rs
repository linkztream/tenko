//! The `Cluster` service: joining, write forwarding, read index, member list, state digest,
//! key transfer, the hand-over of leadership and forwarded membership changes between
//! controllers (WP3.1a). The work is done by [`crate::peers::Peers`]; this file maps the
//! calls and their refusals.

use tenko_core::{NodeId, RequestCtx, Revision, Role};
use tenko_store::raft::network::ForwardError;
use tonic::{Request, Response, Status};

use crate::{
    error::ClusterError,
    peers::{Access, PeerService},
    proto::v1,
    server::{peer_of, status_of},
    wire::{self, BATCH_WIRE, CLUSTER_WIRE, ChangeEnvelope},
};

fn no_answer(error: &ForwardError) -> Status {
    status_of(&ClusterError::new(
        "cluster.forward.no_answer",
        504,
        error.to_string(),
    ))
}

#[tonic::async_trait]
impl v1::cluster_server::Cluster for PeerService {
    async fn join(
        &self,
        request: Request<v1::JoinRequest>,
    ) -> Result<Response<v1::JoinResponse>, Status> {
        let peer = peer_of(&request)?;
        let body = request.into_inner();
        // The joiner itself, or a member that forwards the joiner's request.
        if peer.identity.node.0 != body.node_id {
            self.peers.authenticate(&peer, Access::Member).await?;
        } else if !peer.identity.roles.contains(Role::Controller) {
            return Err(status_of(&ClusterError::new(
                "cluster.peer.not_controller",
                403,
                "only a controller certificate may join the controller cluster",
            )));
        }
        let answer = self
            .peers
            .join(body, peer.local)
            .await
            .map_err(|error| status_of(&error))?;
        Ok(Response::new(answer))
    }

    async fn propose(
        &self,
        request: Request<v1::ProposeRequest>,
    ) -> Result<Response<v1::ProposeResponse>, Status> {
        let peer = peer_of(&request)?;
        self.peers.authenticate(&peer, Access::Member).await?;
        let body = request.into_inner();
        wire::check(&body.wire, BATCH_WIRE).map_err(|error| status_of(&error))?;
        match self.peers.store().accept_forwarded(body.batch.into()).await {
            Ok(committed) => Ok(Response::new(v1::ProposeResponse {
                wire: BATCH_WIRE.to_owned(),
                committed: wire::encode(&committed).map_err(|error| status_of(&error))?,
            })),
            Err(ForwardError::NotLeader { leader }) => {
                Err(wire::not_leader_status(leader.map(NodeId)))
            }
            Err(ForwardError::Store(error)) => Err(wire::store_status(&error)),
            Err(other) => Err(no_answer(&other)),
        }
    }

    async fn read_index(
        &self,
        request: Request<v1::ReadIndexRequest>,
    ) -> Result<Response<v1::ReadIndexResponse>, Status> {
        let peer = peer_of(&request)?;
        self.peers.authenticate(&peer, Access::Member).await?;
        match self.peers.store().read_index().await {
            Ok(index) => Ok(Response::new(v1::ReadIndexResponse {
                log_index: index.log_index,
                term: index.term,
                leader_id: index.leader,
            })),
            Err(ForwardError::NotLeader { leader }) => {
                Err(wire::not_leader_status(leader.map(NodeId)))
            }
            Err(ForwardError::Store(error)) => Err(wire::store_status(&error)),
            Err(other) => Err(no_answer(&other)),
        }
    }

    async fn members(
        &self,
        request: Request<v1::MembersRequest>,
    ) -> Result<Response<v1::MembersResponse>, Status> {
        let peer = peer_of(&request)?;
        self.peers.authenticate(&peer, Access::Member).await?;
        let answer = self
            .peers
            .members_proto()
            .await
            .map_err(|error| status_of(&error))?;
        Ok(Response::new(answer))
    }

    async fn digest(
        &self,
        request: Request<v1::DigestRequest>,
    ) -> Result<Response<v1::DigestResponse>, Status> {
        let peer = peer_of(&request)?;
        self.peers.authenticate(&peer, Access::Member).await?;
        let revision = request.into_inner().revision;
        let at_least = (revision > 0).then_some(Revision(revision));
        let digest = self
            .peers
            .store()
            .digest(at_least)
            .await
            .map_err(|error| wire::store_status(&error))?;
        Ok(Response::new(v1::DigestResponse {
            revision: digest.revision.0,
            sha256: digest.sha256.to_vec(),
            tables: digest.tables,
            entries: digest.entries,
        }))
    }

    async fn transfer_kek(
        &self,
        request: Request<v1::TransferKekRequest>,
    ) -> Result<Response<v1::TransferKekResponse>, Status> {
        let peer = peer_of(&request)?;
        let record = self
            .peers
            .authenticate(&peer, Access::Member)
            .await?
            .ok_or_else(|| {
                status_of(&ClusterError::new(
                    "cluster.node.unknown",
                    403,
                    "the caller is not enrolled",
                ))
            })?;
        let answer = self
            .peers
            .transfer_kek(&record, request.into_inner())
            .await
            .map_err(|error| status_of(&error))?;
        Ok(Response::new(answer))
    }

    async fn campaign(
        &self,
        request: Request<v1::CampaignRequest>,
    ) -> Result<Response<v1::CampaignResponse>, Status> {
        let peer = peer_of(&request)?;
        self.peers.authenticate(&peer, Access::Member).await?;
        let answer = self
            .peers
            .campaign(peer.identity.node)
            .await
            .map_err(|error| status_of(&error))?;
        Ok(Response::new(answer))
    }

    async fn change(
        &self,
        request: Request<v1::ChangeRequest>,
    ) -> Result<Response<v1::ChangeResponse>, Status> {
        let peer = peer_of(&request)?;
        self.peers.authenticate(&peer, Access::Member).await?;
        let body = request.into_inner();
        wire::check(&body.wire, CLUSTER_WIRE).map_err(|error| status_of(&error))?;
        let envelope: ChangeEnvelope =
            wire::decode("membership change", &body.change).map_err(|error| status_of(&error))?;
        let cx = RequestCtx::from(envelope.ctx);
        let result = self
            .peers
            .apply_change(&cx, envelope.change)
            .await
            .map_err(|error| status_of(&error))?;
        Ok(Response::new(v1::ChangeResponse {
            wire: CLUSTER_WIRE.to_owned(),
            result: wire::encode(&result).map_err(|error| status_of(&error))?,
        }))
    }
}
