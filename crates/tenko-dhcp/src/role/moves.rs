//! The role as a move job reaches it (WP8.1, `tenko_ipam::moves::dhcp`): the revision of
//! the configuration image it serves, from the report `dhcp.status`, and the release of a
//! lease through the node command `dhcp.lease.release`, as the lease routes run it.

use std::{net::Ipv4Addr, sync::Arc};

use tenko_core::{CodedError, Revision, VrfId, codec::to_cbor, dhcp::codes};
use tenko_ipam::moves::dhcp::{DhcpRolePort, Released};

use super::{
    DhcpNode, Outcome,
    commands::{LEASE_RELEASE, ReleaseArgs},
};

/// The move port over a node's `dhcp` role.
pub struct MovePort {
    node: Arc<dyn DhcpNode>,
}

impl std::fmt::Debug for MovePort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MovePort")
            .field("node", &self.node.node())
            .finish()
    }
}

impl MovePort {
    /// The port over `node`.
    pub fn new(node: Arc<dyn DhcpNode>) -> Arc<Self> {
        Arc::new(Self { node })
    }
}

#[async_trait::async_trait]
impl DhcpRolePort for MovePort {
    fn image_revision(&self) -> Revision {
        self.node.status().revision
    }

    async fn release(
        &self,
        vrf: VrfId,
        addr: Ipv4Addr,
        reason: &str,
    ) -> Result<Released, CodedError> {
        let args = ReleaseArgs {
            vrf: Some(vrf),
            addr,
            reason: Some(reason.to_owned()),
        };
        let args = to_cbor(&args).map_err(|error| {
            CodedError::new(
                "sys.internal",
                500,
                format!("the release arguments: {error}"),
            )
        })?;
        let result = self.node.execute(LEASE_RELEASE, &args).await;
        match (result.outcome, result.code) {
            (Outcome::Done, _) => Ok(Released::Released),
            // Gone, not bound any more, or renewed meanwhile: nothing to release now.
            (Outcome::Rejected, Some(codes::LEASE_NOT_FOUND | codes::LEASE_STATE)) => {
                Ok(Released::Nothing)
            }
            (_, code) => Err(CodedError::new(
                code.unwrap_or("sys.internal"),
                503,
                result.detail,
            )),
        }
    }
}
