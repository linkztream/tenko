//! The key encryption keys of the installation on their way to another controller (S3-Q5,
//! R22): `Cluster.TransferKek`.
//!
//! A joining controller generates a one-time X25519 key pair and sends its public key with
//! the id of the enrolment token it joined with; a member seals every KEK generation it
//! holds to that key inside the mutual TLS channel ([`KekSource`]) and answers with the
//! sealed bundle ([`SealedKeks`]); the joiner opens it and seals the generations again
//! with its own KEK provider ([`TransferSink`]). A member that lacks generations (it was
//! stopped during an online rotation) fetches them the same way with an empty token id
//! ([`PeerKekFetch`], `tenko_vault::distribution::fetch_missing`). The sealing (X25519,
//! HKDF-SHA-256, AES-256-GCM) is the vault's ([`tenko_vault::transfer`]); this module holds
//! the traits the cluster calls and their implementations over the vault.
//!
//! A join transfer is single use per enrolment token (`cluster.kek_transfers`); every
//! transfer is audited as `vault.kek.transfer` with the generation ids, never the material.

use std::sync::Arc;

use tenko_core::NodeId;
use tenko_vault::{
    KekConfig, StoreVault, VaultError,
    distribution::KekPeers,
    transfer::{self, TransferKey},
};
use uuid::Uuid;

use crate::{error::ClusterError, peers::Peers, proto::v1};

/// What a member answers a joiner with: the sealed generations and their ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedKeks {
    /// The sealing format (`TransferKekResponse.format`).
    pub format: String,
    /// The sealed generations.
    pub sealed: Vec<u8>,
    /// The ids of the generations, oldest first, the active one last.
    pub generation_ids: Vec<String>,
}

/// The sending side: seals this controller's KEK generations for another controller.
pub trait KekSource: Send + Sync + 'static {
    /// Seals every generation to `recipient` (the caller's one-time public key), binding
    /// `context` ([`join_context`] or [`fetch_context`]).
    ///
    /// # Errors
    ///
    /// A `vault.kek.transfer.*` error.
    fn seal_for(&self, recipient: &[u8], context: &[u8]) -> Result<SealedKeks, ClusterError>;
}

/// The bytes both sides bind into a join transfer: a label, the joiner's node id and the
/// id of the enrolment token it joined with.
pub fn join_context(node: NodeId, token: Uuid) -> Vec<u8> {
    transfer::join_context(node, *token.as_bytes())
}

/// The bytes both sides bind into a fetch by a member.
pub fn fetch_context(node: NodeId) -> Vec<u8> {
    transfer::fetch_context(node)
}

/// `vault.kek.transfer.unavailable` (503): this controller cannot hand over keys (its
/// vault is not open yet).
pub fn unavailable() -> ClusterError {
    ClusterError::new(
        "vault.kek.transfer.unavailable",
        503,
        "this controller cannot hand over key encryption keys right now; try again when it \
         has started",
    )
}

/// The KEK generations of this controller's vault.
#[derive(Debug, Clone)]
pub struct VaultKekSource {
    vault: Arc<StoreVault>,
}

impl VaultKekSource {
    /// The generations `vault` holds.
    pub fn new(vault: Arc<StoreVault>) -> Self {
        Self { vault }
    }
}

impl KekSource for VaultKekSource {
    fn seal_for(&self, recipient: &[u8], context: &[u8]) -> Result<SealedKeks, ClusterError> {
        let sealed = transfer::seal_ring(&self.vault.ring(), recipient, context)?;
        Ok(SealedKeks {
            format: sealed.format.to_owned(),
            sealed: sealed.sealed,
            generation_ids: sealed.generation_ids,
        })
    }
}

/// The receiving side of a join: a one-time key pair, opened once into this host's KEK
/// provider.
pub struct TransferSink {
    key: TransferKey,
}

impl std::fmt::Debug for TransferSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferSink").finish_non_exhaustive()
    }
}

impl TransferSink {
    /// A new one-time key pair.
    ///
    /// # Errors
    ///
    /// The vault's error.
    pub fn generate() -> Result<Self, ClusterError> {
        Ok(Self {
            key: TransferKey::generate()?,
        })
    }

    /// The public key to send.
    pub fn public_key(&self) -> [u8; transfer::PUBLIC_KEY_LEN] {
        self.key.public_key()
    }

    /// Opens the answer and seals the generations with `config`'s provider; returns the
    /// generation ids.
    ///
    /// # Errors
    ///
    /// A `vault.kek.transfer.*` error, or the provider's.
    pub fn import(
        self,
        answer: &v1::TransferKekResponse,
        context: &[u8],
        config: &KekConfig,
    ) -> Result<Vec<String>, ClusterError> {
        let generations = self.key.open(&answer.format, &answer.sealed, context)?;
        let ring = config.import(&generations)?;
        Ok(ring.ids().map(str::to_owned).collect())
    }
}

/// Fetches the generations a member lacks from the other members over the cluster port
/// (the leader first): the vault's [`KekPeers`] over [`Peers`].
#[derive(Debug, Clone)]
pub struct PeerKekFetch {
    peers: Peers,
}

impl PeerKekFetch {
    /// Fetches through `peers`.
    pub fn new(peers: Peers) -> Self {
        Self { peers }
    }
}

#[async_trait::async_trait]
impl KekPeers for PeerKekFetch {
    async fn fetch(
        &self,
        recipient: [u8; transfer::PUBLIC_KEY_LEN],
    ) -> Result<transfer::SealedKeks, VaultError> {
        let mut last = String::from("no other member is known");
        for node in self.peers.others_leader_first() {
            let answer = async {
                let mut client = self.peers.network().cluster_client(node).await?;
                client
                    .transfer_kek(v1::TransferKekRequest {
                        ephemeral_public_key: recipient.to_vec(),
                        join_token_id: String::new(),
                    })
                    .await
                    .map(tonic::Response::into_inner)
                    .map_err(|status| {
                        ClusterError::new("cluster.peer.call", 503, status.message().to_owned())
                    })
            }
            .await;
            match answer {
                Ok(answer) if answer.format == transfer::FORMAT => {
                    return Ok(transfer::SealedKeks {
                        format: transfer::FORMAT,
                        sealed: answer.sealed,
                        generation_ids: answer.generation_ids,
                    });
                }
                Ok(answer) => {
                    last = format!("controller {node} answered the format {}", answer.format);
                }
                Err(error) => last = format!("controller {node}: {}", error.detail()),
            }
        }
        Err(VaultError::KekUnavailable {
            reason: format!("no cluster member handed over the key generations ({last})"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contexts_are_the_vaults() {
        let token = Uuid::from_u128(7);
        let context = join_context(NodeId(1001), token);
        assert!(context.starts_with(b"tenko-kek-transfer/1\0"));
        assert_eq!(context.len(), 21 + 8 + 16);
        assert_ne!(context, join_context(NodeId(1002), token));
        assert_ne!(fetch_context(NodeId(1001)), context);
        assert_eq!(unavailable().status(), 503);
    }
}
