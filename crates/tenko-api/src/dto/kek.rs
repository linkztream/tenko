//! The key-encryption key shapes that `GET /system/status` shares with `GET /system/kek`
//! (IAM-15). The full status of the `kek` area and the conversions from the vault's types
//! live with its routes.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// How a key-encryption key is protected at rest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct KekProtectionView {
    /// A stable code: `dpapi_user`, `dpapi_machine`, `systemd_creds_host`,
    /// `systemd_creds_tpm2`, `plain_file` or `memory`. The UI localizes by this code.
    pub code: String,
    /// A short English description, for logs and support.
    pub text: String,
    /// Whether the protection is weak enough to warn about: a plain key file or memory only.
    pub weak: bool,
}

/// Where an online rotation of the key-encryption key stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum KekRotationPhase {
    /// Asked for; the leader creates the new generation next.
    Requested,
    /// The new generation exists; the controllers fetch it and acknowledge it.
    Distributing,
    /// The new generation is active; the leader re-wraps every envelope under it.
    Rewrapping,
    /// Finished.
    Done,
    /// Stopped; see `error`. Nothing changed for the envelopes.
    Failed,
}

/// The key-encryption key fragment of `GET /system/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct KekSummaryView {
    /// The provider of this controller: `dpapi`, `systemd_creds`, `systemd_credential` or
    /// `file`.
    pub provider: String,
    /// The protection of its active key-encryption key.
    pub protection: KekProtectionView,
    /// The active generation.
    pub active: String,
    /// How many generations this controller holds.
    pub generations: u64,
    /// The KEK epoch.
    pub epoch: u64,
    /// The phase of the online rotation in progress or the last one; absent when there never
    /// was one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<KekRotationPhase>,
}
