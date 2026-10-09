//! The connector framework (ADR 0006, CONN-01): the traits every integration implements
//! and the types they exchange.
//!
//! | Trait | Purpose | First drivers |
//! |---|---|---|
//! | [`InventorySource`] | Observed hosts, polled and by webhook (CONN-02) | Proxmox, Home Assistant (Slice 2) |
//! | [`NetworkController`] | Topology reads and guarded L2 writes (CONN-05 to CONN-09) | UniFi (Slice 2) |
//! | [`Actuator`] | Intent applied to systems Tenko does not own (ADR 0005) | Phase 2 onwards |
//! | [`MigrationSource`] | IR plus loss report (MIG-01) | Phase 4 |
//!
//! Every driver is a [`Connector`]: it describes itself and reports health. Drivers live in
//! `tenko-connect-*` crates and may implement several traits. Credentials are vault
//! [`SecretRef`]s, resolved at call time through a [`SecretResolver`]; a driver never
//! stores a secret value.
//!
//! Network-controller writes follow one discipline (CONN-08, CONN-09): `plan` reads the
//! controller back, diffs and checks [`Guardrails`] (uplinks are always protected and the
//! management path is derived from the topology inside `plan`); `apply` re-reads, rejects a
//! stale plan, writes only in [`WriteMode::Apply`] and verifies; `revert` undoes a receipt.
//! Guardrails therefore cannot be bypassed by calling `apply` directly.
//!
//! # Ownership
//!
//! WP1.0 (the lead builder) owns this crate: it is a contract. Other packages never edit
//! it; contract changes go through the lead as a small pull request reviewed by every
//! package that uses the item (plan rule 2.8). The connector scheduler (WP2.5) is added
//! later by the lead on request.

mod actuator;
mod error;
mod inventory;
mod migration;
mod network;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use actuator::{Actuator, ActuatorIntent, ActuatorPlan, ActuatorReceipt, DiffLine, WriteMode};
pub use error::ConnectorError;
pub use inventory::{Cursor, InventoryBatch, InventorySource, WebhookHandler, WebhookRequest};
pub use migration::{MigrationArea, MigrationScope, MigrationSource};
pub use network::{
    ClientAttachment, ControllerDhcp, ControllerNetwork, DeviceKind, DevicePort, DeviceRef,
    Guardrails, L2Change, L2Plan, L2Receipt, NetworkController, NetworkDevice, NetworkRef,
    PortProfile, ProfileRef, ProtectedPath, TopologyLink, TopologySnapshot,
};
pub use tenko_core::secret::SecretRef;

use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use tenko_core::Timestamp;
use zeroize::Zeroizing;

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-connect";

/// Returns the version of this crate as declared in its manifest.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Every driver: identity and health.
#[async_trait::async_trait]
pub trait Connector: Send + Sync + 'static {
    /// What the driver is and can do.
    fn info(&self) -> DriverInfo;

    /// Checks reachability and credentials without changing anything.
    ///
    /// # Errors
    ///
    /// Returns a [`ConnectorError`] when the check itself cannot run; an unhealthy but
    /// reachable system is a [`HealthReport`] with [`Health::Degraded`].
    async fn check(&self) -> Result<HealthReport, ConnectorError>;
}

/// Description of a driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverInfo {
    /// Stable driver name, such as `proxmox` or `unifi`.
    pub driver: Cow<'static, str>,
    /// Driver version.
    pub version: Cow<'static, str>,
    /// The traits the driver implements.
    pub capabilities: Vec<Capability>,
}

/// A connector trait a driver implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// [`InventorySource`].
    Inventory,
    /// [`InventorySource::webhook`] returns a handler.
    Webhook,
    /// [`NetworkController`].
    NetworkController,
    /// [`Actuator`].
    Actuator,
    /// [`MigrationSource`].
    Migration,
}

/// Result of [`Connector::check`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthReport {
    /// Overall health.
    pub health: Health,
    /// When the check ran.
    pub checked_at: Timestamp,
    /// Round-trip time of the check in milliseconds.
    #[serde(default)]
    pub latency_ms: Option<u64>,
    /// Version the remote system reports.
    #[serde(default)]
    pub remote_version: Option<String>,
    /// English detail for the operator.
    #[serde(default)]
    pub detail: Option<String>,
}

/// Health of a connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    /// Reachable, authenticated, working.
    Healthy,
    /// Reachable with problems (missing permissions, unsupported version, rate limits).
    Degraded,
    /// Not reachable.
    Unreachable,
}

/// Resolves vault secret references at call time (implemented by the vault, IAM-16).
///
/// The returned bytes are wiped when dropped; callers keep them no longer than one call.
#[async_trait::async_trait]
pub trait SecretResolver: Send + Sync + 'static {
    /// Returns the secret's value.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::Unauthorized`] if the secret is missing or the caller may
    /// not use it.
    async fn resolve(&self, secret: &SecretRef) -> Result<Zeroizing<Vec<u8>>, ConnectorError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_matches_manifest() {
        assert_eq!(CRATE_NAME, env!("CARGO_PKG_NAME"));
        assert!(version().starts_with(|c: char| c.is_ascii_digit()));
    }

    #[test]
    fn driver_info_round_trips() {
        let info = DriverInfo {
            driver: Cow::Borrowed("proxmox"),
            version: Cow::Borrowed("0.0.1"),
            capabilities: vec![Capability::Inventory, Capability::Webhook],
        };
        let json = serde_json::to_string(&info).expect("json");
        assert_eq!(
            serde_json::from_str::<DriverInfo>(&json).expect("json"),
            info
        );
    }
}
