//! The connector plugin SDK of Tenko DDI (ADR 0006, ADR 0012, CONN-01, CONN-19, CONN-20).
//!
//! Connectors are plugins: separate processes started and supervised by Tenko, speaking a
//! versioned gRPC protocol (`tenko.connect.v1`) over a local Unix socket or Windows named
//! pipe. This crate holds both sides of that contract:
//!
//! | Module | Contents |
//! |---|---|
//! | [`proto`] | the compiled protocol code (`proto/tenko/connect/v1/*.proto`) |
//! | [`manifest`] | `plugin.json`: the manifest, its validation and the settings schema |
//! | [`handshake`] | the stdio handshake: protocol version, endpoint, per-launch token, manifest |
//! | [`transport`] | local endpoints: Unix sockets in a private directory, named pipes |
//! | [`sdk`] | the helper library for plugin authors: implement the traits, call [`sdk::Plugin::run`] |
//! | [`host`] | the host: launch, handshake, supervision, typed calls, the connector service |
//! | [`conformance`] | the conformance suite behind `tenko plugin test` |
//! | [`sample`] | the sample inventory plugin (documentation data) used by the suite and the tests |
//!
//! The four interfaces of ADR 0006 are the traits a plugin implements:
//!
//! | Trait | gRPC service | Capability |
//! |---|---|---|
//! | [`InventorySource`] | `Inventory` | `inventory`, `webhook` |
//! | [`NetworkController`] | `NetworkController` | `network_controller` |
//! | [`Actuator`] | `Actuator` | `actuator` |
//! | [`MigrationSource`] | `Migration` | `migration` |
//!
//! Every plugin also answers [`Connector::check`] (`Plugin.Check`). Every call receives a
//! [`CallContext`]: the settings of the instance and the secrets the manifest declares,
//! injected by the host for that call only. Policy stays in the host: verify-before-write,
//! [`Guardrails`], rate limits, parallelism and observation normalization.

mod actuator;
pub mod conformance;
pub mod context;
pub mod convert;
mod error;
pub mod handshake;
pub mod host;
mod inventory;
pub mod manifest;
mod migration;
mod network;
pub mod proto;
pub mod sample;
pub mod sdk;
pub mod status;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod transport;

pub use actuator::{Actuator, ActuatorIntent, ActuatorPlan, ActuatorReceipt, DiffLine, WriteMode};
pub use context::{CallContext, Secrets};
pub use error::ConnectorError;
pub use inventory::{Cursor, InventoryBatch, InventorySource, VendorFact, WebhookRequest};
pub use manifest::{Capability, Manifest};
pub use migration::{MigrationArea, MigrationScope, MigrationSource};
pub use network::{
    ClientAttachment, ControllerDhcp, ControllerNetwork, DeviceKind, DevicePort, DeviceRef,
    Guardrails, L2Change, L2Plan, L2Receipt, NetworkController, NetworkDevice, NetworkRef,
    PortProfile, ProfileRef, ProtectedPath, TopologyLink, TopologySnapshot, WirelessNetwork,
};
pub use tenko_core::secret::SecretRef;

use serde::{Deserialize, Serialize};
use tenko_core::Timestamp;
use utoipa::ToSchema;

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-connect";

/// Returns the version of this crate as declared in its manifest.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The protocol major version of this build (`tenko.connect.v1`).
pub const PROTOCOL_VERSION: u32 = 1;

/// The protocol major versions this build speaks, as a host and as a plugin.
pub const SUPPORTED_PROTOCOLS: &[u32] = &[PROTOCOL_VERSION];

/// Remote health: every plugin answers it (`Plugin.Check`).
#[async_trait::async_trait]
pub trait Connector: Send + Sync + 'static {
    /// Checks reachability and credentials of the remote system without changing anything.
    ///
    /// # Errors
    ///
    /// Returns a [`ConnectorError`] when the check itself cannot run; an unhealthy but
    /// reachable system is a [`HealthReport`] with [`Health::Degraded`].
    async fn check(&self, ctx: &CallContext) -> Result<HealthReport, ConnectorError>;
}

/// Result of [`Connector::check`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
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

impl HealthReport {
    /// A healthy report checked now.
    pub fn healthy() -> Self {
        Self {
            health: Health::Healthy,
            checked_at: Timestamp::now(),
            latency_ms: None,
            remote_version: None,
            detail: None,
        }
    }
}

/// Health of a remote system.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
#[schema(as = RemoteHealth)]
pub enum Health {
    /// Reachable, authenticated, working.
    Healthy,
    /// Reachable with problems (missing permissions, unsupported version, rate limits).
    Degraded,
    /// Not reachable.
    Unreachable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_matches_manifest() {
        assert_eq!(CRATE_NAME, env!("CARGO_PKG_NAME"));
        assert!(version().starts_with(|c: char| c.is_ascii_digit()));
        assert!(SUPPORTED_PROTOCOLS.contains(&PROTOCOL_VERSION));
    }

    #[test]
    fn health_reports_round_trip() {
        let report = HealthReport {
            remote_version: Some("9.4.19".to_owned()),
            ..HealthReport::healthy()
        };
        let json = serde_json::to_string(&report).expect("json");
        assert_eq!(
            serde_json::from_str::<HealthReport>(&json).expect("json"),
            report
        );
        assert!(json.contains("\"healthy\""));
    }
}
