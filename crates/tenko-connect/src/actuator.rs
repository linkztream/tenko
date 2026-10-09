//! Actuators: intent applied to systems Tenko does not own (ADR 0005). Plugins arrive from
//! Phase 2; the write discipline matches [`NetworkController`](crate::NetworkController):
//! plan, preview, apply with the plan, verify.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use tenko_core::{HostId, MacAddr, Timestamp, VrfId, net::Duid, net::Fqdn};

use crate::{CallContext, ConnectorError};

/// Dry run or real write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteMode {
    /// Read back and diff only.
    DryRun,
    /// Write and verify.
    Apply,
}

/// One line of a read-back diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffLine {
    /// What changes, for example `networks/iot/vlan`.
    pub path: String,
    /// Current value.
    #[serde(default)]
    pub before: Option<String>,
    /// Planned value.
    #[serde(default)]
    pub after: Option<String>,
}

/// Applies intent to an external system as job steps (capability `actuator`).
#[async_trait::async_trait]
pub trait Actuator: Send + Sync + 'static {
    /// Reads back, diffs and validates. Writes nothing.
    ///
    /// # Errors
    ///
    /// Returns a [`ConnectorError`].
    async fn plan(
        &self,
        ctx: &CallContext,
        intent: &ActuatorIntent,
    ) -> Result<ActuatorPlan, ConnectorError>;

    /// Re-reads, rejects a stale plan, writes (only in [`WriteMode::Apply`]) and verifies.
    ///
    /// # Errors
    ///
    /// Returns a [`ConnectorError`].
    async fn apply(
        &self,
        ctx: &CallContext,
        plan: &ActuatorPlan,
        mode: WriteMode,
    ) -> Result<ActuatorReceipt, ConnectorError>;

    /// Undoes an applied change.
    ///
    /// # Errors
    ///
    /// Returns a [`ConnectorError`].
    async fn revert(
        &self,
        ctx: &CallContext,
        receipt: &ActuatorReceipt,
    ) -> Result<(), ConnectorError>;
}

/// Intent an actuator applies.
///
/// Adjacently tagged because variants carry IP addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ActuatorIntent {
    /// Create or move a DHCP reservation (MAC or client id for v4, DUID for v6).
    DhcpReservation {
        /// The VRF.
        vrf: VrfId,
        /// The reserved address.
        ip: IpAddr,
        /// DHCPv4 key.
        #[serde(default)]
        mac: Option<MacAddr>,
        /// DHCPv6 key.
        #[serde(default)]
        duid: Option<Duid>,
        /// The host the reservation belongs to.
        host: HostId,
    },
    /// Remove a DHCP reservation.
    DhcpReservationRemove {
        /// The VRF.
        vrf: VrfId,
        /// The reserved address.
        ip: IpAddr,
    },
    /// Make A or AAAA (and optionally PTR) records match.
    DnsRecords {
        /// The name.
        name: Fqdn,
        /// The addresses.
        addresses: Vec<IpAddr>,
        /// Whether to maintain PTR records.
        ptr: bool,
    },
    /// Remove the records of a name.
    DnsRecordsRemove {
        /// The name.
        name: Fqdn,
    },
    /// Set a guest's address on a hypervisor (Phase 5).
    GuestAddress {
        /// The host.
        host: HostId,
        /// The address.
        ip: IpAddr,
    },
}

/// The plan of one actuation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActuatorPlan {
    /// The intent.
    pub intent: ActuatorIntent,
    /// When the state was read.
    pub read_at: Timestamp,
    /// Fingerprint of the state the plan was made against.
    pub fingerprint: String,
    /// What would change.
    pub diff: Vec<DiffLine>,
}

/// What an actuation did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActuatorReceipt {
    /// The plan that was applied.
    pub plan: ActuatorPlan,
    /// Dry run or real write.
    pub mode: WriteMode,
    /// When the write happened.
    pub applied_at: Timestamp,
    /// Whether the read-back matched.
    pub verified: bool,
}

#[cfg(test)]
mod tests {
    use tenko_core::codec::{from_cbor, to_cbor};

    use super::*;

    #[test]
    fn intents_round_trip_through_cbor() {
        let intent = ActuatorIntent::DnsRecords {
            name: Fqdn::new("printer.example.test").expect("name"),
            addresses: vec![
                "192.0.2.9".parse().expect("ip"),
                "2001:db8::9".parse().expect("ip"),
            ],
            ptr: true,
        };
        assert_eq!(
            from_cbor::<ActuatorIntent>(&to_cbor(&intent).expect("cbor")).expect("cbor"),
            intent
        );
    }
}
