//! An in-memory network controller with the discipline of the connector host: it refuses
//! the management VLAN (CONN-09), refuses writes while they are off (TGL-20), rejects a
//! plan whose fingerprint no longer matches (CONN-08), verifies after a write and keeps
//! undo steps. Tests drive the VLAN job and the topology through it, and the server can
//! use it for demonstrations; it contacts nothing.
//!
//! Every call is recorded ([`MemoryControllers::calls`]), and a test can make the next call
//! of a kind fail ([`MemoryControllers::fail_next`]).

// The port reports `CodedError`s, so the helpers that produce them return it as well.
#![allow(clippy::result_large_err)]

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
};

use sha2::{Digest as _, Sha256};
use tenko_core::{
    CodedError, ConnectorId, Timestamp, UserId,
    codec::{from_cbor, to_cbor},
    serde_util::{HexBytes, to_hex},
};

use super::controllers::{
    ControllerDevice, ControllerInfo, ControllerNetwork, ControllerTopology, ControllerWlan,
    DiffEntry, NetworkControllers, NetworkPlan, NetworkReceipt, NetworkSpec, PortFuture,
};

/// One call the controllers received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// `controllers()`.
    List,
    /// `plan_network()` for a VLAN.
    Plan {
        /// The controller.
        connector: ConnectorId,
        /// The VLAN.
        vid: u16,
    },
    /// `apply_network()`.
    Apply {
        /// The controller.
        connector: ConnectorId,
        /// The VLAN.
        vid: u16,
        /// Whether it was a dry run.
        dry_run: bool,
    },
    /// `revert_network()`.
    Revert {
        /// The controller.
        connector: ConnectorId,
        /// The VLAN.
        vid: u16,
    },
    /// `topology()`.
    Topology {
        /// The controller.
        connector: ConnectorId,
    },
}

/// The kind of a call, for [`MemoryControllers::fail_next`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CallKind {
    /// `controllers()`.
    List,
    /// `plan_network()`.
    Plan,
    /// `apply_network()` as a dry run.
    DryRun,
    /// `apply_network()` as a write.
    Write,
    /// `revert_network()`.
    Revert,
    /// `topology()`.
    Topology,
}

/// One controller of the memory implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryController {
    /// What `controllers()` reports.
    pub info: ControllerInfo,
    /// Its networks.
    pub networks: Vec<ControllerNetwork>,
    /// Its devices.
    pub devices: Vec<ControllerDevice>,
    /// Its wireless networks.
    pub wlans: Vec<ControllerWlan>,
    /// Whether a write reads back something else than it wrote (a misbehaving device).
    pub drift_after_write: bool,
}

impl MemoryController {
    /// An enabled controller named `name` with writes allowed and a management network on
    /// VLAN 10 (192.0.2.0/24).
    pub fn new(name: &str) -> Self {
        Self {
            info: ControllerInfo {
                id: ConnectorId::generate(),
                name: name.to_owned(),
                plugin: "memory".to_owned(),
                enabled: true,
                writes_enabled: true,
            },
            networks: vec![ControllerNetwork {
                id: "net-mgmt".to_owned(),
                name: "Management".to_owned(),
                vlan: Some(10),
                subnet: "192.0.2.0/24".parse().ok(),
                management: true,
            }],
            devices: Vec::new(),
            wlans: Vec::new(),
            drift_after_write: false,
        }
    }

    fn network(&self, vid: u16) -> Option<&ControllerNetwork> {
        self.networks.iter().find(|n| n.vlan == Some(vid))
    }

    fn fingerprint(&self, vid: u16) -> String {
        let mut hasher = Sha256::new();
        match self.network(vid) {
            Some(network) => {
                hasher.update(network.id.as_bytes());
                hasher.update([0]);
                hasher.update(network.name.as_bytes());
            }
            None => hasher.update(b"absent"),
        }
        to_hex(&hasher.finalize()[..8])
    }

    fn diff(&self, spec: &NetworkSpec) -> Vec<DiffEntry> {
        let path = |field: &str| format!("networks/vlan-{}/{field}", spec.vid);
        match self.network(spec.vid) {
            None => vec![
                DiffEntry {
                    path: path("name"),
                    before: None,
                    after: Some(spec.name.clone()),
                },
                DiffEntry {
                    path: path("vlan"),
                    before: None,
                    after: Some(spec.vid.to_string()),
                },
            ],
            Some(network) if network.name != spec.name => vec![DiffEntry {
                path: path("name"),
                before: Some(network.name.clone()),
                after: Some(spec.name.clone()),
            }],
            Some(_) => Vec::new(),
        }
    }
}

/// What a receipt token carries: enough to undo the write.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Undo {
    vid: u16,
    /// The network before the write; `None` when the write created it.
    before: Option<(String, String)>,
}

#[derive(Debug, Default)]
struct State {
    controllers: Vec<MemoryController>,
    calls: Vec<Call>,
    failures: BTreeMap<CallKind, CodedError>,
    next_network: u32,
}

/// Network controllers held in memory. Clones share their state.
#[derive(Debug, Clone, Default)]
pub struct MemoryControllers {
    state: Arc<Mutex<State>>,
}

impl MemoryControllers {
    /// Controllers with the given members.
    pub fn new(controllers: Vec<MemoryController>) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                controllers,
                ..State::default()
            })),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every call so far.
    pub fn calls(&self) -> Vec<Call> {
        self.lock().calls.clone()
    }

    /// The controllers as they are now.
    pub fn snapshot(&self) -> Vec<MemoryController> {
        self.lock().controllers.clone()
    }

    /// Changes one controller in place.
    pub fn update(&self, id: ConnectorId, change: impl FnOnce(&mut MemoryController)) {
        let mut state = self.lock();
        if let Some(controller) = state.controllers.iter_mut().find(|c| c.info.id == id) {
            change(controller);
        }
    }

    /// Makes the next call of `kind` fail with `error`.
    pub fn fail_next(&self, kind: CallKind, error: CodedError) {
        self.lock().failures.insert(kind, error);
    }

    fn take_failure(state: &mut State, kind: CallKind) -> Result<(), CodedError> {
        state.failures.remove(&kind).map_or(Ok(()), Err)
    }
}

fn not_found(connector: ConnectorId) -> CodedError {
    CodedError::new(
        "connect.instance.not_found",
        404,
        format!("no connector instance {connector}"),
    )
    .with_param("id", connector.to_string())
}

fn controller_mut(
    state: &mut State,
    connector: ConnectorId,
) -> Result<&mut MemoryController, CodedError> {
    state
        .controllers
        .iter_mut()
        .find(|c| c.info.id == connector)
        .ok_or_else(|| not_found(connector))
}

fn verify_mismatch(detail: &str) -> CodedError {
    CodedError::new("connect.verify_mismatch", 409, detail.to_owned())
        .with_param("diff", detail.to_owned())
}

impl MemoryControllers {
    fn list_now(&self) -> Result<Vec<ControllerInfo>, CodedError> {
        let mut state = self.lock();
        state.calls.push(Call::List);
        Self::take_failure(&mut state, CallKind::List)?;
        Ok(state.controllers.iter().map(|c| c.info.clone()).collect())
    }

    fn plan_now(
        &self,
        connector: ConnectorId,
        spec: &NetworkSpec,
        _on_behalf_of: Option<UserId>,
    ) -> Result<NetworkPlan, CodedError> {
        let mut state = self.lock();
        state.calls.push(Call::Plan {
            connector,
            vid: spec.vid,
        });
        Self::take_failure(&mut state, CallKind::Plan)?;
        let controller = controller_mut(&mut state, connector)?;
        if controller
            .networks
            .iter()
            .any(|n| n.management && n.vlan == Some(spec.vid))
        {
            return Err(CodedError::new(
                "connect.guardrail.protected_vlan",
                409,
                format!("VLAN {} is the management network", spec.vid),
            )
            .with_title("Refused by a guardrail"));
        }
        let plan = NetworkPlan {
            connector,
            spec: spec.clone(),
            read_at: Timestamp::now(),
            fingerprint: controller.fingerprint(spec.vid),
            diff: controller.diff(spec),
            warnings: Vec::new(),
            token: HexBytes(Vec::new()),
        };
        let token =
            to_cbor(&plan.fingerprint).map_err(|error| CodedError::internal(error.to_string()))?;
        Ok(NetworkPlan {
            token: HexBytes(token.to_vec()),
            ..plan
        })
    }

    fn apply_now(
        &self,
        plan: &NetworkPlan,
        dry_run: bool,
        _on_behalf_of: Option<UserId>,
    ) -> Result<NetworkReceipt, CodedError> {
        let mut state = self.lock();
        state.calls.push(Call::Apply {
            connector: plan.connector,
            vid: plan.spec.vid,
            dry_run,
        });
        Self::take_failure(
            &mut state,
            if dry_run {
                CallKind::DryRun
            } else {
                CallKind::Write
            },
        )?;
        state.next_network += 1;
        let next = state.next_network;
        let controller = controller_mut(&mut state, plan.connector)?;
        if !dry_run && !controller.info.writes_enabled {
            return Err(CodedError::new(
                "connect.writes_disabled",
                403,
                "writes through this connector are off",
            ));
        }
        let fingerprint: String =
            from_cbor(&plan.token.0).map_err(|error| CodedError::internal(error.to_string()))?;
        if fingerprint != controller.fingerprint(plan.spec.vid) {
            return Err(verify_mismatch(
                "the controller changed since the plan was made",
            ));
        }
        let before = controller
            .network(plan.spec.vid)
            .map(|n| (n.id.clone(), n.name.clone()));
        let undo = Undo {
            vid: plan.spec.vid,
            before: before.clone(),
        };
        let mut undo_steps = 0;
        if !dry_run && !plan.diff.is_empty() {
            let written_name = if controller.drift_after_write {
                format!("{}-drift", plan.spec.name)
            } else {
                plan.spec.name.clone()
            };
            match controller
                .networks
                .iter_mut()
                .find(|n| n.vlan == Some(plan.spec.vid))
            {
                Some(network) => network.name = written_name,
                None => controller.networks.push(ControllerNetwork {
                    id: format!("net-{next}"),
                    name: written_name,
                    vlan: Some(plan.spec.vid),
                    subnet: None,
                    management: false,
                }),
            }
            undo_steps = 1;
            if !controller.diff(&plan.spec).is_empty() {
                return Err(verify_mismatch(
                    "the read-back after the write differs from the plan",
                ));
            }
        }
        let token = to_cbor(&undo).map_err(|error| CodedError::internal(error.to_string()))?;
        Ok(NetworkReceipt {
            connector: plan.connector,
            dry_run,
            applied_at: Timestamp::now(),
            verified: true,
            undo_steps,
            token: HexBytes(token.to_vec()),
        })
    }

    fn revert_now(
        &self,
        receipt: &NetworkReceipt,
        _on_behalf_of: Option<UserId>,
    ) -> Result<(), CodedError> {
        let undo: Undo =
            from_cbor(&receipt.token.0).map_err(|error| CodedError::internal(error.to_string()))?;
        let mut state = self.lock();
        state.calls.push(Call::Revert {
            connector: receipt.connector,
            vid: undo.vid,
        });
        Self::take_failure(&mut state, CallKind::Revert)?;
        let controller = controller_mut(&mut state, receipt.connector)?;
        if !controller.info.writes_enabled {
            return Err(CodedError::new(
                "connect.writes_disabled",
                403,
                "writes through this connector are off",
            ));
        }
        match undo.before {
            None => controller.networks.retain(|n| n.vlan != Some(undo.vid)),
            Some((id, name)) => {
                if let Some(network) = controller.networks.iter_mut().find(|n| n.id == id) {
                    network.name = name;
                }
            }
        }
        Ok(())
    }

    fn topology_now(
        &self,
        connector: ConnectorId,
        _on_behalf_of: Option<UserId>,
    ) -> Result<ControllerTopology, CodedError> {
        let mut state = self.lock();
        state.calls.push(Call::Topology { connector });
        Self::take_failure(&mut state, CallKind::Topology)?;
        let controller = controller_mut(&mut state, connector)?;
        Ok(ControllerTopology {
            connector,
            observed_at: Timestamp::now(),
            devices: controller.devices.clone(),
            networks: controller.networks.clone(),
            wlans: controller.wlans.clone(),
        })
    }
}

impl NetworkControllers for MemoryControllers {
    fn controllers(&self) -> PortFuture<'_, Vec<ControllerInfo>> {
        Box::pin(std::future::ready(self.list_now()))
    }

    fn plan_network<'a>(
        &'a self,
        connector: ConnectorId,
        spec: &'a NetworkSpec,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'a, NetworkPlan> {
        Box::pin(std::future::ready(self.plan_now(
            connector,
            spec,
            on_behalf_of,
        )))
    }

    fn apply_network<'a>(
        &'a self,
        plan: &'a NetworkPlan,
        dry_run: bool,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'a, NetworkReceipt> {
        Box::pin(std::future::ready(self.apply_now(
            plan,
            dry_run,
            on_behalf_of,
        )))
    }

    fn revert_network<'a>(
        &'a self,
        receipt: &'a NetworkReceipt,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'a, ()> {
        Box::pin(std::future::ready(self.revert_now(receipt, on_behalf_of)))
    }

    fn topology(
        &self,
        connector: ConnectorId,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'_, ControllerTopology> {
        Box::pin(std::future::ready(
            self.topology_now(connector, on_behalf_of),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(vid: u16, name: &str) -> NetworkSpec {
        NetworkSpec {
            vid,
            name: name.to_owned(),
            dhcp_relay: Vec::new(),
        }
    }

    #[tokio::test]
    async fn a_network_is_planned_written_verified_and_reverted() {
        let controller = MemoryController::new("lab");
        let id = controller.info.id;
        let memory = MemoryControllers::new(vec![controller]);
        let plan = memory
            .plan_network(id, &spec(30, "IoT"), None)
            .await
            .expect("plan");
        assert_eq!(plan.diff.len(), 2);
        let dry = memory.apply_network(&plan, true, None).await.expect("dry");
        assert!(dry.dry_run);
        assert_eq!(memory.snapshot()[0].networks.len(), 1);
        let receipt = memory
            .apply_network(&plan, false, None)
            .await
            .expect("write");
        assert!(receipt.verified);
        assert_eq!(receipt.undo_steps, 1);
        let again = memory
            .plan_network(id, &spec(30, "IoT"), None)
            .await
            .expect("plan again");
        assert_eq!(again.diff, Vec::new());
        let stale = memory.apply_network(&plan, false, None).await;
        assert_eq!(stale.expect_err("stale").code, "connect.verify_mismatch");
        memory.revert_network(&receipt, None).await.expect("revert");
        assert_eq!(memory.snapshot()[0].networks.len(), 1);
    }

    #[tokio::test]
    async fn the_management_vlan_and_read_only_instances_are_refused() {
        let mut controller = MemoryController::new("lab");
        controller.info.writes_enabled = false;
        let id = controller.info.id;
        let memory = MemoryControllers::new(vec![controller]);
        let refused = memory.plan_network(id, &spec(10, "x"), None).await;
        assert_eq!(
            refused.expect_err("guardrail").code,
            "connect.guardrail.protected_vlan"
        );
        let plan = memory
            .plan_network(id, &spec(40, "Guests"), None)
            .await
            .expect("plan");
        memory
            .apply_network(&plan, true, None)
            .await
            .expect("a dry run needs no write access");
        let refused = memory.apply_network(&plan, false, None).await;
        assert_eq!(
            refused.expect_err("read-only").code,
            "connect.writes_disabled"
        );
        memory.fail_next(
            CallKind::Topology,
            CodedError::new("connect.unreachable", 502, "down"),
        );
        assert!(memory.topology(id, None).await.is_err());
        assert!(memory.topology(id, None).await.is_ok());
        assert_eq!(memory.calls().len(), 6);
    }
}
