//! An in-memory network controller with the discipline of the connector host: it refuses
//! the management VLAN, uplinks, management ports, management clients and management
//! networks (CONN-09), refuses writes while they are off (TGL-20), rejects a plan whose
//! fingerprint no longer matches (CONN-08), verifies after a write and keeps undo steps.
//! Tests drive the VLAN job, the L2 step of the move job and the topology through it, and
//! the server can use it for demonstrations; it contacts nothing.
//!
//! For the move job a controller holds switch ports with profiles
//! ([`MemoryController::ports`]), connected clients, port profiles, links and per-client
//! VLAN overrides. A port profile change moves the clients on the port into the profile's
//! untagged network; a per-client VLAN override moves a wireless client. A port without a
//! profile on record gives a receipt without undo steps, as the UniFi plugin does.
//!
//! Every call is recorded ([`MemoryControllers::calls`]), and a test can make the next call
//! of a kind fail ([`MemoryControllers::fail_next`]).

// The port reports `CodedError`s, so the helpers that produce them return it as well.
#![allow(clippy::result_large_err)]

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
};

use tenko_core::MacAddr;

use sha2::{Digest as _, Sha256};
use tenko_core::{
    CodedError, ConnectorId, Timestamp, UserId,
    codec::{from_cbor, to_cbor},
    serde_util::{HexBytes, to_hex},
};

use super::controllers::{
    AttachmentChange, AttachmentPlan, ControllerAttachments, ControllerClient, ControllerDevice,
    ControllerInfo, ControllerLink, ControllerNetwork, ControllerPortState, ControllerProfile,
    ControllerTopology, ControllerWlan, DiffEntry, NetworkControllers, NetworkPlan, NetworkReceipt,
    NetworkSpec, PortFuture, derived_guardrails,
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
    /// `attachments()`.
    Attachments {
        /// The controller.
        connector: ConnectorId,
    },
    /// `plan_attachment()`.
    PlanAttachment {
        /// The controller.
        connector: ConnectorId,
        /// The change.
        change: AttachmentChange,
    },
    /// `apply_attachment()`.
    ApplyAttachment {
        /// The controller.
        connector: ConnectorId,
        /// The change.
        change: AttachmentChange,
        /// Whether it was a dry run.
        dry_run: bool,
    },
    /// `revert_network()` of an attachment change.
    RevertAttachment {
        /// The controller.
        connector: ConnectorId,
        /// The change that is undone.
        change: AttachmentChange,
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
    /// `attachments()`.
    Attachments,
    /// `plan_attachment()`.
    PlanAttachment,
    /// `apply_attachment()` as a dry run.
    AttachmentDryRun,
    /// `apply_attachment()` as a write.
    AttachmentWrite,
    /// `revert_network()` of an attachment change.
    RevertAttachment,
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
    /// Switch ports with profiles and guardrail flags (the move job).
    pub ports: Vec<ControllerPortState>,
    /// Connected clients.
    pub clients: Vec<ControllerClient>,
    /// Port profiles.
    pub profiles: Vec<ControllerProfile>,
    /// Links between devices.
    pub links: Vec<ControllerLink>,
    /// Per-client VLAN overrides: the client and the network it is put into.
    pub overrides: BTreeMap<MacAddr, String>,
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
                dhcp: None,
            }],
            devices: Vec::new(),
            wlans: Vec::new(),
            drift_after_write: false,
            ports: Vec::new(),
            clients: Vec::new(),
            profiles: Vec::new(),
            links: Vec::new(),
            overrides: BTreeMap::new(),
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

    /// What `attachments()` reports.
    fn attachments(&self) -> ControllerAttachments {
        ControllerAttachments {
            connector: self.info.id,
            observed_at: Timestamp::now(),
            devices: self.devices.clone(),
            ports: self.ports.clone(),
            clients: self.clients.clone(),
            networks: self.networks.clone(),
            profiles: self.profiles.clone(),
            wlans: self.wlans.clone(),
            links: self.links.clone(),
        }
    }

    fn profile_name(&self, id: Option<&str>) -> Option<String> {
        id.map(|id| {
            self.profiles
                .iter()
                .find(|p| p.id == id)
                .map_or_else(|| id.to_owned(), |p| p.name.clone())
        })
    }

    fn network_name(&self, id: Option<&str>) -> Option<String> {
        id.map(|id| {
            self.networks
                .iter()
                .find(|n| n.id == id)
                .map_or_else(|| id.to_owned(), |n| n.name.clone())
        })
    }

    /// Whether the controller has a record of the client: connected, or with an override.
    fn knows(&self, mac: MacAddr) -> Result<(), CodedError> {
        if self.clients.iter().any(|c| c.mac == mac) || self.overrides.contains_key(&mac) {
            Ok(())
        } else {
            Err(missing(format!("no client {mac}")))
        }
    }

    /// What an attachment change touches now: the fingerprint and the diff.
    fn attachment_state(
        &self,
        change: &AttachmentChange,
    ) -> Result<(String, Vec<DiffEntry>), CodedError> {
        let (material, diff) = match change {
            AttachmentChange::SetPortProfile {
                device,
                port,
                profile,
            } => {
                let state = self
                    .ports
                    .iter()
                    .find(|p| &p.device == device && p.index == *port)
                    .ok_or_else(|| missing(format!("no port {port} on {device}")))?;
                if !self.profiles.iter().any(|p| &p.id == profile) {
                    return Err(missing(format!("no port profile {profile}")));
                }
                let current = state.profile.as_deref();
                let diff = if current == Some(profile.as_str()) {
                    Vec::new()
                } else {
                    vec![DiffEntry {
                        path: format!("devices/{device}/ports/{port}/profile"),
                        before: self.profile_name(current),
                        after: self.profile_name(Some(profile)),
                    }]
                };
                (
                    format!("port|{device}|{port}|{}", current.unwrap_or("-")),
                    diff,
                )
            }
            AttachmentChange::SetClientVlan { mac, network } => {
                self.knows(*mac)?;
                if !self.networks.iter().any(|n| &n.id == network) {
                    return Err(missing(format!("no network {network}")));
                }
                let current = self.overrides.get(mac).map(String::as_str);
                let diff = if current == Some(network.as_str()) {
                    Vec::new()
                } else {
                    vec![DiffEntry {
                        path: format!("clients/{mac}/network"),
                        before: self.network_name(current),
                        after: self.network_name(Some(network)),
                    }]
                };
                (format!("client|{mac}|{}", current.unwrap_or("-")), diff)
            }
            AttachmentChange::ClearClientVlan { mac } => {
                self.knows(*mac)?;
                let current = self.overrides.get(mac).map(String::as_str);
                let diff = match current {
                    None => Vec::new(),
                    Some(network) => vec![DiffEntry {
                        path: format!("clients/{mac}/network"),
                        before: self.network_name(Some(network)),
                        after: None,
                    }],
                };
                (format!("client|{mac}|{}", current.unwrap_or("-")), diff)
            }
        };
        let mut hasher = Sha256::new();
        hasher.update(material.as_bytes());
        Ok((to_hex(&hasher.finalize()[..8]), diff))
    }

    /// Writes an attachment change and returns the changes that undo it. A port profile
    /// moves the clients on the port into the profile's untagged network; an override
    /// moves a wireless client into its network. With `drift_after_write` nothing sticks.
    fn write_attachment(&mut self, change: &AttachmentChange) -> Vec<AttachmentChange> {
        let drift = self.drift_after_write;
        match change {
            AttachmentChange::SetPortProfile {
                device,
                port,
                profile,
            } => {
                let native = self
                    .profiles
                    .iter()
                    .find(|p| &p.id == profile)
                    .and_then(|p| p.native_network.clone());
                let vlan = native
                    .as_deref()
                    .and_then(|id| self.networks.iter().find(|n| n.id == id))
                    .and_then(|n| n.vlan);
                let Some(state) = self
                    .ports
                    .iter_mut()
                    .find(|p| &p.device == device && p.index == *port)
                else {
                    return Vec::new();
                };
                let previous = state.profile.clone();
                if drift {
                    return Vec::new();
                }
                state.profile = Some(profile.clone());
                state.native_vlan = vlan;
                for client in self
                    .clients
                    .iter_mut()
                    .filter(|c| &c.device == device && c.port == Some(*port))
                {
                    client.network.clone_from(&native);
                    client.vlan = vlan;
                }
                previous
                    .map(|profile| AttachmentChange::SetPortProfile {
                        device: device.clone(),
                        port: *port,
                        profile,
                    })
                    .into_iter()
                    .collect()
            }
            AttachmentChange::SetClientVlan { mac, network } => {
                let previous = self.overrides.get(mac).cloned();
                if drift {
                    return Vec::new();
                }
                self.overrides.insert(*mac, network.clone());
                let vlan = self
                    .networks
                    .iter()
                    .find(|n| &n.id == network)
                    .and_then(|n| n.vlan);
                for client in self
                    .clients
                    .iter_mut()
                    .filter(|c| c.mac == *mac && c.ssid.is_some())
                {
                    client.network = Some(network.clone());
                    client.vlan = vlan;
                }
                vec![match previous {
                    Some(network) => AttachmentChange::SetClientVlan { mac: *mac, network },
                    None => AttachmentChange::ClearClientVlan { mac: *mac },
                }]
            }
            AttachmentChange::ClearClientVlan { mac } => {
                if drift {
                    return Vec::new();
                }
                self.overrides
                    .remove(mac)
                    .map(|network| AttachmentChange::SetClientVlan { mac: *mac, network })
                    .into_iter()
                    .collect()
            }
        }
    }
}

fn missing(detail: String) -> CodedError {
    CodedError::new("connect.not_found", 404, detail)
}

/// What a receipt token carries: enough to undo the write.
///
/// Adjacently tagged because a variant carries MAC addresses.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
enum Undo {
    /// A network write.
    Network {
        vid: u16,
        /// The network before the write; `None` when the write created it.
        before: Option<(String, String)>,
    },
    /// An attachment change and the changes that undo it, in order.
    Attachment {
        change: AttachmentChange,
        undo: Vec<AttachmentChange>,
    },
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

fn writes_disabled() -> CodedError {
    CodedError::new(
        "connect.writes_disabled",
        403,
        "writes through this connector are off",
    )
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
            return Err(writes_disabled());
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
        let undo = Undo::Network {
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
                    dhcp: None,
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
        let (vid, before) = match undo {
            Undo::Network { vid, before } => (vid, before),
            Undo::Attachment { change, undo } => {
                return Self::revert_attachment(&mut state, receipt, &change, &undo);
            }
        };
        state.calls.push(Call::Revert {
            connector: receipt.connector,
            vid,
        });
        Self::take_failure(&mut state, CallKind::Revert)?;
        let controller = controller_mut(&mut state, receipt.connector)?;
        if !controller.info.writes_enabled {
            return Err(writes_disabled());
        }
        match before {
            None => controller.networks.retain(|n| n.vlan != Some(vid)),
            Some((id, name)) => {
                if let Some(network) = controller.networks.iter_mut().find(|n| n.id == id) {
                    network.name = name;
                }
            }
        }
        Ok(())
    }

    /// Undoes an attachment change: only while the controller still shows what the write
    /// left, and each undo step under the guardrails.
    fn revert_attachment(
        state: &mut State,
        receipt: &NetworkReceipt,
        change: &AttachmentChange,
        undo: &[AttachmentChange],
    ) -> Result<(), CodedError> {
        state.calls.push(Call::RevertAttachment {
            connector: receipt.connector,
            change: change.clone(),
        });
        Self::take_failure(state, CallKind::RevertAttachment)?;
        let controller = controller_mut(state, receipt.connector)?;
        if !controller.info.writes_enabled {
            return Err(writes_disabled());
        }
        if receipt.dry_run || undo.is_empty() {
            return Ok(());
        }
        let (_, drift) = controller.attachment_state(change)?;
        if let Some(line) = drift.first() {
            return Err(verify_mismatch(&format!(
                "the controller changed since the write (`{}` is {}); undo it by hand",
                line.path,
                line.before.as_deref().unwrap_or("absent")
            )));
        }
        for step in undo {
            derived_guardrails(&controller.attachments(), step)?;
            controller.write_attachment(step);
        }
        Ok(())
    }

    fn attachments_now(
        &self,
        connector: ConnectorId,
        _on_behalf_of: Option<UserId>,
    ) -> Result<ControllerAttachments, CodedError> {
        let mut state = self.lock();
        state.calls.push(Call::Attachments { connector });
        Self::take_failure(&mut state, CallKind::Attachments)?;
        Ok(controller_mut(&mut state, connector)?.attachments())
    }

    fn plan_attachment_now(
        &self,
        connector: ConnectorId,
        change: &AttachmentChange,
        _on_behalf_of: Option<UserId>,
    ) -> Result<AttachmentPlan, CodedError> {
        let mut state = self.lock();
        state.calls.push(Call::PlanAttachment {
            connector,
            change: change.clone(),
        });
        Self::take_failure(&mut state, CallKind::PlanAttachment)?;
        let controller = controller_mut(&mut state, connector)?;
        derived_guardrails(&controller.attachments(), change)?;
        let (fingerprint, diff) = controller.attachment_state(change)?;
        let token =
            to_cbor(&fingerprint).map_err(|error| CodedError::internal(error.to_string()))?;
        Ok(AttachmentPlan {
            connector,
            change: change.clone(),
            read_at: Timestamp::now(),
            fingerprint,
            diff,
            warnings: Vec::new(),
            token: HexBytes(token.to_vec()),
        })
    }

    fn apply_attachment_now(
        &self,
        plan: &AttachmentPlan,
        dry_run: bool,
        _on_behalf_of: Option<UserId>,
    ) -> Result<NetworkReceipt, CodedError> {
        let mut state = self.lock();
        state.calls.push(Call::ApplyAttachment {
            connector: plan.connector,
            change: plan.change.clone(),
            dry_run,
        });
        Self::take_failure(
            &mut state,
            if dry_run {
                CallKind::AttachmentDryRun
            } else {
                CallKind::AttachmentWrite
            },
        )?;
        let controller = controller_mut(&mut state, plan.connector)?;
        if !dry_run && !controller.info.writes_enabled {
            return Err(writes_disabled());
        }
        derived_guardrails(&controller.attachments(), &plan.change)?;
        let fingerprint: String =
            from_cbor(&plan.token.0).map_err(|error| CodedError::internal(error.to_string()))?;
        let (now, diff) = controller.attachment_state(&plan.change)?;
        if fingerprint != now {
            return Err(verify_mismatch(
                "the controller changed since the plan; plan the change again",
            ));
        }
        let mut undo = Vec::new();
        if !dry_run && !diff.is_empty() {
            undo = controller.write_attachment(&plan.change);
            let (_, remaining) = controller.attachment_state(&plan.change)?;
            if let Some(line) = remaining.first() {
                return Err(verify_mismatch(&format!(
                    "after the write `{}` is {} instead of {}",
                    line.path,
                    line.before.as_deref().unwrap_or("absent"),
                    line.after.as_deref().unwrap_or("absent")
                )));
            }
        }
        let undo_steps = undo.len();
        let token = to_cbor(&Undo::Attachment {
            change: plan.change.clone(),
            undo,
        })
        .map_err(|error| CodedError::internal(error.to_string()))?;
        Ok(NetworkReceipt {
            connector: plan.connector,
            dry_run,
            applied_at: Timestamp::now(),
            verified: true,
            undo_steps,
            token: HexBytes(token.to_vec()),
        })
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

    fn attachments(
        &self,
        connector: ConnectorId,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'_, ControllerAttachments> {
        Box::pin(std::future::ready(
            self.attachments_now(connector, on_behalf_of),
        ))
    }

    fn plan_attachment<'a>(
        &'a self,
        connector: ConnectorId,
        change: &'a AttachmentChange,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'a, AttachmentPlan> {
        Box::pin(std::future::ready(self.plan_attachment_now(
            connector,
            change,
            on_behalf_of,
        )))
    }

    fn apply_attachment<'a>(
        &'a self,
        plan: &'a AttachmentPlan,
        dry_run: bool,
        on_behalf_of: Option<UserId>,
    ) -> PortFuture<'a, NetworkReceipt> {
        Box::pin(std::future::ready(self.apply_attachment_now(
            plan,
            dry_run,
            on_behalf_of,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{super::controllers::ControllerDeviceKind, *};

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

    // The attachments of the move job (IPAM-19 step 4).

    fn mac(n: u8) -> MacAddr {
        MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, n])
    }

    fn device(id: &str, name: &str, kind: ControllerDeviceKind) -> ControllerDevice {
        ControllerDevice {
            id: id.to_owned(),
            name: name.to_owned(),
            model: None,
            mac: None,
            ip: None,
            kind,
            ports: Vec::new(),
        }
    }

    fn network(id: &str, name: &str, vlan: u16) -> ControllerNetwork {
        ControllerNetwork {
            id: id.to_owned(),
            name: name.to_owned(),
            vlan: Some(vlan),
            subnet: None,
            management: false,
            dhcp: None,
        }
    }

    fn profile(id: &str, name: &str, native: &str) -> ControllerProfile {
        ControllerProfile {
            id: id.to_owned(),
            name: name.to_owned(),
            native_network: Some(native.to_owned()),
            tagged: Vec::new(),
        }
    }

    fn port(index: u16, profile: Option<&str>, native_vlan: Option<u16>) -> ControllerPortState {
        ControllerPortState {
            device: "sw-1".to_owned(),
            index,
            name: Some(format!("Port {index}")),
            profile: profile.map(str::to_owned),
            native_vlan,
            uplink: false,
            management: false,
            up: true,
        }
    }

    /// A client of the home network (VLAN 20).
    fn client(n: u8, device: &str, port: Option<u16>, ssid: Option<&str>) -> ControllerClient {
        ControllerClient {
            mac: mac(n),
            ip: None,
            device: device.to_owned(),
            port,
            ssid: ssid.map(str::to_owned),
            network: Some("net-home".to_owned()),
            vlan: Some(20),
            name: None,
            management: false,
        }
    }

    // One switch with four ports (1 on the home profile, 2 without a profile, 3 an uplink,
    // 4 the management port) and one access point; the networks home (20), IoT (30) and the
    // management network; the profiles home, IoT and guest (home's network); the clients
    // 1 and 2 on port 1, 3 on the access point, 4 on port 2 and 5 the management client.
    fn lab() -> MemoryController {
        let mut controller = MemoryController::new("lab");
        controller.networks.push(network("net-home", "Home", 20));
        controller.networks.push(network("net-iot", "IoT", 30));
        controller.devices = vec![
            device("sw-1", "Switch One", ControllerDeviceKind::Switch),
            device(
                "ap-1",
                "Access Point One",
                ControllerDeviceKind::AccessPoint,
            ),
        ];
        controller.profiles = vec![
            profile("prof-home", "Home", "net-home"),
            profile("prof-iot", "IoT", "net-iot"),
            profile("prof-guest", "Guest", "net-home"),
        ];
        controller.ports = vec![
            port(1, Some("prof-home"), Some(20)),
            port(2, None, None),
            ControllerPortState {
                uplink: true,
                ..port(3, None, None)
            },
            ControllerPortState {
                management: true,
                ..port(4, None, None)
            },
        ];
        controller.clients = vec![
            client(1, "sw-1", Some(1), None),
            client(2, "sw-1", Some(1), None),
            client(3, "ap-1", None, Some("home.example.test")),
            client(4, "sw-1", Some(2), None),
            ControllerClient {
                management: true,
                ..client(5, "ap-1", None, Some("home.example.test"))
            },
        ];
        controller
    }

    fn rig() -> (MemoryControllers, ConnectorId) {
        let controller = lab();
        let id = controller.info.id;
        (MemoryControllers::new(vec![controller]), id)
    }

    fn set_profile(port: u16, profile: &str) -> AttachmentChange {
        AttachmentChange::SetPortProfile {
            device: "sw-1".to_owned(),
            port,
            profile: profile.to_owned(),
        }
    }

    fn set_vlan(n: u8, network: &str) -> AttachmentChange {
        AttachmentChange::SetClientVlan {
            mac: mac(n),
            network: network.to_owned(),
        }
    }

    fn port_of(memory: &MemoryControllers, index: u16) -> ControllerPortState {
        memory.snapshot()[0]
            .ports
            .iter()
            .find(|p| p.index == index)
            .cloned()
            .expect("port")
    }

    fn client_of(memory: &MemoryControllers, n: u8) -> ControllerClient {
        memory.snapshot()[0]
            .clients
            .iter()
            .find(|c| c.mac == mac(n))
            .cloned()
            .expect("client")
    }

    /// Where a client is, as the network and the VLAN.
    fn place_of(memory: &MemoryControllers, n: u8) -> (Option<String>, Option<u16>) {
        let client = client_of(memory, n);
        (client.network, client.vlan)
    }

    fn place(network: &str, vlan: u16) -> (Option<String>, Option<u16>) {
        (Some(network.to_owned()), Some(vlan))
    }

    async fn plan_of(
        memory: &MemoryControllers,
        id: ConnectorId,
        change: &AttachmentChange,
    ) -> AttachmentPlan {
        memory
            .plan_attachment(id, change, None)
            .await
            .expect("plan")
    }

    /// Plans and writes `change`.
    async fn write(
        memory: &MemoryControllers,
        id: ConnectorId,
        change: &AttachmentChange,
    ) -> NetworkReceipt {
        let plan = plan_of(memory, id, change).await;
        memory
            .apply_attachment(&plan, false, None)
            .await
            .expect("write")
    }

    /// The change and the undo steps a receipt carries.
    fn undo_of(receipt: &NetworkReceipt) -> (AttachmentChange, Vec<AttachmentChange>) {
        let Undo::Attachment { change, undo } = from_cbor::<Undo>(&receipt.token.0).expect("token")
        else {
            panic!("the receipt of an attachment change");
        };
        (change, undo)
    }

    fn unreachable() -> CodedError {
        CodedError::new("connect.unreachable", 502, "down")
    }

    #[tokio::test]
    async fn a_port_profile_change_is_planned_with_one_diff_line() {
        let (memory, id) = rig();
        let change = set_profile(1, "prof-iot");
        let plan = plan_of(&memory, id, &change).await;
        assert_eq!(plan.connector, id);
        assert_eq!(plan.change, change);
        assert_eq!(
            plan.diff,
            vec![DiffEntry {
                path: "devices/sw-1/ports/1/profile".to_owned(),
                before: Some("Home".to_owned()),
                after: Some("IoT".to_owned()),
            }]
        );
        assert_eq!(plan.warnings, Vec::<String>::new());
        assert_ne!(plan.fingerprint, "");
        // Planning writes nothing.
        assert_eq!(port_of(&memory, 1).profile.as_deref(), Some("prof-home"));
        assert_eq!(
            memory.calls(),
            [Call::PlanAttachment {
                connector: id,
                change
            }]
        );
    }

    #[tokio::test]
    async fn a_dry_run_validates_and_writes_nothing() {
        let controller = lab();
        let id = controller.info.id;
        let memory = MemoryControllers::new(vec![controller.clone()]);
        let change = set_profile(1, "prof-iot");
        let plan = plan_of(&memory, id, &change).await;
        let dry = memory
            .apply_attachment(&plan, true, None)
            .await
            .expect("dry run");
        assert!(dry.dry_run);
        assert!(dry.verified);
        assert_eq!(dry.undo_steps, 0);
        assert_eq!(dry.connector, id);
        assert_eq!(memory.snapshot(), [controller]);
        assert_eq!(
            memory.calls().last(),
            Some(&Call::ApplyAttachment {
                connector: id,
                change,
                dry_run: true
            })
        );
    }

    #[tokio::test]
    async fn the_write_moves_the_clients_on_the_port_into_the_profiles_network() {
        let (memory, id) = rig();
        let receipt = write(&memory, id, &set_profile(1, "prof-iot")).await;
        assert!(!receipt.dry_run);
        assert!(receipt.verified);
        assert_eq!(receipt.undo_steps, 1);
        assert_eq!(receipt.connector, id);
        let moved = port_of(&memory, 1);
        assert_eq!(moved.profile.as_deref(), Some("prof-iot"));
        assert_eq!(moved.native_vlan, Some(30));
        assert_eq!(place_of(&memory, 1), place("net-iot", 30));
        assert_eq!(place_of(&memory, 2), place("net-iot", 30));
        // The clients elsewhere stay.
        assert_eq!(place_of(&memory, 3), place("net-home", 20));
        assert_eq!(place_of(&memory, 4), place("net-home", 20));
        assert_eq!(port_of(&memory, 2).profile, None);
        // The controller reports it.
        let state = memory.attachments(id, None).await.expect("attachments");
        assert_eq!(state.connector, id);
        assert_eq!(
            state.port("sw-1", 1).and_then(|p| p.profile.as_deref()),
            Some("prof-iot")
        );
        assert_eq!(state.client(mac(1)).and_then(|c| c.vlan), Some(30));
        assert_eq!(state.client(mac(3)).and_then(|c| c.vlan), Some(20));
    }

    #[tokio::test]
    async fn planning_again_after_the_write_shows_an_empty_diff() {
        let (memory, id) = rig();
        let change = set_profile(1, "prof-iot");
        write(&memory, id, &change).await;
        let again = plan_of(&memory, id, &change).await;
        assert_eq!(again.diff, Vec::new());
        // Writing a plan without a diff changes nothing and has nothing to undo.
        let before = memory.snapshot();
        let receipt = memory
            .apply_attachment(&again, false, None)
            .await
            .expect("nothing to write");
        assert_eq!(receipt.undo_steps, 0);
        assert_eq!(memory.snapshot(), before);
    }

    #[tokio::test]
    async fn a_plan_is_stale_when_the_port_changed_after_it_was_made() {
        let (memory, id) = rig();
        let plan = plan_of(&memory, id, &set_profile(1, "prof-iot")).await;
        memory.update(id, |c| c.ports[0].profile = Some("prof-guest".to_owned()));
        for dry_run in [true, false] {
            let error = memory
                .apply_attachment(&plan, dry_run, None)
                .await
                .expect_err("stale");
            assert_eq!(error.code, "connect.verify_mismatch");
            assert_eq!(error.status, 409);
        }
        assert_eq!(port_of(&memory, 1).profile.as_deref(), Some("prof-guest"));
        assert_eq!(place_of(&memory, 1), place("net-home", 20));
    }

    #[tokio::test]
    async fn a_plan_cannot_be_applied_twice() {
        let (memory, id) = rig();
        let plan = plan_of(&memory, id, &set_profile(1, "prof-iot")).await;
        memory
            .apply_attachment(&plan, false, None)
            .await
            .expect("write");
        let stale = memory.apply_attachment(&plan, false, None).await;
        assert_eq!(stale.expect_err("stale").code, "connect.verify_mismatch");
    }

    #[tokio::test]
    async fn the_revert_restores_the_old_profile_and_records_the_call() {
        let (memory, id) = rig();
        let change = set_profile(1, "prof-iot");
        let receipt = write(&memory, id, &change).await;
        assert_eq!(
            undo_of(&receipt),
            (change.clone(), vec![set_profile(1, "prof-home")])
        );
        memory.revert_network(&receipt, None).await.expect("revert");
        let restored = port_of(&memory, 1);
        assert_eq!(restored.profile.as_deref(), Some("prof-home"));
        assert_eq!(restored.native_vlan, Some(20));
        assert_eq!(place_of(&memory, 1), place("net-home", 20));
        assert_eq!(place_of(&memory, 2), place("net-home", 20));
        assert_eq!(
            memory.calls().last(),
            Some(&Call::RevertAttachment {
                connector: id,
                change
            })
        );
    }

    #[tokio::test]
    async fn a_port_without_a_profile_gives_a_receipt_without_undo_steps() {
        let (memory, id) = rig();
        let change = set_profile(2, "prof-iot");
        let plan = plan_of(&memory, id, &change).await;
        assert_eq!(
            plan.diff,
            vec![DiffEntry {
                path: "devices/sw-1/ports/2/profile".to_owned(),
                before: None,
                after: Some("IoT".to_owned()),
            }]
        );
        let receipt = memory
            .apply_attachment(&plan, false, None)
            .await
            .expect("write");
        assert!(receipt.verified);
        assert_eq!(receipt.undo_steps, 0);
        assert_eq!(undo_of(&receipt), (change.clone(), Vec::new()));
        assert_eq!(place_of(&memory, 4), place("net-iot", 30));
        // There is nothing to put back: the revert succeeds and leaves the port as it is.
        memory.revert_network(&receipt, None).await.expect("revert");
        assert_eq!(port_of(&memory, 2).profile.as_deref(), Some("prof-iot"));
        assert_eq!(
            memory.calls().last(),
            Some(&Call::RevertAttachment {
                connector: id,
                change
            })
        );
    }

    #[tokio::test]
    async fn a_client_override_is_set_and_its_revert_clears_it() {
        let (memory, id) = rig();
        let change = set_vlan(3, "net-iot");
        let plan = plan_of(&memory, id, &change).await;
        assert_eq!(
            plan.diff,
            vec![DiffEntry {
                path: "clients/00:00:5e:00:53:03/network".to_owned(),
                before: None,
                after: Some("IoT".to_owned()),
            }]
        );
        let receipt = memory
            .apply_attachment(&plan, false, None)
            .await
            .expect("write");
        assert_eq!(receipt.undo_steps, 1);
        assert_eq!(
            undo_of(&receipt),
            (
                change.clone(),
                vec![AttachmentChange::ClearClientVlan { mac: mac(3) }]
            )
        );
        assert_eq!(
            memory.snapshot()[0].overrides,
            BTreeMap::from([(mac(3), "net-iot".to_owned())])
        );
        assert_eq!(place_of(&memory, 3), place("net-iot", 30));
        // Only the wireless client moved.
        assert_eq!(place_of(&memory, 1), place("net-home", 20));
        assert_eq!(plan_of(&memory, id, &change).await.diff, Vec::new());

        memory.revert_network(&receipt, None).await.expect("revert");
        assert_eq!(memory.snapshot()[0].overrides, BTreeMap::new());
        assert_eq!(plan_of(&memory, id, &change).await.diff, plan.diff);
        assert_eq!(
            memory
                .calls()
                .iter()
                .filter(|c| matches!(c, Call::RevertAttachment { .. }))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn changing_an_override_undoes_to_the_previous_network() {
        let (memory, id) = rig();
        memory.update(id, |c| {
            c.overrides.insert(mac(3), "net-home".to_owned());
        });
        let change = set_vlan(3, "net-iot");
        let plan = plan_of(&memory, id, &change).await;
        assert_eq!(plan.diff[0].before.as_deref(), Some("Home"));
        assert_eq!(plan.diff[0].after.as_deref(), Some("IoT"));
        let receipt = memory
            .apply_attachment(&plan, false, None)
            .await
            .expect("write");
        assert_eq!(undo_of(&receipt).1, vec![set_vlan(3, "net-home")]);
        memory.revert_network(&receipt, None).await.expect("revert");
        assert_eq!(
            memory.snapshot()[0].overrides,
            BTreeMap::from([(mac(3), "net-home".to_owned())])
        );
    }

    #[tokio::test]
    async fn clearing_an_override_removes_it_and_the_revert_puts_it_back() {
        let (memory, id) = rig();
        let clear = AttachmentChange::ClearClientVlan { mac: mac(3) };
        // Nothing to clear yet.
        assert_eq!(plan_of(&memory, id, &clear).await.diff, Vec::new());
        memory.update(id, |c| {
            c.overrides.insert(mac(3), "net-iot".to_owned());
        });
        let plan = plan_of(&memory, id, &clear).await;
        assert_eq!(
            plan.diff,
            vec![DiffEntry {
                path: "clients/00:00:5e:00:53:03/network".to_owned(),
                before: Some("IoT".to_owned()),
                after: None,
            }]
        );
        let receipt = memory
            .apply_attachment(&plan, false, None)
            .await
            .expect("write");
        assert_eq!(undo_of(&receipt).1, vec![set_vlan(3, "net-iot")]);
        assert_eq!(memory.snapshot()[0].overrides, BTreeMap::new());
        memory.revert_network(&receipt, None).await.expect("revert");
        assert_eq!(
            memory.snapshot()[0].overrides,
            BTreeMap::from([(mac(3), "net-iot".to_owned())])
        );
    }

    /// The code of the refusal of a plan.
    async fn plan_refusal(
        memory: &MemoryControllers,
        id: ConnectorId,
        change: &AttachmentChange,
    ) -> String {
        let error = memory
            .plan_attachment(id, change, None)
            .await
            .expect_err("refused");
        assert_eq!(error.status, 409);
        error.code.to_string()
    }

    /// The code of the refusal of a write of a plan made before.
    async fn write_refusal(memory: &MemoryControllers, plan: &AttachmentPlan) -> String {
        let error = memory
            .apply_attachment(plan, false, None)
            .await
            .expect_err("refused");
        assert_eq!(error.status, 409);
        error.code.to_string()
    }

    #[tokio::test]
    async fn an_uplink_is_refused_at_plan_and_at_write() {
        let (memory, id) = rig();
        assert_eq!(
            plan_refusal(&memory, id, &set_profile(3, "prof-iot")).await,
            "connect.guardrail.uplink"
        );
        // The port became an uplink after the plan was made.
        let plan = plan_of(&memory, id, &set_profile(1, "prof-iot")).await;
        memory.update(id, |c| c.ports[0].uplink = true);
        assert_eq!(
            write_refusal(&memory, &plan).await,
            "connect.guardrail.uplink"
        );
        assert_eq!(port_of(&memory, 1).profile.as_deref(), Some("prof-home"));
    }

    #[tokio::test]
    async fn the_management_port_is_refused_at_plan_and_at_write() {
        let (memory, id) = rig();
        assert_eq!(
            plan_refusal(&memory, id, &set_profile(4, "prof-iot")).await,
            "connect.guardrail.management_port"
        );
        let plan = plan_of(&memory, id, &set_profile(1, "prof-iot")).await;
        memory.update(id, |c| c.ports[0].management = true);
        assert_eq!(
            write_refusal(&memory, &plan).await,
            "connect.guardrail.management_port"
        );
        assert_eq!(port_of(&memory, 1).profile.as_deref(), Some("prof-home"));
    }

    #[tokio::test]
    async fn a_management_client_is_refused_at_plan_and_at_write() {
        let (memory, id) = rig();
        assert_eq!(
            plan_refusal(&memory, id, &set_vlan(5, "net-iot")).await,
            "connect.guardrail.management_client"
        );
        assert_eq!(
            plan_refusal(
                &memory,
                id,
                &AttachmentChange::ClearClientVlan { mac: mac(5) }
            )
            .await,
            "connect.guardrail.management_client"
        );
        let plan = plan_of(&memory, id, &set_vlan(3, "net-iot")).await;
        memory.update(id, |c| c.clients[2].management = true);
        assert_eq!(
            write_refusal(&memory, &plan).await,
            "connect.guardrail.management_client"
        );
        assert_eq!(memory.snapshot()[0].overrides, BTreeMap::new());
    }

    #[tokio::test]
    async fn a_management_network_is_refused_at_plan_and_at_write() {
        let (memory, id) = rig();
        assert_eq!(
            plan_refusal(&memory, id, &set_vlan(3, "net-mgmt")).await,
            "connect.guardrail.protected_network"
        );
        let plan = plan_of(&memory, id, &set_vlan(3, "net-iot")).await;
        memory.update(id, |c| c.networks[2].management = true);
        assert_eq!(
            write_refusal(&memory, &plan).await,
            "connect.guardrail.protected_network"
        );
        assert_eq!(memory.snapshot()[0].overrides, BTreeMap::new());
    }

    #[tokio::test]
    async fn the_undo_steps_are_checked_against_the_guardrails_too() {
        let (memory, id) = rig();
        let receipt = write(&memory, id, &set_profile(1, "prof-iot")).await;
        memory.update(id, |c| c.ports[0].uplink = true);
        let error = memory
            .revert_network(&receipt, None)
            .await
            .expect_err("the port is an uplink now");
        assert_eq!(error.code, "connect.guardrail.uplink");
        assert_eq!(port_of(&memory, 1).profile.as_deref(), Some("prof-iot"));
    }

    #[tokio::test]
    async fn check_attachment_applies_the_derived_rules_to_what_attachments_read() {
        let (memory, id) = rig();
        let state = memory.attachments(id, None).await.expect("attachments");
        let refusal = |change: &AttachmentChange| {
            memory
                .check_attachment(&state, change)
                .expect_err("refused")
                .code
                .to_string()
        };
        assert_eq!(
            refusal(&set_profile(3, "prof-iot")),
            "connect.guardrail.uplink"
        );
        assert_eq!(
            refusal(&set_profile(4, "prof-iot")),
            "connect.guardrail.management_port"
        );
        assert_eq!(
            refusal(&set_vlan(5, "net-iot")),
            "connect.guardrail.management_client"
        );
        assert_eq!(
            refusal(&set_vlan(3, "net-mgmt")),
            "connect.guardrail.protected_network"
        );
        assert_eq!(
            memory.check_attachment(&state, &set_profile(1, "prof-iot")),
            Ok(())
        );
        assert_eq!(
            memory.check_attachment(&state, &set_vlan(3, "net-iot")),
            Ok(())
        );
        // The check calls no controller.
        assert_eq!(memory.calls(), [Call::Attachments { connector: id }]);
    }

    #[tokio::test]
    async fn writes_off_refuse_the_write_and_the_revert_but_not_the_plan_and_the_dry_run() {
        let (memory, id) = rig();
        let receipt = write(&memory, id, &set_profile(1, "prof-iot")).await;
        memory.update(id, |c| c.info.writes_enabled = false);

        let change = set_profile(2, "prof-iot");
        let plan = plan_of(&memory, id, &change).await;
        assert_eq!(plan.diff.len(), 1);
        let dry = memory
            .apply_attachment(&plan, true, None)
            .await
            .expect("a dry run needs no write access");
        assert!(dry.dry_run);
        let refused = memory.apply_attachment(&plan, false, None).await;
        let error = refused.expect_err("read-only");
        assert_eq!(error.code, "connect.writes_disabled");
        assert_eq!(error.status, 403);
        let refused = memory.revert_network(&receipt, None).await;
        assert_eq!(
            refused.expect_err("read-only").code,
            "connect.writes_disabled"
        );
        assert_eq!(port_of(&memory, 1).profile.as_deref(), Some("prof-iot"));
        assert_eq!(port_of(&memory, 2).profile, None);
    }

    #[tokio::test]
    async fn a_write_that_reads_back_differently_is_a_verify_mismatch() {
        let mut controller = lab();
        controller.drift_after_write = true;
        let id = controller.info.id;
        let memory = MemoryControllers::new(vec![controller]);
        let plan = plan_of(&memory, id, &set_profile(1, "prof-iot")).await;
        let error = memory
            .apply_attachment(&plan, false, None)
            .await
            .expect_err("the port did not take the profile");
        assert_eq!(error.code, "connect.verify_mismatch");
        assert!(error.detail.contains("instead of"), "{}", error.detail);
        assert_eq!(port_of(&memory, 1).profile.as_deref(), Some("prof-home"));

        let plan = plan_of(&memory, id, &set_vlan(3, "net-iot")).await;
        let error = memory
            .apply_attachment(&plan, false, None)
            .await
            .expect_err("the override did not stick");
        assert_eq!(error.code, "connect.verify_mismatch");
        assert_eq!(memory.snapshot()[0].overrides, BTreeMap::new());
    }

    #[tokio::test]
    async fn a_revert_after_the_port_changed_again_is_refused() {
        let (memory, id) = rig();
        let receipt = write(&memory, id, &set_profile(1, "prof-iot")).await;
        // Someone gave the port another profile after the write.
        memory.update(id, |c| c.ports[0].profile = Some("prof-guest".to_owned()));
        let error = memory
            .revert_network(&receipt, None)
            .await
            .expect_err("changed again");
        assert_eq!(error.code, "connect.verify_mismatch");
        assert!(
            error.detail.contains("devices/sw-1/ports/1/profile"),
            "{}",
            error.detail
        );
        assert_eq!(port_of(&memory, 1).profile.as_deref(), Some("prof-guest"));
    }

    #[tokio::test]
    async fn a_revert_after_the_override_changed_again_is_refused() {
        let (memory, id) = rig();
        let receipt = write(&memory, id, &set_vlan(3, "net-iot")).await;
        memory.update(id, |c| {
            c.overrides.insert(mac(3), "net-home".to_owned());
        });
        let error = memory
            .revert_network(&receipt, None)
            .await
            .expect_err("changed again");
        assert_eq!(error.code, "connect.verify_mismatch");
        assert_eq!(
            memory.snapshot()[0].overrides,
            BTreeMap::from([(mac(3), "net-home".to_owned())])
        );
    }

    #[tokio::test]
    async fn fail_next_fails_exactly_one_attachments_call() {
        let (memory, id) = rig();
        memory.fail_next(CallKind::Attachments, unreachable());
        let error = memory.attachments(id, None).await.expect_err("fails");
        assert_eq!(error.code, "connect.unreachable");
        let state = memory
            .attachments(id, None)
            .await
            .expect("the next call works");
        assert_eq!(state.ports.len(), 4);
        assert_eq!(state.clients.len(), 5);
        assert_eq!(
            memory.calls(),
            [
                Call::Attachments { connector: id },
                Call::Attachments { connector: id }
            ]
        );
    }

    #[tokio::test]
    async fn every_attachment_call_can_be_made_to_fail_once() {
        let (memory, id) = rig();
        let change = set_profile(1, "prof-iot");
        memory.fail_next(CallKind::PlanAttachment, unreachable());
        assert!(memory.plan_attachment(id, &change, None).await.is_err());
        let plan = plan_of(&memory, id, &change).await;
        memory.fail_next(CallKind::AttachmentDryRun, unreachable());
        assert!(memory.apply_attachment(&plan, true, None).await.is_err());
        assert!(memory.apply_attachment(&plan, true, None).await.is_ok());
        // A failed write writes nothing, and the plan is still good.
        memory.fail_next(CallKind::AttachmentWrite, unreachable());
        assert!(memory.apply_attachment(&plan, false, None).await.is_err());
        assert_eq!(port_of(&memory, 1).profile.as_deref(), Some("prof-home"));
        let receipt = memory
            .apply_attachment(&plan, false, None)
            .await
            .expect("the next write works");
        memory.fail_next(CallKind::RevertAttachment, unreachable());
        assert!(memory.revert_network(&receipt, None).await.is_err());
        assert_eq!(port_of(&memory, 1).profile.as_deref(), Some("prof-iot"));
        memory.revert_network(&receipt, None).await.expect("revert");
        assert_eq!(port_of(&memory, 1).profile.as_deref(), Some("prof-home"));
    }

    #[tokio::test]
    async fn unknown_ports_profiles_clients_networks_and_controllers_are_not_found() {
        let (memory, id) = rig();
        for change in [
            set_profile(9, "prof-iot"),
            set_profile(1, "prof-none"),
            set_vlan(9, "net-iot"),
            set_vlan(3, "net-none"),
            AttachmentChange::ClearClientVlan { mac: mac(9) },
        ] {
            let error = memory
                .plan_attachment(id, &change, None)
                .await
                .expect_err("unknown");
            assert_eq!(error.code, "connect.not_found", "{change:?}");
            assert_eq!(error.status, 404);
        }
        let error = memory
            .attachments(ConnectorId::generate(), None)
            .await
            .expect_err("unknown controller");
        assert_eq!(error.code, "connect.instance.not_found");
    }
}
