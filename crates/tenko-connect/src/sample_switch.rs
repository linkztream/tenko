//! The sample network controller: one switch and one access point in memory, for the host
//! tests and the conformance suite of the port bounce and the client kick (ADR 0028). It
//! contacts nothing and reports documentation data only (`192.0.2.0/24`, MAC addresses of
//! the RFC 7042 documentation block).
//!
//! The executable `tenko-plugin-sample` runs it with `--mode switch` (capabilities
//! `network_controller`, `port_bounce` and `client_kick`) or `--mode switch-plain` (only
//! `network_controller`, so the SDK refuses a bounce and a kick with `UNIMPLEMENTED`).
//!
//! The switch `00:00:5e:00:53:a0` has eight ports, each a case of the guardrails:
//!
//! | Port | What is on it |
//! |---|---|
//! | 1 | the uplink to the gateway |
//! | 2 | the controller (`00:00:5e:00:53:0a`), the management port |
//! | 3 | one wired client, `00:00:5e:00:53:13` |
//! | 4 | two wired clients, `00:00:5e:00:53:14` and `00:00:5e:00:53:15` |
//! | 5 | nothing: no link |
//! | 6 | the access point `00:00:5e:00:53:b0` |
//! | 7 | one client, `00:00:5e:00:53:17`, behind a dock: three learned MAC addresses |
//! | 8 | one wired client, `00:00:5e:00:53:18` |
//!
//! On the access point: the wireless client `00:00:5e:00:53:21` and Tenko's host
//! `00:00:5e:00:53:0b` (a management client).
//!
//! Settings: `ports_down` (ports that are switched off when the process starts) and
//! `stuck` (bringing a port up fails as if the controller were unreachable). The state lives
//! in the process, as a real controller's would, so a host test can follow a bounce through
//! the topology.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
};

use serde::Deserialize;
use tenko_core::{
    MacAddr, Timestamp,
    observe::{Endpoint, LinkKind},
};

use crate::{
    CallContext, ClientAttachment, Connector, ConnectorError, DeviceKind, DevicePort, DeviceRef,
    DiffLine, Health, HealthReport, L2Change, L2Plan, L2Receipt, NetworkController, NetworkDevice,
    TopologyLink, TopologySnapshot, WriteMode, manifest::Manifest, sdk::Plugin,
};

/// The plugin name.
pub const NAME: &str = "sample-switch";
/// The switch.
pub const SWITCH: &str = "00:00:5e:00:53:a0";
/// The access point.
pub const ACCESS_POINT: &str = "00:00:5e:00:53:b0";
/// The SSID of the access point.
pub const SSID: &str = "lab.example.test";
/// The ports of the switch.
pub const PORTS: u16 = 8;

/// The documentation MAC address `00:00:5e:00:53:<low>`.
pub fn mac(low: u8) -> MacAddr {
    MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, low])
}

/// The manifest; with `nudge`, it declares the port bounce and the client kick.
///
/// # Panics
///
/// Never: the manifest is a constant document checked by the tests.
pub fn manifest(nudge: bool) -> Manifest {
    let mut capabilities = vec!["network_controller"];
    if nudge {
        capabilities.extend(["port_bounce", "client_kick"]);
    }
    serde_json::from_value(serde_json::json!({
        "manifest_version": 1,
        "name": NAME,
        "version": crate::version(),
        "description": "Sample network controller: one switch and one access point in memory; for testing the plugin host.",
        "license": "LicenseRef-Proprietary",
        "protocol": [crate::PROTOCOL_VERSION],
        "capabilities": capabilities,
        "settings": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "ports_down": {
                    "type": "array",
                    "title": "Ports switched off at the start",
                    "items": { "type": "integer", "minimum": 1, "maximum": 8 },
                    "maxItems": 8,
                    "uniqueItems": true
                },
                "stuck": {
                    "type": "boolean",
                    "title": "Bringing a port up fails",
                    "default": false
                }
            },
            "additionalProperties": false
        },
        "platforms": ["any"]
    }))
    .unwrap_or_else(|error| unreachable!("the sample-switch manifest is a constant: {error}"))
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    #[serde(default)]
    ports_down: Vec<u16>,
    #[serde(default)]
    stuck: bool,
}

/// What the switch has switched on, from the first call on.
#[derive(Debug, Default)]
struct State {
    enabled: BTreeMap<u16, bool>,
    kicked: Vec<MacAddr>,
}

/// The sample switch.
#[derive(Debug, Default)]
pub struct SampleSwitch {
    state: Mutex<Option<State>>,
}

impl SampleSwitch {
    fn with_state<T>(&self, settings: &Settings, f: impl FnOnce(&mut State) -> T) -> T {
        let mut guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let state = guard.get_or_insert_with(|| State {
            enabled: (1..=PORTS)
                .map(|port| (port, !settings.ports_down.contains(&port)))
                .collect(),
            kicked: Vec::new(),
        });
        f(state)
    }
}

fn wired(low: u8, port: u16, management: bool) -> ClientAttachment {
    ClientAttachment {
        mac: mac(low),
        ip: Some(std::net::IpAddr::from([192, 0, 2, low])),
        device: DeviceRef(SWITCH.to_owned()),
        port: Some(port),
        ssid: None,
        network: None,
        vlan: Some(20),
        name: None,
        name_placeholder: false,
        vendor: None,
        management,
    }
}

fn wireless(low: u8, management: bool) -> ClientAttachment {
    ClientAttachment {
        port: None,
        ssid: Some(SSID.to_owned()),
        device: DeviceRef(ACCESS_POINT.to_owned()),
        ..wired(low, 0, management)
    }
}

fn clients() -> Vec<ClientAttachment> {
    vec![
        wired(0x0a, 2, true),
        wired(0x13, 3, false),
        wired(0x14, 4, false),
        wired(0x15, 4, false),
        wired(0x17, 7, false),
        wired(0x18, 8, false),
        wireless(0x21, false),
        wireless(0x0b, true),
    ]
}

fn topology(state: &State) -> TopologySnapshot {
    let clients = clients();
    let ports = (1..=PORTS)
        .map(|index| {
            let enabled = state.enabled.get(&index).copied().unwrap_or(true);
            let linked = index == 1 || index == 6 || clients.iter().any(|c| c.port == Some(index));
            DevicePort {
                index,
                name: Some(format!("port {index}")),
                profile: None,
                native_vlan: Some(20),
                uplink: index == 1,
                up: enabled && linked,
                management: index == 2,
                enabled: Some(enabled),
                learned_macs: (index == 7).then_some(3),
            }
        })
        .collect();
    TopologySnapshot {
        observed_at: Timestamp::now(),
        devices: vec![
            NetworkDevice {
                id: DeviceRef(SWITCH.to_owned()),
                name: "switch-a".to_owned(),
                model: Some("sample".to_owned()),
                mac: Some(mac(0xa0)),
                ip: Some(std::net::IpAddr::from([192, 0, 2, 2])),
                kind: DeviceKind::Switch,
                ports,
            },
            NetworkDevice {
                id: DeviceRef(ACCESS_POINT.to_owned()),
                name: "ap-a".to_owned(),
                model: Some("sample".to_owned()),
                mac: Some(mac(0xb0)),
                ip: Some(std::net::IpAddr::from([192, 0, 2, 3])),
                kind: DeviceKind::AccessPoint,
                ports: Vec::new(),
            },
        ],
        links: vec![TopologyLink {
            a: Endpoint {
                device: SWITCH.to_owned(),
                port: Some("6".to_owned()),
            },
            b: Endpoint {
                device: ACCESS_POINT.to_owned(),
                port: Some("1".to_owned()),
            },
            kind: LinkKind::Uplink,
        }],
        clients: state.kicked.iter().fold(clients, |mut clients, kicked| {
            // A kicked client is gone until it associates again.
            clients.retain(|c| c.mac != *kicked);
            clients
        }),
        networks: Vec::new(),
        profiles: Vec::new(),
        wlans: Vec::new(),
    }
}

fn port_of(device: &DeviceRef, port: u16) -> Result<(), ConnectorError> {
    if device.0 == SWITCH && (1..=PORTS).contains(&port) {
        Ok(())
    } else {
        Err(ConnectorError::NotFound)
    }
}

fn enabled_line(port: u16, before: bool) -> DiffLine {
    DiffLine {
        path: format!("devices/{SWITCH}/ports/{port}/enabled"),
        before: Some(before.to_string()),
        after: Some((!before).to_string()),
    }
}

/// The plan of `change` against `state`.
fn plan_of(state: &State, change: &L2Change) -> Result<L2Plan, ConnectorError> {
    let (diff, undo, fingerprint) = match change {
        L2Change::BouncePort { device, port, .. } => {
            port_of(device, *port)?;
            let enabled = state.enabled.get(port).copied().unwrap_or(true);
            (
                if enabled {
                    vec![enabled_line(*port, true)]
                } else {
                    Vec::new()
                },
                vec![L2Change::EnablePort {
                    device: device.clone(),
                    port: *port,
                    restore: r#"{"enabled":true}"#.to_owned(),
                }],
                format!("{port}:{enabled}"),
            )
        }
        L2Change::EnablePort { device, port, .. } => {
            port_of(device, *port)?;
            let enabled = state.enabled.get(port).copied().unwrap_or(true);
            (
                if enabled {
                    Vec::new()
                } else {
                    vec![enabled_line(*port, false)]
                },
                Vec::new(),
                format!("{port}:{enabled}"),
            )
        }
        L2Change::KickClient { mac } => {
            let client = clients()
                .into_iter()
                .find(|c| c.mac == *mac && !state.kicked.contains(mac))
                .filter(|c| c.ssid.is_some())
                .ok_or(ConnectorError::NotFound)?;
            (
                vec![DiffLine {
                    path: format!("clients/{mac}/association"),
                    before: client.ssid.clone(),
                    after: Some("reconnects".to_owned()),
                }],
                Vec::new(),
                format!("{mac}:{}", client.device),
            )
        }
        _ => return Err(ConnectorError::Unsupported),
    };
    Ok(L2Plan {
        change: change.clone(),
        read_at: Timestamp::now(),
        fingerprint,
        diff,
        warnings: Vec::new(),
        undo,
    })
}

#[async_trait::async_trait]
impl Connector for SampleSwitch {
    async fn check(&self, ctx: &CallContext) -> Result<HealthReport, ConnectorError> {
        let _: Settings = ctx.settings()?;
        Ok(HealthReport {
            health: Health::Healthy,
            checked_at: Timestamp::now(),
            latency_ms: Some(0),
            remote_version: Some(format!("sample-switch {}", crate::version())),
            detail: None,
        })
    }
}

#[async_trait::async_trait]
impl NetworkController for SampleSwitch {
    async fn topology(&self, ctx: &CallContext) -> Result<TopologySnapshot, ConnectorError> {
        let settings: Settings = ctx.settings()?;
        Ok(self.with_state(&settings, |state| topology(state)))
    }

    async fn plan(&self, ctx: &CallContext, change: &L2Change) -> Result<L2Plan, ConnectorError> {
        let settings: Settings = ctx.settings()?;
        self.with_state(&settings, |state| plan_of(state, change))
    }

    async fn apply(
        &self,
        ctx: &CallContext,
        plan: &L2Plan,
        mode: WriteMode,
    ) -> Result<L2Receipt, ConnectorError> {
        let settings: Settings = ctx.settings()?;
        self.with_state(&settings, |state| {
            let now = plan_of(state, &plan.change)?;
            if now.fingerprint != plan.fingerprint {
                return Err(ConnectorError::VerifyMismatch {
                    diff: "the switch changed since the plan".to_owned(),
                });
            }
            let mut receipt = L2Receipt {
                plan: plan.clone(),
                mode,
                applied_at: Timestamp::now(),
                verified: true,
                undo: Vec::new(),
            };
            if mode != WriteMode::Apply || now.diff.is_empty() {
                return Ok(receipt);
            }
            match &plan.change {
                L2Change::BouncePort { port, .. } => {
                    state.enabled.insert(*port, false);
                    receipt.undo.clone_from(&now.undo);
                }
                L2Change::EnablePort { port, .. } => {
                    if settings.stuck {
                        return Err(ConnectorError::Unreachable);
                    }
                    state.enabled.insert(*port, true);
                }
                L2Change::KickClient { mac } => state.kicked.push(*mac),
                _ => return Err(ConnectorError::Unsupported),
            }
            receipt.verified = matches!(plan.change, L2Change::KickClient { .. })
                || plan_of(state, &plan.change).is_ok_and(|after| after.diff.is_empty());
            Ok(receipt)
        })
    }

    async fn revert(&self, _ctx: &CallContext, _receipt: &L2Receipt) -> Result<(), ConnectorError> {
        Err(ConnectorError::Unsupported)
    }
}

/// The sample switch as an SDK plugin; with `nudge` it declares the bounce and the kick.
pub fn plugin(nudge: bool) -> Plugin {
    let switch = Arc::new(SampleSwitch::default());
    Plugin::new(manifest(nudge), switch.clone()).with_network_controller(switch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_manifests_are_valid() {
        manifest(true).validate().expect("valid");
        manifest(false).validate().expect("valid");
        assert!(manifest(true).has(crate::Capability::PortBounce));
        assert!(!manifest(false).has(crate::Capability::ClientKick));
    }

    #[test]
    fn a_bounce_plan_carries_its_way_back_up_and_a_bounce_takes_the_port_down() {
        let state = State {
            enabled: (1..=PORTS).map(|port| (port, true)).collect(),
            kicked: Vec::new(),
        };
        let bounce = L2Change::BouncePort {
            device: DeviceRef(SWITCH.to_owned()),
            port: 3,
            down_secs: 5,
        };
        let plan = plan_of(&state, &bounce).expect("plan");
        assert_eq!(plan.diff.len(), 1);
        assert!(matches!(
            plan.undo.as_slice(),
            [L2Change::EnablePort { port: 3, .. }]
        ));
        let snapshot = topology(&state);
        let port = &snapshot.devices[0].ports[2];
        assert!(port.up && port.enabled == Some(true));
        assert!(!snapshot.devices[0].ports[4].up, "port 5 has no link");
        let missing = L2Change::BouncePort {
            device: DeviceRef(ACCESS_POINT.to_owned()),
            port: 1,
            down_secs: 5,
        };
        assert_eq!(plan_of(&state, &missing), Err(ConnectorError::NotFound));
    }
}
