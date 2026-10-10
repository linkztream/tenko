//! Plans, writes, read-back verification and undo of the L2 changes (CONN-06, CONN-08).
//!
//! Every change follows the same steps: read the part of the controller the change touches,
//! diff it against the change, and fingerprint what was read. A write re-reads, refuses a
//! plan whose fingerprint no longer matches, writes only in apply mode, reads back and
//! diffs again: the write is verified when that diff is empty. The receipt carries the undo
//! changes; reverting first checks that the controller still shows what the write left.
//!
//! | Change | Read | Write | Undo |
//! |---|---|---|---|
//! | `EnsureNetwork` | `rest/networkconf` | `POST rest/networkconf` (a `vlan-only` network) or `PUT rest/networkconf/<id>` (name, DHCP mode) | `RemoveNetwork`, or `EnsureNetwork` with the old name and DHCP mode |
//! | `SetPortProfile` | `stat/device`, `rest/portconf` | `PUT rest/device/<id>` with the whole `port_overrides` | `SetPortProfile` with the old profile |
//! | `SetClientVlan`, `ClearClientVlan` | `stat/user/<mac>`, `rest/networkconf` | `PUT rest/user/<id>` (`virtual_network_override_*`) | the opposite change |
//! | `RemoveNetwork` | `rest/networkconf` | `DELETE rest/networkconf/<id>` | `EnsureNetwork` with the old name and DHCP mode |

use std::{collections::HashMap, fmt::Write as _};

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tenko_connect::{
    ConnectorError, ControllerDhcp, DeviceRef, DiffLine, L2Change, L2Plan, L2Receipt, NetworkRef,
    ProfileRef, WriteMode,
};
use tenko_core::{MacAddr, Timestamp};

use crate::{
    classic::{Device, Network, Profile, Session, User},
    json as j,
    model::dhcp_of,
};

/// What a change touches, as read from the controller.
#[derive(Debug, Clone)]
enum State {
    /// `EnsureNetwork`: the network of the VLAN, and whether another network has the name.
    Network {
        existing: Option<Network>,
        name_taken: bool,
    },
    /// `SetPortProfile`: the device, the port's configured profile and the profile names.
    Port {
        device: Box<Device>,
        current: Option<String>,
        profiles: HashMap<String, String>,
    },
    /// `SetClientVlan` and `ClearClientVlan`: the client record and the network names.
    Client {
        user: User,
        networks: HashMap<String, String>,
    },
    /// `RemoveNetwork`: the network, when it still exists.
    Removal { existing: Option<Network> },
}

fn find_device(devices: Vec<Device>, device: &DeviceRef) -> Result<Device, ConnectorError> {
    let mac = j::parse_mac(&device.0).ok_or(ConnectorError::NotFound)?;
    devices
        .into_iter()
        .find(|d| d.mac == mac)
        .ok_or(ConnectorError::NotFound)
}

fn lan_names(networks: &[Network]) -> HashMap<String, String> {
    networks
        .iter()
        .filter(|n| n.is_lan())
        .map(|n| (n.id.clone(), n.name.clone()))
        .collect()
}

/// Reads what `change` touches. Fails for a change the controller cannot carry out.
async fn read(session: &mut Session, change: &L2Change) -> Result<State, ConnectorError> {
    match change {
        L2Change::EnsureNetwork { vlan, name, dhcp } => {
            if matches!(dhcp, ControllerDhcp::RelayTo(servers) if !servers.is_empty()) {
                // The classic API does not show relay targets per network, so a relay list
                // could not be verified after the write.
                return Err(ConnectorError::Unsupported);
            }
            let networks = session.networks().await?;
            let mut matching = networks
                .iter()
                .filter(|n| n.is_lan() && n.vlan == Some(*vlan));
            let existing = matching.next().cloned();
            if matching.next().is_some() {
                return Err(ConnectorError::invalid_settings(format!(
                    "several networks on the controller carry VLAN {vlan}"
                )));
            }
            let name_taken = networks.iter().any(|n| {
                Some(&n.id) != existing.as_ref().map(|e| &e.id)
                    && n.name.eq_ignore_ascii_case(name.trim())
            });
            Ok(State::Network {
                existing,
                name_taken,
            })
        }
        L2Change::SetPortProfile {
            device,
            port,
            profile,
        } => {
            let device = find_device(session.devices().await?, device)?;
            if !device.ports.iter().any(|p| p.idx == *port) {
                return Err(ConnectorError::NotFound);
            }
            let profiles: Vec<Profile> = session.profiles().await?;
            if !profiles.iter().any(|p| p.id == profile.0) {
                return Err(ConnectorError::NotFound);
            }
            Ok(State::Port {
                current: device.profile_of(*port),
                device: Box::new(device),
                profiles: profiles.into_iter().map(|p| (p.id, p.name)).collect(),
            })
        }
        L2Change::SetClientVlan { mac, network } => {
            let user = session.user(*mac).await?;
            if !user.supports_override {
                return Err(ConnectorError::Unsupported);
            }
            let networks = lan_names(&session.networks().await?);
            if !networks.contains_key(&network.0) {
                return Err(ConnectorError::NotFound);
            }
            Ok(State::Client { user, networks })
        }
        L2Change::ClearClientVlan { mac } => {
            let user = session.user(*mac).await?;
            if !user.supports_override {
                return Err(ConnectorError::Unsupported);
            }
            let networks = lan_names(&session.networks().await?);
            Ok(State::Client { user, networks })
        }
        L2Change::RemoveNetwork { network, vlan } => {
            let existing = session
                .networks()
                .await?
                .into_iter()
                .find(|n| n.id == network.0);
            if let Some(existing) = &existing {
                if existing.default || !existing.is_lan() {
                    return Err(ConnectorError::invalid_settings(
                        "the default network and WAN or VPN networks are never removed",
                    ));
                }
                if existing.vlan != Some(*vlan) {
                    return Err(ConnectorError::invalid_settings(format!(
                        "the network carries VLAN {} instead of {vlan}",
                        existing
                            .vlan
                            .map_or_else(|| "none".to_owned(), |v| v.to_string())
                    )));
                }
            }
            Ok(State::Removal { existing })
        }
    }
}

fn dhcp_text(dhcp: &ControllerDhcp) -> &'static str {
    match dhcp {
        ControllerDhcp::Disabled => "disabled",
        ControllerDhcp::RelayTo(_) => "relay",
        ControllerDhcp::Server => "server",
    }
}

fn line(path: String, before: Option<String>, after: Option<String>) -> DiffLine {
    DiffLine {
        path,
        before,
        after,
    }
}

fn named(names: &HashMap<String, String>, id: Option<&str>) -> Option<String> {
    id.map(|id| names.get(id).cloned().unwrap_or_else(|| id.to_owned()))
}

/// Diff lines and warnings of one change.
type Diff = (Vec<DiffLine>, Vec<String>);

/// What the change would alter, and English warnings for the preview.
fn diff(change: &L2Change, state: &State) -> Result<Diff, ConnectorError> {
    match (change, state) {
        (
            L2Change::EnsureNetwork { vlan, name, dhcp },
            State::Network {
                existing,
                name_taken,
            },
        ) => diff_network(*vlan, name.trim(), dhcp, existing.as_ref(), *name_taken),
        (
            L2Change::SetPortProfile { port, profile, .. },
            State::Port {
                device,
                current,
                profiles,
            },
        ) => Ok(diff_port(
            device,
            *port,
            profile,
            current.as_deref(),
            profiles,
        )),
        (L2Change::SetClientVlan { mac, network }, State::Client { user, networks }) => {
            Ok(diff_client(*mac, Some(network), user, networks))
        }
        (L2Change::ClearClientVlan { mac }, State::Client { user, networks }) => {
            Ok(diff_client(*mac, None, user, networks))
        }
        (L2Change::RemoveNetwork { vlan, .. }, State::Removal { existing }) => {
            let path = |field: &str| format!("networks/vlan-{vlan}/{field}");
            Ok((
                existing
                    .iter()
                    .flat_map(|network| {
                        [
                            line(path("name"), Some(network.name.clone()), None),
                            line(path("vlan"), Some(vlan.to_string()), None),
                        ]
                    })
                    .collect(),
                Vec::new(),
            ))
        }
        _ => Err(ConnectorError::PluginFailed(
            "a state of another change".to_owned(),
        )),
    }
}

fn diff_network(
    vlan: u16,
    name: &str,
    dhcp: &ControllerDhcp,
    existing: Option<&Network>,
    name_taken: bool,
) -> Result<Diff, ConnectorError> {
    let path = |field: &str| format!("networks/vlan-{vlan}/{field}");
    if name_taken {
        return Err(ConnectorError::invalid_settings(format!(
            "the controller has another network named `{name}`"
        )));
    }
    let mut lines = Vec::new();
    let mut warnings = Vec::new();
    let Some(network) = existing else {
        if *dhcp != ControllerDhcp::Disabled {
            return Err(ConnectorError::invalid_settings(
                "a new network gets neither a DHCP server nor a DHCP relay from the plugin: it is created as a VLAN-only network",
            ));
        }
        lines.push(line(path("name"), None, Some(name.to_owned())));
        lines.push(line(path("vlan"), None, Some(vlan.to_string())));
        lines.push(line(path("purpose"), None, Some("vlan-only".to_owned())));
        lines.push(line(path("dhcp"), None, Some("disabled".to_owned())));
        warnings.push(format!(
            "VLAN {vlan} is created as a VLAN-only network: the controller neither routes it nor serves DHCP on it"
        ));
        return Ok((lines, warnings));
    };
    if network.name != name {
        lines.push(line(
            path("name"),
            Some(network.name.clone()),
            Some(name.to_owned()),
        ));
    }
    let current = network.dhcp_text();
    let wanted = dhcp_text(dhcp);
    if current != wanted {
        if network.purpose == "vlan-only" {
            return Err(ConnectorError::invalid_settings(
                "a VLAN-only network has no DHCP on the controller",
            ));
        }
        lines.push(line(
            path("dhcp"),
            Some(current.to_owned()),
            Some(wanted.to_owned()),
        ));
        if current == "server" {
            warnings.push(format!(
                "the controller stops serving DHCP on VLAN {vlan}: clients there get no address until another DHCP server answers"
            ));
        }
    }
    Ok((lines, warnings))
}

fn diff_port(
    device: &Device,
    port: u16,
    profile: &ProfileRef,
    current: Option<&str>,
    profiles: &HashMap<String, String>,
) -> Diff {
    let mut lines = Vec::new();
    let mut warnings = Vec::new();
    if current != Some(profile.0.as_str()) {
        lines.push(line(
            format!("devices/{}/ports/{port}/profile", device.mac),
            named(profiles, current),
            named(profiles, Some(&profile.0)),
        ));
        if device.ports.iter().any(|p| p.idx == port && p.up) {
            warnings.push(format!(
                "the device on port {port} loses its link for a moment while the switch applies the profile"
            ));
        }
        if current.is_none() {
            warnings.push(
                "the port has no profile on record, so the receipt carries no undo step".to_owned(),
            );
        }
    }
    (lines, warnings)
}

/// The diff of putting a client into `network`, or of clearing its override (`None`).
fn diff_client(
    mac: MacAddr,
    network: Option<&NetworkRef>,
    user: &User,
    networks: &HashMap<String, String>,
) -> Diff {
    let wanted = network.map(|n| n.0.as_str());
    if user.override_network.as_deref() == wanted {
        return (Vec::new(), Vec::new());
    }
    let mut warnings = vec!["the client moves when it reconnects".to_owned()];
    if wanted.is_some() && user.wired == Some(true) {
        warnings.push(
            "the client is wired: its VLAN follows its switch port's profile, and the override takes effect only where the port allows it"
                .to_owned(),
        );
    }
    (
        vec![line(
            format!("clients/{mac}/network"),
            named(networks, user.override_network.as_deref()),
            named(networks, wanted),
        )],
        warnings,
    )
}

fn fingerprint(state: &State) -> String {
    let material = match state {
        State::Network {
            existing,
            name_taken,
        } => json!({
            "network": existing.as_ref().map(network_material),
            "name_taken": name_taken,
        }),
        State::Port {
            device, current, ..
        } => json!({
            "device": device.id,
            "overrides": device.overrides,
            "current": current,
        }),
        State::Client { user, .. } => json!({
            "user": user.id,
            "override": user.override_network,
        }),
        State::Removal { existing } => json!({
            "network": existing.as_ref().map(network_material),
        }),
    };
    let digest = Sha256::digest(material.to_string().as_bytes());
    digest[..16]
        .iter()
        .fold(String::with_capacity(32), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
}

fn network_material(network: &Network) -> Value {
    json!([
        network.id,
        network.name,
        network.purpose,
        network.vlan,
        network.dhcp_text()
    ])
}

/// Reads back, diffs and fingerprints a change. Writes nothing.
///
/// # Errors
///
/// The controller's error, [`ConnectorError::NotFound`] for an object that does not exist,
/// [`ConnectorError::Unsupported`] for a change this controller cannot verify, or
/// [`ConnectorError::InvalidSettings`] for a change it would refuse.
pub async fn plan(session: &mut Session, change: &L2Change) -> Result<L2Plan, ConnectorError> {
    let state = read(session, change).await?;
    let (diff, warnings) = diff(change, &state)?;
    Ok(L2Plan {
        change: change.clone(),
        read_at: Timestamp::now(),
        fingerprint: fingerprint(&state),
        diff,
        warnings,
    })
}

/// Writes what `state` lacks; returns the undo changes.
async fn write(
    session: &mut Session,
    change: &L2Change,
    state: &State,
) -> Result<Vec<L2Change>, ConnectorError> {
    match (change, state) {
        (L2Change::EnsureNetwork { vlan, name, dhcp }, State::Network { existing, .. }) => {
            write_network(session, *vlan, name.trim(), dhcp, existing.as_ref()).await
        }
        (
            L2Change::SetPortProfile {
                device: reference,
                port,
                profile,
            },
            State::Port {
                device, current, ..
            },
        ) => {
            write_port(session, device, *port, profile).await?;
            Ok(current
                .iter()
                .map(|previous| L2Change::SetPortProfile {
                    device: reference.clone(),
                    port: *port,
                    profile: ProfileRef(previous.clone()),
                })
                .collect())
        }
        (L2Change::SetClientVlan { mac, network }, State::Client { user, .. }) => {
            session
                .update_user(
                    &user.id,
                    &json!({
                        "virtual_network_override_enabled": true,
                        "virtual_network_override_id": network.0,
                    }),
                )
                .await?;
            Ok(vec![undo_client(*mac, user)])
        }
        (L2Change::ClearClientVlan { mac }, State::Client { user, .. }) => {
            session
                .update_user(
                    &user.id,
                    &json!({ "virtual_network_override_enabled": false }),
                )
                .await?;
            Ok(vec![undo_client(*mac, user)])
        }
        (L2Change::RemoveNetwork { vlan, .. }, State::Removal { existing }) => match existing {
            None => Ok(Vec::new()),
            Some(network) => {
                session.delete_network(&network.id).await?;
                Ok(vec![L2Change::EnsureNetwork {
                    vlan: *vlan,
                    name: network.name.clone(),
                    dhcp: dhcp_of(network),
                }])
            }
        },
        _ => Err(ConnectorError::PluginFailed(
            "a state of another change".to_owned(),
        )),
    }
}

async fn write_network(
    session: &mut Session,
    vlan: u16,
    name: &str,
    dhcp: &ControllerDhcp,
    existing: Option<&Network>,
) -> Result<Vec<L2Change>, ConnectorError> {
    let Some(network) = existing else {
        let id = session
            .create_network(&json!({
                "name": name,
                "purpose": "vlan-only",
                "vlan_enabled": true,
                "vlan": vlan,
                "enabled": true,
            }))
            .await?;
        return Ok(vec![L2Change::RemoveNetwork {
            network: NetworkRef(id),
            vlan,
        }]);
    };
    let mut body = serde_json::Map::new();
    if network.name != name {
        body.insert("name".to_owned(), json!(name));
    }
    if network.dhcp_text() != dhcp_text(dhcp) {
        let (server, relay) = match dhcp {
            ControllerDhcp::Disabled => (false, false),
            ControllerDhcp::Server => (true, false),
            ControllerDhcp::RelayTo(_) => (false, true),
        };
        body.insert("dhcpd_enabled".to_owned(), json!(server));
        body.insert("dhcp_relay_enabled".to_owned(), json!(relay));
    }
    session
        .update_network(&network.id, &Value::Object(body))
        .await?;
    Ok(vec![L2Change::EnsureNetwork {
        vlan,
        name: network.name.clone(),
        dhcp: dhcp_of(network),
    }])
}

/// Writes the device's port overrides back whole, with the profile of `port` replaced or
/// added; every other override stays as the controller had it.
async fn write_port(
    session: &mut Session,
    device: &Device,
    port: u16,
    profile: &ProfileRef,
) -> Result<(), ConnectorError> {
    let mut overrides = device.overrides.clone();
    match overrides
        .iter_mut()
        .find(|entry| j::u16(entry, "port_idx") == Some(port))
    {
        Some(Value::Object(entry)) => {
            entry.insert("portconf_id".to_owned(), json!(profile.0));
        }
        Some(_) => {
            return Err(ConnectorError::protocol(
                "a port override of the device is not an object",
            ));
        }
        None => overrides.push(json!({ "port_idx": port, "portconf_id": profile.0 })),
    }
    session.set_port_overrides(&device.id, &overrides).await
}

fn undo_client(mac: MacAddr, user: &User) -> L2Change {
    match &user.override_network {
        Some(previous) => L2Change::SetClientVlan {
            mac,
            network: NetworkRef(previous.clone()),
        },
        None => L2Change::ClearClientVlan { mac },
    }
}

/// Re-reads, refuses a stale plan, writes (apply mode only) and verifies by reading back.
///
/// # Errors
///
/// [`ConnectorError::VerifyMismatch`] for a stale plan, or the errors of [`plan`] and of
/// the write.
pub async fn apply(
    session: &mut Session,
    planned: &L2Plan,
    mode: WriteMode,
) -> Result<L2Receipt, ConnectorError> {
    let state = read(session, &planned.change).await?;
    if fingerprint(&state) != planned.fingerprint {
        return Err(ConnectorError::VerifyMismatch {
            diff: "the controller changed since the plan; plan the change again".to_owned(),
        });
    }
    let (lines, _) = diff(&planned.change, &state)?;
    if mode == WriteMode::DryRun || lines.is_empty() {
        return Ok(L2Receipt {
            plan: planned.clone(),
            mode,
            applied_at: Timestamp::now(),
            verified: true,
            undo: Vec::new(),
        });
    }
    let undo = write(session, &planned.change, &state).await?;
    let applied_at = Timestamp::now();
    let after = read(session, &planned.change).await?;
    let (remaining, _) = diff(&planned.change, &after)?;
    Ok(L2Receipt {
        plan: planned.clone(),
        mode,
        applied_at,
        verified: remaining.is_empty(),
        undo,
    })
}

/// Undoes an applied change: checks that the controller still shows what the write left,
/// then applies the undo changes in order, each verified by reading back.
///
/// # Errors
///
/// [`ConnectorError::VerifyMismatch`] when the controller changed since the write or an
/// undo step does not read back, or the errors of the reads and writes.
pub async fn revert(session: &mut Session, receipt: &L2Receipt) -> Result<(), ConnectorError> {
    if receipt.mode != WriteMode::Apply || receipt.undo.is_empty() {
        return Ok(());
    }
    let now = read(session, &receipt.plan.change).await?;
    let (drift, _) = diff(&receipt.plan.change, &now)?;
    if let Some(first) = drift.first() {
        return Err(ConnectorError::VerifyMismatch {
            diff: format!(
                "the controller changed since the write (`{}` is {}); undo it by hand",
                first.path,
                first.before.as_deref().unwrap_or("absent")
            ),
        });
    }
    for step in &receipt.undo {
        let state = read(session, step).await?;
        let (lines, _) = diff(step, &state)?;
        if lines.is_empty() {
            continue;
        }
        write(session, step, &state).await?;
        let after = read(session, step).await?;
        let (remaining, _) = diff(step, &after)?;
        if let Some(first) = remaining.first() {
            return Err(ConnectorError::VerifyMismatch {
                diff: format!(
                    "after the undo `{}` is {} instead of {}",
                    first.path,
                    first.before.as_deref().unwrap_or("absent"),
                    first.after.as_deref().unwrap_or("absent")
                ),
            });
        }
    }
    Ok(())
}
