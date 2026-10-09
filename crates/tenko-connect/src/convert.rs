//! Conversions between the domain types of this crate and the protocol messages.
//!
//! Domain to message never fails. Message to domain is strict for everything the host bases
//! a decision on (topology, plans, receipts, requests in the plugin): one malformed member
//! fails the whole message with [`ConvertError`], because a dropped port could hide an
//! uplink from the guardrails. Inventory hosts and migration items are lenient: a host
//! without an identifier is dropped and a malformed MAC or IP address is skipped, each
//! with a warning, and a migration item that does not convert becomes a loss entry.

use std::{collections::BTreeMap, net::IpAddr, str::FromStr};

use ipnet::IpNet;
use serde::{Serialize, de::DeserializeOwned};
use tenko_core::{
    ConnectorId, HostId, MacAddr, Timestamp, VrfId,
    ipam::{AssignmentMode, Status},
    ir::{Ir, IrAddress, IrHost, IrNetwork, IrVlan, LossEntry, LossReport, SourceLocation},
    net::{Duid, Fqdn, HostName},
    observe::{Endpoint, LinkKind, ObservedHost},
};
use zeroize::Zeroizing;

use crate::{
    ActuatorIntent, ActuatorPlan, ActuatorReceipt, CallContext, ClientAttachment, ConnectorError,
    ControllerDhcp, ControllerNetwork, Cursor, DeviceKind, DevicePort, DeviceRef, DiffLine, Health,
    HealthReport, InventoryBatch, L2Change, L2Plan, L2Receipt, MigrationArea, MigrationScope,
    NetworkDevice, NetworkRef, PortProfile, ProfileRef, Secrets, TopologyLink, TopologySnapshot,
    WirelessNetwork, WriteMode, proto::v1,
};

/// A message member that does not convert.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{path}: {message}")]
pub struct ConvertError {
    /// Where, for example `devices[2].ports[0].native_vlan`.
    pub path: String,
    /// Why.
    pub message: String,
}

impl ConvertError {
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }

    fn missing(path: &str) -> Self {
        Self::new(path, "is missing")
    }
}

impl From<ConvertError> for ConnectorError {
    fn from(error: ConvertError) -> Self {
        ConnectorError::Protocol(error.to_string())
    }
}

type Result<T> = std::result::Result<T, ConvertError>;

/// Longest identifier, name or tag the host accepts from a plugin, in bytes.
pub const MAX_TEXT: usize = 1024;

// ---------------------------------------------------------------------------------------
// Scalars.

/// A timestamp as a message.
pub fn timestamp_to_proto(at: Timestamp) -> prost_types::Timestamp {
    let nanos = at.unix_nanos();
    let seconds = nanos.div_euclid(1_000_000_000);
    let rest = nanos.rem_euclid(1_000_000_000);
    prost_types::Timestamp {
        seconds: i64::try_from(seconds).unwrap_or(i64::MAX),
        // The remainder is below 10^9, so it fits.
        nanos: i32::try_from(rest).unwrap_or(0),
    }
}

/// A timestamp from a message.
///
/// # Errors
///
/// [`ConvertError`] for a time outside the supported range or negative nanoseconds.
pub fn timestamp_from_proto(path: &str, at: &prost_types::Timestamp) -> Result<Timestamp> {
    if !(0..1_000_000_000).contains(&at.nanos) {
        return Err(ConvertError::new(path, "nanoseconds out of range"));
    }
    Timestamp::from_unix_nanos(i128::from(at.seconds) * 1_000_000_000 + i128::from(at.nanos))
        .map_err(|error| ConvertError::new(path, error.to_string()))
}

fn required_time(path: &str, at: Option<&prost_types::Timestamp>) -> Result<Timestamp> {
    timestamp_from_proto(path, at.ok_or_else(|| ConvertError::missing(path))?)
}

fn parse<T: FromStr>(path: &str, text: &str, what: &str) -> Result<T> {
    text.trim()
        .parse()
        .map_err(|_| ConvertError::new(path, format!("`{}` is not {what}", clip(text))))
}

fn mac(path: &str, text: &str) -> Result<MacAddr> {
    parse(path, text, "a MAC address")
}

fn ip(path: &str, text: &str) -> Result<IpAddr> {
    parse(path, text, "an IP address")
}

fn vlan(path: &str, value: u32) -> Result<u16> {
    match u16::try_from(value) {
        Ok(vid) if (1..=4094).contains(&vid) => Ok(vid),
        _ => Err(ConvertError::new(
            path,
            format!("{value} is not a VLAN id (1 to 4094)"),
        )),
    }
}

fn port(path: &str, value: u32) -> Result<u16> {
    u16::try_from(value)
        .map_err(|_| ConvertError::new(path, format!("{value} is not a port index")))
}

fn text(path: &str, value: String) -> Result<String> {
    if value.len() > MAX_TEXT {
        return Err(ConvertError::new(
            path,
            format!("is longer than {MAX_TEXT} bytes"),
        ));
    }
    Ok(value)
}

fn nonempty(path: &str, value: String) -> Result<String> {
    if value.trim().is_empty() {
        return Err(ConvertError::new(path, "is empty"));
    }
    text(path, value)
}

fn clip(value: &str) -> String {
    value.chars().take(64).collect()
}

/// A serde enum value by its `snake_case` name.
fn enum_from_name<T: DeserializeOwned>(path: &str, name: &str) -> Result<T> {
    serde_json::from_value(serde_json::Value::String(name.to_owned()))
        .map_err(|_| ConvertError::new(path, format!("`{}` is not a known value", clip(name))))
}

/// The `snake_case` name of a serde enum value.
fn enum_name<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => name,
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------------------------
// Call context and health.

/// The call context as a message.
pub fn context_to_proto(ctx: &CallContext) -> v1::CallContext {
    v1::CallContext {
        instance_id: ctx.instance.map(|id| id.to_string()).unwrap_or_default(),
        settings_json: ctx.settings.to_string(),
        secrets: ctx
            .secrets
            .iter()
            .map(|(purpose, value)| v1::Secret {
                purpose: purpose.to_owned(),
                value: value.to_vec(),
            })
            .collect(),
        request_id: ctx.request_id.clone(),
    }
}

/// The call context from a message; an absent context is an empty one.
///
/// # Errors
///
/// [`ConvertError`] for an instance that is not a UUID or settings that are not a JSON
/// object.
pub fn context_from_proto(context: Option<v1::CallContext>) -> Result<CallContext> {
    let Some(mut context) = context else {
        return Ok(CallContext::with_settings(serde_json::Value::Object(
            serde_json::Map::new(),
        )));
    };
    let instance = if context.instance_id.is_empty() {
        None
    } else {
        Some(parse::<ConnectorId>(
            "context.instance_id",
            &context.instance_id,
            "a UUID",
        )?)
    };
    let settings = if context.settings_json.trim().is_empty() {
        serde_json::Value::Object(serde_json::Map::new())
    } else {
        serde_json::from_str(&context.settings_json).map_err(|error| {
            ConvertError::new("context.settings_json", format!("not JSON: {error}"))
        })?
    };
    if !settings.is_object() {
        return Err(ConvertError::new(
            "context.settings_json",
            "is not a JSON object",
        ));
    }
    let mut secrets = Secrets::new();
    for secret in &mut context.secrets {
        // Move the value out; the message wipes what is left when it drops.
        let value = std::mem::take(&mut secret.value);
        secrets.insert(secret.purpose.clone(), Zeroizing::new(value));
    }
    Ok(CallContext {
        instance,
        settings,
        secrets,
        request_id: std::mem::take(&mut context.request_id),
    })
}

/// A health report as a message.
pub fn health_to_proto(report: &HealthReport) -> v1::CheckResponse {
    v1::CheckResponse {
        health: match report.health {
            Health::Healthy => v1::Health::Healthy,
            Health::Degraded => v1::Health::Degraded,
            Health::Unreachable => v1::Health::Unreachable,
        } as i32,
        latency_ms: report.latency_ms,
        remote_version: report.remote_version.clone(),
        detail: report.detail.clone(),
    }
}

/// A health report from a message, checked at `now`.
///
/// # Errors
///
/// [`ConvertError`] for an unspecified or unknown health.
pub fn health_from_proto(response: v1::CheckResponse, now: Timestamp) -> Result<HealthReport> {
    let health = match v1::Health::try_from(response.health) {
        Ok(v1::Health::Healthy) => Health::Healthy,
        Ok(v1::Health::Degraded) => Health::Degraded,
        Ok(v1::Health::Unreachable) => Health::Unreachable,
        _ => {
            return Err(ConvertError::new(
                "health",
                format!("{} is not a health value", response.health),
            ));
        }
    };
    Ok(HealthReport {
        health,
        checked_at: now,
        latency_ms: response.latency_ms,
        remote_version: response
            .remote_version
            .map(|value| text("remote_version", value))
            .transpose()?,
        detail: response
            .detail
            .map(|value| text("detail", value))
            .transpose()?,
    })
}

// ---------------------------------------------------------------------------------------
// Inventory.

/// An observed host as a message.
pub fn host_to_proto(host: &ObservedHost) -> v1::ObservedHost {
    v1::ObservedHost {
        external_id: host.external_id.clone(),
        name: host.name.clone(),
        macs: host.macs.iter().map(ToString::to_string).collect(),
        ips: host.ips.iter().map(ToString::to_string).collect(),
        os: host.os.clone(),
        platform: host.platform.clone(),
        parent: host.parent.clone(),
        tags: host.tags.clone(),
    }
}

/// An observed host from a message, leniently: `None` (with a warning) for a host without
/// an identifier or with an oversized one; malformed addresses and oversized texts are
/// skipped with a warning each.
pub fn host_from_proto(
    index: usize,
    host: v1::ObservedHost,
    warnings: &mut Vec<String>,
) -> Option<ObservedHost> {
    let at = format!("hosts[{index}]");
    let external_id = match nonempty(&format!("{at}.external_id"), host.external_id) {
        Ok(id) => id,
        Err(error) => {
            warnings.push(format!("{error}; the host is skipped"));
            return None;
        }
    };
    let mut keep = |field: &str, value: Option<String>| -> Option<String> {
        let value = value?;
        match text(&format!("{at}.{field}"), value) {
            Ok(value) if !value.trim().is_empty() => Some(value),
            Ok(_) => None,
            Err(error) => {
                warnings.push(format!("{error}; the value is skipped"));
                None
            }
        }
    };
    let name = keep("name", host.name);
    let os = keep("os", host.os);
    let platform = keep("platform", host.platform);
    let parent = keep("parent", host.parent);
    let mut macs = Vec::new();
    for (i, value) in host.macs.iter().enumerate() {
        match mac(&format!("{at}.macs[{i}]"), value) {
            Ok(mac) if !macs.contains(&mac) => macs.push(mac),
            Ok(_) => {}
            Err(error) => warnings.push(format!("{error}; the value is skipped")),
        }
    }
    let mut ips = Vec::new();
    for (i, value) in host.ips.iter().enumerate() {
        match ip(&format!("{at}.ips[{i}]"), value) {
            Ok(ip) if !ips.contains(&ip) => ips.push(ip),
            Ok(_) => {}
            Err(error) => warnings.push(format!("{error}; the value is skipped")),
        }
    }
    let mut tags: Vec<String> = Vec::new();
    for (i, tag) in host.tags.into_iter().enumerate() {
        match text(&format!("{at}.tags[{i}]"), tag) {
            Ok(tag) if !tag.trim().is_empty() && !tags.contains(&tag) => tags.push(tag),
            Ok(_) => {}
            Err(error) => warnings.push(format!("{error}; the value is skipped")),
        }
    }
    Some(ObservedHost {
        external_id,
        name,
        macs,
        ips,
        os,
        platform,
        parent,
        tags,
    })
}

/// An inventory batch as a message.
pub fn batch_to_proto(batch: &InventoryBatch) -> v1::PollResponse {
    v1::PollResponse {
        observed_at: Some(timestamp_to_proto(batch.observed_at)),
        hosts: batch.hosts.iter().map(host_to_proto).collect(),
        complete: batch.complete,
        cursor: batch.cursor.as_ref().map(|cursor| cursor.0.clone()),
        more: batch.more,
    }
}

/// An inventory batch from a message, leniently (see [`host_from_proto`]). A missing or
/// malformed observation time becomes `now`, with a warning for a malformed one.
pub fn batch_from_proto(
    response: v1::PollResponse,
    now: Timestamp,
) -> (InventoryBatch, Vec<String>) {
    let mut warnings = Vec::new();
    let observed_at = match response.observed_at.as_ref() {
        None => now,
        Some(at) => timestamp_from_proto("observed_at", at).unwrap_or_else(|error| {
            warnings.push(format!("{error}; the host clock is used"));
            now
        }),
    };
    let hosts = response
        .hosts
        .into_iter()
        .enumerate()
        .filter_map(|(index, host)| host_from_proto(index, host, &mut warnings))
        .collect();
    let batch = InventoryBatch {
        observed_at,
        hosts,
        complete: response.complete,
        cursor: response
            .cursor
            .filter(|cursor| !cursor.is_empty())
            .map(Cursor),
        more: response.more,
    };
    (batch, warnings)
}

// ---------------------------------------------------------------------------------------
// Network controllers.

/// Diff lines as messages.
pub fn diff_to_proto(diff: &[DiffLine]) -> Vec<v1::DiffLine> {
    diff.iter()
        .map(|line| v1::DiffLine {
            path: line.path.clone(),
            before: line.before.clone(),
            after: line.after.clone(),
        })
        .collect()
}

fn diff_from_proto(path: &str, diff: Vec<v1::DiffLine>) -> Result<Vec<DiffLine>> {
    diff.into_iter()
        .enumerate()
        .map(|(i, line)| {
            let at = format!("{path}[{i}]");
            Ok(DiffLine {
                path: text(&format!("{at}.path"), line.path)?,
                before: line
                    .before
                    .map(|value| text(&format!("{at}.before"), value))
                    .transpose()?,
                after: line
                    .after
                    .map(|value| text(&format!("{at}.after"), value))
                    .transpose()?,
            })
        })
        .collect()
}

/// A write mode as a message value.
pub fn mode_to_proto(mode: WriteMode) -> i32 {
    match mode {
        WriteMode::DryRun => v1::WriteMode::DryRun as i32,
        WriteMode::Apply => v1::WriteMode::Apply as i32,
    }
}

/// A write mode from a message value; anything but an explicit apply is a dry run.
pub fn mode_from_proto(mode: i32) -> WriteMode {
    if mode == v1::WriteMode::Apply as i32 {
        WriteMode::Apply
    } else {
        WriteMode::DryRun
    }
}

/// The DHCP mode of a controller network as a message.
pub fn dhcp_to_proto(dhcp: &ControllerDhcp) -> v1::ControllerDhcp {
    v1::ControllerDhcp {
        mode: Some(match dhcp {
            ControllerDhcp::Disabled => v1::controller_dhcp::Mode::Disabled(v1::DhcpDisabled {}),
            ControllerDhcp::RelayTo(servers) => v1::controller_dhcp::Mode::Relay(v1::DhcpRelay {
                servers: servers.iter().map(ToString::to_string).collect(),
            }),
        }),
    }
}

fn dhcp_from_proto(path: &str, dhcp: Option<v1::ControllerDhcp>) -> Result<ControllerDhcp> {
    match dhcp.and_then(|dhcp| dhcp.mode) {
        None => Err(ConvertError::missing(path)),
        Some(v1::controller_dhcp::Mode::Disabled(_)) => Ok(ControllerDhcp::Disabled),
        Some(v1::controller_dhcp::Mode::Relay(relay)) => Ok(ControllerDhcp::RelayTo(
            relay
                .servers
                .iter()
                .enumerate()
                .map(|(i, server)| ip(&format!("{path}.relay.servers[{i}]"), server))
                .collect::<Result<_>>()?,
        )),
    }
}

/// A change as a message.
pub fn change_to_proto(change: &L2Change) -> v1::L2Change {
    use v1::l2_change::Change;
    v1::L2Change {
        change: Some(match change {
            L2Change::EnsureNetwork { vlan, name, dhcp } => {
                Change::EnsureNetwork(v1::EnsureNetwork {
                    vlan: u32::from(*vlan),
                    name: name.clone(),
                    dhcp: Some(dhcp_to_proto(dhcp)),
                })
            }
            L2Change::SetPortProfile {
                device,
                port,
                profile,
            } => Change::SetPortProfile(v1::SetPortProfile {
                device: device.0.clone(),
                port: u32::from(*port),
                profile: profile.0.clone(),
            }),
            L2Change::SetClientVlan { mac, network } => Change::SetClientVlan(v1::SetClientVlan {
                mac: mac.to_string(),
                network: network.0.clone(),
            }),
            L2Change::ClearClientVlan { mac } => Change::ClearClientVlan(v1::ClearClientVlan {
                mac: mac.to_string(),
            }),
        }),
    }
}

/// A change from a message.
///
/// # Errors
///
/// [`ConvertError`] for a missing or malformed member.
pub fn change_from_proto(path: &str, change: Option<v1::L2Change>) -> Result<L2Change> {
    use v1::l2_change::Change;
    match change.and_then(|change| change.change) {
        None => Err(ConvertError::missing(path)),
        Some(Change::EnsureNetwork(ensure)) => Ok(L2Change::EnsureNetwork {
            vlan: vlan(&format!("{path}.vlan"), ensure.vlan)?,
            name: nonempty(&format!("{path}.name"), ensure.name)?,
            dhcp: dhcp_from_proto(&format!("{path}.dhcp"), ensure.dhcp)?,
        }),
        Some(Change::SetPortProfile(set)) => Ok(L2Change::SetPortProfile {
            device: DeviceRef(nonempty(&format!("{path}.device"), set.device)?),
            port: port(&format!("{path}.port"), set.port)?,
            profile: ProfileRef(nonempty(&format!("{path}.profile"), set.profile)?),
        }),
        Some(Change::SetClientVlan(set)) => Ok(L2Change::SetClientVlan {
            mac: mac(&format!("{path}.mac"), &set.mac)?,
            network: NetworkRef(nonempty(&format!("{path}.network"), set.network)?),
        }),
        Some(Change::ClearClientVlan(clear)) => Ok(L2Change::ClearClientVlan {
            mac: mac(&format!("{path}.mac"), &clear.mac)?,
        }),
    }
}

/// A plan as a message.
pub fn plan_to_proto(plan: &L2Plan) -> v1::L2Plan {
    v1::L2Plan {
        change: Some(change_to_proto(&plan.change)),
        read_at: Some(timestamp_to_proto(plan.read_at)),
        fingerprint: plan.fingerprint.clone(),
        diff: diff_to_proto(&plan.diff),
        warnings: plan.warnings.clone(),
    }
}

/// A plan from a message.
///
/// # Errors
///
/// [`ConvertError`] for a missing or malformed member.
pub fn plan_from_proto(path: &str, plan: Option<v1::L2Plan>) -> Result<L2Plan> {
    let plan = plan.ok_or_else(|| ConvertError::missing(path))?;
    Ok(L2Plan {
        change: change_from_proto(&format!("{path}.change"), plan.change)?,
        read_at: required_time(&format!("{path}.read_at"), plan.read_at.as_ref())?,
        fingerprint: text(&format!("{path}.fingerprint"), plan.fingerprint)?,
        diff: diff_from_proto(&format!("{path}.diff"), plan.diff)?,
        warnings: plan
            .warnings
            .into_iter()
            .enumerate()
            .map(|(i, warning)| text(&format!("{path}.warnings[{i}]"), warning))
            .collect::<Result<_>>()?,
    })
}

/// A receipt as a message.
pub fn receipt_to_proto(receipt: &L2Receipt) -> v1::L2Receipt {
    v1::L2Receipt {
        plan: Some(plan_to_proto(&receipt.plan)),
        mode: mode_to_proto(receipt.mode),
        applied_at: Some(timestamp_to_proto(receipt.applied_at)),
        verified: receipt.verified,
        undo: receipt.undo.iter().map(change_to_proto).collect(),
    }
}

/// A receipt from a message.
///
/// # Errors
///
/// [`ConvertError`] for a missing or malformed member.
pub fn receipt_from_proto(path: &str, receipt: Option<v1::L2Receipt>) -> Result<L2Receipt> {
    let receipt = receipt.ok_or_else(|| ConvertError::missing(path))?;
    Ok(L2Receipt {
        plan: plan_from_proto(&format!("{path}.plan"), receipt.plan)?,
        mode: mode_from_proto(receipt.mode),
        applied_at: required_time(&format!("{path}.applied_at"), receipt.applied_at.as_ref())?,
        verified: receipt.verified,
        undo: receipt
            .undo
            .into_iter()
            .enumerate()
            .map(|(i, change)| change_from_proto(&format!("{path}.undo[{i}]"), Some(change)))
            .collect::<Result<_>>()?,
    })
}

fn kind_to_proto(kind: DeviceKind) -> i32 {
    (match kind {
        DeviceKind::Switch => v1::DeviceKind::Switch,
        DeviceKind::AccessPoint => v1::DeviceKind::AccessPoint,
        DeviceKind::Gateway => v1::DeviceKind::Gateway,
        DeviceKind::Other => v1::DeviceKind::Other,
    }) as i32
}

fn kind_from_proto(kind: i32) -> DeviceKind {
    match v1::DeviceKind::try_from(kind) {
        Ok(v1::DeviceKind::Switch) => DeviceKind::Switch,
        Ok(v1::DeviceKind::AccessPoint) => DeviceKind::AccessPoint,
        Ok(v1::DeviceKind::Gateway) => DeviceKind::Gateway,
        _ => DeviceKind::Other,
    }
}

fn link_kind_to_proto(kind: LinkKind) -> i32 {
    (match kind {
        LinkKind::Lldp => v1::LinkKind::Lldp,
        LinkKind::Uplink => v1::LinkKind::Uplink,
        LinkKind::Wired => v1::LinkKind::Wired,
        LinkKind::Wireless => v1::LinkKind::Wireless,
    }) as i32
}

fn link_kind_from_proto(path: &str, kind: i32) -> Result<LinkKind> {
    match v1::LinkKind::try_from(kind) {
        Ok(v1::LinkKind::Lldp) => Ok(LinkKind::Lldp),
        Ok(v1::LinkKind::Uplink) => Ok(LinkKind::Uplink),
        Ok(v1::LinkKind::Wired) => Ok(LinkKind::Wired),
        Ok(v1::LinkKind::Wireless) => Ok(LinkKind::Wireless),
        _ => Err(ConvertError::new(
            path,
            format!("{kind} is not a link kind"),
        )),
    }
}

fn endpoint_to_proto(endpoint: &Endpoint) -> v1::Endpoint {
    v1::Endpoint {
        device: endpoint.device.clone(),
        port: endpoint.port.clone(),
    }
}

fn endpoint_from_proto(path: &str, endpoint: Option<v1::Endpoint>) -> Result<Endpoint> {
    let endpoint = endpoint.ok_or_else(|| ConvertError::missing(path))?;
    Ok(Endpoint {
        device: nonempty(&format!("{path}.device"), endpoint.device)?,
        port: endpoint
            .port
            .map(|port| text(&format!("{path}.port"), port))
            .transpose()?,
    })
}

/// A topology snapshot as a message.
pub fn topology_to_proto(topology: &TopologySnapshot) -> v1::Topology {
    v1::Topology {
        observed_at: Some(timestamp_to_proto(topology.observed_at)),
        devices: topology
            .devices
            .iter()
            .map(|device| v1::NetworkDevice {
                id: device.id.0.clone(),
                name: device.name.clone(),
                model: device.model.clone(),
                mac: device.mac.map(|mac| mac.to_string()),
                ip: device.ip.map(|ip| ip.to_string()),
                kind: kind_to_proto(device.kind),
                ports: device
                    .ports
                    .iter()
                    .map(|port| v1::DevicePort {
                        index: u32::from(port.index),
                        name: port.name.clone(),
                        profile: port.profile.as_ref().map(|profile| profile.0.clone()),
                        native_vlan: port.native_vlan.map(u32::from),
                        uplink: port.uplink,
                        up: port.up,
                    })
                    .collect(),
            })
            .collect(),
        links: topology
            .links
            .iter()
            .map(|link| v1::TopologyLink {
                a: Some(endpoint_to_proto(&link.a)),
                b: Some(endpoint_to_proto(&link.b)),
                kind: link_kind_to_proto(link.kind),
            })
            .collect(),
        clients: topology
            .clients
            .iter()
            .map(|client| v1::ClientAttachment {
                mac: client.mac.to_string(),
                ip: client.ip.map(|ip| ip.to_string()),
                device: client.device.0.clone(),
                port: client.port.map(u32::from),
                ssid: client.ssid.clone(),
                network: client.network.as_ref().map(|network| network.0.clone()),
                vlan: client.vlan.map(u32::from),
            })
            .collect(),
        networks: topology
            .networks
            .iter()
            .map(|network| v1::ControllerNetwork {
                id: network.id.0.clone(),
                name: network.name.clone(),
                vlan: network.vlan.map(u32::from),
                subnet: network.subnet.map(|subnet| subnet.to_string()),
                dhcp: Some(dhcp_to_proto(&network.dhcp)),
                management: network.management,
            })
            .collect(),
        profiles: topology
            .profiles
            .iter()
            .map(|profile| v1::PortProfile {
                id: profile.id.0.clone(),
                name: profile.name.clone(),
                native_network: profile.native_network.as_ref().map(|n| n.0.clone()),
                tagged: profile.tagged.iter().map(|n| n.0.clone()).collect(),
            })
            .collect(),
        wlans: topology
            .wlans
            .iter()
            .map(|wlan| v1::WirelessNetwork {
                id: wlan.id.clone(),
                ssid: wlan.ssid.clone(),
                network: wlan.network.as_ref().map(|n| n.0.clone()),
                vlan: wlan.vlan.map(u32::from),
                enabled: wlan.enabled,
                access_points: wlan.access_points.iter().map(|ap| ap.0.clone()).collect(),
            })
            .collect(),
    }
}

fn opt_text(path: &str, value: Option<String>) -> Result<Option<String>> {
    value.map(|value| text(path, value)).transpose()
}

/// A topology snapshot from a message, strictly.
///
/// # Errors
///
/// [`ConvertError`] naming the first malformed member.
#[allow(
    clippy::too_many_lines,
    reason = "one block per member of the message, in message order"
)]
pub fn topology_from_proto(topology: Option<v1::Topology>) -> Result<TopologySnapshot> {
    let topology = topology.ok_or_else(|| ConvertError::missing("topology"))?;
    let mut devices = Vec::with_capacity(topology.devices.len());
    for (d, device) in topology.devices.into_iter().enumerate() {
        let at = format!("devices[{d}]");
        let mut ports = Vec::with_capacity(device.ports.len());
        for (p, entry) in device.ports.into_iter().enumerate() {
            let pat = format!("{at}.ports[{p}]");
            ports.push(DevicePort {
                index: port(&format!("{pat}.index"), entry.index)?,
                name: opt_text(&format!("{pat}.name"), entry.name)?,
                profile: opt_text(&format!("{pat}.profile"), entry.profile)?.map(ProfileRef),
                native_vlan: entry
                    .native_vlan
                    .map(|v| vlan(&format!("{pat}.native_vlan"), v))
                    .transpose()?,
                uplink: entry.uplink,
                up: entry.up,
            });
        }
        devices.push(NetworkDevice {
            id: DeviceRef(nonempty(&format!("{at}.id"), device.id)?),
            name: text(&format!("{at}.name"), device.name)?,
            model: opt_text(&format!("{at}.model"), device.model)?,
            mac: device
                .mac
                .map(|value| mac(&format!("{at}.mac"), &value))
                .transpose()?,
            ip: device
                .ip
                .map(|value| ip(&format!("{at}.ip"), &value))
                .transpose()?,
            kind: kind_from_proto(device.kind),
            ports,
        });
    }
    let links = topology
        .links
        .into_iter()
        .enumerate()
        .map(|(i, link)| {
            let at = format!("links[{i}]");
            Ok(TopologyLink {
                a: endpoint_from_proto(&format!("{at}.a"), link.a)?,
                b: endpoint_from_proto(&format!("{at}.b"), link.b)?,
                kind: link_kind_from_proto(&format!("{at}.kind"), link.kind)?,
            })
        })
        .collect::<Result<_>>()?;
    let clients = topology
        .clients
        .into_iter()
        .enumerate()
        .map(|(i, client)| {
            let at = format!("clients[{i}]");
            Ok(ClientAttachment {
                mac: mac(&format!("{at}.mac"), &client.mac)?,
                ip: client
                    .ip
                    .map(|value| ip(&format!("{at}.ip"), &value))
                    .transpose()?,
                device: DeviceRef(nonempty(&format!("{at}.device"), client.device)?),
                port: client
                    .port
                    .map(|value| port(&format!("{at}.port"), value))
                    .transpose()?,
                ssid: opt_text(&format!("{at}.ssid"), client.ssid)?,
                network: opt_text(&format!("{at}.network"), client.network)?.map(NetworkRef),
                vlan: client
                    .vlan
                    .map(|value| vlan(&format!("{at}.vlan"), value))
                    .transpose()?,
            })
        })
        .collect::<Result<_>>()?;
    let networks = topology
        .networks
        .into_iter()
        .enumerate()
        .map(|(i, network)| {
            let at = format!("networks[{i}]");
            Ok(ControllerNetwork {
                id: NetworkRef(nonempty(&format!("{at}.id"), network.id)?),
                name: text(&format!("{at}.name"), network.name)?,
                vlan: network
                    .vlan
                    .map(|value| vlan(&format!("{at}.vlan"), value))
                    .transpose()?,
                subnet: network
                    .subnet
                    .map(|value| parse::<IpNet>(&format!("{at}.subnet"), &value, "a CIDR prefix"))
                    .transpose()?,
                dhcp: dhcp_from_proto(&format!("{at}.dhcp"), network.dhcp)?,
                management: network.management,
            })
        })
        .collect::<Result<_>>()?;
    let profiles = topology
        .profiles
        .into_iter()
        .enumerate()
        .map(|(i, profile)| {
            let at = format!("profiles[{i}]");
            Ok(PortProfile {
                id: ProfileRef(nonempty(&format!("{at}.id"), profile.id)?),
                name: text(&format!("{at}.name"), profile.name)?,
                native_network: opt_text(&format!("{at}.native_network"), profile.native_network)?
                    .map(NetworkRef),
                tagged: profile
                    .tagged
                    .into_iter()
                    .enumerate()
                    .map(|(t, network)| {
                        nonempty(&format!("{at}.tagged[{t}]"), network).map(NetworkRef)
                    })
                    .collect::<Result<_>>()?,
            })
        })
        .collect::<Result<_>>()?;
    let wlans = topology
        .wlans
        .into_iter()
        .enumerate()
        .map(|(i, wlan)| {
            let at = format!("wlans[{i}]");
            Ok(WirelessNetwork {
                id: nonempty(&format!("{at}.id"), wlan.id)?,
                ssid: text(&format!("{at}.ssid"), wlan.ssid)?,
                network: opt_text(&format!("{at}.network"), wlan.network)?.map(NetworkRef),
                vlan: wlan
                    .vlan
                    .map(|value| vlan(&format!("{at}.vlan"), value))
                    .transpose()?,
                enabled: wlan.enabled,
                access_points: wlan
                    .access_points
                    .into_iter()
                    .enumerate()
                    .map(|(a, ap)| nonempty(&format!("{at}.access_points[{a}]"), ap).map(DeviceRef))
                    .collect::<Result<_>>()?,
            })
        })
        .collect::<Result<_>>()?;
    Ok(TopologySnapshot {
        observed_at: required_time("observed_at", topology.observed_at.as_ref())?,
        devices,
        links,
        clients,
        networks,
        profiles,
        wlans,
    })
}

// ---------------------------------------------------------------------------------------
// Actuators.

/// An actuator intent as a message.
pub fn intent_to_proto(intent: &ActuatorIntent) -> v1::ActuatorIntent {
    use v1::actuator_intent::Intent;
    v1::ActuatorIntent {
        intent: Some(match intent {
            ActuatorIntent::DhcpReservation {
                vrf,
                ip,
                mac,
                duid,
                host,
            } => Intent::DhcpReservation(v1::DhcpReservation {
                vrf: vrf.to_string(),
                ip: ip.to_string(),
                mac: mac.map(|mac| mac.to_string()),
                duid: duid.as_ref().map(ToString::to_string),
                host: host.to_string(),
            }),
            ActuatorIntent::DhcpReservationRemove { vrf, ip } => {
                Intent::DhcpReservationRemove(v1::DhcpReservationRemove {
                    vrf: vrf.to_string(),
                    ip: ip.to_string(),
                })
            }
            ActuatorIntent::DnsRecords {
                name,
                addresses,
                ptr,
            } => Intent::DnsRecords(v1::DnsRecords {
                name: name.to_string(),
                addresses: addresses.iter().map(ToString::to_string).collect(),
                ptr: *ptr,
            }),
            ActuatorIntent::DnsRecordsRemove { name } => {
                Intent::DnsRecordsRemove(v1::DnsRecordsRemove {
                    name: name.to_string(),
                })
            }
            ActuatorIntent::GuestAddress { host, ip } => Intent::GuestAddress(v1::GuestAddress {
                host: host.to_string(),
                ip: ip.to_string(),
            }),
        }),
    }
}

/// An actuator intent from a message.
///
/// # Errors
///
/// [`ConvertError`] for a missing or malformed member.
pub fn intent_from_proto(path: &str, intent: Option<v1::ActuatorIntent>) -> Result<ActuatorIntent> {
    use v1::actuator_intent::Intent;
    let fqdn = |at: String, value: &str| -> Result<Fqdn> {
        Fqdn::new(value).map_err(|error| ConvertError::new(at, error.to_string()))
    };
    match intent.and_then(|intent| intent.intent) {
        None => Err(ConvertError::missing(path)),
        Some(Intent::DhcpReservation(r)) => Ok(ActuatorIntent::DhcpReservation {
            vrf: parse::<VrfId>(&format!("{path}.vrf"), &r.vrf, "a UUID")?,
            ip: ip(&format!("{path}.ip"), &r.ip)?,
            mac: r
                .mac
                .map(|value| mac(&format!("{path}.mac"), &value))
                .transpose()?,
            duid: r
                .duid
                .map(|value| parse::<Duid>(&format!("{path}.duid"), &value, "a DUID"))
                .transpose()?,
            host: parse::<HostId>(&format!("{path}.host"), &r.host, "a UUID")?,
        }),
        Some(Intent::DhcpReservationRemove(r)) => Ok(ActuatorIntent::DhcpReservationRemove {
            vrf: parse::<VrfId>(&format!("{path}.vrf"), &r.vrf, "a UUID")?,
            ip: ip(&format!("{path}.ip"), &r.ip)?,
        }),
        Some(Intent::DnsRecords(r)) => Ok(ActuatorIntent::DnsRecords {
            name: fqdn(format!("{path}.name"), &r.name)?,
            addresses: r
                .addresses
                .iter()
                .enumerate()
                .map(|(i, value)| ip(&format!("{path}.addresses[{i}]"), value))
                .collect::<Result<_>>()?,
            ptr: r.ptr,
        }),
        Some(Intent::DnsRecordsRemove(r)) => Ok(ActuatorIntent::DnsRecordsRemove {
            name: fqdn(format!("{path}.name"), &r.name)?,
        }),
        Some(Intent::GuestAddress(r)) => Ok(ActuatorIntent::GuestAddress {
            host: parse::<HostId>(&format!("{path}.host"), &r.host, "a UUID")?,
            ip: ip(&format!("{path}.ip"), &r.ip)?,
        }),
    }
}

/// An actuator plan as a message.
pub fn actuator_plan_to_proto(plan: &ActuatorPlan) -> v1::ActuatorPlan {
    v1::ActuatorPlan {
        intent: Some(intent_to_proto(&plan.intent)),
        read_at: Some(timestamp_to_proto(plan.read_at)),
        fingerprint: plan.fingerprint.clone(),
        diff: diff_to_proto(&plan.diff),
    }
}

/// An actuator plan from a message.
///
/// # Errors
///
/// [`ConvertError`] for a missing or malformed member.
pub fn actuator_plan_from_proto(
    path: &str,
    plan: Option<v1::ActuatorPlan>,
) -> Result<ActuatorPlan> {
    let plan = plan.ok_or_else(|| ConvertError::missing(path))?;
    Ok(ActuatorPlan {
        intent: intent_from_proto(&format!("{path}.intent"), plan.intent)?,
        read_at: required_time(&format!("{path}.read_at"), plan.read_at.as_ref())?,
        fingerprint: text(&format!("{path}.fingerprint"), plan.fingerprint)?,
        diff: diff_from_proto(&format!("{path}.diff"), plan.diff)?,
    })
}

/// An actuator receipt as a message.
pub fn actuator_receipt_to_proto(receipt: &ActuatorReceipt) -> v1::ActuatorReceipt {
    v1::ActuatorReceipt {
        plan: Some(actuator_plan_to_proto(&receipt.plan)),
        mode: mode_to_proto(receipt.mode),
        applied_at: Some(timestamp_to_proto(receipt.applied_at)),
        verified: receipt.verified,
    }
}

/// An actuator receipt from a message.
///
/// # Errors
///
/// [`ConvertError`] for a missing or malformed member.
pub fn actuator_receipt_from_proto(
    path: &str,
    receipt: Option<v1::ActuatorReceipt>,
) -> Result<ActuatorReceipt> {
    let receipt = receipt.ok_or_else(|| ConvertError::missing(path))?;
    Ok(ActuatorReceipt {
        plan: actuator_plan_from_proto(&format!("{path}.plan"), receipt.plan)?,
        mode: mode_from_proto(receipt.mode),
        applied_at: required_time(&format!("{path}.applied_at"), receipt.applied_at.as_ref())?,
        verified: receipt.verified,
    })
}

// ---------------------------------------------------------------------------------------
// Migration.

/// A migration scope as a message.
pub fn scope_to_proto(scope: &MigrationScope) -> v1::MigrationScope {
    v1::MigrationScope {
        areas: scope
            .areas
            .iter()
            .map(|area| {
                (match area {
                    MigrationArea::Ipam => v1::MigrationArea::Ipam,
                    MigrationArea::Dns => v1::MigrationArea::Dns,
                    MigrationArea::Dhcp => v1::MigrationArea::Dhcp,
                }) as i32
            })
            .collect(),
        zones: scope.zones.iter().map(ToString::to_string).collect(),
    }
}

/// A migration scope from a message.
///
/// # Errors
///
/// [`ConvertError`] for an unknown area or a malformed zone name.
pub fn scope_from_proto(scope: Option<v1::MigrationScope>) -> Result<MigrationScope> {
    let Some(scope) = scope else {
        return Ok(MigrationScope::default());
    };
    let mut areas = std::collections::BTreeSet::new();
    for (i, area) in scope.areas.iter().enumerate() {
        areas.insert(match v1::MigrationArea::try_from(*area) {
            Ok(v1::MigrationArea::Ipam) => MigrationArea::Ipam,
            Ok(v1::MigrationArea::Dns) => MigrationArea::Dns,
            Ok(v1::MigrationArea::Dhcp) => MigrationArea::Dhcp,
            _ => {
                return Err(ConvertError::new(
                    format!("scope.areas[{i}]"),
                    format!("{area} is not a migration area"),
                ));
            }
        });
    }
    let zones = scope
        .zones
        .iter()
        .enumerate()
        .map(|(i, zone)| {
            Fqdn::new(zone)
                .map_err(|error| ConvertError::new(format!("scope.zones[{i}]"), error.to_string()))
        })
        .collect::<Result<_>>()?;
    Ok(MigrationScope { areas, zones })
}

fn location_to_proto(location: &SourceLocation) -> v1::SourceLocation {
    v1::SourceLocation {
        sheet: location.sheet.clone(),
        row: location.row,
        column: location.column.clone(),
    }
}

fn location_from_proto(location: Option<v1::SourceLocation>) -> SourceLocation {
    location.map_or_else(SourceLocation::default, |location| SourceLocation {
        sheet: location.sheet,
        row: location.row,
        column: location.column,
    })
}

/// The items that stream an IR and its loss report: networks, VLANs, hosts, addresses, then
/// the loss entries.
pub fn ir_to_items(ir: &Ir, loss: &LossReport) -> Vec<v1::MigrationItem> {
    use v1::migration_item::Item;
    let mut items = Vec::new();
    for network in &ir.networks {
        items.push(Item::Network(v1::IrNetwork {
            cidr: network.cidr.to_string(),
            name: network.name.clone(),
            vlan: network.vlan.map(u32::from),
            site: network.site.clone(),
            status: network.status.as_ref().map(enum_name),
            description: network.description.clone(),
            tags: network.tags.clone(),
            custom: network.custom.clone(),
            origin: Some(location_to_proto(&network.origin)),
        }));
    }
    for vlan in &ir.vlans {
        items.push(Item::Vlan(v1::IrVlan {
            vid: u32::from(vlan.vid),
            name: vlan.name.clone(),
            site: vlan.site.clone(),
            description: vlan.description.clone(),
            origin: Some(location_to_proto(&vlan.origin)),
        }));
    }
    for host in &ir.hosts {
        items.push(Item::Host(v1::IrHost {
            name: host.name.to_string(),
            mode: host.mode.as_ref().map(enum_name),
            macs: host.macs.iter().map(ToString::to_string).collect(),
            site: host.site.clone(),
            description: host.description.clone(),
            tags: host.tags.clone(),
            custom: host.custom.clone(),
            origin: Some(location_to_proto(&host.origin)),
        }));
    }
    for address in &ir.addresses {
        items.push(Item::Address(v1::IrAddress {
            ip: address.ip.to_string(),
            dns_name: address.dns_name.as_ref().map(ToString::to_string),
            host: address.host.as_ref().map(ToString::to_string),
            mac: address.mac.map(|mac| mac.to_string()),
            status: address.status.as_ref().map(enum_name),
            description: address.description.clone(),
            tags: address.tags.clone(),
            custom: address.custom.clone(),
            origin: Some(location_to_proto(&address.origin)),
        }));
    }
    for entry in &loss.entries {
        items.push(Item::Loss(v1::LossEntry {
            location: Some(location_to_proto(&entry.location)),
            code: entry.code.to_string(),
            detail: entry.detail.clone(),
        }));
    }
    items
        .into_iter()
        .map(|item| v1::MigrationItem { item: Some(item) })
        .collect()
}

/// Assembles an IR and its loss report from streamed items. An item that does not convert
/// becomes a loss entry with the code `connect.migration.invalid_item`.
#[derive(Debug, Default)]
pub struct IrAssembler {
    ir: Ir,
    loss: LossReport,
}

/// The loss code of an item that does not convert.
pub const INVALID_ITEM: &str = "connect.migration.invalid_item";

impl IrAssembler {
    /// An empty assembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one streamed item.
    pub fn push(&mut self, item: v1::MigrationItem) {
        use v1::migration_item::Item;
        let Some(item) = item.item else {
            return;
        };
        let outcome = match item {
            Item::Network(network) => {
                let origin = location_from_proto(network.origin.clone());
                Self::network(network)
                    .map(|network| self.ir.networks.push(network))
                    .map_err(|error| (origin, error))
            }
            Item::Vlan(vlan_item) => {
                let origin = location_from_proto(vlan_item.origin.clone());
                vlan("vlan.vid", vlan_item.vid)
                    .map(|vid| {
                        self.ir.vlans.push(IrVlan {
                            vid,
                            name: vlan_item.name,
                            site: vlan_item.site,
                            description: vlan_item.description,
                            origin: location_from_proto(vlan_item.origin),
                        });
                    })
                    .map_err(|error| (origin, error))
            }
            Item::Host(host) => {
                let origin = location_from_proto(host.origin.clone());
                Self::host(host)
                    .map(|host| self.ir.hosts.push(host))
                    .map_err(|error| (origin, error))
            }
            Item::Address(address) => {
                let origin = location_from_proto(address.origin.clone());
                Self::address(address)
                    .map(|address| self.ir.addresses.push(address))
                    .map_err(|error| (origin, error))
            }
            Item::Loss(entry) => {
                self.loss.entries.push(LossEntry {
                    location: location_from_proto(entry.location),
                    code: entry.code.into(),
                    detail: entry.detail,
                });
                Ok(())
            }
        };
        if let Err((location, error)) = outcome {
            self.loss.push(location, INVALID_ITEM, error.to_string());
        }
    }

    /// The IR and the loss report.
    pub fn finish(self) -> (Ir, LossReport) {
        (self.ir, self.loss)
    }

    fn network(network: v1::IrNetwork) -> Result<IrNetwork> {
        Ok(IrNetwork {
            cidr: parse("network.cidr", &network.cidr, "a CIDR prefix")?,
            name: network.name,
            vlan: network
                .vlan
                .map(|value| vlan("network.vlan", value))
                .transpose()?,
            site: network.site,
            status: network
                .status
                .map(|status| enum_from_name::<Status>("network.status", &status))
                .transpose()?,
            description: network.description,
            tags: network.tags,
            custom: network.custom.into_iter().collect::<BTreeMap<_, _>>(),
            origin: location_from_proto(network.origin),
        })
    }

    fn host(host: v1::IrHost) -> Result<IrHost> {
        Ok(IrHost {
            name: HostName::new(&host.name)
                .map_err(|error| ConvertError::new("host.name", error.to_string()))?,
            mode: host
                .mode
                .map(|mode| enum_from_name::<AssignmentMode>("host.mode", &mode))
                .transpose()?,
            macs: host
                .macs
                .iter()
                .enumerate()
                .map(|(i, value)| mac(&format!("host.macs[{i}]"), value))
                .collect::<Result<_>>()?,
            site: host.site,
            description: host.description,
            tags: host.tags,
            custom: host.custom.into_iter().collect(),
            origin: location_from_proto(host.origin),
        })
    }

    fn address(address: v1::IrAddress) -> Result<IrAddress> {
        Ok(IrAddress {
            ip: ip("address.ip", &address.ip)?,
            dns_name: address
                .dns_name
                .map(|name| {
                    Fqdn::new(&name)
                        .map_err(|error| ConvertError::new("address.dns_name", error.to_string()))
                })
                .transpose()?,
            host: address
                .host
                .map(|name| {
                    HostName::new(&name)
                        .map_err(|error| ConvertError::new("address.host", error.to_string()))
                })
                .transpose()?,
            mac: address
                .mac
                .map(|value| mac("address.mac", &value))
                .transpose()?,
            status: address
                .status
                .map(|status| enum_from_name::<Status>("address.status", &status))
                .transpose()?,
            description: address.description,
            tags: address.tags,
            custom: address.custom.into_iter().collect(),
            origin: location_from_proto(address.origin),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::ProtectedPath;

    fn at(text: &str) -> Timestamp {
        text.parse().expect("time")
    }

    #[test]
    fn timestamps_round_trip_including_before_1970() {
        for text in ["2026-10-09T12:00:00.123456789Z", "1960-01-01T00:00:00.5Z"] {
            let time = at(text);
            let message = timestamp_to_proto(time);
            assert!((0..1_000_000_000).contains(&message.nanos));
            assert_eq!(timestamp_from_proto("t", &message).expect("time"), time);
        }
        let bad = prost_types::Timestamp {
            seconds: 0,
            nanos: -1,
        };
        assert!(timestamp_from_proto("t", &bad).is_err());
    }

    #[test]
    fn inventory_hosts_are_lenient() {
        let response = v1::PollResponse {
            observed_at: Some(timestamp_to_proto(at("2026-10-09T12:00:00Z"))),
            hosts: vec![
                v1::ObservedHost {
                    external_id: "qemu/100".to_owned(),
                    name: Some("web01.example.test".to_owned()),
                    macs: vec![
                        "00-00-5E-00-53-10".to_owned(),
                        "not-a-mac".to_owned(),
                        "00:00:5e:00:53:10".to_owned(),
                    ],
                    ips: vec![
                        "192.0.2.10".to_owned(),
                        "2001:db8::10".to_owned(),
                        "x".to_owned(),
                    ],
                    tags: vec!["a".to_owned(), "a".to_owned(), String::new()],
                    ..v1::ObservedHost::default()
                },
                v1::ObservedHost {
                    external_id: "  ".to_owned(),
                    ..v1::ObservedHost::default()
                },
            ],
            complete: true,
            cursor: Some(String::new()),
            more: false,
        };
        let (batch, warnings) = batch_from_proto(response, Timestamp::now());
        assert_eq!(batch.hosts.len(), 1);
        let host = &batch.hosts[0];
        assert_eq!(
            host.macs,
            vec!["00:00:5e:00:53:10".parse::<MacAddr>().expect("mac")]
        );
        assert_eq!(host.ips.len(), 2);
        assert_eq!(host.tags, vec!["a".to_owned()]);
        assert_eq!(batch.cursor, None);
        assert_eq!(warnings.len(), 3, "{warnings:?}");
        assert!(warnings.iter().any(|w| w.contains("hosts[1].external_id")));
        // And back.
        let again = batch_to_proto(&batch);
        let (round, none) = batch_from_proto(again, Timestamp::now());
        assert_eq!(round, batch);
        assert_eq!(none, Vec::<String>::new());
    }

    fn topology() -> TopologySnapshot {
        TopologySnapshot {
            observed_at: at("2026-10-09T12:00:00Z"),
            devices: vec![NetworkDevice {
                id: DeviceRef("switch-a".to_owned()),
                name: "switch-a".to_owned(),
                model: Some("USW-24".to_owned()),
                mac: Some("00:00:5e:00:53:a0".parse().expect("mac")),
                ip: Some("192.0.2.2".parse().expect("ip")),
                kind: DeviceKind::Switch,
                ports: vec![DevicePort {
                    index: 1,
                    name: Some("uplink".to_owned()),
                    profile: Some(ProfileRef("all".to_owned())),
                    native_vlan: Some(1),
                    uplink: true,
                    up: true,
                }],
            }],
            links: vec![TopologyLink {
                a: Endpoint {
                    device: "switch-a".to_owned(),
                    port: Some("1".to_owned()),
                },
                b: Endpoint {
                    device: "gateway".to_owned(),
                    port: None,
                },
                kind: LinkKind::Uplink,
            }],
            clients: vec![ClientAttachment {
                mac: "00:00:5e:00:53:20".parse().expect("mac"),
                ip: Some("198.51.100.20".parse().expect("ip")),
                device: DeviceRef("switch-a".to_owned()),
                port: Some(7),
                ssid: None,
                network: Some(NetworkRef("lan".to_owned())),
                vlan: Some(20),
            }],
            networks: vec![ControllerNetwork {
                id: NetworkRef("lan".to_owned()),
                name: "LAN".to_owned(),
                vlan: Some(20),
                subnet: Some("198.51.100.0/24".parse().expect("net")),
                dhcp: ControllerDhcp::RelayTo(vec!["2001:db8::53".parse().expect("ip")]),
                management: true,
            }],
            profiles: vec![PortProfile {
                id: ProfileRef("all".to_owned()),
                name: "All".to_owned(),
                native_network: Some(NetworkRef("lan".to_owned())),
                tagged: vec![NetworkRef("iot".to_owned())],
            }],
            wlans: vec![WirelessNetwork {
                id: "w1".to_owned(),
                ssid: "lab.example.net".to_owned(),
                network: Some(NetworkRef("lan".to_owned())),
                vlan: Some(20),
                enabled: true,
                access_points: vec![DeviceRef("ap-a".to_owned())],
            }],
        }
    }

    #[test]
    fn topology_round_trips_and_is_strict() {
        let topology = topology();
        let message = topology_to_proto(&topology);
        assert_eq!(
            topology_from_proto(Some(message.clone())).expect("topology"),
            topology
        );
        let mut broken = message;
        broken.devices[0].ports[0].native_vlan = Some(5000);
        let error = topology_from_proto(Some(broken)).expect_err("strict");
        assert_eq!(error.path, "devices[0].ports[0].native_vlan");
        assert!(topology_from_proto(None).is_err());
        let _ = ProtectedPath::Vlan { vid: 1 };
    }

    #[test]
    fn plans_and_receipts_round_trip() {
        let plan = L2Plan {
            change: L2Change::SetClientVlan {
                mac: "00:00:5e:00:53:20".parse().expect("mac"),
                network: NetworkRef("iot".to_owned()),
            },
            read_at: at("2026-10-09T12:00:00Z"),
            fingerprint: "f1".to_owned(),
            diff: vec![DiffLine {
                path: "clients/00:00:5e:00:53:20/network".to_owned(),
                before: Some("lan".to_owned()),
                after: Some("iot".to_owned()),
            }],
            warnings: vec![],
        };
        assert_eq!(
            plan_from_proto("plan", Some(plan_to_proto(&plan))).expect("plan"),
            plan
        );
        let receipt = L2Receipt {
            plan: plan.clone(),
            mode: WriteMode::Apply,
            applied_at: at("2026-10-09T12:00:01Z"),
            verified: true,
            undo: vec![L2Change::ClearClientVlan {
                mac: "00:00:5e:00:53:20".parse().expect("mac"),
            }],
        };
        assert_eq!(
            receipt_from_proto("receipt", Some(receipt_to_proto(&receipt))).expect("receipt"),
            receipt
        );
        assert_eq!(mode_from_proto(0), WriteMode::DryRun);
        assert_eq!(mode_from_proto(99), WriteMode::DryRun);
        let ensure = L2Change::EnsureNetwork {
            vlan: 30,
            name: "IoT".to_owned(),
            dhcp: ControllerDhcp::Disabled,
        };
        assert_eq!(
            change_from_proto("c", Some(change_to_proto(&ensure))).expect("change"),
            ensure
        );
    }

    #[test]
    fn intents_round_trip() {
        let intents = [
            ActuatorIntent::DhcpReservation {
                vrf: VrfId::generate(),
                ip: "192.0.2.9".parse().expect("ip"),
                mac: Some("00:00:5e:00:53:09".parse().expect("mac")),
                duid: Some("00:01:00:01".parse().expect("duid")),
                host: HostId::generate(),
            },
            ActuatorIntent::DnsRecords {
                name: Fqdn::new("printer.example.test").expect("name"),
                addresses: vec!["2001:db8::9".parse().expect("ip")],
                ptr: true,
            },
            ActuatorIntent::GuestAddress {
                host: HostId::generate(),
                ip: "203.0.113.4".parse().expect("ip"),
            },
        ];
        for intent in intents {
            let plan = ActuatorPlan {
                intent,
                read_at: at("2026-10-09T12:00:00Z"),
                fingerprint: "x".to_owned(),
                diff: vec![],
            };
            let receipt = ActuatorReceipt {
                plan,
                mode: WriteMode::DryRun,
                applied_at: at("2026-10-09T12:00:00Z"),
                verified: false,
            };
            assert_eq!(
                actuator_receipt_from_proto("r", Some(actuator_receipt_to_proto(&receipt)))
                    .expect("receipt"),
                receipt
            );
        }
    }

    #[test]
    fn ir_streams_and_reassembles_with_losses() {
        let ir = Ir {
            networks: vec![IrNetwork {
                cidr: "192.0.2.0/24".parse().expect("net"),
                name: Some("LAN".to_owned()),
                vlan: Some(20),
                site: None,
                status: Some(Status::Active),
                description: None,
                tags: vec![],
                custom: BTreeMap::from([("owner".to_owned(), "lab".to_owned())]),
                origin: SourceLocation::default(),
            }],
            vlans: vec![],
            hosts: vec![IrHost {
                name: HostName::new("nas").expect("name"),
                mode: Some(AssignmentMode::Reserved),
                macs: vec!["00:00:5e:00:53:07".parse().expect("mac")],
                site: None,
                description: None,
                tags: vec![],
                custom: BTreeMap::new(),
                origin: SourceLocation::default(),
            }],
            addresses: vec![],
        };
        let mut loss = LossReport::default();
        loss.push(SourceLocation::default(), "migrate.sample.loss", "a loss");
        let mut items = ir_to_items(&ir, &loss);
        items.push(v1::MigrationItem {
            item: Some(v1::migration_item::Item::Address(v1::IrAddress {
                ip: "999.0.0.1".to_owned(),
                ..v1::IrAddress::default()
            })),
        });
        let mut assembler = IrAssembler::new();
        for item in items {
            assembler.push(item);
        }
        let (back, losses) = assembler.finish();
        assert_eq!(back, ir);
        assert_eq!(losses.entries.len(), 2);
        assert_eq!(losses.entries[1].code, INVALID_ITEM);
    }

    #[test]
    fn contexts_carry_settings_and_secrets() {
        let mut secrets = Secrets::new();
        secrets.insert("api_key", Zeroizing::new(b"k".to_vec()));
        let ctx = CallContext {
            instance: Some(ConnectorId::generate()),
            settings: serde_json::json!({ "url": "https://inventory.example.org" }),
            secrets,
            request_id: "r".to_owned(),
        };
        let back = context_from_proto(Some(context_to_proto(&ctx))).expect("context");
        assert_eq!(back.instance, ctx.instance);
        assert_eq!(back.settings, ctx.settings);
        assert_eq!(back.secret("api_key"), Some(&b"k"[..]));
        let bad = v1::CallContext {
            settings_json: "[1]".to_owned(),
            ..v1::CallContext::default()
        };
        assert!(context_from_proto(Some(bad)).is_err());
        assert!(
            context_from_proto(None)
                .expect("empty")
                .settings
                .is_object()
        );
    }

    #[test]
    fn health_converts() {
        let report = HealthReport {
            health: Health::Degraded,
            checked_at: at("2026-10-09T12:00:00Z"),
            latency_ms: Some(12),
            remote_version: Some("1.2".to_owned()),
            detail: Some("slow".to_owned()),
        };
        assert_eq!(
            health_from_proto(health_to_proto(&report), report.checked_at).expect("health"),
            report
        );
        assert!(health_from_proto(v1::CheckResponse::default(), Timestamp::now()).is_err());
    }
}
