//! Proxmox VE reference plugin: an inventory source of the nodes, virtual machines and
//! containers of a Proxmox VE cluster with their MAC and IP addresses (CONN-02, CONN-03),
//! built on the plugin SDK of `tenko-connect` and bundled in the `tenko` binary as
//! `tenko plugin run proxmox` (CONN-20, ADR 0012). It speaks the `tenko.connect.v1`
//! protocol like any third-party plugin and never runs inside the controller.
//!
//! It reads, with GET requests only and an API token (`PVEAPIToken=<id>=<secret>`):
//! `/version`, `/access/permissions` (health check), `/cluster/resources`,
//! `/cluster/status`, `/nodes/<node>/network`, the configuration of each guest, the guest
//! agent's `network-get-interfaces` of running virtual machines, the interfaces of running
//! containers, and the SDN vnets and zones. [`inventory`] turns the answers into hosts:
//! nodes as hypervisors (`node/<name>`), guests (`qemu/<vmid>`, `lxc/<vmid>`) with their node
//! as the parent, so the topology draws VM-to-host edges.
//!
//! Large clusters are read in pages of guests (setting `page_size`); every page reads
//! `/cluster/resources` again and continues after the last guest id of the page before, so
//! the plugin keeps no state between calls.

pub mod api;
pub mod inventory;
pub mod net;

use std::{collections::BTreeSet, fmt::Write as _, process::ExitCode, sync::Arc, time::Instant};

use futures::{StreamExt, stream};
use serde::Deserialize;
use serde_json::Value;
use tenko_connect::{
    CallContext, Connector, ConnectorError, Cursor, Health, HealthReport, InventoryBatch,
    InventorySource, Manifest,
    sdk::{
        Plugin,
        http::{self, Failure, TlsMode, TlsSettings},
    },
};
use tenko_core::Timestamp;

use crate::{
    api::{AGENT_TIMEOUT, Api, Fail, Reply},
    inventory::{Filter, Guest, GuestAnswers, Kind, Snapshot},
};

/// The plugin name.
pub const NAME: &str = "proxmox";

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-connect-proxmox";

/// The secret purpose of the API token's secret.
pub const SECRET: &str = "token_secret";

/// How many guests are asked about at the same time.
const CONCURRENCY: usize = 4;

/// Returns the version of this crate as declared in its manifest.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The settings of an instance (see [`manifest`] for the schema).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Base URL of the API, such as `https://pve.example.net:8006`.
    pub url: String,
    /// The API token id, `user@realm!name`.
    pub token_id: String,
    /// How the server certificate is checked.
    #[serde(default)]
    pub tls: TlsMode,
    /// The pinned certificate fingerprint.
    #[serde(default)]
    pub tls_fingerprint: Option<String>,
    /// The pinned certificate authority.
    #[serde(default)]
    pub tls_ca: Option<String>,
    /// An address to connect to instead of resolving the host of the URL.
    #[serde(default)]
    pub connect_address: Option<String>,
    /// Only these nodes.
    #[serde(default)]
    pub nodes: Vec<String>,
    /// Only guests in these pools.
    #[serde(default)]
    pub pools: Vec<String>,
    /// Report guests that are not running.
    #[serde(default = "yes")]
    pub include_stopped: bool,
    /// Report templates.
    #[serde(default)]
    pub include_templates: bool,
    /// Ask the guest agent of running virtual machines for their addresses.
    #[serde(default = "yes")]
    pub guest_agent: bool,
    /// Guests per page.
    #[serde(default = "default_page_size")]
    pub page_size: u16,
}

const fn yes() -> bool {
    true
}

const fn default_page_size() -> u16 {
    100
}

impl Settings {
    /// The TLS settings.
    pub fn tls(&self) -> TlsSettings {
        TlsSettings {
            mode: self.tls,
            fingerprint: self.tls_fingerprint.clone(),
            ca: self.tls_ca.clone(),
            connect_address: self.connect_address.clone(),
        }
    }

    /// The filter of nodes and guests.
    pub fn filter(&self) -> Filter {
        Filter {
            nodes: self.nodes.clone(),
            pools: self.pools.clone(),
            include_stopped: self.include_stopped,
            include_templates: self.include_templates,
        }
    }
}

/// The manifest of the plugin.
///
/// # Panics
///
/// Never: the manifest is a constant document checked by the tests.
pub fn manifest() -> Manifest {
    let mut properties = serde_json::json!({
        "url": {
            "type": "string",
            "format": "uri",
            "title": "API address",
            "description": "Base URL of the Proxmox VE API of one node of the cluster, with the port (8006 by default).",
            "examples": ["https://pve.example.net:8006"]
        },
        "token_id": {
            "type": "string",
            "title": "API token ID",
            "description": "The token as user@realm!name. Give the token the role PVEAuditor on / (read-only); the token secret is stored as a secret of the instance.",
            "pattern": "^[^\\s@!]+@[^\\s@!]+![A-Za-z][A-Za-z0-9._-]*$",
            "examples": ["tenko@pve!inventory"]
        },
        "nodes": {
            "type": "array",
            "title": "Nodes",
            "description": "Only these nodes and their guests; all nodes when empty.",
            "items": { "type": "string", "minLength": 1, "maxLength": 63 },
            "maxItems": 64,
            "uniqueItems": true
        },
        "pools": {
            "type": "array",
            "title": "Pools",
            "description": "Only guests in these pools; all guests when empty.",
            "items": { "type": "string", "minLength": 1, "maxLength": 64 },
            "maxItems": 64,
            "uniqueItems": true
        },
        "include_stopped": {
            "type": "boolean",
            "title": "Report stopped guests",
            "description": "Stopped guests are reported with the MAC and static addresses of their configuration.",
            "default": true
        },
        "include_templates": {
            "type": "boolean",
            "title": "Report templates",
            "default": false
        },
        "guest_agent": {
            "type": "boolean",
            "title": "Ask the guest agent",
            "description": "Read the addresses of running virtual machines from the QEMU guest agent (needs VM.GuestAgent.Audit on Proxmox VE 9, VM.Monitor on 8).",
            "default": true
        },
        "page_size": {
            "type": "integer",
            "title": "Guests per page",
            "minimum": 10,
            "maximum": 500,
            "default": 100
        }
    });
    if let Value::Object(map) = &mut properties {
        map.extend(http::settings_schema());
    }
    serde_json::from_value(serde_json::json!({
        "manifest_version": 1,
        "name": NAME,
        "version": version(),
        "description": "Reads the nodes, virtual machines and containers of a Proxmox VE cluster with their MAC and IP addresses, read-only through an API token.",
        "license": "LicenseRef-Proprietary",
        "protocol": [tenko_connect::PROTOCOL_VERSION],
        "capabilities": ["inventory"],
        "settings": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "title": "Proxmox VE",
            "properties": properties,
            "required": ["url", "token_id"],
            "additionalProperties": false
        },
        "secrets": [{
            "purpose": SECRET,
            "description": "The secret (a UUID) of the API token.",
            "required": true
        }],
        "network": [
            { "setting": "/url", "ports": [8006], "description": "The Proxmox VE API." },
            { "setting": "/connect_address", "ports": [8006], "description": "The address the API is reached at, when it is set." }
        ],
        "platforms": ["any"],
        "defaults": { "poll_interval_secs": 300, "call_timeout_secs": 60 }
    }))
    .unwrap_or_else(|error| unreachable!("the Proxmox manifest is a constant: {error}"))
}

/// Writes one log line to standard error with a level word and the request id.
fn log(level: &str, request_id: &str, message: &str) {
    if request_id.is_empty() {
        eprintln!("{level} {message}");
    } else {
        eprintln!("{level} [{request_id}] {message}");
    }
}

/// The Proxmox VE inventory source and health check.
#[derive(Debug, Clone, Copy, Default)]
pub struct Proxmox;

/// A failure of the transport as a health report: unreachable, with the cause and, for a
/// TLS failure, the fingerprint of the certificate the server presents.
async fn unreachable_report(api: &Api, failure: &Failure) -> HealthReport {
    let mut detail = failure.describe();
    if matches!(failure, Failure::Tls(_))
        && let Some(fingerprint) = api.web().presented_fingerprint().await
    {
        let _ = write!(
            detail,
            ". The server presents a certificate with the SHA-256 fingerprint {fingerprint}; compare it with the one Proxmox VE shows (node > System > Certificates) before pinning it"
        );
    }
    HealthReport {
        health: Health::Unreachable,
        checked_at: Timestamp::now(),
        latency_ms: None,
        remote_version: None,
        detail: Some(detail),
    }
}

/// The privileges the token holds anywhere, from `/access/permissions`.
fn privileges(permissions: &Value) -> BTreeSet<String> {
    let mut held = BTreeSet::new();
    if let Value::Object(paths) = permissions {
        for privileges in paths.values() {
            if let Value::Object(privileges) = privileges {
                for (name, granted) in privileges {
                    let granted = match granted {
                        Value::Number(n) => n.as_u64().is_some_and(|n| n != 0),
                        Value::Bool(b) => *b,
                        _ => false,
                    };
                    if granted {
                        held.insert(name.clone());
                    }
                }
            }
        }
    }
    held
}

/// The major version of a Proxmox VE version text.
fn major(version: &str) -> Option<u32> {
    version.split('.').next()?.trim().parse().ok()
}

#[async_trait::async_trait]
impl Connector for Proxmox {
    async fn check(&self, ctx: &CallContext) -> Result<HealthReport, ConnectorError> {
        let settings: Settings = ctx.settings()?;
        let api = Api::new(&settings, ctx.secret_str(SECRET)?)?;
        let started = Instant::now();
        let version = match api.fetch("/version", None).await {
            Err(Fail::Transport(failure)) => return Ok(unreachable_report(&api, &failure).await),
            Err(Fail::Answer(error)) => return Err(error),
            Ok(Reply::Status(status)) => return Err(api::status_error(status)),
            Ok(Reply::Data(data)) => data,
        };
        let latency = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let release = version
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut notes = api.web().notes();
        let mut degraded =
            settings.tls == TlsMode::Insecure && api.web().base().scheme() == "https";
        match api.get("/access/permissions").await {
            Ok(permissions) => {
                let held = privileges(&permissions);
                if !held.contains("VM.Audit") {
                    degraded = true;
                    notes.push("the token cannot see any guest (VM.Audit is missing); give the token the role PVEAuditor on /".to_owned());
                }
                if !held.contains("Sys.Audit") {
                    notes.push("node addresses are not read (Sys.Audit is missing)".to_owned());
                }
                let agent = if release.as_deref().and_then(major).is_some_and(|m| m >= 9) {
                    "VM.GuestAgent.Audit"
                } else {
                    "VM.Monitor"
                };
                if settings.guest_agent && !held.contains(agent) {
                    notes.push(format!(
                        "guest agent addresses are not read ({agent} is missing)"
                    ));
                }
                if !held.contains("SDN.Audit") {
                    notes.push("SDN vnets are not read (SDN.Audit is missing)".to_owned());
                }
            }
            Err(ConnectorError::Unauthorized) => return Err(ConnectorError::Unauthorized),
            Err(_) => notes.push("the token's privileges could not be read".to_owned()),
        }
        if settings.tls == TlsMode::Insecure {
            log(
                "WARN",
                &ctx.request_id,
                "certificate checks are off for this instance (tls = insecure)",
            );
        }
        Ok(HealthReport {
            health: if degraded {
                Health::Degraded
            } else {
                Health::Healthy
            },
            checked_at: Timestamp::now(),
            latency_ms: Some(latency),
            remote_version: release.map(|release| format!("Proxmox VE {release}")),
            detail: (!notes.is_empty()).then(|| notes.join("; ")),
        })
    }
}

/// The guest id a cursor continues after.
fn cursor_after(cursor: Option<&Cursor>) -> Result<Option<u32>, ConnectorError> {
    match cursor {
        None => Ok(None),
        Some(Cursor(text)) => text
            .strip_prefix("after:")
            .and_then(|vmid| vmid.parse().ok())
            .map(Some)
            .ok_or_else(|| ConnectorError::invalid_settings("unknown cursor")),
    }
}

/// Whether the configuration of a virtual machine enables the guest agent (`1`,
/// `enabled=1,...` or `1,fstrim_cloned_disks=1`).
fn agent_enabled(config: &Value) -> bool {
    config.get("agent").is_some_and(|agent| match agent {
        Value::Number(n) => n.as_u64() == Some(1),
        Value::String(text) => net::parse_properties(text)
            .iter()
            .any(|(key, value)| matches!((*key, *value), ("1", None) | ("enabled", Some("1")))),
        _ => false,
    })
}

/// What a page learned besides the hosts, for the log.
#[derive(Debug, Default)]
struct Notes {
    config_forbidden: u32,
    agent_forbidden: u32,
    agent_answers: u32,
}

/// Reads one guest: its configuration, and the live interfaces of a running guest. `None`
/// when the guest disappeared in the meantime.
async fn read_guest(
    api: &Api,
    guest: &Guest,
    node_online: bool,
    ask_agent: bool,
    notes: &std::sync::Mutex<Notes>,
) -> (String, Result<Option<GuestAnswers>, ConnectorError>) {
    let answers = read_guest_answers(api, guest, node_online, ask_agent, notes).await;
    (guest.external_id(), answers)
}

/// The answers about one guest; see [`read_guest`].
async fn read_guest_answers(
    api: &Api,
    guest: &Guest,
    node_online: bool,
    ask_agent: bool,
    notes: &std::sync::Mutex<Notes>,
) -> Result<Option<GuestAnswers>, ConnectorError> {
    let mut answers = GuestAnswers::default();
    if !node_online || !inventory::safe_name(&guest.node) {
        return Ok(Some(answers));
    }
    let base = format!(
        "/nodes/{}/{}/{}",
        guest.node,
        guest.kind.as_str(),
        guest.vmid
    );
    match api.fetch(&format!("{base}/config"), None).await? {
        Reply::Data(config) => answers.config = Some(config),
        Reply::Status(status) if status == reqwest::StatusCode::FORBIDDEN => {
            notes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .config_forbidden += 1;
        }
        Reply::Status(status) if status == reqwest::StatusCode::NOT_FOUND => return Ok(None),
        Reply::Status(status) => return Err(api::status_error(status)),
    }
    if !guest.running() {
        return Ok(Some(answers));
    }
    match guest.kind {
        Kind::Qemu => {
            let enabled = answers.config.as_ref().is_some_and(agent_enabled);
            if ask_agent && enabled {
                match api
                    .fetch(
                        &format!("{base}/agent/network-get-interfaces"),
                        Some(AGENT_TIMEOUT),
                    )
                    .await
                {
                    Ok(Reply::Data(agent)) => {
                        answers.agent = Some(agent);
                        notes
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .agent_answers += 1;
                    }
                    Ok(Reply::Status(status)) if status == reqwest::StatusCode::FORBIDDEN => {
                        notes
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .agent_forbidden += 1;
                    }
                    Ok(Reply::Status(status)) if status == reqwest::StatusCode::UNAUTHORIZED => {
                        return Err(ConnectorError::Unauthorized);
                    }
                    // Not running, not installed, timed out: no live addresses this time.
                    Ok(Reply::Status(_)) | Err(_) => {}
                }
            }
        }
        Kind::Lxc => {
            if let Ok(Reply::Data(interfaces)) = api
                .fetch(&format!("{base}/interfaces"), Some(AGENT_TIMEOUT))
                .await
            {
                answers.interfaces = Some(interfaces);
            }
        }
    }
    Ok(Some(answers))
}

/// A list answer, or nothing when the token may not read it or the endpoint does not
/// exist.
async fn optional_list(api: &Api, path: &str) -> Result<Vec<Value>, ConnectorError> {
    match api.fetch(path, None).await? {
        Reply::Data(Value::Array(list)) => Ok(list),
        Reply::Status(status) if status == reqwest::StatusCode::UNAUTHORIZED => {
            Err(ConnectorError::Unauthorized)
        }
        Reply::Data(_) | Reply::Status(_) => Ok(Vec::new()),
    }
}

/// Reads what the first page reports about the nodes: the version, `/cluster/status` and
/// the network configuration of each online node the filter keeps.
async fn read_nodes(
    api: &Api,
    filter: &Filter,
    snapshot: &mut Snapshot,
) -> Result<(), ConnectorError> {
    if let Reply::Data(version) = api.fetch("/version", None).await? {
        snapshot.version = version
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_owned);
    }
    snapshot.cluster_status = optional_list(api, "/cluster/status").await?;
    for node in inventory::nodes(&snapshot.resources, filter) {
        if node.online() && inventory::safe_name(&node.name) {
            let network = optional_list(api, &format!("/nodes/{}/network", node.name)).await?;
            snapshot.node_networks.insert(node.name.clone(), network);
        }
    }
    Ok(())
}

/// Reads the guests of a page, at most [`CONCURRENCY`] at a time, into the snapshot, and
/// returns the guests that still exist with what the reads found.
async fn read_guests(
    api: &Api,
    page: Vec<Guest>,
    ask_agent: bool,
    snapshot: &mut Snapshot,
) -> Result<(Vec<Guest>, Notes), ConnectorError> {
    let online: BTreeSet<String> = inventory::nodes(&snapshot.resources, &Filter::default())
        .into_iter()
        .filter(inventory::Node::online)
        .map(|node| node.name)
        .collect();
    let findings = std::sync::Mutex::new(Notes::default());
    let reads: Vec<_> = page
        .iter()
        .map(|guest| {
            read_guest(
                api,
                guest,
                online.contains(&guest.node),
                ask_agent,
                &findings,
            )
        })
        .collect();
    let read: Vec<(String, Result<Option<GuestAnswers>, ConnectorError>)> = stream::iter(reads)
        .buffer_unordered(CONCURRENCY)
        .collect()
        .await;
    let mut gone = BTreeSet::new();
    for (id, answers) in read {
        match answers? {
            Some(answers) => {
                snapshot.guests.insert(id, answers);
            }
            None => {
                gone.insert(id);
            }
        }
    }
    let page = page
        .into_iter()
        .filter(|guest| !gone.contains(&guest.external_id()))
        .collect();
    let notes = findings
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Ok((page, notes))
}

impl Notes {
    /// Logs what an operator should know about a page.
    fn log(&self, request_id: &str, hosts: usize, guests: usize, more: bool) {
        if self.config_forbidden > 0 {
            log(
                "WARN",
                request_id,
                &format!(
                    "{} guest configurations are not readable (VM.Audit missing on them)",
                    self.config_forbidden
                ),
            );
        }
        if self.agent_forbidden > 0 {
            log(
                "WARN",
                request_id,
                &format!(
                    "the guest agent of {} virtual machines is not readable (VM.GuestAgent.Audit on Proxmox VE 9, VM.Monitor on 8)",
                    self.agent_forbidden
                ),
            );
        }
        log(
            "INFO",
            request_id,
            &format!(
                "page with {hosts} hosts ({guests} guests, {} guest agent answers){}",
                self.agent_answers,
                if more { ", more follow" } else { "" }
            ),
        );
    }
}

impl Proxmox {
    async fn poll_page(
        ctx: &CallContext,
        cursor: Option<&Cursor>,
    ) -> Result<InventoryBatch, ConnectorError> {
        let settings: Settings = ctx.settings()?;
        if !(1..=500).contains(&settings.page_size) {
            return Err(ConnectorError::invalid_settings(
                "page_size must be 1 to 500",
            ));
        }
        let api = Api::new(&settings, ctx.secret_str(SECRET)?)?;
        if settings.tls == TlsMode::Insecure {
            log(
                "WARN",
                &ctx.request_id,
                "certificate checks are off for this instance (tls = insecure)",
            );
        }
        let after = cursor_after(cursor)?;
        let Value::Array(resources) = api.get("/cluster/resources").await? else {
            return Err(ConnectorError::protocol("/cluster/resources is not a list"));
        };
        let filter = settings.filter();
        let all = inventory::guests(&resources, &filter);
        let page: Vec<Guest> = all
            .iter()
            .filter(|guest| after.is_none_or(|after| guest.vmid > after))
            .take(usize::from(settings.page_size))
            .cloned()
            .collect();
        let last = page.last().map(|guest| guest.vmid);
        let more = last.is_some_and(|last| all.iter().any(|guest| guest.vmid > last));
        let mut snapshot = Snapshot {
            resources,
            ..Snapshot::default()
        };
        let first = after.is_none();
        if first {
            read_nodes(&api, &filter, &mut snapshot).await?;
        }
        if !page.is_empty() {
            snapshot.vnets = optional_list(&api, "/cluster/sdn/vnets").await?;
            snapshot.zones = optional_list(&api, "/cluster/sdn/zones").await?;
        }
        let (page, notes) = read_guests(&api, page, settings.guest_agent, &mut snapshot).await?;
        let hosts = inventory::hosts(&snapshot, &filter, &page, first);
        notes.log(&ctx.request_id, hosts.len(), page.len(), more);
        Ok(InventoryBatch {
            observed_at: Timestamp::now(),
            hosts,
            complete: true,
            cursor: if more {
                last.map(|last| Cursor(format!("after:{last}")))
            } else {
                None
            },
            more,
            vendors: Vec::new(),
        })
    }
}

#[async_trait::async_trait]
impl InventorySource for Proxmox {
    async fn poll(
        &self,
        ctx: &CallContext,
        cursor: Option<Cursor>,
    ) -> Result<InventoryBatch, ConnectorError> {
        let result = Self::poll_page(ctx, cursor.as_ref()).await;
        if let Err(error) = &result {
            log("WARN", &ctx.request_id, &format!("poll failed: {error}"));
        }
        result
    }
}

/// The plugin.
pub fn plugin() -> Plugin {
    let proxmox = Arc::new(Proxmox);
    Plugin::new(manifest(), proxmox.clone()).with_inventory(proxmox)
}

/// Runs the plugin on standard input and output and returns the exit status.
pub fn run_status() -> u8 {
    plugin().run_status()
}

/// The entry point of the `tenko-plugin-proxmox` executable.
pub fn main() -> ExitCode {
    ExitCode::from(run_status())
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
    fn the_manifest_is_valid_and_fills_defaults() {
        let manifest = manifest();
        manifest.validate().expect("valid");
        assert_eq!(manifest.name, NAME);
        assert!(manifest.supports_this_platform());
        let filled = manifest
            .validate_settings(&serde_json::json!({
                "url": "https://pve.example.test:8006",
                "token_id": "tenko@pve!inventory"
            }))
            .expect("settings");
        let settings: Settings = serde_json::from_value(filled).expect("settings");
        assert_eq!(settings.tls, TlsMode::System);
        assert!(settings.include_stopped);
        assert!(settings.guest_agent);
        assert_eq!(settings.page_size, 100);
        assert!(
            manifest
                .validate_settings(&serde_json::json!({
                    "url": "https://pve.example.test:8006",
                    "token_id": "not-a-token-id"
                }))
                .is_err()
        );
    }

    #[test]
    fn cursors_continue_after_a_guest_id() {
        assert_eq!(cursor_after(None).expect("none"), None);
        assert_eq!(
            cursor_after(Some(&Cursor("after:105".to_owned()))).expect("after"),
            Some(105)
        );
        assert!(cursor_after(Some(&Cursor("page:2".to_owned()))).is_err());
    }

    #[test]
    fn the_agent_flag_has_several_forms() {
        for (value, enabled) in [
            (serde_json::json!("1"), true),
            (serde_json::json!("enabled=1,fstrim_cloned_disks=1"), true),
            (serde_json::json!("1,type=virtio"), true),
            (serde_json::json!("0"), false),
            (serde_json::json!("enabled=0"), false),
            (serde_json::json!(1), true),
        ] {
            assert_eq!(
                agent_enabled(&serde_json::json!({ "agent": value })),
                enabled,
                "{value}"
            );
        }
        assert!(!agent_enabled(&serde_json::json!({})));
    }

    #[test]
    fn privileges_are_collected_over_paths() {
        let held = privileges(&serde_json::json!({
            "/": { "Sys.Audit": 1, "VM.Audit": 0 },
            "/vms": { "VM.Audit": 1 },
            "/x": "odd"
        }));
        assert_eq!(
            held.into_iter().collect::<Vec<_>>(),
            ["Sys.Audit", "VM.Audit"]
        );
        assert_eq!(major("9.1.6"), Some(9));
        assert_eq!(major("x"), None);
    }
}
