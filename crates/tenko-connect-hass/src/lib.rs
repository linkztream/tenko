//! Home Assistant reference plugin: an inventory source of the devices of the device
//! registry with their MAC and IP addresses, manufacturers and models (CONN-02, CONN-04),
//! built on the plugin SDK of `tenko-connect` and bundled in the `tenko` binary as
//! `tenko plugin run hass` (CONN-20, ADR 0012). It speaks the `tenko.connect.v1` protocol
//! like any third-party plugin and never runs inside the controller.
//!
//! It reads, with a long-lived access token: `GET /api/` and `GET /api/config` (health
//! check), `GET /api/states`, and over the WebSocket API (`/api/websocket`) the list commands
//! `config/device_registry/list`, `config/entity_registry/list`,
//! `config/area_registry/list` and `config_entries/get` (the last one needs an
//! administrator; without it the integration of a device comes from its entities).
//! [`inventory`] turns the answers into hosts and vendor facts. It never calls a service and
//! never writes anything.

pub mod api;
pub mod inventory;
pub mod ws;

use std::{fmt::Write as _, process::ExitCode, sync::Arc, time::Instant};

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
    api::{Api, Fail},
    inventory::{Options, Snapshot},
};

/// The plugin name.
pub const NAME: &str = "hass";

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-connect-hass";

/// The secret purpose of the long-lived access token.
pub const SECRET: &str = "access_token";

/// Hosts per page.
pub const PAGE_SIZE: usize = 500;

/// Returns the version of this crate as declared in its manifest.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The settings of an instance (see [`manifest`] for the schema).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the flat settings schema of the manifest, one switch each"
)]
pub struct Settings {
    /// Base URL, such as `http://homeassistant.example.net:8123`.
    pub url: String,
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
    /// Read addresses from entity states and attributes.
    #[serde(default = "yes")]
    pub entity_addresses: bool,
    /// Report globally routable IPv4 addresses that entities show.
    #[serde(default)]
    pub public_ipv4: bool,
    /// Report disabled devices.
    #[serde(default)]
    pub include_disabled: bool,
    /// Report device trackers that belong to no device.
    #[serde(default = "yes")]
    pub device_trackers: bool,
    /// Only devices of these integrations.
    #[serde(default)]
    pub integrations: Vec<String>,
    /// Never devices of these integrations.
    #[serde(default)]
    pub exclude_integrations: Vec<String>,
}

const fn yes() -> bool {
    true
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

    /// What the inventory reports.
    pub fn options(&self) -> Options {
        Options {
            entity_addresses: self.entity_addresses,
            public_ipv4: self.public_ipv4,
            include_disabled: self.include_disabled,
            device_trackers: self.device_trackers,
            integrations: self.integrations.clone(),
            exclude_integrations: self.exclude_integrations.clone(),
            ..Options::default()
        }
    }
}

/// The manifest of the plugin.
///
/// # Panics
///
/// Never: the manifest is a constant document checked by the tests.
pub fn manifest() -> Manifest {
    let integrations = |title: &str, description: &str| {
        serde_json::json!({
            "type": "array",
            "title": title,
            "description": description,
            "items": { "type": "string", "minLength": 1, "maxLength": 64, "pattern": "^[a-z0-9_]+$" },
            "maxItems": 64,
            "uniqueItems": true
        })
    };
    let mut properties = serde_json::json!({
        "url": {
            "type": "string",
            "format": "uri",
            "title": "Home Assistant address",
            "description": "Base URL of Home Assistant, with the port (8123 by default).",
            "examples": ["http://homeassistant.example.net:8123"]
        },
        "entity_addresses": {
            "type": "boolean",
            "title": "Addresses from entities",
            "description": "Read IP and MAC addresses that entities show as their state or in ip, ip_address, host, mac and mac_address attributes.",
            "default": true
        },
        "public_ipv4": {
            "type": "boolean",
            "title": "Report public IPv4 addresses",
            "description": "Also report globally routable IPv4 addresses that entities show; usually the internet address of a router.",
            "default": false
        },
        "include_disabled": {
            "type": "boolean",
            "title": "Report disabled devices",
            "default": false
        },
        "device_trackers": {
            "type": "boolean",
            "title": "Report device trackers without a device",
            "description": "Device tracker entities with an IP or MAC address that belong to no device become hosts of their own.",
            "default": true
        },
        "integrations": integrations("Integrations", "Only devices of these integrations (domains such as esphome or shelly); all when empty."),
        "exclude_integrations": integrations("Excluded integrations", "Never devices of these integrations, for example one that duplicates another connector.")
    });
    if let Value::Object(map) = &mut properties {
        map.extend(http::settings_schema());
    }
    serde_json::from_value(serde_json::json!({
        "manifest_version": 1,
        "name": NAME,
        "version": version(),
        "description": "Reads the devices of the Home Assistant device registry with their MAC and IP addresses, manufacturers and models, read-only through a long-lived access token.",
        "license": "LicenseRef-Proprietary",
        "protocol": [tenko_connect::PROTOCOL_VERSION],
        "capabilities": ["inventory"],
        "settings": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "title": "Home Assistant",
            "properties": properties,
            "required": ["url"],
            "additionalProperties": false
        },
        "secrets": [{
            "purpose": SECRET,
            "description": "A long-lived access token of a Home Assistant user (Profile > Security).",
            "required": true
        }],
        "network": [
            { "setting": "/url", "ports": [8123], "description": "The Home Assistant REST and WebSocket API." },
            { "setting": "/connect_address", "ports": [8123], "description": "The address Home Assistant is reached at, when it is set." }
        ],
        "platforms": ["any"],
        "defaults": { "poll_interval_secs": 300, "call_timeout_secs": 60 }
    }))
    .unwrap_or_else(|error| unreachable!("the Home Assistant manifest is a constant: {error}"))
}

/// Writes one log line to standard error with a level word and the request id.
fn log(level: &str, request_id: &str, message: &str) {
    if request_id.is_empty() {
        eprintln!("{level} {message}");
    } else {
        eprintln!("{level} [{request_id}] {message}");
    }
}

/// The Home Assistant inventory source and health check.
#[derive(Debug, Clone, Copy, Default)]
pub struct HomeAssistant;

/// A failure of the transport as a health report: unreachable, with the cause and, for a
/// TLS failure, the fingerprint of the certificate the server presents.
async fn unreachable_report(api: &Api, failure: &Failure) -> HealthReport {
    let mut detail = failure.describe();
    if matches!(failure, Failure::Tls(_))
        && let Some(fingerprint) = api.web().presented_fingerprint().await
    {
        let _ = write!(
            detail,
            ". The server presents a certificate with the SHA-256 fingerprint {fingerprint}; check it before pinning it"
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

/// A list answer of a command that the poll needs.
fn required_list(kind: &str, answer: api::Answer) -> Result<Vec<Value>, ConnectorError> {
    match answer {
        Ok(Value::Array(list)) => Ok(list),
        Ok(_) => Err(ConnectorError::protocol(format!("{kind} is not a list"))),
        Err((code, _)) if code == "unauthorized" => Err(ConnectorError::Forbidden),
        Err((code, _)) => Err(ConnectorError::protocol(format!(
            "{kind} failed with {code}"
        ))),
    }
}

/// The external id a cursor continues after.
fn cursor_after(cursor: Option<&Cursor>) -> Result<Option<&str>, ConnectorError> {
    match cursor {
        None => Ok(None),
        Some(Cursor(text)) => text
            .strip_prefix("after:")
            .map(Some)
            .ok_or_else(|| ConnectorError::invalid_settings("unknown cursor")),
    }
}

impl HomeAssistant {
    async fn read(
        api: &Api,
        settings: &Settings,
        request_id: &str,
    ) -> Result<Snapshot, ConnectorError> {
        let mut snapshot = Snapshot::default();
        let mut session = api.session().await?;
        snapshot.devices = required_list(
            "config/device_registry/list",
            session.command("config/device_registry/list").await?,
        )?;
        snapshot.entities = required_list(
            "config/entity_registry/list",
            session.command("config/entity_registry/list").await?,
        )?;
        snapshot.areas = match session.command("config/area_registry/list").await? {
            Ok(Value::Array(areas)) => areas,
            _ => Vec::new(),
        };
        snapshot.entries = if let Ok(Value::Array(entries)) =
            session.command("config_entries/get").await?
        {
            Some(entries)
        } else {
            log(
                "INFO",
                request_id,
                "config entries are not readable (not an administrator); integrations come from the entities",
            );
            None
        };
        session.close().await;
        if settings.entity_addresses || settings.device_trackers {
            match api.get("/api/states").await? {
                Value::Array(states) => snapshot.states = states,
                _ => return Err(ConnectorError::protocol("/api/states is not a list")),
            }
        }
        Ok(snapshot)
    }

    async fn poll_page(
        ctx: &CallContext,
        cursor: Option<&Cursor>,
    ) -> Result<InventoryBatch, ConnectorError> {
        let settings: Settings = ctx.settings()?;
        let api = Api::new(&settings.url, &settings.tls(), ctx.secret_str(SECRET)?)?;
        if settings.tls == TlsMode::Insecure {
            log(
                "WARN",
                &ctx.request_id,
                "certificate checks are off for this instance (tls = insecure)",
            );
        }
        let after = cursor_after(cursor)?;
        let snapshot = Self::read(&api, &settings, &ctx.request_id).await?;
        let built = inventory::build(&snapshot, &settings.options());
        let remaining: Vec<_> = built
            .hosts
            .into_iter()
            .filter(|host| after.is_none_or(|after| host.external_id.as_str() > after))
            .collect();
        let more = remaining.len() > PAGE_SIZE;
        let hosts: Vec<_> = remaining.into_iter().take(PAGE_SIZE).collect();
        let vendors = built
            .vendors
            .into_iter()
            .filter(|fact| hosts.iter().any(|host| host.macs.contains(&fact.mac)))
            .collect::<Vec<_>>();
        log(
            "INFO",
            &ctx.request_id,
            &format!(
                "page with {} hosts and {} vendor facts from {} devices{}",
                hosts.len(),
                vendors.len(),
                snapshot.devices.len(),
                if more { ", more follow" } else { "" }
            ),
        );
        let cursor = more
            .then(|| {
                hosts
                    .last()
                    .map(|host| Cursor(format!("after:{}", host.external_id)))
            })
            .flatten();
        Ok(InventoryBatch {
            observed_at: Timestamp::now(),
            hosts,
            complete: true,
            cursor,
            more,
            vendors,
        })
    }
}

#[async_trait::async_trait]
impl Connector for HomeAssistant {
    async fn check(&self, ctx: &CallContext) -> Result<HealthReport, ConnectorError> {
        let settings: Settings = ctx.settings()?;
        let api = Api::new(&settings.url, &settings.tls(), ctx.secret_str(SECRET)?)?;
        let started = Instant::now();
        match api.get("/api/").await {
            Ok(_) => {}
            Err(Fail::Transport(failure)) => return Ok(unreachable_report(&api, &failure).await),
            Err(Fail::Answer(error)) => return Err(error),
        }
        let latency = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let version = match api.get("/api/config").await {
            Ok(config) => config
                .get("version")
                .and_then(Value::as_str)
                .map(|version| format!("Home Assistant {version}")),
            Err(Fail::Transport(failure)) => return Ok(unreachable_report(&api, &failure).await),
            Err(Fail::Answer(error)) => return Err(error),
        };
        let mut notes = api.web().notes();
        let mut degraded =
            settings.tls == TlsMode::Insecure && api.web().base().scheme() == "https";
        match api.session().await {
            Ok(mut session) => {
                match session.command("config/device_registry/list").await {
                    Ok(Ok(_)) => {}
                    Ok(Err((code, _))) => {
                        degraded = true;
                        notes.push(format!("the device registry is not readable ({code})"));
                    }
                    Err(fail) => {
                        degraded = true;
                        notes.push(format!(
                            "the device registry could not be read ({})",
                            tenko_core::Coded::code(&ConnectorError::from(fail))
                        ));
                    }
                }
                if !matches!(session.command("config_entries/get").await, Ok(Ok(_))) {
                    notes.push("config entries are not readable (not an administrator); integrations come from the entities".to_owned());
                }
                session.close().await;
            }
            Err(Fail::Answer(ConnectorError::Unauthorized)) => {
                return Err(ConnectorError::Unauthorized);
            }
            Err(fail) => {
                degraded = true;
                notes.push(format!(
                    "the WebSocket API is not usable ({})",
                    tenko_core::Coded::code(&ConnectorError::from(fail))
                ));
            }
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
            remote_version: version,
            detail: (!notes.is_empty()).then(|| notes.join("; ")),
        })
    }
}

#[async_trait::async_trait]
impl InventorySource for HomeAssistant {
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
    let hass = Arc::new(HomeAssistant);
    Plugin::new(manifest(), hass.clone()).with_inventory(hass)
}

/// Runs the plugin on standard input and output and returns the exit status.
pub fn run_status() -> u8 {
    plugin().run_status()
}

/// The entry point of the `tenko-plugin-hass` executable.
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
            .validate_settings(&serde_json::json!({ "url": "http://192.0.2.40:8123" }))
            .expect("settings");
        let settings: Settings = serde_json::from_value(filled).expect("settings");
        assert_eq!(settings.tls, TlsMode::System);
        assert!(settings.entity_addresses);
        assert!(settings.device_trackers);
        assert!(!settings.public_ipv4);
        assert!(
            manifest
                .validate_settings(&serde_json::json!({
                    "url": "http://192.0.2.40:8123",
                    "integrations": ["Not A Domain"]
                }))
                .is_err()
        );
    }

    #[test]
    fn cursors_continue_after_an_external_id() {
        assert_eq!(cursor_after(None).expect("none"), None);
        let cursor = Cursor("after:device/d1".to_owned());
        assert_eq!(
            cursor_after(Some(&cursor)).expect("after"),
            Some("device/d1")
        );
        assert!(cursor_after(Some(&Cursor("x".to_owned()))).is_err());
    }
}
