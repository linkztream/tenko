//! The sample plugin: an inventory source that reports documentation data
//! (`192.0.2.0/24`, `2001:db8::/32`, MAC addresses of the RFC 7042 documentation block,
//! names under `example.test`). It contacts nothing.
//!
//! It is the reference for plugin authors, the plugin the conformance suite and the host
//! tests run against, and it is bundled in the `tenko` binary as `tenko plugin run sample`.
//! The binary `tenko-plugin-sample` of this crate runs it as a standalone executable; its
//! `--mode` argument makes it misbehave in one specific way ([`Mode`]), so that the host's
//! supervision and the conformance suite can be tested against a plugin that hangs, crashes,
//! lies or ignores the rules.
//!
//! Settings: `site` (a tag on every host, default `lab`), `hosts` (how many, 0 to 200,
//! default 8), `page_size` (hosts per page, 1 to 100, default 50) and `endpoint` (shown as
//! its network target; never contacted). The optional secret `api_key` is never returned;
//! when the host injects it, every host carries the tag `credential:present`, which lets the
//! tests see the injection without the value.

use std::{process::ExitCode, sync::Arc, time::Duration};

use serde::Deserialize;
use tenko_core::{MacAddr, Timestamp, observe::ObservedHost};

use crate::{
    CallContext, Connector, ConnectorError, Cursor, Health, HealthReport, InventoryBatch,
    InventorySource,
    manifest::Manifest,
    sdk::{Plugin, ServeOptions},
};

/// The plugin name.
pub const NAME: &str = "sample";

/// The tag every host carries when the host injected the `api_key` secret.
pub const CREDENTIAL_TAG: &str = "credential:present";

/// The manifest of the sample plugin.
///
/// # Panics
///
/// Never: the manifest is a constant document checked by the tests.
pub fn manifest() -> Manifest {
    serde_json::from_value(serde_json::json!({
        "manifest_version": 1,
        "name": NAME,
        "version": crate::version(),
        "description": "Sample inventory source that reports documentation data; for testing the plugin host.",
        "license": "LicenseRef-Proprietary",
        "protocol": [crate::PROTOCOL_VERSION],
        "capabilities": ["inventory"],
        "settings": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "site": {
                    "type": "string",
                    "title": "Site tag",
                    "description": "Tag added to every host.",
                    "default": "lab",
                    "minLength": 1,
                    "maxLength": 64
                },
                "hosts": {
                    "type": "integer",
                    "title": "Number of hosts",
                    "minimum": 0,
                    "maximum": 200,
                    "default": 8
                },
                "page_size": {
                    "type": "integer",
                    "title": "Hosts per page",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 50
                },
                "endpoint": {
                    "type": "string",
                    "format": "uri",
                    "title": "Source address",
                    "description": "Shown as the network target; the sample contacts nothing.",
                    "default": "https://inventory.example.net"
                }
            },
            "additionalProperties": false
        },
        "secrets": [{
            "purpose": "api_key",
            "description": "API key of the source; the sample only notes that it was injected.",
            "required": false
        }],
        "network": [{
            "setting": "/endpoint",
            "description": "The inventory source (the sample contacts nothing)."
        }],
        "platforms": ["any"]
    }))
    .unwrap_or_else(|error| unreachable!("the sample manifest is a constant: {error}"))
}

/// How the sample misbehaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// A well-behaved plugin.
    Normal,
    /// Reads the host's hello and never answers.
    HangHandshake,
    /// Prints a broken handshake line and exits with status 3.
    BrokenHandshake,
    /// Speaks only protocol version 2 and refuses the handshake.
    ProtocolTwo,
    /// Reports version 9.9.9 in its manifest.
    WrongVersion,
    /// Exits with status 101 shortly after the handshake.
    CrashAfterStart,
    /// Never answers `Check` and `Poll`.
    HangCalls,
    /// Exits with status 101 during `Poll`.
    CrashOnPoll,
    /// Serves calls without the per-launch token.
    IgnoreToken,
    /// Keeps running when its standard input closes.
    IgnoreStdinClose,
    /// Answers `Poll` with malformed hosts (no identifier, bad addresses).
    MalformedHosts,
    /// Freezes every worker thread on the first `Check`, so that not even `Ping` answers.
    FreezeOnCheck,
}

impl Mode {
    /// Every mode with its command-line name.
    pub const ALL: [(Mode, &'static str); 12] = [
        (Mode::Normal, "normal"),
        (Mode::HangHandshake, "hang-handshake"),
        (Mode::BrokenHandshake, "broken-handshake"),
        (Mode::ProtocolTwo, "protocol-2"),
        (Mode::WrongVersion, "wrong-version"),
        (Mode::CrashAfterStart, "crash-after-start"),
        (Mode::HangCalls, "hang-calls"),
        (Mode::CrashOnPoll, "crash-on-poll"),
        (Mode::IgnoreToken, "ignore-token"),
        (Mode::IgnoreStdinClose, "ignore-stdin-close"),
        (Mode::MalformedHosts, "malformed-hosts"),
        (Mode::FreezeOnCheck, "freeze-on-check"),
    ];

    /// The mode of a command-line name.
    pub fn parse(name: &str) -> Option<Mode> {
        Self::ALL
            .iter()
            .find(|(_, n)| *n == name)
            .map(|(mode, _)| *mode)
    }

    /// The command-line name.
    pub fn name(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(mode, _)| *mode == self)
            .map_or("normal", |(_, name)| name)
    }
}

/// The settings of the sample.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    #[serde(default = "default_site")]
    site: String,
    #[serde(default = "default_hosts")]
    hosts: u16,
    #[serde(default = "default_page_size")]
    page_size: u16,
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "a network target the sample shows but never contacts"
    )]
    endpoint: Option<String>,
}

fn default_site() -> String {
    "lab".to_owned()
}

const fn default_hosts() -> u16 {
    8
}

const fn default_page_size() -> u16 {
    50
}

/// The sample's inventory source and health check.
#[derive(Debug, Clone, Copy)]
pub struct Sample {
    mode: Mode,
}

impl Sample {
    /// The sample in a mode.
    pub fn new(mode: Mode) -> Self {
        Self { mode }
    }

    async fn hang(&self) {
        if self.mode == Mode::HangCalls {
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        }
    }
}

/// The host `index` (from 0) of the documentation inventory.
pub fn sample_host(index: u16, site: &str, credential: bool) -> ObservedHost {
    let low = u8::try_from(index % 200).unwrap_or(0);
    let mut tags = vec![site.to_owned()];
    if credential {
        tags.push(CREDENTIAL_TAG.to_owned());
    }
    ObservedHost {
        external_id: format!("sample/{index}"),
        name: Some(format!("host-{index}.example.test")),
        macs: vec![MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, low])],
        ips: vec![
            std::net::IpAddr::from([192, 0, 2, low.saturating_add(10)]),
            format!("2001:db8::{:x}", u32::from(low) + 0x10)
                .parse()
                .unwrap_or(std::net::IpAddr::from([0u16; 8])),
        ],
        os: Some("Linux".to_owned()),
        platform: Some("sample".to_owned()),
        parent: None,
        tags,
        power: None,
    }
}

#[async_trait::async_trait]
impl Connector for Sample {
    async fn check(&self, ctx: &CallContext) -> Result<HealthReport, ConnectorError> {
        self.hang().await;
        if self.mode == Mode::FreezeOnCheck {
            freeze();
        }
        let settings: Settings = ctx.settings()?;
        let _ = settings;
        Ok(HealthReport {
            health: Health::Healthy,
            checked_at: Timestamp::now(),
            latency_ms: Some(0),
            remote_version: Some(format!("sample {}", crate::version())),
            detail: None,
        })
    }
}

#[async_trait::async_trait]
impl InventorySource for Sample {
    async fn poll(
        &self,
        ctx: &CallContext,
        cursor: Option<Cursor>,
    ) -> Result<InventoryBatch, ConnectorError> {
        self.hang().await;
        if self.mode == Mode::CrashOnPoll {
            eprintln!("ERROR crashing on purpose (mode crash-on-poll)");
            std::process::exit(101);
        }
        let settings: Settings = ctx.settings()?;
        if settings.hosts > 200 || !(1..=100).contains(&settings.page_size) {
            return Err(ConnectorError::invalid_settings(
                "hosts must be at most 200 and page_size 1 to 100",
            ));
        }
        if self.mode == Mode::MalformedHosts {
            let mut good = sample_host(0, &settings.site, false);
            good.ips.clear();
            let mut empty = sample_host(1, &settings.site, false);
            empty.external_id = String::new();
            return Ok(InventoryBatch::complete(
                Timestamp::now(),
                vec![good, empty],
            ));
        }
        let page = match &cursor {
            None => 0u16,
            Some(Cursor(text)) => text
                .strip_prefix("page:")
                .and_then(|page| page.parse().ok())
                .ok_or_else(|| ConnectorError::invalid_settings("unknown cursor"))?,
        };
        let credential = ctx.secret("api_key").is_some_and(|key| !key.is_empty());
        let start = page.saturating_mul(settings.page_size);
        let end = start.saturating_add(settings.page_size).min(settings.hosts);
        let hosts = (start..end)
            .map(|index| sample_host(index, &settings.site, credential))
            .collect();
        let more = end < settings.hosts;
        Ok(InventoryBatch {
            observed_at: Timestamp::now(),
            hosts,
            complete: true,
            cursor: more.then(|| Cursor(format!("page:{}", page + 1))),
            more,
            vendors: Vec::new(),
        })
    }
}

/// Blocks the calling worker thread and, through spawned tasks, the other workers of the
/// runtime, so the process stays alive but answers nothing.
fn freeze() {
    for _ in 0..8 {
        tokio::spawn(async {
            std::thread::sleep(Duration::from_secs(3600));
        });
    }
    std::thread::sleep(Duration::from_secs(3600));
}

/// The sample as an SDK plugin in a mode.
pub fn plugin(mode: Mode) -> Plugin {
    let mut manifest = manifest();
    match mode {
        Mode::ProtocolTwo => manifest.protocol = vec![2],
        Mode::WrongVersion => "9.9.9".clone_into(&mut manifest.version),
        _ => {}
    }
    let sample = Arc::new(Sample::new(mode));
    Plugin::new(manifest, sample.clone())
        .with_inventory(sample)
        .with_options(ServeOptions {
            check_token: mode != Mode::IgnoreToken,
            exit_on_stdin_close: mode != Mode::IgnoreStdinClose,
        })
}

/// Runs the sample in a mode on standard input and output and returns the exit status.
pub fn run(mode: Mode) -> ExitCode {
    ExitCode::from(run_status(mode))
}

/// [`run`] with the exit status as a number.
pub fn run_status(mode: Mode) -> u8 {
    match mode {
        Mode::HangHandshake => hang_in_handshake(),
        Mode::BrokenHandshake => {
            println!("{{\"tenko_plugin\": 1, \"protocol\": ");
            3
        }
        Mode::CrashAfterStart => {
            std::thread::spawn(|| {
                std::thread::sleep(Duration::from_millis(300));
                eprintln!("ERROR crashing on purpose (mode crash-after-start)");
                std::process::exit(101);
            });
            plugin(mode).run_status()
        }
        _ => plugin(mode).run_status(),
    }
}

/// Reads the hello and never answers.
fn hang_in_handshake() -> u8 {
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// The entry point of the `tenko-plugin-sample` executable: `[--mode <mode>]`.
pub fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut mode = Mode::Normal;
    while let Some(arg) = args.next() {
        let name = if arg == "--mode" { args.next() } else { None };
        let Some(name) = name else {
            eprintln!("usage: tenko-plugin-sample [--mode <mode>]");
            return ExitCode::from(2);
        };
        let Some(parsed) = Mode::parse(&name) else {
            eprintln!("ERROR unknown mode `{name}`");
            return ExitCode::from(2);
        };
        mode = parsed;
    }
    run(mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_manifest_is_valid() {
        let manifest = manifest();
        manifest.validate().expect("valid");
        assert_eq!(manifest.name, NAME);
        assert!(manifest.supports_this_platform());
        let filled = manifest
            .validate_settings(&serde_json::json!({}))
            .expect("defaults");
        let _ = filled;
    }

    #[test]
    fn modes_have_unique_names() {
        for (mode, name) in Mode::ALL {
            assert_eq!(Mode::parse(name), Some(mode));
            assert_eq!(mode.name(), name);
        }
        assert_eq!(Mode::parse("nope"), None);
    }

    #[tokio::test]
    async fn the_inventory_pages_through_documentation_data() {
        let sample = Sample::new(Mode::Normal);
        let ctx = CallContext::with_settings(serde_json::json!({ "hosts": 5, "page_size": 2 }));
        let mut cursor = None;
        let mut hosts = Vec::new();
        loop {
            let batch = sample.poll(&ctx, cursor).await.expect("poll");
            hosts.extend(batch.hosts);
            if !batch.more {
                break;
            }
            cursor = batch.cursor;
        }
        assert_eq!(hosts.len(), 5);
        assert_eq!(hosts[4].external_id, "sample/4");
        assert_eq!(
            hosts[4].ips[0],
            "192.0.2.14".parse::<std::net::IpAddr>().expect("ip")
        );
        assert_eq!(
            hosts[4].ips[1],
            "2001:db8::14".parse::<std::net::IpAddr>().expect("ip")
        );
        assert_eq!(hosts[4].macs[0].to_string(), "00:00:5e:00:53:04");
        assert!(!hosts[0].tags.contains(&CREDENTIAL_TAG.to_owned()));
        assert!(matches!(
            sample
                .poll(
                    &CallContext::with_settings(serde_json::json!({ "colour": 1 })),
                    None
                )
                .await,
            Err(ConnectorError::InvalidSettings(_))
        ));
    }
}
