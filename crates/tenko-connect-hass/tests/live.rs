//! A smoke test against a real Home Assistant, read-only. Skipped unless `TENKO_LIVE_HASS=1`;
//! CI never sets it.
//!
//! It reads `HASS_URL` and `HASS_TOKEN`, and optionally `HASS_TLS` (`system`, `ca`,
//! `fingerprint`, `insecure`), `HASS_TLS_FINGERPRINT`, `HASS_TLS_CA` (a PEM file path) and
//! `HASS_CONNECT_ADDRESS`, from the process environment or from the `.env` file at the
//! workspace root. It prints shape and counts only: never a name, an address or a value
//! from Home Assistant.

use std::{collections::BTreeMap, path::PathBuf};

use tenko_connect::{CallContext, Connector, InventorySource, Secrets};
use tenko_connect_hass::{HomeAssistant, SECRET};
use tenko_core::observe::ObservedHost;
use zeroize::Zeroizing;

/// The variables of the process environment, falling back to the workspace `.env`.
fn variables() -> BTreeMap<String, String> {
    let mut variables = BTreeMap::new();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.env");
    if let Ok(text) = std::fs::read_to_string(path) {
        for line in text.lines() {
            if let Some((key, value)) = line.split_once('=')
                && key.starts_with("HASS_")
            {
                let value = value.trim().trim_matches('"').trim_matches('\'');
                variables.insert(key.trim().to_owned(), value.to_owned());
            }
        }
    }
    for (key, value) in std::env::vars() {
        if key.starts_with("HASS_") {
            variables.insert(key, value);
        }
    }
    variables
}

/// The call context of the instance in the environment; `None` while the values are
/// placeholders.
fn context() -> Option<CallContext> {
    let variables = variables();
    let get = |key: &str| {
        variables
            .get(key)
            .cloned()
            .filter(|v| !v.is_empty() && !v.contains('<'))
    };
    let mut settings = serde_json::json!({ "url": get("HASS_URL")? });
    if let Some(mode) = get("HASS_TLS") {
        settings["tls"] = mode.into();
    }
    if let Some(fingerprint) = get("HASS_TLS_FINGERPRINT") {
        settings["tls_fingerprint"] = fingerprint.into();
    }
    if let Some(path) = get("HASS_TLS_CA") {
        settings["tls_ca"] = std::fs::read_to_string(path).expect("CA file").into();
    }
    if let Some(address) = get("HASS_CONNECT_ADDRESS") {
        settings["connect_address"] = address.into();
    }
    let mut secrets = Secrets::new();
    secrets.insert(SECRET, Zeroizing::new(get("HASS_TOKEN")?.into_bytes()));
    Some(CallContext {
        settings,
        secrets,
        request_id: "live".to_owned(),
        ..CallContext::default()
    })
}

/// Prints the health check as shape: health, version family, latency and which notes.
async fn print_check(ctx: &CallContext) {
    match HomeAssistant.check(ctx).await {
        Ok(report) => {
            let detail = report.detail.unwrap_or_default();
            let phrases = [
                ("tls", "TLS:"),
                ("not encrypted", "not encrypted"),
                ("registry not readable", "device registry"),
                ("no config entries", "config entries are not readable"),
                ("websocket unusable", "WebSocket API is not usable"),
            ];
            let notes: Vec<&str> = phrases
                .iter()
                .filter(|(_, phrase)| detail.contains(phrase))
                .map(|(label, _)| *label)
                .collect();
            eprintln!(
                "check: health {:?}, version known {}, latency {:?} ms, notes {notes:?}",
                report.health,
                report.remote_version.is_some(),
                report.latency_ms
            );
        }
        Err(error) => eprintln!("check: error {}", tenko_core::Coded::code(&error)),
    }
}

fn print_shape(hosts: &[ObservedHost], vendors: usize, pages: usize) {
    let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
    let mut integrations: BTreeMap<String, usize> = BTreeMap::new();
    for host in hosts {
        let kind = if host.external_id.starts_with("device/") {
            "device"
        } else {
            "tracker"
        };
        *by_kind.entry(kind).or_default() += 1;
        for tag in &host.tags {
            if let Some(domain) = tag.strip_prefix("integration:") {
                *integrations.entry(domain.to_owned()).or_default() += 1;
            }
        }
    }
    let count = |f: &dyn Fn(&ObservedHost) -> bool| hosts.iter().filter(|h| f(h)).count();
    eprintln!(
        "poll: {} hosts in {pages} page(s) ({by_kind:?}); {vendors} vendor facts; {} integrations",
        hosts.len(),
        integrations.len()
    );
    eprintln!(
        "poll: {} with MAC addresses ({} MACs), {} with IP addresses ({} IPv4, {} IPv6), {} with a platform, {} with an area",
        count(&|h| !h.macs.is_empty()),
        hosts.iter().map(|h| h.macs.len()).sum::<usize>(),
        count(&|h| !h.ips.is_empty()),
        hosts
            .iter()
            .flat_map(|h| &h.ips)
            .filter(|ip| ip.is_ipv4())
            .count(),
        hosts
            .iter()
            .flat_map(|h| &h.ips)
            .filter(|ip| ip.is_ipv6())
            .count(),
        count(&|h| h.platform.is_some()),
        count(&|h| h.tags.iter().any(|t| t.starts_with("area:"))),
    );
}

#[tokio::test]
async fn live_inventory_shape() {
    if std::env::var("TENKO_LIVE_HASS").as_deref() != Ok("1") {
        eprintln!("skipped: set TENKO_LIVE_HASS=1 to run against the Home Assistant in .env");
        return;
    }
    let Some(ctx) = context() else {
        eprintln!("skipped: HASS_URL and HASS_TOKEN are not set (or still placeholders)");
        return;
    };
    print_check(&ctx).await;
    let mut hosts = Vec::new();
    let mut vendors = 0;
    let mut pages = 0;
    let mut cursor = None;
    loop {
        let batch = match HomeAssistant.poll(&ctx, cursor).await {
            Ok(batch) => batch,
            Err(error) => {
                eprintln!("poll: error {}", tenko_core::Coded::code(&error));
                return;
            }
        };
        pages += 1;
        vendors += batch.vendors.len();
        hosts.extend(batch.hosts);
        if !batch.more {
            break;
        }
        cursor = batch.cursor;
    }
    print_shape(&hosts, vendors, pages);
}
