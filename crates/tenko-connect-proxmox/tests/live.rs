//! A smoke test against a real Proxmox VE cluster, read-only. Skipped unless
//! `TENKO_LIVE_PROXMOX=1`; CI never sets it.
//!
//! It reads `PROXMOX_URL`, `PROXMOX_TOKEN_ID` and `PROXMOX_TOKEN_SECRET`, and optionally
//! `PROXMOX_TLS` (`system`, `ca`, `fingerprint`, `insecure`), `PROXMOX_TLS_FINGERPRINT`,
//! `PROXMOX_TLS_CA` (a PEM file path) and `PROXMOX_CONNECT_ADDRESS`, from the process
//! environment or from the `.env` file at the workspace root. It prints shape and counts
//! only: never a name, an address or a value from the cluster.

use std::{collections::BTreeMap, path::PathBuf};

use tenko_connect::{CallContext, Connector, InventorySource, Secrets};
use tenko_connect_proxmox::{Proxmox, SECRET};
use zeroize::Zeroizing;

/// The variables of the process environment, falling back to the workspace `.env`.
fn variables() -> BTreeMap<String, String> {
    let mut variables = BTreeMap::new();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.env");
    if let Ok(text) = std::fs::read_to_string(path) {
        for line in text.lines() {
            if let Some((key, value)) = line.split_once('=')
                && key.starts_with("PROXMOX_")
            {
                let value = value.trim().trim_matches('"').trim_matches('\'');
                variables.insert(key.trim().to_owned(), value.to_owned());
            }
        }
    }
    for (key, value) in std::env::vars() {
        if key.starts_with("PROXMOX_") {
            variables.insert(key, value);
        }
    }
    variables
}

/// The call context of the cluster in the environment.
fn context() -> CallContext {
    let variables = variables();
    let get = |key: &str| variables.get(key).cloned().filter(|v| !v.is_empty());
    let mut settings = serde_json::json!({
        "url": get("PROXMOX_URL").expect("PROXMOX_URL"),
        "token_id": get("PROXMOX_TOKEN_ID").expect("PROXMOX_TOKEN_ID"),
    });
    if let Some(mode) = get("PROXMOX_TLS") {
        settings["tls"] = mode.into();
    }
    if let Some(fingerprint) = get("PROXMOX_TLS_FINGERPRINT") {
        settings["tls_fingerprint"] = fingerprint.into();
    }
    if let Some(path) = get("PROXMOX_TLS_CA") {
        settings["tls_ca"] = std::fs::read_to_string(path).expect("CA file").into();
    }
    if let Some(address) = get("PROXMOX_CONNECT_ADDRESS") {
        settings["connect_address"] = address.into();
    }
    let mut secrets = Secrets::new();
    secrets.insert(
        SECRET,
        Zeroizing::new(
            get("PROXMOX_TOKEN_SECRET")
                .expect("PROXMOX_TOKEN_SECRET")
                .into_bytes(),
        ),
    );
    CallContext {
        settings,
        secrets,
        request_id: "live".to_owned(),
        ..CallContext::default()
    }
}

/// Prints the health check as shape: health, major version, latency and which notes.
async fn print_check(ctx: &CallContext) {
    match Proxmox.check(ctx).await {
        Ok(report) => {
            let detail = report.detail.unwrap_or_default();
            let phrases = [
                ("tls", "TLS:"),
                ("no guests visible (VM.Audit)", "VM.Audit is missing"),
                ("no node addresses (Sys.Audit)", "Sys.Audit is missing"),
                (
                    "no guest agent addresses",
                    "guest agent addresses are not read",
                ),
                ("no SDN (SDN.Audit)", "SDN.Audit is missing"),
                ("fingerprint pinned", "pinned by its fingerprint"),
                ("insecure", "certificate checks are off"),
            ];
            let notes: Vec<&str> = phrases
                .iter()
                .filter(|(_, phrase)| detail.contains(phrase))
                .map(|(label, _)| *label)
                .collect();
            eprintln!(
                "check: health {:?}, version {}, latency {:?} ms, notes {notes:?}",
                report.health,
                report.remote_version.as_deref().map_or(
                    "-",
                    |v| if v.starts_with("Proxmox VE 9") {
                        "9.x"
                    } else {
                        "other"
                    }
                ),
                report.latency_ms
            );
        }
        Err(error) => eprintln!("check: error {}", tenko_core::Coded::code(&error)),
    }
}

#[tokio::test]
async fn live_inventory_shape() {
    if std::env::var("TENKO_LIVE_PROXMOX").as_deref() != Ok("1") {
        eprintln!("skipped: set TENKO_LIVE_PROXMOX=1 to run against the cluster in .env");
        return;
    }
    let ctx = context();
    print_check(&ctx).await;
    let mut hosts = Vec::new();
    let mut pages = 0;
    let mut cursor = None;
    loop {
        let batch = match Proxmox.poll(&ctx, cursor).await {
            Ok(batch) => batch,
            Err(error) => {
                eprintln!("poll: error {}", tenko_core::Coded::code(&error));
                return;
            }
        };
        pages += 1;
        hosts.extend(batch.hosts);
        if !batch.more {
            break;
        }
        cursor = batch.cursor;
    }
    let mut by_platform: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_status: BTreeMap<String, usize> = BTreeMap::new();
    for host in &hosts {
        *by_platform
            .entry(host.platform.clone().unwrap_or_default())
            .or_default() += 1;
        for tag in &host.tags {
            if let Some(status) = tag.strip_prefix("status:") {
                *by_status.entry(status.to_owned()).or_default() += 1;
            }
        }
    }
    let count = |f: &dyn Fn(&tenko_core::observe::ObservedHost) -> bool| {
        hosts.iter().filter(|h| f(h)).count()
    };
    eprintln!(
        "poll: {} hosts in {pages} page(s); by platform {by_platform:?}; by status {by_status:?}",
        hosts.len()
    );
    eprintln!(
        "poll: {} with MAC addresses ({} MACs), {} with IP addresses ({} IPv4, {} IPv6), {} with an OS, {} with a parent, {} with a pool, {} with a VLAN tag, {} on an SDN vnet",
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
        count(&|h| h.os.is_some()),
        count(&|h| h.parent.is_some()),
        count(&|h| h.tags.iter().any(|t| t.starts_with("pool:"))),
        count(&|h| h.tags.iter().any(|t| t.starts_with("vlan:"))),
        count(&|h| h.tags.iter().any(|t| t.starts_with("vnet:"))),
    );
}
