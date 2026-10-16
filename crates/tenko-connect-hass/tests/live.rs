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

// ---- recording the fixture ------------------------------------------------------------

/// The WebSocket commands the recording reads.
const COMMANDS: [&str; 4] = [
    "config/device_registry/list",
    "config/entity_registry/list",
    "config/area_registry/list",
    "config_entries/get",
];

/// One record per line inside the lists, the rest indented: the layout of the fixture files.
fn format_fixture(value: &serde_json::Value, indent: usize) -> String {
    let pad = "  ".repeat(indent);
    let inner = "  ".repeat(indent + 1);
    match value {
        serde_json::Value::Object(map) if map.values().any(|v| v.is_array() || v.is_object()) => {
            let members: Vec<String> = map
                .iter()
                .map(|(key, item)| {
                    format!(
                        "{inner}{}: {}",
                        serde_json::to_string(key).unwrap_or_default(),
                        format_fixture(item, indent + 1)
                    )
                })
                .collect();
            format!("{{\n{}\n{pad}}}", members.join(",\n"))
        }
        serde_json::Value::Array(items) if !items.is_empty() => {
            let lines: Vec<String> = items
                .iter()
                .map(|item| format!("{inner}{}", serde_json::to_string(item).unwrap_or_default()))
                .collect();
            format!("[\n{}\n{pad}]", lines.join(",\n"))
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Records the answers of the real Home Assistant as the anonymised fixture
/// `tests/fixtures/recorded.json`, in the layout of `documented.json`. It runs only with
/// `TENKO_LIVE_HASS=1` and `TENKO_RECORD=1`; it never prints an answer, only counts.
#[tokio::test]
async fn live_record_fixture() {
    use tenko_connect::sdk::anonymise::Anonymiser;
    use tenko_connect_hass::{Settings, api::Api};

    if std::env::var("TENKO_LIVE_HASS").as_deref() != Ok("1")
        || std::env::var("TENKO_RECORD").as_deref() != Ok("1")
    {
        eprintln!("skipped: set TENKO_LIVE_HASS=1 and TENKO_RECORD=1 to record the fixture");
        return;
    }
    let Some(ctx) = context() else {
        eprintln!("skipped: HASS_URL and HASS_TOKEN are not set (or still placeholders)");
        return;
    };
    let settings: Settings = ctx.settings().expect("settings");
    let api = Api::new(
        &settings.url,
        &settings.tls(),
        ctx.secret_str(SECRET).expect("the token"),
    )
    .expect("api client");
    let mut rest = serde_json::Map::new();
    rest.insert("/api/".to_owned(), api.get("/api/").await.expect("/api/"));
    let config = api.get("/api/config").await.expect("/api/config");
    // Of the configuration only the version is read; the rest names the installation.
    rest.insert(
        "/api/config".to_owned(),
        serde_json::json!({ "version": config.get("version").cloned().unwrap_or_default() }),
    );
    rest.insert(
        "/api/states".to_owned(),
        api.get("/api/states").await.expect("/api/states"),
    );
    let mut ws = serde_json::Map::new();
    let mut session = api.session().await.expect("websocket session");
    for command in COMMANDS {
        let answer = session.command(command).await.expect(command);
        let value = match answer {
            Ok(value) => value,
            Err((code, _)) => serde_json::json!({ "error": { "code": code, "message": code } }),
        };
        ws.insert(command.to_owned(), value);
    }
    session.close().await;

    let mut anonymiser = Anonymiser::new();
    let raw = serde_json::json!({ "ws": ws, "rest": rest });
    let mut output = anonymiser.anonymise(&raw);
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (name, list) in output["rest"]
        .as_object()
        .into_iter()
        .flatten()
        .chain(output["ws"].as_object().into_iter().flatten())
    {
        counts.insert(name.clone(), list.as_array().map_or(0, Vec::len));
    }
    let description = format!(
        "The answers of a real Home Assistant, recorded through the plugin's own client and anonymised with tenko_connect::sdk::anonymise (see README.md). Counts: {}.",
        counts
            .iter()
            .map(|(name, count)| format!("{name} {count}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    output["description"] = serde_json::Value::String(description);
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/recorded.json");
    let mut text = format_fixture(&output, 0);
    text.push('\n');
    std::fs::write(&path, text).expect("write the fixture");
    eprintln!("recorded: {counts:?}");
    eprintln!("replaced: {:?}", anonymiser.counts());
}
