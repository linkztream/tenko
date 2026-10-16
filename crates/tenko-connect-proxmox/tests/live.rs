//! A smoke test against a real Proxmox VE cluster, read-only. Skipped unless
//! `TENKO_LIVE_PROXMOX=1`; CI never sets it. With the variable set, a failed health check, a
//! cluster that reports itself unreachable or a failed poll fails the test.
//!
//! It reads `PROXMOX_URL`, `PROXMOX_TOKEN_ID` and `PROXMOX_TOKEN_SECRET`, and optionally
//! `PROXMOX_TLS` (`system`, `ca`, `fingerprint`, `insecure`), `PROXMOX_TLS_FINGERPRINT`,
//! `PROXMOX_TLS_CA` (a PEM file path) and `PROXMOX_CONNECT_ADDRESS`, from the process
//! environment or from the `.env` file at the workspace root. It prints shape and counts
//! only: never a name, an address or a value from the cluster.

use std::{collections::BTreeMap, path::PathBuf};

use tenko_connect::{CallContext, Connector, Health, InventorySource, Secrets};
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

/// Prints the health check as shape: health, major version, latency and which notes. Panics
/// when the check fails or the cluster is unreachable.
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
            assert_ne!(
                report.health,
                Health::Unreachable,
                "the cluster in .env is unreachable"
            );
        }
        Err(error) => panic!("check: error {}", tenko_core::Coded::code(&error)),
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
            Err(error) => panic!("poll: error {}", tenko_core::Coded::code(&error)),
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

// ---- recording the fixture --------------------------------------------------------------

/// The roots of `/access/permissions` the recording keeps; the other paths of that answer
/// name pools, storages and guests of the cluster.
const PERMISSION_ROOTS: [&str; 8] = [
    "/", "/vms", "/nodes", "/storage", "/pool", "/sdn", "/access", "/mapping",
];

/// One route of the recording: the node it belongs to (an index into the node names) and
/// the rest of its path.
struct Route {
    node: Option<usize>,
    path: String,
}

/// An answer as the mock serves it: the `data` of a success, or the status of a refusal.
fn answer(reply: tenko_connect_proxmox::api::Reply) -> serde_json::Value {
    use tenko_connect_proxmox::api::Reply;
    match reply {
        Reply::Data(data) => serde_json::json!({ "data": data }),
        Reply::Status(status) => {
            serde_json::json!({ "status": status.as_u16(), "body": { "data": null } })
        }
    }
}

/// The index of a node name, added when it is new.
fn node_index(nodes: &mut Vec<String>, name: &str) -> usize {
    if let Some(index) = nodes.iter().position(|n| n == name) {
        return index;
    }
    nodes.push(name.to_owned());
    nodes.len() - 1
}

/// The fixture text: the description, then one route per line.
fn fixture_text(description: &str, table: &serde_json::Map<String, serde_json::Value>) -> String {
    let lines: Vec<String> = table
        .iter()
        .map(|(path, answer)| {
            format!(
                "    {}: {}",
                serde_json::Value::String(path.clone()),
                answer
            )
        })
        .collect();
    format!(
        "{{\n  \"description\": {},\n  \"routes\": {{\n{}\n  }}\n}}\n",
        serde_json::Value::String(description.to_owned()),
        lines.join(",\n")
    )
}

/// Records the configuration of a guest on an online node, and the live interfaces of a
/// running one.
async fn record_guest(
    api: &tenko_connect_proxmox::api::Api,
    guest: &serde_json::Value,
    online: &[String],
    nodes: &mut Vec<String>,
    routes: &mut Vec<(Route, serde_json::Value)>,
) {
    use tenko_connect_proxmox::api::AGENT_TIMEOUT;

    let text = |value: &serde_json::Value, key: &str| value[key].as_str().map(str::to_owned);
    let (Some(kind), Some(node), Some(vmid)) = (
        text(guest, "type").filter(|t| t == "qemu" || t == "lxc"),
        text(guest, "node").filter(|n| online.contains(n)),
        guest["vmid"].as_u64(),
    ) else {
        return;
    };
    let index = node_index(nodes, &node);
    let base = format!("/nodes/{node}/{kind}/{vmid}");
    let config = api
        .fetch(&format!("{base}/config"), None)
        .await
        .expect("config");
    let route = Route {
        node: Some(index),
        path: format!("/{kind}/{vmid}/config"),
    };
    routes.push((route, answer(config)));
    if text(guest, "status").as_deref() != Some("running") {
        return;
    }
    let tail = if kind == "qemu" {
        "agent/network-get-interfaces"
    } else {
        "interfaces"
    };
    // An agent that times out is left out: the mock answers 404, which the plugin
    // treats as no live addresses, as it does a timeout.
    if let Ok(reply) = api
        .fetch(&format!("{base}/{tail}"), Some(AGENT_TIMEOUT))
        .await
    {
        let route = Route {
            node: Some(index),
            path: format!("/{kind}/{vmid}/{tail}"),
        };
        routes.push((route, answer(reply)));
    }
}

/// Records the answers of the real cluster as the anonymised fixture
/// `tests/fixtures/recorded.json`, in the layout of `documented.json`: every route the
/// plugin reads, the node names in the paths anonymised like the names in the answers. It
/// runs only with `TENKO_LIVE_PROXMOX=1` and `TENKO_RECORD=1`; it prints counts only.
#[tokio::test]
async fn live_record_fixture() {
    use tenko_connect::sdk::anonymise::Anonymiser;
    use tenko_connect_proxmox::{Settings, api::Api};

    if std::env::var("TENKO_LIVE_PROXMOX").as_deref() != Ok("1")
        || std::env::var("TENKO_RECORD").as_deref() != Ok("1")
    {
        eprintln!("skipped: set TENKO_LIVE_PROXMOX=1 and TENKO_RECORD=1 to record the fixture");
        return;
    }
    let ctx = context();
    let settings: Settings = ctx.settings().expect("settings");
    let api = Api::new(&settings, ctx.secret_str(SECRET).expect("the secret")).expect("client");
    let text = |value: &serde_json::Value, key: &str| value[key].as_str().map(str::to_owned);

    let mut nodes: Vec<String> = Vec::new();
    let mut routes: Vec<(Route, serde_json::Value)> = Vec::new();
    for path in [
        "/version",
        "/access/permissions",
        "/cluster/resources",
        "/cluster/status",
        "/cluster/sdn/vnets",
        "/cluster/sdn/zones",
    ] {
        let reply = api.fetch(path, None).await.expect(path);
        let route = Route {
            node: None,
            path: path.to_owned(),
        };
        routes.push((route, answer(reply)));
    }
    if let Some(serde_json::Value::Object(roots)) = routes[1].1.get_mut("data") {
        roots.retain(|path, _| PERMISSION_ROOTS.contains(&path.as_str()));
    }
    let resources = routes[2].1["data"].as_array().cloned().unwrap_or_default();
    let online: Vec<String> = resources
        .iter()
        .filter(|r| text(r, "type").as_deref() == Some("node"))
        .filter(|r| text(r, "status").as_deref() == Some("online"))
        .filter_map(|r| text(r, "node"))
        .collect();
    for node in &online {
        let index = node_index(&mut nodes, node);
        let reply = api
            .fetch(&format!("/nodes/{node}/network"), None)
            .await
            .expect("node network");
        let route = Route {
            node: Some(index),
            path: "/network".to_owned(),
        };
        routes.push((route, answer(reply)));
    }
    for guest in &resources {
        record_guest(&api, guest, &online, &mut nodes, &mut routes).await;
    }

    // One anonymisation over the node names and every answer, so that the names in the
    // paths and in the answers stay the same placeholder.
    let raw = serde_json::json!({
        "node": nodes,
        "answers": routes.iter().map(|(_, answer)| answer.clone()).collect::<Vec<_>>(),
    });
    let mut anonymiser = Anonymiser::new();
    let output = anonymiser.anonymise(&raw);
    let names: Vec<String> = output["node"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|n| n.as_str().map(str::to_owned))
        .collect();
    let answers = output["answers"].as_array().cloned().unwrap_or_default();
    let mut table = serde_json::Map::new();
    let mut statuses: BTreeMap<u64, usize> = BTreeMap::new();
    for ((route, _), answer) in routes.iter().zip(answers) {
        let path = match route.node {
            Some(index) => format!("/api2/json/nodes/{}{}", names[index], route.path),
            None => format!("/api2/json{}", route.path),
        };
        *statuses
            .entry(answer["status"].as_u64().unwrap_or(200))
            .or_default() += 1;
        table.insert(path, answer);
    }
    let description = format!(
        "The answers of a real Proxmox VE node, recorded through the plugin's own client and anonymised with tenko_connect::sdk::anonymise (see README.md). {} routes, {} cluster resources, {} online node(s).",
        table.len(),
        resources.len(),
        names.len()
    );
    let file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/recorded.json");
    std::fs::write(&file, fixture_text(&description, &table)).expect("write the fixture");
    eprintln!(
        "recorded: {} routes, {} resources, {} nodes, statuses {statuses:?}",
        table.len(),
        resources.len(),
        names.len()
    );
    eprintln!("replaced: {:?}", anonymiser.counts());
}
