//! A read-only smoke test against a real controller, off by default and in CI.
//!
//! Run it with `TENKO_LIVE_UNIFI=1 cargo nextest run -p tenko-connect-unifi --run-ignored all live`.
//! It reads only the `UNIFI_*` lines of the repository's `.env`: `UNIFI_URL`, and either
//! `UNIFI_USER` with `UNIFI_PASSWORD` (a local account) or `UNIFI_LOCAL_API_KEY` (a local
//! Integration API key); optionally `UNIFI_SITE` and `UNIFI_TLS_FINGERPRINT`. Without a
//! pinned fingerprint it pins the certificate the controller presents (trust on first use).
//! With `TENKO_LIVE_UNIFI=1`, missing settings, a failed call or a controller that reports
//! itself unreachable fails the test; without it the test passes as skipped.
//!
//! It calls only `Check`, `Poll` and `Topology`: the plugin's read paths. It never plans,
//! applies or reverts, so it writes nothing. It prints shapes and counts only, never names,
//! addresses or identifiers.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use tenko_connect::{
    CallContext, Connector, ControllerDhcp, InventorySource, NetworkController, Secrets,
    sdk::http::{TlsMode, TlsSettings, WebClient},
};
use tenko_connect_unifi::Unifi;

fn env_file() -> BTreeMap<String, String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../.env");
    let text = std::fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .filter_map(|line| {
            let line = line.trim().trim_start_matches("export ").trim();
            let (name, value) = line.split_once('=')?;
            let name = name.trim();
            if !name.starts_with("UNIFI_") {
                return None;
            }
            let value = value.trim().trim_matches('"').trim_matches('\'');
            Some((name.to_owned(), value.to_owned()))
        })
        .collect()
}

fn count<T>(items: &[T], test: impl Fn(&T) -> bool) -> usize {
    items.iter().filter(|item| test(item)).count()
}

/// The context of the live calls, or `None` (with the reason printed) when .env lacks what
/// they need.
async fn live_context() -> Option<CallContext> {
    let values = env_file();
    let Some(url) = values.get("UNIFI_URL").cloned() else {
        eprintln!("missing: no UNIFI_URL in .env");
        return None;
    };
    let mut secrets = Secrets::new();
    let mut settings = serde_json::json!({
        "url": url,
        "site": values.get("UNIFI_SITE").cloned().unwrap_or_else(|| "default".to_owned()),
    });
    match (
        values.get("UNIFI_USER"),
        values.get("UNIFI_PASSWORD"),
        values.get("UNIFI_LOCAL_API_KEY"),
    ) {
        (Some(user), Some(password), _) if !user.is_empty() && !password.is_empty() => {
            settings["username"] = serde_json::json!(user);
            secrets.insert_bytes("password", password.as_bytes().to_vec());
            println!("credentials: local account (classic API)");
        }
        (_, _, Some(key)) if !key.is_empty() => {
            secrets.insert_bytes("api_key", key.as_bytes().to_vec());
            println!("credentials: local Integration API key");
        }
        _ => {
            eprintln!("missing: no local account and no local Integration API key in .env");
            return None;
        }
    }
    let fingerprint = match values.get("UNIFI_TLS_FINGERPRINT") {
        Some(pin) if !pin.is_empty() => {
            println!("tls: fingerprint from .env");
            Some(pin.clone())
        }
        _ if url.starts_with("https://") => {
            let probe = WebClient::new(
                &url,
                &TlsSettings {
                    mode: TlsMode::Insecure,
                    ..TlsSettings::default()
                },
                Duration::from_secs(10),
                "tenko-live-smoke",
            )
            .expect("probe client");
            let seen = probe.presented_fingerprint().await;
            println!("tls: fingerprint pinned on first use ({})", seen.is_some());
            seen
        }
        _ => None,
    };
    if let Some(pin) = fingerprint {
        settings["tls"] = serde_json::json!("fingerprint");
        settings["tls_fingerprint"] = serde_json::json!(pin);
    }
    Some(CallContext {
        settings,
        secrets,
        request_id: "live-smoke".to_owned(),
        ..CallContext::default()
    })
}

#[tokio::test]
#[ignore = "reads a real controller; set TENKO_LIVE_UNIFI=1 and run the ignored tests"]
async fn live_read_only_smoke() {
    if std::env::var("TENKO_LIVE_UNIFI").ok().as_deref() != Some("1") {
        eprintln!("skipped: TENKO_LIVE_UNIFI is not 1");
        return;
    }
    let ctx = live_context()
        .await
        .expect("TENKO_LIVE_UNIFI=1 needs the controller and its credentials in .env");
    let health = Unifi.check(&ctx).await.expect("check");
    println!(
        "check: health {:?}, version {}",
        health.health,
        health.remote_version.as_deref().map_or_else(
            || "unknown".to_owned(),
            |v| v.split('.').take(2).collect::<Vec<_>>().join(".")
        )
    );
    assert_ne!(
        health.health,
        tenko_connect::Health::Unreachable,
        "the controller in .env is unreachable"
    );

    let topology = Unifi.topology(&ctx).await.expect("topology");
    report(&topology);
    tenko_connect::convert::topology_from_proto(Some(tenko_connect::convert::topology_to_proto(
        &topology,
    )))
    .expect("the topology passes the host's strict conversion");

    let batch = Unifi.poll(&ctx, None).await.expect("poll");
    println!(
        "inventory: {} hosts (devices {}, clients {}), complete {}",
        batch.hosts.len(),
        count(&batch.hosts, |h| h.external_id.starts_with("device:")),
        count(&batch.hosts, |h| h.external_id.starts_with("client:")),
        batch.complete,
    );
}

/// Prints the shape of a topology: counts only.
fn report(topology: &tenko_connect::TopologySnapshot) {
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for device in &topology.devices {
        *kinds.entry(format!("{:?}", device.kind)).or_default() += 1;
    }
    let ports: Vec<_> = topology
        .devices
        .iter()
        .flat_map(|d| d.ports.iter())
        .collect();
    println!(
        "devices: {} {:?}; ports {} (up {}, uplink {}, management {}, with profile {}, with native VLAN {})",
        topology.devices.len(),
        kinds,
        ports.len(),
        count(&ports, |p| p.up),
        count(&ports, |p| p.uplink),
        count(&ports, |p| p.management),
        count(&ports, |p| p.profile.is_some()),
        count(&ports, |p| p.native_vlan.is_some()),
    );
    let mut links: BTreeMap<String, usize> = BTreeMap::new();
    for link in &topology.links {
        *links.entry(format!("{:?}", link.kind)).or_default() += 1;
    }
    println!("links: {} {links:?}", topology.links.len());
    let clients = &topology.clients;
    println!(
        "clients: {} (wired with port {}, wireless with SSID {}, with VLAN {}, with network {}, with address {}, with name {}, with vendor {}, management {})",
        clients.len(),
        count(clients, |c| c.port.is_some()),
        count(clients, |c| c.ssid.is_some()),
        count(clients, |c| c.vlan.is_some()),
        count(clients, |c| c.network.is_some()),
        count(clients, |c| c.ip.is_some()),
        count(clients, |c| c.name.is_some()),
        count(clients, |c| c.vendor.is_some()),
        count(clients, |c| c.management),
    );
    let networks = &topology.networks;
    println!(
        "networks: {} (tagged {}, with subnet {}, management {}, DHCP server {}, relay {}, off {})",
        networks.len(),
        count(networks, |n| n.vlan.is_some()),
        count(networks, |n| n.subnet.is_some()),
        count(networks, |n| n.management),
        count(networks, |n| n.dhcp == ControllerDhcp::Server),
        count(networks, |n| matches!(n.dhcp, ControllerDhcp::RelayTo(_))),
        count(networks, |n| n.dhcp == ControllerDhcp::Disabled),
    );
    println!(
        "profiles: {} (with native network {}, with tagged networks {})",
        topology.profiles.len(),
        count(&topology.profiles, |p| p.native_network.is_some()),
        count(&topology.profiles, |p| !p.tagged.is_empty()),
    );
    let wlans = &topology.wlans;
    println!(
        "wlans: {} (enabled {}, with network {}, with VLAN {}, broadcast by at least one AP {})",
        wlans.len(),
        count(wlans, |w| w.enabled),
        count(wlans, |w| w.network.is_some()),
        count(wlans, |w| w.vlan.is_some()),
        count(wlans, |w| !w.access_points.is_empty()),
    );
}

// ---- recording the fixtures ---------------------------------------------------------

/// The endpoints the recording reads, and the file each one becomes.
const RECORDED: [&str; 7] = [
    "stat/device",
    "stat/sta",
    "rest/networkconf",
    "rest/wlanconf",
    "rest/portconf",
    "rest/user",
    "stat/sysinfo",
];

/// Records the classic answers of the real controller as anonymised fixtures under
/// `tests/fixtures/recorded/`. It runs only with `TENKO_LIVE_UNIFI=1` and `TENKO_RECORD=1`
/// and a local account in `.env`; it never prints an answer, only counts.
#[tokio::test]
#[ignore = "reads a real controller and rewrites the recorded fixtures; set TENKO_LIVE_UNIFI=1 and TENKO_RECORD=1"]
async fn live_record_fixtures() {
    use tenko_connect::sdk::anonymise::Anonymiser;
    use tenko_connect_unifi::{classic::Session, detect, http::Http, settings};

    if std::env::var("TENKO_LIVE_UNIFI").ok().as_deref() != Some("1")
        || std::env::var("TENKO_RECORD").ok().as_deref() != Some("1")
    {
        eprintln!("skipped: TENKO_LIVE_UNIFI and TENKO_RECORD are not both 1");
        return;
    }
    let ctx = live_context()
        .await
        .expect("TENKO_LIVE_UNIFI=1 needs the controller and its credentials in .env");
    let config = settings::config(&ctx).expect("settings");
    let settings::Credentials::Account { username, password } =
        settings::credentials(&ctx).expect("credentials")
    else {
        eprintln!("skipped: recording needs the local account (classic API)");
        return;
    };
    let http = Http::new(&config).expect("http client");
    let detected = detect::detect(&http, config.deployment)
        .await
        .expect("detection");
    let mut session = Session::login(&http, detected.paths, &config.site, &username, &password)
        .await
        .expect("login");
    let mut raw = serde_json::Map::new();
    for path in RECORDED {
        let records = session.records(path).await.expect(path);
        raw.insert(path.to_owned(), serde_json::Value::Array(records));
    }
    session.logout().await;

    // The known-client records are kept for the connected clients and a few others, so that
    // the offline shape is on record without the whole history of the site.
    let connected: BTreeSet<String> = raw["stat/sta"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|client| client["mac"].as_str().map(str::to_ascii_lowercase))
        .collect();
    let mut others = 0;
    if let Some(users) = raw
        .get_mut("rest/user")
        .and_then(serde_json::Value::as_array_mut)
    {
        users.retain(|user| {
            let online = user["mac"]
                .as_str()
                .is_some_and(|mac| connected.contains(&mac.to_ascii_lowercase()));
            others += usize::from(!online);
            online || others <= 3
        });
    }

    let mut anonymiser = Anonymiser::new();
    let output = anonymiser.anonymise(&serde_json::Value::Object(raw));
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/recorded");
    std::fs::create_dir_all(&dir).expect("the recorded directory");
    for path in RECORDED {
        let data = &output[path];
        let file = dir.join(format!("{}.json", path.rsplit('/').next().unwrap_or(path)));
        let envelope = serde_json::json!({ "meta": { "rc": "ok" }, "data": data });
        let mut text = serde_json::to_string_pretty(&envelope).expect("json");
        text.push('\n');
        std::fs::write(&file, text).expect("write the fixture");
        println!(
            "recorded {path}: {} records -> {}",
            data.as_array().map_or(0, Vec::len),
            file.file_name().unwrap_or_default().to_string_lossy()
        );
    }
    println!("replaced: {:?}", anonymiser.counts());
}
