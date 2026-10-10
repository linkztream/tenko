//! A read-only smoke test against a real controller, off by default and in CI.
//!
//! Run it with `TENKO_LIVE_UNIFI=1 cargo nextest run -p tenko-connect-unifi --run-ignored all live`.
//! It reads only the `UNIFI_*` lines of the repository's `.env`: `UNIFI_URL`, and either
//! `UNIFI_USER` with `UNIFI_PASSWORD` (a local account) or `UNIFI_LOCAL_API_KEY` (a local
//! Integration API key); optionally `UNIFI_SITE` and `UNIFI_TLS_FINGERPRINT`. Without a
//! pinned fingerprint it pins the certificate the controller presents (trust on first use).
//!
//! It calls only `Check`, `Poll` and `Topology`: the plugin's read paths. It never plans,
//! applies or reverts, so it writes nothing. It prints shapes and counts only, never names,
//! addresses or identifiers.

use std::{collections::BTreeMap, time::Duration};

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
        eprintln!("skipped: no UNIFI_URL in .env");
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
            eprintln!("skipped: no local account and no local Integration API key in .env");
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
    let Some(ctx) = live_context().await else {
        return;
    };
    let health = Unifi.check(&ctx).await.expect("check");
    println!(
        "check: health {:?}, version {}",
        health.health,
        health.remote_version.as_deref().map_or_else(
            || "unknown".to_owned(),
            |v| v.split('.').take(2).collect::<Vec<_>>().join(".")
        )
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
