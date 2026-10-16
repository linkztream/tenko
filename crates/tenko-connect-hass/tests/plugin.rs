//! The Home Assistant plugin against a mock serving fixtures over REST and the WebSocket
//! API: the inventory with vendor facts, the health check, error mapping, and the
//! conformance suite against the plugin executable.

mod support;

use std::{ffi::OsString, net::IpAddr, path::PathBuf, time::Duration};

use support::{Mock, TOKEN, fixture};
use tenko_connect::{
    CallContext, Connector, ConnectorError, Health, InventorySource, Secrets,
    conformance::{SuiteOptions, run},
    host::launch::LaunchSpec,
};
use tenko_connect_hass::{HomeAssistant, SECRET, manifest};
use zeroize::Zeroizing;

fn secrets(token: &str) -> Secrets {
    let mut secrets = Secrets::new();
    secrets.insert(SECRET, Zeroizing::new(token.as_bytes().to_vec()));
    secrets
}

fn settings(mock: &Mock, extra: &serde_json::Value) -> serde_json::Value {
    let mut settings = serde_json::json!({ "url": mock.url() });
    if let (Some(settings), Some(extra)) = (settings.as_object_mut(), extra.as_object()) {
        settings.extend(extra.clone());
    }
    settings
}

fn context(mock: &Mock, extra: &serde_json::Value) -> CallContext {
    CallContext {
        settings: settings(mock, extra),
        secrets: secrets(TOKEN),
        request_id: "test".to_owned(),
        ..CallContext::default()
    }
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("ip")
}

#[tokio::test]
async fn the_documented_instance_becomes_hosts_and_vendor_facts() {
    let mock = Mock::start(fixture("documented.json")).await;
    let batch = HomeAssistant
        .poll(&context(&mock, &serde_json::json!({})), None)
        .await
        .expect("poll");
    assert!(batch.complete);
    assert!(!batch.more);
    assert_eq!(batch.cursor, None);
    let ids: Vec<&str> = batch.hosts.iter().map(|h| h.external_id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "device/00000000000000000000000000000001",
            "device/00000000000000000000000000000002",
            "device/00000000000000000000000000000006",
            "device/00000000000000000000000000000007",
            "entity/device_tracker.entity_1",
            "entity/device_tracker.entity_2",
        ]
    );
    let plug = &batch.hosts[0];
    assert_eq!(plug.name.as_deref(), Some("Device 01 (renamed)"));
    assert_eq!(plug.platform.as_deref(), Some("Model A"));
    assert_eq!(plug.tags, ["integration:shelly", "area:Area A"]);
    assert_eq!(
        plug.macs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["00:00:5e:00:53:21"]
    );
    let board = &batch.hosts[1];
    assert_eq!(board.ips, [ip("192.0.2.22")]);
    assert_eq!(
        board.macs.len(),
        1,
        "the Bluetooth address is not a network MAC"
    );
    let router = &batch.hosts[2];
    assert_eq!(router.ips, [ip("192.0.2.1"), ip("203.0.113.4")]);
    assert_eq!(router.platform.as_deref(), Some("Model C"));
    let speaker = &batch.hosts[3];
    assert_eq!(speaker.ips, [ip("2001:db8::27")]);
    assert_eq!(speaker.tags, ["integration:examplecast"]);
    let phone = &batch.hosts[4];
    assert_eq!(phone.ips, [ip("192.0.2.31")]);
    assert_eq!(phone.name.as_deref(), Some("entity 1"));
    let away = &batch.hosts[5];
    assert_eq!(away.ips, Vec::<IpAddr>::new());
    assert_eq!(away.macs.len(), 1);

    let vendors: Vec<(String, &str)> = batch
        .vendors
        .iter()
        .map(|f| (f.mac.to_string(), f.vendor.as_str()))
        .collect();
    assert_eq!(
        vendors,
        [
            ("00:00:5e:00:53:21".to_owned(), "Example Manufacturer A"),
            ("00:00:5e:00:53:22".to_owned(), "Example Manufacturer B"),
        ]
    );

    let seen = mock.seen();
    assert!(
        seen.rest.iter().all(|(method, _)| method == "GET"),
        "{:?}",
        seen.rest
    );
    assert_eq!(
        seen.authorized,
        seen.rest.len(),
        "every REST request carries the token"
    );
    let kinds: Vec<&str> = seen.ws.iter().filter_map(|m| m["type"].as_str()).collect();
    assert_eq!(
        kinds,
        [
            "auth",
            "config/device_registry/list",
            "config/entity_registry/list",
            "config/area_registry/list",
            "config_entries/get"
        ],
        "only list commands"
    );
    assert_eq!(seen.pongs, 1, "the ping was answered");
}

#[tokio::test]
async fn without_config_entries_the_integration_comes_from_the_entities() {
    let mock = Mock::start(fixture("documented.json")).await;
    mock.set_ws(
        "config_entries/get",
        serde_json::json!({ "error": { "code": "unauthorized", "message": "Unauthorized" } }),
    );
    let batch = HomeAssistant
        .poll(&context(&mock, &serde_json::json!({})), None)
        .await
        .expect("poll");
    let board = batch
        .hosts
        .iter()
        .find(|h| h.external_id.ends_with("02"))
        .expect("board");
    assert_eq!(board.tags, ["integration:esphome"]);
}

#[tokio::test]
async fn settings_filter_integrations_and_trackers() {
    let mock = Mock::start(fixture("documented.json")).await;
    let ids = |hosts: Vec<tenko_core::observe::ObservedHost>| -> Vec<String> {
        hosts.into_iter().map(|h| h.external_id).collect()
    };
    let batch = HomeAssistant
        .poll(
            &context(
                &mock,
                &serde_json::json!({ "integrations": ["esphome", "shelly"], "include_disabled": true }),
            ),
            None,
        )
        .await
        .expect("poll");
    assert_eq!(
        ids(batch.hosts),
        [
            "device/00000000000000000000000000000001",
            "device/00000000000000000000000000000002",
            "device/00000000000000000000000000000005",
        ]
    );
    let states_read = |mock: &Mock| {
        mock.seen()
            .rest
            .iter()
            .filter(|(_, path)| path == "/api/states")
            .count()
    };
    let before = states_read(&mock);
    let batch = HomeAssistant
        .poll(
            &context(
                &mock,
                &serde_json::json!({ "device_trackers": false, "entity_addresses": false }),
            ),
            None,
        )
        .await
        .expect("poll");
    assert_eq!(
        ids(batch.hosts),
        [
            "device/00000000000000000000000000000001",
            "device/00000000000000000000000000000002",
        ]
    );
    assert_eq!(
        states_read(&mock),
        before,
        "states are not read when nothing needs them"
    );
}

#[tokio::test]
async fn refusals_and_failures_map_to_their_codes() {
    let mock = Mock::start(fixture("documented.json")).await;
    let wrong_token = CallContext {
        settings: settings(&mock, &serde_json::json!({})),
        secrets: secrets("wrong"),
        ..CallContext::default()
    };
    assert_eq!(
        HomeAssistant
            .poll(&wrong_token, None)
            .await
            .expect_err("token"),
        ConnectorError::Unauthorized
    );
    assert_eq!(
        HomeAssistant.check(&wrong_token).await.expect_err("token"),
        ConnectorError::Unauthorized
    );

    let ctx = context(&mock, &serde_json::json!({}));
    mock.set_ws(
        "config/device_registry/list",
        serde_json::json!({ "error": { "code": "unauthorized", "message": "Unauthorized" } }),
    );
    assert_eq!(
        HomeAssistant.poll(&ctx, None).await.expect_err("forbidden"),
        ConnectorError::Forbidden
    );
    let report = HomeAssistant.check(&ctx).await.expect("check");
    assert_eq!(report.health, Health::Degraded);
    assert!(
        report
            .detail
            .unwrap_or_default()
            .contains("device registry is not readable")
    );

    let mock = Mock::start(fixture("documented.json")).await;
    let ctx = context(&mock, &serde_json::json!({}));
    mock.set_rest("/api/states", 200, r#"{"not":"a list"}"#);
    assert!(matches!(
        HomeAssistant.poll(&ctx, None).await.expect_err("shape"),
        ConnectorError::Protocol(_)
    ));
    mock.set_rest("/api/", 404, "{}");
    assert!(matches!(
        HomeAssistant.check(&ctx).await.expect_err("404"),
        ConnectorError::InvalidSettings(_)
    ));

    let closed = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", closed.local_addr().expect("addr"));
    drop(closed);
    let refused = CallContext {
        settings: serde_json::json!({ "url": url }),
        secrets: secrets(TOKEN),
        ..CallContext::default()
    };
    assert_eq!(
        HomeAssistant
            .poll(&refused, None)
            .await
            .expect_err("refused"),
        ConnectorError::Unreachable
    );
    let report = HomeAssistant.check(&refused).await.expect("report");
    assert_eq!(report.health, Health::Unreachable);

    let without_secret = CallContext {
        settings: serde_json::json!({ "url": "http://192.0.2.40:8123" }),
        ..CallContext::default()
    };
    assert!(matches!(
        HomeAssistant.poll(&without_secret, None).await,
        Err(ConnectorError::InvalidSettings(text)) if text.contains(SECRET)
    ));
}

#[tokio::test]
async fn the_check_reports_the_version() {
    let mock = Mock::start(fixture("documented.json")).await;
    let report = HomeAssistant
        .check(&context(&mock, &serde_json::json!({})))
        .await
        .expect("check");
    assert_eq!(report.health, Health::Healthy);
    assert_eq!(
        report.remote_version.as_deref(),
        Some("Home Assistant 2026.10.0")
    );
    assert!(report.detail.unwrap_or_default().contains("not encrypted"));
}

fn launch_spec() -> LaunchSpec {
    LaunchSpec {
        expected: Some(manifest()),
        program: PathBuf::from(env!("CARGO_BIN_EXE_tenko-plugin-hass")),
        args: Vec::<OsString>::new(),
        cwd: None,
        env: Vec::new(),
    }
}

#[tokio::test]
async fn the_plugin_passes_the_conformance_suite_against_the_mock() {
    let mock = Mock::start(fixture("documented.json")).await;
    let options = SuiteOptions {
        settings: Some(settings(&mock, &serde_json::json!({}))),
        secrets: secrets(TOKEN),
        call_timeout: Duration::from_secs(20),
        ..SuiteOptions::default()
    };
    let report = run(&launch_spec(), &options).await;
    assert!(report.passed(), "{report}");
    let inventory = report.check("capability.inventory").expect("inventory");
    assert!(
        inventory
            .detail
            .contains("6 hosts in 1 page(s), 2 vendor facts"),
        "{report}"
    );
}

#[tokio::test]
async fn the_plugin_passes_the_conformance_suite_without_settings() {
    let options = SuiteOptions {
        call_timeout: Duration::from_secs(20),
        ..SuiteOptions::default()
    };
    let report = run(&launch_spec(), &options).await;
    assert!(report.passed(), "{report}");
}

/// The recording of a real instance (`tests/fixtures/recorded.json`, see the README there)
/// reads as the live smoke did on the day of the recording: 106 of 360 devices have a MAC
/// address, no entity shows an IP address, 9 integrations, 34 devices in an area.
#[tokio::test]
async fn the_recorded_instance_reads_like_the_live_one() {
    use std::collections::BTreeSet;

    use tenko_connect_hass::inventory::{self, Options, Snapshot};

    let mock = Mock::start(fixture("recorded.json")).await;
    let ctx = context(&mock, &serde_json::json!({}));
    let report = HomeAssistant.check(&ctx).await.expect("check");
    assert_eq!(report.health, Health::Healthy);
    assert!(
        report
            .remote_version
            .is_some_and(|v| v.starts_with("Home Assistant 20"))
    );
    let batch = HomeAssistant.poll(&ctx, None).await.expect("poll");
    assert!(batch.complete && !batch.more);
    let hosts = &batch.hosts;
    assert_eq!(hosts.len(), 106);
    assert!(hosts.iter().all(|h| h.external_id.starts_with("device/")));
    assert_eq!(hosts.iter().map(|h| h.macs.len()).sum::<usize>(), 115);
    assert!(hosts.iter().all(|h| h.ips.is_empty()));
    assert!(hosts.iter().all(|h| h.platform.is_some()));
    assert_eq!(
        hosts
            .iter()
            .filter(|h| h.tags.iter().any(|t| t.starts_with("area:")))
            .count(),
        34
    );
    assert_eq!(batch.vendors.len(), 52);
    let integrations: BTreeSet<&str> = hosts
        .iter()
        .flat_map(|h| h.tags.iter())
        .filter_map(|t| t.strip_prefix("integration:"))
        .collect();
    assert_eq!(integrations.len(), 9);

    // The recording maps every public IPv4 address into TEST-NET-3, which the plugin counts
    // as local; with TEST-NET-3 as "the internet" the inventory must come out the same.
    let text = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/recorded.json"),
    )
    .expect("fixture");
    let value: serde_json::Value = serde_json::from_str(&text).expect("JSON");
    let list = |v: &serde_json::Value| v.as_array().cloned().unwrap_or_default();
    let snapshot = Snapshot {
        devices: list(&value["ws"]["config/device_registry/list"]),
        entities: list(&value["ws"]["config/entity_registry/list"]),
        areas: list(&value["ws"]["config/area_registry/list"]),
        entries: Some(list(&value["ws"]["config_entries/get"])),
        states: list(&value["rest"]["/api/states"]),
    };
    assert_eq!(snapshot.devices.len(), 360);
    let built = inventory::build(
        &snapshot,
        &Options {
            public_v4: |ip| ip.octets()[..3] == [203, 0, 113],
            ..Options::default()
        },
    );
    assert_eq!(built.hosts, batch.hosts);
    assert_eq!(built.vendors, batch.vendors);
}
