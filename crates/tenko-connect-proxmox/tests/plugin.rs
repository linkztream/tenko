//! The Proxmox VE plugin against a mock API serving fixtures: the inventory, paging, the
//! health check, error mapping, and the conformance suite against the plugin executable.

mod support;

use std::{collections::BTreeMap, ffi::OsString, net::IpAddr, path::PathBuf, time::Duration};

use support::{Mock, fixture};
use tenko_connect::{
    CallContext, Connector, ConnectorError, Cursor, Health, InventorySource, Secrets,
    conformance::{SuiteOptions, run},
    host::launch::LaunchSpec,
};
use tenko_connect_proxmox::{Proxmox, SECRET, manifest};
use tenko_core::observe::ObservedHost;
use zeroize::Zeroizing;

/// A token secret in the shape of a real one; not a credential anywhere.
const TOKEN_SECRET: &str = "00000000-0000-4000-8000-000000000000";

fn secrets() -> Secrets {
    let mut secrets = Secrets::new();
    secrets.insert(SECRET, Zeroizing::new(TOKEN_SECRET.as_bytes().to_vec()));
    secrets
}

fn settings(mock: &Mock, extra: &serde_json::Value) -> serde_json::Value {
    let mut settings = serde_json::json!({
        "url": mock.url(),
        "token_id": "tenko@pve!inventory"
    });
    if let (Some(settings), Some(extra)) = (settings.as_object_mut(), extra.as_object()) {
        settings.extend(extra.clone());
    }
    settings
}

fn context(mock: &Mock, extra: &serde_json::Value) -> CallContext {
    CallContext {
        settings: settings(mock, extra),
        secrets: secrets(),
        request_id: "test".to_owned(),
        ..CallContext::default()
    }
}

/// Polls like the host: every page, following the cursors.
async fn poll_all(
    ctx: &CallContext,
) -> Result<(Vec<ObservedHost>, Vec<Option<Cursor>>), ConnectorError> {
    let mut hosts = Vec::new();
    let mut cursors = Vec::new();
    let mut cursor = None;
    for _ in 0..100 {
        let batch = Proxmox.poll(ctx, cursor).await?;
        assert!(batch.complete);
        hosts.extend(batch.hosts);
        cursors.push(batch.cursor.clone());
        if !batch.more {
            return Ok((hosts, cursors));
        }
        cursor = batch.cursor;
    }
    panic!("paging does not end");
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("ip")
}

fn host<'a>(hosts: &'a [ObservedHost], id: &str) -> &'a ObservedHost {
    hosts
        .iter()
        .find(|host| host.external_id == id)
        .unwrap_or_else(|| panic!("no host {id}"))
}

#[tokio::test]
async fn the_documented_cluster_becomes_hosts() {
    let mock = Mock::start(fixture("documented.json")).await;
    let (hosts, cursors) = poll_all(&context(&mock, &serde_json::json!({})))
        .await
        .expect("poll");
    let ids: Vec<&str> = hosts.iter().map(|h| h.external_id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "node/pve-a",
            "node/pve-b",
            "qemu/101",
            "qemu/102",
            "qemu/103",
            "lxc/105",
            "lxc/106",
            "lxc/107",
            "qemu/108"
        ]
    );
    assert_eq!(cursors, [None]);

    let node = host(&hosts, "node/pve-a");
    assert_eq!(node.ips, [ip("192.0.2.2"), ip("2001:db8::2")]);
    assert_eq!(node.os.as_deref(), Some("Proxmox VE 9.1.6"));
    assert_eq!(node.platform.as_deref(), Some("proxmox-ve"));

    let vm = host(&hosts, "qemu/101");
    assert_eq!(vm.name.as_deref(), Some("vm-01"));
    assert_eq!(
        vm.macs.iter().map(ToString::to_string).collect::<Vec<_>>(),
        ["00:00:5e:00:53:01", "00:00:5e:00:53:02"]
    );
    assert_eq!(
        vm.ips,
        [
            ip("198.51.100.10"),
            ip("203.0.113.10"),
            ip("2001:db8:30::10")
        ],
        "agent addresses on the configured MAC addresses only"
    );
    assert_eq!(vm.parent.as_deref(), Some("node/pve-a"));
    assert_eq!(vm.platform.as_deref(), Some("qemu"));
    assert_eq!(
        vm.tags,
        [
            "tag-a",
            "tag-b",
            "status:running",
            "pool:pool-a",
            "vnet:vnet1",
            "vlan:20",
            "bridge:vmbr0",
            "vlan:30"
        ]
    );

    let not_running_agent = host(&hosts, "qemu/102");
    assert_eq!(
        not_running_agent.ips,
        [ip("192.0.2.12"), ip("2001:db8::12")]
    );
    assert_eq!(
        not_running_agent.os.as_deref(),
        Some("Windows 11/2022/2025")
    );

    let stopped = host(&hosts, "qemu/103");
    assert_eq!(stopped.macs.len(), 1);
    assert_eq!(stopped.ips, Vec::<IpAddr>::new());
    assert!(stopped.tags.contains(&"status:stopped".to_owned()));

    let container = host(&hosts, "lxc/105");
    assert_eq!(container.ips, [ip("192.0.2.15"), ip("2001:db8::15")]);
    assert_eq!(container.os.as_deref(), Some("Linux (Debian)"));
    let dhcp = host(&hosts, "lxc/106");
    assert_eq!(dhcp.ips, [ip("198.51.100.16")]);
    assert!(dhcp.tags.contains(&"vlan:40".to_owned()));
    let stopped_container = host(&hosts, "lxc/107");
    assert_eq!(stopped_container.ips, [ip("192.0.2.17")]);
    assert_eq!(stopped_container.parent.as_deref(), Some("node/pve-b"));
    let forbidden_agent = host(&hosts, "qemu/108");
    assert_eq!(forbidden_agent.macs.len(), 1);
    assert_eq!(forbidden_agent.ips, Vec::<IpAddr>::new());

    let requests = mock.requests();
    assert!(requests.iter().all(|r| r.method == "GET"), "{requests:?}");
    assert!(
        requests.iter().all(|r| r.authorization.as_deref()
            == Some(&format!("PVEAPIToken=tenko@pve!inventory={TOKEN_SECRET}") as &str)),
        "every request carries the token"
    );
    assert!(
        !requests.iter().any(|r| r.path.contains("/104/")),
        "a template is not read"
    );
    assert!(
        !requests.iter().any(|r| r.path.contains("/103/agent")),
        "a stopped guest's agent is not asked"
    );
}

#[tokio::test]
async fn small_pages_report_the_same_hosts() {
    let mock = Mock::start(fixture("documented.json")).await;
    let (whole, _) = poll_all(&context(&mock, &serde_json::json!({})))
        .await
        .expect("poll");
    let (paged, cursors) = poll_all(&context(&mock, &serde_json::json!({ "page_size": 3 })))
        .await
        .expect("poll");
    assert_eq!(paged, whole);
    assert_eq!(
        cursors,
        [
            Some(Cursor("after:103".to_owned())),
            Some(Cursor("after:107".to_owned())),
            None
        ]
    );
}

#[tokio::test]
async fn filters_and_templates_follow_the_settings() {
    let mock = Mock::start(fixture("documented.json")).await;
    let ids = |hosts: Vec<ObservedHost>| -> Vec<String> {
        hosts.into_iter().map(|h| h.external_id).collect()
    };
    let (hosts, _) = poll_all(&context(
        &mock,
        &serde_json::json!({ "nodes": ["pve-b"], "include_stopped": false }),
    ))
    .await
    .expect("poll");
    assert_eq!(ids(hosts), ["node/pve-b", "qemu/108"]);
    let (hosts, _) = poll_all(&context(
        &mock,
        &serde_json::json!({ "pools": ["pool-a"], "include_templates": true }),
    ))
    .await
    .expect("poll");
    assert_eq!(
        ids(hosts),
        ["node/pve-a", "node/pve-b", "qemu/101", "lxc/105"]
    );
    let (hosts, _) = poll_all(&context(
        &mock,
        &serde_json::json!({ "include_templates": true, "guest_agent": false }),
    ))
    .await
    .expect("poll");
    assert!(
        hosts
            .iter()
            .any(|h| h.external_id == "qemu/104" && h.tags.contains(&"template".to_owned()))
    );
    assert_eq!(
        host(&hosts, "qemu/101").ips,
        Vec::<IpAddr>::new(),
        "agent off"
    );
}

#[tokio::test]
async fn refusals_and_failures_map_to_their_codes() {
    let mock = Mock::start(fixture("documented.json")).await;
    let ctx = context(&mock, &serde_json::json!({}));
    mock.set("/api2/json/cluster/resources", 401, r#"{"data":null}"#);
    assert_eq!(
        poll_all(&ctx).await.expect_err("401"),
        ConnectorError::Unauthorized
    );
    mock.set("/api2/json/cluster/resources", 403, r#"{"data":null}"#);
    assert_eq!(
        poll_all(&ctx).await.expect_err("403"),
        ConnectorError::Forbidden
    );
    mock.set(
        "/api2/json/cluster/resources",
        200,
        r#"{"data":{"not":"a list"}}"#,
    );
    assert!(matches!(
        poll_all(&ctx).await.expect_err("shape"),
        ConnectorError::Protocol(_)
    ));
    mock.set("/api2/json/cluster/resources", 200, "not json");
    assert!(matches!(
        poll_all(&ctx).await.expect_err("json"),
        ConnectorError::Protocol(_)
    ));

    // A guest configuration that fails on the server fails the poll rather than report the
    // guest without its addresses.
    let mock = Mock::start(fixture("documented.json")).await;
    let ctx = context(&mock, &serde_json::json!({}));
    mock.set(
        "/api2/json/nodes/pve-a/qemu/102/config",
        500,
        r#"{"data":null}"#,
    );
    assert_eq!(
        poll_all(&ctx).await.expect_err("500"),
        ConnectorError::Unreachable
    );
    // A guest that disappeared between the two requests is left out.
    mock.set(
        "/api2/json/nodes/pve-a/qemu/102/config",
        404,
        r#"{"data":null}"#,
    );
    let (hosts, _) = poll_all(&ctx).await.expect("poll");
    assert!(!hosts.iter().any(|h| h.external_id == "qemu/102"));
    // A configuration the token may not read keeps the guest without addresses.
    mock.set(
        "/api2/json/nodes/pve-a/qemu/102/config",
        403,
        r#"{"data":null}"#,
    );
    let (hosts, _) = poll_all(&ctx).await.expect("poll");
    assert_eq!(host(&hosts, "qemu/102").macs.len(), 0);

    let closed = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", closed.local_addr().expect("addr"));
    drop(closed);
    let ctx = CallContext {
        settings: serde_json::json!({ "url": url, "token_id": "tenko@pve!inventory" }),
        secrets: secrets(),
        ..CallContext::default()
    };
    assert_eq!(
        poll_all(&ctx).await.expect_err("refused"),
        ConnectorError::Unreachable
    );
    let report = Proxmox.check(&ctx).await.expect("report");
    assert_eq!(report.health, Health::Unreachable);
    assert!(
        report
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("no connection"))
    );

    let without_secret = CallContext {
        settings: ctx.settings.clone(),
        ..CallContext::default()
    };
    assert!(matches!(
        Proxmox.poll(&without_secret, None).await,
        Err(ConnectorError::InvalidSettings(text)) if text.contains(SECRET)
    ));
    assert!(matches!(
        Proxmox.poll(&ctx, Some(Cursor("page:2".to_owned()))).await,
        Err(ConnectorError::InvalidSettings(_))
    ));
}

#[tokio::test]
async fn the_check_reports_version_and_missing_privileges() {
    let mock = Mock::start(fixture("documented.json")).await;
    let ctx = context(&mock, &serde_json::json!({}));
    let report = Proxmox.check(&ctx).await.expect("check");
    assert_eq!(report.health, Health::Healthy);
    assert_eq!(report.remote_version.as_deref(), Some("Proxmox VE 9.1.6"));
    assert!(report.latency_ms.is_some());
    let detail = report.detail.unwrap_or_default();
    assert!(detail.contains("not encrypted"), "{detail}");

    mock.set(
        "/api2/json/access/permissions",
        200,
        r#"{"data":{"/":{"Sys.Audit":1}}}"#,
    );
    let report = Proxmox.check(&ctx).await.expect("check");
    assert_eq!(report.health, Health::Degraded);
    let detail = report.detail.unwrap_or_default();
    assert!(detail.contains("VM.Audit is missing"), "{detail}");
    assert!(
        detail.contains("VM.GuestAgent.Audit is missing"),
        "{detail}"
    );
    assert!(detail.contains("SDN.Audit is missing"), "{detail}");

    mock.set("/api2/json/version", 401, r#"{"data":null}"#);
    assert_eq!(
        Proxmox.check(&ctx).await.expect_err("401"),
        ConnectorError::Unauthorized
    );
}

fn launch_spec() -> LaunchSpec {
    LaunchSpec {
        expected: Some(manifest()),
        program: PathBuf::from(env!("CARGO_BIN_EXE_tenko-plugin-proxmox")),
        args: Vec::<OsString>::new(),
        cwd: None,
        env: Vec::new(),
    }
}

#[tokio::test]
async fn the_plugin_passes_the_conformance_suite_against_the_mock() {
    let mock = Mock::start(fixture("documented.json")).await;
    let options = SuiteOptions {
        settings: Some(settings(&mock, &serde_json::json!({ "page_size": 10 }))),
        secrets: secrets(),
        call_timeout: Duration::from_secs(20),
        ..SuiteOptions::default()
    };
    let report = run(&launch_spec(), &options).await;
    assert!(report.passed(), "{report}");
    let inventory = report.check("capability.inventory").expect("inventory");
    assert!(
        inventory.detail.contains("9 hosts in 1 page(s)"),
        "{report}"
    );
    let check = report.check("check").expect("check");
    assert!(check.detail.contains("Healthy"), "{report}");
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

#[test]
fn fixtures_hold_documentation_data_only() {
    let routes: BTreeMap<String, support::Answer> = fixture("documented.json");
    for (path, (_, body)) in &routes {
        for word in body.split(|c: char| !(c.is_ascii_hexdigit() || c == ':' || c == '.')) {
            if let Ok(address) = word.parse::<IpAddr>() {
                let documentation = match address {
                    IpAddr::V4(v4) => {
                        let [a, b, c, _] = v4.octets();
                        matches!((a, b, c), (192, 0, 2) | (198, 51, 100) | (203, 0, 113))
                            || v4.is_loopback()
                    }
                    IpAddr::V6(v6) => {
                        v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8
                            || v6.is_loopback()
                            || (v6.segments()[0] & 0xffc0) == 0xfe80
                    }
                };
                assert!(documentation, "{path}: {address}");
            }
        }
    }
}
