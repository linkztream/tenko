//! The port bounce and the client kick (ADR 0028) against the recordings of a real
//! controller (`tests/fixtures/recorded/`, documentation addresses and MAC addresses only),
//! served by the fake controller: the down switches the port off through its override's
//! `forward` and touches nothing else, the plan carries the way back up, the way back up
//! restores the override exactly (or removes the entry the bounce added), the kick is the
//! station manager's `kick-sta`, and the host's guardrails refuse the ports the recording
//! shows as shared or as uplinks.

mod support;

use serde_json::{Value, json};
use support::{FakeController, Flavor};
use tenko_connect::{
    ConnectorError, DeviceRef, Guardrails, L2Change, NetworkController, WriteMode, guardrail,
};
use tenko_connect_unifi::Unifi;
use tenko_core::{Coded, MacAddr};

/// A switch of the recording: port 1 has an override with `forward: all`, port 2 none; one
/// client on each. Port 7 has 29 learned MAC addresses, port 8 is its uplink.
const SWITCH: &str = "00:00:5e:00:53:02";
const SWITCH_ID: &str = "00000000000000000000005b";
/// A switch of the recording with two clients on port 47.
const SHARED: &str = "00:00:5e:00:53:1f";
/// A wireless client of the recording, and a wired one.
const WIRELESS: &str = "00:00:5e:00:53:14";

fn device(mac: &str) -> DeviceRef {
    DeviceRef(mac.to_owned())
}

fn bounce(port: u16) -> L2Change {
    L2Change::BouncePort {
        device: device(SWITCH),
        port,
        down_secs: 5,
    }
}

fn overrides(fake: &FakeController) -> Vec<Value> {
    let state = fake.state();
    state
        .devices
        .iter()
        .find(|d| d["mac"] == SWITCH)
        .and_then(|d| d["port_overrides"].as_array().cloned())
        .unwrap_or_default()
}

fn entry(overrides: &[Value], port: u16) -> Option<Value> {
    overrides.iter().find(|o| o["port_idx"] == port).cloned()
}

async fn enabled(fake: &FakeController, port: u16) -> Option<bool> {
    let topology = Unifi.topology(&fake.context()).await.expect("topology");
    topology
        .device(&device(SWITCH))
        .and_then(|d| d.ports.iter().find(|p| p.index == port))
        .and_then(|p| p.enabled)
}

/// Bounces `port` down and back up through the plugin, as the host does, and returns the
/// overrides after the down.
async fn down_and_up(fake: &FakeController, port: u16) -> Vec<Value> {
    let ctx = fake.context();
    let plan = Unifi.plan(&ctx, &bounce(port)).await.expect("plan");
    assert_eq!(plan.diff.len(), 1, "{plan:?}");
    assert_eq!(
        plan.diff[0].path,
        format!("devices/{SWITCH}/ports/{port}/enabled")
    );
    assert_eq!(
        (
            plan.diff[0].before.as_deref(),
            plan.diff[0].after.as_deref()
        ),
        (Some("true"), Some("false"))
    );
    let [up @ L2Change::EnablePort { .. }] = plan.undo.as_slice() else {
        panic!("the plan carries one way back up: {plan:?}");
    };
    let receipt = Unifi
        .apply(&ctx, &plan, WriteMode::Apply)
        .await
        .expect("down");
    assert!(receipt.verified);
    assert_eq!(receipt.undo, plan.undo);
    assert!(
        Unifi
            .plan(&ctx, &bounce(port))
            .await
            .expect("again")
            .diff
            .is_empty(),
        "the port reads as off"
    );
    assert_eq!(enabled(fake, port).await, Some(false));
    let after_down = overrides(fake);

    let back = Unifi.plan(&ctx, up).await.expect("plan up");
    assert_eq!(back.diff.len(), 1);
    let receipt = Unifi
        .apply(&ctx, &back, WriteMode::Apply)
        .await
        .expect("up");
    assert!(receipt.verified);
    assert_eq!(Unifi.plan(&ctx, up).await.expect("again").diff.len(), 0);
    assert_eq!(enabled(fake, port).await, Some(true));
    after_down
}

#[tokio::test]
async fn a_bounce_switches_the_override_off_and_the_way_back_up_restores_it_exactly() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    fake.load_recorded();
    let before = overrides(&fake);
    let original = entry(&before, 1).expect("port 1 has an override");
    assert_eq!(original["forward"], "all");

    let after_down = down_and_up(&fake, 1).await;
    // The down changed `forward` only, on port 1 only.
    let mut expected = original.clone();
    expected["forward"] = json!("disabled");
    assert_eq!(entry(&after_down, 1), Some(expected));
    assert_eq!(after_down.len(), before.len());
    for other in before.iter().filter(|o| o["port_idx"] != 1) {
        assert!(after_down.contains(other), "{other} is untouched");
    }
    // The way back up restores the whole array as recorded.
    assert_eq!(overrides(&fake), before);
    let writes = fake.writes();
    assert_eq!(writes.len(), 2, "one write down, one up");
    assert!(
        writes
            .iter()
            .all(|w| w.method == "PUT" && w.route() == format!("rest/device/{SWITCH_ID}"))
    );
}

#[tokio::test]
async fn a_bounce_of_a_port_without_an_override_adds_the_entry_and_removes_it_again() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    fake.load_recorded();
    let before = overrides(&fake);
    assert!(entry(&before, 2).is_none());
    let after_down = down_and_up(&fake, 2).await;
    assert_eq!(
        entry(&after_down, 2),
        Some(json!({ "port_idx": 2, "forward": "disabled" }))
    );
    assert_eq!(overrides(&fake), before);
}

#[tokio::test]
async fn the_way_back_up_keeps_what_someone_changed_meanwhile() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    fake.load_recorded();
    let ctx = fake.context();
    let plan = Unifi.plan(&ctx, &bounce(1)).await.expect("plan");
    Unifi
        .apply(&ctx, &plan, WriteMode::Apply)
        .await
        .expect("down");
    // An administrator renames the port while it is down.
    {
        let mut state = fake.state();
        let switch = state
            .devices
            .iter_mut()
            .find(|d| d["mac"] == SWITCH)
            .expect("switch");
        let entry = switch["port_overrides"]
            .as_array_mut()
            .and_then(|all| all.iter_mut().find(|o| o["port_idx"] == 1))
            .expect("entry");
        entry["name"] = json!("printer-port");
    }
    let up = &plan.undo[0];
    let back = Unifi.plan(&ctx, up).await.expect("plan up");
    Unifi
        .apply(&ctx, &back, WriteMode::Apply)
        .await
        .expect("up");
    let restored = entry(&overrides(&fake), 1).expect("entry");
    assert_eq!(restored["forward"], "all");
    assert_eq!(restored["name"], "printer-port");
}

#[tokio::test]
async fn a_malformed_way_back_up_is_refused_before_anything_is_written() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    fake.load_recorded();
    for restore in [
        "",
        "{}",
        r#"{"entry":true,"forward":"disabled"}"#,
        r#"{"entry":true,"forward":"ALL; x"}"#,
    ] {
        let up = L2Change::EnablePort {
            device: device(SWITCH),
            port: 1,
            restore: restore.to_owned(),
        };
        let error = Unifi.plan(&fake.context(), &up).await.expect_err(restore);
        assert_eq!(error.code(), "connect.invalid_settings", "{restore}");
    }
    assert_eq!(fake.writes().len(), 0);
}

#[tokio::test]
async fn a_kick_is_the_station_managers_kick_sta() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    fake.load_recorded();
    let ctx = fake.context();
    let mac: MacAddr = WIRELESS.parse().expect("mac");
    let kick = L2Change::KickClient { mac };
    let plan = Unifi.plan(&ctx, &kick).await.expect("plan");
    assert_eq!(plan.diff[0].path, format!("clients/{WIRELESS}/association"));
    assert_eq!(plan.undo.len(), 0);
    let receipt = Unifi
        .apply(&ctx, &plan, WriteMode::Apply)
        .await
        .expect("kick");
    assert!(receipt.verified);
    assert_eq!(receipt.undo.len(), 0);
    let writes = fake.writes();
    assert_eq!(writes.len(), 1);
    assert_eq!(
        (writes[0].method.as_str(), writes[0].route()),
        ("POST", "cmd/stamgr")
    );
    assert_eq!(
        writes[0].body,
        json!({ "cmd": "kick-sta", "mac": WIRELESS })
    );
    // The client is gone until it associates again: a second kick finds nothing.
    assert_eq!(
        Unifi.plan(&ctx, &kick).await.expect_err("gone"),
        ConnectorError::NotFound
    );
}

#[tokio::test]
async fn a_wired_client_is_never_kicked() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    fake.load_recorded();
    let wired: MacAddr = {
        let state = fake.state();
        state
            .clients
            .iter()
            .find(|c| c["is_wired"] == true)
            .and_then(|c| c["mac"].as_str())
            .expect("a wired client")
            .parse()
            .expect("mac")
    };
    let error = Unifi
        .plan(&fake.context(), &L2Change::KickClient { mac: wired })
        .await
        .expect_err("wired");
    assert_eq!(error.code(), "connect.invalid_settings");
}

#[tokio::test]
async fn the_host_guardrails_refuse_the_recorded_shared_ports_and_uplinks() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    fake.load_recorded();
    let topology = Unifi.topology(&fake.context()).await.expect("topology");
    let guardrails = Guardrails::default();
    let refuse = |mac: &str, port: u16| match guardrails.check_bounce(&device(mac), port, &topology)
    {
        Err(ConnectorError::GuardrailRefused { rule }) => rule,
        other => panic!("{mac} port {port}: expected a refusal, got {other:?}"),
    };
    assert_eq!(refuse(SHARED, 47), guardrail::SHARED_PORT, "two clients");
    // Port 7 leads to another switch (29 learned MAC addresses): a link, refused as such.
    assert_eq!(refuse(SWITCH, 7), guardrail::UPLINK);
    // Port 4 of the third switch: one listed client, two learned MAC addresses and an LLDP
    // neighbour the controller does not manage behind it.
    assert_eq!(refuse("00:00:5e:00:53:38", 4), guardrail::UPLINK);
    assert_eq!(refuse(SWITCH, 8), guardrail::UPLINK);
    assert_eq!(refuse(SWITCH, 99), guardrail::PORT_UNKNOWN);
    assert!(
        guardrails
            .check_bounce(&device(SWITCH), 1, &topology)
            .is_ok()
    );
    let wireless: MacAddr = WIRELESS.parse().expect("mac");
    assert!(guardrails.check_kick(wireless, &topology).is_ok());
}
