//! The write path against the fake controller: the host's guardrails refuse what the plugin's
//! topology marks, a dry run writes nothing, a write is read back and plans again empty, a
//! drifted read-back is not verified, a stale plan is refused, and an undo restores the
//! previous state (CONN-06, CONN-08, CONN-09).

mod support;

use serde_json::Value;
use support::{FakeController, Flavor};
use tenko_connect::{
    ConnectorError, ControllerDhcp, DeviceRef, Guardrails, L2Change, NetworkController, NetworkRef,
    ProfileRef, WriteMode,
};
use tenko_connect_unifi::Unifi;
use tenko_core::{Coded, MacAddr};

const IOT: &str = "5f1000000000000000000002";
const GUEST: &str = "5f1000000000000000000003";
const DEFAULT_NET: &str = "5f1000000000000000000001";
const TRUNK: &str = "5f2000000000000000000004";
const IOT_PROFILE: &str = "5f2000000000000000000003";
const ALL: &str = "5f2000000000000000000001";
const GATEWAY: &str = "00:00:5e:00:53:01";
const CORE: &str = "00:00:5e:00:53:10";
const ACCESS: &str = "00:00:5e:00:53:11";
const PRINTER: &str = "00:00:5e:00:53:40";
const NAS: &str = "00:00:5e:00:53:80";
const PHONE: &str = "00:00:5e:00:53:42";

fn mac(text: &str) -> MacAddr {
    text.parse().expect("mac")
}

fn port_change(device: &str, port: u16, profile: &str) -> L2Change {
    L2Change::SetPortProfile {
        device: DeviceRef(device.to_owned()),
        port,
        profile: ProfileRef(profile.to_owned()),
    }
}

fn new_network() -> L2Change {
    L2Change::EnsureNetwork {
        vlan: 70,
        name: "Cameras".to_owned(),
        dhcp: ControllerDhcp::Disabled,
    }
}

fn code(error: &ConnectorError) -> &'static str {
    error.code()
}

fn rule(result: Result<(), ConnectorError>) -> &'static str {
    match result {
        Err(ConnectorError::GuardrailRefused { rule }) => rule,
        other => panic!("expected a guardrail refusal, got {other:?}"),
    }
}

fn network_named(fake: &FakeController, name: &str) -> Option<Value> {
    fake.state()
        .networks
        .iter()
        .find(|n| n["name"] == name)
        .cloned()
}

fn user_override(fake: &FakeController, client: &str) -> (bool, String) {
    let state = fake.state();
    let user = state
        .users
        .iter()
        .find(|u| u["mac"] == client)
        .expect("user");
    (
        user["virtual_network_override_enabled"]
            .as_bool()
            .unwrap_or(false),
        user["virtual_network_override_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    )
}

fn port_profile(fake: &FakeController, device: &str, port: u16) -> Option<String> {
    let state = fake.state();
    let device = state.devices.iter().find(|d| d["mac"] == device)?;
    device["port_overrides"]
        .as_array()?
        .iter()
        .find(|o| o["port_idx"] == port)
        .and_then(|o| o["portconf_id"].as_str().map(str::to_owned))
}

#[tokio::test]
async fn the_host_guardrails_refuse_what_the_topology_marks() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    // The NAS plays the controller: its address is the controller's (the URL host).
    {
        let mut state = fake.state();
        let nas = state
            .clients
            .iter_mut()
            .find(|c| c["mac"] == NAS)
            .expect("nas");
        nas["ip"] = Value::from("127.0.0.1");
    }
    let ctx = fake.context();
    let topology = Unifi.topology(&ctx).await.expect("topology");
    let guardrails = Guardrails::default();
    assert_eq!(
        rule(guardrails.check(&port_change(CORE, 1, IOT_PROFILE), &topology)),
        "connect.guardrail.uplink",
        "the switch's own uplink"
    );
    assert_eq!(
        rule(guardrails.check(&port_change(GATEWAY, 2, IOT_PROFILE), &topology)),
        "connect.guardrail.uplink",
        "the gateway port the core switch hangs on"
    );
    assert_eq!(
        rule(guardrails.check(&port_change(CORE, 12, IOT_PROFILE), &topology)),
        "connect.guardrail.management_port",
        "the controller's access port"
    );
    let move_controller = L2Change::SetClientVlan {
        mac: mac(NAS),
        network: NetworkRef(IOT.to_owned()),
    };
    assert_eq!(
        rule(guardrails.check(&move_controller, &topology)),
        "connect.guardrail.management_client"
    );
    let into_management = L2Change::SetClientVlan {
        mac: mac(PRINTER),
        network: NetworkRef(DEFAULT_NET.to_owned()),
    };
    assert_eq!(
        rule(guardrails.check(&into_management, &topology)),
        "connect.guardrail.protected_network"
    );
    assert!(
        guardrails
            .check(&port_change(ACCESS, 5, TRUNK), &topology)
            .is_ok()
    );
    assert_eq!(fake.writes().len(), 0, "reading writes nothing");
}

#[tokio::test]
async fn a_dry_run_writes_nothing() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    let ctx = fake.context();
    let plan = Unifi.plan(&ctx, &new_network()).await.expect("plan");
    let paths: Vec<&str> = plan.diff.iter().map(|line| line.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "networks/vlan-70/name",
            "networks/vlan-70/vlan",
            "networks/vlan-70/purpose",
            "networks/vlan-70/dhcp"
        ]
    );
    assert!(plan.warnings.iter().any(|w| w.contains("VLAN-only")));
    let receipt = Unifi
        .apply(&ctx, &plan, WriteMode::DryRun)
        .await
        .expect("dry run");
    assert_eq!(receipt.mode, WriteMode::DryRun);
    assert!(receipt.verified);
    assert_eq!(receipt.undo, Vec::<L2Change>::new());
    assert_eq!(fake.writes().len(), 0);
    assert!(network_named(&fake, "Cameras").is_none());
}

#[tokio::test]
async fn a_new_network_is_written_read_back_and_undone() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    let ctx = fake.context();
    let plan = Unifi.plan(&ctx, &new_network()).await.expect("plan");
    let receipt = Unifi
        .apply(&ctx, &plan, WriteMode::Apply)
        .await
        .expect("write");
    assert!(receipt.verified);
    let created = network_named(&fake, "Cameras").expect("created");
    assert_eq!(created["purpose"], "vlan-only");
    assert_eq!(created["vlan"], 70);
    let id = created["_id"].as_str().expect("id").to_owned();
    assert_eq!(
        receipt.undo,
        [L2Change::RemoveNetwork {
            network: NetworkRef(id),
            vlan: 70
        }]
    );
    let writes = fake.writes();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].method, "POST");
    assert!(writes[0].path.ends_with("/rest/networkconf"));
    let again = Unifi.plan(&ctx, &new_network()).await.expect("plan again");
    assert_eq!(again.diff.len(), 0, "the host's verification plan is empty");
    Unifi.revert(&ctx, &receipt).await.expect("undo");
    assert!(network_named(&fake, "Cameras").is_none());
    assert_eq!(
        fake.writes().last().map(|w| w.method.as_str()),
        Some("DELETE")
    );
}

#[tokio::test]
async fn an_existing_network_is_renamed_and_its_dhcp_restored_by_the_undo() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    let ctx = fake.context();
    let change = L2Change::EnsureNetwork {
        vlan: 30,
        name: "IoT devices".to_owned(),
        dhcp: ControllerDhcp::Disabled,
    };
    let plan = Unifi.plan(&ctx, &change).await.expect("plan");
    let lines: Vec<(String, Option<String>, Option<String>)> = plan
        .diff
        .iter()
        .map(|l| (l.path.clone(), l.before.clone(), l.after.clone()))
        .collect();
    assert_eq!(
        lines,
        [
            (
                "networks/vlan-30/name".to_owned(),
                Some("IoT".to_owned()),
                Some("IoT devices".to_owned())
            ),
            (
                "networks/vlan-30/dhcp".to_owned(),
                Some("server".to_owned()),
                Some("disabled".to_owned())
            ),
        ]
    );
    assert!(
        plan.warnings
            .iter()
            .any(|w| w.contains("stops serving DHCP"))
    );
    let receipt = Unifi
        .apply(&ctx, &plan, WriteMode::Apply)
        .await
        .expect("write");
    assert!(receipt.verified);
    assert_eq!(
        receipt.undo,
        [L2Change::EnsureNetwork {
            vlan: 30,
            name: "IoT".to_owned(),
            dhcp: ControllerDhcp::Server
        }]
    );
    let changed = network_named(&fake, "IoT devices").expect("renamed");
    assert_eq!(changed["dhcpd_enabled"], false);
    Unifi.revert(&ctx, &receipt).await.expect("undo");
    let restored = network_named(&fake, "IoT").expect("name restored");
    assert_eq!(restored["dhcpd_enabled"], true);
}

#[tokio::test]
async fn a_port_profile_is_written_with_the_other_overrides_kept() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    let ctx = fake.context();
    // Port 5 of the core switch has an override with a name; port 4 has none.
    let plan = Unifi
        .plan(&ctx, &port_change(CORE, 4, TRUNK))
        .await
        .expect("plan");
    assert_eq!(plan.diff.len(), 1);
    assert_eq!(plan.diff[0].path, format!("devices/{CORE}/ports/4/profile"));
    assert_eq!(plan.diff[0].before.as_deref(), Some("All"));
    assert_eq!(plan.diff[0].after.as_deref(), Some("Trunk"));
    let receipt = Unifi
        .apply(&ctx, &plan, WriteMode::Apply)
        .await
        .expect("write");
    assert!(receipt.verified);
    assert_eq!(port_profile(&fake, CORE, 4).as_deref(), Some(TRUNK));
    assert_eq!(
        port_profile(&fake, CORE, 5).as_deref(),
        Some(IOT_PROFILE),
        "the other override is written back unchanged"
    );
    let body = &fake.writes()[0].body;
    let entry = body["port_overrides"]
        .as_array()
        .expect("overrides")
        .iter()
        .find(|o| o["port_idx"] == 5)
        .cloned()
        .expect("port 5");
    assert!(
        entry.get("name").is_some(),
        "members of other overrides survive"
    );
    assert_eq!(receipt.undo, [port_change(CORE, 4, ALL)]);
    assert_eq!(
        Unifi
            .plan(&ctx, &port_change(CORE, 4, TRUNK))
            .await
            .expect("again")
            .diff
            .len(),
        0
    );
    Unifi.revert(&ctx, &receipt).await.expect("undo");
    assert_eq!(port_profile(&fake, CORE, 4).as_deref(), Some(ALL));
}

#[tokio::test]
async fn a_client_vlan_override_is_set_and_undone_to_the_previous_one() {
    let fake = FakeController::start(Flavor::UnifiOs).await;
    let ctx = fake.context();
    // The phone already has an override to IoT.
    let change = L2Change::SetClientVlan {
        mac: mac(PHONE),
        network: NetworkRef(GUEST.to_owned()),
    };
    let plan = Unifi.plan(&ctx, &change).await.expect("plan");
    assert_eq!(plan.diff[0].before.as_deref(), Some("IoT"));
    assert_eq!(plan.diff[0].after.as_deref(), Some("Guest"));
    assert!(plan.warnings.iter().any(|w| w.contains("reconnects")));
    let receipt = Unifi
        .apply(&ctx, &plan, WriteMode::Apply)
        .await
        .expect("write");
    assert!(receipt.verified);
    assert_eq!(user_override(&fake, PHONE), (true, GUEST.to_owned()));
    assert_eq!(
        receipt.undo,
        [L2Change::SetClientVlan {
            mac: mac(PHONE),
            network: NetworkRef(IOT.to_owned())
        }]
    );
    Unifi.revert(&ctx, &receipt).await.expect("undo");
    assert_eq!(user_override(&fake, PHONE), (true, IOT.to_owned()));
    // A client without an override goes back to none.
    let set = L2Change::SetClientVlan {
        mac: mac(PRINTER),
        network: NetworkRef(GUEST.to_owned()),
    };
    let plan = Unifi.plan(&ctx, &set).await.expect("plan");
    let receipt = Unifi
        .apply(&ctx, &plan, WriteMode::Apply)
        .await
        .expect("write");
    assert_eq!(
        receipt.undo,
        [L2Change::ClearClientVlan { mac: mac(PRINTER) }]
    );
    Unifi.revert(&ctx, &receipt).await.expect("undo");
    assert!(!user_override(&fake, PRINTER).0);
}

#[tokio::test]
async fn a_drifted_read_back_is_not_verified() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    let ctx = fake.context();
    fake.set_drift_after_write(true);
    let plan = Unifi.plan(&ctx, &new_network()).await.expect("plan");
    let receipt = Unifi
        .apply(&ctx, &plan, WriteMode::Apply)
        .await
        .expect("the write itself succeeds");
    assert!(!receipt.verified, "the read-back differs from the plan");
    let plan = Unifi
        .plan(&ctx, &port_change(ACCESS, 6, TRUNK))
        .await
        .expect("plan");
    let receipt = Unifi
        .apply(&ctx, &plan, WriteMode::Apply)
        .await
        .expect("write");
    assert!(!receipt.verified);
}

#[tokio::test]
async fn a_stale_plan_is_refused_and_writes_nothing() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    let ctx = fake.context();
    let plan = Unifi
        .plan(&ctx, &port_change(ACCESS, 6, TRUNK))
        .await
        .expect("plan");
    {
        let mut state = fake.state();
        let device = state
            .devices
            .iter_mut()
            .find(|d| d["mac"] == ACCESS)
            .expect("device");
        device["port_overrides"] =
            serde_json::json!([{ "port_idx": 2, "portconf_id": IOT_PROFILE }]);
    }
    let error = Unifi
        .apply(&ctx, &plan, WriteMode::Apply)
        .await
        .expect_err("stale");
    assert_eq!(code(&error), "connect.verify_mismatch");
    assert_eq!(fake.writes().len(), 0);
}

#[tokio::test]
async fn an_undo_after_someone_changed_the_port_is_refused() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    let ctx = fake.context();
    let plan = Unifi
        .plan(&ctx, &port_change(ACCESS, 6, TRUNK))
        .await
        .expect("plan");
    let receipt = Unifi
        .apply(&ctx, &plan, WriteMode::Apply)
        .await
        .expect("write");
    {
        let mut state = fake.state();
        let device = state
            .devices
            .iter_mut()
            .find(|d| d["mac"] == ACCESS)
            .expect("device");
        for entry in device["port_overrides"].as_array_mut().expect("overrides") {
            if entry["port_idx"] == 6 {
                entry["portconf_id"] = Value::from(IOT_PROFILE);
            }
        }
    }
    let writes = fake.writes().len();
    let error = Unifi.revert(&ctx, &receipt).await.expect_err("changed");
    assert_eq!(code(&error), "connect.verify_mismatch");
    assert_eq!(fake.writes().len(), writes, "nothing is undone");
}

#[tokio::test]
async fn changes_the_controller_cannot_verify_or_carry_out_are_refused() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    let ctx = fake.context();
    let relay = L2Change::EnsureNetwork {
        vlan: 70,
        name: "Relayed".to_owned(),
        dhcp: ControllerDhcp::RelayTo(vec!["192.0.2.53".parse().expect("ip")]),
    };
    assert_eq!(
        code(&Unifi.plan(&ctx, &relay).await.expect_err("relay")),
        "connect.unsupported"
    );
    let taken = L2Change::EnsureNetwork {
        vlan: 70,
        name: "guest".to_owned(),
        dhcp: ControllerDhcp::Disabled,
    };
    assert_eq!(
        code(&Unifi.plan(&ctx, &taken).await.expect_err("name taken")),
        "connect.invalid_settings"
    );
    let default = L2Change::RemoveNetwork {
        network: NetworkRef(DEFAULT_NET.to_owned()),
        vlan: 1,
    };
    assert_eq!(
        code(&Unifi.plan(&ctx, &default).await.expect_err("default")),
        "connect.invalid_settings"
    );
    let unknown_port = port_change(ACCESS, 99, TRUNK);
    assert_eq!(
        code(&Unifi.plan(&ctx, &unknown_port).await.expect_err("port")),
        "connect.not_found"
    );
    let unknown_client = L2Change::ClearClientVlan {
        mac: mac("00:00:5e:00:53:ee"),
    };
    assert_eq!(
        code(&Unifi.plan(&ctx, &unknown_client).await.expect_err("client")),
        "connect.not_found"
    );
    assert_eq!(fake.writes().len(), 0);
}
