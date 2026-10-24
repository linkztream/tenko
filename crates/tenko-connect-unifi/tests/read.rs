//! Reads through the public traits of the plugin (`Connector`, `InventorySource`,
//! `NetworkController`) against the in-process fake controller of `tests/support`, in both
//! deployments, over the classic API and the Integration API.

mod support;

use std::{collections::BTreeSet, net::IpAddr, time::Duration};

use ipnet::IpNet;
use serde_json::{Value, json};
use support::{FakeController, Flavor, PASSWORD, ids};
use tenko_connect::{
    ClientAttachment, Connector as _, ConnectorError, ControllerDhcp, ControllerNetwork,
    DeviceKind, DevicePort, DeviceRef, Health, InventorySource as _, L2Change, L2Receipt,
    NetworkController as _, NetworkDevice, NetworkRef, PortProfile, ProfileRef, TopologySnapshot,
    WirelessNetwork, WriteMode,
    convert::{topology_from_proto, topology_to_proto},
};
use tenko_connect_unifi::Unifi;
use tenko_core::{Coded as _, MacAddr, observe::LinkKind};

/// A link as a sortable row: kind, near device and port, far device and port.
type LinkRow = (LinkKind, String, Option<String>, String, Option<String>);

const BOTH: [Flavor; 2] = [Flavor::SelfHosted, Flavor::UnifiOs];

fn mac(text: &str) -> MacAddr {
    text.parse().expect("a MAC address")
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an IP address")
}

fn net(id: &str) -> NetworkRef {
    NetworkRef(id.to_owned())
}

fn nets(ids: &[&str]) -> Vec<NetworkRef> {
    ids.iter().map(|id| net(id)).collect()
}

fn dev(mac: &str) -> DeviceRef {
    DeviceRef(mac.to_owned())
}

async fn topology(fake: &FakeController) -> TopologySnapshot {
    Unifi.topology(&fake.context()).await.expect("the topology")
}

fn device<'a>(snapshot: &'a TopologySnapshot, mac: &str) -> &'a NetworkDevice {
    snapshot
        .device(&dev(mac))
        .unwrap_or_else(|| panic!("no device {mac}"))
}

fn port(device: &NetworkDevice, index: u16) -> &DevicePort {
    device
        .ports
        .iter()
        .find(|port| port.index == index)
        .unwrap_or_else(|| panic!("no port {index} on {}", device.name))
}

/// The indexes of the ports of a device that are reported as uplinks.
fn uplinks(snapshot: &TopologySnapshot, mac: &str) -> Vec<u16> {
    device(snapshot, mac)
        .ports
        .iter()
        .filter(|port| port.uplink)
        .map(|port| port.index)
        .collect()
}

fn client<'a>(snapshot: &'a TopologySnapshot, mac: &str) -> &'a ClientAttachment {
    let wanted = self::mac(mac);
    snapshot
        .clients
        .iter()
        .find(|client| client.mac == wanted)
        .unwrap_or_else(|| panic!("no client {mac}"))
}

fn network<'a>(snapshot: &'a TopologySnapshot, name: &str) -> &'a ControllerNetwork {
    snapshot
        .networks
        .iter()
        .find(|network| network.name == name)
        .unwrap_or_else(|| panic!("no network {name}"))
}

fn profile<'a>(snapshot: &'a TopologySnapshot, name: &str) -> &'a PortProfile {
    snapshot
        .profiles
        .iter()
        .find(|profile| profile.name == name)
        .unwrap_or_else(|| panic!("no profile {name}"))
}

fn wlan<'a>(snapshot: &'a TopologySnapshot, ssid: &str) -> &'a WirelessNetwork {
    snapshot
        .wlans
        .iter()
        .find(|wlan| wlan.ssid == ssid)
        .unwrap_or_else(|| panic!("no wireless network {ssid}"))
}

/// A client attached to a device, with nothing else known.
fn attachment(client: &str, device: &str) -> ClientAttachment {
    ClientAttachment {
        mac: mac(client),
        ip: None,
        device: dev(device),
        port: None,
        ssid: None,
        network: None,
        vlan: None,
        name: None,
        vendor: None,
        management: false,
    }
}

/// The links as sorted tuples: kind, near device and port, far device and port.
fn links(snapshot: &TopologySnapshot) -> Vec<LinkRow> {
    let mut links: Vec<_> = snapshot
        .links
        .iter()
        .map(|link| {
            (
                link.kind,
                link.a.device.clone(),
                link.a.port.clone(),
                link.b.device.clone(),
                link.b.port.clone(),
            )
        })
        .collect();
    links.sort();
    links
}

fn link(kind: LinkKind, near: (&str, Option<&str>), far: (&str, Option<&str>)) -> LinkRow {
    (
        kind,
        near.0.to_owned(),
        near.1.map(str::to_owned),
        far.0.to_owned(),
        far.1.map(str::to_owned),
    )
}

/// The expected links in the order of [`links`].
fn sorted(mut expected: Vec<LinkRow>) -> Vec<LinkRow> {
    expected.sort();
    expected
}

/// Changes the fixture device with the MAC address `mac`.
fn edit_device(fake: &FakeController, mac: &str, edit: impl FnOnce(&mut Value)) {
    let mut state = fake.state();
    let device = state
        .devices
        .iter_mut()
        .find(|device| device["mac"] == mac)
        .expect("a fixture device");
    edit(device);
}

/// Changes the fixture network with the id `id`.
fn edit_network(fake: &FakeController, id: &str, edit: impl FnOnce(&mut Value)) {
    let mut state = fake.state();
    let network = state
        .networks
        .iter_mut()
        .find(|network| network["_id"] == id)
        .expect("a fixture network");
    edit(network);
}

/// The port entry `index` of a fixture device.
fn port_entry(device: &mut Value, index: u64) -> &mut Value {
    device["port_table"]
        .as_array_mut()
        .expect("a port table")
        .iter_mut()
        .find(|port| port["port_idx"] == index)
        .expect("a fixture port")
}

fn code<T: std::fmt::Debug>(result: Result<T, ConnectorError>) -> &'static str {
    result.expect_err("the call fails").code()
}

// ---- deployments and sessions -------------------------------------------------------

#[tokio::test]
async fn both_deployments_are_detected_and_read_in_one_session_per_call() {
    for flavor in BOTH {
        let fake = FakeController::start(flavor).await;
        let snapshot = topology(&fake).await;
        let devices: Vec<(&str, DeviceKind)> = snapshot
            .devices
            .iter()
            .map(|device| (device.id.0.as_str(), device.kind))
            .collect();
        assert_eq!(
            devices,
            [
                (ids::GATEWAY, DeviceKind::Gateway),
                (ids::CORE, DeviceKind::Switch),
                (ids::ACCESS, DeviceKind::Switch),
                (ids::HALL, DeviceKind::AccessPoint),
                (ids::GARDEN, DeviceKind::AccessPoint),
            ],
            "{flavor:?}"
        );
        assert!(snapshot.device(&dev(ids::PENDING)).is_none(), "{flavor:?}");
        assert_eq!((fake.logins(), fake.logouts()), (1, 1), "{flavor:?}");

        Unifi.poll(&fake.context(), None).await.expect("a poll");
        assert_eq!((fake.logins(), fake.logouts()), (2, 2), "{flavor:?}");

        Unifi.check(&fake.context()).await.expect("a check");
        assert_eq!((fake.logins(), fake.logouts()), (3, 3), "{flavor:?}");
        assert_eq!(fake.state().open_sessions(), 0, "{flavor:?}");
        assert_eq!(fake.writes(), Vec::new(), "{flavor:?}");
    }
}

#[tokio::test]
async fn devices_carry_their_name_model_and_address() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    let snapshot = topology(&fake).await;
    let gateway = device(&snapshot, ids::GATEWAY);
    assert_eq!(gateway.name, "gw.example.test");
    assert_eq!(gateway.model.as_deref(), Some("UXG"));
    assert_eq!(gateway.mac, Some(mac(ids::GATEWAY)));
    assert_eq!(gateway.ip, Some(ip("192.0.2.1")));
    let core = device(&snapshot, ids::CORE);
    assert_eq!(core.name, "sw-core.example.test");
    assert_eq!(core.ports.len(), 16);
    assert_eq!(device(&snapshot, ids::ACCESS).ports.len(), 8);
    assert_eq!(device(&snapshot, ids::GATEWAY).ports.len(), 2);
    for access_point in [ids::HALL, ids::GARDEN] {
        assert_eq!(
            device(&snapshot, access_point).ports,
            Vec::<DevicePort>::new(),
            "an access point has no switch ports"
        );
    }
}

#[tokio::test]
async fn an_imported_login_secret_and_a_missing_user_name_are_read_as_documented() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    let mut settings = fake.settings();
    settings
        .as_object_mut()
        .expect("settings are an object")
        .remove("username");
    let login = json!({ "login": support::USERNAME, "password": PASSWORD }).to_string();
    let imported = FakeController::context_with(settings.clone(), &[("password", login.as_str())]);
    Unifi
        .check(&imported)
        .await
        .expect("an imported login works without `username`");
    let no_user = FakeController::context_with(settings, &[("password", PASSWORD)]);
    assert_eq!(
        code(Unifi.check(&no_user).await),
        "connect.invalid_settings"
    );
    let nothing = FakeController::context_with(fake.settings(), &[]);
    assert_eq!(
        code(Unifi.check(&nothing).await),
        "connect.invalid_settings"
    );
}

// ---- ports, uplinks and links -------------------------------------------------------

#[tokio::test]
async fn ports_next_to_other_network_devices_are_uplinks() {
    for flavor in BOTH {
        let fake = FakeController::start(flavor).await;
        let snapshot = topology(&fake).await;
        // The gateway's port 2 has sw-core behind it; port 1 is the WAN.
        assert_eq!(uplinks(&snapshot, ids::GATEWAY), [2], "{flavor:?}");
        // sw-core: its own uplink (1), and sw-access behind port 9, which LLDP sees too.
        // Port 12 holds the NAS; ports 15 and 16 are an aggregate without a link.
        assert_eq!(uplinks(&snapshot, ids::CORE), [1, 9], "{flavor:?}");
        // sw-access: its own uplink (1) and the access point behind port 3.
        assert_eq!(uplinks(&snapshot, ids::ACCESS), [1, 3], "{flavor:?}");
        let core = device(&snapshot, ids::CORE);
        assert!(!port(core, 12).uplink, "the NAS port");
        assert!(!port(core, 15).uplink && !port(core, 16).uplink);
    }
}

#[tokio::test]
async fn an_aggregate_is_an_uplink_when_one_of_its_members_is() {
    for member in [15, 16] {
        let fake = FakeController::start(Flavor::SelfHosted).await;
        edit_device(&fake, ids::CORE, |core| {
            port_entry(core, member)["is_uplink"] = json!(true);
        });
        let snapshot = topology(&fake).await;
        assert_eq!(
            uplinks(&snapshot, ids::CORE),
            [1, 9, 15, 16],
            "member {member} marked"
        );
    }
}

#[tokio::test]
async fn ports_report_their_name_state_profile_and_native_vlan() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    let snapshot = topology(&fake).await;
    let core = device(&snapshot, ids::CORE);
    // Port 5 has an override to the IoT profile, whose native network is IoT (VLAN 30).
    let overridden = port(core, 5);
    assert_eq!(overridden.name.as_deref(), Some("iot-drop"));
    assert_eq!(
        overridden.profile,
        Some(ProfileRef(ids::PROFILE_IOT.to_owned()))
    );
    assert_eq!(overridden.native_vlan, Some(30));
    assert!(overridden.up);
    assert!(!overridden.management);
    let plain = port(core, 4);
    assert_eq!(plain.profile, Some(ProfileRef(ids::PROFILE_ALL.to_owned())));
    assert_eq!(plain.native_vlan, None);
    assert!(!plain.up);
    let wan = port(device(&snapshot, ids::GATEWAY), 1);
    assert_eq!(wan.name.as_deref(), Some("WAN"));
    assert!(wan.up);
}

#[tokio::test]
async fn links_come_from_uplinks_and_from_lldp_neighbours_nothing_else_covers() {
    for flavor in BOTH {
        let fake = FakeController::start(flavor).await;
        let snapshot = topology(&fake).await;
        assert_eq!(
            links(&snapshot),
            sorted(vec![
                link(
                    LinkKind::Lldp,
                    (ids::CORE, Some("12")),
                    (ids::NAS, Some("eth0"))
                ),
                link(
                    LinkKind::Uplink,
                    (ids::ACCESS, Some("1")),
                    (ids::CORE, Some("9"))
                ),
                link(
                    LinkKind::Uplink,
                    (ids::CORE, Some("1")),
                    (ids::GATEWAY, Some("2"))
                ),
                link(
                    LinkKind::Uplink,
                    (ids::HALL, None),
                    (ids::ACCESS, Some("3"))
                ),
                link(LinkKind::Wireless, (ids::GARDEN, None), (ids::HALL, None)),
            ]),
            "{flavor:?}"
        );
    }
}

// ---- clients -------------------------------------------------------------------------

#[tokio::test]
async fn clients_are_attached_to_their_switch_port_or_access_point() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    let snapshot = topology(&fake).await;
    let attached: BTreeSet<String> = snapshot
        .clients
        .iter()
        .map(|client| client.mac.to_string())
        .collect();
    let expected: BTreeSet<String> = [
        ids::PRINTER,
        ids::NAS,
        ids::HOST,
        ids::PHONE,
        ids::SENSOR,
        ids::LAPTOP,
        ids::IDLE,
    ]
    .iter()
    .map(|mac| (*mac).to_owned())
    .collect();
    assert_eq!(
        attached, expected,
        "the client with an invalid MAC address and the offline record are absent"
    );

    assert_eq!(
        client(&snapshot, ids::PRINTER),
        &ClientAttachment {
            ip: Some(ip("198.51.100.20")),
            port: Some(5),
            network: Some(net(ids::NET_IOT)),
            vlan: Some(30),
            name: Some("printer.example.test".to_owned()),
            vendor: Some("Example Print Co".to_owned()),
            ..attachment(ids::PRINTER, ids::ACCESS)
        }
    );
    assert_eq!(
        client(&snapshot, ids::NAS),
        &ClientAttachment {
            ip: Some(ip("192.0.2.30")),
            port: Some(12),
            network: Some(net(ids::NET_DEFAULT)),
            name: Some("nas".to_owned()),
            ..attachment(ids::NAS, ids::CORE)
        }
    );
    assert_eq!(
        client(&snapshot, ids::HOST),
        &ClientAttachment {
            ip: Some(ip("192.0.2.10")),
            port: Some(7),
            network: Some(net(ids::NET_DEFAULT)),
            name: Some("controller".to_owned()),
            ..attachment(ids::HOST, ids::CORE)
        }
    );
    assert_eq!(
        client(&snapshot, ids::PHONE),
        &ClientAttachment {
            ip: Some(ip("192.0.2.40")),
            ssid: Some("home.example".to_owned()),
            network: Some(net(ids::NET_DEFAULT)),
            name: Some("phone.example.test".to_owned()),
            vendor: Some("Example Mobile Co".to_owned()),
            ..attachment(ids::PHONE, ids::HALL)
        }
    );
    assert_eq!(
        client(&snapshot, ids::SENSOR),
        &ClientAttachment {
            ip: Some(ip("198.51.100.41")),
            ssid: Some("iot.example".to_owned()),
            network: Some(net(ids::NET_IOT)),
            vlan: Some(30),
            name: Some("sensor".to_owned()),
            ..attachment(ids::SENSOR, ids::GARDEN)
        }
    );
    assert_eq!(
        client(&snapshot, ids::LAPTOP),
        &ClientAttachment {
            ip: Some(ip("203.0.113.42")),
            ssid: Some("guest.example".to_owned()),
            network: Some(net(ids::NET_GUEST)),
            vlan: Some(40),
            name: Some("laptop".to_owned()),
            ..attachment(ids::LAPTOP, ids::HALL)
        }
    );
    // A client without any address is still attached.
    assert_eq!(
        client(&snapshot, ids::IDLE),
        &ClientAttachment {
            port: Some(6),
            network: Some(net(ids::NET_DEFAULT)),
            name: Some("idle".to_owned()),
            ..attachment(ids::IDLE, ids::ACCESS)
        }
    );
}

#[tokio::test]
async fn no_client_is_a_management_client_when_the_controller_is_on_loopback() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    let snapshot = topology(&fake).await;
    assert!(snapshot.clients.iter().all(|client| !client.management));
    assert!(
        snapshot
            .devices
            .iter()
            .flat_map(|device| &device.ports)
            .all(|port| !port.management)
    );
}

// ---- networks, profiles and wireless networks ----------------------------------------

#[tokio::test]
async fn networks_leave_out_the_wan_and_report_vlan_subnet_and_dhcp() {
    for flavor in BOTH {
        let fake = FakeController::start(flavor).await;
        let snapshot = topology(&fake).await;
        let names: Vec<&str> = snapshot
            .networks
            .iter()
            .map(|network| network.name.as_str())
            .collect();
        assert_eq!(
            names,
            ["Default", "IoT", "Guest", "Lab", "Relay"],
            "{flavor:?}"
        );
        let subnet = |text: &str| Some(text.parse::<IpNet>().expect("a subnet"));

        let default = network(&snapshot, "Default");
        assert_eq!(default.id, net(ids::NET_DEFAULT));
        assert_eq!(default.vlan, None);
        assert_eq!(default.subnet, subnet("192.0.2.0/24"));
        assert_eq!(default.dhcp, ControllerDhcp::Server);
        assert!(default.management);

        // The fixture gives the VLAN of IoT as text; it is read all the same.
        let iot = network(&snapshot, "IoT");
        assert_eq!(iot.id, net(ids::NET_IOT));
        assert_eq!(iot.vlan, Some(30));
        assert_eq!(iot.subnet, subnet("198.51.100.0/24"));
        assert_eq!(iot.dhcp, ControllerDhcp::Server);
        assert!(!iot.management);

        let guest = network(&snapshot, "Guest");
        assert_eq!(guest.vlan, Some(40));
        assert_eq!(guest.subnet, subnet("203.0.113.0/25"));
        assert!(!guest.management);

        let lab = network(&snapshot, "Lab");
        assert_eq!(lab.vlan, Some(50));
        assert_eq!(lab.subnet, None);
        assert_eq!(lab.dhcp, ControllerDhcp::Disabled);

        let relay = network(&snapshot, "Relay");
        assert_eq!(relay.vlan, Some(60));
        assert_eq!(relay.subnet, subnet("203.0.113.128/25"));
        assert_eq!(relay.dhcp, ControllerDhcp::RelayTo(Vec::new()));
    }
}

#[tokio::test]
async fn a_network_is_a_management_network_by_flag_by_managed_devices_or_by_the_controller() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    let management = |snapshot: &TopologySnapshot| -> Vec<String> {
        snapshot
            .networks
            .iter()
            .filter(|network| network.management)
            .map(|network| network.name.clone())
            .collect()
    };
    assert_eq!(management(&topology(&fake).await), ["Default"]);

    // Without the flags that mark the default network, the managed devices in its subnet
    // still make it a management network.
    edit_network(&fake, ids::NET_DEFAULT, |default| {
        default["attr_no_delete"] = json!(false);
        default
            .as_object_mut()
            .expect("an object")
            .remove("attr_hidden_id");
    });
    assert_eq!(management(&topology(&fake).await), ["Default"]);

    // A subnet that holds no managed device and no controller address is none.
    edit_network(&fake, ids::NET_DEFAULT, |default| {
        default["ip_subnet"] = json!("192.0.2.129/25");
    });
    assert_eq!(management(&topology(&fake).await), Vec::<String>::new());

    // A managed device in the subnet of IoT makes IoT one.
    edit_device(&fake, ids::ACCESS, |access| {
        access["ip"] = json!("198.51.100.3");
    });
    assert_eq!(management(&topology(&fake).await), ["IoT"]);

    // The subnet that holds the controller's address (the fake listens on loopback).
    edit_network(&fake, ids::NET_RELAY, |relay| {
        relay["ip_subnet"] = json!("127.0.0.1/8");
    });
    assert_eq!(management(&topology(&fake).await), ["IoT", "Relay"]);
}

#[tokio::test]
async fn profiles_list_the_networks_they_tag() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    let snapshot = topology(&fake).await;
    assert_eq!(snapshot.profiles.len(), 5);

    let trunk = profile(&snapshot, "Trunk");
    assert_eq!(trunk.id, ProfileRef(ids::PROFILE_TRUNK.to_owned()));
    assert_eq!(trunk.native_network, Some(net(ids::NET_DEFAULT)));
    assert_eq!(trunk.tagged, nets(&[ids::NET_IOT, ids::NET_GUEST]));

    // "All" has no native network, so it carries every LAN network.
    let all = profile(&snapshot, "All");
    assert_eq!(all.native_network, None);
    assert_eq!(
        all.tagged,
        nets(&[
            ids::NET_DEFAULT,
            ids::NET_IOT,
            ids::NET_GUEST,
            ids::NET_LAB,
            ids::NET_RELAY
        ])
    );

    let iot = profile(&snapshot, "IoT");
    assert_eq!(iot.native_network, Some(net(ids::NET_IOT)));
    assert_eq!(iot.tagged, Vec::<NetworkRef>::new());

    let disabled = profile(&snapshot, "Disabled");
    assert_eq!(disabled.native_network, None);
    assert_eq!(disabled.tagged, Vec::<NetworkRef>::new());

    // An older "customize" profile lists what it excludes: every LAN network but Guest and
    // its native network.
    let old = profile(&snapshot, "Old custom");
    assert_eq!(old.native_network, Some(net(ids::NET_DEFAULT)));
    assert_eq!(
        old.tagged,
        nets(&[ids::NET_IOT, ids::NET_LAB, ids::NET_RELAY])
    );
}

#[tokio::test]
async fn wireless_networks_name_their_access_points_network_and_vlan() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    let snapshot = topology(&fake).await;
    assert_eq!(snapshot.wlans.len(), 5);

    let home = wlan(&snapshot, "home.example");
    assert_eq!(home.id, ids::WLAN_HOME);
    assert_eq!(home.access_points, [dev(ids::HALL)]);
    assert_eq!(home.network, Some(net(ids::NET_DEFAULT)));
    assert_eq!(home.vlan, None);
    assert!(home.enabled);

    let iot = wlan(&snapshot, "iot.example");
    assert_eq!(iot.access_points, [dev(ids::HALL), dev(ids::GARDEN)]);
    assert_eq!(iot.network, Some(net(ids::NET_IOT)));
    assert_eq!(iot.vlan, Some(30));

    let guest = wlan(&snapshot, "guest.example");
    assert_eq!(guest.network, Some(net(ids::NET_GUEST)));
    assert_eq!(guest.vlan, Some(40));

    // Older controllers tag the SSID itself.
    let legacy = wlan(&snapshot, "legacy.example");
    assert_eq!(legacy.network, None);
    assert_eq!(legacy.vlan, Some(30));
    assert!(legacy.enabled);

    let off = wlan(&snapshot, "off.example");
    assert!(!off.enabled);
}

// ---- inventory -----------------------------------------------------------------------

#[tokio::test]
async fn the_inventory_has_a_host_per_adopted_device_and_per_client() {
    for flavor in BOTH {
        let fake = FakeController::start(flavor).await;
        let batch = Unifi
            .poll(&fake.context(), None)
            .await
            .expect("the inventory");
        assert!(batch.complete, "{flavor:?}");
        assert!(!batch.more, "{flavor:?}");

        let external: BTreeSet<&str> = batch
            .hosts
            .iter()
            .map(|host| host.external_id.as_str())
            .collect();
        let expected: BTreeSet<String> =
            [ids::GATEWAY, ids::CORE, ids::ACCESS, ids::HALL, ids::GARDEN]
                .iter()
                .map(|mac| format!("device:{mac}"))
                .chain(
                    [
                        ids::PRINTER,
                        ids::NAS,
                        ids::HOST,
                        ids::PHONE,
                        ids::SENSOR,
                        ids::LAPTOP,
                        ids::IDLE,
                    ]
                    .iter()
                    .map(|mac| format!("client:{mac}")),
                )
                .collect();
        assert_eq!(
            external,
            expected.iter().map(String::as_str).collect::<BTreeSet<_>>(),
            "{flavor:?}: the unadopted device, the invalid MAC and the offline record are absent"
        );
        for host in &batch.hosts {
            assert_eq!(host.macs.len(), 1, "{}", host.external_id);
        }

        let host = |mac: &str, prefix: &str| {
            let id = format!("{prefix}:{mac}");
            batch
                .hosts
                .iter()
                .find(|host| host.external_id == id)
                .unwrap_or_else(|| panic!("no host {id}"))
        };
        let tags = |mac: &str, prefix: &str| host(mac, prefix).tags.clone();
        assert_eq!(tags(ids::GATEWAY, "device"), ["unifi:gateway"]);
        assert_eq!(tags(ids::CORE, "device"), ["unifi:switch"]);
        assert_eq!(tags(ids::ACCESS, "device"), ["unifi:switch"]);
        assert_eq!(tags(ids::HALL, "device"), ["unifi:access_point"]);
        assert_eq!(tags(ids::GARDEN, "device"), ["unifi:access_point"]);
        assert_eq!(tags(ids::PRINTER, "client"), ["unifi:wired"]);
        assert_eq!(tags(ids::NAS, "client"), ["unifi:wired"]);
        assert_eq!(tags(ids::PHONE, "client"), ["unifi:wireless"]);
        assert_eq!(tags(ids::SENSOR, "client"), ["unifi:wireless"]);
        assert_eq!(
            tags(ids::LAPTOP, "client"),
            ["unifi:wireless", "unifi:guest"]
        );

        let gateway = host(ids::GATEWAY, "device");
        assert_eq!(gateway.name.as_deref(), Some("gw.example.test"));
        assert_eq!(gateway.macs, [mac(ids::GATEWAY)]);
        assert_eq!(gateway.ips, [ip("192.0.2.1")]);

        // The phone has an IPv4 and an IPv6 address on one host.
        let phone = host(ids::PHONE, "client");
        assert_eq!(phone.name.as_deref(), Some("phone.example.test"));
        assert_eq!(phone.ips, [ip("192.0.2.40"), ip("2001:db8::40")]);
        assert_eq!(host(ids::PRINTER, "client").ips, [ip("198.51.100.20")]);
        assert_eq!(host(ids::IDLE, "client").ips, Vec::<IpAddr>::new());
    }
}

// ---- health --------------------------------------------------------------------------

#[tokio::test]
async fn a_pinned_tls_controller_checks_healthy_and_names_its_deployment() {
    for (flavor, description) in [
        (Flavor::SelfHosted, "self-hosted Network Application"),
        (Flavor::UnifiOs, "UniFi OS console"),
    ] {
        let fake = FakeController::start_tls(flavor).await;
        let report = Unifi.check(&fake.context()).await.expect("a check");
        assert_eq!(report.health, Health::Healthy, "{flavor:?}");
        assert_eq!(report.remote_version.as_deref(), Some("9.0.0"));
        let detail = report.detail.expect("a detail");
        assert!(detail.contains(description), "{flavor:?}: {detail}");
        assert!(detail.contains("classic"), "{flavor:?}: {detail}");
        assert!(detail.contains("site `default`"), "{flavor:?}: {detail}");
        assert_eq!((fake.logins(), fake.logouts()), (1, 1));
    }
}

#[tokio::test]
async fn a_controller_without_encryption_checks_degraded_but_reports_its_version() {
    for (flavor, description) in [
        (Flavor::SelfHosted, "self-hosted Network Application"),
        (Flavor::UnifiOs, "UniFi OS console"),
    ] {
        let fake = FakeController::start(flavor).await;
        let report = Unifi.check(&fake.context()).await.expect("a check");
        assert_eq!(report.health, Health::Degraded, "{flavor:?}");
        assert_eq!(report.remote_version.as_deref(), Some("9.0.0"));
        let detail = report.detail.expect("a detail");
        assert!(detail.contains(description), "{flavor:?}: {detail}");
        assert!(detail.contains("classic"), "{flavor:?}: {detail}");
    }
}

#[tokio::test]
async fn a_wrong_password_fails_as_unauthorized_without_naming_it() {
    for flavor in BOTH {
        let fake = FakeController::start(flavor).await;
        let wrong =
            FakeController::context_with(fake.settings(), &[("password", "wrong-password-9")]);
        let error = Unifi.check(&wrong).await.expect_err("wrong password");
        assert_eq!(error.code(), "connect.unauthorized", "{flavor:?}");
        assert!(!error.to_string().contains("wrong-password-9"));
        assert_eq!(code(Unifi.topology(&wrong).await), "connect.unauthorized");
        assert_eq!(code(Unifi.poll(&wrong, None).await), "connect.unauthorized");
        assert_eq!((fake.logins(), fake.login_attempts()), (0, 3), "{flavor:?}");
        assert_eq!(fake.state().open_sessions(), 0);
    }
}

#[tokio::test]
async fn a_site_the_controller_does_not_have_is_an_invalid_setting() {
    for flavor in BOTH {
        let fake = FakeController::start(flavor).await;
        let mut settings = fake.settings();
        settings["site"] = json!("branch");
        let ctx = FakeController::context_with(settings, &[("password", PASSWORD)]);
        assert_eq!(
            code(Unifi.check(&ctx).await),
            "connect.invalid_settings",
            "{flavor:?}"
        );
        assert_eq!(
            code(Unifi.topology(&ctx).await),
            "connect.invalid_settings",
            "{flavor:?}"
        );
        assert_eq!(
            code(Unifi.poll(&ctx, None).await),
            "connect.invalid_settings",
            "{flavor:?}"
        );
        // The session is closed even though the call failed.
        assert_eq!((fake.logins(), fake.logouts()), (3, 3), "{flavor:?}");
    }
}

// ---- TLS -----------------------------------------------------------------------------

#[tokio::test]
async fn a_pinned_certificate_is_read_over_tls() {
    for flavor in BOTH {
        let fake = FakeController::start_tls(flavor).await;
        assert!(fake.url().starts_with("https://127.0.0.1:"));
        let fingerprint = fake.fingerprint().expect("a TLS controller has one");
        assert_eq!(fingerprint.len(), 32 * 3 - 1);
        let snapshot = topology(&fake).await;
        assert_eq!(snapshot.devices.len(), 5, "{flavor:?}");
        assert_eq!(snapshot.clients.len(), 7, "{flavor:?}");
        let batch = Unifi.poll(&fake.context(), None).await.expect("a poll");
        assert_eq!(batch.hosts.len(), 12, "{flavor:?}");
    }
}

#[tokio::test]
async fn another_fingerprint_is_refused_and_named() {
    let fake = FakeController::start_tls(Flavor::SelfHosted).await;
    let real = fake.fingerprint().expect("a fingerprint");
    let mut flipped = real.clone();
    let first = if real.starts_with('0') { "1" } else { "0" };
    flipped.replace_range(0..1, first);
    assert_ne!(flipped, real);
    let mut settings = fake.settings();
    settings["tls_fingerprint"] = json!(flipped);
    let ctx = FakeController::context_with(settings, &[("password", PASSWORD)]);
    for error in [
        Unifi.topology(&ctx).await.expect_err("another certificate"),
        Unifi.check(&ctx).await.expect_err("another certificate"),
    ] {
        assert_eq!(error.code(), "connect.invalid_settings", "{error}");
        assert!(
            error.to_string().to_lowercase().contains("fingerprint"),
            "{error}"
        );
    }
    assert_eq!(
        fake.logins(),
        0,
        "nothing is sent over a refused connection"
    );
}

#[tokio::test]
async fn pinning_without_a_fingerprint_shows_the_one_the_controller_presents() {
    let fake = FakeController::start_tls(Flavor::SelfHosted).await;
    let mut settings = fake.settings();
    settings
        .as_object_mut()
        .expect("settings are an object")
        .remove("tls_fingerprint");
    let ctx = FakeController::context_with(settings, &[("password", PASSWORD)]);
    let report = Unifi.check(&ctx).await.expect("a degraded report");
    assert_eq!(report.health, Health::Degraded);
    let detail = report.detail.expect("a detail");
    let fingerprint = fake.fingerprint().expect("a fingerprint");
    assert!(detail.contains(&fingerprint), "{detail}");
    assert_eq!(
        fake.logins(),
        0,
        "no login before the certificate is pinned"
    );
}

#[tokio::test]
async fn an_unknown_certificate_is_refused_unless_the_instance_opts_out_of_checking() {
    let fake = FakeController::start_tls(Flavor::SelfHosted).await;
    let mut settings = fake.settings();
    {
        let map = settings.as_object_mut().expect("settings are an object");
        map.remove("tls");
        map.remove("tls_fingerprint");
    }
    let strict = FakeController::context_with(settings.clone(), &[("password", PASSWORD)]);
    assert_eq!(
        code(Unifi.topology(&strict).await),
        "connect.invalid_settings"
    );

    settings["tls"] = json!("insecure");
    let lax = FakeController::context_with(settings, &[("password", PASSWORD)]);
    let report = Unifi.check(&lax).await.expect("a check");
    assert_eq!(report.health, Health::Degraded);
    let detail = report.detail.expect("a detail");
    let fingerprint = fake.fingerprint().expect("a fingerprint");
    assert!(detail.contains(&fingerprint), "{detail}");
    assert_eq!(
        Unifi
            .topology(&lax)
            .await
            .expect("a read without a check")
            .devices
            .len(),
        5
    );
}

// ---- rate limits ---------------------------------------------------------------------

#[tokio::test]
async fn a_rate_limit_is_retried_and_a_persistent_one_is_reported() {
    for flavor in BOTH {
        let fake = FakeController::start(flavor).await;
        fake.rate_limit_next(1);
        let snapshot = topology(&fake).await;
        assert_eq!(snapshot.devices.len(), 5, "{flavor:?}");
        assert_eq!(fake.state().open_sessions(), 0);

        fake.rate_limit_next(10);
        let error = Unifi
            .topology(&fake.context())
            .await
            .expect_err("a persistent rate limit");
        assert_eq!(error.code(), "connect.rate_limited", "{flavor:?}");
        assert!(error.is_transient(), "{flavor:?}");
        match error {
            ConnectorError::RateLimited { retry_after } => {
                assert_eq!(retry_after, Duration::ZERO, "the controller's Retry-After");
            }
            other => panic!("expected a rate limit, got {other:?}"),
        }
    }
}

// ---- the Integration API -------------------------------------------------------------

/// One network of a topology: name, VLAN, subnet, DHCP mode and management flag.
type NetworkRow<'a> = (
    &'a str,
    Option<u16>,
    Option<String>,
    &'a ControllerDhcp,
    bool,
);

/// The LAN networks the fake's Integration API reports, as the topology carries them.
fn assert_integration_networks(snapshot: &TopologySnapshot, flavor: Flavor) {
    // The LAN networks of Network 10: VLAN 1 of the default network is untagged, the
    // subnet and the DHCP mode come from the detail of each network.
    let rows: Vec<NetworkRow<'_>> = snapshot
        .networks
        .iter()
        .map(|network| {
            (
                network.name.as_str(),
                network.vlan,
                network.subnet.map(|net| net.to_string()),
                &network.dhcp,
                network.management,
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            (
                "Default",
                None,
                Some("192.0.2.0/24".to_owned()),
                &ControllerDhcp::Server,
                true
            ),
            (
                "IoT",
                Some(30),
                Some("198.51.100.0/24".to_owned()),
                &ControllerDhcp::Server,
                false
            ),
            (
                "Guest",
                Some(40),
                Some("203.0.113.0/25".to_owned()),
                &ControllerDhcp::Server,
                false
            ),
            ("Lab", Some(50), None, &ControllerDhcp::Disabled, false),
            (
                "Relay",
                Some(60),
                Some("203.0.113.128/25".to_owned()),
                &ControllerDhcp::RelayTo(vec![ip("192.0.2.53")]),
                false
            ),
        ],
        "{flavor:?}"
    );
}

#[tokio::test]
async fn the_integration_api_yields_devices_uplinks_networks_and_clients_without_ports() {
    for flavor in BOTH {
        let fake = FakeController::start(flavor).await;
        let snapshot = Unifi
            .topology(&fake.key_context())
            .await
            .expect("the topology");
        let kinds: Vec<(&str, DeviceKind)> = snapshot
            .devices
            .iter()
            .map(|device| (device.id.0.as_str(), device.kind))
            .collect();
        assert_eq!(
            kinds,
            [
                (ids::GATEWAY, DeviceKind::Gateway),
                (ids::CORE, DeviceKind::Switch),
                (ids::ACCESS, DeviceKind::Switch),
                (ids::HALL, DeviceKind::AccessPoint),
                (ids::GARDEN, DeviceKind::AccessPoint),
            ],
            "{flavor:?}"
        );
        for device in &snapshot.devices {
            assert_eq!(device.ports, Vec::<DevicePort>::new(), "{}", device.name);
        }
        let core = device(&snapshot, ids::CORE);
        assert_eq!(core.name, "sw-core.example.test");
        assert_eq!(core.model.as_deref(), Some("US16P150"));
        assert_eq!(core.ip, Some(ip("192.0.2.2")));

        // One link per uplink, the mesh access point included, none with ports.
        assert_eq!(
            links(&snapshot),
            sorted(vec![
                link(LinkKind::Uplink, (ids::ACCESS, None), (ids::CORE, None)),
                link(LinkKind::Uplink, (ids::CORE, None), (ids::GATEWAY, None)),
                link(LinkKind::Uplink, (ids::GARDEN, None), (ids::HALL, None)),
                link(LinkKind::Uplink, (ids::HALL, None), (ids::ACCESS, None)),
            ]),
            "{flavor:?}"
        );

        assert_integration_networks(&snapshot, flavor);
        let iot = support::integration::network_id("5f1000000000000000000002");
        let default = support::integration::network_id("5f1000000000000000000001");

        // Clients hang on a device with no port or SSID, in the network that holds their
        // address.
        assert_eq!(snapshot.clients.len(), 7, "{flavor:?}");
        assert_eq!(
            client(&snapshot, ids::PRINTER),
            &ClientAttachment {
                ip: Some(ip("198.51.100.20")),
                name: Some("printer.example.test".to_owned()),
                network: Some(NetworkRef(iot.clone())),
                vlan: Some(30),
                ..attachment(ids::PRINTER, ids::ACCESS)
            }
        );
        assert_eq!(
            client(&snapshot, ids::PHONE),
            &ClientAttachment {
                ip: Some(ip("192.0.2.40")),
                name: Some("phone.example.test".to_owned()),
                network: Some(NetworkRef(default)),
                ..attachment(ids::PHONE, ids::HALL)
            }
        );
        assert_eq!(
            client(&snapshot, ids::SENSOR),
            &ClientAttachment {
                ip: Some(ip("198.51.100.41")),
                name: Some("sensor".to_owned()),
                network: Some(NetworkRef(iot)),
                vlan: Some(30),
                ..attachment(ids::SENSOR, ids::GARDEN)
            }
        );
        assert_eq!(
            client(&snapshot, ids::IDLE),
            &ClientAttachment {
                name: Some("idle".to_owned()),
                ..attachment(ids::IDLE, ids::ACCESS)
            }
        );
        assert_eq!(snapshot.profiles, Vec::<PortProfile>::new());
        assert_eq!(snapshot.wlans, Vec::<WirelessNetwork>::new());
        assert_eq!(
            (fake.logins(), fake.login_attempts()),
            (0, 0),
            "an API key needs no session"
        );
    }
}

#[tokio::test]
async fn an_integration_api_without_networks_yields_none_and_clients_without_a_network() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    fake.state().integration_networks = false;
    let snapshot = Unifi
        .topology(&fake.key_context())
        .await
        .expect("the topology");
    assert_eq!(snapshot.networks, Vec::<ControllerNetwork>::new());
    assert_eq!(snapshot.clients.len(), 7);
    assert!(
        snapshot
            .clients
            .iter()
            .all(|client| client.network.is_none() && client.vlan.is_none())
    );
}

#[tokio::test]
async fn the_integration_api_reads_every_page_of_a_long_client_list() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    let extra = {
        let mut state = fake.state();
        let used: BTreeSet<String> = state
            .clients
            .iter()
            .chain(&state.devices)
            .filter_map(|record| record["mac"].as_str().map(str::to_owned))
            .collect();
        let free: Vec<String> = (0u8..=255)
            .map(|last| format!("00:00:5e:00:53:{last:02x}"))
            .filter(|mac| !used.contains(mac))
            .take(205)
            .collect();
        assert_eq!(free.len(), 205);
        for mac in &free {
            state.clients.push(json!({
                "_id": "5f7100000000000000000001",
                "mac": mac,
                "is_wired": true,
                "ip": "192.0.2.200",
                "sw_mac": ids::CORE,
                "sw_port": 3,
            }));
        }
        free.len()
    };
    let snapshot = Unifi
        .topology(&fake.key_context())
        .await
        .expect("the topology");
    assert_eq!(snapshot.clients.len(), 7 + extra);
    let batch = Unifi
        .poll(&fake.key_context(), None)
        .await
        .expect("the inventory");
    assert_eq!(batch.hosts.len(), 5 + 7 + extra);
}

#[tokio::test]
async fn the_integration_api_inventory_and_check() {
    for flavor in BOTH {
        let fake = FakeController::start(flavor).await;
        let batch = Unifi
            .poll(&fake.key_context(), None)
            .await
            .expect("the inventory");
        assert!(batch.complete);
        assert_eq!(batch.hosts.len(), 12, "{flavor:?}");
        let device = batch
            .hosts
            .iter()
            .find(|host| host.external_id == format!("device:{}", ids::CORE))
            .expect("sw-core");
        assert_eq!(device.tags, ["unifi:device"]);
        assert_eq!(device.ips, [ip("192.0.2.2")]);
        let phone = batch
            .hosts
            .iter()
            .find(|host| host.external_id == format!("client:{}", ids::PHONE))
            .expect("the phone");
        assert_eq!(phone.tags, ["unifi:wireless"]);

        let report = Unifi.check(&fake.key_context()).await.expect("a check");
        assert_eq!(report.remote_version.as_deref(), Some("9.0.0"));
        let detail = report.detail.expect("a detail");
        assert!(detail.contains("Integration"), "{flavor:?}: {detail}");
    }
}

#[tokio::test]
async fn a_wrong_api_key_is_unauthorized() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    let wrong = FakeController::context_with(
        {
            let mut settings = fake.settings();
            settings
                .as_object_mut()
                .expect("settings are an object")
                .remove("username");
            settings
        },
        &[("api_key", "wrong-key-0001")],
    );
    assert_eq!(code(Unifi.topology(&wrong).await), "connect.unauthorized");
    assert_eq!(code(Unifi.check(&wrong).await), "connect.unauthorized");
}

#[tokio::test]
async fn nothing_can_be_planned_through_the_integration_api() {
    for flavor in BOTH {
        let fake = FakeController::start(flavor).await;
        let ctx = fake.key_context();
        let changes = [
            L2Change::EnsureNetwork {
                vlan: 70,
                name: "Cameras".to_owned(),
                dhcp: ControllerDhcp::Disabled,
            },
            L2Change::SetPortProfile {
                device: dev(ids::CORE),
                port: 3,
                profile: ProfileRef(ids::PROFILE_IOT.to_owned()),
            },
            L2Change::SetClientVlan {
                mac: mac(ids::PHONE),
                network: net(ids::NET_IOT),
            },
            L2Change::ClearClientVlan {
                mac: mac(ids::PHONE),
            },
            L2Change::RemoveNetwork {
                network: net(ids::NET_LAB),
                vlan: 50,
            },
        ];
        for change in &changes {
            assert_eq!(
                code(Unifi.plan(&ctx, change).await),
                "connect.unsupported",
                "{flavor:?}: {change:?}"
            );
        }
        assert_eq!(fake.writes(), Vec::new(), "{flavor:?}");
    }
}

// ---- the host's strict conversion ----------------------------------------------------

#[tokio::test]
async fn classic_snapshots_survive_the_hosts_strict_conversion() {
    for flavor in BOTH {
        let fake = FakeController::start(flavor).await;
        let snapshot = topology(&fake).await;
        let back = topology_from_proto(Some(topology_to_proto(&snapshot)))
            .unwrap_or_else(|error| panic!("{flavor:?}: {error}"));
        assert_eq!(back, snapshot, "{flavor:?}");
    }
}

#[tokio::test]
async fn integration_snapshots_survive_the_hosts_strict_conversion() {
    for flavor in BOTH {
        let fake = FakeController::start(flavor).await;
        let snapshot = Unifi
            .topology(&fake.key_context())
            .await
            .expect("the topology");
        let back = topology_from_proto(Some(topology_to_proto(&snapshot)))
            .unwrap_or_else(|error| panic!("{flavor:?}: {error}"));
        assert_eq!(back, snapshot, "{flavor:?}");
    }
}

// ---- the fake itself -----------------------------------------------------------------

/// The Integration API of the fake answers as the plugin expects, whatever the plugin sends.
#[tokio::test]
async fn the_fake_integration_api_pages_and_derives_its_data_from_the_fixtures() {
    use tenko_connect::sdk::http::reqwest::{Client, StatusCode};

    for flavor in BOTH {
        let fake = FakeController::start(flavor).await;
        let base = format!("{}{}", fake.url(), flavor.integration());
        let client = Client::new();
        let get = |path: String, key: Option<&'static str>| {
            let client = client.clone();
            let url = format!("{base}{path}");
            async move {
                let mut request = client.get(url);
                if let Some(key) = key {
                    request = request.header("X-API-Key", key);
                }
                let response = request.send().await.expect("an answer");
                let status = response.status();
                let body: Value = response.json().await.unwrap_or(Value::Null);
                (status, body)
            }
        };
        let key = Some(support::API_KEY);

        let (status, body) = get("/info".to_owned(), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{flavor:?}");
        assert_eq!(body["statusName"], "UNAUTHORIZED");
        let (_, body) = get("/info".to_owned(), key).await;
        assert_eq!(body, json!({ "applicationVersion": "9.0.0" }));

        let (_, sites) = get("/sites?offset=0&limit=200".to_owned(), key).await;
        assert_eq!(sites["count"], 1);
        assert_eq!(sites["totalCount"], 1);
        assert_eq!(sites["data"][0]["internalReference"], "default");
        let site = sites["data"][0]["id"]
            .as_str()
            .expect("a site id")
            .to_owned();

        // Five adopted devices; the list pages by offset and limit and leaves out `uplink`.
        let (_, page) = get(format!("/sites/{site}/devices?offset=3&limit=2"), key).await;
        assert_eq!(page["offset"], 3);
        assert_eq!(page["limit"], 2);
        assert_eq!(page["count"], 2);
        assert_eq!(page["totalCount"], 5);
        assert!(page["data"][0].get("uplink").is_none());
        assert_eq!(page["data"][0]["macAddress"], ids::HALL);
        assert_eq!(page["data"][0]["features"], json!(["accessPoint"]));
        let (_, page) = get(format!("/sites/{site}/devices?offset=5&limit=2"), key).await;
        assert_eq!(
            (page["count"].clone(), page["totalCount"].clone()),
            (json!(0), json!(5))
        );

        // The detail has the uplink, except for the gateway.
        let detail = |mac: &str| {
            format!(
                "/sites/{site}/devices/00000000-0000-0000-0000-{}",
                mac.replace(':', "")
            )
        };
        let (_, garden) = get(detail(ids::GARDEN), key).await;
        assert_eq!(
            garden["uplink"]["deviceId"],
            format!("00000000-0000-0000-0000-{}", ids::HALL.replace(':', ""))
        );
        let (_, gateway) = get(detail(ids::GATEWAY), key).await;
        assert!(gateway.get("uplink").is_none());
        let (status, _) = get(detail(ids::PENDING), key).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "an unadopted device");

        let (_, clients) = get(format!("/sites/{site}/clients?offset=0&limit=200"), key).await;
        assert_eq!(
            clients["totalCount"], 8,
            "the client with an invalid MAC is served too"
        );
        let printer = clients["data"]
            .as_array()
            .expect("clients")
            .iter()
            .find(|client| client["macAddress"] == ids::PRINTER)
            .expect("the printer");
        assert_eq!(printer["type"], "WIRED");
        assert_eq!(printer["ipAddress"], "198.51.100.20");
        assert_eq!(
            printer["uplinkDeviceId"],
            format!("00000000-0000-0000-0000-{}", ids::ACCESS.replace(':', ""))
        );
    }
}

/// Plans and applies a change, as the host does.
async fn apply(fake: &FakeController, change: &L2Change) -> L2Receipt {
    let ctx = fake.context();
    let plan = Unifi.plan(&ctx, change).await.expect("a plan");
    Unifi
        .apply(&ctx, &plan, WriteMode::Apply)
        .await
        .expect("an applied change")
}

/// The record of the fixture network named `name`, if the fake has one.
fn network_record(fake: &FakeController, name: &str) -> Option<Value> {
    fake.state()
        .networks
        .iter()
        .find(|network| network["name"] == name)
        .cloned()
}

/// The writes of the plugin land in the fake's data, read back and undone.
#[tokio::test]
async fn the_fake_takes_the_plugins_writes_and_shows_them_back() {
    for flavor in BOTH {
        let fake = FakeController::start(flavor).await;
        let ctx = fake.context();

        // A new VLAN-only network, and its removal by the undo step.
        let created = apply(
            &fake,
            &L2Change::EnsureNetwork {
                vlan: 70,
                name: "Cameras".to_owned(),
                dhcp: ControllerDhcp::Disabled,
            },
        )
        .await;
        assert!(created.verified, "{flavor:?}");
        let record = network_record(&fake, "Cameras").expect("the new network");
        assert_eq!(record["vlan"], 70);
        assert_eq!(record["purpose"], "vlan-only");
        assert_eq!(record["site_id"], support::SITE_ID);
        let id = record["_id"].as_str().expect("an id");
        assert!(id.len() == 24 && id.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
        let writes = fake.writes();
        assert_eq!(writes.len(), 1, "{flavor:?}");
        assert_eq!(
            (writes[0].method.as_str(), writes[0].route()),
            ("POST", "rest/networkconf")
        );
        assert!(
            writes[0]
                .path
                .starts_with(&format!("{}/api/s/default/", flavor.network()))
        );
        Unifi.revert(&ctx, &created).await.expect("an undo");
        assert_eq!(network_record(&fake, "Cameras"), None, "{flavor:?}");
        let writes = fake.writes();
        assert_eq!(writes.len(), 2, "{flavor:?}");
        assert_eq!(writes[1].method, "DELETE");

        // A port profile: the override and the effective profile of the port follow.
        let port_change = L2Change::SetPortProfile {
            device: dev(ids::CORE),
            port: 3,
            profile: ProfileRef(ids::PROFILE_IOT.to_owned()),
        };
        let receipt = apply(&fake, &port_change).await;
        assert!(receipt.verified, "{flavor:?}");
        let snapshot = topology(&fake).await;
        assert_eq!(
            port(device(&snapshot, ids::CORE), 3).profile,
            Some(ProfileRef(ids::PROFILE_IOT.to_owned()))
        );
        Unifi.revert(&ctx, &receipt).await.expect("an undo");
        let snapshot = topology(&fake).await;
        assert_eq!(
            port(device(&snapshot, ids::CORE), 3).profile,
            Some(ProfileRef(ids::PROFILE_ALL.to_owned())),
            "{flavor:?}"
        );

        // A per-client VLAN override.
        let receipt = apply(
            &fake,
            &L2Change::SetClientVlan {
                mac: mac(ids::PRINTER),
                network: net(ids::NET_GUEST),
            },
        )
        .await;
        assert!(receipt.verified, "{flavor:?}");
        let printer = |fake: &FakeController| {
            fake.state()
                .users
                .iter()
                .find(|user| user["mac"] == ids::PRINTER)
                .cloned()
                .expect("the printer's record")
        };
        assert_eq!(printer(&fake)["virtual_network_override_enabled"], true);
        assert_eq!(
            printer(&fake)["virtual_network_override_id"],
            ids::NET_GUEST
        );
        Unifi.revert(&ctx, &receipt).await.expect("an undo");
        assert_eq!(printer(&fake)["virtual_network_override_enabled"], false);

        assert_eq!(fake.state().open_sessions(), 0, "{flavor:?}");
    }
}

/// With drift on, the fake answers writes with `ok` and stores something else, which the
/// plugin's read-back reports as unverified.
#[tokio::test]
async fn writes_that_drift_do_not_read_back() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    fake.set_drift_after_write(true);
    let network = apply(
        &fake,
        &L2Change::EnsureNetwork {
            vlan: 71,
            name: "Cameras".to_owned(),
            dhcp: ControllerDhcp::Disabled,
        },
    )
    .await;
    assert!(!network.verified);
    assert!(network_record(&fake, "Cameras-drift").is_some());
    let port = apply(
        &fake,
        &L2Change::SetPortProfile {
            device: dev(ids::CORE),
            port: 4,
            profile: ProfileRef(ids::PROFILE_TRUNK.to_owned()),
        },
    )
    .await;
    assert!(!port.verified);
    let client = apply(
        &fake,
        &L2Change::SetClientVlan {
            mac: mac(ids::SENSOR),
            network: net(ids::NET_GUEST),
        },
    )
    .await;
    assert!(!client.verified);
    assert_eq!(fake.writes().len(), 3);
}

/// A forced deployment skips the detection of `/`.
#[tokio::test]
async fn a_forced_deployment_skips_the_detection_request() {
    for (flavor, forced, first) in [
        (Flavor::SelfHosted, "self_hosted", "GET /status"),
        (Flavor::UnifiOs, "unifi_os", "GET /proxy/network/status"),
    ] {
        let fake = FakeController::start(flavor).await;
        let mut settings = fake.settings();
        settings["deployment"] = json!(forced);
        let ctx = FakeController::context_with(settings, &[("password", PASSWORD)]);
        let snapshot = Unifi.topology(&ctx).await.expect("the topology");
        assert_eq!(snapshot.devices.len(), 5, "{flavor:?}");
        assert_eq!(fake.request_log()[0], first, "{flavor:?}");
    }
}
