//! Tests of the L2 decision of a move (IPAM-19 step 4): every rule of `decide_all` against
//! hand-built controller reads, the offline plans, and the task, argument and text
//! mappings.

use std::sync::Mutex;

use tenko_core::{
    ConnectorId, MacAddr, PrefixId, Timestamp, VrfId, net::HostName, observe::Endpoint,
};

use super::*;
use crate::vlan::controllers::{
    ControllerDevice, ControllerDeviceKind, ControllerLink, ControllerPortState, ControllerProfile,
    ControllerWlan, derived_guardrails,
};

/// The target VLAN of every test.
const VID: u16 = 30;
const HOME_SSID: &str = "home.example.test";
const IOT_SSID: &str = "iot.example.test";

fn mac(n: u8) -> MacAddr {
    MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, n])
}

fn at() -> Timestamp {
    "2026-10-10T12:00:00Z".parse().expect("time")
}

fn info(name: &str) -> ControllerInfo {
    ControllerInfo {
        id: ConnectorId::generate(),
        name: name.to_owned(),
        plugin: "memory".to_owned(),
        enabled: true,
        writes_enabled: true,
    }
}

fn device(id: &str, name: &str, kind: ControllerDeviceKind) -> ControllerDevice {
    ControllerDevice {
        id: id.to_owned(),
        name: name.to_owned(),
        model: None,
        mac: None,
        ip: None,
        kind,
        ports: Vec::new(),
    }
}

fn network(id: &str, name: &str, vlan: u16, management: bool) -> ControllerNetwork {
    ControllerNetwork {
        id: id.to_owned(),
        name: name.to_owned(),
        vlan: Some(vlan),
        subnet: None,
        management,
        dhcp: None,
    }
}

fn profile(id: &str, name: &str, native: &str, tagged: &[&str]) -> ControllerProfile {
    ControllerProfile {
        id: id.to_owned(),
        name: name.to_owned(),
        native_network: Some(native.to_owned()),
        tagged: tagged.iter().map(|t| (*t).to_owned()).collect(),
    }
}

fn switch_port(index: u16, profile: Option<&str>, up: bool) -> ControllerPortState {
    ControllerPortState {
        device: "sw-1".to_owned(),
        index,
        name: Some(format!("Port {index}")),
        profile: profile.map(str::to_owned),
        native_vlan: None,
        uplink: false,
        management: false,
        up,
    }
}

fn wlan(ssid: &str, vlan: u16, enabled: bool, access_points: &[&str]) -> ControllerWlan {
    ControllerWlan {
        ssid: ssid.to_owned(),
        vlan: Some(vlan),
        enabled,
        access_points: access_points.iter().map(|ap| (*ap).to_owned()).collect(),
    }
}

/// A client of the home network on `port` of the switch.
fn wired(n: u8, port: u16) -> ControllerClient {
    ControllerClient {
        mac: mac(n),
        ip: None,
        device: "sw-1".to_owned(),
        port: Some(port),
        ssid: None,
        network: Some("net-home".to_owned()),
        vlan: Some(20),
        name: None,
        management: false,
    }
}

/// A client of the home network on the home SSID of the access point.
fn wireless(n: u8) -> ControllerClient {
    ControllerClient {
        device: "ap-1".to_owned(),
        port: None,
        ssid: Some(HOME_SSID.to_owned()),
        ..wired(n, 0)
    }
}

// One switch "sw-1" with five ports (1 on the home profile and up, 2 without a profile and
// down, 3 an uplink, 4 the management port, 5 the uplink of the access point), one access
// point "ap-1", the networks home (20), IoT (30) and management (10), and the profiles
// home, IoT and an IoT trunk whose name sorts before IoT.
fn state(info: &ControllerInfo) -> ControllerAttachments {
    let mut uplink = switch_port(3, None, true);
    uplink.uplink = true;
    let mut management = switch_port(4, None, true);
    management.management = true;
    ControllerAttachments {
        connector: info.id,
        observed_at: at(),
        devices: vec![
            device("sw-1", "Switch One", ControllerDeviceKind::Switch),
            device(
                "ap-1",
                "Access Point One",
                ControllerDeviceKind::AccessPoint,
            ),
        ],
        ports: vec![
            switch_port(1, Some("prof-home"), true),
            switch_port(2, None, false),
            uplink,
            management,
            switch_port(5, Some("prof-home"), true),
        ],
        clients: Vec::new(),
        networks: vec![
            network("net-home", "Home", 20, false),
            network("net-iot", "IoT", VID, false),
            network("net-mgmt", "Management", 10, true),
        ],
        profiles: vec![
            profile("prof-home", "Home", "net-home", &[]),
            profile("prof-iot-trunk", "Access trunk", "net-iot", &["net-home"]),
            profile("prof-iot", "IoT", "net-iot", &[]),
        ],
        wlans: Vec::new(),
        links: Vec::new(),
    }
}

/// A controller whose only client is wired on `port` of the switch.
fn wired_lab(port: u16) -> (ControllerInfo, ControllerAttachments) {
    let info = info("lab");
    let mut state = state(&info);
    state.clients.push(wired(1, port));
    (info, state)
}

/// A controller whose only client is wireless on the access point.
fn wireless_lab() -> (ControllerInfo, ControllerAttachments) {
    let info = info("lab");
    let mut state = state(&info);
    state.clients.push(wireless(1));
    (info, state)
}

fn port_mut(state: &mut ControllerAttachments, index: u16) -> &mut ControllerPortState {
    state
        .ports
        .iter_mut()
        .find(|p| p.index == index)
        .expect("port")
}

/// The access point is linked to `port` of the switch; the access point is end A.
fn link_ap(state: &mut ControllerAttachments, port: u16) {
    state.links.push(ControllerLink {
        a: Endpoint {
            device: "ap-1".to_owned(),
            port: None,
        },
        b: Endpoint {
            device: "sw-1".to_owned(),
            port: Some(port.to_string()),
        },
    });
}

fn read(info: &ControllerInfo, state: ControllerAttachments) -> Read {
    Read {
        info: info.clone(),
        state: Ok(state),
    }
}

fn failed(info: &ControllerInfo) -> Read {
    Read {
        info: info.clone(),
        state: Err(CodedError::new(
            "connect.unreachable",
            502,
            "the controller does not answer",
        )),
    }
}

fn item(mac: Option<MacAddr>) -> MoveItem {
    MoveItem {
        object: AddressId::generate().into(),
        requested: AddressId::generate().into(),
        host: None,
        host_name: None,
        mode: None,
        interface: None,
        mac,
        old_ip: "192.0.2.10".parse().expect("ip"),
        new_ip: "198.51.100.10".parse().expect("ip"),
        new_address: AddressId::generate(),
        same_host_part: true,
        reason: None,
        dns: None,
        l2: MoveL2::default(),
        timing: crate::moves::timing::MoveTiming::default(),
        steps: Vec::new(),
        warnings: Vec::new(),
    }
}

/// An item on the interface `interface`.
fn item_on(interface: InterfaceId, mac: Option<MacAddr>) -> MoveItem {
    MoveItem {
        interface: Some(interface),
        ..item(mac)
    }
}

fn run(items: &[MoveItem], reads: &[Read]) -> L2Plans {
    decide_all(items, VID, reads, &derived_guardrails)
}

/// The L2 step and the warnings of the device `mac(1)` on one controller.
fn decide_one(info: &ControllerInfo, state: ControllerAttachments) -> (MoveL2, Vec<PlanWarning>) {
    let plans = run(&[item(Some(mac(1)))], &[read(info, state)]);
    let l2 = plans.items.into_iter().next().expect("one item");
    (l2, plans.warnings)
}

fn no_strings() -> Vec<String> {
    Vec::new()
}

/// Decides the device `mac(1)` with `check` and asserts that exactly one refusal, to
/// acknowledge, came out of it.
fn refused_by(
    check: Check<'_>,
    info: &ControllerInfo,
    state: ControllerAttachments,
    rule: &str,
) -> MoveL2 {
    let subject = item(Some(mac(1)));
    let plans = decide_all(
        std::slice::from_ref(&subject),
        VID,
        &[read(info, state)],
        check,
    );
    let l2 = plans.items[0].clone();
    assert_eq!(l2.action, MoveL2Action::Manual);
    assert_eq!(l2.reason.as_deref(), Some(codes::L2_REFUSED_REASON));
    assert_eq!(l2.problem.as_ref().map(|p| p.code.as_str()), Some(rule));
    assert_eq!(l2.change, None);
    assert_eq!(plans.warnings.len(), 1);
    let warning = &plans.warnings[0];
    assert_eq!(warning.code, codes::L2_REFUSED);
    assert!(warning.requires_ack);
    assert!(!warning.acknowledged);
    assert_eq!(warning.object, Some(subject.object));
    assert_eq!(
        warning.params,
        BTreeMap::from([
            ("host".to_owned(), "192.0.2.10".to_owned()),
            ("rule".to_owned(), rule.to_owned()),
        ])
    );
    assert!(warning.message.contains(rule), "{}", warning.message);
    l2
}

fn refused(info: &ControllerInfo, state: ControllerAttachments, rule: &str) -> MoveL2 {
    refused_by(&derived_guardrails, info, state, rule)
}

// The wired rules.

#[test]
fn a_wired_client_gets_the_profile_with_the_target_network_untagged() {
    let (info, state) = wired_lab(1);
    let (l2, warnings) = decide_one(&info, state);
    assert_eq!(warnings, Vec::new());
    assert_eq!(l2.action, MoveL2Action::PortProfile);
    assert_eq!(l2.reason, None);
    assert_eq!(l2.problem, None);
    assert_eq!(l2.connector.as_ref(), Some(&info));
    assert_eq!(l2.read_at, Some(at()));
    // The profile without tagged networks wins over the trunk whose name sorts first.
    assert_eq!(
        l2.change,
        Some(AttachmentChange::SetPortProfile {
            device: "sw-1".to_owned(),
            port: 1,
            profile: "prof-iot".to_owned(),
        })
    );
    assert_eq!(
        l2.attachment,
        Some(MoveAttachment {
            medium: MoveMedium::Wired,
            device: "sw-1".to_owned(),
            device_name: "Switch One".to_owned(),
            port: Some(1),
            port_name: Some("Port 1".to_owned()),
            profile: Some("prof-home".to_owned()),
            profile_name: Some("Home".to_owned()),
            ssid: None,
            network: Some("net-home".to_owned()),
            network_name: Some("Home".to_owned()),
            vlan: Some(20),
        })
    );
    assert_eq!(l2.profile_name.as_deref(), Some("IoT"));
    assert_eq!(l2.network_name.as_deref(), Some("IoT"));
    assert_eq!(
        l2.diff,
        vec![DiffEntry {
            path: "devices/sw-1/ports/1/profile".to_owned(),
            before: Some("Home".to_owned()),
            after: Some("IoT".to_owned()),
        }]
    );
    assert_eq!(l2.notes, [codes::NOTE_LINK_FLAP]);
    assert_eq!(l2.others_on_port, None);
    assert_eq!(l2.ssids, no_strings());
    assert_eq!(l2.with, None);
    assert!(l2.has_step());
    assert!(l2.automatic());
    assert_eq!(l2.connector_id(), Some(info.id));
}

#[test]
fn the_link_flap_note_follows_the_link_state_of_the_port() {
    let (info, mut state) = wired_lab(1);
    port_mut(&mut state, 1).up = false;
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.action, MoveL2Action::PortProfile);
    assert_eq!(l2.notes, no_strings());
}

#[test]
fn a_port_without_a_profile_notes_that_a_rollback_cannot_restore_it() {
    let (info, state) = wired_lab(2);
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.action, MoveL2Action::PortProfile);
    assert_eq!(l2.notes, [codes::NOTE_NO_UNDO]);
    assert_eq!(
        l2.diff,
        vec![DiffEntry {
            path: "devices/sw-1/ports/2/profile".to_owned(),
            before: None,
            after: Some("IoT".to_owned()),
        }]
    );
    let attachment = l2.attachment.expect("attachment");
    assert_eq!((attachment.profile, attachment.profile_name), (None, None));
}

#[test]
fn an_up_port_without_a_profile_notes_both_the_flap_and_the_missing_undo() {
    let (info, mut state) = wired_lab(2);
    port_mut(&mut state, 2).up = true;
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.notes, [codes::NOTE_LINK_FLAP, codes::NOTE_NO_UNDO]);
}

#[test]
fn a_trunk_profile_is_used_with_a_tagged_note_when_it_is_the_only_one() {
    let (info, mut state) = wired_lab(1);
    state.profiles.retain(|p| p.id != "prof-iot");
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.action, MoveL2Action::PortProfile);
    assert_eq!(
        l2.change,
        Some(AttachmentChange::SetPortProfile {
            device: "sw-1".to_owned(),
            port: 1,
            profile: "prof-iot-trunk".to_owned(),
        })
    );
    assert_eq!(l2.profile_name.as_deref(), Some("Access trunk"));
    assert_eq!(l2.notes, [codes::NOTE_LINK_FLAP, codes::NOTE_TAGGED]);
}

#[test]
fn profiles_without_tagged_networks_are_ordered_by_name_then_id() {
    let (info, mut state) = wired_lab(1);
    state
        .profiles
        .push(profile("prof-b", "Camera", "net-iot", &[]));
    state
        .profiles
        .push(profile("prof-a", "Camera", "net-iot", &[]));
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.profile_name.as_deref(), Some("Camera"));
    assert_eq!(
        l2.change,
        Some(AttachmentChange::SetPortProfile {
            device: "sw-1".to_owned(),
            port: 1,
            profile: "prof-a".to_owned(),
        })
    );
}

#[test]
fn a_network_that_is_not_management_is_preferred_for_the_vlan() {
    let (info, mut state) = wired_lab(1);
    state
        .networks
        .insert(0, network("net-iot-mgmt", "IoT management", VID, true));
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.action, MoveL2Action::PortProfile);
    assert_eq!(l2.network_name.as_deref(), Some("IoT"));
}

// Already in the target VLAN.

#[test]
fn a_client_already_in_the_target_vlan_is_unchanged() {
    let (info, mut state) = wired_lab(1);
    state.clients[0].vlan = Some(VID);
    state.clients[0].network = Some("net-iot".to_owned());
    let (l2, warnings) = decide_one(&info, state);
    assert_eq!(warnings, Vec::new());
    assert_eq!(l2.action, MoveL2Action::Unchanged);
    assert_eq!(l2.reason.as_deref(), Some(codes::L2_ALREADY_THERE));
    assert_eq!(l2.change, None);
    assert_eq!(l2.diff, Vec::new());
    assert_eq!(l2.attachment.as_ref().map(|a| a.vlan), Some(Some(VID)));
    assert!(!l2.has_step());
}

#[test]
fn a_port_already_on_the_target_profile_is_unchanged() {
    let (info, mut state) = wired_lab(1);
    port_mut(&mut state, 1).profile = Some("prof-iot".to_owned());
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.action, MoveL2Action::Unchanged);
    assert_eq!(l2.reason.as_deref(), Some(codes::L2_ALREADY_THERE));
    assert_eq!(l2.change, None);
    assert_eq!(l2.diff, Vec::new());
    assert_eq!(l2.notes, no_strings());
    assert_eq!(l2.network_name.as_deref(), Some("IoT"));
}

#[test]
fn a_port_whose_profile_has_the_target_network_untagged_is_unchanged() {
    let (info, mut state) = wired_lab(1);
    port_mut(&mut state, 1).profile = Some("prof-iot-trunk".to_owned());
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.action, MoveL2Action::Unchanged);
    assert_eq!(l2.reason.as_deref(), Some(codes::L2_ALREADY_THERE));
    assert_eq!(l2.change, None);
}

// The wireless rules.

#[test]
fn a_wireless_client_gets_a_per_client_vlan() {
    let (info, mut state) = wireless_lab();
    link_ap(&mut state, 5);
    port_mut(&mut state, 5).native_vlan = Some(VID);
    let (l2, warnings) = decide_one(&info, state);
    assert_eq!(warnings, Vec::new());
    assert_eq!(l2.action, MoveL2Action::ClientVlan);
    assert_eq!(l2.reason, None);
    assert_eq!(
        l2.change,
        Some(AttachmentChange::SetClientVlan {
            mac: mac(1),
            network: "net-iot".to_owned(),
        })
    );
    assert_eq!(l2.notes, [codes::NOTE_RECONNECT]);
    assert_eq!(
        l2.diff,
        vec![DiffEntry {
            path: "clients/00:00:5e:00:53:01/network".to_owned(),
            before: Some("Home".to_owned()),
            after: Some("IoT".to_owned()),
        }]
    );
    assert_eq!(l2.network_name.as_deref(), Some("IoT"));
    assert_eq!(l2.profile_name, None);
    assert_eq!(
        l2.attachment,
        Some(MoveAttachment {
            medium: MoveMedium::Wireless,
            device: "ap-1".to_owned(),
            device_name: "Access Point One".to_owned(),
            port: None,
            port_name: None,
            profile: None,
            profile_name: None,
            ssid: Some(HOME_SSID.to_owned()),
            network: Some("net-home".to_owned()),
            network_name: Some("Home".to_owned()),
            vlan: Some(20),
        })
    );
    assert!(l2.automatic());
}

#[test]
fn an_access_point_carries_the_vlan_when_its_uplink_profile_has_the_network_untagged() {
    let (info, mut state) = wireless_lab();
    link_ap(&mut state, 5);
    port_mut(&mut state, 5).profile = Some("prof-iot".to_owned());
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.action, MoveL2Action::ClientVlan);
    assert_eq!(l2.notes, [codes::NOTE_RECONNECT]);
}

#[test]
fn an_access_point_carries_the_vlan_when_its_uplink_profile_tags_the_network() {
    let (info, mut state) = wireless_lab();
    link_ap(&mut state, 5);
    state
        .profiles
        .push(profile("prof-ap", "Access point", "net-home", &["net-iot"]));
    port_mut(&mut state, 5).profile = Some("prof-ap".to_owned());
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.action, MoveL2Action::ClientVlan);
    assert_eq!(l2.notes, [codes::NOTE_RECONNECT]);
}

#[test]
fn a_link_is_followed_from_either_end() {
    let (info, mut state) = wireless_lab();
    state.links.push(ControllerLink {
        a: Endpoint {
            device: "sw-1".to_owned(),
            port: Some("5".to_owned()),
        },
        b: Endpoint {
            device: "ap-1".to_owned(),
            port: None,
        },
    });
    port_mut(&mut state, 5).native_vlan = Some(VID);
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.action, MoveL2Action::ClientVlan);
    assert_eq!(l2.notes, [codes::NOTE_RECONNECT]);
}

#[test]
fn an_access_point_that_broadcasts_a_ssid_on_the_vlan_carries_it() {
    let (info, mut state) = wireless_lab();
    // The uplink profile lacks the network, the SSID of the access point makes up for it.
    link_ap(&mut state, 5);
    state.wlans.push(wlan(IOT_SSID, VID, true, &["ap-1"]));
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.action, MoveL2Action::ClientVlan);
    assert_eq!(l2.notes, [codes::NOTE_RECONNECT]);
    assert_eq!(l2.ssids, [IOT_SSID]);
}

#[test]
fn an_access_point_without_uplink_information_is_given_the_benefit_of_the_doubt() {
    let (info, state) = wireless_lab();
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.action, MoveL2Action::ClientVlan);
    assert_eq!(l2.notes, [codes::NOTE_CARRY_UNKNOWN, codes::NOTE_RECONNECT]);
    assert!(l2.change.is_some());
}

#[test]
fn an_uplink_port_without_a_profile_leaves_it_unknown_whether_the_vlan_is_carried() {
    let (info, mut state) = wireless_lab();
    link_ap(&mut state, 5);
    port_mut(&mut state, 5).profile = None;
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.action, MoveL2Action::ClientVlan);
    assert_eq!(l2.notes, [codes::NOTE_CARRY_UNKNOWN, codes::NOTE_RECONNECT]);
}

#[test]
fn an_access_point_that_does_not_carry_the_vlan_sends_the_client_to_an_ssid_that_does() {
    let (info, mut state) = wireless_lab();
    link_ap(&mut state, 5);
    // Two enabled SSIDs on the VLAN elsewhere (listed by name), one disabled, one on
    // another VLAN.
    state
        .wlans
        .push(wlan("iot-b.example.test", VID, true, &["ap-2"]));
    state
        .wlans
        .push(wlan("iot-a.example.test", VID, true, &["ap-3"]));
    state
        .wlans
        .push(wlan("off.example.test", VID, false, &["ap-2"]));
    state.wlans.push(wlan(HOME_SSID, 20, true, &["ap-1"]));
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.action, MoveL2Action::Manual);
    assert_eq!(l2.reason.as_deref(), Some(codes::L2_JOIN_SSID));
    assert_eq!(l2.ssids, ["iot-a.example.test", "iot-b.example.test"]);
    assert_eq!(l2.change, None);
    assert_eq!(l2.diff, Vec::new());
    assert_eq!(l2.notes, no_strings());
    assert_eq!(l2.network_name.as_deref(), Some("IoT"));
    assert!(l2.attachment.is_some());
}

#[test]
fn an_access_point_that_does_not_carry_the_vlan_and_no_ssid_either_is_left_to_a_person() {
    let (info, mut state) = wireless_lab();
    link_ap(&mut state, 5);
    // A disabled SSID on the VLAN does not count.
    state
        .wlans
        .push(wlan("off.example.test", VID, false, &["ap-1"]));
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.action, MoveL2Action::Manual);
    assert_eq!(l2.reason.as_deref(), Some(codes::L2_NO_SSID));
    assert_eq!(l2.ssids, no_strings());
    assert_eq!(l2.change, None);
}

// Refusals.

#[test]
fn an_uplink_port_is_refused() {
    let (info, state) = wired_lab(3);
    let l2 = refused(&info, state, "connect.guardrail.uplink");
    assert_eq!(
        l2.problem.map(|p| p.detail).as_deref(),
        Some("port 3 of Switch One is an uplink")
    );
    assert_eq!(l2.network_name.as_deref(), Some("IoT"));
    assert!(l2.attachment.is_some());
    assert_eq!(l2.diff, Vec::new());
}

#[test]
fn the_management_port_is_refused() {
    let (info, state) = wired_lab(4);
    let l2 = refused(&info, state, "connect.guardrail.management_port");
    assert!(l2.problem.expect("problem").detail.contains("port 4"));
}

#[test]
fn a_management_client_is_refused() {
    let (info, mut state) = wired_lab(1);
    state.clients[0].management = true;
    let l2 = refused(&info, state, "connect.guardrail.management_client");
    assert_eq!(
        l2.problem.map(|p| p.detail).as_deref(),
        Some("00:00:5e:00:53:01 is the controller or Tenko's host")
    );
}

#[test]
fn a_wireless_management_client_is_refused() {
    let (info, mut state) = wireless_lab();
    state.clients[0].management = true;
    refused(&info, state, "connect.guardrail.management_client");
}

#[test]
fn a_target_network_that_is_a_management_network_is_refused() {
    let (info, mut state) = wired_lab(1);
    state.networks[1].management = true;
    let l2 = refused(&info, state, "connect.guardrail.protected_network");
    assert_eq!(
        l2.problem.map(|p| p.detail).as_deref(),
        Some("IoT (VLAN 30) is a management network")
    );
}

#[test]
fn the_check_of_the_controllers_port_can_refuse_what_the_derived_rules_allow() {
    let (info, state) = wired_lab(1);
    let check = |_: &ControllerAttachments, _: &AttachmentChange| -> Result<(), CodedError> {
        Err(CodedError::new(
            "connect.guardrail.protected_port",
            409,
            "port 1 of sw-1 is protected",
        ))
    };
    let l2 = refused_by(&check, &info, state, "connect.guardrail.protected_port");
    assert_eq!(
        l2.problem.map(|p| p.detail).as_deref(),
        Some("port 1 of sw-1 is protected")
    );
    // The diff is shown, the change is not offered.
    assert_eq!(l2.diff.len(), 1);
    assert_eq!(l2.profile_name.as_deref(), Some("IoT"));
}

#[test]
fn the_check_is_asked_about_the_change_and_not_about_what_is_refused_before_it() {
    let asked = Mutex::new(Vec::new());
    let check = |_: &ControllerAttachments, change: &AttachmentChange| -> Result<(), CodedError> {
        asked.lock().expect("lock").push(change.clone());
        Ok(())
    };
    let (info, state) = wired_lab(1);
    let plans = decide_all(&[item(Some(mac(1)))], VID, &[read(&info, state)], &check);
    assert_eq!(plans.items[0].action, MoveL2Action::PortProfile);
    assert_eq!(
        *asked.lock().expect("lock"),
        [AttachmentChange::SetPortProfile {
            device: "sw-1".to_owned(),
            port: 1,
            profile: "prof-iot".to_owned(),
        }]
    );
    // An uplink never reaches the check.
    let (info, state) = wired_lab(3);
    asked.lock().expect("lock").clear();
    let plans = decide_all(&[item(Some(mac(1)))], VID, &[read(&info, state)], &check);
    assert_eq!(
        plans.items[0].reason.as_deref(),
        Some(codes::L2_REFUSED_REASON)
    );
    assert_eq!(asked.lock().expect("lock").len(), 0);
}

#[test]
fn a_refusal_names_the_host_by_its_name_when_it_has_one() {
    let (info, state) = wired_lab(3);
    let subject = MoveItem {
        host_name: Some(HostName::new("printer").expect("name")),
        ..item(Some(mac(1)))
    };
    let plans = run(&[subject], &[read(&info, state)]);
    assert_eq!(plans.warnings.len(), 1);
    assert_eq!(
        plans.warnings[0].params.get("host").map(String::as_str),
        Some("printer")
    );
    assert!(plans.warnings[0].message.contains("printer"));
}

#[test]
fn writes_off_do_not_hide_a_refusal() {
    let (mut info, state) = wired_lab(3);
    info.writes_enabled = false;
    refused(&info, state, "connect.guardrail.uplink");
}

// Left to a person.

#[test]
fn a_port_that_serves_other_devices_is_left_to_a_person() {
    let (info, mut state) = wired_lab(1);
    state.clients.push(wired(2, 1));
    // Not on the port: another port, and a wireless client.
    state.clients.push(wired(3, 2));
    state.clients.push(wireless(4));
    let (l2, warnings) = decide_one(&info, state);
    assert_eq!(warnings, Vec::new());
    assert_eq!(l2.action, MoveL2Action::Manual);
    assert_eq!(l2.reason.as_deref(), Some(codes::L2_SHARED_PORT));
    assert_eq!(l2.others_on_port, Some(1));
    assert_eq!(l2.change, None);
    assert_eq!(l2.diff, Vec::new());
    assert_eq!(l2.profile_name, None);
    assert_eq!(l2.network_name.as_deref(), Some("IoT"));
}

#[test]
fn the_other_devices_on_the_port_are_counted() {
    let (info, mut state) = wired_lab(1);
    state.clients.push(wired(2, 1));
    state.clients.push(wired(3, 1));
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.reason.as_deref(), Some(codes::L2_SHARED_PORT));
    assert_eq!(l2.others_on_port, Some(2));
}

#[test]
fn without_a_profile_that_carries_the_network_untagged_the_port_is_left_to_a_person() {
    let (info, mut state) = wired_lab(1);
    state
        .profiles
        .retain(|p| p.native_network.as_deref() != Some("net-iot"));
    // A profile that only tags the network does not count.
    state
        .profiles
        .push(profile("prof-ap", "Access point", "net-home", &["net-iot"]));
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.action, MoveL2Action::Manual);
    assert_eq!(l2.reason.as_deref(), Some(codes::L2_NO_PROFILE));
    assert_eq!(l2.network_name.as_deref(), Some("IoT"));
    assert_eq!(l2.profile_name, None);
    assert_eq!(l2.change, None);
    assert_eq!(l2.diff, Vec::new());
}

#[test]
fn without_a_network_for_the_vlan_the_device_is_left_to_a_person() {
    let (info, mut state) = wired_lab(1);
    state.networks.retain(|n| n.vlan != Some(VID));
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.action, MoveL2Action::Manual);
    assert_eq!(l2.reason.as_deref(), Some(codes::L2_NO_NETWORK));
    assert_eq!(l2.network_name, None);
    assert_eq!(l2.change, None);
    assert!(l2.attachment.is_some());
}

#[test]
fn a_wired_client_on_an_unknown_port_is_left_to_a_person() {
    let (info, state) = wired_lab(9);
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.action, MoveL2Action::Manual);
    assert_eq!(l2.reason.as_deref(), Some(codes::L2_NO_PORT));
    let attachment = l2.attachment.expect("attachment");
    assert_eq!(attachment.port, Some(9));
    assert_eq!(attachment.profile, None);
}

#[test]
fn a_client_with_neither_a_port_nor_an_ssid_is_left_to_a_person() {
    let (info, mut state) = wired_lab(1);
    state.clients[0].port = None;
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.action, MoveL2Action::Manual);
    assert_eq!(l2.reason.as_deref(), Some(codes::L2_NO_PORT));
    assert_eq!(l2.change, None);
}

#[test]
fn with_writes_off_the_change_is_shown_and_a_person_makes_it() {
    let (mut info, state) = wired_lab(1);
    info.writes_enabled = false;
    let (l2, warnings) = decide_one(&info, state);
    assert_eq!(warnings, Vec::new());
    assert_eq!(l2.action, MoveL2Action::Manual);
    assert_eq!(l2.reason.as_deref(), Some(codes::L2_READ_ONLY));
    assert_eq!(
        l2.change,
        Some(AttachmentChange::SetPortProfile {
            device: "sw-1".to_owned(),
            port: 1,
            profile: "prof-iot".to_owned(),
        })
    );
    assert_eq!(l2.diff.len(), 1);
    assert_eq!(l2.profile_name.as_deref(), Some("IoT"));
    assert_eq!(l2.notes, [codes::NOTE_LINK_FLAP]);
    assert!(!l2.automatic());
    assert!(l2.has_step());
}

#[test]
fn with_writes_off_the_client_vlan_is_shown_as_well() {
    let (mut info, mut state) = wireless_lab();
    info.writes_enabled = false;
    link_ap(&mut state, 5);
    port_mut(&mut state, 5).native_vlan = Some(VID);
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.action, MoveL2Action::Manual);
    assert_eq!(l2.reason.as_deref(), Some(codes::L2_READ_ONLY));
    assert_eq!(
        l2.change,
        Some(AttachmentChange::SetClientVlan {
            mac: mac(1),
            network: "net-iot".to_owned(),
        })
    );
    assert_eq!(l2.diff.len(), 1);
    assert_eq!(l2.diff[0].path, "clients/00:00:5e:00:53:01/network");
}

// Finding the device on the controllers.

#[test]
fn a_device_without_a_mac_address_is_left_to_a_person() {
    let (info, mut state) = wired_lab(1);
    state.wlans.push(wlan(IOT_SSID, VID, true, &["ap-2"]));
    let plans = run(&[item(None)], &[read(&info, state)]);
    let l2 = &plans.items[0];
    assert_eq!(l2.action, MoveL2Action::Manual);
    assert_eq!(l2.reason.as_deref(), Some(codes::L2_NO_MAC));
    assert_eq!(l2.connector, None);
    assert_eq!(l2.attachment, None);
    assert_eq!(l2.ssids, [IOT_SSID]);
    assert_eq!(plans.warnings, Vec::new());
}

#[test]
fn a_device_that_no_controller_sees_is_left_to_a_person() {
    let (info, mut state) = wired_lab(1);
    state.wlans.push(wlan(IOT_SSID, VID, true, &["ap-2"]));
    let plans = run(&[item(Some(mac(9)))], &[read(&info, state)]);
    let l2 = &plans.items[0];
    assert_eq!(l2.action, MoveL2Action::Manual);
    assert_eq!(l2.reason.as_deref(), Some(codes::L2_NOT_SEEN));
    assert_eq!(l2.problem, None);
    assert_eq!(l2.connector, None);
    assert_eq!(l2.ssids, [IOT_SSID]);
    assert_eq!(plans.warnings, Vec::new());
}

#[test]
fn a_device_that_two_controllers_see_is_left_to_a_person() {
    let (first, mut first_state) = wired_lab(1);
    first_state.wlans.push(wlan(IOT_SSID, VID, true, &["ap-2"]));
    let (second, mut second_state) = wired_lab(2);
    second_state
        .wlans
        .push(wlan(IOT_SSID, VID, true, &["ap-3"]));
    second_state
        .wlans
        .push(wlan("guest.example.test", VID, true, &["ap-3"]));
    let plans = run(
        &[item(Some(mac(1)))],
        &[read(&first, first_state), read(&second, second_state)],
    );
    let l2 = &plans.items[0];
    assert_eq!(l2.action, MoveL2Action::Manual);
    assert_eq!(l2.reason.as_deref(), Some(codes::L2_AMBIGUOUS));
    assert_eq!(l2.connector, None);
    assert_eq!(l2.change, None);
    assert_eq!(l2.ssids, ["guest.example.test", IOT_SSID]);
    assert_eq!(plans.warnings, Vec::new());
}

#[test]
fn an_unreadable_controller_leaves_a_device_nobody_else_sees_to_a_person() {
    let broken = info("broken");
    let (other, state) = wired_lab(1);
    let subject = item(Some(mac(9)));
    let plans = run(
        std::slice::from_ref(&subject),
        &[failed(&broken), read(&other, state)],
    );
    let l2 = &plans.items[0];
    assert_eq!(l2.action, MoveL2Action::Manual);
    assert_eq!(l2.reason.as_deref(), Some(codes::L2_UNAVAILABLE));
    assert_eq!(
        l2.problem,
        Some(MoveL2Problem {
            code: "connect.unreachable".to_owned(),
            detail: "the controller does not answer".to_owned(),
        })
    );
    assert_eq!(plans.warnings.len(), 1);
    let warning = &plans.warnings[0];
    assert_eq!(warning.code, codes::CONTROLLER_UNAVAILABLE);
    assert!(warning.requires_ack);
    assert!(!warning.acknowledged);
    assert_eq!(warning.object, Some(ObjectRef::from(broken.id)));
    assert_eq!(
        warning.params,
        BTreeMap::from([
            ("connector".to_owned(), "broken".to_owned()),
            ("error".to_owned(), "connect.unreachable".to_owned()),
            ("id".to_owned(), broken.id.to_string()),
        ])
    );
    assert!(
        warning
            .message
            .contains("connect.unreachable: the controller does not answer"),
        "{}",
        warning.message
    );
}

#[test]
fn an_unreadable_controller_needs_no_acknowledgement_when_the_device_was_found_elsewhere() {
    let broken = info("broken");
    let (other, state) = wired_lab(1);
    let plans = run(
        &[item(Some(mac(1)))],
        &[failed(&broken), read(&other, state)],
    );
    assert_eq!(plans.items[0].action, MoveL2Action::PortProfile);
    assert_eq!(plans.items[0].connector.as_ref(), Some(&other));
    assert_eq!(plans.warnings.len(), 1);
    assert_eq!(plans.warnings[0].code, codes::CONTROLLER_UNAVAILABLE);
    assert!(!plans.warnings[0].requires_ack);
    assert_eq!(plans.warnings[0].object, Some(ObjectRef::from(broken.id)));
}

// Several addresses of one interface.

#[test]
fn the_second_address_of_an_interface_shares_the_l2_step_of_the_first() {
    let (info, state) = wired_lab(1);
    let interface = InterfaceId::generate();
    let first = item_on(interface, Some(mac(1)));
    let second = item_on(interface, Some(mac(1)));
    let plans = run(&[first.clone(), second], &[read(&info, state)]);
    assert_eq!(plans.items.len(), 2);
    assert_eq!(plans.items[0].action, MoveL2Action::PortProfile);
    assert_eq!(
        plans.items[1],
        MoveL2 {
            action: MoveL2Action::Shared,
            reason: Some(codes::L2_SAME_INTERFACE.to_owned()),
            with: Some(AddressId::from(first.object.id)),
            ..MoveL2::default()
        }
    );
    assert!(!plans.items[1].has_step());
}

#[test]
fn addresses_of_different_interfaces_and_of_no_interface_are_decided_alone() {
    let (info, state) = wired_lab(1);
    let items = [
        item_on(InterfaceId::generate(), Some(mac(1))),
        item_on(InterfaceId::generate(), Some(mac(1))),
        item(Some(mac(1))),
        item(Some(mac(1))),
    ];
    let plans = run(&items, &[read(&info, state)]);
    let actions: Vec<MoveL2Action> = plans.items.iter().map(|l2| l2.action).collect();
    assert_eq!(actions, [MoveL2Action::PortProfile; 4]);
}

#[test]
fn a_shared_address_raises_no_warning_of_its_own() {
    let (info, state) = wired_lab(3);
    let interface = InterfaceId::generate();
    let items = [
        item_on(interface, Some(mac(1))),
        item_on(interface, Some(mac(1))),
    ];
    let plans = run(&items, &[read(&info, state)]);
    assert_eq!(
        plans.items[0].reason.as_deref(),
        Some(codes::L2_REFUSED_REASON)
    );
    assert_eq!(plans.items[1].action, MoveL2Action::Shared);
    assert_eq!(plans.warnings.len(), 1);
    assert_eq!(plans.warnings[0].object, Some(items[0].object));
}

// Without controllers.

fn target(vid: Option<u16>) -> MoveTarget {
    MoveTarget {
        prefix: PrefixId::generate(),
        cidr: "198.51.100.0/24".parse().expect("net"),
        vrf: VrfId::generate(),
        vlan: None,
        vid,
        lease_secs: None,
    }
}

#[test]
fn without_a_target_vlan_every_device_is_left_to_a_person() {
    let items = [item(Some(mac(1))), item(None)];
    let plans = offline(&items, &target(None));
    assert_eq!(plans.items.len(), 2);
    for l2 in &plans.items {
        assert_eq!(l2.action, MoveL2Action::Manual);
        assert_eq!(l2.reason.as_deref(), Some(codes::L2_NO_VLAN));
    }
    assert_eq!(plans.warnings, Vec::new());
    assert_eq!(plans.controllers, Vec::new());
}

#[test]
fn without_a_controller_every_device_is_left_to_a_person() {
    let items = [item(Some(mac(1))), item(None)];
    let plans = offline(&items, &target(Some(VID)));
    assert_eq!(plans.items.len(), 2);
    for l2 in &plans.items {
        assert_eq!(l2.action, MoveL2Action::Manual);
        assert_eq!(l2.reason.as_deref(), Some(codes::L2_NO_CONTROLLER));
    }
    assert_eq!(plans.warnings, Vec::new());
    assert_eq!(plans.controllers, Vec::new());
}

#[test]
fn an_offline_plan_shares_the_step_of_an_interface_too() {
    let interface = InterfaceId::generate();
    let items = [item_on(interface, None), item_on(interface, None)];
    let plans = offline(&items, &target(Some(VID)));
    assert_eq!(
        plans.items[0].reason.as_deref(),
        Some(codes::L2_NO_CONTROLLER)
    );
    assert_eq!(plans.items[1].action, MoveL2Action::Shared);
    assert_eq!(
        plans.items[1].with,
        Some(AddressId::from(items[0].object.id))
    );
}

// The manual task, the arguments and the text.

fn with_reason(reason: &str, change: Option<AttachmentChange>) -> MoveL2 {
    MoveL2 {
        action: MoveL2Action::Manual,
        reason: Some(reason.to_owned()),
        change,
        ..MoveL2::default()
    }
}

#[test]
fn each_manual_reason_maps_to_its_task() {
    for (reason, key) in [
        (codes::L2_NO_VLAN, "ipam.move.task.l2"),
        (codes::L2_NO_PROFILE, "ipam.move.task.l2_port_vlan"),
        (codes::L2_SHARED_PORT, "ipam.move.task.l2_shared_port"),
        (codes::L2_JOIN_SSID, "ipam.move.task.l2_ssid"),
        (codes::L2_NO_NETWORK, "ipam.move.task.l2_network"),
        (codes::L2_REFUSED_REASON, "ipam.move.task.l2_refused"),
    ] {
        assert_eq!(instruction(&with_reason(reason, None)), key, "{reason}");
    }
}

#[test]
fn the_read_only_task_follows_the_kind_of_change() {
    let port = AttachmentChange::SetPortProfile {
        device: "sw-1".to_owned(),
        port: 1,
        profile: "prof-iot".to_owned(),
    };
    let client = AttachmentChange::SetClientVlan {
        mac: mac(1),
        network: "net-iot".to_owned(),
    };
    let clear = AttachmentChange::ClearClientVlan { mac: mac(1) };
    assert_eq!(
        instruction(&with_reason(codes::L2_READ_ONLY, Some(port))),
        "ipam.move.task.l2_port"
    );
    assert_eq!(
        instruction(&with_reason(codes::L2_READ_ONLY, Some(client))),
        "ipam.move.task.l2_client"
    );
    assert_eq!(
        instruction(&with_reason(codes::L2_READ_ONLY, Some(clear))),
        "ipam.move.task.l2_client"
    );
    assert_eq!(
        instruction(&with_reason(codes::L2_READ_ONLY, None)),
        "ipam.move.task.l2_client"
    );
}

#[test]
fn the_other_reasons_share_the_generic_move_task() {
    for reason in [
        codes::L2_NO_CONTROLLER,
        codes::L2_UNAVAILABLE,
        codes::L2_AMBIGUOUS,
        codes::L2_NO_MAC,
        codes::L2_NOT_SEEN,
        codes::L2_NO_PORT,
        codes::L2_NO_SSID,
    ] {
        assert_eq!(
            instruction(&with_reason(reason, None)),
            "ipam.move.task.l2_vlan",
            "{reason}"
        );
    }
    assert_eq!(instruction(&MoveL2::default()), "ipam.move.task.l2_vlan");
}

fn pairs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

#[test]
fn the_arguments_of_a_port_change_name_the_device_port_profile_and_diff() {
    let (info, state) = wired_lab(1);
    let (l2, _) = decide_one(&info, state);
    let base = pairs(&[("host", "nas01")]);
    assert_eq!(
        args(&l2, &base),
        pairs(&[
            ("host", "nas01"),
            ("action", "port_profile"),
            ("connector", "lab"),
            ("device", "Switch One"),
            ("port", "1"),
            ("port_name", "Port 1"),
            ("current_profile", "Home"),
            ("current_network", "Home"),
            ("profile", "IoT"),
            ("network", "IoT"),
            ("path", "devices/sw-1/ports/1/profile"),
            ("before", "Home"),
            ("after", "IoT"),
        ])
    );
}

#[test]
fn the_arguments_of_a_shared_port_carry_the_count() {
    let (info, mut state) = wired_lab(1);
    state.clients.push(wired(2, 1));
    let (l2, _) = decide_one(&info, state);
    assert_eq!(
        args(&l2, &BTreeMap::new()),
        pairs(&[
            ("action", "manual"),
            ("reason", codes::L2_SHARED_PORT),
            ("connector", "lab"),
            ("device", "Switch One"),
            ("port", "1"),
            ("port_name", "Port 1"),
            ("current_profile", "Home"),
            ("current_network", "Home"),
            ("network", "IoT"),
            ("count", "1"),
        ])
    );
}

#[test]
fn the_arguments_of_a_refusal_carry_the_rule() {
    let (info, state) = wired_lab(3);
    let l2 = refused(&info, state, "connect.guardrail.uplink");
    let args = args(&l2, &BTreeMap::new());
    assert_eq!(
        args.get("rule").map(String::as_str),
        Some("connect.guardrail.uplink")
    );
    assert_eq!(
        args.get("reason").map(String::as_str),
        Some(codes::L2_REFUSED_REASON)
    );
    assert_eq!(args.get("port").map(String::as_str), Some("3"));
}

#[test]
fn the_arguments_of_a_join_name_the_ssid_to_join_and_list_all() {
    let (info, mut state) = wireless_lab();
    link_ap(&mut state, 5);
    state
        .wlans
        .push(wlan("iot-b.example.test", VID, true, &["ap-2"]));
    state
        .wlans
        .push(wlan("iot-a.example.test", VID, true, &["ap-2"]));
    let (l2, _) = decide_one(&info, state);
    assert_eq!(l2.reason.as_deref(), Some(codes::L2_JOIN_SSID));
    assert_eq!(
        args(&l2, &BTreeMap::new()),
        pairs(&[
            ("action", "manual"),
            ("reason", codes::L2_JOIN_SSID),
            ("connector", "lab"),
            ("device", "Access Point One"),
            // The SSID of the device now is replaced by the one to join.
            ("ssid", "iot-a.example.test"),
            ("ssids", "iot-a.example.test, iot-b.example.test"),
            ("current_network", "Home"),
            ("network", "IoT"),
        ])
    );
}

#[test]
fn the_arguments_of_a_step_without_a_controller_are_the_action_and_the_reason() {
    let plans = offline(&[item(None)], &target(None));
    assert_eq!(
        args(&plans.items[0], &BTreeMap::new()),
        pairs(&[("action", "manual"), ("reason", codes::L2_NO_VLAN)])
    );
}

#[test]
fn the_wire_names_of_the_actions_are_snake_case() {
    for (action, name) in [
        (MoveL2Action::PortProfile, "port_profile"),
        (MoveL2Action::ClientVlan, "client_vlan"),
        (MoveL2Action::Manual, "manual"),
        (MoveL2Action::Unchanged, "unchanged"),
        (MoveL2Action::Shared, "shared"),
    ] {
        assert_eq!(action_name(action), name);
        assert_eq!(
            serde_json::to_value(action).expect("json"),
            serde_json::Value::String(name.to_owned())
        );
    }
}

fn text_of(l2: &MoveL2) -> String {
    text(l2, "nas01", "198.51.100.0/24", Some(VID))
}

#[test]
fn the_text_of_a_port_change_mentions_the_device_the_port_and_the_profile() {
    let (info, state) = wired_lab(1);
    let (l2, _) = decide_one(&info, state);
    assert_eq!(
        text_of(&l2),
        "Give port 1 of Switch One the port profile IoT (VLAN 30 untagged) through lab: dry run, write, read back and compare"
    );
}

#[test]
fn the_text_of_a_client_vlan_names_the_network_and_the_ssid() {
    let (info, mut state) = wireless_lab();
    link_ap(&mut state, 5);
    port_mut(&mut state, 5).native_vlan = Some(VID);
    let (l2, _) = decide_one(&info, state);
    assert_eq!(
        text_of(&l2),
        "Set the VLAN override of nas01 to the network IoT (VLAN 30) through lab, on Access Point One (SSID home.example.test): dry run, write, read back and compare"
    );
}

#[test]
fn the_text_names_the_target_network_when_it_has_no_vlan() {
    let l2 = with_reason(codes::L2_NO_VLAN, None);
    assert_eq!(
        text(&l2, "nas01", "198.51.100.0/24", None),
        "Move nas01 to the network 198.51.100.0/24"
    );
    let unchanged = MoveL2 {
        action: MoveL2Action::Unchanged,
        ..MoveL2::default()
    };
    assert_eq!(
        text(&unchanged, "nas01", "198.51.100.0/24", None),
        "nas01 is in the network 198.51.100.0/24 already"
    );
}

#[test]
fn the_text_of_a_step_that_needs_no_work_says_so() {
    let unchanged = MoveL2 {
        action: MoveL2Action::Unchanged,
        ..MoveL2::default()
    };
    assert_eq!(text_of(&unchanged), "nas01 is in VLAN 30 already");
    let shared = MoveL2 {
        action: MoveL2Action::Shared,
        ..MoveL2::default()
    };
    assert_eq!(
        text_of(&shared),
        "nas01 moves with the other address of its interface"
    );
}

#[test]
fn the_text_of_a_read_only_controller_says_what_a_person_sets() {
    let (mut info, state) = wired_lab(1);
    info.writes_enabled = false;
    let (l2, _) = decide_one(&info, state);
    assert_eq!(
        text_of(&l2),
        "On lab, give port 1 of Switch One the port profile IoT (VLAN 30 untagged); writes through it are off"
    );
    let (mut info, mut state) = wireless_lab();
    info.writes_enabled = false;
    link_ap(&mut state, 5);
    port_mut(&mut state, 5).native_vlan = Some(VID);
    let (l2, _) = decide_one(&info, state);
    assert_eq!(
        text_of(&l2),
        "On lab, set the VLAN override of 00:00:5e:00:53:01 to the network IoT (VLAN 30); writes through it are off"
    );
}

#[test]
fn the_text_of_each_manual_reason_tells_what_a_person_does() {
    let (info, mut state) = wired_lab(1);
    state.clients.push(wired(2, 1));
    let (shared, _) = decide_one(&info, state);
    assert_eq!(
        text_of(&shared),
        "Move nas01 to VLAN 30 by hand: port 1 of Switch One serves 1 other devices, and a profile change would move them all"
    );

    let (info, mut state) = wired_lab(1);
    state
        .profiles
        .retain(|p| p.native_network.as_deref() != Some("net-iot"));
    let (no_profile, _) = decide_one(&info, state);
    assert_eq!(
        text_of(&no_profile),
        "Set port 1 of Switch One to VLAN 30 untagged; no port profile on lab carries it"
    );

    let (info, mut state) = wired_lab(1);
    state.networks.retain(|n| n.vlan != Some(VID));
    let (no_network, _) = decide_one(&info, state);
    assert_eq!(
        text_of(&no_network),
        "Create the network for VLAN 30 on lab (provision the VLAN), then move nas01 to it"
    );

    let (info, state) = wired_lab(3);
    let uplink = refused(&info, state, "connect.guardrail.uplink");
    assert_eq!(
        text_of(&uplink),
        "Move nas01 to VLAN 30 by hand if that is intended: Tenko never changes this path (connect.guardrail.uplink)"
    );

    let generic = with_reason(codes::L2_NOT_SEEN, None);
    assert_eq!(
        text_of(&generic),
        "Move nas01 to VLAN 30: set its switch port to VLAN 30 untagged, or join it to a wireless network that carries VLAN 30"
    );
}

#[test]
fn the_text_of_a_join_names_the_ssid_and_the_access_point() {
    let (info, mut state) = wireless_lab();
    link_ap(&mut state, 5);
    state.wlans.push(wlan(IOT_SSID, VID, true, &["ap-2"]));
    let (l2, _) = decide_one(&info, state);
    assert_eq!(
        text_of(&l2),
        "Join nas01 to the wireless network iot.example.test, which carries VLAN 30; its access point Access Point One does not carry it"
    );
}
