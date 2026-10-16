//! The plugin against the anonymised recordings of a real controller
//! (`tests/fixtures/recorded/`, see the README there), served by the fake controller: the
//! shapes a real Network Application answers with, next to the documented ones of
//! `tests/fixtures/classic/`. The assertions are the counts the live smoke printed on the
//! day of the recording, so the recording stands in for the controller.

mod support;

use std::collections::BTreeMap;

use support::{FakeController, Flavor};
use tenko_connect::{
    Connector as _, ControllerDhcp, DeviceKind, Health, InventorySource as _,
    NetworkController as _,
    convert::{topology_from_proto, topology_to_proto},
};
use tenko_connect_unifi::Unifi;
use tenko_core::observe::LinkKind;

fn count<T>(items: &[T], test: impl Fn(&T) -> bool) -> usize {
    items.iter().filter(|item| test(item)).count()
}

#[tokio::test]
async fn the_recorded_controller_reads_like_the_live_one() {
    let fake = FakeController::start(Flavor::SelfHosted).await;
    fake.load_recorded();
    let snapshot = Unifi.topology(&fake.context()).await.expect("topology");

    // Four switches and two access points; no gateway, the site's router is not UniFi.
    let mut kinds: BTreeMap<DeviceKind, usize> = BTreeMap::new();
    for device in &snapshot.devices {
        *kinds.entry(device.kind).or_default() += 1;
    }
    assert_eq!(
        kinds,
        BTreeMap::from([(DeviceKind::Switch, 4), (DeviceKind::AccessPoint, 2)])
    );
    let ports: Vec<_> = snapshot
        .devices
        .iter()
        .flat_map(|d| d.ports.iter())
        .collect();
    assert_eq!(ports.len(), 122);
    assert_eq!(count(&ports, |p| p.up), 29);
    assert_eq!(count(&ports, |p| p.uplink), 9);
    // A Network Application of this release configures ports inline (`forward`,
    // `native_networkconf_id`, `tagged_vlan_mgmt`); the port table carries no `portconf_id`.
    assert_eq!(count(&ports, |p| p.profile.is_some()), 0);
    assert_eq!(count(&ports, |p| p.native_vlan.is_some()), 4);
    // The fake listens on loopback, so nothing is on the management path.
    assert_eq!(count(&ports, |p| p.management), 0);

    // Six uplinks (one of them to the site's router, which the controller does not manage)
    // and one LLDP neighbour the uplinks do not cover.
    let mut links: BTreeMap<LinkKind, usize> = BTreeMap::new();
    for link in &snapshot.links {
        *links.entry(link.kind).or_default() += 1;
    }
    assert_eq!(
        links,
        BTreeMap::from([(LinkKind::Uplink, 6), (LinkKind::Lldp, 1)])
    );
    assert!(
        snapshot
            .links
            .iter()
            .filter(|l| l.kind == LinkKind::Uplink)
            .all(|l| l.a.port.is_some()),
        "every uplink names the device's own port"
    );

    let clients = &snapshot.clients;
    assert_eq!(clients.len(), 63);
    assert_eq!(count(clients, |c| c.port.is_some()), 18, "wired");
    assert_eq!(count(clients, |c| c.ssid.is_some()), 45, "wireless");
    assert_eq!(count(clients, |c| c.vlan.is_some()), 2);
    assert_eq!(count(clients, |c| c.network.is_some()), 50);
    assert_eq!(count(clients, |c| c.ip.is_some()), 61);
    assert_eq!(count(clients, |c| c.name.is_some()), 46);
    assert_eq!(count(clients, |c| c.vendor.is_some()), 53);
    assert_eq!(count(clients, |c| c.management), 0);

    // Five VLAN-only networks (VLAN ids given as text) and the untagged default network
    // with a /16, on which the controller serves no DHCP: every network is `disabled`.
    let networks = &snapshot.networks;
    assert_eq!(networks.len(), 6);
    assert_eq!(count(networks, |n| n.vlan.is_some()), 5);
    assert_eq!(count(networks, |n| n.subnet.is_some()), 1);
    assert_eq!(count(networks, |n| n.management), 1);
    assert!(networks.iter().all(|n| n.dhcp == ControllerDhcp::Disabled));
    let default = networks
        .iter()
        .find(|n| n.management)
        .expect("the default network");
    assert_eq!(default.vlan, None);
    assert_eq!(
        default.subnet.map(|s| s.prefix_len()),
        Some(16),
        "the recording keeps the width of the network"
    );

    // Two port profiles, both with a native network; one `customize` profile lists what it
    // excludes instead of what it tags, the shape the documentation calls the older one.
    assert_eq!(snapshot.profiles.len(), 2);
    assert_eq!(count(&snapshot.profiles, |p| p.native_network.is_some()), 2);
    assert_eq!(count(&snapshot.profiles, |p| !p.tagged.is_empty()), 1);

    assert_eq!(snapshot.wlans.len(), 1);
    let wlan = &snapshot.wlans[0];
    assert!(wlan.enabled);
    assert!(wlan.network.is_some());
    assert_eq!(
        wlan.vlan, None,
        "the SSID carries a network, not a VLAN of its own"
    );
    assert_eq!(wlan.access_points.len(), 2);

    let back = topology_from_proto(Some(topology_to_proto(&snapshot))).expect("round trip");
    assert_eq!(
        back, snapshot,
        "the host's strict conversion keeps it whole"
    );

    let batch = Unifi.poll(&fake.context(), None).await.expect("poll");
    assert!(batch.complete);
    assert_eq!(batch.hosts.len(), 6 + 63);
    assert!(batch.hosts.iter().all(|h| h.macs.len() == 1));

    let report = Unifi.check(&fake.context()).await.expect("check");
    assert_eq!(
        report.health,
        Health::Degraded,
        "the fake speaks plain HTTP"
    );
    assert_eq!((fake.logins(), fake.logouts()), (3, 3));
    assert_eq!(fake.writes(), Vec::new());
}
