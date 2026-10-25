//! From Home Assistant answers to observed hosts and vendor facts, without any I/O.
//!
//! A [`Snapshot`] holds what a poll read, as Home Assistant answered it (JSON values, so that
//! a changed or unexpected answer degrades a field instead of failing the poll): the device,
//! entity and area registries, the config entries (when the user may read them) and the
//! entity states. [`build`] turns it into hosts:
//!
//! | Host | `external_id` | Addresses | Other facts |
//! |---|---|---|---|
//! | Device of the device registry | `device/<id>` | MAC addresses of its `mac` connections and of its entities' `mac` attributes; IP addresses its entities show as their state or in an `ip`, `ip_address` or `host` attribute | name (the user's name first), platform (the model, else the integration), tags `integration:<domain>` and `area:<area>`, a vendor fact (the manufacturer) per MAC address |
//! | Device tracker entity without a device | `entity/<entity_id>` | its `mac` and `ip` attributes | name (`friendly_name`, else `host_name`), tags `integration:<platform>` and `domain:device_tracker` |
//!
//! Devices and trackers without any MAC or IP address are left out: radio devices (Zigbee,
//! Z-Wave, Bluetooth) behind a bridge, services and helpers have no address of their own.
//! Bluetooth and Zigbee identifiers are not MAC addresses of a network interface and are not
//! reported. The address of a tracker that is `not_home` is stale and is not reported. A
//! globally routable IPv4 address shown by an entity is usually the internet address of a
//! router and is left out unless the settings ask for it. The `via_device` relation of
//! Home Assistant (a device behind a bridge) is not a parent host in Tenko's sense and is not
//! reported.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tenko_connect::VendorFact;
use tenko_core::{MacAddr, observe::ObservedHost};

/// What a poll read, as Home Assistant answered.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    /// `config/device_registry/list`.
    #[serde(default)]
    pub devices: Vec<Value>,
    /// `config/entity_registry/list`.
    #[serde(default)]
    pub entities: Vec<Value>,
    /// `config/area_registry/list`.
    #[serde(default)]
    pub areas: Vec<Value>,
    /// `config_entries/get`; `None` when the user may not read it (a non-administrator).
    #[serde(default)]
    pub entries: Option<Vec<Value>>,
    /// `/api/states`.
    #[serde(default)]
    pub states: Vec<Value>,
}

/// What the inventory reports.
#[derive(Debug, Clone)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the switches of the instance's settings, one each"
)]
pub struct Options {
    /// Read addresses from entity states and attributes.
    pub entity_addresses: bool,
    /// Report globally routable IPv4 addresses that entities show.
    pub public_ipv4: bool,
    /// Report disabled devices.
    pub include_disabled: bool,
    /// Report device trackers that belong to no device.
    pub device_trackers: bool,
    /// Only devices of these integrations; all when empty.
    pub integrations: Vec<String>,
    /// Never devices of these integrations.
    pub exclude_integrations: Vec<String>,
    /// Which IPv4 addresses count as public ([`is_global_v4`]).
    pub public_v4: fn(Ipv4Addr) -> bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            entity_addresses: true,
            public_ipv4: false,
            include_disabled: false,
            device_trackers: true,
            integrations: Vec::new(),
            exclude_integrations: Vec::new(),
            public_v4: is_global_v4,
        }
    }
}

impl Options {
    fn keeps(&self, integration: Option<&str>) -> bool {
        let included = self.integrations.is_empty()
            || integration.is_some_and(|domain| self.integrations.iter().any(|i| i == domain));
        let excluded =
            integration.is_some_and(|domain| self.exclude_integrations.iter().any(|i| i == domain));
        included && !excluded
    }
}

/// The hosts and vendor facts of a snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Built {
    /// The hosts, by `external_id`.
    pub hosts: Vec<ObservedHost>,
    /// The vendor of each MAC address whose device reports a manufacturer.
    pub vendors: Vec<VendorFact>,
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)?
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

fn present(value: &Value, key: &str) -> bool {
    value.get(key).is_some_and(|v| !v.is_null())
}

/// A MAC address in any of the forms Home Assistant shows.
fn mac(text: &str) -> Option<MacAddr> {
    let text = text.trim();
    if !(12..=17).contains(&text.len()) {
        return None;
    }
    text.parse().ok()
}

/// Whether an IPv4 address is globally routable: not private, shared, loopback,
/// link-local, documentation, benchmarking, reserved or broadcast.
pub fn is_global_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || (a == 100 && (64..=127).contains(&b))
        || (a == 198 && (b == 18 || b == 19))
        || (a == 192 && b == 0 && c == 0)
        || a >= 240)
}

/// An address an entity shows, if it belongs in the inventory.
fn usable(text: &str, options: &Options) -> Option<IpAddr> {
    let ip: IpAddr = text.trim().parse().ok()?;
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return None;
    }
    match ip {
        IpAddr::V4(v4) => (!v4.is_link_local()
            && !v4.is_broadcast()
            && (options.public_ipv4 || !(options.public_v4)(v4)))
        .then_some(ip),
        IpAddr::V6(v6) => ((v6.segments()[0] & 0xffc0) != 0xfe80).then_some(ip),
    }
}

/// The addresses an entity state shows: the state itself, and the `ip`, `ip_address`,
/// `host`, `mac` and `mac_address` attributes.
fn state_addresses(state: &Value, options: &Options) -> (Vec<MacAddr>, Vec<IpAddr>) {
    let mut macs = Vec::new();
    let mut ips = Vec::new();
    let tracker = text(state, "entity_id").is_some_and(|id| id.starts_with("device_tracker."));
    let away = tracker && text(state, "state") == Some("not_home");
    if !away {
        ips.extend(text(state, "state").and_then(|value| usable(value, options)));
    }
    if let Some(attributes) = state.get("attributes") {
        for key in ["mac", "mac_address"] {
            macs.extend(text(attributes, key).and_then(mac));
        }
        if !away {
            for key in ["ip", "ip_address", "host"] {
                ips.extend(text(attributes, key).and_then(|value| usable(value, options)));
            }
        }
    }
    (macs, ips)
}

/// The integration of a device: the domain of its primary config entry, else of its first
/// config entry, else the platform of its entities (when the config entries are not
/// readable).
fn integration<'a>(
    device: &'a Value,
    domains: &'a BTreeMap<&'a str, &'a str>,
    entities: &'a [&'a Value],
) -> Option<&'a str> {
    let primary = text(device, "primary_config_entry");
    let first = device
        .get("config_entries")
        .and_then(Value::as_array)
        .and_then(|entries| entries.iter().find_map(Value::as_str));
    if let Some(domain) = primary
        .or(first)
        .and_then(|entry| domains.get(entry).copied())
    {
        return Some(domain);
    }
    let by_entry = primary.and_then(|entry| {
        entities
            .iter()
            .find(|entity| text(entity, "config_entry_id") == Some(entry))
            .and_then(|entity| text(entity, "platform"))
    });
    by_entry.or_else(|| entities.iter().find_map(|entity| text(entity, "platform")))
}

/// The lookups of a snapshot.
struct Index<'a> {
    domains: BTreeMap<&'a str, &'a str>,
    areas: BTreeMap<&'a str, &'a str>,
    states: BTreeMap<&'a str, &'a Value>,
    entities: BTreeMap<&'a str, &'a Value>,
    entities_of: BTreeMap<&'a str, Vec<&'a Value>>,
}

impl<'a> Index<'a> {
    fn of(snapshot: &'a Snapshot) -> Self {
        let mut entities = BTreeMap::new();
        let mut entities_of: BTreeMap<&str, Vec<&Value>> = BTreeMap::new();
        for entity in &snapshot.entities {
            let Some(entity_id) = text(entity, "entity_id") else {
                continue;
            };
            entities.insert(entity_id, entity);
            if let Some(device) = text(entity, "device_id") {
                entities_of.entry(device).or_default().push(entity);
            }
        }
        Self {
            domains: snapshot
                .entries
                .iter()
                .flatten()
                .filter_map(|entry| Some((text(entry, "entry_id")?, text(entry, "domain")?)))
                .collect(),
            areas: snapshot
                .areas
                .iter()
                .filter_map(|area| Some((text(area, "area_id")?, text(area, "name")?)))
                .collect(),
            states: snapshot
                .states
                .iter()
                .filter_map(|state| Some((text(state, "entity_id")?, state)))
                .collect(),
            entities,
            entities_of,
        }
    }
}

/// The host of a device, with the vendor of its MAC addresses; `None` for a device the
/// options leave out or that has no address.
fn device_host(
    device: &Value,
    index: &Index<'_>,
    options: &Options,
) -> Option<(ObservedHost, Option<String>)> {
    let id = text(device, "id")?;
    if text(device, "entry_type") == Some("service") {
        return None;
    }
    let disabled = present(device, "disabled_by");
    if disabled && !options.include_disabled {
        return None;
    }
    let entities = index
        .entities_of
        .get(id)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let domain = integration(device, &index.domains, entities);
    if !options.keeps(domain) {
        return None;
    }
    let mut macs: BTreeSet<MacAddr> = device
        .get("connections")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|pair| {
            let pair = pair.as_array()?;
            (pair.first()?.as_str()? == "mac").then(|| pair.get(1)?.as_str().and_then(mac))?
        })
        .collect();
    let mut ips: BTreeSet<IpAddr> = BTreeSet::new();
    if options.entity_addresses {
        for entity in entities {
            if present(entity, "disabled_by") {
                continue;
            }
            let Some(state) = text(entity, "entity_id").and_then(|id| index.states.get(id)) else {
                continue;
            };
            let (found_macs, found_ips) = state_addresses(state, options);
            macs.extend(found_macs);
            ips.extend(found_ips);
        }
    }
    if macs.is_empty() && ips.is_empty() {
        return None;
    }
    let mut tags = Vec::new();
    if let Some(domain) = domain {
        tags.push(format!("integration:{domain}"));
    }
    if let Some(area) = text(device, "area_id") {
        tags.push(format!(
            "area:{}",
            index.areas.get(area).copied().unwrap_or(area)
        ));
    }
    if disabled {
        tags.push("status:disabled".to_owned());
    }
    let host = ObservedHost {
        external_id: format!("device/{id}"),
        name_placeholder: false,
        name: text(device, "name_by_user")
            .or_else(|| text(device, "name"))
            .map(str::to_owned),
        macs: macs.into_iter().collect(),
        ips: ips.into_iter().collect(),
        os: None,
        platform: text(device, "model")
            .or_else(|| text(device, "model_id"))
            .or(domain)
            .map(str::to_owned),
        parent: None,
        tags,
        power: None,
    };
    Some((host, text(device, "manufacturer").map(str::to_owned)))
}

/// The host of a device tracker that belongs to no device; `None` for a tracker the
/// options leave out or that shows no address.
fn tracker_host(
    entity_id: &str,
    state: &Value,
    index: &Index<'_>,
    options: &Options,
) -> Option<ObservedHost> {
    if !entity_id.starts_with("device_tracker.") {
        return None;
    }
    let entity = index.entities.get(entity_id);
    if entity
        .is_some_and(|entity| text(entity, "device_id").is_some() || present(entity, "disabled_by"))
    {
        return None;
    }
    let platform = entity.and_then(|entity| text(entity, "platform"));
    if !options.keeps(platform) {
        return None;
    }
    let (macs, ips) = state_addresses(state, options);
    let macs: BTreeSet<MacAddr> = macs.into_iter().collect();
    let ips: BTreeSet<IpAddr> = ips.into_iter().collect();
    if macs.is_empty() && ips.is_empty() {
        return None;
    }
    let attributes = state.get("attributes").unwrap_or(&Value::Null);
    let mut tags = Vec::new();
    if let Some(platform) = platform {
        tags.push(format!("integration:{platform}"));
    }
    tags.push("domain:device_tracker".to_owned());
    Some(ObservedHost {
        external_id: format!("entity/{entity_id}"),
        name_placeholder: false,
        name: text(attributes, "friendly_name")
            .or_else(|| text(attributes, "host_name"))
            .or_else(|| text(attributes, "hostname"))
            .map(str::to_owned),
        macs: macs.into_iter().collect(),
        ips: ips.into_iter().collect(),
        os: None,
        platform: None,
        parent: None,
        tags,
        power: None,
    })
}

/// The hosts and vendor facts of a snapshot.
pub fn build(snapshot: &Snapshot, options: &Options) -> Built {
    let index = Index::of(snapshot);
    let mut hosts: BTreeMap<String, ObservedHost> = BTreeMap::new();
    let mut vendors: BTreeMap<MacAddr, String> = BTreeMap::new();
    for device in &snapshot.devices {
        if let Some((host, manufacturer)) = device_host(device, &index, options) {
            if let Some(manufacturer) = manufacturer {
                for mac in &host.macs {
                    vendors.insert(*mac, manufacturer.clone());
                }
            }
            hosts.insert(host.external_id.clone(), host);
        }
    }
    if options.device_trackers {
        for (entity_id, state) in &index.states {
            if let Some(host) = tracker_host(entity_id, state, &index, options) {
                hosts.insert(host.external_id.clone(), host);
            }
        }
    }
    Built {
        hosts: hosts.into_values().collect(),
        vendors: vendors
            .into_iter()
            .map(|(mac, vendor)| VendorFact { mac, vendor })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn snapshot() -> Snapshot {
        serde_json::from_value(json!({
            "devices": [
                {"id": "d1", "name": "Plug 1", "name_by_user": "Desk plug", "manufacturer": "Example Devices", "model": "Plug S", "connections": [["mac", "00:00:5e:00:53:21"]], "config_entries": ["e1"], "primary_config_entry": "e1", "area_id": "office", "entry_type": null, "disabled_by": null},
                {"id": "d2", "name": "Sensor board", "manufacturer": "Example Boards", "model": null, "connections": [["mac", "00-00-5E-00-53-22"], ["bluetooth", "00:00:5e:00:53:99"]], "config_entries": ["e2"], "area_id": "unknown_area"},
                {"id": "d3", "name": "Bulb", "manufacturer": "Example Lighting", "connections": [["zigbee", "00:00:5e:ff:fe:00:53:01"]], "config_entries": ["e3"]},
                {"id": "d4", "name": "Backup", "entry_type": "service", "connections": [["mac", "00:00:5e:00:53:24"]]},
                {"id": "d5", "name": "Old plug", "manufacturer": "Example Devices", "connections": [["mac", "00:00:5e:00:53:25"]], "config_entries": ["e1"], "disabled_by": "user"},
                {"id": "d6", "name": "Router", "manufacturer": "Example Networks", "model": "R1", "connections": [], "config_entries": ["e4"]},
                {"id": "d7", "name": "Speaker", "connections": [], "config_entries": ["e5"], "primary_config_entry": "e5"}
            ],
            "entities": [
                {"entity_id": "sensor.sensor_board_ip", "device_id": "d2", "platform": "esphome", "config_entry_id": "e2", "entity_category": "diagnostic"},
                {"entity_id": "sensor.router_wan_ip", "device_id": "d6", "platform": "examplerouter", "config_entry_id": "e4"},
                {"entity_id": "sensor.router_lan_ip", "device_id": "d6", "platform": "examplerouter", "config_entry_id": "e4"},
                {"entity_id": "sensor.router_old_ip", "device_id": "d6", "platform": "examplerouter", "disabled_by": "integration"},
                {"entity_id": "media_player.speaker", "device_id": "d7", "platform": "examplecast", "config_entry_id": "e5"},
                {"entity_id": "device_tracker.phone", "platform": "exampletracker"},
                {"entity_id": "device_tracker.laptop", "platform": "exampletracker"},
                {"entity_id": "device_tracker.plug", "device_id": "d1", "platform": "exampletracker"}
            ],
            "areas": [{"area_id": "office", "name": "Office"}],
            "entries": [
                {"entry_id": "e1", "domain": "shelly"},
                {"entry_id": "e2", "domain": "esphome"},
                {"entry_id": "e3", "domain": "zha"},
                {"entry_id": "e4", "domain": "examplerouter"}
            ],
            "states": [
                {"entity_id": "sensor.sensor_board_ip", "state": "192.0.2.22", "attributes": {}},
                {"entity_id": "sensor.router_wan_ip", "state": "203.0.113.4", "attributes": {}},
                {"entity_id": "sensor.router_lan_ip", "state": "192.0.2.1", "attributes": {}},
                {"entity_id": "sensor.router_old_ip", "state": "192.0.2.254", "attributes": {}},
                {"entity_id": "media_player.speaker", "state": "playing", "attributes": {"ip_address": "2001:db8::27"}},
                {"entity_id": "device_tracker.phone", "state": "home", "attributes": {"friendly_name": "Phone", "ip": "192.0.2.31", "mac": "00:00:5e:00:53:31", "source_type": "router"}},
                {"entity_id": "device_tracker.laptop", "state": "not_home", "attributes": {"host_name": "laptop", "ip": "192.0.2.32", "mac": "00:00:5E:00:53:32"}},
                {"entity_id": "device_tracker.unregistered", "state": "home", "attributes": {"ip": "192.0.2.33"}},
                {"entity_id": "device_tracker.plug", "state": "home", "attributes": {"ip": "192.0.2.21", "mac": "00:00:5e:00:53:21"}},
                {"entity_id": "sensor.loopback", "state": "127.0.0.1", "attributes": {}}
            ]
        }))
        .expect("snapshot")
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("ip")
    }

    /// The tests stand in TEST-NET-3 for the internet: real public addresses do not belong in
    /// test data.
    fn options() -> Options {
        Options {
            public_v4: |ip| ip.octets()[..3] == [203, 0, 113],
            ..Options::default()
        }
    }

    #[test]
    fn devices_and_trackers_become_hosts_with_vendors() {
        let built = build(&snapshot(), &options());
        let ids: Vec<&str> = built.hosts.iter().map(|h| h.external_id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "device/d1",
                "device/d2",
                "device/d6",
                "device/d7",
                "entity/device_tracker.laptop",
                "entity/device_tracker.phone",
                "entity/device_tracker.unregistered"
            ]
        );
        let plug = &built.hosts[0];
        assert_eq!(plug.name.as_deref(), Some("Desk plug"));
        assert_eq!(plug.platform.as_deref(), Some("Plug S"));
        assert_eq!(plug.tags, ["integration:shelly", "area:Office"]);
        assert_eq!(plug.ips, [ip("192.0.2.21")]);
        assert_eq!(plug.macs.len(), 1);
        let board = &built.hosts[1];
        assert_eq!(
            board
                .macs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["00:00:5e:00:53:22"]
        );
        assert_eq!(board.ips, [ip("192.0.2.22")]);
        assert_eq!(
            board.platform.as_deref(),
            Some("esphome"),
            "no model: the integration"
        );
        assert_eq!(board.tags, ["integration:esphome", "area:unknown_area"]);
        let router = &built.hosts[2];
        assert_eq!(
            router.ips,
            [ip("192.0.2.1")],
            "the public and the disabled entity are left out"
        );
        assert_eq!(router.macs.len(), 0);
        let speaker = &built.hosts[3];
        assert_eq!(speaker.ips, [ip("2001:db8::27")]);
        assert_eq!(
            speaker.tags,
            ["integration:examplecast"],
            "integration from the entities"
        );
        let laptop = &built.hosts[4];
        assert_eq!(laptop.ips, Vec::<IpAddr>::new(), "away: no stale address");
        assert_eq!(laptop.macs.len(), 1);
        assert_eq!(laptop.name.as_deref(), Some("laptop"));
        let phone = &built.hosts[5];
        assert_eq!(phone.name.as_deref(), Some("Phone"));
        assert_eq!(
            phone.tags,
            ["integration:exampletracker", "domain:device_tracker"]
        );
        let unregistered = &built.hosts[6];
        assert_eq!(unregistered.tags, ["domain:device_tracker"]);
        let vendors: Vec<(String, &str)> = built
            .vendors
            .iter()
            .map(|f| (f.mac.to_string(), f.vendor.as_str()))
            .collect();
        assert_eq!(
            vendors,
            [
                ("00:00:5e:00:53:21".to_owned(), "Example Devices"),
                ("00:00:5e:00:53:22".to_owned(), "Example Boards")
            ]
        );
    }

    #[test]
    fn options_change_what_is_reported() {
        let snapshot = snapshot();
        let ids = |options: &Options| -> Vec<String> {
            build(&snapshot, options)
                .hosts
                .into_iter()
                .map(|h| h.external_id)
                .collect()
        };
        assert_eq!(
            ids(&Options {
                integrations: vec!["shelly".to_owned()],
                device_trackers: false,
                ..options()
            }),
            ["device/d1"]
        );
        let disabled = ids(&Options {
            include_disabled: true,
            exclude_integrations: vec!["exampletracker".to_owned()],
            ..options()
        });
        assert!(disabled.contains(&"device/d5".to_owned()));
        assert!(!disabled.iter().any(|id| id.contains("phone")));
        let public = build(
            &snapshot,
            &Options {
                public_ipv4: true,
                ..options()
            },
        );
        assert_eq!(public.hosts[2].ips, [ip("192.0.2.1"), ip("203.0.113.4")]);
        let no_entities = ids(&Options {
            entity_addresses: false,
            device_trackers: false,
            ..options()
        });
        assert_eq!(no_entities, ["device/d1", "device/d2"]);
    }

    #[test]
    fn entries_unreadable_fall_back_to_entity_platforms() {
        let mut snapshot = snapshot();
        snapshot.entries = None;
        let built = build(&snapshot, &options());
        let board = built
            .hosts
            .iter()
            .find(|h| h.external_id == "device/d2")
            .expect("board");
        assert_eq!(board.tags[0], "integration:esphome");
        let plug = built
            .hosts
            .iter()
            .find(|h| h.external_id == "device/d1")
            .expect("plug");
        assert_eq!(
            plug.tags[0], "integration:exampletracker",
            "the only entity's platform"
        );
    }

    #[test]
    fn odd_answers_degrade_instead_of_failing() {
        let snapshot: Snapshot = serde_json::from_value(json!({
            "devices": [
                {"id": 5},
                {"id": "x", "connections": "mac"},
                {"id": "y", "connections": [["mac"], [7, "00:00:5e:00:53:01"], ["mac", 7], ["mac", "zz"]]},
                {"id": "z", "connections": [["mac", "00:00:5e:00:53:41"]], "manufacturer": 7, "area_id": 3}
            ],
            "entities": [{"entity_id": 1}, {"device_id": "z"}],
            "states": [{"entity_id": "device_tracker.x", "state": 5, "attributes": "no"}]
        }))
        .expect("snapshot");
        let built = build(&snapshot, &options());
        assert_eq!(built.hosts.len(), 1);
        assert_eq!(built.hosts[0].external_id, "device/z");
        assert_eq!(built.vendors.len(), 0);
    }

    #[test]
    fn global_ipv4_is_told_apart() {
        for (text, global) in [
            ("10.0.0.1", false),
            ("100.64.0.1", false),
            ("192.0.2.1", false),
            ("198.18.0.1", false),
            ("172.16.0.1", false),
            ("240.0.0.1", false),
        ] {
            assert_eq!(is_global_v4(text.parse().expect("ip")), global, "{text}");
        }
    }
}
