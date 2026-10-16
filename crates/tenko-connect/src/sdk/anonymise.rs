//! An anonymiser for recording the answers of a real system as fixtures.
//!
//! A plugin's fixtures should follow the real shapes of the system it talks to, but nothing
//! of the environment they were recorded in may reach the repository: no host name, address,
//! MAC address, SSID, device, area or person name, no identifier that could be looked up.
//! [`Anonymiser`] walks JSON answers and replaces every such value with a documentation
//! value (RFC 5737, RFC 3849, RFC 7042) or a stable generated placeholder, so that shapes,
//! counts and the relations between records survive: the same input value becomes the same
//! placeholder wherever it appears, an address stays inside the network it was in, and an
//! identifier keeps its format.
//!
//! The policy is deny by default: a string is kept as it is only when its key is one of the
//! enumeration-like keys the connectors read (`type`, `purpose`, `platform`, ...), or when
//! its value is a generic word (`on`, `home`, `loaded`), a number, a timestamp or empty.
//! Members whose keys name credentials (`x_passphrase`, `*token*`, `*password*`) or
//! locations (`geo_info`, `latitude`) are dropped or zeroed. The `attributes` of a Home
//! Assistant state are reduced to the ones a connector reads. The property strings of a
//! Proxmox VE guest configuration (`net0`, `ipconfig0`, `agent`:
//! `virtio=<mac>,bridge=vmbr0,tag=20`) are split and each value is anonymised on its own,
//! so the MAC address, bridge and VLAN stay readable; tag lists (`a;b`) keep their length.
//! The all-zero and the broadcast MAC address name nothing and are kept. A bare prefix
//! length next to an address (`netmask`, `netmask6`, `prefix`, as a number, as text or
//! as a dotted mask) is written as the width of the anonymised network that address is in:
//! the width of a wide network as its CIDR is written, else 24.
//!
//! The anonymiser keeps its maps between calls, so several answers of one system can be
//! anonymised one after the other and still agree with each other.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use serde_json::{Map, Value};

/// The documentation networks that private IPv4 blocks are mapped into first.
const DOCUMENTATION_V4: [[u8; 3]; 3] = [[192, 0, 2], [198, 51, 100], [203, 0, 113]];

/// Keys whose members are dropped (lower case, matched as substrings).
const DROP_SUBSTRINGS: [&str; 20] = [
    "password",
    "passphrase",
    "secret",
    "token",
    "psk",
    "private_key",
    "authkey",
    "credential",
    "geo_info",
    "speedtest",
    "context",
    "ssh_",
    "api_key",
    "picture",
    "wireguard",
    "preshared",
    "_key",
    "keys",
    "identity",
    "syslog",
];

/// Keys whose members are dropped (lower case, matched whole): bulky statistics no connector
/// reads, and locations.
const DROP_KEYS: [&str; 10] = [
    "stat",
    "sys_stats",
    "system-stats",
    "ssh_session_table",
    "radio_table_stats",
    "scan_radio_table",
    "location",
    "ipv4_active_leases",
    "x_fingerprint_override",
    "temperatures",
];

/// Keys whose numbers become zero.
const ZERO_KEYS: [&str; 9] = [
    "lat",
    "lng",
    "latitude",
    "longitude",
    "elevation",
    "altitude",
    "gps_accuracy",
    "country_code",
    "countrycode",
];

/// Keys whose string values are kept: enumerations and version texts.
const KEEP_KEYS: [&str; 70] = [
    "type",
    "purpose",
    "networkgroup",
    "wan_networkgroup",
    "forward",
    "op_mode",
    "poe_mode",
    "media",
    "radio",
    "radio_proto",
    "radio_name",
    "security",
    "wpa_mode",
    "wpa_enc",
    "wlan_band",
    "wlan_bands",
    "attr_hidden_id",
    "source",
    "domain",
    "platform",
    "entry_type",
    "disabled_by",
    "hidden_by",
    "entity_category",
    "device_class",
    "original_device_class",
    "state_class",
    "unit_of_measurement",
    "source_type",
    "icon",
    "original_icon",
    "wan_type",
    "version",
    "displayable_version",
    "kernel_version",
    "architecture",
    "sw_version",
    "hw_version",
    "ha_version",
    "message",
    "rc",
    "msg",
    "ifname",
    "port_id",
    "local_port_name",
    "usage",
    "mode",
    "role",
    "setting_preference",
    "ipv6_interface_type",
    "ipv6_setting_preference",
    "ipv6_client_address_assignment",
    "translation_key",
    "fingerprint_source",
    "dhcpd_leasetime",
    "wan_load_balance_type",
    "board_rev",
    "connection_type",
    "ip_type",
    "dhcp_relay_mode",
    "dhcpguard_mode",
    "lte_mode",
    "ostype",
    "arch",
    "status",
    "method",
    "method6",
    "release",
    "ip-address-type",
    "plugintype",
];

/// Keys whose string values are names of things in the owner's environment.
const NAME_KEYS: [&str; 20] = [
    "name",
    "hostname",
    "name_by_user",
    "original_name",
    "friendly_name",
    "host_name",
    "essid",
    "ssid",
    "desc",
    "alias",
    "title",
    "note",
    "chassis_descr",
    "domain_name",
    "last_uplink_name",
    "last_connection_network_name",
    "network",
    "location_name",
    "dev_id_override_name",
    "display_name",
];

/// Keys whose string values are identifiers of records, serial numbers or hashes: they become
/// `id-N` when they are not in one of the formats mapped everywhere.
const ID_KEYS: [&str; 14] = [
    "id",
    "_id",
    "unique_id",
    "serial",
    "serial_number",
    "anon_id",
    "anon_client_id",
    "hash_id",
    "sysid",
    "guid",
    "cfgversion",
    "known_cfgversion",
    "short_id",
    "identifier",
];

/// Keys whose string values are vendor names.
const VENDOR_KEYS: [&str; 3] = ["oui", "manufacturer", "dev_vendor_name"];

/// Keys whose string values are model names.
const MODEL_KEYS: [&str; 4] = ["model", "model_id", "model_display", "dev_family_name"];

/// Keys whose string values are entity ids of Home Assistant (`domain.object_id`); the
/// domain is kept.
const ENTITY_KEYS: [&str; 4] = [
    "entity_id",
    "temperature_entity_id",
    "humidity_entity_id",
    "object_id",
];

/// Generic words that are kept wherever they appear as a whole value.
const WORDS: [&str; 89] = [
    "home",
    "not_home",
    "on",
    "off",
    "unavailable",
    "unknown",
    "playing",
    "paused",
    "idle",
    "standby",
    "buffering",
    "open",
    "closed",
    "opening",
    "closing",
    "locked",
    "unlocked",
    "loaded",
    "not_loaded",
    "setup_error",
    "setup_retry",
    "setup_in_progress",
    "migration_error",
    "failed_unload",
    "cleaning",
    "docked",
    "returning",
    "error",
    "heat",
    "cool",
    "auto",
    "dry",
    "fan_only",
    "heat_cool",
    "charging",
    "discharging",
    "not_charging",
    "connected",
    "disconnected",
    "active",
    "inactive",
    "ok",
    "up",
    "down",
    "armed_home",
    "armed_away",
    "armed_night",
    "disarmed",
    "pending",
    "triggered",
    "arming",
    "clear",
    "detected",
    "above_horizon",
    "below_horizon",
    "sunny",
    "cloudy",
    "partlycloudy",
    "rainy",
    "snowy",
    "fog",
    "windy",
    "pouring",
    "clear-night",
    "user",
    "guest",
    "system",
    "integration",
    "config_entry",
    "device",
    "none",
    "true",
    "false",
    "run",
    "wire",
    "wireless",
    "dhcp",
    "manual",
    "static",
    "veth",
    "online",
    "offline",
    "running",
    "stopped",
    "ipv4",
    "ipv6",
    "inet",
    "inet6",
    "bridge",
];

/// The attributes of a Home Assistant state that survive, besides what the rules keep.
const STATE_ATTRIBUTES: [&str; 17] = [
    "friendly_name",
    "host_name",
    "hostname",
    "ip",
    "ip_address",
    "host",
    "mac",
    "mac_address",
    "source_type",
    "device_class",
    "state_class",
    "unit_of_measurement",
    "icon",
    "supported_features",
    "entity_category",
    "restored",
    "assumed_state",
];

/// Replaces names, addresses and identifiers in JSON with placeholders, consistently.
#[derive(Debug, Default)]
pub struct Anonymiser {
    /// Private and public IPv4 /24 blocks to their placeholder blocks.
    v4_blocks: HashMap<[u8; 3], [u8; 3]>,
    /// The number of /24 blocks handed out in the benchmarking range.
    v4_next: u32,
    /// The prefix lengths of wide networks that were narrowed to the blocks seen in them,
    /// by their first /24 block and their length.
    v4_lengths: HashMap<(u32, u8), u8>,
    /// Every network wider than a /24 that got a run of blocks: its first block, its length
    /// and the length it is written with.
    v4_wide: Vec<(u32, u8, u8)>,
    /// Public IPv4 addresses to their host number in TEST-NET-3.
    v4_public: HashMap<Ipv4Addr, u8>,
    /// Addresses that found no free placeholder (the ranges ran out).
    v4_exhausted: u64,
    /// The number of documentation networks handed out.
    v4_documentation: usize,
    /// IPv6 /48 prefixes to their placeholder.
    v6_prefixes: HashMap<[u16; 3], u16>,
    /// IPv6 interface identifiers that were replaced.
    v6_ifids: HashMap<[u16; 4], u16>,
    /// MAC addresses (6 or 8 bytes) to their placeholder.
    macs: HashMap<Vec<u8>, Vec<u8>>,
    /// Identifier texts to their placeholder of the same format.
    tokens: HashMap<String, String>,
    /// Free text to its placeholder.
    texts: HashMap<String, String>,
    /// The counters of each placeholder family.
    counters: BTreeMap<&'static str, u64>,
}

/// A MAC address in the notation it was found in.
struct MacText {
    original: String,
    bytes: Vec<u8>,
    separator: Option<char>,
    upper: bool,
}

impl Anonymiser {
    /// An anonymiser with empty maps.
    pub fn new() -> Self {
        Self::default()
    }

    /// The anonymised copy of `value`. Keys are matched in lower case.
    pub fn anonymise(&mut self, value: &Value) -> Value {
        self.reserve(value);
        self.walk(value, "")
    }

    /// The number of distinct values replaced in each family, for a report.
    pub fn counts(&self) -> BTreeMap<&'static str, u64> {
        let mut counts = self.counters.clone();
        counts.insert("ipv4 blocks", self.v4_blocks.len() as u64);
        counts.insert("ipv4 narrowed networks", self.v4_lengths.len() as u64);
        counts.insert("ipv4 exhausted", self.v4_exhausted);
        counts.insert("ipv6 prefixes", self.v6_prefixes.len() as u64);
        counts.insert("macs", self.macs.len() as u64);
        counts
    }

    fn next(&mut self, family: &'static str) -> u64 {
        let counter = self.counters.entry(family).or_default();
        *counter += 1;
        *counter
    }

    /// Plans the IPv4 placeholders of a value before it is walked: every private network
    /// wider than a /24 gets an aligned run of blocks of its own size in the benchmarking
    /// range, so that its addresses stay inside it. When the ranges cannot hold every wide
    /// network next to the other blocks seen, each wide network is narrowed to the blocks
    /// seen in it (a power of two), and its prefix length is written narrower too.
    fn reserve(&mut self, value: &Value) {
        let mut wide: Vec<(u32, u8)> = Vec::new();
        let mut seen: BTreeSet<u32> = BTreeSet::new();
        collect_v4(value, &mut wide, &mut seen);
        wide.sort_by_key(|(first, len)| (*len, *first));
        wide.dedup();
        let mut kept: Vec<(u32, u8)> = Vec::new();
        for (first, len) in wide {
            let size = 1u32 << (24 - len);
            let inside = kept
                .iter()
                .any(|(f, l)| first >= *f && first + size <= *f + (1u32 << (24 - *l)));
            let reserved = self.v4_blocks.contains_key(&index_block(first));
            if !inside && !reserved {
                kept.push((first, len));
            }
        }
        let within = |block: u32| {
            kept.iter()
                .any(|(f, l)| block >= *f && block < *f + (1u32 << (24 - *l)))
        };
        let outside = seen
            .iter()
            .filter(|b| !within(**b) && !self.v4_blocks.contains_key(&index_block(**b)))
            .count();
        let documentation = 2usize.saturating_sub(self.v4_documentation);
        let needed: u32 = kept.iter().map(|(_, len)| 1u32 << (24 - len)).sum::<u32>()
            + u32::try_from(outside.saturating_sub(documentation)).unwrap_or(u32::MAX);
        let narrow = needed > BENCH_BLOCKS.saturating_sub(self.v4_next);
        for (first, len) in kept {
            let size = 1u32 << (24 - len);
            let blocks: Vec<u32> = if narrow {
                seen.range(first..first + size).copied().collect()
            } else {
                (first..first + size).collect()
            };
            let run = if narrow {
                u32::try_from(blocks.len().max(1))
                    .unwrap_or(u32::MAX)
                    .next_power_of_two()
            } else {
                size
            };
            let written = 24 - u8::try_from(run.trailing_zeros()).unwrap_or(0);
            if narrow {
                self.v4_lengths.insert((first, len), written);
            }
            self.v4_wide.push((first, len, written));
            let aligned = (self.v4_next + run - 1) & !(run - 1);
            for (i, block) in blocks.into_iter().enumerate() {
                let n = aligned + u32::try_from(i).unwrap_or(u32::MAX);
                let placeholder = self.bench(n);
                self.v4_blocks.insert(index_block(block), placeholder);
            }
            self.v4_next = aligned + run;
        }
    }

    /// The `n`th block of the benchmarking range, counting an address that finds none.
    fn bench(&mut self, n: u32) -> [u8; 3] {
        if n >= BENCH_BLOCKS {
            self.v4_exhausted += 1;
        }
        bench_block(n)
    }

    /// The prefix length a CIDR is written with: narrower for a narrowed wide network.
    fn v4_length(&self, ip: Ipv4Addr, len: u8) -> u8 {
        if len >= 24 {
            return len;
        }
        let first = (u32::from(ip) >> 8) & !((1u32 << (24 - len)) - 1);
        self.v4_lengths.get(&(first, len)).copied().unwrap_or(len)
    }

    fn walk(&mut self, value: &Value, key: &str) -> Value {
        match value {
            Value::Object(map) => Value::Object(self.object(map, key)),
            Value::Array(items) => Value::Array(match key {
                "connections" | "identifiers" => items
                    .iter()
                    .map(|item| match item {
                        Value::Array(pair) if pair.len() == 2 && pair[0].is_string() => {
                            Value::Array(vec![pair[0].clone(), self.walk(&pair[1], "identifier")])
                        }
                        other => self.walk(other, key),
                    })
                    .collect(),
                _ => items.iter().map(|item| self.walk(item, key)).collect(),
            }),
            Value::String(text) => Value::String(self.string(text, key)),
            Value::Number(_) if ZERO_KEYS.contains(&key) => Value::from(0),
            other => other.clone(),
        }
    }

    fn object(&mut self, map: &Map<String, Value>, parent: &str) -> Map<String, Value> {
        let mut out = Map::new();
        for (key, value) in map {
            let lower = key.to_ascii_lowercase();
            if dropped(&lower) {
                continue;
            }
            if parent == "attributes" && !STATE_ATTRIBUTES.contains(&lower.as_str()) {
                continue;
            }
            out.insert(key.clone(), self.walk(value, &lower));
        }
        self.bare_widths(map, &mut out);
        out
    }

    /// Writes the bare prefix lengths of an object (`netmask`, `netmask6`, `prefix`) as
    /// the width of the anonymised network of the address next to them.
    fn bare_widths(&self, map: &Map<String, Value>, out: &mut Map<String, Value>) {
        for (key, value) in map {
            let lower = key.to_ascii_lowercase();
            let siblings: &[&str] = match lower.as_str() {
                "netmask" | "mask" | "prefix" | "prefixlen" | "prefix_length" => &[
                    "address",
                    "ip",
                    "ip-address",
                    "ip_address",
                    "ipaddr",
                    "cidr",
                ],
                "netmask6" | "prefix6" | "prefixlen6" => &["address6", "ip6", "cidr6"],
                _ => continue,
            };
            let address = siblings.iter().find_map(|name| {
                map.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                    .and_then(|(_, v)| v.as_str())
                    .and_then(|text| cidr(text.trim()))
                    .map(|(ip, _)| ip)
            });
            let (len, form) = match value {
                Value::Number(number) => match number.as_u64().and_then(|n| u8::try_from(n).ok()) {
                    Some(len) => (len, Form::Number),
                    None => continue,
                },
                Value::String(text) => match text.trim().parse::<u8>() {
                    Ok(len) => (len, Form::Text),
                    Err(_) => match text.trim().parse::<Ipv4Addr>().ok().and_then(mask_length) {
                        Some(len) => (len, Form::Mask),
                        None => continue,
                    },
                },
                _ => continue,
            };
            let width = match address {
                Some(IpAddr::V4(ip)) if len <= 32 => self.bare_v4_width(ip, len),
                // IPv6 networks keep their widths, as their CIDR texts do.
                Some(IpAddr::V6(_)) => len,
                _ if len <= 32 => 24,
                _ => continue,
            };
            let written = match form {
                Form::Number => Value::from(width),
                Form::Text => Value::String(width.to_string()),
                Form::Mask => Value::String(length_mask(width).to_string()),
            };
            out.insert(key.clone(), written);
        }
    }

    /// The width a bare prefix length of an IPv4 address is written with: the written width
    /// of the wide network the address is in (the narrowest one), else 24. Loopback and the
    /// other addresses that are not replaced keep their width.
    fn bare_v4_width(&self, ip: Ipv4Addr, len: u8) -> u8 {
        if !is_mapped_v4(ip) {
            return len;
        }
        let block = u32::from(ip) >> 8;
        self.v4_wide
            .iter()
            .filter(|(first, wide, _)| block >= *first && block < *first + (1u32 << (24 - *wide)))
            .max_by_key(|(_, wide, _)| *wide)
            .map_or(24, |(_, _, written)| *written)
    }

    /// The placeholder of one string value under `key` (lower case).
    fn string(&mut self, text: &str, key: &str) -> String {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return text.to_owned();
        }
        if let Some(mac) = mac_text(trimmed) {
            return self.mac(&mac);
        }
        if let Some((ip, len)) = cidr(trimmed) {
            let mapped = self.ip(ip);
            return match (ip, len) {
                (IpAddr::V4(v4), Some(len)) => format!("{mapped}/{}", self.v4_length(v4, len)),
                (_, Some(len)) => format!("{mapped}/{len}"),
                (_, None) => mapped.to_string(),
            };
        }
        if (is_property_key(key) && trimmed.contains('=')) || key == "agent" {
            return self.properties(trimmed);
        }
        if key == "tags" && trimmed.contains([';', ',', ' ']) {
            return trimmed
                .split(';')
                .map(|tag| self.string(tag, "tag"))
                .collect::<Vec<_>>()
                .join(";");
        }
        if ENTITY_KEYS.contains(&key) || key.ends_with("_entity_id") {
            return self.entity(trimmed);
        }
        if let Some(placeholder) = self.token(trimmed) {
            return placeholder;
        }
        // Names, vendors, models and identifiers are never kept, whatever they look like.
        if NAME_KEYS.contains(&key) {
            return self.text(trimmed, "name", "name-");
        }
        if VENDOR_KEYS.contains(&key) {
            return self.text(trimmed, "vendor", "Vendor ");
        }
        if MODEL_KEYS.contains(&key) {
            return self.text(trimmed, "model", "Model ");
        }
        if KEEP_KEYS.contains(&key) {
            return text.to_owned();
        }
        if ID_KEYS.contains(&key) || key.ends_with("_id") || key.ends_with("_ids") {
            return self.text(trimmed, "id", "id-");
        }
        if is_number(trimmed) || is_timestamp(trimmed) {
            return text.to_owned();
        }
        if WORDS.contains(&trimmed.to_ascii_lowercase().as_str()) {
            return text.to_owned();
        }
        self.text(trimmed, "text", "text-")
    }

    /// A Proxmox property string, each value anonymised under its own key: the MAC address
    /// of `virtio=<mac>`, the bridge, the VLAN tag and the addresses of `ip=` stay
    /// readable. A key that is not a short lower-case word is not kept either.
    fn properties(&mut self, text: &str) -> String {
        text.split(',')
            .map(|part| match part.split_once('=') {
                Some((name, value)) if is_property_name(name.trim()) => {
                    let name = name.trim();
                    format!("{name}={}", self.string(value, &name.to_ascii_lowercase()))
                }
                Some(_) => self.text(part.trim(), "text", "text-"),
                // A part without a key (`1` of `agent`) is read as a plain value.
                None => self.string(part, "value"),
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    fn text(&mut self, value: &str, family: &'static str, prefix: &str) -> String {
        if let Some(placeholder) = self.texts.get(value) {
            return placeholder.clone();
        }
        let n = self.next(family);
        let placeholder = format!("{prefix}{n}");
        self.texts.insert(value.to_owned(), placeholder.clone());
        placeholder
    }

    /// An entity id keeps its domain: `sensor.kitchen_plug_power` becomes `sensor.entity_7`.
    fn entity(&mut self, value: &str) -> String {
        let Some((domain, object)) = value.split_once('.') else {
            return self.text(value, "text", "text-");
        };
        if object.is_empty() || !domain.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
            return self.text(value, "text", "text-");
        }
        if let Some(placeholder) = self.texts.get(value) {
            return placeholder.clone();
        }
        let n = self.next("entity");
        let placeholder = format!("{domain}.entity_{n}");
        self.texts.insert(value.to_owned(), placeholder.clone());
        placeholder
    }

    /// The placeholder of an identifier, in its format: a hexadecimal id of the same length,
    /// a ULID, or a UUID.
    fn token(&mut self, value: &str) -> Option<String> {
        let format = id_format(value)?;
        if let Some(placeholder) = self.tokens.get(value) {
            return Some(placeholder.clone());
        }
        let n = self.next("ids");
        let placeholder = match format {
            IdFormat::Hex(len) => {
                let digits = format!("{n:x}");
                format!("{}{digits}", "0".repeat(len.saturating_sub(digits.len())))
            }
            IdFormat::Ulid => format!("{n:0>26}"),
            IdFormat::Uuid => format!("00000000-0000-0000-0000-{n:012x}"),
        };
        self.tokens.insert(value.to_owned(), placeholder.clone());
        Some(placeholder)
    }

    fn mac(&mut self, mac: &MacText) -> String {
        if mac.bytes.iter().all(|b| *b == 0) || mac.bytes.iter().all(|b| *b == 0xff) {
            return mac.original.clone();
        }
        let bytes = if let Some(bytes) = self.macs.get(&mac.bytes) {
            bytes.clone()
        } else {
            let n = self.next("mac bytes");
            let bytes = if mac.bytes.len() == 8 {
                // An EUI-64 (Zigbee, Thread): the documentation OUI with the EUI-64 marker.
                vec![0x00, 0x00, 0x5e, 0xff, 0xfe, 0x00, byte(n, 8), byte(n, 0)]
            } else if n <= 256 {
                vec![0x00, 0x00, 0x5e, 0x00, 0x53, byte(n - 1, 0)]
            } else {
                // Beyond the 256 documentation addresses: locally administered, never a
                // vendor's.
                let n = n - 257;
                vec![0x02, 0x00, 0x5e, byte(n, 16), byte(n, 8), byte(n, 0)]
            };
            self.macs.insert(mac.bytes.clone(), bytes.clone());
            bytes
        };
        let text: Vec<String> = bytes
            .iter()
            .map(|b| {
                if mac.upper {
                    format!("{b:02X}")
                } else {
                    format!("{b:02x}")
                }
            })
            .collect();
        match mac.separator {
            Some(sep) => text.join(&sep.to_string()),
            None => text.concat(),
        }
    }

    fn ip(&mut self, ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(v4) => IpAddr::V4(self.v4(v4)),
            IpAddr::V6(v6) => IpAddr::V6(self.v6(v6)),
        }
    }

    fn v4(&mut self, ip: Ipv4Addr) -> Ipv4Addr {
        if !is_mapped_v4(ip) {
            return ip;
        }
        let [_, _, _, host] = ip.octets();
        if is_global_v4(ip) {
            // Every public address lands in TEST-NET-3, each on a host number of its own.
            let next = self.v4_public.len() + 1;
            let number = *self
                .v4_public
                .entry(ip)
                .or_insert_with(|| u8::try_from(next).unwrap_or(u8::MAX));
            if next > 254 {
                self.v4_exhausted += 1;
            }
            let [a, b, c] = DOCUMENTATION_V4[2];
            return Ipv4Addr::new(a, b, c, number);
        }
        let block = block_of(ip);
        let mapped = if let Some(mapped) = self.v4_blocks.get(&block) {
            *mapped
        } else {
            let mapped = if self.v4_documentation < 2 {
                self.v4_documentation += 1;
                DOCUMENTATION_V4[self.v4_documentation - 1]
            } else {
                let n = self.v4_next;
                self.v4_next += 1;
                self.bench(n)
            };
            self.v4_blocks.insert(block, mapped);
            mapped
        };
        Ipv4Addr::new(mapped[0], mapped[1], mapped[2], host)
    }

    fn v6(&mut self, ip: Ipv6Addr) -> Ipv6Addr {
        if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
            return ip;
        }
        let s = ip.segments();
        let ifid = [s[4], s[5], s[6], s[7]];
        let ifid = if s[4] == 0 && s[5] == 0 && s[6] == 0 {
            ifid
        } else if let Some(n) = self.v6_ifids.get(&ifid) {
            [0, 0, 0, *n]
        } else {
            let n = u16::try_from(self.next("ipv6 interface ids") + 0x1000).unwrap_or(u16::MAX);
            self.v6_ifids.insert(ifid, n);
            [0, 0, 0, n]
        };
        let link_local = (s[0] & 0xffc0) == 0xfe80;
        let prefix = if link_local {
            [0xfe80, 0, 0]
        } else {
            let real = [s[0], s[1], s[2]];
            let n = if let Some(n) = self.v6_prefixes.get(&real) {
                *n
            } else {
                let n = u16::try_from(self.v6_prefixes.len()).unwrap_or(u16::MAX);
                self.v6_prefixes.insert(real, n);
                n
            };
            [0x2001, 0xdb8, n]
        };
        Ipv6Addr::new(
            prefix[0],
            prefix[1],
            prefix[2],
            if link_local { 0 } else { s[3] },
            ifid[0],
            ifid[1],
            ifid[2],
            ifid[3],
        )
    }
}

/// Whether the value of a key is a Proxmox property string: `netN` and `ipconfigN` of a
/// guest configuration (`agent` is handled by name).
fn is_property_key(key: &str) -> bool {
    ["net", "ipconfig"].iter().any(|prefix| {
        key.strip_prefix(prefix)
            .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
    })
}

/// Whether the key of a property is a vocabulary word (`bridge`, `ip6`, `hwaddr`).
fn is_property_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Whether a member is dropped by its key.
fn dropped(key: &str) -> bool {
    key.starts_with("x_")
        || DROP_KEYS.contains(&key)
        || DROP_SUBSTRINGS.iter().any(|part| key.contains(part))
}

/// How a bare prefix length was written.
#[derive(Debug, Clone, Copy)]
enum Form {
    /// A number (`24`).
    Number,
    /// Text of a number (`"24"`).
    Text,
    /// A dotted mask (`"255.255.255.0"`).
    Mask,
}

/// The length of a contiguous dotted IPv4 mask.
fn mask_length(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let len = bits.leading_ones();
    (bits.checked_shl(len).unwrap_or(0) == 0).then(|| u8::try_from(len).unwrap_or(32))
}

/// The dotted IPv4 mask of a length.
fn length_mask(len: u8) -> Ipv4Addr {
    Ipv4Addr::from(
        u32::MAX
            .checked_shl(32 - u32::from(len.min(32)))
            .unwrap_or(0),
    )
}

/// The number of /24 blocks of the benchmarking range 198.18.0.0/15.
const BENCH_BLOCKS: u32 = 512;

/// The /24 block of a block index (the address shifted right by eight bits).
fn index_block(index: u32) -> [u8; 3] {
    block_of(Ipv4Addr::from(index << 8))
}

/// The private IPv4 blocks a value names, and its networks wider than a /24 (by first block
/// index and length), also inside property strings and free text.
fn collect_v4(value: &Value, wide: &mut Vec<(u32, u8)>, seen: &mut BTreeSet<u32>) {
    match value {
        Value::String(text) => {
            for token in text.split(|c: char| !(c.is_ascii_digit() || c == '.' || c == '/')) {
                let Some((IpAddr::V4(ip), len)) = cidr(token) else {
                    continue;
                };
                if !is_mapped_v4(ip) || is_global_v4(ip) {
                    continue;
                }
                seen.insert(u32::from(ip) >> 8);
                if let Some(len) = len.filter(|len| *len < 24) {
                    let first = (u32::from(ip) >> 8) & !((1u32 << (24 - len)) - 1);
                    wide.push((first, len));
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_v4(item, wide, seen)),
        Value::Object(map) => map.values().for_each(|item| collect_v4(item, wide, seen)),
        _ => {}
    }
}

/// The /24 block of an address.
fn block_of(ip: Ipv4Addr) -> [u8; 3] {
    let [a, b, c, _] = ip.octets();
    [a, b, c]
}

/// The `n`th /24 block of the benchmarking range 198.18.0.0/15 (RFC 2544).
fn bench_block(n: u32) -> [u8; 3] {
    [
        198,
        18 + byte(u64::from(n >> 8), 0) % 2,
        byte(u64::from(n), 0),
    ]
}

/// The byte of `value` at `shift` bits from the right.
fn byte(value: u64, shift: u32) -> u8 {
    u8::try_from((value >> shift) & 0xff).unwrap_or(0)
}

/// Whether an IPv4 address is replaced at all: loopback, unspecified, broadcast, multicast
/// and link-local addresses name nothing.
fn is_mapped_v4(ip: Ipv4Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_link_local())
}

/// Whether an IPv4 address is globally routable (not private, shared, documentation,
/// benchmarking or reserved).
fn is_global_v4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    !(ip.is_private()
        || ip.is_documentation()
        || (a == 100 && (64..=127).contains(&b))
        || (a == 198 && (b == 18 || b == 19))
        || (a == 192 && b == 0 && ip.octets()[2] == 0)
        || a >= 240)
}

/// A text as an address, with its prefix length when it is a CIDR.
fn cidr(text: &str) -> Option<(IpAddr, Option<u8>)> {
    let (address, len) = match text.split_once('/') {
        Some((address, len)) => (address, Some(len.parse::<u8>().ok()?)),
        None => (text, None),
    };
    let address = address.split_once('%').map_or(address, |(a, _)| a);
    let ip: IpAddr = address.parse().ok()?;
    if let Some(len) = len {
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if len > max {
            return None;
        }
    }
    Some((ip, len))
}

/// A text as a MAC address or EUI-64: six or eight hexadecimal bytes with `:` or `-`, or
/// twelve or sixteen hexadecimal digits.
fn mac_text(text: &str) -> Option<MacText> {
    let separator = text.chars().find(|c| matches!(c, ':' | '-'));
    let parts: Vec<&str> = match separator {
        Some(sep) => text.split(sep).collect(),
        None => return mac_digits(text),
    };
    if !(parts.len() == 6 || parts.len() == 8) {
        return None;
    }
    let mut bytes = Vec::with_capacity(parts.len());
    for part in &parts {
        if part.len() != 2 || !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        bytes.push(u8::from_str_radix(part, 16).ok()?);
    }
    Some(MacText {
        original: text.to_owned(),
        bytes,
        separator,
        upper: text.chars().any(|c| c.is_ascii_uppercase()),
    })
}

fn mac_digits(text: &str) -> Option<MacText> {
    if !(text.len() == 12 || text.len() == 16) || !text.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    // Twelve decimal digits are a number (a timestamp in milliseconds), not an address.
    if text.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let bytes = (0..text.len() / 2)
        .filter_map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok())
        .collect();
    Some(MacText {
        original: text.to_owned(),
        bytes,
        separator: None,
        upper: text.chars().any(|c| c.is_ascii_uppercase()),
    })
}

/// The identifier formats that are mapped wherever they appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdFormat {
    /// Hexadecimal of this length (24 for a BSON object id, 32 for a Home Assistant id).
    Hex(usize),
    /// A 26-character ULID.
    Ulid,
    /// A UUID.
    Uuid,
}

fn id_format(text: &str) -> Option<IdFormat> {
    let hex = |s: &str| s.chars().all(|c| c.is_ascii_hexdigit());
    match text.len() {
        24 | 32 | 40 | 64 if hex(text) && !text.chars().all(|c| c.is_ascii_digit()) => {
            Some(IdFormat::Hex(text.len()))
        }
        26 if text.chars().all(|c| {
            c.is_ascii_digit()
                || matches!(c, 'A'..='H' | 'J' | 'K' | 'M' | 'N' | 'P'..='T' | 'V'..='Z')
        }) =>
        {
            Some(IdFormat::Ulid)
        }
        36 => {
            let parts: Vec<&str> = text.split('-').collect();
            (parts.len() == 5
                && parts.iter().map(|p| p.len()).eq([8, 4, 4, 4, 12])
                && parts.iter().all(|p| hex(p)))
            .then_some(IdFormat::Uuid)
        }
        _ => None,
    }
}

fn is_number(text: &str) -> bool {
    text.parse::<f64>().is_ok()
}

/// An ISO 8601 date or timestamp (`2026-10-16`, `2026-10-16T12:00:00+00:00`).
fn is_timestamp(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() >= 10
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && text[10..]
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, 'T' | ':' | '.' | '+' | '-' | 'Z' | ' '))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn names_addresses_and_ids_become_placeholders_consistently() {
        let mut anonymiser = Anonymiser::new();
        let out = anonymiser.anonymise(&json!({
            "data": [
                { "_id": "66aa11bb22cc33dd44ee55f1", "name": "Office switch", "mac": "D4:01:C3:00:11:22",
                  "ip": "10.20.30.4", "type": "usw", "x_authkey": "secret", "serial": "SN-1",
                  "port_table": [{ "port_idx": 1, "name": "nas", "mac_table": ["d4:01:c3:00:11:23"] }],
                  "lldp_table": [{ "chassis_id": "d4-01-c3-00-11-22", "port_id": "Port 7" }],
                  "country_code": 752, "last_seen": 1_760_000_000 },
                { "_id": "66aa11bb22cc33dd44ee55f2", "name": "Office switch", "hostname": "nas",
                  "network_id": "66aa11bb22cc33dd44ee55f1", "ip": "10.20.30.44",
                  "ipv6_addresses": ["2a01:1:2:10:d601:c3ff:fe00:1122", "fe80::d601:c3ff:fe00:1122"] }
            ]
        }));
        let first = &out["data"][0];
        let second = &out["data"][1];
        assert_eq!(first["name"], "name-1");
        assert_eq!(
            second["name"], "name-1",
            "the same text maps to the same placeholder"
        );
        assert_eq!(first["port_table"][0]["name"], "name-2");
        assert_eq!(second["hostname"], "name-2");
        assert_eq!(first["mac"], "00:00:5E:00:53:00");
        assert_eq!(first["lldp_table"][0]["chassis_id"], "00-00-5e-00-53-00");
        assert_eq!(first["port_table"][0]["mac_table"][0], "00:00:5e:00:53:01");
        assert_eq!(first["ip"], "192.0.2.4");
        assert_eq!(
            second["ip"], "192.0.2.44",
            "the same block, the host part kept"
        );
        assert_eq!(first["type"], "usw");
        assert!(first.get("x_authkey").is_none());
        assert_eq!(first["serial"], "id-1");
        assert_eq!(first["lldp_table"][0]["port_id"], "Port 7");
        assert_eq!(first["country_code"], 0);
        assert_eq!(first["last_seen"], 1_760_000_000);
        assert_eq!(first["_id"], "000000000000000000000001");
        assert_eq!(second["network_id"], "000000000000000000000001");
        assert_eq!(second["_id"], "000000000000000000000002");
        assert_eq!(second["ipv6_addresses"][0], "2001:db8:0:10::1001");
        assert_eq!(second["ipv6_addresses"][1], "fe80::1001");
    }

    #[test]
    fn subnets_keep_their_members_and_public_addresses_land_in_test_net_3() {
        let mut anonymiser = Anonymiser::new();
        let out = anonymiser.anonymise(&json!([
            { "ip": "172.16.5.9" },
            { "ip_subnet": "172.16.4.1/22" },
            { "ip": "172.16.7.200", "wan": "93.184.216.34", "dns": ["1.1.1.1", "127.0.0.1"] },
            { "ip_subnet": "192.168.1.1/24", "dhcpd_start": "192.168.1.100" },
            { "ip_subnet": "192.168.9.1/24" }
        ]));
        assert_eq!(out[1]["ip_subnet"], "198.18.0.1/22");
        assert_eq!(out[0]["ip"], "198.18.1.9");
        assert_eq!(out[2]["ip"], "198.18.3.200");
        assert_eq!(
            out[2]["wan"], "203.0.113.2",
            "keys are walked in order: dns first"
        );
        assert_eq!(out[2]["dns"], json!(["203.0.113.1", "127.0.0.1"]));
        assert_eq!(out[3]["ip_subnet"], "192.0.2.1/24");
        assert_eq!(out[3]["dhcpd_start"], "192.0.2.100");
        assert_eq!(out[4]["ip_subnet"], "198.51.100.1/24");
    }

    #[test]
    fn wide_networks_are_narrowed_when_the_ranges_run_out() {
        let mut anonymiser = Anonymiser::new();
        let out = anonymiser.anonymise(&json!([
            "10.10.0.1/16", "10.10.0.7", "10.10.9.7", "10.10.200.7",
            "172.20.0.1/16", "172.20.5.5",
            "192.168.1.1/24", "192.168.2.1/24", "192.168.3.9", { "ipconfig0": "ip=192.168.4.9/24,gw=192.168.4.1" }
        ]));
        assert_eq!(out[0], "198.18.0.1/22", "three blocks seen: a run of four");
        assert_eq!(out[1], "198.18.0.7");
        assert_eq!(out[2], "198.18.1.7");
        assert_eq!(out[3], "198.18.2.7");
        assert_eq!(out[4], "198.18.4.1/23", "two blocks seen: a run of two");
        assert_eq!(out[5], "198.18.5.5");
        assert_eq!(out[6], "192.0.2.1/24");
        assert_eq!(out[7], "198.51.100.1/24");
        assert_eq!(out[8], "198.18.6.9");
        assert_eq!(out[9]["ipconfig0"], "ip=198.18.7.9/24,gw=198.18.7.1");
        // Two /16 networks and four more blocks do not fit 2 + 512 blocks.
        assert_eq!(anonymiser.counts()["ipv4 narrowed networks"], 2);
        assert_eq!(anonymiser.counts()["ipv4 exhausted"], 0);
    }

    #[test]
    fn bare_prefix_lengths_follow_the_anonymised_network() {
        let mut anonymiser = Anonymiser::new();
        let out = anonymiser.anonymise(&json!({
            "wide": ["10.10.0.1/16", "10.10.0.7", "10.10.9.7", "10.10.200.7",
                     "172.20.0.1/16", "172.20.5.5"],
            "fill": ["192.168.1.1/24", "192.168.2.1/24", "192.168.3.9"],
            "network": [
                { "iface": "vmbr0", "address": "10.10.0.5", "netmask": "16", "cidr": "10.10.0.5/16" },
                { "iface": "vmbr1", "address": "172.20.5.9", "netmask": "255.255.0.0" },
                { "iface": "vmbr2", "address": "192.168.3.32", "netmask": "16" },
                { "iface": "vmbr3", "address6": "fd00:1:2:3::5", "netmask6": "64" },
                { "iface": "lo", "address": "127.0.0.1", "netmask": "8" }
            ],
            "agent": [{ "ip-address": "10.10.9.7", "ip-address-type": "ipv4", "prefix": 16 },
                      { "ip-address": "172.31.0.1", "ip-address-type": "ipv4", "prefix": 16 }]
        }));
        let network = &out["network"];
        assert_eq!(network[0]["cidr"], "198.18.0.5/22");
        assert_eq!(
            network[0]["netmask"], "22",
            "the width of the cidr next to it"
        );
        assert_eq!(
            network[1]["netmask"], "255.255.254.0",
            "a dotted mask stays a mask"
        );
        assert_eq!(network[2]["netmask"], "24", "in no wide network");
        assert_eq!(network[3]["netmask6"], "64");
        assert_eq!(network[4]["netmask"], "8", "loopback is not replaced");
        assert_eq!(out["agent"][0]["prefix"], 22);
        assert_eq!(out["agent"][1]["prefix"], 24);
    }

    #[test]
    fn home_assistant_records_keep_what_the_connector_reads() {
        let mut anonymiser = Anonymiser::new();
        let out = anonymiser.anonymise(&json!({
            "devices": [{ "id": "01HZX3M9Q8K7V6W5T4R3P2N1M0", "name": "Kitchen plug",
                "identifiers": [["shelly", "shellyplus1pm-aabbccddeeff"]],
                "connections": [["mac", "aa:bb:cc:dd:ee:ff"], ["zigbee", "00:12:4b:00:1c:aa:bb:cc"]],
                "manufacturer": "Shelly", "model": "Plus 1PM", "model_id": "440400982842", "sw_version": "1.4.4", "area_id": "pats_office",
                "configuration_url": "http://192.168.1.50", "config_entries": ["0123456789abcdef0123456789abcdef"] }],
            "states": [{ "entity_id": "device_tracker.pats_phone", "state": "not_home",
                "attributes": { "friendly_name": "Pat's phone", "latitude": 59.3, "ip": "192.168.1.77",
                                "mac": "AA:BB:CC:DD:EE:F0", "source_type": "router", "battery_level": 80 },
                "last_changed": "2026-10-16T08:00:00+00:00",
                "context": { "id": "01HZX3M9Q8K7V6W5T4R3P2N1M1", "user_id": null } }],
            "entries": [{ "entry_id": "0123456789abcdef0123456789abcdef", "domain": "shelly", "title": "Kitchen plug", "state": "loaded" }]
        }));
        let device = &out["devices"][0];
        assert_eq!(device["id"], "00000000000000000000000002");
        assert_eq!(device["identifiers"][0][0], "shelly");
        assert_eq!(device["identifiers"][0][1], "id-2");
        assert_eq!(device["connections"][0][0], "mac");
        assert_eq!(device["connections"][0][1], "00:00:5e:00:53:00");
        assert_eq!(device["connections"][1][1], "00:00:5e:ff:fe:00:00:02");
        assert_eq!(device["manufacturer"], "Vendor 1");
        assert_eq!(device["model"], "Model 1");
        assert_eq!(device["sw_version"], "1.4.4");
        assert_eq!(device["configuration_url"], "text-1");
        assert_eq!(
            device["model_id"], "Model 2",
            "a numeric model id is a model"
        );
        assert_eq!(device["area_id"], "id-1", "an area slug names the area");
        assert_eq!(
            device["config_entries"][0],
            "00000000000000000000000000000001"
        );
        let state = &out["states"][0];
        assert_eq!(state["entity_id"], "device_tracker.entity_1");
        assert_eq!(state["state"], "not_home");
        assert_eq!(state["attributes"]["friendly_name"], "name-2");
        assert_eq!(state["attributes"]["ip"], "192.0.2.77");
        assert_eq!(state["attributes"]["mac"], "00:00:5E:00:53:02");
        assert_eq!(state["attributes"]["source_type"], "router");
        assert!(state["attributes"].get("latitude").is_none());
        assert!(state["attributes"].get("battery_level").is_none());
        assert!(state.get("context").is_none());
        assert_eq!(state["last_changed"], "2026-10-16T08:00:00+00:00");
        let entry = &out["entries"][0];
        assert_eq!(entry["entry_id"], device["config_entries"][0]);
        assert_eq!(entry["domain"], "shelly");
        assert_eq!(entry["title"], "name-1", "the device's name again");
        assert_eq!(entry["state"], "loaded");
    }

    #[test]
    fn proxmox_property_strings_keep_their_keys_and_relations() {
        let mut anonymiser = Anonymiser::new();
        let out = anonymiser.anonymise(&json!({
            "resources": [{ "type": "qemu", "vmid": 101, "node": "hv-owner", "name": "owner-vm",
                            "status": "running", "tags": "owner;secret project" }],
            "config": { "net0": "virtio=BC:24:11:12:34:56,bridge=vmbr7,tag=30,firewall=1",
                        "net1": "name=eth0,bridge=vmbr7,hwaddr=BC:24:11:12:34:57,ip=dhcp,ip6=auto,type=veth",
                        "ipconfig0": "ip=10.1.2.3/24,gw=10.1.2.1", "agent": "enabled=1,fstrim_cloned_disks=1",
                        "ostype": "l26", "description": "Owner=Pat,Room=Kitchen" },
            "network": [{ "iface": "vmbr7", "type": "bridge", "method": "static", "cidr": "10.1.2.2/24" }],
            "interfaces": [{ "name": "lo", "hardware-address": "00:00:00:00:00:00" }],
            "status": [{ "type": "node", "name": "hv-owner", "ip": "10.1.2.2" }]
        }));
        let node = out["resources"][0]["node"]
            .as_str()
            .expect("node")
            .to_owned();
        assert_eq!(
            out["status"][0]["name"],
            node.as_str(),
            "the node keeps its relation"
        );
        assert_eq!(out["resources"][0]["status"], "running");
        assert_eq!(
            out["resources"][0]["tags"]
                .as_str()
                .map(|t| t.split(';').count()),
            Some(2)
        );
        let net0 = out["config"]["net0"].as_str().expect("net0");
        assert!(net0.starts_with("virtio=00:00:5E:00:53:"), "{net0}");
        assert!(net0.ends_with(",tag=30,firewall=1"), "{net0}");
        let bridge = out["network"][0]["iface"].as_str().expect("iface");
        assert!(net0.contains(&format!("bridge={bridge},")), "{net0}");
        let net1 = out["config"]["net1"].as_str().expect("net1");
        assert!(net1.contains(",ip=dhcp,ip6=auto,type=veth"), "{net1}");
        assert_eq!(out["config"]["ipconfig0"], "ip=192.0.2.3/24,gw=192.0.2.1");
        assert_eq!(out["config"]["agent"], "enabled=1,fstrim_cloned_disks=1");
        assert_eq!(out["config"]["ostype"], "l26");
        let description = out["config"]["description"].as_str().expect("description");
        assert!(
            !description.contains("Owner") && !description.contains("Pat"),
            "{description}"
        );
        assert_eq!(out["network"][0]["method"], "static");
        assert_eq!(out["status"][0]["ip"], "192.0.2.2");
        assert_eq!(
            out["interfaces"][0]["hardware-address"],
            "00:00:00:00:00:00"
        );
    }

    #[test]
    fn more_than_256_mac_addresses_become_locally_administered() {
        let mut anonymiser = Anonymiser::new();
        let macs: Vec<Value> = (0u32..300)
            .map(|n| {
                json!(format!(
                    "10:20:30:{:02x}:{:02x}:{:02x}",
                    n >> 16,
                    n >> 8,
                    n & 0xff
                ))
            })
            .collect();
        let out = anonymiser.anonymise(&Value::Array(macs));
        assert_eq!(out[0], "00:00:5e:00:53:00");
        assert_eq!(out[255], "00:00:5e:00:53:ff");
        assert_eq!(out[256], "02:00:5e:00:00:00");
        assert_eq!(out[299], "02:00:5e:00:00:2b");
        assert_eq!(anonymiser.counts()["macs"], 300);
    }
}
