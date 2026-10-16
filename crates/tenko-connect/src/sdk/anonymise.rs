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
//! Assistant state are reduced to the ones a connector reads.
//!
//! The anonymiser keeps its maps between calls, so several answers of one system can be
//! anonymised one after the other and still agree with each other.

use std::{
    collections::{BTreeMap, HashMap},
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
const KEEP_KEYS: [&str; 62] = [
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
const WORDS: [&str; 76] = [
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
    v4_next: u16,
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
        counts.insert("ipv6 prefixes", self.v6_prefixes.len() as u64);
        counts.insert("macs", self.macs.len() as u64);
        counts
    }

    fn next(&mut self, family: &'static str) -> u64 {
        let counter = self.counters.entry(family).or_default();
        *counter += 1;
        *counter
    }

    /// Reserves contiguous placeholder blocks for every IPv4 network wider than a /24, so
    /// that its addresses stay inside it.
    fn reserve(&mut self, value: &Value) {
        match value {
            Value::String(text) => {
                if let Some((IpAddr::V4(ip), Some(len))) = cidr(text)
                    && len < 24
                    && is_mapped_v4(ip)
                    && !is_global_v4(ip)
                {
                    let count = 1u32 << (24 - len);
                    let first = u32::from(ip) & !(count - 1);
                    let blocks: Vec<[u8; 3]> = (0..count)
                        .map(|i| block_of(Ipv4Addr::from(first + (i << 8))))
                        .collect();
                    if blocks.iter().any(|b| self.v4_blocks.contains_key(b)) {
                        return;
                    }
                    let aligned = (u32::from(self.v4_next) + count - 1) & !(count - 1);
                    for (i, block) in blocks.into_iter().enumerate() {
                        let n = aligned + u32::try_from(i).unwrap_or(u32::MAX);
                        self.v4_blocks.insert(block, bench_block(n));
                    }
                    self.v4_next = u16::try_from(aligned + count).unwrap_or(u16::MAX);
                }
            }
            Value::Array(items) => items.iter().for_each(|item| self.reserve(item)),
            Value::Object(map) => map.values().for_each(|item| self.reserve(item)),
            _ => {}
        }
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
        out
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
            return match len {
                Some(len) => format!("{mapped}/{len}"),
                None => mapped.to_string(),
            };
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
            // Every public address lands in TEST-NET-3; the host part is kept.
            let [a, b, c] = DOCUMENTATION_V4[2];
            return Ipv4Addr::new(a, b, c, host);
        }
        let block = block_of(ip);
        let mapped = if let Some(mapped) = self.v4_blocks.get(&block) {
            *mapped
        } else {
            let mapped = if self.v4_documentation < 2 {
                self.v4_documentation += 1;
                DOCUMENTATION_V4[self.v4_documentation - 1]
            } else {
                let n = u32::from(self.v4_next);
                self.v4_next = self.v4_next.saturating_add(1);
                bench_block(n)
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

/// Whether a member is dropped by its key.
fn dropped(key: &str) -> bool {
    key.starts_with("x_")
        || DROP_KEYS.contains(&key)
        || DROP_SUBSTRINGS.iter().any(|part| key.contains(part))
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
        assert_eq!(out[2]["wan"], "203.0.113.34");
        assert_eq!(out[2]["dns"], json!(["203.0.113.1", "127.0.0.1"]));
        assert_eq!(out[3]["ip_subnet"], "192.0.2.1/24");
        assert_eq!(out[3]["dhcpd_start"], "192.0.2.100");
        assert_eq!(out[4]["ip_subnet"], "198.51.100.1/24");
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
