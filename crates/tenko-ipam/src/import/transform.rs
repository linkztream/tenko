//! Value transforms of the import: host names from labels, enumerations in English and
//! Swedish, tags, interface lists, and the formula escape of the export.

use tenko_core::{
    MacAddr,
    ipam::{AllocPolicy, AssignmentMode, PrefixRole, Status},
    net::{Duid, HostName},
};

use super::shape;

/// Longest host name label.
const MAX_LABEL: usize = 63;

/// A host name from a label: the label itself when it is valid (case does not count as a
/// change), else a normalized form (lowercase, spaces and other characters turned into
/// `-`, runs collapsed, Swedish and other accented letters folded to ASCII). The flag says
/// whether the name differs from the label beyond case. `None` when nothing usable is
/// left.
pub fn host_name(label: &str) -> Option<(HostName, bool)> {
    let label = label.trim();
    if label.is_empty() {
        return None;
    }
    if let Ok(name) = HostName::new(label) {
        return Some((name, false));
    }
    let mut folded = String::with_capacity(label.len());
    for c in label.chars().flat_map(char::to_lowercase) {
        let c = match c {
            'å' | 'ä' | 'à' | 'á' | 'â' | 'ã' => 'a',
            'ö' | 'ø' | 'ò' | 'ó' | 'ô' | 'õ' => 'o',
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'ü' | 'ù' | 'ú' | 'û' => 'u',
            'í' | 'ì' | 'î' | 'ï' => 'i',
            'ç' => 'c',
            'ñ' => 'n',
            c if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.' => c,
            _ => '-',
        };
        folded.push(c);
    }
    let labels: Vec<String> = folded
        .split('.')
        .map(|part| {
            let mut collapsed = String::with_capacity(part.len());
            for c in part.chars() {
                if c == '-' && collapsed.ends_with('-') {
                    continue;
                }
                collapsed.push(c);
            }
            let trimmed = collapsed.trim_matches('-');
            trimmed.chars().take(MAX_LABEL).collect::<String>()
        })
        .map(|part| part.trim_end_matches('-').to_owned())
        .filter(|part| !part.is_empty())
        .collect();
    if labels.is_empty() {
        return None;
    }
    HostName::new(&labels.join("."))
        .ok()
        .map(|name| (name, true))
}

/// Removes the formula escape the export adds: one leading `'` in front of quotes that
/// stand before `=`, `+`, `-`, `@`, a tab or a carriage return (`'=SUM(1)` → `=SUM(1)`,
/// `''=x` → `'=x`).
pub fn unescape(value: &str) -> &str {
    match value.strip_prefix('\'') {
        Some(rest)
            if rest
                .trim_start_matches('\'')
                .starts_with(['=', '+', '-', '@', '\t', '\r']) =>
        {
            rest
        }
        _ => value,
    }
}

/// A status in English or Swedish.
pub fn status(value: &str) -> Option<Status> {
    match value.trim().to_lowercase().as_str() {
        "planned" | "planerad" | "planerat" => Some(Status::Planned),
        "active" | "aktiv" | "aktivt" | "in use" | "used" | "används" => Some(Status::Active),
        "reserved" | "reserverad" | "reserverat" => Some(Status::Reserved),
        "deprecated" | "utfasad" | "utfasat" => Some(Status::Deprecated),
        _ => None,
    }
}

/// An assignment mode.
pub fn mode(value: &str) -> Option<AssignmentMode> {
    match value.trim().to_lowercase().as_str() {
        "static" | "statisk" | "fast" => Some(AssignmentMode::Static),
        "reserved" | "reservation" | "reserverad" => Some(AssignmentMode::Reserved),
        "dynamic" | "dynamisk" | "dhcp" => Some(AssignmentMode::Dynamic),
        "unmanaged" | "ohanterad" => Some(AssignmentMode::Unmanaged),
        _ => None,
    }
}

/// A boolean in English or Swedish.
pub fn boolean(value: &str) -> Option<bool> {
    match value.trim().to_lowercase().as_str() {
        "true" | "yes" | "y" | "ja" | "j" | "1" | "x" | "sant" => Some(true),
        "false" | "no" | "n" | "nej" | "0" | "falskt" => Some(false),
        _ => None,
    }
}

/// A prefix role.
pub fn role(value: &str) -> Option<PrefixRole> {
    match value.trim().to_lowercase().as_str() {
        "network" | "nät" | "nätverk" => Some(PrefixRole::Network),
        "supernet" | "supernät" | "container" => Some(PrefixRole::Supernet),
        _ => None,
    }
}

/// A next-free policy.
pub fn alloc(value: &str) -> Option<AllocPolicy> {
    match value.trim().to_lowercase().as_str() {
        "lowest" | "lägsta" => Some(AllocPolicy::Lowest),
        "highest" | "högsta" => Some(AllocPolicy::Highest),
        _ => None,
    }
}

/// A percentage from 0 to 100 (`80`, `80%`).
pub fn percent(value: &str) -> Option<u8> {
    let value: u8 = value.trim().trim_end_matches('%').trim().parse().ok()?;
    (value <= 100).then_some(value)
}

/// A VLAN id from 1 to 4094.
pub fn vlan(value: &str) -> Option<u16> {
    let value: u16 = value.trim().parse().ok()?;
    (1..=4094).contains(&value).then_some(value)
}

/// Tags separated by `;`, empty parts dropped.
pub fn tags(value: &str) -> Vec<String> {
    value
        .split(';')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A DHCPv4 client identifier in hexadecimal (separators `:` and `-` allowed); returned
/// as lowercase hexadecimal without separators.
pub fn client_id(value: &str) -> Option<String> {
    let hex: String = value
        .trim()
        .chars()
        .filter(|c| *c != ':' && *c != '-')
        .collect();
    (!hex.is_empty() && hex.len().is_multiple_of(2) && hex.chars().all(|c| c.is_ascii_hexdigit()))
        .then(|| hex.to_lowercase())
}

/// One entry of an `interfaces` cell: `name`, `name=mac`, `name=mac=duid` or
/// `name==duid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceEntry {
    /// The interface name.
    pub name: String,
    /// The MAC address.
    pub mac: Option<MacAddr>,
    /// The DUID.
    pub duid: Option<Duid>,
}

/// Parses an `interfaces` cell (entries separated by `;`). Entries whose MAC or DUID does
/// not parse are returned in the error list with their text.
pub fn interfaces(value: &str) -> (Vec<InterfaceEntry>, Vec<String>) {
    let mut entries = Vec::new();
    let mut bad = Vec::new();
    for part in value.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        let mut pieces = part.splitn(3, '=');
        let name = pieces.next().unwrap_or_default().trim();
        let mac_text = pieces.next().map(str::trim).filter(|t| !t.is_empty());
        let duid_text = pieces.next().map(str::trim).filter(|t| !t.is_empty());
        let mac = mac_text.map(shape::parse_mac);
        let duid = duid_text.map(shape::parse_duid);
        if name.is_empty() || matches!(mac, Some(None)) || matches!(duid, Some(None)) {
            bad.push(part.to_owned());
            continue;
        }
        entries.push(InterfaceEntry {
            name: name.to_owned(),
            mac: mac.flatten(),
            duid: duid.flatten(),
        });
    }
    (entries, bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_become_host_names() {
        let (name, changed) = host_name("dc-a1").expect("name");
        assert_eq!(name.as_str(), "dc-a1");
        assert!(!changed);
        let (name, changed) = host_name("MX-9200").expect("name");
        assert_eq!(name.as_str(), "mx-9200");
        assert!(!changed, "case alone is not a change");
        let (name, changed) = host_name("SW_Attic").expect("name");
        assert_eq!(name.as_str(), "sw_attic");
        assert!(!changed);
        let (name, changed) = host_name("idrac - host1").expect("name");
        assert_eq!(name.as_str(), "idrac-host1");
        assert!(changed);
        let (name, _) = host_name("Wifi Controller Hall").expect("name");
        assert_eq!(name.as_str(), "wifi-controller-hall");
        let (name, _) = host_name("Skrivare Hälsa (2)").expect("name");
        assert_eq!(name.as_str(), "skrivare-halsa-2");
        assert_eq!(host_name("  "), None);
        assert_eq!(host_name("!!!"), None);
    }

    #[test]
    fn the_export_escape_is_removed() {
        assert_eq!(unescape("'=SUM(1)"), "=SUM(1)");
        assert_eq!(unescape("'-5"), "-5");
        assert_eq!(unescape("''=x"), "'=x");
        assert_eq!(unescape("'quoted"), "'quoted");
        assert_eq!(unescape("plain"), "plain");
    }

    #[test]
    fn enumerations_in_english_and_swedish() {
        assert_eq!(status("Aktiv"), Some(Status::Active));
        assert_eq!(status("reserved"), Some(Status::Reserved));
        assert_eq!(status("kanske"), None);
        assert_eq!(mode("static"), Some(AssignmentMode::Static));
        assert_eq!(boolean("Ja"), Some(true));
        assert_eq!(boolean("false"), Some(false));
        assert_eq!(role("supernet"), Some(PrefixRole::Supernet));
        assert_eq!(alloc("highest"), Some(AllocPolicy::Highest));
        assert_eq!(percent("80%"), Some(80));
        assert_eq!(percent("101"), None);
        assert_eq!(vlan("4095"), None);
        assert_eq!(tags("a; b;;c "), ["a", "b", "c"]);
        assert_eq!(client_id("01:AB"), Some("01ab".to_owned()));
        assert_eq!(client_id("0"), None);
    }
}
