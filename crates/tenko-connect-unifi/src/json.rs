//! Lenient readers for the controller's JSON: every member may be missing or of an
//! unexpected type (numbers as text, text as numbers), and text is trimmed and bounded.

use std::net::IpAddr;

use serde_json::Value;
use tenko_core::MacAddr;

/// The longest text the plugin keeps from the controller (names, model codes).
pub const MAX_TEXT: usize = 200;

/// A member as non-empty text, trimmed, control characters removed, at most
/// [`MAX_TEXT`] characters; numbers count as text.
pub fn text(value: &Value, key: &str) -> Option<String> {
    let raw = match value.get(key)? {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        _ => return None,
    };
    clean(&raw)
}

/// Cleans text for the host: trimmed, without control characters, bounded.
pub fn clean(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_TEXT)
        .collect();
    let cleaned = cleaned.trim().to_owned();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// A member as an identifier: non-empty text of printable ASCII, at most 128 characters.
pub fn id(value: &Value, key: &str) -> Option<String> {
    let text = value.get(key)?.as_str()?.trim();
    (!text.is_empty() && text.len() <= 128 && text.chars().all(|c| c.is_ascii_graphic()))
        .then(|| text.to_owned())
}

/// A member as an unsigned number; numeric text counts.
pub fn uint(value: &Value, key: &str) -> Option<u64> {
    match value.get(key)? {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// A member as a 16-bit number.
pub fn u16(value: &Value, key: &str) -> Option<u16> {
    uint(value, key).and_then(|n| u16::try_from(n).ok())
}

/// A member as a VLAN id (1 to 4094).
pub fn vlan(value: &Value, key: &str) -> Option<u16> {
    u16(value, key).filter(|vid| (1..=4094).contains(vid))
}

/// A member as a boolean; `"true"`, `"false"`, `1` and `0` count.
pub fn flag(value: &Value, key: &str) -> Option<bool> {
    match value.get(key)? {
        Value::Bool(flag) => Some(*flag),
        Value::Number(number) => number.as_u64().map(|n| n != 0),
        Value::String(text) => match text.trim() {
            "true" | "1" => Some(true),
            "false" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// A member as a MAC address.
pub fn mac(value: &Value, key: &str) -> Option<MacAddr> {
    parse_mac(value.get(key)?.as_str()?)
}

/// Text as a MAC address (`:` or `-` separators, any case).
pub fn parse_mac(text: &str) -> Option<MacAddr> {
    let text = text.trim();
    if text.len() != 17 {
        return None;
    }
    text.parse().ok()
}

/// A member as an IP address.
pub fn ip(value: &Value, key: &str) -> Option<IpAddr> {
    value.get(key)?.as_str()?.trim().parse().ok()
}

/// A member as an array (empty when absent or not an array).
pub fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// A member as a list of identifiers.
pub fn ids(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .filter_map(|item| {
            let text = item.as_str()?.trim();
            (!text.is_empty() && text.len() <= 128 && text.chars().all(|c| c.is_ascii_graphic()))
                .then(|| text.to_owned())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_are_read_leniently() {
        let value = serde_json::json!({
            "name": "  Switch\u{7} A ",
            "vlan": "30",
            "port": 5,
            "big": 70000,
            "on": "true",
            "mac": "00:00:5E:00:53:01",
            "badmac": "00:00:5e",
            "ip": "192.0.2.4",
            "ids": ["a", "", 3, "b"],
            "empty": "   "
        });
        assert_eq!(text(&value, "name").as_deref(), Some("Switch A"));
        assert_eq!(vlan(&value, "vlan"), Some(30));
        assert_eq!(u16(&value, "port"), Some(5));
        assert_eq!(u16(&value, "big"), None);
        assert_eq!(flag(&value, "on"), Some(true));
        assert_eq!(
            mac(&value, "mac").map(|m| m.to_string()).as_deref(),
            Some("00:00:5e:00:53:01")
        );
        assert!(mac(&value, "badmac").is_none());
        assert_eq!(
            ip(&value, "ip").map(|ip| ip.to_string()).as_deref(),
            Some("192.0.2.4")
        );
        assert_eq!(ids(&value, "ids"), ["a", "b"]);
        assert!(text(&value, "empty").is_none());
        assert!(text(&value, "missing").is_none());
        assert_eq!(text(&value, "port").as_deref(), Some("5"));
    }
}
