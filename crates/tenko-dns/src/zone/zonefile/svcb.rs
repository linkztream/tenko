//! SVCB and HTTPS (RFC 9460): the priority, the target and the parameters, read and
//! written.
//!
//! A parameter is `key` or `key=value`, the value quoted or not, with the escapes of a
//! character string. The keys with a syntax of their own are `mandatory` (key names),
//! `alpn` (protocol identifiers), `no-default-alpn` (no value), `port`, `ipv4hint`, `ech`
//! (base64), `ipv6hint`, `dohpath` (RFC 9461, a URI template) and `ohttp` (RFC 9540, no
//! value); `keyNNNNN` names any key with the generic value of RFC 9460, appendix A. The
//! lists (`mandatory`, `alpn`, the hints) are comma-separated, and in `alpn` a comma or a
//! backslash inside an identifier is escaped with a backslash (appendix A.1), which the
//! character string escapes once more (`alpn="a\\,b"` is the one identifier `a,b`).
//!
//! The writer uses a key's own syntax when the value fits it and the generic form when it
//! does not, so every value the model holds is written and read back unchanged.

use std::{
    fmt::Write as _,
    net::{Ipv4Addr, Ipv6Addr},
};

use tenko_core::dns::SvcParam;

use super::{
    parse::{Bad, Fields},
    text,
};
use crate::zone::encoding;

/// The keys with a name (RFC 9460 section 14.3.2, RFC 9461, RFC 9540).
const KEYS: [(u16, &str); 9] = [
    (0, "mandatory"),
    (1, "alpn"),
    (2, "no-default-alpn"),
    (3, "port"),
    (4, "ipv4hint"),
    (5, "ech"),
    (6, "ipv6hint"),
    (7, "dohpath"),
    (8, "ohttp"),
];

/// The key of a name, and whether the name is the generic `keyNNNNN` (whose value is
/// taken as its wire form, RFC 9460 section 2.1).
fn key_of(name: &str) -> Option<(u16, bool)> {
    if let Some((value, _)) = KEYS.iter().find(|(_, key)| key.eq_ignore_ascii_case(name)) {
        return Some((*value, false));
    }
    name.get(..3)
        .filter(|head| head.eq_ignore_ascii_case("key"))?;
    let number = name.get(3..)?;
    if number.len() > 1 && number.starts_with('0') {
        return None;
    }
    text::decimal(number).map(|key| (key, true))
}

fn key_value(name: &str) -> Option<u16> {
    key_of(name).map(|(key, _)| key)
}

fn key_name(key: u16) -> String {
    KEYS.iter()
        .find(|(value, _)| *value == key)
        .map_or_else(|| format!("key{key}"), |(_, name)| (*name).to_owned())
}

/// Splits a decoded list value at commas; `\,` and `\\` (and any `\X`) stand for the octet
/// after the backslash. Empty items are refused.
fn items(value: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    let mut out = Vec::new();
    let mut item = Vec::new();
    let mut index = 0;
    while let Some(&byte) = value.get(index) {
        match byte {
            b'\\' => {
                let next = value.get(index + 1).ok_or("a list ends with a backslash")?;
                item.push(*next);
                index += 2;
            }
            b',' => {
                if item.is_empty() {
                    return Err("an empty item in a list");
                }
                out.push(std::mem::take(&mut item));
                index += 1;
            }
            other => {
                item.push(other);
                index += 1;
            }
        }
    }
    if item.is_empty() {
        return Err("an empty item in a list");
    }
    out.push(item);
    Ok(out)
}

fn text_of(bytes: &[u8]) -> Result<&str, &'static str> {
    std::str::from_utf8(bytes).map_err(|_| "a value that is not text")
}

/// The wire value of one parameter.
fn value_wire(key: u16, value: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let needs = |value: Option<&[u8]>| -> Result<Vec<u8>, String> {
        value
            .filter(|value| !value.is_empty())
            .map(<[u8]>::to_vec)
            .ok_or_else(|| format!("the parameter {} needs a value", key_name(key)))
    };
    let mut out = Vec::new();
    match key {
        0 => {
            let mut keys = Vec::new();
            for item in items(&needs(value)?)? {
                let name = text_of(&item)?;
                keys.push(
                    key_value(name).ok_or_else(|| format!("`{name}` is not a parameter key"))?,
                );
            }
            keys.sort_unstable();
            if keys.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err("a key is listed twice in mandatory".to_owned());
            }
            for key in keys {
                out.extend_from_slice(&key.to_be_bytes());
            }
        }
        1 => {
            for item in items(&needs(value)?)? {
                let length = u8::try_from(item.len())
                    .map_err(|_| "a protocol identifier is at most 255 octets".to_owned())?;
                out.push(length);
                out.extend_from_slice(&item);
            }
        }
        2 | 8 => {
            if value.is_some_and(|value| !value.is_empty()) {
                return Err(format!("the parameter {} takes no value", key_name(key)));
            }
        }
        3 => {
            let value = needs(value)?;
            let port: u16 = text::decimal(text_of(&value)?)
                .ok_or_else(|| "the port is a number from 0 to 65535".to_owned())?;
            out.extend_from_slice(&port.to_be_bytes());
        }
        4 => {
            for item in items(&needs(value)?)? {
                let address: Ipv4Addr = text_of(&item)?
                    .parse()
                    .map_err(|_| "ipv4hint lists IPv4 addresses".to_owned())?;
                out.extend_from_slice(&address.octets());
            }
        }
        5 => {
            out = encoding::base64_decode(text_of(&needs(value)?)?)
                .map_err(|reason| format!("ech: {reason}"))?;
        }
        6 => {
            for item in items(&needs(value)?)? {
                let address: Ipv6Addr = text_of(&item)?
                    .parse()
                    .map_err(|_| "ipv6hint lists IPv6 addresses".to_owned())?;
                out.extend_from_slice(&address.octets());
            }
        }
        7 => {
            let value = needs(value)?;
            text_of(&value)?;
            out = value;
        }
        _ => out = value.map(<[u8]>::to_vec).unwrap_or_default(),
    }
    if out.len() > usize::from(u16::MAX) {
        return Err("a parameter value is at most 65535 octets".to_owned());
    }
    Ok(out)
}

/// Appends the wire form of SVCB or HTTPS data read from its presentation form.
///
/// # Errors
///
/// The line and reason of a field that does not parse, an unknown key, a key given twice
/// or a value that does not fit its key.
pub(super) fn parse(fields: &mut Fields<'_>, out: &mut Vec<u8>) -> Result<(), Bad> {
    out.extend_from_slice(&fields.priority()?.to_be_bytes());
    fields.target(out)?;
    let mut params: Vec<(u16, Vec<u8>, usize)> = Vec::new();
    while let Some(param) = fields.param()? {
        let (key, generic) = key_of(param.key).ok_or_else(|| {
            (
                param.line,
                format!("`{}` is not a parameter key", param.key),
            )
        })?;
        let value = param
            .value
            .map(text::unescape)
            .transpose()
            .map_err(|reason| (param.line, format!("{}: {reason}", param.key)))?;
        let wire = if generic {
            let wire = value.unwrap_or_default();
            if wire.len() > usize::from(u16::MAX) {
                return Err((
                    param.line,
                    "a parameter value is at most 65535 octets".to_owned(),
                ));
            }
            wire
        } else {
            value_wire(key, value.as_deref()).map_err(|reason| (param.line, reason))?
        };
        params.push((key, wire, param.line));
    }
    params.sort_by_key(|(key, ..)| *key);
    if let Some(pair) = params.windows(2).find(|pair| pair[0].0 == pair[1].0) {
        return Err((
            pair[1].2,
            format!("the parameter {} is given twice", key_name(pair[1].0)),
        ));
    }
    for (key, value, _) in params {
        out.extend_from_slice(&key.to_be_bytes());
        out.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(&value);
    }
    Ok(())
}

/// Writes octets as a value without quotes: the printable characters that need no escape
/// as they are, every other octet as `\DDD`.
fn escaped(bytes: &[u8], out: &mut String) {
    for &byte in bytes {
        if byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\' | b';' | b'(' | b')') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "\\{byte:03}");
        }
    }
}

/// Writes one parameter in its key's own syntax; `false` (and nothing written) when the
/// value does not fit it.
fn typed(param: &SvcParam, out: &mut String) -> bool {
    let value = param.value.0.as_slice();
    let start = out.len();
    let fits = match param.key {
        0 if !value.is_empty()
            && value.len().is_multiple_of(2)
            && value
                .as_chunks::<2>()
                .0
                .windows(2)
                .all(|pair| pair[0] < pair[1]) =>
        {
            out.push_str("mandatory=");
            let names: Vec<String> = value
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| key_name(u16::from_be_bytes(*pair)))
                .collect();
            out.push_str(&names.join(","));
            true
        }
        1 => alpn(value, out),
        2 if value.is_empty() => {
            out.push_str("no-default-alpn");
            true
        }
        3 if value.len() == 2 => {
            let _ = write!(out, "port={}", u16::from_be_bytes([value[0], value[1]]));
            true
        }
        4 if !value.is_empty() && value.len().is_multiple_of(4) => {
            out.push_str("ipv4hint=");
            let addresses: Vec<String> = value
                .as_chunks::<4>()
                .0
                .iter()
                .map(|octets| Ipv4Addr::from(*octets).to_string())
                .collect();
            out.push_str(&addresses.join(","));
            true
        }
        5 if !value.is_empty() => {
            out.push_str("ech=");
            out.push_str(&encoding::base64_encode(value));
            true
        }
        6 if !value.is_empty() && value.len().is_multiple_of(16) => {
            out.push_str("ipv6hint=");
            let addresses: Vec<String> = value
                .as_chunks::<16>()
                .0
                .iter()
                .map(|octets| Ipv6Addr::from(*octets).to_string())
                .collect();
            out.push_str(&addresses.join(","));
            true
        }
        7 if !value.is_empty() && std::str::from_utf8(value).is_ok() => {
            out.push_str("dohpath=");
            escaped(value, out);
            true
        }
        8 if value.is_empty() => {
            out.push_str("ohttp");
            true
        }
        _ => false,
    };
    if !fits {
        out.truncate(start);
    }
    fits
}

fn alpn(value: &[u8], out: &mut String) -> bool {
    let mut ids = Vec::new();
    let mut rest = value;
    while let Some((&length, tail)) = rest.split_first() {
        let Some(id) = tail.get(..usize::from(length)) else {
            return false;
        };
        if id.is_empty() {
            return false;
        }
        ids.push(id);
        rest = &tail[usize::from(length)..];
    }
    if ids.is_empty() {
        return false;
    }
    out.push_str("alpn=");
    for (index, id) in ids.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        // The list escape (`\,`, `\\`), then the character string escape of its backslash.
        for &byte in *id {
            match byte {
                b',' => out.push_str("\\\\,"),
                b'\\' => out.push_str("\\\\\\\\"),
                _ => escaped(&[byte], out),
            }
        }
    }
    true
}

/// The presentation of the parameters, each after a space.
pub(super) fn present(params: &[SvcParam], out: &mut String) {
    for param in params {
        out.push(' ');
        if typed(param, out) {
            continue;
        }
        let _ = write!(out, "key{}", param.key);
        if !param.value.0.is_empty() {
            out.push('=');
            escaped(&param.value.0, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_have_names_and_numbers() {
        assert_eq!(key_value("alpn"), Some(1));
        assert_eq!(key_value("No-Default-ALPN"), Some(2));
        assert_eq!(key_value("key65535"), Some(65_535));
        assert_eq!(key_value("key7"), Some(7));
        assert_eq!(key_value("key07"), None);
        assert_eq!(key_value("key65536"), None);
        assert_eq!(key_value("key"), None);
        assert_eq!(key_value("nodefaultalpn"), None);
        assert_eq!(key_name(8), "ohttp");
        assert_eq!(key_name(9), "key9");
    }

    #[test]
    fn list_items_split_at_unescaped_commas() {
        assert_eq!(items(b"h2,h3"), Ok(vec![b"h2".to_vec(), b"h3".to_vec()]));
        assert_eq!(
            items(b"a\\,b,c\\\\"),
            Ok(vec![b"a,b".to_vec(), b"c\\".to_vec()])
        );
        for bad in [&b""[..], b",", b"a,", b",a", b"a,,b", b"a\\"] {
            assert!(items(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn values_fit_their_keys() {
        assert_eq!(value_wire(3, Some(b"443")), Ok(vec![1, 187]));
        assert!(value_wire(3, Some(b"65536")).is_err());
        assert!(value_wire(3, None).is_err());
        assert_eq!(value_wire(0, Some(b"port,alpn")), Ok(vec![0, 1, 0, 3]));
        assert!(value_wire(0, Some(b"alpn,alpn")).is_err());
        assert!(value_wire(0, Some(b"bogus")).is_err());
        assert_eq!(
            value_wire(1, Some(b"h2,a\\,b")),
            Ok(b"\x02h2\x03a,b".to_vec())
        );
        assert!(value_wire(1, Some(&[b'a'; 256])).is_err());
        assert_eq!(value_wire(2, None), Ok(Vec::new()));
        assert_eq!(value_wire(2, Some(b"")), Ok(Vec::new()));
        assert!(value_wire(2, Some(b"x")).is_err());
        assert_eq!(
            value_wire(4, Some(b"192.0.2.1,192.0.2.2")),
            Ok(vec![192, 0, 2, 1, 192, 0, 2, 2])
        );
        assert!(value_wire(4, Some(b"2001:db8::1")).is_err());
        assert_eq!(value_wire(6, Some(b"2001:db8::1")).map(|v| v.len()), Ok(16));
        assert_eq!(value_wire(5, Some(b"AQID")), Ok(vec![1, 2, 3]));
        assert!(value_wire(5, Some(b"AQI")).is_err());
        assert_eq!(value_wire(7, Some(b"/q{?dns}")), Ok(b"/q{?dns}".to_vec()));
        assert!(value_wire(7, Some(b"\xff")).is_err());
        assert_eq!(value_wire(65_000, None), Ok(Vec::new()));
        assert_eq!(value_wire(65_000, Some(b"\x00a")), Ok(vec![0, b'a']));
    }

    #[test]
    fn values_that_do_not_fit_are_written_generically() {
        let param = |key, value: &[u8]| SvcParam {
            key,
            value: tenko_core::serde_util::HexBytes(value.to_vec()),
        };
        let mut out = String::new();
        present(
            &[
                param(0, &[0, 1, 0, 3]),
                param(1, b"\x02h2\x03a,b\x02c\\"),
                param(2, b""),
                param(3, &[1, 187]),
                param(4, &[192, 0, 2, 1]),
                param(5, &[1, 2, 3]),
                param(
                    6,
                    &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                ),
                param(7, b"/q{?dns}"),
                param(8, b""),
                param(9, b"a b\""),
            ],
            &mut out,
        );
        assert_eq!(
            out,
            " mandatory=alpn,port alpn=h2,a\\\\,b,c\\\\\\\\ no-default-alpn port=443 \
             ipv4hint=192.0.2.1 ech=AQID ipv6hint=2001:db8::1 dohpath=/q{?dns} ohttp \
             key9=a\\032b\\034"
        );
        let mut out = String::new();
        present(
            &[
                param(1, b"\x05h2"),
                param(2, b"x"),
                param(3, &[1]),
                param(8, b"y"),
            ],
            &mut out,
        );
        assert_eq!(out, " key1=\\005h2 key2=x key3=\\001 key8=y");
    }
}
