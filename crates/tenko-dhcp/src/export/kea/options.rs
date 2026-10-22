//! `option-data` and `option-def` in Kea's form.
//!
//! An option is written with its code, its space and, where Kea defines the code or the
//! export adds a definition, its name. Values Kea reads as text are written as text
//! (`csv-format` true): addresses, integers, booleans, names and strings that are printable
//! and hold no comma. Everything else is hexadecimal wire data (`csv-format` false), which
//! Kea unpacks with the option's definition, so the octets the client gets are the ones
//! Tenko sends.
//!
//! Six codes of Tenko's catalog have no definition in Kea 2.6 (150 `tftp-server-address`,
//! 209 to 211 for PXELINUX, 249 `ms-classless-static-route` and 252 `wpad`); the export adds
//! an `option-def` for each one it uses. Tenko's custom definitions become `option-def`
//! entries of their space.

use std::{collections::BTreeSet, fmt::Write as _};

use serde_json::{Map, Value, json};
use tenko_core::dhcp::{
    OptionData, OptionDef, OptionKind, OptionValue, catalog_v4, option::CatalogEntry,
};

/// The codes of Tenko's catalog that Kea 2.6 does not define.
const NOT_IN_KEA: [u8; 6] = [150, 209, 210, 211, 249, 252];

/// Kea's type name of a kind.
pub fn kea_type(kind: OptionKind) -> &'static str {
    match kind {
        OptionKind::Ipv4Address => "ipv4-address",
        OptionKind::Ipv6Address => "ipv6-address",
        OptionKind::Ipv6Prefix => "ipv6-prefix",
        OptionKind::U8 => "uint8",
        OptionKind::U16 => "uint16",
        OptionKind::U32 => "uint32",
        OptionKind::I32 => "int32",
        OptionKind::Bool => "boolean",
        OptionKind::String => "string",
        OptionKind::Fqdn => "fqdn",
        OptionKind::ClasslessRoutes | OptionKind::Binary => "binary",
        OptionKind::Empty => "empty",
    }
}

/// Hexadecimal octets, as Kea's `data` takes them with `csv-format` false.
pub fn hex(octets: &[u8]) -> String {
    let mut out = String::with_capacity(2 * octets.len());
    for b in octets {
        let _ = write!(out, "{b:02X}");
    }
    out
}

fn join<T: ToString>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The value as Kea's text form, when it has a safe one.
fn csv(kind: OptionKind, array: bool, data: &[u8]) -> Option<String> {
    match OptionData::decode(kind, array, data).ok()? {
        OptionData::Ipv4 { values } => Some(join(&values)),
        OptionData::Ipv6 { values } => Some(join(&values)),
        OptionData::Unsigned(values) => Some(join(&values)),
        OptionData::Signed(value) => Some(value.to_string()),
        OptionData::Bool(values) => Some(join(&values)),
        OptionData::Names(names) => Some(join(&names)),
        OptionData::Text(text)
            if !text.is_empty()
                && !text.contains(',')
                && !text.contains('\\')
                && text.bytes().all(|b| (0x20..0x7f).contains(&b)) =>
        {
            Some(text)
        }
        _ => None,
    }
}

/// How the export names and types one option.
#[derive(Debug, Clone)]
struct Typing {
    name: String,
    kind: OptionKind,
    array: bool,
}

/// What the options of a configuration need: the definitions they use.
#[derive(Debug, Default)]
pub struct Options {
    defs: Vec<OptionDef>,
    /// Catalog codes without a Kea definition that the export used.
    pub extra: BTreeSet<u8>,
}

impl Options {
    /// The writer over Tenko's custom definitions.
    pub fn new(defs: Vec<OptionDef>) -> Self {
        Self {
            defs,
            extra: BTreeSet::new(),
        }
    }

    fn typing(&mut self, value: &OptionValue) -> Option<Typing> {
        if value.space.is_dhcp4()
            && let Ok(code) = u8::try_from(value.code)
            && let Some(entry) = catalog_v4(code)
        {
            if NOT_IN_KEA.contains(&code) {
                self.extra.insert(code);
            }
            return Some(Typing {
                name: entry.name.to_owned(),
                kind: entry.kind,
                array: entry.array,
            });
        }
        self.defs
            .iter()
            .find(|def| def.space == value.space && def.code == value.code)
            .map(|def| Typing {
                name: def.name.clone(),
                kind: def.kind,
                array: def.array,
            })
    }

    /// One `option-data` entry; `always_send` sets Kea's `always-send`.
    pub fn entry(&mut self, value: &OptionValue, always_send: bool) -> Value {
        let mut out = Map::new();
        out.insert("code".into(), json!(value.code));
        out.insert("space".into(), json!(value.space.as_str()));
        let typing = self.typing(value);
        if let Some(typing) = &typing {
            out.insert("name".into(), json!(typing.name));
        }
        // Kea types option 15 as a domain name, so its text must stay text.
        let text = typing.and_then(|typing| csv(typing.kind, typing.array, &value.data.0));
        if let Some(text) = text {
            out.insert("csv-format".into(), json!(true));
            out.insert("data".into(), json!(text));
        } else {
            out.insert("csv-format".into(), json!(false));
            out.insert("data".into(), json!(hex(&value.data.0)));
        }
        if always_send {
            out.insert("always-send".into(), json!(true));
        }
        Value::Object(out)
    }

    /// The `option-def` list: Tenko's custom definitions, then the catalog codes Kea lacks
    /// that the export used.
    pub fn defs(&self) -> Vec<Value> {
        let mut out: Vec<Value> = self.defs.iter().map(custom_def).collect();
        for code in &self.extra {
            if let Some(entry) = catalog_v4(*code) {
                out.push(catalog_def(entry));
            }
        }
        out
    }
}

fn custom_def(def: &OptionDef) -> Value {
    json!({
        "name": def.name,
        "code": def.code,
        "space": def.space.as_str(),
        "type": kea_type(def.kind),
        "array": def.array,
        "record-types": "",
        "encapsulate": "",
    })
}

fn catalog_def(entry: &CatalogEntry) -> Value {
    json!({
        "name": entry.name,
        "code": entry.code,
        "space": "dhcp4",
        "type": kea_type(entry.kind),
        "array": entry.array,
        "record-types": "",
        "encapsulate": "",
    })
}

/// The first IPv4 address of an option's data.
pub fn first_ipv4(value: &OptionValue) -> Option<std::net::Ipv4Addr> {
    let data = &value.data.0;
    (data.len() >= 4).then(|| std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3]))
}

/// The option's data as text, when it is UTF-8.
pub fn text(value: &OptionValue) -> Option<&str> {
    std::str::from_utf8(&value.data.0).ok()
}

#[cfg(test)]
mod tests {
    use tenko_core::dhcp::OptionSpace;

    use super::*;

    #[test]
    fn values_are_text_where_kea_reads_text() {
        let mut options = Options::new(Vec::new());
        assert_eq!(
            options.entry(
                &OptionValue::v4(6, vec![192, 0, 2, 53, 192, 0, 2, 54]),
                false
            ),
            json!({"code": 6, "space": "dhcp4", "name": "domain-name-servers", "csv-format": true, "data": "192.0.2.53, 192.0.2.54"})
        );
        assert_eq!(
            options.entry(&OptionValue::v4(15, b"example.test".to_vec()), false)["data"],
            json!("example.test")
        );
        assert_eq!(
            options.entry(&OptionValue::v4(26, vec![5, 220]), false)["data"],
            json!("1500")
        );
        // Classless routes go as wire data.
        let routes = options.entry(
            &OptionValue::v4(121, vec![24, 203, 0, 113, 192, 0, 2, 1]),
            true,
        );
        assert_eq!(routes["csv-format"], json!(false));
        assert_eq!(routes["data"], json!("18CB0071C0000201"));
        assert_eq!(routes["always-send"], json!(true));
        // A string with a comma goes as wire data.
        assert_eq!(
            options.entry(&OptionValue::v4(17, b"a,b".to_vec()), false)["data"],
            json!("612C62")
        );
        assert!(options.extra.is_empty());
        options.entry(
            &OptionValue::v4(252, b"http://wpad.example.test/wpad.dat".to_vec()),
            false,
        );
        assert_eq!(options.extra.iter().copied().collect::<Vec<_>>(), [252]);
        assert_eq!(options.defs()[0]["name"], json!("wpad"));
        assert_eq!(options.defs()[0]["type"], json!("string"));
    }

    #[test]
    fn unknown_codes_go_as_hex_without_a_name() {
        let mut options = Options::new(Vec::new());
        let value = OptionValue {
            space: OptionSpace::dhcp4(),
            code: 230,
            data: tenko_core::serde_util::HexBytes(vec![1, 2]),
        };
        assert_eq!(
            options.entry(&value, false),
            json!({"code": 230, "space": "dhcp4", "csv-format": false, "data": "0102"})
        );
    }
}
