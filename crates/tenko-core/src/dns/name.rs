//! DNS names of the zone model: [`DnsName`], [`ScopeName`] and [`Rtype`].
//!
//! [`DnsName`] is not [`Fqdn`](crate::net::Fqdn): a zone needs the owner names that a host
//! name never has (the wildcard label `*`, the RFC 2317 label `0/26`, a single label, the
//! root), while the canonical form is the same (lowercase, without the trailing dot).

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use utoipa::{PartialSchema, ToSchema, openapi::RefOr, openapi::schema::Schema};

use crate::{
    codec::key::{KeyCodec, KeyError, encode_str},
    error::InvalidValue,
    net::Fqdn,
    serde_util::string_schema,
};

/// The longest name in wire form, length octets and the root label included (RFC 1035).
pub const MAX_WIRE_LEN: usize = 255;

/// The longest label (RFC 1035).
pub const MAX_LABEL_LEN: usize = 63;

/// A DNS name in canonical form: lowercase ASCII labels separated by dots, without the
/// trailing dot; the root is `.`.
///
/// A label is 1 to 63 characters from `a-z`, `0-9`, `-`, `_` and `/` (the RFC 2317 form
/// `0/26`); the label `*` is allowed only as the leftmost label (a wildcard, RFC 4592). The
/// wire form, length octets included, is at most 255 octets. Input is trimmed, lowercased
/// and loses one trailing dot.
///
/// Keys encode the labels from the root down, separated by the octet 0x01, which sorts
/// below every label character: `test`, 0x01, `example`, 0x01, `www` for
/// `www.example.test`. A name and every name below it are therefore one contiguous key
/// range that starts at the name's own key ([`DnsName::subtree_prefix`]).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DnsName(String);

/// The text of the root name.
const ROOT: &str = ".";

/// The label separator of the key encoding (below every label character).
const KEY_SEPARATOR: &str = "\u{1}";

/// [`KEY_SEPARATOR`] as a character, for splitting.
const KEY_SEPARATOR_CHAR: char = '\u{1}';

fn check_label(label: &str, leftmost: bool) -> Result<(), &'static str> {
    if label.is_empty() {
        return Err("empty label");
    }
    if label.len() > MAX_LABEL_LEN {
        return Err("label longer than 63 characters");
    }
    if label == "*" {
        return if leftmost {
            Ok(())
        } else {
            Err("the wildcard label `*` is only allowed as the leftmost label")
        };
    }
    if label.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_' || b == b'/'
    }) {
        Ok(())
    } else {
        Err("only letters, digits, `-`, `_`, `/` and a leftmost `*` are allowed")
    }
}

fn check_name(name: &str) -> Result<(), &'static str> {
    if name == ROOT {
        return Ok(());
    }
    if name.is_empty() {
        return Err("empty");
    }
    let mut wire = 1;
    for (index, label) in name.split('.').enumerate() {
        check_label(label, index == 0)?;
        wire += label.len() + 1;
    }
    if wire > MAX_WIRE_LEN {
        return Err("longer than 255 octets in wire form");
    }
    Ok(())
}

impl DnsName {
    /// The root name `.`.
    pub fn root() -> Self {
        Self(ROOT.to_owned())
    }

    /// Validates and normalizes a name.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidValue`] if the syntax is invalid.
    pub fn new(name: &str) -> Result<Self, InvalidValue> {
        let trimmed = name.trim();
        let normalized = if trimmed == ROOT {
            ROOT.to_owned()
        } else {
            trimmed
                .strip_suffix('.')
                .unwrap_or(trimmed)
                .to_ascii_lowercase()
        };
        if normalized == ROOT && trimmed != ROOT {
            return Err(InvalidValue::new("DNS name", name, "empty label"));
        }
        check_name(&normalized).map_err(|reason| InvalidValue::new("DNS name", name, reason))?;
        Ok(Self(normalized))
    }

    /// The canonical text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the root name.
    pub fn is_root(&self) -> bool {
        self.0 == ROOT
    }

    /// The labels, leftmost first; none for the root.
    pub fn labels(&self) -> impl DoubleEndedIterator<Item = &str> {
        let text = if self.is_root() { "" } else { self.0.as_str() };
        text.split('.').filter(|label| !label.is_empty())
    }

    /// The number of labels, the root not counted (RFC 4034 counts the same way).
    pub fn label_count(&self) -> usize {
        self.labels().count()
    }

    /// Whether the leftmost label is `*`.
    pub fn is_wildcard(&self) -> bool {
        self.0 == "*" || self.0.starts_with("*.")
    }

    /// The name without its leftmost label; `None` for the root.
    pub fn parent(&self) -> Option<DnsName> {
        if self.is_root() {
            return None;
        }
        Some(match self.0.split_once('.') {
            Some((_, rest)) => Self(rest.to_owned()),
            None => Self::root(),
        })
    }

    /// Whether `self` is `zone` or below it.
    pub fn is_subdomain_of(&self, zone: &DnsName) -> bool {
        if zone.is_root() || self == zone {
            return true;
        }
        self.0.len() > zone.0.len()
            && self.0.ends_with(zone.as_str())
            && self.0.as_bytes()[self.0.len() - zone.0.len() - 1] == b'.'
    }

    /// The name with one more label in front.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidValue`] if the result is not a valid name.
    pub fn child(&self, label: &str) -> Result<DnsName, InvalidValue> {
        if self.is_root() {
            Self::new(label)
        } else {
            Self::new(&format!("{label}.{}", self.0))
        }
    }

    /// The length of the wire form, length octets and root label included.
    pub fn wire_len(&self) -> usize {
        self.labels().map(|label| label.len() + 1).sum::<usize>() + 1
    }

    /// Appends the uncompressed wire form.
    pub fn write_wire(&self, out: &mut Vec<u8>) {
        for label in self.labels() {
            // Labels are at most 63 octets (checked on construction).
            out.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }

    /// The uncompressed wire form.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire_len());
        self.write_wire(&mut out);
        out
    }

    /// Reads an uncompressed name from the front of `wire` and returns it with the number
    /// of octets it took. Upper-case letters are lowercased.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidValue`] for a compression pointer, a truncated name or a label
    /// outside the allowed characters.
    pub fn from_wire(wire: &[u8]) -> Result<(DnsName, usize), InvalidValue> {
        let invalid =
            |reason| InvalidValue::new("DNS name in wire form", &hex_prefix(wire), reason);
        let mut text = String::new();
        let mut pos = 0;
        loop {
            let Some(&len) = wire.get(pos) else {
                return Err(invalid("truncated name"));
            };
            pos += 1;
            if len == 0 {
                break;
            }
            if len & 0xc0 != 0 {
                return Err(invalid(
                    "compression pointers are not allowed in stored data",
                ));
            }
            let len = usize::from(len);
            let Some(label) = wire.get(pos..pos + len) else {
                return Err(invalid("truncated label"));
            };
            pos += len;
            if !text.is_empty() {
                text.push('.');
            }
            for &byte in label {
                if !byte.is_ascii_graphic() || byte == b'.' {
                    return Err(invalid(
                        "a label holds an octet outside the allowed characters",
                    ));
                }
                text.push(char::from(byte.to_ascii_lowercase()));
            }
            if pos > MAX_WIRE_LEN {
                return Err(invalid("longer than 255 octets in wire form"));
            }
        }
        if text.is_empty() {
            return Ok((Self::root(), pos));
        }
        check_name(&text).map_err(|reason| InvalidValue::new("DNS name", &text, reason))?;
        Ok((Self(text), pos))
    }

    /// The name from a host's FQDN (which is always a valid DNS name).
    pub fn from_fqdn(fqdn: &Fqdn) -> Self {
        Self(fqdn.as_str().to_owned())
    }

    /// The labels from the root down, joined by [`KEY_SEPARATOR`]: the text of the key
    /// encoding.
    fn reversed(&self) -> String {
        let labels: Vec<&str> = self.labels().rev().collect();
        labels.join(KEY_SEPARATOR)
    }

    /// The key text shared by every name strictly below this one. A scan from the name's
    /// own key to the successor of the encoded prefix covers the name and its subtree.
    pub fn subtree_prefix(&self) -> Vec<u8> {
        let mut out = self.reversed().into_bytes();
        if !self.is_root() {
            out.extend_from_slice(KEY_SEPARATOR.as_bytes());
        }
        out
    }
}

fn hex_prefix(wire: &[u8]) -> String {
    crate::serde_util::to_hex(&wire[..wire.len().min(32)])
}

impl fmt::Debug for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DnsName({:?})", self.0)
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for DnsName {
    type Err = InvalidValue;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<String> for DnsName {
    type Error = InvalidValue;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<DnsName> for String {
    fn from(name: DnsName) -> Self {
        name.0
    }
}

impl From<&Fqdn> for DnsName {
    fn from(fqdn: &Fqdn) -> Self {
        Self::from_fqdn(fqdn)
    }
}

impl PartialSchema for DnsName {
    fn schema() -> RefOr<Schema> {
        string_schema(
            "DNS name in canonical form: lowercase, without the trailing dot, `.` for the root \
             (`www.example.test`, `*.example.test`, `0/26.2.0.192.in-addr.arpa`)",
        )
    }
}

impl ToSchema for DnsName {}

impl KeyCodec for DnsName {
    fn encode_key(&self, out: &mut Vec<u8>) {
        encode_str(&self.reversed(), out);
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        let reversed = String::decode_key(input)?;
        if reversed.is_empty() {
            return Ok(Self::root());
        }
        let labels: Vec<&str> = reversed.split(KEY_SEPARATOR_CHAR).rev().collect();
        Self::new(&labels.join(".")).map_err(|_| KeyError::Invalid("DNS name"))
    }
}

/// The name of a zone scope (DNS-20): 1 to 63 characters from `a-z`, `0-9`, `-` and `_`,
/// starting with a letter or digit. Every zone has the scope [`ScopeName::DEFAULT`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ScopeName(std::borrow::Cow<'static, str>);

impl ScopeName {
    /// The scope every zone has and every query uses without a view that says otherwise.
    pub const DEFAULT: ScopeName = ScopeName(std::borrow::Cow::Borrowed("default"));

    /// Validates a scope name.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidValue`] if the name breaks the pattern.
    pub fn new(name: &str) -> Result<Self, InvalidValue> {
        let valid = (1..=MAX_LABEL_LEN).contains(&name.len())
            && name
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if valid {
            Ok(Self(std::borrow::Cow::Owned(name.to_owned())))
        } else {
            Err(InvalidValue::new(
                "zone scope",
                name,
                "must match [a-z0-9][a-z0-9_-]{0,62}",
            ))
        }
    }

    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ScopeName {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Debug for ScopeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ScopeName({:?})", self.as_str())
    }
}

impl fmt::Display for ScopeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ScopeName {
    type Err = InvalidValue;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<String> for ScopeName {
    type Error = InvalidValue;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<ScopeName> for String {
    fn from(name: ScopeName) -> Self {
        name.0.into_owned()
    }
}

impl PartialSchema for ScopeName {
    fn schema() -> RefOr<Schema> {
        string_schema("Zone scope name ([a-z0-9][a-z0-9_-]{0,62}); `default` for the default scope")
    }
}

impl ToSchema for ScopeName {}

impl KeyCodec for ScopeName {
    fn encode_key(&self, out: &mut Vec<u8>) {
        encode_str(self.as_str(), out);
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        Self::new(&String::decode_key(input)?).map_err(|_| KeyError::Invalid("zone scope"))
    }
}

/// A resource record type (RFC 1035 and later): the 16-bit value, written as its mnemonic
/// (`AAAA`) or in the RFC 3597 form (`TYPE65280`) for a type without one.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rtype(pub u16);

macro_rules! rtypes {
    ($($(#[$meta:meta])* $name:ident = $value:literal),+ $(,)?) => {
        impl Rtype {
            $($(#[$meta])* pub const $name: Rtype = Rtype($value);)+

            /// The mnemonic of a known type.
            pub const fn mnemonic(self) -> Option<&'static str> {
                match self.0 {
                    $($value => Some(stringify!($name)),)+
                    _ => None,
                }
            }

            /// The type of a mnemonic (case-insensitive).
            fn from_mnemonic(text: &str) -> Option<Rtype> {
                $(if text.eq_ignore_ascii_case(stringify!($name)) {
                    return Some(Rtype($value));
                })+
                None
            }
        }
    };
}

rtypes! {
    /// IPv4 address (RFC 1035).
    A = 1,
    /// Authoritative name server (RFC 1035).
    NS = 2,
    /// Canonical name (RFC 1035).
    CNAME = 5,
    /// Start of authority (RFC 1035).
    SOA = 6,
    /// Domain name pointer (RFC 1035).
    PTR = 12,
    /// Host information (RFC 1035, RFC 8482).
    HINFO = 13,
    /// Mail exchange (RFC 1035).
    MX = 15,
    /// Text strings (RFC 1035).
    TXT = 16,
    /// IPv6 address (RFC 3596).
    AAAA = 28,
    /// Service location (RFC 2782).
    SRV = 33,
    /// Naming authority pointer (RFC 3403).
    NAPTR = 35,
    /// Delegation name (RFC 6672).
    DNAME = 39,
    /// EDNS(0) pseudo-record (RFC 6891).
    OPT = 41,
    /// Delegation signer (RFC 4034).
    DS = 43,
    /// SSH key fingerprint (RFC 4255).
    SSHFP = 44,
    /// Resource record signature (RFC 4034).
    RRSIG = 46,
    /// Next secure record (RFC 4034).
    NSEC = 47,
    /// DNS public key (RFC 4034).
    DNSKEY = 48,
    /// Hashed next secure record (RFC 5155).
    NSEC3 = 50,
    /// NSEC3 parameters (RFC 5155).
    NSEC3PARAM = 51,
    /// TLS association (RFC 6698).
    TLSA = 52,
    /// Child DS (RFC 7344).
    CDS = 59,
    /// Child DNSKEY (RFC 7344).
    CDNSKEY = 60,
    /// Service binding (RFC 9460).
    SVCB = 64,
    /// HTTPS service binding (RFC 9460).
    HTTPS = 65,
    /// Transaction key (RFC 2930).
    TKEY = 249,
    /// Transaction signature (RFC 8945).
    TSIG = 250,
    /// Incremental zone transfer (RFC 1995).
    IXFR = 251,
    /// Full zone transfer (RFC 5936).
    AXFR = 252,
    /// Mailbox-related records (RFC 1035).
    MAILB = 253,
    /// Mail agent records (RFC 1035).
    MAILA = 254,
    /// Any type (RFC 1035, RFC 8482).
    ANY = 255,
    /// Certification authority authorization (RFC 8659).
    CAA = 257,
}

impl Rtype {
    /// Whether the type is a meta type or a query type (OPT, TKEY, TSIG, IXFR, AXFR, MAILB,
    /// MAILA, ANY): such a type never appears in zone data.
    pub const fn is_meta(self) -> bool {
        matches!(self.0, 41 | 128..=255)
    }
}

impl fmt::Display for Rtype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.mnemonic() {
            Some(mnemonic) => f.write_str(mnemonic),
            None => write!(f, "TYPE{}", self.0),
        }
    }
}

impl fmt::Debug for Rtype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rtype({self})")
    }
}

impl FromStr for Rtype {
    type Err = InvalidValue;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let text = s.trim();
        if let Some(rtype) = Self::from_mnemonic(text) {
            return Ok(rtype);
        }
        text.get(..4)
            .filter(|prefix| prefix.eq_ignore_ascii_case("TYPE"))
            .and_then(|_| text[4..].parse::<u16>().ok())
            .map(Rtype)
            .ok_or_else(|| InvalidValue::new("record type", s, "not a mnemonic or TYPEnnn"))
    }
}

impl Serialize for Rtype {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Rtype {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

impl PartialSchema for Rtype {
    fn schema() -> RefOr<Schema> {
        string_schema("Record type: a mnemonic (`AAAA`) or the RFC 3597 form (`TYPE65280`)")
    }
}

impl ToSchema for Rtype {}

impl KeyCodec for Rtype {
    fn encode_key(&self, out: &mut Vec<u8>) {
        self.0.encode_key(out);
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        u16::decode_key(input).map(Rtype)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode_key, encode_key, from_cbor, to_cbor};

    #[test]
    fn names_normalize_and_validate() {
        let name = DnsName::new(" WWW.Example.Test. ").expect("valid");
        assert_eq!(name.as_str(), "www.example.test");
        assert_eq!(DnsName::new(".").expect("root"), DnsName::root());
        for valid in [
            "test",
            "*.example.test",
            "_ldap._tcp.example.test",
            "0/26.2.0.192.in-addr.arpa",
            "-odd-.example.test",
        ] {
            assert!(DnsName::new(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "a..b",
            "a.*.b",
            "a b.test",
            "ä.test",
            "..",
            &format!("{}.test", "a".repeat(64)),
            &[["a".repeat(63)].as_slice(); 4].concat().join("."),
        ] {
            assert!(DnsName::new(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn names_know_their_place() {
        let zone = DnsName::new("example.test").expect("zone");
        let www = DnsName::new("www.example.test").expect("www");
        let other = DnsName::new("wwwexample.test").expect("other");
        assert!(www.is_subdomain_of(&zone));
        assert!(zone.is_subdomain_of(&zone));
        assert!(!other.is_subdomain_of(&zone));
        assert!(www.is_subdomain_of(&DnsName::root()));
        assert_eq!(www.parent(), Some(zone.clone()));
        assert_eq!(
            DnsName::new("test").expect("tld").parent(),
            Some(DnsName::root())
        );
        assert_eq!(DnsName::root().parent(), None);
        assert_eq!(
            zone.child("*").expect("wildcard").as_str(),
            "*.example.test"
        );
        assert!(zone.child("*").expect("wildcard").is_wildcard());
        assert_eq!(www.label_count(), 3);
        assert_eq!(DnsName::root().label_count(), 0);
    }

    #[test]
    fn names_round_trip_through_wire_json_cbor_and_keys() {
        let name = DnsName::new("Mail.Example.Test").expect("name");
        let wire = name.to_wire();
        assert_eq!(wire, b"\x04mail\x07example\x04test\x00");
        assert_eq!(wire.len(), name.wire_len());
        assert_eq!(
            DnsName::from_wire(b"\x04MAIL\x07example\x04test\x00rest"),
            Ok((name.clone(), wire.len()))
        );
        assert!(DnsName::from_wire(b"\x04mail\xc0\x0c").is_err());
        assert!(DnsName::from_wire(b"\x04ma").is_err());
        assert_eq!(DnsName::from_wire(b"\x00"), Ok((DnsName::root(), 1)));
        let json = serde_json::to_string(&name).expect("json");
        assert_eq!(json, "\"mail.example.test\"");
        assert_eq!(serde_json::from_str::<DnsName>(&json).expect("json"), name);
        assert_eq!(
            from_cbor::<DnsName>(&to_cbor(&name).expect("cbor")).expect("cbor"),
            name
        );
        for text in [".", "test", "example.test", "a.example.test"] {
            let name = DnsName::new(text).expect("name");
            assert_eq!(decode_key::<DnsName>(&encode_key(&name)), Ok(name));
        }
    }

    #[test]
    fn subtree_keys_are_contiguous() {
        let key = |text: &str| encode_key(&DnsName::new(text).expect("name"));
        let zone = key("example.test");
        // The apex, then its subtree, then the siblings that share its text as a prefix.
        let ordered = [
            "example.test",
            "a.example.test",
            "b.a.example.test",
            "z.example.test",
            "example-a.test",
            "example2.test",
        ];
        for pair in ordered.windows(2) {
            assert!(key(pair[0]) < key(pair[1]), "{pair:?}");
        }
        assert!(zone.starts_with(b"test"));
        assert!(key(".") < key("arpa"));
        let prefix = DnsName::new("example.test").expect("zone").subtree_prefix();
        assert!(key("a.example.test").starts_with(&prefix));
        assert!(!key("example-a.test").starts_with(&prefix));
    }

    #[test]
    fn scope_names_validate() {
        assert_eq!(ScopeName::default().as_str(), "default");
        assert!(ScopeName::new("internal-2").is_ok());
        assert!(ScopeName::new("_x").is_err());
        assert!(ScopeName::new("Internal").is_err());
        assert!(ScopeName::new("").is_err());
        let scope = ScopeName::new("lab").expect("scope");
        assert_eq!(decode_key::<ScopeName>(&encode_key(&scope)), Ok(scope));
    }

    #[test]
    fn rtypes_print_and_parse() {
        assert_eq!(Rtype::AAAA.to_string(), "AAAA");
        assert_eq!(Rtype(65280).to_string(), "TYPE65280");
        assert_eq!("aaaa".parse::<Rtype>(), Ok(Rtype::AAAA));
        assert_eq!("type65280".parse::<Rtype>(), Ok(Rtype(65280)));
        assert_eq!("TYPE1".parse::<Rtype>(), Ok(Rtype::A));
        assert!("NOPE".parse::<Rtype>().is_err());
        assert!("TYPE70000".parse::<Rtype>().is_err());
        assert!(Rtype::ANY.is_meta() && Rtype::OPT.is_meta() && Rtype::TSIG.is_meta());
        assert!(!Rtype::CAA.is_meta() && !Rtype::A.is_meta());
        assert_eq!(serde_json::to_string(&Rtype::SRV).expect("json"), "\"SRV\"");
        assert_eq!(
            serde_json::from_str::<Rtype>("\"TYPE99\"").expect("json"),
            Rtype(99)
        );
    }
}
