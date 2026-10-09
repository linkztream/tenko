//! Network value types: MAC addresses, DNS names, host names and DHCPv6 DUIDs.
//!
//! IP addresses and prefixes use `std::net::IpAddr` and `ipnet::IpNet` directly.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utoipa::{PartialSchema, ToSchema, openapi::RefOr, openapi::schema::Schema};

use crate::{
    codec::key::{KeyCodec, KeyError, encode_str},
    error::InvalidValue,
    serde_util::{
        deserialize_bytes_or_hex, from_hex, serialize_bytes_or_hex, string_schema, to_hex,
    },
};

/// An EUI-48 MAC address.
///
/// A transparent newtype over [`macaddr::MacAddr6`] that adds the encodings Tenko needs:
/// lowercase colon-separated text (`00:00:5e:00:53:01`) in JSON, six bytes in CBOR and in
/// keys. Parsing accepts colons, hyphens, Cisco dots or no separators, in either case.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MacAddr(pub macaddr::MacAddr6);

impl MacAddr {
    /// Creates an address from its six octets.
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(macaddr::MacAddr6::new(
            octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
        ))
    }

    /// The six octets.
    pub fn octets(self) -> [u8; 6] {
        self.0.into_array()
    }
}

impl From<macaddr::MacAddr6> for MacAddr {
    fn from(mac: macaddr::MacAddr6) -> Self {
        Self(mac)
    }
}

impl From<MacAddr> for macaddr::MacAddr6 {
    fn from(mac: MacAddr) -> Self {
        mac.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = self.octets();
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            o[0], o[1], o[2], o[3], o[4], o[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({self})")
    }
}

impl FromStr for MacAddr {
    type Err = InvalidValue;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = from_hex(s.trim())
            .ok_or_else(|| InvalidValue::new("MAC address", s, "not hexadecimal"))?;
        let octets: [u8; 6] = bytes
            .try_into()
            .map_err(|_| InvalidValue::new("MAC address", s, "must have six octets"))?;
        Ok(Self::new(octets))
    }
}

impl Serialize for MacAddr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            serializer.serialize_bytes(&self.octets())
        }
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = deserialize_bytes_or_hex(deserializer, "MAC address")?;
        let octets: [u8; 6] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("a MAC address has six octets"))?;
        Ok(Self::new(octets))
    }
}

impl PartialSchema for MacAddr {
    fn schema() -> RefOr<Schema> {
        string_schema("MAC address, lowercase and colon-separated (00:00:5e:00:53:01)")
    }
}

impl ToSchema for MacAddr {}

impl KeyCodec for MacAddr {
    fn encode_key(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.octets());
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        if input.len() < 6 {
            return Err(KeyError::Truncated);
        }
        let (head, tail) = input.split_at(6);
        *input = tail;
        let mut octets = [0u8; 6];
        octets.copy_from_slice(head);
        Ok(Self::new(octets))
    }
}

/// Checks DNS name syntax: dot-separated labels of 1 to 63 characters from `a-z`, `0-9`,
/// `-` and `_` (underscore for service labels), no label starting or ending with `-`, at
/// most 253 characters. The input must already be lowercase without a trailing dot.
fn check_dns_name(name: &str, min_labels: usize) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("empty");
    }
    if name.len() > 253 {
        return Err("longer than 253 characters");
    }
    let mut labels = 0;
    for label in name.split('.') {
        labels += 1;
        if label.is_empty() {
            return Err("empty label");
        }
        if label.len() > 63 {
            return Err("label longer than 63 characters");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("label starts or ends with a hyphen");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err("only letters, digits, hyphens and underscores are allowed");
        }
    }
    if labels < min_labels {
        return Err("needs at least two labels");
    }
    Ok(())
}

macro_rules! dns_name_type {
    ($(#[$meta:meta])* $name:ident, $what:literal, $min_labels:literal) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Validates and normalizes a name: lowercase, without a trailing dot.
            ///
            /// # Errors
            ///
            /// Returns [`InvalidValue`] if the syntax is invalid.
            pub fn new(name: &str) -> Result<Self, InvalidValue> {
                let normalized = name.trim();
                let normalized = normalized.strip_suffix('.').unwrap_or(normalized);
                let normalized = normalized.to_ascii_lowercase();
                check_dns_name(&normalized, $min_labels)
                    .map_err(|reason| InvalidValue::new($what, name, reason))?;
                Ok(Self(normalized))
            }

            /// The normalized name.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({:?})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = InvalidValue;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }

        impl TryFrom<String> for $name {
            type Error = InvalidValue;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(&value)
            }
        }

        impl From<$name> for String {
            fn from(name: $name) -> Self {
                name.0
            }
        }

        impl PartialSchema for $name {
            fn schema() -> RefOr<Schema> {
                string_schema($what)
            }
        }

        impl ToSchema for $name {}

        impl KeyCodec for $name {
            fn encode_key(&self, out: &mut Vec<u8>) {
                encode_str(&self.0, out);
            }
            fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
                let text = String::decode_key(input)?;
                Self::new(&text).map_err(|_| KeyError::Invalid($what))
            }
        }
    };
}

dns_name_type! {
    /// A fully qualified DNS name with at least two labels, normalized to lowercase without
    /// the trailing dot (`printer.example.test`).
    Fqdn, "DNS name", 2
}

dns_name_type! {
    /// The name of a host: one or more DNS labels, normalized to lowercase (`nas01` or
    /// `nas01.example.test`). Free text belongs in the description.
    HostName, "host name", 1
}

/// A DHCPv6 DUID (RFC 8415): 2 to 130 bytes, hexadecimal text in JSON.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duid(Vec<u8>);

impl Duid {
    /// Validates a DUID.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidValue`] if the length is outside 2 to 130 bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, InvalidValue> {
        if (2..=130).contains(&bytes.len()) {
            Ok(Self(bytes))
        } else {
            Err(InvalidValue::new(
                "DUID",
                &to_hex(&bytes),
                "must be 2 to 130 bytes",
            ))
        }
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Duid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(":")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Duid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Duid({self})")
    }
}

impl FromStr for Duid {
    type Err = InvalidValue;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes =
            from_hex(s.trim()).ok_or_else(|| InvalidValue::new("DUID", s, "not hexadecimal"))?;
        Self::new(bytes)
    }
}

impl Serialize for Duid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_bytes_or_hex(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Duid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = deserialize_bytes_or_hex(deserializer, "DUID")?;
        Self::new(bytes).map_err(serde::de::Error::custom)
    }
}

impl PartialSchema for Duid {
    fn schema() -> RefOr<Schema> {
        string_schema("DHCPv6 DUID as lowercase hexadecimal")
    }
}

impl ToSchema for Duid {}

impl KeyCodec for Duid {
    fn encode_key(&self, out: &mut Vec<u8>) {
        self.0.encode_key(out);
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        Self::new(Vec::<u8>::decode_key(input)?).map_err(|_| KeyError::Invalid("DUID length"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode_key, encode_key, from_cbor, to_cbor};

    #[test]
    fn mac_parses_common_notations() {
        let expected = MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]);
        for text in [
            "00:00:5e:00:53:01",
            "00-00-5E-00-53-01",
            "0000.5e00.5301",
            "00005E005301",
        ] {
            assert_eq!(text.parse::<MacAddr>(), Ok(expected), "{text}");
        }
        assert_eq!(expected.to_string(), "00:00:5e:00:53:01");
        assert!("00:00:5e:00:53".parse::<MacAddr>().is_err());
    }

    #[test]
    fn mac_encodings() {
        let mac: MacAddr = "00:00:5e:00:53:ff".parse().expect("mac");
        assert_eq!(
            serde_json::to_string(&mac).expect("json"),
            "\"00:00:5e:00:53:ff\""
        );
        let cbor = to_cbor(&mac).expect("cbor");
        assert_eq!(cbor.len(), 7);
        assert_eq!(from_cbor::<MacAddr>(&cbor).expect("cbor"), mac);
        assert_eq!(decode_key::<MacAddr>(&encode_key(&mac)), Ok(mac));
        let low: MacAddr = "00:00:5e:00:53:00".parse().expect("mac");
        assert!(low < mac && encode_key(&low) < encode_key(&mac));
    }

    #[test]
    fn dns_names_normalize_and_validate() {
        let name = Fqdn::new("Printer.Example.Test.").expect("valid");
        assert_eq!(name.as_str(), "printer.example.test");
        assert!(Fqdn::new("_ldap._tcp.example.test").is_ok());
        assert!(Fqdn::new("printer").is_err());
        assert!(Fqdn::new("-bad.example.test").is_err());
        assert!(Fqdn::new("a..example.test").is_err());
        assert!(Fqdn::new(&format!("{}.example.test", "a".repeat(64))).is_err());
        assert!(HostName::new("NAS01").is_ok());
        assert!(HostName::new("living room tv").is_err());
        let json = serde_json::to_string(&name).expect("json");
        assert_eq!(serde_json::from_str::<Fqdn>(&json).expect("json"), name);
        assert!(serde_json::from_str::<Fqdn>("\"x\"").is_err());
    }

    #[test]
    fn duid_encodings() {
        let duid: Duid = "00:01:00:01:2a:2b:2c:2d:00:00:5e:00:53:01"
            .parse()
            .expect("duid");
        assert_eq!(
            duid.to_string(),
            "00:01:00:01:2a:2b:2c:2d:00:00:5e:00:53:01"
        );
        let json = serde_json::to_string(&duid).expect("json");
        assert_eq!(json, "\"000100012a2b2c2d00005e005301\"");
        assert_eq!(serde_json::from_str::<Duid>(&json).expect("json"), duid);
        assert_eq!(
            from_cbor::<Duid>(&to_cbor(&duid).expect("cbor")).expect("cbor"),
            duid
        );
        assert!(Duid::new(vec![1]).is_err());
    }
}
