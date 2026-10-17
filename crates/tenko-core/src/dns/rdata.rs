//! Record data: [`Rdata`] is the stored wire form, [`RecordData`] the typed view.
//!
//! Zone data is stored as the uncompressed wire form of each record's data, so that the
//! engine copies it into answers without a conversion and an unknown type round-trips as
//! RFC 3597 bytes. [`RecordData`] reads and writes the wire form of the types the model
//! knows: A, AAAA, CNAME, DNAME, MX, NS, PTR, SOA, SRV, TXT, CAA, DS, DNSKEY, RRSIG, NSEC,
//! NSEC3, NSEC3PARAM, TLSA, SVCB and HTTPS; every other type is
//! [`RecordData::Unknown`]. Names inside record data are stored lowercase and
//! uncompressed (the canonical form of RFC 4034, section 6.2); the codec compresses the
//! RFC 1035 types when it writes an answer.
//!
//! Text (TXT strings, the CAA value) is shown as a string; octets that are not printable
//! UTF-8 are written `\DDD` (decimal) and a backslash as `\\`, as in a zone file. A TXT
//! string longer than 255 octets on input is split into strings of at most 255 octets at
//! character boundaries (DNS-24).

use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utoipa::{PartialSchema, ToSchema, openapi::RefOr, openapi::schema::Schema};

use super::name::{DnsName, Rtype};
use crate::{
    error::InvalidValue,
    serde_util::{
        HexBytes, deserialize_bytes_or_hex, serialize_bytes_or_hex, string_schema, to_hex,
    },
};

/// The longest record data (RDLENGTH is 16 bits).
pub const MAX_RDATA_LEN: usize = 65_535;

/// The longest character-string (RFC 1035, section 3.3).
pub const MAX_CHARSTRING_LEN: usize = 255;

/// The record data of one record in uncompressed wire form: a byte string in CBOR,
/// lowercase hexadecimal in JSON.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rdata(Bytes);

impl Rdata {
    /// Wire bytes checked against the type: a known type must decode, every type must fit
    /// in 65,535 octets. The bytes of a known type are rewritten in canonical form (names
    /// lowercase).
    ///
    /// # Errors
    ///
    /// Returns [`InvalidValue`] when the bytes are not valid data of `rtype`.
    pub fn from_wire(rtype: Rtype, wire: &[u8]) -> Result<Self, InvalidValue> {
        Ok(Self::from_data(&RecordData::from_wire(rtype, wire)?))
    }

    /// The wire form of typed data.
    pub fn from_data(data: &RecordData) -> Self {
        let mut out = Vec::new();
        data.write_wire(&mut out);
        Self(Bytes::from(out))
    }

    /// The wire bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The wire bytes as a shared buffer.
    pub fn bytes(&self) -> &Bytes {
        &self.0
    }

    /// The typed view.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidValue`] when the stored bytes are not valid data of `rtype`.
    pub fn decode(&self, rtype: Rtype) -> Result<RecordData, InvalidValue> {
        RecordData::from_wire(rtype, &self.0)
    }
}

impl fmt::Debug for Rdata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rdata({})", to_hex(&self.0))
    }
}

impl Serialize for Rdata {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_bytes_or_hex(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Rdata {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = deserialize_bytes_or_hex(deserializer, "record data")?;
        if bytes.len() > MAX_RDATA_LEN {
            return Err(serde::de::Error::custom(
                "record data longer than 65535 octets",
            ));
        }
        Ok(Self(Bytes::from(bytes)))
    }
}

impl PartialSchema for Rdata {
    fn schema() -> RefOr<Schema> {
        string_schema("Record data in uncompressed wire form, lowercase hexadecimal")
    }
}

impl ToSchema for Rdata {}

/// Octets shown as text: printable UTF-8 as it is, other octets as `\DDD`, a backslash
/// as `\\`.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TextBytes(pub Vec<u8>);

impl TextBytes {
    /// The octets of a text.
    pub fn from_text(text: &str) -> Self {
        Self(text.as_bytes().to_vec())
    }

    /// Parses the escaped presentation form.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidValue`] for a malformed escape.
    pub fn parse(text: &str) -> Result<Self, InvalidValue> {
        let mut out = Vec::with_capacity(text.len());
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                continue;
            }
            let Some(next) = chars.next() else {
                return Err(InvalidValue::new(
                    "text",
                    text,
                    "ends with a lone backslash",
                ));
            };
            if next.is_ascii_digit() {
                let digits: String = [Some(next), chars.next(), chars.next()]
                    .into_iter()
                    .flatten()
                    .collect();
                let value = (digits.len() == 3 && digits.bytes().all(|b| b.is_ascii_digit()))
                    .then(|| digits.parse::<u16>().ok())
                    .flatten()
                    .and_then(|value| u8::try_from(value).ok())
                    .ok_or_else(|| {
                        InvalidValue::new("text", text, "`\\DDD` needs three digits up to 255")
                    })?;
                out.push(value);
            } else {
                let mut buf = [0u8; 4];
                out.extend_from_slice(next.encode_utf8(&mut buf).as_bytes());
            }
        }
        Ok(Self(out))
    }

    /// The octets.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for TextBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.utf8_chunks() {
            for c in chunk.valid().chars() {
                if c == '\\' {
                    f.write_str("\\\\")?;
                } else if c.is_control() {
                    let mut buf = [0u8; 4];
                    for byte in c.encode_utf8(&mut buf).as_bytes() {
                        write!(f, "\\{byte:03}")?;
                    }
                } else {
                    write!(f, "{c}")?;
                }
            }
            for byte in chunk.invalid() {
                write!(f, "\\{byte:03}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for TextBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TextBytes({:?})", self.to_string())
    }
}

impl Serialize for TextBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for TextBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

impl PartialSchema for TextBytes {
    fn schema() -> RefOr<Schema> {
        string_schema(
            "Text; octets that are not printable UTF-8 are written \\DDD (decimal), a backslash \\\\",
        )
    }
}

impl ToSchema for TextBytes {}

/// Splits octets into character-strings of at most 255 octets (DNS-24). A cut never falls
/// inside a UTF-8 sequence unless the input has no character boundary within 255 octets.
/// Empty input gives one empty string.
pub fn split_txt(bytes: &[u8]) -> Vec<TextBytes> {
    if bytes.is_empty() {
        return vec![TextBytes::default()];
    }
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let mut end = rest.len().min(MAX_CHARSTRING_LEN);
        if end < rest.len() {
            let mut boundary = end;
            while boundary > 0 && rest[boundary] & 0xc0 == 0x80 {
                boundary -= 1;
            }
            if boundary > 0 {
                end = boundary;
            }
        }
        out.push(TextBytes(rest[..end].to_vec()));
        rest = &rest[end..];
    }
    out
}

/// Deserializes TXT strings and splits every one longer than 255 octets (DNS-24).
fn deserialize_txt<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<TextBytes>, D::Error> {
    let strings = Vec::<TextBytes>::deserialize(deserializer)?;
    if strings.is_empty() {
        return Err(serde::de::Error::custom(
            "a TXT record has at least one string",
        ));
    }
    Ok(strings
        .into_iter()
        .flat_map(|string| {
            if string.0.len() > MAX_CHARSTRING_LEN {
                split_txt(&string.0)
            } else {
                vec![string]
            }
        })
        .collect())
}

/// One parameter of an SVCB or HTTPS record (RFC 9460): the key and its value in wire form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct SvcParam {
    /// The parameter key (`1` alpn, `3` port, `4` ipv4hint, ...).
    pub key: u16,
    /// The value in wire form.
    pub value: HexBytes,
}

/// Typed record data of the types the model knows, and RFC 3597 data of every other type.
///
/// Serialized with the record type in `type`: `{"type": "MX", "preference": 10,
/// "exchange": "mail.example.test"}`. Binary fields (digests, keys, signatures, salts,
/// hashes, parameter values) are lowercase hexadecimal.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type")]
pub enum RecordData {
    /// An IPv4 address.
    A {
        /// The address.
        #[schema(value_type = String, example = "192.0.2.10")]
        address: Ipv4Addr,
    },
    /// An IPv6 address.
    #[serde(rename = "AAAA")]
    Aaaa {
        /// The address.
        #[schema(value_type = String, example = "2001:db8::10")]
        address: Ipv6Addr,
    },
    /// A canonical name.
    #[serde(rename = "CNAME")]
    Cname {
        /// The canonical name.
        target: DnsName,
    },
    /// A delegation of a subtree to another name.
    #[serde(rename = "DNAME")]
    Dname {
        /// The target of the subtree.
        target: DnsName,
    },
    /// A mail exchange.
    #[serde(rename = "MX")]
    Mx {
        /// The preference, lower first.
        preference: u16,
        /// The exchange.
        exchange: DnsName,
    },
    /// A name server.
    #[serde(rename = "NS")]
    Ns {
        /// The server's name.
        host: DnsName,
    },
    /// A pointer.
    #[serde(rename = "PTR")]
    Ptr {
        /// The name pointed to.
        target: DnsName,
    },
    /// The start of authority.
    #[serde(rename = "SOA")]
    Soa {
        /// The primary name server.
        mname: DnsName,
        /// The mailbox of the responsible person, as a name.
        rname: DnsName,
        /// The serial.
        serial: u32,
        /// Refresh interval in seconds.
        refresh: u32,
        /// Retry interval in seconds.
        retry: u32,
        /// Expiry in seconds.
        expire: u32,
        /// TTL of negative answers in seconds (RFC 2308).
        minimum: u32,
    },
    /// A service location.
    #[serde(rename = "SRV")]
    Srv {
        /// The priority, lower first.
        priority: u16,
        /// The weight among equal priorities.
        weight: u16,
        /// The port.
        port: u16,
        /// The host.
        target: DnsName,
    },
    /// Text strings.
    #[serde(rename = "TXT")]
    Txt {
        /// The strings, at most 255 octets each; longer input is split (DNS-24).
        #[serde(deserialize_with = "deserialize_txt")]
        #[schema(value_type = Vec<String>)]
        strings: Vec<TextBytes>,
    },
    /// A certification authority authorization.
    #[serde(rename = "CAA")]
    Caa {
        /// The flags (128: issuer critical).
        flags: u8,
        /// The property tag (`issue`, `issuewild`, `iodef`), 1 to 15 letters or digits.
        tag: String,
        /// The property value.
        #[schema(value_type = String)]
        value: TextBytes,
    },
    /// A delegation signer.
    #[serde(rename = "DS")]
    Ds {
        /// The key tag.
        key_tag: u16,
        /// The key algorithm.
        algorithm: u8,
        /// The digest type.
        digest_type: u8,
        /// The digest.
        digest: HexBytes,
    },
    /// A DNSSEC public key.
    #[serde(rename = "DNSKEY")]
    Dnskey {
        /// The flags (256: zone key, 257: zone key and secure entry point).
        flags: u16,
        /// The protocol, always 3.
        protocol: u8,
        /// The algorithm.
        algorithm: u8,
        /// The public key.
        public_key: HexBytes,
    },
    /// A signature over an RRset.
    #[serde(rename = "RRSIG")]
    Rrsig {
        /// The type the signature covers.
        type_covered: Rtype,
        /// The algorithm.
        algorithm: u8,
        /// The label count of the owner name.
        labels: u8,
        /// The TTL of the covered RRset.
        original_ttl: u32,
        /// Expiration, seconds since 1970 modulo 2^32.
        expiration: u32,
        /// Inception, seconds since 1970 modulo 2^32.
        inception: u32,
        /// The key tag of the signing key.
        key_tag: u16,
        /// The signer's name.
        signer: DnsName,
        /// The signature.
        signature: HexBytes,
    },
    /// The next owner name and the types of this one.
    #[serde(rename = "NSEC")]
    Nsec {
        /// The next owner name in canonical order.
        next: DnsName,
        /// The types present at the owner, ascending.
        types: Vec<Rtype>,
    },
    /// The next hashed owner name and the types of this one.
    #[serde(rename = "NSEC3")]
    Nsec3 {
        /// The hash algorithm (1: SHA-1).
        hash_algorithm: u8,
        /// The flags (1: opt-out).
        flags: u8,
        /// Extra hash iterations.
        iterations: u16,
        /// The salt.
        salt: HexBytes,
        /// The next hashed owner name, raw (not base32).
        next_hashed: HexBytes,
        /// The types present at the owner, ascending.
        types: Vec<Rtype>,
    },
    /// The NSEC3 parameters of a zone.
    #[serde(rename = "NSEC3PARAM")]
    Nsec3param {
        /// The hash algorithm (1: SHA-1).
        hash_algorithm: u8,
        /// The flags, zero.
        flags: u8,
        /// Extra hash iterations.
        iterations: u16,
        /// The salt.
        salt: HexBytes,
    },
    /// A TLS association.
    #[serde(rename = "TLSA")]
    Tlsa {
        /// The certificate usage.
        usage: u8,
        /// The selector.
        selector: u8,
        /// The matching type.
        matching_type: u8,
        /// The association data.
        data: HexBytes,
    },
    /// A service binding.
    #[serde(rename = "SVCB")]
    Svcb {
        /// The priority; 0 is the alias form.
        priority: u16,
        /// The target name (`.` for the owner itself).
        target: DnsName,
        /// The parameters, keys strictly ascending.
        params: Vec<SvcParam>,
    },
    /// An HTTPS service binding.
    #[serde(rename = "HTTPS")]
    Https {
        /// The priority; 0 is the alias form.
        priority: u16,
        /// The target name (`.` for the owner itself).
        target: DnsName,
        /// The parameters, keys strictly ascending.
        params: Vec<SvcParam>,
    },
    /// Data of a type the model does not interpret (RFC 3597).
    #[serde(rename = "unknown")]
    Unknown {
        /// The record type.
        rtype: Rtype,
        /// The data in wire form.
        data: HexBytes,
    },
}

/// A cursor over wire data.
struct Reader<'a> {
    wire: &'a [u8],
    pos: usize,
    rtype: Rtype,
}

impl<'a> Reader<'a> {
    fn invalid(&self, reason: &'static str) -> InvalidValue {
        InvalidValue::new(
            "record data",
            &format!(
                "{} {}",
                self.rtype,
                to_hex(&self.wire[..self.wire.len().min(32)])
            ),
            reason,
        )
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], InvalidValue> {
        let bytes = self
            .wire
            .get(self.pos..self.pos + len)
            .ok_or_else(|| self.invalid("truncated record data"))?;
        self.pos += len;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, InvalidValue> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, InvalidValue> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, InvalidValue> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn name(&mut self) -> Result<DnsName, InvalidValue> {
        let (name, len) = DnsName::from_wire(&self.wire[self.pos..])?;
        self.pos += len;
        Ok(name)
    }

    fn charstring(&mut self) -> Result<TextBytes, InvalidValue> {
        let len = usize::from(self.u8()?);
        Ok(TextBytes(self.take(len)?.to_vec()))
    }

    fn rest(&mut self) -> &'a [u8] {
        let rest = &self.wire[self.pos..];
        self.pos = self.wire.len();
        rest
    }

    fn sized(&mut self) -> Result<HexBytes, InvalidValue> {
        let len = usize::from(self.u8()?);
        Ok(HexBytes(self.take(len)?.to_vec()))
    }

    fn bitmap(&mut self) -> Result<Vec<Rtype>, InvalidValue> {
        let mut types = Vec::new();
        let mut last_window = None;
        while self.pos < self.wire.len() {
            let window = self.u8()?;
            let len = usize::from(self.u8()?);
            if len == 0 || len > 32 {
                return Err(self.invalid("a type bitmap window is 1 to 32 octets"));
            }
            if last_window.is_some_and(|last| window <= last) {
                return Err(self.invalid("type bitmap windows must ascend"));
            }
            last_window = Some(window);
            for (index, &byte) in self.take(len)?.iter().enumerate() {
                for bit in 0..8u16 {
                    if byte & (0x80 >> bit) != 0 {
                        let low = u16::try_from(index).unwrap_or(0) * 8 + bit;
                        types.push(Rtype(u16::from(window) << 8 | low));
                    }
                }
            }
        }
        Ok(types)
    }

    fn params(&mut self) -> Result<Vec<SvcParam>, InvalidValue> {
        let mut params: Vec<SvcParam> = Vec::new();
        while self.pos < self.wire.len() {
            let key = self.u16()?;
            if params.last().is_some_and(|last| key <= last.key) {
                return Err(self.invalid("service parameter keys must ascend strictly"));
            }
            let len = usize::from(self.u16()?);
            let value = HexBytes(self.take(len)?.to_vec());
            params.push(SvcParam { key, value });
        }
        Ok(params)
    }

    fn finish(&self) -> Result<(), InvalidValue> {
        if self.pos == self.wire.len() {
            Ok(())
        } else {
            Err(self.invalid("trailing octets after the record data"))
        }
    }
}

fn write_bitmap(types: &[Rtype], out: &mut Vec<u8>) {
    let mut sorted: Vec<u16> = types.iter().map(|rtype| rtype.0).collect();
    sorted.sort_unstable();
    sorted.dedup();
    let mut index = 0;
    while index < sorted.len() {
        let window = sorted[index] >> 8;
        let mut bits = [0u8; 32];
        let mut used = 0;
        while index < sorted.len() && sorted[index] >> 8 == window {
            let low = usize::from(sorted[index] & 0xff);
            bits[low / 8] |= 0x80 >> (low % 8);
            used = used.max(low / 8 + 1);
            index += 1;
        }
        out.push(u8::try_from(window).unwrap_or(u8::MAX));
        out.push(u8::try_from(used).unwrap_or(u8::MAX));
        out.extend_from_slice(&bits[..used]);
    }
}

fn write_sized(bytes: &[u8], out: &mut Vec<u8>) {
    out.push(u8::try_from(bytes.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(&bytes[..bytes.len().min(255)]);
}

impl RecordData {
    /// The record type of the data.
    pub fn rtype(&self) -> Rtype {
        match self {
            RecordData::A { .. } => Rtype::A,
            RecordData::Aaaa { .. } => Rtype::AAAA,
            RecordData::Cname { .. } => Rtype::CNAME,
            RecordData::Dname { .. } => Rtype::DNAME,
            RecordData::Mx { .. } => Rtype::MX,
            RecordData::Ns { .. } => Rtype::NS,
            RecordData::Ptr { .. } => Rtype::PTR,
            RecordData::Soa { .. } => Rtype::SOA,
            RecordData::Srv { .. } => Rtype::SRV,
            RecordData::Txt { .. } => Rtype::TXT,
            RecordData::Caa { .. } => Rtype::CAA,
            RecordData::Ds { .. } => Rtype::DS,
            RecordData::Dnskey { .. } => Rtype::DNSKEY,
            RecordData::Rrsig { .. } => Rtype::RRSIG,
            RecordData::Nsec { .. } => Rtype::NSEC,
            RecordData::Nsec3 { .. } => Rtype::NSEC3,
            RecordData::Nsec3param { .. } => Rtype::NSEC3PARAM,
            RecordData::Tlsa { .. } => Rtype::TLSA,
            RecordData::Svcb { .. } => Rtype::SVCB,
            RecordData::Https { .. } => Rtype::HTTPS,
            RecordData::Unknown { rtype, .. } => *rtype,
        }
    }

    /// Whether the model interprets data of this type.
    pub fn is_known(rtype: Rtype) -> bool {
        matches!(
            rtype,
            Rtype::A
                | Rtype::AAAA
                | Rtype::CNAME
                | Rtype::DNAME
                | Rtype::MX
                | Rtype::NS
                | Rtype::PTR
                | Rtype::SOA
                | Rtype::SRV
                | Rtype::TXT
                | Rtype::CAA
                | Rtype::DS
                | Rtype::DNSKEY
                | Rtype::RRSIG
                | Rtype::NSEC
                | Rtype::NSEC3
                | Rtype::NSEC3PARAM
                | Rtype::TLSA
                | Rtype::SVCB
                | Rtype::HTTPS
        )
    }

    /// TXT data from text, split into strings of at most 255 octets (DNS-24).
    pub fn txt(text: &str) -> Self {
        RecordData::Txt {
            strings: split_txt(text.as_bytes()),
        }
    }

    /// Checks the limits that the wire form cannot express: a TXT string of at most 255
    /// octets, at least one TXT string, a CAA tag of 1 to 15 letters and digits, salts and
    /// hashes of at most 255 octets, ascending SVCB keys, data of at most 65,535 octets.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidValue`] for the first limit broken.
    pub fn validate(&self) -> Result<(), InvalidValue> {
        let invalid = |reason| InvalidValue::new("record data", &self.rtype().to_string(), reason);
        match self {
            RecordData::Txt { strings } => {
                if strings.is_empty() {
                    return Err(invalid("a TXT record has at least one string"));
                }
                if strings.iter().any(|s| s.0.len() > MAX_CHARSTRING_LEN) {
                    return Err(invalid("a TXT string is at most 255 octets"));
                }
            }
            RecordData::Caa { tag, .. } => {
                if tag.is_empty()
                    || tag.len() > 15
                    || !tag.bytes().all(|b| b.is_ascii_alphanumeric())
                {
                    return Err(invalid("a CAA tag is 1 to 15 letters or digits"));
                }
            }
            RecordData::Nsec3 {
                salt, next_hashed, ..
            } => {
                if salt.0.len() > 255 || next_hashed.0.len() > 255 || next_hashed.0.is_empty() {
                    return Err(invalid("salt and next hashed name are at most 255 octets"));
                }
            }
            RecordData::Nsec3param { salt, .. } => {
                if salt.0.len() > 255 {
                    return Err(invalid("a salt is at most 255 octets"));
                }
            }
            RecordData::Svcb { params, .. } | RecordData::Https { params, .. } => {
                if params.windows(2).any(|pair| pair[0].key >= pair[1].key) {
                    return Err(invalid("service parameter keys must ascend strictly"));
                }
                if params
                    .iter()
                    .any(|param| param.value.0.len() > usize::from(u16::MAX))
                {
                    return Err(invalid("a service parameter value is at most 65535 octets"));
                }
            }
            RecordData::Unknown { rtype, .. } => {
                if Self::is_known(*rtype) {
                    return Err(invalid("data of a known type must use its typed form"));
                }
                if rtype.is_meta() {
                    return Err(invalid("a meta type is not zone data"));
                }
            }
            _ => {}
        }
        let mut wire = Vec::new();
        self.write_wire(&mut wire);
        if wire.len() > MAX_RDATA_LEN {
            return Err(invalid("record data longer than 65535 octets"));
        }
        Ok(())
    }

    /// Reads data of `rtype` from its uncompressed wire form.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidValue`] when the bytes are truncated, have trailing octets, hold a
    #[allow(
        clippy::too_many_lines,
        reason = "one arm per record type reads best as one match"
    )]
    /// compressed or invalid name or break a limit of the type.
    pub fn from_wire(rtype: Rtype, wire: &[u8]) -> Result<Self, InvalidValue> {
        let mut r = Reader {
            wire,
            pos: 0,
            rtype,
        };
        if wire.len() > MAX_RDATA_LEN {
            return Err(r.invalid("record data longer than 65535 octets"));
        }
        if rtype.is_meta() {
            return Err(r.invalid("a meta type is not zone data"));
        }
        let data = match rtype {
            Rtype::A => {
                let b = r.take(4)?;
                RecordData::A {
                    address: Ipv4Addr::new(b[0], b[1], b[2], b[3]),
                }
            }
            Rtype::AAAA => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(r.take(16)?);
                RecordData::Aaaa {
                    address: Ipv6Addr::from(octets),
                }
            }
            Rtype::CNAME => RecordData::Cname { target: r.name()? },
            Rtype::DNAME => RecordData::Dname { target: r.name()? },
            Rtype::MX => RecordData::Mx {
                preference: r.u16()?,
                exchange: r.name()?,
            },
            Rtype::NS => RecordData::Ns { host: r.name()? },
            Rtype::PTR => RecordData::Ptr { target: r.name()? },
            Rtype::SOA => RecordData::Soa {
                mname: r.name()?,
                rname: r.name()?,
                serial: r.u32()?,
                refresh: r.u32()?,
                retry: r.u32()?,
                expire: r.u32()?,
                minimum: r.u32()?,
            },
            Rtype::SRV => RecordData::Srv {
                priority: r.u16()?,
                weight: r.u16()?,
                port: r.u16()?,
                target: r.name()?,
            },
            Rtype::TXT => {
                let mut strings = Vec::new();
                while r.pos < wire.len() {
                    strings.push(r.charstring()?);
                }
                RecordData::Txt { strings }
            }
            Rtype::CAA => {
                let flags = r.u8()?;
                let tag = r.charstring()?;
                let tag = String::from_utf8(tag.0).map_err(|_| r.invalid("a CAA tag is ASCII"))?;
                RecordData::Caa {
                    flags,
                    tag,
                    value: TextBytes(r.rest().to_vec()),
                }
            }
            Rtype::DS => RecordData::Ds {
                key_tag: r.u16()?,
                algorithm: r.u8()?,
                digest_type: r.u8()?,
                digest: HexBytes(r.rest().to_vec()),
            },
            Rtype::DNSKEY => RecordData::Dnskey {
                flags: r.u16()?,
                protocol: r.u8()?,
                algorithm: r.u8()?,
                public_key: HexBytes(r.rest().to_vec()),
            },
            Rtype::RRSIG => RecordData::Rrsig {
                type_covered: Rtype(r.u16()?),
                algorithm: r.u8()?,
                labels: r.u8()?,
                original_ttl: r.u32()?,
                expiration: r.u32()?,
                inception: r.u32()?,
                key_tag: r.u16()?,
                signer: r.name()?,
                signature: HexBytes(r.rest().to_vec()),
            },
            Rtype::NSEC => RecordData::Nsec {
                next: r.name()?,
                types: r.bitmap()?,
            },
            Rtype::NSEC3 => RecordData::Nsec3 {
                hash_algorithm: r.u8()?,
                flags: r.u8()?,
                iterations: r.u16()?,
                salt: r.sized()?,
                next_hashed: r.sized()?,
                types: r.bitmap()?,
            },
            Rtype::NSEC3PARAM => RecordData::Nsec3param {
                hash_algorithm: r.u8()?,
                flags: r.u8()?,
                iterations: r.u16()?,
                salt: r.sized()?,
            },
            Rtype::TLSA => RecordData::Tlsa {
                usage: r.u8()?,
                selector: r.u8()?,
                matching_type: r.u8()?,
                data: HexBytes(r.rest().to_vec()),
            },
            Rtype::SVCB => RecordData::Svcb {
                priority: r.u16()?,
                target: r.name()?,
                params: r.params()?,
            },
            Rtype::HTTPS => RecordData::Https {
                priority: r.u16()?,
                target: r.name()?,
                params: r.params()?,
            },
            _ => RecordData::Unknown {
                rtype,
                data: HexBytes(r.rest().to_vec()),
            },
        };
        r.finish()?;
        data.validate()?;
        Ok(data)
    }

    /// Appends the uncompressed wire form. Oversized fields that [`RecordData::validate`]
    /// refuses are cut to their length octet's range.
    #[allow(
        clippy::too_many_lines,
        reason = "one arm per record type reads best as one match"
    )]
    pub fn write_wire(&self, out: &mut Vec<u8>) {
        match self {
            RecordData::A { address } => out.extend_from_slice(&address.octets()),
            RecordData::Aaaa { address } => out.extend_from_slice(&address.octets()),
            RecordData::Cname { target }
            | RecordData::Dname { target }
            | RecordData::Ptr { target } => target.write_wire(out),
            RecordData::Ns { host } => host.write_wire(out),
            RecordData::Mx {
                preference,
                exchange,
            } => {
                out.extend_from_slice(&preference.to_be_bytes());
                exchange.write_wire(out);
            }
            RecordData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                mname.write_wire(out);
                rname.write_wire(out);
                for value in [serial, refresh, retry, expire, minimum] {
                    out.extend_from_slice(&value.to_be_bytes());
                }
            }
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                for value in [priority, weight, port] {
                    out.extend_from_slice(&value.to_be_bytes());
                }
                target.write_wire(out);
            }
            RecordData::Txt { strings } => {
                for string in strings {
                    write_sized(&string.0, out);
                }
            }
            RecordData::Caa { flags, tag, value } => {
                out.push(*flags);
                write_sized(tag.as_bytes(), out);
                out.extend_from_slice(&value.0);
            }
            RecordData::Ds {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => {
                out.extend_from_slice(&key_tag.to_be_bytes());
                out.extend_from_slice(&[*algorithm, *digest_type]);
                out.extend_from_slice(&digest.0);
            }
            RecordData::Dnskey {
                flags,
                protocol,
                algorithm,
                public_key,
            } => {
                out.extend_from_slice(&flags.to_be_bytes());
                out.extend_from_slice(&[*protocol, *algorithm]);
                out.extend_from_slice(&public_key.0);
            }
            RecordData::Rrsig {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer,
                signature,
            } => {
                out.extend_from_slice(&type_covered.0.to_be_bytes());
                out.extend_from_slice(&[*algorithm, *labels]);
                for value in [original_ttl, expiration, inception] {
                    out.extend_from_slice(&value.to_be_bytes());
                }
                out.extend_from_slice(&key_tag.to_be_bytes());
                signer.write_wire(out);
                out.extend_from_slice(&signature.0);
            }
            RecordData::Nsec { next, types } => {
                next.write_wire(out);
                write_bitmap(types, out);
            }
            RecordData::Nsec3 {
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hashed,
                types,
            } => {
                out.extend_from_slice(&[*hash_algorithm, *flags]);
                out.extend_from_slice(&iterations.to_be_bytes());
                write_sized(&salt.0, out);
                write_sized(&next_hashed.0, out);
                write_bitmap(types, out);
            }
            RecordData::Nsec3param {
                hash_algorithm,
                flags,
                iterations,
                salt,
            } => {
                out.extend_from_slice(&[*hash_algorithm, *flags]);
                out.extend_from_slice(&iterations.to_be_bytes());
                write_sized(&salt.0, out);
            }
            RecordData::Tlsa {
                usage,
                selector,
                matching_type,
                data,
            } => {
                out.extend_from_slice(&[*usage, *selector, *matching_type]);
                out.extend_from_slice(&data.0);
            }
            RecordData::Svcb {
                priority,
                target,
                params,
            }
            | RecordData::Https {
                priority,
                target,
                params,
            } => {
                out.extend_from_slice(&priority.to_be_bytes());
                target.write_wire(out);
                for param in params {
                    out.extend_from_slice(&param.key.to_be_bytes());
                    let len = u16::try_from(param.value.0.len()).unwrap_or(u16::MAX);
                    out.extend_from_slice(&len.to_be_bytes());
                    out.extend_from_slice(&param.value.0[..usize::from(len)]);
                }
            }
            RecordData::Unknown { data, .. } => out.extend_from_slice(&data.0),
        }
    }

    /// The names inside the data that the record points to (targets, exchanges, hosts), for
    /// glue and additional-section processing.
    pub fn target(&self) -> Option<&DnsName> {
        match self {
            RecordData::Cname { target }
            | RecordData::Dname { target }
            | RecordData::Ptr { target }
            | RecordData::Srv { target, .. }
            | RecordData::Svcb { target, .. }
            | RecordData::Https { target, .. } => Some(target),
            RecordData::Mx { exchange, .. } => Some(exchange),
            RecordData::Ns { host } => Some(host),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> DnsName {
        DnsName::new(text).expect("name")
    }

    fn round_trip(data: &RecordData) {
        let rdata = Rdata::from_data(data);
        assert_eq!(rdata.decode(data.rtype()).as_ref(), Ok(data), "{data:?}");
        let json = serde_json::to_value(data).expect("json");
        assert_eq!(
            &serde_json::from_value::<RecordData>(json).expect("json"),
            data
        );
    }

    #[test]
    #[allow(clippy::too_many_lines, reason = "one sample per record type")]
    fn every_known_type_round_trips() {
        let samples = [
            RecordData::A {
                address: Ipv4Addr::new(192, 0, 2, 1),
            },
            RecordData::Aaaa {
                address: "2001:db8::1".parse().expect("ip"),
            },
            RecordData::Cname {
                target: name("www.example.test"),
            },
            RecordData::Dname {
                target: name("example.net"),
            },
            RecordData::Mx {
                preference: 10,
                exchange: name("mail.example.test"),
            },
            RecordData::Ns {
                host: name("ns1.example.test"),
            },
            RecordData::Ptr {
                target: name("host.example.test"),
            },
            RecordData::Soa {
                mname: name("ns1.example.test"),
                rname: name("hostmaster.example.test"),
                serial: 2_026_101_701,
                refresh: 3600,
                retry: 900,
                expire: 604_800,
                minimum: 300,
            },
            RecordData::Srv {
                priority: 0,
                weight: 5,
                port: 389,
                target: name("dc1.example.test"),
            },
            RecordData::txt("v=spf1 -all"),
            RecordData::Caa {
                flags: 0,
                tag: "issue".to_owned(),
                value: TextBytes::from_text("ca.example.net"),
            },
            RecordData::Ds {
                key_tag: 12345,
                algorithm: 13,
                digest_type: 2,
                digest: HexBytes(vec![0xab; 32]),
            },
            RecordData::Dnskey {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                public_key: HexBytes(vec![1; 64]),
            },
            RecordData::Rrsig {
                type_covered: Rtype::A,
                algorithm: 13,
                labels: 3,
                original_ttl: 300,
                expiration: 1_800_000_000,
                inception: 1_790_000_000,
                key_tag: 12345,
                signer: name("example.test"),
                signature: HexBytes(vec![2; 64]),
            },
            RecordData::Nsec {
                next: name("b.example.test"),
                types: vec![Rtype::A, Rtype::MX, Rtype::RRSIG, Rtype::NSEC, Rtype::CAA],
            },
            RecordData::Nsec3 {
                hash_algorithm: 1,
                flags: 0,
                iterations: 0,
                salt: HexBytes(Vec::new()),
                next_hashed: HexBytes(vec![7; 20]),
                types: vec![Rtype::A, Rtype::RRSIG],
            },
            RecordData::Nsec3param {
                hash_algorithm: 1,
                flags: 0,
                iterations: 0,
                salt: HexBytes(vec![0xaa, 0xbb]),
            },
            RecordData::Tlsa {
                usage: 3,
                selector: 1,
                matching_type: 1,
                data: HexBytes(vec![9; 32]),
            },
            RecordData::Svcb {
                priority: 1,
                target: DnsName::root(),
                params: vec![
                    SvcParam {
                        key: 1,
                        value: HexBytes(b"\x02h2".to_vec()),
                    },
                    SvcParam {
                        key: 3,
                        value: HexBytes(vec![0x01, 0xbb]),
                    },
                ],
            },
            RecordData::Https {
                priority: 0,
                target: name("cdn.example.net"),
                params: Vec::new(),
            },
            RecordData::Unknown {
                rtype: Rtype(65280),
                data: HexBytes(vec![1, 2, 3]),
            },
        ];
        for sample in &samples {
            sample.validate().expect("valid");
            round_trip(sample);
        }
    }

    #[test]
    fn json_uses_the_type_tag() {
        let json = serde_json::to_value(RecordData::Mx {
            preference: 10,
            exchange: name("mail.example.test"),
        })
        .expect("json");
        assert_eq!(
            json,
            serde_json::json!({"type": "MX", "preference": 10, "exchange": "mail.example.test"})
        );
        let unknown: RecordData = serde_json::from_value(
            serde_json::json!({"type": "unknown", "rtype": "TYPE65280", "data": "0102"}),
        )
        .expect("json");
        assert_eq!(unknown.rtype(), Rtype(65280));
    }

    #[test]
    fn long_txt_input_is_split_at_255_octets() {
        let long = "a".repeat(600);
        let data: RecordData =
            serde_json::from_value(serde_json::json!({"type": "TXT", "strings": [long]}))
                .expect("json");
        let RecordData::Txt { strings } = &data else {
            panic!("TXT");
        };
        assert_eq!(
            strings.iter().map(|s| s.0.len()).collect::<Vec<_>>(),
            [255, 255, 90]
        );
        round_trip(&data);
        // A cut never splits a character: 254 ASCII octets, then a two-octet character.
        let text = format!("{}åb", "a".repeat(254));
        let parts = split_txt(text.as_bytes());
        assert_eq!(parts[0].0.len(), 254);
        assert_eq!(parts[1].to_string(), "åb");
        assert!(
            serde_json::from_value::<RecordData>(serde_json::json!({"type": "TXT", "strings": []}))
                .is_err()
        );
    }

    #[test]
    fn text_escapes_round_trip() {
        let text = TextBytes(vec![b'a', b'\\', 0x00, 0xff, b'"', 0xc3, 0xa5]);
        let shown = text.to_string();
        assert_eq!(shown, "a\\\\\\000\\255\"å");
        assert_eq!(TextBytes::parse(&shown), Ok(text));
        assert!(TextBytes::parse("x\\").is_err());
        assert!(TextBytes::parse("\\25").is_err());
        assert!(TextBytes::parse("\\256").is_err());
        assert_eq!(TextBytes::parse("\\;").expect("escape").0, b";");
    }

    #[test]
    fn malformed_wire_data_is_refused() {
        assert!(RecordData::from_wire(Rtype::A, &[192, 0, 2]).is_err());
        assert!(RecordData::from_wire(Rtype::A, &[192, 0, 2, 1, 0]).is_err());
        assert!(RecordData::from_wire(Rtype::CNAME, b"\x03www\xc0\x0c").is_err());
        assert!(RecordData::from_wire(Rtype::TXT, b"\x05abc").is_err());
        assert!(RecordData::from_wire(Rtype::NSEC, b"\x00\x00\x00").is_err());
        assert!(RecordData::from_wire(Rtype::NSEC, b"\x00\x01\x00\x00\x01\x00").is_err());
        assert!(
            RecordData::from_wire(Rtype::SVCB, b"\x00\x01\x00\x00\x03\x00\x00\x00\x01\x00\x00")
                .is_err()
        );
        assert!(RecordData::from_wire(Rtype::OPT, b"").is_err());
        assert!(RecordData::from_wire(Rtype::CAA, b"\x00\x00").is_err());
        // An empty TXT is no record; one empty string is.
        assert!(RecordData::from_wire(Rtype::TXT, b"").is_err());
        assert!(RecordData::from_wire(Rtype::TXT, b"\x00").is_ok());
        // Unknown types keep their bytes; known types must use the typed form.
        assert!(RecordData::from_wire(Rtype(65280), b"\xde\xad").is_ok());
        assert!(
            RecordData::Unknown {
                rtype: Rtype::A,
                data: HexBytes(vec![1, 2, 3, 4])
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn names_in_data_are_lowercased() {
        let rdata =
            Rdata::from_wire(Rtype::CNAME, b"\x03WWW\x07Example\x04TEST\x00").expect("cname");
        assert_eq!(rdata.as_bytes(), b"\x03www\x07example\x04test\x00");
    }

    #[test]
    fn rdata_serializes_as_hex_and_bytes() {
        let rdata = Rdata::from_data(&RecordData::A {
            address: Ipv4Addr::new(192, 0, 2, 1),
        });
        assert_eq!(serde_json::to_string(&rdata).expect("json"), "\"c0000201\"");
        let cbor = crate::codec::to_cbor(&rdata).expect("cbor");
        assert_eq!(
            crate::codec::from_cbor::<Rdata>(&cbor).expect("cbor"),
            rdata
        );
    }
}
