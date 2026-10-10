//! BER encoding and decoding for SNMP (the subset of X.690 that RFC 3416 uses).
//!
//! Only definite lengths of at most four length octets and single-octet tags are
//! accepted. Nesting is limited to [`MAX_DEPTH`] levels and a message to
//! [`MAX_MESSAGE_LEN`] octets, so a hostile datagram cannot make the decoder allocate or
//! recurse without bound.

use std::{fmt, str::FromStr};

/// The largest SNMP message: the payload of a UDP datagram over IPv4 (65,535 minus the
/// IP and UDP headers).
pub const MAX_MESSAGE_LEN: usize = 65_507;

/// The deepest nesting of constructed values the decoder follows.
pub const MAX_DEPTH: usize = 16;

/// The most sub-identifiers of an object identifier (RFC 3416, section 4.2.1).
pub const MAX_OID_ARCS: usize = 128;

/// The most octets that encode a length.
const MAX_LENGTH_OCTETS: usize = 4;

/// The largest value of a first sub-identifier octet group: `2 * 40 + u32::MAX`.
const MAX_FIRST_SUBID: u64 = 0xFFFF_FFFF + 80;

/// BER tags used by SNMP.
pub mod tag {
    /// `INTEGER`.
    pub const INTEGER: u8 = 0x02;
    /// `OCTET STRING`.
    pub const OCTET_STRING: u8 = 0x04;
    /// `NULL`.
    pub const NULL: u8 = 0x05;
    /// `OBJECT IDENTIFIER`.
    pub const OBJECT_IDENTIFIER: u8 = 0x06;
    /// `SEQUENCE`.
    pub const SEQUENCE: u8 = 0x30;
    /// `IpAddress`.
    pub const IP_ADDRESS: u8 = 0x40;
    /// `Counter32`.
    pub const COUNTER32: u8 = 0x41;
    /// `Gauge32` (also `Unsigned32`).
    pub const GAUGE32: u8 = 0x42;
    /// `TimeTicks`.
    pub const TIME_TICKS: u8 = 0x43;
    /// `Opaque`.
    pub const OPAQUE: u8 = 0x44;
    /// `Counter64`.
    pub const COUNTER64: u8 = 0x46;
    /// The `noSuchObject` exception.
    pub const NO_SUCH_OBJECT: u8 = 0x80;
    /// The `noSuchInstance` exception.
    pub const NO_SUCH_INSTANCE: u8 = 0x81;
    /// The `endOfMibView` exception.
    pub const END_OF_MIB_VIEW: u8 = 0x82;
    /// `GetRequest-PDU`.
    pub const GET_REQUEST: u8 = 0xA0;
    /// `GetNextRequest-PDU`.
    pub const GET_NEXT_REQUEST: u8 = 0xA1;
    /// `Response-PDU`.
    pub const RESPONSE: u8 = 0xA2;
    /// `GetBulkRequest-PDU`.
    pub const GET_BULK_REQUEST: u8 = 0xA5;
    /// `Report-PDU`.
    pub const REPORT: u8 = 0xA8;
}

/// Why a BER value could not be decoded or encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BerError {
    /// The data ends inside a value.
    Truncated,
    /// A length of the indefinite form (`0x80`).
    IndefiniteLength,
    /// A length that needs more than four octets.
    LengthTooLarge,
    /// A message longer than [`MAX_MESSAGE_LEN`].
    MessageTooLarge,
    /// More than [`MAX_DEPTH`] levels of nesting.
    TooDeep,
    /// A tag of more than one octet.
    MultiByteTag,
    /// A tag other than the expected one.
    UnexpectedTag {
        /// The tag the structure requires.
        expected: u8,
        /// The tag found.
        found: u8,
    },
    /// Octets left after the last value of a structure.
    TrailingBytes,
    /// Anything else that breaks the encoding rules.
    Malformed(&'static str),
}

impl fmt::Display for BerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BerError::Truncated => f.write_str("the data ends inside a value"),
            BerError::IndefiniteLength => f.write_str("indefinite lengths are not allowed"),
            BerError::LengthTooLarge => f.write_str("a length needs more than four octets"),
            BerError::MessageTooLarge => {
                write!(f, "the message is longer than {MAX_MESSAGE_LEN} octets")
            }
            BerError::TooDeep => write!(f, "nesting is deeper than {MAX_DEPTH} levels"),
            BerError::MultiByteTag => f.write_str("multi-octet tags are not allowed"),
            BerError::UnexpectedTag { expected, found } => {
                write!(f, "expected tag 0x{expected:02x}, found 0x{found:02x}")
            }
            BerError::TrailingBytes => f.write_str("unexpected octets after the last value"),
            BerError::Malformed(what) => f.write_str(what),
        }
    }
}

impl std::error::Error for BerError {}

/// An object identifier: the sub-identifiers in order.
///
/// The text form is dotted without a leading dot (`1.3.6.1.2.1.1.5.0`); parsing also
/// accepts the leading dot of `snmpwalk -On`. Ordering is the MIB order: arc by arc,
/// a prefix before the longer identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Oid(pub Vec<u32>);

impl Oid {
    /// An identifier from its arcs.
    pub fn new(arcs: &[u32]) -> Self {
        Self(arcs.to_vec())
    }

    /// The arcs.
    pub fn arcs(&self) -> &[u32] {
        &self.0
    }

    /// The number of arcs.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no arcs.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `prefix` is a prefix of this identifier (an identifier is a prefix of
    /// itself).
    pub fn starts_with(&self, prefix: &Oid) -> bool {
        self.0.starts_with(&prefix.0)
    }

    /// The arcs after `prefix`, or `None` when `prefix` is not a prefix.
    pub fn strip_prefix(&self, prefix: &Oid) -> Option<&[u32]> {
        self.0.strip_prefix(prefix.0.as_slice())
    }

    /// This identifier with `arc` appended.
    #[must_use]
    pub fn child(&self, arc: u32) -> Oid {
        let mut arcs = self.0.clone();
        arcs.push(arc);
        Oid(arcs)
    }

    /// This identifier with `arcs` appended.
    #[must_use]
    pub fn join(&self, arcs: &[u32]) -> Oid {
        let mut all = self.0.clone();
        all.extend_from_slice(arcs);
        Oid(all)
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (position, arc) in self.0.iter().enumerate() {
            if position > 0 {
                f.write_str(".")?;
            }
            write!(f, "{arc}")?;
        }
        Ok(())
    }
}

impl FromStr for Oid {
    type Err = BerError;

    fn from_str(text: &str) -> Result<Self, BerError> {
        let text = text.trim();
        let text = text.strip_prefix('.').unwrap_or(text);
        if text.is_empty() {
            return Err(BerError::Malformed("an object identifier needs an arc"));
        }
        let mut arcs = Vec::new();
        for part in text.split('.') {
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(BerError::Malformed(
                    "an object identifier is made of numbers separated by dots",
                ));
            }
            arcs.push(
                part.parse::<u32>()
                    .map_err(|_| BerError::Malformed("an arc does not fit in 32 bits"))?,
            );
        }
        if arcs.len() > MAX_OID_ARCS {
            return Err(BerError::Malformed(
                "an object identifier has too many arcs",
            ));
        }
        Ok(Oid(arcs))
    }
}

impl From<&[u32]> for Oid {
    fn from(arcs: &[u32]) -> Self {
        Self(arcs.to_vec())
    }
}

/// A value of a variable binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// `INTEGER` (read up to 64 bits).
    Integer(i64),
    /// `OCTET STRING`.
    OctetString(Vec<u8>),
    /// `NULL`; the value of a request's variable bindings.
    Null,
    /// `OBJECT IDENTIFIER`.
    Oid(Oid),
    /// `IpAddress`.
    IpAddress([u8; 4]),
    /// `Counter32`.
    Counter32(u32),
    /// `Gauge32` (`Unsigned32`).
    Gauge32(u32),
    /// `TimeTicks`, in hundredths of a second.
    TimeTicks(u32),
    /// `Opaque`.
    Opaque(Vec<u8>),
    /// `Counter64`.
    Counter64(u64),
    /// The `noSuchObject` exception: the agent has no such object.
    NoSuchObject,
    /// The `noSuchInstance` exception: the object has no such instance.
    NoSuchInstance,
    /// The `endOfMibView` exception: nothing follows in the MIB view.
    EndOfMibView,
}

impl Value {
    /// The octets of an `OCTET STRING`.
    pub fn as_octets(&self) -> Option<&[u8]> {
        match self {
            Value::OctetString(octets) => Some(octets),
            _ => None,
        }
    }

    /// The number of an `INTEGER`.
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Value::Integer(number) => Some(*number),
            _ => None,
        }
    }

    /// Whether the value is one of the three exceptions.
    pub fn is_exception(&self) -> bool {
        matches!(
            self,
            Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView
        )
    }

    /// Decodes the value in `tlv`.
    ///
    /// # Errors
    /// The tag is not an SNMP value or the content breaks the rules of its type.
    pub fn decode(tlv: &Tlv<'_>) -> Result<Value, BerError> {
        let content = tlv.content;
        Ok(match tlv.tag {
            tag::INTEGER => Value::Integer(decode_integer(content)?),
            tag::OCTET_STRING => Value::OctetString(content.to_vec()),
            tag::NULL => {
                if !content.is_empty() {
                    return Err(BerError::Malformed("NULL has content"));
                }
                Value::Null
            }
            tag::OBJECT_IDENTIFIER => Value::Oid(decode_oid(content)?),
            tag::IP_ADDRESS => Value::IpAddress(
                <[u8; 4]>::try_from(content)
                    .map_err(|_| BerError::Malformed("an IpAddress has four octets"))?,
            ),
            tag::COUNTER32 => Value::Counter32(decode_unsigned32(content)?),
            tag::GAUGE32 => Value::Gauge32(decode_unsigned32(content)?),
            tag::TIME_TICKS => Value::TimeTicks(decode_unsigned32(content)?),
            tag::OPAQUE => Value::Opaque(content.to_vec()),
            tag::COUNTER64 => Value::Counter64(decode_unsigned64(content)?),
            tag::NO_SUCH_OBJECT | tag::NO_SUCH_INSTANCE | tag::END_OF_MIB_VIEW => {
                if !content.is_empty() {
                    return Err(BerError::Malformed("an exception has content"));
                }
                match tlv.tag {
                    tag::NO_SUCH_OBJECT => Value::NoSuchObject,
                    tag::NO_SUCH_INSTANCE => Value::NoSuchInstance,
                    _ => Value::EndOfMibView,
                }
            }
            _ => return Err(BerError::Malformed("not an SNMP value type")),
        })
    }

    /// Encodes the value as a complete BER value.
    ///
    /// # Errors
    /// An object identifier that cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, BerError> {
        Ok(match self {
            Value::Integer(number) => encode_integer(*number),
            Value::OctetString(octets) => encode_tlv(tag::OCTET_STRING, octets),
            Value::Null => encode_tlv(tag::NULL, &[]),
            Value::Oid(oid) => encode_oid(oid)?,
            Value::IpAddress(octets) => encode_tlv(tag::IP_ADDRESS, octets),
            Value::Counter32(number) => encode_unsigned(tag::COUNTER32, u64::from(*number)),
            Value::Gauge32(number) => encode_unsigned(tag::GAUGE32, u64::from(*number)),
            Value::TimeTicks(number) => encode_unsigned(tag::TIME_TICKS, u64::from(*number)),
            Value::Opaque(octets) => encode_tlv(tag::OPAQUE, octets),
            Value::Counter64(number) => encode_unsigned(tag::COUNTER64, *number),
            Value::NoSuchObject => encode_tlv(tag::NO_SUCH_OBJECT, &[]),
            Value::NoSuchInstance => encode_tlv(tag::NO_SUCH_INSTANCE, &[]),
            Value::EndOfMibView => encode_tlv(tag::END_OF_MIB_VIEW, &[]),
        })
    }
}

/// A variable binding: an object identifier and its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarBind {
    /// The object instance.
    pub oid: Oid,
    /// Its value.
    pub value: Value,
}

impl VarBind {
    /// A binding for a request: the identifier with a `NULL` value.
    pub fn request(oid: Oid) -> Self {
        Self {
            oid,
            value: Value::Null,
        }
    }

    /// Encodes the binding as a `SEQUENCE`.
    ///
    /// # Errors
    /// An object identifier that cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, BerError> {
        let mut content = encode_oid(&self.oid)?;
        content.extend(self.value.encode()?);
        Ok(encode_tlv(tag::SEQUENCE, &content))
    }
}

// Encoding.

fn push_length(out: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        // Short form: the length fits in seven bits.
        out.push(u8::try_from(length).unwrap_or(0x7F));
    } else {
        let bytes = u32::try_from(length).unwrap_or(u32::MAX).to_be_bytes();
        let skip = bytes.iter().take_while(|byte| **byte == 0).count();
        let used = &bytes[skip..];
        out.push(0x80 | u8::try_from(used.len()).unwrap_or(4));
        out.extend_from_slice(used);
    }
}

/// A complete BER value: `tag`, the length of `content` and `content`.
pub fn encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    push_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// A `SEQUENCE` of already encoded values.
pub fn encode_sequence(content: &[u8]) -> Vec<u8> {
    encode_tlv(tag::SEQUENCE, content)
}

/// An `OCTET STRING`.
pub fn encode_octet_string(octets: &[u8]) -> Vec<u8> {
    encode_tlv(tag::OCTET_STRING, octets)
}

/// An `INTEGER` in the fewest octets.
pub fn encode_integer(value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start < bytes.len() - 1 {
        let redundant_zero = bytes[start] == 0x00 && bytes[start + 1] & 0x80 == 0;
        let redundant_ones = bytes[start] == 0xFF && bytes[start + 1] & 0x80 != 0;
        if redundant_zero || redundant_ones {
            start += 1;
        } else {
            break;
        }
    }
    encode_tlv(tag::INTEGER, &bytes[start..])
}

/// An unsigned value (`Counter32`, `Gauge32`, `TimeTicks`, `Counter64`) in the fewest
/// octets, with a leading zero when the top bit would otherwise be set.
pub fn encode_unsigned(tag: u8, value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let skip = bytes
        .iter()
        .take_while(|byte| **byte == 0)
        .count()
        .min(bytes.len() - 1);
    let mut content = Vec::with_capacity(9);
    if bytes[skip] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(&bytes[skip..]);
    encode_tlv(tag, &content)
}

fn push_base128(out: &mut Vec<u8>, value: u64) {
    let mut groups = [0u8; 10];
    let mut count = 0;
    let mut rest = value;
    loop {
        groups[count] = u8::try_from(rest & 0x7F).unwrap_or(0);
        count += 1;
        rest >>= 7;
        if rest == 0 {
            break;
        }
    }
    for position in (0..count).rev() {
        let more = if position > 0 { 0x80 } else { 0 };
        out.push(groups[position] | more);
    }
}

/// An `OBJECT IDENTIFIER`.
///
/// # Errors
/// Fewer than two arcs, a first arc above 2, a second arc of 40 or more under the first
/// arcs 0 and 1, or more than [`MAX_OID_ARCS`] arcs.
pub fn encode_oid(oid: &Oid) -> Result<Vec<u8>, BerError> {
    let arcs = oid.arcs();
    if arcs.len() < 2 {
        return Err(BerError::Malformed("an object identifier needs two arcs"));
    }
    if arcs.len() > MAX_OID_ARCS {
        return Err(BerError::Malformed(
            "an object identifier has too many arcs",
        ));
    }
    let (first, second) = (arcs[0], arcs[1]);
    if first > 2 || (first < 2 && second >= 40) {
        return Err(BerError::Malformed("the first two arcs are out of range"));
    }
    let mut content = Vec::with_capacity(arcs.len() * 2);
    push_base128(&mut content, u64::from(first) * 40 + u64::from(second));
    for arc in &arcs[2..] {
        push_base128(&mut content, u64::from(*arc));
    }
    Ok(encode_tlv(tag::OBJECT_IDENTIFIER, &content))
}

// Decoding.

/// The content of an `INTEGER`, up to 64 bits, two's complement.
///
/// # Errors
/// Empty content or more than eight octets.
pub fn decode_integer(content: &[u8]) -> Result<i64, BerError> {
    let Some(first) = content.first() else {
        return Err(BerError::Malformed("an INTEGER has no content"));
    };
    if content.len() > 8 {
        return Err(BerError::Malformed("an INTEGER is wider than 64 bits"));
    }
    let mut value: i64 = if first & 0x80 != 0 { -1 } else { 0 };
    for byte in content {
        value = (value << 8) | i64::from(*byte);
    }
    Ok(value)
}

fn unsigned_magnitude(content: &[u8], width: usize) -> Result<&[u8], BerError> {
    if content.is_empty() {
        return Err(BerError::Malformed("an unsigned value has no content"));
    }
    let skip = content.iter().take_while(|byte| **byte == 0).count();
    let magnitude = &content[skip..];
    if magnitude.len() > width {
        return Err(BerError::Malformed("an unsigned value is too wide"));
    }
    Ok(magnitude)
}

/// The content of a `Counter32`, `Gauge32` or `TimeTicks`. Agents that leave out the
/// leading zero for values with the top bit set are accepted.
///
/// # Errors
/// Empty content or a value above `u32::MAX`.
pub fn decode_unsigned32(content: &[u8]) -> Result<u32, BerError> {
    let magnitude = unsigned_magnitude(content, 4)?;
    Ok(magnitude
        .iter()
        .fold(0u32, |value, byte| (value << 8) | u32::from(*byte)))
}

/// The content of a `Counter64`.
///
/// # Errors
/// Empty content or a value above `u64::MAX`.
pub fn decode_unsigned64(content: &[u8]) -> Result<u64, BerError> {
    let magnitude = unsigned_magnitude(content, 8)?;
    Ok(magnitude
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte)))
}

/// The content of an `OBJECT IDENTIFIER`.
///
/// # Errors
/// Empty content, a sub-identifier above 32 bits, an unterminated sub-identifier or more
/// than [`MAX_OID_ARCS`] arcs.
pub fn decode_oid(content: &[u8]) -> Result<Oid, BerError> {
    if content.is_empty() {
        return Err(BerError::Malformed("an object identifier has no content"));
    }
    let mut arcs: Vec<u32> = Vec::new();
    let mut accumulator: u64 = 0;
    let mut pending = false;
    for byte in content {
        accumulator = (accumulator << 7) | u64::from(byte & 0x7F);
        if accumulator > MAX_FIRST_SUBID {
            return Err(BerError::Malformed(
                "a sub-identifier does not fit in 32 bits",
            ));
        }
        if byte & 0x80 != 0 {
            pending = true;
            continue;
        }
        pending = false;
        if arcs.is_empty() {
            let (first, second) = match accumulator {
                0..=39 => (0, accumulator),
                40..=79 => (1, accumulator - 40),
                _ => (2, accumulator - 80),
            };
            arcs.push(first);
            arcs.push(
                u32::try_from(second)
                    .map_err(|_| BerError::Malformed("a sub-identifier does not fit in 32 bits"))?,
            );
        } else {
            arcs.push(
                u32::try_from(accumulator)
                    .map_err(|_| BerError::Malformed("a sub-identifier does not fit in 32 bits"))?,
            );
        }
        if arcs.len() > MAX_OID_ARCS {
            return Err(BerError::Malformed(
                "an object identifier has too many arcs",
            ));
        }
        accumulator = 0;
    }
    if pending {
        return Err(BerError::Malformed("an unterminated sub-identifier"));
    }
    Ok(Oid(arcs))
}

/// One decoded value: its tag, its content and where the content begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The tag octet.
    pub tag: u8,
    /// The content octets.
    pub content: &'a [u8],
    /// The offset of the first content octet in the buffer the outermost [`Reader`] was
    /// made over.
    pub offset: usize,
}

/// Reads consecutive BER values from a buffer.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    position: usize,
    base: usize,
    depth: usize,
}

impl<'a> Reader<'a> {
    /// A reader over `data` at nesting depth 1.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            position: 0,
            base: 0,
            depth: 1,
        }
    }

    /// Whether every value has been read.
    pub fn is_empty(&self) -> bool {
        self.position >= self.data.len()
    }

    /// The tag of the next value, if any.
    pub fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.position).copied()
    }

    /// Reads the next value.
    ///
    /// # Errors
    /// Truncated data, an indefinite or oversized length or a multi-octet tag.
    pub fn read(&mut self) -> Result<Tlv<'a>, BerError> {
        let tag = *self.data.get(self.position).ok_or(BerError::Truncated)?;
        if tag & 0x1F == 0x1F {
            return Err(BerError::MultiByteTag);
        }
        let mut cursor = self.position + 1;
        let first = *self.data.get(cursor).ok_or(BerError::Truncated)?;
        cursor += 1;
        let length = if first < 0x80 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7F);
            if count == 0 {
                return Err(BerError::IndefiniteLength);
            }
            if count > MAX_LENGTH_OCTETS {
                return Err(BerError::LengthTooLarge);
            }
            let octets = self
                .data
                .get(cursor..cursor + count)
                .ok_or(BerError::Truncated)?;
            cursor += count;
            octets
                .iter()
                .fold(0usize, |length, byte| (length << 8) | usize::from(*byte))
        };
        let end = cursor.checked_add(length).ok_or(BerError::Truncated)?;
        let content = self.data.get(cursor..end).ok_or(BerError::Truncated)?;
        self.position = end;
        Ok(Tlv {
            tag,
            content,
            offset: self.base + cursor,
        })
    }

    /// Reads the next value and requires `expected` as its tag.
    ///
    /// # Errors
    /// The errors of [`Reader::read`], or [`BerError::UnexpectedTag`].
    pub fn expect(&mut self, expected: u8) -> Result<Tlv<'a>, BerError> {
        let tlv = self.read()?;
        if tlv.tag == expected {
            Ok(tlv)
        } else {
            Err(BerError::UnexpectedTag {
                expected,
                found: tlv.tag,
            })
        }
    }

    /// A reader over the content of `tlv`, one level deeper.
    ///
    /// # Errors
    /// [`BerError::TooDeep`] when that exceeds [`MAX_DEPTH`].
    pub fn enter(&self, tlv: &Tlv<'a>) -> Result<Reader<'a>, BerError> {
        if self.depth >= MAX_DEPTH {
            return Err(BerError::TooDeep);
        }
        Ok(Reader {
            data: tlv.content,
            position: 0,
            base: tlv.offset,
            depth: self.depth + 1,
        })
    }

    /// Reads a `SEQUENCE` and returns a reader over its content.
    ///
    /// # Errors
    /// The errors of [`Reader::expect`] and [`Reader::enter`].
    pub fn sequence(&mut self) -> Result<Reader<'a>, BerError> {
        let tlv = self.expect(tag::SEQUENCE)?;
        self.enter(&tlv)
    }

    /// Reads an `INTEGER`.
    ///
    /// # Errors
    /// The errors of [`Reader::expect`] and [`decode_integer`].
    pub fn integer(&mut self) -> Result<i64, BerError> {
        decode_integer(self.expect(tag::INTEGER)?.content)
    }

    /// Reads an `OCTET STRING`.
    ///
    /// # Errors
    /// The errors of [`Reader::expect`].
    pub fn octet_string(&mut self) -> Result<&'a [u8], BerError> {
        Ok(self.expect(tag::OCTET_STRING)?.content)
    }

    /// Reads an `OBJECT IDENTIFIER`.
    ///
    /// # Errors
    /// The errors of [`Reader::expect`] and [`decode_oid`].
    pub fn oid(&mut self) -> Result<Oid, BerError> {
        decode_oid(self.expect(tag::OBJECT_IDENTIFIER)?.content)
    }

    /// Reads an SNMP value.
    ///
    /// # Errors
    /// The errors of [`Reader::read`] and [`Value::decode`].
    pub fn value(&mut self) -> Result<Value, BerError> {
        Value::decode(&self.read()?)
    }

    /// Requires that every value has been read.
    ///
    /// # Errors
    /// [`BerError::TrailingBytes`].
    pub fn finish(&self) -> Result<(), BerError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(BerError::TrailingBytes)
        }
    }
}

/// Checks that `data` is well-formed BER down to the leaves: lengths fit, constructed
/// values (bit `0x20` of the tag) hold well-formed values, nesting is within
/// [`MAX_DEPTH`] and the whole is within [`MAX_MESSAGE_LEN`].
///
/// # Errors
/// The first problem found.
pub fn check_structure(data: &[u8]) -> Result<(), BerError> {
    if data.len() > MAX_MESSAGE_LEN {
        return Err(BerError::MessageTooLarge);
    }
    check_values(Reader::new(data))
}

fn check_values(mut reader: Reader<'_>) -> Result<(), BerError> {
    while !reader.is_empty() {
        let tlv = reader.read()?;
        if tlv.tag & 0x20 != 0 {
            check_values(reader.enter(&tlv)?)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value_roundtrip(value: &Value) {
        let encoded = value.encode().expect("encode");
        let mut reader = Reader::new(&encoded);
        let decoded = reader.value().expect("decode");
        reader.finish().expect("nothing left");
        assert_eq!(&decoded, value);
    }

    #[test]
    fn integers_use_the_fewest_octets() {
        let cases: [(i64, &[u8]); 9] = [
            (0, &[0x02, 0x01, 0x00]),
            (127, &[0x02, 0x01, 0x7F]),
            (128, &[0x02, 0x02, 0x00, 0x80]),
            (256, &[0x02, 0x02, 0x01, 0x00]),
            (-1, &[0x02, 0x01, 0xFF]),
            (-128, &[0x02, 0x01, 0x80]),
            (-129, &[0x02, 0x02, 0xFF, 0x7F]),
            (65_535, &[0x02, 0x03, 0x00, 0xFF, 0xFF]),
            (-32_768, &[0x02, 0x02, 0x80, 0x00]),
        ];
        for (number, expected) in cases {
            assert_eq!(encode_integer(number), expected, "{number}");
            value_roundtrip(&Value::Integer(number));
        }
        for number in [i64::MIN, i64::MAX, i64::from(i32::MIN), i64::from(i32::MAX)] {
            value_roundtrip(&Value::Integer(number));
        }
    }

    #[test]
    fn unsigned_values_get_a_leading_zero_when_needed() {
        assert_eq!(
            encode_unsigned(tag::COUNTER32, 0),
            [tag::COUNTER32, 0x01, 0x00]
        );
        assert_eq!(
            encode_unsigned(tag::GAUGE32, 0x80),
            [tag::GAUGE32, 0x02, 0x00, 0x80]
        );
        assert_eq!(
            encode_unsigned(tag::COUNTER32, u64::from(u32::MAX)),
            [tag::COUNTER32, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        for value in [
            Value::Counter32(0),
            Value::Counter32(u32::MAX),
            Value::Gauge32(3),
            Value::Gauge32(0x8000_0000),
            Value::TimeTicks(123_456),
            Value::Counter64(0),
            Value::Counter64(u64::MAX),
            Value::Counter64(123_456_789_012),
        ] {
            value_roundtrip(&value);
        }
    }

    #[test]
    fn unsigned_values_without_leading_zero_are_read_as_unsigned() {
        // Some agents encode a Counter32 of 4,000,000,000 without the leading zero.
        let encoded = [tag::COUNTER32, 0x04, 0xEE, 0x6B, 0x28, 0x00];
        assert_eq!(
            Reader::new(&encoded).value(),
            Ok(Value::Counter32(4_000_000_000))
        );
    }

    #[test]
    fn every_value_type_roundtrips() {
        for value in [
            Value::OctetString(Vec::new()),
            Value::OctetString(b"switch-a.example.net".to_vec()),
            Value::OctetString(vec![0; 300]),
            Value::Null,
            Value::Oid("1.3.6.1.4.1.8072.3.2.10".parse().expect("oid")),
            Value::IpAddress([192, 0, 2, 1]),
            Value::Opaque(vec![1, 2, 3]),
            Value::NoSuchObject,
            Value::NoSuchInstance,
            Value::EndOfMibView,
        ] {
            value_roundtrip(&value);
        }
    }

    #[test]
    fn lengths_use_short_and_long_forms() {
        assert_eq!(&encode_octet_string(&[7; 127])[..2], [0x04, 0x7F]);
        assert_eq!(&encode_octet_string(&[7; 128])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(
            &encode_octet_string(&[7; 256])[..4],
            [0x04, 0x82, 0x01, 0x00]
        );
        let long = encode_octet_string(&vec![7; 65_536]);
        assert_eq!(&long[..5], [0x04, 0x83, 0x01, 0x00, 0x00]);
        let mut reader = Reader::new(&long);
        assert_eq!(reader.octet_string().expect("read").len(), 65_536);
    }

    #[test]
    fn oids_encode_the_first_two_arcs_in_one_octet() {
        let oid: Oid = "1.3.6.1.2.1.1.5.0".parse().expect("oid");
        assert_eq!(
            encode_oid(&oid).expect("encode"),
            [0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00]
        );
        // X.690 section 8.19.5: 2.100.3 is 81 34 03.
        let oid: Oid = "2.100.3".parse().expect("oid");
        let encoded = encode_oid(&oid).expect("encode");
        assert_eq!(encoded, [0x06, 0x03, 0x81, 0x34, 0x03]);
        assert_eq!(Reader::new(&encoded).oid(), Ok(oid));
        value_roundtrip(&Value::Oid(
            "1.0.8802.1.1.2.1.4.1.1.9".parse().expect("oid"),
        ));
        value_roundtrip(&Value::Oid(Oid::new(&[1, 3, 6, 1, u32::MAX])));
        value_roundtrip(&Value::Oid(Oid::new(&[2, u32::MAX, 1])));
    }

    #[test]
    fn oids_that_cannot_be_encoded_are_refused() {
        for arcs in [&[1u32][..], &[3, 1], &[1, 40], &[]] {
            assert!(encode_oid(&Oid::new(arcs)).is_err(), "{arcs:?}");
        }
        assert!(encode_oid(&Oid(vec![1; MAX_OID_ARCS + 1])).is_err());
    }

    #[test]
    fn oid_text_roundtrips() {
        let oid: Oid = ".1.3.6.1.2.1.1.5.0".parse().expect("leading dot");
        assert_eq!(oid.to_string(), "1.3.6.1.2.1.1.5.0");
        assert_eq!(oid.arcs(), [1, 3, 6, 1, 2, 1, 1, 5, 0]);
        for bad in [
            "",
            ".",
            "1..3",
            "1.3.x",
            "1.3.",
            "1.-3",
            "1.3.4294967296",
            "1.3 .4",
        ] {
            assert!(bad.parse::<Oid>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn oids_order_like_a_mib() {
        let parent: Oid = "1.3.6.1.2.1.2.2.1.2".parse().expect("oid");
        let child = parent.child(1);
        let sibling: Oid = "1.3.6.1.2.1.2.2.1.6".parse().expect("oid");
        let larger_index = parent.child(10);
        assert!(parent < child);
        assert!(child < larger_index);
        assert!(larger_index < sibling);
        assert!(child.starts_with(&parent));
        assert!(parent.starts_with(&parent));
        assert!(!sibling.starts_with(&parent));
        assert_eq!(child.strip_prefix(&parent), Some(&[1u32][..]));
        assert_eq!(sibling.strip_prefix(&parent), None);
        assert_eq!(parent.join(&[4, 5]).to_string(), "1.3.6.1.2.1.2.2.1.2.4.5");
    }

    #[test]
    fn long_oid_decoding_stops_at_the_limit() {
        let mut content = vec![0x2B];
        content.extend(std::iter::repeat_n(0x01, MAX_OID_ARCS - 2));
        assert!(decode_oid(&content).is_ok());
        content.push(0x01);
        assert!(decode_oid(&content).is_err());
    }

    #[test]
    fn malformed_values_are_refused() {
        let cases: [(&str, &[u8]); 14] = [
            ("empty input", &[]),
            ("tag only", &[0x04]),
            ("short content", &[0x04, 0x05, 0x01]),
            ("indefinite length", &[0x30, 0x80, 0x00, 0x00]),
            ("five length octets", &[0x04, 0x85, 0, 0, 0, 0, 1, 0]),
            ("multi-octet tag", &[0x1F, 0x81, 0x00, 0x00]),
            ("empty integer", &[0x02, 0x00]),
            (
                "nine octet integer",
                &[0x02, 0x09, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            ("null with content", &[0x05, 0x01, 0x00]),
            ("short ip address", &[0x40, 0x03, 1, 2, 3]),
            ("empty oid", &[0x06, 0x00]),
            ("unterminated oid", &[0x06, 0x02, 0x2B, 0x86]),
            ("wide counter32", &[0x41, 0x06, 1, 0, 0, 0, 0, 0]),
            ("exception with content", &[0x82, 0x01, 0x00]),
        ];
        for (name, bytes) in cases {
            assert!(Reader::new(bytes).value().is_err(), "{name}");
        }
        let mut reader = Reader::new(&[0x04, 0x01, 0x00, 0x00]);
        reader.octet_string().expect("string");
        assert_eq!(reader.finish(), Err(BerError::TrailingBytes));
        assert_eq!(
            Reader::new(&[0x02, 0x01, 0x00]).octet_string(),
            Err(BerError::UnexpectedTag {
                expected: tag::OCTET_STRING,
                found: tag::INTEGER
            })
        );
    }

    #[test]
    fn nesting_is_limited() {
        fn nested(levels: usize) -> Vec<u8> {
            let mut value = encode_integer(1);
            for _ in 0..levels {
                value = encode_sequence(&value);
            }
            value
        }
        assert!(check_structure(&nested(MAX_DEPTH - 1)).is_ok());
        assert_eq!(check_structure(&nested(MAX_DEPTH)), Err(BerError::TooDeep));
        assert_eq!(check_structure(&nested(200)), Err(BerError::TooDeep));
        // Declared lengths beyond the data, stacked ten thousand times.
        let mut hostile = Vec::new();
        for _ in 0..10_000 {
            hostile.extend_from_slice(&[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]);
        }
        assert_eq!(check_structure(&hostile), Err(BerError::Truncated));
    }

    #[test]
    fn messages_over_the_limit_are_refused() {
        let big = vec![0u8; MAX_MESSAGE_LEN + 1];
        assert_eq!(check_structure(&big), Err(BerError::MessageTooLarge));
    }

    #[test]
    fn offsets_are_relative_to_the_outermost_buffer() {
        let inner = encode_octet_string(b"abc");
        let outer = encode_sequence(&[encode_integer(1), inner].concat());
        let mut top = Reader::new(&outer);
        let sequence = top.expect(tag::SEQUENCE).expect("sequence");
        let mut reader = top.enter(&sequence).expect("enter");
        reader.integer().expect("integer");
        let string = reader.expect(tag::OCTET_STRING).expect("string");
        assert_eq!(&outer[string.offset..string.offset + 3], b"abc");
    }

    mod property {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #[test]
            fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
                let _ = check_structure(&data);
                let mut reader = Reader::new(&data);
                while !reader.is_empty() {
                    match reader.value() {
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                let _ = decode_oid(&data);
                let _ = decode_integer(&data);
                let _ = decode_unsigned32(&data);
                let _ = decode_unsigned64(&data);
            }

            #[test]
            fn values_roundtrip(
                number in any::<i64>(),
                counter in any::<u64>(),
                octets in proptest::collection::vec(any::<u8>(), 0..400),
                arcs in proptest::collection::vec(any::<u32>(), 0..20),
            ) {
                for value in [
                    Value::Integer(number),
                    Value::Counter64(counter),
                    Value::Counter32(u32::try_from(counter & 0xFFFF_FFFF).unwrap_or(0)),
                    Value::OctetString(octets.clone()),
                    Value::Opaque(octets),
                ] {
                    value_roundtrip(&value);
                }
                let mut full = vec![1, 3];
                full.extend(arcs);
                value_roundtrip(&Value::Oid(Oid(full)));
            }
        }
    }
}
