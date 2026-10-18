//! dnstap in Frame Streams files (`format = "dnstap"`): the encoder of the writer and a
//! small decoder for the reader and the tests. No protobuf compiler: the few fields of
//! `dnstap.proto` that Tenko writes are encoded by hand.
//!
//! A segment is a unidirectional Frame Streams file:
//!
//! ```text
//! START control frame   00000000 | length | 00000002 | 00000001 | 22 | "protobuf:dnstap.Dnstap"
//! data frame            length (4 octets, big endian, not 0) | one Dnstap protobuf message
//! ...
//! STOP control frame    00000000 | 00000004 | 00000003      (when the segment is closed)
//! ```
//!
//! Each logged query is two data frames: a `Message` of type `CLIENT_QUERY` with the query
//! time and the query message, and one of type `CLIENT_RESPONSE` with both times and the
//! response message. Both carry the socket family and protocol (UDP, TCP, DOT, DOH) and the
//! client address (or its pseudonym as an address of the same family, or none when the
//! client is hidden). The `Dnstap` envelope carries `identity` (the node's name), `version`
//! (the Tenko version) and `extra`, which says how the client field was written
//! (`tenko;client=pseudonym`, `address` or `hidden`, and `;cached` for an answer from the
//! cache). The ring keeps fixed-size slots, not the messages themselves, so the messages
//! are rebuilt from the logged fields: the header with the RCODE (an OPT record carries an
//! extended RCODE) and the question; the answer sections are not in the log.

use std::net::IpAddr;

use tenko_core::{
    Timestamp,
    dns::{DnsName, QueryTransport, Rtype},
};

use super::{ClientField, LogLine};

/// The Frame Streams content type of dnstap.
pub const CONTENT_TYPE: &[u8] = b"protobuf:dnstap.Dnstap";

/// Frame Streams control frame types.
pub mod control {
    /// ACCEPT (bidirectional streams only).
    pub const ACCEPT: u32 = 0x01;
    /// START: the first frame of a stream.
    pub const START: u32 = 0x02;
    /// STOP: the last frame of a stream.
    pub const STOP: u32 = 0x03;
    /// The control field that names a content type.
    pub const FIELD_CONTENT_TYPE: u32 = 0x01;
}

/// `Dnstap.Type.MESSAGE`.
pub const DNSTAP_MESSAGE: u64 = 1;

/// `Message.Type` values Tenko writes or reads.
pub mod message_type {
    /// A query from a client to this server.
    pub const CLIENT_QUERY: u64 = 5;
    /// The response to a client.
    pub const CLIENT_RESPONSE: u64 = 6;
}

/// `SocketFamily`.
pub mod family {
    /// IPv4.
    pub const INET: u64 = 1;
    /// IPv6.
    pub const INET6: u64 = 2;
}

/// `SocketProtocol`.
pub mod protocol {
    /// UDP.
    pub const UDP: u64 = 1;
    /// TCP.
    pub const TCP: u64 = 2;
    /// DNS over TLS.
    pub const DOT: u64 = 3;
    /// DNS over HTTPS.
    pub const DOH: u64 = 4;
}

/// The socket protocol of a transport.
pub const fn protocol_of(transport: QueryTransport) -> u64 {
    match transport {
        QueryTransport::Udp => protocol::UDP,
        QueryTransport::Tcp => protocol::TCP,
        QueryTransport::Dot => protocol::DOT,
        QueryTransport::Doh => protocol::DOH,
    }
}

const fn transport_of(protocol: u64) -> Option<QueryTransport> {
    match protocol {
        protocol::UDP => Some(QueryTransport::Udp),
        protocol::TCP => Some(QueryTransport::Tcp),
        protocol::DOT => Some(QueryTransport::Dot),
        protocol::DOH => Some(QueryTransport::Doh),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------
// Frame Streams.

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Appends the START control frame with the dnstap content type.
pub fn start_frame(out: &mut Vec<u8>) {
    let length = 4 + 4 + 4 + CONTENT_TYPE.len();
    put_u32(out, 0);
    put_u32(out, u32::try_from(length).unwrap_or(u32::MAX));
    put_u32(out, control::START);
    put_u32(out, control::FIELD_CONTENT_TYPE);
    put_u32(out, u32::try_from(CONTENT_TYPE.len()).unwrap_or(u32::MAX));
    out.extend_from_slice(CONTENT_TYPE);
}

/// Appends the STOP control frame.
pub fn stop_frame(out: &mut Vec<u8>) {
    put_u32(out, 0);
    put_u32(out, 4);
    put_u32(out, control::STOP);
}

/// Appends a data frame whose payload `payload` writes.
pub fn data_frame(out: &mut Vec<u8>, payload: impl FnOnce(&mut Vec<u8>)) {
    let at = out.len();
    put_u32(out, 0);
    payload(out);
    let length = u32::try_from(out.len() - at - 4).unwrap_or(u32::MAX);
    out[at..at + 4].copy_from_slice(&length.to_be_bytes());
}

/// One frame of a Frame Streams file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame<'a> {
    /// A control frame: its type and the content types it names.
    Control {
        /// START, STOP, ...
        kind: u32,
        /// The content type fields.
        content_types: Vec<&'a [u8]>,
    },
    /// A data frame's payload.
    Data(&'a [u8]),
}

/// The whole frames of a Frame Streams file with their offsets, and the offset where the
/// whole frames end (the file's length unless its tail is unfinished or damaged).
pub fn frames(bytes: &[u8]) -> (Vec<(usize, Frame<'_>)>, usize) {
    let read_u32 = |at: usize| -> Option<u32> {
        let quad = bytes.get(at..at + 4)?;
        Some(u32::from_be_bytes([quad[0], quad[1], quad[2], quad[3]]))
    };
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(length) = read_u32(at) {
        if length > 0 {
            let start = at + 4;
            let Some(payload) = usize::try_from(length)
                .ok()
                .and_then(|length| bytes.get(start..start.checked_add(length)?))
            else {
                break;
            };
            out.push((at, Frame::Data(payload)));
            at = start + payload.len();
            continue;
        }
        let Some(control_length) = read_u32(at + 4).and_then(|n| usize::try_from(n).ok()) else {
            break;
        };
        let start = at + 8;
        let Some(control) = start
            .checked_add(control_length)
            .and_then(|end| bytes.get(start..end))
        else {
            break;
        };
        let Some(kind) = control
            .get(..4)
            .map(|quad| u32::from_be_bytes([quad[0], quad[1], quad[2], quad[3]]))
        else {
            break;
        };
        let mut content_types = Vec::new();
        let mut field = 4;
        let mut damaged = false;
        while field < control.len() {
            let (Some(kind), Some(length)) = (
                control.get(field..field + 4),
                control.get(field + 4..field + 8).and_then(|quad| {
                    usize::try_from(u32::from_be_bytes([quad[0], quad[1], quad[2], quad[3]])).ok()
                }),
            ) else {
                damaged = true;
                break;
            };
            let Some(value) = control.get(field + 8..field + 8 + length) else {
                damaged = true;
                break;
            };
            if u32::from_be_bytes([kind[0], kind[1], kind[2], kind[3]])
                == control::FIELD_CONTENT_TYPE
            {
                content_types.push(value);
            }
            field += 8 + length;
        }
        if damaged {
            break;
        }
        out.push((
            at,
            Frame::Control {
                kind,
                content_types,
            },
        ));
        at = start + control_length;
    }
    (out, at)
}

// ---------------------------------------------------------------------------------------
// Protobuf.

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(u8::try_from(value & 0x7f).unwrap_or(0) | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).unwrap_or(0));
}

fn put_key(out: &mut Vec<u8>, field: u64, wire: u64) {
    put_varint(out, (field << 3) | wire);
}

fn put_uint(out: &mut Vec<u8>, field: u64, value: u64) {
    put_key(out, field, 0);
    put_varint(out, value);
}

fn put_bytes(out: &mut Vec<u8>, field: u64, value: &[u8]) {
    put_key(out, field, 2);
    put_varint(out, u64::try_from(value.len()).unwrap_or(u64::MAX));
    out.extend_from_slice(value);
}

fn put_fixed32(out: &mut Vec<u8>, field: u64, value: u32) {
    put_key(out, field, 5);
    out.extend_from_slice(&value.to_le_bytes());
}

/// The `Message` fields Tenko writes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message {
    /// `Message.Type`.
    pub kind: u64,
    /// `SocketFamily`.
    pub socket_family: Option<u64>,
    /// `SocketProtocol`.
    pub socket_protocol: Option<u64>,
    /// The client's address (4 or 16 octets).
    pub query_address: Option<Vec<u8>>,
    /// The client's port.
    pub query_port: Option<u64>,
    /// Seconds since 1970 when the query arrived.
    pub query_time_sec: Option<u64>,
    /// And the nanoseconds.
    pub query_time_nsec: Option<u32>,
    /// The query in wire form.
    pub query_message: Option<Vec<u8>>,
    /// Seconds since 1970 when the response left.
    pub response_time_sec: Option<u64>,
    /// And the nanoseconds.
    pub response_time_nsec: Option<u32>,
    /// The response in wire form.
    pub response_message: Option<Vec<u8>>,
}

/// The `Dnstap` envelope.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dnstap {
    /// The server's identity.
    pub identity: Option<Vec<u8>>,
    /// The server's version.
    pub version: Option<Vec<u8>>,
    /// Free-form extra data.
    pub extra: Option<Vec<u8>>,
    /// `Dnstap.Type` (1: MESSAGE).
    pub kind: u64,
    /// The message.
    pub message: Option<Message>,
}

impl Message {
    fn encode(&self, out: &mut Vec<u8>) {
        put_uint(out, 1, self.kind);
        if let Some(value) = self.socket_family {
            put_uint(out, 2, value);
        }
        if let Some(value) = self.socket_protocol {
            put_uint(out, 3, value);
        }
        if let Some(value) = &self.query_address {
            put_bytes(out, 4, value);
        }
        if let Some(value) = self.query_port {
            put_uint(out, 6, value);
        }
        if let Some(value) = self.query_time_sec {
            put_uint(out, 8, value);
        }
        if let Some(value) = self.query_time_nsec {
            put_fixed32(out, 9, value);
        }
        if let Some(value) = &self.query_message {
            put_bytes(out, 10, value);
        }
        if let Some(value) = self.response_time_sec {
            put_uint(out, 12, value);
        }
        if let Some(value) = self.response_time_nsec {
            put_fixed32(out, 13, value);
        }
        if let Some(value) = &self.response_message {
            put_bytes(out, 14, value);
        }
    }
}

impl Dnstap {
    /// Appends the protobuf encoding; `scratch` holds the nested message meanwhile.
    pub fn encode(&self, out: &mut Vec<u8>, scratch: &mut Vec<u8>) {
        if let Some(value) = &self.identity {
            put_bytes(out, 1, value);
        }
        if let Some(value) = &self.version {
            put_bytes(out, 2, value);
        }
        if let Some(value) = &self.extra {
            put_bytes(out, 3, value);
        }
        if let Some(message) = &self.message {
            scratch.clear();
            message.encode(scratch);
            put_bytes(out, 14, scratch);
        }
        put_uint(out, 15, self.kind);
    }

    /// Decodes a protobuf `Dnstap` message; unknown fields are skipped.
    ///
    /// # Errors
    ///
    /// The bytes are not a well-formed protobuf message.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut out = Self::default();
        let mut reader = Reader { bytes, at: 0 };
        while let Some((field, value)) = reader.next()? {
            match (field, value) {
                (1, Value::Bytes(bytes)) => out.identity = Some(bytes.to_vec()),
                (2, Value::Bytes(bytes)) => out.version = Some(bytes.to_vec()),
                (3, Value::Bytes(bytes)) => out.extra = Some(bytes.to_vec()),
                (14, Value::Bytes(bytes)) => out.message = Some(Message::decode(bytes)?),
                (15, Value::Varint(value)) => out.kind = value,
                _ => {}
            }
        }
        Ok(out)
    }
}

impl Message {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut out = Self::default();
        let mut reader = Reader { bytes, at: 0 };
        while let Some((field, value)) = reader.next()? {
            match (field, value) {
                (1, Value::Varint(value)) => out.kind = value,
                (2, Value::Varint(value)) => out.socket_family = Some(value),
                (3, Value::Varint(value)) => out.socket_protocol = Some(value),
                (4, Value::Bytes(bytes)) => out.query_address = Some(bytes.to_vec()),
                (6, Value::Varint(value)) => out.query_port = Some(value),
                (8, Value::Varint(value)) => out.query_time_sec = Some(value),
                (9, Value::Fixed32(value)) => out.query_time_nsec = Some(value),
                (10, Value::Bytes(bytes)) => out.query_message = Some(bytes.to_vec()),
                (12, Value::Varint(value)) => out.response_time_sec = Some(value),
                (13, Value::Fixed32(value)) => out.response_time_nsec = Some(value),
                (14, Value::Bytes(bytes)) => out.response_message = Some(bytes.to_vec()),
                _ => {}
            }
        }
        Ok(out)
    }
}

/// A protobuf message that does not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a dnstap frame is not a well-formed protobuf message")]
pub struct DecodeError;

enum Value<'a> {
    Varint(u64),
    Fixed64,
    Bytes(&'a [u8]),
    Fixed32(u32),
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn varint(&mut self) -> Result<u64, DecodeError> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *self.bytes.get(self.at).ok_or(DecodeError)?;
            self.at += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(DecodeError)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.at.checked_add(length).ok_or(DecodeError)?;
        let out = self.bytes.get(self.at..end).ok_or(DecodeError)?;
        self.at = end;
        Ok(out)
    }

    fn next(&mut self) -> Result<Option<(u64, Value<'a>)>, DecodeError> {
        if self.at >= self.bytes.len() {
            return Ok(None);
        }
        let key = self.varint()?;
        let value = match key & 7 {
            0 => Value::Varint(self.varint()?),
            1 => {
                self.take(8)?;
                Value::Fixed64
            }
            2 => {
                let length = usize::try_from(self.varint()?).map_err(|_| DecodeError)?;
                Value::Bytes(self.take(length)?)
            }
            5 => {
                let quad = self.take(4)?;
                Value::Fixed32(u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]]))
            }
            _ => return Err(DecodeError),
        };
        Ok(Some((key >> 3, value)))
    }
}

// ---------------------------------------------------------------------------------------
// The DNS messages rebuilt from a log entry.

/// Appends a DNS message with the question `qname`/`qtype` (class IN): a query when
/// `rcode` is `None`, else a response with that RCODE (an OPT record carries the upper
/// bits of an extended RCODE).
pub fn build_message(out: &mut Vec<u8>, qname: &[u8], qtype: u16, rcode: Option<u16>) {
    let (flags, extended) = match rcode {
        None => (0u16, None),
        Some(rcode) => (
            0x8000 | (rcode & 0x0f),
            (rcode > 0x0f).then_some(rcode >> 4),
        ),
    };
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&u16::from(extended.is_some()).to_be_bytes());
    out.extend_from_slice(if qname.is_empty() { &[0] } else { qname });
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    if let Some(upper) = extended {
        out.push(0);
        out.extend_from_slice(&41u16.to_be_bytes());
        out.extend_from_slice(&1232u16.to_be_bytes());
        let ttl = u32::from(upper & 0xff) << 24;
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
    }
}

/// The question and the RCODE of a message [`build_message`] wrote.
fn parse_message(bytes: &[u8]) -> Option<(String, u16, u16)> {
    let header = bytes.get(..12)?;
    let flags = u16::from_be_bytes([header[2], header[3]]);
    let counts = |at: usize| u16::from_be_bytes([header[at], header[at + 1]]);
    if counts(4) == 0 {
        return None;
    }
    let (name, used) = DnsName::from_wire(&bytes[12..]).ok()?;
    let mut at = 12 + used;
    let qtype = u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]);
    at += 4;
    let mut rcode = flags & 0x0f;
    if counts(6) == 0 && counts(8) == 0 && counts(10) == 1 && bytes.get(at) == Some(&0) {
        let rtype = u16::from_be_bytes([*bytes.get(at + 1)?, *bytes.get(at + 2)?]);
        if rtype == 41 {
            rcode |= u16::from(*bytes.get(at + 5)?) << 4;
        }
    }
    Some((name.to_string(), qtype, rcode))
}

/// The address octets of an address.
pub fn address_octets(address: IpAddr) -> Vec<u8> {
    match address.to_canonical() {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// The `extra` field Tenko writes.
pub fn extra(client: ClientField, cached: bool) -> Vec<u8> {
    let mut out = format!("tenko;client={}", client.as_str());
    if cached {
        out.push_str(";cached");
    }
    out.into_bytes()
}

fn time_of(seconds: u64, nanos: u32) -> Option<Timestamp> {
    let nanos = i128::from(seconds) * 1_000_000_000 + i128::from(nanos);
    Timestamp::from_unix_nanos(nanos).ok()
}

/// The log line of a decoded `CLIENT_RESPONSE` frame; `None` for any other frame.
pub fn line_of(dnstap: &Dnstap) -> Option<LogLine> {
    let message = dnstap.message.as_ref()?;
    if dnstap.kind != DNSTAP_MESSAGE || message.kind != message_type::CLIENT_RESPONSE {
        return None;
    }
    let extra = dnstap
        .extra
        .as_deref()
        .and_then(|extra| std::str::from_utf8(extra).ok())
        .unwrap_or("");
    let field = |name: &str| extra.split(';').any(|part| part == name);
    let client = if field("client=hidden") {
        None
    } else if field("client=pseudonym") {
        message
            .query_address
            .as_deref()
            .map(super::keys::pseudonym_text)
    } else {
        message.query_address.as_deref().and_then(|octets| {
            match octets.len() {
                4 => <[u8; 4]>::try_from(octets).ok().map(IpAddr::from),
                16 => <[u8; 16]>::try_from(octets).ok().map(IpAddr::from),
                _ => None,
            }
            .map(|address| address.to_canonical().to_string())
        })
    };
    let at = time_of(
        message.query_time_sec?,
        message.query_time_nsec.unwrap_or(0),
    )?;
    let answered = time_of(
        message.response_time_sec.or(message.query_time_sec)?,
        message
            .response_time_nsec
            .or(message.query_time_nsec)
            .unwrap_or(0),
    )?;
    let duration = answered.saturating_since(at);
    let wire = message
        .response_message
        .as_deref()
        .or(message.query_message.as_deref())?;
    let (qname, qtype, rcode) = parse_message(wire)?;
    Some(LogLine {
        at,
        client,
        transport: transport_of(message.socket_protocol?)?,
        qname,
        rtype: Rtype(qtype),
        rcode,
        view: None,
        blocked: None,
        cached: field("cached"),
        duration_micros: u32::try_from(duration.as_micros()).unwrap_or(u32::MAX),
    })
}
