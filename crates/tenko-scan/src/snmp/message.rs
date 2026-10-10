//! The SNMPv3 message (RFC 3412) with the user-based security parameters (RFC 3414).
//!
//! `decode_message` reads the structure of a datagram without trusting it: it does not
//! check a digest and does not decrypt. The caller authenticates the datagram with
//! [`crate::snmp::usm`] first, then reads the scoped PDU (decrypting it when the message
//! carries it encrypted).

use std::{fmt, ops::Range};

use super::ber::{
    BerError, MAX_MESSAGE_LEN, Reader, Tlv, VarBind, encode_integer, encode_octet_string,
    encode_sequence, encode_tlv, tag,
};

/// The message version of SNMPv3.
pub const MSG_VERSION: i64 = 3;

/// The security model number of the user-based security model.
pub const SECURITY_MODEL_USM: i64 = 3;

/// The smallest `msgMaxSize` an engine may announce (RFC 3412, section 6.2).
const MIN_MAX_SIZE: i64 = 484;

/// The longest engine id and the longest user name (RFC 3411, RFC 3414).
const MAX_ID_LEN: usize = 32;

/// Why a message could not be decoded or encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageError {
    /// The BER structure is broken.
    Ber(BerError),
    /// A message version other than 3.
    Version(i64),
    /// A field out of range or a combination of fields that the standard forbids.
    Invalid(&'static str),
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageError::Ber(error) => write!(f, "malformed message: {error}"),
            MessageError::Version(version) => {
                write!(f, "message version {version} is not SNMPv3")
            }
            MessageError::Invalid(what) => write!(f, "invalid message: {what}"),
        }
    }
}

impl std::error::Error for MessageError {}

impl From<BerError> for MessageError {
    fn from(error: BerError) -> Self {
        MessageError::Ber(error)
    }
}

/// The flags of `msgFlags`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MsgFlags {
    /// The message is authenticated.
    pub auth: bool,
    /// The scoped PDU is encrypted (requires `auth`).
    pub privacy: bool,
    /// The receiver should send a Report when it cannot process the message.
    pub reportable: bool,
}

impl MsgFlags {
    /// The flags octet.
    pub fn to_byte(self) -> u8 {
        u8::from(self.auth) | (u8::from(self.privacy) << 1) | (u8::from(self.reportable) << 2)
    }

    /// The flags of an octet; unknown bits are ignored.
    pub fn from_byte(byte: u8) -> Self {
        Self {
            auth: byte & 0x01 != 0,
            privacy: byte & 0x02 != 0,
            reportable: byte & 0x04 != 0,
        }
    }
}

/// The user-based security parameters (RFC 3414, section 2.4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UsmParameters {
    /// `msgAuthoritativeEngineID`; empty in a discovery request.
    pub engine_id: Vec<u8>,
    /// `msgAuthoritativeEngineBoots`.
    pub boots: u32,
    /// `msgAuthoritativeEngineTime`, in seconds.
    pub time: u32,
    /// `msgUserName`.
    pub user: Vec<u8>,
    /// `msgAuthenticationParameters`: the truncated HMAC, or empty.
    pub auth_params: Vec<u8>,
    /// `msgPrivacyParameters`: the salt, or empty.
    pub priv_params: Vec<u8>,
}

/// The kind of a PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduKind {
    /// `GetRequest-PDU`.
    Get,
    /// `GetNextRequest-PDU`.
    GetNext,
    /// `Response-PDU`.
    Response,
    /// `GetBulkRequest-PDU`.
    GetBulk,
    /// `Report-PDU`.
    Report,
}

impl PduKind {
    /// The BER tag.
    pub fn tag(self) -> u8 {
        match self {
            PduKind::Get => tag::GET_REQUEST,
            PduKind::GetNext => tag::GET_NEXT_REQUEST,
            PduKind::Response => tag::RESPONSE,
            PduKind::GetBulk => tag::GET_BULK_REQUEST,
            PduKind::Report => tag::REPORT,
        }
    }

    /// The kind of a tag; `None` for the PDUs a manager never handles (`SetRequest`,
    /// `InformRequest`, traps).
    pub fn from_tag(tag_octet: u8) -> Option<Self> {
        match tag_octet {
            tag::GET_REQUEST => Some(PduKind::Get),
            tag::GET_NEXT_REQUEST => Some(PduKind::GetNext),
            tag::RESPONSE => Some(PduKind::Response),
            tag::GET_BULK_REQUEST => Some(PduKind::GetBulk),
            tag::REPORT => Some(PduKind::Report),
            _ => None,
        }
    }
}

/// A protocol data unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdu {
    /// What it is.
    pub kind: PduKind,
    /// `request-id`.
    pub request_id: i32,
    /// `error-status`; for a `GetBulk` request, `non-repeaters`.
    pub error_status: i32,
    /// `error-index`; for a `GetBulk` request, `max-repetitions`.
    pub error_index: i32,
    /// The variable bindings.
    pub varbinds: Vec<VarBind>,
}

impl Pdu {
    /// A `Get` or `GetNext` request.
    pub fn request(kind: PduKind, request_id: i32, varbinds: Vec<VarBind>) -> Self {
        Self {
            kind,
            request_id,
            error_status: 0,
            error_index: 0,
            varbinds,
        }
    }

    /// A `GetBulk` request.
    pub fn bulk(
        request_id: i32,
        non_repeaters: i32,
        max_repetitions: i32,
        varbinds: Vec<VarBind>,
    ) -> Self {
        Self {
            kind: PduKind::GetBulk,
            request_id,
            error_status: non_repeaters,
            error_index: max_repetitions,
            varbinds,
        }
    }

    /// Encodes the PDU.
    ///
    /// # Errors
    /// A variable binding that cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, BerError> {
        let mut bindings = Vec::new();
        for binding in &self.varbinds {
            bindings.extend(binding.encode()?);
        }
        let mut content = encode_integer(i64::from(self.request_id));
        content.extend(encode_integer(i64::from(self.error_status)));
        content.extend(encode_integer(i64::from(self.error_index)));
        content.extend(encode_sequence(&bindings));
        Ok(encode_tlv(self.kind.tag(), &content))
    }
}

/// A PDU with the context it is addressed to (RFC 3412, section 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedPdu {
    /// `contextEngineID`.
    pub context_engine_id: Vec<u8>,
    /// `contextName`.
    pub context_name: Vec<u8>,
    /// The PDU.
    pub pdu: Pdu,
}

impl ScopedPdu {
    /// Encodes the scoped PDU: the plaintext of an encrypted message.
    ///
    /// # Errors
    /// A variable binding that cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, BerError> {
        let mut content = encode_octet_string(&self.context_engine_id);
        content.extend(encode_octet_string(&self.context_name));
        content.extend(self.pdu.encode()?);
        Ok(encode_sequence(&content))
    }
}

/// The data of a message: the scoped PDU in the clear or encrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageData {
    /// A plaintext scoped PDU (privacy flag clear).
    Plain(ScopedPdu),
    /// The encrypted scoped PDU (privacy flag set): the content of the `OCTET STRING`.
    Encrypted(Vec<u8>),
}

/// An SNMPv3 message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// `msgID`.
    pub msg_id: i32,
    /// `msgMaxSize`: the largest message the sender accepts.
    pub max_size: u32,
    /// `msgFlags`.
    pub flags: MsgFlags,
    /// `msgSecurityModel`; 3 is the user-based model.
    pub security_model: i64,
    /// The security parameters.
    pub usm: UsmParameters,
    /// The data.
    pub data: MessageData,
    /// Where `msgAuthenticationParameters` sit in the datagram this message was decoded
    /// from, for the digest check; `0..0` for a message built in memory.
    pub auth_params_at: Range<usize>,
}

/// An encoded message and where its authentication parameters sit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoded {
    /// The datagram.
    pub bytes: Vec<u8>,
    /// The range of `msgAuthenticationParameters` in `bytes`, to be filled in with the
    /// digest once the rest is final.
    pub auth_params: Range<usize>,
}

impl Message {
    /// Encodes the message.
    ///
    /// # Errors
    /// A variable binding that cannot be encoded or a message over
    /// [`MAX_MESSAGE_LEN`] octets.
    pub fn encode(&self) -> Result<Encoded, MessageError> {
        let global = encode_sequence(
            &[
                encode_integer(i64::from(self.msg_id)),
                encode_integer(i64::from(self.max_size)),
                encode_octet_string(&[self.flags.to_byte()]),
                encode_integer(self.security_model),
            ]
            .concat(),
        );
        let usm = encode_sequence(
            &[
                encode_octet_string(&self.usm.engine_id),
                encode_integer(i64::from(self.usm.boots)),
                encode_integer(i64::from(self.usm.time)),
                encode_octet_string(&self.usm.user),
                encode_octet_string(&self.usm.auth_params),
                encode_octet_string(&self.usm.priv_params),
            ]
            .concat(),
        );
        let data = match &self.data {
            MessageData::Plain(scoped) => scoped.encode()?,
            MessageData::Encrypted(octets) => encode_octet_string(octets),
        };
        let content = [
            encode_integer(MSG_VERSION),
            global,
            encode_octet_string(&usm),
            data,
        ]
        .concat();
        let bytes = encode_sequence(&content);
        if bytes.len() > MAX_MESSAGE_LEN {
            return Err(BerError::MessageTooLarge.into());
        }
        Ok(Encoded {
            auth_params: find_auth_params(&bytes)?,
            bytes,
        })
    }

    /// The plaintext scoped PDU.
    ///
    /// # Errors
    /// The message carries the scoped PDU encrypted.
    pub fn scoped_pdu(&self) -> Result<&ScopedPdu, MessageError> {
        match &self.data {
            MessageData::Plain(scoped) => Ok(scoped),
            MessageData::Encrypted(_) => Err(MessageError::Invalid("the scoped PDU is encrypted")),
        }
    }
}

/// Finds `msgAuthenticationParameters` in an encoded message without checking any value.
fn find_auth_params(bytes: &[u8]) -> Result<Range<usize>, BerError> {
    let mut top = Reader::new(bytes);
    let outer = top.expect(tag::SEQUENCE)?;
    let mut message = top.enter(&outer)?;
    message.expect(tag::INTEGER)?;
    message.expect(tag::SEQUENCE)?;
    let parameters = message.expect(tag::OCTET_STRING)?;
    let mut wrapper = message.enter(&parameters)?;
    let mut sequence = wrapper.sequence()?;
    for expected in [
        tag::OCTET_STRING,
        tag::INTEGER,
        tag::INTEGER,
        tag::OCTET_STRING,
    ] {
        sequence.expect(expected)?;
    }
    let auth = sequence.expect(tag::OCTET_STRING)?;
    Ok(auth.offset..auth.offset + auth.content.len())
}

/// The parts of a message that come before its data.
struct Header<'a> {
    msg_id: i32,
    max_size: u32,
    flags: MsgFlags,
    security_model: i64,
    usm: UsmParameters,
    auth_params_at: Range<usize>,
    data: Tlv<'a>,
    data_reader: Reader<'a>,
}

fn to_i32(value: i64, what: &'static str) -> Result<i32, MessageError> {
    i32::try_from(value).map_err(|_| MessageError::Invalid(what))
}

fn to_u32_in_i32_range(value: i64, what: &'static str) -> Result<u32, MessageError> {
    if (0..=i64::from(i32::MAX)).contains(&value) {
        u32::try_from(value).map_err(|_| MessageError::Invalid(what))
    } else {
        Err(MessageError::Invalid(what))
    }
}

fn bounded(octets: &[u8], limit: usize, what: &'static str) -> Result<Vec<u8>, MessageError> {
    if octets.len() > limit {
        Err(MessageError::Invalid(what))
    } else {
        Ok(octets.to_vec())
    }
}

fn read_header(bytes: &[u8]) -> Result<Header<'_>, MessageError> {
    if bytes.len() > MAX_MESSAGE_LEN {
        return Err(BerError::MessageTooLarge.into());
    }
    let mut top = Reader::new(bytes);
    let outer = top.expect(tag::SEQUENCE)?;
    top.finish()?;
    let mut message = top.enter(&outer)?;

    let version = message.integer()?;
    if version != MSG_VERSION {
        return Err(MessageError::Version(version));
    }

    let mut global = message.sequence()?;
    let msg_id = to_u32_in_i32_range(global.integer()?, "msgID is out of range")?;
    let max_size = global.integer()?;
    if !(MIN_MAX_SIZE..=i64::from(i32::MAX)).contains(&max_size) {
        return Err(MessageError::Invalid("msgMaxSize is out of range"));
    }
    let flags = match global.octet_string()? {
        [byte] => MsgFlags::from_byte(*byte),
        _ => return Err(MessageError::Invalid("msgFlags is not one octet")),
    };
    let security_model = global.integer()?;
    global.finish()?;
    if flags.privacy && !flags.auth {
        return Err(MessageError::Invalid("privacy without authentication"));
    }

    let parameters = message.expect(tag::OCTET_STRING)?;
    let mut wrapper = message.enter(&parameters)?;
    let mut sequence = wrapper.sequence()?;
    wrapper.finish()?;
    let engine_id = bounded(
        sequence.octet_string()?,
        MAX_ID_LEN,
        "the authoritative engine id is longer than 32 octets",
    )?;
    let boots = to_u32_in_i32_range(sequence.integer()?, "engine boots out of range")?;
    let time = to_u32_in_i32_range(sequence.integer()?, "engine time out of range")?;
    let user = bounded(
        sequence.octet_string()?,
        MAX_ID_LEN,
        "the user name is longer than 32 octets",
    )?;
    let auth = sequence.expect(tag::OCTET_STRING)?;
    let auth_params = bounded(
        auth.content,
        64,
        "the authentication parameters are longer than 64 octets",
    )?;
    let priv_params = bounded(
        sequence.octet_string()?,
        16,
        "the privacy parameters are longer than 16 octets",
    )?;
    sequence.finish()?;

    let data = message.read()?;
    let data_reader = message.enter(&data)?;
    message.finish()?;
    Ok(Header {
        msg_id: i32::try_from(msg_id)
            .map_err(|_| MessageError::Invalid("msgID is out of range"))?,
        max_size: to_u32_in_i32_range(max_size, "msgMaxSize is out of range")?,
        flags,
        security_model,
        usm: UsmParameters {
            engine_id,
            boots,
            time,
            user,
            auth_params,
            priv_params,
        },
        auth_params_at: auth.offset..auth.offset + auth.content.len(),
        data,
        data_reader,
    })
}

/// Reads the structure of a datagram as an SNMPv3 message.
///
/// The digest is not checked and encrypted data stays encrypted; see the module
/// documentation. Input over [`MAX_MESSAGE_LEN`] octets, trailing octets, a version other
/// than 3, out-of-range fields and a privacy flag that disagrees with the data are
/// refused.
///
/// # Errors
/// The first problem found.
pub fn decode_message(bytes: &[u8]) -> Result<Message, MessageError> {
    let header = read_header(bytes)?;
    let data = match header.data.tag {
        tag::SEQUENCE => {
            if header.flags.privacy {
                return Err(MessageError::Invalid(
                    "the privacy flag is set but the scoped PDU is in the clear",
                ));
            }
            MessageData::Plain(read_scoped_pdu(header.data_reader)?)
        }
        tag::OCTET_STRING => {
            if !header.flags.privacy {
                return Err(MessageError::Invalid(
                    "the scoped PDU is encrypted but the privacy flag is clear",
                ));
            }
            MessageData::Encrypted(header.data.content.to_vec())
        }
        found => {
            return Err(BerError::UnexpectedTag {
                expected: tag::SEQUENCE,
                found,
            }
            .into());
        }
    };
    Ok(Message {
        msg_id: header.msg_id,
        max_size: header.max_size,
        flags: header.flags,
        security_model: header.security_model,
        usm: header.usm,
        data,
        auth_params_at: header.auth_params_at,
    })
}

/// Reads a scoped PDU: the plaintext of an encrypted message once it is decrypted.
///
/// # Errors
/// The first problem found.
pub fn decode_scoped_pdu(bytes: &[u8]) -> Result<ScopedPdu, MessageError> {
    if bytes.len() > MAX_MESSAGE_LEN {
        return Err(BerError::MessageTooLarge.into());
    }
    let mut top = Reader::new(bytes);
    let outer = top.expect(tag::SEQUENCE)?;
    top.finish()?;
    read_scoped_pdu(top.enter(&outer)?)
}

fn read_scoped_pdu(mut scoped: Reader<'_>) -> Result<ScopedPdu, MessageError> {
    let context_engine_id = bounded(
        scoped.octet_string()?,
        MAX_ID_LEN,
        "the context engine id is longer than 32 octets",
    )?;
    let context_name = bounded(
        scoped.octet_string()?,
        255,
        "the context name is longer than 255 octets",
    )?;
    let pdu_tlv = scoped.read()?;
    scoped.finish()?;
    let kind =
        PduKind::from_tag(pdu_tlv.tag).ok_or(MessageError::Invalid("unsupported PDU type"))?;
    let mut pdu = scoped.enter(&pdu_tlv)?;
    let request_id = to_i32(pdu.integer()?, "request-id is out of range")?;
    let error_status = to_i32(pdu.integer()?, "error-status is out of range")?;
    let error_index = to_i32(pdu.integer()?, "error-index is out of range")?;
    let mut bindings = pdu.sequence()?;
    pdu.finish()?;
    let mut varbinds = Vec::new();
    while !bindings.is_empty() {
        let mut binding = bindings.sequence()?;
        let oid = binding.oid()?;
        let value = binding.value()?;
        binding.finish()?;
        varbinds.push(VarBind { oid, value });
    }
    Ok(ScopedPdu {
        context_engine_id,
        context_name,
        pdu: Pdu {
            kind,
            request_id,
            error_status,
            error_index,
            varbinds,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snmp::ber::{Oid, Value};

    fn oid(text: &str) -> Oid {
        text.parse().expect("oid")
    }

    fn sample_pdu() -> Pdu {
        Pdu {
            kind: PduKind::Response,
            request_id: 4711,
            error_status: 0,
            error_index: 0,
            varbinds: vec![
                VarBind {
                    oid: oid("1.3.6.1.2.1.1.5.0"),
                    value: Value::OctetString(b"switch-a.example.net".to_vec()),
                },
                VarBind {
                    oid: oid("1.3.6.1.2.1.1.3.0"),
                    value: Value::TimeTicks(123_456),
                },
                VarBind {
                    oid: oid("1.3.6.1.2.1.1.9.0"),
                    value: Value::NoSuchObject,
                },
            ],
        }
    }

    fn sample_message(flags: MsgFlags, data: MessageData) -> Message {
        Message {
            msg_id: 1_234_567,
            max_size: 65_507,
            flags,
            security_model: SECURITY_MODEL_USM,
            usm: UsmParameters {
                engine_id: vec![0x80, 0x00, 0x1F, 0x88, 0x80, 0x01, 0x02, 0x03, 0x04],
                boots: 17,
                time: 123_456,
                user: b"monitor".to_vec(),
                auth_params: if flags.auth {
                    vec![0xAA; 12]
                } else {
                    Vec::new()
                },
                priv_params: if flags.privacy {
                    vec![0x55; 8]
                } else {
                    Vec::new()
                },
            },
            data,
            auth_params_at: 0..0,
        }
    }

    fn sample_scoped() -> ScopedPdu {
        ScopedPdu {
            context_engine_id: vec![0x80, 0x00, 0x1F, 0x88, 0x80, 0x01, 0x02, 0x03, 0x04],
            context_name: b"ctx".to_vec(),
            pdu: sample_pdu(),
        }
    }

    #[test]
    fn plaintext_message_roundtrips() {
        let flags = MsgFlags {
            auth: false,
            privacy: false,
            reportable: true,
        };
        let message = sample_message(flags, MessageData::Plain(sample_scoped()));
        let encoded = message.encode().expect("encode");
        let decoded = decode_message(&encoded.bytes).expect("decode");
        assert_eq!(decoded.auth_params_at, encoded.auth_params);
        assert!(decoded.auth_params_at.is_empty());
        assert_eq!(
            Message {
                auth_params_at: 0..0,
                ..decoded
            },
            message
        );
    }

    #[test]
    fn authenticated_message_records_where_the_digest_goes() {
        let flags = MsgFlags {
            auth: true,
            privacy: false,
            reportable: true,
        };
        let message = sample_message(flags, MessageData::Plain(sample_scoped()));
        let encoded = message.encode().expect("encode");
        assert_eq!(encoded.auth_params.len(), 12);
        assert_eq!(&encoded.bytes[encoded.auth_params.clone()], [0xAA; 12]);
        let decoded = decode_message(&encoded.bytes).expect("decode");
        assert_eq!(decoded.auth_params_at, encoded.auth_params);
        assert!(decoded.flags.auth);
    }

    #[test]
    fn encrypted_message_roundtrips() {
        let flags = MsgFlags {
            auth: true,
            privacy: true,
            reportable: false,
        };
        let scoped = sample_scoped().encode().expect("encode scoped pdu");
        let message = sample_message(flags, MessageData::Encrypted(scoped.clone()));
        let encoded = message.encode().expect("encode");
        let decoded = decode_message(&encoded.bytes).expect("decode");
        assert_eq!(decoded.data, MessageData::Encrypted(scoped.clone()));
        assert!(decoded.scoped_pdu().is_err());
        assert_eq!(decode_scoped_pdu(&scoped), Ok(sample_scoped()));
    }

    #[test]
    fn bulk_requests_carry_their_parameters() {
        let pdu = Pdu::bulk(9, 0, 25, vec![VarBind::request(oid("1.3.6.1.2.1.2.2.1.2"))]);
        let scoped = ScopedPdu {
            context_engine_id: Vec::new(),
            context_name: Vec::new(),
            pdu,
        };
        let decoded = decode_scoped_pdu(&scoped.encode().expect("encode")).expect("decode");
        assert_eq!(decoded.pdu.kind, PduKind::GetBulk);
        assert_eq!(decoded.pdu.error_status, 0);
        assert_eq!(decoded.pdu.error_index, 25);
        assert_eq!(decoded.pdu.varbinds[0].value, Value::Null);
    }

    #[test]
    fn a_discovery_request_has_the_expected_shape() {
        // msgID 1, noAuthNoPriv and reportable, USM with an empty engine id and user, and a
        // `GetRequest` without bindings: the packet an SNMPv3 manager sends to find an engine id.
        let expected: &[u8] = &[
            0x30, 0x38, 0x02, 0x01, 0x03, 0x30, 0x0E, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0xFF,
            0xE3, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x10, 0x30, 0x0E, 0x04, 0x00, 0x02,
            0x01, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x30, 0x11, 0x04,
            0x00, 0x04, 0x00, 0xA0, 0x0B, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            0x30, 0x00,
        ];
        let message = Message {
            msg_id: 1,
            max_size: 65_507,
            flags: MsgFlags {
                auth: false,
                privacy: false,
                reportable: true,
            },
            security_model: SECURITY_MODEL_USM,
            usm: UsmParameters::default(),
            data: MessageData::Plain(ScopedPdu {
                context_engine_id: Vec::new(),
                context_name: Vec::new(),
                pdu: Pdu::request(PduKind::Get, 1, Vec::new()),
            }),
            auth_params_at: 0..0,
        };
        assert_eq!(message.encode().expect("encode").bytes, expected);
        assert_eq!(decode_message(expected).expect("decode").msg_id, 1);
    }

    fn valid_bytes() -> Vec<u8> {
        let flags = MsgFlags {
            auth: false,
            privacy: false,
            reportable: true,
        };
        sample_message(flags, MessageData::Plain(sample_scoped()))
            .encode()
            .expect("encode")
            .bytes
    }

    #[test]
    fn every_truncation_is_refused() {
        let bytes = valid_bytes();
        for length in 0..bytes.len() {
            assert!(decode_message(&bytes[..length]).is_err(), "{length}");
        }
    }

    #[test]
    fn trailing_octets_are_refused() {
        let mut bytes = valid_bytes();
        bytes.push(0);
        assert_eq!(
            decode_message(&bytes),
            Err(MessageError::Ber(BerError::TrailingBytes))
        );
    }

    #[test]
    fn other_versions_are_refused() {
        let mut bytes = valid_bytes();
        // The version INTEGER is the first value inside the outer SEQUENCE, whose header is
        // two or three octets long.
        let position = bytes
            .windows(3)
            .position(|window| window == [0x02, 0x01, 0x03])
            .expect("version");
        assert!(position <= 4);
        bytes[position + 2] = 1;
        assert_eq!(decode_message(&bytes), Err(MessageError::Version(1)));
    }

    #[test]
    fn privacy_flag_and_data_must_agree() {
        let flags = MsgFlags {
            auth: true,
            privacy: true,
            reportable: false,
        };
        let plain = sample_message(flags, MessageData::Plain(sample_scoped()));
        assert!(decode_message(&plain.encode().expect("encode").bytes).is_err());
        let flags = MsgFlags {
            auth: true,
            privacy: false,
            reportable: false,
        };
        let encrypted = sample_message(flags, MessageData::Encrypted(vec![1, 2, 3]));
        assert!(decode_message(&encrypted.encode().expect("encode").bytes).is_err());
        let flags = MsgFlags {
            auth: false,
            privacy: true,
            reportable: false,
        };
        let without_auth = sample_message(flags, MessageData::Encrypted(vec![1, 2, 3]));
        assert!(decode_message(&without_auth.encode().expect("encode").bytes).is_err());
    }

    #[test]
    fn out_of_range_fields_are_refused() {
        let flags = MsgFlags::default();
        let mut message = sample_message(flags, MessageData::Plain(sample_scoped()));
        message.max_size = 100;
        assert!(decode_message(&message.encode().expect("encode").bytes).is_err());
        let mut message = sample_message(flags, MessageData::Plain(sample_scoped()));
        message.msg_id = -1;
        assert!(decode_message(&message.encode().expect("encode").bytes).is_err());
        let mut message = sample_message(flags, MessageData::Plain(sample_scoped()));
        message.usm.engine_id = vec![1; 33];
        assert!(decode_message(&message.encode().expect("encode").bytes).is_err());
        let mut message = sample_message(flags, MessageData::Plain(sample_scoped()));
        message.usm.user = vec![b'u'; 33];
        assert!(decode_message(&message.encode().expect("encode").bytes).is_err());
    }

    #[test]
    fn unsupported_pdu_types_are_refused() {
        // A SetRequest-PDU (0xA3) inside an otherwise valid scoped PDU.
        let mut scoped = sample_scoped().encode().expect("encode");
        let position = scoped
            .iter()
            .position(|byte| *byte == 0xA2)
            .expect("pdu tag");
        scoped[position] = 0xA3;
        assert_eq!(
            decode_scoped_pdu(&scoped),
            Err(MessageError::Invalid("unsupported PDU type"))
        );
    }

    #[test]
    fn oversized_messages_are_refused() {
        let flags = MsgFlags::default();
        let mut scoped = sample_scoped();
        scoped.pdu.varbinds = vec![VarBind {
            oid: oid("1.3.6.1.2.1.1.1.0"),
            value: Value::OctetString(vec![b'x'; MAX_MESSAGE_LEN]),
        }];
        let message = sample_message(flags, MessageData::Plain(scoped));
        assert_eq!(
            message.encode(),
            Err(MessageError::Ber(BerError::MessageTooLarge))
        );
        assert!(decode_message(&vec![0u8; MAX_MESSAGE_LEN + 1]).is_err());
    }

    #[test]
    fn the_fuzz_target_path_works() {
        // The body of fuzz/fuzz_targets/scan_snmp_message.rs.
        fuzz_body(&valid_bytes());
        let flags = MsgFlags {
            auth: true,
            privacy: true,
            reportable: false,
        };
        let scoped = sample_scoped().encode().expect("encode scoped pdu");
        let encrypted = sample_message(flags, MessageData::Encrypted(scoped))
            .encode()
            .expect("encode")
            .bytes;
        fuzz_body(&encrypted);
    }

    /// The body of the fuzz target, so that the property tests run it too.
    fn fuzz_body(data: &[u8]) {
        if let Ok(message) = decode_message(data) {
            let scoped = match &message.data {
                MessageData::Plain(scoped) => Some(scoped.clone()),
                MessageData::Encrypted(octets) => decode_scoped_pdu(octets).ok(),
            };
            if let Some(scoped) = scoped {
                let encoded = scoped.encode().expect("a decoded scoped PDU encodes");
                assert_eq!(decode_scoped_pdu(&encoded), Ok(scoped));
            }
        }
        let _ = decode_scoped_pdu(data);
    }

    mod property {
        use proptest::prelude::*;

        use super::*;

        fn exercise(data: &[u8]) {
            fuzz_body(data);
            let _ = crate::snmp::ber::check_structure(data);
            if let Ok(message) = decode_message(data)
                && let MessageData::Encrypted(octets) = &message.data
            {
                let _ = decode_scoped_pdu(octets);
            }
            let _ = decode_scoped_pdu(data);
        }

        fn any_value() -> impl Strategy<Value = Value> {
            prop_oneof![
                any::<i64>().prop_map(Value::Integer),
                proptest::collection::vec(any::<u8>(), 0..64).prop_map(Value::OctetString),
                Just(Value::Null),
                proptest::collection::vec(any::<u32>(), 0..10).prop_map(|arcs| {
                    let mut full = vec![1, 3];
                    full.extend(arcs);
                    Value::Oid(Oid(full))
                }),
                any::<[u8; 4]>().prop_map(Value::IpAddress),
                any::<u32>().prop_map(Value::Counter32),
                any::<u32>().prop_map(Value::Gauge32),
                any::<u32>().prop_map(Value::TimeTicks),
                proptest::collection::vec(any::<u8>(), 0..64).prop_map(Value::Opaque),
                any::<u64>().prop_map(Value::Counter64),
                Just(Value::NoSuchObject),
                Just(Value::NoSuchInstance),
                Just(Value::EndOfMibView),
            ]
        }

        fn any_oid() -> impl Strategy<Value = Oid> {
            (0u32..3, proptest::collection::vec(any::<u32>(), 1..12)).prop_map(|(first, rest)| {
                let second = if first < 2 { rest[0] % 40 } else { rest[0] };
                let mut arcs = vec![first, second];
                arcs.extend_from_slice(&rest[1..]);
                Oid(arcs)
            })
        }

        proptest! {
            #[test]
            fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
                exercise(&data);
            }

            #[test]
            fn messages_roundtrip(
                msg_id in 0i32..=i32::MAX,
                request_id in any::<i32>(),
                error_status in 0i32..=18,
                bindings in proptest::collection::vec((any_oid(), any_value()), 0..12),
                engine_id in proptest::collection::vec(any::<u8>(), 0..=32),
                user in proptest::collection::vec(any::<u8>(), 0..=32),
                boots in 0u32..=i32::MAX as u32,
                time in 0u32..=i32::MAX as u32,
            ) {
                let scoped = ScopedPdu {
                    context_engine_id: engine_id.clone(),
                    context_name: user.clone(),
                    pdu: Pdu {
                        kind: PduKind::Response,
                        request_id,
                        error_status,
                        error_index: 0,
                        varbinds: bindings.into_iter().map(|(oid, value)| VarBind { oid, value }).collect(),
                    },
                };
                prop_assert_eq!(decode_scoped_pdu(&scoped.encode().expect("encode")), Ok(scoped.clone()));
                let message = Message {
                    msg_id,
                    max_size: 65_507,
                    flags: MsgFlags::default(),
                    security_model: SECURITY_MODEL_USM,
                    usm: UsmParameters { engine_id, boots, time, user, auth_params: Vec::new(), priv_params: Vec::new() },
                    data: MessageData::Plain(scoped),
                    auth_params_at: 0..0,
                };
                let encoded = message.encode().expect("encode");
                let decoded = decode_message(&encoded.bytes).expect("decode");
                prop_assert_eq!(decoded.auth_params_at.clone(), encoded.auth_params);
                prop_assert_eq!(Message { auth_params_at: 0..0, ..decoded }, message);
            }

            #[test]
            fn mutated_messages_never_panic(
                position in 0usize..4096,
                replacement in any::<u8>(),
                cut in 0usize..4096,
                insert in proptest::collection::vec(any::<u8>(), 0..8),
            ) {
                for base in [valid_bytes(), {
                    let flags = MsgFlags { auth: true, privacy: true, reportable: false };
                    let scoped = sample_scoped().encode().expect("encode");
                    sample_message(flags, MessageData::Encrypted(scoped))
                        .encode()
                        .expect("encode")
                        .bytes
                }] {
                    let mut flipped = base.clone();
                    let index = position % flipped.len();
                    flipped[index] = replacement;
                    exercise(&flipped);

                    let mut truncated = base.clone();
                    truncated.truncate(cut % (truncated.len() + 1));
                    exercise(&truncated);

                    let mut inserted = base.clone();
                    let at = position % (inserted.len() + 1);
                    for (offset, byte) in insert.iter().enumerate() {
                        inserted.insert(at + offset, *byte);
                    }
                    exercise(&inserted);
                }
            }
        }
    }
}
