//! Tenko's own DER codec of the Kerberos structures (RFC 4120 section 5), the GSS-API
//! initial context token (RFC 2743 section 3.1) and the SPNEGO tokens (RFC 4178), with no
//! ASN.1 library (ADR 0026 point 1, CON-03).
//!
//! The rules every decoder here keeps (R126):
//!
//! - **DER only.** Definite lengths in their shortest form, single-octet tags; an
//!   indefinite length (BER), a long form for a short length, a multi-octet tag or an
//!   INTEGER with a redundant leading octet is refused.
//! - **Bounded by the input.** Every length is checked against the octets that are there
//!   before anything is read; values are borrowed from the input, and an owned value is
//!   copied only once its octets have been read, so no allocation is sized by a declared
//!   length.
//! - **Bounded counts.** Every `SEQUENCE OF` has a maximum number of elements
//!   ([`MAX_ELEMENTS`] unless a field names a smaller one).
//! - **Typed refusals.** Every error is a [`DerError`] that names the structure and the
//!   field, and says what was wrong ([`DerErrorKind`]).
//!
//! The modules: [`reader`] and [`writer`] are the TLV layer, [`krb`] the structures of RFC
//! 4120 and RFC 3244, [`gss`] the GSS-API framing and SPNEGO.

pub mod gss;
pub mod krb;
pub mod reader;
pub mod writer;

pub use gss::{
    InitialContextToken, KrbToken, NegState, NegTokenInit, NegTokenResp, NegotiationToken, oid,
};
pub use krb::*;
pub use reader::Reader;
pub use writer::Der;

/// The most elements a `SEQUENCE OF` may hold unless the field names a smaller bound.
pub const MAX_ELEMENTS: usize = 256;

/// The deepest nesting the codec follows (`AD-IF-RELEVANT` inside authorization data, a
/// SPNEGO token inside a GSS token).
pub const MAX_DEPTH: usize = 4;

/// What was wrong with an encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerErrorKind {
    /// The input ended inside a tag, a length or a value.
    Truncated,
    /// Another tag was found than the one the structure requires.
    UnexpectedTag {
        /// The tag the field requires.
        expected: u8,
        /// The tag found.
        found: u8,
    },
    /// A required field is missing.
    Missing,
    /// A tag of more than one octet (tag number 31 or more).
    LongTag,
    /// An indefinite length (BER), which DER forbids.
    IndefiniteLength,
    /// A length in more octets than needed, or in more than four.
    BadLength,
    /// Octets after the last field of a structure.
    TrailingData,
    /// An INTEGER that is empty, has a redundant leading octet, or does not fit.
    BadInteger,
    /// A value outside the range the field allows.
    OutOfRange,
    /// A `KerberosTime` that is not `YYYYMMDDHHMMSSZ` with a valid date and time.
    BadTime,
    /// A string that is not UTF-8.
    BadString,
    /// A BIT STRING with a bad unused-bits octet.
    BadBitString,
    /// An OBJECT IDENTIFIER that is empty or not in its shortest form.
    BadOid,
    /// A BOOLEAN that is not one octet of 0x00 or 0xff.
    BadBoolean,
    /// More elements in a `SEQUENCE OF` than the field allows.
    TooMany,
    /// Nesting deeper than [`MAX_DEPTH`].
    TooDeep,
    /// A value the structure defines but Tenko does not take (the message type, the
    /// protocol version, a token identifier).
    Unsupported,
}

impl std::fmt::Display for DerErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DerErrorKind::Truncated => f.write_str("the input ends inside the value"),
            DerErrorKind::UnexpectedTag { expected, found } => {
                write!(f, "tag {found:#04x} where {expected:#04x} is required")
            }
            DerErrorKind::Missing => f.write_str("a required field is missing"),
            DerErrorKind::LongTag => f.write_str("a tag of more than one octet"),
            DerErrorKind::IndefiniteLength => f.write_str("an indefinite length (BER, not DER)"),
            DerErrorKind::BadLength => f.write_str("a length not in its shortest DER form"),
            DerErrorKind::TrailingData => f.write_str("octets after the last field"),
            DerErrorKind::BadInteger => f.write_str("an INTEGER not in DER or too large"),
            DerErrorKind::OutOfRange => f.write_str("a value outside the field's range"),
            DerErrorKind::BadTime => f.write_str("a time that is not YYYYMMDDHHMMSSZ"),
            DerErrorKind::BadString => f.write_str("a string that is not UTF-8"),
            DerErrorKind::BadBitString => f.write_str("a malformed BIT STRING"),
            DerErrorKind::BadOid => f.write_str("a malformed OBJECT IDENTIFIER"),
            DerErrorKind::BadBoolean => f.write_str("a BOOLEAN that is not DER"),
            DerErrorKind::TooMany => f.write_str("more elements than the field allows"),
            DerErrorKind::TooDeep => f.write_str("nesting deeper than allowed"),
            DerErrorKind::Unsupported => f.write_str("a value Tenko does not take"),
        }
    }
}

/// A refused encoding: the structure, the field and what was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{structure}.{field}: {kind}")]
pub struct DerError {
    /// The structure being decoded (`Ticket`, `NegTokenInit`).
    pub structure: &'static str,
    /// The field (`enc-part`, `mechTypes`); `-` for the structure's own tag and length.
    pub field: &'static str,
    /// What was wrong.
    pub kind: DerErrorKind,
}

impl DerError {
    /// A refusal of `field` in `structure`.
    pub const fn new(structure: &'static str, field: &'static str, kind: DerErrorKind) -> Self {
        Self {
            structure,
            field,
            kind,
        }
    }
}

/// Universal and Kerberos tags used by the codec.
pub mod tag {
    /// BOOLEAN.
    pub const BOOLEAN: u8 = 0x01;
    /// INTEGER.
    pub const INTEGER: u8 = 0x02;
    /// BIT STRING.
    pub const BIT_STRING: u8 = 0x03;
    /// OCTET STRING.
    pub const OCTET_STRING: u8 = 0x04;
    /// OBJECT IDENTIFIER.
    pub const OID: u8 = 0x06;
    /// ENUMERATED.
    pub const ENUMERATED: u8 = 0x0a;
    /// `GeneralizedTime`.
    pub const GENERALIZED_TIME: u8 = 0x18;
    /// `GeneralString`, the `KerberosString` of RFC 4120.
    pub const GENERAL_STRING: u8 = 0x1b;
    /// SEQUENCE and SEQUENCE OF.
    pub const SEQUENCE: u8 = 0x30;

    /// The explicit context tag `[n]` (constructed).
    pub const fn context(n: u8) -> u8 {
        0xa0 | n
    }

    /// The application tag `[APPLICATION n]` (constructed).
    pub const fn application(n: u8) -> u8 {
        0x60 | n
    }
}

#[cfg(test)]
mod tests;
