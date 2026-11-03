//! Record data from presentation form: one parser per type, each appending the type's
//! uncompressed wire form, which the model then checks ([`Rdata::from_wire`]).
//!
//! The model's types (A, AAAA, CAA, CNAME, DNAME, DNSKEY, DS, HTTPS, MX, NS, NSEC, NSEC3,
//! NSEC3PARAM, PTR, RRSIG, SOA, SRV, SVCB, TLSA, TXT) have a parser here, and so have
//! the types the model keeps as opaque data whose syntax is simple (CDS and CDNSKEY like
//! DS and DNSKEY, HINFO, MB, MD, MF, MG, MINFO, MR, NAPTR, OPENPGPKEY, RP, SSHFP, ZONEMD).
//! Every type also reads the generic form of RFC 3597 (`\# length hex`). A type with
//! neither is not read: [`data`] answers `None`.
//!
//! [`Rdata::from_wire`]: tenko_core::dns::Rdata::from_wire

use std::net::{Ipv4Addr, Ipv6Addr};

use tenko_core::dns::{DnsName, RecordData, Rtype, rdata::MAX_RDATA_LEN, split_txt};

use super::{lexer::Token, text, types};
use crate::zone::encoding;

/// A syntax error: the line and the reason.
pub(super) type Bad = (usize, String);

/// The data fields of one record.
pub(super) struct Fields<'a> {
    src: &'a str,
    tokens: &'a [Token],
    index: usize,
    /// The line of the record's last token, for a field that is missing.
    last_line: usize,
    origin: &'a [u8],
}

/// One field.
#[derive(Clone, Copy)]
struct Field<'a> {
    text: &'a str,
    line: usize,
    quoted: bool,
    glued: bool,
}

impl<'a> Fields<'a> {
    /// The fields `tokens` of `src`, with names relative to `origin` (wire form).
    pub(super) fn new(
        src: &'a str,
        tokens: &'a [Token],
        last_line: usize,
        origin: &'a [u8],
    ) -> Self {
        Self {
            src,
            tokens,
            index: 0,
            last_line,
            origin,
        }
    }

    fn peek(&self) -> Option<Field<'a>> {
        self.tokens.get(self.index).map(|token| Field {
            text: token.text(self.src),
            line: token.line,
            quoted: token.quoted,
            glued: token.glued,
        })
    }

    fn next(&mut self, what: &str) -> Result<Field<'a>, Bad> {
        let field = self
            .peek()
            .ok_or_else(|| (self.last_line, format!("{what} is missing")))?;
        self.index += 1;
        Ok(field)
    }

    fn is_empty(&self) -> bool {
        self.index >= self.tokens.len()
    }

    fn number<T: std::str::FromStr>(&mut self, what: &str, range: &str) -> Result<T, Bad> {
        let field = self.next(what)?;
        text::decimal(field.text).ok_or_else(|| {
            (
                field.line,
                format!("{what} is a number from {range}, not `{}`", field.text),
            )
        })
    }

    fn u8(&mut self, what: &str) -> Result<u8, Bad> {
        self.number(what, "0 to 255")
    }

    fn u16(&mut self, what: &str) -> Result<u16, Bad> {
        self.number(what, "0 to 65535")
    }

    fn u32(&mut self, what: &str) -> Result<u32, Bad> {
        self.number(what, "0 to 4294967295")
    }

    fn duration(&mut self, what: &str) -> Result<u32, Bad> {
        let field = self.next(what)?;
        text::ttl(field.text).ok_or_else(|| {
            (
                field.line,
                format!(
                    "{what} is a number of seconds or a duration such as 1h30m, not `{}`",
                    field.text
                ),
            )
        })
    }

    fn algorithm(&mut self) -> Result<u8, Bad> {
        let field = self.next("the algorithm")?;
        types::parse_algorithm(field.text).ok_or_else(|| {
            (
                field.line,
                format!(
                    "the algorithm is a number from 0 to 255 or a mnemonic, not `{}`",
                    field.text
                ),
            )
        })
    }

    fn rtype(&mut self, what: &str) -> Result<Rtype, Bad> {
        let field = self.next(what)?;
        types::parse(field.text).ok_or_else(|| {
            (
                field.line,
                format!("{what} is a type mnemonic or TYPEnnn, not `{}`", field.text),
            )
        })
    }

    fn name(&mut self, what: &str, out: &mut Vec<u8>) -> Result<(), Bad> {
        let field = self.next(what)?;
        text::name(field.text, self.origin, out)
            .map_err(|reason| (field.line, format!("{what}: {reason}")))
    }

    fn charstring(&mut self, what: &str, out: &mut Vec<u8>) -> Result<(), Bad> {
        let field = self.next(what)?;
        let bytes = text::charstring(field.text)
            .map_err(|reason| (field.line, format!("{what}: {reason}")))?;
        push_sized(&bytes, out);
        Ok(())
    }

    /// The remaining fields joined, for base64 and hex that may be split across tokens; at
    /// most [`text::MAX_TOKEN_LEN`] characters.
    fn joined(&mut self, what: &str) -> Result<(String, usize), Bad> {
        let line = self.peek().map_or(self.last_line, |field| field.line);
        let mut joined = String::new();
        while let Some(field) = self.peek() {
            if joined.len() + field.text.len() > text::MAX_TOKEN_LEN {
                return Err((field.line, format!("{what} is longer than any record data")));
            }
            joined.push_str(field.text);
            self.index += 1;
        }
        Ok((joined, line))
    }

    fn base64(&mut self, what: &str, out: &mut Vec<u8>) -> Result<(), Bad> {
        let (joined, line) = self.joined(what)?;
        let bytes = encoding::base64_decode(&joined)
            .map_err(|reason| (line, format!("{what}: {reason}")))?;
        out.extend_from_slice(&bytes);
        Ok(())
    }

    fn hex(&mut self, what: &str, out: &mut Vec<u8>) -> Result<(), Bad> {
        let (joined, line) = self.joined(what)?;
        let bytes =
            encoding::hex_decode(&joined).map_err(|reason| (line, format!("{what}: {reason}")))?;
        out.extend_from_slice(&bytes);
        Ok(())
    }

    fn types(&mut self) -> Result<Vec<Rtype>, Bad> {
        let mut types = Vec::new();
        while !self.is_empty() {
            types.push(self.rtype("a type of the bitmap")?);
        }
        Ok(types)
    }

    /// Refuses fields left over.
    fn finish(&self) -> Result<(), Bad> {
        match self.peek() {
            None => Ok(()),
            Some(field) => Err((
                field.line,
                format!("`{}` is more data than the type takes", field.text),
            )),
        }
    }
}

fn push_sized(bytes: &[u8], out: &mut Vec<u8>) {
    out.push(u8::try_from(bytes.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(bytes);
}

/// Whether the data starts with the generic marker `\#`.
pub(super) fn is_generic(src: &str, tokens: &[Token]) -> bool {
    tokens
        .first()
        .is_some_and(|token| !token.quoted && token.text(src) == "\\#")
}

/// The generic form of RFC 3597, section 5: `\#`, the length in octets, then the octets in
/// hex, split across tokens as the writer likes.
pub(super) fn generic(fields: &mut Fields<'_>, out: &mut Vec<u8>) -> Result<(), Bad> {
    let _ = fields.next("the marker \\#")?;
    let length = usize::from(fields.number::<u16>("the length of the generic data", "0 to 65535")?);
    let start = out.len();
    fields.hex("the generic data", out)?;
    if out.len() - start != length {
        return Err((
            fields.last_line,
            format!(
                "the generic data has {} octets, not the {length} its length says",
                out.len() - start
            ),
        ));
    }
    Ok(())
}

/// Appends the wire form of the data of `rtype` read from its presentation form; `None`
/// for a type without a parser here.
///
/// # Errors
///
/// The line and reason of a field that does not parse, a missing field or a field too
/// many.
pub(super) fn data(
    rtype: Rtype,
    fields: &mut Fields<'_>,
    out: &mut Vec<u8>,
) -> Option<Result<(), Bad>> {
    let result = match rtype.0 {
        // A
        1 => address4(fields, out),
        // NS, MD, MF, CNAME, MB, MG, MR, PTR, DNAME
        2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 | 39 => fields.name("the name", out),
        // SOA
        6 => soa(fields, out),
        // HINFO
        13 => fields
            .charstring("the CPU", out)
            .and_then(|()| fields.charstring("the OS", out)),
        // MINFO, RP
        14 | 17 => fields
            .name("the first name", out)
            .and_then(|()| fields.name("the second name", out)),
        // MX
        15 => fields.u16("the preference").and_then(|preference| {
            out.extend_from_slice(&preference.to_be_bytes());
            fields.name("the exchange", out)
        }),
        // TXT
        16 => txt(fields, out),
        // AAAA
        28 => address6(fields, out),
        // SRV
        33 => srv(fields, out),
        // NAPTR
        35 => naptr(fields, out),
        // DS, CDS
        43 | 59 => ds(fields, out),
        // SSHFP
        44 => fields.u8("the algorithm").and_then(|algorithm| {
            let kind = fields.u8("the fingerprint type")?;
            out.extend_from_slice(&[algorithm, kind]);
            fields.hex("the fingerprint", out)
        }),
        // RRSIG
        46 => rrsig(fields, out),
        // NSEC
        47 => nsec(fields, out),
        // DNSKEY, CDNSKEY
        48 | 60 => dnskey(fields, out),
        // NSEC3
        50 => nsec3(fields, out),
        // NSEC3PARAM
        51 => nsec3param(fields, out),
        // TLSA
        52 => fields.u8("the certificate usage").and_then(|usage| {
            let selector = fields.u8("the selector")?;
            let matching = fields.u8("the matching type")?;
            out.extend_from_slice(&[usage, selector, matching]);
            fields.hex("the association data", out)
        }),
        // OPENPGPKEY
        61 => fields.base64("the key", out),
        // ZONEMD
        63 => fields.u32("the serial").and_then(|serial| {
            out.extend_from_slice(&serial.to_be_bytes());
            let scheme = fields.u8("the scheme")?;
            let algorithm = fields.u8("the hash algorithm")?;
            out.extend_from_slice(&[scheme, algorithm]);
            fields.hex("the digest", out)
        }),
        // SVCB, HTTPS
        64 | 65 => super::svcb::parse(fields, out),
        // CAA
        257 => caa(fields, out),
        _ => return None,
    };
    Some(result.and_then(|()| fields.finish()))
}

fn address4(fields: &mut Fields<'_>, out: &mut Vec<u8>) -> Result<(), Bad> {
    let field = fields.next("the address")?;
    let address: Ipv4Addr = field.text.parse().map_err(|_| {
        (
            field.line,
            format!("`{}` is not an IPv4 address", field.text),
        )
    })?;
    out.extend_from_slice(&address.octets());
    Ok(())
}

fn address6(fields: &mut Fields<'_>, out: &mut Vec<u8>) -> Result<(), Bad> {
    let field = fields.next("the address")?;
    let address: Ipv6Addr = field.text.parse().map_err(|_| {
        (
            field.line,
            format!("`{}` is not an IPv6 address", field.text),
        )
    })?;
    out.extend_from_slice(&address.octets());
    Ok(())
}

fn soa(fields: &mut Fields<'_>, out: &mut Vec<u8>) -> Result<(), Bad> {
    fields.name("the primary name server", out)?;
    fields.name("the mailbox", out)?;
    out.extend_from_slice(&fields.u32("the serial")?.to_be_bytes());
    for what in ["the refresh", "the retry", "the expire", "the minimum"] {
        out.extend_from_slice(&fields.duration(what)?.to_be_bytes());
    }
    Ok(())
}

/// TXT: one or more character strings; a string longer than 255 octets is split into
/// strings of at most 255 octets, as the model splits it (DNS-24).
fn txt(fields: &mut Fields<'_>, out: &mut Vec<u8>) -> Result<(), Bad> {
    if fields.is_empty() {
        return Err((
            fields.last_line,
            "a TXT record has at least one string".to_owned(),
        ));
    }
    while !fields.is_empty() {
        let field = fields.next("a string")?;
        let bytes = text::unescape(field.text).map_err(|reason| (field.line, reason.to_owned()))?;
        for part in split_txt(&bytes) {
            push_sized(part.as_bytes(), out);
        }
        if out.len() > MAX_RDATA_LEN {
            return Err((
                field.line,
                "the TXT data is longer than 65535 octets".to_owned(),
            ));
        }
    }
    Ok(())
}

fn srv(fields: &mut Fields<'_>, out: &mut Vec<u8>) -> Result<(), Bad> {
    for what in ["the priority", "the weight", "the port"] {
        out.extend_from_slice(&fields.u16(what)?.to_be_bytes());
    }
    fields.name("the target", out)
}

fn naptr(fields: &mut Fields<'_>, out: &mut Vec<u8>) -> Result<(), Bad> {
    for what in ["the order", "the preference"] {
        out.extend_from_slice(&fields.u16(what)?.to_be_bytes());
    }
    for what in ["the flags", "the services", "the regular expression"] {
        fields.charstring(what, out)?;
    }
    fields.name("the replacement", out)
}

fn ds(fields: &mut Fields<'_>, out: &mut Vec<u8>) -> Result<(), Bad> {
    out.extend_from_slice(&fields.u16("the key tag")?.to_be_bytes());
    let algorithm = fields.algorithm()?;
    let digest_type = fields.u8("the digest type")?;
    out.extend_from_slice(&[algorithm, digest_type]);
    fields.hex("the digest", out)
}

fn dnskey(fields: &mut Fields<'_>, out: &mut Vec<u8>) -> Result<(), Bad> {
    out.extend_from_slice(&fields.u16("the flags")?.to_be_bytes());
    let protocol = fields.u8("the protocol")?;
    let algorithm = fields.algorithm()?;
    out.extend_from_slice(&[protocol, algorithm]);
    fields.base64("the public key", out)
}

fn rrsig(fields: &mut Fields<'_>, out: &mut Vec<u8>) -> Result<(), Bad> {
    out.extend_from_slice(&fields.rtype("the type covered")?.0.to_be_bytes());
    let algorithm = fields.algorithm()?;
    let labels = fields.u8("the label count")?;
    out.extend_from_slice(&[algorithm, labels]);
    out.extend_from_slice(&fields.duration("the original TTL")?.to_be_bytes());
    for what in ["the expiration", "the inception"] {
        let field = fields.next(what)?;
        let time = text::time(field.text).ok_or_else(|| {
            (
                field.line,
                format!(
                    "{what} is YYYYMMDDHHmmSS or a number of seconds, not `{}`",
                    field.text
                ),
            )
        })?;
        out.extend_from_slice(&time.to_be_bytes());
    }
    out.extend_from_slice(&fields.u16("the key tag")?.to_be_bytes());
    fields.name("the signer", out)?;
    fields.base64("the signature", out)
}

fn nsec(fields: &mut Fields<'_>, out: &mut Vec<u8>) -> Result<(), Bad> {
    let mut next = Vec::new();
    fields.name("the next name", &mut next)?;
    out.extend_from_slice(&next);
    let types = fields.types()?;
    bitmap(&types, out);
    Ok(())
}

/// The type bitmap of NSEC and NSEC3 (RFC 4034, section 4.1.2), as the model writes it.
fn bitmap(types: &[Rtype], out: &mut Vec<u8>) {
    let mut wire = Vec::new();
    RecordData::Nsec {
        next: DnsName::root(),
        types: types.to_vec(),
    }
    .write_wire(&mut wire);
    // The root name is the first octet.
    out.extend_from_slice(wire.get(1..).unwrap_or_default());
}

fn salt(fields: &mut Fields<'_>, out: &mut Vec<u8>) -> Result<(), Bad> {
    let field = fields.next("the salt")?;
    let bytes = if field.text == "-" {
        Vec::new()
    } else {
        encoding::hex_decode(field.text)
            .map_err(|reason| (field.line, format!("the salt: {reason}")))?
    };
    if bytes.len() > 255 {
        return Err((field.line, "the salt is at most 255 octets".to_owned()));
    }
    push_sized(&bytes, out);
    Ok(())
}

fn nsec3(fields: &mut Fields<'_>, out: &mut Vec<u8>) -> Result<(), Bad> {
    nsec3param(fields, out)?;
    let field = fields.next("the next hashed owner name")?;
    let hashed = encoding::base32hex_decode(field.text)
        .map_err(|reason| (field.line, format!("the next hashed owner name: {reason}")))?;
    if hashed.is_empty() || hashed.len() > 255 {
        return Err((
            field.line,
            "the next hashed owner name is 1 to 255 octets".to_owned(),
        ));
    }
    push_sized(&hashed, out);
    let types = fields.types()?;
    bitmap(&types, out);
    Ok(())
}

fn nsec3param(fields: &mut Fields<'_>, out: &mut Vec<u8>) -> Result<(), Bad> {
    let algorithm = fields.u8("the hash algorithm")?;
    let flags = fields.u8("the flags")?;
    out.extend_from_slice(&[algorithm, flags]);
    out.extend_from_slice(&fields.u16("the iterations")?.to_be_bytes());
    salt(fields, out)
}

fn caa(fields: &mut Fields<'_>, out: &mut Vec<u8>) -> Result<(), Bad> {
    out.push(fields.u8("the flags")?);
    fields.charstring("the tag", out)?;
    let field = fields.next("the value")?;
    let value = text::unescape(field.text)
        .map_err(|reason| (field.line, format!("the value: {reason}")))?;
    out.extend_from_slice(&value);
    Ok(())
}

/// One SVCB parameter as written: the key, the raw value (escapes not yet decoded) and the
/// line.
pub(super) struct Param<'a> {
    pub(super) key: &'a str,
    pub(super) value: Option<&'a str>,
    pub(super) line: usize,
}

/// The fields' API for the SVCB parser.
mod svcb_fields {
    use super::{Bad, Fields, Param};

    impl<'a> Fields<'a> {
        /// The priority.
        pub(in super::super) fn priority(&mut self) -> Result<u16, Bad> {
            self.u16("the priority")
        }

        /// The target name.
        pub(in super::super) fn target(&mut self, out: &mut Vec<u8>) -> Result<(), Bad> {
            self.name("the target", out)
        }

        /// The next parameter, `None` after the last. `key="value"` is the unquoted
        /// `key=` and the quoted value glued to it.
        pub(in super::super) fn param(&mut self) -> Result<Option<Param<'a>>, Bad> {
            let Some(field) = self.peek() else {
                return Ok(None);
            };
            self.index += 1;
            if field.quoted {
                return Err((
                    field.line,
                    format!("a parameter key is expected, not `\"{}\"`", field.text),
                ));
            }
            let Some((key, value)) = field.text.split_once('=') else {
                return Ok(Some(Param {
                    key: field.text,
                    value: None,
                    line: field.line,
                }));
            };
            let quoted = self.peek().filter(|next| next.glued);
            let value = match quoted {
                Some(next) if value.is_empty() && next.quoted => {
                    self.index += 1;
                    next.text
                }
                Some(next) => {
                    return Err((
                        next.line,
                        format!("`{}` is glued to the parameter {key}", next.text),
                    ));
                }
                None => value,
            };
            Ok(Some(Param {
                key,
                value: Some(value),
                line: field.line,
            }))
        }
    }
}
