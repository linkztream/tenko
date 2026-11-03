//! Record data in presentation form, the writer's half of [`super::parse`].
//!
//! Names are absolute (with the trailing dot), character strings are quoted with `"` and
//! `\` escaped and every octet outside printable ASCII as `\DDD`, binary fields are upper
//! case hex (DS, TLSA, NSEC3 salts), base64 (DNSKEY, RRSIG) or base32hex (NSEC3), RRSIG
//! times are seconds. A type the writer has no form for, and a value its form cannot
//! carry (an empty digest, key or signature; opaque data that does not parse as its
//! type), is written in the generic form of RFC 3597 (`\# length hex`).

use std::fmt::Write as _;

use tenko_core::dns::{RecordData, Rtype};

use super::{absolute, svcb, types};
use crate::zone::encoding;

/// The generic form: `\# length` and the octets in lower case hex, each after a space.
pub(super) fn generic(data: &[u8]) -> String {
    let mut out = String::with_capacity(8 + data.len() * 3);
    let _ = write!(out, "\\# {}", data.len());
    for byte in data {
        let _ = write!(out, " {byte:02x}");
    }
    out
}

/// A character string, quoted.
fn quoted(bytes: &[u8], out: &mut String) {
    out.push('"');
    for &byte in bytes {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(byte)),
            _ => {
                let _ = write!(out, "\\{byte:03}");
            }
        }
    }
    out.push('"');
}

fn types_list(types: &[Rtype], out: &mut String) {
    for rtype in types {
        out.push(' ');
        out.push_str(&types::name(*rtype));
    }
}

/// The presentation of typed data; `None` when its form cannot carry the value.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per record type reads best as one match"
)]
pub(super) fn typed(data: &RecordData) -> Option<String> {
    let mut out = String::new();
    match data {
        RecordData::A { address } => {
            let _ = write!(out, "{address}");
        }
        RecordData::Aaaa { address } => {
            let _ = write!(out, "{address}");
        }
        RecordData::Cname { target }
        | RecordData::Dname { target }
        | RecordData::Ptr { target } => {
            out.push_str(&absolute(target));
        }
        RecordData::Ns { host } => out.push_str(&absolute(host)),
        RecordData::Mx {
            preference,
            exchange,
        } => {
            let _ = write!(out, "{preference} {}", absolute(exchange));
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
            let _ = write!(
                out,
                "{} {} {serial} {refresh} {retry} {expire} {minimum}",
                absolute(mname),
                absolute(rname)
            );
        }
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            let _ = write!(out, "{priority} {weight} {port} {}", absolute(target));
        }
        RecordData::Txt { strings } => {
            for (index, string) in strings.iter().enumerate() {
                if index > 0 {
                    out.push(' ');
                }
                quoted(string.as_bytes(), &mut out);
            }
        }
        RecordData::Caa { flags, tag, value } => {
            let _ = write!(out, "{flags} {tag} ");
            quoted(value.as_bytes(), &mut out);
        }
        RecordData::Ds {
            key_tag,
            algorithm,
            digest_type,
            digest,
        } => {
            if digest.0.is_empty() {
                return None;
            }
            let _ = write!(
                out,
                "{key_tag} {algorithm} {digest_type} {}",
                encoding::hex_upper(&digest.0)
            );
        }
        RecordData::Dnskey {
            flags,
            protocol,
            algorithm,
            public_key,
        } => {
            if public_key.0.is_empty() {
                return None;
            }
            let _ = write!(
                out,
                "{flags} {protocol} {algorithm} {}",
                encoding::base64_encode(&public_key.0)
            );
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
            if signature.0.is_empty() {
                return None;
            }
            let _ = write!(
                out,
                "{} {algorithm} {labels} {original_ttl} {expiration} {inception} {key_tag} {} {}",
                types::name(*type_covered),
                absolute(signer),
                encoding::base64_encode(&signature.0)
            );
        }
        RecordData::Nsec { next, types } => {
            out.push_str(&absolute(next));
            types_list(types, &mut out);
        }
        RecordData::Nsec3 {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed,
            types,
        } => {
            let _ = write!(
                out,
                "{hash_algorithm} {flags} {iterations} {} {}",
                salt_text(&salt.0),
                encoding::base32hex_encode(&next_hashed.0)
            );
            types_list(types, &mut out);
        }
        RecordData::Nsec3param {
            hash_algorithm,
            flags,
            iterations,
            salt,
        } => {
            let _ = write!(
                out,
                "{hash_algorithm} {flags} {iterations} {}",
                salt_text(&salt.0)
            );
        }
        RecordData::Tlsa {
            usage,
            selector,
            matching_type,
            data,
        } => {
            if data.0.is_empty() {
                return None;
            }
            let _ = write!(
                out,
                "{usage} {selector} {matching_type} {}",
                encoding::hex_upper(&data.0)
            );
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
            let _ = write!(out, "{priority} {}", absolute(target));
            svcb::present(params, &mut out);
        }
        RecordData::Unknown { rtype, data } => return opaque(*rtype, &data.0),
    }
    Some(out)
}

fn salt_text(salt: &[u8]) -> String {
    if salt.is_empty() {
        "-".to_owned()
    } else {
        encoding::hex_upper(salt)
    }
}

/// A cursor over the wire form of opaque data.
struct Wire<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Wire<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let taken = self.bytes.get(self.pos..self.pos.checked_add(len)?)?;
        self.pos += len;
        Some(taken)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|bytes| bytes[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn rest(&mut self) -> &'a [u8] {
        let rest = self.bytes.get(self.pos..).unwrap_or_default();
        self.pos = self.bytes.len();
        rest
    }

    fn charstring(&mut self, out: &mut String) -> Option<()> {
        let len = self.u8()?;
        quoted(self.take(usize::from(len))?, out);
        Some(())
    }

    /// An uncompressed name with its labels escaped.
    fn name(&mut self, out: &mut String) -> Option<()> {
        let start = self.pos;
        let mut labels = 0;
        loop {
            let len = usize::from(self.u8()?);
            if len == 0 {
                break;
            }
            if len > 63 {
                return None;
            }
            for &byte in self.take(len)? {
                if byte.is_ascii_graphic() {
                    if matches!(byte, b'.' | b'\\' | b'"' | b'(' | b')' | b';' | b'@' | b'$') {
                        out.push('\\');
                    }
                    out.push(char::from(byte));
                } else {
                    let _ = write!(out, "\\{byte:03}");
                }
            }
            out.push('.');
            labels += 1;
            if self.pos - start > 255 {
                return None;
            }
        }
        if self.pos - start > 255 {
            return None;
        }
        if labels == 0 {
            out.push('.');
        }
        Some(())
    }

    fn done(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

/// The presentation of a type the model keeps opaque, when the writer knows its form and
/// the data parses as that type.
fn opaque(rtype: Rtype, data: &[u8]) -> Option<String> {
    let mut wire = Wire {
        bytes: data,
        pos: 0,
    };
    let mut out = String::new();
    match rtype.0 {
        // MD, MF, MB, MG, MR
        3 | 4 | 7 | 8 | 9 => wire.name(&mut out)?,
        // HINFO
        13 => {
            wire.charstring(&mut out)?;
            out.push(' ');
            wire.charstring(&mut out)?;
        }
        // MINFO, RP
        14 | 17 => {
            wire.name(&mut out)?;
            out.push(' ');
            wire.name(&mut out)?;
        }
        // NAPTR
        35 => {
            let _ = write!(out, "{} {}", wire.u16()?, wire.u16()?);
            for _ in 0..3 {
                out.push(' ');
                wire.charstring(&mut out)?;
            }
            out.push(' ');
            wire.name(&mut out)?;
        }
        // SSHFP
        44 => {
            let _ = write!(out, "{} {} ", wire.u8()?, wire.u8()?);
            let fingerprint = wire.rest();
            if fingerprint.is_empty() {
                return None;
            }
            out.push_str(&encoding::hex_upper(fingerprint));
        }
        // CDS
        59 => {
            let _ = write!(out, "{} {} {} ", wire.u16()?, wire.u8()?, wire.u8()?);
            let digest = wire.rest();
            if digest.is_empty() {
                return None;
            }
            out.push_str(&encoding::hex_upper(digest));
        }
        // CDNSKEY
        60 => {
            let _ = write!(out, "{} {} {} ", wire.u16()?, wire.u8()?, wire.u8()?);
            let key = wire.rest();
            if key.is_empty() {
                return None;
            }
            out.push_str(&encoding::base64_encode(key));
        }
        // OPENPGPKEY
        61 => {
            let key = wire.rest();
            if key.is_empty() {
                return None;
            }
            out.push_str(&encoding::base64_encode(key));
        }
        // ZONEMD
        63 => {
            let _ = write!(out, "{} {} {} ", wire.u32()?, wire.u8()?, wire.u8()?);
            let digest = wire.rest();
            if digest.is_empty() {
                return None;
            }
            out.push_str(&encoding::hex_upper(digest));
        }
        _ => return None,
    }
    wire.done().then_some(out)
}
