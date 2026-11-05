//! The DER writer. Structures that carry keys or passwords are encoded through it, so its
//! buffer is zeroed when it is dropped and [`Der::finish`] hands the octets over in a
//! [`Zeroizing`] vector.

use zeroize::{Zeroize, Zeroizing};

use super::{reader::format_time, tag};

/// A DER encoding being built: each method appends one TLV.
#[derive(Default)]
pub struct Der(Vec<u8>);

impl Drop for Der {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Appends a DER length.
pub(crate) fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        #[allow(clippy::cast_possible_truncation)]
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|octet| **octet == 0).count();
        let count = bytes.len() - skip;
        #[allow(clippy::cast_possible_truncation)]
        out.push(0x80 | count as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

/// The minimal two's-complement content octets of an INTEGER.
pub(crate) fn integer_octets(value: i64) -> ([u8; 8], usize) {
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let redundant = (bytes[start] == 0x00 && bytes[start + 1] & 0x80 == 0)
            || (bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0);
        if !redundant {
            break;
        }
        start += 1;
    }
    (bytes, start)
}

impl Der {
    /// An empty encoding.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Appends a TLV with `tag` and `content`.
    pub fn tlv(&mut self, tag_octet: u8, content: &[u8]) -> &mut Self {
        self.0.push(tag_octet);
        push_len(&mut self.0, content.len());
        self.0.extend_from_slice(content);
        self
    }

    /// Appends octets that are already DER.
    pub fn raw(&mut self, encoded: &[u8]) -> &mut Self {
        self.0.extend_from_slice(encoded);
        self
    }

    /// Appends a constructed TLV whose content `build` appends.
    pub fn constructed(&mut self, tag_octet: u8, build: impl FnOnce(&mut Der)) -> &mut Self {
        let mut inner = Der::new();
        build(&mut inner);
        self.tlv(tag_octet, &inner.0)
    }

    /// Appends the explicit field `[n]`.
    pub fn field(&mut self, n: u8, build: impl FnOnce(&mut Der)) -> &mut Self {
        self.constructed(tag::context(n), build)
    }

    /// Appends a SEQUENCE.
    pub fn sequence(&mut self, build: impl FnOnce(&mut Der)) -> &mut Self {
        self.constructed(tag::SEQUENCE, build)
    }

    /// Appends `[APPLICATION n]`.
    pub fn application(&mut self, n: u8, build: impl FnOnce(&mut Der)) -> &mut Self {
        self.constructed(tag::application(n), build)
    }

    /// Appends an INTEGER.
    pub fn integer(&mut self, value: i64) -> &mut Self {
        let (bytes, start) = integer_octets(value);
        self.tlv(tag::INTEGER, &bytes[start..])
    }

    /// Appends a `UInt32` (positive, so 2^31 and above take a leading zero octet).
    pub fn uint32(&mut self, value: u32) -> &mut Self {
        self.integer(i64::from(value))
    }

    /// Appends an ENUMERATED.
    pub fn enumerated(&mut self, value: i64) -> &mut Self {
        let (bytes, start) = integer_octets(value);
        self.tlv(tag::ENUMERATED, &bytes[start..])
    }

    /// Appends a BOOLEAN.
    pub fn boolean(&mut self, value: bool) -> &mut Self {
        self.tlv(tag::BOOLEAN, &[if value { 0xff } else { 0x00 }])
    }

    /// Appends an OCTET STRING.
    pub fn octets(&mut self, value: &[u8]) -> &mut Self {
        self.tlv(tag::OCTET_STRING, value)
    }

    /// Appends a `KerberosString` (`GeneralString`).
    pub fn string(&mut self, value: &str) -> &mut Self {
        self.tlv(tag::GENERAL_STRING, value.as_bytes())
    }

    /// Appends a `KerberosTime` from Unix seconds.
    pub fn time(&mut self, unix: i64) -> &mut Self {
        self.tlv(tag::GENERALIZED_TIME, &format_time(unix))
    }

    /// Appends `KerberosFlags` as the 32-bit BIT STRING every implementation sends.
    pub fn flags(&mut self, flags: u32) -> &mut Self {
        let bytes = flags.to_be_bytes();
        self.tlv(
            tag::BIT_STRING,
            &[0, bytes[0], bytes[1], bytes[2], bytes[3]],
        )
    }

    /// Appends an OBJECT IDENTIFIER from its content octets.
    pub fn oid(&mut self, content: &[u8]) -> &mut Self {
        self.tlv(tag::OID, content)
    }

    /// The encoding.
    pub fn finish(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut self.0))
    }

    /// The encoding, for structures that hold no secret.
    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

/// Encodes one structure with `build` and returns the octets.
pub fn encode(build: impl FnOnce(&mut Der)) -> Vec<u8> {
    let mut der = Der::new();
    build(&mut der);
    der.into_vec()
}

/// Encodes one structure that holds a key or a password.
pub fn encode_secret(build: impl FnOnce(&mut Der)) -> Zeroizing<Vec<u8>> {
    let mut der = Der::new();
    build(&mut der);
    der.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::Reader;

    #[test]
    fn integers_and_lengths_are_written_in_their_shortest_form() {
        for value in [
            0_i64,
            1,
            127,
            128,
            255,
            256,
            -1,
            -128,
            -129,
            0x3fff_ffff,
            0x8000_0000,
            0xffff_ffff,
            i64::from(i32::MIN),
            i64::MAX,
            i64::MIN,
        ] {
            let der = encode(|d| {
                d.integer(value);
            });
            let mut reader = Reader::new(&der, "T");
            let content = reader.expect(tag::INTEGER).expect("integer");
            assert_eq!(crate::der::reader::decode_integer(content), Some(value));
        }
        assert_eq!(
            encode(|d| {
                d.uint32(0x8000_0000);
            }),
            [0x02, 0x05, 0x00, 0x80, 0, 0, 0]
        );
        for len in [0_usize, 127, 128, 255, 256, 65_535, 65_536] {
            let content = vec![0_u8; len];
            let der = encode(|d| {
                d.octets(&content);
            });
            assert_eq!(Reader::new(&der, "T").octets().expect("octets").len(), len);
        }
    }
}
