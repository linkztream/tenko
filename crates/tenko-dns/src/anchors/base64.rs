//! Base64 (RFC 4648 section 4) for the presentation forms of DNSKEY records (RFC 4034
//! section 2.2) and the IANA trust anchor file (RFC 7958): the standard alphabet, padding
//! written and accepted, white space inside the text skipped as zone files allow.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes `bytes` with padding.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut bits: u32 = 0;
        for (index, byte) in chunk.iter().enumerate() {
            bits |= u32::from(*byte) << (16 - 8 * index);
        }
        for index in 0..4 {
            if index <= chunk.len() {
                let value = usize::try_from((bits >> (18 - 6 * index)) & 0x3f).unwrap_or(0);
                out.push(char::from(ALPHABET[value]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn value_of(character: u8) -> Option<u32> {
    let value = match character {
        b'A'..=b'Z' => character - b'A',
        b'a'..=b'z' => character - b'a' + 26,
        b'0'..=b'9' => character - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(value))
}

/// Decodes `text`, white space skipped; `None` for a character outside the alphabet, a
/// length that is not a whole number of groups, or padding in the wrong place.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut bits: u32 = 0;
    let mut count = 0;
    let mut padding = 0;
    for character in text.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        if character == b'=' {
            padding += 1;
            count += 1;
            bits <<= 6;
        } else {
            if padding > 0 {
                return None;
            }
            bits = (bits << 6) | value_of(character)?;
            count += 1;
        }
        if count == 4 {
            let bytes = bits.to_be_bytes();
            out.extend_from_slice(&bytes[1..4 - padding.min(2)]);
            if padding > 2 {
                return None;
            }
            bits = 0;
            count = 0;
            if padding > 0 {
                padding = 3;
            }
        }
    }
    (count == 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_pads() {
        for (plain, encoded) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain), encoded);
            assert_eq!(decode(encoded).as_deref(), Some(plain));
        }
        assert_eq!(decode("Zm9v YmFy\n"), Some(b"foobar".to_vec()));
        assert_eq!(decode("Zm9"), None);
        assert_eq!(decode("Zm=v"), None);
        assert_eq!(decode("Z==="), None);
        assert_eq!(decode("Zm9v!"), None);
    }
}
