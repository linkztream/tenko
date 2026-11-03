//! The binary-to-text encodings of zone files and TSIG secrets (RFC 4648): base64 with
//! padding (DNSKEY, RRSIG, the SVCB `ech` parameter, TSIG secrets), base32 with the
//! extended hex alphabet and no padding (NSEC3 next hashed owner names, RFC 5155) and
//! hexadecimal (DS, TLSA, NSEC3 salts, the generic record form of RFC 3597).
//!
//! These few functions are written here rather than taken from a crate: each is a table
//! and a loop. Decoding never allocates more than the input's length and refuses every
//! character outside the alphabet.

/// The base64 alphabet (RFC 4648, section 4).
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The base32 alphabet with the extended hex digits (RFC 4648, section 7).
const BASE32HEX: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// Encodes bytes as base64 with padding.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        for i in 0..4 {
            if i <= chunk.len() {
                let index = (n >> (18 - 6 * i)) & 0x3f;
                out.push(char::from(BASE64[index as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn base64_value(c: u8) -> Option<u32> {
    let value = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(value))
}

/// Decodes base64 in groups of four characters, the last one padded with `=` (as BIND and
/// `domain` require). Bits after the last full octet are ignored.
///
/// # Errors
///
/// A reason in English for a character outside the alphabet, a missing group character or
/// padding anywhere but at the end.
pub fn base64_decode(text: &str) -> Result<Vec<u8>, &'static str> {
    let input = text.as_bytes();
    if !input.len().is_multiple_of(4) {
        return Err("base64 comes in groups of four characters");
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let groups = input.len() / 4;
    for (index, group) in input.as_chunks::<4>().0.iter().enumerate() {
        let last = index + 1 == groups;
        let pad = group.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return Err("base64 padding is one or two `=` at the end");
        }
        let mut n = 0u32;
        for (position, &c) in group.iter().enumerate() {
            let value = if position >= 4 - pad {
                0
            } else {
                base64_value(c).ok_or("a character outside the base64 alphabet")?
            };
            n = (n << 6) | value;
        }
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - pad]);
    }
    Ok(out)
}

/// Encodes bytes as base32 with the extended hex alphabet, upper case, without padding.
pub fn base32hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer = 0u16;
    let mut bits = 0u32;
    for &byte in bytes {
        buffer = (buffer << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(BASE32HEX[usize::from((buffer >> bits) & 0x1f)]));
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(
            BASE32HEX[usize::from((buffer << (5 - bits)) & 0x1f)],
        ));
    }
    out
}

/// Decodes base32 with the extended hex alphabet, either case, without padding. Bits after
/// the last full octet are ignored.
///
/// # Errors
///
/// A reason in English for a character outside the alphabet or an impossible length.
pub fn base32hex_decode(text: &str) -> Result<Vec<u8>, &'static str> {
    if matches!(text.len() % 8, 1 | 3 | 6) {
        return Err("base32hex has an impossible length");
    }
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer = 0u16;
    let mut bits = 0u32;
    for c in text.bytes() {
        let value = match c {
            b'0'..=b'9' => c - b'0',
            b'A'..=b'V' => c - b'A' + 10,
            b'a'..=b'v' => c - b'a' + 10,
            _ => return Err("a character outside the base32hex alphabet"),
        };
        buffer = (buffer << 5) | u16::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).unwrap_or_default());
        }
        buffer &= (1 << bits) - 1;
    }
    Ok(out)
}

/// Encodes bytes as hexadecimal, upper case (the DS, TLSA and NSEC3 salt form).
pub fn hex_upper(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0xf)]));
    }
    out
}

/// Decodes hexadecimal digits, either case, an even number of them.
///
/// # Errors
///
/// A reason in English for a character that is not a hex digit or an odd count.
pub fn hex_decode(text: &str) -> Result<Vec<u8>, &'static str> {
    let input = text.as_bytes();
    if !input.len().is_multiple_of(2) {
        return Err("hexadecimal comes in pairs of digits");
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for pair in input.as_chunks::<2>().0 {
        let high = char::from(pair[0])
            .to_digit(16)
            .ok_or("a character that is not a hex digit")?;
        let low = char::from(pair[1])
            .to_digit(16)
            .ok_or("a character that is not a hex digit")?;
        out.push(u8::try_from(high << 4 | low).unwrap_or_default());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_rfc_4648_vectors() {
        let vectors: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (bytes, text) in vectors {
            assert_eq!(base64_encode(bytes), text);
            assert_eq!(base64_decode(text).as_deref(), Ok(bytes), "{text}");
        }
        for bad in ["Zg", "Zg=", "Z===", "Zg==Zg==", "Zm9v!A==", "=Zm9", "Zm9vé"] {
            assert!(base64_decode(bad).is_err(), "{bad}");
        }
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(base64_decode(&base64_encode(&all)), Ok(all));
    }

    #[test]
    fn base32hex_matches_the_rfc_4648_vectors() {
        let vectors: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "CO"),
            (b"fo", "CPNG"),
            (b"foo", "CPNMU"),
            (b"foob", "CPNMUOG"),
            (b"fooba", "CPNMUOJ1"),
            (b"foobar", "CPNMUOJ1E8"),
        ];
        for (bytes, text) in vectors {
            assert_eq!(base32hex_encode(bytes), text);
            assert_eq!(base32hex_decode(text).as_deref(), Ok(bytes), "{text}");
            assert_eq!(
                base32hex_decode(&text.to_ascii_lowercase()).as_deref(),
                Ok(bytes)
            );
        }
        for bad in ["C", "CPN", "CPNMUO", "CPNW", "CP=G"] {
            assert!(base32hex_decode(bad).is_err(), "{bad}");
        }
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(base32hex_decode(&base32hex_encode(&all)), Ok(all));
    }

    #[test]
    fn hex_round_trips_and_refuses_odd_input() {
        assert_eq!(hex_upper(&[0xab, 0x01, 0xff]), "AB01FF");
        assert_eq!(hex_decode("ab01Ff"), Ok(vec![0xab, 0x01, 0xff]));
        assert_eq!(hex_decode(""), Ok(Vec::new()));
        assert!(hex_decode("abc").is_err());
        assert!(hex_decode("zz").is_err());
        assert!(hex_decode("éé").is_err());
    }
}
