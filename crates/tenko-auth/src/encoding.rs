//! Text encodings used on the wire: unpadded base64url (WebAuthn, session cookies, tokens),
//! RFC 4648 base32 (TOTP secrets) and lowercase hexadecimal.

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The input is not valid in the expected encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid {0} encoding")]
pub struct DecodeError(pub &'static str);

/// Encodes bytes as base64url without padding (RFC 4648 section 5).
pub fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let symbols = chunk.len() + 1;
        for i in 0..symbols {
            let index = (n >> (18 - 6 * i)) & 0x3f;
            out.push(char::from(BASE64URL[index as usize]));
        }
    }
    out
}

fn base64url_value(c: u8) -> Option<u32> {
    let value = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    };
    Some(u32::from(value))
}

/// Decodes base64url. Padding (`=`) at the end is accepted and ignored; any other character
/// outside the base64url alphabet, an impossible length or non-zero trailing bits are
/// refused, so every byte string has exactly one accepted unpadded encoding.
///
/// # Errors
///
/// [`DecodeError`] for malformed input.
pub fn base64url_decode(text: &str) -> Result<Vec<u8>, DecodeError> {
    const ERR: DecodeError = DecodeError("base64url");
    let trimmed = text.trim_end_matches('=');
    if text.len() - trimmed.len() > 2 {
        return Err(ERR);
    }
    let input = trimmed.as_bytes();
    if input.len() % 4 == 1 {
        return Err(ERR);
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for chunk in input.chunks(4) {
        let mut n = 0_u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= base64url_value(c).ok_or(ERR)? << (18 - 6 * i);
        }
        let bytes = n.to_be_bytes();
        let produced = chunk.len() - 1;
        out.extend_from_slice(&bytes[1..=produced]);
        // Bits beyond the produced bytes must be zero (canonical encoding).
        let unused = match chunk.len() {
            2 => n & 0xffff,
            3 => n & 0xff,
            _ => 0,
        };
        if unused != 0 {
            return Err(ERR);
        }
    }
    Ok(out)
}

/// Encodes bytes as RFC 4648 base32, uppercase, without padding (the form of TOTP secrets in
/// `otpauth://` URIs).
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer = 0_u32;
    let mut bits = 0_u32;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(BASE32[((buffer >> bits) & 0x1f) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(BASE32[((buffer << (5 - bits)) & 0x1f) as usize]));
    }
    out
}

/// Decodes RFC 4648 base32, case-insensitive; spaces, hyphens and trailing padding are
/// ignored, as users type secrets in groups.
///
/// # Errors
///
/// [`DecodeError`] for characters outside the alphabet.
pub fn base32_decode(text: &str) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer = 0_u32;
    let mut bits = 0_u32;
    for c in text.trim_end_matches('=').bytes() {
        let value = match c.to_ascii_uppercase() {
            c @ b'A'..=b'Z' => c - b'A',
            c @ b'2'..=b'7' => c - b'2' + 26,
            b' ' | b'-' => continue,
            _ => return Err(DecodeError("base32")),
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Lowercase hexadecimal.
pub fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Decodes hexadecimal (either case).
///
/// # Errors
///
/// [`DecodeError`] for odd length or non-hexadecimal characters.
pub fn hex_decode(text: &str) -> Result<Vec<u8>, DecodeError> {
    const ERR: DecodeError = DecodeError("hexadecimal");
    let input = text.as_bytes();
    if !input.len().is_multiple_of(2) {
        return Err(ERR);
    }
    input
        .chunks(2)
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16).ok_or(ERR)?;
            let low = char::from(pair[1]).to_digit(16).ok_or(ERR)?;
            Ok(u8::try_from(high * 16 + low).unwrap_or_default())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_rfc_4648_vectors() {
        // RFC 4648 section 10, with the URL alphabet and no padding.
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64url_encode(plain.as_bytes()), encoded);
            assert_eq!(base64url_decode(encoded).expect("decode"), plain.as_bytes());
        }
        assert_eq!(base64url_encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(base64url_decode("Zm8=").expect("padded"), b"fo");
    }

    #[test]
    fn base64url_refuses_malformed_input() {
        // "Zh" has non-zero trailing bits; "Z" is an impossible length.
        for bad in ["Z", "Zm9v+", "Zm9v/", "Zg===", "Zh", "a b"] {
            assert!(base64url_decode(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn base64url_round_trips_every_length() {
        let data: Vec<u8> = (0..=255).collect();
        for len in 0..data.len() {
            let encoded = base64url_encode(&data[..len]);
            assert_eq!(base64url_decode(&encoded).expect("decode"), &data[..len]);
        }
    }

    #[test]
    fn base32_matches_rfc_4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32_encode(plain.as_bytes()), encoded);
            assert_eq!(base32_decode(encoded).expect("decode"), plain.as_bytes());
        }
        assert_eq!(
            base32_decode("mzxw 6ytb-oi======").expect("lenient"),
            b"foobar"
        );
        assert!(base32_decode("MZXW1").is_err());
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(hex_encode(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(hex_decode("00ABff").expect("hex"), [0x00, 0xab, 0xff]);
        assert!(hex_decode("abc").is_err());
        assert!(hex_decode("zz").is_err());
    }
}
