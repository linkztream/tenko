//! Text encodings used on the wire: RFC 4648 base32 (TOTP secrets) and lowercase hexadecimal.
//! Unpadded base64url (WebAuthn, session cookies, tokens) is the `base64` crate's
//! `URL_SAFE_NO_PAD`, which refuses padding and non-zero trailing bits.

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The input is not valid in the expected encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid {0} encoding")]
pub struct DecodeError(pub &'static str);

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
