//! The presentation forms of trust anchor keys: a DS record's data (RFC 4034 section
//! 5.3: `20326 8 2 E06D44B8...`) and a DNSKEY record's data (section 2.2: `257 3 8
//! AwEAAa...`), as `POST /dns/trust-anchors` and `tenko dns trust-anchor add` take them,
//! and the DS form of a DNSKEY for the status and the lab.

use tenko_core::{
    Timestamp,
    dns::{AnchorData, AnchorKey, AnchorSource, AnchorState, DnsError, codes},
    serde_util::HexBytes,
};

use std::fmt::Write as _;

use super::base64;
use crate::dnssec::crypto;

fn invalid(reason: &str) -> DnsError {
    DnsError::invalid(codes::TRUST_ANCHOR_INVALID, "keys", reason)
}

/// The value of one hexadecimal digit; `None` for any other octet (a sign, a letter
/// outside `a` to `f`, an octet of a character outside ASCII).
const fn nibble(octet: u8) -> Option<u8> {
    match octet {
        b'0'..=b'9' => Some(octet - b'0'),
        b'a'..=b'f' => Some(octet - b'a' + 10),
        b'A'..=b'F' => Some(octet - b'A' + 10),
        _ => None,
    }
}

/// The octets of a hexadecimal text, white space between digits allowed. Reads the text
/// octet by octet, so that a character of several octets is refused rather than cut.
fn hex(text: &str) -> Option<Vec<u8>> {
    let mut digits = text.bytes().filter(|octet| !octet.is_ascii_whitespace());
    let mut octets = Vec::with_capacity(text.len() / 2);
    while let Some(high) = digits.next() {
        let low = digits.next()?;
        octets.push((nibble(high)? << 4) | nibble(low)?);
    }
    // White space of a character outside ASCII is not ASCII white space, so a text that
    // holds such a character reaches `nibble` and is refused there.
    Some(octets)
}

/// A DS record's data from its presentation form: the key tag, the algorithm, the digest
/// type and the digest in hexadecimal (white space inside the digest allowed).
///
/// # Errors
///
/// `dns.trust_anchor.invalid` naming `keys`.
pub fn parse_ds(text: &str) -> Result<Vec<u8>, DnsError> {
    let mut fields = text.split_whitespace();
    let key_tag: u16 = fields
        .next()
        .and_then(|field| field.parse().ok())
        .ok_or_else(|| invalid("a DS starts with the key tag"))?;
    let algorithm: u8 = fields
        .next()
        .and_then(|field| field.parse().ok())
        .ok_or_else(|| invalid("the DS algorithm is a number"))?;
    let digest_type: u8 = fields
        .next()
        .and_then(|field| field.parse().ok())
        .ok_or_else(|| invalid("the DS digest type is a number"))?;
    let digest = hex(&fields.collect::<Vec<_>>().join(""))
        .filter(|digest| !digest.is_empty())
        .ok_or_else(|| invalid("the DS digest is hexadecimal"))?;
    let expected = match digest_type {
        1 => Some(20),
        2 => Some(32),
        4 => Some(48),
        _ => None,
    };
    if expected.is_some_and(|len| digest.len() != len) {
        return Err(invalid("the digest has the wrong length for its type"));
    }
    let mut rdata = key_tag.to_be_bytes().to_vec();
    rdata.push(algorithm);
    rdata.push(digest_type);
    rdata.extend_from_slice(&digest);
    Ok(rdata)
}

/// A DNSKEY record's data from its presentation form: the flags, the protocol, the
/// algorithm and the key in base64 (white space inside the key allowed).
///
/// # Errors
///
/// `dns.trust_anchor.invalid` naming `keys`.
pub fn parse_dnskey(text: &str) -> Result<Vec<u8>, DnsError> {
    let mut fields = text.split_whitespace();
    let flags: u16 = fields
        .next()
        .and_then(|field| field.parse().ok())
        .ok_or_else(|| invalid("a DNSKEY starts with the flags"))?;
    let protocol: u8 = fields
        .next()
        .and_then(|field| field.parse().ok())
        .ok_or_else(|| invalid("the DNSKEY protocol is a number"))?;
    let algorithm: u8 = fields
        .next()
        .and_then(|field| field.parse().ok())
        .ok_or_else(|| invalid("the DNSKEY algorithm is a number"))?;
    let key = base64::decode(&fields.collect::<Vec<_>>().join(""))
        .filter(|key| !key.is_empty())
        .ok_or_else(|| invalid("the DNSKEY key is base64"))?;
    if protocol != 3 {
        return Err(invalid("the DNSKEY protocol is 3"));
    }
    let mut rdata = flags.to_be_bytes().to_vec();
    rdata.push(protocol);
    rdata.push(algorithm);
    rdata.extend_from_slice(&key);
    Ok(rdata)
}

/// An operator's trust anchor key from DS record data, Valid at `now`.
pub fn ds_key(rdata: Vec<u8>, now: Timestamp) -> AnchorKey {
    AnchorKey {
        key_tag: u16::from_be_bytes([rdata[0], rdata[1]]),
        algorithm: rdata[2],
        digest_type: Some(rdata[3]),
        data: AnchorData::Ds {
            rdata: HexBytes(rdata),
        },
        state: AnchorState::Valid,
        source: AnchorSource::Operator,
        added_at: now,
        state_since: now,
        last_seen: None,
    }
}

/// An operator's trust anchor key from DNSKEY record data, Valid at `now`.
pub fn dnskey_key(rdata: Vec<u8>, now: Timestamp) -> AnchorKey {
    AnchorKey {
        key_tag: crypto::key_tag(&rdata),
        algorithm: rdata[3],
        digest_type: None,
        data: AnchorData::Dnskey {
            rdata: HexBytes(rdata),
        },
        state: AnchorState::Valid,
        source: AnchorSource::Operator,
        added_at: now,
        state_since: now,
        last_seen: None,
    }
}

/// The presentation form of a DS record's data.
pub fn ds_text(rdata: &[u8]) -> String {
    if rdata.len() < 4 {
        return String::new();
    }
    let mut digest = String::with_capacity(rdata.len() * 2);
    for byte in &rdata[4..] {
        let _ = write!(digest, "{byte:02X}");
    }
    format!(
        "{} {} {} {digest}",
        u16::from_be_bytes([rdata[0], rdata[1]]),
        rdata[2],
        rdata[3]
    )
}

/// The presentation form of a DNSKEY record's data.
pub fn dnskey_text(rdata: &[u8]) -> String {
    if rdata.len() < 4 {
        return String::new();
    }
    format!(
        "{} {} {} {}",
        u16::from_be_bytes([rdata[0], rdata[1]]),
        rdata[2],
        rdata[3],
        base64::encode(&rdata[4..])
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ds_and_dnskey_read_and_write_their_presentation_forms() {
        let ds =
            parse_ds("20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D084 58E880409BBC683457104237C7F8EC8D")
                .expect("ds");
        assert_eq!(ds.len(), 36);
        assert_eq!(&ds[..4], &[0x4f, 0x66, 8, 2]);
        assert_eq!(
            ds_text(&ds),
            "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
        );
        let key = ds_key(ds, Timestamp::now());
        assert_eq!(key.key_tag, 20326);
        assert_eq!(key.digest_type, Some(2));
        key.validate().expect("a valid key");
        let dnskey =
            parse_dnskey("257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=").expect("dnskey");
        assert_eq!(
            dnskey_text(&dnskey),
            "257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="
        );
        let key = dnskey_key(dnskey, Timestamp::now());
        assert_eq!(key.key_tag, 3613);
        key.validate().expect("a valid key");
        for bad in [
            "",
            "x 8 2 ab",
            "1 8 2",
            "1 8 2 zz",
            "1 8 2 abcd",
            "1 8 2 +f+f",
            "1 8 2 ab\u{a0}cd",
        ] {
            let error = parse_ds(bad).expect_err(bad);
            assert!(
                format!("{error:?}").contains(codes::TRUST_ANCHOR_INVALID),
                "{error:?}"
            );
        }
        for bad in ["", "257 3", "257 2 15 AA==", "257 3 15 !!"] {
            assert!(parse_dnskey(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_digest_with_a_character_outside_ascii_is_refused_not_cut() {
        // An accented letter is two octets in UTF-8; the digest is read octet by octet
        // and refuses it instead of cutting the text inside the character.
        for text in [
            "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D084é",
            "20326 8 2 éE06D44B80B8F1D39A95C0B0D7C65D084",
            "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8ECé",
            "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8DÄ",
            "20326 8 2 \u{ff21}\u{ff22}",
        ] {
            let error = parse_ds(text).expect_err(text);
            assert!(
                format!("{error:?}").contains(codes::TRUST_ANCHOR_INVALID),
                "{error:?}"
            );
        }
        assert_eq!(hex("ab cd\tef\n01"), Some(vec![0xab, 0xcd, 0xef, 0x01]));
        assert_eq!(hex(""), Some(Vec::new()));
        assert_eq!(hex("abc"), None);
        assert_eq!(hex("+1"), None);
        assert_eq!(hex("é"), None);
    }
}
