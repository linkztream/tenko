//! The approval code and the collect's signature (ADR 0038 decision 4). The test vector
//! `tests/fixtures/approval-code.json` gives every input and intermediate value, for the
//! script's own implementation.

use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use sha2::{Digest, Sha256};
use tenko_core::ApprovalId;

/// The context string at the start of the code's input.
pub const CODE_CONTEXT: &[u8] = b"tenko-takeover-approval-v1";
/// The context string at the start of the collect's signed message.
pub const COLLECT_CONTEXT: &[u8] = b"tenko-takeover-collect-v1";

/// Crockford's base32 alphabet.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// The characters of a code without its hyphens: 80 bits, five to a character.
const CODE_CHARS: usize = 16;

/// The code of an approval: the first 80 bits of
/// `SHA-256(CODE_CONTEXT || 0x00 || len(domain) || domain || root_sha256 || plan_sha256 ||
/// key || id)`, where `domain` is the plan's domain in canonical form (lowercase ASCII, no
/// trailing dot) preceded by its length in one octet, `root_sha256` the SHA-256 of the TLS
/// root's DER, `plan_sha256` the SHA-256 of the request body as sent, `key` the 65-octet
/// uncompressed point and `id` the approval id's 16 octets (RFC 9562 order). Written as 16
/// characters of Crockford's base32, most significant bits first, in four groups of four:
/// `K7QD-M2XR-9FHA-T4WB`.
pub fn code(
    domain: &str,
    root_sha256: &[u8; 32],
    plan_sha256: &[u8; 32],
    key: &[u8],
    id: ApprovalId,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CODE_CONTEXT);
    hasher.update([0]);
    // A canonical domain is at most 253 octets.
    hasher.update([u8::try_from(domain.len()).unwrap_or(u8::MAX)]);
    hasher.update(domain.as_bytes());
    hasher.update(root_sha256);
    hasher.update(plan_sha256);
    hasher.update(key);
    hasher.update(id.uuid().as_bytes());
    let digest = hasher.finalize();
    let bits = digest[..10]
        .iter()
        .fold(0u128, |bits, byte| (bits << 8) | u128::from(*byte));
    let chars: Vec<u8> = (0..CODE_CHARS)
        .map(|index| ALPHABET[usize::try_from((bits >> (75 - 5 * index)) & 0x1f).unwrap_or(0)])
        .collect();
    group(&chars)
}

/// A typed code in the canonical form [`code`] writes, or `None` when it is not one: case,
/// spaces and hyphens are ignored, and Crockford's look-alikes are read as their digits (`O`
/// as `0`, `I` and `L` as `1`).
pub fn canonical_code(typed: &str) -> Option<String> {
    if typed.len() > 64 {
        return None;
    }
    let chars: Vec<u8> = typed
        .bytes()
        .filter(|b| !matches!(b, b'-' | b' '))
        .map(|b| match b.to_ascii_uppercase() {
            b'O' => b'0',
            b'I' | b'L' => b'1',
            other => other,
        })
        .collect();
    (chars.len() == CODE_CHARS && chars.iter().all(|c| ALPHABET.contains(c))).then(|| group(&chars))
}

fn group(chars: &[u8]) -> String {
    chars
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// The message the collect signs: `COLLECT_CONTEXT || 0x00 || id || nonce`, the id's 16
/// octets and the nonce's 32.
pub fn collect_message(id: ApprovalId, nonce: &[u8]) -> Vec<u8> {
    let mut message = COLLECT_CONTEXT.to_vec();
    message.push(0);
    message.extend_from_slice(id.uuid().as_bytes());
    message.extend_from_slice(nonce);
    message
}

/// Whether `signature` (`r || s`, 64 octets) is the key's ECDSA P-256 SHA-256 signature of
/// [`collect_message`].
pub fn verify_collect(key: &[u8], id: ApprovalId, nonce: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key)
        .verify(&collect_message(id, nonce), signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_sixteen_crockford_characters_in_four_groups() {
        let id = ApprovalId::generate();
        let code = code("corp.example.test", &[1; 32], &[2; 32], &[4; 65], id);
        assert_eq!(code.len(), 19);
        assert_eq!(canonical_code(&code), Some(code.clone()));
        assert_eq!(
            canonical_code(&code.to_lowercase().replace('-', " ")),
            Some(code.clone())
        );
        let other = super::code("corp.example.test", &[3; 32], &[2; 32], &[4; 65], id);
        assert_ne!(code, other, "another root, another code");
    }

    #[test]
    fn typed_codes_read_look_alikes_and_refuse_the_rest() {
        assert_eq!(
            canonical_code("o1il-0000-0000-000z").as_deref(),
            Some("0111-0000-0000-000Z")
        );
        for bad in [
            "",
            "0000-0000-0000-000",
            "0000-0000-0000-0000-0",
            "UUUU-0000-0000-0000",
        ] {
            assert_eq!(canonical_code(bad), None, "{bad}");
        }
        assert_eq!(canonical_code(&"0".repeat(65)), None);
    }
}
