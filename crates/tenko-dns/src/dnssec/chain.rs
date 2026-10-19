//! The pieces of the denial chains: which types the signer owns, the NSEC3 hash (RFC 5155,
//! section 5) and the base32hex owner label of a hash (RFC 4648, section 7).
//!
//! The hash and the label are written without allocating, so the answer path can hash a
//! query name for the NSEC3 proof.

use aws_lc_rs::digest;
use tenko_core::dns::{DnsName, Rtype, SoaDefaults};

/// The types the signer writes, with the origin `dnssec`. In a zone signed online no other
/// writer may hold them; in an imported zone they are the operator's data.
pub const GENERATED: [Rtype; 7] = [
    Rtype::RRSIG,
    Rtype::NSEC,
    Rtype::NSEC3,
    Rtype::NSEC3PARAM,
    Rtype::DNSKEY,
    Rtype::CDS,
    Rtype::CDNSKEY,
];

/// Whether the signer owns `rtype` in a zone it signs.
pub fn is_generated(rtype: Rtype) -> bool {
    GENERATED.contains(&rtype)
}

/// The NSEC3 hash algorithm Tenko uses: SHA-1, the only one defined.
pub const NSEC3_SHA1: u8 = 1;

/// Octets of an NSEC3 hash.
pub const HASH_LEN: usize = 20;

/// Characters of the base32hex label of a hash.
pub const LABEL_LEN: usize = 32;

/// The NSEC3 hash of a name in lowercase wire form (RFC 5155, section 5): SHA-1 over the
/// name and the salt, then `iterations` more times over the hash and the salt.
pub fn nsec3_hash(owner: &[u8], salt: &[u8], iterations: u16) -> [u8; HASH_LEN] {
    let mut context = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    context.update(owner);
    context.update(salt);
    let mut hash = [0u8; HASH_LEN];
    hash.copy_from_slice(context.finish().as_ref());
    for _ in 0..iterations {
        let mut context = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
        context.update(&hash);
        context.update(salt);
        hash.copy_from_slice(context.finish().as_ref());
    }
    hash
}

const BASE32HEX: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";

/// The lowercase base32hex form of a hash, without padding: the first label of its NSEC3
/// owner name.
pub fn base32hex(hash: &[u8; HASH_LEN]) -> [u8; LABEL_LEN] {
    let mut out = [0u8; LABEL_LEN];
    for (group, chunk) in hash.chunks(5).enumerate() {
        let mut bits: u64 = 0;
        for &byte in chunk {
            bits = bits << 8 | u64::from(byte);
        }
        for index in 0..8 {
            let shift = 35 - index * 5;
            let value = usize::try_from((bits >> shift) & 0x1f).unwrap_or_default();
            out[group * 8 + index] = BASE32HEX[value];
        }
    }
    out
}

/// The hash of a base32hex label of 32 characters, either case.
pub fn base32hex_decode(label: &[u8]) -> Option<[u8; HASH_LEN]> {
    if label.len() != LABEL_LEN {
        return None;
    }
    let mut out = [0u8; HASH_LEN];
    for (group, chunk) in label.chunks(8).enumerate() {
        let mut bits: u64 = 0;
        for &character in chunk {
            let value = match character.to_ascii_lowercase() {
                digit @ b'0'..=b'9' => digit - b'0',
                letter @ b'a'..=b'v' => letter - b'a' + 10,
                _ => return None,
            };
            bits = bits << 5 | u64::from(value);
        }
        for index in 0..5 {
            out[group * 5 + index] = u8::try_from((bits >> (32 - index * 8)) & 0xff).ok()?;
        }
    }
    Some(out)
}

/// The NSEC3 owner name of a hash in a zone: the base32hex label and the apex.
pub fn hashed_owner(hash: &[u8; HASH_LEN], apex: &DnsName) -> DnsName {
    let label = base32hex(hash);
    let label = std::str::from_utf8(&label).unwrap_or_default();
    apex.child(label).unwrap_or_else(|_| apex.clone())
}

/// The hash a hashed owner name stands for, if it is one of the zone at `apex`.
pub fn hash_of_owner(owner: &DnsName, apex: &DnsName) -> Option<[u8; HASH_LEN]> {
    if owner.parent().as_ref() != Some(apex) {
        return None;
    }
    base32hex_decode(owner.labels().next()?.as_bytes())
}

/// The TTL of NSEC and NSEC3 records (RFC 9077): the smaller of the SOA's TTL and its
/// MINIMUM.
pub fn denial_ttl(soa: &SoaDefaults) -> u32 {
    soa.ttl.min(soa.minimum)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(text: &str) -> Vec<u8> {
        DnsName::new(text).expect("name").to_wire()
    }

    /// RFC 5155, appendix A: salt `aabbccdd`, 12 iterations.
    #[test]
    fn hashes_match_rfc5155_appendix_a() {
        let salt = [0xaa, 0xbb, 0xcc, 0xdd];
        for (name, label) in [
            ("example", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"),
            ("a.example", "35mthgpgcu1qg68fab165klnsnk3dpvl"),
            ("ai.example", "gjeqe526plbf1g8mklp59enfd789njgi"),
            ("ns1.example", "2t7b4g4vsa5smi47k61mv5bv1a22bojr"),
            ("ns2.example", "q04jkcevqvmu85r014c7dkba38o0ji5r"),
            ("w.example", "k8udemvp1j2f7eg6jebps17vp3n8i58h"),
            ("*.w.example", "r53bq7cc2uvmubfu5ocmm6pers9tk9en"),
            ("x.w.example", "b4um86eghhds6nea196smvmlo4ors995"),
            ("y.w.example", "ji6neoaepv8b5o6k4ev33abha8ht9fgc"),
            ("x.y.w.example", "2vptu5timamqttgl4luu9kg21e0aor3s"),
            ("xx.example", "t644ebqk9bibcna874givr6joj62mlhv"),
        ] {
            let hash = nsec3_hash(&wire(name), &salt, 12);
            assert_eq!(&base32hex(&hash), label.as_bytes(), "{name}");
            assert_eq!(base32hex_decode(label.as_bytes()), Some(hash));
            assert_eq!(
                base32hex_decode(label.to_ascii_uppercase().as_bytes()),
                Some(hash)
            );
        }
        assert_eq!(base32hex_decode(b"too-short"), None);
        assert_eq!(base32hex_decode(b"wp9mhaveqvm6t7vbl5lop2u3t2rp3tom"), None);
    }

    #[test]
    fn hashed_owners_round_trip() {
        let apex = DnsName::new("example.test").expect("apex");
        let hash = nsec3_hash(&apex.to_wire(), &[], 0);
        let owner = hashed_owner(&hash, &apex);
        assert_eq!(owner.label_count(), 3);
        assert_eq!(hash_of_owner(&owner, &apex), Some(hash));
        assert_eq!(hash_of_owner(&apex, &apex), None);
        let deeper = DnsName::new("a.b.example.test").expect("name");
        assert_eq!(hash_of_owner(&deeper, &apex), None);
    }
}
