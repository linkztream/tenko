//! RRsets as the validator sees them: the records of one owner and type with the RRSIGs
//! that cover them ([`group`]), the canonical form of their data (RFC 4034 section 6.2
//! with the corrections of RFC 6840 section 5.1), and the check of one RRset against a key
//! set ([`verify`]) under the cost caps of recursion plan section 2.3.
//!
//! Everything here works on the owned records of [`crate::recurse::message::parse`]: the
//! owners are lowercase wire names and the names inside record data are decompressed, so
//! a record can be hashed, compared and signed over as it is.

use std::borrow::Cow;

use crate::{
    dnssec::{canonical, crypto},
    name,
    recurse::message::{Rr, types},
    recursion::ValidationCaps,
};

/// The fields of an RRSIG record (RFC 4034 section 3.1), borrowed from its data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sig<'a> {
    /// The whole record data.
    pub data: &'a [u8],
    /// The type covered.
    pub type_covered: u16,
    /// The algorithm.
    pub algorithm: u8,
    /// The labels of the signed owner (a wildcard expansion has fewer than the owner).
    pub labels: u8,
    /// The original TTL.
    pub original_ttl: u32,
    /// The expiration, seconds since 1970 modulo 2^32.
    pub expiration: u32,
    /// The inception.
    pub inception: u32,
    /// The key tag.
    pub key_tag: u16,
    /// The signer's name, wire form as sent.
    pub signer: &'a [u8],
    /// The signature.
    pub signature: &'a [u8],
}

impl<'a> Sig<'a> {
    /// Reads RRSIG record data; `None` when it is too short or its signer name does not
    /// parse (a compressed name inside RRSIG data is a server's fault, RFC 4034 section
    /// 3.1.7).
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 19 {
            return None;
        }
        let u32_at =
            |at: usize| u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]);
        let signer_len = uncompressed_len(&data[18..])?;
        let signer = &data[18..18 + signer_len];
        Some(Self {
            data,
            type_covered: u16::from_be_bytes([data[0], data[1]]),
            algorithm: data[2],
            labels: data[3],
            original_ttl: u32_at(4),
            expiration: u32_at(8),
            inception: u32_at(12),
            key_tag: u16::from_be_bytes([data[16], data[17]]),
            signer,
            signature: &data[18 + signer_len..],
        })
    }

    /// The signer's name in lowercase.
    pub fn signer_lower(&self) -> Vec<u8> {
        let mut signer = self.signer.to_vec();
        signer.make_ascii_lowercase();
        signer
    }

    /// The RRSIG data without the signature, the signer in lowercase (RFC 6840 section
    /// 5.1): the head of the signed data.
    pub fn head(&self) -> Vec<u8> {
        let mut head = self.data[..18].to_vec();
        head.extend_from_slice(&self.signer_lower());
        head
    }
}

/// The length of the uncompressed wire name at the start of `data`, or `None` when it is
/// not one (a compression pointer, a long label, a missing root).
pub fn uncompressed_len(data: &[u8]) -> Option<usize> {
    let mut pos = 0;
    loop {
        let len = usize::from(*data.get(pos)?);
        if len == 0 {
            return (pos < name::MAX_NAME_LEN).then_some(pos + 1);
        }
        if len > 63 {
            return None;
        }
        pos += 1 + len;
    }
}

/// The fields of a DNSKEY record (RFC 4034 section 2.1), borrowed from its data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key<'a> {
    /// The whole record data.
    pub data: &'a [u8],
    /// The flags.
    pub flags: u16,
    /// The protocol, 3.
    pub protocol: u8,
    /// The algorithm.
    pub algorithm: u8,
    /// The public key.
    pub public_key: &'a [u8],
    /// The key tag (RFC 4034 appendix B).
    pub key_tag: u16,
}

impl<'a> Key<'a> {
    /// Reads DNSKEY record data.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }
        Some(Self {
            data,
            flags: u16::from_be_bytes([data[0], data[1]]),
            protocol: data[2],
            algorithm: data[3],
            public_key: &data[4..],
            key_tag: crypto::key_tag(data),
        })
    }

    /// Whether the key may sign (the zone key bit, protocol 3, RFC 4034 section 2.1.1 and
    /// 2.1.2) and is not revoked (RFC 5011 section 2.1).
    pub fn usable(&self) -> bool {
        self.flags & tenko_core::dns::recursion::DNSKEY_ZONE != 0
            && self.protocol == 3
            && self.flags & tenko_core::dns::recursion::DNSKEY_REVOKE == 0
    }

    /// Whether the key carries the revoke bit.
    pub fn revoked(&self) -> bool {
        self.flags & tenko_core::dns::recursion::DNSKEY_REVOKE != 0
    }

    /// Whether the key carries the secure entry point bit.
    pub fn sep(&self) -> bool {
        self.flags & tenko_core::dns::recursion::DNSKEY_SEP != 0
    }
}

/// The records of one owner and type with the signatures that cover them.
#[derive(Debug, Clone)]
pub struct RrSet<'a> {
    /// The owner, lowercase wire form.
    pub owner: &'a [u8],
    /// The type.
    pub rtype: u16,
    /// The smallest TTL of the records.
    pub ttl: u32,
    /// The record data.
    pub records: Vec<&'a [u8]>,
    /// The RRSIGs covering the type at the owner.
    pub sigs: Vec<Sig<'a>>,
}

impl RrSet<'_> {
    /// The labels of the owner as an RRSIG counts them (RFC 4034 section 3.1.3): the root
    /// not counted, nor a leftmost `*`.
    pub fn owner_labels(&self) -> u8 {
        u8::try_from(signing_labels(self.owner)).unwrap_or(u8::MAX)
    }
}

/// The labels of a lowercase wire name without the root and without a leftmost `*`.
fn signing_labels(owner: &[u8]) -> usize {
    name::label_count(owner) - usize::from(owner.starts_with(b"\x01*"))
}

/// Groups the records of a section into RRsets with their signatures, in first-seen order.
pub fn group(section: &[Rr]) -> Vec<RrSet<'_>> {
    let mut sets: Vec<RrSet<'_>> = Vec::new();
    for rr in section {
        if rr.rtype == types::RRSIG {
            continue;
        }
        match sets
            .iter_mut()
            .find(|set| set.owner == rr.owner.as_slice() && set.rtype == rr.rtype)
        {
            Some(set) => {
                set.ttl = set.ttl.min(rr.ttl);
                set.records.push(&rr.data);
            }
            None => sets.push(RrSet {
                owner: &rr.owner,
                rtype: rr.rtype,
                ttl: rr.ttl,
                records: vec![&rr.data],
                sigs: Vec::new(),
            }),
        }
    }
    for rr in section {
        if rr.rtype != types::RRSIG {
            continue;
        }
        let Some(sig) = Sig::parse(&rr.data) else {
            continue;
        };
        if let Some(set) = sets
            .iter_mut()
            .find(|set| set.owner == rr.owner.as_slice() && set.rtype == sig.type_covered)
        {
            set.sigs.push(sig);
        }
    }
    sets
}

/// Where the names inside record data lie, for the types RFC 4034 section 6.2 lists
/// (HINFO left out and NSEC kept as it is, RFC 6840 section 5.1).
#[derive(Debug, Clone, Copy)]
enum Part {
    Fixed(usize),
    Name,
    /// A character string (NAPTR).
    Text,
}

fn layout(rtype: u16) -> Option<&'static [Part]> {
    const NAME: &[Part] = &[Part::Name];
    const SOA: &[Part] = &[Part::Name, Part::Name, Part::Fixed(20)];
    const TWO_NAMES: &[Part] = &[Part::Name, Part::Name];
    const PREF_NAME: &[Part] = &[Part::Fixed(2), Part::Name];
    const PX: &[Part] = &[Part::Fixed(2), Part::Name, Part::Name];
    const SRV: &[Part] = &[Part::Fixed(6), Part::Name];
    const NAPTR: &[Part] = &[
        Part::Fixed(4),
        Part::Text,
        Part::Text,
        Part::Text,
        Part::Name,
    ];
    Some(match rtype {
        // NS, MD, MF, CNAME, MB, MG, MR, PTR, DNAME
        2..=5 | 7..=9 | 12 | 39 => NAME,
        6 => SOA,
        // MINFO, RP
        14 | 17 => TWO_NAMES,
        // MX, AFSDB, RT, KX
        15 | 18 | 21 | 36 => PREF_NAME,
        26 => PX,
        33 => SRV,
        35 => NAPTR,
        _ => return None,
    })
}

/// Lowercases the letters of the uncompressed wire name at `pos` in `data`; returns the
/// position after it, or `None` when it does not parse.
fn lower_name(data: &mut [u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = usize::from(*data.get(pos)?);
        if len == 0 {
            return Some(pos + 1);
        }
        if len > 63 || pos + 1 + len > data.len() {
            return None;
        }
        data[pos + 1..pos + 1 + len].make_ascii_lowercase();
        pos += 1 + len;
    }
}

/// The canonical form of record data (RFC 4034 section 6.2 as RFC 6840 section 5.1
/// corrects it): the names inside the data of the types listed there in lowercase,
/// everything else as it is.
pub fn canonical_rdata(rtype: u16, data: &[u8]) -> Cow<'_, [u8]> {
    let Some(parts) = layout(rtype) else {
        return Cow::Borrowed(data);
    };
    let mut out = data.to_vec();
    let mut pos = 0;
    for part in parts {
        match part {
            Part::Fixed(len) => pos += len,
            Part::Text => pos += 1 + usize::from(*out.get(pos).unwrap_or(&0)),
            Part::Name => match lower_name(&mut out, pos) {
                Some(next) => pos = next,
                None => return Cow::Borrowed(data),
            },
        }
        if pos > out.len() {
            return Cow::Borrowed(data);
        }
    }
    Cow::Owned(out)
}

/// Why an RRset did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// No RRSIG covers it.
    NoSig,
    /// No signature names a key of the set with a supported algorithm.
    NoKey,
    /// Every usable signature has expired.
    Expired,
    /// Every usable signature is not valid yet.
    NotYetValid,
    /// A signature with a matching key does not verify.
    Signature,
    /// A cost cap was hit.
    Cap,
}

/// What a verified RRset tells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    /// The expiration of the signature that verified.
    pub expiration: u32,
    /// The original TTL of that signature.
    pub original_ttl: u32,
    /// The signature's signer labels when the RRset is a wildcard expansion: the labels
    /// of the closest encloser plus one (the wildcard's own), RFC 4035 section 5.3.4.
    pub wildcard_labels: Option<u8>,
    /// The key tag of the key that verified it.
    pub key_tag: u16,
}

/// The costs of one client query's validation against the caps.
#[derive(Debug, Clone, Copy, Default)]
pub struct Budget {
    /// Signature verifications so far.
    pub verifications: u32,
    /// Sub-queries so far.
    pub fetches: u32,
    /// NSEC3 hash computations in the current proof step.
    pub hashes: u32,
}

/// The owner an RRSIG signed: the owner itself, or `*.` and its last `labels` labels for
/// a wildcard expansion (RFC 4034 section 3.1.3).
fn signed_owner(owner: &[u8], labels: u8) -> Option<Cow<'_, [u8]>> {
    let count = signing_labels(owner);
    let labels = usize::from(labels);
    if labels == count {
        return Some(Cow::Borrowed(owner));
    }
    if labels > count {
        return None;
    }
    let suffix = name::suffix(owner, name::label_count(owner) - labels);
    let mut out = Vec::with_capacity(suffix.len() + 2);
    out.extend_from_slice(b"\x01*");
    out.extend_from_slice(suffix);
    Some(Cow::Owned(out))
}

/// Whether `now` lies in the signature's validity (RFC 4034 section 3.1.5, serial
/// arithmetic).
fn in_window(sig: &Sig<'_>, now: u32) -> Result<(), Fault> {
    if crate::dnssec::sign::seconds_until(sig.expiration, now) < 0 {
        return Err(Fault::Expired);
    }
    if crate::dnssec::sign::seconds_until(sig.inception, now) > 0 {
        return Err(Fault::NotYetValid);
    }
    Ok(())
}

/// Verifies `set` with the DNSKEY records `keys` (record data) of the zone `zone`
/// (lowercase wire form) at `now`, within `caps` and `budget`; `accept` narrows the keys
/// a signature may be checked with (the DS matching of a DNSKEY set, every usable key
/// otherwise).
///
/// Signatures whose signer is not `zone`, whose type does not match, whose algorithm is
/// unsupported or whose labels exceed the owner's are passed over. At most
/// `caps.key_candidates` keys of one tag are tried, at most `caps.per_rrset`
/// verifications are spent on the set and at most `caps.per_query` on the query.
///
/// # Errors
///
/// The [`Fault`] that describes every signature's failure: a time fault only when no
/// signature failed otherwise, a cap when one was hit.
pub fn verify(
    set: &RrSet<'_>,
    zone: &[u8],
    keys: &[&[u8]],
    accept: &dyn Fn(&Key<'_>) -> bool,
    now: u32,
    caps: &ValidationCaps,
    budget: &mut Budget,
) -> Result<Verified, Fault> {
    if set.sigs.is_empty() {
        return Err(Fault::NoSig);
    }
    let owner_labels = set.owner_labels();
    let mut fault = Fault::NoKey;
    let mut spent = 0u32;
    let mut saw_time_fault = false;
    let mut saw_other = false;
    let note = |fault: &mut Fault, saw_time: &mut bool, saw_other: &mut bool, new: Fault| {
        // A time fault is reported only when nothing else went wrong.
        match new {
            Fault::Expired | Fault::NotYetValid => {
                if !*saw_time {
                    *saw_time = true;
                    if !*saw_other {
                        *fault = new;
                    }
                }
            }
            other => {
                *saw_other = true;
                *fault = other;
            }
        }
    };
    for sig in &set.sigs {
        if sig.type_covered != set.rtype
            || sig.labels > owner_labels
            || !crypto::supported_algorithm(sig.algorithm)
            || !sig.signer.eq_ignore_ascii_case(zone)
        {
            continue;
        }
        let Some(owner) = signed_owner(set.owner, sig.labels) else {
            continue;
        };
        let mut candidates = 0u32;
        let mut signed = None;
        for data in keys {
            let Some(key) = Key::parse(data) else {
                continue;
            };
            if key.key_tag != sig.key_tag
                || key.algorithm != sig.algorithm
                || !key.usable()
                || !accept(&key)
            {
                continue;
            }
            candidates += 1;
            if candidates > caps.key_candidates {
                return Err(Fault::Cap);
            }
            if let Err(time) = in_window(sig, now) {
                note(&mut fault, &mut saw_time_fault, &mut saw_other, time);
                break;
            }
            if spent >= caps.per_rrset || budget.verifications >= caps.per_query {
                return Err(Fault::Cap);
            }
            spent += 1;
            budget.verifications += 1;
            let signed_data = signed.get_or_insert_with(|| {
                let records: Vec<Cow<'_, [u8]>> = set
                    .records
                    .iter()
                    .map(|data| canonical_rdata(set.rtype, data))
                    .collect();
                canonical::signed_data_wire(
                    &sig.head(),
                    &owner,
                    tenko_core::dns::Rtype(set.rtype),
                    sig.original_ttl,
                    records.iter().map(AsRef::as_ref),
                )
            });
            if crypto::verify(sig.algorithm, key.public_key, signed_data, sig.signature) {
                return Ok(Verified {
                    expiration: sig.expiration,
                    original_ttl: sig.original_ttl,
                    wildcard_labels: (sig.labels < owner_labels).then_some(sig.labels),
                    key_tag: sig.key_tag,
                });
            }
            note(
                &mut fault,
                &mut saw_time_fault,
                &mut saw_other,
                Fault::Signature,
            );
        }
    }
    Err(fault)
}

/// Whether a signature over `set` by the key `key` (DNSKEY record data, revoked or not)
/// verifies at `now`: the self-signature check of RFC 5011 section 2.1, where a key with
/// the REVOKE bit must have signed the DNSKEY set it is in. Costs one verification per
/// signature of the key's tag, at most `caps.per_rrset`.
pub fn self_signed(
    set: &RrSet<'_>,
    zone: &[u8],
    key: &[u8],
    now: u32,
    caps: &ValidationCaps,
    budget: &mut Budget,
) -> bool {
    let Some(key) = Key::parse(key) else {
        return false;
    };
    if key.protocol != 3 || !crypto::supported_algorithm(key.algorithm) {
        return false;
    }
    let mut spent = 0;
    for sig in &set.sigs {
        if sig.type_covered != set.rtype
            || sig.key_tag != key.key_tag
            || sig.algorithm != key.algorithm
            || !sig.signer.eq_ignore_ascii_case(zone)
            || in_window(sig, now).is_err()
        {
            continue;
        }
        let Some(owner) = signed_owner(set.owner, sig.labels) else {
            continue;
        };
        if spent >= caps.per_rrset || budget.verifications >= caps.per_query {
            return false;
        }
        spent += 1;
        budget.verifications += 1;
        let records: Vec<Cow<'_, [u8]>> = set
            .records
            .iter()
            .map(|data| canonical_rdata(set.rtype, data))
            .collect();
        let signed = canonical::signed_data_wire(
            &sig.head(),
            &owner,
            tenko_core::dns::Rtype(set.rtype),
            sig.original_ttl,
            records.iter().map(AsRef::as_ref),
        );
        if crypto::verify(sig.algorithm, key.public_key, &signed, sig.signature) {
            return true;
        }
    }
    false
}

/// The type bitmap of an NSEC or NSEC3 record (RFC 4034 section 4.1.2): whether `rtype`
/// is set.
pub fn bitmap_has(bitmap: &[u8], rtype: u16) -> bool {
    let window = u8::try_from(rtype >> 8).unwrap_or(0);
    let low = rtype & 0xff;
    let mut pos = 0;
    while pos + 2 <= bitmap.len() {
        let (number, len) = (bitmap[pos], usize::from(bitmap[pos + 1]));
        let Some(map) = bitmap.get(pos + 2..pos + 2 + len) else {
            return false;
        };
        if number == window {
            let octet = usize::from(low >> 3);
            return map
                .get(octet)
                .is_some_and(|byte| byte & (0x80 >> (low & 7)) != 0);
        }
        pos += 2 + len;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_data_lowercases_the_names_of_the_listed_types() {
        let mx = [
            0, 10, 4, b'M', b'A', b'I', b'L', 4, b'T', b'e', b'S', b't', 0,
        ];
        let out = canonical_rdata(15, &mx);
        assert_eq!(&out[2..], b"\x04mail\x04test\x00");
        // NSEC's next name keeps its case (RFC 6840 section 5.1).
        let nsec = [1, b'A', 0, 0, 1, 0x40];
        assert_eq!(canonical_rdata(47, &nsec).as_ref(), &nsec);
        // Data that does not parse as its type stays as it is.
        let broken = [0, 10, 70, b'x'];
        assert_eq!(canonical_rdata(15, &broken).as_ref(), &broken);
        // A NAPTR's replacement name is the one after three strings.
        let naptr = [0, 1, 0, 2, 1, b'U', 0, 0, 3, b'F', b'O', b'O', 0];
        let out = canonical_rdata(35, &naptr);
        assert_eq!(&out[8..], b"\x03foo\x00");
    }

    #[test]
    fn bitmaps_read_as_rfc4034_says() {
        // A, MX, RRSIG, NSEC in window 0; TYPE1234 in window 4.
        let mut bitmap = vec![0, 6, 0x40, 0x01, 0, 0, 0, 0x03, 4, 27];
        bitmap.extend_from_slice(&[0; 26]);
        bitmap.push(0x20);
        assert!(bitmap_has(&bitmap, 1));
        assert!(bitmap_has(&bitmap, 15));
        assert!(bitmap_has(&bitmap, 46));
        assert!(bitmap_has(&bitmap, 47));
        assert!(!bitmap_has(&bitmap, 2));
        assert!(!bitmap_has(&bitmap, 48));
        assert!(bitmap_has(&bitmap, 1234));
        assert!(!bitmap_has(&bitmap, 1235));
        assert!(!bitmap_has(&[0, 9, 1], 1));
    }

    #[test]
    fn a_wildcard_signature_signs_the_wildcard_owner() {
        let owner = b"\x03www\x07example\x04test\x00";
        assert_eq!(
            signed_owner(owner, 3).map(Cow::into_owned),
            Some(owner.to_vec())
        );
        assert_eq!(
            signed_owner(owner, 2).map(Cow::into_owned),
            Some(b"\x01*\x07example\x04test\x00".to_vec())
        );
        assert!(signed_owner(owner, 4).is_none());
        // A wildcard owner's own signature names the labels without the `*`.
        let wildcard = b"\x01*\x07example\x04test\x00";
        assert_eq!(
            signed_owner(wildcard, 2).map(Cow::into_owned),
            Some(wildcard.to_vec())
        );
        assert_eq!(signing_labels(wildcard), 2);
    }
}
