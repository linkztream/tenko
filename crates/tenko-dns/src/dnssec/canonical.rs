//! The canonical form of RRsets (RFC 4034, section 6) and the data an RRSIG signs (RFC
//! 4034, section 3.1.8.1).
//!
//! Tenko stores names in lowercase and record data with lowercase names, so the canonical
//! form of an owner name is its wire form and the canonical form of record data is the
//! stored octets. What remains is the order: the records of an RRset sorted as unsigned
//! octet strings, each with the owner, type, class, the original TTL and its length, after
//! the RRSIG record data without the signature.

use tenko_core::dns::{DnsName, Rdata, Rtype};

/// The class every record of a zone has: IN.
pub const CLASS_IN: u16 = 1;

/// The labels field of an RRSIG over `owner` (RFC 4034, section 3.1.3): its labels without
/// the root and without a leftmost `*`.
pub fn rrsig_labels(owner: &DnsName) -> u8 {
    let count = owner.label_count() - usize::from(owner.is_wildcard());
    u8::try_from(count).unwrap_or(u8::MAX)
}

/// The fields of an RRSIG before its signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RrsigHead<'a> {
    /// The type the signature covers.
    pub type_covered: Rtype,
    /// The algorithm number.
    pub algorithm: u8,
    /// The labels of the owner ([`rrsig_labels`]).
    pub labels: u8,
    /// The TTL of the covered RRset.
    pub original_ttl: u32,
    /// Expiration, seconds since 1970 modulo 2^32.
    pub expiration: u32,
    /// Inception, seconds since 1970 modulo 2^32.
    pub inception: u32,
    /// The key tag of the signing key.
    pub key_tag: u16,
    /// The zone apex.
    pub signer: &'a DnsName,
}

impl RrsigHead<'_> {
    /// The RRSIG record data without the signature.
    pub fn wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(18 + self.signer.wire_len());
        out.extend_from_slice(&self.type_covered.0.to_be_bytes());
        out.push(self.algorithm);
        out.push(self.labels);
        out.extend_from_slice(&self.original_ttl.to_be_bytes());
        out.extend_from_slice(&self.expiration.to_be_bytes());
        out.extend_from_slice(&self.inception.to_be_bytes());
        out.extend_from_slice(&self.key_tag.to_be_bytes());
        self.signer.write_wire(&mut out);
        out
    }

    /// The complete RRSIG record data with `signature`.
    pub fn with_signature(&self, signature: &[u8]) -> Vec<u8> {
        let mut out = self.wire();
        out.extend_from_slice(signature);
        out
    }
}

/// The records of an RRset in canonical order: their data sorted as unsigned octet
/// strings, duplicates dropped.
pub fn sorted<'a>(rdata: impl IntoIterator<Item = &'a [u8]>) -> Vec<&'a [u8]> {
    let mut records: Vec<&[u8]> = rdata.into_iter().collect();
    records.sort_unstable();
    records.dedup();
    records
}

/// The octets an RRSIG with `head` signs over the RRset of `owner` and `rtype` (RFC 4034,
/// section 3.1.8.1). A wildcard owner is signed as `*.` and its closest encloser, which is
/// how a stored wildcard RRset reads.
pub fn signed_data<'a>(
    head: &RrsigHead<'_>,
    owner: &DnsName,
    rtype: Rtype,
    rdata: impl IntoIterator<Item = &'a [u8]>,
) -> Vec<u8> {
    signed_data_wire(
        &head.wire(),
        &owner.to_wire(),
        rtype,
        head.original_ttl,
        rdata,
    )
}

/// [`signed_data`] over the RRSIG head and the owner in wire form.
pub fn signed_data_wire<'a>(
    head: &[u8],
    owner: &[u8],
    rtype: Rtype,
    ttl: u32,
    rdata: impl IntoIterator<Item = &'a [u8]>,
) -> Vec<u8> {
    let records = sorted(rdata);
    let size = head.len()
        + records
            .iter()
            .map(|data| owner.len() + 10 + data.len())
            .sum::<usize>();
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(head);
    for data in records {
        out.extend_from_slice(owner);
        out.extend_from_slice(&rtype.0.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        let len = u16::try_from(data.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}

/// The record data of an RRset as octet slices.
pub fn slices(rdata: &[Rdata]) -> impl Iterator<Item = &[u8]> {
    rdata.iter().map(Rdata::as_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_leave_out_the_wildcard() {
        let name = |text: &str| DnsName::new(text).expect("name");
        assert_eq!(rrsig_labels(&name("www.example.test")), 3);
        assert_eq!(rrsig_labels(&name("*.example.test")), 2);
        assert_eq!(rrsig_labels(&name("example.test")), 2);
    }

    #[test]
    fn records_sort_as_octet_strings() {
        let a: &[u8] = &[1, 2];
        let b: &[u8] = &[1];
        let c: &[u8] = &[0, 9];
        assert_eq!(sorted([a, b, c, b]), vec![c, b, a]);
    }
}
