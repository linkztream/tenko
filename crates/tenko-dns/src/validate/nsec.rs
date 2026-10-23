//! NSEC proofs (RFC 4035 section 5.4, RFC 6840 section 4): that a name does not exist,
//! that a name has no records of a type (an empty non-terminal included), that a wildcard
//! answer was the right one, and that a delegation has no DS. The records given to the
//! functions here have been verified against the keys of the zone at `apex`; the proofs
//! only read them.
//!
//! Names are lowercase wire form; the order is the canonical order of RFC 4034 section
//! 6.1 ([`crate::tree::canonical_cmp`]).

use std::cmp::Ordering;

use crate::{name, recurse::message::types, tree::canonical_cmp};

use super::rrset::{bitmap_has, uncompressed_len};

/// One NSEC record of a zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec<'a> {
    /// The owner, lowercase wire form.
    pub owner: &'a [u8],
    /// The next owner name, in lowercase.
    pub next: Vec<u8>,
    /// The type bitmap.
    pub bitmap: &'a [u8],
}

impl<'a> Nsec<'a> {
    /// Reads NSEC record data at `owner`.
    pub fn parse(owner: &'a [u8], data: &'a [u8]) -> Option<Self> {
        let len = uncompressed_len(data)?;
        let mut next = data[..len].to_vec();
        next.make_ascii_lowercase();
        Some(Self {
            owner,
            next,
            bitmap: &data[len..],
        })
    }

    /// Whether the bitmap has `rtype`.
    pub fn has(&self, rtype: u16) -> bool {
        bitmap_has(self.bitmap, rtype)
    }

    /// Whether the record is an ancestor delegation's NSEC for `name` (RFC 6840 section
    /// 4.1): its owner is a strict ancestor of `name` with the NS bit and without the SOA
    /// bit, or with the DNAME bit; such a record says nothing about `name`, which lives in
    /// the child zone or under the DNAME.
    fn ancestor_delegation(&self, name: &[u8]) -> bool {
        self.owner != name
            && name::is_within(name, self.owner)
            && ((self.has(types::NS) && !self.has(types::SOA)) || self.has(types::DNAME))
    }

    /// Whether the record matches `name` (its owner is the name).
    pub fn matches(&self, name: &[u8]) -> bool {
        self.owner == name
    }

    /// Whether the record covers `name`: the name sorts after the owner and before the
    /// next name, or after the owner of the last record of the zone (whose next name is
    /// the apex), within the zone.
    pub fn covers(&self, name: &[u8], apex: &[u8]) -> bool {
        if !name::is_within(name, apex) || self.ancestor_delegation(name) {
            return false;
        }
        let after_owner = canonical_cmp(self.owner, name) == Ordering::Less;
        let before_next = canonical_cmp(name, &self.next) == Ordering::Less
            || (self.next == apex && canonical_cmp(&self.next, self.owner) != Ordering::Greater);
        after_owner && before_next
    }

    /// Whether the record proves `name` an empty non-terminal: it covers the name and its
    /// next name is below it.
    pub fn proves_empty_non_terminal(&self, name: &[u8], apex: &[u8]) -> bool {
        self.covers(name, apex) && self.next != name && name::is_within(&self.next, name)
    }
}

/// Why a proof is not there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofFault {
    /// No record proves it.
    Missing,
    /// A record shows the name exists, or has the type, or the wildcard exists.
    Exists,
    /// A cost cap was hit (NSEC3).
    Cap,
}

/// The longest common suffix of two lowercase wire names.
pub fn common_suffix<'a>(a: &'a [u8], b: &[u8]) -> &'a [u8] {
    let (la, lb) = (name::label_count(a), name::label_count(b));
    let mut common = 0;
    for index in 1..=la.min(lb) {
        let sa = name::suffix(a, la - index);
        let sb = name::suffix(b, lb - index);
        if sa == sb {
            common = index;
        } else {
            break;
        }
    }
    name::suffix(a, la - common)
}

/// The wildcard at `encloser`: `*.encloser`.
pub fn wildcard_of(encloser: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(encloser.len() + 2);
    out.extend_from_slice(b"\x01*");
    out.extend_from_slice(encloser);
    out
}

/// Proves that `qname` does not exist in the zone at `apex` (RFC 4035 section 5.4): a
/// record covers the name, no record matches it or proves it an empty non-terminal, and a
/// record covers the wildcard at the closest encloser (the longest common suffix of the
/// name and the covering record's owner or next name).
///
/// # Errors
///
/// [`ProofFault`].
pub fn prove_nxdomain(records: &[Nsec<'_>], qname: &[u8], apex: &[u8]) -> Result<(), ProofFault> {
    if records
        .iter()
        .any(|nsec| nsec.matches(qname) || nsec.proves_empty_non_terminal(qname, apex))
    {
        return Err(ProofFault::Exists);
    }
    let covering = records
        .iter()
        .find(|nsec| nsec.covers(qname, apex))
        .ok_or(ProofFault::Missing)?;
    let by_owner = common_suffix(qname, covering.owner);
    let by_next = common_suffix(qname, &covering.next);
    let encloser = if name::label_count(by_owner) >= name::label_count(by_next) {
        by_owner
    } else {
        by_next
    };
    let wildcard = wildcard_of(encloser);
    if records.iter().any(|nsec| nsec.matches(&wildcard)) {
        return Err(ProofFault::Exists);
    }
    if records.iter().any(|nsec| nsec.covers(&wildcard, apex)) {
        Ok(())
    } else {
        Err(ProofFault::Missing)
    }
}

/// What a NODATA proof found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nodata {
    /// The name exists without the type.
    Plain,
    /// The name is an empty non-terminal.
    EmptyNonTerminal,
    /// A wildcard answers the name, without the type.
    Wildcard,
}

/// Proves that `qname` has no records of `qtype` (RFC 4035 section 5.4, RFC 6840 section
/// 4.3): a record matches the name without the type and without CNAME (unless the type is
/// CNAME) and, for a type other than DS, is not the parent's record of a delegation; or
/// a record proves the name an empty non-terminal; or (a wildcard NODATA) a record covers
/// the name and one matches the wildcard at its closest encloser without the type.
///
/// # Errors
///
/// [`ProofFault`].
pub fn prove_nodata(
    records: &[Nsec<'_>],
    qname: &[u8],
    qtype: u16,
    apex: &[u8],
) -> Result<Nodata, ProofFault> {
    if let Some(nsec) = records.iter().find(|nsec| nsec.matches(qname)) {
        if nsec.has(qtype) || (qtype != types::CNAME && nsec.has(types::CNAME)) {
            return Err(ProofFault::Exists);
        }
        if qtype != types::DS && nsec.has(types::NS) && !nsec.has(types::SOA) {
            // The parent's record at a delegation says nothing about the child's data.
            return Err(ProofFault::Missing);
        }
        return Ok(Nodata::Plain);
    }
    if records
        .iter()
        .any(|nsec| nsec.proves_empty_non_terminal(qname, apex))
    {
        return Ok(Nodata::EmptyNonTerminal);
    }
    let covering = records
        .iter()
        .find(|nsec| nsec.covers(qname, apex))
        .ok_or(ProofFault::Missing)?;
    let by_owner = common_suffix(qname, covering.owner);
    let by_next = common_suffix(qname, &covering.next);
    let encloser = if name::label_count(by_owner) >= name::label_count(by_next) {
        by_owner
    } else {
        by_next
    };
    let wildcard = wildcard_of(encloser);
    let star = records
        .iter()
        .find(|nsec| nsec.matches(&wildcard))
        .ok_or(ProofFault::Missing)?;
    if star.has(qtype) || (qtype != types::CNAME && star.has(types::CNAME)) {
        return Err(ProofFault::Exists);
    }
    Ok(Nodata::Wildcard)
}

/// Proves that a wildcard answer for `qname` was right (RFC 4035 section 5.3.4): a record
/// covers the name itself, so no closer match exists.
///
/// # Errors
///
/// [`ProofFault`].
pub fn prove_wildcard(records: &[Nsec<'_>], qname: &[u8], apex: &[u8]) -> Result<(), ProofFault> {
    if records.iter().any(|nsec| nsec.matches(qname)) {
        return Err(ProofFault::Exists);
    }
    if records.iter().any(|nsec| nsec.covers(qname, apex)) {
        Ok(())
    } else {
        Err(ProofFault::Missing)
    }
}

/// What the parent's records say about a name asked for DS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutProof {
    /// A delegation without DS: the child is insecure (RFC 4035 section 5.2, RFC 6840
    /// section 4.4).
    Insecure,
    /// Not a delegation: the parent's keys go on applying below the name.
    NotACut,
    /// The records say the DS exists after all, or the delegation is the zone's own apex.
    Bogus,
}

/// What the parent's NSEC records prove about `child` asked for DS: a matching record with
/// NS, without DS and without SOA proves an insecure delegation; a matching record
/// without NS, a record proving an empty non-terminal, or one covering the name proves
/// there is no delegation at it.
pub fn delegation(records: &[Nsec<'_>], child: &[u8], apex: &[u8]) -> Option<CutProof> {
    if let Some(nsec) = records.iter().find(|nsec| nsec.matches(child)) {
        if nsec.has(types::DS) || nsec.has(types::SOA) {
            return Some(CutProof::Bogus);
        }
        return Some(if nsec.has(types::NS) {
            CutProof::Insecure
        } else {
            CutProof::NotACut
        });
    }
    records
        .iter()
        .any(|nsec| nsec.covers(child, apex))
        .then_some(CutProof::NotACut)
}
