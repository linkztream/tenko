//! NSEC3 proofs (RFC 5155 section 8, RFC 6840 section 4, RFC 9276): the closest encloser
//! proof, name errors, NODATA with and without opt-out, wildcard answers and unsigned
//! delegations, over records verified against the keys of the zone at `apex`.
//!
//! Hashing costs: every hash of a name counts against the cap of hashes per proof step
//! (`ValidationCaps::nsec3_hashes_per_step`, the `KeyTrap` class). A step is the closest
//! encloser search (one hash per label from the name up to its encloser), the wildcard
//! check (one hash) or a match (one hash); a proof that needs more hashes than the cap
//! fails as a cap, so a name more than the cap's labels below its closest encloser is
//! not proven.

use std::cmp::Ordering;

use crate::{
    dnssec::chain::{HASH_LEN, NSEC3_SHA1, base32hex_decode, nsec3_hash},
    name,
    recurse::message::types,
    recursion::ValidationCaps,
};

use super::{
    nsec::{CutProof, Nodata, ProofFault, wildcard_of},
    rrset::{Budget, bitmap_has},
};

/// The opt-out flag of an NSEC3 record (RFC 5155 section 3.1.2.1).
pub const OPT_OUT: u8 = 1;

/// One NSEC3 record of a zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec3<'a> {
    /// The hash the owner name stands for.
    pub hash: [u8; HASH_LEN],
    /// The flags.
    pub flags: u8,
    /// The iterations.
    pub iterations: u16,
    /// The salt.
    pub salt: &'a [u8],
    /// The next hashed owner.
    pub next: &'a [u8],
    /// The type bitmap.
    pub bitmap: &'a [u8],
}

impl<'a> Nsec3<'a> {
    /// Reads NSEC3 record data at `owner`, a hashed owner of the zone at `apex` (one label
    /// below it), with the SHA-1 hash algorithm.
    pub fn parse(owner: &'a [u8], data: &'a [u8], apex: &[u8]) -> Option<Self> {
        let label_len = usize::from(*owner.first()?);
        let label = owner.get(1..1 + label_len)?;
        if owner.get(1 + label_len..) != Some(apex) {
            return None;
        }
        let hash = base32hex_decode(label)?;
        let [
            hash_algorithm,
            flags,
            iterations_high,
            iterations_low,
            salt_len,
            rest @ ..,
        ] = data
        else {
            return None;
        };
        if *hash_algorithm != NSEC3_SHA1 {
            return None;
        }
        let salt = rest.get(..usize::from(*salt_len))?;
        let rest = &rest[usize::from(*salt_len)..];
        let next_len = usize::from(*rest.first()?);
        let next = rest.get(1..1 + next_len)?;
        if next.len() != HASH_LEN {
            return None;
        }
        Some(Self {
            hash,
            flags: *flags,
            iterations: u16::from_be_bytes([*iterations_high, *iterations_low]),
            salt,
            next,
            bitmap: &rest[1 + next_len..],
        })
    }

    /// Whether the bitmap has `rtype`.
    pub fn has(&self, rtype: u16) -> bool {
        bitmap_has(self.bitmap, rtype)
    }

    /// Whether the record has the opt-out flag.
    pub fn opt_out(&self) -> bool {
        self.flags & OPT_OUT != 0
    }

    /// Whether the record matches `hash`.
    pub fn matches(&self, hash: &[u8; HASH_LEN]) -> bool {
        self.hash == *hash
    }

    /// Whether the record covers `hash`: between its own hash and the next, or past the
    /// last record of the chain (whose next hash is the smallest).
    pub fn covers(&self, hash: &[u8; HASH_LEN]) -> bool {
        let after = hash.as_slice().cmp(&self.hash[..]) == Ordering::Greater;
        let before = hash.as_slice().cmp(self.next) == Ordering::Less;
        if self.next.cmp(&self.hash[..]) == Ordering::Greater {
            after && before
        } else {
            // The last record wraps around.
            after || before
        }
    }
}

/// The NSEC3 records of one answer with the parameters they share (RFC 5155 section
/// 8.2: records of other parameters are ignored) and the hash budget.
pub struct Chain<'a> {
    records: Vec<&'a Nsec3<'a>>,
    salt: &'a [u8],
    iterations: u16,
    apex: &'a [u8],
}

impl<'a> Chain<'a> {
    /// The records of the first record's parameters.
    pub fn new(records: &'a [Nsec3<'a>], apex: &'a [u8]) -> Option<Self> {
        let first = records.first()?;
        Some(Self {
            records: records
                .iter()
                .filter(|record| record.salt == first.salt && record.iterations == first.iterations)
                .collect(),
            salt: first.salt,
            iterations: first.iterations,
            apex,
        })
    }

    /// The iterations the chain uses.
    pub fn iterations(&self) -> u16 {
        self.iterations
    }

    /// Starts a proof step: the hashes of the step count from zero.
    fn step(budget: &mut Budget) {
        budget.hashes = 0;
    }

    /// Hashes `name` within the cap.
    fn hash(
        &self,
        name: &[u8],
        caps: &ValidationCaps,
        budget: &mut Budget,
    ) -> Result<[u8; HASH_LEN], ProofFault> {
        if budget.hashes >= caps.nsec3_hashes_per_step {
            return Err(ProofFault::Cap);
        }
        budget.hashes += 1;
        Ok(nsec3_hash(name, self.salt, self.iterations))
    }

    fn matching(&self, hash: &[u8; HASH_LEN]) -> Option<&'a Nsec3<'a>> {
        self.records
            .iter()
            .copied()
            .find(|record| record.matches(hash))
    }

    fn covering(&self, hash: &[u8; HASH_LEN]) -> Option<&'a Nsec3<'a>> {
        self.records
            .iter()
            .copied()
            .find(|record| record.covers(hash))
    }

    /// The closest encloser proof for `qname` (RFC 5155 section 8.3, as written there):
    /// from the name upwards, the first ancestor a record matches is the encloser, and
    /// the name one label below it must be covered by a record. Returns the encloser, its
    /// record and the record covering the next closer name.
    ///
    /// # Errors
    ///
    /// [`ProofFault::Exists`] when the name itself is matched, [`ProofFault::Missing`]
    /// when the chain has a gap, [`ProofFault::Cap`] past the hash cap (a name more than
    /// the cap's labels below its encloser).
    pub fn closest_encloser<'q>(
        &self,
        qname: &'q [u8],
        caps: &ValidationCaps,
        budget: &mut Budget,
    ) -> Result<(&'q [u8], &'a Nsec3<'a>, &'a Nsec3<'a>), ProofFault> {
        let labels = name::label_count(qname);
        let apex_labels = name::label_count(self.apex);
        if labels < apex_labels || !name::is_within(qname, self.apex) {
            return Err(ProofFault::Missing);
        }
        Self::step(budget);
        let mut covered: Option<&'a Nsec3<'a>> = None;
        for skip in 0..=labels - apex_labels {
            let candidate = name::suffix(qname, skip);
            let hash = self.hash(candidate, caps, budget)?;
            if let Some(record) = self.matching(&hash) {
                if skip == 0 {
                    return Err(ProofFault::Exists);
                }
                // RFC 5155 section 8.3: the encloser's record is the zone's own.
                if record.has(types::DNAME) || (record.has(types::NS) && !record.has(types::SOA)) {
                    return Err(ProofFault::Missing);
                }
                let next_closer = covered.ok_or(ProofFault::Missing)?;
                return Ok((candidate, record, next_closer));
            }
            covered = self.covering(&hash);
        }
        Err(ProofFault::Missing)
    }

    /// Proves the name error for `qname` (RFC 5155 section 8.4): the closest encloser
    /// proof and a record covering the wildcard at the encloser. Returns whether the
    /// record covering the next closer name has the opt-out flag (RFC 5155 section 9.2:
    /// the answer is then insecure, not secure).
    ///
    /// # Errors
    ///
    /// [`ProofFault`].
    pub fn prove_nxdomain(
        &self,
        qname: &[u8],
        caps: &ValidationCaps,
        budget: &mut Budget,
    ) -> Result<bool, ProofFault> {
        let (encloser, _, next_closer) = self.closest_encloser(qname, caps, budget)?;
        Self::step(budget);
        let wildcard = self.hash(&wildcard_of(encloser), caps, budget)?;
        if self.matching(&wildcard).is_some() {
            return Err(ProofFault::Exists);
        }
        self.covering(&wildcard).ok_or(ProofFault::Missing)?;
        Ok(next_closer.opt_out())
    }

    /// Proves that `qname` has no records of `qtype` (RFC 5155 sections 8.5 to 8.7): a
    /// matching record without the type and without CNAME; else, for DS, the closest
    /// encloser proof with opt-out on the next closer name (an insecure delegation);
    /// else the closest encloser proof and a matching wildcard without the type.
    ///
    /// # Errors
    ///
    /// [`ProofFault`].
    pub fn prove_nodata(
        &self,
        qname: &[u8],
        qtype: u16,
        caps: &ValidationCaps,
        budget: &mut Budget,
    ) -> Result<(Nodata, bool), ProofFault> {
        Self::step(budget);
        let hash = self.hash(qname, caps, budget)?;
        if let Some(record) = self.matching(&hash) {
            if record.has(qtype) || (qtype != types::CNAME && record.has(types::CNAME)) {
                return Err(ProofFault::Exists);
            }
            if qtype != types::DS && record.has(types::NS) && !record.has(types::SOA) {
                return Err(ProofFault::Missing);
            }
            return Ok((Nodata::Plain, false));
        }
        let (encloser, _, next_closer) = self.closest_encloser(qname, caps, budget)?;
        if qtype == types::DS && next_closer.opt_out() {
            return Ok((Nodata::Plain, true));
        }
        Self::step(budget);
        let wildcard = self.hash(&wildcard_of(encloser), caps, budget)?;
        let star = self.matching(&wildcard).ok_or(ProofFault::Missing)?;
        if star.has(qtype) || (qtype != types::CNAME && star.has(types::CNAME)) {
            return Err(ProofFault::Exists);
        }
        Ok((Nodata::Wildcard, next_closer.opt_out()))
    }

    /// Proves that a wildcard answer for `qname` was right (RFC 5155 section 8.8): the
    /// next closer name below the encloser of `encloser_labels` labels is covered. Returns
    /// whether the covering record has the opt-out flag.
    ///
    /// # Errors
    ///
    /// [`ProofFault`].
    pub fn prove_wildcard(
        &self,
        qname: &[u8],
        encloser_labels: u8,
        caps: &ValidationCaps,
        budget: &mut Budget,
    ) -> Result<bool, ProofFault> {
        let labels = name::label_count(qname);
        let encloser_labels = usize::from(encloser_labels);
        if encloser_labels >= labels {
            return Err(ProofFault::Missing);
        }
        let next_closer = name::suffix(qname, labels - encloser_labels - 1);
        Self::step(budget);
        let hash = self.hash(next_closer, caps, budget)?;
        if self.matching(&hash).is_some() {
            return Err(ProofFault::Exists);
        }
        let covering = self.covering(&hash).ok_or(ProofFault::Missing)?;
        Ok(covering.opt_out())
    }

    /// What the parent's records prove about `child` asked for DS (RFC 5155 section 8.9,
    /// RFC 6840 section 4.4): a matching record with NS, without DS and SOA, proves an
    /// insecure delegation; a matching record without NS proves there is no delegation;
    /// the closest encloser proof with opt-out on the next closer name proves an
    /// insecure delegation that may exist; without opt-out it proves there is none.
    ///
    /// # Errors
    ///
    /// A proof the records do not give (`Missing`), one they contradict (`Exists`), or
    /// one the hash cap cuts short (`Cap`).
    pub fn delegation(
        &self,
        child: &[u8],
        caps: &ValidationCaps,
        budget: &mut Budget,
    ) -> Result<Option<CutProof>, ProofFault> {
        Self::step(budget);
        let hash = self.hash(child, caps, budget)?;
        if let Some(record) = self.matching(&hash) {
            if record.has(types::DS) || record.has(types::SOA) {
                return Ok(Some(CutProof::Bogus));
            }
            return Ok(Some(if record.has(types::NS) {
                CutProof::Insecure
            } else {
                CutProof::NotACut
            }));
        }
        match self.closest_encloser(child, caps, budget) {
            Ok((_, _, next_closer)) => Ok(Some(if next_closer.opt_out() {
                CutProof::Insecure
            } else {
                CutProof::NotACut
            })),
            Err(ProofFault::Cap) => Err(ProofFault::Cap),
            Err(_) => Ok(None),
        }
    }
}
