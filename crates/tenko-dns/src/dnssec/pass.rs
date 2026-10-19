//! One signing pass over a zone scope: what the generated rows must be, compared with what
//! the store holds, as row changes.
//!
//! # What is signed
//!
//! Every owner name that holds data and is not below a zone cut or a DNAME is in the chain.
//! At such an owner every RRset is signed, except at a cut, where only the DS is (the NS
//! set and the glue belong to the child). The apex also holds the DNSKEY set and, while a
//! key-signing key should be in the parent, the CDS and CDNSKEY sets (RFC 7344); an NSEC3
//! zone holds NSEC3PARAM there. The DNSKEY, CDS and CDNSKEY sets are signed by the
//! key-signing keys, everything else by the zone-signing keys ([`KeySet::signers`]).
//!
//! # Denial
//!
//! With NSEC each chain owner gets an NSEC record naming the next chain owner in canonical
//! order (the last names the apex) and the types of the owner with RRSIG and NSEC. With
//! NSEC3 (RFC 5155, without opt-out, RFC 9276 parameters by default) each chain owner and
//! each empty non-terminal above one gets an NSEC3 record at the hashed owner name, in hash
//! order; an empty non-terminal has no types, a cut without DS only NS.
//!
//! # Full and incremental passes
//!
//! A full pass streams every row of the scope in canonical order (the store keys sort
//! that way), builds the chain on the way and signs what has no signature it can keep
//! ([`sign::keeps`]; with `verify`, a kept signature must also verify over the data). An
//! incremental pass starts from the RRsets that changed: their owners, the chain neighbours
//! whose NSEC must point elsewhere, and for NSEC3 the empty non-terminals above them and the
//! hashed owners before them in hash order. Both re-sign the changed RRsets and keep the
//! other signatures. The SOA is not signed here: the pass that writes anything moves the
//! serial, and the signature of the new SOA is made with the apex at the end
//! ([`Pass::apex`]).

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Arc,
};

use tenko_core::{
    Revision,
    codec::key::encode_key,
    dns::{
        Denial, DnsName, Origin, Rdata, RecordData, RrSet, RrSetKey, Rtype, ScopeName, Zone, codes,
        tables::RRSETS,
    },
    ipam::Stamp,
    serde_util::HexBytes,
};
use tenko_store::{KeyRange, ReadView, ReadViewExt};

use super::{
    chain::{self, HASH_LEN, NSEC3_SHA1, is_generated},
    keys::KeySet,
    sign::{self, Times},
};
use crate::zone::{ZoneError, ZoneResult};

/// One row the pass changes: the row before (with its revision, which the write expects)
/// and after.
#[derive(Debug, Clone)]
pub struct RowChange {
    /// The row.
    pub key: RrSetKey,
    /// Before; none when it is new.
    pub old: Option<(RrSet, Revision)>,
    /// After; none when it goes.
    pub new: Option<RrSet>,
}

/// An RRset to sign at an owner.
#[derive(Debug, Clone)]
pub struct SignSet {
    /// The type.
    pub rtype: Rtype,
    /// The TTL.
    pub ttl: u32,
    /// The records.
    pub rdata: Vec<Rdata>,
    /// The data changed: no signature of it is kept.
    pub dirty: bool,
}

impl SignSet {
    fn of(rrset: &RrSet, dirty: bool) -> Self {
        Self {
            rtype: rrset.rtype,
            ttl: rrset.ttl,
            rdata: rrset.rdata.clone(),
            dirty,
        }
    }
}

/// The work at one owner name.
#[derive(Debug, Default)]
pub struct OwnerJob {
    /// The owner.
    pub name: Option<DnsName>,
    /// The data RRsets to sign.
    pub data: Vec<SignSet>,
    /// The generated rows the owner must hold, without the RRSIG row.
    pub desired: Vec<RrSet>,
    /// The generated rows it holds (origin `dnssec`), the RRSIG row included.
    pub existing: Vec<(RrSet, Revision)>,
    /// Rows to delete outright: types of the signer written by another origin.
    pub stale: Vec<(RrSet, Revision)>,
}

/// What one pass needs to know.
pub struct Pass<'a> {
    /// The zone.
    pub zone: &'a Zone,
    /// The scope.
    pub scope: &'a ScopeName,
    /// The keys.
    pub keys: &'a KeySet,
    /// The times.
    pub times: Times,
    /// Kept signatures must verify.
    pub verify: bool,
    /// The stamp of the rows written.
    pub stamp: Stamp,
    /// The RRsets whose data changed (owner and type), re-signed whatever their signature.
    pub dirty: &'a HashSet<(DnsName, Rtype)>,
}

/// What a job produced: the row changes and the earliest expiration of the signatures the
/// owner holds after it.
pub type JobOutput = (Vec<RowChange>, Option<u32>);

/// The earlier of two expirations, as seen from `now`.
pub fn earlier(a: Option<u32>, b: Option<u32>, now: u32) -> Option<u32> {
    match (a, b) {
        (Some(a), Some(b)) => Some(
            if sign::seconds_until(a, now) <= sign::seconds_until(b, now) {
                a
            } else {
                b
            },
        ),
        (a, None) => a,
        (None, b) => b,
    }
}

fn failed(zone: &Zone, reason: impl Into<String>) -> ZoneError {
    let reason = reason.into();
    ZoneError::new(
        codes::DNSSEC_SIGNING_FAILED,
        500,
        format!("zone {} could not be signed: {reason}", zone.name),
    )
    .param("zone", zone.name.as_str())
    .param("reason", reason)
}

/// Whether two rows hold the same TTL and records.
pub fn same_rows(a: &RrSet, b: &RrSet) -> bool {
    a.ttl == b.ttl && a.rdata.len() == b.rdata.len() && a.rdata.iter().all(|r| b.rdata.contains(r))
}

impl Pass<'_> {
    /// A generated row of this zone scope.
    pub fn row(&self, name: &DnsName, rtype: Rtype, ttl: u32, rdata: Vec<Rdata>) -> RrSet {
        RrSet {
            zone: self.zone.id,
            scope: self.scope.clone(),
            name: name.clone(),
            rtype,
            ttl,
            rdata,
            origin: Origin::Dnssec,
            key: None,
            updated: self.stamp.clone(),
        }
    }

    fn is_dirty(&self, name: &DnsName, rtype: Rtype) -> bool {
        self.dirty.contains(&(name.clone(), rtype))
    }

    /// The TTL of NSEC and NSEC3 records.
    fn denial_ttl(&self) -> u32 {
        chain::denial_ttl(&self.zone.soa)
    }

    /// The generated rows of the apex besides the denial records: DNSKEY, CDS and CDNSKEY
    /// (while a key should be in the parent), NSEC3PARAM for NSEC3.
    pub fn apex_rows(&self) -> Vec<RrSet> {
        let apex = &self.zone.name;
        let ttl = self.zone.soa.ttl;
        let mut rows = vec![self.row(apex, Rtype::DNSKEY, ttl, self.keys.dnskeys())];
        let cds = self.keys.cds(apex);
        if !cds.is_empty() {
            rows.push(self.row(apex, Rtype::CDS, ttl, cds));
            rows.push(self.row(apex, Rtype::CDNSKEY, ttl, self.keys.cdnskeys()));
        }
        if let Denial::Nsec3 { iterations, salt } = &self.zone.dnssec.denial {
            let param = RecordData::Nsec3param {
                hash_algorithm: NSEC3_SHA1,
                flags: 0,
                iterations: *iterations,
                salt: salt.clone(),
            };
            rows.push(self.row(apex, Rtype::NSEC3PARAM, 0, vec![Rdata::from_data(&param)]));
        }
        rows.retain(|row| !row.rdata.is_empty());
        rows
    }

    /// The NSEC row of an owner.
    pub fn nsec(&self, name: &DnsName, next: &DnsName, types: Vec<Rtype>) -> RrSet {
        let data = RecordData::Nsec {
            next: next.clone(),
            types,
        };
        self.row(
            name,
            Rtype::NSEC,
            self.denial_ttl(),
            vec![Rdata::from_data(&data)],
        )
    }

    /// The NSEC3 row at a hashed owner.
    pub fn nsec3(&self, hash: &[u8; HASH_LEN], next: &[u8; HASH_LEN], types: Vec<Rtype>) -> RrSet {
        let (iterations, salt) = self.nsec3_params();
        let data = RecordData::Nsec3 {
            hash_algorithm: NSEC3_SHA1,
            flags: 0,
            iterations,
            salt: HexBytes(salt.to_vec()),
            next_hashed: HexBytes(next.to_vec()),
            types,
        };
        let owner = chain::hashed_owner(hash, &self.zone.name);
        self.row(
            &owner,
            Rtype::NSEC3,
            self.denial_ttl(),
            vec![Rdata::from_data(&data)],
        )
    }

    /// The NSEC3 parameters of the zone (zero and empty for an NSEC zone).
    pub fn nsec3_params(&self) -> (u16, &[u8]) {
        match &self.zone.dnssec.denial {
            Denial::Nsec3 { iterations, salt } => (*iterations, &salt.0),
            Denial::Nsec => (0, &[]),
        }
    }

    /// The NSEC3 hash of a name of the zone.
    pub fn hash(&self, name: &DnsName) -> [u8; HASH_LEN] {
        let (iterations, salt) = self.nsec3_params();
        chain::nsec3_hash(&name.to_wire(), salt, iterations)
    }

    /// Whether the zone uses NSEC3.
    pub fn nsec3_zone(&self) -> bool {
        matches!(self.zone.dnssec.denial, Denial::Nsec3 { .. })
    }

    /// Runs one job: the RRSIG row over the data and the desired generated rows, and the
    /// row changes against what the owner holds.
    ///
    /// # Errors
    ///
    /// `dns.dnssec.signing_failed` when a signature fails or no key signs a type.
    pub fn run(&self, job: OwnerJob) -> ZoneResult<JobOutput> {
        let Some(name) = job.name.clone() else {
            return Ok((Vec::new(), None));
        };
        let mut existing: BTreeMap<Rtype, (RrSet, Revision)> = job
            .existing
            .into_iter()
            .map(|(row, revision)| (row.rtype, (row, revision)))
            .collect();
        let mut changes = Vec::new();
        let mut sets = job.data;
        for row in job.desired {
            let unchanged = existing
                .get(&row.rtype)
                .is_some_and(|(old, _)| same_rows(old, &row));
            sets.push(SignSet::of(&row, !unchanged));
            let old = existing.remove(&row.rtype);
            if !unchanged {
                changes.push(RowChange {
                    key: row.key(),
                    old,
                    new: Some(row),
                });
            }
        }
        let old_sigs = existing.remove(&Rtype::RRSIG);
        for (_, (row, revision)) in existing {
            changes.push(RowChange {
                key: row.key(),
                old: Some((row, revision)),
                new: None,
            });
        }
        for (row, revision) in job.stale {
            changes.push(RowChange {
                key: row.key(),
                old: Some((row, revision)),
                new: None,
            });
        }
        let (sigs, expires) =
            self.signatures(&name, &sets, old_sigs.as_ref().map(|(row, _)| row))?;
        match (sigs, old_sigs) {
            (Some(new), Some((old, revision))) => {
                if !same_rows(&old, &new) {
                    changes.push(RowChange {
                        key: new.key(),
                        old: Some((old, revision)),
                        new: Some(new),
                    });
                }
            }
            (Some(new), None) => changes.push(RowChange {
                key: new.key(),
                old: None,
                new: Some(new),
            }),
            (None, Some((old, revision))) => changes.push(RowChange {
                key: old.key(),
                old: Some((old, revision)),
                new: None,
            }),
            (None, None) => {}
        }
        Ok((changes, expires))
    }

    /// The RRSIG row of an owner over `sets`, keeping the signatures of `old` that can
    /// stay, and the earliest expiration in it.
    fn signatures(
        &self,
        name: &DnsName,
        sets: &[SignSet],
        old: Option<&RrSet>,
    ) -> ZoneResult<(Option<RrSet>, Option<u32>)> {
        if sets.is_empty() {
            return Ok((None, None));
        }
        let old_fields: Vec<(sign::SigFields, &Rdata)> = old
            .map(|row| {
                row.rdata
                    .iter()
                    .filter_map(|rdata| sign::fields(rdata).map(|fields| (fields, rdata)))
                    .collect()
            })
            .unwrap_or_default();
        let mut rdata = Vec::new();
        let mut ttl = u32::MAX;
        let mut expires = None;
        for set in sets {
            let mut signed = false;
            for key in self.keys.signers(set.rtype) {
                signed = true;
                let dirty = set.dirty || self.is_dirty(name, set.rtype);
                let kept = (!dirty)
                    .then(|| {
                        old_fields.iter().find(|(fields, sig)| {
                            sign::keeps(fields, key, name, set.rtype, set.ttl, &self.times)
                                && (!self.verify
                                    || sign::verifies(
                                        sig,
                                        key,
                                        &self.zone.name,
                                        name,
                                        set.rtype,
                                        &set.rdata,
                                    ))
                        })
                    })
                    .flatten();
                let sig = match kept {
                    Some((_, sig)) => (*sig).clone(),
                    None => sign::rrsig(
                        key,
                        &self.zone.name,
                        name,
                        set.rtype,
                        set.ttl,
                        &set.rdata,
                        &self.times,
                    )
                    .map_err(|error| failed(self.zone, error.0))?,
                };
                if let Some(fields) = sign::fields(&sig) {
                    expires = earlier(expires, Some(fields.expiration), self.times.now);
                }
                if !rdata.contains(&sig) {
                    rdata.push(sig);
                }
            }
            if !signed {
                return Err(failed(
                    self.zone,
                    format!("no active key signs {} RRsets", set.rtype),
                ));
            }
            ttl = ttl.min(set.ttl);
        }
        Ok((Some(self.row(name, Rtype::RRSIG, ttl, rdata)), expires))
    }

    /// Runs `jobs` on up to `threads` threads; the outputs in the order of the jobs.
    ///
    /// # Errors
    ///
    /// The first job's error.
    pub fn run_all(&self, jobs: Vec<OwnerJob>, threads: usize) -> ZoneResult<Vec<JobOutput>> {
        if jobs.len() < 64 || threads <= 1 {
            return jobs.into_iter().map(|job| self.run(job)).collect();
        }
        let per = jobs.len().div_ceil(threads);
        let mut parts: Vec<Vec<OwnerJob>> = Vec::new();
        let mut jobs = jobs.into_iter().peekable();
        while jobs.peek().is_some() {
            parts.push(jobs.by_ref().take(per).collect());
        }
        let results: Vec<ZoneResult<Vec<JobOutput>>> = std::thread::scope(|scope| {
            let handles: Vec<_> = parts
                .into_iter()
                .map(|part| {
                    scope.spawn(move || part.into_iter().map(|job| self.run(job)).collect())
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .unwrap_or_else(|_| Err(failed(self.zone, "a signing thread panicked")))
                })
                .collect()
        });
        let mut out = Vec::new();
        for result in results {
            out.extend(result?);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------------------
// Reading a scope

/// The rows of one owner name.
#[derive(Debug)]
pub struct Owner {
    /// The name.
    pub name: DnsName,
    /// Its rows with their revisions, by type.
    pub rows: Vec<(RrSet, Revision)>,
}

/// The rows of an owner split by who owns them.
#[derive(Debug, Default)]
pub struct Split {
    /// Data rows: another origin than `dnssec`, a type the signer does not own.
    pub data: Vec<(RrSet, Revision)>,
    /// The signer's rows.
    pub generated: Vec<(RrSet, Revision)>,
    /// Types of the signer written by another origin, which a zone signed online drops.
    pub stale: Vec<(RrSet, Revision)>,
}

impl Split {
    /// Splits the rows of an owner.
    pub fn of(rows: Vec<(RrSet, Revision)>) -> Self {
        let mut split = Self::default();
        for (row, revision) in rows {
            if row.origin == Origin::Dnssec {
                split.generated.push((row, revision));
            } else if is_generated(row.rtype) {
                split.stale.push((row, revision));
            } else {
                split.data.push((row, revision));
            }
        }
        split
    }

    /// Whether the owner holds data.
    pub fn has_data(&self) -> bool {
        !self.data.is_empty()
    }

    fn has(&self, rtype: Rtype) -> bool {
        self.data.iter().any(|(row, _)| row.rtype == rtype)
    }
}

/// The owners of a key range in key order (canonical order), read in pages.
pub struct OwnerScan<'v> {
    view: &'v dyn ReadView,
    range: KeyRange,
    reverse: bool,
    page: std::collections::VecDeque<(RrSet, Revision)>,
    cursor: Option<bytes::Bytes>,
    done: bool,
    page_size: usize,
}

impl<'v> OwnerScan<'v> {
    /// The owners of `range`, forward or backward.
    pub fn new(view: &'v dyn ReadView, range: KeyRange, reverse: bool, page_size: usize) -> Self {
        Self {
            view,
            range,
            reverse,
            page: std::collections::VecDeque::new(),
            cursor: None,
            done: false,
            page_size,
        }
    }

    fn fill(&mut self) -> ZoneResult<()> {
        if self.done || !self.page.is_empty() {
            return Ok(());
        }
        let mut range = self.range.clone();
        if let Some(cursor) = &self.cursor {
            range = if self.reverse {
                range.before(cursor.clone())
            } else {
                range.after(cursor.clone())
            };
        }
        let rows = self
            .view
            .scan(RRSETS.name(), range, self.page_size, self.reverse)?;
        if rows.len() < self.page_size {
            self.done = true;
        }
        for (key, versioned) in rows {
            self.cursor = Some(key);
            let row: RrSet = RRSETS.decode(&versioned.value)?;
            self.page.push_back((row, versioned.revision));
        }
        Ok(())
    }

    /// The next owner.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn next_owner(&mut self) -> ZoneResult<Option<Owner>> {
        self.fill()?;
        let Some(first) = self.page.pop_front() else {
            return Ok(None);
        };
        let name = first.0.name.clone();
        let mut rows = vec![first];
        loop {
            self.fill()?;
            match self.page.front() {
                Some((row, _)) if row.name == name => {
                    if let Some(row) = self.page.pop_front() {
                        rows.push(row);
                    }
                }
                _ => break,
            }
        }
        if self.reverse {
            rows.reverse();
        }
        Ok(Some(Owner { name, rows }))
    }
}

/// The key prefix of a zone scope.
fn scope_prefix(zone: &Zone, scope: &ScopeName) -> Vec<u8> {
    encode_key(&(zone.id, scope.clone())).to_vec()
}

/// The rows of a zone scope.
pub fn scope_range(zone: &Zone, scope: &ScopeName) -> KeyRange {
    KeyRange::prefix(scope_prefix(zone, scope))
}

/// The rows strictly below `name` in a zone scope.
pub fn subtree_range(zone: &Zone, scope: &ScopeName, name: &DnsName) -> KeyRange {
    let mut prefix = scope_prefix(zone, scope);
    prefix.extend_from_slice(&name.subtree_prefix());
    KeyRange::prefix(prefix)
}

/// The first key after every row of `name`.
fn after_name(zone: &Zone, scope: &ScopeName, name: &DnsName) -> Vec<u8> {
    encode_key(&(zone.id, scope.clone(), name.clone(), Rtype(u16::MAX))).to_vec()
}

/// The first key of the rows of `name`.
fn name_start(zone: &Zone, scope: &ScopeName, name: &DnsName) -> Vec<u8> {
    encode_key(&(zone.id, scope.clone(), name.clone())).to_vec()
}

/// The rows of one owner.
///
/// # Errors
///
/// The store's error.
pub fn rows_of(
    view: &dyn ReadView,
    zone: &Zone,
    scope: &ScopeName,
    name: &DnsName,
) -> ZoneResult<Vec<(RrSet, Revision)>> {
    crate::zone::node(view, zone.id, scope, name)
}

// ---------------------------------------------------------------------------------------
// Chain membership

/// Answers what the chain needs to know about names of one scope from a read view, with
/// the cuts it found remembered.
pub struct Reader<'v> {
    view: &'v dyn ReadView,
    zone: &'v Zone,
    scope: &'v ScopeName,
    guards: HashMap<DnsName, bool>,
}

impl<'v> Reader<'v> {
    /// A reader of a scope.
    pub fn new(view: &'v dyn ReadView, zone: &'v Zone, scope: &'v ScopeName) -> Self {
        Self {
            view,
            zone,
            scope,
            guards: HashMap::new(),
        }
    }

    /// Whether `name` holds a cut (NS below the apex) or a DNAME, which hide the names
    /// below it.
    fn guards(&mut self, name: &DnsName) -> ZoneResult<bool> {
        if let Some(known) = self.guards.get(name) {
            return Ok(*known);
        }
        let get = |rtype: Rtype| {
            self.view.get_typed(
                &RRSETS,
                &RrSetKey {
                    zone: self.zone.id,
                    scope: self.scope.clone(),
                    name: name.clone(),
                    rtype,
                },
            )
        };
        let cut = name != &self.zone.name && get(Rtype::NS)?.is_some();
        let guard = cut || get(Rtype::DNAME)?.is_some();
        self.guards.insert(name.clone(), guard);
        Ok(guard)
    }

    /// Whether `name` lies below a cut or a DNAME of the zone.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn occluded(&mut self, name: &DnsName) -> ZoneResult<bool> {
        let mut current = name.parent();
        while let Some(ancestor) = current {
            if !ancestor.is_subdomain_of(&self.zone.name) {
                break;
            }
            if self.guards(&ancestor)? {
                return Ok(true);
            }
            if ancestor == self.zone.name {
                break;
            }
            current = ancestor.parent();
        }
        Ok(false)
    }

    /// Whether `name` with these rows is in the chain.
    fn in_chain(&mut self, name: &DnsName, split: &Split) -> ZoneResult<bool> {
        Ok(split.has_data() && !self.occluded(name)?)
    }

    /// The next owner in the chain after `name`, the apex when none follows.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn next_in_chain(&mut self, name: &DnsName) -> ZoneResult<DnsName> {
        let range =
            scope_range(self.zone, self.scope).after(after_name(self.zone, self.scope, name));
        let mut scan = OwnerScan::new(self.view, range, false, 64);
        while let Some(owner) = scan.next_owner()? {
            let split = Split::of(owner.rows);
            if self.in_chain(&owner.name, &split)? {
                return Ok(owner.name);
            }
        }
        Ok(self.zone.name.clone())
    }

    /// The owner in the chain before `name` (the apex at least).
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn prev_in_chain(&mut self, name: &DnsName) -> ZoneResult<DnsName> {
        let range =
            scope_range(self.zone, self.scope).before(name_start(self.zone, self.scope, name));
        let mut scan = OwnerScan::new(self.view, range, true, 64);
        while let Some(owner) = scan.next_owner()? {
            let split = Split::of(owner.rows);
            if self.in_chain(&owner.name, &split)? {
                return Ok(owner.name);
            }
        }
        Ok(self.zone.name.clone())
    }

    /// Whether a name without data is an empty non-terminal of the chain: not hidden, with
    /// a chain owner below it.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn is_empty_non_terminal(&mut self, name: &DnsName) -> ZoneResult<bool> {
        if self.occluded(name)? || self.guards(name)? {
            return Ok(false);
        }
        let mut scan = OwnerScan::new(
            self.view,
            subtree_range(self.zone, self.scope, name),
            false,
            64,
        );
        while let Some(owner) = scan.next_owner()? {
            let split = Split::of(owner.rows);
            if self.in_chain(&owner.name, &split)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// The types an NSEC or NSEC3 record lists for a chain owner, the RRSIG and NSEC bits
/// included as the denial needs them.
pub fn chain_types(
    pass: &Pass<'_>,
    name: &DnsName,
    split: &Split,
    apex_rows: &[RrSet],
) -> Vec<Rtype> {
    let apex = name == &pass.zone.name;
    let cut = !apex && split.has(Rtype::NS);
    let mut types: Vec<Rtype> = split
        .data
        .iter()
        .map(|(row, _)| row.rtype)
        .filter(|rtype| !cut || matches!(*rtype, Rtype::NS | Rtype::DS))
        .collect();
    if apex {
        types.extend(apex_rows.iter().map(|row| row.rtype));
    }
    let signed = !cut || split.has(Rtype::DS);
    if pass.nsec3_zone() {
        if signed {
            types.push(Rtype::RRSIG);
        }
    } else {
        types.push(Rtype::RRSIG);
        types.push(Rtype::NSEC);
    }
    types.sort_unstable();
    types.dedup();
    types
}

/// The data RRsets a chain owner signs: every one, or the DS alone at a cut.
pub fn data_sets(pass: &Pass<'_>, name: &DnsName, split: &Split) -> Vec<SignSet> {
    let apex = name == &pass.zone.name;
    let cut = !apex && split.has(Rtype::NS);
    split
        .data
        .iter()
        .filter(|(row, _)| !cut || row.rtype == Rtype::DS)
        .map(|(row, _)| SignSet::of(row, false))
        .collect()
}

/// A job that only clears an owner: its generated and stale rows go.
fn clearing(name: DnsName, split: Split) -> Option<OwnerJob> {
    (!split.generated.is_empty() || !split.stale.is_empty()).then(|| OwnerJob {
        name: Some(name),
        data: Vec::new(),
        desired: Vec::new(),
        existing: split.generated,
        stale: split.stale,
    })
}

// ---------------------------------------------------------------------------------------
// Full passes

/// Where a full pass leaves a scope: the row changes still to write, the apex, and the
/// earliest expiration seen.
#[derive(Debug, Default)]
pub struct ScopeOutcome {
    /// Row changes not yet written.
    pub pending: Vec<RowChange>,
    /// Row changes written in chunks already.
    pub flushed: usize,
    /// The NSEC next name of the apex (NSEC zones).
    pub apex_next: Option<DnsName>,
    /// The earliest expiration of the signatures outside the apex.
    pub expires: Option<u32>,
    /// The hashes of the NSEC3 chain (NSEC3 zones), for the next incremental pass.
    pub hashes: Option<BTreeSet<[u8; HASH_LEN]>>,
}

/// Limits of a full pass.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Owners signed together.
    pub owners: usize,
    /// Row changes per written chunk.
    pub rows: usize,
    /// Signing threads.
    pub threads: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            owners: 4_096,
            rows: 4_000,
            threads: std::thread::available_parallelism().map_or(1, std::num::NonZero::get),
        }
    }
}

/// A sink for chunks of row changes written while a full pass runs.
pub type Flush<'f> = dyn FnMut(Vec<RowChange>) -> ZoneResult<()> + 'f;

struct Collector<'p, 'f> {
    pass: &'p Pass<'p>,
    limits: Limits,
    jobs: Vec<OwnerJob>,
    outcome: ScopeOutcome,
    flush: &'f mut Flush<'f>,
}

impl Collector<'_, '_> {
    fn push(&mut self, job: OwnerJob) -> ZoneResult<()> {
        self.jobs.push(job);
        if self.jobs.len() >= self.limits.owners {
            self.drain()?;
        }
        Ok(())
    }

    fn drain(&mut self) -> ZoneResult<()> {
        let jobs = std::mem::take(&mut self.jobs);
        for (changes, expires) in self.pass.run_all(jobs, self.limits.threads)? {
            self.outcome.pending.extend(changes);
            self.outcome.expires = earlier(self.outcome.expires, expires, self.pass.times.now);
        }
        if self.outcome.pending.len() >= self.limits.rows {
            let chunk = std::mem::take(&mut self.outcome.pending);
            self.outcome.flushed += chunk.len();
            (self.flush)(chunk)?;
        }
        Ok(())
    }
}

/// A chain owner waiting for the name of the next one.
struct Waiting {
    name: DnsName,
    split: Split,
}

/// The full pass of a scope with NSEC or NSEC3: every owner except the apex, whose rows
/// [`apex_job`] makes at the end. Chunks of changes go to `flush` while it runs.
///
/// # Errors
///
/// A store error or `dns.dnssec.signing_failed`.
#[allow(
    clippy::too_many_lines,
    reason = "one stream over the scope builds both chains"
)]
pub fn full<'f>(
    pass: &Pass<'_>,
    view: &dyn ReadView,
    limits: Limits,
    flush: &'f mut Flush<'f>,
) -> ZoneResult<ScopeOutcome> {
    let apex_rows = pass.apex_rows();
    let mut collector = Collector {
        pass,
        limits,
        jobs: Vec::new(),
        outcome: ScopeOutcome::default(),
        flush,
    };
    let nsec3 = pass.nsec3_zone();
    let apex = &pass.zone.name;
    let mut scan = OwnerScan::new(view, scope_range(pass.zone, pass.scope), false, 4_096);
    let mut guard: Option<DnsName> = None;
    let mut waiting: Option<Waiting> = None;
    // NSEC3: the types of each hashed chain name, and the hashed owners present.
    let mut hashes: HashMap<[u8; HASH_LEN], Vec<Rtype>> = HashMap::new();
    while let Some(owner) = scan.next_owner()? {
        let name = owner.name;
        let split = Split::of(owner.rows);
        if &name == apex {
            if nsec3 {
                hashes.insert(pass.hash(apex), chain_types(pass, apex, &split, &apex_rows));
            } else {
                waiting = Some(Waiting { name, split });
            }
            continue;
        }
        if nsec3
            && !split.has_data()
            && split.stale.is_empty()
            && chain::hash_of_owner(&name, apex).is_some()
            && split
                .generated
                .iter()
                .all(|(row, _)| matches!(row.rtype, Rtype::NSEC3 | Rtype::RRSIG))
        {
            // A hashed owner: phase two meets it in hash order.
            continue;
        }
        if guard
            .as_ref()
            .is_some_and(|guard| !name.is_subdomain_of(guard))
        {
            guard = None;
        }
        let occluded = guard.is_some();
        if occluded || !split.has_data() {
            if let Some(job) = clearing(name, split) {
                collector.push(job)?;
            }
            continue;
        }
        if split.has(Rtype::NS) || split.has(Rtype::DNAME) {
            guard = Some(name.clone());
        }
        if nsec3 {
            hashes.insert(pass.hash(&name), chain_types(pass, &name, &split, &[]));
            // The empty non-terminals between the name and the apex.
            let mut current = name.parent();
            while let Some(ancestor) = current {
                if &ancestor == apex || !ancestor.is_subdomain_of(apex) {
                    break;
                }
                let hash = pass.hash(&ancestor);
                if hashes.contains_key(&hash) {
                    break;
                }
                hashes.insert(hash, Vec::new());
                current = ancestor.parent();
            }
            collector.push(OwnerJob {
                data: data_sets(pass, &name, &split),
                name: Some(name),
                desired: Vec::new(),
                existing: split.generated,
                stale: split.stale,
            })?;
        } else {
            if let Some(previous) = waiting.take() {
                finish_nsec(&mut collector, previous, &name, &apex_rows)?;
            }
            waiting = Some(Waiting { name, split });
        }
    }
    if let Some(previous) = waiting.take() {
        finish_nsec(&mut collector, previous, apex, &apex_rows)?;
    }
    if nsec3 {
        let mut order: Vec<[u8; HASH_LEN]> = hashes.keys().copied().collect();
        order.sort_unstable();
        // The hashed owners the zone holds come in hash order from one scan of the apex's
        // children, merged with the chain: no read per owner.
        let mut stored = HashedOwners::new(view, pass.zone, pass.scope);
        for (index, hash) in order.iter().enumerate() {
            let next = order[(index + 1) % order.len()];
            let types = hashes.get(hash).cloned().unwrap_or_default();
            let row = pass.nsec3(hash, &next, types);
            let mut existing = Split::default();
            while let Some((found, split)) = stored.next_before_or_at(hash)? {
                if &found == hash {
                    existing = split;
                } else if let Some(job) = clearing(chain::hashed_owner(&found, apex), split) {
                    collector.push(job)?;
                }
            }
            collector.push(OwnerJob {
                name: Some(row.name.clone()),
                data: Vec::new(),
                desired: vec![row],
                existing: existing.generated,
                stale: existing.stale,
            })?;
        }
        while let Some((found, split)) = stored.next_before_or_at(&[0xff; HASH_LEN])? {
            if let Some(job) = clearing(chain::hashed_owner(&found, apex), split) {
                collector.push(job)?;
            }
        }
        collector.outcome.hashes = Some(order.into_iter().collect());
    }
    collector.drain()?;
    Ok(collector.outcome)
}

/// The hashed owners of a scope in hash order, read in one scan of the apex's children
/// (whose canonical order is the order of the base32hex labels, which is hash order).
struct HashedOwners<'v> {
    scan: OwnerScan<'v>,
    apex: DnsName,
    peeked: Option<([u8; HASH_LEN], Split)>,
    done: bool,
}

impl<'v> HashedOwners<'v> {
    fn new(view: &'v dyn ReadView, zone: &Zone, scope: &ScopeName) -> Self {
        Self {
            scan: OwnerScan::new(view, subtree_range(zone, scope, &zone.name), false, 4_096),
            apex: zone.name.clone(),
            peeked: None,
            done: false,
        }
    }

    /// The next hashed owner with only the signer's rows, if its hash is at most `bound`.
    fn next_before_or_at(
        &mut self,
        bound: &[u8; HASH_LEN],
    ) -> ZoneResult<Option<([u8; HASH_LEN], Split)>> {
        if self.peeked.is_none() && !self.done {
            self.peeked = self.read()?;
            self.done = self.peeked.is_none();
        }
        match &self.peeked {
            Some((hash, _)) if hash <= bound => Ok(self.peeked.take()),
            _ => Ok(None),
        }
    }

    fn read(&mut self) -> ZoneResult<Option<([u8; HASH_LEN], Split)>> {
        while let Some(owner) = self.scan.next_owner()? {
            let Some(hash) = chain::hash_of_owner(&owner.name, &self.apex) else {
                continue;
            };
            let split = Split::of(owner.rows);
            if split.has_data() {
                continue;
            }
            return Ok(Some((hash, split)));
        }
        Ok(None)
    }
}

/// The NSEC job of a waiting owner once its next owner is known; the apex waits for the
/// end of the pass.
fn finish_nsec(
    collector: &mut Collector<'_, '_>,
    waiting: Waiting,
    next: &DnsName,
    apex_rows: &[RrSet],
) -> ZoneResult<()> {
    let pass = collector.pass;
    if waiting.name == pass.zone.name {
        collector.outcome.apex_next = Some(next.clone());
        return Ok(());
    }
    let types = chain_types(pass, &waiting.name, &waiting.split, apex_rows);
    let nsec = pass.nsec(&waiting.name, next, types);
    collector.push(OwnerJob {
        data: data_sets(pass, &waiting.name, &waiting.split),
        name: Some(waiting.name),
        desired: vec![nsec],
        existing: waiting.split.generated,
        stale: waiting.split.stale,
    })
}

/// The job of the apex with its rows as read and `soa` in place of the stored SOA (the
/// next serial's, or the stored one to find out whether anything else changes).
pub fn apex_job(
    pass: &Pass<'_>,
    rows: Vec<(RrSet, Revision)>,
    soa: &RrSet,
    soa_dirty: bool,
    apex_next: Option<&DnsName>,
) -> OwnerJob {
    let apex = &pass.zone.name;
    let split = Split::of(rows);
    let apex_rows = pass.apex_rows();
    let mut desired = apex_rows.clone();
    if !pass.nsec3_zone() {
        let next = apex_next.cloned().unwrap_or_else(|| apex.clone());
        desired.push(pass.nsec(apex, &next, chain_types(pass, apex, &split, &apex_rows)));
    }
    let data = split
        .data
        .iter()
        .map(|(row, _)| {
            if row.rtype == Rtype::SOA {
                SignSet::of(soa, soa_dirty)
            } else {
                SignSet::of(row, false)
            }
        })
        .collect();
    OwnerJob {
        name: Some(apex.clone()),
        data,
        desired,
        existing: split.generated,
        stale: split.stale,
    }
}

// ---------------------------------------------------------------------------------------
// Incremental passes

/// The incremental pass of a scope from the changed RRsets: the jobs of every affected
/// owner except the apex, the NSEC next name of the apex, and the NSEC3 chain after it.
/// `hashes` is the NSEC3 chain of the last pass (updated in place); `None` for an NSEC3
/// zone means it is unknown and a full pass is needed.
///
/// # Errors
///
/// A store error, `dns.dnssec.signing_failed`, or [`Incremental::NeedsFull`] when the
/// chain is unknown.
#[allow(
    clippy::too_many_lines,
    reason = "the NSEC and NSEC3 cases of one pass"
)]
pub fn incremental(
    pass: &Pass<'_>,
    view: &dyn ReadView,
    changed: &BTreeSet<DnsName>,
    hashes: Option<&mut BTreeSet<[u8; HASH_LEN]>>,
) -> Result<ScopeOutcome, Incremental> {
    let apex = &pass.zone.name;
    let mut reader = Reader::new(view, pass.zone, pass.scope);
    // The changed owners, with the names below a changed cut or DNAME.
    let mut owners: BTreeSet<DnsName> = BTreeSet::new();
    for name in changed {
        owners.insert(name.clone());
        let guard = pass
            .dirty
            .iter()
            .any(|(owner, rtype)| owner == name && matches!(*rtype, Rtype::NS | Rtype::DNAME));
        if guard && name != apex {
            let mut scan = OwnerScan::new(
                view,
                subtree_range(pass.zone, pass.scope, name),
                false,
                1_024,
            );
            while let Some(owner) = scan.next_owner()? {
                owners.insert(owner.name);
            }
        }
    }
    let mut jobs = Vec::new();
    let mut outcome = ScopeOutcome::default();
    if pass.nsec3_zone() {
        let Some(hashes) = hashes else {
            return Err(Incremental::NeedsFull);
        };
        // The names whose NSEC3 may change: the owners and their ancestors.
        let mut names: BTreeSet<DnsName> = BTreeSet::new();
        for name in &owners {
            let mut current = Some(name.clone());
            while let Some(candidate) = current {
                if !candidate.is_subdomain_of(apex) {
                    break;
                }
                let stop = &candidate == apex;
                current = candidate.parent();
                names.insert(candidate);
                if stop {
                    break;
                }
            }
        }
        let mut types: BTreeMap<[u8; HASH_LEN], Vec<Rtype>> = BTreeMap::new();
        let mut touched: BTreeSet<[u8; HASH_LEN]> = BTreeSet::new();
        let apex_rows = pass.apex_rows();
        for name in &names {
            let split = Split::of(rows_of(view, pass.zone, pass.scope, name)?);
            let hash = pass.hash(name);
            touched.insert(hash);
            if name == apex {
                types.insert(hash, chain_types(pass, name, &split, &apex_rows));
                hashes.insert(hash);
                continue;
            }
            if reader.in_chain(name, &split)? {
                types.insert(hash, chain_types(pass, name, &split, &[]));
                hashes.insert(hash);
                jobs.push(OwnerJob {
                    data: data_sets(pass, name, &split),
                    name: Some(name.clone()),
                    desired: Vec::new(),
                    existing: split.generated,
                    stale: split.stale,
                });
            } else {
                if !split.has_data() && reader.is_empty_non_terminal(name)? {
                    types.insert(hash, Vec::new());
                    hashes.insert(hash);
                } else {
                    hashes.remove(&hash);
                }
                if let Some(job) = clearing(name.clone(), split) {
                    jobs.push(job);
                }
            }
        }
        // The hashed owners to rewrite: the touched ones and the one before each.
        let mut rewrite: BTreeSet<[u8; HASH_LEN]> = BTreeSet::new();
        for hash in &touched {
            if hashes.contains(hash) {
                rewrite.insert(*hash);
            }
            if let Some(previous) = before(hashes, hash) {
                rewrite.insert(previous);
            }
        }
        for hash in &touched {
            if !hashes.contains(hash) {
                let owner = chain::hashed_owner(hash, apex);
                if let Some(job) = clearing(
                    owner.clone(),
                    Split::of(rows_of(view, pass.zone, pass.scope, &owner)?),
                ) {
                    jobs.push(job);
                }
            }
        }
        for hash in rewrite {
            let owner = chain::hashed_owner(&hash, apex);
            let existing = Split::of(rows_of(view, pass.zone, pass.scope, &owner)?);
            let listed = match types.get(&hash) {
                Some(listed) => listed.clone(),
                None => existing
                    .generated
                    .iter()
                    .find(|(row, _)| row.rtype == Rtype::NSEC3)
                    .and_then(|(row, _)| row.records().ok())
                    .and_then(|records| records.into_iter().next())
                    .and_then(|data| match data {
                        RecordData::Nsec3 { types, .. } => Some(types),
                        _ => None,
                    })
                    .ok_or(Incremental::NeedsFull)?,
            };
            let next = after(hashes, &hash).unwrap_or(hash);
            jobs.push(OwnerJob {
                name: Some(owner),
                data: Vec::new(),
                desired: vec![pass.nsec3(&hash, &next, listed)],
                existing: existing.generated,
                stale: existing.stale,
            });
        }
    } else {
        // NSEC: the owners and the chain owner before each.
        let mut affected: BTreeSet<DnsName> = owners.clone();
        for name in &owners {
            if name != apex {
                affected.insert(reader.prev_in_chain(name)?);
            }
        }
        let apex_rows = pass.apex_rows();
        for name in affected {
            if &name == apex {
                continue;
            }
            let split = Split::of(rows_of(view, pass.zone, pass.scope, &name)?);
            if reader.in_chain(&name, &split)? {
                let next = reader.next_in_chain(&name)?;
                let nsec = pass.nsec(&name, &next, chain_types(pass, &name, &split, &apex_rows));
                jobs.push(OwnerJob {
                    data: data_sets(pass, &name, &split),
                    name: Some(name),
                    desired: vec![nsec],
                    existing: split.generated,
                    stale: split.stale,
                });
            } else if let Some(job) = clearing(name, split) {
                jobs.push(job);
            }
        }
        outcome.apex_next = Some(reader.next_in_chain(apex)?);
    }
    for (changes, expires) in pass.run_all(jobs, Limits::default().threads)? {
        outcome.pending.extend(changes);
        outcome.expires = earlier(outcome.expires, expires, pass.times.now);
    }
    Ok(outcome)
}

/// Why an incremental pass did not finish.
#[derive(Debug)]
pub enum Incremental {
    /// The NSEC3 chain is not known: run a full pass.
    NeedsFull,
    /// The pass failed.
    Failed(ZoneError),
}

impl From<ZoneError> for Incremental {
    fn from(error: ZoneError) -> Self {
        Self::Failed(error)
    }
}

/// The hash before `hash` in the chain, wrapping around.
fn before(hashes: &BTreeSet<[u8; HASH_LEN]>, hash: &[u8; HASH_LEN]) -> Option<[u8; HASH_LEN]> {
    hashes
        .range(..*hash)
        .next_back()
        .or_else(|| hashes.iter().next_back())
        .copied()
        .filter(|previous| previous != hash)
}

/// The hash after `hash` in the chain, wrapping around.
fn after(hashes: &BTreeSet<[u8; HASH_LEN]>, hash: &[u8; HASH_LEN]) -> Option<[u8; HASH_LEN]> {
    use std::ops::Bound::{Excluded, Unbounded};
    hashes
        .range((Excluded(*hash), Unbounded))
        .next()
        .or_else(|| hashes.iter().next())
        .copied()
}

/// The NSEC3 chain of a scope as the store holds it: the hashes of its NSEC3 owners.
///
/// # Errors
///
/// The store's error.
pub fn stored_hashes(
    view: &dyn ReadView,
    zone: &Zone,
    scope: &ScopeName,
) -> ZoneResult<BTreeSet<[u8; HASH_LEN]>> {
    let mut hashes = BTreeSet::new();
    let mut scan = OwnerScan::new(view, subtree_range(zone, scope, &zone.name), false, 4_096);
    while let Some(owner) = scan.next_owner()? {
        if owner
            .rows
            .iter()
            .any(|(row, _)| row.rtype == Rtype::NSEC3 && row.origin == Origin::Dnssec)
            && let Some(hash) = chain::hash_of_owner(&owner.name, &zone.name)
        {
            hashes.insert(hash);
        }
    }
    Ok(hashes)
}

/// Every row of the signer in a scope, for removal.
///
/// # Errors
///
/// The store's error.
pub fn generated_rows(
    view: &dyn ReadView,
    zone: &Zone,
    scope: &ScopeName,
) -> ZoneResult<Vec<(RrSet, Revision)>> {
    let mut out = Vec::new();
    let mut scan = OwnerScan::new(view, scope_range(zone, scope), false, 4_096);
    while let Some(owner) = scan.next_owner()? {
        out.extend(
            owner
                .rows
                .into_iter()
                .filter(|(row, _)| row.origin == Origin::Dnssec),
        );
    }
    Ok(out)
}

/// The earliest expiration of the RRSIG records of a scope written by another origin (an
/// imported signed zone), and the largest TTL of the scope's RRsets.
///
/// # Errors
///
/// The store's error.
pub fn scan_signatures(
    view: &dyn ReadView,
    zone: &Zone,
    scope: &ScopeName,
    origin_dnssec: bool,
    now: u32,
) -> ZoneResult<(Option<u32>, u32)> {
    let mut expires = None;
    let mut max_ttl = 0;
    let mut scan = OwnerScan::new(view, scope_range(zone, scope), false, 4_096);
    while let Some(owner) = scan.next_owner()? {
        for (row, _) in &owner.rows {
            max_ttl = max_ttl.max(row.ttl);
            if row.rtype != Rtype::RRSIG || (row.origin == Origin::Dnssec) != origin_dnssec {
                continue;
            }
            for rdata in &row.rdata {
                if let Some(fields) = sign::fields(rdata) {
                    expires = earlier(expires, Some(fields.expiration), now);
                }
            }
        }
    }
    Ok((expires, max_ttl))
}

/// Shares a key set between threads.
pub type SharedKeys = Arc<KeySet>;
