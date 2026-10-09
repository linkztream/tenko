//! Deterministic synthetic record generator for the load benchmarks.
//!
//! The data set is a single forward zone (`example.test`, [`ZONE_FORWARD`]) holding one A
//! RRset per host, plus a configurable share of PTR RRsets spread over three reverse zones.
//! Every record is a pure function of `(GenConfig, index)`, so any record can be regenerated
//! on demand without storing the data set, and two runs with the same configuration produce
//! byte-identical keys and values.
//!
//! # Index layout
//!
//! With `F = forward_records` and `P = ptr_records()` the index space is `0..F + P`:
//!
//! * `0..F`: the A RRset of host `n = i`. Owner `host-{n}`, relative to `example.test`.
//! * `F..F + P`: PTR number `j = i - F`, which belongs to host `h = j * 100 / ptr_percent`
//!   (128-bit intermediate). For `ptr_percent` in `1..=100` the mapping is strictly
//!   increasing, so every host gets at most one PTR, and `h < F`.
//!
//! # Addressing
//!
//! Hosts are spread over the three RFC 5737 documentation networks. For host `n`:
//!
//! * range `r = n % 3` selects `192.0.2.0/24`, `198.51.100.0/24` or `203.0.113.0/24`;
//! * last octet `o = 1 + (n / 3) % 254`, never `.0` and never `.255`.
//!
//! RFC 5737 only provides 768 addresses, so the A rdata repeats for large data sets. That is
//! intended: the benchmark needs millions of distinct owner names, not distinct addresses.
//!
//! # Reverse owner names
//!
//! The PTR record of host `h` lives in the reverse zone of its range (`r = h % 3`, zones
//! [`ZONE_REV_192_0_2`], [`ZONE_REV_198_51_100`], [`ZONE_REV_203_0_113`]). A real reverse zone
//! would use just the octet as owner, which would collide as soon as more than 768 hosts exist.
//! To keep the PTR keys unique the owner is an RFC 2317-style sub-label name,
//! `{o}.{block}` with `block = h / 762` (762 = 3 * 254 hosts per block). Within one reverse
//! zone the pair `(o, block)` is unique per host, so the owner is unique too, while the
//! zone/owner/rtype key shape stays the same as for real data.
//!
//! # Per-host variation
//!
//! TTL (one of 300, 600, 900, 3600), creation and modification time, record source (about 90 %
//! IPAM, 7 % DDNS, 3 % manual) and the management comment fields come from a splitmix64 hash
//! of `(seed, host)`. The A and the PTR record of one host therefore share TTL, timestamps and
//! source. The comment text is tuned so that the average encoded entry (key plus postcard
//! value) is about 150 bytes, which is checked by the unit tests.
//!
//! # Cost
//!
//! [`encoded_batch`] reuses one scratch record and one stack buffer for the whole batch, so the
//! only heap allocations per record are the two output vectors. [`key_at`] never builds the
//! value.

// Not every item is used by every binary that includes this file.
#![allow(dead_code)]

use crate::model::*;

/// 2026-01-01T00:00:00Z, the earliest creation time.
const BASE_UNIX: u64 = 1_767_225_600;
/// Creation times are spread over 180 days.
const CREATED_SPAN: u64 = 180 * 86_400;
/// Modification happens within 30 days after creation.
const MODIFIED_SPAN: u64 = 30 * 86_400;
const TTLS: [u32; 4] = [300, 600, 900, 3600];
/// First three octets of the three RFC 5737 networks.
const NET_PREFIX: [[u8; 3]; 3] = [[192, 0, 2], [198, 51, 100], [203, 0, 113]];
const REV_ZONES: [u32; 3] = [ZONE_REV_192_0_2, ZONE_REV_198_51_100, ZONE_REV_203_0_113];
/// Usable host addresses per /24 (`.1` to `.254`).
const ADDRS_PER_RANGE: u64 = 254;
/// Hosts per reverse block: all three ranges, 254 addresses each.
const HOSTS_PER_BLOCK: u64 = 3 * ADDRS_PER_RANGE;
const ROLES: [&str; 12] = [
    "web", "db", "app", "dns", "mail", "cache", "lb", "ntp", "ldap", "proxy", "backup", "monitor",
];
const ENVS: [&str; 4] = ["prod", "stage", "dev", "lab"];
/// Wire form of the fixed suffix `.example.test.` (labels `example` and `test`, root).
const WIRE_SUFFIX: &[u8] = b"\x07example\x04test\x00";
/// Upper bound for one encoded value; the longest value is about 220 bytes.
const ENC_BUF: usize = 512;
const COMMENT_MAX: usize = 256;

/// Parameters of a synthetic data set.
#[derive(Clone, Copy, Debug)]
pub struct GenConfig {
    /// Number of A RRsets in the single forward zone `example.test` (ZONE_FORWARD).
    pub forward_records: u64,
    /// PTR RRsets generated per 100 hosts (0..=100).
    pub ptr_percent: u8,
    /// Seed for deterministic pseudo-random variation (TTL, timestamps, comment fields).
    pub seed: u64,
}

impl GenConfig {
    /// `forward_records * ptr_percent / 100` (integer division, 128-bit intermediate so the
    /// multiplication cannot overflow). Values of `ptr_percent` above 100 are treated as 100.
    pub fn ptr_records(&self) -> u64 {
        (self.forward_records as u128 * self.percent() as u128 / 100) as u64
    }

    /// `forward_records + ptr_records()`.
    pub fn total_records(&self) -> u64 {
        self.forward_records + self.ptr_records()
    }

    fn percent(&self) -> u8 {
        self.ptr_percent.min(100)
    }

    /// Host a given PTR number belongs to: `j * 100 / ptr_percent`.
    fn ptr_host(&self, j: u64) -> u64 {
        (j as u128 * 100 / self.percent().max(1) as u128) as u64
    }
}

// ---------------------------------------------------------------------------------------------
// Small helpers: hashing and allocation-free text building
// ---------------------------------------------------------------------------------------------

/// splitmix64 output function applied to `x + golden gamma`.
fn mix(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A fixed-capacity byte buffer on the stack. Used to assemble owner names, comments and wire
/// names without touching the heap. Input beyond the capacity is dropped; all text pushed here
/// is ASCII and far below the capacities in use.
struct StackBuf<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> StackBuf<N> {
    fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        let n = bytes.len().min(N - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
    }

    fn push_str(&mut self, s: &str) {
        self.push_bytes(s.as_bytes());
    }

    fn push_byte(&mut self, b: u8) {
        self.push_bytes(&[b]);
    }

    /// Append `v` in decimal, left-padded with zeros to at least `min_width` digits.
    fn push_dec(&mut self, v: u64, min_width: usize) {
        let mut tmp = [b'0'; 20];
        let mut pos = 20;
        let mut x = v;
        while x > 0 {
            pos -= 1;
            tmp[pos] = b'0' + (x % 10) as u8;
            x /= 10;
        }
        let width = (20 - pos).max(min_width).clamp(1, 20);
        self.push_bytes(&tmp[20 - width..]);
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(self.as_bytes()).unwrap_or("")
    }
}

// ---------------------------------------------------------------------------------------------
// Per-index derivation
// ---------------------------------------------------------------------------------------------

/// Address range (0..3) and last octet (1..=254) of host `n`.
fn host_addr(n: u64) -> (usize, u8) {
    ((n % 3) as usize, 1 + ((n / 3) % ADDRS_PER_RANGE) as u8)
}

/// Everything that determines the key of record `i`.
struct KeyParts {
    zone_id: u32,
    rtype: u16,
    owner: StackBuf<32>,
    host: u64,
    ptr: bool,
}

/// Key parts of record `i`. Panics if `i` is out of range.
fn key_parts(cfg: &GenConfig, i: u64) -> KeyParts {
    let total = cfg.total_records();
    assert!(i < total, "record index {i} out of range 0..{total}");
    let mut owner = StackBuf::new();
    if i < cfg.forward_records {
        owner.push_str("host-");
        owner.push_dec(i, 0);
        KeyParts {
            zone_id: ZONE_FORWARD,
            rtype: RTYPE_A,
            owner,
            host: i,
            ptr: false,
        }
    } else {
        let h = cfg.ptr_host(i - cfg.forward_records);
        let (range, octet) = host_addr(h);
        owner.push_dec(octet as u64, 0);
        owner.push_byte(b'.');
        owner.push_dec(h / HOSTS_PER_BLOCK, 0);
        KeyParts {
            zone_id: REV_ZONES[range],
            rtype: RTYPE_PTR,
            owner,
            host: h,
            ptr: true,
        }
    }
}

/// Hash-derived attributes of one host.
struct HostInfo {
    ttl: u32,
    created: u64,
    modified: u64,
    source: u8,
    site: u64,
    rack: u64,
    team: u64,
    vlan: u64,
    role: &'static str,
    env: &'static str,
}

fn host_info(seed: u64, host: u64) -> HostInfo {
    let h0 = mix(seed.wrapping_add(mix(host)));
    let h1 = mix(h0);
    let h2 = mix(h1);
    let h3 = mix(h2);
    let created = BASE_UNIX + (h0 >> 2) % CREATED_SPAN;
    let source = match h2 % 100 {
        0..=89 => SOURCE_IPAM,
        90..=96 => SOURCE_DDNS,
        _ => SOURCE_MANUAL,
    };
    HostInfo {
        ttl: TTLS[(h0 & 3) as usize],
        created,
        modified: created + h1 % MODIFIED_SPAN,
        source,
        site: h3 % 24,
        rack: (h3 >> 8) % 400,
        team: (h3 >> 20) % 64,
        vlan: 100 + (h3 >> 28) % 900,
        role: ROLES[((h3 >> 40) % ROLES.len() as u64) as usize],
        env: ENVS[((h3 >> 52) & 3) as usize],
    }
}

/// Management comment in the style of an IPAM export. The PTR variant is shorter because its
/// rdata (a full domain name) and key already weigh more than an A record's.
fn write_comment(
    out: &mut StackBuf<COMMENT_MAX>,
    host: u64,
    ptr: bool,
    range: usize,
    info: &HostInfo,
) {
    out.push_str(match info.source {
        SOURCE_IPAM => "ipam",
        SOURCE_DDNS => "ddns",
        _ => "manual",
    });
    out.push_str(" subnet=");
    let net = NET_PREFIX[range];
    out.push_dec(net[0] as u64, 0);
    out.push_byte(b'.');
    out.push_dec(net[1] as u64, 0);
    out.push_byte(b'.');
    out.push_dec(net[2] as u64, 0);
    out.push_str(".0/24 site=dc");
    out.push_dec(info.site, 2);
    out.push_str(" rack=r");
    out.push_dec(info.rack, 3);
    out.push_str(" owner=team-");
    out.push_dec(info.team, 3);
    out.push_str(" env=");
    out.push_str(info.env);
    if ptr {
        out.push_str(" asset=AS");
        out.push_dec(host, 10);
    } else {
        out.push_str(" role=");
        out.push_str(info.role);
        out.push_str(" vlan=");
        out.push_dec(info.vlan, 4);
        out.push_str(" asset=AS");
        out.push_dec(host, 10);
    }
}

/// A reusable record under construction. `fill` overwrites every field, keeping the existing
/// heap buffers, so repeated use needs no allocation.
struct Scratch {
    owner: String,
    rrset: StoredRRset,
}

impl Scratch {
    fn new() -> Self {
        Self {
            owner: String::new(),
            rrset: StoredRRset {
                ttl: 0,
                rdata: vec![Vec::new()],
                meta: RecordMeta {
                    created_unix: 0,
                    modified_unix: 0,
                    source: SOURCE_IPAM,
                    ipam_ref: 0,
                    comment: String::new(),
                },
            },
        }
    }

    /// Build record `i` into `self`; returns its `(zone_id, rtype)`.
    fn fill(&mut self, cfg: &GenConfig, i: u64) -> (u32, u16) {
        let k = key_parts(cfg, i);
        let info = host_info(cfg.seed, k.host);
        let (range, octet) = host_addr(k.host);

        self.owner.clear();
        self.owner.push_str(k.owner.as_str());

        let rrset = &mut self.rrset;
        rrset.ttl = info.ttl;
        rrset.meta.created_unix = info.created;
        rrset.meta.modified_unix = info.modified;
        rrset.meta.source = info.source;
        rrset.meta.ipam_ref = 1_000_000 + k.host;

        let rdata = &mut rrset.rdata[0];
        rdata.clear();
        if k.ptr {
            // host-{h}.example.test in DNS wire format, assembled on the stack and copied once.
            let mut label = StackBuf::<32>::new();
            label.push_str("host-");
            label.push_dec(k.host, 0);
            let mut wire = StackBuf::<64>::new();
            wire.push_byte(label.as_bytes().len() as u8);
            wire.push_bytes(label.as_bytes());
            wire.push_bytes(WIRE_SUFFIX);
            rdata.extend_from_slice(wire.as_bytes());
        } else {
            let net = NET_PREFIX[range];
            rdata.extend_from_slice(&[net[0], net[1], net[2], octet]);
        }

        let mut comment = StackBuf::<COMMENT_MAX>::new();
        write_comment(&mut comment, k.host, k.ptr, range, &info);
        rrset.meta.comment.clear();
        rrset.meta.comment.push_str(comment.as_str());

        (k.zone_id, k.rtype)
    }
}

/// postcard-encode `v` through a stack buffer, then copy into an exactly sized vector. Falls
/// back to the heap encoder if the value does not fit the buffer.
fn encode_via(v: &StoredRRset, buf: &mut [u8]) -> Vec<u8> {
    match postcard::to_slice(v, buf) {
        Ok(used) => used.to_vec(),
        Err(_) => encode_value(v),
    }
}

// ---------------------------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------------------------

/// The i-th record of the data set, for i in 0..cfg.total_records(). Panics if out of range.
pub fn record_at(cfg: &GenConfig, i: u64) -> Record {
    let mut s = Scratch::new();
    let (zone_id, rtype) = s.fill(cfg, i);
    Record {
        zone_id,
        owner: s.owner,
        rtype,
        rrset: s.rrset,
    }
}

/// Encoded key of record i, identical to `record_at(cfg, i).encoded().0`, but without building
/// the value (cheap). Panics if out of range.
pub fn key_at(cfg: &GenConfig, i: u64) -> Vec<u8> {
    let k = key_parts(cfg, i);
    encode_key(k.zone_id, k.owner.as_str(), k.rtype)
}

/// Encoded (key, value) pairs for records start..start+len (clamped to total_records()).
pub fn encoded_batch(cfg: &GenConfig, start: u64, len: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    let total = cfg.total_records();
    if start >= total || len == 0 {
        return Vec::new();
    }
    let end = start.saturating_add(len as u64).min(total);
    let mut out = Vec::with_capacity((end - start) as usize);
    let mut scratch = Scratch::new();
    let mut buf = [0u8; ENC_BUF];
    for i in start..end {
        let (zone_id, rtype) = scratch.fill(cfg, i);
        let key = encode_key(zone_id, &scratch.owner, rtype);
        let value = encode_via(&scratch.rrset, &mut buf);
        out.push((key, value));
    }
    out
}

/// Iterator over consecutive batches of `batch` records (last batch may be shorter), in index
/// order. A `batch` of 0 is treated as 1.
pub fn batches(cfg: GenConfig, batch: usize) -> Batches {
    Batches {
        cfg,
        next: 0,
        total: cfg.total_records(),
        batch: batch.max(1) as u64,
    }
}

/// Iterator returned by [`batches`].
pub struct Batches {
    cfg: GenConfig,
    next: u64,
    total: u64,
    batch: u64,
}

impl Iterator for Batches {
    type Item = Vec<Record>;

    fn next(&mut self) -> Option<Vec<Record>> {
        if self.next >= self.total {
            return None;
        }
        let end = self.next.saturating_add(self.batch).min(self.total);
        let records = (self.next..end).map(|i| record_at(&self.cfg, i)).collect();
        self.next = end;
        Some(records)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = (self.total - self.next.min(self.total)).div_ceil(self.batch) as usize;
        (n, Some(n))
    }
}

/// A modified version of record i for steady-state update tests: same key as
/// `record_at(cfg, i)`, but a different value whenever `seq >= 1`.
///
/// For `seq >= 1`: the TTL moves 1 to 3 steps along the TTL list (never back to the original),
/// `meta.modified_unix = created_unix + seq`, `meta.source = SOURCE_DDNS`, and for A records
/// the last octet moves by 1 to 253 positions within the same /24 (never back to the original);
/// PTR rdata is unchanged. `seq == 0` returns the original record. Deterministic in
/// `(cfg, i, seq)`.
pub fn updated_record(cfg: &GenConfig, i: u64, seq: u64) -> Record {
    let mut r = record_at(cfg, i);
    if seq == 0 {
        return r;
    }
    let idx = TTLS.iter().position(|&t| t == r.rrset.ttl).unwrap_or(0);
    r.rrset.ttl = TTLS[(idx + 1 + ((seq - 1) % 3) as usize) % TTLS.len()];
    r.rrset.meta.modified_unix = r.rrset.meta.created_unix.saturating_add(seq);
    r.rrset.meta.source = SOURCE_DDNS;
    if r.rtype == RTYPE_A
        && let Some(last) = r.rrset.rdata.first_mut().and_then(|a| a.last_mut())
    {
        let shift = 1 + (seq - 1) % (ADDRS_PER_RANGE - 1);
        *last = 1 + ((*last as u64 - 1 + shift) % ADDRS_PER_RANGE) as u8;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::time::Instant;

    fn cfg(forward_records: u64, ptr_percent: u8) -> GenConfig {
        GenConfig {
            forward_records,
            ptr_percent,
            seed: 42,
        }
    }

    fn entry_size(r: &Record) -> usize {
        let (k, v) = r.encoded();
        k.len() + v.len()
    }

    /// Average encoded entry size over indexes `from..to` taking every `stride`-th record.
    fn avg_entry(cfg: &GenConfig, from: u64, to: u64, stride: u64) -> f64 {
        let (mut sum, mut n) = (0u64, 0u64);
        let mut i = from;
        while i < to {
            sum += entry_size(&record_at(cfg, i)) as u64;
            n += 1;
            i += stride;
        }
        sum as f64 / n as f64
    }

    /// A sample of indexes touching both ranges and the boundaries.
    fn sample_indexes(c: &GenConfig) -> Vec<u64> {
        let total = c.total_records();
        let f = c.forward_records;
        let mut v = vec![0, 1, 2, 3, f - 1, f, f + 1, total - 1, total / 2];
        let mut i = 5;
        while i < total {
            v.push(i);
            i += 997;
        }
        v
    }

    #[test]
    fn config_counts() {
        let c = cfg(1_000, 20);
        assert_eq!(c.ptr_records(), 200);
        assert_eq!(c.total_records(), 1_200);
        assert_eq!(cfg(999, 33).ptr_records(), 329);
        assert_eq!(cfg(1_000, 0).ptr_records(), 0);
        assert_eq!(cfg(1_000, 100).ptr_records(), 1_000);
        // No overflow with a huge forward count.
        let big = cfg(u64::MAX / 2, 100);
        assert_eq!(big.ptr_records(), u64::MAX / 2);
    }

    #[test]
    fn deterministic() {
        let c = cfg(10_000, 20);
        for i in [0u64, 1, 77, 9_999, 10_000, 10_001, 11_999] {
            assert_eq!(record_at(&c, i), record_at(&c, i));
            assert_eq!(record_at(&c, i).encoded(), record_at(&c, i).encoded());
        }
        let other = GenConfig { seed: 43, ..c };
        assert_ne!(record_at(&c, 5).rrset.meta, record_at(&other, 5).rrset.meta);
    }

    #[test]
    fn keys_unique() {
        let c = cfg(300_000, 20);
        let total = c.total_records();
        let mut seen = HashSet::with_capacity(total as usize);
        for i in 0..total {
            assert!(seen.insert(key_at(&c, i)), "duplicate key at index {i}");
        }
        assert_eq!(seen.len() as u64, total);
    }

    #[test]
    fn keys_unique_full_ptr_and_odd_percent() {
        for (f, p) in [(50_000u64, 100u8), (50_000, 1), (50_000, 33), (50_000, 99)] {
            let c = cfg(f, p);
            let total = c.total_records();
            let mut seen = HashSet::with_capacity(total as usize);
            for i in 0..total {
                assert!(
                    seen.insert(key_at(&c, i)),
                    "duplicate key at {i} for percent {p}"
                );
            }
        }
    }

    #[test]
    fn key_at_matches_record() {
        let c = cfg(50_000, 20);
        for i in sample_indexes(&c) {
            let r = record_at(&c, i);
            let key = key_at(&c, i);
            assert_eq!(key, r.encoded().0, "index {i}");
            assert_eq!(
                decode_key(&key),
                Some((r.zone_id, r.owner.as_str(), r.rtype)),
                "index {i}"
            );
        }
    }

    #[test]
    fn addressing_and_naming() {
        let c = cfg(5_000, 100);
        let f = c.forward_records;
        for n in [0u64, 1, 2, 3, 4, 761, 762, 763, 2_000, 4_999] {
            let r = record_at(&c, n);
            assert_eq!(r.zone_id, ZONE_FORWARD);
            assert_eq!(r.rtype, RTYPE_A);
            assert_eq!(r.owner, format!("host-{n}"));
            let net = [[192u8, 0, 2], [198, 51, 100], [203, 0, 113]][(n % 3) as usize];
            let o = 1 + ((n / 3) % 254) as u8;
            assert_eq!(r.rrset.rdata, vec![vec![net[0], net[1], net[2], o]]);
            assert!((1..=254).contains(&o));

            // ptr_percent 100: PTR number j belongs to host j.
            let p = record_at(&c, f + n);
            let zone =
                [ZONE_REV_192_0_2, ZONE_REV_198_51_100, ZONE_REV_203_0_113][(n % 3) as usize];
            assert_eq!(p.zone_id, zone);
            assert_eq!(p.rtype, RTYPE_PTR);
            assert_eq!(p.owner, format!("{o}.{}", n / 762));
            assert_eq!(
                p.rrset.rdata,
                vec![name_to_wire(&format!("host-{n}.example.test"))]
            );
            assert_eq!(p.rrset.meta.ipam_ref, 1_000_000 + n);
            assert_eq!(r.rrset.meta.ipam_ref, 1_000_000 + n);
            assert_eq!(p.rrset.ttl, r.rrset.ttl);
        }
        // Partial PTR share: PTR number j maps to host j * 100 / percent.
        let c = cfg(1_000, 20);
        for j in [0u64, 1, 2, 199] {
            let h = j * 100 / 20;
            let p = record_at(&c, 1_000 + j);
            assert_eq!(
                p.rrset.rdata,
                vec![name_to_wire(&format!("host-{h}.example.test"))]
            );
        }
    }

    #[test]
    fn metadata_distribution() {
        let c = cfg(100_000, 0);
        let (mut ipam, mut ddns, mut manual) = (0u32, 0u32, 0u32);
        let mut ttls = [0u32; 4];
        for i in 0..c.forward_records {
            let r = record_at(&c, i);
            let m = &r.rrset.meta;
            match m.source {
                SOURCE_IPAM => ipam += 1,
                SOURCE_DDNS => ddns += 1,
                SOURCE_MANUAL => manual += 1,
                s => panic!("unexpected source {s}"),
            }
            ttls[TTLS
                .iter()
                .position(|&t| t == r.rrset.ttl)
                .expect("ttl in set")] += 1;
            assert!(m.created_unix >= BASE_UNIX && m.created_unix < BASE_UNIX + CREATED_SPAN);
            assert!(
                m.modified_unix >= m.created_unix
                    && m.modified_unix < m.created_unix + MODIFIED_SPAN
            );
            assert!(m.comment.is_ascii());
        }
        let pct = |x: u32| x as f64 * 100.0 / 100_000.0;
        println!(
            "source mix: ipam {:.1}%  ddns {:.1}%  manual {:.1}%  ttl buckets {ttls:?}",
            pct(ipam),
            pct(ddns),
            pct(manual)
        );
        assert!((88.0..92.0).contains(&pct(ipam)));
        assert!((5.5..8.5).contains(&pct(ddns)));
        assert!((2.0..4.0).contains(&pct(manual)));
        assert!(ttls.iter().all(|&n| n > 20_000));
    }

    #[test]
    fn average_entry_size() {
        let f = 1_000_000;
        let a = cfg(f, 0);
        let avg_a = avg_entry(&a, 0, f, 7);
        let p = cfg(f, 100);
        let avg_p = avg_entry(&p, f, 2 * f, 7);
        let m = cfg(f, 20);
        let avg_m = avg_entry(&m, 0, m.total_records(), 7);
        println!(
            "avg encoded entry (key+value), 1M hosts: A only {avg_a:.1} B, PTR only {avg_p:.1} B, mix(20%) {avg_m:.1} B"
        );
        for (name, v) in [("A", avg_a), ("PTR", avg_p), ("mix", avg_m)] {
            assert!(
                (130.0..=180.0).contains(&v),
                "{name} average {v:.1} outside 130..=180"
            );
        }

        // The target must also hold for other data set sizes (owner names and ids grow with n).
        for f in [1_000u64, 100_000, 10_000_000, 100_000_000, 1_000_000_000] {
            let a = cfg(f, 0);
            let p = cfg(f, 100);
            let m = cfg(f, 20);
            let (xa, xp, xm) = (
                avg_entry(&a, 0, f, f / 5_000 + 1),
                avg_entry(&p, f, 2 * f, f / 5_000 + 1),
                avg_entry(&m, 0, m.total_records(), m.total_records() / 5_000 + 1),
            );
            println!(
                "avg encoded entry, {f} hosts: A {xa:.1} B, PTR {xp:.1} B, mix(20%) {xm:.1} B"
            );
            for (name, v) in [("A", xa), ("PTR", xp), ("mix", xm)] {
                assert!(
                    (130.0..=180.0).contains(&v),
                    "{name} average {v:.1} outside 130..=180 at {f}"
                );
            }
        }
    }

    #[test]
    fn batches_cover_everything_in_order() {
        let c = cfg(1_000, 20);
        let total = c.total_records();
        assert_eq!(total, 1_200);
        let it = batches(c, 128);
        assert_eq!(it.size_hint(), (10, Some(10)));
        let all: Vec<Vec<Record>> = it.collect();
        let sizes: Vec<usize> = all.iter().map(Vec::len).collect();
        assert_eq!(sizes, vec![128, 128, 128, 128, 128, 128, 128, 128, 128, 48]);
        let flat: Vec<&Record> = all.iter().flatten().collect();
        assert_eq!(flat.len() as u64, total);
        for (i, r) in flat.iter().enumerate() {
            assert_eq!(**r, record_at(&c, i as u64));
        }
        // Exact multiple, batch larger than the data set, and batch of 0.
        assert_eq!(
            batches(cfg(100, 0), 25)
                .map(|b| b.len())
                .collect::<Vec<_>>(),
            vec![25; 4]
        );
        assert_eq!(
            batches(cfg(100, 0), 1_000)
                .map(|b| b.len())
                .collect::<Vec<_>>(),
            vec![100]
        );
        assert_eq!(batches(cfg(10, 0), 0).count(), 10);
        assert_eq!(batches(cfg(0, 50), 10).count(), 0);
    }

    #[test]
    fn encoded_batch_matches_and_clamps() {
        let c = cfg(1_000, 20);
        let total = c.total_records();
        for (start, len) in [(0u64, 50usize), (990, 30), (total - 5, 100), (500, 1)] {
            let b = encoded_batch(&c, start, len);
            let end = (start + len as u64).min(total);
            assert_eq!(b.len() as u64, end - start);
            for (off, kv) in b.iter().enumerate() {
                assert_eq!(*kv, record_at(&c, start + off as u64).encoded());
                assert_eq!(kv.0, key_at(&c, start + off as u64));
            }
        }
        assert_eq!(encoded_batch(&c, total - 5, 100).len(), 5);
        assert!(encoded_batch(&c, total, 10).is_empty());
        assert!(encoded_batch(&c, total + 1_000, 10).is_empty());
        assert!(encoded_batch(&c, 0, 0).is_empty());
        // Values decode back to the generated record.
        let r = record_at(&c, 1_100);
        let (_, v) = &encoded_batch(&c, 1_100, 1)[0];
        assert_eq!(decode_value(v).expect("decode"), r.rrset);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn record_at_out_of_range_panics() {
        let c = cfg(10, 0);
        let _ = record_at(&c, 10);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn key_at_out_of_range_panics() {
        let c = cfg(10, 50);
        let _ = key_at(&c, 15);
    }

    #[test]
    fn updated_records() {
        let c = cfg(50_000, 20);
        for i in sample_indexes(&c) {
            let base = record_at(&c, i);
            let base_enc = base.encoded();
            assert_eq!(updated_record(&c, i, 0), base);
            for seq in [
                1u64,
                2,
                3,
                4,
                5,
                253,
                254,
                255,
                256,
                762,
                1_000,
                u64::MAX / 2,
            ] {
                let u = updated_record(&c, i, seq);
                assert_eq!(u, updated_record(&c, i, seq), "deterministic");
                let enc = u.encoded();
                assert_eq!(enc.0, base_enc.0, "same key (i {i}, seq {seq})");
                assert_ne!(enc.1, base_enc.1, "different value (i {i}, seq {seq})");
                assert_eq!(
                    (u.zone_id, &u.owner, u.rtype),
                    (base.zone_id, &base.owner, base.rtype)
                );
                assert_ne!(u.rrset.ttl, base.rrset.ttl);
                assert!(TTLS.contains(&u.rrset.ttl));
                assert_eq!(u.rrset.meta.source, SOURCE_DDNS);
                assert_eq!(u.rrset.meta.created_unix, base.rrset.meta.created_unix);
                assert_eq!(
                    u.rrset.meta.modified_unix,
                    base.rrset.meta.created_unix + seq
                );
                assert_eq!(u.rrset.meta.ipam_ref, base.rrset.meta.ipam_ref);
                if base.rtype == RTYPE_A {
                    let (a, b) = (&base.rrset.rdata[0], &u.rrset.rdata[0]);
                    assert_eq!(a[..3], b[..3], "same /24");
                    assert_ne!(a[3], b[3]);
                    assert!((1..=254).contains(&b[3]));
                } else {
                    assert_eq!(u.rrset.rdata, base.rrset.rdata);
                }
            }
        }
    }

    #[test]
    fn timing_one_million() {
        // 800k A + 200k PTR = exactly 1M records.
        let c = cfg(800_000, 25);
        assert_eq!(c.total_records(), 1_000_000);

        let t = Instant::now();
        let mut bytes = 0usize;
        let mut count = 0usize;
        let mut start = 0;
        while start < c.total_records() {
            let b = encoded_batch(&c, start, 50_000);
            for (k, v) in &b {
                bytes += k.len() + v.len();
            }
            count += b.len();
            start += 50_000;
        }
        let enc = t.elapsed();
        assert_eq!(count, 1_000_000);
        println!(
            "encoded_batch: {count} records in {:.3} s = {:.0} ns/record, {:.1} B/entry, {:.1} MB total",
            enc.as_secs_f64(),
            enc.as_nanos() as f64 / count as f64,
            bytes as f64 / count as f64,
            bytes as f64 / 1e6
        );

        let t = Instant::now();
        let mut keys = 0usize;
        for i in 0..c.total_records() {
            keys += key_at(&c, i).len();
        }
        let kt = t.elapsed();
        println!(
            "key_at:        1000000 keys in {:.3} s = {:.0} ns/key ({keys} key bytes)",
            kt.as_secs_f64(),
            kt.as_nanos() as f64 / 1e6
        );

        let t = Instant::now();
        let mut sink = 0usize;
        for i in 0..c.total_records() {
            sink += record_at(&c, i).owner.len();
        }
        let rt = t.elapsed();
        println!(
            "record_at:     1000000 records in {:.3} s = {:.0} ns/record ({sink})",
            rt.as_secs_f64(),
            rt.as_nanos() as f64 / 1e6
        );
    }
}
