//! The offline breach corpus: a binary fuse filter over SHA-1 prefixes (IAM-04, TGL-06).
//!
//! The corpus of the Have I Been Pwned "Pwned Passwords" list has close to a billion SHA-1
//! hashes. Storing them exactly takes tens of gigabytes; a binary fuse filter with 16-bit
//! fingerprints answers "is this hash in the corpus?" from about 18 bits per key (roughly
//! 2.3 GB for a billion keys), never misses a member and reports a non-member as present with
//! probability about 1 in 65,536. That is the right trade for a breach check: a false
//! positive asks one user in 65,536 to pick another password, a false negative cannot happen.
//!
//! # Credit
//!
//! The data structure and the construction are the binary fuse filter of Thomas Mueller Graf
//! and Daniel Lemire, "Binary Fuse Filters: Fast and Smaller Than Xor Filters", ACM Journal of
//! Experimental Algorithmics 27 (2022). This module is an independent implementation in safe
//! Rust of the 3-wise variant from the published algorithm: the segment length follows from the
//! key count, the table is sized by a factor that shrinks towards 1.125 as the key count grows,
//! keys are peeled onto a stack and the fingerprints are assigned in reverse peeling order so
//! that the exclusive or of three table entries reproduces each key's fingerprint. A failed
//! peeling (a stuck core, which is rare for large key sets and common enough for tiny ones)
//! retries with the next seed of a fixed, deterministic seed sequence, so equal input gives a
//! byte-identical file.
//!
//! # Keys
//!
//! A key is the first 8 bytes of the SHA-1 of the normalized password as a big-endian `u64`;
//! with the hexadecimal form of the downloader that is the first 16 characters of each line.
//! SHA-1 output is already uniform, so this prefix needs no further mixing beyond the seeded
//! finalizer the filter applies for the retry logic. Two different hashes that share a prefix
//! collapse into one key (the chance is about `n^2 / 2^65`, a few percent for a billion keys
//! and without consequence: both stay members).
//!
//! # File format, version 1
//!
//! All integers are little-endian. The file is a header of 88 bytes followed by the
//! fingerprint array.
//!
//! | Offset | Size | Field | Value |
//! |---:|---:|---|---|
//! | 0 | 8 | magic | `b"TKHIBPF1"` |
//! | 8 | 2 | version | `u16`, 1 |
//! | 10 | 1 | fingerprint bits | `u8`, 16 |
//! | 11 | 1 | key kind | `u8`, 1 = SHA-1 prefix (first 8 bytes, big-endian `u64`) |
//! | 12 | 4 | reserved | `u32`, 0 |
//! | 16 | 8 | seed | `u64` |
//! | 24 | 4 | `segment_length` | `u32`, a power of two, at most 262,144 |
//! | 28 | 4 | `segment_length_mask` | `u32`, `segment_length - 1` |
//! | 32 | 4 | `segment_count_length` | `u32`, `segment_count * segment_length` |
//! | 36 | 4 | `array_length` | `u32`, `segment_count_length + 2 * segment_length` |
//! | 40 | 8 | `key_count` | `u64`, distinct keys stored |
//! | 48 | 8 | `min_count` | `u64`, lines with a smaller count were left out |
//! | 56 | 32 | checksum | SHA-256 of the fingerprint array (its bytes as stored) |
//! | 88 | 2 * `array_length` | fingerprints | `array_length` times `u16` |
//!
//! The file length must be exactly `88 + 2 * array_length`. An empty key set is valid; the
//! array is then all zero and every lookup answers "not present".
//!
//! # Lookup
//!
//! With `key` the key, `L = segment_length` and `m = segment_length_mask`:
//!
//! ```text
//! hash = fmix64(key + seed)                       (wrapping; fmix64 is the MurmurHash3 finalizer)
//! fp   = low 16 bits of (hash ^ (hash >> 32))
//! h0   = high 64 bits of (hash * segment_count_length)
//! h1   = (h0 + L)     ^ ((hash >> 18) & m)
//! h2   = (h0 + 2 * L) ^ (hash & m)
//! present  <=>  fp ^ array[h0] ^ array[h1] ^ array[h2] == 0
//! ```
//!
//! The three positions lie in three consecutive segments, so they are always distinct and
//! below `array_length`. A lookup in a file reads exactly three 2-byte fingerprints.
//!
//! # Build memory
//!
//! [`build_filter`] keeps all keys and its working tables in memory: about 8 bytes per key for
//! the key list and about 24 bytes per key for the tables, so roughly 32 bytes per key. The
//! `min_count` option shrinks that by dropping the long tail of rarely seen passwords.

use std::fs::File;
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use aws_lc_rs::digest::{Context, SHA256};
use zeroize::Zeroizing;

const MAGIC: [u8; 8] = *b"TKHIBPF1";
const VERSION: u16 = 1;
const FINGERPRINT_BITS: u8 = 16;
const KEY_KIND_SHA1_PREFIX: u8 = 1;
const HEADER_LEN: usize = 88;
const MAX_SEGMENT_LENGTH: u32 = 1 << 18;
/// Upper bound on the seeds tried before the construction gives up.
const MAX_ATTEMPTS: u32 = 100;
/// Start of the deterministic seed sequence (the ASCII bytes of `tenko_hi`).
const SEED_STREAM_START: u64 = 0x7465_6e6b_6f5f_6869;
/// Longest accepted input line: 40 hexadecimal characters, a colon, up to 20 digits, a line
/// ending, and some slack.
const MAX_LINE_LEN: u64 = 128;
/// Chunk size for checksum computation over a file.
const CHECKSUM_CHUNK: usize = 1 << 20;
/// Fingerprints per write when serializing.
const WRITE_CHUNK: usize = 1 << 13;

/// What can go wrong building, opening or reading a filter.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FilterError {
    /// Reading, writing or seeking failed.
    #[error("filter I/O error: {0}")]
    Io(String),
    /// The file is not a valid filter of this format version.
    #[error("invalid filter file: {0}")]
    Format(&'static str),
    /// A line of the build input is malformed.
    #[error("malformed input at line {line}")]
    Input {
        /// The 1-based line number.
        line: u64,
    },
}

impl From<std::io::Error> for FilterError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

/// Options of [`build_filter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildOptions {
    /// Input lines with a count below this are left out of the filter. The downloader's
    /// counts are the number of times a password appeared in breaches; passwords seen once
    /// are the bulk of the corpus.
    pub min_count: u64,
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self { min_count: 1 }
    }
}

/// What [`build_filter`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildSummary {
    /// Distinct keys stored in the filter.
    pub keys: u64,
    /// Input lines left out because their count was below `min_count`.
    pub skipped: u64,
    /// Bytes written: the header and the fingerprint array.
    pub bytes: u64,
}

// ---------------------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------------------

/// The finalizer of `MurmurHash3` (64 bit): a bijection with good avalanche.
const fn fmix64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^= h >> 33;
    h
}

/// `SplitMix64`: the deterministic seed sequence of the construction.
const fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// The key of a SHA-1 digest: its first 8 bytes as a big-endian `u64`.
fn key_of_sha1(sha1: &[u8; 20]) -> u64 {
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&sha1[..8]);
    u64::from_be_bytes(prefix)
}

/// The fingerprint of a hashed key: 16 bits mixed from both halves of the hash.
fn fingerprint_of(hash: u64) -> u16 {
    u16::try_from((hash ^ (hash >> 32)) & 0xffff).unwrap_or_default()
}

/// Widening conversion for table indexes (the crate targets 64-bit platforms; on a 32-bit
/// target the table sizes are bounded by `u32` anyway).
#[allow(clippy::cast_possible_truncation)]
const fn index(value: u32) -> usize {
    value as usize
}

/// As [`index`] for a 64-bit value that is known to be a table index.
#[allow(clippy::cast_possible_truncation)]
const fn index64(value: u64) -> usize {
    value as usize
}

fn sha256_of_fingerprints(fingerprints: &[u16]) -> [u8; 32] {
    let mut context = Context::new(&SHA256);
    let mut chunk = Vec::with_capacity(WRITE_CHUNK * 2);
    for part in fingerprints.chunks(WRITE_CHUNK) {
        chunk.clear();
        for fingerprint in part {
            chunk.extend_from_slice(&fingerprint.to_le_bytes());
        }
        context.update(&chunk);
    }
    digest_to_array(context.finish().as_ref())
}

fn digest_to_array(bytes: &[u8]) -> [u8; 32] {
    <[u8; 32]>::try_from(bytes).unwrap_or_default()
}

// ---------------------------------------------------------------------------------------
// Table geometry
// ---------------------------------------------------------------------------------------

/// The shape of the fingerprint array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Layout {
    segment_length: u32,
    segment_length_mask: u32,
    segment_count_length: u32,
    array_length: u32,
}

impl Layout {
    /// The geometry for `size` keys: the segment length from the key count, the size factor
    /// that makes the table fit the key count, and the array of `segment_count + 2` segments.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    fn for_key_count(size: u64) -> Result<Self, FilterError> {
        const TOO_MANY: FilterError = FilterError::Format("too many keys for one filter");
        let size = u32::try_from(size).map_err(|_| TOO_MANY)?;
        let count = f64::from(size);

        // 2^floor(ln(n) / ln(3.33) + 2.25), at most 2^18; 4 for an empty set.
        let segment_length: u32 = if size == 0 {
            4
        } else {
            let exponent = (count.ln() / 3.33_f64.ln() + 2.25).floor().clamp(0.0, 18.0);
            1_u32 << (exponent as u32)
        };
        // max(1.125, 0.875 + 0.25 ln(10^6) / ln(n)); no slack for fewer than two keys.
        let capacity: u64 = if size <= 1 {
            0
        } else {
            let factor = (0.875 + 0.25 * 1_000_000_f64.ln() / count.ln()).max(1.125);
            (count * factor).round() as u64
        };
        let length = u64::from(segment_length);
        let segment_count = capacity.div_ceil(length).saturating_sub(2).max(1);
        let segment_count_length = u32::try_from(segment_count * length).map_err(|_| TOO_MANY)?;
        let array_length =
            u32::try_from(segment_count * length + 2 * length).map_err(|_| TOO_MANY)?;
        Ok(Self {
            segment_length,
            segment_length_mask: segment_length - 1,
            segment_count_length,
            array_length,
        })
    }

    fn segment_count(&self) -> u32 {
        self.segment_count_length / self.segment_length
    }

    /// The three table positions of a hashed key, one in each of three consecutive segments.
    fn positions(&self, hash: u64) -> [u32; 3] {
        let wide = u128::from(hash) * u128::from(self.segment_count_length);
        // The product is below 2^64 * segment_count_length, so the high half fits a u32.
        let h0 = u32::try_from(wide >> 64).unwrap_or_default();
        let mask = u64::from(self.segment_length_mask);
        let h1 =
            (h0 + self.segment_length) ^ u32::try_from((hash >> 18) & mask).unwrap_or_default();
        let h2 = (h0 + 2 * self.segment_length) ^ u32::try_from(hash & mask).unwrap_or_default();
        [h0, h1, h2]
    }
}

/// A layout together with a seed: enough to hash keys and locate their fingerprints.
#[derive(Debug, Clone, Copy)]
struct Params {
    seed: u64,
    layout: Layout,
}

impl Params {
    fn hash(&self, key: u64) -> u64 {
        fmix64(key.wrapping_add(self.seed))
    }
}

// ---------------------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------------------

/// Working tables of one construction; reused across seed attempts.
struct Builder<'a> {
    keys: &'a [u64],
    layout: Layout,
    /// Hashes ordered by their high bits, later reused as the peeling stack.
    order: Vec<u64>,
    /// For each stack entry, which of the three positions was the single-key slot.
    slot_of: Vec<u8>,
    /// Per table slot: key count in bits 2..8, exclusive or of position indexes in bits 0..2.
    counts: Vec<u8>,
    /// Per table slot: exclusive or of the hashes of the keys mapped to it.
    xors: Vec<u64>,
    /// Slots that held exactly one key when queued.
    queue: Vec<u32>,
    /// Bucket offsets for the counting sort by high hash bits.
    starts: Vec<usize>,
    block_shift: u32,
}

impl<'a> Builder<'a> {
    fn new(keys: &'a [u64], layout: Layout) -> Self {
        let slots = index(layout.array_length);
        let segments = index(layout.segment_count());
        let mut block_bits = 1_u32;
        while (1_usize << block_bits) < segments {
            block_bits += 1;
        }
        Self {
            keys,
            layout,
            order: vec![0; keys.len()],
            slot_of: vec![0; keys.len()],
            counts: vec![0; slots],
            xors: vec![0; slots],
            queue: vec![0; slots],
            starts: vec![0; (1_usize << block_bits) + 1],
            block_shift: 64 - block_bits,
        }
    }

    /// Hashes every key and orders the hashes by their high bits (a counting sort), which
    /// groups the keys that land in the same region of the table and keeps the insertion
    /// phase cache friendly for large key sets.
    fn scatter(&mut self, params: &Params) {
        self.starts.fill(0);
        for &key in self.keys {
            let bucket = index64(params.hash(key) >> self.block_shift);
            self.starts[bucket + 1] += 1;
        }
        for i in 1..self.starts.len() {
            self.starts[i] += self.starts[i - 1];
        }
        for &key in self.keys {
            let hash = params.hash(key);
            let bucket = index64(hash >> self.block_shift);
            self.order[self.starts[bucket]] = hash;
            self.starts[bucket] += 1;
        }
    }

    /// Adds every key to the three slots it maps to. `false` if a slot counter overflowed.
    fn insert(&mut self) -> bool {
        self.counts.fill(0);
        self.xors.fill(0);
        let mut ok = true;
        for &hash in &self.order {
            for (position, slot) in self.layout.positions(hash).into_iter().enumerate() {
                let slot = index(slot);
                // The position index (0, 1 or 2) is folded in by exclusive or; the low two
                // bits of a single-key slot then name the position of that slot.
                let tag = u8::try_from(position).unwrap_or_default();
                match self.counts[slot].checked_add(4) {
                    Some(count) => self.counts[slot] = count ^ tag,
                    None => ok = false,
                }
                self.xors[slot] ^= hash;
            }
        }
        ok
    }

    /// Peels keys off slots that hold exactly one key, pushing them onto the stack. `true`
    /// if every key was peeled.
    fn peel(&mut self) -> bool {
        let mut queued = 0_usize;
        for (slot, &count) in self.counts.iter().enumerate() {
            if count >> 2 == 1 {
                self.queue[queued] = u32::try_from(slot).unwrap_or_default();
                queued += 1;
            }
        }
        let mut stacked = 0_usize;
        while queued > 0 {
            queued -= 1;
            let slot = index(self.queue[queued]);
            // The slot may have lost its last key to another slot since it was queued.
            if self.counts[slot] >> 2 != 1 {
                continue;
            }
            let hash = self.xors[slot];
            let found = usize::from(self.counts[slot] & 3);
            let positions = self.layout.positions(hash);
            self.order[stacked] = hash;
            self.slot_of[stacked] = u8::try_from(found).unwrap_or_default();
            stacked += 1;
            for step in 1..=2 {
                let other = (found + step) % 3;
                let other_slot = index(positions[other]);
                let tag = u8::try_from(other).unwrap_or_default();
                self.counts[other_slot] = (self.counts[other_slot] - 4) ^ tag;
                self.xors[other_slot] ^= hash;
                if self.counts[other_slot] >> 2 == 1 {
                    self.queue[queued] = positions[other];
                    queued += 1;
                }
            }
        }
        stacked == self.keys.len()
    }

    /// Assigns the fingerprints in reverse peeling order: each key's single-key slot is set
    /// so that the exclusive or of its three slots equals its fingerprint.
    fn assign(&self) -> Vec<u16> {
        let mut table = vec![0_u16; index(self.layout.array_length)];
        for (&hash, &found) in self.order.iter().zip(&self.slot_of).rev() {
            let positions = self.layout.positions(hash);
            let found = usize::from(found);
            let first = index(positions[found]);
            let second = index(positions[(found + 1) % 3]);
            let third = index(positions[(found + 2) % 3]);
            table[first] = fingerprint_of(hash) ^ table[second] ^ table[third];
        }
        table
    }
}

/// Whether `key` passes the membership test against a complete `table`.
fn is_member(params: &Params, key: u64, table: &[u16]) -> bool {
    let hash = params.hash(key);
    let [h0, h1, h2] = params.layout.positions(hash);
    fingerprint_of(hash) ^ table[index(h0)] ^ table[index(h1)] ^ table[index(h2)] == 0
}

/// Builds the fingerprint array for sorted, distinct `keys`; returns the seed that worked.
fn construct(keys: &[u64], layout: Layout) -> Result<(u64, Vec<u16>), FilterError> {
    let mut builder = Builder::new(keys, layout);
    let mut stream = SEED_STREAM_START;
    for _ in 0..MAX_ATTEMPTS {
        let params = Params {
            seed: splitmix64(&mut stream),
            layout,
        };
        builder.scatter(&params);
        if builder.insert() && builder.peel() {
            let table = builder.assign();
            // A last, linear check that no key can be missed.
            if !keys.iter().all(|&key| is_member(&params, key, &table)) {
                return Err(FilterError::Format(
                    "constructed filter failed verification",
                ));
            }
            return Ok((params.seed, table));
        }
    }
    Err(FilterError::Format("filter construction did not converge"))
}

// ---------------------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Header {
    params: Params,
    key_count: u64,
    min_count: u64,
    checksum: [u8; 32],
}

impl Header {
    fn file_len(&self) -> u64 {
        HEADER_LEN as u64 + 2 * u64::from(self.params.layout.array_length)
    }

    fn encode(&self) -> Vec<u8> {
        let layout = &self.params.layout;
        let mut out = Vec::with_capacity(HEADER_LEN);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.push(FINGERPRINT_BITS);
        out.push(KEY_KIND_SHA1_PREFIX);
        out.extend_from_slice(&0_u32.to_le_bytes());
        out.extend_from_slice(&self.params.seed.to_le_bytes());
        out.extend_from_slice(&layout.segment_length.to_le_bytes());
        out.extend_from_slice(&layout.segment_length_mask.to_le_bytes());
        out.extend_from_slice(&layout.segment_count_length.to_le_bytes());
        out.extend_from_slice(&layout.array_length.to_le_bytes());
        out.extend_from_slice(&self.key_count.to_le_bytes());
        out.extend_from_slice(&self.min_count.to_le_bytes());
        out.extend_from_slice(&self.checksum);
        debug_assert_eq!(out.len(), HEADER_LEN);
        out
    }

    /// Parses and validates the header; the file length is checked by the caller.
    fn decode(bytes: &[u8]) -> Result<Self, FilterError> {
        let mut cursor = Cursor(bytes);
        if cursor.take::<8>()? != MAGIC {
            return Err(FilterError::Format("bad magic"));
        }
        if u16::from_le_bytes(cursor.take()?) != VERSION {
            return Err(FilterError::Format("unsupported version"));
        }
        if cursor.take::<1>()?[0] != FINGERPRINT_BITS {
            return Err(FilterError::Format("unsupported fingerprint size"));
        }
        if cursor.take::<1>()?[0] != KEY_KIND_SHA1_PREFIX {
            return Err(FilterError::Format("unsupported key kind"));
        }
        if u32::from_le_bytes(cursor.take()?) != 0 {
            return Err(FilterError::Format("reserved field is not zero"));
        }
        let seed = u64::from_le_bytes(cursor.take()?);
        let segment_length = u32::from_le_bytes(cursor.take()?);
        let segment_length_mask = u32::from_le_bytes(cursor.take()?);
        let segment_count_length = u32::from_le_bytes(cursor.take()?);
        let array_length = u32::from_le_bytes(cursor.take()?);
        let key_count = u64::from_le_bytes(cursor.take()?);
        let min_count = u64::from_le_bytes(cursor.take()?);
        let checksum = cursor.take::<32>()?;

        if !segment_length.is_power_of_two() || segment_length > MAX_SEGMENT_LENGTH {
            return Err(FilterError::Format("invalid segment length"));
        }
        if segment_length_mask != segment_length - 1 {
            return Err(FilterError::Format("invalid segment length mask"));
        }
        if segment_count_length == 0 || segment_count_length % segment_length != 0 {
            return Err(FilterError::Format("invalid segment count"));
        }
        if u64::from(array_length)
            != u64::from(segment_count_length) + 2 * u64::from(segment_length)
        {
            return Err(FilterError::Format("invalid array length"));
        }
        if key_count > u64::from(array_length) {
            return Err(FilterError::Format("key count exceeds the table size"));
        }
        Ok(Self {
            params: Params {
                seed,
                layout: Layout {
                    segment_length,
                    segment_length_mask,
                    segment_count_length,
                    array_length,
                },
            },
            key_count,
            min_count,
            checksum,
        })
    }
}

struct Cursor<'a>(&'a [u8]);

impl Cursor<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], FilterError> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(FilterError::Format("truncated header"))?;
        self.0 = rest;
        Ok(*head)
    }
}

// ---------------------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------------------

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Parses `SHA1HEX:COUNT` into the key (first 16 hexadecimal characters) and the count.
fn parse_line(line: &[u8]) -> Option<(u64, u64)> {
    if line.get(40) != Some(&b':') {
        return None;
    }
    let mut key = 0_u64;
    for (i, &byte) in line.iter().take(40).enumerate() {
        let value = hex_value(byte)?;
        if i < 16 {
            key = (key << 4) | u64::from(value);
        }
    }
    let digits = line.get(41..)?;
    if digits.is_empty() {
        return None;
    }
    let mut count = 0_u64;
    for &digit in digits {
        if !digit.is_ascii_digit() {
            return None;
        }
        count = count
            .checked_mul(10)?
            .checked_add(u64::from(digit - b'0'))?;
    }
    Some((key, count))
}

/// Builds a filter from the lines of the Pwned Passwords downloader and writes it to
/// `output` in the version 1 format described in the module documentation.
///
/// This is the library function behind `tenko hibp build`. Each input line is
/// `SHA1HEX:COUNT` (40 hexadecimal characters of either case, a colon, a decimal count) with
/// LF or CRLF line endings; blank lines are ignored. Lines whose count is below
/// [`BuildOptions::min_count`] are skipped. The keys are sorted and de-duplicated before the
/// construction, so the input order does not matter and the output is deterministic.
///
/// # Errors
///
/// [`FilterError::Input`] with the 1-based line number for a malformed line (also for lines
/// that would be skipped by `min_count`), [`FilterError::Io`] if reading the input or writing
/// the output fails, [`FilterError::Format`] if there are too many keys for one filter or the
/// construction does not converge, which is not expected for any input.
pub fn build_filter(
    mut input: impl BufRead,
    mut output: impl Write,
    options: &BuildOptions,
) -> Result<BuildSummary, FilterError> {
    let mut keys: Vec<u64> = Vec::new();
    let mut skipped = 0_u64;
    let mut line_number = 0_u64;
    let mut line = Vec::with_capacity(64);
    loop {
        line.clear();
        let read = (&mut input)
            .take(MAX_LINE_LEN)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        line_number += 1;
        let complete = line.last() == Some(&b'\n');
        if complete {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if !complete && read as u64 == MAX_LINE_LEN {
            // Cut off by the length limit: no valid line is this long.
            return Err(FilterError::Input { line: line_number });
        }
        if line.is_empty() {
            continue;
        }
        let (key, count) = parse_line(&line).ok_or(FilterError::Input { line: line_number })?;
        if count < options.min_count {
            skipped += 1;
        } else {
            keys.push(key);
        }
    }
    keys.sort_unstable();
    keys.dedup();

    let key_count = keys.len() as u64;
    let layout = Layout::for_key_count(key_count)?;
    let (seed, table) = construct(&keys, layout)?;
    drop(keys);

    let header = Header {
        params: Params { seed, layout },
        key_count,
        min_count: options.min_count,
        checksum: sha256_of_fingerprints(&table),
    };
    output.write_all(&header.encode())?;
    let mut chunk = Vec::with_capacity(WRITE_CHUNK * 2);
    for part in table.chunks(WRITE_CHUNK) {
        chunk.clear();
        for fingerprint in part {
            chunk.extend_from_slice(&fingerprint.to_le_bytes());
        }
        output.write_all(&chunk)?;
    }
    output.flush()?;
    Ok(BuildSummary {
        keys: key_count,
        skipped,
        bytes: header.file_len(),
    })
}

// ---------------------------------------------------------------------------------------
// The filter
// ---------------------------------------------------------------------------------------

enum Storage {
    /// The whole file, header included.
    Memory(Vec<u8>),
    /// A file read by seeking; lookups touch three fingerprints and nothing else.
    File(Mutex<File>),
}

/// An opened offline breach filter. Lookups never report a member as absent; a non-member is
/// reported as present with probability about 1 in 65,536.
///
/// Open it once and share it (`Arc<HibpFilter>`): [`open`](Self::open) reads only the header,
/// so a multi-gigabyte file costs no memory beyond the operating system's page cache.
pub struct HibpFilter {
    header: Header,
    storage: Storage,
}

impl std::fmt::Debug for HibpFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HibpFilter")
            .field("key_count", &self.header.key_count)
            .field("array_length", &self.header.params.layout.array_length)
            .field(
                "backing",
                &match self.storage {
                    Storage::Memory(_) => "memory",
                    Storage::File(_) => "file",
                },
            )
            .finish_non_exhaustive()
    }
}

impl HibpFilter {
    /// Opens a filter file. The header and the file length are validated; the fingerprint
    /// array is not read, lookups seek and read the three fingerprints they need.
    ///
    /// # Errors
    ///
    /// [`FilterError::Io`] if the file cannot be opened or read, [`FilterError::Format`] if
    /// it is not a valid version 1 filter (wrong magic, version, field values or length).
    pub fn open(path: &Path) -> Result<Self, FilterError> {
        let mut file = File::open(path)?;
        let length = file.metadata()?.len();
        if length < HEADER_LEN as u64 {
            return Err(FilterError::Format("file is shorter than the header"));
        }
        let mut head = [0_u8; HEADER_LEN];
        file.read_exact(&mut head)?;
        let header = Header::decode(&head)?;
        if length != header.file_len() {
            return Err(FilterError::Format("file length does not match the header"));
        }
        Ok(Self {
            header,
            storage: Storage::File(Mutex::new(file)),
        })
    }

    /// Reads a filter from bytes in memory, with the same validation as [`open`](Self::open).
    ///
    /// # Errors
    ///
    /// [`FilterError::Format`] if the bytes are not a valid version 1 filter.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, FilterError> {
        let header = Header::decode(&bytes)?;
        if bytes.len() as u64 != header.file_len() {
            return Err(FilterError::Format("file length does not match the header"));
        }
        Ok(Self {
            header,
            storage: Storage::Memory(bytes),
        })
    }

    /// Reads the whole fingerprint array and compares its SHA-256 with the header. `false`
    /// means the file was damaged after it was built. This reads the entire file, so it is
    /// for tooling (`tenko hibp verify`), not for the request path.
    ///
    /// # Errors
    ///
    /// [`FilterError::Io`] if the file cannot be read.
    pub fn verify_checksum(&self) -> Result<bool, FilterError> {
        let mut context = Context::new(&SHA256);
        match &self.storage {
            Storage::Memory(bytes) => {
                let array = bytes
                    .get(HEADER_LEN..)
                    .ok_or(FilterError::Format("file is shorter than the header"))?;
                context.update(array);
            }
            Storage::File(file) => {
                let mut file = file.lock().unwrap_or_else(PoisonError::into_inner);
                file.seek(SeekFrom::Start(HEADER_LEN as u64))?;
                let mut remaining = self.header.file_len() - HEADER_LEN as u64;
                let mut buffer = vec![0_u8; CHECKSUM_CHUNK];
                while remaining > 0 {
                    let want = index64(remaining.min(CHECKSUM_CHUNK as u64));
                    file.read_exact(&mut buffer[..want])?;
                    context.update(&buffer[..want]);
                    remaining -= want as u64;
                }
            }
        }
        Ok(digest_to_array(context.finish().as_ref()) == self.header.checksum)
    }

    /// Whether the filter contains this SHA-1 digest (its first 8 bytes are the key).
    ///
    /// # Errors
    ///
    /// [`FilterError::Io`] if reading from the file fails.
    pub fn contains_sha1(&self, sha1: &[u8; 20]) -> Result<bool, FilterError> {
        if self.header.key_count == 0 {
            return Ok(false);
        }
        let key = key_of_sha1(sha1);
        let hash = self.header.params.hash(key);
        let positions = self.header.params.layout.positions(hash);
        let [a, b, c] = self.read_fingerprints(positions)?;
        Ok(fingerprint_of(hash) ^ a ^ b ^ c == 0)
    }

    /// Whether the filter contains the SHA-1 of this normalized password.
    ///
    /// # Errors
    ///
    /// [`FilterError::Io`] if reading from the file fails.
    pub fn contains_password(&self, normalized_password: &str) -> Result<bool, FilterError> {
        let digest = Zeroizing::new(super::sha1(normalized_password));
        self.contains_sha1(&digest)
    }

    /// The number of distinct keys stored (an empty set has none).
    pub fn key_count(&self) -> u64 {
        self.header.key_count
    }

    /// The smallest count a line needed to be included when the filter was built.
    pub fn min_count(&self) -> u64 {
        self.header.min_count
    }

    fn read_fingerprints(&self, positions: [u32; 3]) -> Result<[u16; 3], FilterError> {
        const SHORT: FilterError = FilterError::Format("fingerprint beyond the end of the file");
        let offset = |position: u32| HEADER_LEN as u64 + 2 * u64::from(position);
        match &self.storage {
            Storage::Memory(bytes) => {
                let mut out = [0_u16; 3];
                for (slot, &position) in out.iter_mut().zip(&positions) {
                    let at = index64(offset(position));
                    let pair = bytes.get(at..at + 2).ok_or(SHORT)?;
                    *slot = u16::from_le_bytes([pair[0], pair[1]]);
                }
                Ok(out)
            }
            Storage::File(file) => {
                let mut file = file.lock().unwrap_or_else(PoisonError::into_inner);
                let mut out = [0_u16; 3];
                for (slot, &position) in out.iter_mut().zip(&positions) {
                    file.seek(SeekFrom::Start(offset(position)))?;
                    let mut pair = [0_u8; 2];
                    file.read_exact(&mut pair)?;
                    *slot = u16::from_le_bytes(pair);
                }
                Ok(out)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    /// A deterministic stream of 64-bit values for test keys.
    fn stream(seed: u64) -> impl FnMut() -> u64 {
        let mut state = seed;
        move || splitmix64(&mut state)
    }

    fn sha1_with_key(key: u64) -> [u8; 20] {
        let mut out = [0_u8; 20];
        out[..8].copy_from_slice(&key.to_be_bytes());
        out
    }

    fn build_from_keys(keys: &[u64]) -> Vec<u8> {
        let mut text = String::new();
        for key in keys {
            writeln!(text, "{key:016X}{:024X}:7", 0).expect("write to string");
        }
        let mut out = Vec::new();
        build_filter(text.as_bytes(), &mut out, &BuildOptions::default()).expect("build");
        out
    }

    #[test]
    fn fmix64_is_a_bijection_on_samples_and_mixes() {
        assert_eq!(fmix64(0), 0);
        let mut next = stream(1);
        for _ in 0..1000 {
            let a = next();
            let b = next();
            assert_eq!(fmix64(a) == fmix64(b), a == b);
        }
        assert_ne!(fmix64(1), 1);
    }

    #[test]
    fn layout_follows_the_published_parameters() {
        // Empty and tiny sets: segment length 4 (or 8), a single segment plus two.
        let empty = Layout::for_key_count(0).expect("layout");
        assert_eq!(empty.segment_length, 4);
        assert_eq!(empty.array_length, 12);
        let one = Layout::for_key_count(1).expect("layout");
        assert_eq!((one.segment_length, one.array_length), (4, 12));
        let two = Layout::for_key_count(2).expect("layout");
        assert_eq!((two.segment_length, two.array_length), (4, 12));
        let three = Layout::for_key_count(3).expect("layout");
        assert_eq!((three.segment_length, three.array_length), (8, 24));
        // A million keys: 2^floor(ln(1e6)/ln(3.33)+2.25) = 2^13, factor 1.125.
        let million = Layout::for_key_count(1_000_000).expect("layout");
        assert_eq!(million.segment_length, 1 << 13);
        let slots = f64::from(million.array_length) / 1_000_000.0;
        assert!((1.12..1.16).contains(&slots), "slots per key {slots}");
        // The segment length is capped.
        let big = Layout::for_key_count(900_000_000).expect("layout");
        assert_eq!(big.segment_length, MAX_SEGMENT_LENGTH);
        assert!(Layout::for_key_count(u64::from(u32::MAX) + 1).is_err());
    }

    #[test]
    fn positions_stay_in_three_distinct_segments() {
        for size in [0_u64, 1, 2, 3, 10, 1000, 123_456] {
            let layout = Layout::for_key_count(size).expect("layout");
            let mut next = stream(size);
            for _ in 0..2000 {
                let hash = next();
                let [h0, h1, h2] = layout.positions(hash);
                assert!(h2 < layout.array_length);
                let segments = [
                    h0 / layout.segment_length,
                    h1 / layout.segment_length,
                    h2 / layout.segment_length,
                ];
                assert_eq!(segments[1], segments[0] + 1);
                assert_eq!(segments[2], segments[0] + 2);
            }
        }
    }

    #[test]
    fn header_round_trips_and_has_the_documented_layout() {
        let header = Header {
            params: Params {
                seed: 0x0102_0304_0506_0708,
                layout: Layout::for_key_count(1000).expect("layout"),
            },
            key_count: 1000,
            min_count: 3,
            checksum: [0xab; 32],
        };
        let bytes = header.encode();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(&bytes[..8], b"TKHIBPF1");
        assert_eq!(&bytes[8..10], &1_u16.to_le_bytes());
        assert_eq!(bytes[10], 16);
        assert_eq!(bytes[11], 1);
        assert_eq!(&bytes[12..16], &[0, 0, 0, 0]);
        assert_eq!(&bytes[16..24], &0x0102_0304_0506_0708_u64.to_le_bytes());
        assert_eq!(
            &bytes[24..28],
            &header.params.layout.segment_length.to_le_bytes()
        );
        assert_eq!(
            &bytes[28..32],
            &header.params.layout.segment_length_mask.to_le_bytes()
        );
        assert_eq!(
            &bytes[32..36],
            &header.params.layout.segment_count_length.to_le_bytes()
        );
        assert_eq!(
            &bytes[36..40],
            &header.params.layout.array_length.to_le_bytes()
        );
        assert_eq!(&bytes[40..48], &1000_u64.to_le_bytes());
        assert_eq!(&bytes[48..56], &3_u64.to_le_bytes());
        assert_eq!(&bytes[56..88], &[0xab; 32]);
        let back = Header::decode(&bytes).expect("decode");
        assert_eq!(back.params.seed, header.params.seed);
        assert_eq!(back.params.layout, header.params.layout);
        assert_eq!(
            (back.key_count, back.min_count, back.checksum),
            (1000, 3, [0xab; 32])
        );
    }

    #[test]
    fn header_refuses_inconsistent_geometry() {
        let good = Header {
            params: Params {
                seed: 1,
                layout: Layout::for_key_count(1000).expect("layout"),
            },
            key_count: 1000,
            min_count: 1,
            checksum: [0; 32],
        }
        .encode();
        let patch = |range: std::ops::Range<usize>, value: &[u8]| {
            let mut bytes = good.clone();
            bytes[range].copy_from_slice(value);
            Header::decode(&bytes)
        };
        assert!(Header::decode(&good).is_ok());
        assert!(patch(24..28, &3_u32.to_le_bytes()).is_err());
        assert!(patch(24..28, &(1_u32 << 19).to_le_bytes()).is_err());
        assert!(patch(28..32, &0_u32.to_le_bytes()).is_err());
        assert!(patch(32..36, &0_u32.to_le_bytes()).is_err());
        assert!(patch(36..40, &1_u32.to_le_bytes()).is_err());
        assert!(patch(40..48, &u64::MAX.to_le_bytes()).is_err());
        assert!(patch(12..16, &1_u32.to_le_bytes()).is_err());
        assert!(Header::decode(&good[..HEADER_LEN - 1]).is_err());
    }

    #[test]
    fn parse_line_reads_the_key_and_the_count() {
        let (key, count) =
            parse_line(b"5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824").expect("line");
        assert_eq!(key, 0x5baa_61e4_c9b9_3f3f);
        assert_eq!(count, 9_545_824);
        assert!(parse_line(b"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8:0").is_some());
        for bad in [
            &b""[..],
            b"5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8",
            b"5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:",
            b"5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:12x",
            b"5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD:12",
            b"5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8;12",
            b"ZBAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:12",
            b"5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:99999999999999999999999",
        ] {
            assert!(
                parse_line(bad).is_none(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn small_sets_build_and_answer() {
        for size in [0_usize, 1, 2, 3, 4, 5, 7, 10, 33] {
            let mut next = stream(size as u64 + 100);
            let keys: Vec<u64> = (0..size).map(|_| next()).collect();
            let filter = HibpFilter::from_bytes(build_from_keys(&keys)).expect("filter");
            assert_eq!(filter.key_count(), size as u64);
            for &key in &keys {
                assert!(
                    filter.contains_sha1(&sha1_with_key(key)).expect("lookup"),
                    "size {size}"
                );
            }
        }
    }

    #[test]
    fn construction_is_deterministic() {
        let mut next = stream(9);
        let keys: Vec<u64> = (0..500).map(|_| next()).collect();
        assert_eq!(build_from_keys(&keys), build_from_keys(&keys));
    }
}
