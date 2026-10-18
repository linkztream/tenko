//! The list text, the compiled version and the matcher the query path reads.
//!
//! **The text** ([`parse`]): one entry per line; `#` starts a comment anywhere on a line,
//! `!` at the start of a line too (the comment of Adblock-style lists); blank lines are
//! skipped. A hosts file (`ListFormat::Hosts`) has an address and then one or more names on
//! a line (`0.0.0.0 ads.example.test`, `127.0.0.1 a.example.test b.example.test`); the
//! boilerplate names of a hosts file (`localhost`, `broadcasthost`, the `ip6-*` names) are
//! skipped. A domain list (`ListFormat::Domains`) has one name per line; a line in hosts
//! form is read as one, and the Adblock forms `||name^` and `*.name` are read as `name`.
//! Names are folded to canonical lowercase; a label outside ASCII is lowercased and written
//! in Punycode (RFC 3492, the `xn--` form of IDNA). A line that holds no valid name (a URL,
//! a label over 63 octets, a name over 255) is counted as skipped, never an error.
//!
//! **The compiled version** ([`compile`], stored as `ListVersion.compiled`): the names as
//! one sorted suffix set. Each name becomes its key, its labels from the right with a length
//! octet before each (`example.test` is `\x04test\x07example`), so that a name's key starts
//! with the key of every name above it. The keys are sorted, duplicates removed, and a name
//! at or below a name already in the set is dropped (the parent covers it). The bytes are
//! the magic, the entry count (LEB128), then each key front-coded against the one before
//! it: the octets it shares (one octet), the octets that follow (one octet), those octets.
//! Up to 64 KiB of entries follow as they are (magic `TKL1`); above that the entries are
//! deflated (RFC 1951, magic `TKL2`, their length in LEB128 before them), so that a list of
//! a million names stays one store value well below the 16 MiB of a store batch (about 11
//! MiB for a million random names, less for real lists, whose names share their parents;
//! [`MAX_COMPILED`] is the limit). A million names compile in about one second (M25).
//!
//! **The matcher** ([`ListMatcher`]), built by the catalog from the newest version: a name
//! matches when it or a name above it is in the set. The table is an open-addressing hash
//! of the wire form of every name, keyed by a hash computed label by label from the right,
//! so a lookup walks the labels of the query name once from the top label down, extends
//! the hash by one label, and probes once per label: time linear in the labels of the name
//! and constant per label, whatever the size of the list. A probe compares the stored name,
//! so a match is exact. Nothing is allocated.

use tenko_core::dns::ListFormat;

/// The first octets of a compiled version whose entries follow as they are.
pub const MAGIC: &[u8; 4] = b"TKL1";

/// The first octets of a compiled version whose entries follow deflated (RFC 1951).
pub const MAGIC_DEFLATE: &[u8; 4] = b"TKL2";

/// Octets of front-coded entries above which a version is deflated.
pub const DEFLATE_ABOVE: usize = 64 * 1024;

/// Names a version may hold.
pub const MAX_ENTRIES: usize = 4_000_000;

/// Octets of a compiled version at most: it is one store value, and a store batch holds at
/// most 16 MiB.
pub const MAX_COMPILED: usize = 12 * 1024 * 1024;

/// The longest key: a wire name without its root octet.
const MAX_KEY: usize = 254;

/// What [`parse`] read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    /// The keys of the names read (labels from the right), in the order of the text.
    pub keys: Vec<Vec<u8>>,
    /// Lines that held no valid name.
    pub skipped: u64,
}

/// Why a list could not be compiled or a version not read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompileError {
    /// More names than [`MAX_ENTRIES`].
    #[error("the list holds more than {MAX_ENTRIES} names")]
    TooManyNames,
    /// The compiled form would be larger than [`MAX_COMPILED`].
    #[error("the compiled list would take more than {MAX_COMPILED} octets")]
    TooLarge,
    /// The bytes are not a compiled version.
    #[error("the compiled list is malformed")]
    Malformed,
}

/// The names of hosts files that are not entries.
const HOSTS_BOILERPLATE: [&str; 11] = [
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
];

/// Reads the names of a list's text.
pub fn parse(text: &[u8], format: ListFormat) -> Parsed {
    let mut parsed = Parsed::default();
    for line in text.split(|byte| *byte == b'\n') {
        let line = match line.iter().position(|byte| *byte == b'#') {
            Some(at) => &line[..at],
            None => line,
        };
        let line = String::from_utf8_lossy(line);
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(first) = fields.next() else {
            continue;
        };
        let hosts_form = first.parse::<std::net::IpAddr>().is_ok();
        let mut found = false;
        if hosts_form {
            for name in fields {
                if HOSTS_BOILERPLATE.contains(&name) || name.parse::<std::net::IpAddr>().is_ok() {
                    found = true;
                    continue;
                }
                if let Some(key) = name_key(name) {
                    parsed.keys.push(key);
                    found = true;
                }
            }
        } else if format == ListFormat::Domains && fields.next().is_none() {
            let name = first
                .strip_prefix("||")
                .unwrap_or(first)
                .trim_end_matches('^');
            let name = name.strip_prefix("*.").unwrap_or(name);
            if let Some(key) = name_key(name) {
                parsed.keys.push(key);
                found = true;
            }
        }
        if !found {
            parsed.skipped += 1;
        }
    }
    parsed
}

/// Whether an ASCII label octet may appear in a listed name: letters, digits, `-`, `_`.
fn label_octet(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

/// The key of a name in text: labels from the right with their lengths, lowercase, IDN in
/// Punycode. `None` for a name that is not valid.
pub fn name_key(name: &str) -> Option<Vec<u8>> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return None;
    }
    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut wire = 1;
    for label in name.split('.') {
        let label = if label.is_ascii() {
            label.to_ascii_lowercase().into_bytes()
        } else {
            let lower: String = label.chars().flat_map(char::to_lowercase).collect();
            let mut out = b"xn--".to_vec();
            punycode(&lower, &mut out)?;
            out
        };
        if label.is_empty() || label.len() > 63 || !label.iter().all(|byte| label_octet(*byte)) {
            return None;
        }
        wire += 1 + label.len();
        if wire > MAX_KEY + 1 {
            return None;
        }
        labels.push(label);
    }
    let mut key = Vec::with_capacity(wire - 1);
    for label in labels.iter().rev() {
        key.push(u8::try_from(label.len()).ok()?);
        key.extend_from_slice(label);
    }
    Some(key)
}

/// Appends the Punycode encoding (RFC 3492, section 6.3) of `input` to `out`; `None` on
/// overflow. The names are those of the RFC's pseudocode.
#[allow(
    clippy::many_single_char_names,
    reason = "the variables of RFC 3492, section 6.3"
)]
fn punycode(input: &str, out: &mut Vec<u8>) -> Option<()> {
    const BASE: u32 = 36;
    const T_MIN: u32 = 1;
    const T_MAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;
    fn adapt(mut delta: u32, points: u32, first: bool) -> u32 {
        delta /= if first { DAMP } else { 2 };
        delta += delta / points;
        let mut k = 0;
        while delta > ((BASE - T_MIN) * T_MAX) / 2 {
            delta /= BASE - T_MIN;
            k += BASE;
        }
        k + (BASE - T_MIN + 1) * delta / (delta + SKEW)
    }
    fn digit(value: u32) -> u8 {
        #[allow(clippy::cast_possible_truncation, reason = "a digit below 36")]
        let value = value as u8;
        if value < 26 {
            b'a' + value
        } else {
            b'0' + value - 26
        }
    }
    let points: Vec<u32> = input.chars().map(u32::from).collect();
    let basic = points.iter().filter(|point| **point < 0x80).count();
    for point in points.iter().filter(|point| **point < 0x80) {
        out.push(u8::try_from(*point).ok()?);
    }
    let basic = u32::try_from(basic).ok()?;
    if basic > 0 {
        out.push(b'-');
    }
    let total = u32::try_from(points.len()).ok()?;
    let (mut n, mut delta, mut bias, mut handled) = (0x80u32, 0u32, 72u32, basic);
    while handled < total {
        let m = *points.iter().filter(|point| **point >= n).min()?;
        delta = delta.checked_add((m - n).checked_mul(handled + 1)?)?;
        n = m;
        for point in &points {
            if *point < n {
                delta = delta.checked_add(1)?;
            }
            if *point == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        T_MIN
                    } else if k >= bias + T_MAX {
                        T_MAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    out.push(digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                out.push(digit(q));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }
    Some(())
}

/// A compiled version: its bytes and the names it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiled {
    /// The bytes of `ListVersion.compiled`.
    pub bytes: Vec<u8>,
    /// The names in the set (after duplicates and covered names were dropped).
    pub entries: u64,
}

fn push_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        #[allow(clippy::cast_possible_truncation, reason = "the low seven bits")]
        let low = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

fn read_varint(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *bytes.get(*pos)?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// Compiles the keys of a parsed list into a version.
///
/// # Errors
///
/// [`CompileError::TooManyNames`] or [`CompileError::TooLarge`].
pub fn compile(mut keys: Vec<Vec<u8>>) -> Result<Compiled, CompileError> {
    keys.sort_unstable();
    keys.dedup();
    let mut kept: Vec<Vec<u8>> = Vec::with_capacity(keys.len());
    for key in keys {
        if kept.last().is_some_and(|parent| covers(parent, &key)) {
            continue;
        }
        kept.push(key);
    }
    if kept.len() > MAX_ENTRIES {
        return Err(CompileError::TooManyNames);
    }
    let mut body = Vec::with_capacity(kept.len() * 12);
    let mut previous: &[u8] = &[];
    for key in &kept {
        let shared = previous
            .iter()
            .zip(key.iter())
            .take_while(|(a, b)| a == b)
            .count();
        let rest = &key[shared..];
        body.push(u8::try_from(shared).map_err(|_| CompileError::Malformed)?);
        body.push(u8::try_from(rest.len()).map_err(|_| CompileError::Malformed)?);
        body.extend_from_slice(rest);
        previous = key;
    }
    let mut bytes = Vec::with_capacity(16 + body.len().min(MAX_COMPILED));
    if body.len() <= DEFLATE_ABOVE {
        bytes.extend_from_slice(MAGIC);
        push_varint(&mut bytes, kept.len() as u64);
        bytes.extend_from_slice(&body);
    } else {
        bytes.extend_from_slice(MAGIC_DEFLATE);
        push_varint(&mut bytes, kept.len() as u64);
        push_varint(&mut bytes, body.len() as u64);
        let mut encoder = flate2::write::DeflateEncoder::new(bytes, flate2::Compression::new(6));
        std::io::Write::write_all(&mut encoder, &body).map_err(|_| CompileError::TooLarge)?;
        bytes = encoder.finish().map_err(|_| CompileError::TooLarge)?;
    }
    if bytes.len() > MAX_COMPILED {
        return Err(CompileError::TooLarge);
    }
    Ok(Compiled {
        bytes,
        entries: kept.len() as u64,
    })
}

/// Whether the key `parent` covers `key`: `key` is the same name or a name below it.
fn covers(parent: &[u8], key: &[u8]) -> bool {
    key.starts_with(parent)
}

/// Reads the keys of a compiled version, in their sorted order.
///
/// # Errors
///
/// [`CompileError::Malformed`] when the bytes are not a compiled version.
pub fn decode(bytes: &[u8]) -> Result<Vec<Vec<u8>>, CompileError> {
    let mut keys = Vec::new();
    for_each_key(bytes, |key| keys.push(key.to_vec()))?;
    Ok(keys)
}

/// The entries of a deflated version: exactly `len` octets inflated from all of `deflated`.
fn inflate(deflated: &[u8], len: u64) -> Result<Vec<u8>, CompileError> {
    use std::io::Read as _;
    let mut decoder = flate2::read::DeflateDecoder::new(deflated);
    let capacity = usize::try_from(len).map_err(|_| CompileError::Malformed)?;
    let mut body = Vec::with_capacity(capacity.min(64 * 1024 * 1024));
    (&mut decoder)
        .take(len + 1)
        .read_to_end(&mut body)
        .map_err(|_| CompileError::Malformed)?;
    if body.len() as u64 != len || decoder.total_in() != deflated.len() as u64 {
        return Err(CompileError::Malformed);
    }
    Ok(body)
}

fn for_each_key(bytes: &[u8], mut each: impl FnMut(&[u8])) -> Result<u64, CompileError> {
    let deflated = match bytes.get(..4) {
        Some(magic) if magic == &MAGIC[..] => false,
        Some(magic) if magic == &MAGIC_DEFLATE[..] => true,
        _ => return Err(CompileError::Malformed),
    };
    let mut pos = 4;
    let count = read_varint(bytes, &mut pos).ok_or(CompileError::Malformed)?;
    if count > MAX_ENTRIES as u64 {
        return Err(CompileError::Malformed);
    }
    let inflated;
    let (bytes, mut pos) = if deflated {
        let len = read_varint(bytes, &mut pos).ok_or(CompileError::Malformed)?;
        // An entry takes at most two octets and a key of 254.
        if len > count * (2 + MAX_KEY as u64) {
            return Err(CompileError::Malformed);
        }
        inflated = inflate(&bytes[pos..], len)?;
        (&inflated[..], 0)
    } else {
        (bytes, pos)
    };
    let mut key = [0u8; MAX_KEY];
    let mut len = 0;
    for _ in 0..count {
        let shared = usize::from(*bytes.get(pos).ok_or(CompileError::Malformed)?);
        let rest = usize::from(*bytes.get(pos + 1).ok_or(CompileError::Malformed)?);
        pos += 2;
        let tail = bytes.get(pos..pos + rest).ok_or(CompileError::Malformed)?;
        if shared > len || shared + rest > MAX_KEY || shared + rest == 0 {
            return Err(CompileError::Malformed);
        }
        key[shared..shared + rest].copy_from_slice(tail);
        len = shared + rest;
        pos += rest;
        if !valid_key(&key[..len]) {
            return Err(CompileError::Malformed);
        }
        each(&key[..len]);
    }
    if pos != bytes.len() {
        return Err(CompileError::Malformed);
    }
    Ok(count)
}

/// Whether a key is a sequence of labels of 1 to 63 octets.
fn valid_key(key: &[u8]) -> bool {
    let mut pos = 0;
    while pos < key.len() {
        let len = usize::from(key[pos]);
        if len == 0 || len > 63 || pos + 1 + len > key.len() {
            return false;
        }
        pos += 1 + len;
    }
    true
}

/// The wire form (root octet included) of a key, into `out`.
fn key_to_wire(key: &[u8], out: &mut Vec<u8>) {
    let mut labels = [(0usize, 0usize); 127];
    let mut count = 0;
    let mut pos = 0;
    while pos < key.len() && count < labels.len() {
        let len = usize::from(key[pos]);
        labels[count] = (pos, len);
        count += 1;
        pos += 1 + len;
    }
    for &(at, len) in labels[..count].iter().rev() {
        out.extend_from_slice(&key[at..=at + len]);
    }
    out.push(0);
}

/// The text form of a key (`ads.example.test`), for tests and tools.
pub fn key_text(key: &[u8]) -> String {
    let mut wire = Vec::with_capacity(key.len() + 1);
    key_to_wire(key, &mut wire);
    let mut text = String::new();
    for label in crate::name::Labels::new(&wire) {
        if !text.is_empty() {
            text.push('.');
        }
        text.push_str(&String::from_utf8_lossy(label));
    }
    text
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// The hash after one more label (its length octet and its octets) to the left.
fn extend(mut hash: u64, label: &[u8]) -> u64 {
    for byte in label {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// The slot hash of a running label hash.
fn finish(hash: u64) -> u64 {
    let mut h = hash ^ (hash >> 33);
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^ (h >> 33)
}

/// The compiled set of one list version as the query path reads it.
#[derive(Clone, Default)]
pub struct ListMatcher {
    /// Per slot: 0 when empty, else the high 32 bits of the hash and the arena offset plus
    /// one.
    slots: Box<[u64]>,
    /// Per name: its wire length (one octet) and its wire form.
    arena: Box<[u8]>,
    mask: usize,
    entries: u64,
}

impl std::fmt::Debug for ListMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListMatcher")
            .field("entries", &self.entries)
            .field("bytes", &self.bytes())
            .finish_non_exhaustive()
    }
}

/// The label offsets of a wire name, at most 127.
fn label_offsets(wire: &[u8], offsets: &mut [u8; 128]) -> usize {
    let mut count = 0;
    let mut pos = 0usize;
    while let Some(&len) = wire.get(pos) {
        if len == 0 || count == offsets.len() || pos > 255 {
            break;
        }
        #[allow(
            clippy::cast_possible_truncation,
            reason = "a wire name is at most 255 octets"
        )]
        {
            offsets[count] = pos as u8;
        }
        count += 1;
        pos += 1 + usize::from(len);
    }
    count
}

impl ListMatcher {
    /// The matcher of a compiled version.
    ///
    /// # Errors
    ///
    /// [`CompileError::Malformed`] when the bytes are not a compiled version.
    pub fn build(bytes: &[u8]) -> Result<Self, CompileError> {
        let mut arena = Vec::with_capacity(bytes.len() * 2);
        let mut hashes: Vec<(u64, u32)> = Vec::new();
        let mut wire = Vec::with_capacity(256);
        for_each_key(bytes, |key| {
            wire.clear();
            key_to_wire(key, &mut wire);
            let mut hash = FNV_OFFSET;
            let mut pos = 0;
            while pos < key.len() {
                let len = usize::from(key[pos]);
                hash = extend(hash, &key[pos..=pos + len]);
                pos += 1 + len;
            }
            #[allow(
                clippy::cast_possible_truncation,
                reason = "the arena of a version is far below 4 GiB"
            )]
            let offset = arena.len() as u32;
            #[allow(
                clippy::cast_possible_truncation,
                reason = "a wire name is at most 255 octets"
            )]
            arena.push(wire.len() as u8);
            arena.extend_from_slice(&wire);
            hashes.push((finish(hash), offset));
        })?;
        let capacity = (hashes.len() * 2).next_power_of_two().max(8);
        let mask = capacity - 1;
        let mut slots = vec![0u64; capacity];
        for (hash, offset) in &hashes {
            #[allow(clippy::cast_possible_truncation, reason = "masked to the table")]
            let mut at = (*hash as usize) & mask;
            while slots[at] != 0 {
                at = (at + 1) & mask;
            }
            slots[at] = (hash & 0xffff_ffff_0000_0000) | (u64::from(*offset) + 1);
        }
        Ok(Self {
            slots: slots.into_boxed_slice(),
            arena: arena.into_boxed_slice(),
            mask,
            entries: hashes.len() as u64,
        })
    }

    /// The names in the set.
    pub fn entries(&self) -> u64 {
        self.entries
    }

    /// Octets the matcher holds (table and names).
    pub fn bytes(&self) -> usize {
        self.slots.len() * 8 + self.arena.len()
    }

    /// Whether the lowercase wire name `qname` or a name above it is in the set. Reads
    /// memory only and allocates nothing.
    pub fn matches(&self, qname: &[u8]) -> bool {
        if self.entries == 0 {
            return false;
        }
        let mut offsets = [0u8; 128];
        let count = label_offsets(qname, &mut offsets);
        let mut hash = FNV_OFFSET;
        for &offset in offsets[..count].iter().rev() {
            let at = usize::from(offset);
            let len = usize::from(qname[at]);
            let Some(label) = qname.get(at..=at + len) else {
                return false;
            };
            hash = extend(hash, label);
            if self.contains(finish(hash), &qname[at..]) {
                return true;
            }
        }
        false
    }

    fn contains(&self, hash: u64, suffix: &[u8]) -> bool {
        let tag = hash & 0xffff_ffff_0000_0000;
        #[allow(clippy::cast_possible_truncation, reason = "masked to the table")]
        let mut at = (hash as usize) & self.mask;
        loop {
            let slot = self.slots[at];
            if slot == 0 {
                return false;
            }
            if slot & 0xffff_ffff_0000_0000 == tag {
                #[allow(clippy::cast_possible_truncation, reason = "the low 32 bits")]
                let offset = ((slot & 0xffff_ffff) - 1) as usize;
                let len = usize::from(self.arena[offset]);
                if self.arena.get(offset + 1..offset + 1 + len) == Some(suffix) {
                    return true;
                }
            }
            at = (at + 1) & self.mask;
        }
    }
}
