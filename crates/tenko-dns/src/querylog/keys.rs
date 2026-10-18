//! The pseudonymisation keys of the query log: one random 256-bit key per UTC day.
//!
//! A client address is written as `p:` and the hexadecimal digits of an HMAC-SHA-256 of
//! the address under the key of the query's day: 8 octets in JSON lines, and in dnstap an
//! address of the same family made of the first 4 or 16 octets. The keys are kept in the
//! file `pseudonym-keys` of the log directory (owner-only on Unix), one line per day, and
//! removed with the last segment of their day, so that
//!
//! - a client keeps its pseudonym for the whole day, also across a restart of the node;
//! - the next day it gets another, so pseudonyms of two days cannot be linked;
//! - the node can tell which pseudonym an address had on a day that is still in the log
//!   (the reader's client filter), but nobody can turn a pseudonym back into an address
//!   without the key of its day. Whoever holds the key file can: IPv4 has 2^32 addresses,
//!   so an HMAC under a known key is reversed by trying them all. The key file never leaves
//!   the node, and the API never returns a key.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs, io,
    io::Write as _,
    net::IpAddr,
    path::{Path, PathBuf},
};

use zeroize::Zeroize;

/// The name of the key file in the log directory.
pub const KEYS_FILE: &str = "pseudonym-keys";

/// Octets of the HMAC a JSON-lines pseudonym keeps.
pub const PSEUDONYM_OCTETS: usize = 8;

/// The keys of the days still in the log.
pub struct Keys {
    path: PathBuf,
    days: BTreeMap<u64, [u8; 32]>,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("path", &self.path)
            .field("days", &self.days.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        for key in self.days.values_mut() {
            key.zeroize();
        }
    }
}

impl Keys {
    /// The keys stored in `dir`; none when the file is missing or unreadable (lines that
    /// do not parse are skipped).
    pub fn load(dir: &Path) -> Self {
        let path = dir.join(KEYS_FILE);
        let mut days = BTreeMap::new();
        if let Ok(mut text) = fs::read_to_string(&path) {
            for line in text.lines() {
                let Some((day, hex)) = line.split_once(' ') else {
                    continue;
                };
                if let (Ok(day), Some(key)) = (day.parse::<u64>(), parse_key(hex)) {
                    days.insert(day, key);
                }
            }
            text.zeroize();
        }
        Self { path, days }
    }

    /// The key of `day`, if it is kept.
    pub fn get(&self, day: u64) -> Option<&[u8; 32]> {
        self.days.get(&day)
    }

    /// The days whose keys are kept, oldest first.
    pub fn days(&self) -> impl Iterator<Item = u64> + '_ {
        self.days.keys().copied()
    }

    /// The key of `day`, made and stored when it is new. `None` only when the system's
    /// random generator fails (the entry is then written without a client). A key that
    /// cannot be stored is used anyway and reported through `error`.
    pub(crate) fn key_for(
        &mut self,
        day: u64,
        error: &mut dyn FnMut(io::Error),
    ) -> Option<[u8; 32]> {
        if let Some(key) = self.days.get(&day) {
            return Some(*key);
        }
        let mut key = [0u8; 32];
        aws_lc_rs::rand::fill(&mut key).ok()?;
        self.days.insert(day, key);
        if let Err(io) = self.save() {
            error(io);
        }
        Some(key)
    }

    /// Removes the keys of the days before `day`.
    pub(crate) fn retain_from(&mut self, day: u64) -> io::Result<()> {
        let before = self.days.len();
        let mut kept = self.days.split_off(&day);
        std::mem::swap(&mut kept, &mut self.days);
        for key in kept.values_mut() {
            key.zeroize();
        }
        if self.days.len() == before {
            Ok(())
        } else {
            self.save()
        }
    }

    fn save(&self) -> io::Result<()> {
        let mut text = String::from(
            "# Tenko DNS query log: the pseudonymisation key of each UTC day (days since 1970).\n",
        );
        for (day, key) in &self.days {
            let _ = write!(text, "{day} ");
            hex_into(&mut text, key);
            text.push('\n');
        }
        let temporary = self.path.with_extension("tmp");
        let result = write_private(&temporary, text.as_bytes())
            .and_then(|()| fs::rename(&temporary, &self.path));
        text.zeroize();
        result
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn parse_key(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.trim().as_bytes();
    if hex.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (at, pair) in hex.as_chunks::<2>().0.iter().enumerate() {
        let digits = std::str::from_utf8(pair).ok()?;
        key[at] = u8::from_str_radix(digits, 16).ok()?;
    }
    Some(key)
}

/// Appends the lowercase hexadecimal digits of `bytes`.
pub(crate) fn hex_into(out: &mut String, bytes: &[u8]) {
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
}

/// The HMAC-SHA-256 of an address under a key (an IPv4-mapped IPv6 address counts as the
/// IPv4 address).
pub fn tag(key: &[u8; 32], client: IpAddr) -> [u8; 32] {
    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
    let tag = match client.to_canonical() {
        IpAddr::V4(v4) => aws_lc_rs::hmac::sign(&key, &v4.octets()),
        IpAddr::V6(v6) => aws_lc_rs::hmac::sign(&key, &v6.octets()),
    };
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// The pseudonym text of the leading `octets` of a tag (or of a pseudonymised address):
/// `p:` and their hexadecimal digits.
pub fn pseudonym_text(octets: &[u8]) -> String {
    let mut out = String::with_capacity(2 + octets.len() * 2);
    out.push_str("p:");
    hex_into(&mut out, octets);
    out
}

/// Whether `text` has the shape of a pseudonym: `p:` and 4 to 32 octets in hexadecimal.
pub fn is_pseudonym(text: &str) -> bool {
    text.strip_prefix("p:").is_some_and(|hex| {
        (8..=64).contains(&hex.len())
            && hex.len().is_multiple_of(2)
            && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}
