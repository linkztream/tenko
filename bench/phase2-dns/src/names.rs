//! The query names file.
//!
//! One query per line: `name [TYPE]`, the dnsperf input format. The type
//! defaults to `A`. Blank lines and lines starting with `;` or `#` are
//! skipped. Names are held pre-encoded in wire format in one contiguous
//! buffer, so picking a query costs no allocation.

use std::fs;
use std::path::Path;

use anyhow::{Context, bail};
use rand::{Rng, RngExt};

/// Longest wire-format name, root label included.
const MAX_WIRE_NAME: usize = 255;
/// Longest label.
const MAX_LABEL: usize = 63;

#[derive(Debug, Clone, Copy)]
struct Entry {
    off: u32,
    len: u8,
    qtype: u16,
}

/// A list of pre-encoded query names with their types.
#[derive(Debug, Default)]
pub struct Names {
    wire: Vec<u8>,
    entries: Vec<Entry>,
}

/// Encodes a presentation-format name (dots between labels, optional trailing
/// dot, no escapes) as wire-format labels and appends it to `out`.
pub fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), String> {
    let start = out.len();
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            if label.is_empty() {
                return Err(format!("empty label in {name:?}"));
            }
            if label.len() > MAX_LABEL {
                return Err(format!("label longer than {MAX_LABEL} octets in {name:?}"));
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    if out.len() - start > MAX_WIRE_NAME {
        out.truncate(start);
        return Err(format!("name longer than {MAX_WIRE_NAME} octets: {name:?}"));
    }
    Ok(())
}

/// Maps a record type mnemonic (`A`, `PTR`, `TYPE65`) to its number.
pub fn parse_qtype(s: &str) -> Option<u16> {
    let upper = s.to_ascii_uppercase();
    if let Some(n) = upper.strip_prefix("TYPE") {
        return n.parse().ok();
    }
    Some(match upper.as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "DS" => 43,
        "RRSIG" => 46,
        "DNSKEY" => 48,
        "HTTPS" => 65,
        "ANY" => 255,
        _ => return None,
    })
}

impl Names {
    /// Parses the text of a names file.
    pub fn parse(text: &str) -> anyhow::Result<Names> {
        let mut names = Names::default();
        for (index, raw) in text.lines().enumerate() {
            let line_no = index + 1;
            let line = raw.trim_start_matches('\u{feff}').trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let name = fields.next().unwrap_or_default();
            let qtype = match fields.next() {
                None => 1,
                Some(t) => parse_qtype(t)
                    .with_context(|| format!("line {line_no}: unknown record type {t:?}"))?,
            };
            let off = u32::try_from(names.wire.len()).context("names file is too large")?;
            if let Err(e) = encode_name(name, &mut names.wire) {
                bail!("line {line_no}: {e}");
            }
            let len = (names.wire.len() - off as usize) as u8;
            names.entries.push(Entry { off, len, qtype });
        }
        if names.entries.is_empty() {
            bail!("the names file holds no queries");
        }
        Ok(names)
    }

    /// Reads and parses a names file.
    pub fn from_file(path: &Path) -> anyhow::Result<Names> {
        let text =
            fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
        Names::parse(&text).with_context(|| format!("in {}", path.display()))
    }

    /// Number of queries in the list.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the list holds no query (never true for a parsed list).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// A uniformly random entry: the wire-format name and the query type.
    #[inline]
    pub fn pick<R: Rng>(&self, rng: &mut R) -> (&[u8], u16) {
        let e = self.entries[rng.random_range(0..self.entries.len())];
        (
            &self.wire[e.off as usize..e.off as usize + usize::from(e.len)],
            e.qtype,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    #[test]
    fn parses_names_types_and_comments() {
        let n = Names::parse(
            "; a comment\n\nhost-1.example.test A\nhost-2.example.test.\n# x\n5.3.2.0.192.in-addr.arpa ptr\n. NS\n",
        )
        .unwrap();
        assert_eq!(n.len(), 4);
        let mut rng = SmallRng::seed_from_u64(1);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..200 {
            let (w, t) = n.pick(&mut rng);
            seen.insert((w.to_vec(), t));
        }
        assert!(seen.contains(&(b"\x06host-1\x07example\x04test\x00".to_vec(), 1)));
        assert!(seen.contains(&(b"\x06host-2\x07example\x04test\x00".to_vec(), 1)));
        assert!(
            seen.iter()
                .any(|(w, t)| *t == 12 && w.starts_with(b"\x015\x013"))
        );
        assert!(seen.contains(&(vec![0], 2)));
    }

    #[test]
    fn rejects_bad_lines() {
        assert!(Names::parse("").is_err());
        assert!(Names::parse("a..b A\n").is_err());
        assert!(Names::parse("a.example.test BOGUS\n").is_err());
        let long_label = format!("{}.test A\n", "x".repeat(64));
        assert!(Names::parse(&long_label).is_err());
        let long_name = format!("{} A\n", vec!["abcdefghi"; 30].join("."));
        assert!(Names::parse(&long_name).is_err());
        let err = Names::parse("ok.test A\nbad..test A\n").unwrap_err();
        assert!(err.to_string().contains("line 2"), "{err}");
    }

    #[test]
    fn type_mnemonics() {
        assert_eq!(parse_qtype("aaaa"), Some(28));
        assert_eq!(parse_qtype("TYPE65"), Some(65));
        assert_eq!(parse_qtype("nope"), None);
    }
}
