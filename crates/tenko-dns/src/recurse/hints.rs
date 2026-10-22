//! The root hints (recursion plan section 2.5): the shipped file
//! ([`crate::recursion::shipped::ROOT_HINTS`]) or the file `[dns.recursion] hints` names,
//! in the zone file format of `named.root`, read into the root's name servers and their
//! addresses. They are used for priming only (RFC 8109): the answer of a root server
//! replaces them, and they come back when the root's NS set expires or the infrastructure
//! cache is flushed.

use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    time::SystemTime,
};

use tenko_core::dns::DnsName;

use crate::recursion::shipped::{ROOT_HINTS, ROOT_HINTS_DATE};

/// Where the hints came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HintsSource {
    /// The file shipped in the binary.
    Shipped,
    /// A file, with its modification time when it was read.
    File(PathBuf, Option<SystemTime>),
}

impl HintsSource {
    /// `shipped`, or the file's path (the status's `hints_source`).
    pub fn describe(&self) -> String {
        match self {
            HintsSource::Shipped => "shipped".to_owned(),
            HintsSource::File(path, _) => path.display().to_string(),
        }
    }
}

/// The root's name servers and their addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hints {
    /// Where they came from.
    pub source: HintsSource,
    /// The date of the shipped file, or of the file's modification.
    pub date: String,
    /// The name servers of the root with their addresses, in the file's order.
    pub servers: Vec<(DnsName, Vec<IpAddr>)>,
    /// The NS records' TTL in the file.
    pub ttl: u32,
}

/// Why hints could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HintsError {
    /// The file could not be read.
    #[error("the root hints file {0} cannot be read: {1}")]
    Read(String, String),
    /// A line does not parse.
    #[error("the root hints, line {0}: {1}")]
    Line(usize, String),
    /// No root name server with an address.
    #[error("the root hints name no root name server with an address")]
    Empty,
}

impl Hints {
    /// The hints shipped in the binary.
    ///
    /// # Panics
    ///
    /// Never: the shipped file is checked by a test.
    pub fn shipped() -> Self {
        let mut hints = parse(ROOT_HINTS).unwrap_or_else(|error| {
            // The shipped file is checked by the tests; an empty set fails every priming
            // loudly rather than the start.
            tracing::error!(%error, "the shipped root hints do not parse");
            Hints {
                source: HintsSource::Shipped,
                date: String::new(),
                servers: Vec::new(),
                ttl: 0,
            }
        });
        hints.source = HintsSource::Shipped;
        ROOT_HINTS_DATE.clone_into(&mut hints.date);
        hints
    }

    /// The hints of `path`.
    ///
    /// # Errors
    ///
    /// [`HintsError`] when the file cannot be read or holds no usable server.
    pub fn from_file(path: &Path) -> Result<Self, HintsError> {
        let text = std::fs::read_to_string(path)
            .map_err(|io| HintsError::Read(path.display().to_string(), io.to_string()))?;
        let modified = std::fs::metadata(path)
            .and_then(|meta| meta.modified())
            .ok();
        let mut hints = parse(&text)?;
        hints.date = modified.map(date_of).unwrap_or_default();
        hints.source = HintsSource::File(path.to_path_buf(), modified);
        Ok(hints)
    }

    /// Whether the file the hints came from changed since it was read.
    pub fn changed(&self) -> bool {
        match &self.source {
            HintsSource::Shipped => false,
            HintsSource::File(path, read) => {
                let now = std::fs::metadata(path)
                    .and_then(|meta| meta.modified())
                    .ok();
                now.is_some() && now != *read
            }
        }
    }

    /// Every address, in the file's order.
    pub fn addresses(&self) -> impl Iterator<Item = (&DnsName, IpAddr)> {
        self.servers
            .iter()
            .flat_map(|(name, addresses)| addresses.iter().map(move |address| (name, *address)))
    }
}

/// `YYYY-MM-DD` of a time (UTC).
fn date_of(time: SystemTime) -> String {
    let secs = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    // Civil from days (the inverse of days from civil).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Reads hints in the zone file format of `named.root`: `owner [ttl] [IN] type data` per
/// line, `;` comments; NS records of the root, A and AAAA records of their names; other
/// lines are refused.
///
/// # Errors
///
/// [`HintsError`] for a line that does not parse or hints without a usable server.
pub fn parse(text: &str) -> Result<Hints, HintsError> {
    let mut names: Vec<DnsName> = Vec::new();
    let mut addresses: Vec<(DnsName, IpAddr)> = Vec::new();
    let mut ttl = u32::MAX;
    for (index, line) in text.lines().enumerate() {
        let line = line.split(';').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let bad = |reason: &str| HintsError::Line(index + 1, reason.to_owned());
        let mut fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            return Err(bad("expected an owner, a type and data"));
        }
        let owner = DnsName::new(fields.remove(0)).map_err(|_| bad("the owner is not a name"))?;
        let mut record_ttl = None;
        if let Ok(value) = fields[0].parse::<u32>() {
            record_ttl = Some(value);
            fields.remove(0);
        }
        if fields
            .first()
            .is_some_and(|class| class.eq_ignore_ascii_case("IN"))
        {
            fields.remove(0);
        }
        let [rtype, data] = fields[..] else {
            return Err(bad("expected a type and one datum"));
        };
        match rtype.to_ascii_uppercase().as_str() {
            "NS" => {
                if !owner.is_root() {
                    return Err(bad("an NS record of a name other than the root"));
                }
                let host = DnsName::new(data).map_err(|_| bad("the name server is not a name"))?;
                if let Some(value) = record_ttl {
                    ttl = ttl.min(value);
                }
                names.push(host);
            }
            "A" | "AAAA" => {
                let address: IpAddr = data.parse().map_err(|_| bad("not an address"))?;
                if address.is_ipv4() != (rtype.eq_ignore_ascii_case("A")) {
                    return Err(bad("the address does not fit the type"));
                }
                addresses.push((owner, address));
            }
            _ => return Err(bad("only NS, A and AAAA records belong in root hints")),
        }
    }
    let servers: Vec<(DnsName, Vec<IpAddr>)> = names
        .into_iter()
        .map(|name| {
            let found = addresses
                .iter()
                .filter(|(owner, _)| *owner == name)
                .map(|(_, address)| *address)
                .collect();
            (name, found)
        })
        .filter(|(_, found): &(DnsName, Vec<IpAddr>)| !found.is_empty())
        .collect();
    if servers.is_empty() {
        return Err(HintsError::Empty);
    }
    Ok(Hints {
        source: HintsSource::Shipped,
        date: String::new(),
        servers,
        ttl: if ttl == u32::MAX { 3_600_000 } else { ttl },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_hints_name_thirteen_servers_with_both_families() {
        let hints = Hints::shipped();
        assert_eq!(hints.servers.len(), 13);
        assert_eq!(hints.date, ROOT_HINTS_DATE);
        assert!(hints.addresses().any(|(_, address)| address.is_ipv4()));
        assert!(hints.addresses().any(|(_, address)| address.is_ipv6()));
        assert_eq!(hints.source.describe(), "shipped");
        assert!(!hints.changed());
    }

    #[test]
    fn a_lab_file_parses_and_bad_lines_are_refused() {
        let hints =
            parse(".  3600000 IN NS a.root.test.\na.root.test. 3600000 A 203.0.113.10 ; lab\n")
                .expect("hints");
        assert_eq!(hints.servers.len(), 1);
        assert_eq!(hints.ttl, 3_600_000);
        assert_eq!(hints.servers[0].0.as_str(), "a.root.test");
        for bad in [
            "test. NS a.root.test.\n",
            ". NS a.root.test.\na.root.test. A 2001:db8::1\n",
            ". MX 10 a.root.test.\n",
            ". NS a.root.test.\n",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        assert_eq!(date_of(SystemTime::UNIX_EPOCH), "1970-01-01");
        assert_eq!(
            date_of(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_792_972_800)),
            "2026-10-26"
        );
    }
}
