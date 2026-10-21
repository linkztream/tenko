//! The passive OS classifier of the `os_fingerprint` method (SCAN-04): from a SYN-ACK (or
//! a SYN) it guesses the operating system family from the TTL, the window size, the TCP
//! option layout and the don't-fragment flag, p0f-style. The signatures live in a fixture
//! table (`fixtures/os_fingerprints.tsv`) compiled into the binary, so adding a signature
//! is a data change. A product name is never guessed beyond the family.

use std::sync::OnceLock;

use crate::frame::{ipv4::Ipv4, tcp::Tcp};

/// The signature table, as shipped.
const TABLE: &str = include_str!("../../../fixtures/os_fingerprints.tsv");

/// One observed packet reduced to the fields the classifier reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// The observed TTL (the hop count left when the probe saw the packet).
    pub ttl: u8,
    /// The advertised window size.
    pub window: u16,
    /// The TCP option layout (`MSTNW`), in order.
    pub options: String,
    /// Whether the don't-fragment flag was set.
    pub dont_fragment: bool,
}

impl Observed {
    /// The fields of a TCP segment inside an IPv4 packet.
    pub fn from_ipv4_tcp(ip: &Ipv4, tcp: &Tcp) -> Self {
        Self {
            ttl: ip.ttl,
            window: tcp.window,
            options: tcp.option_layout(),
            dont_fragment: ip.dont_fragment,
        }
    }
}

/// A guess of the operating system family and the confidence in percent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// The family, such as `Linux` or `Windows`.
    pub family: String,
    /// Confidence in percent.
    pub confidence: u8,
}

/// A parsed signature row.
#[derive(Debug, Clone)]
struct Signature {
    family: String,
    ttl: u8,
    window: Option<u16>,
    options: Option<String>,
    dont_fragment: Option<bool>,
    confidence: u8,
}

fn table() -> &'static [Signature] {
    static TABLE_ONCE: OnceLock<Vec<Signature>> = OnceLock::new();
    TABLE_ONCE.get_or_init(|| {
        TABLE
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(parse_row)
            .collect()
    })
}

fn parse_row(line: &str) -> Option<Signature> {
    let mut fields = line.split('\t');
    let family = fields.next()?.trim().to_owned();
    let ttl = fields.next()?.trim().parse().ok()?;
    let window = match fields.next()?.trim() {
        "*" => None,
        value => Some(value.parse().ok()?),
    };
    let options = match fields.next()?.trim() {
        "*" => None,
        value => Some(value.to_owned()),
    };
    let dont_fragment = match fields.next()?.trim() {
        "y" => Some(true),
        "n" => Some(false),
        _ => None,
    };
    let confidence = fields.next()?.trim().parse().ok()?;
    Some(Signature {
        family,
        ttl,
        window,
        options,
        dont_fragment,
        confidence,
    })
}

/// Rounds an observed TTL up to the usual initial value (32, 64, 128 or 255). A packet
/// crosses a few routers at most on a segment, so the next value up is the initial TTL.
pub fn initial_ttl(observed: u8) -> u8 {
    match observed {
        0..=32 => 32,
        33..=64 => 64,
        65..=128 => 128,
        _ => 255,
    }
}

/// The family a TTL alone suggests, for the low-confidence fallback.
fn ttl_family(initial: u8) -> &'static str {
    match initial {
        64 => "Linux",
        128 => "Windows",
        255 => "network gear",
        _ => "unknown",
    }
}

/// Classifies an observed packet. The most confident matching signature wins; with none,
/// the family the TTL suggests is returned at confidence 40 (`unknown` at 20 when even the
/// TTL says nothing).
pub fn classify(observed: &Observed) -> Fingerprint {
    let initial = initial_ttl(observed.ttl);
    let best = table()
        .iter()
        .filter(|signature| signature.ttl == initial)
        .filter(|signature| signature.window.is_none_or(|w| w == observed.window))
        .filter(|signature| {
            signature
                .options
                .as_deref()
                .is_none_or(|o| o == observed.options)
        })
        .filter(|signature| {
            signature
                .dont_fragment
                .is_none_or(|df| df == observed.dont_fragment)
        })
        .max_by_key(|signature| signature.confidence);
    if let Some(signature) = best {
        return Fingerprint {
            family: signature.family.clone(),
            confidence: signature.confidence,
        };
    }
    let family = ttl_family(initial);
    Fingerprint {
        family: family.to_owned(),
        confidence: if family == "unknown" { 20 } else { 40 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(ttl: u8, window: u16, options: &str, df: bool) -> Observed {
        Observed {
            ttl,
            window,
            options: options.to_owned(),
            dont_fragment: df,
        }
    }

    #[test]
    fn the_table_parses() {
        assert!(table().len() >= 10, "the fixture table loaded");
    }

    #[test]
    fn initial_ttl_rounds_up() {
        assert_eq!(initial_ttl(58), 64);
        assert_eq!(initial_ttl(64), 64);
        assert_eq!(initial_ttl(120), 128);
        assert_eq!(initial_ttl(250), 255);
    }

    #[test]
    fn a_linux_syn_ack_is_linux() {
        let fingerprint = classify(&observed(58, 65160, "MSTNW", true));
        assert_eq!(fingerprint.family, "Linux");
        assert!(fingerprint.confidence >= 70, "{fingerprint:?}");
    }

    #[test]
    fn a_windows_syn_ack_is_windows() {
        let fingerprint = classify(&observed(122, 64240, "MNWNNS", true));
        assert_eq!(fingerprint.family, "Windows");
        assert!(fingerprint.confidence >= 75);
    }

    #[test]
    fn a_router_ttl_is_network_gear() {
        let fingerprint = classify(&observed(250, 4128, "M", false));
        assert_eq!(fingerprint.family, "network gear");
    }

    #[test]
    fn an_unseen_signature_falls_back_to_the_ttl_family() {
        let fingerprint = classify(&observed(60, 1234, "XYZ", true));
        assert_eq!(fingerprint.family, "Linux");
        assert_eq!(fingerprint.confidence, 40);
    }
}
