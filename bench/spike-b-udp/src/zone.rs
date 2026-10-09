//! The fixed in-memory zone `example.test`.
//!
//! `host-{n}.example.test` for `n` in `0..size` maps to one A record taken
//! from the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
//! 203.0.113.0/24); addresses repeat because the ranges hold 768 addresses.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::wire::{APEX, QCLASS_IN, QTYPE_A, QTYPE_SOA};

/// Default number of names in the zone.
pub const DEFAULT_ZONE_SIZE: u32 = 100_000;
/// TTL of every record in the zone, seconds.
pub const TTL: u32 = 300;

/// SOA fields of the zone (names in presentation format, no trailing dot).
#[derive(Debug, Clone)]
pub struct SoaData {
    pub mname: &'static str,
    pub rname: &'static str,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

/// The SOA record served for `example.test`.
pub const SOA: SoaData = SoaData {
    mname: "ns1.example.test",
    rname: "hostmaster.example.test",
    serial: 2026100901,
    refresh: 3600,
    retry: 900,
    expire: 604800,
    minimum: 300,
};

/// Lookup key: the query name lowercased, in presentation format without
/// the trailing dot, built label by label into a fixed stack buffer.
#[derive(Clone)]
pub struct NameKey {
    buf: [u8; 256],
    len: usize,
    /// Set when a label contains a '.' byte (or the name is too long), which
    /// the dotted key cannot represent. Such names never match the zone.
    unrepresentable: bool,
}

impl Default for NameKey {
    fn default() -> Self {
        Self::new()
    }
}

impl NameKey {
    pub const fn new() -> Self {
        Self {
            buf: [0; 256],
            len: 0,
            unrepresentable: false,
        }
    }

    pub fn clear(&mut self) {
        self.len = 0;
        self.unrepresentable = false;
    }

    /// Appends one (non-root) label. Empty labels (the root) are ignored.
    #[inline]
    pub fn push_label(&mut self, label: &[u8]) {
        if label.is_empty() {
            return;
        }
        let sep = usize::from(self.len != 0);
        if self.len + sep + label.len() > self.buf.len() || label.contains(&b'.') {
            self.unrepresentable = true;
            return;
        }
        if sep == 1 {
            self.buf[self.len] = b'.';
            self.len += 1;
        }
        let dst = &mut self.buf[self.len..self.len + label.len()];
        for (d, s) in dst.iter_mut().zip(label) {
            *d = s.to_ascii_lowercase();
        }
        self.len += label.len();
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub fn is_representable(&self) -> bool {
        !self.unrepresentable
    }
}

/// What the zone says about a question. Crate independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// NOERROR, one A record in the answer section.
    Answer(Ipv4Addr),
    /// NOERROR without data for this type (the name exists): SOA in authority.
    NoData,
    /// NXDOMAIN: SOA in authority.
    NxDomain,
    /// NOERROR, the zone SOA in the answer section.
    ApexSoa,
    /// REFUSED: not authoritative for the name or class.
    Refused,
    /// NOTIMP: opcode other than QUERY.
    NotImp,
    /// BADVERS (extended RCODE 16): EDNS version other than 0.
    BadVers,
}

impl Outcome {
    /// The 12-bit RCODE of the response.
    pub fn rcode(self) -> u16 {
        match self {
            Outcome::Answer(_) | Outcome::NoData | Outcome::ApexSoa => 0,
            Outcome::NxDomain => 3,
            Outcome::Refused => 5,
            Outcome::NotImp => 4,
            Outcome::BadVers => 16,
        }
    }
}

/// The zone data: a `HashMap` keyed by the lowercase dotted name.
pub struct Zone {
    size: u32,
    names: HashMap<Box<[u8]>, Ipv4Addr>,
}

impl Zone {
    pub fn new(size: u32) -> Self {
        let mut names = HashMap::with_capacity(size as usize);
        for n in 0..size {
            let name = format!("host-{n}.{APEX}");
            names.insert(name.into_bytes().into_boxed_slice(), Self::address_for(n));
        }
        Self { size, names }
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    /// The A record of `host-{n}`.
    pub fn address_for(n: u32) -> Ipv4Addr {
        const BASES: [[u8; 3]; 3] = [[192, 0, 2], [198, 51, 100], [203, 0, 113]];
        let b = BASES[(n % 3) as usize];
        Ipv4Addr::new(b[0], b[1], b[2], ((n / 3) % 256) as u8)
    }

    /// Answers a question. `key` must have been filled from the query name.
    #[inline]
    pub fn lookup(&self, key: &NameKey, qtype: u16, qclass: u16) -> Outcome {
        const ANY: u16 = 255;
        if qclass != QCLASS_IN && qclass != ANY {
            return Outcome::Refused;
        }
        if !key.is_representable() {
            return Outcome::Refused;
        }
        let name = key.as_bytes();
        let apex = APEX.as_bytes();
        if name == apex {
            return if qtype == QTYPE_SOA || qtype == ANY {
                Outcome::ApexSoa
            } else {
                Outcome::NoData
            };
        }
        let in_zone = name.len() > apex.len()
            && name.ends_with(apex)
            && name[name.len() - apex.len() - 1] == b'.';
        if !in_zone {
            return Outcome::Refused;
        }
        match self.names.get(name) {
            Some(addr) if qtype == QTYPE_A || qtype == ANY => Outcome::Answer(*addr),
            Some(_) => Outcome::NoData,
            None => Outcome::NxDomain,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(s: &str) -> NameKey {
        let mut k = NameKey::new();
        for l in s.split('.') {
            k.push_label(l.as_bytes());
        }
        k
    }

    #[test]
    fn lookups() {
        let z = Zone::new(1000);
        assert_eq!(
            z.lookup(&key("HOST-5.Example.TEST"), QTYPE_A, 1),
            Outcome::Answer(Zone::address_for(5))
        );
        assert_eq!(
            z.lookup(&key("host-5.example.test"), 28, 1),
            Outcome::NoData
        );
        assert_eq!(
            z.lookup(&key("host-5000.example.test"), QTYPE_A, 1),
            Outcome::NxDomain
        );
        assert_eq!(
            z.lookup(&key("example.test"), QTYPE_SOA, 1),
            Outcome::ApexSoa
        );
        assert_eq!(z.lookup(&key("example.org"), QTYPE_A, 1), Outcome::Refused);
        assert_eq!(
            z.lookup(&key("xexample.test"), QTYPE_A, 1),
            Outcome::Refused
        );
        assert_eq!(
            z.lookup(&key("host-5.example.test"), QTYPE_A, 3),
            Outcome::Refused
        );
        let mut k = NameKey::new();
        k.push_label(b"host-5.example");
        k.push_label(b"test");
        assert_eq!(z.lookup(&k, QTYPE_A, 1), Outcome::Refused);
    }
}
