//! Shared builders of the integration tests: zones, RRsets and record data in the model of
//! `tenko_core::dns`, and a small deterministic random generator.

#![allow(dead_code, reason = "each test binary uses a part of the helpers")]

pub mod answer;

use std::net::{Ipv4Addr, Ipv6Addr};

use tenko_core::{
    dns::{
        DnsName, Origin, Rdata, RecordData, RrSet, ScopeName, SoaDefaults, Zone, ZoneId, ZoneKind,
        ZoneScope,
    },
    ipam::Stamp,
    principal::{Principal, SystemComponent},
};
use tenko_dns::NameBuf;

pub fn stamp() -> Stamp {
    Stamp::new(
        "2026-10-17T12:00:00Z".parse().expect("time"),
        Principal::system(SystemComponent::Dns),
    )
}

pub fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

/// The lowercase wire form of a name in presentation form without escapes; any labels,
/// the root for an empty text.
pub fn wire(text: &str) -> Vec<u8> {
    let mut name = NameBuf::root();
    for label in text.split('.').filter(|label| !label.is_empty()) {
        name.push_label(label.as_bytes()).expect("label");
    }
    name.as_wire().to_vec()
}

pub fn internal() -> ScopeName {
    ScopeName::new("internal").expect("scope")
}

pub fn zone(apex: &str) -> Zone {
    Zone {
        id: ZoneId::generate(),
        name: name(apex),
        kind: ZoneKind::Primary,
        tenant: None,
        scopes: vec![
            ZoneScope::default_scope(),
            ZoneScope {
                name: internal(),
                description: None,
            },
        ],
        serial: tenko_core::dns::SerialPolicy::default(),
        soa: SoaDefaults::new(
            name(&format!("ns1.{apex}")),
            name(&format!("hostmaster.{apex}")),
        ),
        transfer: tenko_core::dns::TransferPolicy::default(),
        update: tenko_core::dns::UpdatePolicy::default(),
        dnssec: tenko_core::dns::DnssecPolicy::default(),
        source: None,
        reverse_of: None,
        catalog: false,
        description: None,
        created: stamp(),
        updated: stamp(),
    }
}

pub fn rrset_ttl(
    zone: &Zone,
    scope: &ScopeName,
    owner: &str,
    ttl: u32,
    data: &[RecordData],
) -> RrSet {
    RrSet {
        zone: zone.id,
        scope: scope.clone(),
        name: name(owner),
        rtype: data[0].rtype(),
        ttl,
        rdata: data.iter().map(Rdata::from_data).collect(),
        origin: Origin::Manual,
        key: None,
        updated: stamp(),
    }
}

pub fn rrset(zone: &Zone, scope: &ScopeName, owner: &str, data: &[RecordData]) -> RrSet {
    rrset_ttl(zone, scope, owner, 300, data)
}

pub fn a(last: u8) -> RecordData {
    RecordData::A {
        address: Ipv4Addr::new(192, 0, 2, last),
    }
}

pub fn aaaa(last: u16) -> RecordData {
    RecordData::Aaaa {
        address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last),
    }
}

pub fn cname(target: &str) -> RecordData {
    RecordData::Cname {
        target: name(target),
    }
}

pub fn dname(target: &str) -> RecordData {
    RecordData::Dname {
        target: name(target),
    }
}

pub fn ns(host: &str) -> RecordData {
    RecordData::Ns { host: name(host) }
}

pub fn mx(preference: u16, exchange: &str) -> RecordData {
    RecordData::Mx {
        preference,
        exchange: name(exchange),
    }
}

pub fn txt(text: &str) -> RecordData {
    RecordData::txt(text)
}

pub fn soa(apex: &str, minimum: u32) -> RecordData {
    RecordData::Soa {
        mname: name(&format!("ns1.{apex}")),
        rname: name(&format!("hostmaster.{apex}")),
        serial: 1,
        refresh: 3600,
        retry: 900,
        expire: 1_209_600,
        minimum,
    }
}

/// splitmix64: a deterministic generator for the random tests.
#[derive(Debug, Clone)]
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    /// An index below `len`.
    pub fn index(&mut self, len: usize) -> usize {
        usize::try_from(self.below(len as u64)).unwrap_or(0)
    }

    /// One of the items.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.index(items.len())]
    }

    pub fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}
