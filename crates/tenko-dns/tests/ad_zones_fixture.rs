//! The AD zone fixtures of the Windows takeover (`tests/fixtures/ad-zones/`, WP14.0, plan
//! section 3.4): the three zones of the fictitious domain `corp.example.test` as a zone
//! transfer would bring them to a secondary, derived from the mirror fixture of
//! `tenko-core` so that every DHCP name in the zone stands for a lease or a reservation of
//! the snapshot, two stale names apart.
//!
//! - `corp.example.test.zone`: the apex, the two controllers, the locator records Netlogon
//!   registers, `DomainDnsZones` and `ForestDnsZones`, the static host `tenko1`, and sixty
//!   names Windows DHCP registered, each with an A and a DHCID record (RFC 4701): the
//!   sixteen `laptop-NN` names carry a DHCID of identifier type 1 (option 61 of type 1
//!   with the MAC address), the sixteen `desk-NN` names one of type 0 (`htype` and
//!   `chaddr`), the sixteen `phone-NN` names one of type 2 (the DUID of their RFC 4361
//!   identifier), the ten reserved names one of type 1, and the two stale names
//!   `old-laptop-01` (type 1) and `old-laptop-02` (type 0) stand for no lease or
//!   reservation of the snapshot;
//! - `_msdcs.corp.example.test.zone`: the forest-wide locator records and the DSA GUID
//!   aliases of the controllers;
//! - `2.0.192.in-addr.arpa.zone`: the PTR records of the controllers, the static host, the
//!   sixty names and the two stale addresses.
//!
//! The DHCID values are computed here from RFC 4701 (the identifier type, SHA-256 over the
//! identifier and the canonical name), checked against the RFC's own examples, so that the
//! identity choice of plan section 2.8 can be tested both ways: for a six-octet identifier
//! the takeover computes the type 1 and the type 0 candidate and takes the one that equals
//! the record. Regenerate the files with
//!
//! ```text
//! TENKO_REGENERATE_FIXTURES=1 cargo test -p tenko-dns --test ad_zones_fixture
//! ```

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

use aws_lc_rs::digest::{SHA256, digest};
use tenko_core::{
    dns::{DnsName, Rtype},
    ir::{
        MirrorSnapshot,
        dhcp::{IrLease, IrLeaseState},
    },
};
use tenko_dns::zone::zonefile::{Item, Reader};

/// The zone of the domain.
const ZONE: &str = "corp.example.test";

/// The TTL Windows DHCP gives the records it registers (20 minutes).
const DHCP_TTL: u32 = 1200;

/// The identifier type of a DHCID (RFC 4701, section 3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdType {
    /// `htype` and `chaddr`.
    Chaddr = 0,
    /// Option 61 as sent.
    ClientId = 1,
    /// The DUID of an RFC 4361 identifier.
    Duid = 2,
}

/// The DHCID RDATA of `identifier` (the octets after the type) for `name`.
fn dhcid(kind: IdType, identifier: &[u8], name: &DnsName) -> Vec<u8> {
    let mut input = identifier.to_vec();
    input.extend_from_slice(&name.to_wire());
    let hash = digest(&SHA256, &input);
    let mut out = Vec::with_capacity(35);
    out.extend_from_slice(&(kind as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(hash.as_ref());
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// The generic form of RFC 3597 for a DHCID record.
fn dhcid_text(rdata: &[u8]) -> String {
    format!("\\# {} {}", rdata.len(), hex(rdata))
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("ad-zones")
}

fn mirror_fixture() -> MirrorSnapshot {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tenko-core/tests/fixtures/mirror/snapshot.json");
    let text = fs::read_to_string(&path).expect("the mirror fixture");
    serde_json::from_str(&text).expect("the mirror fixture parses")
}

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("a name")
}

/// A DHCP name of the forward zone: its owner, its address and its DHCID identifier.
#[derive(Debug, Clone)]
struct DhcpName {
    owner: DnsName,
    addr: IpAddr,
    kind: IdType,
    identifier: Vec<u8>,
}

/// The identity a lease of the fixture carries, and how Windows wrote its DHCID: a
/// six-octet identifier of a `laptop-` name as type 1, of a `desk-` or reserved name as
/// type 0 or 1 (see the module), an RFC 4361 identifier as type 2.
fn identity_of(lease: &IrLease, hostname: &str) -> (IdType, Vec<u8>) {
    if let Some(id) = &lease.client.client_id {
        if id.0.first() == Some(&255) && id.0.len() > 5 {
            return (IdType::Duid, id.0[5..].to_vec());
        }
        return (IdType::ClientId, id.0.clone());
    }
    let mac = lease.client.mac.expect("a MAC address").octets();
    if hostname.starts_with("desk-") {
        let mut identifier = vec![1u8];
        identifier.extend_from_slice(&mac);
        (IdType::Chaddr, identifier)
    } else {
        let mut identifier = vec![1u8];
        identifier.extend_from_slice(&mac);
        (IdType::ClientId, identifier)
    }
}

/// The DHCP names of the forward zone, from the leases of the snapshot (the declined ones
/// have no name), plus the two stale names.
fn dhcp_names(snapshot: &MirrorSnapshot) -> Vec<DhcpName> {
    let zone = name(ZONE);
    let mut names: Vec<DhcpName> = snapshot
        .dhcp
        .leases
        .iter()
        .filter(|lease| {
            matches!(
                lease.state,
                IrLeaseState::Active | IrLeaseState::ActiveReservation
            )
        })
        .map(|lease| {
            let hostname = lease.hostname.as_deref().expect("a named lease");
            let lower = hostname.to_ascii_lowercase();
            let owner = if lower.contains('.') {
                name(&lower)
            } else {
                name(&format!("{lower}.{ZONE}"))
            };
            assert!(owner.is_subdomain_of(&zone), "{owner} is in the zone");
            let (kind, identifier) = identity_of(lease, &lower);
            DhcpName {
                owner,
                addr: lease.ip,
                kind,
                identifier,
            }
        })
        .collect();
    // Two stale names: Windows would have scavenged them; no lease or reservation stands
    // behind them.
    for (index, (kind, last)) in [(IdType::ClientId, 0xfe_u8), (IdType::Chaddr, 0xff)]
        .into_iter()
        .enumerate()
    {
        let mut identifier = vec![1u8];
        identifier.extend_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x53, last]);
        names.push(DhcpName {
            owner: name(&format!("old-laptop-{:02}.{ZONE}", index + 1)),
            addr: format!("192.0.2.{}", 198 + index).parse().expect("ip"),
            kind,
            identifier,
        });
    }
    names.sort_by(|a, b| a.owner.as_str().cmp(b.owner.as_str()));
    names
}

/// The locator records Netlogon registers in the domain zone (two controllers, one site).
const LOCATORS: [&str; 11] = [
    "_ldap._tcp",
    "_kerberos._tcp",
    "_kpasswd._tcp",
    "_gc._tcp",
    "_kerberos._udp",
    "_kpasswd._udp",
    "_ldap._tcp.default-first-site-name._sites",
    "_kerberos._tcp.default-first-site-name._sites",
    "_gc._tcp.default-first-site-name._sites",
    "_ldap._tcp.domaindnszones",
    "_ldap._tcp.forestdnszones",
];

fn locator_port(owner: &str) -> u16 {
    if owner.starts_with("_kerberos") {
        88
    } else if owner.starts_with("_kpasswd") {
        464
    } else if owner.starts_with("_gc") {
        3268
    } else {
        389
    }
}

fn soa(out: &mut String, mname: &str) {
    let _ = writeln!(
        out,
        "@ 3600 IN SOA {mname}. hostmaster.corp.example.test. 2026110105 900 600 86400 3600"
    );
    let _ = writeln!(out, "@ 3600 IN NS dc1.corp.example.test.");
    let _ = writeln!(out, "@ 3600 IN NS dc2.corp.example.test.");
}

fn forward_zone(names: &[DhcpName]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "; The AD domain zone {ZONE} as a zone transfer brings it: the controllers' records,"
    );
    let _ = writeln!(
        out,
        "; the names Windows DHCP registered with their DHCID records, two of them stale."
    );
    let _ = writeln!(out, "$ORIGIN {ZONE}.");
    let _ = writeln!(out, "$TTL 3600");
    soa(&mut out, "dc1.corp.example.test");
    let _ = writeln!(out, "@ 600 IN A 192.0.2.5");
    let _ = writeln!(out, "@ 600 IN A 192.0.2.6");
    let _ = writeln!(out, "dc1 3600 IN A 192.0.2.5");
    let _ = writeln!(out, "dc2 3600 IN A 192.0.2.6");
    let _ = writeln!(out, "domaindnszones 600 IN A 192.0.2.5");
    let _ = writeln!(out, "domaindnszones 600 IN A 192.0.2.6");
    let _ = writeln!(out, "forestdnszones 600 IN A 192.0.2.5");
    let _ = writeln!(out, "forestdnszones 600 IN A 192.0.2.6");
    for owner in LOCATORS {
        let port = locator_port(owner);
        for dc in ["dc1", "dc2"] {
            let _ = writeln!(
                out,
                "{owner} 600 IN SRV 0 100 {port} {dc}.corp.example.test."
            );
        }
    }
    let _ = writeln!(out, "tenko1 3600 IN A 192.0.2.53");
    let _ = writeln!(
        out,
        "; The names Windows DHCP registered (name protection on)."
    );
    for item in names {
        let owner = item
            .owner
            .as_str()
            .strip_suffix(&format!(".{ZONE}"))
            .expect("in the zone");
        let _ = writeln!(out, "{owner} {DHCP_TTL} IN A {}", item.addr);
        let rdata = dhcid(item.kind, &item.identifier, &item.owner);
        let _ = writeln!(out, "{owner} {DHCP_TTL} IN DHCID {}", dhcid_text(&rdata));
    }
    out
}

fn msdcs_zone() -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "; The forest-wide zone _msdcs.{ZONE}: the DSA GUID aliases and the locator records."
    );
    let _ = writeln!(out, "$ORIGIN _msdcs.{ZONE}.");
    let _ = writeln!(out, "$TTL 3600");
    soa(&mut out, "dc1.corp.example.test");
    let _ = writeln!(out, "gc 600 IN A 192.0.2.5");
    let _ = writeln!(out, "gc 600 IN A 192.0.2.6");
    for (owner, port) in [
        ("_ldap._tcp.dc", 389),
        ("_kerberos._tcp.dc", 88),
        ("_ldap._tcp.default-first-site-name._sites.dc", 389),
        ("_kerberos._tcp.default-first-site-name._sites.dc", 88),
        ("_ldap._tcp.gc", 3268),
        ("_ldap._tcp.default-first-site-name._sites.gc", 3268),
        (
            "_ldap._tcp.0d9e7f2a-4b1c-4e63-9a8d-2f5c6b7e8a90.domains",
            389,
        ),
    ] {
        for dc in ["dc1", "dc2"] {
            let _ = writeln!(
                out,
                "{owner} 600 IN SRV 0 100 {port} {dc}.corp.example.test."
            );
        }
    }
    let _ = writeln!(
        out,
        "_ldap._tcp.pdc 600 IN SRV 0 100 389 dc1.corp.example.test."
    );
    let _ = writeln!(
        out,
        "6f1c2e3d-8a9b-4c5d-9e0f-1a2b3c4d5e6f 600 IN CNAME dc1.corp.example.test."
    );
    let _ = writeln!(
        out,
        "7a2d3f4e-9b0c-4d6e-8f1a-2b3c4d5e6f70 600 IN CNAME dc2.corp.example.test."
    );
    out
}

fn reverse_zone(names: &[DhcpName]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "; The reverse zone of the client network: the controllers, the static host, the"
    );
    let _ = writeln!(
        out,
        "; names Windows DHCP registered and the two stale addresses."
    );
    let _ = writeln!(out, "$ORIGIN 2.0.192.in-addr.arpa.");
    let _ = writeln!(out, "$TTL 3600");
    soa(&mut out, "dc1.corp.example.test");
    let mut ptrs: BTreeMap<u8, String> = BTreeMap::new();
    ptrs.insert(5, "dc1.corp.example.test".to_owned());
    ptrs.insert(6, "dc2.corp.example.test".to_owned());
    ptrs.insert(53, "tenko1.corp.example.test".to_owned());
    for item in names {
        let IpAddr::V4(addr) = item.addr else {
            panic!("an IPv4 address");
        };
        ptrs.insert(addr.octets()[3], item.owner.as_str().to_owned());
    }
    for (last, target) in ptrs {
        let ttl = if last == 5 || last == 6 || last == 53 {
            3600
        } else {
            DHCP_TTL
        };
        let _ = writeln!(out, "{last} {ttl} IN PTR {target}.");
    }
    out
}

/// Every record of a zone file.
fn read(text: &str, apex: &str) -> Vec<(DnsName, Rtype, u32, Vec<u8>)> {
    let apex = name(apex);
    let mut reader = Reader::new(text, &apex, 65_536).expect("a reader");
    let mut out = Vec::new();
    while let Some(item) = reader.next_item().expect("the file parses") {
        match item {
            Item::Record(record) => out.push((
                record.name,
                record.rtype,
                record.ttl,
                record.rdata.as_bytes().to_vec(),
            )),
            Item::Loss(loss) => panic!("a loss in the fixture: {loss:?}"),
        }
    }
    out
}

const DHCID: Rtype = Rtype(49);

#[test]
fn the_fixture_zones_are_the_contract() {
    let regenerate = std::env::var_os("TENKO_REGENERATE_FIXTURES").is_some();
    let snapshot = mirror_fixture();
    let names = dhcp_names(&snapshot);
    assert_eq!(names.len(), 60, "sixty DHCP names, two of them stale");
    let files = [
        ("corp.example.test.zone", forward_zone(&names), ZONE),
        (
            "_msdcs.corp.example.test.zone",
            msdcs_zone(),
            "_msdcs.corp.example.test",
        ),
        (
            "2.0.192.in-addr.arpa.zone",
            reverse_zone(&names),
            "2.0.192.in-addr.arpa",
        ),
    ];
    for (file, text, apex) in &files {
        let path = fixtures().join(file);
        if regenerate {
            fs::create_dir_all(fixtures()).expect("the directory");
            fs::write(&path, text).expect("write the fixture");
        }
        let stored = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{}: {error}; regenerate it", path.display()));
        assert_eq!(
            &stored, text,
            "{file} differs from what the generator writes"
        );
        let records = read(&stored, apex);
        assert!(records.iter().any(|(_, rtype, ..)| *rtype == Rtype::SOA));
        assert_eq!(
            records
                .iter()
                .filter(|(_, rtype, ..)| *rtype == Rtype::NS)
                .count(),
            2
        );
    }

    // The forward zone: sixty A and DHCID pairs with the DHCID computed as RFC 4701 says.
    let forward = read(&files[0].1, ZONE);
    let dhcids: Vec<_> = forward
        .iter()
        .filter(|(_, rtype, ..)| *rtype == DHCID)
        .collect();
    assert_eq!(dhcids.len(), 60);
    for item in &names {
        let (_, _, ttl, rdata) = dhcids
            .iter()
            .find(|(owner, ..)| *owner == item.owner)
            .unwrap_or_else(|| panic!("{} has a DHCID", item.owner));
        assert_eq!(*ttl, DHCP_TTL);
        assert_eq!(**rdata, dhcid(item.kind, &item.identifier, &item.owner));
        assert_eq!(rdata.len(), 35);
        assert_eq!(rdata[..2], (item.kind as u16).to_be_bytes());
        assert!(
            forward
                .iter()
                .any(|(owner, rtype, _, data)| *owner == item.owner
                    && *rtype == Rtype::A
                    && IpAddr::from(<[u8; 4]>::try_from(data.as_slice()).expect("four"))
                        == item.addr),
            "{} has its A record",
            item.owner
        );
    }
    let by_kind = |kind: IdType| names.iter().filter(|item| item.kind == kind).count();
    assert_eq!(by_kind(IdType::ClientId), 16 + 10 + 1);
    assert_eq!(by_kind(IdType::Chaddr), 16 + 1);
    assert_eq!(by_kind(IdType::Duid), 16);

    // The reverse zone: one PTR per DHCP name and per controller.
    let reverse = read(&files[2].1, "2.0.192.in-addr.arpa");
    assert_eq!(
        reverse
            .iter()
            .filter(|(_, rtype, ..)| *rtype == Rtype::PTR)
            .count(),
        60 + 3
    );
}

/// The identity choice of plan section 2.8: for a six-octet identifier, the type 1 and the
/// type 0 candidate differ, and exactly one equals the record Windows wrote.
#[test]
fn a_six_octet_identifier_is_told_apart_by_the_record() {
    let snapshot = mirror_fixture();
    let names = dhcp_names(&snapshot);
    let laptop = names
        .iter()
        .find(|item| item.owner.as_str().starts_with("laptop-01."))
        .expect("laptop-01");
    let desk = names
        .iter()
        .find(|item| item.owner.as_str().starts_with("desk-01."))
        .expect("desk-01");
    for (item, written) in [(laptop, IdType::ClientId), (desk, IdType::Chaddr)] {
        let record = dhcid(item.kind, &item.identifier, &item.owner);
        // Both candidates are built from the MAC address alone: `01` and the MAC as option
        // 61 of type 1, `htype` 1 and the MAC as `chaddr`. Their octets happen to be the
        // same; the identifier type in the record tells them apart.
        let type1 = dhcid(IdType::ClientId, &item.identifier, &item.owner);
        let type0 = dhcid(IdType::Chaddr, &item.identifier, &item.owner);
        assert_ne!(type1, type0);
        assert_eq!(record == type1, written == IdType::ClientId);
        assert_eq!(record == type0, written == IdType::Chaddr);
    }
}

/// The DHCID computation against the examples of RFC 4701, section 3.6.
#[test]
fn the_dhcid_computation_matches_the_rfc() {
    fn base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }
    assert_eq!(
        base64(&dhcid(
            IdType::Duid,
            &[0, 1, 0, 6, 0x41, 0x2d, 0xf1, 0x66, 1, 2, 3, 4, 5, 6],
            &name("chi6.example.com"),
        )),
        "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA="
    );
    assert_eq!(
        base64(&dhcid(
            IdType::ClientId,
            &[1, 7, 8, 9, 10, 11, 12],
            &name("chi.example.com"),
        )),
        "AAEBOSD+XR3Os/0LozeXVqcNc7FwCfQdWL3b/NaiUDlW2No="
    );
    assert_eq!(
        base64(&dhcid(
            IdType::Chaddr,
            &[1, 1, 2, 3, 4, 5, 6],
            &name("client.example.com"),
        )),
        "AAABxLmlskllE0MVjd57zHcWmEH3pCQ6VytcKD//7es/deY="
    );
}
