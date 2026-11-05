//! The envelope of a mirrored source (`tenko_core::ir::MirrorSnapshot`, WP14.0): the fixture
//! `tests/fixtures/mirror/snapshot.json` is the contract between the exporter of
//! `deploy/windows/mirror/` and this crate, so this test holds the file to the types byte
//! for byte, checks that it validates and round-trips through JSON and CBOR, that every
//! field the exporter fills parses (a Windows host name with uppercase letters, an option
//! value's text form, an uppercase client identifier), that an unknown field on the
//! envelope is refused, and with random snapshots that validation accepts what the
//! builder makes and names the path of the first error otherwise.
//!
//! The fixture (plan section 3.4): the fictitious domain `corp.example.test`, one scope
//! `192.0.2.0/24`, thirty reservations named in every way of section 2.9, sixty leases over
//! the identity kinds (a six-octet identifier for a client that sends option 61 of type 1 or
//! none, an RFC 4361 identifier), options at the server, scope and reservation level, and
//! one policy, one filter and one superscope in the loss report. `snapshot-inactive.json`
//! is the same with the scope inactive, one sequence and one minute later. Regenerate both
//! with
//!
//! ```text
//! TENKO_REGENERATE_FIXTURES=1 cargo test -p tenko-core --test mirror_model
//! ```
//!
//! and review the diff: the exporter's Pester suite produces these bytes from recorded
//! cmdlet output, so a change here is a change of the contract.

use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
};

use ipnet::IpNet;
use proptest::prelude::*;
use tenko_core::{
    Coded, MacAddr, Timestamp,
    codec::{from_cbor, to_cbor},
    dhcp::{DdnsConflict, DdnsPolicy, OptionKind},
    ir::{
        LossEntry, LossReport, MirrorOrigin, MirrorSnapshot, SourceKindLabel, SourceLocation,
        dhcp::{
            DhcpIr, IrClientId, IrLease, IrLeaseState, IrOption, IrOptionDef, IrRange,
            IrReservation, IrScope,
        },
        mirror::{FORMAT, MAX_LEASES, MAX_SCOPES},
    },
    migrate::losses,
    net::HostName,
    serde_util::HexBytes,
};

// ---------------------------------------------------------------------------------------
// The fixture

/// The zone of the fictitious domain.
const ZONE: &str = "corp.example.test";

/// The scope.
const SCOPE: &str = "192.0.2.0/24";

/// When the exporter read the source.
const TAKEN_AT: &str = "2026-11-01T08:00:00Z";

/// The fixture directory.
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("mirror")
}

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
}

fn scope() -> IpNet {
    SCOPE.parse().expect("the scope")
}

fn at(text: &str) -> Timestamp {
    text.parse().expect("a time")
}

/// A MAC address of the RFC 7042 documentation range.
fn mac(last: u8) -> MacAddr {
    MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, last])
}

/// An RFC 4361 client identifier: type 255, the IAID, a DUID-LLT over the MAC address.
fn rfc4361(last: u8) -> HexBytes {
    let mut id = vec![255, 0, 0, 0, 1];
    // DUID-LLT: type 1, hardware type 1, a time, the link-layer address.
    id.extend_from_slice(&[0, 1, 0, 1, 0x2e, 0x5a, 0x1c, 0x40]);
    id.extend_from_slice(&mac(last).octets());
    HexBytes(id)
}

fn location(cmdlet: &str, key: &str) -> SourceLocation {
    SourceLocation {
        sheet: Some(cmdlet.to_owned()),
        row: None,
        column: Some(key.to_owned()),
    }
}

fn option(code: u16, values: &[&str]) -> IrOption {
    IrOption {
        code,
        vendor_class: None,
        user_class: None,
        values: values.iter().map(|value| (*value).to_owned()).collect(),
        origin: location("Get-DhcpServerv4OptionValue", &format!("OptionId={code}")),
    }
}

fn ddns() -> DdnsPolicy {
    DdnsPolicy {
        enabled: true,
        forward_zone: None,
        reverse: true,
        ttl: None,
        conflict: DdnsConflict::Protect,
        client_may_update_a: false,
        legacy_clients: true,
        refuse_foreign: false,
    }
}

/// The thirty reservations, named in every way of section 2.9: bare names (0 to 9, which
/// also hold a lease), fully qualified names under the zone (10 to 14), fully qualified
/// names the source wrote in mixed case (15 to 17, lowercased by the host name type),
/// fully qualified names outside the zone (18 to 20), factory names that are valid labels
/// (21 to 24), names that are not host names (25 to 27, kept in `source_name`) and no name
/// (28 and 29). Reservations 25 to 29 are keyed by an RFC 4361 identifier, the others by
/// their MAC address.
fn reservations() -> Vec<IrReservation> {
    const BARE: [&str; 10] = [
        "printer01",
        "printer02",
        "nas01",
        "nas02",
        "switch01",
        "ap01",
        "ap02",
        "cam01",
        "cam02",
        "tv01",
    ];
    const QUALIFIED: [&str; 5] = [
        "scanner01.corp.example.test",
        "plotter01.corp.example.test",
        "nvr01.corp.example.test",
        "ups01.corp.example.test",
        "pdu01.corp.example.test",
    ];
    const MIXED_CASE: [&str; 3] = [
        "MEDIA01.corp.example.test",
        "Thermostat01.Corp.Example.Test",
        "DOORBELL01.CORP.EXAMPLE.TEST",
    ];
    const FOREIGN: [&str; 3] = [
        "backup01.lab.example.test",
        "router01.example.net",
        "kiosk01.other.example.test",
    ];
    const FACTORY: [&str; 4] = [
        "ESP_3A1F2B",
        "android-5f2c9e01d4a6b7c8",
        "RPI-4B",
        "DESKTOP-7Q2M9K1",
    ];
    const NOT_NAMES: [&str; 3] = ["Living Room TV", "Bob's iPad", "cam 03"];
    (0u8..30)
        .map(|index| {
            let last = 10 + index;
            let name = match index {
                0..=9 => Some(BARE[usize::from(index)]),
                10..=14 => Some(QUALIFIED[usize::from(index - 10)]),
                15..=17 => Some(MIXED_CASE[usize::from(index - 15)]),
                18..=20 => Some(FOREIGN[usize::from(index - 18)]),
                21..=24 => Some(FACTORY[usize::from(index - 21)]),
                _ => None,
            };
            let client = if index >= 25 {
                IrClientId {
                    mac: None,
                    client_id: Some(rfc4361(last)),
                }
            } else {
                IrClientId {
                    mac: Some(mac(last)),
                    client_id: None,
                }
            };
            let options = match index {
                0 => vec![option(3, &["192.0.2.254"])],
                10 => vec![
                    option(66, &["boot.corp.example.test"]),
                    option(67, &["lpxelinux.0"]),
                ],
                _ => Vec::new(),
            };
            IrReservation {
                ip: ip(last),
                client,
                name: name.map(|name| HostName::new(name).expect("a host name")),
                source_name: match index {
                    25..=27 => Some(NOT_NAMES[usize::from(index - 25)].to_owned()),
                    _ => None,
                },
                description: match index {
                    28 => Some("Guest printer".to_owned()),
                    29 => Some("BOOTP terminal".to_owned()),
                    _ => None,
                },
                bootp: index == 29,
                options,
                origin: location(
                    "Get-DhcpServerv4Reservation",
                    &format!("IPAddress=192.0.2.{last}"),
                ),
            }
        })
        .collect()
}

/// The identity kind of a lease of the fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    /// A six-octet identifier: option 61 of type 1 with the MAC address, or no option 61;
    /// the mirror cannot tell them apart (section 2.8).
    Mac,
    /// An RFC 4361 identifier (type 255, the IAID, a DUID).
    Duid,
}

/// The sixty leases: forty-eight pool leases at `192.0.2.110` to `.157` (the first
/// thirty-two keyed by a MAC address, the next sixteen by an RFC 4361 identifier), ten
/// leases of the reservations with a bare name (`192.0.2.10` to `.19`) and two declined
/// addresses (`192.0.2.158` and `.159`).
fn leases() -> Vec<IrLease> {
    let taken_at = at(TAKEN_AT);
    let scope = scope();
    let mut out = Vec::new();
    for index in 0u8..48 {
        let last = 110 + index;
        let (client, hostname) = if index < 16 {
            (
                IrClientId {
                    mac: Some(mac(0x40 + index)),
                    client_id: None,
                },
                format!("LAPTOP-{:02}.corp.example.test", index + 1),
            )
        } else if index < 32 {
            (
                IrClientId {
                    mac: Some(mac(0x40 + index)),
                    client_id: None,
                },
                format!("desk-{:02}.corp.example.test", index - 15),
            )
        } else {
            (
                IrClientId {
                    mac: None,
                    client_id: Some(rfc4361(0x40 + index)),
                },
                format!("phone-{:02}", index - 31),
            )
        };
        // One to eight days left, in steps of two and a half hours.
        let remaining = 86_400 + u64::from(index) * 9_000;
        out.push(IrLease {
            ip: ip(last),
            scope,
            client,
            hostname: Some(hostname),
            expires: taken_at.checked_add(std::time::Duration::from_secs(remaining)),
            state: IrLeaseState::Active,
            origin: location(
                "Get-DhcpServerv4Lease",
                &format!("IPAddress=192.0.2.{last}"),
            ),
        });
    }
    for (index, reservation) in reservations().into_iter().take(10).enumerate() {
        let last = 10 + u8::try_from(index).expect("ten");
        out.push(IrLease {
            ip: reservation.ip,
            scope,
            client: reservation.client,
            hostname: Some(format!(
                "{}.corp.example.test",
                reservation.name.expect("a bare name")
            )),
            expires: None,
            state: IrLeaseState::ActiveReservation,
            origin: location(
                "Get-DhcpServerv4Lease",
                &format!("IPAddress=192.0.2.{last}"),
            ),
        });
    }
    for index in 0u8..2 {
        let last = 158 + index;
        out.push(IrLease {
            ip: ip(last),
            scope,
            client: IrClientId {
                mac: Some(mac(0x70 + index)),
                client_id: None,
            },
            hostname: None,
            expires: taken_at.checked_add(std::time::Duration::from_secs(3_600)),
            state: IrLeaseState::Declined,
            origin: location(
                "Get-DhcpServerv4Lease",
                &format!("IPAddress=192.0.2.{last}"),
            ),
        });
    }
    out
}

fn loss(cmdlet: &str, key: &str, code: &'static str, detail: &str) -> LossEntry {
    LossEntry {
        location: location(cmdlet, key),
        code: std::borrow::Cow::Borrowed(code),
        detail: detail.to_owned(),
    }
}

/// The snapshot of the fixture; `active` is the state of the source's scope.
#[allow(clippy::too_many_lines, reason = "the fixture, read top to bottom")]
fn fixture(active: bool) -> MirrorSnapshot {
    let scope = IrScope {
        cidr: scope(),
        name: Some("Office".to_owned()),
        description: Some("Clients of the office network".to_owned()),
        active,
        lease_secs: Some(691_200),
        ranges: vec![IrRange {
            first: ip(100),
            last: ip(199),
        }],
        exclusions: vec![IrRange {
            first: ip(100),
            last: ip(109),
        }],
        reservations: reservations(),
        options: vec![
            option(3, &["192.0.2.1"]),
            option(6, &["192.0.2.5", "192.0.2.6"]),
            option(15, &[ZONE]),
            option(42, &["192.0.2.5"]),
            IrOption {
                code: 1,
                vendor_class: Some("Microsoft Windows 2000 Options".to_owned()),
                user_class: None,
                values: vec!["1".to_owned()],
                origin: location(
                    "Get-DhcpServerv4OptionValue",
                    "OptionId=1,VendorClass=Microsoft Windows 2000 Options",
                ),
            },
        ],
        ddns: Some(ddns()),
        superscope: None,
        restricted: false,
        delay_ms: 0,
        origin: location("Get-DhcpServerv4Scope", "ScopeId=192.0.2.0"),
    };
    let dhcp = DhcpIr {
        server_options: vec![
            option(6, &["192.0.2.5", "192.0.2.6"]),
            option(15, &[ZONE]),
            option(252, &["http://wpad.corp.example.test/wpad.dat"]),
        ],
        server_ddns: Some(ddns()),
        option_defs: vec![IrOptionDef {
            code: 252,
            name: "WPAD".to_owned(),
            kind: OptionKind::String,
            array: false,
            vendor_class: None,
            description: Some("Web proxy auto-discovery URL".to_owned()),
            origin: location("Get-DhcpServerv4OptionDefinition", "OptionId=252"),
        }],
        classes: Vec::new(),
        scopes: vec![scope],
        superscopes: Vec::new(),
        policies: Vec::new(),
        filters: Vec::new(),
        failover: Vec::new(),
        leases: leases(),
    };
    let losses = LossReport {
        entries: vec![
            loss(
                "Get-DhcpServerv4Policy",
                "Name=Printers",
                losses::POLICY,
                "the policy `Printers` of scope 192.0.2.0 (enabled, vendor class `HP Printers`) is not carried; policies go to the loss report",
            ),
            loss(
                "Get-DhcpServerv4Filter",
                "MacAddress=00-00-5E-00-53-F0",
                losses::FILTER,
                "the deny filter for `00-00-5E-00-53-F0` (`Rogue AP`) is not carried; filters go to the loss report",
            ),
            loss(
                "Get-DhcpServerv4Superscope",
                "SuperscopeName=Campus",
                losses::SUPERSCOPE,
                "the superscope `Campus` over 192.0.2.0 is not carried; superscopes go to the loss report",
            ),
            loss(
                "Get-DhcpServerv4Lease",
                "IPAddress=192.0.2.198",
                losses::LEASE_STATE,
                "the lease of 192.0.2.198 is in the state `Offered`, which the mirror does not carry",
            ),
        ],
    };
    MirrorSnapshot {
        format: FORMAT,
        sequence: if active { 1 } else { 2 },
        taken_at: if active {
            at(TAKEN_AT)
        } else {
            at("2026-11-01T08:01:00Z")
        },
        source: MirrorOrigin {
            kind: SourceKindLabel::new(SourceKindLabel::WINDOWS_DHCP).expect("a label"),
            server: "dc1.corp.example.test".to_owned(),
            adapter: "Tenko-DhcpMirror.ps1".to_owned(),
            adapter_version: "0.1.0".to_owned(),
        },
        dhcp,
        losses,
    }
}

fn pretty(snapshot: &MirrorSnapshot) -> String {
    format!(
        "{}\n",
        serde_json::to_string_pretty(snapshot).expect("the snapshot serializes")
    )
}

#[test]
fn the_fixture_is_the_contract() {
    let regenerate = std::env::var_os("TENKO_REGENERATE_FIXTURES").is_some();
    for (name, active) in [("snapshot.json", true), ("snapshot-inactive.json", false)] {
        let path = fixtures().join(name);
        let built = fixture(active);
        built.validate().expect("the fixture validates");
        let text = pretty(&built);
        if regenerate {
            fs::create_dir_all(fixtures()).expect("the directory");
            fs::write(&path, &text).expect("write the fixture");
        }
        let stored = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{}: {error}; regenerate it", path.display()));
        assert_eq!(stored, text, "{name} differs from what the types write");
        let parsed: MirrorSnapshot = serde_json::from_str(&stored).expect("the fixture parses");
        assert_eq!(parsed, built);
        parsed.validate().expect("the parsed fixture validates");
        assert_eq!(
            from_cbor::<MirrorSnapshot>(&to_cbor(&parsed).expect("cbor")).expect("cbor"),
            parsed
        );
        assert_eq!(parsed.dhcp.scopes.len(), 1);
        assert_eq!(parsed.dhcp.scopes[0].active, active);
        assert_eq!(parsed.reservation_count(), 30);
        assert_eq!(parsed.dhcp.leases.len(), 60);
        assert_eq!(parsed.losses.entries.len(), 4);
    }
}

#[test]
fn the_fixture_holds_every_way_of_naming_and_every_identity_kind() {
    let snapshot = fixture(true);
    let scope = &snapshot.dhcp.scopes[0];
    let names: Vec<Option<&str>> = scope
        .reservations
        .iter()
        .map(|reservation| reservation.name.as_ref().map(HostName::as_str))
        .collect();
    // Bare names, fully qualified names under the zone, mixed case lowercased, foreign
    // names, factory names kept as they are, names that are not host names, no name.
    assert_eq!(names[0], Some("printer01"));
    assert_eq!(names[10], Some("scanner01.corp.example.test"));
    assert_eq!(names[15], Some("media01.corp.example.test"));
    assert_eq!(names[16], Some("thermostat01.corp.example.test"));
    assert_eq!(names[18], Some("backup01.lab.example.test"));
    assert_eq!(names[21], Some("esp_3a1f2b"));
    assert_eq!(names[22], Some("android-5f2c9e01d4a6b7c8"));
    assert_eq!(names[25], None);
    assert_eq!(
        scope.reservations[25].source_name.as_deref(),
        Some("Living Room TV")
    );
    assert_eq!(names[28], None);
    assert_eq!(scope.reservations[28].source_name, None);
    assert!(scope.reservations[29].bootp);
    assert!(scope.reservations[25].client.client_id.is_some());
    assert!(scope.reservations[0].client.mac.is_some());
    // Options at the three levels.
    assert_eq!(snapshot.dhcp.server_options.len(), 3);
    assert_eq!(scope.options.len(), 5);
    assert_eq!(scope.reservations[10].options.len(), 2);
    assert!(snapshot.dhcp.server_ddns.is_some() && scope.ddns.is_some());
    // The leases: thirty-two six-octet identities, sixteen RFC 4361 identities, ten of
    // reservations, two declined.
    let by_kind = |kind: Identity| {
        snapshot
            .dhcp
            .leases
            .iter()
            .filter(|lease| lease.state == IrLeaseState::Active)
            .filter(|lease| match kind {
                Identity::Mac => lease.client.mac.is_some(),
                Identity::Duid => lease
                    .client
                    .client_id
                    .as_ref()
                    .is_some_and(|id| id.0.first() == Some(&255)),
            })
            .count()
    };
    assert_eq!(by_kind(Identity::Mac), 32);
    assert_eq!(by_kind(Identity::Duid), 16);
    assert_eq!(
        snapshot
            .dhcp
            .leases
            .iter()
            .filter(|lease| lease.state == IrLeaseState::ActiveReservation)
            .count(),
        10
    );
    assert_eq!(
        snapshot
            .dhcp
            .leases
            .iter()
            .filter(|lease| lease.state == IrLeaseState::Declined)
            .count(),
        2
    );
    // A Windows host name with uppercase letters is kept as the source wrote it.
    assert_eq!(
        snapshot.dhcp.leases[0].hostname.as_deref(),
        Some("LAPTOP-01.corp.example.test")
    );
    // The loss report names the policy, the filter, the superscope and a lease state.
    let codes: Vec<&str> = snapshot
        .losses
        .entries
        .iter()
        .map(|entry| entry.code.as_ref())
        .collect();
    assert_eq!(
        codes,
        [
            losses::POLICY,
            losses::FILTER,
            losses::SUPERSCOPE,
            losses::LEASE_STATE
        ]
    );
    assert_eq!(
        snapshot.losses.entries[0].key(),
        "Get-DhcpServerv4Policy, column Name=Printers|migrate.loss.policy"
    );
}

#[test]
fn what_the_exporter_writes_parses() {
    // A reservation name in uppercase, as Windows shows it, parses and is lowercased.
    let reservation: IrReservation = serde_json::from_str(
        r#"{"ip":"192.0.2.10","client":{"mac":"00:00:5E:00:53:10"},"name":"NAS01.Corp.Example.Test"}"#,
    )
    .expect("parses");
    assert_eq!(
        reservation.name.as_ref().map(HostName::as_str),
        Some("nas01.corp.example.test")
    );
    assert_eq!(reservation.client.mac, Some(mac(0x10)));
    // A client identifier in uppercase hexadecimal, with or without separators.
    let client: IrClientId =
        serde_json::from_str(r#"{"client_id":"FF00000100010001AABBCCDD"}"#).expect("parses");
    assert_eq!(client.client_id.expect("id").0[0], 255);
    let client: IrClientId =
        serde_json::from_str(r#"{"client_id":"ff-00-00-00-01"}"#).expect("parses");
    assert_eq!(client.client_id.expect("id").0.len(), 5);
    // An option value's text form is any text: an address list, a name, a number, a URL.
    let option: IrOption =
        serde_json::from_str(r#"{"code":121,"values":["24,192.0.2.0,192.0.2.1","0,192.0.2.1"]}"#)
            .expect("parses");
    assert_eq!(option.values.len(), 2);
    // A MAC address in Windows' form, with hyphens and uppercase.
    let client: IrClientId =
        serde_json::from_str(r#"{"mac":"00-00-5E-00-53-2A"}"#).expect("parses");
    assert_eq!(client.mac, Some(mac(0x2a)));
    // A name with a space is not a host name: the exporter puts it in `source_name`.
    assert!(
        serde_json::from_str::<IrReservation>(
            r#"{"ip":"192.0.2.10","client":{"mac":"00:00:5e:00:53:10"},"name":"Living Room TV"}"#,
        )
        .is_err()
    );
    // A lease time of the exporter's `Get-DhcpServerv4Lease`: an RFC 3339 time in UTC.
    let lease: IrLease = serde_json::from_str(
        r#"{"ip":"192.0.2.110","scope":"192.0.2.0/24","client":{"mac":"00:00:5e:00:53:40"},"hostname":"LAPTOP-01","expires":"2026-11-02T08:00:00Z","state":"active"}"#,
    )
    .expect("parses");
    assert_eq!(lease.state, IrLeaseState::Active);
}

#[test]
fn an_unknown_field_on_the_envelope_is_refused() {
    let text = pretty(&fixture(true));
    let with_extra = text.replacen("\"format\": 1,", "\"format\": 1,\n  \"extra\": true,", 1);
    let error = serde_json::from_str::<MirrorSnapshot>(&with_extra).expect_err("refused");
    assert!(error.to_string().contains("extra"), "{error}");
    let with_extra = text.replacen(
        "\"kind\": \"windows-dhcp\",",
        "\"kind\": \"windows-dhcp\",\n    \"host\": \"dc1\",",
        1,
    );
    let error = serde_json::from_str::<MirrorSnapshot>(&with_extra).expect_err("refused");
    assert!(error.to_string().contains("host"), "{error}");
    // A label that is not `[a-z0-9-]{1,32}` is refused while parsing.
    let bad_kind = text.replacen("\"windows-dhcp\"", "\"Windows DHCP\"", 1);
    assert!(serde_json::from_str::<MirrorSnapshot>(&bad_kind).is_err());
    assert!(SourceKindLabel::new("kea").is_ok());
    assert!(SourceKindLabel::new("").is_err());
    assert!(SourceKindLabel::new(&"a".repeat(33)).is_err());
}

#[test]
fn validation_names_the_path_of_the_first_error() {
    let snapshot = fixture(true);
    let path = |snapshot: &MirrorSnapshot| {
        let error = snapshot.validate().expect_err("invalid");
        assert_eq!(error.code(), "migrate.mirror.invalid");
        assert_eq!(error.http_status(), 422);
        assert_eq!(error.params()["path"], error.path);
        error.path
    };
    let mut bad = snapshot.clone();
    bad.format = 2;
    assert_eq!(path(&bad), "format");
    let mut bad = snapshot.clone();
    bad.sequence = 0;
    assert_eq!(path(&bad), "sequence");
    let mut bad = snapshot.clone();
    bad.source.server = String::new();
    assert_eq!(path(&bad), "source.server");
    let mut bad = snapshot.clone();
    bad.source.adapter_version = "1\n".to_owned();
    assert_eq!(path(&bad), "source.adapter_version");
    let mut bad = snapshot.clone();
    bad.dhcp.scopes[0].ranges[0].last = ip(200);
    bad.dhcp.scopes[0].ranges[0].first = ip(201);
    assert_eq!(path(&bad), "dhcp.scopes[0].ranges[0]");
    let mut bad = snapshot.clone();
    bad.dhcp.scopes[0].exclusions.push(IrRange {
        first: "198.51.100.1".parse().expect("ip"),
        last: "198.51.100.2".parse().expect("ip"),
    });
    assert_eq!(path(&bad), "dhcp.scopes[0].exclusions[1]");
    let mut bad = snapshot.clone();
    bad.dhcp.scopes[0].cidr = "192.0.2.1/24".parse().expect("net");
    assert_eq!(path(&bad), "dhcp.scopes[0].cidr");
    let mut bad = snapshot.clone();
    bad.dhcp.scopes[0].reservations[3].client = IrClientId {
        mac: None,
        client_id: None,
    };
    assert_eq!(path(&bad), "dhcp.scopes[0].reservations[3].client");
    let mut bad = snapshot.clone();
    bad.dhcp.scopes[0].reservations[4].ip = bad.dhcp.scopes[0].reservations[2].ip;
    assert_eq!(path(&bad), "dhcp.scopes[0].reservations[4].ip");
    let mut bad = snapshot.clone();
    bad.dhcp.scopes[0].options[1].values.clear();
    assert_eq!(path(&bad), "dhcp.scopes[0].options[1].values");
    let mut bad = snapshot.clone();
    bad.dhcp.server_options[0].code = 0;
    assert_eq!(path(&bad), "dhcp.server_options[0].code");
    let mut bad = snapshot.clone();
    bad.dhcp.leases[5].scope = "198.51.100.0/24".parse().expect("net");
    assert_eq!(path(&bad), "dhcp.leases[5].scope");
    let mut bad = snapshot.clone();
    bad.dhcp.leases[5].ip = ip(200);
    bad.dhcp.leases[6].ip = ip(200);
    assert_eq!(path(&bad), "dhcp.leases[6].ip");
    let mut bad = snapshot.clone();
    bad.dhcp.leases[7].state = IrLeaseState::Other;
    assert_eq!(path(&bad), "dhcp.leases[7].state");
    let mut bad = snapshot.clone();
    bad.dhcp.leases[8].expires = None;
    assert_eq!(path(&bad), "dhcp.leases[8].expires");
    let mut bad = snapshot.clone();
    bad.dhcp.leases[9].hostname = Some("x".repeat(256));
    assert_eq!(path(&bad), "dhcp.leases[9].hostname");
    let mut bad = snapshot.clone();
    bad.dhcp
        .superscopes
        .push(tenko_core::ir::dhcp::IrSuperscope {
            name: "Campus".to_owned(),
            scopes: vec!["198.51.100.0/24".parse().expect("net")],
            origin: SourceLocation::default(),
        });
    assert_eq!(path(&bad), "dhcp.superscopes[0].scopes[0]");
    let mut bad = snapshot.clone();
    bad.losses.entries[2].code = std::borrow::Cow::Borrowed("");
    assert_eq!(path(&bad), "losses.entries[2].code");
    // The bounds.
    let mut bad = snapshot.clone();
    let template = bad.dhcp.leases[0].clone();
    bad.dhcp.leases = (0..=MAX_LEASES).map(|_| template.clone()).collect();
    assert_eq!(path(&bad), "dhcp.leases");
    let mut bad = snapshot;
    let template = bad.dhcp.scopes[0].clone();
    bad.dhcp.scopes = (0..=MAX_SCOPES).map(|_| template.clone()).collect();
    assert_eq!(path(&bad), "dhcp.scopes");
}

// ---------------------------------------------------------------------------------------
// Random snapshots

fn label() -> impl Strategy<Value = String> {
    "[a-z0-9-]{1,32}"
}

fn plain_text(max: usize) -> impl Strategy<Value = String> {
    prop::string::string_regex(&format!("[A-Za-z0-9 ._-]{{1,{max}}}")).expect("a regex")
}

/// A small valid snapshot: one to three IPv4 /24 scopes of the documentation ranges, each
/// with ranges inside it, reservations and leases keyed by either identity kind.
#[allow(clippy::too_many_lines, reason = "one strategy, read top to bottom")]
fn snapshot() -> impl Strategy<Value = MirrorSnapshot> {
    let networks =
        prop::sample::subsequence(vec![[192u8, 0, 2], [198, 51, 100], [203, 0, 113]], 1..=3);
    let scope = |net: [u8; 3]| {
        let host = move |last: u8| IpAddr::V4(Ipv4Addr::new(net[0], net[1], net[2], last));
        (
            prop::collection::vec((any::<u8>(), any::<u8>()), 0..3),
            prop::collection::vec(
                (
                    0u8..30,
                    any::<u8>(),
                    any::<bool>(),
                    prop::option::of(label()),
                ),
                0..6,
            ),
            prop::collection::vec(
                (
                    100u8..200,
                    any::<u8>(),
                    any::<bool>(),
                    prop::sample::select(vec![
                        IrLeaseState::Active,
                        IrLeaseState::ActiveReservation,
                        IrLeaseState::Declined,
                    ]),
                    prop::option::of(plain_text(40)),
                ),
                0..12,
            ),
            prop::collection::vec(
                (1u16..=254, prop::collection::vec(plain_text(20), 1..3)),
                0..4,
            ),
            any::<bool>(),
        )
            .prop_map(move |(ranges, reservations, leases, options, active)| {
                let cidr: IpNet = format!("{}.{}.{}.0/24", net[0], net[1], net[2])
                    .parse()
                    .expect("a network");
                let mut seen = std::collections::BTreeSet::new();
                let reservations: Vec<IrReservation> = reservations
                    .into_iter()
                    .filter(|(last, ..)| seen.insert(*last))
                    .map(|(last, octet, by_mac, name)| IrReservation {
                        ip: host(last),
                        client: client(octet, by_mac),
                        name: name.and_then(|name| HostName::new(&name).ok()),
                        source_name: None,
                        description: None,
                        bootp: false,
                        options: Vec::new(),
                        origin: SourceLocation::default(),
                    })
                    .collect();
                let mut seen = std::collections::BTreeSet::new();
                let leases: Vec<IrLease> = leases
                    .into_iter()
                    .filter(|(last, ..)| seen.insert(*last))
                    .map(|(last, octet, by_mac, state, hostname)| IrLease {
                        ip: host(last),
                        scope: cidr,
                        client: client(octet, by_mac),
                        hostname,
                        expires: Some(at(TAKEN_AT)),
                        state,
                        origin: SourceLocation::default(),
                    })
                    .collect();
                let scope = IrScope {
                    cidr,
                    name: None,
                    description: None,
                    active,
                    lease_secs: Some(3_600),
                    ranges: ranges
                        .into_iter()
                        .map(|(a, b)| IrRange {
                            first: host(a.min(b)),
                            last: host(a.max(b)),
                        })
                        .collect(),
                    exclusions: Vec::new(),
                    reservations,
                    options: options
                        .into_iter()
                        .map(|(code, values)| IrOption {
                            code,
                            vendor_class: None,
                            user_class: None,
                            values,
                            origin: SourceLocation::default(),
                        })
                        .collect(),
                    ddns: None,
                    superscope: None,
                    restricted: false,
                    delay_ms: 0,
                    origin: SourceLocation::default(),
                };
                (scope, leases)
            })
    };
    (
        networks.prop_flat_map(move |nets| nets.into_iter().map(scope).collect::<Vec<_>>()),
        1u64..1_000_000,
        label(),
        plain_text(30),
        plain_text(10),
    )
        .prop_map(|(scopes, sequence, kind, server, version)| {
            let mut leases = Vec::new();
            let scopes = scopes
                .into_iter()
                .map(|(scope, mut scope_leases)| {
                    leases.append(&mut scope_leases);
                    scope
                })
                .collect();
            MirrorSnapshot {
                format: FORMAT,
                sequence,
                taken_at: at(TAKEN_AT),
                source: MirrorOrigin {
                    kind: SourceKindLabel::new(&kind).expect("a label"),
                    server,
                    adapter: "Tenko-DhcpMirror.ps1".to_owned(),
                    adapter_version: version,
                },
                dhcp: DhcpIr {
                    scopes,
                    leases,
                    ..DhcpIr::default()
                },
                losses: LossReport::default(),
            }
        })
}

fn client(octet: u8, by_mac: bool) -> IrClientId {
    if by_mac {
        IrClientId {
            mac: Some(mac(octet)),
            client_id: None,
        }
    } else {
        IrClientId {
            mac: None,
            client_id: Some(rfc4361(octet)),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn a_built_snapshot_validates_and_round_trips(snapshot in snapshot()) {
        prop_assert!(snapshot.validate().is_ok(), "{:?}", snapshot.validate());
        let json = serde_json::to_string(&snapshot).expect("json");
        prop_assert_eq!(serde_json::from_str::<MirrorSnapshot>(&json).expect("json"), snapshot.clone());
        let cbor = to_cbor(&snapshot).expect("cbor");
        prop_assert_eq!(from_cbor::<MirrorSnapshot>(&cbor).expect("cbor"), snapshot);
    }

    #[test]
    fn a_lease_outside_its_scope_or_of_an_unknown_scope_is_refused_by_path(
        snapshot in snapshot(),
        index in any::<prop::sample::Index>(),
        outside in any::<bool>(),
    ) {
        let mut snapshot = snapshot;
        prop_assume!(!snapshot.dhcp.leases.is_empty());
        let at = index.index(snapshot.dhcp.leases.len());
        if outside {
            snapshot.dhcp.leases[at].ip = "192.0.3.1".parse().expect("ip");
            if snapshot.dhcp.leases[at].scope.contains(&snapshot.dhcp.leases[at].ip) {
                return Ok(());
            }
        } else {
            snapshot.dhcp.leases[at].scope = "10.0.0.0/8".parse().expect("net");
        }
        let error = snapshot.validate().expect_err("refused");
        let field = if outside { "ip" } else { "scope" };
        prop_assert_eq!(error.path, format!("dhcp.leases[{at}].{field}"));
    }

    #[test]
    fn a_source_kind_label_parses_exactly_the_pattern(text in "[ -~]{0,40}") {
        let valid = (1..=32).contains(&text.len())
            && text.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        prop_assert_eq!(SourceKindLabel::new(&text).is_ok(), valid);
        if valid {
            let json = serde_json::to_string(&SourceKindLabel::new(&text).expect("valid")).expect("json");
            let back = serde_json::from_str::<SourceKindLabel>(&json).expect("json");
            prop_assert_eq!(back.as_str(), text.as_str());
        }
    }
}
