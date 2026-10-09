//! The fixture workbook of `docs/plans/import-fixtures.md` through readers, mapping and
//! translation: the suggested mapping, the model (prefixes, hosts, interfaces, addresses,
//! credentials by reference) and the loss report equal `ip-plan.expected.json`, for the
//! xlsx, the ods and the per-sheet CSV files alike.
//!
//! Regenerate the expected file after a deliberate change with
//! `TENKO_REGENERATE_FIXTURES=1 cargo test -p tenko-ipam --test import_fixture`, and review
//! the difference line by line against the specification.

use std::{fs, path::PathBuf};

use serde_json::{Value, json};
use tenko_ipam::import::{
    codes,
    mapping::{self, SheetKind},
    read::{self, ReadLimits, SourceFile},
    translate::{self, KnownPrefixes, Translation},
};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn read(name: &str) -> SourceFile {
    let path = fixtures().join(name);
    let bytes = fs::read(&path).expect("fixture");
    read::read_file(name, &bytes, &ReadLimits::default()).expect("readable")
}

/// The per-sheet CSV files in workbook order.
fn csv_files() -> Vec<SourceFile> {
    let order = [
        "Index",
        "192.0.2.0",
        "203.0.113.0",
        "192.0.2.64",
        "198.51.100.0",
        "192.0.2.128",
        "192.0.2.9",
        "203.0.113.128",
        "192.0.2.192",
        "198.51.100.128",
    ];
    order
        .iter()
        .map(|sheet| read(&format!("ip-plan-csv/{sheet}.csv")))
        .collect()
}

fn outcome(files: &[SourceFile]) -> (Value, Translation) {
    let (_, suggested) = mapping::analyze(files);
    let translation = translate::translate(files, &suggested, &KnownPrefixes::default(), None);
    let value = json!({
        "mapping": suggested,
        "sheets": translation.sheets,
        "model": translation.model,
        "proposals": translation.proposals,
        "loss": translation.loss,
    });
    (value, translation)
}

fn expected_path() -> PathBuf {
    fixtures().join("ip-plan.expected.json")
}

fn check(name: &str, actual: &Value) {
    if std::env::var("TENKO_REGENERATE_FIXTURES").as_deref() == Ok("1") && name == "xlsx" {
        let mut text = serde_json::to_string_pretty(actual).expect("json");
        text.push('\n');
        fs::write(expected_path(), text).expect("write expected");
    }
    let expected: Value =
        serde_json::from_str(&fs::read_to_string(expected_path()).expect("expected file"))
            .expect("expected json");
    if &expected != actual {
        let pretty = serde_json::to_string_pretty(actual).expect("json");
        let out = std::env::temp_dir().join(format!("ip-plan.actual.{name}.json"));
        fs::write(&out, pretty).expect("write actual");
        panic!(
            "the {name} fixture differs from ip-plan.expected.json; actual written to {}",
            out.display()
        );
    }
}

#[test]
fn the_xlsx_fixture_gives_the_expected_ir_and_loss_report() {
    let (actual, _) = outcome(&[read("ip-plan.xlsx")]);
    check("xlsx", &actual);
}

#[test]
fn the_ods_fixture_gives_the_same() {
    let (actual, _) = outcome(&[read("ip-plan.ods")]);
    check("ods", &actual);
}

#[test]
fn the_csv_fixtures_give_the_same() {
    let (actual, _) = outcome(&csv_files());
    check("csv", &actual);
}

fn fixture_translation() -> Translation {
    outcome(&[read("ip-plan.xlsx")]).1
}

/// Rule 6: every loss code of the specification, at its cell.
#[test]
fn every_specified_loss_code_is_reported() {
    let translation = fixture_translation();
    let loss = &translation.loss.entries;
    let at = |code: &str| -> Vec<String> {
        loss.iter()
            .filter(|e| e.code == code)
            .map(|e| e.location.to_string())
            .collect()
    };
    // Rule 6: the expected loss entries.
    assert_eq!(
        at(codes::ADDRESS_UNPARSABLE),
        ["203.0.113.0, row 51, column A"]
    );
    assert_eq!(
        at(codes::COLUMN_UNMAPPED),
        ["203.0.113.0, row 31, column E"]
    );
    assert_eq!(
        at(codes::CREDENTIAL_SUSPICIOUS),
        ["192.0.2.0, row 3, column C"]
    );
    assert_eq!(
        at(codes::ADDRESS_IS_NETWORK),
        ["192.0.2.64, row 2, column A"]
    );
    assert_eq!(
        at(codes::CREDENTIAL_NUMERIC),
        ["192.0.2.9, row 2, column D"]
    );
    assert_eq!(at(codes::PREFIX_UNLISTED), ["192.0.2.64", "203.0.113.128"]);
    assert_eq!(at(codes::SHEET_EMPTY), ["198.51.100.128"]);
}

/// Rules 1 to 3: sheets, headers, column roles, credentials.
#[test]
fn sheets_headers_and_columns_follow_rules_one_to_three() {
    let translation = fixture_translation();
    let model = &translation.model;
    let prefix = |cidr: &str| {
        model
            .prefixes
            .iter()
            .find(|p| p.cidr.to_string() == cidr)
            .unwrap_or_else(|| panic!("prefix {cidr}"))
    };
    let host = |name: &str| {
        model
            .hosts
            .iter()
            .find(|h| h.name.as_str() == name)
            .unwrap_or_else(|| panic!("host {name}"))
    };

    // Rule 1: sheet names to prefixes, masks from Index, the row count or the addresses.
    assert_eq!(
        prefix("192.0.2.0/24").description.as_deref(),
        Some("Network gear, hypervisors")
    );
    assert_eq!(prefix("192.0.2.64/29").description, None);
    assert_eq!(prefix("203.0.113.128/29").description, None);
    assert_eq!(
        prefix("198.51.100.128/26").description.as_deref(),
        Some("Printers")
    );
    assert!(
        model
            .prefixes
            .iter()
            .all(|p| p.cidr.to_string() != "192.0.2.9/32"),
        "a sheet named after an address listed as one in Index is a host"
    );
    let ds = host("mx-9200");
    assert_eq!(ds.description.as_deref(), Some("NAS"));
    // The Index sheet is the network list; nested sheets make 192.0.2.0/24 a supernet.
    assert_eq!(
        prefix("192.0.2.0/24").role,
        Some(tenko_core::ipam::PrefixRole::Supernet)
    );

    // Rule 2: no header when the first row holds an address; roles borrowed by position.
    let (analyses, suggested) = mapping::analyze(&[read("ip-plan.xlsx")]);
    let headerless = suggested.sheet("192.0.2.128").expect("sheet");
    assert_eq!(headerless.header_row, None);
    let borrowed = analyses
        .iter()
        .find(|a| a.sheet == "192.0.2.128")
        .expect("analysis");
    assert!(borrowed.roles_from.is_some());
    assert_eq!(
        suggested.sheet("Index").expect("index").kind,
        SheetKind::Index
    );
    assert_eq!(
        suggested.sheet("192.0.2.9").expect("host").kind,
        SheetKind::Host
    );
    assert_eq!(
        suggested.sheet("198.51.100.128").expect("empty").kind,
        SheetKind::Network
    );

    // Rule 3: credentials by reference only, names normalized with the label kept.
    assert!(
        model
            .credentials
            .iter()
            .any(|c| c.host.as_str() == "idrac-host1" && c.login && c.password)
    );
    assert_eq!(
        host("idrac-host1").description.as_deref(),
        Some("idrac - host1")
    );
    assert_eq!(
        host("wifi-controller-hall").description.as_deref(),
        Some("Wifi Controller Hall")
    );
    let printed = serde_json::to_string(model).expect("json");
    for secret in [
        "example-gw-pass",
        "example-pve-pass",
        "example-idrac-1",
        "1234\"",
    ] {
        assert!(
            !printed.contains(secret),
            "the model must not carry {secret}"
        );
    }
    assert_eq!(translation.credentials.0.len(), model.credentials.len());
}

/// Rules 4 and 5 and the transforms: device rows, proposals, free rows, ranges, the
/// network address.
#[test]
fn devices_free_rows_and_transforms_follow_rules_four_and_five() {
    let translation = fixture_translation();
    let model = &translation.model;
    let host = |name: &str| {
        model
            .hosts
            .iter()
            .find(|h| h.name.as_str() == name)
            .unwrap_or_else(|| panic!("host {name}"))
    };
    let address = |ip: &str| model.addresses.iter().find(|a| a.ip.to_string() == ip);
    // Rule 4: one host per device row, one interface and address per Nic column, and a
    // proposal for addresses outside every network.
    let hyper3 = host("hyper3");
    let names: Vec<&str> = hyper3.interfaces.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(names, ["nic1", "nic2", "nic3", "nic4"]);
    for (ip, nic) in [
        ("198.51.100.3", "nic1"),
        ("198.51.100.67", "nic2"),
        ("203.0.113.3", "nic3"),
        ("192.0.2.3", "nic4"),
    ] {
        let a = address(ip).unwrap_or_else(|| panic!("address {ip}"));
        assert_eq!(
            a.host.as_ref().map(tenko_core::net::HostName::as_str),
            Some("hyper3")
        );
        assert_eq!(a.interface.as_deref(), Some(nic));
    }
    let proposed: Vec<String> = translation
        .proposals
        .iter()
        .map(|p| p.cidr.to_string())
        .collect();
    assert_eq!(proposed, ["198.51.100.64/26", "2001:db8::/64"]);
    assert!(
        model
            .prefixes
            .iter()
            .any(|p| p.cidr.to_string() == "198.51.100.64/26")
    );

    // Rule 5: address-only rows create nothing and count as free.
    assert!(address("192.0.2.200").is_none());
    let pool = translation
        .sheets
        .iter()
        .find(|s| s.sheet == "192.0.2.0")
        .expect("sheet");
    assert_eq!(pool.rows, 256);
    assert_eq!(pool.free, 255 - 21);

    // Transforms: the range split into reserved addresses, the network address left out.
    for n in 10..=20 {
        let a = address(&format!("192.0.2.{n}")).expect("range member");
        assert_eq!(a.status, Some(tenko_core::ipam::Status::Reserved));
        assert_eq!(a.description.as_deref(), Some("DHCP pool"));
        assert_eq!(a.host, None);
    }
    assert!(address("192.0.2.64").is_none());
    assert_eq!(host("lab-gw").interfaces.len(), 0);
    assert!(address("2001:db8::10").is_some());
}
