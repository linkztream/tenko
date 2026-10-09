//! Mapping suggestions from headers and value shapes, end to end from file bytes.

use tenko_ipam::import::{
    mapping::{self, SheetKind},
    read::{self, ReadLimits},
    translate::{self, KnownPrefixes},
    vocab::Target,
};

fn targets(sheet: &mapping::SheetMapping) -> Vec<(String, Target)> {
    sheet
        .columns
        .iter()
        .map(|c| (c.column.clone(), c.target.clone()))
        .collect()
}

/// A Swedish Excel CSV: Windows-1252, semicolons, header words with å, ä and ö.
#[test]
fn swedish_windows_1252_headers_are_recognized() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"IP;Namn;Anv\xe4ndare;L\xf6sen;Beskrivning;MAC;VLAN\r\n");
    bytes.extend_from_slice(
        b"192.0.2.10;skrivare;admin;example-only;Skrivare i k\xe4llaren;00-00-5E-00-53-10;10\r\n",
    );
    bytes.extend_from_slice(b"192.0.2.11;;;;;;\r\n");
    let file = read::read_file("lista.csv", &bytes, &ReadLimits::default()).expect("read");
    assert_eq!(
        file.text.as_ref().map(|t| t.encoding.as_str()),
        Some("windows-1252")
    );
    let (analyses, suggested) = mapping::analyze(std::slice::from_ref(&file));
    let sheet = suggested.sheet("lista").expect("sheet");
    assert_eq!(sheet.kind, SheetKind::List);
    assert_eq!(sheet.header_row, Some(1));
    assert_eq!(
        targets(sheet),
        [
            ("A".to_owned(), Target::Address),
            ("B".to_owned(), Target::Name),
            ("C".to_owned(), Target::Login),
            ("D".to_owned(), Target::Password),
            ("E".to_owned(), Target::Description),
            ("F".to_owned(), Target::Mac),
            ("G".to_owned(), Target::Vlan),
        ]
    );
    // Credential samples are never shown.
    let columns = &analyses[0].columns;
    assert!(
        columns[3]
            .samples
            .iter()
            .all(|s| s == mapping::HIDDEN_SAMPLE)
    );
    assert_eq!(columns[1].samples, ["skrivare"]);

    let translation = translate::translate(&[file], &suggested, &KnownPrefixes::default(), None);
    let model = &translation.model;
    assert_eq!(model.hosts.len(), 1);
    let host = &model.hosts[0];
    assert_eq!(
        host.interfaces[0].mac.map(|m| m.to_string()).as_deref(),
        Some("00:00:5e:00:53:10")
    );
    assert_eq!(model.addresses.len(), 1, "the address-only row is free");
    assert_eq!(
        model.addresses[0].description.as_deref(),
        Some("Skrivare i källaren")
    );
    assert_eq!(model.credentials.len(), 1);
    // The VLAN of the row goes to the network that holds the address (here proposed).
    assert_eq!(model.prefixes.len(), 1);
    assert_eq!(model.prefixes[0].vlan, Some(10));
    assert_eq!(model.vlans.len(), 1);
}

/// Without a header, column roles come from value shapes.
#[test]
fn roles_come_from_shapes_without_a_header() {
    let csv = "192.0.2.20,printer,00:00:5e:00:53:20\n192.0.2.21,scanner,00:00:5e:00:53:21\n";
    let file =
        read::read_file("devices.csv", csv.as_bytes(), &ReadLimits::default()).expect("read");
    let (_, suggested) = mapping::analyze(std::slice::from_ref(&file));
    let sheet = suggested.sheet("devices").expect("sheet");
    assert_eq!(sheet.header_row, None);
    assert_eq!(
        targets(sheet),
        [
            ("A".to_owned(), Target::Address),
            ("B".to_owned(), Target::Name),
            ("C".to_owned(), Target::Mac),
        ]
    );
}

/// A header below a title row is found, and an address with a mask adds its network.
#[test]
fn a_late_header_and_masks() {
    let csv = "IP plan for the lab\n\nAddress;Hostname;Netmask\n198.51.100.5;nas;255.255.255.192\n";
    let file = read::read_file("lab.csv", csv.as_bytes(), &ReadLimits::default()).expect("read");
    let (_, suggested) = mapping::analyze(std::slice::from_ref(&file));
    let sheet = suggested.sheet("lab").expect("sheet");
    assert_eq!(sheet.header_row, Some(3));
    let translation = translate::translate(&[file], &suggested, &KnownPrefixes::default(), None);
    let prefixes: Vec<String> = translation
        .model
        .prefixes
        .iter()
        .map(|p| p.cidr.to_string())
        .collect();
    assert_eq!(prefixes, ["198.51.100.0/26"]);
    assert_eq!(translation.proposals.len(), 0);
}
