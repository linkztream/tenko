//! The rule table against captured and modelled requests: the lab's captures
//! (`src/fingerprint/captured/`) and the WP7.3 corpus (`fixtures/requests/`, `fixtures/`).

use std::{collections::BTreeSet, path::Path};

use tenko_core::{dhcp::Fingerprint, serde_util::HexBytes};

use super::{
    Fingerprinter, OsGuess, RuleTable, fingerprint_of,
    table::{ENTRIES, Entry, List, Provenance, Vendor},
};
use crate::v4::Message;

/// A fixture file: hexadecimal octets, `xx*n` for `n` repeats, `#` comments.
fn octets(path: &Path) -> Vec<u8> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default();
        for token in line.split_whitespace() {
            let (octet, count) = token.split_once('*').unwrap_or((token, "1"));
            let octet = u8::from_str_radix(octet, 16).expect("an octet");
            let count: usize = count.parse().expect("a count");
            out.extend(std::iter::repeat_n(octet, count));
        }
    }
    out
}

fn fixture(relative: &str) -> Fingerprint {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    let bytes = octets(&path);
    let message = Message::parse(&bytes).unwrap_or_else(|e| panic!("{relative}: {e:?}"));
    fingerprint_of(&message)
}

/// The entry and the description the built-in table gives a fixture.
fn classified(relative: &str) -> (Option<&'static str>, Option<String>, Option<u8>) {
    let table = RuleTable::builtin();
    let fingerprint = fixture(relative);
    let guess = table.classify(&fingerprint);
    (
        table.entry_for(&fingerprint).map(|entry| entry.id),
        guess.as_ref().map(OsGuess::describe),
        guess.map(|guess| guess.confidence),
    )
}

#[test]
fn the_lab_captures_are_classified() {
    assert_eq!(
        classified("src/fingerprint/captured/debian12-dhclient.hex"),
        (
            Some("debian-dhclient"),
            Some("Linux (Debian or Ubuntu, ISC dhclient)".to_owned()),
            Some(75)
        )
    );
    assert_eq!(
        classified("src/fingerprint/captured/busybox-udhcpc.hex"),
        (
            Some("udhcpc"),
            Some("Linux (BusyBox udhcpc 1.35.0)".to_owned()),
            Some(85)
        )
    );
    // A request list written in a configuration file is nobody's fingerprint.
    assert_eq!(
        classified("src/fingerprint/captured/debian12-dhclient-lab.hex"),
        (None, None, None)
    );
}

#[test]
fn the_modelled_corpus_is_classified() {
    let cases: [(&str, &str, &str); 10] = [
        (
            "fixtures/requests/windows-discover.hex",
            "windows-10",
            "Windows 10 or 11 (or Server 2016 and later)",
        ),
        (
            "fixtures/requests/windows-request-selecting.hex",
            "windows-10",
            "Windows 10 or 11 (or Server 2016 and later)",
        ),
        (
            "fixtures/requests/inform-windows.hex",
            "windows-7",
            "Windows 7 or 8 (or Server 2008 R2 to 2012 R2)",
        ),
        (
            "fixtures/requests/macos-discover.hex",
            "macos-13",
            "macOS 13 or later",
        ),
        (
            "fixtures/requests/android-discover.hex",
            "android-13",
            "Android 13",
        ),
        (
            "fixtures/requests/linux-dhclient-discover.hex",
            "debian-dhclient",
            "Linux (Debian or Ubuntu, ISC dhclient)",
        ),
        (
            "fixtures/requests/systemd-networkd-discover.hex",
            "systemd-networkd",
            "Linux (systemd-networkd: Ubuntu Server, Debian)",
        ),
        (
            "fixtures/linux-discover-duid.hex",
            "systemd-networkd",
            "Linux (systemd-networkd: Ubuntu Server, Debian)",
        ),
        (
            "fixtures/requests/pxe-bios-discover.hex",
            "bios-pxe",
            "Boot firmware (BIOS PXE)",
        ),
        (
            "fixtures/pxe-discover.hex",
            "uefi-pxe-x64",
            "Boot firmware (UEFI PXE, x64)",
        ),
    ];
    for (path, id, text) in cases {
        let (entry, guess, _) = classified(path);
        assert_eq!(entry, Some(id), "{path}");
        assert_eq!(guess.as_deref(), Some(text), "{path}");
    }
    // Requests the corpus made up for other purposes (a bare 1,3,6,15) are no system.
    for path in [
        "fixtures/requests/renew-unicast.hex",
        "fixtures/requests/init-reboot.hex",
        "fixtures/requests/denied-discover.hex",
    ] {
        assert_eq!(classified(path), (None, None, None), "{path}");
    }
}

fn print(list: &[u8], vendor: Option<&str>) -> Fingerprint {
    Fingerprint {
        parameters: HexBytes(list.to_vec()),
        vendor_class: vendor.map(str::to_owned),
        ..Fingerprint::default()
    }
}

#[test]
fn an_exact_list_wins_over_a_prefix_and_a_prefix_over_the_vendor_alone() {
    let table = RuleTable::builtin();
    // Android 13's list: the exact entry, with the release from the vendor class.
    let android = [1, 3, 6, 15, 26, 28, 51, 58, 59, 43, 114, 108];
    let exact = print(&android, Some("android-dhcp-13"));
    assert_eq!(table.entry_for(&exact).map(|e| e.id), Some("android-13"));
    // A longer list of a later release: the prefix entry, still with the release.
    let later = print(
        &[1, 3, 6, 15, 26, 28, 51, 58, 59, 43, 114, 108, 119],
        Some("android-dhcp-15"),
    );
    assert_eq!(
        table.entry_for(&later).map(|e| e.id),
        Some("android-family")
    );
    assert_eq!(
        table.classify(&later).map(|guess| guess.describe()),
        Some("Android 15".to_owned())
    );
    // A list the table does not know: the vendor class alone.
    let odd = print(&[1, 3, 6], Some("android-dhcp-16"));
    assert_eq!(table.entry_for(&odd).map(|e| e.id), Some("android-vendor"));
    // An exact list with the wrong vendor class falls through to what the vendor says.
    let windows = [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252];
    assert_eq!(
        table
            .entry_for(&print(&windows, Some("MSFT 5.0 XBOX")))
            .map(|e| e.id),
        Some("xbox")
    );
    assert_eq!(
        table.entry_for(&print(&windows, None)).map(|e| e.id),
        None,
        "Windows always sends its vendor class"
    );
    // A vendor class's version is taken only when it is short and printable.
    let noisy = print(&android, Some("android-dhcp-\u{7}13"));
    assert_eq!(
        table.classify(&noisy).map(|guess| guess.describe()),
        Some("Android".to_owned())
    );
}

/// A fingerprint that shows what the entry asks for and as little else as possible.
fn sample(entry: &Entry) -> Fingerprint {
    let parameters = match entry.list {
        List::Exact(list) => list.to_vec(),
        List::Prefix(list) => [list, &[250]].concat(),
        List::Any => vec![1, 250],
    };
    let vendor_class = match entry.vendor {
        Vendor::Any | Vendor::Absent => None,
        Vendor::Exact(text) => Some(text.to_owned()),
        Vendor::Prefix(text) => Some(format!("{text}9")),
        Vendor::Contains(text) => Some(format!("x{text}y")),
    };
    Fingerprint {
        parameters: HexBytes(parameters),
        vendor_class,
        user_class: entry.user_class.unwrap_or(false),
        client_fqdn: entry.client_fqdn.unwrap_or(false),
        architecture: entry.architecture.unwrap_or(false).then_some(0),
    }
}

#[test]
fn every_entry_is_reachable_and_well_formed() {
    let table = RuleTable::builtin();
    assert_eq!(table.len(), ENTRIES.len());
    assert!(
        ENTRIES.len() >= 30,
        "the table has {} entries",
        ENTRIES.len()
    );
    let mut ids = BTreeSet::new();
    for entry in ENTRIES {
        assert!(ids.insert(entry.id), "{} twice", entry.id);
        assert!(entry.confidence <= 100, "{}", entry.id);
        assert!(!entry.family.is_empty(), "{}", entry.id);
        // No earlier entry shadows it.
        assert_eq!(
            table.entry_for(&sample(entry)).map(|found| found.id),
            Some(entry.id),
            "{} is shadowed",
            entry.id
        );
        let guess = table.classify(&sample(entry)).expect("a guess");
        assert_eq!(guess.family, entry.family);
        assert!(!guess.describe().contains("{}"), "{}", entry.id);
    }
    // The table names where its knowledge comes from.
    let captured = ENTRIES
        .iter()
        .filter(|entry| entry.provenance == Provenance::Captured)
        .count();
    let modelled = ENTRIES
        .iter()
        .filter(|entry| entry.provenance == Provenance::Modelled)
        .count();
    assert!(
        captured >= 4 && modelled >= 4,
        "{captured} captured, {modelled} modelled"
    );
    // The families the plan names are all there.
    let families: BTreeSet<&str> = ENTRIES.iter().map(|entry| entry.family).collect();
    for family in [
        "windows",
        "macos",
        "ios",
        "android",
        "linux",
        "chromeos",
        "playstation",
        "xbox",
        "printer",
        "embedded",
        "firmware",
    ] {
        assert!(families.contains(family), "{family}");
    }
}

#[test]
fn the_classifier_of_the_lease_facts_describes_the_guess() {
    use tenko_ipam::observe::dhcp::LeaseClassifier as _;
    let table = RuleTable::builtin();
    let reading = table
        .os(&fixture("fixtures/requests/windows-discover.hex"))
        .expect("a reading");
    assert_eq!(reading.guess, "Windows 10 or 11 (or Server 2016 and later)");
    assert_eq!(reading.confidence, 85);
    assert!(table.os(&print(&[], None)).is_none());
    assert!(
        super::lease_classifier()
            .os(&print(&[1, 3, 28, 6], None))
            .is_some()
    );
    // A family alone reads as its name.
    let guess = OsGuess {
        family: "chromeos".to_owned(),
        version: None,
        confidence: 50,
    };
    assert_eq!(guess.describe(), "ChromeOS");
}
