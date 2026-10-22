//! The shipped root trust anchors and root hints (recursion plan sections 2.4, 2.5 and 3.3):
//! the generated constants equal what an independent parser reads from the shipped XML
//! again, the file's digest is the recorded one, and the hints hold the thirteen root
//! servers with both address families.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use aws_lc_rs::digest;
use tenko_dns::recursion::shipped::{
    ROOT_ANCHORS, ROOT_ANCHORS_ID, ROOT_ANCHORS_SHA256, ROOT_ANCHORS_XML, ROOT_HINTS,
    ROOT_HINTS_DATE, ROOT_HINTS_SERIAL, ShippedAnchor, summary, valid_at,
};

/// A `KeyDigest` as the test's own parser reads it.
#[derive(Debug, PartialEq, Eq)]
struct Parsed {
    id: String,
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: Vec<u8>,
    valid_from: String,
    valid_until: Option<String>,
}

/// The text between `<name>` and `</name>` in `block`.
fn element_text<'a>(block: &'a str, name: &str) -> &'a str {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = block.find(&open).unwrap_or_else(|| panic!("no <{name}>")) + open.len();
    let end = start
        + block[start..]
            .find(&close)
            .unwrap_or_else(|| panic!("no </{name}>"));
    block[start..end].trim()
}

/// The value of attribute `name` in the opening tag text `tag`.
fn attribute<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!(" {name}=\"");
    let start = tag.find(&needle)? + needle.len();
    let end = start + tag[start..].find('"')?;
    Some(&tag[start..end])
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "odd hex length");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// Every `KeyDigest` of the XML, found by scanning for the tags.
fn parse_xml(xml: &str) -> Vec<Parsed> {
    let mut found = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<KeyDigest ") {
        let after = &rest[start..];
        let tag_end = after.find('>').expect("end of the KeyDigest tag");
        let tag = &after[..tag_end];
        let close = after.find("</KeyDigest>").expect("closing KeyDigest");
        let block = &after[tag_end + 1..close];
        found.push(Parsed {
            id: attribute(tag, "id").expect("id").to_owned(),
            key_tag: element_text(block, "KeyTag").parse().expect("key tag"),
            algorithm: element_text(block, "Algorithm").parse().expect("algorithm"),
            digest_type: element_text(block, "DigestType").parse().expect("type"),
            digest: hex_to_bytes(element_text(block, "Digest")),
            valid_from: attribute(tag, "validFrom").expect("validFrom").to_owned(),
            valid_until: attribute(tag, "validUntil").map(str::to_owned),
        });
        rest = &after[close + "</KeyDigest>".len()..];
    }
    found
}

fn anchor(key_tag: u16) -> Option<&'static ShippedAnchor> {
    ROOT_ANCHORS.iter().find(|a| a.key_tag == key_tag)
}

/// Unix seconds of midnight UTC on a date (days from civil, written out once more here so the
/// test does not lean on the code it checks).
fn midnight(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe - 719_468) * 86_400
}

#[test]
fn constants_equal_a_second_parse_of_the_shipped_xml() {
    let parsed = parse_xml(ROOT_ANCHORS_XML);
    assert!(!parsed.is_empty(), "the file holds key digests");
    assert_eq!(parsed.len(), ROOT_ANCHORS.len());
    for (expected, shipped) in parsed.iter().zip(ROOT_ANCHORS) {
        let actual = Parsed {
            id: shipped.id.to_owned(),
            key_tag: shipped.key_tag,
            algorithm: shipped.algorithm,
            digest_type: shipped.digest_type,
            digest: shipped.digest.to_vec(),
            valid_from: shipped.valid_from.to_owned(),
            valid_until: shipped.valid_until.map(str::to_owned),
        };
        assert_eq!(&actual, expected);
    }
    let tag = ROOT_ANCHORS_XML
        .find("<TrustAnchor ")
        .map(|s| &ROOT_ANCHORS_XML[s..])
        .and_then(|t| t.find('>').map(|e| &t[..e]))
        .expect("the TrustAnchor tag");
    assert_eq!(attribute(tag, "id"), Some(ROOT_ANCHORS_ID));
    assert_eq!(element_text(ROOT_ANCHORS_XML, "Zone"), ".");
}

#[test]
fn the_recorded_sha256_is_the_digest_of_the_shipped_xml() {
    let sum = digest::digest(&digest::SHA256, ROOT_ANCHORS_XML.as_bytes());
    let hex = sum.as_ref().iter().fold(String::new(), |mut acc, b| {
        write!(acc, "{b:02x}").expect("writing to a String");
        acc
    });
    assert_eq!(hex, ROOT_ANCHORS_SHA256);
}

#[test]
fn digests_have_the_length_of_their_type() {
    for a in ROOT_ANCHORS {
        let expected = match a.digest_type {
            1 => 20,
            2 => 32,
            4 => 48,
            other => panic!("unexpected digest type {other}"),
        };
        assert_eq!(a.digest.len(), expected, "key tag {}", a.key_tag);
    }
}

#[test]
fn the_current_root_keys_are_present() {
    for key_tag in [20326, 38696] {
        let a = anchor(key_tag).unwrap_or_else(|| panic!("key tag {key_tag} is missing"));
        assert_eq!(a.algorithm, 8, "RSA/SHA-256");
        assert_eq!(a.digest_type, 2, "SHA-256");
        assert_eq!(a.valid_until, None);
    }
}

#[test]
fn valid_at_follows_the_validity_window() {
    let tags_at = |t: i64| -> Vec<u16> { valid_at(t).map(|a| a.key_tag).collect() };
    // Before the first key of the file nothing is valid.
    assert_eq!(tags_at(midnight(2009, 6, 1)), Vec::<u16>::new());
    // The 2010 key is valid from its validFrom to its validUntil, excluded.
    assert_eq!(tags_at(midnight(2012, 1, 1)), [19036]);
    assert_eq!(tags_at(midnight(2017, 6, 1)), [19036, 20326]);
    assert_eq!(tags_at(midnight(2019, 1, 10)), [19036, 20326]);
    assert_eq!(tags_at(midnight(2019, 1, 11)), [20326]);
    // Today's keys.
    assert_eq!(tags_at(midnight(2026, 10, 22)), [20326, 38696]);
    assert_eq!(tags_at(midnight(2024, 7, 17) + 86_399), [20326]);
    assert_eq!(tags_at(midnight(2024, 7, 18)), [20326, 38696]);
}

#[test]
fn the_summary_names_the_unretired_key_tags_and_the_hints_date() {
    let text = summary();
    for a in ROOT_ANCHORS.iter().filter(|a| a.valid_until.is_none()) {
        assert!(text.contains(&a.key_tag.to_string()), "{text}");
    }
    for a in ROOT_ANCHORS.iter().filter(|a| a.valid_until.is_some()) {
        assert!(!text.contains(&a.key_tag.to_string()), "{text}");
    }
    assert!(text.contains(ROOT_HINTS_DATE), "{text}");
    assert!(text.starts_with("root anchors "), "{text}");
}

#[test]
fn the_hints_hold_the_thirteen_root_servers_with_both_address_families() {
    // letter -> (A records, AAAA records)
    let mut servers: BTreeMap<char, (Vec<std::net::Ipv4Addr>, Vec<std::net::Ipv6Addr>)> =
        BTreeMap::new();
    for line in ROOT_HINTS.lines().filter(|l| !l.starts_with(';')) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [name, _ttl, kind, value] = fields[..] else {
            continue;
        };
        let name = name.to_ascii_lowercase();
        let Some(letter) = name.strip_suffix(".root-servers.net.") else {
            continue;
        };
        let mut chars = letter.chars();
        let (Some(letter), None) = (chars.next(), chars.next()) else {
            panic!("unexpected server name {name}");
        };
        let entry = servers.entry(letter).or_default();
        match kind {
            "A" => entry.0.push(value.parse().expect("IPv4 address")),
            "AAAA" => entry.1.push(value.parse().expect("IPv6 address")),
            other => panic!("unexpected record type {other}"),
        }
    }
    let letters: Vec<char> = servers.keys().copied().collect();
    assert_eq!(letters, ('a'..='m').collect::<Vec<_>>());
    for (letter, (v4, v6)) in &servers {
        assert_eq!(v4.len(), 1, "{letter}.root-servers.net. A records");
        assert_eq!(v6.len(), 1, "{letter}.root-servers.net. AAAA records");
    }
    // One NS record per server for the root.
    let ns = ROOT_HINTS
        .lines()
        .filter(|l| !l.starts_with(';'))
        .filter(|l| l.split_whitespace().nth(2) == Some("NS"))
        .count();
    assert_eq!(ns, 13);
}

#[test]
fn the_hints_date_and_serial_match_the_comment_lines() {
    let value_of = |label: &str| -> &str {
        let line = ROOT_HINTS
            .lines()
            .find(|l| l.starts_with(';') && l.contains(label))
            .unwrap_or_else(|| panic!("no comment line with {label}"));
        line.split_once(':').expect("a colon").1.trim()
    };
    let serial: u32 = value_of("related version of root zone")
        .parse()
        .expect("serial");
    assert_eq!(serial, ROOT_HINTS_SERIAL);

    let date = value_of("last update");
    let (month_day, year) = date.split_once(',').expect("month day, year");
    let (month, day) = month_day.trim().split_once(' ').expect("month day");
    let month_number = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ]
    .iter()
    .position(|m| *m == month)
    .expect("a month name")
        + 1;
    let day: u32 = day.trim().parse().expect("day");
    let year: u32 = year.trim().parse().expect("year");
    assert_eq!(
        ROOT_HINTS_DATE,
        format!("{year:04}-{month_number:02}-{day:02}")
    );
}
