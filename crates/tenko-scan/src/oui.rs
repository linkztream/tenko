//! Vendor names of MAC addresses from their OUI (IEEE MA-L registry), compiled in.
//!
//! The table is `data/oui.tsv`: comment lines that start with `#` (the source, the date the
//! file was generated and the number of entries), then one line per OUI with six hexadecimal
//! digits, a tab and the name of the organisation, sorted by OUI. `data/generate-oui.mjs`
//! writes the file from the registry's CSV. Only the 24-bit MA-L blocks are in it; the
//! smaller MA-M and MA-S blocks share an OUI between several organisations and are not
//! looked up.

use std::sync::OnceLock;

use tenko_core::MacAddr;

/// The compiled-in table.
const TABLE: &str = include_str!("../data/oui.tsv");

/// Where the table comes from and how much it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dataset {
    /// The registry the table was made from (a URL).
    pub source: &'static str,
    /// The date the table was generated (`YYYY-MM-DD`).
    pub generated: &'static str,
    /// Number of OUIs in the table.
    pub entries: usize,
}

/// The organisation the OUI of `mac` is registered to; `None` for locally administered
/// or group addresses, for the all-zero address (its block is registered, but no device
/// carries it) and for OUIs the table does not know.
pub fn vendor(mac: MacAddr) -> Option<&'static str> {
    let octets = mac.octets();
    if octets[0] & 0x03 != 0 || octets == [0; 6] {
        return None;
    }
    table().lookup(u32::from_be_bytes([0, octets[0], octets[1], octets[2]]))
}

/// What the compiled-in table was made from.
pub fn dataset() -> Dataset {
    let table = table();
    Dataset {
        source: table.source,
        generated: table.generated,
        entries: table.entries.len(),
    }
}

fn table() -> &'static Table<'static> {
    static PARSED: OnceLock<Table<'static>> = OnceLock::new();
    PARSED.get_or_init(|| Table::parse(TABLE))
}

/// The parsed table: OUIs in ascending order, each once.
#[derive(Debug)]
struct Table<'a> {
    source: &'a str,
    generated: &'a str,
    entries: Vec<(u32, &'a str)>,
    /// Lines that were neither comments nor entries; the tests check that the shipped file
    /// has none.
    #[cfg_attr(not(test), allow(dead_code))]
    skipped: usize,
}

impl<'a> Table<'a> {
    /// Reads `text`. A line that is not an entry is skipped; a repeated OUI keeps its first
    /// name; the entries are sorted whatever order the lines came in.
    fn parse(text: &'a str) -> Self {
        let mut source = "unknown";
        let mut generated = "unknown";
        let mut entries = Vec::new();
        let mut skipped = 0;
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            if let Some(comment) = line.strip_prefix('#') {
                if let Some((key, value)) = comment.split_once(':') {
                    match key.trim() {
                        "source" => source = value.trim(),
                        "generated" => generated = value.trim(),
                        _ => {}
                    }
                }
            } else if !line.trim().is_empty() {
                match parse_entry(line) {
                    Some(entry) => entries.push(entry),
                    None => skipped += 1,
                }
            }
        }
        entries.sort_by_key(|(oui, _)| *oui);
        entries.dedup_by_key(|(oui, _)| *oui);
        Self {
            source,
            generated,
            entries,
            skipped,
        }
    }

    /// The name registered for `oui` (the first three octets as a number).
    fn lookup(&self, oui: u32) -> Option<&'a str> {
        self.entries
            .binary_search_by_key(&oui, |(key, _)| *key)
            .ok()
            .map(|index| self.entries[index].1)
    }
}

/// `005E<TAB>name` as `(0x00005e, "name")`; the OUI is exactly six hexadecimal digits and
/// the name is not empty.
fn parse_entry(line: &str) -> Option<(u32, &str)> {
    let (oui, name) = line.split_once('\t')?;
    let name = name.trim();
    if oui.len() != 6 || name.is_empty() || !oui.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some((u32::from_str_radix(oui, 16).ok()?, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(text: &str) -> MacAddr {
        text.parse().expect("a valid MAC address")
    }

    #[test]
    fn iana_block_is_known() {
        // 00:00:5e:00:53:00 to 00:00:5e:00:53:ff is the documentation block of RFC 7042.
        assert_eq!(
            vendor(mac("00:00:5e:00:53:01")),
            Some("ICANN, IANA Department")
        );
        assert_eq!(
            vendor(mac("00:00:5E:FF:FF:FF")),
            Some("ICANN, IANA Department")
        );
    }

    #[test]
    fn locally_administered_and_group_addresses_have_no_vendor() {
        assert_eq!(
            vendor(mac("02:00:5e:00:53:01")),
            None,
            "locally administered"
        );
        assert_eq!(vendor(mac("01:00:5e:00:53:01")), None, "group");
        assert_eq!(vendor(mac("03:00:5e:00:53:01")), None, "both bits");
        assert_eq!(vendor(mac("ff:ff:ff:ff:ff:ff")), None, "broadcast");
    }

    #[test]
    fn unknown_oui_has_no_vendor() {
        assert_eq!(vendor(mac("00:ff:ff:00:53:01")), None);
        assert_eq!(vendor(mac("00:00:00:00:00:00")), None);
        assert_eq!(vendor(mac("fc:ff:ff:00:00:01")), None);
    }

    #[test]
    fn shipped_file_is_well_formed() {
        let table = Table::parse(TABLE);
        assert_eq!(table.skipped, 0, "malformed lines in data/oui.tsv");
        assert!(
            table.lookup(0x00_00_5e).is_some(),
            "the IANA block is in the table"
        );
        // Sorted without repeats, as the generator writes it.
        let lines: Vec<&str> = TABLE
            .lines()
            .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
            .collect();
        let keys: Vec<&str> = lines.iter().map(|line| &line[..6]).collect();
        assert!(keys.windows(2).all(|pair| pair[0] < pair[1]), "not sorted");
        assert!(
            keys.iter().all(|key| key
                .bytes()
                .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())),
            "OUIs are upper-case"
        );
        assert!(!TABLE.contains('\r'), "lines end with LF");
    }

    #[test]
    fn dataset_describes_the_shipped_file() {
        let data = dataset();
        let lines = TABLE
            .lines()
            .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
            .count();
        assert_eq!(data.entries, lines);
        assert!(data.source.starts_with("https://"), "{}", data.source);
        let stamp = data.generated.as_bytes();
        assert!(
            stamp.len() == 10
                && stamp[4] == b'-'
                && stamp[7] == b'-'
                && stamp
                    .iter()
                    .enumerate()
                    .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit()),
            "{}",
            data.generated
        );
        let declared = TABLE
            .lines()
            .find_map(|line| line.strip_prefix("# entries:"))
            .and_then(|count| count.trim().parse::<usize>().ok());
        assert_eq!(declared, Some(data.entries), "# entries: matches the lines");
    }

    const SYNTHETIC: &str = "\
# source: https://example.org/registry.csv
# generated: 2026-01-02
# entries: 5
000042\tExample Networks Ltd
00005E\tICANN, IANA Department
0A1B2C\tExample Devices
\x20\x20
ABCDEF\tOrganisation Test
FFFFFF\tLast Entry
";

    #[test]
    fn synthetic_table_is_searched_by_binary_search() {
        let table = Table::parse(SYNTHETIC);
        assert_eq!(table.entries.len(), 5);
        assert_eq!(table.skipped, 0);
        assert_eq!(table.source, "https://example.org/registry.csv");
        assert_eq!(table.generated, "2026-01-02");
        assert_eq!(table.lookup(0x00_00_42), Some("Example Networks Ltd"));
        assert_eq!(table.lookup(0x00_00_5e), Some("ICANN, IANA Department"));
        assert_eq!(table.lookup(0x0a_1b_2c), Some("Example Devices"));
        assert_eq!(table.lookup(0xab_cd_ef), Some("Organisation Test"));
        assert_eq!(table.lookup(0xff_ff_ff), Some("Last Entry"));
        for missing in [
            0x00_00_00, 0x00_00_41, 0x00_00_43, 0x00_00_5f, 0x0a_1b_2d, 0xff_ff_fe,
        ] {
            assert_eq!(table.lookup(missing), None, "{missing:06x}");
        }
        assert_eq!(Table::parse("").lookup(0x00_00_5e), None);
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let text = "\
# generated: 2026-01-02
00005E\tICANN, IANA Department
00005\tfive digits
00005E7\tseven digits
00005G\tnot hexadecimal
00005F no tab
00005F\t
00005F\t   \t
-0005F\tsign
00006A\tKept
";
        let table = Table::parse(text);
        assert_eq!(table.skipped, 7);
        let kept: Vec<u32> = table.entries.iter().map(|(oui, _)| *oui).collect();
        assert_eq!(kept, [0x00_00_5e, 0x00_00_6a]);
    }

    #[test]
    fn unsorted_and_repeated_lines_still_look_up() {
        let text = "# source: x\r\nFFFFFF\tLast\r\n000001\tFirst\r\n00005e\tLower case digits\r\n000001\tAgain\r\n";
        let table = Table::parse(text);
        assert_eq!(table.entries.len(), 3);
        assert_eq!(table.lookup(1), Some("First"));
        assert_eq!(table.lookup(0x5e), Some("Lower case digits"));
        assert_eq!(table.lookup(0xff_ff_ff), Some("Last"));
        assert_eq!(table.generated, "unknown");
    }
}
