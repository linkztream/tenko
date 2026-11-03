//! Record type and class mnemonics of zone files.
//!
//! The model names only the types it serves ([`Rtype`]'s mnemonics); a zone file may name
//! any type of the IANA registry, so the reader and the writer carry the registry's
//! mnemonics here. A type without one is `TYPEnnn` (RFC 3597, section 5).

use tenko_core::dns::Rtype;

/// The IANA record types with a mnemonic (the registry as of 2026), by value.
const MNEMONICS: &[(u16, &str)] = &[
    (1, "A"),
    (2, "NS"),
    (3, "MD"),
    (4, "MF"),
    (5, "CNAME"),
    (6, "SOA"),
    (7, "MB"),
    (8, "MG"),
    (9, "MR"),
    (10, "NULL"),
    (11, "WKS"),
    (12, "PTR"),
    (13, "HINFO"),
    (14, "MINFO"),
    (15, "MX"),
    (16, "TXT"),
    (17, "RP"),
    (18, "AFSDB"),
    (19, "X25"),
    (20, "ISDN"),
    (21, "RT"),
    (22, "NSAP"),
    (23, "NSAP-PTR"),
    (24, "SIG"),
    (25, "KEY"),
    (26, "PX"),
    (27, "GPOS"),
    (28, "AAAA"),
    (29, "LOC"),
    (30, "NXT"),
    (31, "EID"),
    (32, "NIMLOC"),
    (33, "SRV"),
    (34, "ATMA"),
    (35, "NAPTR"),
    (36, "KX"),
    (37, "CERT"),
    (38, "A6"),
    (39, "DNAME"),
    (40, "SINK"),
    (41, "OPT"),
    (42, "APL"),
    (43, "DS"),
    (44, "SSHFP"),
    (45, "IPSECKEY"),
    (46, "RRSIG"),
    (47, "NSEC"),
    (48, "DNSKEY"),
    (49, "DHCID"),
    (50, "NSEC3"),
    (51, "NSEC3PARAM"),
    (52, "TLSA"),
    (53, "SMIMEA"),
    (55, "HIP"),
    (56, "NINFO"),
    (57, "RKEY"),
    (58, "TALINK"),
    (59, "CDS"),
    (60, "CDNSKEY"),
    (61, "OPENPGPKEY"),
    (62, "CSYNC"),
    (63, "ZONEMD"),
    (64, "SVCB"),
    (65, "HTTPS"),
    (66, "DSYNC"),
    (67, "HHIT"),
    (68, "BRID"),
    (99, "SPF"),
    (100, "UINFO"),
    (101, "UID"),
    (102, "GID"),
    (103, "UNSPEC"),
    (104, "NID"),
    (105, "L32"),
    (106, "L64"),
    (107, "LP"),
    (108, "EUI48"),
    (109, "EUI64"),
    (128, "NXNAME"),
    (249, "TKEY"),
    (250, "TSIG"),
    (251, "IXFR"),
    (252, "AXFR"),
    (253, "MAILB"),
    (254, "MAILA"),
    (255, "ANY"),
    (256, "URI"),
    (257, "CAA"),
    (258, "AVC"),
    (259, "DOA"),
    (260, "AMTRELAY"),
    (261, "RESINFO"),
    (262, "WALLET"),
    (263, "CLA"),
    (264, "IPN"),
    (32768, "TA"),
    (32769, "DLV"),
];

/// The mnemonic of a type, if the registry has one.
pub(super) fn mnemonic(rtype: Rtype) -> Option<&'static str> {
    MNEMONICS
        .binary_search_by_key(&rtype.0, |(value, _)| *value)
        .ok()
        .map(|index| MNEMONICS[index].1)
}

/// The type as a zone file names it: the mnemonic or `TYPEnnn`.
pub(super) fn name(rtype: Rtype) -> String {
    mnemonic(rtype).map_or_else(|| format!("TYPE{}", rtype.0), str::to_owned)
}

/// A type from its mnemonic (any case) or `TYPEnnn`.
pub(super) fn parse(text: &str) -> Option<Rtype> {
    if let Some((value, _)) = MNEMONICS
        .iter()
        .find(|(_, mnemonic)| mnemonic.eq_ignore_ascii_case(text))
    {
        return Some(Rtype(*value));
    }
    numbered(text, "TYPE").map(Rtype)
}

/// The value of `PREFIXnnn` (the prefix in any case), decimal digits only.
fn numbered(text: &str, prefix: &str) -> Option<u16> {
    let head = text.get(..prefix.len())?;
    if !head.eq_ignore_ascii_case(prefix) {
        return None;
    }
    let digits = text.get(prefix.len()..)?;
    if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The class IN.
pub(super) const IN: u16 = 1;

/// A class from its mnemonic (any case) or `CLASSnnn`.
pub(super) fn parse_class(text: &str) -> Option<u16> {
    const CLASSES: [(u16, &str); 6] = [
        (1, "IN"),
        (3, "CH"),
        (2, "CS"),
        (4, "HS"),
        (254, "NONE"),
        (255, "ANY"),
    ];
    if let Some((value, _)) = CLASSES
        .iter()
        .find(|(_, mnemonic)| mnemonic.eq_ignore_ascii_case(text))
    {
        return Some(*value);
    }
    numbered(text, "CLASS")
}

/// The class as a zone file names it.
pub(super) fn class_name(class: u16) -> String {
    match class {
        1 => "IN".to_owned(),
        2 => "CS".to_owned(),
        3 => "CH".to_owned(),
        4 => "HS".to_owned(),
        254 => "NONE".to_owned(),
        255 => "ANY".to_owned(),
        other => format!("CLASS{other}"),
    }
}

/// The DNSSEC algorithm of a mnemonic (RFC 4034 appendix A.1 and the IANA registry) or a
/// number.
pub(super) fn parse_algorithm(text: &str) -> Option<u8> {
    const ALGORITHMS: [(u8, &str); 15] = [
        (1, "RSAMD5"),
        (2, "DH"),
        (3, "DSA"),
        (5, "RSASHA1"),
        (6, "DSA-NSEC3-SHA1"),
        (7, "RSASHA1-NSEC3-SHA1"),
        (8, "RSASHA256"),
        (10, "RSASHA512"),
        (12, "ECC-GOST"),
        (13, "ECDSAP256SHA256"),
        (14, "ECDSAP384SHA384"),
        (15, "ED25519"),
        (16, "ED448"),
        (252, "INDIRECT"),
        (253, "PRIVATEDNS"),
    ];
    if let Some((value, _)) = ALGORITHMS
        .iter()
        .find(|(_, mnemonic)| mnemonic.eq_ignore_ascii_case(text))
    {
        return Some(*value);
    }
    if text.eq_ignore_ascii_case("PRIVATEOID") {
        return Some(254);
    }
    super::text::decimal::<u8>(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_sorted_and_names_the_model_types_alike() {
        assert!(MNEMONICS.windows(2).all(|pair| pair[0].0 < pair[1].0));
        for value in 0..=u16::MAX {
            let rtype = Rtype(value);
            if let Some(model) = rtype.mnemonic() {
                assert_eq!(mnemonic(rtype), Some(model), "{value}");
            }
        }
    }

    #[test]
    fn types_parse_by_mnemonic_or_number() {
        assert_eq!(parse("a"), Some(Rtype::A));
        assert_eq!(parse("Nsec3Param"), Some(Rtype::NSEC3PARAM));
        assert_eq!(parse("TYPE65280"), Some(Rtype(65280)));
        assert_eq!(parse("type1"), Some(Rtype::A));
        assert_eq!(parse("TYPE65536"), None);
        assert_eq!(parse("TYPE"), None);
        assert_eq!(parse("TYPE+1"), None);
        assert_eq!(parse("TYPÉ1"), None);
        assert_eq!(parse("300"), None);
        assert_eq!(name(Rtype(99)), "SPF");
        assert_eq!(name(Rtype(1234)), "TYPE1234");
        assert_eq!(parse_class("in"), Some(IN));
        assert_eq!(parse_class("CLASS3"), Some(3));
        assert_eq!(class_name(3), "CH");
        assert_eq!(class_name(77), "CLASS77");
        assert_eq!(parse_algorithm("ecdsap256sha256"), Some(13));
        assert_eq!(parse_algorithm("8"), Some(8));
        assert_eq!(parse_algorithm("256"), None);
    }
}
