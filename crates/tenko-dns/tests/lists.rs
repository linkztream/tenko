//! The list compiler and the matcher of the block and allow lists: how hosts files and
//! domain lists are read (boilerplate, comments, Adblock forms, IDN, bad lines), what the
//! compiler keeps (sorted, no duplicates, no name under a listed name), how the compiled
//! bytes are decoded and refused, and what the matcher answers for names at, under and beside
//! a listed name. A property test checks the matcher against a naive suffix scan.
//!
//! Test data stays under `example.test`.

use std::fmt::Write as _;

use proptest::prelude::*;
use tenko_core::dns::{DnsName, ListFormat};
use tenko_dns::{
    lists::{
        CompileError, ListMatcher,
        compile::{DEFLATE_ABOVE, MAGIC, MAGIC_DEFLATE, MAX_ENTRIES, decode, key_text, name_key},
        compile_keys, compile_text, parse,
    },
    name::NameBuf,
};

/// The lowercase wire form of a name in text, written by hand.
fn wire(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.').filter(|label| !label.is_empty()) {
        out.push(u8::try_from(label.len()).expect("label length"));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// The key of a name that must be valid.
fn key(name: &str) -> Vec<u8> {
    name_key(name).expect("a valid name")
}

/// The names of a parse, as text.
fn texts(keys: &[Vec<u8>]) -> Vec<String> {
    keys.iter().map(|key| key_text(key)).collect()
}

/// The compiled bytes of a list of names.
fn compiled(names: &[&str]) -> Vec<u8> {
    compile_keys(names.iter().map(|name| key(name)).collect())
        .expect("compiles")
        .bytes
}

/// The matcher of a list of names.
fn matcher(names: &[&str]) -> ListMatcher {
    ListMatcher::build(&compiled(names)).expect("a matcher")
}

/// An unsigned LEB128 count, as the compiled format writes it.
fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let low = u8::try_from(value & 0x7f).expect("seven bits");
        value >>= 7;
        if value == 0 {
            out.push(low);
            return out;
        }
        out.push(low | 0x80);
    }
}

/// A compiled version written by hand: the magic, the count and the raw entries.
fn raw(count: u64, entries: &[u8]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend(varint(count));
    out.extend_from_slice(entries);
    out
}

// ---- The text: hosts files ----

#[test]
fn a_hosts_file_is_read_with_its_boilerplate_skipped() {
    let text = b"# a hosts file\n\
        127.0.0.1 localhost\n\
        127.0.0.1 localhost.localdomain\n\
        ::1 localhost ip6-localhost ip6-loopback\n\
        255.255.255.255 broadcasthost\n\
        0.0.0.0 ads.example.test\n\
        127.0.0.1 a.example.test b.example.test\n";
    let parsed = parse(text, ListFormat::Hosts);
    assert_eq!(
        texts(&parsed.keys),
        ["ads.example.test", "a.example.test", "b.example.test"]
    );
    assert_eq!(parsed.skipped, 0, "the boilerplate is not a bad line");
}

#[test]
fn comments_blank_lines_and_crlf_line_ends_are_handled() {
    let text = "# first\r\n\
        \r\n\
        0.0.0.0 ads.example.test   # a trailing comment\r\n\
        \t\r\n\
        #0.0.0.0 commented.example.test\r\n\
        0.0.0.0\ttab.example.test\r\n";
    let parsed = parse(text.as_bytes(), ListFormat::Hosts);
    assert_eq!(
        texts(&parsed.keys),
        ["ads.example.test", "tab.example.test"]
    );
    assert_eq!(parsed.skipped, 0);
}

#[test]
fn a_hosts_file_without_a_final_newline_keeps_its_last_line() {
    let parsed = parse(b"0.0.0.0 last.example.test", ListFormat::Hosts);
    assert_eq!(texts(&parsed.keys), ["last.example.test"]);
}

#[test]
fn upper_case_and_a_trailing_dot_fold_to_the_canonical_name() {
    let text = b"0.0.0.0 ADS.Example.TEST\n0.0.0.0 dotted.example.test.\n";
    let parsed = parse(text, ListFormat::Hosts);
    assert_eq!(
        parsed.keys,
        [key("ads.example.test"), key("dotted.example.test")]
    );
    assert_eq!(key("Ads.EXAMPLE.test."), key("ads.example.test"));
}

#[test]
fn a_key_holds_the_labels_from_the_right_with_their_lengths() {
    assert_eq!(key("example.test"), b"\x04test\x07example");
    assert_eq!(key_text(b"\x04test\x07example"), "example.test");
}

#[test]
fn junk_lines_are_counted_as_skipped() {
    let long_label = "a".repeat(64);
    let long_name = format!("{}.example.test", vec!["a".repeat(63); 4].join("."));
    let text = format!(
        "0.0.0.0 good.example.test\n\
         http://x.example.test/path\n\
         0.0.0.0 {long_label}.example.test\n\
         0.0.0.0 {long_name}\n\
         0.0.0.0\n\
         0.0.0.0 under_score.example.test\n\
         0.0.0.0 bad!char.example.test\n\
         0.0.0.0 empty..label.example.test\n"
    );
    let parsed = parse(text.as_bytes(), ListFormat::Hosts);
    assert_eq!(
        texts(&parsed.keys),
        ["good.example.test", "under_score.example.test"]
    );
    assert_eq!(parsed.skipped, 6);
}

#[test]
fn a_line_of_a_hosts_file_with_one_good_name_among_bad_ones_is_not_skipped() {
    let parsed = parse(b"0.0.0.0 bad!name good.example.test\n", ListFormat::Hosts);
    assert_eq!(texts(&parsed.keys), ["good.example.test"]);
    assert_eq!(parsed.skipped, 0);
}

#[test]
fn a_bare_name_in_a_hosts_file_is_skipped() {
    let parsed = parse(b"ads.example.test\n", ListFormat::Hosts);
    assert_eq!(texts(&parsed.keys), Vec::<String>::new());
    assert_eq!(parsed.skipped, 1);
}

#[test]
fn a_name_may_take_the_whole_wire_length_and_not_one_octet_more() {
    // 3 labels of 63 octets and one of 61: 3 * 64 + 62 + the root octet is 255.
    let longest = format!("{}.{}", vec!["a".repeat(63); 3].join("."), "b".repeat(61));
    assert!(name_key(&longest).is_some());
    let too_long = format!("{}.{}", vec!["a".repeat(63); 3].join("."), "b".repeat(62));
    assert!(name_key(&too_long).is_none());
    assert!(name_key(&"a".repeat(63)).is_some());
    assert!(name_key(&"a".repeat(64)).is_none());
}

#[test]
fn the_empty_name_and_the_root_are_no_entries() {
    assert!(name_key("").is_none());
    assert!(name_key(".").is_none());
}

// ---- The text: domain lists ----

#[test]
fn a_domain_list_has_one_name_per_line() {
    let text = b"! an Adblock comment\n\
        tracker.example.test\n\
        # a comment\n\
        ||pipe.example.test^\n\
        *.wild.example.test\n\
        Upper.Example.Test.\n\
        \n";
    let parsed = parse(text, ListFormat::Domains);
    assert_eq!(
        texts(&parsed.keys),
        [
            "tracker.example.test",
            "pipe.example.test",
            "wild.example.test",
            "upper.example.test"
        ]
    );
    assert_eq!(parsed.skipped, 0);
}

#[test]
fn a_domain_list_reads_a_line_in_hosts_form_as_hosts() {
    let text = b"0.0.0.0 hosts.example.test other.example.test\n127.0.0.1 localhost\n";
    let parsed = parse(text, ListFormat::Domains);
    assert_eq!(
        texts(&parsed.keys),
        ["hosts.example.test", "other.example.test"]
    );
    assert_eq!(parsed.skipped, 0);
}

#[test]
fn a_domain_list_line_with_two_names_is_skipped() {
    let text = b"one.example.test two.example.test\nkept.example.test\n";
    let parsed = parse(text, ListFormat::Domains);
    assert_eq!(texts(&parsed.keys), ["kept.example.test"]);
    assert_eq!(parsed.skipped, 1);
}

#[test]
fn a_domain_list_line_that_is_a_url_is_skipped() {
    let parsed = parse(b"http://x.example.test/path\n", ListFormat::Domains);
    assert_eq!(texts(&parsed.keys), Vec::<String>::new());
    assert_eq!(parsed.skipped, 1);
}

// ---- The text: IDN ----

#[test]
fn an_idn_label_is_written_in_punycode() {
    assert_eq!(
        key_text(&key("b\u{fc}cher.example.test")),
        "xn--bcher-kva.example.test"
    );
    assert_eq!(
        key_text(&key("M\u{dc}NCHEN.example.test")),
        "xn--mnchen-3ya.example.test"
    );
}

#[test]
fn an_idn_name_matches_the_vectors_of_the_idna_registrations() {
    // "tda" is the encoding of the single letter u-umlaut (RFC 3492, section 7.1 style).
    assert_eq!(
        key_text(&key("\u{fc}.example.test")),
        "xn--tda.example.test"
    );
    // The Japanese word "nihongo" (language of Japan), as registered under .jp.
    assert_eq!(
        key_text(&key("\u{65e5}\u{672c}\u{8a9e}.example.test")),
        "xn--wgv71a119e.example.test"
    );
    // RFC 3492, section 7.1, sample (L), with the Latin letter in lower case.
    assert_eq!(
        key_text(&key(
            "3\u{5e74}b\u{7d44}\u{91d1}\u{516b}\u{5148}\u{751f}.example.test"
        )),
        "xn--3b-ww4c5e180e575a65lsy2b.example.test"
    );
}

#[test]
fn an_idn_list_entry_matches_its_punycode_query_name() {
    let (compiled, skipped) =
        compile_text("b\u{fc}cher.example.test\n".as_bytes(), ListFormat::Domains)
            .expect("compiles");
    assert_eq!(skipped, 0);
    let matcher = ListMatcher::build(&compiled.bytes).expect("a matcher");
    assert!(matcher.matches(&wire("xn--bcher-kva.example.test")));
    assert!(matcher.matches(&wire("www.xn--bcher-kva.example.test")));
}

// ---- The compiler ----

#[test]
fn duplicates_are_removed() {
    let compiled = compile_keys(vec![
        key("a.example.test"),
        key("b.example.test"),
        key("a.example.test"),
        key("A.Example.Test."),
    ])
    .expect("compiles");
    assert_eq!(compiled.entries, 2);
    assert_eq!(
        texts(&decode(&compiled.bytes).expect("decodes")),
        ["a.example.test", "b.example.test"]
    );
}

#[test]
fn a_name_below_a_listed_name_is_dropped() {
    let compiled = compile_keys(vec![
        key("a.example.test"),
        key("example.test"),
        key("deep.a.example.test"),
    ])
    .expect("compiles");
    assert_eq!(compiled.entries, 1);
    assert_eq!(
        decode(&compiled.bytes).expect("decodes"),
        [key("example.test")]
    );
}

#[test]
fn a_name_that_only_shares_octets_with_a_listed_name_is_kept() {
    // The keys of "example.test" and "exampled.test" differ in a length octet, not at a label
    // boundary, and "notexample.test" is a different name altogether.
    let compiled = compile_keys(vec![
        key("example.test"),
        key("exampled.test"),
        key("notexample.test"),
        key("example.other"),
    ])
    .expect("compiles");
    assert_eq!(compiled.entries, 4);
}

#[test]
fn decode_returns_the_keys_sorted() {
    let names = [
        "zz.example.test",
        "aa.example.test",
        "mm.other.test",
        "b.test2",
    ];
    let bytes = compiled(&names);
    let decoded = decode(&bytes).expect("decodes");
    let mut expected: Vec<Vec<u8>> = names.iter().map(|name| key(name)).collect();
    expected.sort();
    assert_eq!(decoded, expected);
}

#[test]
fn the_bytes_start_with_the_magic_and_the_count() {
    let compiled = compile_keys(vec![key("a.example.test"), key("b.example.test")]).expect("ok");
    assert_eq!(&compiled.bytes[..4], MAGIC);
    assert_eq!(compiled.bytes[4], 2, "the entry count follows the magic");
}

#[test]
fn compiled_bytes_round_trip() {
    let names: Vec<String> = (0..500)
        .map(|i| format!("host{i}.zone{}.example.test", i % 7))
        .collect();
    let keys: Vec<Vec<u8>> = names.iter().map(|name| key(name)).collect();
    let compiled = compile_keys(keys.clone()).expect("compiles");
    assert_eq!(compiled.entries, 500);
    let mut sorted = keys;
    sorted.sort();
    assert_eq!(decode(&compiled.bytes).expect("decodes"), sorted);
    let recompiled = compile_keys(sorted).expect("compiles again");
    assert_eq!(recompiled, compiled, "the format is canonical");
}

#[test]
fn an_empty_list_compiles_to_the_magic_and_a_zero() {
    let compiled = compile_keys(Vec::new()).expect("compiles");
    assert_eq!(compiled.entries, 0);
    assert_eq!(compiled.bytes, [b'T', b'K', b'L', b'1', 0]);
    assert_eq!(decode(&compiled.bytes), Ok(Vec::new()));
}

#[test]
fn compile_text_returns_the_compiled_version_and_the_skipped_lines() {
    let text = b"0.0.0.0 a.example.test\n0.0.0.0 b.example.test\nnot a hosts line\n";
    let (compiled, skipped) = compile_text(text, ListFormat::Hosts).expect("compiles");
    assert_eq!(compiled.entries, 2);
    assert_eq!(skipped, 1);
}

#[test]
fn decode_refuses_truncated_bytes() {
    let bytes = compiled(&["a.example.test", "b.example.test"]);
    for len in 0..bytes.len() {
        assert_eq!(
            decode(&bytes[..len]),
            Err(CompileError::Malformed),
            "{len} of {} octets",
            bytes.len()
        );
    }
    assert!(decode(&bytes).is_ok());
}

#[test]
fn decode_refuses_a_wrong_magic() {
    let mut bytes = compiled(&["a.example.test"]);
    bytes[3] = b'2';
    assert_eq!(decode(&bytes), Err(CompileError::Malformed));
    assert_eq!(decode(b"XXXX\x00"), Err(CompileError::Malformed));
    assert_eq!(decode(b""), Err(CompileError::Malformed));
}

#[test]
fn decode_refuses_trailing_bytes() {
    let mut bytes = compiled(&["a.example.test"]);
    bytes.push(0);
    assert_eq!(decode(&bytes), Err(CompileError::Malformed));
    assert_eq!(decode(&raw(0, &[0])), Err(CompileError::Malformed));
}

#[test]
fn decode_refuses_a_key_with_a_zero_length_label() {
    // One entry: shares 0 octets, 3 follow: label "a", then a label of length 0.
    assert_eq!(
        decode(&raw(1, &[0, 3, 1, b'a', 0])),
        Err(CompileError::Malformed)
    );
    // One entry whose only octet is a zero label length.
    assert_eq!(decode(&raw(1, &[0, 1, 0])), Err(CompileError::Malformed));
    // The same entries, valid, decode.
    assert_eq!(
        decode(&raw(1, &[0, 2, 1, b'a'])).expect("decodes"),
        [vec![1, b'a']]
    );
}

#[test]
fn decode_refuses_an_entry_that_is_not_a_whole_key() {
    // A label that claims more octets than the key holds.
    assert_eq!(
        decode(&raw(1, &[0, 2, 5, b'a'])),
        Err(CompileError::Malformed)
    );
    // A label longer than 63 octets.
    let mut long = vec![0, 65, 64];
    long.extend(std::iter::repeat_n(b'a', 64));
    assert_eq!(decode(&raw(1, &long)), Err(CompileError::Malformed));
    // An entry that adds nothing.
    assert_eq!(decode(&raw(1, &[0, 0])), Err(CompileError::Malformed));
}

#[test]
fn decode_refuses_a_front_coding_that_shares_more_than_the_key_before() {
    assert_eq!(
        decode(&raw(1, &[3, 2, 1, b'a'])),
        Err(CompileError::Malformed)
    );
    let two = [0, 2, 1, b'a', 5, 2, 1, b'b'];
    assert_eq!(decode(&raw(2, &two)), Err(CompileError::Malformed));
}

#[test]
fn decode_refuses_a_count_that_does_not_match_the_entries() {
    let entries = [0, 2, 1, b'a'];
    assert_eq!(decode(&raw(2, &entries)), Err(CompileError::Malformed));
    assert_eq!(decode(&raw(0, &entries)), Err(CompileError::Malformed));
}

#[test]
fn decode_refuses_a_count_above_the_limit() {
    let over = u64::try_from(MAX_ENTRIES).expect("fits") + 1;
    assert_eq!(decode(&raw(over, &[])), Err(CompileError::Malformed));
    assert_eq!(
        decode(&[
            b'T', b'K', b'L', b'1', 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
            0x01
        ]),
        Err(CompileError::Malformed),
        "a varint of more than ten octets"
    );
}

#[test]
fn the_matcher_refuses_malformed_bytes() {
    let good = compiled(&["a.example.test"]);
    let mut truncated = good.clone();
    truncated.pop();
    let mut trailing = good;
    trailing.push(7);
    for bytes in [
        Vec::new(),
        b"TKL".to_vec(),
        b"NOPE\x00".to_vec(),
        truncated,
        trailing,
        raw(1, &[0, 3, 1, b'a', 0]),
    ] {
        assert_eq!(
            ListMatcher::build(&bytes).err(),
            Some(CompileError::Malformed),
            "{bytes:?}"
        );
    }
}

// ---- The matcher ----

#[test]
fn a_name_at_a_listed_name_matches() {
    let matcher = matcher(&["ads.example.test", "tracker.example.test"]);
    assert!(matcher.matches(&wire("ads.example.test")));
    assert!(matcher.matches(&wire("tracker.example.test")));
}

#[test]
fn a_name_built_by_the_name_buffer_matches_like_the_hand_written_wire() {
    let matcher = matcher(&["ads.example.test"]);
    let name = DnsName::new("www.ads.example.test").expect("name");
    let buffer = NameBuf::from_dns_name(&name);
    assert_eq!(buffer.as_wire(), wire("www.ads.example.test"));
    assert!(matcher.matches(buffer.as_wire()));
}

#[test]
fn a_name_under_a_listed_name_matches() {
    let matcher = matcher(&["example.test"]);
    assert!(matcher.matches(&wire("www.example.test")));
    assert!(matcher.matches(&wire("a.b.c.d.example.test")));
}

#[test]
fn a_name_beside_a_listed_name_does_not_match() {
    let matcher = matcher(&["example.test"]);
    assert!(!matcher.matches(&wire("notexample.test")));
    assert!(!matcher.matches(&wire("www.notexample.test")));
    assert!(!matcher.matches(&wire("example.test.other")));
    assert!(!matcher.matches(&wire("example.other")));
    assert!(!matcher.matches(&wire("exampled.test")));
    assert!(!matcher.matches(&wire("xample.test")));
}

#[test]
fn the_parent_of_a_listed_name_does_not_match() {
    let matcher = matcher(&["ads.example.test"]);
    assert!(!matcher.matches(&wire("example.test")));
    assert!(!matcher.matches(&wire("test")));
    assert!(!matcher.matches(&wire("other.example.test")));
}

#[test]
fn the_root_does_not_match() {
    let matcher = matcher(&["example.test", "test"]);
    assert!(!matcher.matches(&[0]));
    assert!(!matcher.matches(&[]));
}

#[test]
fn a_listed_top_label_covers_every_name_below_it() {
    let matcher = matcher(&["test"]);
    assert!(matcher.matches(&wire("test")));
    assert!(matcher.matches(&wire("anything.example.test")));
    assert!(!matcher.matches(&wire("example.other")));
}

#[test]
fn an_empty_matcher_matches_nothing() {
    let matcher = matcher(&[]);
    assert_eq!(matcher.entries(), 0);
    assert!(!matcher.matches(&wire("example.test")));
    assert!(!matcher.matches(&[0]));
    let default = ListMatcher::default();
    assert!(!default.matches(&wire("example.test")));
    assert_eq!(default.entries(), 0);
}

#[test]
fn the_matcher_counts_the_names_after_the_compiler_dropped_the_covered_ones() {
    let matcher = matcher(&["a.example.test", "example.test", "b.other.test"]);
    assert_eq!(matcher.entries(), 2);
    assert!(matcher.matches(&wire("a.example.test")));
}

#[test]
fn a_query_name_that_ends_inside_a_label_does_not_match_or_panic() {
    let matcher = matcher(&["example.test"]);
    assert!(!matcher.matches(&[7, b'e', b'x']));
    assert!(!matcher.matches(&[4, b't', b'e', b's', b't', 9]));
    assert!(!matcher.matches(&[4, b't', b'e', b's', b't', 0, 0, 0]));
}

#[test]
fn ten_thousand_names_match_and_ten_thousand_others_do_not() {
    let mut text = String::new();
    for i in 0..10_000 {
        writeln!(text, "host{i}.example.test").expect("a string");
    }
    let (compiled, skipped) = compile_text(text.as_bytes(), ListFormat::Domains).expect("ok");
    assert_eq!(skipped, 0);
    assert_eq!(compiled.entries, 10_000);
    assert!(
        compiled.bytes.len() < text.len(),
        "the version is smaller than the text"
    );
    let matcher = ListMatcher::build(&compiled.bytes).expect("a matcher");
    assert_eq!(matcher.entries(), 10_000);
    for i in 0..10_000 {
        assert!(
            matcher.matches(&wire(&format!("host{i}.example.test"))),
            "host{i}"
        );
        assert!(
            matcher.matches(&wire(&format!("www.host{i}.example.test"))),
            "www.host{i}"
        );
    }
    for i in 0..10_000 {
        assert!(
            !matcher.matches(&wire(&format!("other{i}.example.test"))),
            "other{i}"
        );
        assert!(
            !matcher.matches(&wire(&format!("host{i}.example.other"))),
            "host{i} elsewhere"
        );
    }
    assert!(!matcher.matches(&wire("example.test")));
}

#[test]
fn the_matcher_size_is_sane() {
    let names: Vec<String> = (0..10_000)
        .map(|i| format!("host{i}.example.test"))
        .collect();
    let keys: Vec<Vec<u8>> = names.iter().map(|name| key(name)).collect();
    let compiled = compile_keys(keys).expect("compiles");
    let matcher = ListMatcher::build(&compiled.bytes).expect("a matcher");
    assert_eq!(matcher.entries(), compiled.entries);
    // A table of at least two slots a name (eight octets each) and the names themselves.
    assert!(matcher.bytes() > 10_000 * 16, "{} octets", matcher.bytes());
    assert!(matcher.bytes() < 10_000 * 100, "{} octets", matcher.bytes());
    let debug = format!("{matcher:?}");
    assert!(debug.contains("10000"), "{debug}");
}

#[test]
fn a_matcher_clone_answers_like_the_original() {
    let matcher = matcher(&["example.test"]);
    let copy = matcher.clone();
    assert!(copy.matches(&wire("www.example.test")));
    assert_eq!(copy.entries(), matcher.entries());
    assert_eq!(copy.bytes(), matcher.bytes());
}

// ---- The property test ----

/// A name as labels from the left, each from a small alphabet so that names often share a
/// suffix and labels often share a prefix.
fn labels(max: usize) -> impl Strategy<Value = Vec<&'static str>> {
    prop::collection::vec(
        prop::sample::select(vec!["a", "b", "ab", "ba", "abc"]),
        1..=max,
    )
}

proptest! {
    #[test]
    fn matches_equals_a_listed_name_being_a_suffix_at_a_label_boundary(
        listed in prop::collection::vec(labels(4), 0..8),
        queries in prop::collection::vec(labels(6), 1..16),
    ) {
        let names: Vec<String> = listed.iter().map(|labels| labels.join(".")).collect();
        let bytes = compile_keys(names.iter().map(|name| key(name)).collect())
            .expect("compiles")
            .bytes;
        let matcher = ListMatcher::build(&bytes).expect("a matcher");
        for query in &queries {
            let naive = listed.iter().any(|name| query.ends_with(name));
            let text = query.join(".");
            prop_assert_eq!(matcher.matches(&wire(&text)), naive, "{}", text);
        }
    }

    #[test]
    fn the_compiler_keeps_exactly_the_names_no_other_name_covers(
        listed in prop::collection::vec(labels(4), 0..12),
    ) {
        let names: std::collections::BTreeSet<String> =
            listed.iter().map(|labels| labels.join(".")).collect();
        let compiled = compile_keys(names.iter().map(|name| key(name)).collect())
            .expect("compiles");
        let kept: Vec<String> = texts(&decode(&compiled.bytes).expect("decodes"));
        let expected: std::collections::BTreeSet<String> = listed
            .iter()
            .filter(|name| {
                !listed
                    .iter()
                    .any(|other| other.len() < name.len() && name.ends_with(other))
            })
            .map(|labels| labels.join("."))
            .collect();
        prop_assert_eq!(compiled.entries, u64::try_from(kept.len()).expect("fits"));
        prop_assert_eq!(
            kept.into_iter().collect::<std::collections::BTreeSet<_>>(),
            expected
        );
    }

    #[test]
    fn a_query_of_any_octets_never_panics(
        query in prop::collection::vec(any::<u8>(), 0..300),
    ) {
        let matcher = matcher(&["a.example.test", "example.other", "b"]);
        let _ = matcher.matches(&query);
    }

    #[test]
    fn decode_never_panics_and_a_matcher_follows_it(
        bytes in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let decoded = decode(&bytes);
        let built = ListMatcher::build(&bytes);
        prop_assert_eq!(decoded.is_ok(), built.is_ok());
    }
}

/// A list whose entries are larger than `DEFLATE_ABOVE`, so its version is deflated.
fn large_version() -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut text = String::new();
    for i in 0..50_000u64 {
        let spread = i.wrapping_mul(0x9e37_79b9) % 1_000_003;
        writeln!(text, "name{i}-{spread}.large.example.test").expect("a string");
    }
    let (compiled, _) = compile_text(text.as_bytes(), ListFormat::Domains).expect("ok");
    let keys = decode(&compiled.bytes).expect("decodes");
    (compiled.bytes, keys)
}

#[test]
fn a_large_version_is_deflated_and_reads_back_whole() {
    let (bytes, keys) = large_version();
    assert_eq!(&bytes[..4], MAGIC_DEFLATE);
    assert_eq!(keys.len(), 50_000);
    assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
    let matcher = ListMatcher::build(&bytes).expect("a matcher");
    let spread = 7u64.wrapping_mul(0x9e37_79b9) % 1_000_003;
    assert!(matcher.matches(&wire(&format!("name7-{spread}.large.example.test"))));
    assert!(matcher.matches(&wire(&format!("www.name7-{spread}.large.example.test"))));
    assert!(!matcher.matches(&wire("name7.large.example.test")));
    // A small list stays as it is.
    let (small, _) = compile_text(b"a.example.test\n", ListFormat::Domains).expect("ok");
    assert_eq!(&small.bytes[..4], MAGIC);
    const { assert!(DEFLATE_ABOVE >= 1024) };
}

#[test]
fn a_deflated_version_with_trailing_or_missing_bytes_or_a_wrong_length_is_refused() {
    let (bytes, _) = large_version();
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(decode(&trailing), Err(CompileError::Malformed));
    let truncated = &bytes[..bytes.len() - 10];
    assert_eq!(decode(truncated), Err(CompileError::Malformed));
    // The length of the entries (after the magic and the count) one larger than they are.
    let mut pos = 4;
    while bytes[pos] & 0x80 != 0 {
        pos += 1;
    }
    pos += 1;
    let mut longer = bytes[..pos].to_vec();
    let mut len = 0u64;
    let mut shift = 0;
    let mut at = pos;
    loop {
        len |= u64::from(bytes[at] & 0x7f) << shift;
        shift += 7;
        at += 1;
        if bytes[at - 1] & 0x80 == 0 {
            break;
        }
    }
    let mut value = len + 1;
    loop {
        let low = u8::try_from(value & 0x7f).expect("seven bits");
        value >>= 7;
        if value == 0 {
            longer.push(low);
            break;
        }
        longer.push(low | 0x80);
    }
    longer.extend_from_slice(&bytes[at..]);
    assert_eq!(decode(&longer), Err(CompileError::Malformed));
    assert!(ListMatcher::build(&longer).is_err());
}
