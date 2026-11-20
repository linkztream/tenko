//! Decoding a push allocates no more than `body::DECODE_ALLOCATION_BOUND` in all, however the
//! body is shaped: a counting global allocator (`stats_alloc`, as the DNS, DHCP and dashboard
//! allocation tests use it) sums every allocation `body::decode` makes and every growth of
//! one, for the most element-dense bodies of each kind the bounds let through to the parser
//! (the cheapest items, the largest top-level items, the largest nested items in lists of
//! one, the longest strings with escapes, the largest text), gzipped so that they pass the
//! wire bound, and for one item more, which is refused before the parse. The first check
//! proves that the counter sees an allocation and a growth, so a pass means something.
//!
//! The allocator counts every thread of the process, so the binary is its own harness
//! (`harness = false` in Cargo.toml), for the reason `crates/tenko-dns/tests/alloc.rs` gives.

use std::{alloc::System, io::Write as _};

use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use tenko_core::ir::mirror::{MAX_ELEMENTS, MAX_INFLATED_BYTES};
use tenko_migrate::mirror::body::{self, DECODE_ALLOCATION_BOUND, MAX_STRING_OCTETS};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const TEST_NAME: &str = "a_hostile_body_allocates_within_the_bound";

/// An envelope whose DHCP content is `dhcp`.
fn envelope(dhcp: &str) -> String {
    format!(
        r#"{{"format":1,"sequence":1,"taken_at":"2026-11-01T08:00:00Z","source":{{"kind":"windows-dhcp","server":"dc1.corp.example.test","adapter":"a","adapter_version":"1"}},"dhcp":{{{dhcp}}},"losses":{{"entries":[]}}}}"#
    )
}

/// `count` copies of `item`, as a JSON list.
fn list(item: &str, count: usize) -> String {
    format!("[{}]", vec![item; count].join(","))
}

fn gzip(text: &str) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(text.as_bytes()).expect("gzip");
    encoder.finish().expect("gzip")
}

/// The octets `decode` allocates for `body`, growths included, and whether it refused it.
fn measured(body: &[u8]) -> (usize, bool) {
    let region = Region::new(GLOBAL);
    let refused = std::hint::black_box(body::decode(body, true)).is_err();
    // `bytes_allocated` counts the growth of a reallocation as well.
    (region.change().bytes_allocated, refused)
}

fn a_hostile_body_allocates_within_the_bound() {
    let region = Region::new(GLOBAL);
    let mut probe = std::hint::black_box(vec![0u8; 64]);
    probe.extend_from_slice(&[0; 64]);
    drop(probe);
    let change = region.change();
    assert!(
        change.allocations > 0 && change.reallocations > 0 && change.bytes_allocated >= 128,
        "the counter counts allocations and growths"
    );

    let half = MAX_ELEMENTS / 2;
    let escaped = format!(r#""{}""#, "\\n".repeat(MAX_STRING_OCTETS / 2));
    let shapes = [
        // Options with one empty value each: two items in about 26 octets.
        (
            "options",
            envelope(&format!(
                r#""server_options":{}"#,
                list(r#"{"code":1,"values":[""]}"#, half - 1)
            )),
        ),
        // Empty strings: one item in three octets, the cheapest the parser keeps.
        (
            "values",
            envelope(&format!(
                r#""server_options":[{{"code":1,"values":{}}}]"#,
                list(r#""""#, MAX_ELEMENTS - 2)
            )),
        ),
        // Scopes, the largest top-level item, each with one reservation, the largest item
        // of a list inside another, in a list of one.
        (
            "scopes",
            envelope(&format!(
                r#""scopes":{}"#,
                list(
                    r#"{"cidr":"192.0.2.0/24","reservations":[{"ip":"192.0.2.1","client":{}}]}"#,
                    half - 1
                )
            )),
        ),
        // Leases, the bulk of a real source.
        (
            "leases",
            envelope(&format!(
                r#""leases":{}"#,
                list(
                    r#"{"ip":"192.0.2.1","scope":"192.0.2.0/24","client":{},"state":"active"}"#,
                    MAX_ELEMENTS - 1
                )
            )),
        ),
        // The longest strings with escapes, as many as the text holds.
        (
            "strings",
            envelope(&format!(
                r#""server_options":[{{"code":1,"values":{}}}]"#,
                list(&escaped, (MAX_INFLATED_BYTES - 1024) / (escaped.len() + 1))
            )),
        ),
        // The largest text: inflated to the bound exactly, and one octet more.
        ("text", format!("{}0", " ".repeat(MAX_INFLATED_BYTES - 1))),
        ("over the text", " ".repeat(MAX_INFLATED_BYTES + 1)),
    ];
    for (what, text) in &shapes {
        assert!(
            text.len() <= MAX_INFLATED_BYTES + 1,
            "{what}: within the inflated bound"
        );
        let (allocated, refused) = measured(&gzip(text));
        assert!(refused, "{what}: refused by a bound or a count");
        assert!(
            allocated <= DECODE_ALLOCATION_BOUND,
            "{what}: {allocated} octets allocated, the bound is {DECODE_ALLOCATION_BOUND}"
        );
        println!(
            "{what}: {} octets of JSON, {allocated} octets allocated",
            text.len()
        );
    }

    // One item more is refused before anything is parsed: little more than the text.
    let over = envelope(&format!(
        r#""server_options":{}"#,
        list(r#"{"code":1,"values":[""]}"#, half + 1)
    ));
    let (allocated, refused) = measured(&gzip(&over));
    assert!(refused, "over the bound");
    assert!(
        allocated <= 2 * over.len(),
        "{allocated} octets for {} of text",
        over.len()
    );
}

/// Flags of libtest that take a value, which is not a name filter.
const VALUED_FLAGS: [&str; 5] = ["--format", "--test-threads", "--color", "--skip", "-Z"];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--list") {
        if !args.iter().any(|arg| arg == "--ignored") {
            println!("{TEST_NAME}: test");
        }
        return;
    }
    let exact = args.iter().any(|arg| arg == "--exact");
    let mut after_valued = false;
    let mut filters = Vec::new();
    for arg in &args {
        if after_valued {
            after_valued = false;
        } else if arg.starts_with('-') {
            after_valued = VALUED_FLAGS.contains(&arg.as_str());
        } else {
            filters.push(arg.as_str());
        }
    }
    let selected = filters.is_empty()
        || filters.iter().any(|filter| {
            (exact && *filter == TEST_NAME) || (!exact && TEST_NAME.contains(filter))
        });
    if !selected {
        println!("\nrunning 0 tests\n\ntest result: ok. 0 passed; 1 filtered out\n");
        return;
    }
    println!("\nrunning 1 test");
    a_hostile_body_allocates_within_the_bound();
    println!("test {TEST_NAME} ... ok\n\ntest result: ok. 1 passed; 0 failed\n");
}
