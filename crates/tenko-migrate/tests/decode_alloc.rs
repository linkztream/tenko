//! Decoding a push allocates no more than `body::DECODE_ALLOCATION_BOUND` in all, however the
//! body is shaped: a counting global allocator (`stats_alloc`, as the DNS, DHCP and dashboard
//! allocation tests use it) sums every allocation `body::decode` makes for the most
//! element-dense bodies the bounds let through to the parser (list items of the cheapest
//! kinds, up to `MAX_ELEMENTS`, gzipped so that they pass the wire bound), and for one item
//! more, which is refused before the parse. The first check proves that the counter sees an
//! allocation, so a pass means something.
//!
//! The allocator counts every thread of the process, so the binary is its own harness
//! (`harness = false` in Cargo.toml), for the reason `crates/tenko-dns/tests/alloc.rs` gives.

use std::{alloc::System, io::Write as _};

use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use tenko_core::ir::mirror::{MAX_ELEMENTS, MAX_INFLATED_BYTES};
use tenko_migrate::mirror::body::{self, DECODE_ALLOCATION_BOUND};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const TEST_NAME: &str = "a_hostile_body_allocates_within_the_bound";

/// An envelope whose server options are `items`, in the shape the parser reads in full.
fn envelope(items: &str) -> String {
    format!(
        r#"{{"format":1,"sequence":1,"taken_at":"2026-11-01T08:00:00Z","source":{{"kind":"windows-dhcp","server":"dc1.corp.example.test","adapter":"a","adapter_version":"1"}},"dhcp":{{"server_options":[{items}]}},"losses":{{"entries":[]}}}}"#
    )
}

fn gzip(text: &str) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(text.as_bytes()).expect("gzip");
    encoder.finish().expect("gzip")
}

/// The octets `decode` allocates for `body`, and whether it refused the body.
fn measured(body: &[u8]) -> (usize, bool) {
    let region = Region::new(GLOBAL);
    let refused = std::hint::black_box(body::decode(body, true)).is_err();
    (region.change().bytes_allocated, refused)
}

fn a_hostile_body_allocates_within_the_bound() {
    let region = Region::new(GLOBAL);
    drop(std::hint::black_box(vec![0u8; 64]));
    assert!(region.change().allocations > 0, "the counter counts");

    // Options with one empty value each: two list items in about 26 octets.
    let options = envelope(&vec![r#"{"code":1,"values":[""]}"#; MAX_ELEMENTS / 2 - 1].join(","));
    // Empty strings: one list item in three octets, the cheapest the parser keeps.
    let values = envelope(&format!(
        r#"{{"code":1,"values":[{}]}}"#,
        vec![r#""""#; MAX_ELEMENTS - 2].join(",")
    ));
    for (what, text) in [("options", &options), ("values", &values)] {
        assert!(
            text.len() <= MAX_INFLATED_BYTES,
            "{what}: within the inflated bound"
        );
        let (allocated, refused) = measured(&gzip(text));
        assert!(refused, "{what}: the counts refuse it after the parse");
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
    let over = envelope(&vec![r#"{"code":1,"values":[""]}"#; MAX_ELEMENTS / 2 + 1].join(","));
    let (allocated, refused) = measured(&gzip(&over));
    assert!(refused, "over the bound");
    assert!(
        allocated <= 3 * over.len(),
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
