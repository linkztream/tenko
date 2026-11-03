//! The import's reader against the reader of 0.0.10 (`domain`'s zone file scanner, the copy
//! in `zonefile_support`) on a generated zone of 100,000 records of mixed types: wall time
//! (the best of five runs each) and the allocations (count, bytes, and the peak of the bytes
//! held while reading, sampled after every record). Tenko's reader must not be slower.
//!
//! The zone file import is a cold path, so the comparison is a measurement run by hand on
//! a release build, not a gate of every test run:
//!
//! ```text
//! cargo test -p tenko-dns --release --test zonefile_perf -- --ignored --nocapture
//! ```

mod zonefile_support;

use std::{alloc::System, fmt::Write as _, hint::black_box, time::Instant};

use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use tenko_core::dns::DnsName;
use tenko_dns::zone::zonefile::Reader;
use zonefile_support::OldReader;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// A zone of `count` records of mixed types, as an operator's file looks: an SOA, NS,
/// then hosts with A, AAAA, TXT, MX, SRV, CNAME, CAA, DS and HTTPS records, some in
/// parentheses with comments, some with omitted owners.
fn zone(count: usize) -> String {
    let mut text = String::with_capacity(count * 60);
    text.push_str(
        "$ORIGIN example.test.\n$TTL 3600\n\
         @ IN SOA ns1 hostmaster ( 2026110301 ; serial\n 3600 900 1209600 300 )\n\
         @ IN NS ns1\n",
    );
    for n in 0..count {
        let host = n / 4;
        let _ = match n % 12 {
            0 => writeln!(text, "host{host} IN A 192.0.2.{}", n % 250 + 1),
            1 => writeln!(text, "  IN AAAA 2001:db8::{:x}", n % 65_000 + 1),
            2 => writeln!(text, "  300 IN TXT \"v=spf1 -all\" \"host {n}\""),
            3 => writeln!(text, "host{host} IN MX 10 mail{}.example.test.", n % 7),
            4 => writeln!(
                text,
                "_sip._tcp.host{host} IN SRV 10 60 5060 sip{}.example.test.",
                n % 5
            ),
            5 => writeln!(text, "alias{n} IN CNAME host{host}"),
            6 => writeln!(text, "host{host} IN CAA 0 issue \"ca.example.net\""),
            7 => writeln!(
                text,
                "sub{n} IN DS 12345 13 2 ( 2BB183AF5F22588179A53B0A98631FAD1A292118 ; digest\n \
                 2BB183AF5F225881 )"
            ),
            8 => writeln!(text, "web{n} IN HTTPS 1 . alpn=h2,h3 port=443"),
            9 => writeln!(text, "host{host} 600 IN A 198.51.100.{}", n % 250 + 1),
            10 => writeln!(
                text,
                "txt{n} IN TXT ( \"part one\" ; a comment\n \"part two\" )"
            ),
            _ => writeln!(text, "ns{n} IN NS ns1.example.test."),
        };
    }
    text
}

fn read_new(text: &str, apex: &DnsName) -> usize {
    let mut reader = Reader::new(text, apex, 1).expect("reader");
    let mut count = 0;
    while let Some(item) = reader.next_item().expect("reads") {
        black_box(item);
        count += 1;
    }
    count
}

fn read_old(text: &str, apex: &DnsName) -> usize {
    let mut reader = OldReader::new(text, apex, 1).expect("reader");
    let mut count = 0;
    while let Some(item) = reader.next_item().expect("reads") {
        black_box(item);
        count += 1;
    }
    count
}

/// The best wall time of five runs, in milliseconds, and the items read.
fn time(read: &dyn Fn() -> usize) -> (f64, usize) {
    let mut best = f64::MAX;
    let mut count = 0;
    for _ in 0..5 {
        let start = Instant::now();
        count = read();
        best = best.min(start.elapsed().as_secs_f64() * 1_000.0);
    }
    (best, count)
}

/// The allocations of one run (count, bytes) and the peak of the bytes held, sampled after
/// every item.
fn memory(next: &mut dyn FnMut() -> bool) -> (usize, usize, isize) {
    let region = Region::new(GLOBAL);
    let mut peak = 0isize;
    while next() {
        let stats = region.change();
        let held = isize::try_from(stats.bytes_allocated).unwrap_or(isize::MAX)
            - isize::try_from(stats.bytes_deallocated).unwrap_or(isize::MAX)
            + stats.bytes_reallocated;
        peak = peak.max(held);
    }
    let stats = region.change();
    (stats.allocations, stats.bytes_allocated, peak)
}

#[test]
#[ignore = "a measurement on a release build, run by hand"]
fn the_new_reader_is_not_slower_than_the_reader_of_0_0_10() {
    let apex = DnsName::new("example.test").expect("name");
    let text = zone(100_000);
    let (old_ms, old_count) = time(&|| read_old(&text, &apex));
    let (new_ms, new_count) = time(&|| read_new(&text, &apex));
    assert_eq!(new_count, old_count);

    let mut old = OldReader::new(&text, &apex, 1).expect("reader");
    let old_memory = memory(&mut || old.next_item().expect("reads").is_some());
    drop(old);
    let mut new = Reader::new(&text, &apex, 1).expect("reader");
    let new_memory = memory(&mut || new.next_item().expect("reads").is_some());
    drop(new);

    println!(
        "{new_count} records, {} bytes of text\n\
         reader of 0.0.10: {old_ms:.1} ms, {} allocations, {} bytes allocated, peak {} bytes held\n\
         Tenko's reader:   {new_ms:.1} ms, {} allocations, {} bytes allocated, peak {} bytes held",
        text.len(),
        old_memory.0,
        old_memory.1,
        old_memory.2,
        new_memory.0,
        new_memory.1,
        new_memory.2,
    );
    assert!(
        new_ms <= old_ms,
        "Tenko's reader took {new_ms:.1} ms, the reader of 0.0.10 {old_ms:.1} ms"
    );
}
