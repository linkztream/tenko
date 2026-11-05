//! The readers of UPDATE and transfer messages size their vectors by what parses, not by
//! the record counts of the header: a short message that claims 65,535 records reserves
//! nothing large (DNS-09, DNS-11). The counting allocator measures the parse.

use std::{alloc::System, hint::black_box};

use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use tenko_dns::{
    update::message::{parse, write_request},
    wire,
    xfr::message::read_answer,
};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// Bytes a parse of a message without records may allocate: far below one element per
/// claimed record (65,535 elements of any of these record types are megabytes).
const SMALL: usize = 16 * 1024;

/// The fewest bytes `f` allocated over several runs (other threads of the harness may
/// allocate during one run).
fn least_allocated(mut f: impl FnMut()) -> usize {
    f();
    (0..5)
        .map(|_| {
            let region = Region::new(GLOBAL);
            f();
            region.change().bytes_allocated
        })
        .min()
        .expect("five runs")
}

#[test]
fn an_update_that_claims_many_records_reserves_nothing_large() {
    let mut message = Vec::new();
    write_request(
        &mut message,
        1,
        b"\x07example\x04test\x00",
        (0, &[]),
        (0, &[]),
    );
    // PRCOUNT and UPCOUNT claim 65,535 records each; the message holds none.
    message[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
    message[8..10].copy_from_slice(&u16::MAX.to_be_bytes());
    let bytes = least_allocated(|| {
        let _ = black_box(parse(black_box(&message)));
    });
    assert!(bytes < SMALL, "the parse allocated {bytes} bytes");
    assert!(parse(&message).is_err(), "the message is cut short");
}

#[test]
fn a_transfer_answer_that_claims_many_records_reserves_nothing_large() {
    let mut message = Vec::new();
    // A SOA query (type 6) and its answer.
    wire::write_query(&mut message, 1, "example.test", 6, None);
    // A response whose ANCOUNT claims 65,535 records and holds none.
    message[2] |= 0x80;
    message[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
    let bytes = least_allocated(|| {
        let _ = black_box(read_answer(black_box(&message)));
    });
    assert!(bytes < SMALL, "the read allocated {bytes} bytes");
    assert!(read_answer(&message).is_err(), "the message is cut short");
}
