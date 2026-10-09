//! Criterion micro-benchmarks of the two DNS wire-format backends.
//!
//! Every operation is written once, generic over [`Codec`], and instantiated
//! for `DomainCodec` and `HickoryCodec`; the same operation objects are used
//! for the allocation counts and for the timing runs. Benchmark names are
//! `<operation>/<backend>`:
//!
//! * `parse`: `Codec::parse` of a captured A query with an OPT record.
//! * `build_a`: `Codec::build` of the A answer (parse and lookup done once,
//!   outside the timed loop).
//! * `build_nxdomain`: `Codec::build` of an NXDOMAIN with the SOA in the
//!   authority section (name compression of the SOA names).
//! * `roundtrip`: `respond`, the server's whole per-packet hot path (parse,
//!   zone lookup, build) for one A query.
//! * `roundtrip_mix`: `respond` over 1,024 pre-generated queries, one query
//!   per iteration, every 20th query NXDOMAIN.
//! * `hickory_message/parse` and `hickory_message/roundtrip`: reference only,
//!   hickory's high-level `Message` API instead of the lean path used by
//!   `HickoryCodec`. Not a `Codec`.
//!
//! Before criterion runs, the allocator counters (`stats_alloc`) are read over
//! 10,000 calls of each operation and printed as a Markdown table. After the
//! run, criterion's `estimates.json` files are summarised in a second table.
//! Both tables are also written to `results/raw/codec-bench.md`.
//!
//! The counting allocator is installed for the whole process, so the timing
//! runs include its overhead (atomic counter updates on every allocation and
//! deallocation). Building with `RUSTFLAGS="--cfg no_alloc_counting"` leaves
//! the system allocator in place: no allocation table, uninstrumented timings.

#![forbid(unsafe_code)]
// `no_alloc_counting` is a cfg flag set through RUSTFLAGS, not a Cargo feature.
#![allow(unexpected_cfgs)]

#[cfg(not(no_alloc_counting))]
use std::alloc::System;
use std::fmt::Write as _;
use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use criterion::{Bencher, Criterion};
#[cfg(not(no_alloc_counting))]
use stats_alloc::StatsAlloc;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats};

#[cfg(feature = "backend-domain")]
use spike_b_udp::backend::DomainCodec;
#[cfg(feature = "backend-hickory")]
use spike_b_udp::backend::HickoryCodec;
use spike_b_udp::backend::{Codec, QueryMeta, decide, max_response_len, respond};
use spike_b_udp::wire::{self, QTYPE_A, write_host_query};
use spike_b_udp::zone::{NameKey, Outcome, Zone};

#[cfg(not(no_alloc_counting))]
#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// Calls per operation before the allocation counters are read.
const ALLOC_WARMUP: usize = 100;
/// Calls per operation inside the allocation counting region.
const ALLOC_CALLS: usize = 10_000;

const ZONE_SIZE: u32 = 100_000;
const QUERY_ID: u16 = 0x1234;
/// Host number of the captured single-query packets.
const HOST_N: u32 = 4242;
const EDNS_UDP: u16 = 1232;
/// Number of pre-generated packets of `roundtrip_mix`.
const MIX_PACKETS: u32 = 1024;
/// Capacity of the reused response buffers.
const OUT_CAPACITY: usize = 4096;

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// One benchmarked operation: all state lives in the value, `run` is exactly
/// what is timed (and what is counted for allocations).
trait Op {
    fn run(&mut self);
}

/// Object-safe face of an [`Op`]. The dynamic dispatch happens once per
/// benchmark, outside the timed loop, which is monomorphic.
trait Case {
    fn time(&mut self, b: &mut Bencher<'_>);
    fn alloc_stats(&mut self) -> Stats;
}

impl<O: Op> Case for O {
    fn time(&mut self, b: &mut Bencher<'_>) {
        b.iter(|| self.run());
    }

    fn alloc_stats(&mut self) -> Stats {
        for _ in 0..ALLOC_WARMUP {
            self.run();
        }
        let region = Region::new(&INSTRUMENTED_SYSTEM);
        for _ in 0..ALLOC_CALLS {
            self.run();
        }
        region.change()
    }
}

/// Checks the header of a response to the captured `host-4242` / `nohost-4242`
/// A query (EDNS present, so one OPT record in the additional section).
fn check_response(label: &str, resp: &[u8], id: u16, rcode: u8, answers: u16, authorities: u16) {
    let h = wire::parse_header(resp)
        .unwrap_or_else(|| panic!("{label}: response shorter than a header"));
    assert!(h.qr && h.aa && !h.tc, "{label}: unexpected flags {h:?}");
    assert_eq!(h.id, id, "{label}: id");
    assert_eq!(h.rcode, rcode, "{label}: rcode");
    assert_eq!(
        (h.qdcount, h.ancount, h.nscount, h.arcount),
        (1, answers, authorities, 1),
        "{label}: section counts"
    );
}

fn check_a_response(label: &str, resp: &[u8]) {
    check_response(label, resp, QUERY_ID, wire::RCODE_NOERROR, 1, 0);
    // The A record is the last RR before the 11-byte OPT; its RDATA is the address.
    let ip = Zone::address_for(HOST_N).octets();
    let rdata = &resp[resp.len() - wire::OPT_LEN - 4..resp.len() - wire::OPT_LEN];
    assert_eq!(rdata, ip, "{label}: A record address");
}

fn check_nx_response(label: &str, resp: &[u8]) {
    check_response(label, resp, QUERY_ID, wire::RCODE_NXDOMAIN, 0, 1);
}

/// `Codec::parse` of one packet.
struct ParseOp<'a, C: Codec> {
    codec: C,
    packet: &'a [u8],
    key: NameKey,
}

impl<'a, C: Codec> ParseOp<'a, C> {
    fn new(packet: &'a [u8]) -> Self {
        let codec = C::new();
        let mut key = NameKey::new();
        let (_query, meta) = codec
            .parse(packet, &mut key)
            .unwrap_or_else(|e| panic!("{}: parse failed: {e}", C::NAME));
        assert_eq!(meta.id, QUERY_ID);
        assert_eq!(meta.qtype, QTYPE_A);
        assert_eq!(meta.edns.map(|e| e.udp_size), Some(EDNS_UDP));
        assert_eq!(key.as_bytes(), b"host-4242.example.test");
        Self { codec, packet, key }
    }
}

impl<C: Codec> Op for ParseOp<'_, C> {
    fn run(&mut self) {
        // The server clears the key before every parse.
        self.key.clear();
        let _ = black_box(self.codec.parse(black_box(self.packet), &mut self.key));
    }
}

/// `Codec::build` of the response to one pre-parsed packet.
struct BuildOp<'a, C: Codec> {
    codec: C,
    query: C::Query<'a>,
    meta: QueryMeta,
    outcome: Outcome,
    max_len: usize,
    out: Vec<u8>,
}

impl<'a, C: Codec> BuildOp<'a, C> {
    fn new(packet: &'a [u8], zone: &Zone, nx: bool) -> Self {
        let codec = C::new();
        let mut key = NameKey::new();
        let (query, meta) = codec
            .parse(packet, &mut key)
            .unwrap_or_else(|e| panic!("{}: parse failed: {e}", C::NAME));
        let outcome = decide(zone, &key, &meta);
        match outcome {
            Outcome::Answer(ip) if !nx => assert_eq!(ip, Zone::address_for(HOST_N)),
            Outcome::NxDomain if nx => {}
            other => panic!("{}: unexpected outcome {other:?} (nx = {nx})", C::NAME),
        }
        let max_len = max_response_len(&meta);
        let mut out = Vec::with_capacity(OUT_CAPACITY);
        let label = format!("build/{}", C::NAME);
        codec
            .build(&query, &meta, outcome, max_len, &mut out)
            .unwrap_or_else(|e| panic!("{label}: build failed: {e}"));
        if nx {
            check_nx_response(&label, &out);
        } else {
            check_a_response(&label, &out);
        }
        // A second build into the same buffer must discard the previous content.
        let first = out.clone();
        codec
            .build(&query, &meta, outcome, max_len, &mut out)
            .unwrap_or_else(|e| panic!("{label}: second build failed: {e}"));
        assert_eq!(out, first, "{label}: build into a reused buffer differs");
        Self {
            codec,
            query,
            meta,
            outcome,
            max_len,
            out,
        }
    }
}

impl<C: Codec> Op for BuildOp<'_, C> {
    fn run(&mut self) {
        let result = self.codec.build(
            black_box(&self.query),
            black_box(&self.meta),
            black_box(self.outcome),
            black_box(self.max_len),
            &mut self.out,
        );
        let _ = black_box(result);
        black_box(&self.out);
    }
}

/// `respond` (parse, lookup, build) for one packet.
struct RoundtripOp<'a, C: Codec> {
    codec: C,
    zone: &'a Zone,
    packet: &'a [u8],
    key: NameKey,
    out: Vec<u8>,
}

impl<'a, C: Codec> RoundtripOp<'a, C> {
    fn new(zone: &'a Zone, packet: &'a [u8]) -> Self {
        let codec = C::new();
        let mut key = NameKey::new();
        let mut out = Vec::with_capacity(OUT_CAPACITY);
        assert!(
            respond(&codec, zone, packet, &mut key, &mut out),
            "{}: respond dropped the packet",
            C::NAME
        );
        check_a_response(&format!("roundtrip/{}", C::NAME), &out);
        Self {
            codec,
            zone,
            packet,
            key,
            out,
        }
    }
}

impl<C: Codec> Op for RoundtripOp<'_, C> {
    fn run(&mut self) {
        let sent = respond(
            &self.codec,
            self.zone,
            black_box(self.packet),
            &mut self.key,
            &mut self.out,
        );
        black_box(sent);
        black_box(&self.out);
    }
}

/// `respond` cycling through many different packets, one per call.
struct RoundtripMixOp<'a, C: Codec> {
    codec: C,
    zone: &'a Zone,
    packets: &'a [Vec<u8>],
    next: usize,
    key: NameKey,
    out: Vec<u8>,
}

impl<'a, C: Codec> RoundtripMixOp<'a, C> {
    fn new(zone: &'a Zone, packets: &'a [Vec<u8>]) -> Self {
        let codec = C::new();
        let mut key = NameKey::new();
        let mut out = Vec::with_capacity(OUT_CAPACITY);
        let mut nx_count = 0;
        for (i, packet) in packets.iter().enumerate() {
            assert!(
                respond(&codec, zone, packet, &mut key, &mut out),
                "{}: respond dropped packet {i}",
                C::NAME
            );
            let h = wire::parse_header(&out).expect("response header");
            let nx = is_nx(i as u32);
            let want = if nx {
                wire::RCODE_NXDOMAIN
            } else {
                wire::RCODE_NOERROR
            };
            assert_eq!(
                (h.id, h.rcode, h.ancount),
                (i as u16, want, u16::from(!nx)),
                "{}: packet {i}",
                C::NAME
            );
            nx_count += usize::from(nx);
        }
        assert_eq!(
            nx_count,
            packets
                .iter()
                .enumerate()
                .filter(|(i, _)| is_nx(*i as u32))
                .count()
        );
        Self {
            codec,
            zone,
            packets,
            next: 0,
            key,
            out,
        }
    }
}

impl<C: Codec> Op for RoundtripMixOp<'_, C> {
    fn run(&mut self) {
        let packet = &self.packets[self.next];
        self.next += 1;
        if self.next == self.packets.len() {
            self.next = 0;
        }
        let sent = respond(
            &self.codec,
            self.zone,
            black_box(packet.as_slice()),
            &mut self.key,
            &mut self.out,
        );
        black_box(sent);
        black_box(&self.out);
    }
}

/// Reference operations that use hickory's high-level `Message` API.
#[cfg(feature = "backend-hickory")]
mod hickory_message {
    use std::net::Ipv4Addr;

    use hickory_proto::op::{Edns, Message};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, Record};
    use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
    use spike_b_udp::wire::SERVER_EDNS_UDP;
    use spike_b_udp::zone::{TTL, Zone};

    use super::{HOST_N, Op, QUERY_ID, black_box, check_a_response};

    /// `Message::from_vec` of the captured query.
    pub struct ParseOp<'a> {
        packet: &'a [u8],
    }

    impl<'a> ParseOp<'a> {
        pub fn new(packet: &'a [u8]) -> Self {
            let msg = Message::from_vec(packet).expect("Message::from_vec");
            assert_eq!(msg.metadata.id, QUERY_ID);
            assert_eq!(msg.queries.len(), 1);
            assert_eq!(
                msg.edns.as_ref().map(|e| e.max_payload()),
                Some(super::EDNS_UDP)
            );
            Self { packet }
        }
    }

    impl Op for ParseOp<'_> {
        fn run(&mut self) {
            let _ = black_box(Message::from_vec(black_box(self.packet)));
        }
    }

    /// Decodes the query into a `Message`, builds the response `Message` with
    /// the high-level API and encodes it into a reused buffer.
    ///
    /// The answer is the fixed address of `host-4242` (`Zone::address_for`):
    /// there is no zone lookup, so this is slightly less work than `respond`.
    pub struct RoundtripOp<'a> {
        packet: &'a [u8],
        addr: Ipv4Addr,
        out: Vec<u8>,
    }

    impl<'a> RoundtripOp<'a> {
        pub fn new(packet: &'a [u8]) -> Self {
            let addr = Zone::address_for(HOST_N);
            let mut out = Vec::with_capacity(super::OUT_CAPACITY);
            assert!(
                respond_with_message(packet, addr, &mut out),
                "hickory_message: roundtrip failed"
            );
            check_a_response("hickory_message/roundtrip", &out);
            Self { packet, addr, out }
        }
    }

    impl Op for RoundtripOp<'_> {
        fn run(&mut self) {
            black_box(respond_with_message(
                black_box(self.packet),
                self.addr,
                &mut self.out,
            ));
            black_box(&self.out);
        }
    }

    fn respond_with_message(packet: &[u8], addr: Ipv4Addr, out: &mut Vec<u8>) -> bool {
        let Ok(request) = Message::from_vec(packet) else {
            return false;
        };
        let Some(query) = request.queries.first() else {
            return false;
        };
        let mut response = Message::response(request.metadata.id, request.metadata.op_code);
        response.metadata.recursion_desired = request.metadata.recursion_desired;
        response.metadata.authoritative = true;
        response.add_query(query.clone());
        response.add_answer(Record::from_rdata(
            query.name().clone(),
            TTL,
            RData::A(A(addr)),
        ));
        let mut edns = Edns::new();
        edns.set_max_payload(SERVER_EDNS_UDP);
        response.set_edns(edns);
        // `BinEncodable::emit` writes into the caller's buffer, so the reused
        // `Vec<u8>` works here (`Message::to_vec` would allocate a new one).
        out.clear();
        let mut encoder = BinEncoder::new(out);
        response.emit(&mut encoder).is_ok()
    }
}

// ---------------------------------------------------------------------------
// Fixture and case list
// ---------------------------------------------------------------------------

/// Whether the `i`-th packet of `roundtrip_mix` is an NXDOMAIN query
/// (every 20th: the 20th, 40th, ...).
fn is_nx(i: u32) -> bool {
    (i + 1).is_multiple_of(20)
}

/// Shared inputs; the operations borrow from it.
struct Fixture {
    zone: Zone,
    /// `host-4242.example.test` A, EDNS 1232.
    packet_a: Vec<u8>,
    /// `nohost-4242.example.test` A, EDNS 1232.
    packet_nx: Vec<u8>,
    /// `MIX_PACKETS` deterministic packets for `roundtrip_mix`.
    mix: Vec<Vec<u8>>,
}

impl Fixture {
    fn new() -> Self {
        let mut packet_a = Vec::new();
        write_host_query(&mut packet_a, QUERY_ID, HOST_N, false, Some(EDNS_UDP));
        let mut packet_nx = Vec::new();
        write_host_query(&mut packet_nx, QUERY_ID, HOST_N, true, Some(EDNS_UDP));
        let mix = (0..MIX_PACKETS)
            .map(|i| {
                let mut p = Vec::with_capacity(64);
                write_host_query(
                    &mut p,
                    i as u16,
                    (i * 7919) % ZONE_SIZE,
                    is_nx(i),
                    Some(EDNS_UDP),
                );
                p
            })
            .collect();
        Self {
            zone: Zone::new(ZONE_SIZE),
            packet_a,
            packet_nx,
            mix,
        }
    }
}

/// A criterion group: one operation, one case per backend.
struct Group<'a> {
    name: &'static str,
    cases: Vec<(&'static str, Box<dyn Case + 'a>)>,
}

fn add<'a>(groups: &mut Vec<Group<'a>>, group: &'static str, id: &'static str, op: impl Op + 'a) {
    let case: Box<dyn Case + 'a> = Box::new(op);
    match groups.iter_mut().find(|g| g.name == group) {
        Some(g) => g.cases.push((id, case)),
        None => groups.push(Group {
            name: group,
            cases: vec![(id, case)],
        }),
    }
}

fn add_codec<'a, C: Codec>(groups: &mut Vec<Group<'a>>, fx: &'a Fixture) {
    add(groups, "parse", C::NAME, ParseOp::<C>::new(&fx.packet_a));
    add(
        groups,
        "build_a",
        C::NAME,
        BuildOp::<C>::new(&fx.packet_a, &fx.zone, false),
    );
    add(
        groups,
        "build_nxdomain",
        C::NAME,
        BuildOp::<C>::new(&fx.packet_nx, &fx.zone, true),
    );
    add(
        groups,
        "roundtrip",
        C::NAME,
        RoundtripOp::<C>::new(&fx.zone, &fx.packet_a),
    );
    add(
        groups,
        "roundtrip_mix",
        C::NAME,
        RoundtripMixOp::<C>::new(&fx.zone, &fx.mix),
    );
}

fn build_groups(fx: &Fixture) -> Vec<Group<'_>> {
    let mut groups = Vec::new();
    #[cfg(feature = "backend-domain")]
    add_codec::<DomainCodec>(&mut groups, fx);
    #[cfg(feature = "backend-hickory")]
    add_codec::<HickoryCodec>(&mut groups, fx);
    #[cfg(feature = "backend-hickory")]
    {
        add(
            &mut groups,
            "hickory_message",
            "parse",
            hickory_message::ParseOp::new(&fx.packet_a),
        );
        add(
            &mut groups,
            "hickory_message",
            "roundtrip",
            hickory_message::RoundtripOp::new(&fx.packet_a),
        );
    }
    groups
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

fn alloc_table(rows: &[(String, Stats)]) -> String {
    let per_op = |n: usize| n as f64 / ALLOC_CALLS as f64;
    let mut s = String::new();
    s.push_str("| benchmark | allocations/op | reallocations/op | deallocations/op | bytes allocated/op |\n");
    s.push_str("|---|---:|---:|---:|---:|\n");
    for (name, st) in rows {
        let _ = writeln!(
            s,
            "| {name} | {:.2} | {:.2} | {:.2} | {:.2} |",
            per_op(st.allocations),
            per_op(st.reallocations),
            per_op(st.deallocations),
            per_op(st.bytes_allocated),
        );
    }
    s
}

/// Where criterion writes its output: `$CRITERION_HOME`, else
/// `<target dir>/criterion`. Relative paths are relative to the crate dir.
/// The result is also handed to criterion, so reader and writer agree.
fn criterion_dir() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let resolve = |p: std::ffi::OsString| {
        let p = PathBuf::from(p);
        if p.is_absolute() { p } else { manifest.join(p) }
    };
    if let Some(home) = std::env::var_os("CRITERION_HOME") {
        return resolve(home);
    }
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(target) => resolve(target),
        None => manifest.join("target"),
    }
    .join("criterion")
}

struct Estimate {
    mean: f64,
    mean_lo: f64,
    mean_hi: f64,
    median: f64,
    confidence_level: f64,
}

/// Reads `<criterion dir>/<group>/<id>/new/estimates.json`. Returns `None` if
/// the benchmark did not run (filtered out) or the file predates this run.
fn read_estimate(dir: &Path, group: &str, id: &str, not_before: SystemTime) -> Option<Estimate> {
    let path = dir.join(group).join(id).join("new").join("estimates.json");
    if fs::metadata(&path).ok()?.modified().ok()? < not_before {
        return None;
    }
    let json: serde_json::Value = serde_json::from_slice(&fs::read(&path).ok()?).ok()?;
    let ci = &json["mean"]["confidence_interval"];
    Some(Estimate {
        mean: json["mean"]["point_estimate"].as_f64()?,
        mean_lo: ci["lower_bound"].as_f64()?,
        mean_hi: ci["upper_bound"].as_f64()?,
        median: json["median"]["point_estimate"].as_f64()?,
        confidence_level: ci["confidence_level"].as_f64()?,
    })
}

fn time_table(rows: &[(String, Estimate)]) -> String {
    let level = rows.first().map_or(0.95, |(_, e)| e.confidence_level);
    let mut s = String::new();
    let _ = writeln!(
        s,
        "| benchmark | mean (ns) | median (ns) | mean {:.0}% CI (ns) |",
        level * 100.0
    );
    s.push_str("|---|---:|---:|---:|\n");
    for (name, e) in rows {
        let _ = writeln!(
            s,
            "| {name} | {:.1} | {:.1} | {:.1} to {:.1} |",
            e.mean, e.median, e.mean_lo, e.mean_hi
        );
    }
    s
}

fn write_results(args: &[String], alloc: &str, time: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("results")
        .join("raw")
        .join("codec-bench.md");
    let mut s = String::new();
    s.push_str("# Codec micro-benchmarks\n\n");
    let _ = writeln!(s, "Benchmark arguments: `{}`\n", args.join(" "));
    s.push_str("## Allocations per operation\n\n");
    let _ = writeln!(
        s,
        "Allocator counters (`stats_alloc`) over {ALLOC_CALLS} calls after {ALLOC_WARMUP} warm-up calls. \
         Bytes allocated include the growth requested by reallocations.\n"
    );
    s.push_str(alloc);
    s.push_str("\n## Time per operation\n\n");
    s.push_str(
        "Wall time per iteration from criterion (`new/estimates.json`). In-memory, one thread, no I/O. \
         The numbers depend on the machine and on its load during the run.\n\n",
    );
    s.push_str(time);
    let written = path
        .parent()
        .map_or(Ok(()), fs::create_dir_all)
        .and_then(|()| fs::write(&path, s));
    match written {
        Ok(()) => eprintln!("wrote {}", path.display()),
        Err(e) => eprintln!("cannot write {}: {e}", path.display()),
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let has = |flag: &str| {
        args.iter()
            .any(|a| a == flag || a.starts_with(&format!("{flag}=")))
    };
    let listing = has("--list");
    // Criterion only measures under `cargo bench` (`--bench`) without these modes.
    let measuring = has("--bench") && !has("--test") && !listing && !has("--profile-time");

    let fx = Fixture::new();
    let mut groups = build_groups(&fx);

    let mut alloc_md = String::new();
    if !listing {
        if cfg!(no_alloc_counting) {
            println!("Allocation counting disabled (`--cfg no_alloc_counting`).\n");
        } else {
            let mut rows = Vec::new();
            for g in &mut groups {
                for (id, case) in &mut g.cases {
                    rows.push((format!("{}/{}", g.name, id), case.alloc_stats()));
                }
            }
            alloc_md = alloc_table(&rows);
            println!(
                "Allocations per operation ({ALLOC_CALLS} calls after {ALLOC_WARMUP} warm-up calls):\n"
            );
            println!("{alloc_md}");
        }
    }

    let started = SystemTime::now();
    let dir = criterion_dir();
    let mut c = Criterion::default()
        .output_directory(&dir)
        .configure_from_args();
    for g in &mut groups {
        let mut group = c.benchmark_group(g.name);
        for (id, case) in &mut g.cases {
            group.bench_function(*id, |b| case.time(b));
        }
        group.finish();
    }
    c.final_summary();

    if measuring {
        let rows: Vec<(String, Estimate)> = groups
            .iter()
            .flat_map(|g| g.cases.iter().map(move |(id, _)| (g.name, *id)))
            .filter_map(|(group, id)| {
                read_estimate(&dir, group, id, started).map(|e| (format!("{group}/{id}"), e))
            })
            .collect();
        let time_md = time_table(&rows);
        println!(
            "\nTime per operation (criterion, from {}):\n",
            dir.display()
        );
        println!("{time_md}");
        write_results(&args, &alloc_md, &time_md);
    }
}
