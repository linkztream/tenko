//! M25 (`docs/plans/phase-2-plan.md` section 6): the compile time of a block list of a
//! million names and the match cost per label of the query path's matcher.
//!
//! The list is generated (a fixed seed, so every run sees the same names): `--names` distinct
//! names of two to four labels, written as a hosts file (`0.0.0.0 name`) and as a domain
//! list. Each is parsed and compiled (`tenko_dns::lists::compile_text`) and the matcher is
//! built from the compiled bytes (`ListMatcher::build`), each timed `--rounds` times; the
//! median is reported. Then, for query names of 2, 4 and 8 labels, `--lookups` names (half
//! at or below a listed name, half not listed) are matched `--rounds` times, and the median
//! time per lookup and per label is reported. One JSON line per figure goes to standard
//! output, after a human summary on standard error.
//!
//! Usage: `cargo run -p tenko-dns --example lists_bench --release -- [--names N]
//! [--lookups N] [--rounds N]`.

use std::{hint::black_box, time::Instant};

use tenko_core::dns::ListFormat;
use tenko_dns::lists::{ListMatcher, compile_text};

/// A small deterministic generator (splitmix64).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn label(&mut self) -> String {
        const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let len = 3 + self.below(10);
        (0..len)
            .map(|_| {
                let at = usize::try_from(self.below(CHARS.len() as u64)).unwrap_or(0);
                char::from(CHARS[at])
            })
            .collect()
    }
}

const TLDS: [&str; 5] = ["test", "example", "invalid", "localhost", "arpa"];

fn arg(args: &[String], name: &str, default: usize) -> usize {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|at| args.get(at + 1))
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

#[allow(
    clippy::cast_precision_loss,
    clippy::too_many_lines,
    reason = "figures for a report, one run from data to figures"
)]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let names = arg(&args, "--names", 1_000_000);
    let lookups = arg(&args, "--lookups", 100_000);
    let rounds = arg(&args, "--rounds", 5).max(1);
    let mut rng = Rng(0x7e4b_0025);
    let mut listed: Vec<String> = Vec::with_capacity(names);
    let mut seen = std::collections::HashSet::with_capacity(names);
    while listed.len() < names {
        let depth = 2 + rng.below(3);
        let mut name = String::new();
        for _ in 0..depth - 1 {
            name.push_str(&rng.label());
            name.push('.');
        }
        name.push_str(TLDS[usize::try_from(rng.below(5)).unwrap_or(0)]);
        if seen.insert(name.clone()) {
            listed.push(name);
        }
    }
    drop(seen);
    let mut hosts = String::with_capacity(names * 24);
    for name in &listed {
        hosts.push_str("0.0.0.0 ");
        hosts.push_str(name);
        hosts.push('\n');
    }
    let mut domains = String::with_capacity(names * 16);
    for name in &listed {
        domains.push_str(name);
        domains.push('\n');
    }
    let mut compiled_bytes = Vec::new();
    for (form, text, format) in [
        ("hosts", &hosts, ListFormat::Hosts),
        ("domains", &domains, ListFormat::Domains),
    ] {
        let mut compile = Vec::new();
        let mut build = Vec::new();
        let mut entries = 0;
        for _ in 0..rounds {
            let started = Instant::now();
            let (compiled, _) = compile_text(text.as_bytes(), format).expect("compile");
            compile.push(started.elapsed().as_secs_f64());
            let started = Instant::now();
            let matcher = ListMatcher::build(&compiled.bytes).expect("build");
            build.push(started.elapsed().as_secs_f64());
            entries = compiled.entries;
            black_box(&matcher);
            compiled_bytes = compiled.bytes;
        }
        let (compile, build) = (median(compile), median(build));
        eprintln!(
            "{form}: {} names, text {:.1} MiB, compiled {:.1} MiB, {entries} entries; compile {compile:.3} s, matcher {build:.3} s, total {:.3} s",
            listed.len(),
            text.len() as f64 / 1_048_576.0,
            compiled_bytes.len() as f64 / 1_048_576.0,
            compile + build
        );
        println!(
            "{{\"figure\":\"compile\",\"form\":\"{form}\",\"names\":{},\"text_bytes\":{},\"compiled_bytes\":{},\"entries\":{entries},\"compile_s\":{compile:.4},\"matcher_s\":{build:.4},\"total_s\":{:.4}}}",
            listed.len(),
            text.len(),
            compiled_bytes.len(),
            compile + build
        );
    }
    let matcher = ListMatcher::build(&compiled_bytes).expect("build");
    eprintln!(
        "matcher: {} entries, {:.1} MiB",
        matcher.entries(),
        matcher.bytes() as f64 / 1_048_576.0
    );
    for labels in [2usize, 4, 8] {
        let mut queries: Vec<Vec<u8>> = Vec::with_capacity(lookups);
        let mut hits = 0;
        while queries.len() < lookups {
            let hit = queries.len().is_multiple_of(2);
            let mut parts: Vec<String> = if hit {
                let base = &listed[usize::try_from(rng.below(listed.len() as u64)).unwrap_or(0)];
                base.split('.').map(str::to_owned).collect()
            } else {
                vec!["unlisted".to_owned(), "zz".to_owned()]
            };
            if parts.len() > labels {
                continue;
            }
            while parts.len() < labels {
                parts.insert(0, rng.label());
            }
            let mut wire = Vec::with_capacity(64);
            for part in &parts {
                wire.push(u8::try_from(part.len()).expect("label"));
                wire.extend_from_slice(part.as_bytes());
            }
            wire.push(0);
            if hit {
                hits += 1;
            }
            queries.push(wire);
        }
        let mut times = Vec::new();
        let mut found = 0;
        for _ in 0..rounds {
            found = 0;
            let started = Instant::now();
            for query in &queries {
                if matcher.matches(black_box(query)) {
                    found += 1;
                }
            }
            times.push(started.elapsed().as_secs_f64());
        }
        let per_lookup = median(times) * 1e9 / queries.len() as f64;
        let per_label = per_lookup / labels as f64;
        assert_eq!(found, hits, "every listed name matches, no other");
        eprintln!(
            "{labels} labels: {} lookups, {found} matched, {per_lookup:.1} ns per lookup, {per_label:.1} ns per label",
            queries.len()
        );
        println!(
            "{{\"figure\":\"match\",\"labels\":{labels},\"lookups\":{},\"matched\":{found},\"ns_per_lookup\":{per_lookup:.2},\"ns_per_label\":{per_label:.2}}}",
            queries.len()
        );
    }
}
