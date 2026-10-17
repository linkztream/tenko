//! Deterministic zone file and query file generator.
//!
//! The data set is the one of Spike A (`bench/spike-a-raft/src/gen.rs`),
//! written as RFC 1035 zone files:
//!
//! * `example.test.zone`: `forward_records` A records `host-{n}`, n in
//!   `0..forward_records`. Host `n` is in range `r = n % 3` of the three
//!   RFC 5737 documentation networks (192.0.2.0/24, 198.51.100.0/24,
//!   203.0.113.0/24) with last octet `1 + (n / 3) % 254`, so the addresses
//!   repeat; the benchmark needs many owner names, not many addresses.
//! * Three reverse zones with `ptr_percent` PTR records per 100 hosts:
//!   `2.0.192.in-addr.arpa`, `100.51.198.in-addr.arpa` and
//!   `113.0.203.in-addr.arpa`. PTR number `j` belongs to host
//!   `h = j * 100 / ptr_percent` (strictly increasing, so a host has at most
//!   one PTR). Its owner is the RFC 2317-style `{octet}.{block}` with
//!   `block = h / 762`, as in Spike A, so every owner is unique even though
//!   there are only 768 real addresses.
//! * Per host, a TTL out of 300, 600, 900 and 3600 from the same splitmix64
//!   hash of `(seed, host)` as Spike A uses; the A and the PTR record of a host
//!   share it.
//!
//! The query file (`queries.txt`, dnsperf format `name TYPE`) is sampled with
//! replacement from the zone: A queries for existing hosts, a share of A
//! queries for names that do not exist (`nohost-{n}`, NXDOMAIN) and, if
//! asked, PTR queries for existing reverse owners.
//!
//! Everything is a pure function of the parameters, so two runs write
//! byte-identical files.

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};

/// The forward zone.
pub const FORWARD_ZONE: &str = "example.test";
/// Reverse zones, indexed like the address ranges.
pub const REVERSE_ZONES: [&str; 3] = [
    "2.0.192.in-addr.arpa",
    "100.51.198.in-addr.arpa",
    "113.0.203.in-addr.arpa",
];
/// First three octets of the three RFC 5737 networks.
const NET_PREFIX: [[u8; 3]; 3] = [[192, 0, 2], [198, 51, 100], [203, 0, 113]];
const TTLS: [u32; 4] = [300, 600, 900, 3600];
/// Usable host addresses per /24 (`.1` to `.254`).
const ADDRS_PER_RANGE: u64 = 254;
/// Hosts per reverse block: all three ranges, 254 addresses each.
const HOSTS_PER_BLOCK: u64 = 3 * ADDRS_PER_RANGE;
/// SOA serial of every generated zone.
const SERIAL: u32 = 2026101701;
/// Default seed, the one Spike A uses.
pub const DEFAULT_SEED: u64 = 42;

/// Parameters of a generated data set.
#[derive(Debug, Clone, Copy)]
pub struct Params {
    /// Number of A records in the forward zone.
    pub records: u64,
    /// PTR records per 100 hosts, 0..=100.
    pub ptr_percent: u8,
    /// Seed for the per-host TTL.
    pub seed: u64,
}

impl Params {
    /// `records * ptr_percent / 100`.
    pub fn ptr_records(&self) -> u64 {
        (u128::from(self.records) * u128::from(self.ptr_percent.min(100)) / 100) as u64
    }

    /// Host that PTR number `j` belongs to: `j * 100 / ptr_percent`.
    fn ptr_host(&self, j: u64) -> u64 {
        (u128::from(j) * 100 / u128::from(self.ptr_percent.clamp(1, 100))) as u64
    }

    fn ttl(&self, host: u64) -> u32 {
        TTLS[(mix(self.seed.wrapping_add(mix(host))) & 3) as usize]
    }
}

/// splitmix64 output function applied to `x + golden gamma` (as in Spike A).
fn mix(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Address range (0..3) and last octet (1..=254) of host `n`.
fn host_addr(n: u64) -> (usize, u8) {
    ((n % 3) as usize, 1 + ((n / 3) % ADDRS_PER_RANGE) as u8)
}

/// Reverse zone index and `{octet}.{block}` owner of host `h`'s PTR.
fn ptr_owner(h: u64) -> (usize, u8, u64) {
    let (range, octet) = host_addr(h);
    (range, octet, h / HOSTS_PER_BLOCK)
}

fn write_zone_header<W: Write>(w: &mut W, apex: &str) -> io::Result<()> {
    writeln!(w, "$ORIGIN {apex}.")?;
    writeln!(w, "$TTL 300")?;
    writeln!(
        w,
        "@ IN SOA ns1.{FORWARD_ZONE}. hostmaster.{FORWARD_ZONE}. {SERIAL} 3600 900 604800 300"
    )?;
    writeln!(w, "@ IN NS ns1.{FORWARD_ZONE}.")
}

/// Writes the forward zone.
pub fn write_forward<W: Write>(w: &mut W, p: &Params) -> io::Result<()> {
    write_zone_header(w, FORWARD_ZONE)?;
    writeln!(w, "ns1 IN A 192.0.2.254")?;
    for n in 0..p.records {
        let (range, octet) = host_addr(n);
        let net = NET_PREFIX[range];
        writeln!(
            w,
            "host-{n} {} IN A {}.{}.{}.{octet}",
            p.ttl(n),
            net[0],
            net[1],
            net[2]
        )?;
    }
    Ok(())
}

/// Writes the reverse zone of address range `range` (0..3).
pub fn write_reverse<W: Write>(w: &mut W, p: &Params, range: usize) -> io::Result<()> {
    write_zone_header(w, REVERSE_ZONES[range])?;
    if p.ptr_percent == 0 {
        return Ok(());
    }
    for j in 0..p.ptr_records() {
        let h = p.ptr_host(j);
        let (r, octet, block) = ptr_owner(h);
        if r == range {
            writeln!(
                w,
                "{octet}.{block} {} IN PTR host-{h}.{FORWARD_ZONE}.",
                p.ttl(h)
            )?;
        }
    }
    Ok(())
}

/// Shares of the query mix.
#[derive(Debug, Clone, Copy)]
pub struct QueryMix {
    /// Number of queries to write.
    pub count: u64,
    /// Percent of queries for names that do not exist.
    pub nx_percent: f64,
    /// Percent of PTR queries for existing reverse owners.
    pub ptr_percent: f64,
}

/// Writes the query file: `count` lines `name TYPE`, sampled with replacement.
pub fn write_queries<W: Write>(w: &mut W, p: &Params, mix_: &QueryMix) -> io::Result<()> {
    let nx_cut = (mix_.nx_percent * 100.0).round() as u64;
    let ptr_cut = nx_cut + (mix_.ptr_percent * 100.0).round() as u64;
    let ptr_total = p.ptr_records();
    for k in 0..mix_.count {
        let r = mix(p.seed ^ mix(k ^ 0x5155_4552_4945_5321));
        let kind = r % 10_000;
        let pick = mix(r) as u128;
        if kind < nx_cut {
            writeln!(
                w,
                "nohost-{}.{FORWARD_ZONE} A",
                (pick % u128::from(p.records.max(1))) as u64
            )?;
        } else if kind < ptr_cut && ptr_total > 0 {
            let h = p.ptr_host((pick % u128::from(ptr_total)) as u64);
            let (range, octet, block) = ptr_owner(h);
            writeln!(w, "{octet}.{block}.{} PTR", REVERSE_ZONES[range])?;
        } else {
            writeln!(
                w,
                "host-{}.{FORWARD_ZONE} A",
                (pick % u128::from(p.records.max(1))) as u64
            )?;
        }
    }
    Ok(())
}

#[derive(clap::Args, Debug, Clone)]
pub struct ZonegenArgs {
    /// Number of A records in `example.test` (Phase 2 sizes: 100000, 1000000, 6000000).
    #[arg(long)]
    pub records: u64,
    /// PTR records per 100 hosts, spread over the three reverse zones.
    #[arg(long, default_value_t = 20)]
    pub ptr_percent: u8,
    /// Seed of the per-host TTL; Spike A used 42.
    #[arg(long, default_value_t = DEFAULT_SEED)]
    pub seed: u64,
    /// Directory for the zone files and the query file (created if missing).
    #[arg(long)]
    pub out_dir: PathBuf,
    /// Number of lines in `queries.txt` (0: write no query file).
    #[arg(long, default_value_t = 1_000_000)]
    pub queries: u64,
    /// Percent of the queries for names that do not exist.
    #[arg(long, default_value_t = 5.0)]
    pub nx_percent: f64,
    /// Percent of the queries that are PTR queries.
    #[arg(long, default_value_t = 0.0)]
    pub ptr_query_percent: f64,
}

fn check_args(args: &ZonegenArgs) -> anyhow::Result<()> {
    if args.records == 0 {
        bail!("--records must be at least 1");
    }
    if args.ptr_percent > 100 {
        bail!("--ptr-percent must be in 0..=100");
    }
    if !(0.0..=100.0).contains(&args.nx_percent)
        || !(0.0..=100.0).contains(&args.ptr_query_percent)
        || args.nx_percent + args.ptr_query_percent > 100.0
    {
        bail!("--nx-percent and --ptr-query-percent must be in 0..=100 and add up to at most 100");
    }
    if args.ptr_query_percent > 0.0 && args.ptr_percent == 0 {
        bail!("--ptr-query-percent needs --ptr-percent above 0");
    }
    Ok(())
}

/// One written file.
#[derive(Debug)]
pub struct Written {
    pub path: PathBuf,
    pub bytes: u64,
    pub elapsed: Duration,
}

fn write_file<F>(path: PathBuf, f: F) -> anyhow::Result<Written>
where
    F: FnOnce(&mut BufWriter<File>) -> io::Result<()>,
{
    let start = Instant::now();
    let file = File::create(&path).with_context(|| format!("cannot create {}", path.display()))?;
    let mut w = BufWriter::with_capacity(1 << 20, file);
    f(&mut w).with_context(|| format!("cannot write {}", path.display()))?;
    w.flush()
        .with_context(|| format!("cannot write {}", path.display()))?;
    let bytes = w.get_ref().metadata().map(|m| m.len()).unwrap_or(0);
    Ok(Written {
        path,
        bytes,
        elapsed: start.elapsed(),
    })
}

/// Writes the data set into `args.out_dir` and returns the files written.
pub fn generate(args: &ZonegenArgs) -> anyhow::Result<Vec<Written>> {
    check_args(args)?;
    let p = Params {
        records: args.records,
        ptr_percent: args.ptr_percent,
        seed: args.seed,
    };
    fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("cannot create {}", args.out_dir.display()))?;
    let dir = &args.out_dir;
    let mut out = vec![write_file(dir.join(format!("{FORWARD_ZONE}.zone")), |w| {
        write_forward(w, &p)
    })?];
    for (range, zone) in REVERSE_ZONES.iter().enumerate() {
        out.push(write_file(dir.join(format!("{zone}.zone")), |w| {
            write_reverse(w, &p, range)
        })?);
    }
    if args.queries > 0 {
        let mix_ = QueryMix {
            count: args.queries,
            nx_percent: args.nx_percent,
            ptr_percent: args.ptr_query_percent,
        };
        out.push(write_file(dir.join("queries.txt"), |w| {
            write_queries(w, &p, &mix_)
        })?);
    }
    Ok(out)
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / 1_048_576.0
}

/// Writes the data set and prints what was written.
pub fn run(args: &ZonegenArgs) -> anyhow::Result<()> {
    let start = Instant::now();
    let files = generate(args)?;
    let p = Params {
        records: args.records,
        ptr_percent: args.ptr_percent,
        seed: args.seed,
    };
    println!(
        "records       {} A + {} PTR = {} RRsets (seed {})",
        args.records,
        p.ptr_records(),
        args.records + p.ptr_records(),
        args.seed
    );
    for f in &files {
        println!(
            "{:<40} {:>10.1} MiB  {:>6.2} s",
            f.path.display(),
            mib(f.bytes),
            f.elapsed.as_secs_f64()
        );
    }
    println!("total time    {:.2} s", start.elapsed().as_secs_f64());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(records: u64, seed: u64) -> Params {
        Params {
            records,
            ptr_percent: 20,
            seed,
        }
    }

    fn forward(p: &Params) -> String {
        let mut v = Vec::new();
        write_forward(&mut v, p).unwrap();
        String::from_utf8(v).unwrap()
    }

    fn reverse(p: &Params, range: usize) -> String {
        let mut v = Vec::new();
        write_reverse(&mut v, p, range).unwrap();
        String::from_utf8(v).unwrap()
    }

    fn queries(p: &Params, mix_: &QueryMix) -> String {
        let mut v = Vec::new();
        write_queries(&mut v, p, mix_).unwrap();
        String::from_utf8(v).unwrap()
    }

    #[test]
    fn output_is_deterministic_and_seed_dependent() {
        let p = params(5000, 42);
        assert_eq!(forward(&p), forward(&p));
        for r in 0..3 {
            assert_eq!(reverse(&p, r), reverse(&p, r));
        }
        let mix_ = QueryMix {
            count: 1000,
            nx_percent: 5.0,
            ptr_percent: 10.0,
        };
        assert_eq!(queries(&p, &mix_), queries(&p, &mix_));
        // The seed changes the TTLs and the sample, not the owner names.
        let q = params(5000, 43);
        assert_ne!(forward(&p), forward(&q));
        assert_ne!(queries(&p, &mix_), queries(&q, &mix_));
    }

    #[test]
    fn forward_zone_record_format() {
        let p = params(10, 42);
        let text = forward(&p);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "$ORIGIN example.test.");
        assert_eq!(lines[1], "$TTL 300");
        assert!(lines[2].starts_with("@ IN SOA ns1.example.test. hostmaster.example.test. "));
        assert_eq!(lines[3], "@ IN NS ns1.example.test.");
        assert_eq!(lines[4], "ns1 IN A 192.0.2.254");
        assert_eq!(lines.len(), 5 + 10);
        // Host n: range n % 3, octet 1 + (n / 3) % 254, as in Spike A.
        let fields: Vec<&str> = lines[5].split(' ').collect();
        assert_eq!(fields[0], "host-0");
        assert!(TTLS.contains(&fields[1].parse().unwrap()));
        assert_eq!(&fields[2..], ["IN", "A", "192.0.2.1"]);
        assert!(lines[6].ends_with(" IN A 198.51.100.1"), "{}", lines[6]);
        assert!(lines[7].ends_with(" IN A 203.0.113.1"), "{}", lines[7]);
        assert!(lines[8].ends_with(" IN A 192.0.2.2"), "{}", lines[8]);
        // No address ends in .0 or .255.
        for l in &lines[5..] {
            let last = l.rsplit('.').next().unwrap();
            assert!(last != "0" && last != "255", "{l}");
        }
    }

    #[test]
    fn ptr_records_are_a_fifth_of_the_hosts_and_unique() {
        let p = params(10_000, 42);
        assert_eq!(p.ptr_records(), 2000);
        let mut owners = std::collections::BTreeSet::new();
        let mut total = 0;
        for (r, zone) in REVERSE_ZONES.iter().enumerate() {
            let text = reverse(&p, r);
            let mut lines = text.lines();
            assert_eq!(lines.next().unwrap(), format!("$ORIGIN {}.", zone));
            for l in text.lines().skip(4) {
                let f: Vec<&str> = l.split(' ').collect();
                assert_eq!((f[2], f[3]), ("IN", "PTR"), "{l}");
                assert!(f[4].starts_with("host-") && f[4].ends_with(".example.test."));
                assert!(owners.insert((r, f[0].to_string())), "duplicate owner {l}");
                total += 1;
            }
        }
        assert_eq!(total, 2000);
        // The PTR of host 0 is in the first reverse zone, owner 1.0.
        assert!(reverse(&p, 0).contains("\n1.0 "));
        // A host's A and PTR record share the TTL.
        let fwd = forward(&p);
        let a_line = fwd.lines().find(|l| l.starts_with("host-0 ")).unwrap();
        let ptr_line = reverse(&p, 0)
            .lines()
            .find(|l| l.starts_with("1.0 "))
            .unwrap()
            .to_string();
        assert_eq!(
            a_line.split(' ').nth(1).unwrap(),
            ptr_line.split(' ').nth(1).unwrap()
        );
    }

    #[test]
    fn no_ptr_percent_means_empty_reverse_zones() {
        let p = Params {
            records: 100,
            ptr_percent: 0,
            seed: 1,
        };
        assert_eq!(reverse(&p, 1).lines().count(), 4);
    }

    #[test]
    fn query_mix_follows_the_shares() {
        let p = params(100_000, 42);
        let mix_ = QueryMix {
            count: 20_000,
            nx_percent: 5.0,
            ptr_percent: 10.0,
        };
        let text = queries(&p, &mix_);
        assert_eq!(text.lines().count(), 20_000);
        let nx = text.lines().filter(|l| l.starts_with("nohost-")).count();
        let ptr = text.lines().filter(|l| l.ends_with(" PTR")).count();
        let a = text.lines().filter(|l| l.starts_with("host-")).count();
        assert_eq!(nx + ptr + a, 20_000);
        assert!((800..=1200).contains(&nx), "nx {nx}");
        assert!((1700..=2300).contains(&ptr), "ptr {ptr}");
        // Every sampled name is in range.
        for l in text.lines().filter(|l| l.starts_with("host-")) {
            let n: u64 = l["host-".len()..l.find('.').unwrap()].parse().unwrap();
            assert!(n < 100_000);
        }
        // Every PTR query names an existing PTR owner.
        let mut owners = std::collections::BTreeSet::new();
        for (r, zone) in REVERSE_ZONES.iter().enumerate() {
            for l in reverse(&p, r).lines().skip(4) {
                owners.insert(format!("{}.{} PTR", l.split(' ').next().unwrap(), zone));
            }
        }
        for l in text.lines().filter(|l| l.ends_with(" PTR")) {
            assert!(owners.contains(l), "unknown PTR owner {l}");
        }
        // The names file parser accepts the output.
        let names = crate::names::Names::parse(&text).unwrap();
        assert_eq!(names.len(), 20_000);
    }

    #[test]
    fn generate_writes_the_files() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp")
            .join(format!("zonegen-{}", std::process::id()));
        let args = ZonegenArgs {
            records: 3000,
            ptr_percent: 20,
            seed: 42,
            out_dir: dir.clone(),
            queries: 500,
            nx_percent: 5.0,
            ptr_query_percent: 0.0,
        };
        let files = generate(&args).unwrap();
        assert_eq!(files.len(), 5);
        for f in &files {
            assert!(f.bytes > 0, "{f:?}");
        }
        assert!(dir.join("example.test.zone").exists());
        assert_eq!(
            fs::read_to_string(dir.join("queries.txt"))
                .unwrap()
                .lines()
                .count(),
            500
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_bad_arguments() {
        let ok = ZonegenArgs {
            records: 10,
            ptr_percent: 20,
            seed: 1,
            out_dir: PathBuf::from("x"),
            queries: 0,
            nx_percent: 5.0,
            ptr_query_percent: 0.0,
        };
        assert!(check_args(&ok).is_ok());
        let mut a = ok.clone();
        a.records = 0;
        assert!(check_args(&a).is_err());
        let mut a = ok.clone();
        a.ptr_percent = 101;
        assert!(check_args(&a).is_err());
        let mut a = ok.clone();
        a.nx_percent = 60.0;
        a.ptr_query_percent = 50.0;
        assert!(check_args(&a).is_err());
        let mut a = ok;
        a.ptr_percent = 0;
        a.ptr_query_percent = 5.0;
        assert!(check_args(&a).is_err());
    }
}
