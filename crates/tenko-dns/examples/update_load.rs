//! The load generator of M21 (WP6.2): RFC 2136 updates at a fixed rate over UDP, signed with
//! TSIG, against one DNS server; the time from the send of each update to its answer.
//!
//! Each update replaces the A RRset of one of `--names` owners (`m21-<n>.<zone>`: delete the
//! RRset, add one address), the form of a DHCP client's DDNS update, so the zone stays at
//! the same size however long the run is. Updates go out paced (open loop) at `--rate` per
//! second from one socket; a second thread takes the answers, matches them by message id,
//! checks the RCODE and the TSIG of the answer (the MAC chain of RFC 8945), and records the
//! latency of every update sent after the warm-up. An update not answered within
//! `--timeout` counts as lost.
//!
//! Output: a summary in text and one JSON line (`--out FILE` appends it).
//!
//! ```text
//! cargo run -p tenko-dns --release --example update_load -- \
//!     --target 127.0.0.1:5300 --zone example.test --key update.example.test \
//!     --secret-file key.b64 --rate 1000 --duration 60 --warmup 5 --names 1000
//! ```

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    net::{SocketAddr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tenko_core::dns::{DnsName, TsigAlgorithm};
use tenko_dns::{
    tsig::{Mac, Signer, TsigKey, Verifier},
    update::message::{CLASS_ANY, CLASS_IN, push_record, write_request},
    wire::{self, MAX_MESSAGE_LEN},
};

struct Args {
    target: SocketAddr,
    zone: DnsName,
    key: Option<Arc<TsigKey>>,
    rate: u64,
    duration: Duration,
    warmup: Duration,
    names: u64,
    timeout: Duration,
    out: Option<String>,
    label: String,
}

fn usage() -> ! {
    eprintln!(
        "usage: update_load --target ADDR:PORT --zone ZONE [--key NAME --secret-file PATH] \
         [--rate N] [--duration SECS] [--warmup SECS] [--names N] [--timeout MS] [--out FILE] \
         [--label TEXT]"
    );
    std::process::exit(2);
}

fn args() -> Args {
    let mut map = BTreeMap::new();
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let Some(name) = flag.strip_prefix("--") else {
            usage();
        };
        let Some(value) = it.next() else { usage() };
        map.insert(name.to_owned(), value);
    }
    let get = |name: &str| map.get(name).cloned();
    let number = |name: &str, default: u64| {
        get(name).map_or(default, |text| text.parse().unwrap_or_else(|_| usage()))
    };
    let target = get("target")
        .and_then(|text| text.parse().ok())
        .unwrap_or_else(|| usage());
    let zone = get("zone")
        .and_then(|text| DnsName::new(&text).ok())
        .unwrap_or_else(|| usage());
    let key = match (get("key"), get("secret-file")) {
        (Some(name), Some(path)) => {
            let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
                eprintln!("{path}: {error}");
                std::process::exit(2)
            });
            let secret: Vec<u8> = domain::utils::base64::decode(text.trim()).unwrap_or_else(|_| {
                eprintln!("{path}: not base64");
                std::process::exit(2)
            });
            let name = DnsName::new(&name).unwrap_or_else(|_| usage());
            Some(Arc::new(TsigKey::new(
                &name,
                TsigAlgorithm::HmacSha256,
                &secret,
            )))
        }
        (None, None) => None,
        _ => usage(),
    };
    Args {
        target,
        zone,
        key,
        rate: number("rate", 1000).max(1),
        duration: Duration::from_secs(number("duration", 60)),
        warmup: Duration::from_secs(number("warmup", 5)),
        names: number("names", 1000).max(1),
        timeout: Duration::from_millis(number("timeout", 2000)),
        out: get("out"),
        label: get("label").unwrap_or_default(),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The update of sequence number `seq`: replace the A RRset of `m21-<seq mod names>`.
fn update(args: &Args, seq: u64, out: &mut Vec<u8>) {
    let owner = DnsName::new(&format!("m21-{}.{}", seq % args.names, args.zone))
        .unwrap_or_else(|_| usage())
        .to_wire();
    let address = [
        198,
        51,
        u8::try_from((seq >> 8) & 0xff).unwrap_or(0),
        u8::try_from(seq & 0xff).unwrap_or(0),
    ];
    let mut records = Vec::with_capacity(96);
    push_record(&mut records, &owner, 1, CLASS_ANY, 0, &[]);
    push_record(&mut records, &owner, 1, CLASS_IN, 60, &address);
    let id = u16::try_from(seq & 0xffff).unwrap_or(0);
    write_request(out, id, &args.zone.to_wire(), (0, &[]), (2, &records));
}

/// An update in flight: when it went out and the MAC its answer covers.
#[derive(Clone, Copy)]
struct Flight {
    sent: Instant,
    mac: Option<Mac>,
    measured: bool,
}

#[derive(Default)]
struct Tally {
    latencies_us: Vec<u64>,
    rcodes: BTreeMap<u8, u64>,
    bad_signatures: u64,
    late: u64,
    stray: u64,
}

fn percentile(sorted: &[u64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "an index into a sorted list"
    )]
    let at = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    #[allow(clippy::cast_precision_loss, reason = "microseconds to milliseconds")]
    let ms = sorted[at.min(sorted.len() - 1)] as f64 / 1000.0;
    ms
}

#[allow(clippy::too_many_lines, reason = "the run in its order")]
fn main() {
    let args = Arc::new(args());
    let socket = UdpSocket::bind(if args.target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .expect("bind a UDP socket");
    socket.connect(args.target).expect("connect the socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("read timeout");
    let socket = Arc::new(socket);
    let flights: Arc<Mutex<Vec<Option<Flight>>>> = Arc::new(Mutex::new(vec![None; 65_536]));
    let tally = Arc::new(Mutex::new(Tally::default()));
    let done = Arc::new(AtomicBool::new(false));
    let start = Instant::now();
    let measure_from = start + args.warmup;
    let stop_at = measure_from + args.duration;

    let receiver = {
        let (socket, flights, tally, done, args) = (
            Arc::clone(&socket),
            Arc::clone(&flights),
            Arc::clone(&tally),
            Arc::clone(&done),
            Arc::clone(&args),
        );
        std::thread::spawn(move || {
            let mut buf = vec![0u8; MAX_MESSAGE_LEN];
            loop {
                let Ok(len) = socket.recv(&mut buf) else {
                    if done.load(Ordering::Relaxed) {
                        return;
                    }
                    continue;
                };
                let now = Instant::now();
                let answer = &buf[..len];
                let Some(header) = wire::parse_header(answer) else {
                    continue;
                };
                let flight = flights.lock().expect("flights")[usize::from(header.id)].take();
                let mut tally = tally.lock().expect("tally");
                let Some(flight) = flight else {
                    tally.stray += 1;
                    continue;
                };
                let took = now.duration_since(flight.sent);
                if took > args.timeout {
                    tally.late += 1;
                    continue;
                }
                if let (Some(key), Some(mac)) = (&args.key, flight.mac) {
                    let mut verifier = Verifier::new(Arc::clone(key), mac);
                    if verifier.verify(answer, unix_now()).is_err() {
                        tally.bad_signatures += 1;
                    }
                }
                if flight.measured {
                    *tally.rcodes.entry(header.rcode).or_insert(0) += 1;
                    tally
                        .latencies_us
                        .push(u64::try_from(took.as_micros()).unwrap_or(u64::MAX));
                }
            }
        })
    };

    // The sender: paced, in steps of about a millisecond.
    let mut seq: u64 = 0;
    let mut sent_measured: u64 = 0;
    let mut message = Vec::with_capacity(512);
    let per_sec = args.rate;
    loop {
        let now = Instant::now();
        if now >= stop_at {
            break;
        }
        let due = u64::try_from(now.duration_since(start).as_micros()).unwrap_or(u64::MAX)
            * per_sec
            / 1_000_000;
        while seq < due {
            update(&args, seq, &mut message);
            let mac = args.key.as_ref().map(|key| {
                let mut signer = Signer::request(Arc::clone(key));
                signer.sign(&mut message, unix_now(), 0, &[], MAX_MESSAGE_LEN);
                signer.last_mac().unwrap_or_default()
            });
            let sent = Instant::now();
            let measured = sent >= measure_from;
            flights.lock().expect("flights")[usize::try_from(seq & 0xffff).unwrap_or(0)] =
                Some(Flight {
                    sent,
                    mac,
                    measured,
                });
            let _ = socket.send(&message);
            if measured {
                sent_measured += 1;
            }
            seq += 1;
        }
        std::thread::sleep(Duration::from_micros(500));
    }
    std::thread::sleep(args.timeout);
    done.store(true, Ordering::Relaxed);
    let _ = receiver.join();

    let mut tally = Arc::try_unwrap(tally)
        .ok()
        .map(|tally| tally.into_inner().expect("tally"))
        .unwrap_or_default();
    tally.latencies_us.sort_unstable();
    let answered = tally.latencies_us.len() as u64;
    let lost = sent_measured.saturating_sub(answered);
    let noerror = tally.rcodes.get(&0).copied().unwrap_or(0);
    #[allow(clippy::cast_precision_loss, reason = "a rate")]
    let achieved = answered as f64 / args.duration.as_secs_f64().max(1e-9);
    let (p50, p90, p99, p999) = (
        percentile(&tally.latencies_us, 50.0),
        percentile(&tally.latencies_us, 90.0),
        percentile(&tally.latencies_us, 99.0),
        percentile(&tally.latencies_us, 99.9),
    );
    #[allow(clippy::cast_precision_loss, reason = "microseconds to milliseconds")]
    let max = tally.latencies_us.last().copied().unwrap_or(0) as f64 / 1000.0;
    let mut rcodes = String::new();
    for (code, count) in &tally.rcodes {
        let _ = write!(
            rcodes,
            "{}\"{code}\": {count}",
            if rcodes.is_empty() { "" } else { ", " }
        );
    }
    println!(
        "target {} rate {}/s duration {} s (after {} s warm-up), names {}, signed {}",
        args.target,
        args.rate,
        args.duration.as_secs(),
        args.warmup.as_secs(),
        args.names,
        args.key.is_some()
    );
    println!(
        "sent {sent_measured} answered {answered} noerror {noerror} lost {lost} late {} stray {} bad_signatures {}",
        tally.late, tally.stray, tally.bad_signatures
    );
    println!("answered rate {achieved:.1}/s");
    println!("latency ms p50 {p50:.2} p90 {p90:.2} p99 {p99:.2} p99.9 {p999:.2} max {max:.2}");
    let line = format!(
        "{{\"label\": \"{}\", \"target\": \"{}\", \"rate\": {}, \"duration_s\": {}, \"warmup_s\": {}, \"names\": {}, \"signed\": {}, \"sent\": {sent_measured}, \"answered\": {answered}, \"noerror\": {noerror}, \"lost\": {lost}, \"late\": {}, \"bad_signatures\": {}, \"rcodes\": {{{rcodes}}}, \"answered_per_s\": {achieved:.1}, \"p50_ms\": {p50:.3}, \"p90_ms\": {p90:.3}, \"p99_ms\": {p99:.3}, \"p999_ms\": {p999:.3}, \"max_ms\": {max:.3}}}",
        args.label,
        args.target,
        args.rate,
        args.duration.as_secs(),
        args.warmup.as_secs(),
        args.names,
        args.key.is_some(),
        tally.late,
        tally.bad_signatures,
    );
    println!("{line}");
    if let Some(path) = &args.out {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open the output file");
        writeln!(file, "{line}").expect("write the output file");
    }
}
