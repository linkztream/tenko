//! The engine as a standalone authoritative server, for the loopback measurement M16 (and
//! M22) until the `dns` role of `tenko serve` exists (WP4.3).
//!
//! It builds the `example.test` zone of `bench/phase2-dns zonegen` in memory (the same
//! owners, addresses and TTLs, so the harness's `queries.txt` fits), feeds it through
//! `MemFeed` into the catalog, and serves it over UDP and TCP on the listen addresses:
//!
//! ```text
//! authoritative [--listen ADDR]... [--workers N] [--names N] [--metrics on|off]
//!               [--mode shared|reuseport] [--tcp on|off] [--pid-file PATH]
//! ```
//!
//! `--listen` defaults to 127.0.0.1:5399 and may be given more than once; `--workers` is
//! the number of UDP workers per address (and of tokio threads for TCP), default 1;
//! `--names` the number of `host-{n}` names, default 100,000. It prints one `ready ...` line
//! when it answers and runs until it is interrupted, then prints the worker counters.

use std::{
    net::{Ipv4Addr, SocketAddr},
    process::ExitCode,
    time::Instant,
};

use tenko_core::{
    Revision,
    dns::{
        DnsName, Origin, Rdata, RecordData, RrSet, ScopeName, SerialPolicy, SoaDefaults, Zone,
        ZoneId, ZoneKind, ZoneScope,
    },
    ipam::Stamp,
    principal::{Principal, SystemComponent},
};
use tenko_dns::{
    DnsData, MemFeed, catalog,
    cookie::CookieMode,
    server::{Hooks, Server, ServerConfig},
    transport::{SocketMode, tcp::TcpSettings, udp::UdpSettings},
};

/// The forward zone of the generator.
const ZONE: &str = "example.test";
/// The first three octets of the three RFC 5737 networks, as the generator uses them.
const NETWORKS: [[u8; 3]; 3] = [[192, 0, 2], [198, 51, 100], [203, 0, 113]];
const TTLS: [u32; 4] = [300, 600, 900, 3600];
const SERIAL: u32 = 2_026_101_701;
const SEED: u64 = 42;

/// splitmix64's output function on `x` plus the golden gamma (the generator's TTL hash).
fn mix(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn ttl(host: u64) -> u32 {
    let index = usize::try_from(mix(SEED.wrapping_add(mix(host))) & 3).unwrap_or(0);
    TTLS[index]
}

fn address(host: u64) -> Ipv4Addr {
    let range = usize::try_from(host % 3).unwrap_or(0);
    let last = u8::try_from(1 + (host / 3) % 254).unwrap_or(1);
    let [a, b, c] = NETWORKS[range];
    Ipv4Addr::new(a, b, c, last)
}

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("a valid name")
}

/// The image: the zone of `zonegen --records names`, forward part only.
fn image(names: u64) -> DnsData {
    let stamp = Stamp::new(
        "2026-10-17T12:00:00Z".parse().expect("a time"),
        Principal::system(SystemComponent::Dns),
    );
    let zone = Zone {
        id: ZoneId::generate(),
        name: name(ZONE),
        kind: ZoneKind::Primary,
        tenant: None,
        scopes: vec![ZoneScope::default_scope()],
        serial: SerialPolicy::default(),
        soa: SoaDefaults::new(name("ns1.example.test"), name("hostmaster.example.test")),
        transfer: tenko_core::dns::TransferPolicy::default(),
        update: tenko_core::dns::UpdatePolicy::default(),
        dnssec: tenko_core::dns::DnssecPolicy::default(),
        source: None,
        reverse_of: None,
        description: None,
        created: stamp.clone(),
        updated: stamp.clone(),
    };
    let mut image = DnsData::at(Revision(1));
    let mut add = |owner: DnsName, ttl: u32, data: RecordData| {
        let set = RrSet {
            zone: zone.id,
            scope: ScopeName::DEFAULT,
            name: owner,
            rtype: data.rtype(),
            ttl,
            rdata: vec![Rdata::from_data(&data)],
            origin: Origin::Manual,
            key: None,
            updated: stamp.clone(),
        };
        image.rrsets.insert(set.key(), set);
    };
    add(
        name(ZONE),
        300,
        RecordData::Soa {
            mname: name("ns1.example.test"),
            rname: name("hostmaster.example.test"),
            serial: SERIAL,
            refresh: 3600,
            retry: 900,
            expire: 604_800,
            minimum: 300,
        },
    );
    add(
        name(ZONE),
        300,
        RecordData::Ns {
            host: name("ns1.example.test"),
        },
    );
    add(
        name("ns1.example.test"),
        300,
        RecordData::A {
            address: Ipv4Addr::new(192, 0, 2, 254),
        },
    );
    for host in 0..names {
        add(
            name(&format!("host-{host}.{ZONE}")),
            ttl(host),
            RecordData::A {
                address: address(host),
            },
        );
    }
    image.zones.insert(zone.id, zone);
    image
}

struct Args {
    listen: Vec<SocketAddr>,
    workers: usize,
    names: u64,
    metrics: bool,
    mode: SocketMode,
    tcp: bool,
    pid_file: Option<String>,
}

fn on_off(value: &str) -> Result<bool, String> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(format!("expected on or off, not {value}")),
    }
}

fn parse() -> Result<Args, String> {
    let mut args = Args {
        listen: Vec::new(),
        workers: 1,
        names: 100_000,
        metrics: true,
        mode: SocketMode::platform_default(),
        tcp: true,
        pid_file: None,
    };
    let mut items = std::env::args().skip(1);
    while let Some(flag) = items.next() {
        let mut value = || items.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--listen" => args.listen.push(
                value()?
                    .parse()
                    .map_err(|error| format!("--listen: {error}"))?,
            ),
            "--workers" => {
                args.workers = value()?
                    .parse()
                    .map_err(|error| format!("--workers: {error}"))?;
            }
            "--names" => {
                args.names = value()?
                    .parse()
                    .map_err(|error| format!("--names: {error}"))?;
            }
            "--metrics" => args.metrics = on_off(&value()?)?,
            "--tcp" => args.tcp = on_off(&value()?)?,
            "--mode" => {
                args.mode = match value()?.as_str() {
                    "shared" => SocketMode::Shared,
                    "reuseport" => SocketMode::ReusePort,
                    other => return Err(format!("--mode: shared or reuseport, not {other}")),
                };
            }
            "--pid-file" => args.pid_file = Some(value()?),
            "-h" | "--help" => {
                return Err(
                    "usage: authoritative [--listen ADDR]... [--workers N] [--names N] \
                     [--metrics on|off] [--mode shared|reuseport] [--tcp on|off] [--pid-file PATH]"
                        .to_string(),
                );
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if args.listen.is_empty() {
        args.listen
            .push(SocketAddr::from((Ipv4Addr::LOCALHOST, 5399)));
    }
    if args.workers == 0 {
        return Err("--workers must be at least 1".to_string());
    }
    Ok(args)
}

async fn run(args: Args) -> Result<(), String> {
    let started = Instant::now();
    let (mut feed, _writer) = MemFeed::new(image(args.names));
    let handle = catalog::initial(&mut feed)
        .await
        .map_err(|error| format!("the index: {error}"))?;
    let built = started.elapsed();
    let stats = handle.load().index().stats();
    let config = ServerConfig {
        listen: args.listen.clone(),
        udp: UdpSettings {
            workers: args.workers,
            mode: args.mode,
            ..UdpSettings::default()
        },
        tcp: args.tcp.then(TcpSettings::default),
        metrics: args.metrics,
        cookies: CookieMode::On,
        edns_udp_size: 1232,
        tls: None,
    };
    let server = Server::start_authoritative(config, handle, Hooks::default())
        .await
        .map_err(|error| format!("start: {error}"))?;
    if let Some(path) = &args.pid_file {
        std::fs::write(path, format!("{}\n", std::process::id()))
            .map_err(|error| format!("--pid-file {path}: {error}"))?;
    }
    let listen: Vec<String> = server
        .udp_addresses()
        .iter()
        .map(ToString::to_string)
        .collect();
    println!(
        "ready pid={} listen={} workers={} mode={} tcp={} metrics={} names={} index_nodes={} index_ms={}",
        std::process::id(),
        listen.join(","),
        args.workers,
        args.mode.as_str(),
        if args.tcp { "on" } else { "off" },
        if args.metrics { "on" } else { "off" },
        args.names,
        stats.base_nodes,
        built.as_millis(),
    );
    stopped().await?;
    let layout = server.layout();
    server.stop().await;
    let received: Vec<u64> = layout.udp.iter().map(|worker| worker.received).collect();
    println!(
        "stats received={} sent={} dropped={} recv_errors={} send_errors={} per_worker_received={received:?}",
        received.iter().sum::<u64>(),
        layout.udp.iter().map(|worker| worker.sent).sum::<u64>(),
        layout.udp.iter().map(|worker| worker.dropped).sum::<u64>(),
        layout
            .udp
            .iter()
            .map(|worker| worker.recv_errors)
            .sum::<u64>(),
        layout
            .udp
            .iter()
            .map(|worker| worker.send_errors)
            .sum::<u64>(),
    );
    Ok(())
}

/// Waits for an interrupt, or on Unix also for SIGTERM (what the measurement scripts send),
/// so that the worker counters are printed either way.
async fn stopped() -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|error| format!("signal: {error}"))?;
        tokio::select! {
            interrupted = tokio::signal::ctrl_c() => interrupted.map_err(|error| format!("signal: {error}")),
            _ = term.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|error| format!("signal: {error}"))
    }
}

fn main() -> ExitCode {
    let args = match parse() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.workers)
        .thread_name("dns-tcp")
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
