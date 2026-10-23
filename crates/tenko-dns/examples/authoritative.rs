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
//!
//! # Quirk mode
//!
//! The recursive resolver's lab (`deploy/compose/lab-dns`, the service `quirk`) needs an
//! authoritative server that misbehaves on purpose, one misbehaviour per container. Giving
//! `--quirk-zone` switches to that mode, and `--workers`, `--names`, `--metrics`, `--mode`,
//! `--tcp` and `--pid-file` are then refused:
//!
//! ```text
//! authoritative --quirk-zone ZONE --quirk-address IP [--listen ADDR]...
//!               [--no-edns] [--lower-case] [--truncate] [--delay-ms N] [--wrong-source]
//!               [--referral CHILD=NSNAME]... [--glue NAME=ADDR]...
//! ```
//!
//! The server is authoritative for `ZONE` only: the SOA and the NS record at the apex
//! (`ns.ZONE` is the primary and the only name server), `ns.ZONE` at `--quirk-address`,
//! `www.ZONE` with the addresses `192.0.2.7` and `2001:db8::7`, and `txt.ZONE` with the text
//! `quirk`, all with a TTL of 60 seconds. The engine answers from that zone through the
//! same [`Responder`] as the server of the `dns` role, so the answers are its own:
//! authoritative answers, NXDOMAIN and NODATA with the SOA, REFUSED outside the zone. A
//! small UDP and TCP loop on tokio runs each query through the responder and then spoils
//! the finished answer as asked. `--listen` defaults to 0.0.0.0:53 in this mode. The
//! misbehaviours combine.
//!
//! `--no-edns` answers a query that carries an OPT record with FORMERR, the question and no
//! OPT record, as a server that predates EDNS does, and answers a query without one
//! normally. `--lower-case` writes the question name of every answer in lower case, which
//! breaks the 0x20 case randomisation of a resolver. `--truncate` answers every UDP query
//! with the header and the question and the TC bit (and an empty OPT record when the query
//! had one); TCP is answered in full. `--delay-ms` holds every answer back by that many
//! milliseconds. `--wrong-source` sends the UDP answers from a second socket on the same
//! address and port 5353, so that they arrive from the wrong source port; TCP is
//! unchanged.
//!
//! `--referral CHILD=NSNAME` (repeatable; `CHILD` must be below `ZONE`) makes the server
//! answer a query for `CHILD` or any name below it as a referral that the engine does not
//! know: NOERROR, no AA bit, an empty answer section, `CHILD NS NSNAME` (TTL 60) in the
//! authority section, the question as asked, and the OPT record when the query had one. A DS
//! query at `CHILD` itself is the parent's to answer and goes to the engine. `--glue
//! NAME=ADDR` (repeatable, IPv4 or IPv6) adds `NAME A ADDR` (or `AAAA`) to the additional
//! section of every referral, before the OPT record and whatever `NAME` is, so that it can
//! be glue outside the bailiwick that a resolver must ignore. The other misbehaviours apply
//! to a referral as to any answer. The line `ready quirk ZONE on ADDR... flags ...` on
//! standard output tells that the server answers.
//!
//! `--proxy ADDR` (WP10.2) turns the server into a forwarding proxy for the lab's
//! forwarded rows: every query is asked of `ADDR` on port 53 over UDP and its answer
//! relayed; with `--strip-dnssec` the RRSIG, NSEC and NSEC3 records are left out of it, as
//! an upstream that strips the DNSSEC records answers (`dns.forwarder.strips_dnssec`).

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::ExitCode,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{sleep, timeout},
};

use tenko_core::{
    Revision,
    dns::{
        DnsName, Origin, QueryTransport, Rdata, RecordData, RrSet, ScopeName, SerialPolicy,
        SoaDefaults, TextBytes, Zone, ZoneId, ZoneKind, ZoneScope,
    },
    ipam::Stamp,
    principal::{Principal, SystemComponent},
};
use tenko_dns::{
    DnsData, MemFeed,
    authoritative::Authoritative,
    catalog,
    cookie::{CookieMode, CookieSecret},
    respond::{Clock, Conn, Reply, Responder, Scratch},
    server::{Hooks, Server, ServerConfig},
    transport::{SocketMode, tcp::TcpSettings, udp::UdpSettings},
    wire,
};

/// The forward zone of the generator.
const ZONE: &str = "example.test";
/// The first three octets of the three RFC 5737 networks, as the generator uses them.
const NETWORKS: [[u8; 3]; 3] = [[192, 0, 2], [198, 51, 100], [203, 0, 113]];
const TTLS: [u32; 4] = [300, 600, 900, 3600];
const SERIAL: u32 = 2_026_101_701;
const SEED: u64 = 42;

/// The port of the second socket of `--wrong-source`.
const WRONG_SOURCE_PORT: u16 = 5353;
/// How long a quirk-mode TCP connection may stay silent before it is closed.
const TCP_IDLE: Duration = Duration::from_secs(10);

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

/// A primary zone being built in memory: its row, and the record sets added to its image.
struct Builder {
    image: DnsData,
    zone: ZoneId,
    stamp: Stamp,
}

impl Builder {
    /// A zone `origin` with the given primary name server and responsible mailbox.
    fn new(origin: &str, primary: &str, hostmaster: &str) -> Self {
        let stamp = Stamp::new(
            "2026-10-17T12:00:00Z".parse().expect("a time"),
            Principal::system(SystemComponent::Dns),
        );
        let zone = Zone {
            id: ZoneId::generate(),
            name: name(origin),
            kind: ZoneKind::Primary,
            tenant: None,
            scopes: vec![ZoneScope::default_scope()],
            serial: SerialPolicy::default(),
            soa: SoaDefaults::new(name(primary), name(hostmaster)),
            transfer: tenko_core::dns::TransferPolicy::default(),
            update: tenko_core::dns::UpdatePolicy::default(),
            dnssec: tenko_core::dns::DnssecPolicy::default(),
            source: None,
            reverse_of: None,
            catalog: false,
            description: None,
            created: stamp.clone(),
            updated: stamp.clone(),
        };
        let id = zone.id;
        let mut image = DnsData::at(Revision(1));
        image.zones.insert(id, zone);
        Self {
            image,
            zone: id,
            stamp,
        }
    }

    fn add(&mut self, owner: DnsName, ttl: u32, data: &RecordData) {
        let set = RrSet {
            zone: self.zone,
            scope: ScopeName::DEFAULT,
            name: owner,
            rtype: data.rtype(),
            ttl,
            rdata: vec![Rdata::from_data(data)],
            origin: Origin::Manual,
            key: None,
            updated: self.stamp.clone(),
        };
        self.image.rrsets.insert(set.key(), set);
    }
}

/// The image: the zone of `zonegen --records names`, forward part only.
fn image(names: u64) -> DnsData {
    let mut zone = Builder::new(ZONE, "ns1.example.test", "hostmaster.example.test");
    zone.add(
        name(ZONE),
        300,
        &RecordData::Soa {
            mname: name("ns1.example.test"),
            rname: name("hostmaster.example.test"),
            serial: SERIAL,
            refresh: 3600,
            retry: 900,
            expire: 604_800,
            minimum: 300,
        },
    );
    zone.add(
        name(ZONE),
        300,
        &RecordData::Ns {
            host: name("ns1.example.test"),
        },
    );
    zone.add(
        name("ns1.example.test"),
        300,
        &RecordData::A {
            address: Ipv4Addr::new(192, 0, 2, 254),
        },
    );
    for host in 0..names {
        zone.add(
            name(&format!("host-{host}.{ZONE}")),
            ttl(host),
            &RecordData::A {
                address: address(host),
            },
        );
    }
    zone.image
}

/// The image of quirk mode: the small zone of the module documentation.
fn quirk_image(origin: &str, address: Ipv4Addr) -> DnsData {
    let server = format!("ns.{origin}");
    let hostmaster = format!("hostmaster.{origin}");
    let mut zone = Builder::new(origin, &server, &hostmaster);
    zone.add(
        name(origin),
        60,
        &RecordData::Soa {
            mname: name(&server),
            rname: name(&hostmaster),
            serial: 1,
            refresh: 3600,
            retry: 900,
            expire: 1_209_600,
            minimum: 60,
        },
    );
    zone.add(
        name(origin),
        60,
        &RecordData::Ns {
            host: name(&server),
        },
    );
    zone.add(name(&server), 60, &RecordData::A { address });
    zone.add(
        name(&format!("www.{origin}")),
        60,
        &RecordData::A {
            address: Ipv4Addr::new(192, 0, 2, 7),
        },
    );
    zone.add(
        name(&format!("www.{origin}")),
        60,
        &RecordData::Aaaa {
            address: "2001:db8::7".parse().expect("an address"),
        },
    );
    zone.add(
        name(&format!("txt.{origin}")),
        60,
        &RecordData::Txt {
            strings: vec![TextBytes::from_text("quirk")],
        },
    );
    zone.image
}

/// The misbehaviours of quirk mode.
#[derive(Debug, Clone, Copy, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one switch per misbehaviour, as the flags"
)]
struct Quirks {
    no_edns: bool,
    lower_case: bool,
    truncate: bool,
    delay: Duration,
    wrong_source: bool,
    // WP10.2: the stripping proxy.
    /// `--proxy ADDR`: every query is asked of this server instead of the zone.
    proxy: Option<SocketAddr>,
    /// `--strip-dnssec`: the RRSIG, NSEC and NSEC3 records leave the proxied answer.
    strip_dnssec: bool,
}

impl Quirks {
    /// The switches that are on, as the ready line prints them.
    fn flags(&self) -> Vec<String> {
        let mut flags = Vec::new();
        // WP10.2: the stripping proxy.
        if let Some(proxy) = self.proxy {
            flags.push(format!("proxy={proxy}"));
        }
        if self.strip_dnssec {
            flags.push("strip-dnssec".to_string());
        }
        if self.no_edns {
            flags.push("no-edns".to_string());
        }
        if self.lower_case {
            flags.push("lower-case".to_string());
        }
        if self.truncate {
            flags.push("truncate".to_string());
        }
        if !self.delay.is_zero() {
            flags.push(format!("delay-ms={}", self.delay.as_millis()));
        }
        if self.wrong_source {
            flags.push("wrong-source".to_string());
        }
        flags
    }
}

/// What `--quirk-zone` asks for.
struct QuirkArgs {
    zone: String,
    address: Ipv4Addr,
    quirks: Quirks,
    /// `--referral CHILD=NSNAME`.
    referrals: Vec<(String, String)>,
    /// `--glue NAME=ADDR`.
    glue: Vec<(String, IpAddr)>,
}

impl QuirkArgs {
    /// The flags as the ready line prints them.
    fn describe(&self) -> String {
        let mut flags = self.quirks.flags();
        flags.extend(
            self.referrals
                .iter()
                .map(|(child, host)| format!("referral={child}={host}")),
        );
        flags.extend(
            self.glue
                .iter()
                .map(|(name, address)| format!("glue={name}={address}")),
        );
        if flags.is_empty() {
            "none".to_string()
        } else {
            flags.join(" ")
        }
    }
}

/// Splits `NAME=VALUE` of a flag.
fn pair(flag: &str, value: &str) -> Result<(String, String), String> {
    let (name, rest) = value
        .split_once('=')
        .ok_or(format!("{flag}: expected NAME=VALUE, not {value}"))?;
    DnsName::new(name).map_err(|error| format!("{flag}: {error}"))?;
    Ok((name.to_string(), rest.to_string()))
}

struct Args {
    listen: Vec<SocketAddr>,
    workers: usize,
    names: u64,
    metrics: bool,
    mode: SocketMode,
    tcp: bool,
    pid_file: Option<String>,
    quirk: Option<QuirkArgs>,
}

fn on_off(value: &str) -> Result<bool, String> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(format!("expected on or off, not {value}")),
    }
}

const USAGE: &str = "usage: authoritative [--listen ADDR]... [--workers N] [--names N] \
                     [--metrics on|off] [--mode shared|reuseport] [--tcp on|off] [--pid-file PATH]\n       \
                     authoritative --quirk-zone ZONE --quirk-address IP [--listen ADDR]... \
                     [--no-edns] [--lower-case] [--truncate] [--delay-ms N] [--wrong-source] \
                     [--referral CHILD=NSNAME]... [--glue NAME=ADDR]...";

#[allow(
    clippy::too_many_lines,
    reason = "one arm per flag, the two modes side by side"
)]
fn parse() -> Result<Args, String> {
    let mut args = Args {
        listen: Vec::new(),
        workers: 1,
        names: 100_000,
        metrics: true,
        mode: SocketMode::platform_default(),
        tcp: true,
        pid_file: None,
        quirk: None,
    };
    let mut quirk_zone: Option<String> = None;
    let mut quirk_address: Option<Ipv4Addr> = None;
    let mut quirks = Quirks::default();
    let mut referrals: Vec<(String, String)> = Vec::new();
    let mut glue: Vec<(String, IpAddr)> = Vec::new();
    // The flags of the engine's mode that quirk mode does not take.
    let mut plain_flag: Option<String> = None;
    let mut items = std::env::args().skip(1);
    while let Some(flag) = items.next() {
        let mut value = || items.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--listen" => args.listen.push(
                value()?
                    .parse()
                    .map_err(|error| format!("--listen: {error}"))?,
            ),
            "--quirk-zone" => {
                let zone = value()?;
                DnsName::new(&zone).map_err(|error| format!("--quirk-zone: {error}"))?;
                quirk_zone = Some(zone);
            }
            "--quirk-address" => {
                quirk_address = Some(
                    value()?
                        .parse()
                        .map_err(|error| format!("--quirk-address: {error}"))?,
                );
            }
            "--no-edns" => quirks.no_edns = true,
            "--lower-case" => quirks.lower_case = true,
            "--truncate" => quirks.truncate = true,
            "--wrong-source" => quirks.wrong_source = true,
            // WP10.2: the stripping proxy.
            "--strip-dnssec" => quirks.strip_dnssec = true,
            "--proxy" => {
                let address: IpAddr = value()?
                    .parse()
                    .map_err(|error| format!("--proxy: {error}"))?;
                quirks.proxy = Some(SocketAddr::new(address, 53));
            }
            "--referral" => referrals.push(pair(&flag, &value()?)?),
            "--glue" => {
                let (name, address) = pair(&flag, &value()?)?;
                glue.push((
                    name,
                    address
                        .parse()
                        .map_err(|error| format!("--glue: {error}"))?,
                ));
            }
            "--delay-ms" => {
                let millis: u64 = value()?
                    .parse()
                    .map_err(|error| format!("--delay-ms: {error}"))?;
                quirks.delay = Duration::from_millis(millis);
            }
            "--workers" => {
                plain_flag = Some(flag.clone());
                args.workers = value()?
                    .parse()
                    .map_err(|error| format!("--workers: {error}"))?;
            }
            "--names" => {
                plain_flag = Some(flag.clone());
                args.names = value()?
                    .parse()
                    .map_err(|error| format!("--names: {error}"))?;
            }
            "--metrics" => {
                plain_flag = Some(flag.clone());
                args.metrics = on_off(&value()?)?;
            }
            "--tcp" => {
                plain_flag = Some(flag.clone());
                args.tcp = on_off(&value()?)?;
            }
            "--mode" => {
                plain_flag = Some(flag.clone());
                args.mode = match value()?.as_str() {
                    "shared" => SocketMode::Shared,
                    "reuseport" => SocketMode::ReusePort,
                    other => return Err(format!("--mode: shared or reuseport, not {other}")),
                };
            }
            "--pid-file" => {
                plain_flag = Some(flag.clone());
                args.pid_file = Some(value()?);
            }
            "-h" | "--help" => return Err(USAGE.to_string()),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if let Some(zone) = quirk_zone {
        if let Some(flag) = plain_flag {
            return Err(format!("{flag} does not apply with --quirk-zone"));
        }
        let address = quirk_address.ok_or("--quirk-zone needs --quirk-address")?;
        let suffix = format!(".{}", zone.trim_end_matches('.').to_ascii_lowercase());
        for (child, host) in &referrals {
            DnsName::new(host).map_err(|error| format!("--referral: {error}"))?;
            if !child
                .trim_end_matches('.')
                .to_ascii_lowercase()
                .ends_with(&suffix)
            {
                return Err(format!("--referral: {child} is not below {zone}"));
            }
        }
        args.quirk = Some(QuirkArgs {
            zone,
            address,
            quirks,
            referrals,
            glue,
        });
        if args.listen.is_empty() {
            args.listen
                .push(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 53)));
        }
    } else {
        let quirk_flag = quirk_address.map(|_| "--quirk-address").or_else(|| {
            [
                (quirks.no_edns, "--no-edns"),
                (quirks.lower_case, "--lower-case"),
                (quirks.truncate, "--truncate"),
                (quirks.wrong_source, "--wrong-source"),
                (!quirks.delay.is_zero(), "--delay-ms"),
                (!referrals.is_empty(), "--referral"),
                (!glue.is_empty(), "--glue"),
            ]
            .into_iter()
            .find_map(|(given, flag)| given.then_some(flag))
        });
        if let Some(flag) = quirk_flag {
            return Err(format!("{flag} needs --quirk-zone"));
        }
        if args.listen.is_empty() {
            args.listen
                .push(SocketAddr::from((Ipv4Addr::LOCALHOST, 5399)));
        }
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

// Quirk mode.

/// The responder of quirk mode: the engine's authoritative resolver, cookies and all, with
/// metrics off (nothing reads them here).
type Engine = Arc<Setup>;

/// What the loops of quirk mode share: the responder and the referrals.
struct Setup {
    responder: Responder<Authoritative>,
    referrals: Referrals,
}

/// A delegation that `--referral` makes the server answer with a referral.
struct Child {
    /// The name in lower case without the final dot.
    name: String,
    /// The name and the name server in wire format.
    owner: Vec<u8>,
    host: Vec<u8>,
}

/// An address record of `--glue`, in wire format.
struct Glue {
    owner: Vec<u8>,
    rtype: u16,
    rdata: Vec<u8>,
}

/// The referrals of `--referral` and the glue of `--glue`.
struct Referrals {
    children: Vec<Child>,
    glue: Vec<Glue>,
}

/// The wire format of a name in presentation form (no compression).
fn wire_name(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in text.split('.').filter(|label| !label.is_empty()) {
        out.push(u8::try_from(label.len()).unwrap_or(63));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

impl Referrals {
    fn new(children: &[(String, String)], glue: &[(String, IpAddr)]) -> Self {
        Self {
            children: children
                .iter()
                .map(|(name, host)| Child {
                    name: name.trim_end_matches('.').to_ascii_lowercase(),
                    owner: wire_name(name),
                    host: wire_name(host),
                })
                .collect(),
            glue: glue
                .iter()
                .map(|(name, address)| match address {
                    IpAddr::V4(v4) => Glue {
                        owner: wire_name(name),
                        rtype: 1,
                        rdata: v4.octets().to_vec(),
                    },
                    IpAddr::V6(v6) => Glue {
                        owner: wire_name(name),
                        rtype: 28,
                        rdata: v6.octets().to_vec(),
                    },
                })
                .collect(),
        }
    }

    /// The most specific child that the query asks for or below: any type, except DS at the
    /// child itself (the parent answers that one, so the engine does).
    fn find(&self, query: &[u8]) -> Option<&Child> {
        let header = wire::parse_header(query)?;
        if header.qr || header.opcode != 0 || header.qdcount != 1 {
            return None;
        }
        let mut labels = Vec::new();
        let mut position = wire::HEADER_LEN;
        loop {
            let length = usize::from(*query.get(position)?);
            if length == 0 {
                position += 1;
                break;
            }
            if length >= 0xC0 {
                return None;
            }
            labels.push(
                String::from_utf8_lossy(query.get(position + 1..position + 1 + length)?)
                    .to_ascii_lowercase(),
            );
            position += 1 + length;
        }
        let qtype = u16::from_be_bytes([*query.get(position)?, *query.get(position + 1)?]);
        let qname = labels.join(".");
        self.children
            .iter()
            .filter(|child| {
                let below = qname
                    .strip_suffix(child.name.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'));
                below && !(qtype == 43 && qname == child.name)
            })
            .max_by_key(|child| child.name.len())
    }

    /// The referral to `child`: NOERROR, no AA, the question of the query, `child NS host`
    /// in the authority section, the glue and the OPT record (when the query had one) in
    /// the additional section.
    fn answer(&self, query: &[u8], child: &Child) -> Option<Vec<u8>> {
        let header = wire::parse_header(query)?;
        let end = wire::questions_end(query, header.qdcount)?;
        let mut out = query.get(..end)?.to_vec();
        out[2] = 0x80 | u8::from(header.rd);
        out[3] = 0;
        out[6..wire::HEADER_LEN].fill(0);
        out[9] = 1;
        out.extend_from_slice(&child.owner);
        out.extend_from_slice(&2u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&60u32.to_be_bytes());
        out.extend_from_slice(&u16::try_from(child.host.len()).ok()?.to_be_bytes());
        out.extend_from_slice(&child.host);
        let mut additional = u16::try_from(self.glue.len()).ok()?;
        for glue in &self.glue {
            out.extend_from_slice(&glue.owner);
            out.extend_from_slice(&glue.rtype.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&60u32.to_be_bytes());
            out.extend_from_slice(&u16::try_from(glue.rdata.len()).ok()?.to_be_bytes());
            out.extend_from_slice(&glue.rdata);
        }
        if has_opt(query) {
            push_opt(&mut out);
            additional += 1;
        }
        out[10..wire::HEADER_LEN].copy_from_slice(&additional.to_be_bytes());
        Some(out)
    }
}

/// Appends an empty OPT record advertising the server's UDP size.
fn push_opt(out: &mut Vec<u8>) {
    out.push(0);
    out.extend_from_slice(&wire::TYPE_OPT.to_be_bytes());
    out.extend_from_slice(&wire::SERVER_UDP_PAYLOAD.to_be_bytes());
    out.extend_from_slice(&[0; 6]);
}

/// Whether the query message carries an OPT record in its additional section.
fn has_opt(query: &[u8]) -> bool {
    let Some(header) = wire::parse_header(query) else {
        return false;
    };
    let Some(mut position) = wire::questions_end(query, header.qdcount) else {
        return false;
    };
    let before = usize::from(header.ancount) + usize::from(header.nscount);
    for index in 0..before + usize::from(header.arcount) {
        let Some(record) = wire::read_record(query, position) else {
            return false;
        };
        if index >= before && record.rtype == wire::TYPE_OPT {
            return true;
        }
        position = record.end();
    }
    false
}

/// FORMERR with the question of the query and no other section, no OPT record. `None` for
/// a response or a message that is no query at all.
fn formerr_with_question(query: &[u8]) -> Option<Vec<u8>> {
    let header = wire::parse_header(query)?;
    if header.qr {
        return None;
    }
    let end = wire::questions_end(query, header.qdcount)?;
    let mut out = query.get(..end)?.to_vec();
    out[2] = 0x80 | (header.opcode << 3) | u8::from(header.rd);
    out[3] = 1;
    out[6..wire::HEADER_LEN].fill(0);
    Some(out)
}

/// Writes the labels of the first question name of `message` in lower case (a compression
/// pointer ends the walk; the question of an answer has none).
fn lower_question(message: &mut [u8]) {
    let mut position = wire::HEADER_LEN;
    while let Some(&length) = message.get(position) {
        if length == 0 || length >= 0xC0 {
            break;
        }
        let end = position + 1 + usize::from(length);
        let Some(label) = message.get_mut(position + 1..end) else {
            break;
        };
        label.make_ascii_lowercase();
        position = end;
    }
}

/// The header and the question of `answer` with TC set and every count zero; with an empty
/// OPT record when the query had one.
fn truncated(answer: &[u8], query: &[u8]) -> Vec<u8> {
    let Some(header) = wire::parse_header(answer) else {
        return answer.to_vec();
    };
    let Some(end) = wire::questions_end(answer, header.qdcount) else {
        return answer.to_vec();
    };
    let mut out = answer[..end].to_vec();
    out[2] |= 0x02;
    out[6..wire::HEADER_LEN].fill(0);
    if has_opt(query) {
        out[11] = 1;
        push_opt(&mut out);
    }
    out
}

// WP10.2: the stripping proxy of the lab's forwarded rows (`dns.forwarder.strips_dnssec`).
/// Asks `upstream` the query over UDP (two seconds) and returns its answer; with `strip`,
/// the RRSIG, NSEC and NSEC3 records of every section are left out, as an upstream that
/// strips the DNSSEC records answers. `None` when the upstream does not answer.
fn proxy_answer(upstream: SocketAddr, query: &[u8], strip: bool) -> Option<Vec<u8>> {
    use tenko_dns::recurse::message::{Composed, Rr, compose, parse};
    let socket = std::net::UdpSocket::bind(if upstream.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    socket.send_to(query, upstream).ok()?;
    let mut buffer = vec![0u8; 4096];
    let (len, from) = socket.recv_from(&mut buffer).ok()?;
    if from != upstream {
        return None;
    }
    buffer.truncate(len);
    if !strip {
        return Some(buffer);
    }
    let parsed = parse(&buffer)?;
    let keep = |rr: &&Rr| !matches!(rr.rtype, 46 | 47 | 50);
    let answer: Vec<Rr> = parsed.answer.iter().filter(keep).cloned().collect();
    let authority: Vec<Rr> = parsed.authority.iter().filter(keep).cloned().collect();
    let additional: Vec<Rr> = parsed.additional.iter().filter(keep).cloned().collect();
    let mut out = compose(&Composed {
        qname: &parsed.qname,
        qtype: parsed.qtype,
        qclass: 1,
        rcode: u8::try_from(parsed.rcode & 0x0f).unwrap_or(2),
        answer: &answer,
        authority: &authority,
        additional: &additional,
    });
    // The client's id, the AA bit and the question as asked.
    out[..2].copy_from_slice(&query[..2]);
    if parsed.aa {
        out[2] |= 0x04;
    }
    Some(out)
}
// WP10.2: end.

/// The answer to one query message with the misbehaviours applied, or `None` when the
/// responder drops it.
fn quirk_answer(
    responder: &Engine,
    quirks: &Quirks,
    query: &[u8],
    conn: &Conn,
    clock: &Clock,
    scratch: &mut Scratch,
) -> Option<Vec<u8>> {
    if quirks.no_edns && has_opt(query) {
        return formerr_with_question(query);
    }
    // WP10.2: a proxied query never reaches the zone.
    if let Some(upstream) = quirks.proxy {
        return proxy_answer(upstream, query, quirks.strip_dnssec);
    }
    let referral = responder
        .referrals
        .find(query)
        .and_then(|child| responder.referrals.answer(query, child));
    let mut out = if let Some(referral) = referral {
        referral
    } else {
        match responder
            .responder
            .respond(query, conn, clock, Instant::now(), scratch)
        {
            Reply::Send => {}
            Reply::Drop | Reply::Forward { .. } => return None,
        }
        scratch.out.clone()
    };
    if quirks.lower_case {
        lower_question(&mut out);
    }
    if quirks.truncate && conn.transport == QueryTransport::Udp {
        out = truncated(&out, query);
    }
    Some(out)
}

/// Answers the datagrams of one socket; the answers leave from `sender` (a second socket
/// with `--wrong-source`).
async fn serve_udp(
    socket: Arc<UdpSocket>,
    sender: Arc<UdpSocket>,
    responder: Engine,
    quirks: Quirks,
) {
    let Ok(local) = socket.local_addr() else {
        return;
    };
    let mut scratch = Scratch::new();
    let mut clock = Clock::now();
    let mut buffer = vec![0u8; 4096];
    loop {
        // On Windows an ICMP port unreachable of an earlier answer shows up as a receive
        // error; it names no query, so the next receive goes on.
        let Ok((length, client)) = socket.recv_from(&mut buffer).await else {
            continue;
        };
        clock.refresh(Instant::now());
        let conn = Conn {
            client,
            local,
            transport: QueryTransport::Udp,
        };
        let Some(answer) = quirk_answer(
            &responder,
            &quirks,
            &buffer[..length],
            &conn,
            &clock,
            &mut scratch,
        ) else {
            continue;
        };
        if quirks.delay.is_zero() {
            let _ = sender.send_to(&answer, client).await;
        } else {
            let sender = Arc::clone(&sender);
            let delay = quirks.delay;
            tokio::spawn(async move {
                sleep(delay).await;
                let _ = sender.send_to(&answer, client).await;
            });
        }
    }
}

/// Accepts the TCP connections of one address.
async fn serve_tcp(listener: TcpListener, responder: Engine, quirks: Quirks) {
    let Ok(local) = listener.local_addr() else {
        return;
    };
    loop {
        match listener.accept().await {
            Ok((stream, client)) => {
                tokio::spawn(tcp_connection(
                    stream,
                    Conn {
                        client,
                        local,
                        transport: QueryTransport::Tcp,
                    },
                    Arc::clone(&responder),
                    quirks,
                ));
            }
            Err(_) => sleep(Duration::from_millis(50)).await,
        }
    }
}

/// Answers the queries of one TCP connection until the client closes it or stays silent.
async fn tcp_connection(mut stream: TcpStream, conn: Conn, responder: Engine, quirks: Quirks) {
    let mut scratch = Scratch::new();
    let mut clock = Clock::now();
    let mut message = Vec::new();
    loop {
        let mut prefix = [0u8; 2];
        if !matches!(
            timeout(TCP_IDLE, stream.read_exact(&mut prefix)).await,
            Ok(Ok(_))
        ) {
            return;
        }
        message.clear();
        message.resize(usize::from(u16::from_be_bytes(prefix)), 0);
        if !matches!(
            timeout(TCP_IDLE, stream.read_exact(&mut message)).await,
            Ok(Ok(_))
        ) {
            return;
        }
        clock.refresh(Instant::now());
        let Some(answer) = quirk_answer(&responder, &quirks, &message, &conn, &clock, &mut scratch)
        else {
            return;
        };
        let Ok(length) = u16::try_from(answer.len()) else {
            return;
        };
        sleep(quirks.delay).await;
        let mut framed = Vec::with_capacity(answer.len() + 2);
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(&answer);
        if stream.write_all(&framed).await.is_err() {
            return;
        }
    }
}

async fn run_quirk(args: Args, quirk: QuirkArgs) -> Result<(), String> {
    let (mut feed, _writer) = MemFeed::new(quirk_image(&quirk.zone, quirk.address));
    let handle = catalog::initial(&mut feed)
        .await
        .map_err(|error| format!("the index: {error}"))?;
    let cookies = CookieSecret::random().map_err(|_| "the random generator failed".to_string())?;
    let responder: Engine = Arc::new(Setup {
        responder: Responder::new(Authoritative::new(handle), cookies).with_metrics(false),
        referrals: Referrals::new(&quirk.referrals, &quirk.glue),
    });
    // Bind everything before anything runs, so that a port in use fails the start.
    let mut bound = Vec::new();
    for address in &args.listen {
        let udp = UdpSocket::bind(address)
            .await
            .map_err(|error| format!("udp {address}: {error}"))?;
        let local = udp
            .local_addr()
            .map_err(|error| format!("udp {address}: {error}"))?;
        let tcp = TcpListener::bind(local)
            .await
            .map_err(|error| format!("tcp {local}: {error}"))?;
        let other = if quirk.quirks.wrong_source {
            let wrong = SocketAddr::new(local.ip(), WRONG_SOURCE_PORT);
            Some(
                UdpSocket::bind(wrong)
                    .await
                    .map_err(|error| format!("udp {wrong} (--wrong-source): {error}"))?,
            )
        } else {
            None
        };
        bound.push((local, udp, tcp, other));
    }
    let mut tasks = Vec::new();
    let mut listening = Vec::new();
    for (local, udp, tcp, other) in bound {
        listening.push(local.to_string());
        let udp = Arc::new(udp);
        let sender = other.map_or_else(|| Arc::clone(&udp), Arc::new);
        tasks.push(tokio::spawn(serve_udp(
            udp,
            sender,
            Arc::clone(&responder),
            quirk.quirks,
        )));
        tasks.push(tokio::spawn(serve_tcp(
            tcp,
            Arc::clone(&responder),
            quirk.quirks,
        )));
    }
    println!(
        "ready quirk {} on {} flags {}",
        quirk.zone,
        listening.join(" "),
        quirk.describe(),
    );
    stopped().await?;
    for task in tasks {
        task.abort();
    }
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
    let mut args = match parse() {
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
    let result = match args.quirk.take() {
        Some(quirk) => runtime.block_on(run_quirk(args, quirk)),
        None => runtime.block_on(run(args)),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
