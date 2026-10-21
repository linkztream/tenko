//! Lab integration test of the raw-socket scan methods (WP3.14), run on a Linux host that
//! has `CAP_NET_RAW` (as root in the lab). It covers the raw methods of SCAN-02 (LLDP and
//! CDP), SCAN-03 (DHCP snooping), SCAN-04 (ARP sweep, SYN scan, OS fingerprinting) and
//! SCAN-05 (LLDP neighbours). It is `#[ignore]`d: it needs a real segment and a target
//! host, so it runs only when invoked by name with the environment set. No address is
//! hard-coded; every address comes from the environment, so the repository names no
//! infrastructure.
//!
//! Set, then run as root on the probe host (the node VM) against the target (the load VM):
//!
//! ```sh
//! export TENKO_RAWTEST=1
//! export TENKO_RAWTEST_PREFIX=<segment prefix, e.g. 203.0.113.0/24>
//! export TENKO_RAWTEST_TARGET=<target address on that segment>
//! export TENKO_RAWTEST_OPEN_PORT=22          # a port open on the target
//! export TENKO_RAWTEST_CLOSED_PORT=9          # a port closed on the target
//! export TENKO_RAWTEST_IFACE=eth0            # optional interface override
//! export TENKO_RAWTEST_BIN=/path/to/tenko     # optional: the shipped binary under test
//! cargo test -p tenko --test node_scan_raw -- --ignored --nocapture
//! ```
//!
//! On the target, `lldpd` advertises LLDP (and CDP when `configure system allow-receive`),
//! and a DHCP DISCOVER is sent with `dhcping -i` or `nmap --script broadcast-dhcp-discover`
//! so the snoop sees it.

mod serve_support;

use std::{path::PathBuf, process::Command};

use serde_json::Value;
use serve_support::{Outcome, run, tenko};
use tempfile::TempDir;

/// The environment, or `None` when the gate variable is unset (the test then skips).
struct Lab {
    prefix: String,
    target: String,
    open_port: u16,
    closed_port: u16,
    iface: Option<String>,
}

impl Lab {
    fn from_env() -> Option<Self> {
        if std::env::var("TENKO_RAWTEST").ok().as_deref() != Some("1") {
            eprintln!("TENKO_RAWTEST is not set; skipping the raw-socket lab test");
            return None;
        }
        Some(Self {
            prefix: var("TENKO_RAWTEST_PREFIX"),
            target: var("TENKO_RAWTEST_TARGET"),
            open_port: var("TENKO_RAWTEST_OPEN_PORT").parse().expect("open port"),
            closed_port: var("TENKO_RAWTEST_CLOSED_PORT")
                .parse()
                .expect("closed port"),
            iface: std::env::var("TENKO_RAWTEST_IFACE").ok(),
        })
    }

    fn config(&self) -> String {
        let iface = self
            .iface
            .as_ref()
            .map_or_else(String::new, |name| format!("interface = \"{name}\"\n"));
        format!(
            "[scan]\n\
             prefixes = [\"{prefix}\"]\n\
             rate = \"unlimited\"\n\
             per_host_interval_ms = 0\n\
             active = true\n\
             [scan.arp]\nenabled = false\n\
             [scan.nd]\nenabled = false\n\
             [scan.icmp]\nenabled = false\n\
             [scan.mdns]\nenabled = false\n\
             [scan.llmnr]\nenabled = false\n\
             [scan.reverse_dns]\nenabled = false\n\
             [scan.tcp_connect]\nenabled = false\n\
             [scan.arp_sweep]\nenabled = true\ntimeout_ms = 3000\n{iface}\
             [scan.tcp_syn]\nenabled = true\ntargets = \"all\"\ntimeout_ms = 3000\nports = [{open}, {closed}]\n{iface}\
             [scan.os_fingerprint]\nenabled = true\ntimeout_ms = 3000\nports = [{open}]\n{iface}\
             [scan.lldp]\nenabled = true\nlisten_secs = 40\ncdp = true\n{iface}\
             [scan.dhcp_snoop]\nenabled = true\nlisten_secs = 25\n{iface}",
            prefix = self.prefix,
            open = self.open_port,
            closed = self.closed_port,
        )
    }
}

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set for the raw-socket lab test"))
}

struct Site {
    dir: TempDir,
}

impl Site {
    fn new(config: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix("tenko-raw-")
            .tempdir()
            .expect("temporary directory");
        std::fs::write(dir.path().join("tenko.toml"), config).expect("write config");
        Self { dir }
    }

    fn data_dir(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    /// Runs `tenko node scan run <args>` and returns the outcome.
    fn run(&self, args: &[&str]) -> Outcome {
        let mut command = shipped_tenko();
        command
            .args(["node", "scan", "run"])
            .args(args)
            .arg("--data-dir")
            .arg(self.data_dir())
            .env("TENKO_CONFIG", self.dir.path().join("tenko.toml"));
        run(command, None)
    }
}

/// The `tenko` command under test: the binary `TENKO_RAWTEST_BIN` names (the shipped musl
/// build copied to the lab host), else the one cargo built. The environment is cleaned as
/// the shared harness does it.
fn shipped_tenko() -> Command {
    let template = tenko();
    let Some(path) = std::env::var_os("TENKO_RAWTEST_BIN") else {
        return template;
    };
    let mut command = Command::new(path);
    for (name, value) in template.get_envs() {
        match value {
            Some(value) => command.env(name, value),
            None => command.env_remove(name),
        };
    }
    command
}

/// The sightings of a dry run of `method` (optionally narrowed to `target`).
fn sightings(site: &Site, method: &str, target: Option<&str>) -> Vec<Value> {
    let mut args = vec![method, "--dry-run", "--json"];
    if let Some(target) = target {
        args.push("--target");
        args.push(target);
    }
    let outcome = site.run(&args);
    outcome.assert_code(0);
    let body = outcome.json();
    eprintln!("{method}: {}", body["run"]);
    body["batch"]["sightings"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

#[test]
#[ignore = "needs a lab segment, a target host and CAP_NET_RAW; set TENKO_RAWTEST"]
fn the_raw_methods_find_the_lab_target() {
    let Some(lab) = Lab::from_env() else {
        return;
    };
    let site = Site::new(&lab.config());

    // ARP sweep: the target answers with its MAC.
    let arp = sightings(&site, "arp_sweep", Some(&lab.target));
    assert!(
        arp.iter().any(|s| {
            s["subject"]["type"] == "address"
                && s["subject"]["data"]["ip"] == lab.target.as_str()
                && s["subject"]["data"]["mac"].is_string()
        }),
        "arp_sweep did not find the target's MAC: {arp:?}"
    );

    // SYN scan: the open port is open, the closed port is not reported open.
    let syn = sightings(&site, "tcp_syn", Some(&lab.target));
    let services = syn
        .iter()
        .find(|s| {
            s["subject"]["type"] == "services" && s["subject"]["data"]["ip"] == lab.target.as_str()
        })
        .unwrap_or_else(|| panic!("tcp_syn reported no services for the target: {syn:?}"));
    let open: Vec<u64> = services["subject"]["data"]["open_tcp"]
        .as_array()
        .expect("open_tcp")
        .iter()
        .filter_map(Value::as_u64)
        .collect();
    assert!(
        open.contains(&u64::from(lab.open_port)),
        "open port missing: {open:?}"
    );
    assert!(
        !open.contains(&u64::from(lab.closed_port)),
        "the closed port was reported open: {open:?}"
    );

    // Fingerprint: the Linux target is classified as Linux.
    let os = sightings(&site, "os_fingerprint", Some(&lab.target));
    assert!(
        os.iter().any(|s| {
            s["subject"]["type"] == "os"
                && s["subject"]["data"]["ip"] == lab.target.as_str()
                && s["subject"]["data"]["guess"]
                    .as_str()
                    .is_some_and(|g| g.contains("Linux"))
        }),
        "os_fingerprint did not say Linux: {os:?}"
    );

    // LLDP: the frame lldpd sends is seen as a neighbour (a link or an attachment).
    let lldp = sightings(&site, "lldp", None);
    assert!(
        lldp.iter().any(|s| matches!(
            s["subject"]["type"].as_str(),
            Some("link" | "attachment" | "address")
        )),
        "lldp saw no neighbour frame: {lldp:?}"
    );

    // DHCP snoop: a DISCOVER (or its reply) from the target is seen. A DISCOVER has no
    // yiaddr, so assert the run recorded at least one DHCP message in its probe count or a
    // note; an ACK in scope would also add an address sighting.
    let outcome = site.run(&["dhcp_snoop", "--dry-run", "--json"]);
    outcome.assert_code(0);
    let body = outcome.json();
    let probes = body["run"]["probes"].as_u64().unwrap_or(0);
    let notes = body["run"]["notes"].as_array().map_or(0, Vec::len);
    let saw = body["batch"]["sightings"].as_array().map_or(0, Vec::len);
    eprintln!("dhcp_snoop: {}", body["run"]);
    assert!(
        probes >= 1 || notes >= 1 || saw >= 1,
        "dhcp_snoop saw no DHCP frame: {}",
        body["run"]
    );
}
