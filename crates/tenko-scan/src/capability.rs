//! What the probe host allows: raw sockets for the methods that need them, and how ICMP
//! echo can be sent without them.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::sys::System;

/// How the probe sends ICMP echo requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IcmpSupport {
    /// Unprivileged ICMP datagram sockets (Linux, `net.ipv4.ping_group_range`).
    DatagramSocket,
    /// The operating system's `ping` command (Windows; Linux without datagram sockets).
    PingCommand,
    /// Neither.
    Unavailable,
}

/// The capabilities of the probe host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Whether raw sockets are available: `CAP_NET_RAW` on Linux, Npcap on Windows.
    pub raw_sockets: bool,
    /// Why, in words.
    pub raw_detail: String,
    /// How ICMP echo is sent.
    pub icmp: IcmpSupport,
}

/// The ping command of the platform.
pub fn ping_program() -> &'static str {
    if cfg!(windows) { "ping.exe" } else { "ping" }
}

impl Capabilities {
    /// Detects the capabilities of this host.
    pub fn detect(system: &dyn System) -> Self {
        let (raw_sockets, raw_detail) = raw_sockets(system);
        let icmp = if datagram_icmp() {
            IcmpSupport::DatagramSocket
        } else if ping_command(system) {
            IcmpSupport::PingCommand
        } else {
            IcmpSupport::Unavailable
        };
        Self {
            raw_sockets,
            raw_detail,
            icmp,
        }
    }
}

/// Bit 13 of the effective capability set is `CAP_NET_RAW`.
const CAP_NET_RAW: u32 = 13;

/// Whether `CapEff` in the text of `/proc/self/status` holds `CAP_NET_RAW`.
pub fn status_has_net_raw(status: &str) -> Option<bool> {
    let line = status.lines().find(|line| line.starts_with("CapEff:"))?;
    let hex = line.trim_start_matches("CapEff:").trim();
    let mask = u64::from_str_radix(hex, 16).ok()?;
    Some(mask & (1 << CAP_NET_RAW) != 0)
}

fn raw_sockets(system: &dyn System) -> (bool, String) {
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot").map_or_else(
            || Path::new("C:\\Windows").to_path_buf(),
            std::path::PathBuf::from,
        );
        let npcap = root.join("System32").join("Npcap").join("wpcap.dll");
        if system.exists(&npcap) {
            (true, format!("Npcap found ({})", npcap.display()))
        } else {
            (
                false,
                "Npcap is not installed; the raw-socket methods need it on Windows".to_owned(),
            )
        }
    } else {
        match system
            .read(Path::new("/proc/self/status"))
            .ok()
            .as_deref()
            .and_then(status_has_net_raw)
        {
            Some(true) => (true, "CAP_NET_RAW is in the effective set".to_owned()),
            Some(false) => (
                false,
                "CAP_NET_RAW is missing; grant it with AmbientCapabilities=CAP_NET_RAW or \
                 setcap cap_net_raw+ep"
                    .to_owned(),
            ),
            None => (
                false,
                "the capabilities of the process are unknown".to_owned(),
            ),
        }
    }
}

/// Whether this process may open an unprivileged ICMP datagram socket (Linux).
fn datagram_icmp() -> bool {
    #[cfg(target_os = "linux")]
    {
        socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::ICMPV4),
        )
        .is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn ping_command(system: &dyn System) -> bool {
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot").map_or_else(
            || Path::new("C:\\Windows").to_path_buf(),
            std::path::PathBuf::from,
        );
        system.exists(&root.join("System32").join("PING.EXE"))
    } else {
        ["/usr/bin/ping", "/bin/ping", "/usr/sbin/ping", "/sbin/ping"]
            .iter()
            .any(|path| system.exists(Path::new(path)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_net_raw_is_read_from_the_effective_set() {
        let root = "Name:\ttenko\nCapInh:\t0000000000000000\nCapEff:\t000001ffffffffff\n";
        assert_eq!(status_has_net_raw(root), Some(true));
        let user = "CapEff:\t0000000000000000\n";
        assert_eq!(status_has_net_raw(user), Some(false));
        let only_raw = "CapEff:\t0000000000002000\n";
        assert_eq!(status_has_net_raw(only_raw), Some(true));
        assert_eq!(status_has_net_raw("Name:\ttenko\n"), None);
        assert_eq!(status_has_net_raw("CapEff:\tnot-hex\n"), None);
    }
}
