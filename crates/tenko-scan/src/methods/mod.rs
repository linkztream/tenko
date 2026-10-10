//! The scan methods.
//!
//! | Module | Methods |
//! |---|---|
//! | [`neighbours`] | `arp`, `nd`: the neighbour tables of the probe host |
//! | [`icmp`] | `icmp`: echo requests through the operating system |
//! | [`tcp`] | `tcp_connect`: connect scan with a TLS hint |
//! | [`rdns`] | `reverse_dns`: PTR lookups of discovered addresses |
//! | [`names`] | `mdns`, `llmnr`: link-local name protocols |
//! | [`snmp`] | `snmp`: SNMPv3 polling of switches |
//! | [`raw`] | `arp_sweep`, `tcp_syn`, `os_fingerprint`, `lldp`: declared, not implemented |

pub mod icmp;
pub mod names;
pub mod neighbours;
pub mod raw;
pub mod rdns;
pub mod snmp;
pub mod tcp;
