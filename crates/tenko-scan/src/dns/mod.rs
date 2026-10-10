//! DNS messages for mDNS, LLMNR and reverse DNS, over the `domain` crate (ADR 0009).
//!
//! The module has no sockets. [`message`] builds queries and parses responses with bounds for
//! untrusted input, [`mdns`] and [`llmnr`] turn a parsed response into [`NameFindings`]: what
//! the responder says about names, addresses, service ports and the operating system.
//!
//! | Module | Contents |
//! |---|---|
//! | [`message`] | queries, reverse names, response parsing, PTR lookups |
//! | [`mdns`] | multicast DNS (RFC 6762) and DNS-SD (RFC 6763) answers |
//! | [`llmnr`] | link-local multicast name resolution (RFC 4795) answers |

mod collect;
pub mod llmnr;
pub mod mdns;
pub mod message;

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

pub use message::{
    DnsError, QueryOptions, QueryType, Record, RecordData, Response, Section, build_query,
    parse_response, ptr_names, reverse_address, reverse_name,
};

/// What the answers of one responder say about the network.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameFindings {
    /// Addresses that answered or announced themselves, sorted.
    pub addresses: BTreeSet<IpAddr>,
    /// The host name of an address (`printer.local`, `host.example.net`), without a trailing
    /// dot, lower case.
    pub names: BTreeMap<IpAddr, String>,
    /// TCP ports an address announces through SRV records of `_<service>._tcp` services.
    pub services: BTreeMap<IpAddr, BTreeSet<u16>>,
    /// An operating system guess per address with a confidence in percent.
    pub os: BTreeMap<IpAddr, (String, u8)>,
}

impl NameFindings {
    /// Adds what `other` found. The first name and the first operating system guess of an
    /// address win; addresses and port sets unite.
    pub fn merge(&mut self, other: NameFindings) {
        self.addresses.extend(other.addresses);
        for (ip, name) in other.names {
            self.names.entry(ip).or_insert(name);
        }
        for (ip, ports) in other.services {
            self.services.entry(ip).or_default().extend(ports);
        }
        for (ip, guess) in other.os {
            self.os.entry(ip).or_insert(guess);
        }
    }

    /// True when nothing was found.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
            && self.names.is_empty()
            && self.services.is_empty()
            && self.os.is_empty()
    }
}
