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

/// The most addresses the answers of one listen window keep. Names, service port sets and
/// operating system guesses are kept only for these addresses, so no map of the window holds
/// more. A segment a probe covers (a /20 at most is enumerated, 4,096 addresses) fits.
pub const MAX_WINDOW_ADDRESSES: usize = 4096;

/// The most service ports a listen window keeps per address.
pub const MAX_WINDOW_PORTS: usize = collect::MAX_PORTS_PER_ADDRESS;

impl NameFindings {
    /// Adds what `other` found for the addresses `keep` accepts (the scope of the run). The
    /// first name and the first operating system guess of an address win; addresses and port
    /// sets unite. The window keeps at most [`MAX_WINDOW_ADDRESSES`] addresses and
    /// [`MAX_WINDOW_PORTS`] ports per address; returns how many entries (an address with what
    /// was said about it, or a port) were dropped because the window was full. Addresses that
    /// `keep` refuses are left out and not counted.
    pub fn merge(&mut self, other: NameFindings, keep: impl Fn(IpAddr) -> bool) -> usize {
        let mut dropped = 0;
        // The addresses of `other` the full window refused; each counts once.
        let mut refused = BTreeSet::new();
        let mut admit = |window: &mut BTreeSet<IpAddr>, ip: IpAddr| -> bool {
            if window.contains(&ip) {
                return true;
            }
            if !keep(ip) || refused.contains(&ip) {
                return false;
            }
            if window.len() >= MAX_WINDOW_ADDRESSES {
                refused.insert(ip);
                dropped += 1;
                return false;
            }
            window.insert(ip);
            true
        };
        for ip in other.addresses {
            admit(&mut self.addresses, ip);
        }
        for (ip, name) in other.names {
            if admit(&mut self.addresses, ip) {
                self.names.entry(ip).or_insert(name);
            }
        }
        let mut dropped_ports = 0;
        for (ip, ports) in other.services {
            if !admit(&mut self.addresses, ip) {
                continue;
            }
            let kept = self.services.entry(ip).or_default();
            for port in ports {
                if kept.len() < MAX_WINDOW_PORTS || kept.contains(&port) {
                    kept.insert(port);
                } else {
                    dropped_ports += 1;
                }
            }
        }
        for (ip, guess) in other.os {
            if admit(&mut self.addresses, ip) {
                self.os.entry(ip).or_insert(guess);
            }
        }
        dropped + dropped_ports
    }

    /// True when nothing was found.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
            && self.names.is_empty()
            && self.services.is_empty()
            && self.os.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    /// The `n`-th address of the documentation prefix `2001:db8::/32` (RFC 3849).
    fn nth(n: usize) -> IpAddr {
        let n = u128::try_from(n).expect("test index fits a u128");
        IpAddr::V6(Ipv6Addr::from(
            0x2001_0db8_0000_0000_0000_0000_0000_0000_u128 + n,
        ))
    }

    fn answer(ip: IpAddr) -> NameFindings {
        let mut found = NameFindings::default();
        found.addresses.insert(ip);
        found.names.insert(ip, format!("host-{ip}.local"));
        found.services.insert(ip, BTreeSet::from([22, 80]));
        found.os.insert(ip, ("Linux".to_owned(), 40));
        found
    }

    #[test]
    fn answers_below_the_cap_merge_unchanged() {
        let doc: IpAddr = "192.0.2.10".parse().expect("ip");
        let mut window = NameFindings::default();
        assert_eq!(window.merge(answer(doc), |_| true), 0);
        let mut later = answer(doc);
        later.names.insert(doc, "other.local".to_owned());
        later.services.insert(doc, BTreeSet::from([443]));
        assert_eq!(window.merge(later, |_| true), 0);
        assert_eq!(window.addresses, BTreeSet::from([doc]));
        assert_eq!(
            window.names[&doc], "host-192.0.2.10.local",
            "the first name wins"
        );
        assert_eq!(window.services[&doc], BTreeSet::from([22, 80, 443]));
        assert_eq!(window.os[&doc], ("Linux".to_owned(), 40));
    }

    #[test]
    fn the_window_keeps_at_most_the_cap_and_counts_the_rest() {
        let mut window = NameFindings::default();
        let mut dropped = 0;
        for n in 0..MAX_WINDOW_ADDRESSES + 10 {
            dropped += window.merge(answer(nth(n)), |_| true);
        }
        assert_eq!(dropped, 10, "one per refused address, not per map");
        assert_eq!(window.addresses.len(), MAX_WINDOW_ADDRESSES);
        assert_eq!(window.names.len(), MAX_WINDOW_ADDRESSES);
        assert_eq!(window.services.len(), MAX_WINDOW_ADDRESSES);
        assert_eq!(window.os.len(), MAX_WINDOW_ADDRESSES);
        assert!(!window.addresses.contains(&nth(MAX_WINDOW_ADDRESSES)));
        // An address already in the window still takes news when the window is full.
        let mut news = NameFindings::default();
        news.services.insert(nth(0), BTreeSet::from([8080]));
        assert_eq!(window.merge(news, |_| true), 0);
        assert!(window.services[&nth(0)].contains(&8080));
    }

    #[test]
    fn a_name_without_an_address_entry_cannot_pass_the_cap() {
        let mut window = NameFindings::default();
        for n in 0..MAX_WINDOW_ADDRESSES {
            window.merge(answer(nth(n)), |_| true);
        }
        let mut stray = NameFindings::default();
        let outside = nth(MAX_WINDOW_ADDRESSES + 1);
        stray.names.insert(outside, "stray.local".to_owned());
        stray.os.insert(outside, ("Linux".to_owned(), 40));
        assert_eq!(window.merge(stray, |_| true), 1);
        assert!(!window.names.contains_key(&outside));
        assert!(!window.os.contains_key(&outside));
    }

    #[test]
    fn the_ports_of_an_address_are_capped() {
        let ip: IpAddr = "192.0.2.11".parse().expect("ip");
        let mut window = NameFindings::default();
        let mut dropped = 0;
        for chunk in (1..=200u16).collect::<Vec<_>>().chunks(50) {
            let mut found = NameFindings::default();
            found.addresses.insert(ip);
            found.services.insert(ip, chunk.iter().copied().collect());
            dropped += window.merge(found, |_| true);
        }
        assert_eq!(window.services[&ip].len(), MAX_WINDOW_PORTS);
        assert_eq!(dropped, 200 - MAX_WINDOW_PORTS);
    }

    #[test]
    fn addresses_outside_the_scope_are_left_out_and_not_counted() {
        let inside: IpAddr = "192.0.2.12".parse().expect("ip");
        let outside: IpAddr = "198.51.100.12".parse().expect("ip");
        let mut found = answer(inside);
        found.merge(answer(outside), |_| true);
        let mut window = NameFindings::default();
        let in_scope = |ip: IpAddr| ip == inside;
        assert_eq!(window.merge(found, in_scope), 0);
        assert_eq!(window.addresses, BTreeSet::from([inside]));
        assert!(!window.names.contains_key(&outside));
        assert!(!window.services.contains_key(&outside));
        assert!(!window.os.contains_key(&outside));
    }
}
