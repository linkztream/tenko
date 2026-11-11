//! Which relay agents the server trusts (`dhcp.settings.trusted_relays`), and what it tells
//! the operator about the relays it refused or that reached it before the list existed.
//!
//! - **The rule.** Relay data is honored only from a trusted sender: `giaddr`, option 82
//!   (link selection, the server identifier override, circuit-id and remote-id for the
//!   classes), option 118 and a DHCPv6 RELAY-FORW. A sender is trusted when its address
//!   (the datagram's source) is in a prefix of the list. Unset, the list follows the
//!   security profile: every sender under Lab (the behavior before the list existed, said
//!   as the warning [`TRUST_ANY`]), none under Home, Standard and Hardened. A list that is
//!   set, even an empty one, applies under every profile.
//! - **What is refused.** A relayed request (a `giaddr`, or a RELAY-FORW) from an untrusted
//!   sender is dropped (`tenko_dhcp_dropped_total{reason="untrusted_relay"}`); option 82 and
//!   option 118 of a request that is not relayed are not used to select a scope, a class or
//!   a server identifier (option 82 is still echoed, RFC 3046 section 2.2).
//! - **What the operator is told** ([`UNTRUSTED`]). [`RelayLog`] keeps the senders it
//!   refused ([`MAX_REFUSED`], the ones refused most often stay), with the relay address
//!   they named and how often, and the networks whose lease rows say that they came through
//!   a relay, with the relay addresses seen, so that an installation that relied on relays
//!   before the list existed sees them at the first start, before any client is refused.
//!   The list of seen relays trusts nothing: only the operator's list does.
//!
//! Nothing here allocates on the request path: the trust check walks the image's list,
//! and a refusal takes the log's lock only when it is free (a refusal that finds it taken
//! is counted, not logged); the log's room is made once, at its first entry.

use std::{
    net::IpAddr,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use ipnet::IpNet;
use tenko_core::{PrefixId, Timestamp};

/// The warning while no list is set under Lab and every sender is trusted as a relay.
pub const TRUST_ANY: &str = "dhcp.relay.trust_any";

/// The warning while relays reach the node that are not trusted, or lease rows say that a
/// network was served through a relay while no list is set.
pub const UNTRUSTED: &str = "dhcp.relay.untrusted";

/// The refused senders the log keeps.
pub const MAX_REFUSED: usize = 32;

/// The relayed networks the log keeps.
pub const MAX_RELAYED: usize = 32;

/// The relay addresses kept per relayed network.
pub const MAX_RELAYS_PER_NETWORK: usize = 8;

/// The trusted relays of a configuration image: the stored list, or none when it is unset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayTrust {
    list: Option<Box<[IpNet]>>,
}

impl RelayTrust {
    /// The trust of a stored setting.
    pub fn new(list: Option<&[IpNet]>) -> Self {
        Self {
            list: list.map(|list| list.iter().map(IpNet::trunc).collect()),
        }
    }

    /// Whether a list is set.
    pub fn is_set(&self) -> bool {
        self.list.is_some()
    }

    /// The list, when set.
    pub fn list(&self) -> Option<&[IpNet]> {
        self.list.as_deref()
    }

    /// Whether the sender of a datagram is a trusted relay: as [`RelayTrust::trusts`], except
    /// that an IPv6 link-local sender needs an entry of its own address (`/128`): `fe80::/10`
    /// in the list trusts the lightweight relays below a trusted relay, never a link-local
    /// sender as a relay of its own.
    pub fn trusts_sender(&self, sender: IpAddr, any_when_unset: bool) -> bool {
        let sender = canonical(sender);
        match (&self.list, sender) {
            (None, _) => any_when_unset,
            (Some(list), IpAddr::V6(v6)) if v6.is_unicast_link_local() => list
                .iter()
                .any(|prefix| prefix.prefix_len() == 128 && prefix.contains(&sender)),
            (Some(_), _) => self.trusts(sender, any_when_unset),
        }
    }

    /// Whether `addr` is in the list; `any_when_unset` is what an unset list means (the
    /// profile: true under Lab).
    pub fn trusts(&self, sender: IpAddr, any_when_unset: bool) -> bool {
        let sender = canonical(sender);
        match &self.list {
            None => any_when_unset,
            Some(list) => list.iter().any(|prefix| prefix.contains(&sender)),
        }
    }
}

/// An IPv4 address mapped into IPv6 as the IPv4 address.
fn canonical(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
        IpAddr::V4(_) => addr,
    }
}

/// A sender the server refused as a relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedRelay {
    /// The datagram's source: the address to trust.
    pub source: IpAddr,
    /// The relay address the request named: `giaddr`, or the link address of the outermost
    /// RELAY-FORW.
    pub relay: IpAddr,
    /// Refusals since the first.
    pub count: u64,
    /// The first refusal.
    pub first: Timestamp,
    /// The last refusal.
    pub last: Timestamp,
}

/// A network that lease rows say was served through a relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayedNetwork {
    /// The scope.
    pub scope: PrefixId,
    /// Its network.
    pub network: IpNet,
    /// The relay addresses the rows name (`giaddr`, or the DHCPv6 link address), at most
    /// [`MAX_RELAYS_PER_NETWORK`].
    pub relays: Vec<IpAddr>,
}

/// What the node reports about relays.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayReport {
    /// Whether a list is set.
    pub listed: bool,
    /// Whether every sender is trusted (no list, under Lab).
    pub trust_any: bool,
    /// The senders refused since the start, the most refused first.
    pub refused: Vec<RefusedRelay>,
    /// Refusals not kept in [`RelayReport::refused`] (the log was full or busy).
    pub unlogged: u64,
    /// The networks served through a relay according to the lease rows, while no list is
    /// set.
    pub relayed: Vec<RelayedNetwork>,
}

impl RelayReport {
    /// Whether the warning [`UNTRUSTED`] is raised.
    pub fn untrusted(&self) -> bool {
        !self.refused.is_empty() || (!self.listed && !self.trust_any && !self.relayed.is_empty())
    }

    /// Whether a refused sender's address is a relay address of the lease rows: the relay
    /// the operator knows, sending from the address it puts in `giaddr`.
    pub fn seen_before(&self, refused: &RefusedRelay) -> bool {
        self.relayed
            .iter()
            .any(|network| network.relays.contains(&refused.source))
    }
}

/// A health row of the report: its code, the English text and its parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayWarning {
    /// [`TRUST_ANY`] or [`UNTRUSTED`].
    pub code: &'static str,
    /// What it means and what to do, in English.
    pub detail: String,
    /// `senders` (the refused senders, comma-separated), `refused` (refusals in all),
    /// `networks` (the relayed networks and their relays).
    pub params: std::collections::BTreeMap<String, String>,
}

/// The refused senders a health row names; the rest are counted.
const NAMED: usize = 5;

impl RelayReport {
    /// The health rows of the report.
    pub fn warnings(&self) -> Vec<RelayWarning> {
        let mut out = Vec::new();
        if self.trust_any {
            out.push(RelayWarning {
                code: TRUST_ANY,
                detail: "no trusted relays are set and the security profile is Lab, so every                          sender is trusted as a relay agent: any host that reaches this node                          can be served from any scope; list the relay agents under the DHCP                          settings"
                    .to_owned(),
                params: std::collections::BTreeMap::new(),
            });
        }
        if !self.untrusted() {
            return out;
        }
        let mut params = std::collections::BTreeMap::new();
        let networks = self
            .relayed
            .iter()
            .map(|network| {
                let relays = network
                    .relays
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" and ");
                format!("{} through {relays}", network.network)
            })
            .collect::<Vec<_>>();
        let detail = if self.refused.is_empty() {
            params.insert("networks".to_owned(), networks.join(", "));
            format!(
                "lease rows show networks served through relay agents ({}), and no relay is                  trusted yet: add the addresses your relay agents send from to the trusted                  relays of the DHCP settings, or their clients get no new address",
                networks.join(", ")
            )
        } else {
            let total: u64 = self
                .refused
                .iter()
                .map(|refused| refused.count)
                .sum::<u64>()
                .saturating_add(self.unlogged);
            let senders = self
                .refused
                .iter()
                .take(NAMED)
                .map(|refused| {
                    let known = if self.seen_before(refused) {
                        ", a relay of the lease rows"
                    } else {
                        ""
                    };
                    format!(
                        "{} (relay address {}, {} time(s){known})",
                        refused.source, refused.relay, refused.count
                    )
                })
                .collect::<Vec<_>>();
            let more = self.refused.len().saturating_sub(NAMED);
            params.insert(
                "senders".to_owned(),
                self.refused
                    .iter()
                    .take(NAMED)
                    .map(|refused| refused.source.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            params.insert("refused".to_owned(), total.to_string());
            if !networks.is_empty() {
                params.insert("networks".to_owned(), networks.join(", "));
            }
            let more = if more > 0 {
                format!(" and {more} more")
            } else {
                String::new()
            };
            format!(
                "requests from relay agents that are not trusted were dropped: {}{more}; add                  the ones you run to the trusted relays of the DHCP settings",
                senders.join(", ")
            )
        };
        out.push(RelayWarning {
            code: UNTRUSTED,
            detail,
            params,
        });
        out
    }
}

/// The refused senders and the relayed networks of one node.
#[derive(Debug, Default)]
pub struct RelayLog {
    refused: Mutex<Vec<RefusedRelay>>,
    unlogged: AtomicU64,
    relayed: Mutex<Vec<RelayedNetwork>>,
}

impl RelayLog {
    /// An empty log.
    pub const fn new() -> Self {
        Self {
            refused: Mutex::new(Vec::new()),
            unlogged: AtomicU64::new(0),
            relayed: Mutex::new(Vec::new()),
        }
    }

    /// Notes a refusal of `source`, which named `relay`.
    pub fn refuse(&self, source: IpAddr, relay: IpAddr, now: Timestamp) {
        let source = canonical(source);
        let Ok(mut refused) = self.refused.try_lock() else {
            self.unlogged.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if let Some(entry) = refused.iter_mut().find(|entry| entry.source == source) {
            entry.count = entry.count.saturating_add(1);
            entry.relay = relay;
            entry.last = now;
            return;
        }
        let entry = RefusedRelay {
            source,
            relay,
            count: 1,
            first: now,
            last: now,
        };
        if refused.len() < MAX_REFUSED {
            if refused.capacity() == 0 {
                refused.reserve_exact(MAX_REFUSED);
            }
            refused.push(entry);
            return;
        }
        // Full: a sender not refused for an hour gives way first, then the one refused
        // least often, so that neither a spray of one-off sources nor a few senders refused
        // twice long ago keep out a relay that is refused now.
        self.unlogged.fetch_add(1, Ordering::Relaxed);
        let stale = |entry: &RefusedRelay| {
            now.saturating_since(entry.last) >= std::time::Duration::from_secs(3_600)
        };
        if let Some(weakest) = refused
            .iter_mut()
            .min_by_key(|entry| (!stale(entry), entry.count, entry.last))
            && (stale(weakest) || weakest.count == 1)
        {
            *weakest = entry;
        }
    }

    /// Replaces the relayed networks (the role reads them from the lease rows at each
    /// install of its tables).
    pub fn set_relayed(&self, mut networks: Vec<RelayedNetwork>) {
        networks.truncate(MAX_RELAYED);
        *self.relayed.lock().unwrap_or_else(PoisonError::into_inner) = networks;
    }

    /// The report, given whether a list is set and what an unset one means.
    pub fn report(&self, listed: bool, trust_any: bool) -> RelayReport {
        let mut refused = self
            .refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        refused.sort_by(|a, b| b.count.cmp(&a.count).then(a.source.cmp(&b.source)));
        RelayReport {
            listed,
            trust_any,
            refused,
            unlogged: self.unlogged.load(Ordering::Relaxed),
            relayed: if listed {
                Vec::new()
            } else {
                self.relayed
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone()
            },
        }
    }
}

/// Collects relayed networks: one entry per scope, its relay addresses in the order seen.
#[derive(Debug, Default)]
pub struct RelayedCollector {
    networks: Vec<RelayedNetwork>,
}

impl RelayedCollector {
    /// Notes that a row of `scope` (on `network`) came through `relay`.
    pub fn note(&mut self, scope: PrefixId, network: IpNet, relay: IpAddr) {
        if relay.is_unspecified() {
            return;
        }
        if let Some(entry) = self.networks.iter_mut().find(|entry| entry.scope == scope) {
            if !entry.relays.contains(&relay) && entry.relays.len() < MAX_RELAYS_PER_NETWORK {
                entry.relays.push(relay);
            }
            return;
        }
        if self.networks.len() < MAX_RELAYED {
            self.networks.push(RelayedNetwork {
                scope,
                network,
                relays: vec![relay],
            });
        }
    }

    /// The networks, by network.
    pub fn finish(mut self) -> Vec<RelayedNetwork> {
        self.networks.sort_by_key(|entry| entry.network);
        self.networks
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn prefixes(list: &[&str]) -> Vec<IpNet> {
        list.iter()
            .map(|text| text.parse().expect("a prefix"))
            .collect()
    }

    #[test]
    fn an_unset_list_follows_the_profile_and_a_set_one_applies_everywhere() {
        let sender: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
        let unset = RelayTrust::new(None);
        assert!(unset.trusts(sender, true));
        assert!(!unset.trusts(sender, false));
        let empty = RelayTrust::new(Some(&[]));
        assert!(!empty.trusts(sender, true));
        let listed = RelayTrust::new(Some(&prefixes(&["192.0.2.0/30", "2001:db8::/64"])));
        assert!(listed.trusts(sender, false));
        assert!(!listed.trusts(Ipv4Addr::new(192, 0, 2, 4).into(), true));
        assert!(listed.trusts("2001:db8::7".parse::<Ipv6Addr>().expect("v6").into(), false));
        // An IPv4 sender seen on a dual-stack socket is the IPv4 address.
        assert!(listed.trusts(Ipv4Addr::new(192, 0, 2, 2).to_ipv6_mapped().into(), false));
    }

    #[test]
    fn the_log_keeps_the_relays_that_come_back() {
        let log = RelayLog::default();
        let now = Timestamp::now();
        let relay: IpAddr = Ipv4Addr::new(198, 51, 100, 1).into();
        let known: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
        for _ in 0..5 {
            log.refuse(known, relay, now);
        }
        for n in 0..100u8 {
            log.refuse(Ipv4Addr::new(203, 0, 113, n).into(), relay, now);
        }
        let report = log.report(false, false);
        assert_eq!(report.refused.len(), MAX_REFUSED);
        assert_eq!(report.refused[0].source, known);
        assert_eq!(report.refused[0].count, 5);
        assert!(report.unlogged >= 100 - (MAX_REFUSED as u64 - 1));
        assert!(report.untrusted());
    }

    #[test]
    fn relayed_networks_show_until_a_list_is_set() {
        let log = RelayLog::default();
        let scope = PrefixId::generate();
        let mut collect = RelayedCollector::default();
        let giaddr: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
        for _ in 0..3 {
            collect.note(scope, "192.0.2.0/24".parse().expect("net"), giaddr);
        }
        collect.note(
            scope,
            "192.0.2.0/24".parse().expect("net"),
            Ipv4Addr::UNSPECIFIED.into(),
        );
        log.set_relayed(collect.finish());
        let report = log.report(false, false);
        assert_eq!(report.relayed.len(), 1);
        assert_eq!(report.relayed[0].relays, [giaddr]);
        assert!(report.untrusted());
        log.refuse(giaddr, giaddr, Timestamp::now());
        let report = log.report(false, false);
        assert!(report.seen_before(&report.refused[0]));
        // Lab without a list trusts everyone: the networks are no warning.
        let lab = RelayLog::default();
        lab.set_relayed(report.relayed.clone());
        assert!(!lab.report(false, true).untrusted());
        // Once the operator set a list, the networks are no longer shown.
        assert_eq!(log.report(true, false).relayed, Vec::new());
    }

    #[test]
    fn the_health_rows_name_the_networks_first_and_the_refused_senders_after() {
        let scope = PrefixId::generate();
        let giaddr: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
        let mut collect = RelayedCollector::default();
        collect.note(scope, "192.0.2.0/24".parse().expect("net"), giaddr);
        let log = RelayLog::new();
        log.set_relayed(collect.finish());
        let rows = log.report(false, false).warnings();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].code, UNTRUSTED);
        assert!(
            rows[0].detail.contains("192.0.2.0/24 through 192.0.2.1"),
            "{rows:?}"
        );
        log.refuse(giaddr, giaddr, Timestamp::now());
        let rows = log.report(false, false).warnings();
        assert!(
            rows[0].detail.contains("a relay of the lease rows"),
            "{rows:?}"
        );
        assert_eq!(rows[0].params["senders"], "192.0.2.1");
        assert_eq!(rows[0].params["refused"], "1");
        let lab = RelayLog::new().report(false, true).warnings();
        assert_eq!(lab.len(), 1);
        assert_eq!(lab[0].code, TRUST_ANY);
        assert_eq!(RelayLog::new().report(true, false).warnings(), Vec::new());
    }
}
