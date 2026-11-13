//! Which relay agents the server trusts (`dhcp.settings.trusted_relays`), for which links,
//! and what it tells the operator about the relays it refused or that reached it before the
//! list existed.
//!
//! - **The rule.** Relay data is honored only from a trusted sender: `giaddr`, option 82
//!   (link selection, the server identifier override, circuit-id and remote-id for the
//!   classes), option 118 and a DHCPv6 RELAY-FORW. A sender is trusted when its address
//!   (the datagram's source) is in the relay prefix of an entry of the list. Unset, the list
//!   follows the security profile: every sender under Lab (the behavior before the list
//!   existed, said as the warning [`TRUST_ANY`]), none under Home, Standard and Hardened. A
//!   list that is set, even an empty one, applies under every profile.
//! - **The links.** Each entry names the links its relay may name
//!   ([`tenko_core::dhcp::TrustedRelay`]): relay data counts only for a scope that is one
//!   of them ([`RelayTrust::may_name`]), judged by the most specific entry that holds the
//!   relay's address. A forged source address of a trusted relay therefore reaches only the
//!   scopes that relay serves. Links that cover their whole address family (such as
//!   `0.0.0.0/0`) name every link: the meaning of an entry stored before entries had links,
//!   said as the warning [`ANY_LINK`].
//! - **What is refused.** A relayed request (a `giaddr`, or a RELAY-FORW) from an untrusted
//!   sender, or one whose relay data selects a scope outside the relay's links, is dropped
//!   (`tenko_dhcp_dropped_total{reason="untrusted_relay"}`); option 82 and option 118 of a
//!   request that is not relayed are not used to select a scope, a class or a server
//!   identifier (option 82 is still echoed, RFC 3046 section 2.2).
//! - **What the operator is told** ([`UNTRUSTED`], [`LINK_REFUSED`], [`ANY_LINK`],
//!   [`WRONG_NETWORK`]). [`RelayLog`] keeps the senders it refused ([`MAX_REFUSED`], the
//!   ones refused most often stay), with the relay address they named, the link a trusted
//!   relay named outside its links, and how often; in a room of the same size, the senders of
//!   requests that were not relayed and came from another network than the one they would
//!   be served on (`docs/dhcp.md` section 9.1), and the networks whose lease rows say that they came through a
//!   relay, with the relay addresses seen, so that an installation that relied on relays
//!   before the list existed sees them at the first start, before any client is refused.
//!   The list of seen relays trusts nothing: only the operator's list does.
//!
//! Nothing here allocates on the request path: the trust check walks the image's list,
//! and a refusal takes the log's lock only when it is free (a refusal that finds it taken
//! is counted, not logged); the log's room is made once, at its first entry.

use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use ipnet::IpNet;
use tenko_core::{PrefixId, Timestamp, dhcp::TrustedRelay};

/// The warning while no list is set under Lab and every sender is trusted as a relay.
pub const TRUST_ANY: &str = "dhcp.relay.trust_any";

/// The warning while relays reach the node that are not trusted, or lease rows say that a
/// network was served through a relay while no list is set.
pub const UNTRUSTED: &str = "dhcp.relay.untrusted";

/// The warning while trusted relays name links they are not bound to.
pub const LINK_REFUSED: &str = "dhcp.relay.link_refused";

/// The warning while the list holds relays that may name every link.
pub const ANY_LINK: &str = "dhcp.relay.any_link";

/// The warning while requests that were not relayed came from another network than the one
/// they would be served on (a client address, `ciaddr`, of another network, or a source
/// address outside the listener's network).
pub const WRONG_NETWORK: &str = "dhcp.client.wrong_network";

/// The refused senders the log keeps.
pub const MAX_REFUSED: usize = 32;

/// The relayed networks the log keeps.
pub const MAX_RELAYED: usize = 32;

/// The relay addresses kept per relayed network.
pub const MAX_RELAYS_PER_NETWORK: usize = 8;

/// One entry of the list: the relay prefix and the links it may name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Bound {
    relay: IpNet,
    links: Box<[IpNet]>,
    /// Whether the links cover the relay's whole address family.
    any_link: bool,
}

/// The trusted relays of a configuration image: the stored list, or none when it is unset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayTrust {
    list: Option<Box<[Bound]>>,
}

impl RelayTrust {
    /// The trust of a stored setting.
    pub fn new(list: Option<&[TrustedRelay]>) -> Self {
        Self {
            list: list.map(|list| {
                list.iter()
                    .map(|entry| Bound {
                        relay: entry.relay.trunc(),
                        links: entry.links.iter().map(IpNet::trunc).collect(),
                        any_link: entry.is_any_link(),
                    })
                    .collect()
            }),
        }
    }

    /// Whether a list is set.
    pub fn is_set(&self) -> bool {
        self.list.is_some()
    }

    /// The relay prefixes of the entries that may name every link of their family, except
    /// link-local prefixes shorter than `/128` ([`exempt_from_links`]).
    pub fn any_link(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.list
            .iter()
            .flatten()
            .filter(|entry| entry.any_link && !exempt_from_links(entry.relay))
            .map(|entry| entry.relay)
    }

    /// The most specific entry whose relay prefix holds `addr`.
    fn holder(&self, addr: IpAddr) -> Option<&Bound> {
        let addr = canonical(addr);
        self.list
            .iter()
            .flatten()
            .filter(|entry| entry.relay.contains(&addr))
            .max_by_key(|entry| entry.relay.prefix_len())
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
                .any(|entry| entry.relay.prefix_len() == 128 && entry.relay.contains(&sender)),
            (Some(_), _) => self.trusts(sender, any_when_unset),
        }
    }

    /// Whether `addr` is in the list; `any_when_unset` is what an unset list means (the
    /// profile: true under Lab).
    pub fn trusts(&self, sender: IpAddr, any_when_unset: bool) -> bool {
        match &self.list {
            None => any_when_unset,
            Some(_) => self.holder(sender).is_some(),
        }
    }

    /// Whether the relay at `relay` may name the scope of `network`: the most specific entry
    /// that holds the relay has a link that holds the network, or a link inside the network
    /// whose own scope is this one. `home` gives the network of the scope a link's first
    /// address selects (the most specific scope that holds it), so that a link given as the
    /// relay's `giaddr` names the scope around it but not a wider scope around that one.
    /// `any_when_unset` is what an unset list means. An address no entry holds may name
    /// nothing.
    pub fn may_name(
        &self,
        relay: IpAddr,
        network: IpNet,
        any_when_unset: bool,
        home: impl Fn(IpNet) -> Option<IpNet>,
    ) -> bool {
        match &self.list {
            None => any_when_unset,
            Some(_) => self.holder(relay).is_some_and(|entry| {
                entry.links.iter().any(|link| {
                    link.contains(&network)
                        || (network.contains(link) && home(*link) == Some(network))
                })
            }),
        }
    }
}

/// Whether an entry needs no links of its own to be safe: a link-local relay prefix shorter
/// than `/128` (such as `fe80::/10`) only ever trusts inner DHCPv6 relays below a trusted
/// relay (never a sender of its own, [`RelayTrust::trusts_sender`]), and the relay above
/// it must be bound to the client's link as well. Such an entry may name every link without
/// a warning and without the Hardened refusal.
pub fn exempt_from_links(relay: IpNet) -> bool {
    match relay {
        IpNet::V6(v6) => v6.addr().is_unicast_link_local() && v6.prefix_len() < 128,
        IpNet::V4(_) => false,
    }
}

/// An IPv4 address mapped into IPv6 as the IPv4 address.
fn canonical(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
        IpAddr::V4(_) => addr,
    }
}

/// A sender the server refused as a relay, or a client whose own address named another
/// network ([`RelayReport::wrong_network`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedRelay {
    /// The datagram's source: the address to trust (or, for an inner DHCPv6 relay, the
    /// peer address its enclosing relay recorded).
    pub source: IpAddr,
    /// The relay address the request named: `giaddr`, or the link address of the refused
    /// DHCPv6 relay; for a client, the `ciaddr` it named.
    pub relay: IpAddr,
    /// For a trusted relay refused because its data selected a scope outside its links,
    /// and for a client: that scope's network. None for a sender that is not trusted.
    pub link: Option<IpNet>,
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

/// A trusted relay that may name every link, and the networks the lease rows say it
/// served (a hint for the links to give it; empty when the rows say nothing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnyLinkRelay {
    /// The relay prefix of the entry.
    pub relay: IpNet,
    /// The networks whose lease rows name a relay address in the prefix.
    pub seen: Vec<IpNet>,
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
    /// The listed relays that may name every link.
    pub any_link: Vec<AnyLinkRelay>,
    /// Whether the profile is Hardened (which refuses such an entry when it is written).
    pub hardened: bool,
    /// The senders of requests that were not relayed and came from another network than
    /// the one they were served on, the most refused first: `relay` the address each named
    /// (unspecified when none), `link` the network.
    pub wrong_network: Vec<RefusedRelay>,
    /// Such refusals not kept in [`RelayReport::wrong_network`] (the room was full or busy).
    pub wrong_network_unlogged: u64,
}

impl RelayReport {
    /// Whether the warning [`UNTRUSTED`] is raised.
    pub fn untrusted(&self) -> bool {
        self.refused.iter().any(|refused| refused.link.is_none())
            || (!self.listed && !self.trust_any && !self.relayed.is_empty())
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
    /// [`TRUST_ANY`], [`UNTRUSTED`], [`LINK_REFUSED`], [`ANY_LINK`] or [`WRONG_NETWORK`].
    pub code: &'static str,
    /// What it means and what to do, in English.
    pub detail: String,
    /// `senders` (the refused senders, comma-separated), `refused` (refusals in all),
    /// `networks` (the relayed networks and their relays), `links` (the links refused),
    /// `relays` (the relays that may name every link).
    pub params: BTreeMap<String, String>,
}

/// The refused senders a health row names; the rest are counted.
const NAMED: usize = 5;

/// " and N more" for the entries a row does not name.
fn more(total: usize) -> String {
    match total.saturating_sub(NAMED) {
        0 => String::new(),
        more => format!(" and {more} more"),
    }
}

impl RelayReport {
    /// The health rows of the report.
    pub fn warnings(&self) -> Vec<RelayWarning> {
        let mut out = Vec::new();
        if self.trust_any {
            out.push(RelayWarning {
                code: TRUST_ANY,
                detail: "no trusted relays are set and the security profile is Lab, so every \
                         sender is trusted as a relay agent: any host that reaches this node \
                         can be served from any scope; list the relay agents and their links \
                         under the DHCP settings"
                    .to_owned(),
                params: BTreeMap::new(),
            });
        }
        if let Some(row) = self.any_link_warning() {
            out.push(row);
        }
        if let Some(row) = self.link_warning() {
            out.push(row);
        }
        if self.untrusted() {
            out.push(self.untrusted_warning());
        }
        if let Some(row) = self.wrong_network_warning() {
            out.push(row);
        }
        out
    }

    fn wrong_network_warning(&self) -> Option<RelayWarning> {
        let refused = &self.wrong_network;
        if refused.is_empty() {
            return None;
        }
        let named = refused
            .iter()
            .take(NAMED)
            .map(|refused| {
                let named = if refused.relay.is_unspecified() {
                    String::new()
                } else {
                    format!("address {} of ", refused.relay)
                };
                format!(
                    "{} ({named}{}, {} time(s))",
                    refused.source,
                    refused
                        .link
                        .map(|link| link.to_string())
                        .unwrap_or_default(),
                    refused.count
                )
            })
            .collect::<Vec<_>>();
        let mut params = BTreeMap::new();
        params.insert(
            "senders".to_owned(),
            refused
                .iter()
                .take(NAMED)
                .map(|refused| refused.source.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );
        params.insert(
            "refused".to_owned(),
            refused
                .iter()
                .map(|refused| refused.count)
                .sum::<u64>()
                .saturating_add(self.wrong_network_unlogged)
                .to_string(),
        );
        Some(RelayWarning {
            code: WRONG_NETWORK,
            detail: format!(
                "requests that were not relayed came from an address outside the network \
                 they would be served on, and were dropped: {}{}; a client sends from no \
                 address, a link-local address or its address on that network, so these came \
                 from a host on another network, which reaches the server through its relay \
                 agent instead, or from a host that is not that client",
                named.join(", "),
                more(refused.len()),
            ),
            params,
        })
    }

    fn any_link_warning(&self) -> Option<RelayWarning> {
        if self.any_link.is_empty() {
            return None;
        }
        let relays = self
            .any_link
            .iter()
            .take(NAMED)
            .map(|entry| {
                if entry.seen.is_empty() {
                    entry.relay.to_string()
                } else {
                    let seen = entry
                        .seen
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" and ");
                    format!("{} (lease rows show it on {seen})", entry.relay)
                }
            })
            .collect::<Vec<_>>();
        let hardened = if self.hardened {
            "; the Hardened profile refuses such an entry when it is written, and these were \
             stored before"
        } else {
            ""
        };
        let mut params = BTreeMap::new();
        params.insert(
            "relays".to_owned(),
            self.any_link
                .iter()
                .take(NAMED)
                .map(|entry| entry.relay.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );
        Some(RelayWarning {
            code: ANY_LINK,
            detail: format!(
                "trusted relays may name every link: {}{}, so relay data from such a relay's \
                 address counts for every scope; under the DHCP settings, give each relay the \
                 links it serves{hardened}",
                relays.join(", "),
                more(self.any_link.len()),
            ),
            params,
        })
    }

    fn link_warning(&self) -> Option<RelayWarning> {
        let refused = self
            .refused
            .iter()
            .filter(|refused| refused.link.is_some())
            .collect::<Vec<_>>();
        if refused.is_empty() {
            return None;
        }
        let named = refused
            .iter()
            .take(NAMED)
            .map(|refused| {
                format!(
                    "{} (link {}, {} time(s))",
                    refused.source,
                    refused
                        .link
                        .map(|link| link.to_string())
                        .unwrap_or_default(),
                    refused.count
                )
            })
            .collect::<Vec<_>>();
        let mut params = BTreeMap::new();
        params.insert(
            "senders".to_owned(),
            refused
                .iter()
                .take(NAMED)
                .map(|refused| refused.source.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );
        params.insert(
            "links".to_owned(),
            refused
                .iter()
                .take(NAMED)
                .filter_map(|refused| refused.link.map(|link| link.to_string()))
                .collect::<Vec<_>>()
                .join(", "),
        );
        params.insert(
            "refused".to_owned(),
            refused
                .iter()
                .map(|refused| refused.count)
                .sum::<u64>()
                .to_string(),
        );
        Some(RelayWarning {
            code: LINK_REFUSED,
            detail: format!(
                "trusted relays named links they are not bound to, and the requests were \
                 dropped: {}{}; if a relay serves that link, add the link to the relay under \
                 the DHCP settings; if it does not, the requests did not come from that relay",
                named.join(", "),
                more(refused.len()),
            ),
            params,
        })
    }

    fn untrusted_warning(&self) -> RelayWarning {
        let mut params = BTreeMap::new();
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
        let refused = self
            .refused
            .iter()
            .filter(|refused| refused.link.is_none())
            .collect::<Vec<_>>();
        let detail = if refused.is_empty() {
            params.insert("networks".to_owned(), networks.join(", "));
            format!(
                "lease rows show networks served through relay agents ({}), and no relay is \
                 trusted yet: add the addresses your relay agents send from, with the links \
                 they serve, to the trusted relays of the DHCP settings, or their clients get \
                 no new address",
                networks.join(", ")
            )
        } else {
            let total: u64 = refused
                .iter()
                .map(|refused| refused.count)
                .sum::<u64>()
                .saturating_add(self.unlogged);
            let senders = refused
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
            params.insert(
                "senders".to_owned(),
                refused
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
            format!(
                "requests from relay agents that are not trusted were dropped: {}{}; add the \
                 ones you run, with the links they serve, to the trusted relays of the DHCP \
                 settings",
                senders.join(", "),
                more(refused.len()),
            )
        };
        RelayWarning {
            code: UNTRUSTED,
            detail,
            params,
        }
    }
}

/// The refusals of one kind: at most [`MAX_REFUSED`] senders, the ones refused most often
/// staying, and a count of the refusals not kept.
#[derive(Debug, Default)]
struct Room {
    entries: Mutex<Vec<RefusedRelay>>,
    unlogged: AtomicU64,
}

impl Room {
    const fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            unlogged: AtomicU64::new(0),
        }
    }

    fn note(&self, source: IpAddr, relay: IpAddr, link: Option<IpNet>, now: Timestamp) {
        let source = canonical(source);
        let Ok(mut refused) = self.entries.try_lock() else {
            self.unlogged.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if let Some(entry) = refused
            .iter_mut()
            .find(|entry| entry.source == source && entry.link.is_some() == link.is_some())
        {
            entry.count = entry.count.saturating_add(1);
            entry.relay = relay;
            entry.link = link;
            entry.last = now;
            return;
        }
        let entry = RefusedRelay {
            source,
            relay,
            link,
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

    /// The entries, the most refused first, and the refusals not kept.
    fn entries(&self) -> (Vec<RefusedRelay>, u64) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        entries.sort_by(|a, b| b.count.cmp(&a.count).then(a.source.cmp(&b.source)));
        (entries, self.unlogged.load(Ordering::Relaxed))
    }
}

/// The refused senders and the relayed networks of one node.
#[derive(Debug, Default)]
pub struct RelayLog {
    /// Senders refused as relays.
    relays: Room,
    /// Senders of requests that were not relayed and came from another network than the
    /// one they were served on: a room of their own, so that they never push out a relay.
    clients: Room,
    relayed: Mutex<Vec<RelayedNetwork>>,
}

impl RelayLog {
    /// An empty log.
    pub const fn new() -> Self {
        Self {
            relays: Room::new(),
            clients: Room::new(),
            relayed: Mutex::new(Vec::new()),
        }
    }

    /// Notes a refusal of `source`, which named `relay`, as a relay that is not trusted.
    pub fn refuse(&self, source: IpAddr, relay: IpAddr, now: Timestamp) {
        self.relays.note(source, relay, None, now);
    }

    /// Notes a refusal of the trusted relay `source`, which named `relay` and selected a
    /// scope of `link`, outside its links.
    pub fn refuse_link(&self, source: IpAddr, relay: IpAddr, link: IpNet, now: Timestamp) {
        self.relays.note(source, relay, Some(link), now);
    }

    /// Notes a request from `source` that was not relayed and was refused for `network`,
    /// another network than the one it came from; `named` is the address it named there
    /// (`ciaddr` or the requested address), unspecified when it named none.
    pub fn refuse_client(&self, source: IpAddr, named: IpAddr, network: IpNet, now: Timestamp) {
        self.clients.note(source, named, Some(network), now);
    }

    /// Replaces the relayed networks (the role reads them from the lease rows at each
    /// install of its tables).
    pub fn set_relayed(&self, mut networks: Vec<RelayedNetwork>) {
        networks.truncate(MAX_RELAYED);
        *self.relayed.lock().unwrap_or_else(PoisonError::into_inner) = networks;
    }

    /// The report, given whether a list is set and what an unset one means.
    pub fn report(&self, listed: bool, trust_any: bool) -> RelayReport {
        let (refused, unlogged) = self.relays.entries();
        let (wrong_network, wrong_network_unlogged) = self.clients.entries();
        RelayReport {
            wrong_network,
            wrong_network_unlogged,
            refused,
            listed,
            trust_any,
            unlogged,
            relayed: if listed {
                Vec::new()
            } else {
                self.relayed
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone()
            },
            any_link: Vec::new(),
            hardened: false,
        }
    }

    /// The relays of `relays` (prefixes that may name every link), each with the networks
    /// whose lease rows name a relay address in it.
    pub fn any_link(&self, relays: impl Iterator<Item = IpNet>) -> Vec<AnyLinkRelay> {
        let relayed = self.relayed.lock().unwrap_or_else(PoisonError::into_inner);
        relays
            .map(|relay| AnyLinkRelay {
                relay,
                seen: relayed
                    .iter()
                    .filter(|network| {
                        network
                            .relays
                            .iter()
                            .any(|addr| relay.contains(&canonical(*addr)))
                    })
                    .map(|network| network.network)
                    .collect(),
            })
            .collect()
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

    fn net(text: &str) -> IpNet {
        text.parse().expect("a prefix")
    }

    fn entry(relay: &str, links: &[&str]) -> TrustedRelay {
        TrustedRelay {
            relay: net(relay),
            links: links.iter().map(|link| net(link)).collect(),
        }
    }

    /// The scope a link's first address selects among the scopes of these tests: the most
    /// specific of them that holds it.
    fn home(link: IpNet) -> Option<IpNet> {
        ["203.0.113.64/26", "10.0.0.0/8", "10.1.0.0/16"]
            .iter()
            .map(|scope| net(scope))
            .filter(|scope| scope.contains(&link))
            .max_by_key(IpNet::prefix_len)
    }

    fn any(list: &[&str]) -> Vec<TrustedRelay> {
        list.iter()
            .map(|relay| TrustedRelay::any_link(net(relay)))
            .collect()
    }

    #[test]
    fn an_unset_list_follows_the_profile_and_a_set_one_applies_everywhere() {
        let sender: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
        let unset = RelayTrust::new(None);
        assert!(unset.trusts(sender, true));
        assert!(!unset.trusts(sender, false));
        assert!(unset.may_name(sender, net("198.51.100.0/24"), true, home));
        assert!(!unset.may_name(sender, net("198.51.100.0/24"), false, home));
        let empty = RelayTrust::new(Some(&[]));
        assert!(!empty.trusts(sender, true));
        assert!(!empty.may_name(sender, net("198.51.100.0/24"), true, home));
        let listed = RelayTrust::new(Some(&any(&["192.0.2.0/30", "2001:db8::/64"])));
        assert!(listed.trusts(sender, false));
        assert!(!listed.trusts(Ipv4Addr::new(192, 0, 2, 4).into(), true));
        assert!(listed.trusts("2001:db8::7".parse::<Ipv6Addr>().expect("v6").into(), false));
        // An IPv4 sender seen on a dual-stack socket is the IPv4 address.
        assert!(listed.trusts(Ipv4Addr::new(192, 0, 2, 2).to_ipv6_mapped().into(), false));
    }

    #[test]
    fn a_relay_names_only_scopes_that_overlap_its_links() {
        let trust = RelayTrust::new(Some(&[
            entry("192.0.2.1/32", &["198.51.100.0/24", "203.0.113.65/32"]),
            entry("2001:db8::1/128", &["2001:db8:10::/48"]),
        ]));
        let v4: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
        let v6: IpAddr = "2001:db8::1".parse().expect("v6");
        // A scope inside a link, and a scope that holds a link given as a giaddr.
        assert!(trust.may_name(v4, net("198.51.100.0/24"), false, home));
        assert!(trust.may_name(v4, net("198.51.100.128/25"), false, home));
        assert!(trust.may_name(v4, net("203.0.113.64/26"), false, home));
        // Any other scope, and a scope of the other family, is not the relay's.
        assert!(!trust.may_name(v4, net("198.51.101.0/24"), false, home));
        assert!(!trust.may_name(v4, net("203.0.113.0/26"), false, home));
        assert!(!trust.may_name(v4, net("2001:db8:10::/64"), false, home));
        assert!(trust.may_name(v6, net("2001:db8:10:5::/64"), false, home));
        assert!(!trust.may_name(v6, net("2001:db8:11::/64"), false, home));
        // An address no entry holds names nothing, whatever the profile.
        assert!(!trust.may_name(
            Ipv4Addr::new(192, 0, 2, 2).into(),
            net("198.51.100.0/24"),
            true,
            home
        ));
        // An entry stored before entries had links names every link of its family.
        let old = RelayTrust::new(Some(&any(&["192.0.2.1/32"])));
        assert!(old.may_name(v4, net("198.51.101.0/24"), false, home));
        assert_eq!(old.any_link().collect::<Vec<_>>(), [net("192.0.2.1/32")]);
        assert_eq!(trust.any_link().count(), 0);
    }

    #[test]
    fn a_link_inside_a_scope_names_that_scope_and_not_a_wider_one_around_it() {
        // Scope 10.0.0.0/8 holds the more specific scope 10.1.0.0/16; the relay serves the
        // link of the /16, given as the /16 or as its giaddr.
        let relay: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
        for link in ["10.1.0.0/16", "10.1.0.1/32"] {
            let trust = RelayTrust::new(Some(&[entry("192.0.2.1/32", &[link])]));
            assert!(
                trust.may_name(relay, net("10.1.0.0/16"), false, home),
                "{link}"
            );
            assert!(
                !trust.may_name(relay, net("10.0.0.0/8"), false, home),
                "{link}"
            );
        }
        // A link of the /8 outside the /16 names the /8.
        let trust = RelayTrust::new(Some(&[entry("192.0.2.1/32", &["10.2.0.0/16"])]));
        assert!(trust.may_name(relay, net("10.0.0.0/8"), false, home));
        assert!(!trust.may_name(relay, net("10.1.0.0/16"), false, home));
    }

    #[test]
    fn the_most_specific_relay_prefix_decides() {
        // The routers of 192.0.2.0/24 serve the access networks; the one at 192.0.2.9 is
        // the lab's router and serves only the lab link, although the wider entry would
        // allow more.
        let trust = RelayTrust::new(Some(&[
            entry("192.0.2.0/24", &["198.51.100.0/24", "203.0.113.0/24"]),
            entry("192.0.2.9/32", &["203.0.113.128/25"]),
        ]));
        let router: IpAddr = Ipv4Addr::new(192, 0, 2, 5).into();
        let lab: IpAddr = Ipv4Addr::new(192, 0, 2, 9).into();
        assert!(trust.may_name(router, net("198.51.100.0/24"), false, home));
        assert!(trust.may_name(router, net("203.0.113.0/25"), false, home));
        assert!(trust.may_name(lab, net("203.0.113.128/25"), false, home));
        assert!(!trust.may_name(lab, net("198.51.100.0/24"), false, home));
        assert!(!trust.may_name(lab, net("203.0.113.0/25"), false, home));
        // The order of the list does not matter.
        let reversed = RelayTrust::new(Some(&[
            entry("192.0.2.9/32", &["203.0.113.128/25"]),
            entry("192.0.2.0/24", &["198.51.100.0/24", "203.0.113.0/24"]),
        ]));
        assert!(!reversed.may_name(lab, net("198.51.100.0/24"), false, home));
        assert!(reversed.may_name(router, net("198.51.100.0/24"), false, home));
    }

    #[test]
    fn a_link_local_prefix_for_lightweight_relays_is_no_any_link_finding() {
        let trust = RelayTrust::new(Some(&any(&["fe80::/10", "fe80::1/128", "2001:db8::1/128"])));
        assert_eq!(
            trust.any_link().collect::<Vec<_>>(),
            [net("fe80::1/128"), net("2001:db8::1/128")]
        );
        assert!(exempt_from_links(net("fe80::/10")));
        assert!(exempt_from_links(net("fe80::/64")));
        assert!(!exempt_from_links(net("fe80::1/128")));
        assert!(!exempt_from_links(net("2001:db8::/32")));
        assert!(!exempt_from_links(net("192.0.2.0/24")));
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
    fn client_refusals_have_a_room_and_a_row_of_their_own() {
        let log = RelayLog::default();
        let now = Timestamp::now();
        let relay: IpAddr = Ipv4Addr::new(198, 51, 100, 1).into();
        let known: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
        let ciaddr: IpAddr = Ipv4Addr::new(192, 0, 2, 140).into();
        for _ in 0..5 {
            log.refuse(known, relay, now);
        }
        for n in 0..100u8 {
            log.refuse_client(
                Ipv4Addr::new(203, 0, 113, n).into(),
                ciaddr,
                net("192.0.2.0/24"),
                now,
            );
        }
        let report = log.report(true, false);
        assert_eq!(report.refused.len(), 1, "the relay stays: {report:?}");
        assert_eq!(report.refused[0].count, 5);
        assert_eq!(report.unlogged, 0);
        assert_eq!(report.wrong_network.len(), MAX_REFUSED);
        assert_eq!(report.wrong_network_unlogged, 100 - MAX_REFUSED as u64);
        let rows = report.warnings();
        let codes: Vec<_> = rows.iter().map(|row| row.code).collect();
        assert_eq!(codes, [UNTRUSTED, WRONG_NETWORK]);
        assert!(!rows[1].detail.contains("  "), "{rows:?}");
        assert!(
            rows[1].detail.contains(" more;"),
            "the rest are counted: {rows:?}"
        );
        assert_eq!(rows[1].params["refused"], "100");
        // The same sender refused as a relay and as a client: two entries.
        log.refuse_client(known, ciaddr, net("192.0.2.0/24"), now);
        let report = log.report(true, false);
        assert_eq!(report.refused[0].source, known);
        assert!(
            report
                .wrong_network
                .iter()
                .any(|entry| entry.source == known)
        );
    }

    #[test]
    fn relayed_networks_show_until_a_list_is_set() {
        let log = RelayLog::default();
        let scope = PrefixId::generate();
        let mut collect = RelayedCollector::default();
        let giaddr: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
        for _ in 0..3 {
            collect.note(scope, net("192.0.2.0/24"), giaddr);
        }
        collect.note(scope, net("192.0.2.0/24"), Ipv4Addr::UNSPECIFIED.into());
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
        // Once the operator set a list, the networks are no longer shown, but they still
        // tell which links a relay that may name every link served.
        assert_eq!(log.report(true, false).relayed, Vec::new());
        assert_eq!(
            log.any_link([net("192.0.2.0/30"), net("10.0.0.0/8")].into_iter()),
            [
                AnyLinkRelay {
                    relay: net("192.0.2.0/30"),
                    seen: vec![net("192.0.2.0/24")],
                },
                AnyLinkRelay {
                    relay: net("10.0.0.0/8"),
                    seen: Vec::new(),
                },
            ]
        );
    }

    #[test]
    fn the_health_rows_name_the_networks_first_and_the_refused_senders_after() {
        let scope = PrefixId::generate();
        let giaddr: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
        let mut collect = RelayedCollector::default();
        collect.note(scope, net("192.0.2.0/24"), giaddr);
        let log = RelayLog::new();
        log.set_relayed(collect.finish());
        let rows = log.report(false, false).warnings();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].code, UNTRUSTED);
        assert!(
            rows[0].detail.contains("192.0.2.0/24 through 192.0.2.1"),
            "{rows:?}"
        );
        assert!(!rows[0].detail.contains("  "), "{rows:?}");
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
        assert!(!lab[0].detail.contains("  "), "{lab:?}");
        assert_eq!(RelayLog::new().report(true, false).warnings(), Vec::new());
    }

    #[test]
    fn a_link_refusal_is_its_own_row_and_says_what_to_do() {
        let log = RelayLog::new();
        let relay: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
        let giaddr: IpAddr = Ipv4Addr::new(198, 51, 101, 1).into();
        log.refuse_link(relay, giaddr, net("198.51.101.0/24"), Timestamp::now());
        log.refuse_link(relay, giaddr, net("198.51.101.0/24"), Timestamp::now());
        let report = log.report(true, false);
        assert!(!report.untrusted());
        assert_eq!(report.refused.len(), 1);
        assert_eq!(report.refused[0].link, Some(net("198.51.101.0/24")));
        assert_eq!(report.refused[0].count, 2);
        let rows = report.warnings();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].code, LINK_REFUSED);
        assert_eq!(rows[0].params["senders"], "192.0.2.1");
        assert_eq!(rows[0].params["links"], "198.51.101.0/24");
        assert_eq!(rows[0].params["refused"], "2");
        assert!(
            rows[0]
                .detail
                .contains("add the link to the relay under the DHCP settings"),
            "{rows:?}"
        );
        // The same sender refused as untrusted is a second entry with its own row.
        log.refuse(relay, giaddr, Timestamp::now());
        let codes: Vec<_> = log
            .report(true, false)
            .warnings()
            .into_iter()
            .map(|row| row.code)
            .collect();
        assert_eq!(codes, [LINK_REFUSED, UNTRUSTED]);
    }

    #[test]
    fn a_relay_with_every_link_is_a_finding_that_names_what_to_do() {
        let report = RelayReport {
            listed: true,
            any_link: vec![AnyLinkRelay {
                relay: net("192.0.2.1/32"),
                seen: vec![net("198.51.100.0/24")],
            }],
            ..RelayReport::default()
        };
        let rows = report.warnings();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].code, ANY_LINK);
        assert_eq!(rows[0].params["relays"], "192.0.2.1/32");
        assert!(
            rows[0]
                .detail
                .contains("192.0.2.1/32 (lease rows show it on 198.51.100.0/24)"),
            "{rows:?}"
        );
        assert!(
            rows[0]
                .detail
                .contains("give each relay the links it serves"),
            "{rows:?}"
        );
        assert!(!rows[0].detail.contains("Hardened"), "{rows:?}");
        let hardened = RelayReport {
            hardened: true,
            ..report
        };
        assert!(
            hardened.warnings()[0]
                .detail
                .contains("the Hardened profile refuses such an entry when it is written"),
        );
    }
}
