//! The router advertisement check of DHCP-10 (WP9.2): the M and O flags the routers send
//! on the links this node sits on, against the DHCPv6 scopes the role serves there.
//!
//! IPv6 hosts learn from router advertisements (RFC 4861 section 4.2) whether to ask
//! DHCPv6 at all: M (managed address configuration) for addresses, O (other
//! configuration) for the other options only (RFC 4862 section 5.5.3, RFC 8415 section 1).
//! A DHCPv6 scope on a link whose routers set neither serves nobody, and a router that sets
//! M on a link without a scope sends its hosts to a server that does not answer. DHCPv6
//! never sets a default route: the default route stays with the advertisements' router
//! lifetime, so a host needs the advertisements even when DHCPv6 gives its address.
//!
//! - **What runs.** [`run`], started by the role when a `probe` role runs in the process
//!   (as conflict detection borrows the probe's methods, `docs/dhcp.md` section 14.4): a
//!   raw `ICMPv6` socket of `tenko_scan::ra` hears every advertisement the host receives,
//!   and a Router Solicitation on every IPv6 link at the start and every
//!   [`SOLICIT_EVERY`] asks the routers to answer now. The socket needs `CAP_NET_RAW`,
//!   which `deploy/systemd/probe.conf` grants with the probe role; without it the check
//!   is [`RaCheck::Unavailable`], said once in the log and as the health row
//!   [`UNCHECKED`] while DHCPv6 scopes exist. No other capability is used.
//! - **What it keeps.** [`RaWatch`]: per link and router the flags, the router lifetime,
//!   the prefixes of the prefix information options and the link's own IPv6 networks, at
//!   most [`MAX_ROUTERS`] routers per link and [`MAX_HEARD`] in all (a host on the link
//!   that sends advertisements from many addresses cannot grow it), each forgotten
//!   [`STALE`] after it was last heard (RFC 4861 allows at most 1,800 seconds between
//!   unsolicited advertisements).
//! - **What it finds.** [`evaluate`]: a link's flags are those of any of its routers (a
//!   host acts on the flags of every advertisement it accepts); its scopes are the enabled
//!   DHCPv6 scopes whose network overlaps a prefix the routers advertise or a network of
//!   the node's own addresses on the link. The findings are [`FLAGS_OFF`] (scopes, and
//!   neither M nor O), [`OTHER_ONLY`] (scopes with address pools, and O without M) and
//!   [`MANAGED_WITHOUT_SCOPE`] (M, and no scope). The health view shows them as the role's
//!   rows (`GET /system/status`).
//!
//! The check sees only the links this node is on: a relayed link's advertisements reach a
//! probe on that link, which in this phase is a probe in the same process as the `dhcp`
//! role.

use std::{
    collections::BTreeMap,
    net::Ipv6Addr,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use ipnet::Ipv6Net;
use tenko_core::Timestamp;
use tokio_util::sync::CancellationToken;

use crate::v6::image::Image6;

/// The health row of a link with DHCPv6 scopes whose advertisements set neither M nor O.
pub const FLAGS_OFF: &str = "dhcp.ra.flags_off";
/// The health row of a link whose advertisements set O but not M while its scopes have
/// address pools.
pub const OTHER_ONLY: &str = "dhcp.ra.other_only";
/// The health row of a link whose advertisements set M while no DHCPv6 scope covers it.
pub const MANAGED_WITHOUT_SCOPE: &str = "dhcp.ra.managed_without_scope";
/// The health row of a check that cannot run (no raw `ICMPv6` socket) while DHCPv6 scopes
/// exist.
pub const UNCHECKED: &str = "dhcp.ra.unchecked";

/// How long a router's advertisement counts after it was heard.
pub const STALE: Duration = Duration::from_secs(3_600);
/// How often the links are asked again with a Router Solicitation.
pub const SOLICIT_EVERY: Duration = Duration::from_secs(600);
/// The most routers kept per link.
pub const MAX_ROUTERS: usize = 16;
/// The most routers kept in all.
pub const MAX_HEARD: usize = 1_024;

/// Whether the check runs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RaCheck {
    /// No `probe` role runs in the process.
    #[default]
    Off,
    /// The socket could not be opened; why.
    Unavailable(String),
    /// The socket hears the links.
    Watching,
}

impl RaCheck {
    /// The state as a word: `off`, `unavailable` or `watching`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Unavailable(_) => "unavailable",
            Self::Watching => "watching",
        }
    }
}

/// One router's last advertisement on one link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaHeard {
    /// The interface index.
    pub interface: u32,
    /// The interface name.
    pub name: String,
    /// The router's link-local address.
    pub router: Ipv6Addr,
    /// The M flag.
    pub managed: bool,
    /// The O flag.
    pub other: bool,
    /// The router lifetime in seconds (0: not a default router).
    pub router_lifetime: u16,
    /// The prefixes of its prefix information options.
    pub prefixes: Vec<Ipv6Net>,
    /// The node's own IPv6 networks on the link.
    pub networks: Vec<Ipv6Net>,
    /// When it was heard.
    pub at: Timestamp,
}

/// One link as the report shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaLinkReport {
    /// The interface name.
    pub interface: String,
    /// The routers heard, by link-local address.
    pub routers: Vec<Ipv6Addr>,
    /// Whether a router sets M.
    pub managed: bool,
    /// Whether a router sets O.
    pub other: bool,
    /// The prefixes the routers advertise.
    pub prefixes: Vec<Ipv6Net>,
    /// The networks of the enabled DHCPv6 scopes of the link.
    pub scopes: Vec<Ipv6Net>,
    /// When the last advertisement was heard.
    pub seen: Timestamp,
}

/// One finding of the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaFinding {
    /// The health row's code.
    pub code: &'static str,
    /// The interface name.
    pub interface: String,
    /// What it means and what to do, in English.
    pub detail: String,
    /// The parameters: `interface`, `routers`, and `scopes` or `prefixes`.
    pub params: BTreeMap<String, String>,
}

/// The check's part of the role's report.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RaReport {
    /// Whether it runs.
    pub check: RaCheck,
    /// The links heard.
    pub links: Vec<RaLinkReport>,
    /// The findings.
    pub findings: Vec<RaFinding>,
}

#[derive(Debug, Default)]
struct State {
    check: RaCheck,
    heard: BTreeMap<(u32, Ipv6Addr), RaHeard>,
}

/// What the check heard, shared by its task and the role's report.
#[derive(Debug, Default)]
pub struct RaWatch {
    state: Mutex<State>,
}

impl RaWatch {
    /// An empty watch, off.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sets whether the check runs.
    pub fn set_check(&self, check: RaCheck) {
        self.state().check = check;
    }

    /// Whether the check runs.
    pub fn check(&self) -> RaCheck {
        self.state().check.clone()
    }

    /// Records an advertisement, replacing the router's last one on the link; the oldest
    /// router of the link, else of all links, makes room past the limits.
    pub fn record(&self, heard: RaHeard) {
        let mut state = self.state();
        let key = (heard.interface, heard.router);
        if !state.heard.contains_key(&key) {
            let on_link: Vec<_> = state
                .heard
                .iter()
                .filter(|((interface, _), _)| *interface == heard.interface)
                .map(|(key, held)| (held.at, *key))
                .collect();
            let oldest = if on_link.len() >= MAX_ROUTERS {
                on_link.iter().min().map(|(_, key)| *key)
            } else if state.heard.len() >= MAX_HEARD {
                state
                    .heard
                    .iter()
                    .map(|(key, held)| (held.at, *key))
                    .min()
                    .map(|(_, key)| key)
            } else {
                None
            };
            if let Some(oldest) = oldest {
                state.heard.remove(&oldest);
            }
        }
        state.heard.insert(key, heard);
    }

    /// The advertisements heard within [`STALE`] of `now`; older ones are forgotten.
    pub fn heard(&self, now: Timestamp) -> Vec<RaHeard> {
        let mut state = self.state();
        state
            .heard
            .retain(|_, held| now.saturating_since(held.at) < STALE);
        state.heard.values().cloned().collect()
    }

    /// The report against the DHCPv6 part of the image.
    pub fn report(&self, image: Option<&Image6>, now: Timestamp) -> RaReport {
        let check = self.check();
        let heard = self.heard(now);
        let (links, mut findings) =
            image.map_or_else(|| (Vec::new(), Vec::new()), |image| evaluate(image, &heard));
        if let RaCheck::Unavailable(why) = &check
            && image.is_some_and(|image| !image.scopes().is_empty())
        {
            findings.push(RaFinding {
                code: UNCHECKED,
                interface: String::new(),
                detail: format!(
                    "the router advertisements of this node's links are not checked against \
                     its DHCPv6 scopes: {why}"
                ),
                params: BTreeMap::from([("reason".to_owned(), why.clone())]),
            });
        }
        RaReport {
            check,
            links,
            findings,
        }
    }
}

/// Whether two networks overlap: one holds the other's first address.
fn overlaps(a: &Ipv6Net, b: &Ipv6Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

fn join<T: ToString>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The shortest advertised prefix the check reads: a shorter one (a router that announces
/// `::/0`, say) would cover every scope and says nothing about the link.
pub const MIN_PREFIX_LEN: u8 = 16;

/// The links of `heard` with their scopes, and the findings.
pub fn evaluate(image: &Image6, heard: &[RaHeard]) -> (Vec<RaLinkReport>, Vec<RaFinding>) {
    let mut by_link: BTreeMap<u32, Vec<&RaHeard>> = BTreeMap::new();
    for entry in heard {
        by_link.entry(entry.interface).or_default().push(entry);
    }
    let mut links = Vec::new();
    let mut findings = Vec::new();
    for entries in by_link.values() {
        let mut routers: Vec<Ipv6Addr> = entries.iter().map(|entry| entry.router).collect();
        routers.sort_unstable();
        let mut prefixes: Vec<Ipv6Net> = entries
            .iter()
            .flat_map(|entry| entry.prefixes.iter().copied())
            .filter(|prefix| prefix.prefix_len() >= MIN_PREFIX_LEN)
            .collect();
        prefixes.sort_unstable();
        prefixes.dedup();
        let networks: Vec<Ipv6Net> = entries
            .iter()
            .flat_map(|entry| entry.networks.iter().map(Ipv6Net::trunc))
            .filter(|network| network.prefix_len() >= MIN_PREFIX_LEN)
            .collect();
        let scopes: Vec<_> = image
            .scopes()
            .iter()
            .filter(|scope| {
                prefixes
                    .iter()
                    .chain(networks.iter())
                    .any(|net| overlaps(&scope.network, net))
            })
            .collect();
        let link = RaLinkReport {
            interface: entries[0].name.clone(),
            routers,
            managed: entries.iter().any(|entry| entry.managed),
            other: entries.iter().any(|entry| entry.other),
            prefixes,
            scopes: scopes.iter().map(|scope| scope.network).collect(),
            seen: entries
                .iter()
                .map(|entry| entry.at)
                .max()
                .unwrap_or_else(Timestamp::now),
        };
        let pools = scopes.iter().any(|scope| !scope.pools.is_empty());
        findings.extend(finding_of(&link, &networks, pools));
        links.push(link);
    }
    (links, findings)
}

/// The finding of one link, if any: flags off with scopes, O without M where the scopes
/// have address pools, M without a scope.
fn finding_of(link: &RaLinkReport, networks: &[Ipv6Net], pools: bool) -> Option<RaFinding> {
    let name = &link.interface;
    let routers = join(&link.routers);
    let scopes = join(&link.scopes);
    let mut params = BTreeMap::from([
        ("interface".to_owned(), name.clone()),
        ("routers".to_owned(), routers.clone()),
    ]);
    let (code, detail) = if !link.scopes.is_empty() && !link.managed && !link.other {
        params.insert("scopes".to_owned(), scopes.clone());
        (
            FLAGS_OFF,
            format!(
                "the router advertisements on {name} (from {routers}) set neither the M nor the \
                 O flag, so the hosts of the link never ask DHCPv6 and the scope {scopes} \
                 serves none of them; set M (addresses from DHCPv6) or O (other configuration \
                 only) on the router. DHCPv6 never sets a default route: that stays with the \
                 advertisements"
            ),
        )
    } else if !link.managed && link.other && pools {
        params.insert("scopes".to_owned(), scopes.clone());
        (
            OTHER_ONLY,
            format!(
                "the router advertisements on {name} (from {routers}) set the O flag without M, \
                 so the hosts of the link ask DHCPv6 for other configuration only and take no \
                 address from the pools of {scopes}; set M on the router for addresses from \
                 DHCPv6"
            ),
        )
    } else if link.scopes.is_empty() && link.managed {
        let shown = if link.prefixes.is_empty() {
            join(networks)
        } else {
            join(&link.prefixes)
        };
        params.insert("prefixes".to_owned(), shown.clone());
        (
            MANAGED_WITHOUT_SCOPE,
            format!(
                "the router advertisements on {name} (from {routers}) set the M flag, and no \
                 enabled DHCPv6 scope of this server covers the link ({shown}): its hosts ask \
                 DHCPv6 for addresses and this server does not answer them; add a scope or \
                 clear M on the router"
            ),
        )
    } else {
        return None;
    };
    Some(RaFinding {
        code,
        interface: name.clone(),
        detail,
        params,
    })
}

/// Hears the advertisements of this node's links into `watch` until `stop`: the socket,
/// the solicitations, the parse; see the module documentation.
pub async fn run(watch: Arc<RaWatch>, stop: CancellationToken) {
    use tenko_scan::ra::{RaSocket, RouterAdvert, links};
    let socket = match RaSocket::open() {
        Ok(socket) => socket,
        Err(error) => {
            tracing::warn!(
                reason = error.detail(),
                "the dhcp role cannot check the router advertisements of its links (DHCP-10)"
            );
            watch.set_check(RaCheck::Unavailable(error.detail().to_owned()));
            return;
        }
    };
    watch.set_check(RaCheck::Watching);
    tracing::info!(
        "the dhcp role checks the M and O flags of the router advertisements on its links"
    );
    let mut known = links();
    let mut solicit = tokio::time::interval(SOLICIT_EVERY);
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            _ = solicit.tick() => {
                known = links();
                for link in &known {
                    if let Err(error) = socket.solicit(link).await {
                        tracing::debug!(link = %link.name, %error, "a router solicitation was not sent");
                    }
                }
            }
            heard = socket.next() => match heard {
                Ok(heard) => {
                    let Ok(advert) = RouterAdvert::parse(&heard.message) else {
                        continue;
                    };
                    if !known.iter().any(|link| link.index == heard.interface) {
                        known = links();
                    }
                    let Some(link) = known.iter().find(|link| link.index == heard.interface)
                    else {
                        continue;
                    };
                    watch.record(RaHeard {
                        interface: heard.interface,
                        name: link.name.clone(),
                        router: heard.router,
                        managed: advert.managed(),
                        other: advert.other(),
                        router_lifetime: advert.router_lifetime,
                        prefixes: advert.prefixes().map(|info| info.prefix).collect(),
                        networks: link.networks.clone(),
                        at: Timestamp::now(),
                    });
                }
                Err(error) => {
                    tracing::warn!(%error, "the router advertisement socket failed; trying again");
                    tokio::select! {
                        () = stop.cancelled() => return,
                        () = tokio::time::sleep(Duration::from_secs(1)) => {}
                    }
                }
            },
        }
    }
}
