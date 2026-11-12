//! The protections of one node that both engines read on every request: the security
//! profile in force, which decides what an unset setting means, the relay log
//! ([`crate::relay`]), and the limits per client and per scope with their log, the offer
//! buckets and the conflict budget ([`crate::limits`]).
//!
//! The profile is the installation's (`sys.settings`); the process follows it while it
//! runs ([`Guard::set_profile`]). Reading it is one relaxed load.

use std::{
    net::IpAddr,
    sync::atomic::{AtomicU8, Ordering},
};

use tenko_core::Timestamp;

use crate::{
    image::ConfigImage,
    limits::{ConflictBudget, Limit, LimitLog, Limits, OfferRate},
    relay::{RelayLog, RelayReport},
};

/// The security profile as the DHCP role reads it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum DhcpProfile {
    /// Lab: the insecure choices of a test bench are allowed, loudly.
    Lab,
    /// Home, the profile before setup.
    #[default]
    Home,
    /// Standard.
    Standard,
    /// Hardened.
    Hardened,
}

impl DhcpProfile {
    const fn to_u8(self) -> u8 {
        match self {
            Self::Lab => 0,
            Self::Home => 1,
            Self::Standard => 2,
            Self::Hardened => 3,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Lab,
            2 => Self::Standard,
            3 => Self::Hardened,
            _ => Self::Home,
        }
    }

    /// Whether an unset relay list trusts every sender (Lab only).
    pub fn trusts_any_relay(self) -> bool {
        self == Self::Lab
    }
}

/// The protections of one node, shared by its DHCPv4 and DHCPv6 workers. The default is
/// the profile before setup, Home.
#[derive(Debug)]
pub struct Guard {
    profile: AtomicU8,
    relays: RelayLog,
    limits: LimitLog,
    offers: OfferRate,
    conflicts: ConflictBudget,
    /// The DECLINE limit of DHCPv6, with the values of the DHCPv4 server's
    /// (`[dhcp.decline]`) in a table of its own.
    declines6: std::sync::OnceLock<crate::conflict::DeclineLimit>,
    /// RELEASEs per client and hour, both families ([`RELEASES_PER_HOUR`]).
    releases: crate::conflict::DeclineLimit,
}

/// The RELEASEs one client may send per hour; one beyond is dropped (`rate_limited`) and the
/// client keeps its lease, so that a client cannot turn a loop of RELEASE and REQUEST into
/// store writes.
pub const RELEASES_PER_HOUR: u32 = 10;

impl Default for Guard {
    fn default() -> Self {
        Self::new(DhcpProfile::Home)
    }
}

impl Guard {
    /// The protections under `profile`.
    pub fn new(profile: DhcpProfile) -> Self {
        Self {
            profile: AtomicU8::new(profile.to_u8()),
            relays: RelayLog::new(),
            limits: LimitLog::default(),
            offers: OfferRate::default(),
            conflicts: ConflictBudget::default(),
            declines6: std::sync::OnceLock::new(),
            releases: crate::conflict::DeclineLimit::new(
                4_096,
                RELEASES_PER_HOUR,
                std::time::Duration::from_secs(3_600),
            ),
        }
    }

    /// Gives the DHCPv6 engine the DECLINE limit of the DHCPv4 server: the same values, in
    /// a table of its own, so that a DUID never counts against a DHCPv4 client (the first
    /// server started over this guard).
    pub fn share_declines(&self, conflicts: &std::sync::Arc<crate::conflict::Conflicts>) {
        let _ = self.declines6.set(conflicts.decline_limit().like(4_096));
    }

    /// Whether the DHCPv6 client of `duid` may decline one more address now (`[dhcp.decline]
    /// limit` per `window_secs`). Without a DHCPv4 server every DECLINE is allowed.
    pub fn decline_allowed(&self, duid: &[u8]) -> bool {
        self.declines6
            .get()
            .is_none_or(|limit| limit.allow(duid, std::time::Instant::now()))
    }

    /// Whether the client of `identity` (a DHCPv4 identity, or a DHCPv6 DUID) may release
    /// once more now ([`RELEASES_PER_HOUR`]).
    pub fn release_allowed(&self, identity: &[u8]) -> bool {
        self.releases.allow(identity, std::time::Instant::now())
    }

    /// Gives back an offer of `scope` taken for a request the server runs again (a conflict
    /// probe's next address), so that one DISCOVER costs one token.
    pub fn refund_offer(&self, scope: tenko_core::PrefixId, rate: u32) {
        self.offers.refund(scope, rate);
    }

    /// The profile in force.
    pub fn profile(&self) -> DhcpProfile {
        DhcpProfile::from_u8(self.profile.load(Ordering::Relaxed))
    }

    /// Follows a profile change.
    pub fn set_profile(&self, profile: DhcpProfile) {
        self.profile.store(profile.to_u8(), Ordering::Relaxed);
    }

    /// Whether `addr` is in the trusted relays under `image`'s list and the profile.
    pub fn trusts_relay(&self, image: &ConfigImage, addr: IpAddr) -> bool {
        image
            .relay_trust()
            .trusts(addr, self.profile().trusts_any_relay())
    }

    /// Whether the sender of a datagram is a trusted relay
    /// ([`crate::relay::RelayTrust::trusts_sender`]).
    pub fn trusts_sender(&self, image: &ConfigImage, sender: IpAddr) -> bool {
        image
            .relay_trust()
            .trusts_sender(sender, self.profile().trusts_any_relay())
    }

    /// Whether the trusted relay at `relay` may name a scope of `network` under `image`'s
    /// list and the profile ([`crate::relay::RelayTrust::may_name`]).
    pub fn relay_may_name(
        &self,
        image: &ConfigImage,
        relay: IpAddr,
        network: ipnet::IpNet,
    ) -> bool {
        image
            .relay_trust()
            .may_name(relay, network, self.profile().trusts_any_relay())
    }

    /// Notes that `sender`, which named `relay`, was refused as a relay.
    pub fn refuse_relay(&self, sender: IpAddr, relay: IpAddr, now: Timestamp) {
        self.relays.refuse(sender, relay, now);
    }

    /// Notes that the trusted relay `sender`, which named `relay`, selected a scope of
    /// `link` outside its links and was refused.
    pub fn refuse_relay_link(
        &self,
        sender: IpAddr,
        relay: IpAddr,
        link: ipnet::IpNet,
        now: Timestamp,
    ) {
        self.relays.refuse_link(sender, relay, link, now);
    }

    /// The relay log.
    pub fn relays(&self) -> &RelayLog {
        &self.relays
    }

    /// The limits in force under `image`'s stored values and the profile.
    pub fn limits(&self, image: &ConfigImage) -> Limits {
        Limits::resolve(image.limits(), self.profile())
    }

    /// Takes an offer to a new client of `scope` at `rate` per second; false (and the
    /// refusal logged) when the scope's bucket is empty.
    pub fn take_offer(&self, scope: tenko_core::PrefixId, rate: u32, now: Timestamp) -> bool {
        if self.offers.take(scope, rate) {
            return true;
        }
        self.limits
            .refuse(Limit::OffersPerSecond, &[], scope, (rate, rate), now);
        false
    }

    /// Notes a refusal by a limit of a client.
    pub fn refuse_limit(
        &self,
        limit: Limit,
        client: &[u8],
        scope: tenko_core::PrefixId,
        (cap, held): (u32, u32),
        now: Timestamp,
    ) {
        self.limits.refuse(limit, client, scope, (cap, held), now);
    }

    /// The refusals of the limits.
    pub fn limit_log(&self) -> &LimitLog {
        &self.limits
    }

    /// The conflict budget.
    pub fn conflicts(&self) -> &ConflictBudget {
        &self.conflicts
    }

    /// What the node reports about its limits under `image`.
    pub fn limit_report(&self, image: Option<&ConfigImage>) -> crate::limits::LimitReport {
        let (entries, unlogged) = self.limits.report();
        crate::limits::LimitReport {
            limits: image.map(|image| self.limits(image)),
            refusals: entries
                .into_iter()
                .map(|entry| {
                    let network = image.and_then(|image| {
                        image
                            .scope(entry.scope)
                            .map(|scope| ipnet::IpNet::V4(scope.network))
                            .or_else(|| {
                                image
                                    .v6()
                                    .scope(entry.scope)
                                    .map(|scope| ipnet::IpNet::V6(scope.network))
                            })
                    });
                    (entry, network)
                })
                .collect(),
            unlogged,
        }
    }

    /// What the node reports about relays under `image`.
    pub fn relay_report(&self, image: Option<&ConfigImage>) -> RelayReport {
        let listed = image.is_some_and(|image| image.relay_trust().is_set());
        let mut report = self
            .relays
            .report(listed, !listed && self.profile().trusts_any_relay());
        if let Some(image) = image {
            report.any_link = self.relays.any_link(image.relay_trust().any_link());
        }
        report.hardened = self.profile() == DhcpProfile::Hardened;
        report
    }
}
