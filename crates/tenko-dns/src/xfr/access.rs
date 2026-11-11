//! Who may ask the transfer path for a zone (DNS-09, TGL-10): one decision for AXFR, IXFR
//! and the signed SOA query of a secondary, and one for NOTIFY in.
//!
//! A transfer-shaped request (AXFR, IXFR, a TSIG-signed SOA query) is checked in this
//! order, and the first failure refuses it:
//!
//! 1. the zone names at least one access list in `transfer.allow`;
//! 2. the transport: TLS ended by this node when the zone has `xot`, and under Hardened
//!    for every client outside the site ([`Site`]);
//! 3. the access lists allow the client with its address and its TSIG key, "deny wins"
//!    ([`tenko_core::dns::lists_allow`]): a list whose first matching entry is a `deny`
//!    refuses whatever another list allows;
//! 4. a signature: when the zone has `require_tsig`, and under Hardened always, the request
//!    is signed with a key that an allowing `key` entry of the lists names.
//!
//! The profile sets a floor, never a ceiling: under Hardened the zone's own `require_tsig`
//! and `xot` can add to the rule but not take away from it; under Home, Standard and Lab
//! the zone's settings apply as stored, and a zone weaker than the profile's value is a
//! finding ([`super::health`]).
//!
//! A NOTIFY for a secondary zone is accepted from the address of one of its primaries,
//! signed with the primary's key when it has one; under Hardened it must be signed in any
//! case, so a primary without a key is refreshed on its timers only.

use std::net::IpAddr;

use ipnet::IpNet;
use tenko_core::dns::{self, Acl, AclEntry, KeyName, Zone, ZoneId, ZoneKind};

use crate::update::policy::UpdateProfile;

/// The networks that count as the site for the XoT rule of Hardened: the security setting
/// `transfer_site`, whose default is [`tenko_core::dns::TRANSFER_SITE_DEFAULT`] (private,
/// shared, unique-local, loopback and link-local ranges). A transfer to any other address
/// leaves the site; an empty list is a site without networks. The role keeps it current
/// from the settings ([`Site::set`]) and reads it without a lock; [`Site::contains`] is the
/// one answer to "is this client inside the site".
#[derive(Debug)]
pub struct Site(arc_swap::ArcSwap<Vec<IpNet>>);

impl Default for Site {
    fn default() -> Self {
        Self::new(
            tenko_core::dns::TRANSFER_SITE_DEFAULT
                .iter()
                .filter_map(|text| text.parse().ok())
                .collect(),
        )
    }
}

impl Site {
    /// A site of `networks`.
    pub fn new(networks: Vec<IpNet>) -> Self {
        Self(arc_swap::ArcSwap::from_pointee(networks))
    }

    /// The site of a stored list (`transfer_site`, as the settings hold it); the default
    /// when it does not read, which the settings' own check prevents.
    pub fn of(entries: &[String]) -> Self {
        dns::parse_transfer_site(entries).map_or_else(|_| Self::default(), Self::new)
    }

    /// Replaces the networks.
    pub fn set(&self, networks: Vec<IpNet>) {
        self.0.store(std::sync::Arc::new(networks));
    }

    /// Whether `client` is inside the site; an IPv4-mapped IPv6 address counts as its
    /// IPv4 address.
    pub fn contains(&self, client: IpAddr) -> bool {
        let client = canonical(client);
        self.0
            .load()
            .iter()
            .any(|network| network.contains(&client))
    }

    /// Whether every address of `network` is inside the site.
    pub fn contains_network(&self, network: &IpNet) -> bool {
        self.0.load().iter().any(|site| site.contains(network))
    }
}

/// IPv4-mapped IPv6 addresses compare as IPv4.
pub fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

/// Why a request was refused: a stable code for the audit record and the logs, and the
/// reason in words an operator can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    /// The stable code.
    pub code: &'static str,
    /// What to do about it, in English.
    pub reason: &'static str,
}

/// The stable codes of [`Refusal`].
pub mod codes {
    /// The zone names no access list in `transfer.allow`.
    pub const NO_ACCESS_LIST: &str = "no_access_list";
    /// The zone has `xot` and the request did not come over TLS ended by this node.
    pub const XOT: &str = "xot";
    /// Hardened: a client outside the site asked over plain TCP or UDP.
    pub const PROFILE_XOT: &str = "profile_xot";
    /// The access lists do not allow the client, or one of them denies it.
    pub const NOT_ALLOWED: &str = "not_allowed";
    /// The zone has `require_tsig` and the request is not signed.
    pub const UNSIGNED: &str = "unsigned";
    /// Hardened: the request is not signed.
    pub const PROFILE_UNSIGNED: &str = "profile_unsigned";
    /// The request is signed with a key no allowing `key` entry names.
    pub const KEY_NOT_NAMED: &str = "key_not_named";
    /// A NOTIFY for a zone that is not a secondary zone of this node.
    pub const NOT_SECONDARY: &str = "not_secondary";
    /// A NOTIFY from an address that is not one of the zone's primaries.
    pub const NOT_A_PRIMARY: &str = "not_a_primary";
    /// A NOTIFY that is not signed with the primary's key.
    pub const NOTIFY_KEY: &str = "notify_key";
    /// Hardened: an unsigned NOTIFY.
    pub const PROFILE_NOTIFY_UNSIGNED: &str = "profile_notify_unsigned";
}

const fn refusal(code: &'static str, reason: &'static str) -> Refusal {
    Refusal { code, reason }
}

/// Who sets a rule of a zone's transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// The rule is off.
    Off,
    /// The zone's own setting: for every client.
    Zone,
    /// The Hardened profile, although the zone has it off: a signature for every client,
    /// TLS for clients outside the site.
    Profile,
}

impl Rule {
    fn of(zone: bool, hardened: bool) -> Self {
        match (zone, hardened) {
            (true, _) => Rule::Zone,
            (false, true) => Rule::Profile,
            (false, false) => Rule::Off,
        }
    }
}

/// The rules in force for the transfers of a zone, as the refusal path applies them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Effective {
    /// A signature with a key the lists name: the zone's `require_tsig`, or Hardened.
    pub tsig: Rule,
    /// TLS ended by this node: the zone's `xot`, or Hardened outside the site.
    pub xot: Rule,
}

/// The rules in force for the transfers of `zone` under `profile`.
pub fn effective(zone: &Zone, profile: UpdateProfile) -> Effective {
    let hardened = profile == UpdateProfile::Hardened;
    Effective {
        tsig: Rule::of(zone.transfer.require_tsig, hardened),
        xot: Rule::of(zone.transfer.xot, hardened),
    }
}

/// Whether a request from `client`, signed with `key` if any, over TLS ended by this node
/// when `tls`, may transfer `zone` (AXFR, IXFR, or the signed SOA query of a secondary)
/// under `profile` with the site `site`; `lists` are the zone's `transfer.allow` lists
/// that exist.
///
/// # Errors
///
/// The [`Refusal`] of the first rule that fails.
pub fn transfer(
    zone: &Zone,
    lists: &[&Acl],
    profile: UpdateProfile,
    site: &Site,
    client: IpAddr,
    key: Option<&KeyName>,
    tls: bool,
) -> Result<(), Refusal> {
    if zone.transfer.allow.is_empty() {
        return Err(refusal(
            codes::NO_ACCESS_LIST,
            "the zone names no access list for transfers: add one under the zone's transfer settings",
        ));
    }
    let rules = effective(zone, profile);
    if !tls {
        match rules.xot {
            Rule::Zone => {
                return Err(refusal(
                    codes::XOT,
                    "the zone transfers over TLS only (XoT): the secondary must use the DoT port",
                ));
            }
            Rule::Profile if !site.contains(client) => {
                return Err(refusal(
                    codes::PROFILE_XOT,
                    "the Hardened profile requires TLS (XoT) for a transfer to an address outside the site: configure the secondary for XoT on the DoT port",
                ));
            }
            _ => {}
        }
    }
    let client = canonical(client);
    if !dns::lists_allow(lists.iter().copied(), |list| list.decide(client, key)) {
        return Err(refusal(
            codes::NOT_ALLOWED,
            "no access list of the zone allows the client, or one of them denies it (a deny in any list wins)",
        ));
    }
    if rules.tsig != Rule::Off {
        let Some(key) = key else {
            return Err(if rules.tsig == Rule::Profile {
                refusal(
                    codes::PROFILE_UNSIGNED,
                    "the Hardened profile requires a TSIG key for every zone transfer, whatever the zone's setting: sign the transfer with a key an access list of the zone names",
                )
            } else {
                refusal(
                    codes::UNSIGNED,
                    "the zone's transfers need a TSIG key: sign the transfer with a key an access list of the zone names",
                )
            });
        };
        let named = lists.iter().any(|list| {
            list.entries
                .iter()
                .any(|entry| matches!(entry, AclEntry::Key { name, deny: false } if name == key))
        });
        if !named {
            return Err(refusal(
                codes::KEY_NOT_NAMED,
                "the TSIG key of the request is not named by an allowing key entry of the zone's access lists",
            ));
        }
    }
    Ok(())
}

/// Whether a NOTIFY from `from`, signed with `key` if any, for `zone` is accepted under
/// `profile`: the zone is a secondary zone and `from` is one of its primaries, signed with
/// the primary's key when it has one, and signed in any case under Hardened. Accepted, the
/// zone and whether the NOTIFY is authenticated: signed with the primary's own key (a
/// signature with another key of the node proves nothing about the primary).
///
/// # Errors
///
/// The [`Refusal`] of the first rule that fails.
pub fn notify(
    zone: &Zone,
    profile: UpdateProfile,
    from: IpAddr,
    key: Option<&KeyName>,
) -> Result<(ZoneId, bool), Refusal> {
    if zone.kind != ZoneKind::Secondary {
        return Err(refusal(
            codes::NOT_SECONDARY,
            "a NOTIFY for a zone that is not a secondary zone of this node",
        ));
    }
    let from = canonical(from);
    let Some(primary) = zone.source.as_ref().and_then(|source| {
        source
            .primaries
            .iter()
            .find(|primary| canonical(primary.address) == from)
    }) else {
        return Err(refusal(
            codes::NOT_A_PRIMARY,
            "a NOTIFY from an address that is not one of the zone's primaries",
        ));
    };
    match (&primary.key, key) {
        (Some(wanted), Some(key)) if wanted == key => Ok((zone.id, true)),
        (Some(_), _) => Err(refusal(
            codes::NOTIFY_KEY,
            "a NOTIFY not signed with the key of the zone's primary",
        )),
        (None, _) if profile == UpdateProfile::Hardened => Err(refusal(
            codes::PROFILE_NOTIFY_UNSIGNED,
            "the Hardened profile accepts only signed NOTIFY messages: give the zone's primary a TSIG key; until then the zone is refreshed on its SOA timers",
        )),
        (None, _) => Ok((zone.id, false)),
    }
}

#[cfg(test)]
pub(crate) mod tests;
