//! DNSSEC signing on the controllers (WP6.3, plan section 2.7, P2-Q4, ADR 0018).
//!
//! The private keys are system secrets of the vault (purpose `dnssec`); the signer, a
//! leader-only service, signs the zones whose policy says `online` and writes what it
//! generates as rows of the zone with the origin `dnssec` through the zone service, so
//! nodes serve signed data from their index and never sign. A zone whose policy says
//! `imported` is served with its own signatures, and their expiry is watched.
//!
//! | Module | What |
//! |---|---|
//! | [`crypto`] | ECDSA P-256 and Ed25519 over `aws-lc-rs`, DNSKEY, key tag, DS |
//! | [`canonical`] | the canonical form of an RRset and the data an RRSIG signs |
//! | [`chain`] | the types the signer owns, the NSEC3 hash and base32hex |
//! | [`sign`] | making an RRSIG, inception, expiration with jitter, keeping one |
//! | [`keys`] | the keys of a zone, their states, generation into the vault |
//! | [`pass`] | one full or incremental signing pass of a zone scope |
//! | [`signer`] | the leader-only service `dns.signer` and its timer |
//! | [`rollover`] | ZSK and KSK rollovers as the job `dns.dnssec.rollover` |
//! | [`health`] | the clock and expiry findings (OPS-09) |
//! | this module | the profile defaults (TGL-13) and the write guard of the zone service |

pub mod canonical;
pub mod chain;
pub mod crypto;
pub mod health;
pub mod keys;
pub mod pass;
pub mod rollover;
pub mod sign;
pub mod signer;

pub use signer::{Signer, SignerConfig, Trigger};

use tenko_core::dns::{DnsName, DnssecMode, DnssecPolicy, Origin, Rtype, Zone, ZoneKind};

/// Why the zone service refuses a change of an RRset of `rtype` whose stored origin is
/// `existing`: the signer's rows belong to the signer, and in a zone signed online so do
/// the types it generates. `None` when the change may go ahead.
pub fn refused_change(zone: &Zone, rtype: Rtype, existing: Option<Origin>) -> Option<&'static str> {
    if existing == Some(Origin::Dnssec) {
        return Some("the RRset belongs to the DNSSEC signer and is not changed by hand");
    }
    if zone.dnssec.mode == DnssecMode::Online && chain::is_generated(rtype) {
        return Some("the zone is signed online; the signer writes this type");
    }
    None
}

/// Names under which a zone is private by convention (RFC 6761, RFC 8375, RFC 6762) or
/// by common use; a zone under one of them is not served outside.
const PRIVATE_SUFFIXES: [&str; 13] = [
    "home.arpa",
    "local",
    "localhost",
    "test",
    "example",
    "invalid",
    "internal",
    "lan",
    "corp",
    "home",
    "intranet",
    "private",
    "localdomain",
];

/// Reverse zones of private and special address ranges.
const PRIVATE_REVERSE: [&str; 11] = [
    "10.in-addr.arpa",
    "168.192.in-addr.arpa",
    "254.169.in-addr.arpa",
    "127.in-addr.arpa",
    "0.in-addr.arpa",
    "c.f.ip6.arpa",
    "d.f.ip6.arpa",
    "8.e.f.ip6.arpa",
    "9.e.f.ip6.arpa",
    "a.e.f.ip6.arpa",
    "b.e.f.ip6.arpa",
];

/// Whether a zone is served outside by the TGL-13 rule: a name that is neither under a
/// private suffix nor the reverse zone of a private range (RFC 1918 including
/// 172.16.0.0/12, link-local, loopback, ULA).
pub fn served_externally(name: &DnsName) -> bool {
    let under =
        |suffix: &str| DnsName::new(suffix).is_ok_and(|suffix| name.is_subdomain_of(&suffix));
    if PRIVATE_SUFFIXES
        .iter()
        .chain(PRIVATE_REVERSE.iter())
        .any(|suffix| under(suffix))
    {
        return false;
    }
    let rfc1918_172 = (16..32).any(|octet| under(&format!("{octet}.172.in-addr.arpa")));
    !rfc1918_172
}

/// The signing policy of a new zone whose request names none (TGL-13): signed online
/// under the Hardened profile when it is a primary zone served outside, off otherwise
/// (Home and Lab off, Standard opt-in per zone).
pub fn profile_default(hardened: bool, name: &DnsName, kind: ZoneKind) -> DnssecPolicy {
    let mut policy = DnssecPolicy::default();
    if hardened && kind == ZoneKind::Primary && served_externally(name) {
        policy.mode = DnssecMode::Online;
    }
    policy
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> DnsName {
        DnsName::new(text).expect("name")
    }

    #[test]
    fn profiles_sign_only_external_zones_when_hardened() {
        let external = name("example.com");
        let hardened = profile_default(true, &external, ZoneKind::Primary);
        assert_eq!(hardened.mode, DnssecMode::Online);
        assert_eq!(
            profile_default(false, &external, ZoneKind::Primary).mode,
            DnssecMode::Off
        );
        for private in [
            "corp.example.test",
            "home.arpa",
            "office.lan",
            "1.168.192.in-addr.arpa",
            "20.172.in-addr.arpa",
            "d.f.ip6.arpa",
        ] {
            assert!(!served_externally(&name(private)), "{private}");
            assert_eq!(
                profile_default(true, &name(private), ZoneKind::Primary).mode,
                DnssecMode::Off
            );
        }
        assert!(served_externally(&name("2.0.192.in-addr.arpa")));
        assert!(served_externally(&name("8.b.d.0.1.0.0.2.ip6.arpa")));
        assert_eq!(
            profile_default(true, &external, ZoneKind::Secondary).mode,
            DnssecMode::Off
        );
    }
}
