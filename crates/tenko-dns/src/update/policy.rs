//! Who may update a zone (DNS-11, TGL-09, RFC 2136 section 3.3, RFC 3007).
//!
//! An update passes when the zone is a primary zone the node serves, the access lists of
//! `update.allowed` allow the client with its address and its TSIG key (none means
//! nobody; the first matching entry of a list decides, and a list whose first match is a
//! `deny` refuses whatever another list allows: "deny wins", [`dns::lists_allow`]), and,
//! where a signature is
//! required, the request is signed with a key that an allowing `key` entry of the lists
//! names. Whether a signature is required follows the zone's `require_tsig` under the
//! security profile in force (TGL-09):
//!
//! | Profile | Without `update.allowed` | Signature |
//! |---|---|---|
//! | Home | no external update at all | as the zone says (`require_tsig`, on by default) |
//! | Standard | no update | as the zone says (on by default: TSIG) |
//! | Hardened | no update | always, TSIG or GSS-TSIG; an unsigned update is refused even when the zone switched `require_tsig` off, and a zone with Kerberos settings keeps the Windows ownership rules whatever its `ownership` says |
//! | Lab | no update | never required: an unsigned update from an address the lists allow passes; a list that names only keys still asks for its key |
//!
//! A zone overrides the default by naming access lists in `update.allowed`, and in Home
//! and Standard by switching `require_tsig` off; Hardened and Lab hold their rule for the
//! signature whatever the zone says. TSIG failures (BADKEY, BADSIG, BADTIME) are answered
//! before this check, as NOTAUTH with the TSIG error.
//!
//! An update signed with GSS-TSIG (identity plan section 3.5) is checked by its principal:
//! the zone must have Kerberos settings (`update.kerberos`) naming the principal's realm,
//! the lists decide by [`Acl::decide_principal`], deny wins (a prefix entry by the address, a
//! `kerberos` entry by the realm, the name pattern and its prefix, `any`; a key entry never
//! matches it), and where a signature is required an allowing `kerberos` entry must name
//! the principal, as a `key` entry must name a TSIG key. `require_tsig` thus means "a
//! signature is required, TSIG or GSS-TSIG".

use std::{
    net::IpAddr,
    sync::atomic::{AtomicU8, Ordering},
};

use tenko_core::dns::{
    self, Acl, AclEntry, AclId, Ownership, PrincipalName, Zone, ZoneKind, identity,
};

use super::Signer;

/// The security profile the update policy follows (TGL-09); the role maps the installation's
/// profile onto it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum UpdateProfile {
    /// Home: no external update unless a zone names access lists.
    Home = 0,
    /// Standard: TSIG required by default.
    #[default]
    Standard = 1,
    /// Hardened: TSIG always required, unsigned refused.
    Hardened = 2,
    /// Lab: unsigned updates allowed from the access lists.
    Lab = 3,
}

impl UpdateProfile {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => UpdateProfile::Home,
            2 => UpdateProfile::Hardened,
            3 => UpdateProfile::Lab,
            _ => UpdateProfile::Standard,
        }
    }

    /// The stable name.
    pub const fn name(self) -> &'static str {
        match self {
            UpdateProfile::Home => "home",
            UpdateProfile::Standard => "standard",
            UpdateProfile::Hardened => "hardened",
            UpdateProfile::Lab => "lab",
        }
    }
}

/// The profile in force, shared between the role (which follows the settings) and the
/// update path.
#[derive(Debug, Default)]
pub struct ProfileCell(AtomicU8);

impl ProfileCell {
    /// A cell holding `profile`.
    pub fn new(profile: UpdateProfile) -> Self {
        Self(AtomicU8::new(profile as u8))
    }

    /// The profile in force.
    pub fn get(&self) -> UpdateProfile {
        UpdateProfile::from_u8(self.0.load(Ordering::Relaxed))
    }

    /// Sets the profile.
    pub fn set(&self, profile: UpdateProfile) {
        self.0.store(profile as u8, Ordering::Relaxed);
    }
}

/// Whether an update of `zone` needs a TSIG signature under `profile`.
pub fn require_tsig(zone: &Zone, profile: UpdateProfile) -> bool {
    match profile {
        UpdateProfile::Hardened => true,
        UpdateProfile::Lab => false,
        UpdateProfile::Home | UpdateProfile::Standard => zone.update.require_tsig,
    }
}

// WP13.2: the ownership rules in force (identity plan sections 3.6 and 3.7).
/// Whether the ownership rules of section 3.6 apply to `zone` under `profile`: the zone has
/// Kerberos settings with `ownership = windows`, or any Kerberos settings under Hardened.
pub fn ownership_on(zone: &Zone, profile: UpdateProfile) -> bool {
    zone.update.kerberos.as_ref().is_some_and(|kerberos| {
        kerberos.ownership == Ownership::Windows || profile == UpdateProfile::Hardened
    })
}

/// Whether an allowing `kerberos` entry of `lists` names `principal` from `client`.
fn principal_named(lists: &[&Acl], client: IpAddr, principal: &PrincipalName) -> bool {
    lists.iter().any(|list| {
        list.entries.iter().any(|entry| {
            matches!(entry, AclEntry::Kerberos { realm, principal: pattern, from, deny: false }
                if realm == principal.realm()
                    && pattern
                        .as_deref()
                        .is_none_or(|pattern| identity::principal_matches(pattern, principal))
                    && from.is_none_or(|from| from.contains(&client)))
        })
    })
}
// WP13.2: end.

/// Why an update is refused: the text of the extended error and the audit record.
pub type Refusal = &'static str;

/// Checks whether a client at `client`, signed by `signer`, may update `zone` under
/// `profile`; `acl` finds an access list by id.
///
/// # Errors
///
/// The reason of the refusal (REFUSED).
pub fn check<'a>(
    zone: &Zone,
    acl: impl Fn(AclId) -> Option<&'a Acl>,
    profile: UpdateProfile,
    client: IpAddr,
    signer: &Signer,
) -> Result<(), Refusal> {
    if zone.kind != ZoneKind::Primary {
        return Err(match zone.kind {
            ZoneKind::Secondary => "the zone is a secondary zone; send updates to its primary",
            _ => "only a primary zone takes dynamic updates",
        });
    }
    if zone.update.allowed.is_empty() {
        return Err(match profile {
            UpdateProfile::Home => {
                "no access list allows updates of the zone (the Home profile allows no external updates)"
            }
            _ => "no access list allows updates of the zone",
        });
    }
    let lists: Vec<&Acl> = zone
        .update
        .allowed
        .iter()
        .filter_map(|id| acl(*id))
        .collect();
    // WP13.2: an update signed with GSS-TSIG is checked by its principal.
    if let Signer::Gss(identity) = signer {
        let Some(kerberos) = &zone.update.kerberos else {
            return Err("the zone takes no GSS-TSIG updates (it has no Kerberos settings)");
        };
        if !kerberos.accepts_realm(identity.realm()) {
            return Err("the zone takes no GSS-TSIG updates from the principal's realm");
        }
        let principal = &identity.principal;
        if !dns::lists_allow(lists.iter().copied(), |list| {
            list.decide_principal(client, principal)
        }) {
            return Err("no update access list allows the principal, or one denies it");
        }
        if require_tsig(zone, profile) && !principal_named(&lists, client, principal) {
            return Err(
                "the principal is not named by a Kerberos entry of the zone's update access lists",
            );
        }
        return Ok(());
    }
    let key = signer.key();
    // WP13.2: end.
    if !dns::lists_allow(lists.iter().copied(), |list| list.decide(client, key)) {
        return Err("no update access list allows the client, or one denies it");
    }
    if require_tsig(zone, profile) {
        let Some(key) = key else {
            return Err(if profile == UpdateProfile::Hardened {
                "unsigned updates are refused (Hardened profile); sign with a TSIG key or GSS-TSIG"
            } else {
                "the zone's updates need a TSIG key"
            });
        };
        let named = lists.iter().any(|list| {
            list.entries
                .iter()
                .any(|entry| matches!(entry, AclEntry::Key { name, deny: false } if name == key))
        });
        if !named {
            return Err("the TSIG key is not named by the zone's update access lists");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tenko_core::{
        dns::{DnsName, SoaDefaults, UpdatePolicy},
        ipam::Stamp,
    };

    use super::*;

    fn name(text: &str) -> DnsName {
        DnsName::new(text).expect("name")
    }

    fn zone(update: UpdatePolicy) -> Zone {
        let stamp = Stamp::new(
            "2026-10-17T12:00:00Z".parse().expect("time"),
            tenko_core::Principal::system(tenko_core::SystemComponent::Dns),
        );
        Zone {
            id: tenko_core::dns::ZoneId::generate(),
            name: name("example.test"),
            kind: ZoneKind::Primary,
            tenant: None,
            scopes: vec![tenko_core::dns::ZoneScope::default_scope()],
            serial: tenko_core::dns::SerialPolicy::Counter,
            soa: SoaDefaults::new(name("ns1.example.test"), name("hostmaster.example.test")),
            transfer: tenko_core::dns::TransferPolicy::default(),
            update,
            dnssec: tenko_core::dns::DnssecPolicy::default(),
            source: None,
            reverse_of: None,
            catalog: false,
            description: None,
            created: stamp.clone(),
            updated: stamp,
        }
    }

    fn lists() -> (Acl, Acl) {
        let signed = Acl {
            id: AclId::generate(),
            name: "signed".to_owned(),
            entries: vec![AclEntry::Key {
                name: name("update.example.test"),
                deny: false,
            }],
            description: None,
        };
        let lan = Acl {
            id: AclId::generate(),
            name: "lan".to_owned(),
            entries: vec![AclEntry::Prefix {
                prefix: "192.0.2.0/24".parse().expect("prefix"),
                deny: false,
            }],
            description: None,
        };
        (signed, lan)
    }

    /// Deny wins (owner decision of 2026-11-06): a list whose first matching entry denies
    /// the client refuses the update although another list allows it.
    #[test]
    fn a_deny_in_any_update_list_wins() {
        let (_, lan) = lists();
        let blocked = Acl {
            id: AclId::generate(),
            name: "blocked".to_owned(),
            entries: vec![AclEntry::Prefix {
                prefix: "192.0.2.66/32".parse().expect("prefix"),
                deny: true,
            }],
            description: None,
        };
        let find = |id: AclId| [&blocked, &lan].into_iter().find(|acl| acl.id == id);
        let zone = zone(UpdatePolicy {
            allowed: vec![lan.id, blocked.id],
            require_tsig: false,
            may_replace_ipam: false,
            dhcp: None,
            kerberos: None,
        });
        let denied: IpAddr = "192.0.2.66".parse().expect("address");
        let other: IpAddr = "192.0.2.10".parse().expect("address");
        let standard = UpdateProfile::Standard;
        assert_eq!(
            check(&zone, find, standard, denied, &Signer::None),
            Err("no update access list allows the client, or one denies it")
        );
        assert_eq!(check(&zone, find, standard, other, &Signer::None), Ok(()));
    }

    /// TGL-09: the profile defaults of the signature, in both directions for every profile:
    /// what each profile takes and what it refuses, with the reason of the refusal.
    #[test]
    fn the_profiles_decide_the_signature() {
        const NONE_HOME: &str = "no access list allows updates of the zone (the Home profile allows no external updates)";
        const NONE: &str = "no access list allows updates of the zone";
        const NOT_ALLOWED: &str = "no update access list allows the client, or one denies it";
        const NEEDS_KEY: &str = "the zone's updates need a TSIG key";
        const HARDENED_UNSIGNED: &str =
            "unsigned updates are refused (Hardened profile); sign with a TSIG key or GSS-TSIG";
        const NOT_NAMED: &str = "the TSIG key is not named by the zone's update access lists";
        const SECONDARY: &str = "the zone is a secondary zone; send updates to its primary";
        use UpdateProfile::{Hardened, Home, Lab, Standard};
        /// A zone, a profile, a client, a signer and the decision.
        type Case<'a> = (
            &'a Zone,
            UpdateProfile,
            IpAddr,
            &'a Signer,
            Result<(), Refusal>,
        );

        let (signed, lan) = lists();
        let find = |id: AclId| [&signed, &lan].into_iter().find(|acl| acl.id == id);
        let client: IpAddr = "192.0.2.10".parse().expect("address");
        let outside: IpAddr = "198.51.100.10".parse().expect("address");
        let key = Signer::Tsig(name("update.example.test"));
        let other_key = Signer::Tsig(name("other.example.test"));
        let none = zone(UpdatePolicy::default());
        // `signed` names the key, `lan` holds the client's address.
        let both = zone(UpdatePolicy {
            allowed: vec![signed.id, lan.id],
            require_tsig: true,
            may_replace_ipam: false,
            dhcp: None,
            kerberos: None,
        });
        let unsigned = zone(UpdatePolicy {
            allowed: vec![lan.id],
            require_tsig: false,
            may_replace_ipam: false,
            dhcp: None,
            kerberos: None,
        });
        let mut secondary = both.clone();
        secondary.kind = ZoneKind::Secondary;

        // The signature each profile requires, for a zone that asks for one and one that
        // does not.
        for (profile, with, without) in [
            (Home, true, false),
            (Standard, true, false),
            (Hardened, true, true),
            (Lab, false, false),
        ] {
            assert_eq!(require_tsig(&both, profile), with, "{profile:?}");
            assert_eq!(require_tsig(&unsigned, profile), without, "{profile:?}");
        }

        let cases: [Case<'_>; 30] = [
            // No access list: nobody, whatever the profile.
            (&none, Home, client, &key, Err(NONE_HOME)),
            (&none, Standard, client, &key, Err(NONE)),
            (&none, Hardened, client, &key, Err(NONE)),
            (&none, Lab, client, &Signer::None, Err(NONE)),
            // A zone that requires TSIG.
            (&both, Home, client, &key, Ok(())),
            (&both, Home, client, &Signer::None, Err(NEEDS_KEY)),
            (&both, Standard, client, &key, Ok(())),
            (&both, Standard, outside, &key, Ok(())),
            (&both, Standard, client, &Signer::None, Err(NEEDS_KEY)),
            (&both, Standard, outside, &Signer::None, Err(NOT_ALLOWED)),
            (&both, Standard, client, &other_key, Err(NOT_NAMED)),
            (&both, Hardened, client, &key, Ok(())),
            (
                &both,
                Hardened,
                client,
                &Signer::None,
                Err(HARDENED_UNSIGNED),
            ),
            (&both, Hardened, client, &other_key, Err(NOT_NAMED)),
            (&both, Lab, client, &Signer::None, Ok(())),
            (&both, Lab, client, &key, Ok(())),
            (&both, Lab, client, &other_key, Ok(())),
            (&both, Lab, outside, &Signer::None, Err(NOT_ALLOWED)),
            // A zone that switched TSIG off: Home, Standard and Lab follow it, Hardened not.
            (&unsigned, Home, client, &Signer::None, Ok(())),
            (&unsigned, Home, client, &key, Ok(())),
            (&unsigned, Standard, client, &Signer::None, Ok(())),
            (&unsigned, Standard, outside, &key, Err(NOT_ALLOWED)),
            (
                &unsigned,
                Hardened,
                client,
                &Signer::None,
                Err(HARDENED_UNSIGNED),
            ),
            (&unsigned, Hardened, client, &key, Err(NOT_NAMED)),
            (&unsigned, Lab, client, &Signer::None, Ok(())),
            (&unsigned, Lab, outside, &Signer::None, Err(NOT_ALLOWED)),
            // A secondary zone takes no update under any profile.
            (&secondary, Home, client, &key, Err(SECONDARY)),
            (&secondary, Standard, client, &key, Err(SECONDARY)),
            (&secondary, Hardened, client, &key, Err(SECONDARY)),
            (&secondary, Lab, client, &key, Err(SECONDARY)),
        ];
        for (index, (zone, profile, from, signer, expected)) in cases.into_iter().enumerate() {
            assert_eq!(
                check(zone, find, profile, from, signer),
                expected,
                "case {index}: {profile:?} from {from}"
            );
        }
    }
}

#[cfg(test)]
mod gss_tests {
    use tenko_core::{
        dns::{DnsName, KerberosUpdate, PrincipalName, Realm, SoaDefaults, UpdatePolicy},
        ipam::Stamp,
    };

    use super::*;
    use crate::update::GssIdentity;

    fn zone(kerberos: Option<KerberosUpdate>, allowed: Vec<AclId>) -> Zone {
        let stamp = Stamp::new(
            "2026-11-06T12:00:00Z".parse().expect("time"),
            tenko_core::Principal::system(tenko_core::SystemComponent::Dns),
        );
        let name = |text: &str| DnsName::new(text).expect("name");
        Zone {
            id: tenko_core::dns::ZoneId::generate(),
            name: name("corp.example.test"),
            kind: ZoneKind::Primary,
            tenant: None,
            scopes: vec![tenko_core::dns::ZoneScope::default_scope()],
            serial: tenko_core::dns::SerialPolicy::Counter,
            soa: SoaDefaults::new(
                name("ns1.corp.example.test"),
                name("hostmaster.corp.example.test"),
            ),
            transfer: tenko_core::dns::TransferPolicy::default(),
            update: UpdatePolicy {
                allowed,
                require_tsig: true,
                may_replace_ipam: false,
                dhcp: None,
                kerberos,
            },
            dnssec: tenko_core::dns::DnssecPolicy::default(),
            source: None,
            reverse_of: None,
            catalog: false,
            description: None,
            created: stamp.clone(),
            updated: stamp,
        }
    }

    fn gss(principal: &str) -> Signer {
        Signer::Gss(GssIdentity {
            principal: PrincipalName::parse(principal).expect("principal"),
            sid: None,
            groups: Vec::new(),
        })
    }

    /// DNS-28, TGL-09: a GSS-TSIG update needs the zone's Kerberos settings with the
    /// principal's realm and a `kerberos` entry naming the principal; a prefix entry alone
    /// does not stand for a signature, and the entry's pattern and prefix hold.
    #[test]
    fn dns_28_a_gss_tsig_update_is_checked_by_its_principal() {
        let realm = Realm::new("CORP.EXAMPLE.TEST").expect("realm");
        let computers = Acl {
            id: AclId::generate(),
            name: "computers".to_owned(),
            entries: vec![AclEntry::Kerberos {
                realm: realm.clone(),
                principal: Some("*$".to_owned()),
                from: Some("192.0.2.0/24".parse().expect("prefix")),
                deny: false,
            }],
            description: None,
        };
        let lan = Acl {
            id: AclId::generate(),
            name: "lan".to_owned(),
            entries: vec![AclEntry::Prefix {
                prefix: "192.0.2.0/24".parse().expect("prefix"),
                deny: false,
            }],
            description: None,
        };
        let find = |id: AclId| [&computers, &lan].into_iter().find(|acl| acl.id == id);
        let inside: IpAddr = "192.0.2.10".parse().expect("address");
        let outside: IpAddr = "198.51.100.10".parse().expect("address");
        let kerberos = Some(KerberosUpdate::for_realm(realm));
        let secure = zone(kerberos.clone(), vec![computers.id]);
        let std = UpdateProfile::Standard;
        let pc01 = gss("pc01$@CORP.EXAMPLE.TEST");
        assert_eq!(check(&secure, find, std, inside, &pc01), Ok(()));
        let alice = gss("alice@CORP.EXAMPLE.TEST");
        assert_eq!(
            check(&secure, find, std, inside, &alice),
            Err("no update access list allows the principal, or one denies it"),
            "the pattern"
        );
        assert_eq!(
            check(&secure, find, std, outside, &pc01),
            Err("no update access list allows the principal, or one denies it"),
            "the prefix"
        );
        let other = gss("pc01$@OTHER.EXAMPLE.TEST");
        assert_eq!(
            check(&secure, find, std, inside, &other),
            Err("the zone takes no GSS-TSIG updates from the principal's realm"),
            "the realm"
        );
        assert_eq!(
            check(&secure, find, std, inside, &Signer::None),
            Err("no update access list allows the client, or one denies it"),
            "unsigned"
        );
        let without = zone(None, vec![computers.id]);
        assert_eq!(
            check(&without, find, std, inside, &pc01),
            Err("the zone takes no GSS-TSIG updates (it has no Kerberos settings)"),
            "no Kerberos settings"
        );
        let by_address = zone(kerberos, vec![lan.id]);
        assert_eq!(
            check(&by_address, find, std, inside, &pc01),
            Err("the principal is not named by a Kerberos entry of the zone's update access lists"),
            "a prefix entry allows the address but names no principal"
        );
        assert_eq!(
            check(&by_address, find, UpdateProfile::Lab, inside, &pc01),
            Ok(()),
            "the Lab profile requires no signature"
        );
    }
}
