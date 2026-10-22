//! Who may update a zone (DNS-11, TGL-09, RFC 2136 section 3.3, RFC 3007).
//!
//! An update passes when the zone is a primary zone the node serves, an access list of
//! `update.allowed` allows the client with its address and its TSIG key (none means
//! nobody; the first matching entry of a list decides), and, where a signature is
//! required, the request is signed with a key that an allowing `key` entry of the lists
//! names. Whether a signature is required follows the zone's `require_tsig` under the
//! security profile in force (TGL-09):
//!
//! | Profile | Without `update.allowed` | Signature |
//! |---|---|---|
//! | Home | no external update at all | as the zone says (`require_tsig`, on by default) |
//! | Standard | no update | as the zone says (on by default: TSIG) |
//! | Hardened | no update | always; an unsigned update is refused even when the zone switched `require_tsig` off (GSS-TSIG is Phase 4) |
//! | Lab | no update | never required: an unsigned update from an address the lists allow passes; a list that names only keys still asks for its key |
//!
//! A zone overrides the default by naming access lists in `update.allowed`, and in Home
//! and Standard by switching `require_tsig` off; Hardened and Lab hold their rule for the
//! signature whatever the zone says. TSIG failures (BADKEY, BADSIG, BADTIME) are answered
//! before this check, as NOTAUTH with the TSIG error.

use std::{
    net::IpAddr,
    sync::atomic::{AtomicU8, Ordering},
};

use tenko_core::dns::{Acl, AclEntry, AclId, KeyName, Zone, ZoneKind};

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

/// Why an update is refused: the text of the extended error and the audit record.
pub type Refusal = &'static str;

/// Checks whether a client at `client`, signed with `key` if any, may update `zone` under
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
    key: Option<&KeyName>,
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
    if !lists.iter().any(|list| list.allows(client, key)) {
        return Err("the client is not in the zone's update access lists");
    }
    if require_tsig(zone, profile) {
        let Some(key) = key else {
            return Err(if profile == UpdateProfile::Hardened {
                "unsigned updates are refused (Hardened profile); sign with a TSIG key"
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

    /// TGL-09: the profile defaults of the signature.
    #[test]
    fn the_profiles_decide_the_signature() {
        let (signed, lan) = lists();
        let find = |id: AclId| [&signed, &lan].into_iter().find(|acl| acl.id == id);
        let client: IpAddr = "192.0.2.10".parse().expect("address");
        let outside: IpAddr = "198.51.100.10".parse().expect("address");
        let key = name("update.example.test");
        let none = zone(UpdatePolicy::default());
        for profile in [
            UpdateProfile::Home,
            UpdateProfile::Standard,
            UpdateProfile::Hardened,
            UpdateProfile::Lab,
        ] {
            assert!(
                check(&none, find, profile, client, Some(&key)).is_err(),
                "none means nobody"
            );
        }
        let both = zone(UpdatePolicy {
            allowed: vec![signed.id, lan.id],
            require_tsig: true,
            may_replace_ipam: false,
            dhcp: None,
        });
        assert!(check(&both, find, UpdateProfile::Standard, client, Some(&key)).is_ok());
        assert!(check(&both, find, UpdateProfile::Standard, outside, Some(&key)).is_ok());
        assert!(check(&both, find, UpdateProfile::Standard, client, None).is_err());
        assert!(check(&both, find, UpdateProfile::Lab, client, None).is_ok());
        assert!(
            check(&both, find, UpdateProfile::Lab, outside, None).is_err(),
            "outside the lists"
        );
        let unsigned = zone(UpdatePolicy {
            allowed: vec![lan.id],
            require_tsig: false,
            may_replace_ipam: false,
            dhcp: None,
        });
        assert!(check(&unsigned, find, UpdateProfile::Home, client, None).is_ok());
        assert!(check(&unsigned, find, UpdateProfile::Hardened, client, None).is_err());
        let other = name("other.example.test");
        assert!(
            check(&both, find, UpdateProfile::Hardened, client, Some(&other)).is_err(),
            "a key the lists do not name"
        );
        let mut secondary = both.clone();
        secondary.kind = ZoneKind::Secondary;
        assert!(check(&secondary, find, UpdateProfile::Lab, client, Some(&key)).is_err());
    }
}
