//! Node roles (ADR 0004): every node runs the same binary with a chosen set of roles.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

/// A role that a Tenko node can run.
///
/// Every node ships the same binary; the operator chooses which roles it runs at start-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Control plane: API, UI, replicated store, and job engine.
    Controller,
    /// DNS data plane: authoritative, forwarding, and caching service.
    Dns,
    /// DHCP data plane: DHCPv4 and DHCPv6 service.
    Dhcp,
    /// Discovery probe: passive and active network scanning.
    Probe,
}

impl Role {
    /// Every role, in canonical order.
    pub const ALL: [Role; 4] = [Role::Controller, Role::Dns, Role::Dhcp, Role::Probe];

    /// Canonical lowercase name, as used on the command line and in configuration.
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Controller => "controller",
            Role::Dns => "dns",
            Role::Dhcp => "dhcp",
            Role::Probe => "probe",
        }
    }

    /// One-line human-readable description of the role.
    pub const fn description(self) -> &'static str {
        match self {
            Role::Controller => "control plane: API, UI, replicated store, job engine",
            Role::Dns => "DNS data plane: authoritative, forwarder, cache",
            Role::Dhcp => "DHCP data plane: DHCPv4 and DHCPv6",
            Role::Probe => "discovery probe: passive and active scanning, SNMP",
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Role::Controller => 0b0001,
            Role::Dns => 0b0010,
            Role::Dhcp => 0b0100,
            Role::Probe => 0b1000,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Role {
    type Err = ParseRoleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let name = s.trim();
        Role::ALL
            .into_iter()
            .find(|role| role.as_str().eq_ignore_ascii_case(name))
            .ok_or_else(|| ParseRoleError::Unknown(name.to_owned()))
    }
}

/// Error returned when a role name or a role list cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseRoleError {
    /// The name does not match any known role.
    #[error("unknown role `{0}` (expected one of: controller, dns, dhcp, probe)")]
    Unknown(String),
    /// The list contains no roles.
    #[error("the role list is empty")]
    Empty,
}

/// A set of [`Role`]s.
///
/// Parses from a comma-separated list such as `controller,dns` or the keyword `all`, and
/// displays in canonical order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RoleSet(u8);

impl RoleSet {
    /// The empty set.
    pub const EMPTY: RoleSet = RoleSet(0);

    /// The set of every role.
    pub const ALL: RoleSet = RoleSet(0b1111);

    /// Adds a role to the set.
    pub fn insert(&mut self, role: Role) {
        self.0 |= role.bit();
    }

    /// Returns `true` if the set contains `role`.
    pub const fn contains(self, role: Role) -> bool {
        (self.0 & role.bit()) != 0
    }

    /// Returns `true` if the set contains no roles.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Iterates over the roles in the set, in canonical order.
    pub fn roles(self) -> impl Iterator<Item = Role> {
        Role::ALL.into_iter().filter(move |&r| self.contains(r))
    }
}

impl FromIterator<Role> for RoleSet {
    fn from_iter<I: IntoIterator<Item = Role>>(iter: I) -> Self {
        let mut set = RoleSet::EMPTY;
        for role in iter {
            set.insert(role);
        }
        set
    }
}

impl fmt::Display for RoleSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, role) in self.roles().enumerate() {
            if index > 0 {
                f.write_str(",")?;
            }
            f.write_str(role.as_str())?;
        }
        Ok(())
    }
}

impl FromStr for RoleSet {
    type Err = ParseRoleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let list = s.trim();
        if list.eq_ignore_ascii_case("all") {
            return Ok(RoleSet::ALL);
        }
        let mut set = RoleSet::EMPTY;
        for name in list.split(',').map(str::trim) {
            if !name.is_empty() {
                set.insert(name.parse()?);
            }
        }
        if set.is_empty() {
            Err(ParseRoleError::Empty)
        } else {
            Ok(set)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_names_round_trip() {
        for role in Role::ALL {
            assert_eq!(role.as_str().parse::<Role>(), Ok(role));
            assert_eq!(role.to_string(), role.as_str());
        }
        assert_eq!(" DHCP ".parse::<Role>(), Ok(Role::Dhcp));
    }

    #[test]
    fn unknown_role_is_rejected() {
        assert_eq!(
            "ntp".parse::<Role>(),
            Err(ParseRoleError::Unknown("ntp".to_owned()))
        );
    }

    #[test]
    fn role_serializes_as_lowercase_name() {
        let json = serde_json::to_string(&Role::Controller).expect("serialize role");
        assert_eq!(json, "\"controller\"");
        let role: Role = serde_json::from_str("\"probe\"").expect("deserialize role");
        assert_eq!(role, Role::Probe);
    }

    #[test]
    fn role_set_parses_lists_and_all() {
        let set: RoleSet = "dhcp, controller".parse().expect("valid list");
        assert!(set.contains(Role::Controller));
        assert!(set.contains(Role::Dhcp));
        assert!(!set.contains(Role::Dns));
        assert!(!set.contains(Role::Probe));
        assert_eq!(set.to_string(), "controller,dhcp");

        assert_eq!("all".parse::<RoleSet>(), Ok(RoleSet::ALL));
        assert_eq!(RoleSet::ALL.roles().collect::<Vec<_>>(), Role::ALL);
    }

    #[test]
    fn role_set_rejects_empty_and_unknown() {
        assert_eq!("".parse::<RoleSet>(), Err(ParseRoleError::Empty));
        assert_eq!(" , ".parse::<RoleSet>(), Err(ParseRoleError::Empty));
        assert!("dns,ntp".parse::<RoleSet>().is_err());
    }

    #[test]
    fn role_set_collects_from_iterator() {
        let set: RoleSet = [Role::Probe, Role::Dns, Role::Probe].into_iter().collect();
        assert_eq!(set.to_string(), "dns,probe");
        assert!(RoleSet::EMPTY.is_empty());
        assert!(RoleSet::default().is_empty());
    }
}
