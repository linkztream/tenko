//! Classes, policies and MAC filters (plan section 2.4, P3-Q12; DHCP-03, DHCP-08, TGL-17).
//!
//! A [`Class`] is a named match on a request: it matches when any of its [`Match`]es
//! holds. A [`Policy`] is an ordered rule of one scope or of the server: its [`Condition`]
//! joins terms (a class, a negated class, a single field match) with AND or OR, as Windows
//! DHCP policies do, and its [`PolicyAction`] restricts the address range, sets the lease
//! time and the DDNS behaviour; the policy's options are the option set it owns
//! (`OptionOwner::Policy`). The condition is a tree of depth two (the policy's AND or OR
//! over its terms, a class's OR over its matches), which is what the Windows export of
//! Phase 4 holds and what Kea's `test` expressions of the WP9.3 export express.
//!
//! A [`Filter`] allows or denies MAC addresses server-wide (DHCP-08): a deny entry drops
//! the client everywhere, and on a scope marked `restricted` only clients that match an
//! allow entry are served (TGL-17 makes Hardened scopes restricted by default).

use std::{fmt, net::IpAddr, str::FromStr};

use serde::{Deserialize, Serialize};
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{RefOr, schema::Schema},
};

use super::{
    ClassId, DdnsPolicy, DhcpError, FilterId, LeaseTimes, PolicyId, codes, option::valid_name,
};
use crate::{
    error::InvalidValue,
    id::PrefixId,
    ipam::Stamp,
    serde_util::{HexBytes, string_schema},
};

/// The most matches of a class and terms of a policy.
pub const MAX_TERMS: usize = 64;

/// A MAC address with wildcard octets (DHCP-03, DHCP-08): six octets in hexadecimal
/// separated by `:` or `-`, any of them `*`, or fewer octets followed by a final `*` that
/// covers the rest (`00:00:5e:00:53:*`, `00-00-5E-*`). Written canonical: lowercase,
/// colons, six positions.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacPattern {
    octets: [u8; 6],
    mask: [u8; 6],
}

impl MacPattern {
    /// Parses a pattern.
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] when the text is not a pattern.
    pub fn new(text: &str) -> Result<Self, InvalidValue> {
        let invalid = || {
            InvalidValue::new(
                "MAC pattern",
                text,
                "six hexadecimal octets, any of them `*`, or a prefix ending in `*`",
            )
        };
        let parts: Vec<&str> = text.trim().split([':', '-']).collect();
        if parts.is_empty() || parts.len() > 6 {
            return Err(invalid());
        }
        let open_end = parts.len() < 6;
        if open_end && parts.last() != Some(&"*") {
            return Err(invalid());
        }
        let mut octets = [0u8; 6];
        let mut mask = [0u8; 6];
        for (index, part) in parts.iter().enumerate() {
            if *part == "*" {
                continue;
            }
            if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid());
            }
            octets[index] = u8::from_str_radix(part, 16).map_err(|_| invalid())?;
            mask[index] = 0xff;
        }
        Ok(Self { octets, mask })
    }

    /// A pattern that matches exactly one address.
    pub const fn exact(octets: [u8; 6]) -> Self {
        Self {
            octets,
            mask: [0xff; 6],
        }
    }

    /// Whether `mac` matches.
    pub fn matches(&self, mac: &[u8; 6]) -> bool {
        (0..6).all(|i| mac[i] & self.mask[i] == self.octets[i])
    }

    /// Whether the pattern has no wildcard.
    pub fn is_exact(&self) -> bool {
        self.mask == [0xff; 6]
    }
}

impl fmt::Display for MacPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for i in 0..6 {
            if i > 0 {
                f.write_str(":")?;
            }
            if self.mask[i] == 0 {
                f.write_str("*")?;
            } else {
                write!(f, "{:02x}", self.octets[i])?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for MacPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacPattern({self})")
    }
}

impl FromStr for MacPattern {
    type Err = InvalidValue;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for MacPattern {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for MacPattern {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(&text).map_err(serde::de::Error::custom)
    }
}

impl PartialSchema for MacPattern {
    fn schema() -> RefOr<Schema> {
        string_schema("MAC address pattern, `*` for any octet (`00:00:5e:00:53:*`)")
    }
}

impl ToSchema for MacPattern {}

/// One test on a request (plan section 2.4).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Match {
    /// The vendor class identifier (option 60), exactly or as a prefix (`MSFT`,
    /// `PXEClient:Arch:00007`).
    VendorClass {
        /// The text.
        value: String,
        /// Whether `value` is a prefix of the client's option 60.
        #[serde(default)]
        prefix: bool,
    },
    /// One of the user classes of option 77 (RFC 3004).
    UserClass {
        /// The class data as text.
        value: String,
    },
    /// The client's hardware address.
    Mac {
        /// The pattern.
        pattern: MacPattern,
    },
    /// The client identifier (option 61).
    ClientId {
        /// The identifier octets.
        value: HexBytes,
    },
    /// The relay agent's circuit-id (option 82, sub-option 1).
    CircuitId {
        /// The octets.
        value: HexBytes,
    },
    /// The relay agent's remote-id (option 82, sub-option 2).
    RemoteId {
        /// The octets.
        value: HexBytes,
    },
    /// The client system architecture (option 93, RFC 4578): 0 BIOS, 7 and 9 UEFI x64,
    /// 16 UEFI HTTP boot x64.
    Architecture {
        /// The architecture type.
        code: u16,
    },
    /// The host name the client sent (option 12), exactly or as a prefix, ignoring case.
    HostName {
        /// The name.
        value: String,
        /// Whether `value` is a prefix.
        #[serde(default)]
        prefix: bool,
    },
}

impl Match {
    fn validate(&self, field: &str) -> Result<(), DhcpError> {
        let invalid = |reason: &str| Err(DhcpError::invalid(codes::CLASS_INVALID, field, reason));
        match self {
            Self::VendorClass { value, .. }
            | Self::UserClass { value }
            | Self::HostName { value, .. }
                if value.is_empty() || value.len() > 255 =>
            {
                invalid("the text is 1 to 255 characters")
            }
            Self::ClientId { value } | Self::CircuitId { value } | Self::RemoteId { value }
                if value.0.is_empty() || value.0.len() > 255 =>
            {
                invalid("the value is 1 to 255 octets")
            }
            _ => Ok(()),
        }
    }
}

/// A named match on requests (`dhcp.classes`, DHCP-03): it matches when any of its
/// matches holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Class {
    /// Identifier.
    pub id: ClassId,
    /// The name, unique: 1 to 64 characters of `a-z`, `0-9` and `-`.
    pub name: String,
    /// The matches, joined by OR.
    pub matches: Vec<Match>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Creation.
    pub created: Stamp,
    /// Last change.
    pub updated: Stamp,
}

impl Class {
    /// Checks a class: the name follows the rule; one to [`MAX_TERMS`] matches, each with
    /// a value of the allowed length.
    ///
    /// # Errors
    ///
    /// `dhcp.class.invalid` naming the field.
    pub fn validate(&self) -> Result<(), DhcpError> {
        if !valid_name(&self.name) {
            return Err(DhcpError::invalid(
                codes::CLASS_INVALID,
                "name",
                "1 to 64 characters of a-z, 0-9 and -",
            ));
        }
        if self.matches.is_empty() || self.matches.len() > MAX_TERMS {
            return Err(DhcpError::invalid(
                codes::CLASS_INVALID,
                "matches",
                "a class has 1 to 64 matches",
            ));
        }
        for (index, item) in self.matches.iter().enumerate() {
            item.validate(&format!("matches[{index}]"))?;
        }
        Ok(())
    }
}

/// How the terms of a condition are joined.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Join {
    /// Every term holds.
    And,
    /// At least one term holds.
    Or,
}

/// One term of a policy's condition.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Term {
    /// The request is in the class.
    Class(ClassId),
    /// The request is not in the class.
    NotClass(ClassId),
    /// A field matches.
    Match(Match),
    /// A field does not match.
    NotMatch(Match),
}

/// The condition of a policy: terms joined by AND or OR.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct Condition {
    /// How the terms are joined.
    pub join: Join,
    /// The terms, 1 to [`MAX_TERMS`].
    pub terms: Vec<Term>,
}

/// An address range inside a scope, inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct AddressRange {
    /// The first address.
    #[schema(value_type = String, example = "192.0.2.100")]
    pub first: IpAddr,
    /// The last address.
    #[schema(value_type = String, example = "192.0.2.149")]
    pub last: IpAddr,
}

impl AddressRange {
    /// Whether the range is ordered and of one family.
    pub fn is_ordered(&self) -> bool {
        self.first.is_ipv4() == self.last.is_ipv4() && self.first <= self.last
    }

    /// Whether `address` lies in the range.
    pub fn contains(&self, address: IpAddr) -> bool {
        self.first <= address && address <= self.last
    }
}

/// What a matching policy does (plan section 3.1). Each part is applied by the first
/// matching policy that sets it; the policy's options are its option set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PolicyAction {
    /// Restricts the clients to this range of the scope's pools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<AddressRange>,
    /// The lease times for the clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<LeaseTimes>,
    /// The DDNS behaviour for the clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ddns: Option<DdnsPolicy>,
}

/// An ordered rule of a scope or of the server (`dhcp.policies`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Policy {
    /// Identifier.
    pub id: PolicyId,
    /// The name, unique in its scope.
    pub name: String,
    /// The scope; none for a server-level policy, which applies after the scope's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<PrefixId>,
    /// The processing order within the scope, lowest first.
    pub order: u32,
    /// Whether the policy applies.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// When the policy applies.
    pub condition: Condition,
    /// What it does.
    #[serde(default)]
    pub action: PolicyAction,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Creation.
    pub created: Stamp,
    /// Last change.
    pub updated: Stamp,
}

const fn yes() -> bool {
    true
}

impl Policy {
    /// Checks a policy: the name follows the rule; one to [`MAX_TERMS`] terms with valid
    /// matches; an ordered range; valid lease times and DDNS settings.
    ///
    /// # Errors
    ///
    /// `dhcp.policy.invalid` naming the field (the codes of the nested lease and DDNS
    /// checks for those parts).
    pub fn validate(&self) -> Result<(), DhcpError> {
        let invalid = |field: &str, reason: &str| {
            Err(DhcpError::invalid(codes::POLICY_INVALID, field, reason))
        };
        if !valid_name(&self.name) {
            return invalid("name", "1 to 64 characters of a-z, 0-9 and -");
        }
        let terms = &self.condition.terms;
        if terms.is_empty() || terms.len() > MAX_TERMS {
            return invalid("condition.terms", "a condition has 1 to 64 terms");
        }
        for (index, term) in terms.iter().enumerate() {
            if let Term::Match(item) | Term::NotMatch(item) = term {
                item.validate(&format!("condition.terms[{index}]"))
                    .map_err(|_| {
                        DhcpError::invalid(
                            codes::POLICY_INVALID,
                            "condition.terms",
                            "a match value has the wrong length",
                        )
                    })?;
            }
        }
        if let Some(range) = &self.action.range
            && !range.is_ordered()
        {
            return invalid("action.range", "the first address is not after the last");
        }
        if let Some(lease) = &self.action.lease {
            lease.validate("action.lease")?;
        }
        if let Some(ddns) = &self.action.ddns {
            ddns.validate("action.ddns")?;
        }
        Ok(())
    }
}

/// Whether a filter entry allows or denies.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FilterKind {
    /// Clients that match may be served by restricted scopes.
    Allow,
    /// Clients that match are never served.
    Deny,
}

/// A server-wide MAC filter entry (`dhcp.filters`, DHCP-08).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Filter {
    /// Identifier.
    pub id: FilterId,
    /// The addresses.
    pub mac: MacPattern,
    /// Allow or deny.
    pub kind: FilterKind,
    /// Why the entry exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Creation.
    pub created: Stamp,
    /// Last change.
    pub updated: Stamp,
}

impl Filter {
    /// Checks a filter: the note is at most 1,024 characters.
    ///
    /// # Errors
    ///
    /// `dhcp.filter.invalid`.
    pub fn validate(&self) -> Result<(), DhcpError> {
        if self.note.as_ref().is_some_and(|note| note.len() > 1024) {
            return Err(DhcpError::invalid(
                codes::FILTER_INVALID,
                "note",
                "at most 1024 characters",
            ));
        }
        Ok(())
    }
}

/// The verdict of the filters on a client (DHCP-08, TGL-17): denied anywhere, allowed on
/// restricted scopes, or neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterVerdict {
    /// A deny entry matches; the client is not served.
    Denied,
    /// An allow entry matches and no deny entry does.
    Allowed,
    /// No entry matches; served except on restricted scopes.
    Unlisted,
}

/// Applies the filters to a client's hardware address: deny wins over allow.
pub fn filter_verdict<'a>(
    filters: impl IntoIterator<Item = &'a Filter>,
    mac: &[u8; 6],
) -> FilterVerdict {
    let mut verdict = FilterVerdict::Unlisted;
    for filter in filters {
        if filter.mac.matches(mac) {
            match filter.kind {
                FilterKind::Deny => return FilterVerdict::Denied,
                FilterKind::Allow => verdict = FilterVerdict::Allowed,
            }
        }
    }
    verdict
}
