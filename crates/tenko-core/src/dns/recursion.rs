//! The model of the recursive resolver (recursion plan section 3.1, ADR 0021): trust
//! anchors with their RFC 5011 states, negative trust anchors (RFC 7646), the resolution
//! mode of views and forwarding rules, the security state of an answer with its wire
//! rendering (RFC 4035 section 3.2, RFC 6840 section 5.8), and the extended DNS errors of
//! RFC 8914 the resolver and the validator answer with.
//!
//! The rows are plain data and rules, like the rest of [`super`]: the trust anchor service
//! and the negative trust anchor routes (WP10.2, WP10.4) write them through the store; the
//! engine reads them through its catalog and never writes.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{DnsError, DnsName, codes};
use crate::{principal::Principal, serde_util::HexBytes, timestamp::Timestamp};

crate::id_type! {
    /// Identifier of a negative trust anchor (RFC 7646).
    NtaId,
}

/// The longest lifetime of a negative trust anchor: seven days (recursion plan section
/// 2.3, RFC 7646 section 2 recommends a week at most).
pub const NTA_MAX_SECS: u64 = 7 * 86_400;

const NTA_MAX: std::time::Duration = std::time::Duration::from_secs(NTA_MAX_SECS);

/// The longest reason of a negative trust anchor, in characters.
pub const NTA_REASON_MAX: usize = 500;

/// The most keys one trust anchor row holds (a zone in a roll holds two or three).
pub const ANCHOR_KEYS_MAX: usize = 16;

/// The DNSKEY flag of a zone key (RFC 4034 section 2.1.1).
pub const DNSKEY_ZONE: u16 = 0x0100;

/// The DNSKEY flag of a revoked key (RFC 5011 section 3).
pub const DNSKEY_REVOKE: u16 = 0x0080;

/// The DNSKEY flag of a secure entry point (RFC 4034 section 2.1.1).
pub const DNSKEY_SEP: u16 = 0x0001;

// ---------------------------------------------------------------------------------------
// Resolution modes

/// How a view's clients get names outside the zones and the forwarding rules (recursion
/// plan section 2.7). A view without one follows the profile's default (REC-Q2: recurse in
/// every profile).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionMode {
    /// Resolve iteratively from the root hints (DNS-03).
    Recurse,
    /// Forward to the default forwarder of the configuration file (`[dns] forwarders`).
    Forward,
    /// Answer REFUSED.
    Refuse,
}

impl ResolutionMode {
    /// Every mode.
    pub const ALL: [ResolutionMode; 3] = [
        ResolutionMode::Recurse,
        ResolutionMode::Forward,
        ResolutionMode::Refuse,
    ];

    /// The stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            ResolutionMode::Recurse => "recurse",
            ResolutionMode::Forward => "forward",
            ResolutionMode::Refuse => "refuse",
        }
    }
}

impl fmt::Display for ResolutionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ResolutionMode {
    type Err = DnsError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|mode| mode.as_str() == text)
            .ok_or_else(|| {
                DnsError::invalid(
                    codes::VIEW_INVALID,
                    "resolution",
                    "recurse, forward or refuse",
                )
            })
    }
}

/// What a forwarding rule does with the names under its suffix (recursion plan section
/// 2.7).
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RuleMode {
    /// Ask the rule's upstreams (Phase 2's behaviour).
    #[default]
    Forward,
    /// Resolve iteratively; the rule names no upstream.
    Recurse,
}

impl RuleMode {
    /// The stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            RuleMode::Forward => "forward",
            RuleMode::Recurse => "recurse",
        }
    }

    /// Whether this is the default mode (for `skip_serializing_if`).
    pub fn is_forward(&self) -> bool {
        *self == RuleMode::Forward
    }
}

// ---------------------------------------------------------------------------------------
// The security state of an answer

/// The DNSSEC state of an answer (RFC 4033 section 5, RFC 4035 section 4.3), shared by the
/// cache entry, its listing and the query log.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SecurityState {
    /// A chain of trust from an anchor proves the data (or its absence).
    Secure,
    /// A proof shows the data needs no signature (an unsigned delegation, an unsupported
    /// algorithm, a negative trust anchor).
    Insecure,
    /// The data should be signed and the proof fails.
    Bogus,
    /// No trust anchor covers the name.
    Indeterminate,
    /// Not validated: validation is off (Lab) or the answer came before validation existed.
    #[default]
    Unvalidated,
}

/// The flags of a client's query that decide how an answer is rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientFlags {
    /// The DO bit of the client's OPT record (RFC 3225).
    pub dnssec_ok: bool,
    /// The AD bit of the client's query (RFC 6840 section 5.7).
    pub ad: bool,
    /// The CD bit of the client's query (RFC 4035 section 3.2.2).
    pub cd: bool,
}

/// How an answer of a [`SecurityState`] goes to one client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rendering {
    /// SERVFAIL with no records instead of the data.
    pub servfail: bool,
    /// The AD bit.
    pub ad: bool,
    /// The DNSSEC records (RRSIG anywhere, NSEC and NSEC3 in the authority section) are
    /// included.
    pub dnssec_records: bool,
    /// The extended error in the OPT record when the client sent EDNS.
    pub ede: Option<ExtendedError>,
}

impl SecurityState {
    /// Every state.
    pub const ALL: [SecurityState; 5] = [
        SecurityState::Secure,
        SecurityState::Insecure,
        SecurityState::Bogus,
        SecurityState::Indeterminate,
        SecurityState::Unvalidated,
    ];

    /// The stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            SecurityState::Secure => "secure",
            SecurityState::Insecure => "insecure",
            SecurityState::Bogus => "bogus",
            SecurityState::Indeterminate => "indeterminate",
            SecurityState::Unvalidated => "unvalidated",
        }
    }

    /// The rendering rules of recursion plan section 2.3:
    ///
    /// - `secure`: the data, AD set when the client asked with AD or DO;
    /// - `insecure`, `unvalidated`: the data, AD clear;
    /// - `bogus`: SERVFAIL with `ede` (6 "DNSSEC Bogus" when the validator named no more
    ///   precise one), unless the client set CD, which gets the data with AD clear and the
    ///   same extended error;
    /// - `indeterminate`: the data, AD clear, extended error 5 "DNSSEC Indeterminate".
    ///
    /// The DNSSEC records go to clients that set DO only (RFC 4035 section 3.2.1). The
    /// function is `const` and allocation-free: the cache calls it on the worker.
    pub const fn render(self, client: ClientFlags, ede: Option<ExtendedError>) -> Rendering {
        let (servfail, ad, ede) = match self {
            SecurityState::Secure => (false, client.ad || client.dnssec_ok, ede),
            SecurityState::Insecure | SecurityState::Unvalidated => (false, false, ede),
            SecurityState::Bogus => {
                let ede = match ede {
                    Some(ede) => ede,
                    None => ExtendedError::DNSSEC_BOGUS,
                };
                (!client.cd, false, Some(ede))
            }
            SecurityState::Indeterminate => {
                (false, false, Some(ExtendedError::DNSSEC_INDETERMINATE))
            }
        };
        Rendering {
            servfail,
            ad,
            dnssec_records: client.dnssec_ok && !servfail,
            ede,
        }
    }

    /// The compact form the cache stores.
    pub const fn to_u8(self) -> u8 {
        match self {
            SecurityState::Secure => 1,
            SecurityState::Insecure => 2,
            SecurityState::Bogus => 3,
            SecurityState::Indeterminate => 4,
            SecurityState::Unvalidated => 0,
        }
    }

    /// The state of a compact form; an unknown value is `unvalidated`.
    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => SecurityState::Secure,
            2 => SecurityState::Insecure,
            3 => SecurityState::Bogus,
            4 => SecurityState::Indeterminate,
            _ => SecurityState::Unvalidated,
        }
    }
}

impl fmt::Display for SecurityState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An extended DNS error's INFO-CODE (RFC 8914 section 4), with the codes the resolver and
/// the validator answer with as named constants.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(transparent)]
pub struct ExtendedError(pub u16);

impl ExtendedError {
    /// 0 Other Error.
    pub const OTHER: Self = Self(0);
    /// 1 Unsupported DNSKEY Algorithm (where it makes a chain bogus rather than insecure).
    pub const UNSUPPORTED_DNSKEY_ALGORITHM: Self = Self(1);
    /// 2 Unsupported DS Digest Type.
    pub const UNSUPPORTED_DS_DIGEST: Self = Self(2);
    /// 3 Stale Answer (RFC 8767).
    pub const STALE_ANSWER: Self = Self(3);
    /// 5 DNSSEC Indeterminate: no trust anchor covers the name.
    pub const DNSSEC_INDETERMINATE: Self = Self(5);
    /// 6 DNSSEC Bogus.
    pub const DNSSEC_BOGUS: Self = Self(6);
    /// 7 Signature Expired.
    pub const SIGNATURE_EXPIRED: Self = Self(7);
    /// 8 Signature Not Yet Valid.
    pub const SIGNATURE_NOT_YET_VALID: Self = Self(8);
    /// 9 DNSKEY Missing.
    pub const DNSKEY_MISSING: Self = Self(9);
    /// 10 RRSIGs Missing.
    pub const RRSIGS_MISSING: Self = Self(10);
    /// 11 No Zone Key Bit Set.
    pub const NO_ZONE_KEY_BIT_SET: Self = Self(11);
    /// 12 NSEC Missing.
    pub const NSEC_MISSING: Self = Self(12);
    /// 13 Cached Error (RFC 9520: a failure answered from the failure cache).
    pub const CACHED_ERROR: Self = Self(13);
    /// 15 Blocked (a block list).
    pub const BLOCKED: Self = Self(15);
    /// 17 Filtered (RPZ).
    pub const FILTERED: Self = Self(17);
    /// 18 Prohibited (the recursion access list).
    pub const PROHIBITED: Self = Self(18);
    /// 20 Not Authoritative.
    pub const NOT_AUTHORITATIVE: Self = Self(20);
    /// 21 Not Supported.
    pub const NOT_SUPPORTED: Self = Self(21);
    /// 22 No Reachable Authority: priming failed, the budget ran out, a delegation loop.
    pub const NO_REACHABLE_AUTHORITY: Self = Self(22);
    /// 23 Network Error.
    pub const NETWORK_ERROR: Self = Self(23);
    /// 27 Unsupported NSEC3 Iterations Value (RFC 9276: above 500 iterations).
    pub const UNSUPPORTED_NSEC3_ITERATIONS: Self = Self(27);

    /// The codes this model names, in code order.
    pub const NAMED: [ExtendedError; 21] = [
        Self::OTHER,
        Self::UNSUPPORTED_DNSKEY_ALGORITHM,
        Self::UNSUPPORTED_DS_DIGEST,
        Self::STALE_ANSWER,
        Self::DNSSEC_INDETERMINATE,
        Self::DNSSEC_BOGUS,
        Self::SIGNATURE_EXPIRED,
        Self::SIGNATURE_NOT_YET_VALID,
        Self::DNSKEY_MISSING,
        Self::RRSIGS_MISSING,
        Self::NO_ZONE_KEY_BIT_SET,
        Self::NSEC_MISSING,
        Self::CACHED_ERROR,
        Self::BLOCKED,
        Self::FILTERED,
        Self::PROHIBITED,
        Self::NOT_AUTHORITATIVE,
        Self::NOT_SUPPORTED,
        Self::NO_REACHABLE_AUTHORITY,
        Self::NETWORK_ERROR,
        Self::UNSUPPORTED_NSEC3_ITERATIONS,
    ];

    /// The INFO-CODE.
    pub const fn code(self) -> u16 {
        self.0
    }

    /// The RFC 8914 name of a named code.
    pub const fn name(self) -> Option<&'static str> {
        Some(match self.0 {
            0 => "Other Error",
            1 => "Unsupported DNSKEY Algorithm",
            2 => "Unsupported DS Digest Type",
            3 => "Stale Answer",
            5 => "DNSSEC Indeterminate",
            6 => "DNSSEC Bogus",
            7 => "Signature Expired",
            8 => "Signature Not Yet Valid",
            9 => "DNSKEY Missing",
            10 => "RRSIGs Missing",
            11 => "No Zone Key Bit Set",
            12 => "NSEC Missing",
            13 => "Cached Error",
            15 => "Blocked",
            17 => "Filtered",
            18 => "Prohibited",
            20 => "Not Authoritative",
            21 => "Not Supported",
            22 => "No Reachable Authority",
            23 => "Network Error",
            27 => "Unsupported NSEC3 Iterations Value",
            _ => return None,
        })
    }
}

// ---------------------------------------------------------------------------------------
// Trust anchors

/// The RFC 5011 state of a trust anchor key (RFC 5011 section 4).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AnchorState {
    /// Seen for the first time; the add hold-down has not started.
    Start,
    /// Seen with the SEP bit and validated; waiting for the add hold-down (30 days).
    AddPend,
    /// A trust anchor: validation uses it.
    Valid,
    /// A valid key that the zone's DNSKEY set no longer holds; still used.
    Missing,
    /// Revoked by the zone (the REVOKE bit, self-signed); no longer used.
    Revoked,
    /// Removed after the remove hold-down; kept as a row until the service forgets it.
    Removed,
}

impl AnchorState {
    /// Every state.
    pub const ALL: [AnchorState; 6] = [
        AnchorState::Start,
        AnchorState::AddPend,
        AnchorState::Valid,
        AnchorState::Missing,
        AnchorState::Revoked,
        AnchorState::Removed,
    ];

    /// The stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            AnchorState::Start => "start",
            AnchorState::AddPend => "add_pend",
            AnchorState::Valid => "valid",
            AnchorState::Missing => "missing",
            AnchorState::Revoked => "revoked",
            AnchorState::Removed => "removed",
        }
    }

    /// Whether validation trusts a key in this state (RFC 5011 section 4: Valid and
    /// Missing keys are trust anchors).
    pub const fn trusted(self) -> bool {
        matches!(self, AnchorState::Valid | AnchorState::Missing)
    }
}

/// Where a trust anchor key came from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AnchorSource {
    /// Shipped in the binary from the IANA file (RFC 7958).
    Shipped {
        /// The release that shipped it (the crate version).
        release: String,
    },
    /// Added by an operator.
    Operator,
    /// Learnt by RFC 5011 from the zone's DNSKEY set.
    Rfc5011,
}

/// The key material of a trust anchor key, in wire form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AnchorData {
    /// A DS record's data (RFC 4034 section 5.1): key tag, algorithm, digest type, digest.
    Ds {
        /// The record data.
        #[schema(value_type = String)]
        rdata: HexBytes,
    },
    /// A DNSKEY record's data (RFC 4034 section 2.1): flags, protocol, algorithm, key.
    Dnskey {
        /// The record data.
        #[schema(value_type = String)]
        rdata: HexBytes,
    },
}

/// One key of a trust anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AnchorKey {
    /// The key tag (RFC 4034 appendix B).
    pub key_tag: u16,
    /// The DNSSEC algorithm number.
    pub algorithm: u8,
    /// The DS digest type; present exactly for a DS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_type: Option<u8>,
    /// The key material.
    pub data: AnchorData,
    /// The RFC 5011 state.
    pub state: AnchorState,
    /// Where it came from.
    pub source: AnchorSource,
    /// When it was added.
    pub added_at: Timestamp,
    /// When it entered its state (the add hold-down counts from here).
    pub state_since: Timestamp,
    /// When the zone's DNSKEY set last held it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<Timestamp>,
}

impl AnchorKey {
    /// Checks the key: its material parses and agrees with the key tag, the algorithm and
    /// the digest type.
    ///
    /// # Errors
    ///
    /// `dns.trust_anchor.invalid` naming `keys`.
    pub fn validate(&self) -> Result<(), DnsError> {
        let invalid = |reason: &str| {
            Err(DnsError::invalid(
                codes::TRUST_ANCHOR_INVALID,
                "keys",
                reason,
            ))
        };
        match (&self.data, self.digest_type) {
            (AnchorData::Ds { rdata }, Some(digest_type)) => {
                let rdata = &rdata.0;
                if rdata.len() < 5 {
                    return invalid(
                        "a DS holds a key tag, an algorithm, a digest type and a digest",
                    );
                }
                if u16::from_be_bytes([rdata[0], rdata[1]]) != self.key_tag
                    || rdata[2] != self.algorithm
                    || rdata[3] != digest_type
                {
                    return invalid("the DS does not match the key tag, algorithm or digest type");
                }
                let expected = match digest_type {
                    1 => Some(20),
                    2 => Some(32),
                    4 => Some(48),
                    _ => None,
                };
                if expected.is_some_and(|len| rdata.len() - 4 != len) {
                    return invalid("the digest has the wrong length for its type");
                }
            }
            (AnchorData::Dnskey { rdata }, None) => {
                let rdata = &rdata.0;
                if rdata.len() < 5 {
                    return invalid("a DNSKEY holds flags, a protocol, an algorithm and a key");
                }
                let flags = u16::from_be_bytes([rdata[0], rdata[1]]);
                if flags & DNSKEY_ZONE == 0 {
                    return invalid("a trust anchor DNSKEY has the zone key bit set");
                }
                if rdata[2] != 3 || rdata[3] != self.algorithm {
                    return invalid("the DNSKEY's protocol is 3 and its algorithm the key's");
                }
                if key_tag(rdata) != self.key_tag {
                    return invalid("the key tag is not the DNSKEY's");
                }
            }
            (AnchorData::Ds { .. }, None) => return invalid("a DS names its digest type"),
            (AnchorData::Dnskey { .. }, Some(_)) => {
                return invalid("a DNSKEY has no digest type");
            }
        }
        if self.state_since < self.added_at {
            return invalid("a key enters its state after it was added");
        }
        Ok(())
    }
}

/// The key tag of a DNSKEY record's data (RFC 4034 appendix B, algorithms other than 1).
pub fn key_tag(dnskey_rdata: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for (index, &byte) in dnskey_rdata.iter().enumerate() {
        sum += if index % 2 == 0 {
            u32::from(byte) << 8
        } else {
            u32::from(byte)
        };
    }
    sum += (sum >> 16) & 0xffff;
    u16::try_from(sum & 0xffff).unwrap_or_default()
}

/// The trust anchors of one zone (`dns.trust_anchors`, one row per zone; the root by
/// default, an operator's anchor for a private zone beside it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TrustAnchor {
    /// The zone.
    pub zone: DnsName,
    /// The keys, 1 to 16.
    pub keys: Vec<AnchorKey>,
    /// When the trust anchor service last asked the zone's DNSKEY set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_query: Option<Timestamp>,
    /// When it asks next (RFC 5011 section 2.3: the active refresh).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_query: Option<Timestamp>,
}

impl TrustAnchor {
    /// Checks a row: 1 to 16 keys, each of which parses, no key twice (the same tag,
    /// algorithm and material), and outside the Lab profile (`lab` false) at least one
    /// trusted key in the root's row.
    ///
    /// # Errors
    ///
    /// `dns.trust_anchor.invalid` naming the field.
    pub fn validate(&self, lab: bool) -> Result<(), DnsError> {
        let invalid = |field: &str, reason: &str| {
            Err(DnsError::invalid(
                codes::TRUST_ANCHOR_INVALID,
                field,
                reason,
            ))
        };
        if self.keys.is_empty() || self.keys.len() > ANCHOR_KEYS_MAX {
            return invalid("keys", "a trust anchor has 1 to 16 keys");
        }
        for (index, key) in self.keys.iter().enumerate() {
            key.validate()?;
            if self.keys[..index].iter().any(|other| {
                other.key_tag == key.key_tag
                    && other.algorithm == key.algorithm
                    && other.data == key.data
            }) {
                return invalid("keys", "a key appears twice");
            }
        }
        if self.zone.is_root() && !lab && !self.keys.iter().any(|key| key.state.trusted()) {
            return invalid(
                "keys",
                "the root keeps a trusted key outside the Lab profile",
            );
        }
        if let (Some(last), Some(next)) = (self.last_query, self.next_query)
            && next < last
        {
            return invalid("next_query", "the next query is after the last one");
        }
        Ok(())
    }

    /// The keys validation trusts now.
    pub fn trusted(&self) -> impl Iterator<Item = &AnchorKey> {
        self.keys.iter().filter(|key| key.state.trusted())
    }
}

// ---------------------------------------------------------------------------------------
// Negative trust anchors

/// A negative trust anchor (RFC 7646, `dns.ntas`): names at or below `zone` are
/// `insecure` instead of `bogus` until it expires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NegativeTrustAnchor {
    /// Identifier.
    pub id: NtaId,
    /// The zone; never the root.
    pub zone: DnsName,
    /// When it stops applying, at most seven days after it was created.
    pub expires_at: Timestamp,
    /// Why it exists, 1 to 500 characters.
    pub reason: String,
    /// Who created it.
    pub created_by: Principal,
    /// When.
    pub created_at: Timestamp,
}

impl NegativeTrustAnchor {
    /// Checks a row: not the root, a reason of 1 to 500 characters without control
    /// characters, an expiry after its creation and at most seven days later.
    ///
    /// The Hardened profile's rule that an expiry is required (TGL-12) is the model's
    /// shape: `expires_at` is never absent. A request without one is refused by
    /// [`NegativeTrustAnchor::expiry_for`].
    ///
    /// # Errors
    ///
    /// `dns.nta.invalid` naming the field.
    pub fn validate(&self) -> Result<(), DnsError> {
        let invalid =
            |field: &str, reason: &str| Err(DnsError::invalid(codes::NTA_INVALID, field, reason));
        if self.zone.is_root() {
            return invalid("zone", "a negative trust anchor is never the root");
        }
        let reason = self.reason.trim();
        if reason.is_empty() || self.reason.chars().count() > NTA_REASON_MAX {
            return invalid("reason", "1 to 500 characters");
        }
        if self.reason.chars().any(char::is_control) {
            return invalid("reason", "control characters are not allowed");
        }
        if self.expires_at <= self.created_at {
            return invalid("expires_at", "the expiry is after the creation");
        }
        if self.expires_at.saturating_since(self.created_at) > NTA_MAX {
            return invalid("expires_at", "at most seven days ahead");
        }
        Ok(())
    }

    /// The expiry of a new negative trust anchor created at `now`: the requested one, or
    /// seven days when none is requested and the profile does not require one (`required`
    /// is true under Hardened, TGL-12).
    ///
    /// # Errors
    ///
    /// `dns.nta.invalid` naming `expires_at`: none under Hardened, or more than seven days.
    pub fn expiry_for(
        now: Timestamp,
        requested: Option<Timestamp>,
        required: bool,
    ) -> Result<Timestamp, DnsError> {
        let invalid =
            |reason: &str| Err(DnsError::invalid(codes::NTA_INVALID, "expires_at", reason));
        match requested {
            None if required => invalid("the profile requires an expiry"),
            None => now
                .checked_add(NTA_MAX)
                .map_or_else(|| invalid("the expiry is out of range"), Ok),
            Some(at) if at <= now => invalid("the expiry is in the future"),
            Some(at) if at.saturating_since(now) > NTA_MAX => invalid("at most seven days ahead"),
            Some(at) => Ok(at),
        }
    }

    /// Whether it applies to `name` at `now`.
    pub fn covers(&self, name: &DnsName, now: Timestamp) -> bool {
        now < self.expires_at && name.is_subdomain_of(&self.zone)
    }
}
