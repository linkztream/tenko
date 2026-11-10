//! The identity of a secure dynamic update (identity plan sections 3.5, 3.6 and 4.1; ADR
//! 0026, WP13.0): the Kerberos realm, the principal name, the Windows security identifier,
//! the Kerberos part of a zone's update policy, the owner of a name and the metadata of the
//! AD computer account whose keys Tenko holds.
//!
//! These are the contracts the Kerberos line of Slice 13 builds on; nothing here talks to
//! a KDC or reads a ticket. The keys of the account are a system secret in the vault
//! (purpose [`super::KRB_PURPOSE`]) and never appear in these types.
//!
//! | Type | What |
//! |---|---|
//! | [`Realm`] | A Kerberos realm in its canonical (upper-case) form |
//! | [`PrincipalName`] | `component/component@REALM` in the string form of RFC 1964 section 2.1.1 |
//! | [`Sid`] | A Windows security identifier in its string form (`S-1-5-21-...`) |
//! | [`KerberosUpdate`] | The Kerberos settings of a zone's update policy (section 3.5) |
//! | [`Ownership`] | Whether the Windows ownership rules apply (section 3.6) |
//! | [`NameOwner`], [`NameOwnerKey`], [`OwnerSource`] | The owner of a name in `dns.name_owners`, and how it got the name (WP13.4) |
//! | [`KrbAccount`], [`KeyVersionMeta`] | The account and its key versions, metadata only |
//! | [`KrbFinding`] | A finding of the account's self-test, bounded and cleaned (WP13.3) |

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use utoipa::{PartialSchema, ToSchema, openapi::RefOr, openapi::schema::Schema};

use super::{DnsError, DnsName, ScopeName, ZoneId, codes};
use crate::{
    codec::key::{KeyCodec, KeyError},
    error::InvalidValue,
    serde_util::string_schema,
    timestamp::Timestamp,
};

// ---------------------------------------------------------------------------------------
// Realms

/// The longest realm name accepted: a realm is a DNS name in practice, and a DNS name is
/// at most 253 characters in text form.
pub const MAX_REALM_LEN: usize = 253;

/// A Kerberos realm (RFC 4120 section 6.1) in its canonical form.
///
/// Active Directory and MIT realms are domain-style realms, the DNS name of the domain in
/// upper case (`CORP.EXAMPLE.TEST`). A realm is compared by that form: `Realm::new` folds
/// ASCII letters to upper case, so `corp.example.test` and `CORP.EXAMPLE.TEST` are one
/// realm. The lower-case form is the domain name ([`Realm::domain`]) that the MS-KILE salt
/// and the KDC discovery (`_kerberos._tcp.<realm>`) use. A realm is 1 to 253 ASCII
/// characters without whitespace, control characters, `@`, `/` or `\`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Realm(String);

impl PartialSchema for Realm {
    fn schema() -> RefOr<Schema> {
        string_schema("Kerberos realm in upper case (`CORP.EXAMPLE.TEST`)")
    }
}

impl ToSchema for Realm {}

impl Realm {
    /// Parses and canonicalizes a realm.
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] when the text is empty, too long, or holds a character a realm
    /// cannot carry.
    pub fn new(text: &str) -> Result<Self, InvalidValue> {
        let text = text.trim();
        let invalid = |reason| InvalidValue::new("realm", text, reason);
        if text.is_empty() {
            return Err(invalid("a realm is not empty"));
        }
        if text.len() > MAX_REALM_LEN {
            return Err(invalid("a realm is at most 253 characters"));
        }
        if !text.is_ascii() {
            return Err(invalid("a realm is ASCII"));
        }
        if text
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(invalid("a realm holds no whitespace or control characters"));
        }
        if text.contains(['@', '/', '\\']) {
            return Err(invalid("a realm holds no `@`, `/` or `\\`"));
        }
        Ok(Self(text.to_ascii_uppercase()))
    }

    /// The canonical (upper-case) form.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The realm as a domain name: the lower-case form, which the MS-KILE salt of a
    /// computer account and the KDC discovery use.
    pub fn domain(&self) -> String {
        self.0.to_ascii_lowercase()
    }

    /// The realm as a DNS name, for the `_kerberos._tcp.<realm>` lookup.
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] when the realm is not a DNS name (an MIT realm need not be one).
    pub fn to_dns_name(&self) -> Result<DnsName, InvalidValue> {
        DnsName::new(&self.domain())
    }
}

impl fmt::Debug for Realm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Realm({})", self.0)
    }
}

impl fmt::Display for Realm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Realm {
    type Err = InvalidValue;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::new(text)
    }
}

impl TryFrom<String> for Realm {
    type Error = InvalidValue;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::new(&text)
    }
}

impl From<Realm> for String {
    fn from(realm: Realm) -> Self {
        realm.0
    }
}

impl KeyCodec for Realm {
    fn encode_key(&self, out: &mut Vec<u8>) {
        self.0.encode_key(out);
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        let text = String::decode_key(input)?;
        Realm::new(&text).map_err(|_| KeyError::Invalid("not a realm"))
    }
}

// ---------------------------------------------------------------------------------------
// Principal names

/// The most components a principal name may have. Kerberos names have one or two in
/// practice (`host/server.corp.example.test`, `TENKO-DNS$`); the bound keeps a parser
/// honest.
pub const MAX_PRINCIPAL_COMPONENTS: usize = 8;

/// The longest principal name in its string form.
pub const MAX_PRINCIPAL_LEN: usize = 1024;

/// A Kerberos principal name with its realm, in the string form of RFC 1964 section 2.1.1:
/// the components joined by `/`, then `@` and the realm (`host/dc01.corp.example.test@
/// CORP.EXAMPLE.TEST`, `WS01$@CORP.EXAMPLE.TEST`). In a component `/`, `@` and `\` are
/// escaped with `\`; the escapes `\n`, `\t`, `\b` and `\0` of that section are read and
/// written as well.
///
/// The realm is always present: a principal is what a ticket names (`cname` and `crealm`),
/// and the ownership rules of section 3.6 match a principal across realms (R134). Names are
/// compared as the KDC issued them: the components are case-sensitive, the realm is
/// canonical.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PrincipalName {
    components: Vec<String>,
    realm: Realm,
}

impl PartialSchema for PrincipalName {
    fn schema() -> RefOr<Schema> {
        string_schema(
            "Kerberos principal with its realm (`WS01$@CORP.EXAMPLE.TEST`, \
             `host/dc01.corp.example.test@CORP.EXAMPLE.TEST`)",
        )
    }
}

impl ToSchema for PrincipalName {}

impl PrincipalName {
    /// A principal from its components and realm.
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] when there is no component, more than eight, an empty one, one with
    /// a control character, or the string form would be longer than 1,024 characters.
    pub fn new(components: Vec<String>, realm: Realm) -> Result<Self, InvalidValue> {
        let principal = Self { components, realm };
        principal.check()?;
        Ok(principal)
    }

    /// Parses the string form.
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] when the text has no realm, a bad escape, an empty component, too
    /// many components, or an invalid realm.
    pub fn parse(text: &str) -> Result<Self, InvalidValue> {
        let invalid = |reason| InvalidValue::new("principal", text, reason);
        if text.len() > MAX_PRINCIPAL_LEN {
            return Err(invalid("a principal name is at most 1024 characters"));
        }
        let mut components = Vec::new();
        let mut current = String::new();
        let mut realm = None;
        let mut chars = text.chars();
        while let Some(ch) = chars.next() {
            match ch {
                '\\' => {
                    let escaped = chars
                        .next()
                        .ok_or_else(|| invalid("a `\\` ends the name"))?;
                    current.push(match escaped {
                        'n' => '\n',
                        't' => '\t',
                        'b' => '\u{8}',
                        '0' => '\0',
                        '/' | '@' | '\\' => escaped,
                        _ => return Err(invalid("unknown escape after `\\`")),
                    });
                }
                '/' => components.push(std::mem::take(&mut current)),
                '@' => {
                    components.push(std::mem::take(&mut current));
                    let rest: String = chars.collect();
                    realm = Some(
                        Realm::new(&rest)
                            .map_err(|_| invalid("the realm after `@` is not a realm"))?,
                    );
                    break;
                }
                _ => current.push(ch),
            }
        }
        let Some(realm) = realm else {
            return Err(invalid("a principal name ends with `@` and its realm"));
        };
        Self::new(components, realm)
    }

    fn check(&self) -> Result<(), InvalidValue> {
        let invalid = |reason| InvalidValue::new("principal", &self.to_string(), reason);
        if self.components.is_empty() {
            return Err(invalid("a principal has at least one component"));
        }
        if self.components.len() > MAX_PRINCIPAL_COMPONENTS {
            return Err(invalid("a principal has at most 8 components"));
        }
        for component in &self.components {
            if component.is_empty() {
                return Err(invalid("a component is not empty"));
            }
            if component
                .chars()
                .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\t' | '\u{8}' | '\0'))
            {
                return Err(invalid("a component holds no control characters"));
            }
        }
        if self.to_string().len() > MAX_PRINCIPAL_LEN {
            return Err(invalid("a principal name is at most 1024 characters"));
        }
        Ok(())
    }

    /// The components, in order.
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// The first component: the account name of a user or computer principal
    /// (`WS01$`), the service of a service principal (`host`).
    pub fn primary(&self) -> &str {
        &self.components[0]
    }

    /// The realm.
    pub fn realm(&self) -> &Realm {
        &self.realm
    }

    /// Whether the principal is a computer account of Active Directory: one component
    /// that ends with `$`.
    pub fn is_computer(&self) -> bool {
        self.components.len() == 1 && self.primary().ends_with('$')
    }

    /// The host name a computer account's principal claims under BIND's `ms-self` rule
    /// (section 3.6): `ws01` for `WS01$@CORP.EXAMPLE.TEST`, lower case, for the name
    /// `ws01.<zone>` and its PTR record. None for a user or a service principal.
    pub fn host_label(&self) -> Option<String> {
        if !self.is_computer() {
            return None;
        }
        let label = self.primary().trim_end_matches('$').to_ascii_lowercase();
        (!label.is_empty()).then_some(label)
    }

    /// The name without the realm, with the escapes of the string form.
    pub fn without_realm(&self) -> String {
        let mut out = String::new();
        for (index, component) in self.components.iter().enumerate() {
            if index > 0 {
                out.push('/');
            }
            escape_into(component, &mut out);
        }
        out
    }
}

fn escape_into(component: &str, out: &mut String) {
    for ch in component.chars() {
        match ch {
            '/' | '@' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\0' => out.push_str("\\0"),
            _ => out.push(ch),
        }
    }
}

impl fmt::Debug for PrincipalName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrincipalName({self})")
    }
}

impl fmt::Display for PrincipalName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.without_realm(), self.realm)
    }
}

impl FromStr for PrincipalName {
    type Err = InvalidValue;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl TryFrom<String> for PrincipalName {
    type Error = InvalidValue;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<PrincipalName> for String {
    fn from(principal: PrincipalName) -> Self {
        principal.to_string()
    }
}

/// Whether a principal's name without the realm matches a pattern of
/// [`super::AclEntry::Kerberos`]: the pattern is compared literally, except that `*`
/// matches any run of characters (`*$` is every computer account, `dc*$` the controllers
/// named so, `*` every principal). The comparison ignores ASCII case, as Windows does for
/// account names.
pub fn principal_matches(pattern: &str, principal: &PrincipalName) -> bool {
    let name = principal.without_realm().to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    glob_matches(pattern.as_bytes(), name.as_bytes())
}

/// Matches `pattern` against `text` with `*` as any run of bytes, in linear time: the
/// last `*` seen is the point to back up to, so a pattern of many stars cannot make the
/// update path backtrack exponentially.
fn glob_matches(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, t));
            p += 1;
        } else if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some((star_p, star_t)) = star {
            p = star_p + 1;
            t = star_t + 1;
            star = Some((star_p, star_t + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|byte| *byte == b'*')
}

/// Checks a principal pattern of an access list entry: 1 to 256 characters, no `@`
/// (the realm is the entry's own field), no whitespace or control characters.
///
/// # Errors
///
/// [`InvalidValue`] naming the rule broken.
pub fn check_principal_pattern(pattern: &str) -> Result<(), InvalidValue> {
    let invalid = |reason| InvalidValue::new("principal pattern", pattern, reason);
    if pattern.is_empty() || pattern.len() > 256 {
        return Err(invalid("a pattern is 1 to 256 characters"));
    }
    if pattern.contains('@') {
        return Err(invalid("a pattern names no realm; the entry has its own"));
    }
    if pattern
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(invalid(
            "a pattern holds no whitespace or control characters",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Security identifiers

/// The most sub-authorities a SID carries ([MS-DTYP] section 2.4.2).
pub const MAX_SID_SUB_AUTHORITIES: usize = 15;

/// The relative identifiers of the well-known domain groups the ownership rules name
/// (section 3.6): Domain Admins, Domain Controllers and Enterprise Admins.
pub const RID_DOMAIN_ADMINS: u32 = 512;
/// Domain Controllers.
pub const RID_DOMAIN_CONTROLLERS: u32 = 516;
/// Enterprise Admins.
pub const RID_ENTERPRISE_ADMINS: u32 = 519;

/// A Windows security identifier ([MS-DTYP] section 2.4.2) in its string form
/// `S-1-<authority>-<sub-authority>-...`: revision 1, a 48-bit identifier authority
/// (written in decimal below 2^32, in hexadecimal with `0x` from there on, as Windows
/// writes it), and 0 to 15 sub-authorities. A domain SID is `S-1-5-21-a-b-c`; a principal
/// or group of the domain adds its relative identifier.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sid {
    authority: u64,
    sub_authorities: Vec<u32>,
}

impl PartialSchema for Sid {
    fn schema() -> RefOr<Schema> {
        string_schema(
            "Windows security identifier (`S-1-5-21-1004336348-1177238915-682003330-512`)",
        )
    }
}

impl ToSchema for Sid {}

impl Sid {
    /// A SID from its identifier authority and sub-authorities.
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] when the authority exceeds 48 bits or there are more than 15
    /// sub-authorities.
    pub fn new(authority: u64, sub_authorities: Vec<u32>) -> Result<Self, InvalidValue> {
        if authority >= 1 << 48 {
            return Err(InvalidValue::new(
                "sid",
                &authority.to_string(),
                "the identifier authority is 48 bits",
            ));
        }
        if sub_authorities.len() > MAX_SID_SUB_AUTHORITIES {
            return Err(InvalidValue::new(
                "sid",
                &sub_authorities.len().to_string(),
                "a SID has at most 15 sub-authorities",
            ));
        }
        Ok(Self {
            authority,
            sub_authorities,
        })
    }

    /// Parses the string form (`S-1-5-21-...`); the `S` and the `0x` of a large authority
    /// are accepted in either case.
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] naming the part that does not parse.
    pub fn parse(text: &str) -> Result<Self, InvalidValue> {
        let invalid = |reason| InvalidValue::new("sid", text, reason);
        let mut parts = text.trim().split('-');
        match parts.next() {
            Some("S" | "s") => {}
            _ => return Err(invalid("a SID starts with `S-`")),
        }
        match parts.next() {
            Some("1") => {}
            _ => return Err(invalid("the revision is 1")),
        }
        let authority = parts
            .next()
            .ok_or_else(|| invalid("the identifier authority is missing"))?;
        let authority = if let Some(hex) = authority
            .strip_prefix("0x")
            .or_else(|| authority.strip_prefix("0X"))
        {
            if hex.is_empty() || hex.len() > 12 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid(
                    "the identifier authority is at most 12 hexadecimal digits",
                ));
            }
            u64::from_str_radix(hex, 16)
                .map_err(|_| invalid("the identifier authority is not a number"))?
        } else {
            if authority.is_empty()
                || authority.len() > 15
                || !authority.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(invalid("the identifier authority is a decimal number"));
            }
            authority
                .parse::<u64>()
                .map_err(|_| invalid("the identifier authority is not a number"))?
        };
        let mut sub_authorities = Vec::new();
        for part in parts {
            if part.is_empty() || part.len() > 10 || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid("a sub-authority is a decimal number"));
            }
            let value: u32 = part
                .parse()
                .map_err(|_| invalid("a sub-authority is below 2^32"))?;
            sub_authorities.push(value);
            if sub_authorities.len() > MAX_SID_SUB_AUTHORITIES {
                return Err(invalid("a SID has at most 15 sub-authorities"));
            }
        }
        Self::new(authority, sub_authorities)
    }

    /// The identifier authority.
    pub fn authority(&self) -> u64 {
        self.authority
    }

    /// The sub-authorities.
    pub fn sub_authorities(&self) -> &[u32] {
        &self.sub_authorities
    }

    /// The relative identifier: the last sub-authority.
    pub fn rid(&self) -> Option<u32> {
        self.sub_authorities.last().copied()
    }

    /// The SID without its relative identifier: the domain of a domain principal.
    pub fn parent(&self) -> Option<Sid> {
        let (_, rest) = self.sub_authorities.split_last()?;
        Some(Sid {
            authority: self.authority,
            sub_authorities: rest.to_vec(),
        })
    }

    /// Whether this is a SID of an Active Directory domain or of something in one
    /// (`S-1-5-21-...`).
    pub fn is_domain_sid(&self) -> bool {
        self.authority == 5 && self.sub_authorities.first() == Some(&21)
    }

    /// The packet representation ([MS-DTYP] section 2.4.2.2), as the PAC carries it: the
    /// revision, the count, the authority in six big-endian bytes, the sub-authorities in
    /// little-endian.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 4 * self.sub_authorities.len());
        out.push(1);
        out.push(u8::try_from(self.sub_authorities.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(&self.authority.to_be_bytes()[2..]);
        for sub in &self.sub_authorities {
            out.extend_from_slice(&sub.to_le_bytes());
        }
        out
    }

    /// Reads the packet representation.
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] when the bytes are not a SID of revision 1 with the count of
    /// sub-authorities they announce.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidValue> {
        let invalid = |reason| InvalidValue::new("sid", &format!("{} bytes", bytes.len()), reason);
        if bytes.len() < 8 {
            return Err(invalid("a SID is at least 8 bytes"));
        }
        if bytes[0] != 1 {
            return Err(invalid("the revision is 1"));
        }
        let count = usize::from(bytes[1]);
        if count > MAX_SID_SUB_AUTHORITIES {
            return Err(invalid("a SID has at most 15 sub-authorities"));
        }
        if bytes.len() != 8 + 4 * count {
            return Err(invalid("the length does not match the sub-authority count"));
        }
        let mut authority = [0_u8; 8];
        authority[2..].copy_from_slice(&bytes[2..8]);
        let sub_authorities = bytes[8..]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|chunk| u32::from_le_bytes(*chunk))
            .collect();
        Self::new(u64::from_be_bytes(authority), sub_authorities)
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sid({self})")
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.authority < 1 << 32 {
            write!(f, "S-1-{}", self.authority)?;
        } else {
            write!(f, "S-1-0x{:012X}", self.authority)?;
        }
        for sub in &self.sub_authorities {
            write!(f, "-{sub}")?;
        }
        Ok(())
    }
}

impl FromStr for Sid {
    type Err = InvalidValue;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl TryFrom<String> for Sid {
    type Error = InvalidValue;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<Sid> for String {
    fn from(sid: Sid) -> Self {
        sid.to_string()
    }
}

// ---------------------------------------------------------------------------------------
// The Kerberos part of the update policy

/// Whether the ownership rules of section 3.6 apply to a zone (ID-Q8).
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
pub enum Ownership {
    /// Windows' rules with Tenko's protections: the creator owns a name, privileged
    /// groups may change any name, locator and manual names are protected.
    #[default]
    Windows,
    /// No ownership: a zone behaves as before Slice 13.
    None,
}

/// The default owner hold after a name's last record goes (section 3.6, proposed 14 days).
pub const DEFAULT_OWNER_HOLD_DAYS: u16 = 14;

/// The longest owner hold.
pub const MAX_OWNER_HOLD_DAYS: u16 = 3650;

/// The Kerberos settings of a zone's update policy (section 3.5): the realms whose
/// principals may sign updates with GSS-TSIG, the ownership rule and its hold, the groups
/// whose members are privileged and the group whose members leave names unowned.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct KerberosUpdate {
    /// The realms whose tickets the zone accepts (R134: a child domain is its own realm).
    pub realms: Vec<Realm>,
    /// Whether the Windows ownership rules apply.
    #[serde(default)]
    pub ownership: Ownership,
    /// Days the owner of a removed name is held before the name is new again.
    #[serde(default = "default_owner_hold_days")]
    pub owner_hold_days: u16,
    /// The privileged groups by SID: Domain Admins (RID 512), Enterprise Admins (519),
    /// Domain Controllers (516), `DnsAdmins`, and any the operator adds. Membership comes
    /// from the PAC.
    #[serde(default)]
    pub privileged: Vec<Sid>,
    /// The `DnsUpdateProxy` group: a member that creates a name leaves it unowned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_proxy: Option<Sid>,
}

const fn default_owner_hold_days() -> u16 {
    DEFAULT_OWNER_HOLD_DAYS
}

impl KerberosUpdate {
    /// The settings for one realm with the defaults: ownership on, a 14-day hold, no
    /// privileged group yet (the wizard fills them in).
    pub fn for_realm(realm: Realm) -> Self {
        Self {
            realms: vec![realm],
            ownership: Ownership::Windows,
            owner_hold_days: DEFAULT_OWNER_HOLD_DAYS,
            privileged: Vec::new(),
            update_proxy: None,
        }
    }

    /// Checks the settings: at least one realm and none twice, a hold of at most 3,650
    /// days, no privileged SID twice, and the proxy group not among the privileged.
    ///
    /// # Errors
    ///
    /// `dns.zone.invalid` naming the field under `update.kerberos`.
    pub fn validate(&self) -> Result<(), DnsError> {
        let invalid = |field: &str, reason: &str| {
            Err(DnsError::invalid(
                codes::ZONE_INVALID,
                &format!("update.kerberos.{field}"),
                reason,
            ))
        };
        if self.realms.is_empty() {
            return invalid("realms", "at least one realm");
        }
        if has_duplicate(&self.realms) {
            return invalid("realms", "a realm appears twice");
        }
        if self.owner_hold_days > MAX_OWNER_HOLD_DAYS {
            return invalid("owner_hold_days", "at most 3650 days");
        }
        if has_duplicate(&self.privileged) {
            return invalid("privileged", "a group appears twice");
        }
        if let Some(proxy) = &self.update_proxy
            && self.privileged.contains(proxy)
        {
            return invalid("update_proxy", "the proxy group is not a privileged group");
        }
        Ok(())
    }

    /// Whether a realm is one of the zone's.
    pub fn accepts_realm(&self, realm: &Realm) -> bool {
        self.realms.contains(realm)
    }

    /// Whether a principal with these group SIDs (from its PAC) is privileged.
    pub fn is_privileged<'a>(&self, groups: impl IntoIterator<Item = &'a Sid>) -> bool {
        groups
            .into_iter()
            .any(|group| self.privileged.contains(group))
    }

    /// Whether a principal with these group SIDs is a member of `DnsUpdateProxy`.
    pub fn is_update_proxy<'a>(&self, groups: impl IntoIterator<Item = &'a Sid>) -> bool {
        match &self.update_proxy {
            Some(proxy) => groups.into_iter().any(|group| group == proxy),
            None => false,
        }
    }
}

fn has_duplicate<T: PartialEq>(items: &[T]) -> bool {
    items
        .iter()
        .enumerate()
        .any(|(index, item)| items[..index].contains(item))
}

// ---------------------------------------------------------------------------------------
// Name owners

/// The key of `dns.name_owners`: the zone, the scope and the name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema)]
pub struct NameOwnerKey {
    /// The zone.
    pub zone: ZoneId,
    /// The zone scope.
    pub scope: ScopeName,
    /// The owner name.
    pub name: DnsName,
}

impl KeyCodec for NameOwnerKey {
    fn encode_key(&self, out: &mut Vec<u8>) {
        self.zone.encode_key(out);
        self.scope.encode_key(out);
        self.name.encode_key(out);
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        Ok(Self {
            zone: ZoneId::decode_key(input)?,
            scope: ScopeName::decode_key(input)?,
            name: DnsName::decode_key(input)?,
        })
    }
}

/// Who owns a name in a zone with ownership on (section 3.6): written in the same batch
/// as the change that created or claimed the name. The SID is the key of the match when
/// both sides have one (it survives a rename), the principal name otherwise (an MIT realm
/// has no PAC).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NameOwner {
    /// The owner's SID, from the PAC of the ticket that created the name, or from the
    /// Windows adapter (MIG-06).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<Sid>,
    /// The owner's principal, for the match without a SID and for display.
    pub principal: PrincipalName,
    /// When the ownership started.
    pub since: Timestamp,
    /// Until when the owner is held after the name's last record went; none while the
    /// name has records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_until: Option<Timestamp>,
    // WP13.4: how the ownership started, for the owner view.
    /// How the owner came to own the name; `created` for rows written before the field.
    #[serde(default)]
    pub how: OwnerSource,
}

// WP13.4: the ways a name gets its owner (identity plan section 3.6).
/// How a name got its owner.
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
pub enum OwnerSource {
    /// The principal's secure update created the name (or wrote it while it had no owner).
    #[default]
    Created,
    /// The principal claimed a name imported without an owner: its own host name, or a
    /// PTR name pointing at it.
    Claimed,
    /// An administrator assigned the name to the principal.
    Assigned,
    /// A migration adapter read the owner from the source (MIG-06: the owner SID of a
    /// Windows `dnsNode`).
    Imported,
}

impl OwnerSource {
    /// The stable name, as in the API and the audit context.
    pub const fn name(self) -> &'static str {
        match self {
            OwnerSource::Created => "created",
            OwnerSource::Claimed => "claimed",
            OwnerSource::Assigned => "assigned",
            OwnerSource::Imported => "imported",
        }
    }
}

impl NameOwner {
    /// Whether a principal with `sid` is this owner: by SID when the owner has one (a
    /// principal without a SID, from a ticket without a PAC, never matches it, since its
    /// name alone does not prove the account), by the principal name otherwise.
    pub fn is_owner(&self, principal: &PrincipalName, sid: Option<&Sid>) -> bool {
        match (&self.sid, sid) {
            (Some(own), Some(other)) => own == other,
            (Some(_), None) => false,
            (None, _) => &self.principal == principal,
        }
    }

    /// Whether the hold has passed at `now`: the name is new again.
    pub fn hold_passed(&self, now: Timestamp) -> bool {
        self.hold_until.is_some_and(|until| now >= until)
    }
}

// ---------------------------------------------------------------------------------------
// The account

/// The Kerberos encryption types the account holds (RFC 3962): AES only (ID-Q3). RC4, DES
/// and 3DES are never accepted (ADR 0026 point 3).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum EncryptionType {
    /// `aes128-cts-hmac-sha1-96`, type 17.
    Aes128CtsHmacSha1,
    /// `aes256-cts-hmac-sha1-96`, type 18.
    Aes256CtsHmacSha1,
}

impl EncryptionType {
    /// The number of RFC 3961.
    pub const fn number(self) -> i32 {
        match self {
            EncryptionType::Aes128CtsHmacSha1 => 17,
            EncryptionType::Aes256CtsHmacSha1 => 18,
        }
    }

    /// The type of a number, for the AES types only.
    pub const fn from_number(number: i32) -> Option<Self> {
        match number {
            17 => Some(EncryptionType::Aes128CtsHmacSha1),
            18 => Some(EncryptionType::Aes256CtsHmacSha1),
            _ => None,
        }
    }
}

/// Where a key version stands in the rotation (section 3.1).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum KeyVersionState {
    /// The version the KDC issues tickets with.
    Current,
    /// The version before the last rotation, accepted until the next one.
    Previous,
    /// Written before the change-password request; a restart finds it and tests which
    /// version the KDC now issues.
    Pending,
}

/// One key version of the account: the metadata beside the secret, never the key bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct KeyVersionMeta {
    /// The key version number the KDC puts in tickets.
    pub kvno: u32,
    /// The encryption types the version holds keys for.
    pub etypes: Vec<EncryptionType>,
    /// Current, previous or pending.
    pub state: KeyVersionState,
    /// When the version was made.
    pub created: Timestamp,
}

/// The default rotation interval of an account Tenko owns (ID-Q5, TGL-32).
pub const DEFAULT_ROTATION_DAYS: u16 = 30;

/// The longest rotation interval.
pub const MAX_ROTATION_DAYS: u16 = 365;

/// The AD computer account whose keys Tenko holds (section 3.1): one per realm, with the
/// SPN of every node name. Metadata only; the keys are the system secret of purpose
/// [`super::KRB_PURPOSE`] in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct KrbAccount {
    /// The realm.
    pub realm: Realm,
    /// The account name as the KDC knows it (`TENKO-DNS$` for a computer account, a user
    /// name for an imported user account).
    pub name: String,
    /// The service principal names (`DNS/<fqdn>`, `HTTP/<fqdn>`).
    pub spns: Vec<String>,
    /// The KDCs the operator listed; empty: found through `_kerberos._tcp.<realm>`.
    #[serde(default)]
    pub kdcs: Vec<String>,
    /// Whether Tenko owns the password (adopted) or an administrator does (imported
    /// keytab).
    pub owned: bool,
    /// Days between rotations of an owned account; 0 is off (Lab only, TGL-32).
    #[serde(default = "default_rotation_days")]
    pub rotation_days: u16,
    /// The key versions held.
    #[serde(default)]
    pub versions: Vec<KeyVersionMeta>,
    /// The last successful rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_rotation: Option<Timestamp>,
    /// The last self-test.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_check: Option<Timestamp>,
    // WP13.3: the link to the keys and the findings of the last self-test.
    /// The vault secret of purpose [`super::KRB_PURPOSE`] that holds the keys; absent only
    /// while an adopt or an import writes its first keys. Never shown in the API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<crate::secret::SecretRef>,
    /// The findings of the last self-test (section 3.10), at most [`MAX_KRB_FINDINGS`];
    /// empty when it passed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<KrbFinding>,
    // WP13.3: end.
}

// WP13.3: the most SPNs of the account (the self-test asks a ticket for each).
/// The most service principal names an account holds.
pub const MAX_KRB_SPNS: usize = 64;

// WP13.3: the findings of the account's self-test, bounded and cleaned: a KDC's error text
// is network input, and no password, key, salt or one-time secret is ever put in one.
/// The most findings an account keeps.
pub const MAX_KRB_FINDINGS: usize = 32;
/// The longest `detail` of a finding, in octets.
pub const MAX_KRB_FINDING_DETAIL: usize = 512;
/// The longest value of a finding's parameter, in octets.
pub const MAX_KRB_FINDING_PARAM: usize = 256;
/// The parameters a finding may carry: the SPN, the key version seen and the versions
/// held, the skew measured, the encryption type, the KDC's error code, the reason and the
/// failures in a row of a rotation.
pub const KRB_FINDING_PARAMS: [&str; 8] = [
    "spn",
    "kvno",
    "held",
    "skew_secs",
    "etype",
    "kdc_error",
    "reason",
    "failures",
];

/// One finding of the account's self-test (identity plan section 3.10): the code of
/// `tenko_core::dns::findings`, what was seen in English, the parameters the UI fills its
/// localized text with, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct KrbFinding {
    /// The finding (`dns.gss.spn_missing`, ...).
    pub code: String,
    /// What was seen, in English, without control characters.
    pub detail: String,
    /// Parameters from [`KRB_FINDING_PARAMS`].
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub params: std::collections::BTreeMap<String, String>,
    /// When it was found.
    pub at: Timestamp,
}

/// `text` with every control character replaced by a space, cut to at most `max` octets
/// at a character boundary.
pub fn clean_finding_text(text: &str, max: usize) -> String {
    let mut out = String::with_capacity(text.len().min(max));
    for c in text.chars() {
        let c = if c.is_control() { ' ' } else { c };
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(c);
    }
    out
}

impl KrbFinding {
    /// A finding with its detail cleaned and cut to [`MAX_KRB_FINDING_DETAIL`].
    pub fn new(code: &str, detail: &str, at: Timestamp) -> Self {
        Self {
            code: code.to_owned(),
            detail: clean_finding_text(detail, MAX_KRB_FINDING_DETAIL),
            params: std::collections::BTreeMap::new(),
            at,
        }
    }

    /// The finding with a parameter, its value cleaned and cut to
    /// [`MAX_KRB_FINDING_PARAM`]; a key outside [`KRB_FINDING_PARAMS`] is not added.
    #[must_use]
    pub fn param(mut self, key: &str, value: impl fmt::Display) -> Self {
        if KRB_FINDING_PARAMS.contains(&key) {
            self.params.insert(
                key.to_owned(),
                clean_finding_text(&value.to_string(), MAX_KRB_FINDING_PARAM),
            );
        }
        self
    }

    fn validate(&self) -> Result<(), &'static str> {
        if !super::findings::ALL.contains(&self.code.as_str()) {
            return Err("a finding's code is not a DNS finding");
        }
        let clean =
            |text: &str, max: usize| text.len() <= max && !text.chars().any(char::is_control);
        if !clean(&self.detail, MAX_KRB_FINDING_DETAIL) {
            return Err("a finding's detail is too long or holds control characters");
        }
        for (key, value) in &self.params {
            if !KRB_FINDING_PARAMS.contains(&key.as_str()) || !clean(value, MAX_KRB_FINDING_PARAM) {
                return Err("a finding's parameter is not one of the set, too long or not clean");
            }
        }
        Ok(())
    }
}
// WP13.3: end.

const fn default_rotation_days() -> u16 {
    DEFAULT_ROTATION_DAYS
}

impl KrbAccount {
    /// Checks the account: a name of 1 to 256 characters without `@`, `/` or control
    /// characters; at least one SPN, each `service/host` and none twice; KDCs that are
    /// not empty; a rotation interval of at most 365 days; key versions with distinct
    /// numbers, at most one current and one pending, each with at least one type.
    ///
    /// # Errors
    ///
    /// `dns.krb.account.invalid` naming the field.
    pub fn validate(&self) -> Result<(), DnsError> {
        let invalid = |field: &str, reason: &str| {
            Err(DnsError::invalid(codes::KRB_ACCOUNT_INVALID, field, reason))
        };
        if self.name.is_empty() || self.name.len() > 256 {
            return invalid("name", "1 to 256 characters");
        }
        if self.name.contains(['@', '/']) || self.name.chars().any(char::is_control) {
            return invalid(
                "name",
                "an account name holds no `@`, `/` or control characters",
            );
        }
        if self.spns.is_empty() {
            return invalid("spns", "at least one service principal name");
        }
        // WP13.3: the self-test asks a ticket for each.
        if self.spns.len() > MAX_KRB_SPNS {
            return invalid("spns", "at most 64 service principal names");
        }
        for spn in &self.spns {
            let Some((service, host)) = spn.split_once('/') else {
                return invalid("spns", "a service principal name is `service/host`");
            };
            if service.is_empty() || host.is_empty() || spn.contains('@') || spn.len() > 512 {
                return invalid("spns", "a service principal name is `service/host`");
            }
        }
        if self.spns.iter().enumerate().any(|(index, spn)| {
            self.spns[..index]
                .iter()
                .any(|other| other.eq_ignore_ascii_case(spn))
        }) {
            return invalid("spns", "a service principal name appears twice");
        }
        if self
            .kdcs
            .iter()
            .any(|kdc| kdc.trim().is_empty() || kdc.len() > 256)
        {
            return invalid("kdcs", "a KDC is a host name with an optional port");
        }
        if self.rotation_days > MAX_ROTATION_DAYS {
            return invalid("rotation_days", "at most 365 days");
        }
        let mut current = 0;
        let mut pending = 0;
        for (index, version) in self.versions.iter().enumerate() {
            if self.versions[..index]
                .iter()
                .any(|other| other.kvno == version.kvno)
            {
                return invalid("versions", "a key version number appears twice");
            }
            if version.etypes.is_empty() {
                return invalid("versions", "a key version holds at least one type");
            }
            match version.state {
                KeyVersionState::Current => current += 1,
                KeyVersionState::Pending => pending += 1,
                KeyVersionState::Previous => {}
            }
        }
        if current > 1 || pending > 1 {
            return invalid("versions", "at most one current and one pending version");
        }
        // WP13.3
        if self.findings.len() > MAX_KRB_FINDINGS {
            return invalid("findings", "at most 32 findings");
        }
        for finding in &self.findings {
            finding
                .validate()
                .or_else(|reason| invalid("findings", reason))?;
        }
        // WP13.3: end.
        Ok(())
    }

    /// The current key version, if any.
    pub fn current(&self) -> Option<&KeyVersionMeta> {
        self.versions
            .iter()
            .find(|version| version.state == KeyVersionState::Current)
    }

    /// Whether a key version number is held, in any state.
    pub fn holds_kvno(&self, kvno: u32) -> bool {
        self.versions.iter().any(|version| version.kvno == kvno)
    }

    /// The principal of the account (`TENKO-DNS$@CORP.EXAMPLE.TEST`).
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] when the name is not a principal component.
    pub fn principal(&self) -> Result<PrincipalName, InvalidValue> {
        PrincipalName::new(vec![self.name.clone()], self.realm.clone())
    }

    /// The MS-KILE salt of a computer account (section 3.1): the realm in upper case,
    /// `host`, the account name in lower case without the `$`, a dot, the realm in lower
    /// case. None for a user account (its salt is the realm and the name).
    pub fn computer_salt(&self) -> Option<String> {
        let name = self.name.strip_suffix('$')?;
        Some(format!(
            "{}host{}.{}",
            self.realm.as_str(),
            name.to_ascii_lowercase(),
            self.realm.domain()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realm() -> Realm {
        Realm::new("CORP.EXAMPLE.TEST").expect("realm")
    }

    #[test]
    fn realms_fold_to_upper_case_and_refuse_bad_text() {
        assert_eq!(Realm::new("corp.example.test").expect("realm"), realm());
        assert_eq!(realm().domain(), "corp.example.test");
        assert_eq!(
            realm().to_dns_name().expect("name").as_str(),
            "corp.example.test"
        );
        for bad in ["", " ", "a@b", "a/b", "a\\b", "a b", "a\tb", "ö"] {
            assert!(Realm::new(bad).is_err(), "{bad:?}");
        }
        assert!(Realm::new(&"a".repeat(254)).is_err());
        assert!(Realm::new(&"a".repeat(253)).is_ok());
        let json = serde_json::to_string(&realm()).expect("json");
        assert_eq!(json, "\"CORP.EXAMPLE.TEST\"");
        let back: Realm = serde_json::from_str("\"corp.example.test\"").expect("json");
        assert_eq!(back, realm());
        assert!(serde_json::from_str::<Realm>("\"a@b\"").is_err());
    }

    #[test]
    fn principal_names_parse_and_print_their_string_form() {
        let computer = PrincipalName::parse("WS01$@corp.example.test").expect("principal");
        assert_eq!(computer.components(), ["WS01$"]);
        assert_eq!(computer.realm(), &realm());
        assert!(computer.is_computer());
        assert_eq!(computer.host_label().as_deref(), Some("ws01"));
        assert_eq!(computer.to_string(), "WS01$@CORP.EXAMPLE.TEST");
        let service = PrincipalName::parse("host/dc01.corp.example.test@CORP.EXAMPLE.TEST")
            .expect("principal");
        assert_eq!(service.components(), ["host", "dc01.corp.example.test"]);
        assert_eq!(service.primary(), "host");
        assert!(!service.is_computer());
        assert_eq!(service.host_label(), None);
        let escaped =
            PrincipalName::parse("a\\/b\\@c\\\\d\\n@CORP.EXAMPLE.TEST").expect("principal");
        assert_eq!(escaped.components(), ["a/b@c\\d\n"]);
        assert_eq!(escaped.to_string(), "a\\/b\\@c\\\\d\\n@CORP.EXAMPLE.TEST");
        assert_eq!(
            PrincipalName::parse(&escaped.to_string()).expect("round trip"),
            escaped
        );
        for bad in [
            "",
            "WS01$",
            "@CORP.EXAMPLE.TEST",
            "a/@CORP.EXAMPLE.TEST",
            "a\\x@CORP.EXAMPLE.TEST",
            "a\\",
            "a@b@c",
            "a/b/c/d/e/f/g/h/i@CORP.EXAMPLE.TEST",
            "a\u{1}@CORP.EXAMPLE.TEST",
        ] {
            assert!(PrincipalName::parse(bad).is_err(), "{bad:?}");
        }
        assert!(PrincipalName::parse(&format!("{}@R", "a".repeat(1100))).is_err());
        assert_eq!(
            PrincipalName::parse("$@CORP.EXAMPLE.TEST")
                .expect("principal")
                .host_label(),
            None
        );
    }

    #[test]
    fn principal_patterns_match_computers_and_names() {
        let computer = PrincipalName::parse("DC01$@CORP.EXAMPLE.TEST").expect("principal");
        let user = PrincipalName::parse("alex@CORP.EXAMPLE.TEST").expect("principal");
        assert!(principal_matches("*$", &computer));
        assert!(principal_matches("dc*$", &computer));
        assert!(principal_matches("DC01$", &computer));
        assert!(principal_matches("*", &computer));
        assert!(!principal_matches("*$", &user));
        assert!(!principal_matches("ws*$", &computer));
        assert!(principal_matches("a*x", &user));
        assert!(!principal_matches("", &user));
        assert!(check_principal_pattern("*$").is_ok());
        assert!(check_principal_pattern("").is_err());
        assert!(check_principal_pattern("a@b").is_err());
        assert!(check_principal_pattern("a\nb").is_err());
        assert!(check_principal_pattern("a b").is_err());
        // A pattern of many stars against a long name that does not match stays linear.
        let long = PrincipalName::parse(&format!("{}b@CORP.EXAMPLE.TEST", "a".repeat(200)))
            .expect("principal");
        assert!(!principal_matches("*a*a*a*a*a*a*a*a", &long));
        assert!(principal_matches("*a*a*a*a*a*a*a*a*", &long));
        assert!(principal_matches("a*b", &long));
        assert!(!principal_matches("a*c", &long));
        assert!(check_principal_pattern(&"a".repeat(257)).is_err());
    }

    #[test]
    fn sids_parse_print_and_pack() {
        let text = "S-1-5-21-1004336348-1177238915-682003330-512";
        let sid = Sid::parse(text).expect("sid");
        assert_eq!(sid.to_string(), text);
        assert_eq!(sid.authority(), 5);
        assert_eq!(sid.rid(), Some(512));
        assert!(sid.is_domain_sid());
        assert_eq!(
            sid.parent().expect("domain").to_string(),
            "S-1-5-21-1004336348-1177238915-682003330"
        );
        assert_eq!(Sid::parse("s-1-5-18").expect("sid").to_string(), "S-1-5-18");
        assert_eq!(Sid::parse("S-1-0").expect("sid").rid(), None);
        let big = Sid::parse("S-1-0x123456789ABC-1").expect("sid");
        assert_eq!(big.authority(), 0x1234_5678_9ABC);
        assert_eq!(big.to_string(), "S-1-0x123456789ABC-1");
        assert_eq!(
            Sid::parse("S-1-4294967296-1").expect("sid").to_string(),
            "S-1-0x000100000000-1"
        );
        for bad in [
            "",
            "S",
            "S-2-5-18",
            "X-1-5-18",
            "S-1-5-",
            "S-1-5-a",
            "S-1-5-4294967296",
            "S-1-281474976710656-1",
            "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
            "S-1-+5-21-1",
            "S-1-0x+5-1",
            "S-1-0x-1",
            "S-1--5-1",
        ] {
            assert!(Sid::parse(bad).is_err(), "{bad:?}");
        }
        let bytes = sid.to_bytes();
        assert_eq!(bytes.len(), 8 + 4 * 5);
        assert_eq!(&bytes[..8], &[1, 5, 0, 0, 0, 0, 0, 5]);
        assert_eq!(Sid::from_bytes(&bytes).expect("sid"), sid);
        assert!(Sid::from_bytes(&bytes[..7]).is_err());
        assert!(Sid::from_bytes(&bytes[..12]).is_err());
        let mut wrong = bytes.clone();
        wrong[0] = 2;
        assert!(Sid::from_bytes(&wrong).is_err());
        let json = serde_json::to_string(&sid).expect("json");
        assert_eq!(json, format!("\"{text}\""));
        assert!(serde_json::from_str::<Sid>("\"S-1\"").is_err());
    }

    #[test]
    fn the_kerberos_policy_validates_and_decides_groups() {
        let admins = Sid::parse("S-1-5-21-1004336348-1177238915-682003330-512").expect("sid");
        let proxy = Sid::parse("S-1-5-21-1004336348-1177238915-682003330-1105").expect("sid");
        let mut settings = KerberosUpdate::for_realm(realm());
        assert_eq!(settings.owner_hold_days, 14);
        assert_eq!(settings.ownership, Ownership::Windows);
        settings.validate().expect("valid");
        settings.privileged.push(admins.clone());
        settings.update_proxy = Some(proxy.clone());
        settings.validate().expect("valid");
        assert!(settings.accepts_realm(&realm()));
        assert!(!settings.accepts_realm(&Realm::new("OTHER.EXAMPLE.TEST").expect("realm")));
        assert!(settings.is_privileged([&admins]));
        assert!(!settings.is_privileged([&proxy]));
        assert!(settings.is_update_proxy([&proxy]));
        assert!(!settings.is_update_proxy([&admins]));
        let json = serde_json::to_value(&settings).expect("json");
        assert_eq!(json["ownership"], "windows");
        assert_eq!(json["realms"][0], "CORP.EXAMPLE.TEST");
        let back: KerberosUpdate = serde_json::from_value(json).expect("json");
        assert_eq!(back, settings);
        let minimal: KerberosUpdate =
            serde_json::from_value(serde_json::json!({ "realms": ["corp.example.test"] }))
                .expect("json");
        assert_eq!(minimal, KerberosUpdate::for_realm(realm()));

        let mut empty = settings.clone();
        empty.realms.clear();
        assert!(empty.validate().is_err());
        let mut twice = settings.clone();
        twice.realms.push(realm());
        assert!(twice.validate().is_err());
        let mut long = settings.clone();
        long.owner_hold_days = 3651;
        assert!(long.validate().is_err());
        let mut dup = settings.clone();
        dup.privileged.push(admins.clone());
        assert!(dup.validate().is_err());
        let mut both = settings.clone();
        both.update_proxy = Some(admins);
        let error = both.validate().expect_err("the proxy is not privileged");
        assert_eq!(
            error
                .as_coded_error()
                .params
                .get("field")
                .map(String::as_str),
            Some("update.kerberos.update_proxy")
        );
    }

    #[test]
    fn name_owners_match_by_sid_then_by_principal() {
        let at: Timestamp = "2026-10-25T12:00:00Z".parse().expect("time");
        let later: Timestamp = "2026-11-10T12:00:00Z".parse().expect("time");
        let principal = PrincipalName::parse("WS01$@CORP.EXAMPLE.TEST").expect("principal");
        let renamed = PrincipalName::parse("WS02$@CORP.EXAMPLE.TEST").expect("principal");
        let sid = Sid::parse("S-1-5-21-1004336348-1177238915-682003330-1200").expect("sid");
        let other = Sid::parse("S-1-5-21-1004336348-1177238915-682003330-1201").expect("sid");
        let owner = NameOwner {
            sid: Some(sid.clone()),
            principal: principal.clone(),
            since: at,
            hold_until: None,
            how: OwnerSource::Created,
        };
        assert!(
            owner.is_owner(&renamed, Some(&sid)),
            "the SID survives a rename"
        );
        assert!(!owner.is_owner(&principal, Some(&other)));
        assert!(
            !owner.is_owner(&principal, None),
            "a principal without a SID never matches an owner with one"
        );
        assert!(!owner.hold_passed(later));
        let mit = NameOwner {
            sid: None,
            principal: principal.clone(),
            since: at,
            hold_until: Some(later),
            how: OwnerSource::Assigned,
        };
        assert!(mit.is_owner(&principal, Some(&sid)));
        assert!(!mit.is_owner(&renamed, Some(&sid)));
        assert!(!mit.hold_passed(at));
        assert!(mit.hold_passed(later));
    }

    fn account() -> KrbAccount {
        KrbAccount {
            realm: realm(),
            name: "TENKO-DNS$".to_owned(),
            spns: vec![
                "DNS/ns1.corp.example.test".to_owned(),
                "HTTP/ns1.corp.example.test".to_owned(),
            ],
            kdcs: Vec::new(),
            owned: true,
            rotation_days: DEFAULT_ROTATION_DAYS,
            versions: vec![KeyVersionMeta {
                kvno: 3,
                etypes: vec![
                    EncryptionType::Aes256CtsHmacSha1,
                    EncryptionType::Aes128CtsHmacSha1,
                ],
                state: KeyVersionState::Current,
                created: "2026-10-25T12:00:00Z".parse().expect("time"),
            }],
            last_rotation: None,
            last_check: None,
            secret: None,
            findings: Vec::new(),
        }
    }

    /// DNS-28 (WP13.3): a finding's text is cleaned and bounded, its parameters come from
    /// the fixed set, and an account refuses findings that break those bounds, too many
    /// of them, or a code that is not a DNS finding.
    #[test]
    fn dns_28_findings_are_bounded_and_cleaned() {
        let at: Timestamp = "2026-11-06T12:00:00Z".parse().expect("time");
        let finding = KrbFinding::new(
            super::super::findings::GSS_SPN_MISSING,
            "the KDC said\r\n\u{1b}[31mforged\u{0}",
            at,
        )
        .param("spn", "DNS/ns1.corp.example.test\n")
        .param("password", "never")
        .param("reason", "x".repeat(1_000));
        assert_eq!(finding.detail, "the KDC said   [31mforged ");
        assert_eq!(finding.params["spn"], "DNS/ns1.corp.example.test ");
        assert!(!finding.params.contains_key("password"));
        assert_eq!(finding.params["reason"].len(), MAX_KRB_FINDING_PARAM);
        let long = KrbFinding::new(
            super::super::findings::GSS_SPN_MISSING,
            &"ö".repeat(400),
            at,
        );
        assert!(long.detail.len() <= MAX_KRB_FINDING_DETAIL);
        assert!(long.detail.chars().all(|c| c == 'ö'));
        let mut account = account();
        account.findings = vec![finding.clone()];
        account.validate().expect("valid");
        account.findings = vec![finding.clone(); MAX_KRB_FINDINGS + 1];
        assert!(account.validate().is_err());
        let breaks: [fn(&mut KrbFinding); 4] = [
            |f| f.code = "dns.made.up".to_owned(),
            |f| f.detail = "a\nb".to_owned(),
            |f| {
                f.params.insert("password".to_owned(), "x".to_owned());
            },
            |f| {
                f.params
                    .insert("spn".to_owned(), "y".repeat(MAX_KRB_FINDING_PARAM + 1));
            },
        ];
        for broken in breaks {
            let mut bad = finding.clone();
            broken(&mut bad);
            account.findings = vec![bad];
            assert!(account.validate().is_err(), "{:?}", account.findings);
        }
        // The new fields are optional in the stored and the API form.
        let plain = self::account();
        let json = serde_json::to_value(&plain).expect("json");
        assert!(json.get("secret").is_none() && json.get("findings").is_none());
        let back: KrbAccount = serde_json::from_value(json).expect("back");
        assert_eq!(back, plain);
    }

    /// One change that breaks the account.
    type Change = fn(&mut KrbAccount);

    #[test]
    fn the_account_validates_and_derives_its_principal_and_salt() {
        let account = account();
        account.validate().expect("valid");
        assert_eq!(
            account.principal().expect("principal").to_string(),
            "TENKO-DNS$@CORP.EXAMPLE.TEST"
        );
        assert_eq!(
            account.computer_salt().as_deref(),
            Some("CORP.EXAMPLE.TESThosttenko-dns.corp.example.test")
        );
        assert_eq!(account.current().map(|version| version.kvno), Some(3));
        assert!(account.holds_kvno(3) && !account.holds_kvno(2));
        assert_eq!(EncryptionType::Aes256CtsHmacSha1.number(), 18);
        assert_eq!(
            EncryptionType::from_number(17),
            Some(EncryptionType::Aes128CtsHmacSha1)
        );
        assert_eq!(EncryptionType::from_number(23), None, "RC4 is never a type");
        let json = serde_json::to_value(&account).expect("json");
        assert_eq!(json["versions"][0]["etypes"][0], "aes256-cts-hmac-sha1");
        assert_eq!(json["versions"][0]["state"], "current");
        let back: KrbAccount = serde_json::from_value(json).expect("json");
        assert_eq!(back, account);

        let mut user = account.clone();
        user.name = "svc-dns".to_owned();
        assert_eq!(user.computer_salt(), None);
        user.validate().expect("a user account is valid");

        let failures: [(&str, Change); 9] = [
            ("name", |a| a.name.clear()),
            ("name", |a| a.name = "a@b".to_owned()),
            ("spns", |a| a.spns.clear()),
            ("spns", |a| a.spns.push("nohost".to_owned())),
            ("spns", |a| {
                a.spns.push("dns/ns1.corp.example.test".to_owned());
            }),
            ("kdcs", |a| a.kdcs.push(" ".to_owned())),
            ("rotation_days", |a| a.rotation_days = 366),
            ("versions", |a| a.versions.push(a.versions[0].clone())),
            ("versions", |a| a.versions[0].etypes.clear()),
        ];
        for (field, change) in failures {
            let mut broken = account.clone();
            change(&mut broken);
            let error = broken.validate().expect_err(field);
            assert_eq!(
                error
                    .as_coded_error()
                    .params
                    .get("field")
                    .map(String::as_str),
                Some(field)
            );
        }
        let mut two_current = account.clone();
        let mut second = two_current.versions[0].clone();
        second.kvno = 4;
        two_current.versions.push(second);
        assert!(two_current.validate().is_err());
    }
}
