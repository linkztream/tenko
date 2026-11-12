//! Directory sign-in: the contracts of the identity plan's directory line (sections 3.12
//! to 3.17 and 4.1; ADR 0026 points 8 and 9; WP13.0). Providers (`OpenID Connect`, LDAP,
//! Kerberos through the browser), the certificate trust of an LDAP provider, the mappings
//! of directory groups onto roles and scopes, the external identity of a user, and the
//! state of an `OpenID Connect` sign-in in flight.
//!
//! This module holds the records, their tables, the error codes and the audit actions.
//! Nothing here talks to a directory: the LDAP and OIDC clients are `tenko-directory`
//! (section 4.2, WP13.5 and WP13.6), the sign-in flows `tenko-auth`'s service (WP13.5).
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `auth.providers` | [`ProviderId`] | [`ProviderRecord`] |
//! | `auth.mappings` | [`MappingId`] | [`DirectoryMapping`] |
//! | `auth.oidc_flows` | SHA-256 of the flow secret | [`OidcFlow`] |
//! | `auth.external_ids` | ([`ProviderId`], subject) | [`UserId`] (unique) |
//!
//! Secrets never enter these tables: a provider's client secret and an LDAP service
//! account's password are system secrets in the vault (purposes [`OIDC_PURPOSE`] and
//! [`LDAP_PURPOSE`]), referenced by [`SecretRef`]; a trust holds certificates, never a
//! key. The flow record holds the state, the nonce and the PKCE verifier of one sign-in,
//! which the callback compares and the token request sends; it lives ten minutes under the
//! hash of the flow cookie's secret and is used once.

use serde::{Deserialize, Serialize};
use tenko_core::{
    ScopeRule, Timestamp, UserId,
    dns::{Realm, Sid},
    error::InvalidValue,
    secret::SecretRef,
    table::TableDef,
};
use utoipa::ToSchema;

use crate::roles::RoleName;

tenko_core::id_type! {
    /// Identifier of a sign-in provider.
    ProviderId,
    /// Identifier of a directory mapping.
    MappingId,
}

/// Sign-in providers by id.
pub const PROVIDERS: TableDef<ProviderId, ProviderRecord> = TableDef::new("auth.providers");
/// Directory mappings by id.
pub const MAPPINGS: TableDef<MappingId, DirectoryMapping> = TableDef::new("auth.mappings");
/// `OpenID Connect` sign-ins in flight, by the SHA-256 of the flow cookie's secret.
pub const OIDC_FLOWS: TableDef<Vec<u8>, OidcFlow> = TableDef::new("auth.oidc_flows");
/// The user of each external identity: provider and subject to user id, unique, so that
/// a subject is one Tenko record whatever its display name becomes.
pub const EXTERNAL_IDS: TableDef<(ProviderId, String), UserId> = TableDef::new("auth.external_ids");

/// The secret purpose of an OIDC provider's client secret in the vault.
pub const OIDC_PURPOSE: &str = "auth.oidc";
/// The secret purpose of an LDAP provider's service account password in the vault.
pub const LDAP_PURPOSE: &str = "auth.ldap";

/// How long an `OpenID Connect` sign-in may take between the start and the callback.
pub const OIDC_FLOW_SECS: u64 = 600;

/// The longest provider name.
pub const MAX_PROVIDER_NAME: usize = 64;

/// The most URLs an LDAP provider lists.
pub const MAX_LDAP_URLS: usize = 16;

/// The most certificates a trust holds.
pub const MAX_TRUST_CERTS: usize = 16;

// ---------------------------------------------------------------------------------------
// Users and sessions

/// Where a user record comes from (section 3.16).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UserSource {
    /// A local account: password, passkeys, second factors (IAM-03 to IAM-10).
    #[default]
    Local,
    /// Created at the first sign-in through a provider, keyed by the immutable subject
    /// (the OIDC `iss` and `sub`, the AD `objectGUID`, the Kerberos SID), never the
    /// display name. The record has no password.
    External {
        /// The provider.
        provider: ProviderId,
        /// The subject as the provider identifies it.
        subject: String,
    },
}

impl UserSource {
    /// Whether the record is a local account, for `skip_serializing_if`.
    pub fn is_local(&self) -> bool {
        *self == Self::Local
    }
}

/// How a session was signed in (section 3.17).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionSource {
    /// A local sign-in: password, passkey, second factor, recovery code.
    #[default]
    Local,
    /// An `OpenID Connect` sign-in through the provider.
    Oidc {
        /// The provider.
        provider: ProviderId,
    },
    /// An LDAP bind through the provider.
    Ldap {
        /// The provider.
        provider: ProviderId,
    },
    /// Kerberos through the browser (SPNEGO, RFC 4559) under the provider.
    Negotiate {
        /// The provider.
        provider: ProviderId,
    },
}

impl SessionSource {
    /// Whether the session is a local one, for `skip_serializing_if`.
    pub fn is_local(&self) -> bool {
        *self == Self::Local
    }

    /// The provider of a directory session.
    pub fn provider(&self) -> Option<ProviderId> {
        match self {
            Self::Local => None,
            Self::Oidc { provider } | Self::Ldap { provider } | Self::Negotiate { provider } => {
                Some(*provider)
            }
        }
    }

    /// The method as the audit record `auth.login` names it.
    pub const fn method(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Oidc { .. } => "oidc",
            Self::Ldap { .. } => "ldap",
            Self::Negotiate { .. } => "negotiate",
        }
    }
}

// ---------------------------------------------------------------------------------------
// Providers

/// Where a provider stands (section 3.12): a provider becomes `verified` only after an
/// administrator completed a test sign-in through it; under Hardened the local person
/// accounts step back once one is verified (ID-Q15).
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProviderState {
    /// Configured, no test sign-in completed yet: offered to nobody.
    #[default]
    Draft,
    /// A test sign-in completed: offered on the sign-in page.
    Verified,
    /// Switched off by an administrator; its users keep their records, local accounts
    /// sign in again under Hardened.
    Disabled,
}

/// What an OIDC provider's `amr` claim says about a second factor (ID-Q16).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OidcMfa {
    /// The claim is not trusted: the profile's MFA rule asks for a Tenko factor.
    #[default]
    None,
    /// An `amr` value in the list yields the strength of a password with TOTP; `hwk`
    /// yields a hardware key when the provider is marked as attesting it.
    TrustAmr {
        /// The values that count as a second factor (`mfa`, `hwk`, `otp`, ...).
        values: Vec<String>,
        /// Whether `hwk` from this provider counts as a hardware security key.
        #[serde(default)]
        hardware_key: bool,
    },
}

/// An `OpenID Connect` provider (section 3.12): Entra ID, AD FS, Keycloak, Okta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OidcSettings {
    /// The issuer, exactly as the ID token names it; discovery reads
    /// `<issuer>/.well-known/openid-configuration`.
    pub issuer: String,
    /// The client id of Tenko at the provider.
    pub client_id: String,
    /// The client secret in the vault (purpose [`OIDC_PURPOSE`]).
    pub client_secret: SecretRef,
    /// The scopes asked beyond `openid`.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// The claim that becomes the user name (`preferred_username` by default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username_claim: Option<String>,
    /// The claim that lists the groups or app roles (`groups`, `roles`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups_claim: Option<String>,
    /// What the `amr` claim is trusted for.
    #[serde(default)]
    pub mfa: OidcMfa,
    /// A PEM bundle the provider's certificate is checked against instead of the system
    /// trust store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<String>,
    /// The text of the sign-in button; the provider's name when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub button_label: Option<String>,
}

/// How an LDAP provider is reached (ID-Q13, TGL-34).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LdapTransport {
    /// LDAP over TLS on 636.
    #[default]
    Ldaps,
    /// `StartTLS` on 389.
    StartTls,
    /// Plain LDAP: the Lab profile only, with the clear-text warning.
    Plain,
}

/// What an LDAP provider's TLS connection verifies the server against (the owner's
/// addition to ID-Q13, section 3.13). Certificates only, never a key; "accept whatever is
/// presented" does not exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LdapTrust {
    /// The system trust store.
    System,
    /// A PEM bundle the administrator pasted or uploaded.
    Pem {
        /// The certificates, PEM, one or more.
        certs: Vec<String>,
    },
    /// The chain fetched from the server and pinned after the administrator confirmed
    /// it by its fingerprints; a chain that changes later is refused and shown, never
    /// pinned again silently.
    Imported {
        /// The certificates confirmed, PEM.
        certs: Vec<String>,
        /// Their SHA-256 fingerprints, lower-case hexadecimal, in the order of `certs`.
        fingerprints: Vec<String>,
        /// The administrator who confirmed them.
        confirmed_by: UserId,
        /// When.
        confirmed_at: Timestamp,
    },
}

impl LdapTrust {
    /// Checks the trust: 1 to 16 certificates, each a PEM certificate and never a key, and
    /// one fingerprint per imported certificate.
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] naming the rule broken.
    pub fn validate(&self) -> Result<(), InvalidValue> {
        let (certs, fingerprints) = match self {
            Self::System => return Ok(()),
            Self::Pem { certs } => (certs, None),
            Self::Imported {
                certs,
                fingerprints,
                ..
            } => (certs, Some(fingerprints)),
        };
        if certs.is_empty() || certs.len() > MAX_TRUST_CERTS {
            return Err(InvalidValue::new(
                "trust",
                &certs.len().to_string(),
                "a trust holds 1 to 16 certificates",
            ));
        }
        for cert in certs {
            check_pem_certificate(cert)?;
        }
        if let Some(fingerprints) = fingerprints {
            if fingerprints.len() != certs.len() {
                return Err(InvalidValue::new(
                    "trust",
                    &fingerprints.len().to_string(),
                    "one fingerprint per certificate",
                ));
            }
            for fingerprint in fingerprints {
                if fingerprint.len() != 64
                    || !fingerprint
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                {
                    return Err(InvalidValue::new(
                        "trust",
                        fingerprint,
                        "a fingerprint is SHA-256 in lower-case hexadecimal",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Checks that a PEM block is a certificate and not a key.
///
/// # Errors
///
/// [`InvalidValue`] for text that is not a `CERTIFICATE` block, or that holds a key.
pub fn check_pem_certificate(text: &str) -> Result<(), InvalidValue> {
    let shown: String = text.chars().take(40).collect();
    if text.contains("PRIVATE KEY") {
        return Err(InvalidValue::new(
            "certificate",
            &shown,
            "a trust holds certificates, never a key",
        ));
    }
    let trimmed = text.trim();
    if !trimmed.starts_with("-----BEGIN CERTIFICATE-----")
        || !trimmed.ends_with("-----END CERTIFICATE-----")
        || trimmed.len() > 64 * 1024
    {
        return Err(InvalidValue::new(
            "certificate",
            &shown,
            "a PEM certificate block of at most 64 KiB",
        ));
    }
    Ok(())
}

/// The read-only service account that finds users and runs the directory check (ID-Q13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LdapBind {
    /// The distinguished name (or user principal name) it binds as.
    pub dn: String,
    /// Its password in the vault (purpose [`LDAP_PURPOSE`]).
    pub secret: SecretRef,
}

/// How the groups of a user are read (section 3.13).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LdapGroupMode {
    /// `tokenGroups` of the user's entry: every group SID held transitively (AD only).
    #[default]
    TokenGroups,
    /// The `memberOf` attribute, with nesting only where the server resolves it.
    MemberOf,
    /// A search for groups whose member attribute names the user.
    Search,
}

/// An LDAP provider (section 3.13): Active Directory or another directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LdapSettings {
    /// The servers, `ldaps://` or `ldap://` URLs tried in order, or one entry
    /// `srv:<domain>` for `_ldap._tcp.<domain>` discovery.
    pub urls: Vec<String>,
    /// LDAPS, `StartTLS` or plain (Lab only).
    #[serde(default)]
    pub transport: LdapTransport,
    /// What the server's certificate is verified against.
    pub trust: LdapTrust,
    /// The service account; absent: the user's own bind only, no directory check (allowed
    /// under Home, ID-Q13).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<LdapBind>,
    /// Where users are searched.
    pub base_dn: String,
    /// A filter that narrows the users found, in RFC 4515 syntax, combined with the name
    /// match (`(memberOf=cn=Tenko,...)`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_filter: Option<String>,
    /// How groups are read.
    #[serde(default)]
    pub group_mode: LdapGroupMode,
    /// Minutes between directory checks of a session; absent: the profile's (TGL-35).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recheck_minutes: Option<u16>,
    /// Minutes a session is kept while the directory cannot be reached; absent: the
    /// profile's (TGL-35).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_minutes: Option<u16>,
    /// The name suffixes and `NetBIOS` domains that route a user name to this provider
    /// (`corp.example.test` for `alex@corp.example.test`, `CORP` for `CORP\alex`).
    #[serde(default)]
    pub suffixes: Vec<String>,
    /// Whether a bare user name without a local account goes to this provider.
    #[serde(default)]
    pub default: bool,
}

/// A Kerberos sign-in provider (section 3.14): the realm whose tickets `GET
/// /auth/negotiate` accepts; its mappings are by SID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NegotiateSettings {
    /// The realm.
    pub realm: Realm,
}

/// A sign-in provider's settings by kind (section 4.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DirectoryProvider {
    /// `OpenID Connect`.
    Oidc(OidcSettings),
    /// LDAP.
    Ldap(LdapSettings),
    /// Kerberos through the browser.
    Negotiate(NegotiateSettings),
}

impl DirectoryProvider {
    /// The kind as the audit record and the API name it.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Oidc(_) => "oidc",
            Self::Ldap(_) => "ldap",
            Self::Negotiate(_) => "negotiate",
        }
    }

    /// Checks the settings: an `https://` issuer and a client id for OIDC; 1 to 16 URLs
    /// of the right scheme, a base DN and a valid trust for LDAP (the transport's rule
    /// against the profile is the service's, TGL-34).
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] naming the field.
    pub fn validate(&self) -> Result<(), InvalidValue> {
        match self {
            Self::Oidc(oidc) => {
                if !oidc.issuer.starts_with("https://") || oidc.issuer.len() > 512 {
                    return Err(InvalidValue::new(
                        "issuer",
                        &oidc.issuer,
                        "an https URL of at most 512 characters",
                    ));
                }
                if oidc.client_id.trim().is_empty() || oidc.client_id.len() > 256 {
                    return Err(InvalidValue::new(
                        "client_id",
                        &oidc.client_id,
                        "1 to 256 characters",
                    ));
                }
                if let Some(ca) = &oidc.ca {
                    check_pem_certificate(ca)?;
                }
                Ok(())
            }
            Self::Ldap(ldap) => {
                if ldap.urls.is_empty() || ldap.urls.len() > MAX_LDAP_URLS {
                    return Err(InvalidValue::new(
                        "urls",
                        &ldap.urls.len().to_string(),
                        "1 to 16 servers",
                    ));
                }
                for url in &ldap.urls {
                    let scheme_ok = match ldap.transport {
                        LdapTransport::Ldaps => url.starts_with("ldaps://"),
                        LdapTransport::StartTls | LdapTransport::Plain => {
                            url.starts_with("ldap://")
                        }
                    } || url.starts_with("srv:");
                    if !scheme_ok || url.len() > 512 {
                        return Err(InvalidValue::new(
                            "urls",
                            url,
                            "an ldaps:// URL for LDAPS, an ldap:// URL otherwise, or srv:<domain>",
                        ));
                    }
                }
                if ldap.base_dn.trim().is_empty() || ldap.base_dn.len() > 1024 {
                    return Err(InvalidValue::new(
                        "base_dn",
                        &ldap.base_dn,
                        "1 to 1024 characters",
                    ));
                }
                ldap.trust.validate()?;
                if matches!(ldap.recheck_minutes, Some(0)) {
                    return Err(InvalidValue::new(
                        "recheck_minutes",
                        "0",
                        "at least one minute",
                    ));
                }
                Ok(())
            }
            Self::Negotiate(_) => Ok(()),
        }
    }
}

/// A stored sign-in provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRecord {
    /// The id.
    pub id: ProviderId,
    /// A unique name, 1 to 64 characters, shown on the sign-in button and in the audit log.
    pub name: String,
    /// The settings.
    pub provider: DirectoryProvider,
    /// Draft, verified or disabled.
    #[serde(default)]
    pub state: ProviderState,
    /// When it was created.
    pub created_at: Timestamp,
    /// The last change.
    pub updated_at: Timestamp,
    /// The last successful sign-in or test.
    #[serde(default)]
    pub last_success: Option<Timestamp>,
    /// The last error, as a message key with its detail, for the provider's page.
    #[serde(default)]
    pub last_error: Option<String>,
}

impl ProviderRecord {
    /// Checks the record: the name and the settings.
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] naming the field.
    pub fn validate(&self) -> Result<(), InvalidValue> {
        let name = self.name.trim();
        if name.is_empty() || name.chars().count() > MAX_PROVIDER_NAME || name != self.name {
            return Err(InvalidValue::new(
                "name",
                &self.name,
                "1 to 64 characters without surrounding spaces",
            ));
        }
        if self.name.chars().any(char::is_control) {
            return Err(InvalidValue::new(
                "name",
                &self.name,
                "no control characters",
            ));
        }
        self.provider.validate()
    }

    /// Whether the provider is offered on the sign-in page.
    pub fn is_offered(&self) -> bool {
        self.state == ProviderState::Verified
    }
}

// ---------------------------------------------------------------------------------------
// Mappings

/// The group a mapping matches (section 3.16).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GroupMatch {
    /// A group SID, from `tokenGroups` or the PAC.
    Sid {
        /// The SID.
        sid: Sid,
    },
    /// A group's distinguished name, from `memberOf` or a search.
    Dn {
        /// The DN.
        dn: String,
    },
    /// A value of the OIDC groups claim (a group id or an app role).
    Claim {
        /// The value.
        value: String,
    },
}

/// A mapping of a directory group onto a role and a scope (section 3.16): evaluated at
/// sign-in and at each directory check, held on the session, never stored as a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DirectoryMapping {
    /// The id.
    pub id: MappingId,
    /// The provider whose groups this mapping reads.
    pub provider: ProviderId,
    /// The group.
    pub group: GroupMatch,
    /// The role.
    pub role: RoleName,
    /// Where the role applies (`{kind, value}` as in a grant); absent for the whole
    /// installation. `admin` and `auditor` take none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<crate::service::types::ScopeRuleSchema>)]
    pub scope: Option<ScopeRule>,
}

impl DirectoryMapping {
    /// Checks the mapping: a DN or a claim value of 1 to 1024 characters, and no scope on
    /// a global role.
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] naming the field.
    pub fn validate(&self) -> Result<(), InvalidValue> {
        let text = match &self.group {
            GroupMatch::Sid { .. } => None,
            GroupMatch::Dn { dn } => Some(("dn", dn)),
            GroupMatch::Claim { value } => Some(("value", value)),
        };
        if let Some((field, value)) = text
            && (value.trim().is_empty()
                || value.len() > 1024
                || value.chars().any(char::is_control))
        {
            return Err(InvalidValue::new(field, value, "1 to 1024 characters"));
        }
        if self.scope.is_some() && matches!(self.role, RoleName::Admin | RoleName::Auditor) {
            return Err(InvalidValue::new(
                "scope",
                self.role.as_str(),
                "a global role takes no scope",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// `OpenID Connect` flows

/// One `OpenID Connect` sign-in between the start and the callback (section 3.12): single
/// use, ten minutes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcFlow {
    /// The provider.
    pub provider: ProviderId,
    /// The `state` sent to the provider and expected back.
    pub state: String,
    /// The `nonce` the ID token must carry.
    pub nonce: String,
    /// The PKCE verifier (S256) sent with the token request.
    pub pkce_verifier: String,
    /// Where the browser goes after the sign-in; a path of the UI, never a URL.
    pub return_path: String,
    /// When the flow started.
    pub created_at: Timestamp,
    /// When it expires (ten minutes after the start).
    pub expires_at: Timestamp,
}

impl OidcFlow {
    /// Whether the flow has expired at `now`.
    pub fn expired(&self, now: Timestamp) -> bool {
        now >= self.expires_at
    }
}

/// The state, the nonce and the verifier are the secrets of a live sign-in: a log shows
/// the provider, the return path and the times only.
impl std::fmt::Debug for OidcFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcFlow")
            .field("provider", &self.provider)
            .field("return_path", &self.return_path)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------------------
// Codes and actions

/// The stable error codes of directory sign-in (API-08; sections 3.12, 3.13 and 4.3).
pub mod codes {
    /// The provider does not exist (404). Params: `id`.
    pub const PROVIDER_NOT_FOUND: &str = "auth.provider.not_found";
    /// The provider settings are invalid (400). Params: `field`, `reason`.
    pub const PROVIDER_INVALID: &str = "auth.provider.invalid";
    /// A provider of this name exists already (409). Params: `name`.
    pub const PROVIDER_EXISTS: &str = "auth.provider.exists";
    /// The provider has not completed a test sign-in, so it cannot be offered (409).
    /// Params: `id`.
    pub const PROVIDER_UNVERIFIED: &str = "auth.provider.unverified";
    /// The provider or the directory cannot be reached (503). Params: `id`, `reason`.
    pub const PROVIDER_UNAVAILABLE: &str = "auth.provider.unavailable";
    /// Plain LDAP is allowed under the Lab profile only (409, TGL-34). Params: `profile`.
    pub const PROVIDER_PLAIN_REFUSED: &str = "auth.provider.plain_refused";
    /// The certificate chain the server presents is not the pinned one (a finding and a
    /// refusal, 502). Params: `id`, `fingerprint`.
    pub const PROVIDER_CHAIN_CHANGED: &str = "auth.provider.chain_changed";
    /// The fetched chain does not verify against the system trust store: shown for
    /// confirmation, not an error of the fetch (a finding). Params: `id`, `fingerprint`.
    pub const PROVIDER_CHAIN_UNVERIFIED: &str = "auth.provider.chain_unverified";
    /// No mapping matches the user's groups: the sign-in is refused and no record is
    /// created (403). Params: `provider`.
    pub const DIRECTORY_NO_MAPPING: &str = "auth.directory.no_mapping";
    /// The directory reports the account disabled or expired (403). Params: `provider`.
    pub const DIRECTORY_ACCOUNT_DISABLED: &str = "auth.directory.account_disabled";
    /// The provider sent a group overage marker instead of the groups (403; Entra ID
    /// beyond 200 groups: use app roles). Params: `provider`.
    pub const DIRECTORY_OVERAGE: &str = "auth.directory.overage";
    /// The mapping does not exist (404). Params: `id`.
    pub const DIRECTORY_MAPPING_NOT_FOUND: &str = "auth.directory.mapping_not_found";
    /// The mapping is invalid (400). Params: `field`, `reason`.
    pub const DIRECTORY_MAPPING_INVALID: &str = "auth.directory.mapping_invalid";
    /// The same group, role and scope is mapped already for the provider (409). Params:
    /// `id`.
    pub const DIRECTORY_MAPPING_DUPLICATE: &str = "auth.directory.mapping_duplicate";
    /// The callback does not match a flow: no cookie, a wrong `state`, or the flow
    /// expired or was used (400). Params: `reason`.
    pub const OIDC_FLOW_INVALID: &str = "auth.oidc.flow_invalid";
    /// The ID token was refused: issuer, audience, `azp`, nonce, time, algorithm or
    /// signature (401). Params: `reason`.
    pub const OIDC_TOKEN_INVALID: &str = "auth.oidc.token_invalid";
    /// The provider answered an error at the callback or the token endpoint (502).
    /// Params: `error`.
    pub const OIDC_PROVIDER_ERROR: &str = "auth.oidc.provider_error";
    /// The provider's discovery document could not be fetched or is not one (502).
    /// Params: `issuer`, `reason`.
    pub const OIDC_DISCOVERY_FAILED: &str = "auth.oidc.discovery_failed";

    /// Every code, for the contracts document and its test.
    pub const ALL: [&str; 18] = [
        PROVIDER_NOT_FOUND,
        PROVIDER_INVALID,
        PROVIDER_EXISTS,
        PROVIDER_UNVERIFIED,
        PROVIDER_UNAVAILABLE,
        PROVIDER_PLAIN_REFUSED,
        PROVIDER_CHAIN_CHANGED,
        PROVIDER_CHAIN_UNVERIFIED,
        DIRECTORY_NO_MAPPING,
        DIRECTORY_ACCOUNT_DISABLED,
        DIRECTORY_OVERAGE,
        DIRECTORY_MAPPING_NOT_FOUND,
        DIRECTORY_MAPPING_INVALID,
        DIRECTORY_MAPPING_DUPLICATE,
        OIDC_FLOW_INVALID,
        OIDC_TOKEN_INVALID,
        OIDC_PROVIDER_ERROR,
        OIDC_DISCOVERY_FAILED,
    ];
}

/// The audit actions of directory sign-in (section 3.11). `auth.login.*` records gain the
/// method and the provider when WP13.5 writes them; never a token, a password or a
/// ticket in a record.
pub mod actions {
    use tenko_core::audit::AuditAction;

    /// A provider was created.
    pub const PROVIDER_CREATE: AuditAction = AuditAction::from_static("auth.provider.create");
    /// A provider changed (settings, state, trust).
    pub const PROVIDER_UPDATE: AuditAction = AuditAction::from_static("auth.provider.update");
    /// A provider was deleted.
    pub const PROVIDER_DELETE: AuditAction = AuditAction::from_static("auth.provider.delete");
    /// A test sign-in completed, or failed.
    pub const PROVIDER_VERIFY: AuditAction = AuditAction::from_static("auth.provider.verify");
    /// A mapping was created.
    pub const MAPPING_CREATE: AuditAction = AuditAction::from_static("auth.mapping.create");
    /// A mapping was deleted.
    pub const MAPPING_DELETE: AuditAction = AuditAction::from_static("auth.mapping.delete");
    /// A directory check ended a session or narrowed its rights.
    pub const DIRECTORY_REVOKE: AuditAction = AuditAction::from_static("auth.directory.revoke");

    /// Every action, for the contracts document and its test.
    pub const ALL: [&AuditAction; 7] = [
        &PROVIDER_CREATE,
        &PROVIDER_UPDATE,
        &PROVIDER_DELETE,
        &PROVIDER_VERIFY,
        &MAPPING_CREATE,
        &MAPPING_DELETE,
        &DIRECTORY_REVOKE,
    ];
}

#[cfg(test)]
mod tests {
    use tenko_core::{
        AuthStrength, SessionId, Timestamp,
        codec::{from_cbor, to_cbor},
        names::is_valid_name,
    };

    use super::*;
    use crate::model::{SESSIONS, SessionRecord, USERS, UserRecord};

    fn at(text: &str) -> Timestamp {
        text.parse().expect("time")
    }

    fn cert() -> String {
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----".to_owned()
    }

    fn ldap() -> DirectoryProvider {
        DirectoryProvider::Ldap(LdapSettings {
            urls: vec!["ldaps://dc01.corp.example.test".to_owned()],
            transport: LdapTransport::Ldaps,
            trust: LdapTrust::Imported {
                certs: vec![cert()],
                fingerprints: vec!["ab".repeat(32)],
                confirmed_by: UserId::generate(),
                confirmed_at: at("2026-10-25T12:00:00Z"),
            },
            bind: Some(LdapBind {
                dn: "CN=svc-tenko,OU=Service,DC=corp,DC=example,DC=test".to_owned(),
                secret: SecretRef {
                    secret: tenko_core::SecretId::generate(),
                },
            }),
            base_dn: "DC=corp,DC=example,DC=test".to_owned(),
            user_filter: None,
            group_mode: LdapGroupMode::TokenGroups,
            recheck_minutes: None,
            grace_minutes: None,
            suffixes: vec!["corp.example.test".to_owned(), "CORP".to_owned()],
            default: true,
        })
    }

    fn record(provider: DirectoryProvider) -> ProviderRecord {
        ProviderRecord {
            id: ProviderId::generate(),
            name: "Corp AD".to_owned(),
            provider,
            state: ProviderState::Draft,
            created_at: at("2026-10-25T12:00:00Z"),
            updated_at: at("2026-10-25T12:00:00Z"),
            last_success: None,
            last_error: None,
        }
    }

    #[test]
    fn providers_validate_and_round_trip() {
        let ldap = record(ldap());
        ldap.validate().expect("valid");
        assert_eq!(ldap.provider.kind(), "ldap");
        assert!(!ldap.is_offered());
        let encoded = PROVIDERS.encode(&ldap).expect("cbor");
        assert_eq!(PROVIDERS.decode(&encoded).expect("cbor"), ldap);
        let json = serde_json::to_value(&ldap.provider).expect("json");
        assert_eq!(json["kind"], "ldap");
        assert_eq!(json["trust"]["kind"], "imported");
        assert_eq!(json["transport"], "ldaps");
        assert_eq!(json["group_mode"], "token_groups");

        let oidc = record(DirectoryProvider::Oidc(OidcSettings {
            issuer: "https://login.example.test/realms/corp".to_owned(),
            client_id: "tenko".to_owned(),
            client_secret: SecretRef {
                secret: tenko_core::SecretId::generate(),
            },
            scopes: vec!["profile".to_owned()],
            username_claim: None,
            groups_claim: Some("groups".to_owned()),
            mfa: OidcMfa::TrustAmr {
                values: vec!["mfa".to_owned(), "hwk".to_owned()],
                hardware_key: false,
            },
            ca: None,
            button_label: None,
        }));
        oidc.validate().expect("valid");
        let json = serde_json::to_value(&oidc.provider).expect("json");
        assert_eq!(json["kind"], "oidc");
        assert_eq!(json["mfa"]["kind"], "trust_amr");
        let negotiate = record(DirectoryProvider::Negotiate(NegotiateSettings {
            realm: Realm::new("corp.example.test").expect("realm"),
        }));
        negotiate.validate().expect("valid");
        assert_eq!(
            serde_json::to_value(&negotiate.provider).expect("json")["realm"],
            "CORP.EXAMPLE.TEST"
        );

        let mut unnamed = ldap.clone();
        unnamed.name = " ".to_owned();
        assert!(unnamed.validate().is_err());
        let mut http = oidc.clone();
        if let DirectoryProvider::Oidc(settings) = &mut http.provider {
            settings.issuer = "http://login.example.test".to_owned();
        }
        assert!(http.validate().is_err(), "an issuer is https");
        let mut wrong_scheme = ldap.clone();
        if let DirectoryProvider::Ldap(settings) = &mut wrong_scheme.provider {
            settings.urls = vec!["ldap://dc01.corp.example.test".to_owned()];
        }
        assert!(wrong_scheme.validate().is_err(), "LDAPS needs ldaps://");
        let mut no_base = ldap.clone();
        if let DirectoryProvider::Ldap(settings) = &mut no_base.provider {
            settings.base_dn.clear();
        }
        assert!(no_base.validate().is_err());
    }

    #[test]
    fn a_trust_holds_certificates_and_never_a_key() {
        LdapTrust::System.validate().expect("the system store");
        LdapTrust::Pem {
            certs: vec![cert()],
        }
        .validate()
        .expect("a bundle");
        assert!(LdapTrust::Pem { certs: Vec::new() }.validate().is_err());
        assert!(
            LdapTrust::Pem {
                certs: vec![cert(); 17]
            }
            .validate()
            .is_err()
        );
        let key = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----".to_owned();
        let error = LdapTrust::Pem { certs: vec![key] }
            .validate()
            .expect_err("a key");
        assert!(error.to_string().contains("never a key"), "{error}");
        assert!(
            LdapTrust::Pem {
                certs: vec!["hello".to_owned()]
            }
            .validate()
            .is_err()
        );
        let imported = |fingerprints: Vec<String>| LdapTrust::Imported {
            certs: vec![cert()],
            fingerprints,
            confirmed_by: UserId::generate(),
            confirmed_at: at("2026-10-25T12:00:00Z"),
        };
        imported(vec!["0f".repeat(32)])
            .validate()
            .expect("one fingerprint");
        assert!(
            imported(Vec::new()).validate().is_err(),
            "a fingerprint each"
        );
        assert!(
            imported(vec!["0F".repeat(32)]).validate().is_err(),
            "lower case"
        );
        assert!(
            imported(vec!["0f".repeat(31)]).validate().is_err(),
            "SHA-256"
        );
    }

    #[test]
    fn mappings_validate_their_group_and_scope() {
        let provider = ProviderId::generate();
        let mapping = DirectoryMapping {
            id: MappingId::generate(),
            provider,
            group: GroupMatch::Sid {
                sid: Sid::parse("S-1-5-21-1004336348-1177238915-682003330-1105").expect("sid"),
            },
            role: RoleName::Operator,
            scope: None,
        };
        mapping.validate().expect("valid");
        let json = serde_json::to_value(&mapping).expect("json");
        assert_eq!(json["group"]["kind"], "sid");
        assert_eq!(json["role"], "operator");
        assert!(json.get("scope").is_none());
        let back: DirectoryMapping = serde_json::from_value(json).expect("json");
        assert_eq!(back, mapping);
        assert_eq!(
            from_cbor::<DirectoryMapping>(&to_cbor(&mapping).expect("cbor")).expect("cbor"),
            mapping
        );
        let claim = DirectoryMapping {
            group: GroupMatch::Claim {
                value: "tenko-admins".to_owned(),
            },
            role: RoleName::Admin,
            ..mapping.clone()
        };
        claim.validate().expect("valid");
        let scoped_admin = DirectoryMapping {
            scope: Some(ScopeRule::Tenant(tenko_core::TenantId::generate())),
            ..claim.clone()
        };
        assert!(scoped_admin.validate().is_err(), "admin takes no scope");
        let empty_dn = DirectoryMapping {
            group: GroupMatch::Dn { dn: " ".to_owned() },
            ..mapping.clone()
        };
        assert!(empty_dn.validate().is_err());
    }

    #[test]
    fn flows_expire_and_sources_default_to_local() {
        let flow = OidcFlow {
            provider: ProviderId::generate(),
            state: "s".to_owned(),
            nonce: "n".to_owned(),
            pkce_verifier: "v".to_owned(),
            return_path: "/dns".to_owned(),
            created_at: at("2026-10-25T12:00:00Z"),
            expires_at: at("2026-10-25T12:10:00Z"),
        };
        assert!(!flow.expired(at("2026-10-25T12:09:59Z")));
        assert!(flow.expired(at("2026-10-25T12:10:00Z")));
        let encoded = OIDC_FLOWS.encode(&flow).expect("cbor");
        assert_eq!(OIDC_FLOWS.decode(&encoded).expect("cbor"), flow);

        assert_eq!(UserSource::default(), UserSource::Local);
        assert!(UserSource::Local.is_local());
        let external = UserSource::External {
            provider: ProviderId::generate(),
            subject: "S-1-5-21-1004336348-1177238915-682003330-1200".to_owned(),
        };
        assert!(!external.is_local());
        assert_eq!(
            serde_json::to_value(&external).expect("json")["kind"],
            "external"
        );
        let source = SessionSource::Ldap {
            provider: ProviderId::generate(),
        };
        assert_eq!(source.method(), "ldap");
        assert!(source.provider().is_some());
        assert_eq!(SessionSource::Local.provider(), None);
        assert_eq!(SessionSource::Local.method(), "local");

        // A user and a session stored by 0.0.11 (no source, no directory check) read as
        // local, and write back without the fields.
        let user = UserRecord::new(
            "alex".to_owned(),
            "Alex".to_owned(),
            vec![],
            at("2026-10-10T08:00:00Z"),
        );
        assert_eq!(user.source, UserSource::Local);
        // The CBOR text key `source` is six characters: 0x66 then the text.
        let source_key = b"\x66source";
        let bytes = USERS.encode(&user).expect("cbor");
        assert!(
            !bytes.windows(7).any(|w| w == source_key),
            "absent when local"
        );
        assert_eq!(USERS.decode(&bytes).expect("cbor"), user);
        let session = SessionRecord {
            id: SessionId::generate(),
            user: user.id,
            strength: AuthStrength::Password,
            created_at: at("2026-10-10T08:00:00Z"),
            authenticated_at: at("2026-10-10T08:00:00Z"),
            expires_at: at("2026-10-10T09:00:00Z"),
            idle_expires_at: at("2026-10-10T08:30:00Z"),
            last_seen_at: at("2026-10-10T08:00:00Z"),
            source_ip: None,
            user_agent: None,
            break_glass: false,
            mfa_enrollment_required: false,
            source: SessionSource::Local,
            directory_checked_at: None,
            generation: 0,
        };
        let bytes = SESSIONS.encode(&session).expect("cbor");
        assert!(!bytes.windows(7).any(|w| w == source_key));
        assert_eq!(SESSIONS.decode(&bytes).expect("cbor"), session);
    }

    #[test]
    fn tables_codes_and_actions_are_in_the_namespace() {
        for table in [
            PROVIDERS.name(),
            MAPPINGS.name(),
            OIDC_FLOWS.name(),
            EXTERNAL_IDS.name(),
        ] {
            assert_eq!(table.namespace(), "auth", "{table}");
        }
        assert_eq!(EXTERNAL_IDS.name().as_str(), "auth.external_ids");
        for code in codes::ALL {
            assert!(code.starts_with("auth.") && is_valid_name(code), "{code}");
        }
        for prefix in ["auth.provider.", "auth.directory.", "auth.oidc."] {
            assert!(
                codes::ALL.iter().any(|code| code.starts_with(prefix)),
                "{prefix}"
            );
        }
        for action in actions::ALL {
            assert!(action.as_str().starts_with("auth."), "{action}");
        }
        assert_eq!([OIDC_PURPOSE, LDAP_PURPOSE], ["auth.oidc", "auth.ldap"]);
        assert_eq!(OIDC_FLOW_SECS, 600);
    }
}
