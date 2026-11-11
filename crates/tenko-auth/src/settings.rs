//! Security profiles, the authentication toggles TGL-01 to TGL-07, the in-app update
//! toggle TGL-23, the secret reveal toggle TGL-24 and the audit export toggle TGL-21
//! (SECURITY-PROFILES.md).
//!
//! A profile is a bundle of toggle values, not a code path: [`Profile::defaults`] gives the
//! values, every toggle can then be changed on its own, and [`SecuritySettings::toggles`]
//! reports each one with its profile default, whether it deviates and whether it is weaker
//! than the Home baseline (which turns on the warning banner).

use std::time::Duration;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    hibp::BreachMode,
    lockout::{LockPolicy, LockoutMode},
    password::policy::PasswordPolicy,
};

/// The longest session lifetime TGL-04 accepts: one year.
pub const MAX_SESSION_SECS: u64 = 366 * 86_400;

/// The largest TGL-05 maximum (100 years); beyond it, use `unlimited`.
pub const MAX_TOKEN_DAYS: u32 = 36_500;

/// The default of [`SecuritySettings::unconfirmed_pin_days`].
pub const DEFAULT_UNCONFIRMED_PIN_DAYS: u32 = 30;
/// The longest period [`SecuritySettings::unconfirmed_pin_days`] accepts.
pub const MAX_UNCONFIRMED_PIN_DAYS: u32 = 365;

/// A security profile (API-10).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// One box, minimal friction (PER-01).
    Home,
    /// Business AD environment (PER-02).
    Standard,
    /// Regulated environments (PER-03).
    Hardened,
    /// Permissive configuration for testing and training (PER-04).
    Lab,
}

impl Profile {
    /// Every profile.
    pub const ALL: [Profile; 4] = [Self::Home, Self::Standard, Self::Hardened, Self::Lab];

    /// The stable `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Home => "home",
            Self::Standard => "standard",
            Self::Hardened => "hardened",
            Self::Lab => "lab",
        }
    }

    /// The toggle values of the profile (the matrix of SECURITY-PROFILES.md).
    pub fn defaults(self) -> SecuritySettings {
        const DAY: u64 = 86_400;
        const HOUR: u64 = 3_600;
        match self {
            Self::Home => SecuritySettings {
                profile: self,
                password_policy: PasswordPolicy::Pin,
                mfa: MfaRequirement::Optional,
                passkey_for_admins: false,
                session: SessionLifetime {
                    absolute_secs: 30 * DAY,
                    idle_secs: 7 * DAY,
                },
                token_max_days: Some(365),
                breach_check: BreachMode::Online,
                lockout: LockoutMode::ProgressiveDelay,
                lockout_policy: Some(LockPolicy::default()),
                unconfirmed_pin_days: Some(DEFAULT_UNCONFIRMED_PIN_DAYS),
                updates: Some(UpdatePolicy::new(UpdateInstall::Ui)),
                secret_reveal: Some(RevealPolicy::new(RevealStepUp::Session, false)),
                audit_export: Some(AuditExport::Local),
                transfer_site: None,
            },
            Self::Standard => SecuritySettings {
                profile: self,
                password_policy: PasswordPolicy::Standard,
                mfa: MfaRequirement::Administrators,
                passkey_for_admins: false,
                session: SessionLifetime {
                    absolute_secs: 12 * HOUR,
                    idle_secs: HOUR,
                },
                token_max_days: Some(90),
                breach_check: BreachMode::Online,
                lockout: LockoutMode::DelayThenTemporaryLock,
                lockout_policy: Some(LockPolicy::default()),
                unconfirmed_pin_days: Some(DEFAULT_UNCONFIRMED_PIN_DAYS),
                updates: Some(UpdatePolicy::new(UpdateInstall::UiStepUp)),
                secret_reveal: Some(RevealPolicy::new(RevealStepUp::Fresh, false)),
                audit_export: Some(AuditExport::Optional),
                transfer_site: None,
            },
            Self::Hardened => SecuritySettings {
                profile: self,
                password_policy: PasswordPolicy::Hardened,
                mfa: MfaRequirement::Everyone,
                passkey_for_admins: true,
                session: SessionLifetime {
                    absolute_secs: 8 * HOUR,
                    idle_secs: 15 * 60,
                },
                token_max_days: Some(30),
                breach_check: BreachMode::OfflinePreferred,
                lockout: LockoutMode::LockUntilUnlock,
                lockout_policy: Some(LockPolicy::hardened()),
                unconfirmed_pin_days: Some(DEFAULT_UNCONFIRMED_PIN_DAYS),
                updates: Some(UpdatePolicy::new(UpdateInstall::UploadOnly)),
                secret_reveal: Some(RevealPolicy::new(RevealStepUp::Passkey, true)),
                audit_export: Some(AuditExport::Required),
                transfer_site: None,
            },
            Self::Lab => SecuritySettings {
                profile: self,
                password_policy: PasswordPolicy::Pin,
                mfa: MfaRequirement::Optional,
                passkey_for_admins: false,
                session: SessionLifetime {
                    absolute_secs: 30 * DAY,
                    idle_secs: 7 * DAY,
                },
                token_max_days: None,
                breach_check: BreachMode::Off,
                lockout: LockoutMode::Off,
                lockout_policy: Some(LockPolicy::default()),
                unconfirmed_pin_days: Some(DEFAULT_UNCONFIRMED_PIN_DAYS),
                updates: Some(UpdatePolicy::new(UpdateInstall::Ui)),
                secret_reveal: Some(RevealPolicy::new(RevealStepUp::Session, false)),
                audit_export: Some(AuditExport::Local),
                transfer_site: None,
            },
        }
    }
}

/// How an administrator may install a new version from the UI (TGL-23, OPS-24).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum UpdateInstall {
    /// Download from the release source and install from the UI (Home, Lab).
    Ui,
    /// As `ui`, with a fresh authentication for every install (Standard).
    UiStepUp,
    /// Only an uploaded and verified release file, with a fresh authentication (Hardened).
    UploadOnly,
}

impl UpdateInstall {
    /// Whether installing needs a fresh authentication (step-up).
    pub const fn needs_step_up(self) -> bool {
        !matches!(self, Self::Ui)
    }

    /// Whether a release may be downloaded from the source and installed.
    pub const fn allows_download(self) -> bool {
        !matches!(self, Self::UploadOnly)
    }
}

/// TGL-23: the in-app update check and install (OPS-24). The check sends nothing but the
/// running version; `updates.air_gapped` in `tenko.toml` stops it regardless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct UpdatePolicy {
    /// Check the release source daily.
    pub check: bool,
    /// How a new version may be installed.
    pub install: UpdateInstall,
}

impl UpdatePolicy {
    /// Daily checks with the given install mode (every profile checks daily).
    pub const fn new(install: UpdateInstall) -> Self {
        Self {
            check: true,
            install,
        }
    }
}

/// How the audit trail leaves the installation (TGL-21, IAM-18). The audit log itself is
/// never off; the toggle decides whether export sinks are required. The variants are
/// ordered from the weakest to the strongest.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuditExport {
    /// The local, hash-chained audit log only (Home, Lab).
    Local,
    /// The local log; export sinks (syslog, CEF, JSON) may be configured (Standard).
    Optional,
    /// At least one export sink, with an alarm while one fails (Hardened).
    Required,
}

/// The authentication a reveal of an operator secret needs (TGL-24). The variants are
/// ordered from the weakest to the strongest.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RevealStepUp {
    /// The signed-in session, of password strength or stronger (Home, Lab).
    Session,
    /// A sign-in within the last five minutes (Standard).
    Fresh,
    /// A sign-in with a passkey or a hardware security key within the last five minutes
    /// (Hardened).
    Passkey,
}

/// TGL-24: what revealing an operator secret takes (IAM-16, API-11). The PIN coupling rule
/// (IAM-07) holds in every profile on top of it: a PIN-strength session never reveals, and
/// personal API tokens never reveal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct RevealPolicy {
    /// The authentication a reveal needs.
    pub step_up: RevealStepUp,
    /// Reveal only a secret that is bound to the host the request names: the host the
    /// person is looking at (Hardened). The secrets page cannot reveal then.
    pub bound_host_only: bool,
}

impl RevealPolicy {
    /// A policy.
    pub const fn new(step_up: RevealStepUp, bound_host_only: bool) -> Self {
        Self {
            step_up,
            bound_host_only,
        }
    }
}

/// Who must use a second factor (TGL-02). The PIN coupling rule (IAM-07) can force it
/// regardless.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MfaRequirement {
    /// Nobody (users may still enroll).
    Optional,
    /// Accounts with the `admin` role.
    Administrators,
    /// Every account.
    Everyone,
}

/// Session lifetimes (TGL-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct SessionLifetime {
    /// Seconds from login until the session ends regardless of activity.
    pub absolute_secs: u64,
    /// Seconds of inactivity that end the session.
    pub idle_secs: u64,
}

impl SessionLifetime {
    /// The absolute lifetime.
    pub const fn absolute(&self) -> Duration {
        Duration::from_secs(self.absolute_secs)
    }

    /// The idle lifetime.
    pub const fn idle(&self) -> Duration {
        Duration::from_secs(self.idle_secs)
    }
}

/// The authentication part of the security settings: the profile and TGL-01 to TGL-07.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecuritySettings {
    /// The selected profile.
    pub profile: Profile,
    /// TGL-01: password policy preset.
    pub password_policy: PasswordPolicy,
    /// TGL-02: MFA requirement.
    pub mfa: MfaRequirement,
    /// TGL-03: passkey required for administrators.
    pub passkey_for_admins: bool,
    /// TGL-04: session lifetime.
    pub session: SessionLifetime,
    /// TGL-05: API token maximum lifetime in days; `None` allows non-expiring tokens.
    #[serde(default)]
    pub token_max_days: Option<u32>,
    /// TGL-06: breached-password check.
    pub breach_check: BreachMode,
    /// TGL-07: lockout.
    pub lockout: LockoutMode,
    /// TGL-07: the numbers of the lock. `None` in settings stored before they could be
    /// set: the profile's value applies ([`SecuritySettings::lockout_policy`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockout_policy: Option<LockPolicy>,
    /// Days a PIN stored before the six-digit minimum keeps working without a sign-in that
    /// shows it meets the policy, counted from the upgrade (1 to 365). Afterwards it is
    /// refused like a wrong PIN until an administrator resets it, or, for the last
    /// administrator, until `tenko user unlock` on the host starts a new period. `None` in
    /// settings stored before the rule: 30 days.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unconfirmed_pin_days: Option<u32>,
    /// TGL-23: the in-app update check and install. `None` in settings stored before the
    /// toggle existed: the profile's value applies ([`SecuritySettings::updates`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updates: Option<UpdatePolicy>,
    /// TGL-24: what revealing an operator secret takes. `None` in settings stored before the
    /// toggle existed: the profile's value applies ([`SecuritySettings::secret_reveal`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_reveal: Option<RevealPolicy>,
    /// TGL-21: the audit export. `None` in settings stored before the toggle existed: the
    /// profile's value applies ([`SecuritySettings::audit_export`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_export: Option<AuditExport>,
    /// TGL-10: the networks that count as the site, in CIDR notation. Under Hardened a zone
    /// transfer to an address outside them needs XoT; an empty list makes every transfer
    /// need it. Absent in settings stored before the setting existed, and after a change of
    /// profile: the default ranges apply (private, shared, unique-local, loopback and
    /// link-local).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_site: Option<Vec<String>>,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Profile::Standard.defaults()
    }
}

/// One toggle as reported to the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ToggleState {
    /// The toggle id, for example `TGL-04`.
    pub id: String,
    /// The setting name in [`SecuritySettings`], for example `session`.
    pub setting: String,
    /// The current value.
    #[schema(value_type = Object)]
    pub value: serde_json::Value,
    /// The value of the selected profile.
    #[schema(value_type = Object)]
    pub profile_default: serde_json::Value,
    /// Whether the value differs from the profile.
    pub deviates: bool,
    /// Whether the value is weaker than the Home baseline (shown as a warning banner).
    pub weaker_than_home: bool,
}

impl SecuritySettings {
    /// The effective site list of TGL-10: the stored one, else the default ranges
    /// ([`tenko_core::dns::TRANSFER_SITE_DEFAULT`]).
    pub fn transfer_site(&self) -> Vec<String> {
        self.transfer_site.clone().unwrap_or_else(|| {
            tenko_core::dns::TRANSFER_SITE_DEFAULT
                .iter()
                .map(|network| (*network).to_owned())
                .collect()
        })
    }

    /// The effective TGL-23 value: the stored one, else the profile's.
    pub fn updates(&self) -> UpdatePolicy {
        self.updates
            .or_else(|| self.profile.defaults().updates)
            .unwrap_or(UpdatePolicy::new(UpdateInstall::UiStepUp))
    }

    /// The effective period of an unconfirmed PIN from before the six-digit minimum.
    pub fn unconfirmed_pin_days(&self) -> u32 {
        self.unconfirmed_pin_days
            .unwrap_or(DEFAULT_UNCONFIRMED_PIN_DAYS)
    }

    /// The effective lock policy of TGL-07: the stored one, else the profile's.
    pub fn lockout_policy(&self) -> LockPolicy {
        self.lockout_policy
            .clone()
            .or_else(|| self.profile.defaults().lockout_policy)
            .unwrap_or_default()
    }

    /// The value TGL-07 reports: the mode with the numbers of the lock.
    fn lockout_toggle(&self) -> serde_json::Value {
        let mut value = serde_json::to_value(self.lockout_policy()).unwrap_or_default();
        if let Some(object) = value.as_object_mut() {
            object.insert(
                "mode".to_owned(),
                serde_json::Value::String(self.lockout.as_str().to_owned()),
            );
        }
        value
    }

    /// The effective TGL-21 value: the stored one, else the profile's.
    pub fn audit_export(&self) -> AuditExport {
        self.audit_export
            .or_else(|| self.profile.defaults().audit_export)
            .unwrap_or(AuditExport::Optional)
    }

    /// The effective TGL-24 value: the stored one, else the profile's.
    pub fn secret_reveal(&self) -> RevealPolicy {
        self.secret_reveal
            .or_else(|| self.profile.defaults().secret_reveal)
            .unwrap_or(RevealPolicy::new(RevealStepUp::Fresh, false))
    }

    /// The toggles TGL-01 to TGL-07, TGL-21, TGL-23 and TGL-24 with deviation and weakness markers.
    pub fn toggles(&self) -> Vec<ToggleState> {
        let profile = self.profile.defaults();
        let home = Profile::Home.defaults();
        let json =
            |value: serde_json::Result<serde_json::Value>| value.unwrap_or(serde_json::Value::Null);
        let entry = |id: &str, setting: &str, value, default, weaker: bool| ToggleState {
            id: id.to_owned(),
            setting: setting.to_owned(),
            deviates: value != default,
            value,
            profile_default: default,
            weaker_than_home: weaker,
        };
        vec![
            entry(
                "TGL-01",
                "password_policy",
                json(serde_json::to_value(&self.password_policy)),
                json(serde_json::to_value(&profile.password_policy)),
                self.password_policy.min_length() < home.password_policy.min_length(),
            ),
            entry(
                "TGL-02",
                "mfa",
                json(serde_json::to_value(self.mfa)),
                json(serde_json::to_value(profile.mfa)),
                self.mfa < home.mfa,
            ),
            entry(
                "TGL-03",
                "passkey_for_admins",
                serde_json::Value::Bool(self.passkey_for_admins),
                serde_json::Value::Bool(profile.passkey_for_admins),
                !self.passkey_for_admins && home.passkey_for_admins,
            ),
            entry(
                "TGL-04",
                "session",
                json(serde_json::to_value(self.session)),
                json(serde_json::to_value(profile.session)),
                self.session.absolute_secs > home.session.absolute_secs
                    || self.session.idle_secs > home.session.idle_secs,
            ),
            entry(
                "TGL-05",
                "token_max_days",
                json(serde_json::to_value(self.token_max_days)),
                json(serde_json::to_value(profile.token_max_days)),
                match (self.token_max_days, home.token_max_days) {
                    (None, Some(_)) => true,
                    (Some(days), Some(home_days)) => days > home_days,
                    _ => false,
                },
            ),
            entry(
                "TGL-06",
                "breach_check",
                json(serde_json::to_value(self.breach_check)),
                json(serde_json::to_value(profile.breach_check)),
                self.breach_check == BreachMode::Off && home.breach_check != BreachMode::Off,
            ),
            // Weaker than Home: no lockout at all, more attempts or shorter waits and locks
            // than Home's, or no account-wide delay where Home has one.
            entry(
                "TGL-07",
                "lockout",
                self.lockout_toggle(),
                profile.lockout_toggle(),
                (self.lockout == LockoutMode::Off && home.lockout != LockoutMode::Off)
                    || self.lockout_policy().weaker_than(&home.lockout_policy()),
            ),
            // Home keeps the audit log local, the weakest value, so no value is weaker.
            entry(
                "TGL-21",
                "audit_export",
                json(serde_json::to_value(self.audit_export())),
                json(serde_json::to_value(profile.audit_export())),
                self.audit_export() < home.audit_export(),
            ),
            // No install mode is weaker than the Home value (install from the UI); a check
            // that is off is, because security fixes then go unnoticed.
            entry(
                "TGL-23",
                "updates",
                json(serde_json::to_value(self.updates())),
                json(serde_json::to_value(profile.updates())),
                !self.updates().check && home.updates().check,
            ),
            // A weaker step-up than Home's, or dropping a host binding Home asks for, is
            // weaker; Home asks for neither, so no value is weaker today.
            entry(
                "TGL-24",
                "secret_reveal",
                json(serde_json::to_value(self.secret_reveal())),
                json(serde_json::to_value(profile.secret_reveal())),
                self.secret_reveal().step_up < home.secret_reveal().step_up
                    || (!self.secret_reveal().bound_host_only
                        && home.secret_reveal().bound_host_only),
            ),
        ]
    }

    /// The banner state: the Lab profile, or any toggle weaker than Home.
    pub fn banner(&self) -> Banner {
        let toggles = self.toggles();
        Banner {
            lab: self.profile == Profile::Lab,
            weaker_than_home: toggles.iter().any(|toggle| toggle.weaker_than_home),
            deviations: toggles
                .iter()
                .filter(|toggle| toggle.deviates)
                .map(|toggle| toggle.id.clone())
                .collect(),
        }
    }

    /// Checks values that the type system does not: a valid Custom preset, positive
    /// lifetimes with idle not above absolute, a positive token maximum.
    ///
    /// # Errors
    ///
    /// [`crate::AuthError::Invalid`] naming the setting.
    pub fn validate(&self) -> Result<(), crate::AuthError> {
        self.password_policy.validate()?;
        if let Some(policy) = &self.lockout_policy {
            policy.validate()?;
        }
        if self
            .unconfirmed_pin_days
            .is_some_and(|days| days == 0 || days > MAX_UNCONFIRMED_PIN_DAYS)
        {
            return Err(crate::AuthError::invalid(
                "unconfirmed_pin_days",
                "the period must be 1 to 365 days",
            ));
        }
        if self.session.absolute_secs == 0
            || self.session.idle_secs == 0
            || self.session.idle_secs > self.session.absolute_secs
            || self.session.absolute_secs > MAX_SESSION_SECS
        {
            return Err(crate::AuthError::invalid(
                "session",
                "lifetimes must be positive, at most one year, and idle must not exceed absolute",
            ));
        }
        if self
            .token_max_days
            .is_some_and(|days| days == 0 || days > MAX_TOKEN_DAYS)
        {
            return Err(crate::AuthError::invalid(
                "token_max_days",
                "the maximum must be 1 to 36,500 days",
            ));
        }
        if let Some(site) = &self.transfer_site {
            tenko_core::dns::parse_transfer_site(site).map_err(|_| {
                crate::AuthError::invalid(
                    "transfer_site",
                    "every entry is a network in CIDR notation, such as 10.0.0.0/8, at most 256",
                )
            })?;
        }
        Ok(())
    }
}

/// What the UI needs for its warning banner (API-10: insecure settings are loud).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Banner {
    /// The Lab profile is active.
    pub lab: bool,
    /// At least one toggle is weaker than the Home baseline.
    pub weaker_than_home: bool,
    /// Toggles that deviate from the selected profile.
    pub deviations: Vec<String>,
}

/// A change of the security settings (`PATCH /settings/security`). A new profile resets
/// every toggle to its values first; explicit toggles then apply on top.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SettingsPatch {
    /// Switch to this profile.
    #[serde(default)]
    pub profile: Option<Profile>,
    /// TGL-01.
    #[serde(default)]
    pub password_policy: Option<PasswordPolicy>,
    /// TGL-02.
    #[serde(default)]
    pub mfa: Option<MfaRequirement>,
    /// TGL-03.
    #[serde(default)]
    pub passkey_for_admins: Option<bool>,
    /// TGL-04.
    #[serde(default)]
    pub session: Option<SessionLifetime>,
    /// TGL-05: a number of days, or `unlimited`.
    #[serde(default)]
    pub token_max_lifetime: Option<TokenMaxLifetime>,
    /// TGL-06.
    #[serde(default)]
    pub breach_check: Option<BreachMode>,
    /// TGL-07.
    #[serde(default)]
    pub lockout: Option<LockoutMode>,
    /// TGL-07: the numbers of the lock.
    #[serde(default)]
    pub lockout_policy: Option<LockPolicy>,
    /// The period of an unconfirmed PIN from before the six-digit minimum, in days.
    #[serde(default)]
    pub unconfirmed_pin_days: Option<u32>,
    /// TGL-23.
    #[serde(default)]
    pub updates: Option<UpdatePolicy>,
    /// TGL-24.
    #[serde(default)]
    pub secret_reveal: Option<RevealPolicy>,
    /// TGL-21.
    #[serde(default)]
    pub audit_export: Option<AuditExport>,
    /// TGL-10: the networks that count as the site, in CIDR notation; an empty list is
    /// allowed (every transfer needs XoT under Hardened).
    #[serde(default)]
    pub transfer_site: Option<Vec<String>>,
}

/// The TGL-05 value in a patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenMaxLifetime {
    /// At most this many days.
    Days(u32),
    /// Non-expiring tokens are allowed.
    Unlimited,
}

impl SettingsPatch {
    /// Applies the patch to `current`.
    pub fn apply(&self, current: &SecuritySettings) -> SecuritySettings {
        let mut next = self
            .profile
            .map_or_else(|| current.clone(), Profile::defaults);
        if let Some(policy) = &self.password_policy {
            next.password_policy = policy.clone();
        }
        if let Some(mfa) = self.mfa {
            next.mfa = mfa;
        }
        if let Some(passkey) = self.passkey_for_admins {
            next.passkey_for_admins = passkey;
        }
        if let Some(session) = self.session {
            next.session = session;
        }
        if let Some(lifetime) = self.token_max_lifetime {
            next.token_max_days = match lifetime {
                TokenMaxLifetime::Days(days) => Some(days),
                TokenMaxLifetime::Unlimited => None,
            };
        }
        if let Some(mode) = self.breach_check {
            next.breach_check = mode;
        }
        if let Some(mode) = self.lockout {
            next.lockout = mode;
        }
        if let Some(policy) = &self.lockout_policy {
            next.lockout_policy = Some(policy.clone());
        }
        if let Some(days) = self.unconfirmed_pin_days {
            next.unconfirmed_pin_days = Some(days);
        }
        if let Some(updates) = self.updates {
            next.updates = Some(updates);
        }
        if let Some(reveal) = self.secret_reveal {
            next.secret_reveal = Some(reveal);
        }
        if let Some(export) = self.audit_export {
            next.audit_export = Some(export);
        }
        if let Some(site) = &self.transfer_site {
            next.transfer_site = Some(
                site.iter()
                    .map(|network| network.trim().to_owned())
                    .collect(),
            );
        }
        next
    }
}

/// The audit changes between two settings: one entry per changed toggle (`TGL-xx`) and
/// the profile, with old and new values as compact JSON.
pub fn changes(
    old: &SecuritySettings,
    new: &SecuritySettings,
) -> Vec<tenko_core::audit::FieldChange> {
    let mut changes = Vec::new();
    if old.profile != new.profile {
        changes.push(tenko_core::audit::FieldChange {
            object: None,
            field: "profile".to_owned(),
            old: Some(old.profile.as_str().to_owned()),
            new: Some(new.profile.as_str().to_owned()),
        });
    }
    if old.transfer_site() != new.transfer_site() {
        changes.push(tenko_core::audit::FieldChange {
            object: None,
            field: "transfer_site".to_owned(),
            old: Some(old.transfer_site().join(", ")),
            new: Some(new.transfer_site().join(", ")),
        });
    }
    if old.unconfirmed_pin_days() != new.unconfirmed_pin_days() {
        changes.push(tenko_core::audit::FieldChange {
            object: None,
            field: "unconfirmed_pin_days".to_owned(),
            old: Some(old.unconfirmed_pin_days().to_string()),
            new: Some(new.unconfirmed_pin_days().to_string()),
        });
    }
    for (before, after) in old.toggles().into_iter().zip(new.toggles()) {
        if before.value != after.value {
            changes.push(tenko_core::audit::FieldChange {
                object: None,
                field: before.id,
                old: Some(before.value.to_string()),
                new: Some(after.value.to_string()),
            });
        }
    }
    changes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_export_follows_the_matrix_and_old_settings() {
        assert_eq!(Profile::Home.defaults().audit_export(), AuditExport::Local);
        assert_eq!(
            Profile::Standard.defaults().audit_export(),
            AuditExport::Optional
        );
        assert_eq!(
            Profile::Hardened.defaults().audit_export(),
            AuditExport::Required
        );
        assert_eq!(Profile::Lab.defaults().audit_export(), AuditExport::Local);
        let mut stored = serde_json::to_value(Profile::Hardened.defaults()).expect("json");
        stored
            .as_object_mut()
            .expect("an object")
            .remove("audit_export");
        let old: SecuritySettings = serde_json::from_value(stored).expect("older settings");
        assert_eq!(old.audit_export, None);
        assert_eq!(old.audit_export(), AuditExport::Required);
        let toggles = Profile::Home.defaults().toggles();
        let toggle = toggles
            .iter()
            .find(|toggle| toggle.id == "TGL-21")
            .expect("TGL-21 is listed");
        assert_eq!(toggle.setting, "audit_export");
        assert!(!toggle.weaker_than_home);
        let patched = SettingsPatch {
            audit_export: Some(AuditExport::Required),
            ..SettingsPatch::default()
        }
        .apply(&Profile::Home.defaults());
        assert_eq!(patched.audit_export(), AuditExport::Required);
        assert!(
            patched
                .toggles()
                .iter()
                .any(|toggle| toggle.id == "TGL-21" && toggle.deviates)
        );
    }

    /// TGL-10: the site of the Hardened XoT rule is a list the administrator sets; settings
    /// without it, and a new profile, have the default ranges; an empty list is allowed;
    /// a change is audited with both lists.
    #[test]
    fn the_transfer_site_defaults_validates_and_is_audited() {
        let defaults: Vec<String> = tenko_core::dns::TRANSFER_SITE_DEFAULT
            .iter()
            .map(|network| (*network).to_owned())
            .collect();
        let hardened = Profile::Hardened.defaults();
        assert_eq!(hardened.transfer_site, None);
        assert_eq!(hardened.transfer_site(), defaults);
        let mut stored = serde_json::to_value(&hardened).expect("json");
        assert!(stored.get("transfer_site").is_none(), "absent when not set");
        stored.as_object_mut().expect("an object").insert(
            "transfer_site".to_owned(),
            serde_json::json!(["198.51.100.0/24"]),
        );
        let set: SecuritySettings = serde_json::from_value(stored).expect("settings");
        assert_eq!(set.transfer_site(), ["198.51.100.0/24"]);
        let empty = SettingsPatch {
            transfer_site: Some(Vec::new()),
            ..SettingsPatch::default()
        }
        .apply(&hardened);
        empty.validate().expect("an empty site is allowed");
        assert_eq!(empty.transfer_site(), Vec::<String>::new());
        let changed = changes(&hardened, &empty);
        assert!(changed.iter().any(|change| change.field == "transfer_site"
            && change.old.as_deref() == Some(defaults.join(", ").as_str())
            && change.new.as_deref() == Some("")));
        let wrong = SettingsPatch {
            transfer_site: Some(vec!["10.0.0.0/33".to_owned()]),
            ..SettingsPatch::default()
        }
        .apply(&hardened);
        assert!(wrong.validate().is_err());
        let switched = SettingsPatch {
            profile: Some(Profile::Standard),
            ..SettingsPatch::default()
        }
        .apply(&set);
        assert_eq!(
            switched.transfer_site(),
            defaults,
            "a new profile resets the site"
        );
    }

    #[test]
    fn profile_defaults_follow_the_matrix() {
        let home = Profile::Home.defaults();
        assert_eq!(home.password_policy, PasswordPolicy::Pin);
        assert_eq!(home.session.absolute(), Duration::from_secs(30 * 86_400));
        assert_eq!(home.token_max_days, Some(365));
        let standard = Profile::Standard.defaults();
        assert_eq!(standard.mfa, MfaRequirement::Administrators);
        assert_eq!(standard.session.idle_secs, 3_600);
        assert_eq!(standard.lockout, LockoutMode::DelayThenTemporaryLock);
        let hardened = Profile::Hardened.defaults();
        assert_eq!(hardened.password_policy, PasswordPolicy::Hardened);
        assert!(hardened.passkey_for_admins);
        assert_eq!(hardened.session.idle_secs, 900);
        assert_eq!(hardened.breach_check, BreachMode::OfflinePreferred);
        assert_eq!(home.updates().install, UpdateInstall::Ui);
        assert_eq!(standard.updates().install, UpdateInstall::UiStepUp);
        assert_eq!(hardened.updates().install, UpdateInstall::UploadOnly);
        assert!(hardened.updates().check);
        let lab = Profile::Lab.defaults();
        assert_eq!(lab.updates().install, UpdateInstall::Ui);
        assert_eq!(lab.token_max_days, None);
        assert_eq!(lab.breach_check, BreachMode::Off);
        assert_eq!(lab.lockout, LockoutMode::Off);
        for profile in Profile::ALL {
            profile
                .defaults()
                .validate()
                .expect("profile defaults are valid");
        }
    }

    #[test]
    fn profiles_have_no_deviations_and_only_lab_is_weaker() {
        for profile in Profile::ALL {
            let banner = profile.defaults().banner();
            assert!(banner.deviations.is_empty(), "{profile:?}");
            assert_eq!(banner.lab, profile == Profile::Lab);
            assert_eq!(
                banner.weaker_than_home,
                profile == Profile::Lab,
                "{profile:?}"
            );
        }
    }

    #[test]
    fn a_changed_toggle_is_a_deviation_and_may_be_weaker() {
        let mut settings = Profile::Standard.defaults();
        settings.session.absolute_secs = 60 * 86_400;
        let toggles = settings.toggles();
        let session = toggles.iter().find(|t| t.id == "TGL-04").expect("TGL-04");
        assert!(session.deviates);
        assert!(session.weaker_than_home);
        let banner = settings.banner();
        assert_eq!(banner.deviations, vec!["TGL-04".to_owned()]);
        assert!(banner.weaker_than_home);
    }

    #[test]
    fn patches_reset_to_the_profile_then_apply_toggles() {
        let current = Profile::Home.defaults();
        let patch = SettingsPatch {
            profile: Some(Profile::Hardened),
            lockout: Some(LockoutMode::ProgressiveDelay),
            token_max_lifetime: Some(TokenMaxLifetime::Unlimited),
            ..SettingsPatch::default()
        };
        let next = patch.apply(&current);
        assert_eq!(next.profile, Profile::Hardened);
        assert_eq!(next.password_policy, PasswordPolicy::Hardened);
        assert_eq!(next.lockout, LockoutMode::ProgressiveDelay);
        assert_eq!(next.token_max_days, None);
        let audit = changes(&current, &next);
        let fields: Vec<&str> = audit.iter().map(|change| change.field.as_str()).collect();
        assert!(fields.contains(&"profile"));
        assert!(fields.contains(&"TGL-01"));
        // The mode stayed, but Hardened's lock also holds for a passkey.
        assert!(fields.contains(&"TGL-07"));
        assert!(next.lockout_policy().passkey_holds_lock);
    }

    #[test]
    fn the_lock_policy_follows_the_profile_and_reports_with_its_mode() {
        for profile in Profile::ALL {
            let settings = profile.defaults();
            assert_eq!(
                settings.lockout_policy().passkey_holds_lock,
                profile == Profile::Hardened,
                "{profile:?}"
            );
            assert_eq!(settings.unconfirmed_pin_days(), 30);
        }
        // Settings stored before the policy could be set take the profile's.
        let mut stored = serde_json::to_value(Profile::Hardened.defaults()).expect("json");
        let object = stored.as_object_mut().expect("an object");
        object.remove("lockout_policy");
        object.remove("unconfirmed_pin_days");
        let old: SecuritySettings = serde_json::from_value(stored).expect("older settings");
        assert_eq!(old.lockout_policy(), LockPolicy::hardened());
        assert_eq!(old.unconfirmed_pin_days(), DEFAULT_UNCONFIRMED_PIN_DAYS);
        // TGL-07 reports the mode with the numbers.
        let toggles = Profile::Standard.defaults().toggles();
        let toggle = toggles.iter().find(|t| t.id == "TGL-07").expect("TGL-07");
        assert_eq!(toggle.value["mode"], "delay_then_temporary_lock");
        assert_eq!(toggle.value["attempts"], 3);
        assert_eq!(
            toggle.value["waits_secs"],
            serde_json::json!([10, 30, 180, 300, 600])
        );
        assert_eq!(toggle.value["lock_secs"], 1_800);
        assert_eq!(toggle.value["account_max_delay_secs"], 60);
        // A weaker policy than Home's deviates and is weaker than Home.
        let patched = SettingsPatch {
            lockout_policy: Some(LockPolicy {
                attempts: 10,
                ..LockPolicy::default()
            }),
            ..SettingsPatch::default()
        }
        .apply(&Profile::Standard.defaults());
        let banner = patched.banner();
        assert_eq!(banner.deviations, vec!["TGL-07".to_owned()]);
        assert!(banner.weaker_than_home);
        // Out of bounds is refused.
        let mut invalid = Profile::Standard.defaults();
        invalid.lockout_policy = Some(LockPolicy {
            attempts: 0,
            ..LockPolicy::default()
        });
        assert!(invalid.validate().is_err());
        let mut invalid = Profile::Standard.defaults();
        invalid.unconfirmed_pin_days = Some(0);
        assert!(invalid.validate().is_err());
        invalid.unconfirmed_pin_days = Some(366);
        assert!(invalid.validate().is_err());
        // A changed period is audited.
        let longer = SettingsPatch {
            unconfirmed_pin_days: Some(60),
            ..SettingsPatch::default()
        }
        .apply(&Profile::Home.defaults());
        let audit = changes(&Profile::Home.defaults(), &longer);
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].field, "unconfirmed_pin_days");
    }

    #[test]
    fn stored_settings_without_tgl_23_take_the_profile_value() {
        let mut stored = serde_json::to_value(Profile::Hardened.defaults()).expect("json");
        stored.as_object_mut().expect("an object").remove("updates");
        let settings: SecuritySettings = serde_json::from_value(stored).expect("old settings");
        assert_eq!(settings.updates, None);
        assert_eq!(settings.updates().install, UpdateInstall::UploadOnly);
        assert_eq!(settings.banner().deviations, Vec::<String>::new());
        assert!(UpdateInstall::UploadOnly.needs_step_up());
        assert!(!UpdateInstall::Ui.needs_step_up());
        assert!(!UpdateInstall::UploadOnly.allows_download());
    }

    #[test]
    fn switching_the_update_check_off_is_weaker_than_home() {
        let patch = SettingsPatch {
            updates: Some(UpdatePolicy {
                check: false,
                install: UpdateInstall::UiStepUp,
            }),
            ..SettingsPatch::default()
        };
        let next = patch.apply(&Profile::Standard.defaults());
        let banner = next.banner();
        assert_eq!(banner.deviations, vec!["TGL-23".to_owned()]);
        assert!(banner.weaker_than_home);
        let audit = changes(&Profile::Standard.defaults(), &next);
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].field, "TGL-23");
    }

    #[test]
    fn secret_reveal_follows_the_matrix() {
        assert_eq!(
            Profile::Home.defaults().secret_reveal(),
            RevealPolicy::new(RevealStepUp::Session, false)
        );
        assert_eq!(
            Profile::Standard.defaults().secret_reveal(),
            RevealPolicy::new(RevealStepUp::Fresh, false)
        );
        assert_eq!(
            Profile::Hardened.defaults().secret_reveal(),
            RevealPolicy::new(RevealStepUp::Passkey, true)
        );
        assert_eq!(
            Profile::Lab.defaults().secret_reveal(),
            RevealPolicy::new(RevealStepUp::Session, false)
        );
        assert!(RevealStepUp::Session < RevealStepUp::Fresh);
        assert!(RevealStepUp::Fresh < RevealStepUp::Passkey);
        let json =
            serde_json::to_value(RevealPolicy::new(RevealStepUp::Passkey, true)).expect("json");
        assert_eq!(
            json,
            serde_json::json!({ "step_up": "passkey", "bound_host_only": true })
        );
    }

    #[test]
    fn stored_settings_without_tgl_24_take_the_profile_value() {
        let mut stored = serde_json::to_value(Profile::Standard.defaults()).expect("json");
        stored
            .as_object_mut()
            .expect("an object")
            .remove("secret_reveal");
        let settings: SecuritySettings = serde_json::from_value(stored).expect("old settings");
        assert_eq!(settings.secret_reveal, None);
        assert_eq!(settings.secret_reveal().step_up, RevealStepUp::Fresh);
        assert_eq!(settings.banner().deviations, Vec::<String>::new());
    }

    #[test]
    fn a_changed_reveal_policy_is_a_deviation_and_audited() {
        let patch = SettingsPatch {
            secret_reveal: Some(RevealPolicy::new(RevealStepUp::Session, false)),
            ..SettingsPatch::default()
        };
        let next = patch.apply(&Profile::Standard.defaults());
        let banner = next.banner();
        assert_eq!(banner.deviations, vec!["TGL-24".to_owned()]);
        assert!(!banner.weaker_than_home);
        let audit = changes(&Profile::Standard.defaults(), &next);
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].field, "TGL-24");
        let toggles = next.toggles();
        let toggle = toggles.iter().find(|t| t.id == "TGL-24").expect("TGL-24");
        assert_eq!(toggle.setting, "secret_reveal");
        assert!(toggle.deviates);
        // A new profile resets the toggle to the profile's value.
        let reset = SettingsPatch {
            profile: Some(Profile::Hardened),
            ..SettingsPatch::default()
        }
        .apply(&next);
        assert_eq!(
            reset.secret_reveal(),
            RevealPolicy::new(RevealStepUp::Passkey, true)
        );
    }

    #[test]
    fn invalid_values_are_refused() {
        let mut settings = Profile::Standard.defaults();
        settings.session.idle_secs = settings.session.absolute_secs + 1;
        assert!(settings.validate().is_err());
        let mut settings = Profile::Standard.defaults();
        settings.token_max_days = Some(0);
        assert!(settings.validate().is_err());
    }
}
