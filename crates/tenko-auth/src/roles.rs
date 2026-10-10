//! Roles (`admin`, `operator`, `viewer`, and `auditor` since Slice 3), their permissions,
//! their order for delegation and the strength rules.
//!
//! A role held globally (`UserRecord::roles`) covers every object of the kinds it allows; a
//! role held through a scoped grant (`auth.grants`, IAM-01) covers the objects its rule
//! reaches ([`crate::authz`]). The MFA requirement of a role (IAM-06) defaults to the
//! profile's TGL-02 and TGL-03 ([`default_policy`]) and can be raised per role.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use tenko_core::{Action, AuthStrength, ObjectKind};
use utoipa::ToSchema;

use crate::{
    model::RoleMfa,
    settings::{MfaRequirement, SecuritySettings},
};

/// A global role.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RoleName {
    /// Everything, including users, settings and the system.
    Admin,
    /// Day-to-day IPAM work: read, change and run, but no administration.
    Operator,
    /// Read-only access to the inventory.
    Viewer,
    /// Reads the audit trail, the audit export status and the system status, and nothing
    /// else: no inventory, users or settings (owner decision S3-Q18, IAM-18). Global only.
    Auditor,
}

impl RoleName {
    /// Every role.
    pub const ALL: [RoleName; 4] = [Self::Admin, Self::Operator, Self::Viewer, Self::Auditor];

    /// The stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Viewer => "viewer",
            Self::Auditor => "auditor",
        }
    }

    /// An English description for the role list.
    pub const fn description(self) -> &'static str {
        match self {
            Self::Admin => "Full access, including users, security settings and the system",
            Self::Operator => {
                "Reads and changes the IPAM inventory, runs imports and jobs, reveals operator secrets; no administration"
            }
            Self::Viewer => "Reads the IPAM inventory, jobs and imports",
            Self::Auditor => {
                "Reads the audit log, the audit export status and the system status; nothing else"
            }
        }
    }

    /// Whether the role grants `action` on objects of `kind`.
    pub fn allows(self, action: Action, kind: ObjectKind) -> bool {
        match self {
            Self::Admin => true,
            Self::Operator => operator_allows(action, kind),
            Self::Viewer => action == Action::Read && is_inventory(kind),
            // The audit log, the export status and the system status are reads of the
            // system object; every other kind (inventory, users, settings, secrets, nodes)
            // stays closed, and scoped grants never carry the role.
            Self::Auditor => action == Action::Read && kind == ObjectKind::System,
        }
    }

    /// Whether a holder of this role may hand out `other` (delegation, the grants of a
    /// scoped token): a role no higher. The administrator covers every role, the operator
    /// covers the viewer, and the auditor covers only itself.
    pub const fn covers(self, other: RoleName) -> bool {
        matches!(
            (self, other),
            (Self::Admin, _)
                | (Self::Operator, Self::Operator | Self::Viewer)
                | (Self::Viewer, Self::Viewer)
                | (Self::Auditor, Self::Auditor)
        )
    }
}

impl fmt::Display for RoleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RoleName {
    type Err = crate::AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|role| role.as_str() == s)
            .ok_or_else(|| crate::AuthError::invalid("roles", format!("unknown role `{s}`")))
    }
}

/// Kinds a viewer may read and an operator may work with.
fn is_inventory(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::Tenant
            | ObjectKind::Vrf
            | ObjectKind::Site
            | ObjectKind::Vlan
            | ObjectKind::Prefix
            | ObjectKind::Range
            | ObjectKind::Address
            | ObjectKind::Host
            | ObjectKind::Interface
            | ObjectKind::CustomField
            | ObjectKind::Job
            | ObjectKind::Observation
            | ObjectKind::Proposal
            | ObjectKind::Import
            | ObjectKind::Connector
            | ObjectKind::Node
            | ObjectKind::System
    )
}

fn operator_allows(action: Action, kind: ObjectKind) -> bool {
    match action {
        // Operator secrets: the metadata and the host bindings (WP2.1), never the values.
        Action::Read => {
            is_inventory(kind)
                || matches!(
                    kind,
                    ObjectKind::User | ObjectKind::Settings | ObjectKind::Secret
                )
        }
        Action::Create | Action::Update | Action::Delete => matches!(
            kind,
            ObjectKind::Tenant
                | ObjectKind::Vrf
                | ObjectKind::Site
                | ObjectKind::Vlan
                | ObjectKind::Prefix
                | ObjectKind::Range
                | ObjectKind::Address
                | ObjectKind::Host
                | ObjectKind::Interface
                | ObjectKind::Import
                | ObjectKind::Connector
        ),
        Action::Execute => matches!(
            kind,
            ObjectKind::Job
                | ObjectKind::Import
                | ObjectKind::Prefix
                | ObjectKind::Host
                | ObjectKind::Address
                | ObjectKind::Connector
        ),
        Action::Approve => kind == ObjectKind::Proposal,
        // An operator may reveal an operator secret under the reveal policy (TGL-24) and the
        // PIN coupling rule (IAM-07), which therefore counts operators as accounts that can
        // reach the vault; creating, changing and binding secrets stays with administrators.
        Action::Reveal => kind == ObjectKind::Secret,
        Action::Administer => false,
    }
}

/// Administrative kinds that a personal token may never administer: changing users,
/// settings, tokens, sessions or the system needs an interactive session.
pub(crate) fn interactive_only(action: Action, kind: ObjectKind) -> bool {
    matches!(action, Action::Administer | Action::Reveal)
        || (matches!(action, Action::Create | Action::Update | Action::Delete)
            && matches!(
                kind,
                ObjectKind::User
                    | ObjectKind::Settings
                    | ObjectKind::System
                    | ObjectKind::ApiToken
                    | ObjectKind::Session
                    | ObjectKind::Secret
            ))
}

/// The weakest session strength that may act with these roles under the settings
/// (TGL-02, TGL-03), for `action`, and under the PIN coupling rule (IAM-07, CON-07): once
/// the vault holds an operator secret, a PIN alone no longer serves an account that can
/// reveal secrets, and revealing never works with a PIN alone.
pub fn required_strength(
    roles: &[RoleName],
    settings: &SecuritySettings,
    action: Action,
    operator_secrets: bool,
) -> AuthStrength {
    let admin = roles.contains(&RoleName::Admin);
    let mut required = AuthStrength::Pin;
    let mfa = match settings.mfa {
        MfaRequirement::Optional => false,
        MfaRequirement::Administrators => admin,
        MfaRequirement::Everyone => true,
    };
    if mfa {
        required = required.max(AuthStrength::PasswordTotp);
    }
    if settings.passkey_for_admins && admin {
        required = required.max(AuthStrength::Passkey);
    }
    let can_reveal = roles
        .iter()
        .any(|role| role.allows(Action::Reveal, ObjectKind::Secret));
    if action == Action::Reveal || (operator_secrets && can_reveal) {
        required = required.max(AuthStrength::Password);
    }
    required
}

/// The MFA policy a role has when none is stored (IAM-06): the profile's TGL-03 and TGL-02
/// for the administrator, TGL-02 alone for the other roles.
pub fn default_policy(role: RoleName, settings: &SecuritySettings) -> RoleMfa {
    let admin = role == RoleName::Admin;
    if admin && settings.passkey_for_admins {
        return RoleMfa::Passkey;
    }
    match settings.mfa {
        MfaRequirement::Everyone => RoleMfa::TotpOrStronger,
        MfaRequirement::Administrators if admin => RoleMfa::TotpOrStronger,
        MfaRequirement::Administrators | MfaRequirement::Optional => RoleMfa::Optional,
    }
}

/// Whether a session of `strength` satisfies `required`. A passkey satisfies a two-factor
/// requirement: it combines possession with user verification.
pub fn satisfies(strength: AuthStrength, required: AuthStrength) -> bool {
    strength >= required
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::Profile;

    #[test]
    fn viewers_only_read_the_inventory() {
        assert!(RoleName::Viewer.allows(Action::Read, ObjectKind::Prefix));
        assert!(!RoleName::Viewer.allows(Action::Update, ObjectKind::Prefix));
        assert!(!RoleName::Viewer.allows(Action::Read, ObjectKind::User));
        assert!(!RoleName::Viewer.allows(Action::Read, ObjectKind::Settings));
        assert!(!RoleName::Viewer.allows(Action::Read, ObjectKind::Secret));
    }

    #[test]
    fn operators_change_the_inventory_but_do_not_administer() {
        assert!(RoleName::Operator.allows(Action::Create, ObjectKind::Host));
        assert!(RoleName::Operator.allows(Action::Execute, ObjectKind::Job));
        assert!(RoleName::Operator.allows(Action::Approve, ObjectKind::Proposal));
        assert!(!RoleName::Operator.allows(Action::Administer, ObjectKind::User));
        assert!(!RoleName::Operator.allows(Action::Update, ObjectKind::Settings));
        assert!(!RoleName::Operator.allows(Action::Create, ObjectKind::CustomField));
    }

    #[test]
    fn operators_read_and_reveal_secrets_but_do_not_manage_them() {
        assert!(RoleName::Operator.allows(Action::Read, ObjectKind::Secret));
        assert!(RoleName::Operator.allows(Action::Reveal, ObjectKind::Secret));
        assert!(!RoleName::Operator.allows(Action::Reveal, ObjectKind::User));
        for action in [Action::Create, Action::Update, Action::Delete] {
            assert!(!RoleName::Operator.allows(action, ObjectKind::Secret));
        }
        // Revealing makes an operator an account that can reach the vault (IAM-07).
        let home = Profile::Home.defaults();
        assert_eq!(
            required_strength(&[RoleName::Operator], &home, Action::Read, true),
            AuthStrength::Password
        );
        assert_eq!(
            required_strength(&[RoleName::Operator], &home, Action::Read, false),
            AuthStrength::Pin
        );
    }

    #[test]
    fn auditors_read_the_system_and_nothing_else() {
        assert!(RoleName::Auditor.allows(Action::Read, ObjectKind::System));
        for &kind in ObjectKind::ALL {
            if kind != ObjectKind::System {
                assert!(!RoleName::Auditor.allows(Action::Read, kind), "{kind}");
            }
            for action in [
                Action::Create,
                Action::Update,
                Action::Delete,
                Action::Execute,
                Action::Approve,
                Action::Reveal,
                Action::Administer,
            ] {
                assert!(!RoleName::Auditor.allows(action, kind), "{kind}");
            }
        }
        assert_eq!("auditor".parse::<RoleName>().ok(), Some(RoleName::Auditor));
        let hardened = Profile::Hardened.defaults();
        assert_eq!(
            required_strength(&[RoleName::Auditor], &hardened, Action::Read, true),
            AuthStrength::PasswordTotp
        );
    }

    #[test]
    fn admins_may_do_everything() {
        for &kind in ObjectKind::ALL {
            assert!(RoleName::Admin.allows(Action::Administer, kind));
        }
    }

    #[test]
    fn required_strength_follows_the_toggles() {
        let admin = [RoleName::Admin];
        let viewer = [RoleName::Viewer];
        let home = Profile::Home.defaults();
        assert_eq!(
            required_strength(&admin, &home, Action::Read, false),
            AuthStrength::Pin
        );
        assert_eq!(
            required_strength(&admin, &home, Action::Reveal, false),
            AuthStrength::Password
        );
        let standard = Profile::Standard.defaults();
        assert_eq!(
            required_strength(&admin, &standard, Action::Read, false),
            AuthStrength::PasswordTotp
        );
        assert_eq!(
            required_strength(&viewer, &standard, Action::Read, false),
            AuthStrength::Pin
        );
        let hardened = Profile::Hardened.defaults();
        assert_eq!(
            required_strength(&admin, &hardened, Action::Read, false),
            AuthStrength::Passkey
        );
        assert_eq!(
            required_strength(&viewer, &hardened, Action::Read, false),
            AuthStrength::PasswordTotp
        );
        assert!(satisfies(AuthStrength::HardwareKey, AuthStrength::Passkey));
        // IAM-07: with operator secrets in the vault a PIN alone no longer serves an admin.
        assert_eq!(
            required_strength(&admin, &home, Action::Read, true),
            AuthStrength::Password
        );
        assert_eq!(
            required_strength(&viewer, &home, Action::Read, true),
            AuthStrength::Pin
        );
        assert!(!satisfies(
            AuthStrength::Password,
            AuthStrength::PasswordTotp
        ));
    }

    #[test]
    fn roles_cover_themselves_and_lower_roles_only() {
        for role in RoleName::ALL {
            assert!(role.covers(role), "{role}");
            assert!(RoleName::Admin.covers(role), "{role}");
        }
        assert!(RoleName::Operator.covers(RoleName::Viewer));
        assert!(!RoleName::Viewer.covers(RoleName::Operator));
        assert!(!RoleName::Operator.covers(RoleName::Admin));
        assert!(!RoleName::Operator.covers(RoleName::Auditor));
        assert!(!RoleName::Auditor.covers(RoleName::Viewer));
    }

    #[test]
    fn default_policies_follow_the_profile() {
        let policy = |profile: Profile, role| default_policy(role, &profile.defaults());
        assert_eq!(policy(Profile::Home, RoleName::Admin), RoleMfa::Optional);
        assert_eq!(
            policy(Profile::Standard, RoleName::Admin),
            RoleMfa::TotpOrStronger
        );
        assert_eq!(
            policy(Profile::Standard, RoleName::Operator),
            RoleMfa::Optional
        );
        assert_eq!(policy(Profile::Hardened, RoleName::Admin), RoleMfa::Passkey);
        assert_eq!(
            policy(Profile::Hardened, RoleName::Viewer),
            RoleMfa::TotpOrStronger
        );
        assert_eq!(policy(Profile::Lab, RoleName::Auditor), RoleMfa::Optional);
        // The default of every role is what the profile already requires of it.
        for profile in Profile::ALL {
            let settings = profile.defaults();
            for role in RoleName::ALL {
                assert_eq!(
                    default_policy(role, &settings).strength(),
                    required_strength(&[role], &settings, Action::Read, false),
                    "{profile:?} {role}"
                );
            }
        }
    }

    #[test]
    fn role_names_parse() {
        assert_eq!(
            "operator".parse::<RoleName>().expect("role"),
            RoleName::Operator
        );
        assert!("root".parse::<RoleName>().is_err());
    }
}
