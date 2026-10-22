//! The checks around operator secrets (WP2.1): whether a person may reveal one now (the
//! reveal policy TGL-24 on top of the role and the PIN coupling rule IAM-07), and which
//! accounts keep the vault from taking operator secrets at all (CON-07).

use tenko_core::{
    Action, AuthStrength, CodedError, ObjectKind, ObjectRef, RequestCtx, SecretId, UserId,
};
use tenko_store::{KeyRange, ReadViewExt};

use super::{AuthService, FRESH_AUTHENTICATION};
use crate::{
    error::AuthError,
    model::{CREDENTIALS, PasswordKind, USERS, UserRecord},
    settings::{RevealPolicy, RevealStepUp},
};

/// The `required` parameter of a step-up for a policy that wants a sign-in within the last
/// five minutes, whatever the method.
pub const STEP_UP_FRESH: &str = "fresh";

/// The `required` parameter of a step-up for a policy that wants a sign-in with a passkey
/// or a hardware security key within the last five minutes.
pub const STEP_UP_PASSKEY: &str = "passkey";

// Backlog: the PIN coupling refusal names the rule in words and the next step.
/// The code of the refusal to store an operator secret while an account that may reveal
/// secrets signs in with a PIN alone (IAM-07, CON-07).
pub const VAULT_PIN_COUPLING: &str = "vault.pin_coupling";

/// The `next` parameter of that refusal: the step that lifts it.
pub const PIN_COUPLING_NEXT: &str = "passkey";

/// The route that starts the next step, passkey enrolment (the `route` parameter).
pub const PASSKEY_ENROLMENT_ROUTE: &str = "/api/v1/auth/webauthn/register/start";

/// The PIN coupling rule in words, the accounts that break it and the next step, for the
/// refusal of `POST /secrets` and for the import's credential columns.
pub fn pin_coupling_detail(accounts: &[String]) -> String {
    let (who, them) = if accounts.len() == 1 {
        ("this account signs", "it")
    } else {
        ("these accounts sign", "them")
    };
    format!(
        "a secret cannot be stored while an account that may reveal secrets signs in with a PIN alone (the PIN coupling rule, IAM-07); {who} in with a PIN alone: {}. Next step: enrol a passkey for {them} (POST {PASSKEY_ENROLMENT_ROUTE}, in the UI under Account, Security); adding TOTP, a password or other roles also lifts the rule",
        accounts.join(", ")
    )
}

/// The refusal of `POST /secrets` under the PIN coupling rule: 409 `vault.pin_coupling`
/// with the parameters `accounts` (comma-separated), `next` (`passkey`) and `route` (the
/// passkey enrolment route).
pub fn pin_coupling_refusal(accounts: &[String]) -> CodedError {
    CodedError::new(VAULT_PIN_COUPLING, 409, pin_coupling_detail(accounts))
        .with_title("PIN coupling rule: enrol a passkey first")
        .with_param("accounts", accounts.join(","))
        .with_param("next", PIN_COUPLING_NEXT)
        .with_param("route", PASSKEY_ENROLMENT_ROUTE)
}

/// What a granted reveal check found out: who reveals and under which policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevealGrant {
    /// The person.
    pub user: UserId,
    /// Their login name, for the last-revealed stamp.
    pub user_name: String,
    /// The strength of the session.
    pub strength: AuthStrength,
    /// The reveal policy in force (TGL-24); the caller enforces `bound_host_only`, which
    /// needs the host bindings of the vault.
    pub policy: RevealPolicy,
}

/// Decides TGL-24 for a session: its strength and the age of its authentication.
///
/// # Errors
///
/// [`AuthError::StepUpRequired`] with `required` [`STEP_UP_FRESH`] or [`STEP_UP_PASSKEY`].
pub fn check_step_up(
    policy: RevealPolicy,
    strength: AuthStrength,
    authenticated_at: tenko_core::Timestamp,
    now: tenko_core::Timestamp,
) -> Result<(), AuthError> {
    let fresh = now.saturating_since(authenticated_at) <= FRESH_AUTHENTICATION;
    match policy.step_up {
        RevealStepUp::Session => Ok(()),
        RevealStepUp::Fresh if fresh => Ok(()),
        RevealStepUp::Fresh => Err(AuthError::StepUpRequired {
            required: STEP_UP_FRESH,
        }),
        RevealStepUp::Passkey if fresh && strength >= AuthStrength::Passkey => Ok(()),
        RevealStepUp::Passkey => Err(AuthError::StepUpRequired {
            required: STEP_UP_PASSKEY,
        }),
    }
}

impl AuthService {
    /// Checks that the person behind `ctx` may reveal `secret` now, without writing
    /// anything (the caller audits the reveal or its refusal in one record):
    ///
    /// 1. the role grants [`Action::Reveal`] on the secret, and the session is of password
    ///    strength or stronger: a PIN-strength session never reveals (IAM-07), and a
    ///    personal token never reveals (an interactive session is required);
    /// 2. the session satisfies the reveal policy TGL-24 ([`check_step_up`]).
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`] (forbidden, or a step-up to the strength `password`),
    /// [`AuthError::Unauthenticated`] for anything but a live session,
    /// [`AuthError::StepUpRequired`] from the policy, or a store error.
    pub async fn authorize_reveal(
        &self,
        ctx: &RequestCtx,
        secret: SecretId,
    ) -> Result<RevealGrant, AuthError> {
        self.authorized(ctx, Action::Reveal, ObjectRef::from(secret))?;
        let (user_id, session_id, strength) = Self::session_principal(ctx)?;
        let view = self.view().await?;
        let (user, _) = Self::load_user(view.as_ref(), user_id)?;
        let (_, session) = Self::load_session(view.as_ref(), user_id, session_id)?
            .ok_or(AuthError::Unauthenticated)?;
        let policy = self.settings().secret_reveal();
        check_step_up(policy, strength, session.authenticated_at, ctx.now)?;
        Ok(RevealGrant {
            user: user.id,
            user_name: user.name,
            strength,
            policy,
        })
    }

    /// The reveal policy in force (TGL-24), from the index: no store read.
    pub fn reveal_policy(&self) -> RevealPolicy {
        self.settings().secret_reveal()
    }

    /// The enabled accounts that may reveal operator secrets but sign in with a PIN alone:
    /// a PIN-kind password, no TOTP and no passkey or security key. The PIN coupling rule
    /// (CON-07, IAM-07) lets the vault take operator secrets only once this list is empty.
    /// Names in login order (case-insensitive).
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn pin_only_revealers(&self) -> Result<Vec<String>, AuthError> {
        let view = self.view().await?;
        let mut names = Vec::new();
        for (_, user, _) in view.scan_typed(&USERS, KeyRange::all(), usize::MAX, false)? {
            if !Self::pin_only_revealer(view.as_ref(), &user)? {
                continue;
            }
            names.push(user.name);
        }
        names.sort_by_key(|name| name.to_lowercase());
        Ok(names)
    }

    fn pin_only_revealer(
        view: &dyn tenko_store::ReadView,
        user: &UserRecord,
    ) -> Result<bool, AuthError> {
        if user.disabled || user.break_glass {
            return Ok(false);
        }
        let reveals = user
            .roles
            .iter()
            .any(|role| role.allows(Action::Reveal, ObjectKind::Secret));
        let pin = user
            .password
            .as_ref()
            .is_some_and(|password| password.kind == PasswordKind::Pin);
        if !reveals || !pin || user.totp.is_some() {
            return Ok(false);
        }
        let range = KeyRange::prefix(tenko_core::codec::encode_key(&(user.id,)));
        Ok(view.scan_typed(&CREDENTIALS, range, 1, false)?.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tenko_core::Timestamp;

    use super::*;

    #[test]
    fn the_pin_coupling_refusal_names_the_rule_and_the_next_step() {
        let one = pin_coupling_refusal(&["olga".to_owned()]);
        assert_eq!(one.code, VAULT_PIN_COUPLING);
        assert_eq!(one.status, 409);
        assert!(
            one.detail.contains("signs in with a PIN alone"),
            "{}",
            one.detail
        );
        assert!(
            one.detail
                .contains("this account signs in with a PIN alone: olga")
        );
        assert!(one.detail.contains("enrol a passkey for it"));
        assert!(one.detail.contains(PASSKEY_ENROLMENT_ROUTE));
        let params = &one.params;
        assert_eq!(params["accounts"], "olga");
        assert_eq!(params["next"], "passkey");
        assert_eq!(params["route"], PASSKEY_ENROLMENT_ROUTE);
        let two = pin_coupling_detail(&["olga".to_owned(), "per".to_owned()]);
        assert!(two.contains("these accounts sign in with a PIN alone: olga, per"));
        assert!(two.contains("enrol a passkey for them"));
    }

    fn at(secs: u64) -> Timestamp {
        Timestamp::from_unix_nanos(1_800_000_000_000_000_000)
            .expect("a time")
            .checked_add(Duration::from_secs(secs))
            .expect("a time")
    }

    #[test]
    fn the_session_policy_needs_no_fresh_sign_in() {
        let policy = RevealPolicy::new(RevealStepUp::Session, false);
        assert!(check_step_up(policy, AuthStrength::Password, at(0), at(86_400)).is_ok());
    }

    #[test]
    fn the_fresh_policy_needs_a_sign_in_within_five_minutes() {
        let policy = RevealPolicy::new(RevealStepUp::Fresh, false);
        assert!(check_step_up(policy, AuthStrength::Password, at(0), at(300)).is_ok());
        assert_eq!(
            check_step_up(policy, AuthStrength::Passkey, at(0), at(301)),
            Err(AuthError::StepUpRequired {
                required: STEP_UP_FRESH
            })
        );
    }

    #[test]
    fn the_passkey_policy_needs_a_fresh_passkey_sign_in() {
        let policy = RevealPolicy::new(RevealStepUp::Passkey, true);
        assert!(check_step_up(policy, AuthStrength::Passkey, at(0), at(60)).is_ok());
        assert!(check_step_up(policy, AuthStrength::HardwareKey, at(0), at(60)).is_ok());
        for (strength, now) in [
            (AuthStrength::PasswordTotp, at(60)),
            (AuthStrength::Password, at(0)),
            (AuthStrength::Passkey, at(301)),
        ] {
            let error = check_step_up(policy, strength, at(0), now).expect_err("refused");
            assert_eq!(
                error,
                AuthError::StepUpRequired {
                    required: STEP_UP_PASSKEY
                }
            );
        }
    }
}
