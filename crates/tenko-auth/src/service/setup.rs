//! First-run setup (API-10): the one-time setup token, the profile, the first
//! administrator and the host name.

use std::net::IpAddr;

use tenko_core::{ObjectKind, ObjectRef, Principal, RequestCtx, SystemComponent, net::HostName};
use tenko_store::{ReadViewExt, WriteBatch};

use super::{
    AuthService, NewSession,
    account::PasswordOwner,
    actions,
    admin::{valid_language, valid_user_name},
    types::{ProfileInfo, SetupRequest, SetupState},
};
use crate::{
    authz::AuthImage,
    error::AuthError,
    lockout::{LockoutMode, LockoutPolicy, ThrottleKey},
    model::{INSTALLATION, Installation, SETTINGS, USER_NAMES, USERS, UserRecord},
    roles::RoleName,
    secret::SetupToken,
    settings::Profile,
};

/// Checks a host name for use as TLS subject and WebAuthn RP ID: DNS syntax, and not an
/// IP address (an RP ID cannot be one, Q5 and R10). `localhost` is allowed for development.
///
/// # Errors
///
/// [`AuthError::InvalidHostName`].
pub fn validate_host_name(name: &str) -> Result<String, AuthError> {
    let trimmed = name.trim();
    let bare = trimmed.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<IpAddr>().is_ok() {
        return Err(AuthError::InvalidHostName(trimmed.to_owned()));
    }
    let host =
        HostName::new(trimmed).map_err(|_| AuthError::InvalidHostName(trimmed.to_owned()))?;
    // A name made of digits and dots only would be read as an address by browsers.
    if host
        .as_str()
        .split('.')
        .all(|label| label.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(AuthError::InvalidHostName(trimmed.to_owned()));
    }
    Ok(host.as_str().to_owned())
}

/// The checked host name, language, administrator name and display name of a request.
fn validated(
    request: &SetupRequest,
    image: &AuthImage,
) -> Result<(String, String, String, String), AuthError> {
    let host_name = validate_host_name(&request.host_name)?;
    let language = valid_language(&request.language, image)?;
    let name = valid_user_name(&request.admin.name)?;
    let display_name = request
        .admin
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .unwrap_or(&name)
        .to_owned();
    Ok((host_name, language, name, display_name))
}

/// Wrong setup tokens tolerated before delays (the token has 100 bits; this only slows
/// down noise).
fn setup_policy() -> LockoutPolicy {
    LockoutPolicy::for_mode(LockoutMode::ProgressiveDelay)
}

fn setup_key() -> ThrottleKey {
    ThrottleKey::Account("\u{1}setup".to_owned())
}

impl AuthService {
    /// Opens setup at server start: while the installation has no administrator, generates
    /// the one-time setup token, keeps its verifier in memory and returns the token for the
    /// console and the log (WP1.8 prints it). Returns `None` once setup has completed. A
    /// restart replaces the token.
    ///
    /// # Errors
    ///
    /// A store error or a random-source failure.
    pub async fn prepare_setup(&self) -> Result<Option<SetupToken>, AuthError> {
        if self.is_installed().await? {
            *self.setup_verifier() = None;
            return Ok(None);
        }
        let (token, verifier) = SetupToken::generate()?;
        *self.setup_verifier() = Some(verifier);
        Ok(Some(token))
    }

    /// `GET /setup`.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn setup_state(&self) -> Result<SetupState, AuthError> {
        let open = !self.is_installed().await?;
        let profiles = if open {
            Profile::ALL
                .into_iter()
                .map(|profile| {
                    let settings = profile.defaults();
                    ProfileInfo {
                        profile,
                        banner: settings.banner(),
                        settings,
                    }
                })
                .collect()
        } else {
            Vec::new()
        };
        Ok(SetupState { open, profiles })
    }

    /// `POST /setup`: creates the settings of the chosen profile, the first administrator
    /// and the installation record in one batch, closes setup and logs the administrator
    /// in.
    ///
    /// # Errors
    ///
    /// [`AuthError::SetupClosed`] after setup, [`AuthError::SetupTokenInvalid`],
    /// [`AuthError::InvalidHostName`], [`AuthError::PasswordPolicy`],
    /// [`AuthError::Invalid`], [`AuthError::Throttled`].
    pub async fn complete_setup(
        &self,
        ctx: &RequestCtx,
        user_agent: Option<&str>,
        request: &SetupRequest,
    ) -> Result<NewSession, AuthError> {
        if self.is_installed().await? {
            return Err(AuthError::SetupClosed);
        }
        self.throttle
            .check(&setup_key(), &setup_policy(), ctx.now)
            .map_err(|retry| AuthError::Throttled {
                retry_after: retry.after.map(|after| after.as_secs().max(1)),
            })?;
        let valid = self
            .setup_verifier()
            .as_ref()
            .is_some_and(|verifier| verifier.verify(request.setup_token.expose()));
        if !valid {
            self.throttle
                .record_failure(&setup_key(), &setup_policy(), ctx.now);
            return Err(AuthError::SetupTokenInvalid);
        }
        let (host_name, language, name, display_name) = validated(request, &self.index.image())?;
        let settings = request.profile.defaults();
        let (password, _) = self
            .new_password(
                &settings,
                &request.admin.password,
                &PasswordOwner {
                    user_name: &name,
                    display_name: Some(&display_name),
                    host_name: Some(&host_name),
                },
                ctx.now,
            )
            .await?;
        let user = UserRecord {
            password: Some(password),
            ..UserRecord::new(name, display_name, vec![RoleName::Admin], ctx.now)
        };
        let installation = Installation {
            completed_at: ctx.now,
            host_name: host_name.clone(),
            language,
            first_admin: user.id,
        };
        let key = UserRecord::name_key(&user.name);
        let mut batch = WriteBatch::new(
            Principal::System {
                component: SystemComponent::Setup,
                on_behalf_of: Some(user.id),
            },
            ctx.now,
        );
        batch.request = Some(ctx.request);
        batch.expect_typed(&INSTALLATION, &(), None);
        batch.expect_typed(&USER_NAMES, &key, None);
        batch.put_typed(&SETTINGS, &(), &settings)?;
        batch.put_typed(&INSTALLATION, &(), &installation)?;
        batch.put_typed(&USER_NAMES, &key, &user.id)?;
        batch.put_typed(&USERS, &user.id, &user)?;
        let strength = if settings.password_policy.is_pin() {
            tenko_core::AuthStrength::Pin
        } else {
            tenko_core::AuthStrength::Password
        };
        let (secret, record) = self.stage_session(
            &mut batch,
            &settings,
            &user,
            strength,
            ctx.now,
            ctx.source_ip,
            user_agent,
            false,
        )?;
        batch.audit(
            Self::audit(
                actions::SETUP_COMPLETE,
                vec![
                    ObjectRef::singleton(ObjectKind::System),
                    ObjectRef::from(user.id),
                ],
                ctx,
            )
            .with_context("profile", settings.profile.as_str())
            .with_context("host_name", host_name)
            .with_context("administrator", user.name.clone()),
        );
        let session = match self.complete_login(batch, &user, secret, record).await {
            Err(AuthError::Conflict) => return Err(AuthError::SetupClosed),
            other => other?,
        };
        *self.setup_verifier() = None;
        self.throttle.unlock(&setup_key());
        self.configure_relying_party(Some(&installation))?;
        Ok(session)
    }

    /// The installation record, once setup has completed.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn installation(&self) -> Result<Option<Installation>, AuthError> {
        Ok(self
            .view()
            .await?
            .get_typed(&INSTALLATION, &())?
            .map(|(installation, _)| installation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_names_must_not_be_addresses() {
        assert_eq!(
            validate_host_name("Tenko.Example.Test.").expect("valid"),
            "tenko.example.test"
        );
        assert_eq!(validate_host_name("localhost").expect("valid"), "localhost");
        for bad in [
            "192.0.2.10",
            "[2001:db8::1]",
            "2001:db8::1",
            "10.1",
            "",
            "bad name",
        ] {
            assert!(validate_host_name(bad).is_err(), "{bad}");
        }
    }
}
