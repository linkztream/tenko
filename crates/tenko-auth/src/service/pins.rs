//! PINs stored before the six-digit minimum (IAM-03).
//!
//! The hash of a PIN does not tell its length, so a PIN stored before the minimum rose
//! from four to six digits is "unconfirmed" until a sign-in shows it meets the policy (the
//! sign-in then records `policy_checked_at`) or the PIN is replaced. An unconfirmed PIN keeps
//! working for [`SecuritySettings::unconfirmed_pin_days`] from the day this installation first
//! ran with the minimum ([`PIN_RULE_SINCE`], written once through the store, so every
//! controller counts from the same day). After that the sign-in refuses it like a wrong PIN;
//! an administrator resets it, and `tenko user unlock` on the host starts a new period for
//! any account, the last administrator included.
//!
//! The expiry is decided at sign-in from the stored dates. The hourly sweep only raises the
//! alarm (once per account), so a sweep that does not run never keeps an expired PIN alive.
//! The same sweep removes stored sign-in locks that have ended.

use std::{sync::Arc, time::Duration};

use tenko_core::{Principal, RequestCtx, SystemComponent, Timestamp};
use tenko_store::{KeyRange, ReadView, ReadViewExt, StoreError, WriteBatch};

use super::AuthService;
use crate::{
    clock::{Clock, SystemClock},
    error::AuthError,
    model::{AlarmKind, LOCKS, PIN_RULE_SINCE, SETTINGS, USERS},
    settings::{DEFAULT_UNCONFIRMED_PIN_DAYS, SecuritySettings},
};

/// Whether the period also ends for the last administrator. The way back is then
/// `tenko user unlock` on the host, which starts a new period; an exemption would keep the
/// most valuable account on a short PIN for good where nobody signs in for months.
pub(super) const LAST_ADMIN_PIN_EXPIRES: bool = true;

/// How often the sweep looks for ended periods.
const SWEEP_EVERY: Duration = Duration::from_secs(3_600);
/// The first sweep after start.
const FIRST_SWEEP: Duration = Duration::from_secs(60);

/// The day the installation first ran with the six-digit minimum, once written.
pub(super) fn pin_rule_since(view: &dyn ReadView) -> Result<Option<Timestamp>, AuthError> {
    Ok(view.get_typed(&PIN_RULE_SINCE, &())?.map(|(at, _)| at))
}

/// The period in days as the stored settings give it (the default before setup).
pub(super) fn stored_pin_days(view: &dyn ReadView) -> Result<u32, AuthError> {
    Ok(view
        .get_typed(&SETTINGS, &())?
        .map_or(DEFAULT_UNCONFIRMED_PIN_DAYS, |(settings, _)| {
            settings.unconfirmed_pin_days()
        }))
}

impl AuthService {
    /// Whether the unconfirmed PIN `stored` has passed the end of its period at `now`,
    /// for an account the last-administrator guard covers (`guarded`) or not.
    pub(super) fn pin_expired(
        view: &dyn ReadView,
        stored: &crate::model::StoredPassword,
        settings: &SecuritySettings,
        guarded: bool,
        now: Timestamp,
    ) -> Result<bool, AuthError> {
        if guarded && !LAST_ADMIN_PIN_EXPIRES {
            return Ok(false);
        }
        Ok(stored
            .pin_expires_at(pin_rule_since(view)?, settings.unconfirmed_pin_days())
            .is_some_and(|end| now >= end))
    }

    /// Writes the day the installation first ran with the six-digit minimum, if no
    /// controller has yet. The first writer wins; the others find it written.
    ///
    /// # Errors
    ///
    /// A store error other than the precondition another controller won.
    pub async fn record_pin_rule_since(&self, now: Timestamp) -> Result<(), AuthError> {
        if pin_rule_since(self.view().await?.as_ref())?.is_some() {
            return Ok(());
        }
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
        batch.expect_typed(&PIN_RULE_SINCE, &(), None);
        batch.put_typed(&PIN_RULE_SINCE, &(), &now)?;
        match self.store.propose(batch).await {
            Ok(_) | Err(StoreError::PreconditionFailed(_)) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Raises the alarm `auth.alarm.pin_expired` once for every unconfirmed PIN whose period
    /// has ended at `now`, and notes on the record that it was raised. Returns the number of
    /// alarms raised. A record changed meanwhile, or noted by another controller first, is
    /// left for the next sweep.
    ///
    /// # Errors
    ///
    /// A store error reading the users.
    pub async fn sweep_unconfirmed_pins(&self, now: Timestamp) -> Result<usize, AuthError> {
        self.record_pin_rule_since(now).await?;
        let view = self.view().await?;
        let settings = self.settings();
        let image = self.index.image();
        let mut raised = 0;
        for (id, user, revision) in
            view.scan_typed(&USERS, KeyRange::all(), super::LIST_LIMIT, false)?
        {
            let Some(stored) = user.password.as_ref() else {
                continue;
            };
            if stored.pin_expiry_noticed_at.is_some()
                || !Self::pin_expired(
                    view.as_ref(),
                    stored,
                    &settings,
                    image.is_last_admin(id),
                    now,
                )?
            {
                continue;
            }
            let mut updated = user.clone();
            if let Some(password) = updated.password.as_mut() {
                password.pin_expiry_noticed_at = Some(now);
            }
            let ctx = RequestCtx::system(SystemComponent::Auth).at(now);
            let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
            batch.expect_typed(&USERS, &id, Some(revision));
            batch.put_typed(&USERS, &id, &updated)?;
            Self::stage_alarm(&mut batch, &ctx, AlarmKind::PinExpired, Some(id))?;
            match self.store.propose(batch).await {
                Ok(_) => raised += 1,
                Err(StoreError::PreconditionFailed(_)) => {}
                Err(error) => tracing::warn!(%error, "could not raise a PIN expiry alarm"),
            }
        }
        Ok(raised)
    }

    /// Removes stored sign-in locks that have ended, up to a listing's worth per call, so
    /// the table of locks does not grow with locks nobody reads any more. Returns how many
    /// were removed.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn prune_ended_locks(&self, now: Timestamp) -> Result<usize, AuthError> {
        let view = self.view().await?;
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
        let mut removed = 0;
        for (key, lock, _) in view.scan_typed(&LOCKS, KeyRange::all(), super::LIST_LIMIT, false)? {
            if lock.until <= now {
                batch.delete_typed(&LOCKS, &key);
                removed += 1;
            }
        }
        if removed > 0 {
            self.store.propose(batch).await?;
        }
        Ok(removed)
    }

    /// Starts the hourly sweep on the current runtime, if there is one. The day of the rule
    /// is written at once; the first alarm sweep follows a minute later.
    pub(super) fn spawn_pin_sweep(self: &Arc<Self>) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let weak = Arc::downgrade(self);
        handle.spawn(async move {
            if let Some(service) = weak.upgrade()
                && let Err(error) = service.record_pin_rule_since(SystemClock.now()).await
            {
                tracing::debug!(%error, "the PIN rule date is not written yet");
            }
            tokio::time::sleep(FIRST_SWEEP).await;
            loop {
                let Some(service) = weak.upgrade() else {
                    return;
                };
                if let Err(error) = service.sweep_unconfirmed_pins(SystemClock.now()).await {
                    tracing::debug!(%error, "the PIN sweep could not run");
                }
                if let Err(error) = service.prune_ended_locks(SystemClock.now()).await {
                    tracing::debug!(%error, "ended sign-in locks could not be removed");
                }
                if let Err(error) = service.prune_known_devices(SystemClock.now()).await {
                    tracing::debug!(%error, "ended known devices could not be removed");
                }
                if let Err(error) = service.resume_account_ends(SystemClock.now()).await {
                    tracing::warn!(%error, "the credentials of ended accounts could not be removed");
                }
                drop(service);
                tokio::time::sleep(SWEEP_EVERY).await;
            }
        });
    }
}
