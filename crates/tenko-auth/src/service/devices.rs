//! Known devices (IAM-05, TGL-07): a browser that completed a sign-in of an account holds
//! a mark that lets its later attempts on that account pass the account-wide delay.
//!
//! The account-wide delay keeps guesses spread over many networks slow, but someone who
//! fails at the moment each delay ends takes every turn, and the person signing in from a
//! new network then waits behind them. The mark takes that person's device out of the
//! queue. It authenticates nothing and shortens nobody else's wait:
//!
//! - It is a 256-bit random value in an `HttpOnly`, `SameSite=Strict` cookie
//!   ([`device_cookie_name`]: `__Host-tenko_device` over HTTPS, `tenko_device` over plain
//!   HTTP). The store keeps only its SHA-256 ([`KNOWN_DEVICES`]) with the account, the
//!   dates and a failure count: no address, no user agent, nothing that describes the
//!   device.
//! - It is set only after a completed sign-in (the password with its second factor, or a
//!   passkey), and renewed with a new value at each one, so a copy taken from the device
//!   ends at the device's next sign-in. It ends after [`DEVICE_KEPT`], when the account's
//!   password changes or is reset, when the account is signed out everywhere, disabled or
//!   deleted, and when its owner or an administrator removes it.
//! - It holds for the one account it was issued to. A mark of another account, an ended
//!   one, or a value that is no mark is read, looked up and ignored, exactly like no mark.
//! - Each failed attempt made with it counts on the mark; at the policy's lock threshold
//!   (8 with the defaults) the mark is spent: removed on every controller. The account is
//!   not locked by this. The count is written on its own, conditionally on the record read,
//!   so concurrent failures on several controllers each count and a removed mark is never
//!   written back; each controller also keeps the failures it saw in memory, so a count
//!   that could not be written still holds there. One attempt with a mark is in flight per
//!   controller at a time, so attempts that arrive together cannot pass the count
//!   together.
//! - An account keeps at most [`MARKS_PER_ACCOUNT`] marks; a new one removes the one used
//!   longest ago. A browser keeps at most [`MARKS_PER_BROWSER`], one per account.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use tenko_core::{ObjectRef, Principal, RequestCtx, SystemComponent, Timestamp, UserId};
use tenko_store::{KeyRange, ReadView, ReadViewExt, StoreError, WriteBatch};
use zeroize::Zeroizing;

use super::{AuthService, actions, guard::Attempt};
use crate::{
    error::AuthError,
    model::{KNOWN_DEVICES, KnownDeviceId, KnownDeviceRecord, USER_KNOWN_DEVICES, UserRecord},
    secret::{hash_secret, looks_like_session_secret},
    service::types::KnownDeviceInfo,
};

/// The name of the device cookie over HTTPS (see [`super::HOST_SESSION_COOKIE`] for what
/// the prefix guarantees).
pub const HOST_DEVICE_COOKIE: &str = "__Host-tenko_device";
/// The name of the device cookie over plain HTTP (the Lab profile, and `localhost`).
pub const DEVICE_COOKIE: &str = "tenko_device";
/// How long a mark lasts after the sign-in that issued it.
pub const DEVICE_KEPT: Duration = Duration::from_secs(30 * 86_400);
/// The most marks one account keeps: a person's phone, laptops and a few shared or
/// replaced machines. A new mark beyond them removes the one used longest ago; only a
/// completed sign-in makes one, so only someone who has the account can push marks out.
pub const MARKS_PER_ACCOUNT: usize = 10;
/// The most marks one browser carries, each for another account.
pub const MARKS_PER_BROWSER: usize = 5;

/// The name of the device cookie for a request over HTTPS or plain HTTP. A request is read
/// with the name of its own scheme only, as the session cookie is.
pub fn device_cookie_name(https: bool) -> &'static str {
    if https {
        HOST_DEVICE_COOKIE
    } else {
        DEVICE_COOKIE
    }
}

/// The marks a request carries: the values of its device cookie that have the shape of a
/// mark, at most [`MARKS_PER_BROWSER`], without repeats. `Debug` redacts them.
#[derive(Clone, Default)]
pub struct DeviceMarks(Vec<Zeroizing<String>>);

impl DeviceMarks {
    /// The marks of a cookie value: values separated by `.`; anything else is ignored.
    pub fn parse(value: &str) -> Self {
        let mut marks: Vec<Zeroizing<String>> = Vec::new();
        for part in value.split('.') {
            if marks.len() == MARKS_PER_BROWSER {
                break;
            }
            if looks_like_session_secret(part) && !marks.iter().any(|mark| mark.as_str() == part) {
                marks.push(Zeroizing::new(part.to_owned()));
            }
        }
        Self(marks)
    }

    /// Whether the request carries no mark.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The number of marks.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    fn digests(&self) -> impl Iterator<Item = (&str, Vec<u8>)> {
        self.0.iter().map(|mark| (mark.as_str(), hash_secret(mark)))
    }
}

impl std::fmt::Debug for DeviceMarks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeviceMarks({} redacted)", self.0.len())
    }
}

/// The device cookie a completed sign-in sets: the new mark first, then the browser's
/// marks of other accounts that still hold.
#[derive(Clone)]
pub struct DeviceCookie {
    value: Zeroizing<String>,
}

impl DeviceCookie {
    /// The `Set-Cookie` value for a request over HTTPS or plain HTTP: `HttpOnly`,
    /// `SameSite=Strict`, `Path=/`, and `Secure` with the `__Host-` name over HTTPS.
    pub fn set_cookie(&self, https: bool) -> String {
        let secure = if https { "; Secure" } else { "" };
        format!(
            "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{secure}",
            device_cookie_name(https),
            self.value.as_str(),
            DEVICE_KEPT.as_secs()
        )
    }
}

impl std::fmt::Debug for DeviceCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceCookie(<redacted>)")
    }
}

/// What this controller keeps about marks in memory: the marks with an attempt in
/// flight, the failures it saw with each mark, and where the hourly sweep goes on.
#[derive(Debug, Default)]
pub(super) struct DevicesInFlight {
    in_flight: Arc<Mutex<HashSet<Vec<u8>>>>,
    failures: Mutex<HashMap<Vec<u8>, u32>>,
    sweep_from: Mutex<Option<Vec<u8>>>,
}

/// The most marks whose failures a controller keeps in memory. Only a completed sign-in
/// makes a mark, so this many marks with failures on one controller is far beyond use; at
/// the cap the oldest knowledge goes, and the stored count still holds.
const FAILURES_KEPT: usize = 10_000;

impl DevicesInFlight {
    /// Takes the mark's slot, unless an attempt with it is in flight already.
    fn take(&self, digest: &[u8]) -> Option<DeviceSlot> {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        in_flight.insert(digest.to_vec()).then(|| DeviceSlot {
            in_flight: Arc::clone(&self.in_flight),
            digest: digest.to_vec(),
        })
    }

    /// The failures this controller saw with the mark.
    fn seen(&self, digest: &[u8]) -> u32 {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(digest)
            .copied()
            .unwrap_or(0)
    }

    /// Notes one more failure with the mark at least `stored` deep; returns the count.
    fn note_failure(&self, digest: &[u8], stored: u32) -> u32 {
        let mut failures = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        if failures.len() >= FAILURES_KEPT && !failures.contains_key(digest) {
            failures.clear();
        }
        let count = failures.entry(digest.to_vec()).or_insert(0);
        *count = (*count).max(stored).saturating_add(1);
        *count
    }
}

/// Holds a mark's slot until the attempt ends.
pub(super) struct DeviceSlot {
    in_flight: Arc<Mutex<HashSet<Vec<u8>>>>,
    digest: Vec<u8>,
}

impl Drop for DeviceSlot {
    fn drop(&mut self) {
        self.in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.digest);
    }
}

impl std::fmt::Debug for DeviceSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceSlot")
    }
}

/// The mark an attempt carries for its account, with the slot it holds.
#[derive(Debug, Clone)]
pub(super) struct DeviceUse {
    digest: Vec<u8>,
    record: KnownDeviceRecord,
    _slot: Arc<DeviceSlot>,
}

/// What a failure did to the mark of the attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MarkFailure {
    /// The failure was counted on the mark.
    Counted,
    /// The failure reached the budget: the mark is removed.
    Spent,
    /// The mark was removed meanwhile (spent elsewhere, renewed or forgotten).
    Ended,
}

impl MarkFailure {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Counted => "used",
            Self::Spent => "spent",
            Self::Ended => "ended",
        }
    }
}

/// A row of [`USER_KNOWN_DEVICES`] as a scan returns it.
type IndexRow = ((UserId, Vec<u8>), KnownDeviceId, tenko_core::Revision);

/// How often a failure's count is tried again when another write changed the mark first.
const COUNT_TRIES: usize = 4;

/// Whether `record` holds for `user` at `now`: issued to it, not ended, issued under its
/// current password, and with failures left under `budget`.
fn holds(record: &KnownDeviceRecord, user: &UserRecord, budget: u32, now: Timestamp) -> bool {
    record.user == user.id
        && now < record.expires_at
        && record.password_changed_at == user.password.as_ref().map(|p| p.changed_at)
        && record.failures < budget
}

impl AuthService {
    /// The attempt on the account named `name` from the client of `ctx` (see
    /// [`AuthService::attempt`]), with the mark of a known device of the account that the
    /// request carries ([`AuthService::recognize_device`]).
    pub(super) fn attempt_from(
        &self,
        view: &dyn ReadView,
        name: &str,
        user: Option<&UserRecord>,
        ctx: &RequestCtx,
        marks: &DeviceMarks,
    ) -> Result<Attempt, AuthError> {
        let mut attempt = self.attempt(name, user, ctx, &self.settings());
        self.recognize_device(view, &mut attempt, user, marks, ctx.now)?;
        Ok(attempt)
    }

    /// Looks up every mark of the request and gives the attempt the one issued to `user`
    /// that still holds, when no other attempt with it is in flight here. Every mark is
    /// looked up whether the name is an account or not, so the work does not tell.
    pub(super) fn recognize_device(
        &self,
        view: &dyn ReadView,
        attempt: &mut Attempt,
        user: Option<&UserRecord>,
        marks: &DeviceMarks,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let budget = attempt.policy.lock_threshold().max(1);
        let mut found = None;
        for (_, digest) in marks.digests() {
            let record = view.get_typed(&KNOWN_DEVICES, &digest)?.map(|(r, _)| r);
            if found.is_none()
                && let (Some(record), Some(user)) = (record, user)
                && holds(&record, user, budget, now)
                && self.devices_in_flight.seen(&digest) < budget
            {
                found = Some((digest, record));
            }
        }
        attempt.device = found.and_then(|(digest, record)| {
            let slot = self.devices_in_flight.take(&digest)?;
            Some(DeviceUse {
                digest,
                record,
                _slot: Arc::new(slot),
            })
        });
        Ok(())
    }

    /// Counts a failed attempt on its mark: in this controller's memory, and in the store
    /// by a write of its own that holds only if the record is still the one read, tried
    /// again when another write came first. At the budget the mark is removed. A mark
    /// removed meanwhile is never written back.
    pub(super) async fn count_mark_failure(
        &self,
        attempt: &Attempt,
        now: Timestamp,
    ) -> Option<MarkFailure> {
        let device = attempt.device.as_ref()?;
        let budget = attempt.policy.lock_threshold().max(1);
        let seen = self
            .devices_in_flight
            .note_failure(&device.digest, device.record.failures);
        for _ in 0..COUNT_TRIES {
            let view = match self.view().await {
                Ok(view) => view,
                Err(error) => {
                    tracing::warn!(%error, "could not read a mark to count a failure");
                    break;
                }
            };
            let found = match view.get_typed(&KNOWN_DEVICES, &device.digest) {
                Ok(found) => found,
                Err(error) => {
                    tracing::warn!(%error, "could not read a mark to count a failure");
                    break;
                }
            };
            let Some((record, revision)) = found else {
                return Some(MarkFailure::Ended);
            };
            let failures = record.failures.saturating_add(1).max(seen);
            let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
            batch.expect_typed(&KNOWN_DEVICES, &device.digest, Some(revision));
            let outcome = if failures >= budget {
                batch.delete_typed(&KNOWN_DEVICES, &device.digest);
                batch.delete_typed(&USER_KNOWN_DEVICES, &(record.user, device.digest.clone()));
                MarkFailure::Spent
            } else {
                if let Err(error) = batch.put_typed(
                    &KNOWN_DEVICES,
                    &device.digest,
                    &KnownDeviceRecord { failures, ..record },
                ) {
                    tracing::warn!(%error, "could not encode a mark's count");
                    break;
                }
                MarkFailure::Counted
            };
            match self.store.propose(batch).await {
                Ok(_) => return Some(outcome),
                Err(StoreError::PreconditionFailed(_)) => {}
                Err(error) => {
                    tracing::warn!(%error, "could not count a failure on its mark");
                    break;
                }
            }
        }
        // Not written: this controller's memory still holds the count.
        Some(if seen >= budget {
            MarkFailure::Spent
        } else {
            MarkFailure::Counted
        })
    }

    /// Adds a new mark for `user` to the batch of a completed sign-in and returns the
    /// cookie: it replaces the browser's mark of the account (keeping its id and first
    /// date), removes the account's ended marks and, beyond [`MARKS_PER_ACCOUNT`], the one
    /// used longest ago. The break-glass account, which signs in with its key only, gets
    /// none.
    pub(super) fn stage_known_device(
        view: &dyn ReadView,
        batch: &mut WriteBatch,
        user: &UserRecord,
        marks: &DeviceMarks,
        now: Timestamp,
    ) -> Result<Option<DeviceCookie>, AuthError> {
        if user.break_glass || user.is_service() {
            return Ok(None);
        }
        let password_changed_at = user.password.as_ref().map(|p| p.changed_at);
        // The browser's marks: this account's goes; every other value stays as it came,
        // whether it is a mark or not, so the answer does not tell which still hold.
        let mut own = None;
        let mut kept: Vec<&str> = Vec::new();
        for (mark, digest) in marks.digests() {
            match view.get_typed(&KNOWN_DEVICES, &digest)?.map(|(r, _)| r) {
                Some(record) if record.user == user.id => {
                    batch.delete_typed(&KNOWN_DEVICES, &digest);
                    batch.delete_typed(&USER_KNOWN_DEVICES, &(user.id, digest.clone()));
                    if own.is_none() && now < record.expires_at {
                        own = Some(record);
                    }
                }
                _ => kept.push(mark),
            }
        }
        let id = own.as_ref().map_or_else(KnownDeviceId::generate, |r| r.id);
        // The account's other marks: ended ones go, and the oldest beyond the cap.
        let mut live: Vec<(Vec<u8>, Timestamp)> = Vec::new();
        for ((_, digest), other, _) in Self::user_device_index(view, user.id)? {
            if marks.digests().any(|(_, carried)| carried == digest) {
                continue; // Removed above.
            }
            match view.get_typed(&KNOWN_DEVICES, &digest)?.map(|(r, _)| r) {
                Some(record)
                    if other != id
                        && now < record.expires_at
                        && record.password_changed_at == password_changed_at =>
                {
                    live.push((digest, record.issued_at));
                }
                // Ended, or another mark of this device (renewed twice at once): it goes.
                _ => {
                    batch.delete_typed(&KNOWN_DEVICES, &digest);
                    batch.delete_typed(&USER_KNOWN_DEVICES, &(user.id, digest));
                }
            }
        }
        live.sort_by_key(|(_, issued)| *issued);
        let excess = (live.len() + 1).saturating_sub(MARKS_PER_ACCOUNT);
        for (digest, _) in live.into_iter().take(excess) {
            batch.delete_typed(&KNOWN_DEVICES, &digest);
            batch.delete_typed(&USER_KNOWN_DEVICES, &(user.id, digest));
        }
        let secret = crate::secret::new_session_secret()?;
        let digest = secret.hash();
        batch.put_typed(
            &KNOWN_DEVICES,
            &digest,
            &KnownDeviceRecord {
                id,
                user: user.id,
                known_since: own.as_ref().map_or(now, |r| r.known_since),
                issued_at: now,
                expires_at: now.checked_add(DEVICE_KEPT).unwrap_or(now),
                password_changed_at,
                failures: 0,
            },
        )?;
        batch.put_typed(&USER_KNOWN_DEVICES, &(user.id, digest), &id)?;
        let mut value = Zeroizing::new(secret.expose().to_owned());
        for mark in kept.into_iter().take(MARKS_PER_BROWSER - 1) {
            value.push('.');
            value.push_str(mark);
        }
        Ok(Some(DeviceCookie { value }))
    }

    /// The rows of [`USER_KNOWN_DEVICES`] of `user`.
    fn user_device_index(view: &dyn ReadView, user: UserId) -> Result<Vec<IndexRow>, AuthError> {
        let range = KeyRange::prefix(tenko_core::codec::encode_key(&(user,)));
        Ok(view.scan_typed(&USER_KNOWN_DEVICES, range, super::LIST_LIMIT, false)?)
    }

    /// Adds the removal of every mark of `user` to `batch`; returns how many.
    pub(super) fn stage_known_devices_end(
        view: &dyn ReadView,
        batch: &mut WriteBatch,
        user: UserId,
    ) -> Result<usize, AuthError> {
        let rows = Self::user_device_index(view, user)?;
        for ((_, digest), _, _) in &rows {
            batch.delete_typed(&KNOWN_DEVICES, digest);
            batch.delete_typed(&USER_KNOWN_DEVICES, &(user, digest.clone()));
        }
        Ok(rows.len())
    }

    /// The marks of `user` that hold at `now`, newest first; `current` marks those the
    /// request carries.
    fn known_devices_of(
        view: &dyn ReadView,
        user: &UserRecord,
        marks: &DeviceMarks,
        now: Timestamp,
    ) -> Result<Vec<KnownDeviceInfo>, AuthError> {
        let carried: Vec<Vec<u8>> = marks.digests().map(|(_, digest)| digest).collect();
        let mut devices = Vec::new();
        for ((_, digest), _, _) in Self::user_device_index(view, user.id)? {
            let Some((record, _)) = view.get_typed(&KNOWN_DEVICES, &digest)? else {
                continue;
            };
            if !holds(&record, user, u32::MAX, now) {
                continue;
            }
            devices.push(KnownDeviceInfo {
                id: record.id,
                known_since: record.known_since,
                last_sign_in: record.issued_at,
                expires_at: record.expires_at,
                current: carried.contains(&digest),
            });
        }
        devices.sort_by_key(|device| std::cmp::Reverse(device.last_sign_in));
        Ok(devices)
    }

    /// Removes the marks of `user` (one, or all with `id` `None`) with an audit record;
    /// returns how many.
    async fn forget_devices(
        &self,
        ctx: &RequestCtx,
        user: UserId,
        id: Option<KnownDeviceId>,
    ) -> Result<usize, AuthError> {
        let view = self.view().await?;
        let mut batch = WriteBatch::for_request(ctx);
        let removed = match id {
            None => Self::stage_known_devices_end(view.as_ref(), &mut batch, user)?,
            Some(id) => {
                // A device renewed twice at once can have two marks under one id.
                let mut found = 0;
                for ((_, digest), device, _) in Self::user_device_index(view.as_ref(), user)? {
                    if device == id {
                        batch.delete_typed(&KNOWN_DEVICES, &digest);
                        batch.delete_typed(&USER_KNOWN_DEVICES, &(user, digest));
                        found = 1;
                    }
                }
                if found == 0 {
                    return Err(AuthError::NotFound {
                        kind: "known_device",
                    });
                }
                found
            }
        };
        batch.audit(
            Self::audit(
                actions::KNOWN_DEVICE_REMOVE,
                vec![ObjectRef::from(user)],
                ctx,
            )
            .with_context("known_devices", removed.to_string()),
        );
        self.commit(batch).await?;
        Ok(removed)
    }

    /// `GET /auth/known-devices`: the devices that pass the account-wide delay for the
    /// account of the session; `current` marks this browser.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`] for anything but a session, or a store error.
    pub async fn list_known_devices(
        &self,
        ctx: &RequestCtx,
        marks: &DeviceMarks,
    ) -> Result<Vec<KnownDeviceInfo>, AuthError> {
        let (user, _, _) = Self::session_principal(ctx)?;
        let view = self.view().await?;
        let (user, _) = Self::load_user(view.as_ref(), user)?;
        Self::known_devices_of(view.as_ref(), &user, marks, ctx.now)
    }

    /// `DELETE /auth/known-devices/{id}`, or every one with `id` `None`
    /// (`DELETE /auth/known-devices`): the device meets the account-wide delay again
    /// until its next completed sign-in. Returns how many were removed.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`] for anything but a session, [`AuthError::NotFound`]
    /// for a device of another account.
    pub async fn forget_known_devices(
        &self,
        ctx: &RequestCtx,
        id: Option<KnownDeviceId>,
    ) -> Result<usize, AuthError> {
        let (user, _, _) = Self::session_principal(ctx)?;
        self.forget_devices(ctx, user, id).await
    }

    /// `GET /users/{id}/known-devices`: an account's known devices, for an administrator.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`] or [`AuthError::NotFound`].
    pub async fn user_known_devices(
        &self,
        ctx: &RequestCtx,
        id: UserId,
    ) -> Result<Vec<KnownDeviceInfo>, AuthError> {
        self.authorize(ctx, tenko_core::Action::Administer, ObjectRef::from(id))
            .await?;
        let view = self.view().await?;
        let (user, _) = Self::load_user(view.as_ref(), id)?;
        Self::known_devices_of(view.as_ref(), &user, &DeviceMarks::default(), ctx.now)
    }

    /// `DELETE /users/{id}/known-devices[/{device}]`: an administrator removes one known
    /// device of an account, or every one. Returns how many.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`] or [`AuthError::NotFound`].
    pub async fn forget_user_known_devices(
        &self,
        ctx: &RequestCtx,
        id: UserId,
        device: Option<KnownDeviceId>,
    ) -> Result<usize, AuthError> {
        self.authorize(ctx, tenko_core::Action::Administer, ObjectRef::from(id))
            .await?;
        Self::load_user(self.view().await?.as_ref(), id)?;
        self.forget_devices(ctx, id, device).await
    }

    /// Removes marks that have ended, whose account is gone or whose password changed, and
    /// marks without their row in [`USER_KNOWN_DEVICES`] (which no removal of the account
    /// would find): a listing's worth per call, going on where the last call stopped (the
    /// hourly sweep). Returns how many.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn prune_known_devices(&self, now: Timestamp) -> Result<usize, AuthError> {
        let view = self.view().await?;
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
        let from = self
            .devices_in_flight
            .sweep_from
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let range = match from {
            Some(key) => KeyRange::all().after(key),
            None => KeyRange::all(),
        };
        let rows = view.scan_typed(&KNOWN_DEVICES, range, super::LIST_LIMIT, false)?;
        *self
            .devices_in_flight
            .sweep_from
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = (rows.len() == super::LIST_LIMIT)
            .then(|| {
                rows.last()
                    .map(|(digest, _, _)| tenko_core::codec::encode_key(digest).to_vec())
            })
            .flatten();
        let mut removed = 0;
        for (digest, record, _) in rows {
            let ended = record.expires_at <= now
                || view
                    .get_typed(&USER_KNOWN_DEVICES, &(record.user, digest.clone()))?
                    .is_none()
                || view
                    .get_typed(&crate::model::USERS, &record.user)?
                    .is_none_or(|(user, _)| {
                        record.password_changed_at != user.password.as_ref().map(|p| p.changed_at)
                    });
            if ended {
                batch.delete_typed(&USER_KNOWN_DEVICES, &(record.user, digest.clone()));
                batch.delete_typed(&KNOWN_DEVICES, &digest);
                removed += 1;
            }
        }
        if removed > 0 {
            self.store.propose(batch).await?;
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const B: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";

    #[test]
    fn a_cookie_yields_at_most_five_distinct_marks_of_the_right_shape() {
        assert!(DeviceMarks::parse("").is_empty());
        assert!(DeviceMarks::parse("not-a-mark").is_empty());
        assert_eq!(DeviceMarks::parse(&format!("{A}.{A}.{B}")).len(), 2);
        assert_eq!(DeviceMarks::parse(&format!("x.{A}..{B}.")).len(), 2);
        let many: Vec<String> = (0..8)
            .map(|n| {
                format!(
                    "{}{}",
                    &A[..42],
                    ["A", "E", "I", "M", "Q", "U", "Y", "c"][n]
                )
            })
            .collect();
        assert_eq!(DeviceMarks::parse(&many.join(".")).len(), 5);
        assert!(!format!("{:?}", DeviceMarks::parse(A)).contains(A));
    }

    #[test]
    fn the_cookie_follows_the_scheme() {
        let cookie = DeviceCookie {
            value: Zeroizing::new(A.to_owned()),
        };
        let https = cookie.set_cookie(true);
        assert!(https.starts_with(&format!("__Host-tenko_device={A}; Path=/; HttpOnly")));
        assert!(https.contains("SameSite=Strict") && https.ends_with("; Secure"));
        assert!(!https.contains("Domain"));
        let plain = cookie.set_cookie(false);
        assert!(plain.starts_with("tenko_device=") && !plain.contains("Secure"));
        assert!(plain.contains(&format!("Max-Age={}", 30 * 86_400)));
        assert!(!format!("{cookie:?}").contains(A));
    }

    #[test]
    fn one_attempt_per_mark_is_in_flight() {
        let in_flight = DevicesInFlight::default();
        let first = in_flight.take(b"mark").expect("free");
        assert!(in_flight.take(b"mark").is_none());
        assert!(in_flight.take(b"other").is_some());
        drop(first);
        assert!(in_flight.take(b"mark").is_some());
    }
}
