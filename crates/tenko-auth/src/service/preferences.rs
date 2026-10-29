//! The personal preferences of the person behind a session (`crate::preferences`): list,
//! write and delete one key.
//!
//! Own data only: every operation reads and writes the rows of the user of the request's
//! session and takes no user id, so no role reaches another person's preferences, an
//! administrator included. A personal or scoped token is refused like on the other
//! operations that act on the person's own account (`auth.unauthenticated`): the layouts
//! belong to the interactive UI. Nothing here is audited and nothing reaches the event
//! stream; a layout is not a change of the installation.

use tenko_core::RequestCtx;
use tenko_store::{KeyRange, ReadView, ReadViewExt as _, WriteBatch};

use super::{AuthService, LIST_LIMIT};
use crate::{
    error::AuthError,
    model::{PREFERENCES, preference_keys_counter},
    preferences::{MAX_KEYS, Preference, StoredPreference, TableLayout, check_key},
};

impl AuthService {
    /// `GET /auth/preferences`: every preference of the person, ordered by key.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`] without a session, or a store error.
    pub async fn list_preferences(&self, ctx: &RequestCtx) -> Result<Vec<Preference>, AuthError> {
        let (user, _, _) = Self::session_principal(ctx)?;
        let view = self.view().await?;
        Ok(Self::user_preferences(view.as_ref(), user)?
            .into_iter()
            .map(|(key, stored)| stored.to_preference(key))
            .collect())
    }

    /// `PUT /auth/preferences/{key}`: writes the document of one key, creating the key when
    /// the person has fewer than [`MAX_KEYS`].
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`], [`AuthError::Invalid`] for the key or the document,
    /// [`AuthError::PreferenceTooLarge`], [`AuthError::PreferenceLimit`], or
    /// [`AuthError::Conflict`] when another write of the person's keys came first.
    pub async fn put_preference(
        &self,
        ctx: &RequestCtx,
        key: &str,
        layout: &TableLayout,
    ) -> Result<Preference, AuthError> {
        let (user, _, _) = Self::session_principal(ctx)?;
        check_key(key)?;
        let document = layout.validate()?;
        let view = self.view().await?;
        let row = (user, key.to_owned());
        let stored = StoredPreference {
            document,
            updated_at: ctx.now,
        };
        let mut batch = WriteBatch::for_request(ctx);
        if let Some((_, revision)) = view.get_typed(&PREFERENCES, &row)? {
            // The key exists: the write replaces it, unless it was deleted meanwhile.
            batch.expect_typed(&PREFERENCES, &row, Some(revision));
        } else {
            let existing = Self::user_preferences(view.as_ref(), user)?.len();
            if existing >= MAX_KEYS {
                return Err(AuthError::PreferenceLimit { max_keys: MAX_KEYS });
            }
            let counter = preference_keys_counter(user);
            let seen = view.counter(&counter)?;
            batch.expect_typed(&PREFERENCES, &row, None);
            batch.expect_counter(counter.clone(), seen);
            batch.bump(counter);
        }
        batch.put_typed(&PREFERENCES, &row, &stored)?;
        self.commit(batch).await?;
        Ok(stored.to_preference(row.1))
    }

    /// `DELETE /auth/preferences/{key}`: removes one key; the table returns to its default.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`], [`AuthError::Invalid`] for the key, or
    /// [`AuthError::NotFound`] (`auth.preference.not_found`) for a key the person does not
    /// have.
    pub async fn delete_preference(&self, ctx: &RequestCtx, key: &str) -> Result<(), AuthError> {
        let (user, _, _) = Self::session_principal(ctx)?;
        check_key(key)?;
        let view = self.view().await?;
        let row = (user, key.to_owned());
        let Some((_, revision)) = view.get_typed(&PREFERENCES, &row)? else {
            return Err(AuthError::NotFound { kind: "preference" });
        };
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&PREFERENCES, &row, Some(revision));
        batch.delete_typed(&PREFERENCES, &row);
        self.commit(batch).await?;
        Ok(())
    }

    /// Every preference row of `user`, by key.
    pub(super) fn user_preferences(
        view: &dyn ReadView,
        user: tenko_core::UserId,
    ) -> Result<Vec<(String, StoredPreference)>, AuthError> {
        let range = KeyRange::prefix(tenko_core::codec::encode_key(&(user,)));
        Ok(view
            .scan_typed(&PREFERENCES, range, LIST_LIMIT, false)?
            .into_iter()
            .map(|((_, key), stored, _)| (key, stored))
            .collect())
    }

    /// Adds the deletion of every preference of `user` to a batch (the account is deleted).
    pub(super) fn stage_preference_removal(
        view: &dyn ReadView,
        batch: &mut WriteBatch,
        user: tenko_core::UserId,
    ) -> Result<(), AuthError> {
        for (key, _) in Self::user_preferences(view, user)? {
            batch.delete_typed(&PREFERENCES, &(user, key));
        }
        Ok(())
    }
}
