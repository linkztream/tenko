//! The end of an account's access: one operation, whatever the reason.
//!
//! A password change, an administrator's reset, disabling, deleting, signing out everywhere
//! and the break-glass designation all end the account's access through
//! [`AuthService::stage_account_end`]; each caller names only its [`EndReason`].
//!
//! | Credential | What ends it | What survives on purpose | Proved by |
//! |---|---|---|---|
//! | Sessions | every reason, however many the account holds | the session that changes its own password (`POST /auth/password` keeps it signed in) | `account_end.rs`: `every_path_ends_every_credential_issued_before_it`, `a_sign_in_that_races_a_reset_does_not_survive_it`, `a_session_that_authenticated_before_an_end_acts_no_more_after_it` |
//! | Known-device marks | every reason | nothing | `account_end.rs`: `every_path_ends_every_credential_issued_before_it` |
//! | A second factor pending after a correct password (TOTP, recovery code, passkey) | every reason | nothing | `account_end.rs`: `a_second_factor_opened_before_a_reset_does_not_finish_after_it` |
//! | Personal and scoped tokens | every reason but signing out everywhere | every token when an administrator signs the account out everywhere: that ends sign-ins, not API access | `account_end.rs`: `every_path_ends_every_credential_issued_before_it`; `service_flows.rs`: `the_break_glass_designation_ends_every_token_and_its_release_brings_none_back` |
//! | Known networks (each controller's memory) | every reason, on every controller, by the watch of the user records; a network noted by a sign-in that raced the end carries the old generation | nothing | `service::tests::the_watch_forgets_known_networks_at_every_end_and_after_a_lag`, `guard::tests::a_network_stays_known_for_thirty_days_and_is_forgotten_on_request` |
//! | Passkeys, the TOTP seed, recovery codes | deleting; a password change that asks for it | every other reason: they are factors, and the end of a password does not end them | `service_admin.rs`, `service_passwords.rs` |
//!
//! A crash between the steps below is proved harmless and finished by
//! `account_end.rs`: `an_end_a_crash_interrupts_is_finished_by_the_hourly_sweep`, and the
//! stored bytes by `stored_formats.rs`.
//!
//! # Order against a concurrent sign-in
//!
//! Every credential carries the generation of the account it was issued under, and the end
//! raises the account's generations in the write that carries the caller's own change,
//! conditional on the revision of the user record it read. One check,
//! [`UserRecord::admits`], refuses a credential issued under a lower generation; a session or
//! token meets it in [`AuthService::holder`], which every authentication passes and which a
//! handler that reads its session again passes too ([`AuthService::live_session`]), a mark in
//! `devices::holds`, and a pending second factor when it is taken. A sign-in that read the
//! account before the end and commits after it stamps the old generation, so it is refused
//! whichever commit comes first.
//!
//! # Steps
//!
//! The first write raises the generations, carries the caller's audit record with the
//! count of each kind of credential that still held, removes up to [`PAGE`] rows of each
//! kind and records the account in [`ACCESS_ENDS`]. When more rows are left,
//! [`AuthService::sweep_account`] removes them right after, in steps of at most [`PAGE`]
//! rows of each kind. The hourly sweep ([`AuthService::resume_account_ends`]) looks at every
//! recorded account once more and then removes its record: it finishes what a crash
//! interrupted, and removes what a sign-in racing the end wrote after it. Until then such
//! rows authenticate nothing. Every step removes only what the generations already refuse,
//! so a step repeated changes nothing.

use serde::{Serialize, de::DeserializeOwned};
use tenko_core::{
    Principal, SessionId, SystemComponent, TableName, Timestamp, UserId, audit::AuditDraft,
    codec::KeyCodec, table::TableDef,
};
use tenko_store::{KeyRange, ReadConsistency, ReadView, ReadViewExt, WriteBatch};

use super::{AuthService, LIST_LIMIT, effective_expiry, token_expired};
use crate::{
    error::AuthError,
    model::{
        ACCESS_ENDS, Issued, KNOWN_DEVICES, SCOPED_TOKENS, SESSIONS, TOKENS, USER_KNOWN_DEVICES,
        USER_SCOPED_TOKENS, USER_SESSIONS, USER_TOKENS, USERS, UserRecord,
    },
    settings::SecuritySettings,
};

/// Rows of each kind read, and removed at most, in one step.
const PAGE: usize = 1_000;

/// Why an account's access ends. The reason decides only what survives (the table above).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EndReason {
    /// The person changes their own password in the given session, which survives.
    PasswordChange(SessionId),
    /// An administrator resets the password.
    PasswordReset,
    /// The account is disabled.
    Disable,
    /// The account is deleted.
    Delete,
    /// An administrator signs the account out everywhere; its tokens survive.
    SignOutEverywhere,
    /// The account becomes the break-glass account, which signs in with its key only.
    BreakGlass,
}

/// An end staged into a write: the count of each kind of credential that still held, and
/// whether rows are left for [`AuthService::finish_account_end`].
#[must_use = "the end goes on after its write commits"]
pub(super) struct AccountEnd {
    user: UserId,
    /// Sessions that had not expired.
    pub(super) sessions: usize,
    /// Personal and scoped tokens that had not expired.
    pub(super) tokens: usize,
    /// Known-device marks that had not expired.
    pub(super) known_devices: usize,
    rest: bool,
}

impl AccountEnd {
    /// The caller's audit record with the count of each kind.
    pub(super) fn annotate(&self, draft: AuditDraft) -> AuditDraft {
        draft
            .with_context("sessions_revoked", self.sessions.to_string())
            .with_context("tokens_revoked", self.tokens.to_string())
            .with_context("known_devices", self.known_devices.to_string())
    }
}

/// The kinds of stored credential, each a row under its digest and an index row per account.
#[derive(Debug, Clone, Copy)]
enum Kind {
    Sessions,
    KnownDevices,
    Tokens,
    ScopedTokens,
}

impl Kind {
    const ALL: [Self; 4] = [
        Self::Sessions,
        Self::KnownDevices,
        Self::Tokens,
        Self::ScopedTokens,
    ];
}

/// One step's read of one kind of one account.
struct Page {
    /// The index table and the table of the credentials.
    tables: (TableName, TableName),
    /// The ended rows: the encoded index key and the encoded key of the credential.
    ended: Vec<(Vec<u8>, Vec<u8>)>,
    /// How many of the ended rows had not expired.
    held: usize,
    /// Where the next step starts, when the read filled its page.
    next: Option<Vec<u8>>,
}

/// What decides whether a stored credential has ended.
struct Judge<'a> {
    /// The account as the end leaves it; `None` once it is deleted, which ends everything.
    user: Option<&'a UserRecord>,
    /// The session that survives a password change.
    keep: Option<SessionId>,
    settings: &'a SecuritySettings,
    now: Timestamp,
}

impl Page {
    /// Adds the removal of the ended rows to `batch`.
    fn stage_removal(&self, batch: &mut WriteBatch) {
        let (index, rows) = &self.tables;
        for (key, credential) in &self.ended {
            batch.delete(index.clone(), key.clone());
            batch.delete(rows.clone(), credential.clone());
        }
    }
}

impl Judge<'_> {
    fn ended(&self, issued: Issued) -> bool {
        self.user.is_none_or(|user| !user.admits(issued))
    }

    /// For a token: `None` while it holds, else whether it had not expired.
    fn token(
        &self,
        generation: u64,
        created: Timestamp,
        expires: Option<Timestamp>,
    ) -> Option<bool> {
        self.ended(Issued::Token(generation))
            .then(|| !token_expired(created, expires, self.settings, self.now))
    }

    /// Reads up to [`PAGE`] index rows of `kind` after `after`.
    fn page(
        &self,
        view: &dyn ReadView,
        kind: Kind,
        id: UserId,
        after: Option<&[u8]>,
    ) -> Result<Page, AuthError> {
        match kind {
            Kind::Sessions => Self::read(
                view,
                &USER_SESSIONS,
                &SESSIONS,
                id,
                after,
                |_, hash| hash,
                |record| {
                    let ended = Some(record.id) != self.keep
                        && self.ended(Issued::Session(record.generation));
                    ended.then(|| effective_expiry(record, self.settings).0 > self.now)
                },
            ),
            Kind::KnownDevices => Self::read(
                view,
                &USER_KNOWN_DEVICES,
                &KNOWN_DEVICES,
                id,
                after,
                |(_, digest), _| digest.clone(),
                |record| {
                    self.ended(Issued::Session(record.generation))
                        .then_some(self.now < record.expires_at)
                },
            ),
            Kind::Tokens => Self::read(
                view,
                &USER_TOKENS,
                &TOKENS,
                id,
                after,
                |_, hash| hash,
                |record| self.token(record.generation, record.created_at, record.expires_at),
            ),
            Kind::ScopedTokens => Self::read(
                view,
                &USER_SCOPED_TOKENS,
                &SCOPED_TOKENS,
                id,
                after,
                |_, hash| hash,
                |record| self.token(record.generation, record.created_at, record.expires_at),
            ),
        }
    }

    /// The page of one kind: `ended` answers `None` for a credential that holds, else
    /// whether it had not expired. An index row without its credential is ended too.
    #[allow(clippy::too_many_arguments)]
    fn read<K, I, R>(
        view: &dyn ReadView,
        index: &TableDef<K, I>,
        rows: &TableDef<Vec<u8>, R>,
        id: UserId,
        after: Option<&[u8]>,
        digest: impl Fn(&K, I) -> Vec<u8>,
        ended: impl Fn(&R) -> Option<bool>,
    ) -> Result<Page, AuthError>
    where
        K: KeyCodec,
        I: Serialize + DeserializeOwned,
        R: Serialize + DeserializeOwned,
    {
        let mut range = KeyRange::prefix(tenko_core::codec::encode_key(&(id,)));
        if let Some(after) = after {
            range = range.after(after.to_vec());
        }
        let found = view.scan_typed(index, range, PAGE, false)?;
        let next = (found.len() == PAGE)
            .then(|| found.last().map(|(key, _, _)| index.key(key).to_vec()))
            .flatten();
        let mut page = Page {
            tables: (index.name().clone(), rows.name().clone()),
            ended: Vec::new(),
            held: 0,
            next,
        };
        for (key, value, _) in found {
            let digest = digest(&key, value);
            let verdict = match view.get_typed(rows, &digest)? {
                Some((record, _)) => ended(&record),
                None => Some(false),
            };
            if let Some(held) = verdict {
                page.held += usize::from(held);
                page.ended
                    .push((index.key(&key).to_vec(), rows.key(&digest).to_vec()));
            }
        }
        Ok(page)
    }
}

impl AuthService {
    /// Ends the access of `user` for `reason` in `batch`, the write that carries the
    /// caller's own change: raises the account's generations on `user` (the caller writes
    /// the record, conditional on the revision it read, or deletes it), counts what still
    /// held, removes the first step of rows and, when more are left, records the account
    /// in [`ACCESS_ENDS`]. After the write commits, the caller hands the result to
    /// [`AuthService::finish_account_end`].
    ///
    /// # Errors
    ///
    /// A store error.
    pub(super) fn stage_account_end(
        &self,
        view: &dyn ReadView,
        batch: &mut WriteBatch,
        user: &mut UserRecord,
        reason: EndReason,
    ) -> Result<AccountEnd, AuthError> {
        user.sessions_generation += 1;
        if reason != EndReason::SignOutEverywhere {
            user.tokens_generation += 1;
        }
        let keep = match reason {
            EndReason::PasswordChange(session) => Some(session),
            _ => None,
        };
        // The kept session is written back only as it was read: one revoked meanwhile stays
        // revoked.
        if let Some(session) = keep
            && let Some((hash, _)) = view.get_typed(&USER_SESSIONS, &(user.id, session))?
            && let Some((mut record, revision)) = view.get_typed(&SESSIONS, &hash)?
        {
            record.generation = user.sessions_generation;
            batch.expect_typed(&SESSIONS, &hash, Some(revision));
            batch.put_typed(&SESSIONS, &hash, &record)?;
        }
        let settings = self.settings();
        let judge = Judge {
            user: (reason != EndReason::Delete).then_some(&*user),
            keep,
            settings: &settings,
            now: batch.proposed_at,
        };
        let mut end = AccountEnd {
            user: user.id,
            sessions: 0,
            tokens: 0,
            known_devices: 0,
            rest: false,
        };
        for kind in Kind::ALL {
            let mut first = true;
            let mut after: Option<Vec<u8>> = None;
            loop {
                let page = judge.page(view, kind, user.id, after.as_deref())?;
                if first {
                    page.stage_removal(batch);
                    first = false;
                } else {
                    end.rest |= !page.ended.is_empty();
                }
                *match kind {
                    Kind::Sessions => &mut end.sessions,
                    Kind::KnownDevices => &mut end.known_devices,
                    Kind::Tokens | Kind::ScopedTokens => &mut end.tokens,
                } += page.held;
                match page.next {
                    Some(next) => after = Some(next),
                    None => break,
                }
            }
        }
        // The hourly sweep looks at every ended account once more: what a sign-in racing the
        // end wrote after it authenticates nothing, and goes then.
        let at = batch.proposed_at;
        batch.put_typed(&ACCESS_ENDS, &user.id, &at)?;
        Ok(end)
    }

    /// Removes what an end left after its first write (`committed` is that write), when it
    /// left more than one step. A failure is logged: the rows authenticate nothing, and the
    /// hourly sweep goes on with them.
    pub(super) async fn finish_account_end(
        &self,
        end: &AccountEnd,
        committed: tenko_core::Revision,
        now: Timestamp,
    ) {
        if end.rest
            && let Err(error) = self.sweep_account(end.user, committed, now, None).await
        {
            tracing::warn!(%error, user = %end.user, "the credentials of an ended account are removed by the hourly sweep");
        }
    }

    /// Removes the credentials of `id` that its generations refuse, in steps of at most
    /// [`PAGE`] rows of each kind, reading at least revision `from`. With `record` (the
    /// revision of the account's row of [`ACCESS_ENDS`]) the row goes afterwards, unless a
    /// later end wrote it again. Returns how many rows went.
    async fn sweep_account(
        &self,
        id: UserId,
        from: tenko_core::Revision,
        now: Timestamp,
        record: Option<tenko_core::Revision>,
    ) -> Result<usize, AuthError> {
        let settings = self.settings();
        // The kinds with rows left, each with where its next step starts.
        let mut open: Vec<(Kind, Option<Vec<u8>>)> =
            Kind::ALL.into_iter().map(|kind| (kind, None)).collect();
        let mut from = from;
        let mut removed = 0;
        loop {
            let view = self.store.read(ReadConsistency::AtLeast(from)).await?;
            let user = view.get_typed(&USERS, &id)?.map(|(user, _)| user);
            let judge = Judge {
                user: user.as_ref(),
                keep: None,
                settings: &settings,
                now,
            };
            let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
            for (kind, after) in &mut open {
                let page = judge.page(view.as_ref(), *kind, id, after.as_deref())?;
                page.stage_removal(&mut batch);
                removed += page.ended.len();
                *after = page.next;
            }
            open.retain(|(_, after)| after.is_some());
            // A step that read only credentials that hold writes nothing.
            if !batch.is_empty() {
                from = self.commit(batch).await?.revision;
            }
            if open.is_empty() {
                break;
            }
        }
        if let Some(revision) = record {
            let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
            batch.expect_typed(&ACCESS_ENDS, &id, Some(revision));
            batch.delete_typed(&ACCESS_ENDS, &id);
            match self.commit(batch).await {
                Ok(_) | Err(AuthError::Conflict) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(removed)
    }

    /// Looks at every recorded end once more and removes its record (the hourly sweep): it
    /// finishes what a crash or a failed step left, and removes what a sign-in racing the
    /// end wrote after it. Returns how many rows went.
    ///
    /// # Errors
    ///
    /// A store error reading the records; an account whose rows cannot be removed is
    /// logged and left for the next sweep.
    pub async fn resume_account_ends(&self, now: Timestamp) -> Result<usize, AuthError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        let mut removed = 0;
        for (id, _, revision) in
            view.scan_typed(&ACCESS_ENDS, KeyRange::all(), LIST_LIMIT, false)?
        {
            match self.sweep_account(id, revision, now, Some(revision)).await {
                Ok(rows) => removed += rows,
                // One account the store refuses does not hold up the others.
                Err(error) => {
                    tracing::warn!(%error, user = %id, "the credentials of an ended account could not be removed");
                }
            }
        }
        Ok(removed)
    }
}
