//! What an answer that outlives its request (an event stream) keeps of the credential that
//! opened it, so that it ends when the credential does.
//!
//! A request is authenticated once; a stream goes on. The stream keeps a [`Hold`]: its
//! account's record and the store row of its session or token. The store's journal names
//! every row a commit changes, on every controller, so the stream learns of a change of
//! either row, or of a table every decision of authorization reads
//! ([`crate::authz::authorization_tables`]), and asks [`AuthService::standing`] again: the
//! rules every request meets ([`AuthService::session_holds`], [`AuthService::token_holds`]),
//! read without a request's side effects (no activity refresh, no removal of an expired
//! session).

use bytes::Bytes;
use tenko_core::{Credentials, Revision, TableName, Timestamp, UserId};
use tenko_store::{ReadConsistency, ReadViewExt};

use super::{AuthService, FoundToken};
use crate::{
    error::AuthError,
    model::{SCOPED_TOKENS, SESSIONS, SETTINGS, TOKENS, USERS},
};

/// The credential a stream was opened with, as the stream follows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hold {
    owner: UserId,
    /// The hash of the session's or the token's secret.
    hash: Vec<u8>,
    /// The account's record and the row of the session or token.
    rows: [(TableName, Bytes); 2],
    /// The revision the credential was found at: a later check reads no older view, so a
    /// session that reached this controller through the leader is not taken for a removed one.
    seen_at: Revision,
}

/// What a change of a table followed by holds asks of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Follow {
    /// A change of one row (an account, a session, a token) may end the holds of that row.
    Row,
    /// Any change may end any credential (the security settings: lifetimes).
    Credentials,
    /// Any change may change what any credential reads (grants, role policies, the strength
    /// rules), never whether it acts.
    Reads,
}

impl Hold {
    /// The tables whose changes a hold follows, and how: the sessions and the tables of
    /// authorization.
    pub fn tables() -> Vec<(TableName, Follow)> {
        let mut tables: Vec<(TableName, Follow)> = crate::authz::authorization_tables()
            .into_iter()
            .map(|table| {
                let follow =
                    if [USERS.name(), TOKENS.name(), SCOPED_TOKENS.name()].contains(&&table) {
                        Follow::Row
                    } else if &table == SETTINGS.name() {
                        Follow::Credentials
                    } else {
                        Follow::Reads
                    };
                (table, follow)
            })
            .collect();
        tables.push((SESSIONS.name().clone(), Follow::Row));
        tables
    }

    /// The rows whose change may end this credential: its account's record and its own row.
    pub fn rows(&self) -> &[(TableName, Bytes); 2] {
        &self.rows
    }
}

impl AuthService {
    /// The hold of the session or token that `credentials` name; whether it acts is
    /// [`AuthService::standing`]'s to say.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`] when they name none, or a store error.
    pub async fn hold(&self, credentials: &Credentials, now: Timestamp) -> Result<Hold, AuthError> {
        let (owner, hash, row, seen_at) = match credentials {
            Credentials::None => return Err(AuthError::Unauthenticated),
            Credentials::Session(secret) => {
                let (hash, session, _, view) = self.session_of(secret, now).await?;
                let row = (SESSIONS.name().clone(), SESSIONS.key(&hash));
                (session.user, hash, row, view.revision())
            }
            Credentials::Bearer(token) => {
                let (hash, found, view) = self.token_of(token, now).await?;
                let (owner, row) = match found {
                    FoundToken::Personal(record, _) => {
                        (record.owner, (TOKENS.name().clone(), TOKENS.key(&hash)))
                    }
                    FoundToken::Scoped(record, _) => (
                        record.owner,
                        (SCOPED_TOKENS.name().clone(), SCOPED_TOKENS.key(&hash)),
                    ),
                };
                (owner, hash, row, view.revision())
            }
        };
        Ok(Hold {
            owner,
            hash,
            rows: [(USERS.name().clone(), USERS.key(&owner)), row],
            seen_at,
        })
    }

    /// When a held credential expires (`None`: not by time), read at revision `at` or later,
    /// under the rules of a request at `now`. A session whose account must change its password
    /// no longer acts here: every request of it but the change is refused.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`], [`AuthError::SessionExpired`] or
    /// [`AuthError::PasswordChangeRequired`] once the credential no longer acts; a store error
    /// when the view cannot be read.
    pub async fn standing(
        &self,
        hold: &Hold,
        at: Revision,
        now: Timestamp,
    ) -> Result<Option<Timestamp>, AuthError> {
        let view = self
            .store
            .read(ReadConsistency::AtLeast(at.max(hold.seen_at)))
            .await?;
        let settings = self.settings();
        if &hold.rows[1].0 == SESSIONS.name() {
            let (session, _) = view
                .get_typed(&SESSIONS, &hold.hash)?
                .filter(|(session, _)| session.user == hold.owner)
                .ok_or(AuthError::Unauthenticated)?;
            let (user, until) = Self::session_holds(view.as_ref(), &session, &settings, now)?;
            if user.password_change_required {
                return Err(AuthError::PasswordChangeRequired);
            }
            return Ok(Some(until));
        }
        let found =
            Self::find_token(view.as_ref(), &hold.hash)?.ok_or(AuthError::Unauthenticated)?;
        let (user, until) = Self::token_holds(view.as_ref(), &found, &settings, now)?;
        if user.id != hold.owner {
            return Err(AuthError::Unauthenticated);
        }
        Ok(until)
    }
}
