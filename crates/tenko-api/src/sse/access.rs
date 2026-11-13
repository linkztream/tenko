//! The end of an open stream's access: a stream is never more privileged than a request made
//! at the same moment with the credential that opened it.
//!
//! The handler of `GET /events` takes the stream's credential as a [`Held`] (the session or
//! token, through `tenko_auth::service::Hold`). The hub follows the store journal and, in the
//! same order as the events, tells every stream of each commit that changed a table of
//! credentials or of authorization ([`AccessTables`]). A stream whose credential's rows (its
//! account's record, its session's or token's row) or the security settings changed reads the
//! credential again with the rules of a request (one read of its controller's copy of the
//! store); a change of grants, role policies or the strength rules makes every stream compute
//! the topics it reads again, from the authorization index. It ends with an `end` event when:
//!
//! - the credential no longer acts (`access_ended`): signed out, revoked, expired, ended with
//!   the account's access (a password change or reset, sign-out everywhere, the break-glass
//!   designation), the account disabled or deleted, or, for a session, the account must
//!   change its password before anything else;
//! - a topic it was opened for is no longer readable (`access_changed`), or the credential
//!   could not be read again.
//!
//! **The bound**: the check of a commit runs before the stream takes the events of that
//! commit or of any later one from the hub, so no event of the commit that ends the access,
//! or of a later commit, reaches the stream; a commit through another controller reaches this
//! controller's hub through its copy of the journal, and the bound is the same there. Expiry
//! by time needs no commit: the stream holds the end its last check found and checks once
//! more when it comes, so it delivers nothing after the moment a request would be refused.
//! The window between the handler's authentication and the stream's subscription is closed
//! by one more check after subscribing, right before the first byte: a commit up to the
//! subscription is in that check's view, every later one reaches the stream through the hub.

use std::collections::{HashMap, HashSet};

use bytes::Bytes;
use futures::future::BoxFuture;
use tenko_auth::{
    AuthError, AuthService,
    service::{Follow, Hold},
};
use tenko_core::{Revision, TableName, Timestamp};
use tenko_store::ChangeSet;

use std::sync::Arc;

/// The credential an event stream was opened with, as the stream follows it.
pub trait Held: Send + Sync + 'static {
    /// The rows whose change may end the credential: its account's record and its own row.
    fn rows(&self) -> &[(TableName, Bytes)];

    /// When the credential expires (`None`: not by time), read at revision `at` or later
    /// under the rules of a request at `now`; an error once it no longer acts.
    fn standing(
        &self,
        at: Revision,
        now: Timestamp,
    ) -> BoxFuture<'_, Result<Option<Timestamp>, AuthError>>;
}

/// A session or token of the authentication service.
pub(crate) struct Credential {
    pub(crate) service: Arc<AuthService>,
    pub(crate) hold: Hold,
}

impl Held for Credential {
    fn rows(&self) -> &[(TableName, Bytes)] {
        self.hold.rows()
    }

    fn standing(
        &self,
        at: Revision,
        now: Timestamp,
    ) -> BoxFuture<'_, Result<Option<Timestamp>, AuthError>> {
        Box::pin(self.service.standing(&self.hold, at, now))
    }
}

/// The tables whose changes may end a stream's access, and what a change of each asks.
#[derive(Debug, Clone)]
pub(crate) struct AccessTables(HashMap<TableName, Follow>);

impl Default for AccessTables {
    fn default() -> Self {
        Self(Hold::tables().into_iter().collect())
    }
}

impl AccessTables {
    /// What of a commit may end a stream's access; `None` when nothing.
    pub(crate) fn change(&self, changes: &ChangeSet) -> Option<AccessChange> {
        let mut change = AccessChange {
            revision: changes.revision,
            rows: HashSet::new(),
            credentials: false,
            reads: false,
        };
        for row in &changes.changes {
            match self.0.get(&row.table) {
                Some(Follow::Row) => {
                    change.rows.insert((row.table.clone(), row.key.clone()));
                }
                Some(Follow::Credentials) => change.credentials = true,
                Some(Follow::Reads) => change.reads = true,
                None => {}
            }
        }
        (change.credentials || change.reads || !change.rows.is_empty()).then_some(change)
    }
}

/// What one commit asks of the streams.
#[derive(Debug)]
pub(crate) struct AccessChange {
    pub(crate) revision: Revision,
    /// The changed rows of accounts, sessions and tokens.
    rows: HashSet<(TableName, Bytes)>,
    /// Every credential is read again.
    credentials: bool,
    /// Every stream's readable topics are computed again.
    reads: bool,
}

/// What a stream does about an [`AccessChange`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Check {
    /// Nothing: the change does not concern it.
    None,
    /// Compute the topics it reads again (no store read).
    Reads,
    /// Read the credential again, then the topics.
    Credential,
}

impl AccessChange {
    /// A change that makes every stream read its credential again at `revision`.
    pub(crate) fn all(revision: Revision) -> Self {
        Self {
            revision,
            rows: HashSet::new(),
            credentials: true,
            reads: false,
        }
    }

    /// What the commit asks of the stream that holds `held`.
    pub(crate) fn check(&self, held: &dyn Held) -> Check {
        if self.credentials || held.rows().iter().any(|row| self.rows.contains(row)) {
            Check::Credential
        } else if self.reads {
            Check::Reads
        } else {
            Check::None
        }
    }
}

#[cfg(test)]
mod tests;
