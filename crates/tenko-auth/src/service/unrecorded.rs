//! Failed sign-ins while the store's disk is short of room. Below the store's margin the
//! store refuses an audit record alone, so a failed sign-in writes none: it is counted here
//! in memory, bounded, and one summary record is written once the store has room again
//! (`docs/cluster.md` section 12.12). A crash in between loses that summary. The protections
//! against guessing do not wait for it: the waits and locks live in memory, and a lock that
//! starts is stored as a sign-in's row, which the store takes below its margin.

use std::collections::{BTreeMap, BTreeSet};

use tenko_core::{ObjectRef, UserId, audit::AuditAction, audit::AuditDraft};

use crate::error::AuthError;

/// The distinct names tried that the summary keeps; further ones are only counted.
pub(crate) const NAMES_KEPT: usize = 256;
/// The distinct networks the summary keeps; further ones are only counted.
pub(crate) const NETWORKS_KEPT: usize = 256;
/// The existing accounts the summary names; further ones are only counted.
pub(crate) const ACCOUNTS_KEPT: usize = 64;

/// The failed sign-ins counted since the store last had room.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Unrecorded {
    /// The action of the first failure (the kind of sign-in).
    action: Option<AuditAction>,
    attempts: u64,
    names: BTreeSet<String>,
    /// Attempts with a name beyond [`NAMES_KEPT`] others.
    more_names: u64,
    networks: BTreeSet<String>,
    /// Attempts from a network beyond [`NETWORKS_KEPT`] others.
    more_networks: u64,
    /// The existing accounts that were tried, by name.
    accounts: BTreeMap<String, UserId>,
    /// Attempts on an existing account beyond [`ACCOUNTS_KEPT`] others.
    more_accounts: u64,
}

/// Inserts `item` into `kept` while it holds fewer than `cap`; counts it in `more` otherwise.
fn keep<T: Ord>(kept: &mut BTreeSet<T>, more: &mut u64, cap: usize, item: T) {
    if kept.contains(&item) {
        return;
    }
    if kept.len() < cap {
        kept.insert(item);
    } else {
        *more = more.saturating_add(1);
    }
}

impl Unrecorded {
    /// Counts one failed sign-in of `action` with the name `name` (`account`: the existing
    /// account of that name) from `network`.
    pub(crate) fn note(
        &mut self,
        action: AuditAction,
        name: &str,
        account: Option<UserId>,
        network: String,
    ) {
        self.action.get_or_insert(action);
        self.attempts = self.attempts.saturating_add(1);
        keep(
            &mut self.names,
            &mut self.more_names,
            NAMES_KEPT,
            name.to_owned(),
        );
        keep(
            &mut self.networks,
            &mut self.more_networks,
            NETWORKS_KEPT,
            network,
        );
        if let Some(account) = account
            && !self.accounts.contains_key(name)
        {
            if self.accounts.len() < ACCOUNTS_KEPT {
                self.accounts.insert(name.to_owned(), account);
            } else {
                self.more_accounts = self.more_accounts.saturating_add(1);
            }
        }
    }

    /// The summary record, or `None` when nothing was counted.
    pub(crate) fn draft(&self) -> Option<AuditDraft> {
        let action = self.action.clone()?;
        let objects = self
            .accounts
            .values()
            .map(|id| ObjectRef::from(*id))
            .collect();
        let names: Vec<&str> = self.accounts.keys().map(String::as_str).collect();
        Some(
            AuditDraft::failed(action, objects, &AuthError::InvalidCredentials)
                .with_context(
                    "summary",
                    "failed sign-ins while the store's disk was short of room",
                )
                .with_context("attempts", self.attempts.to_string())
                .with_context("names", self.names.len().to_string())
                .with_context("more_names", self.more_names.to_string())
                .with_context("networks", self.networks.len().to_string())
                .with_context("more_networks", self.more_networks.to_string())
                .with_context("accounts", names.join(", "))
                .with_context("more_accounts", self.more_accounts.to_string()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_summary_counts_and_names_within_its_bounds() {
        let action = AuditAction::from_static("auth.login.password");
        let mut unrecorded = Unrecorded::default();
        assert_eq!(unrecorded.draft(), None, "nothing counted");
        let ada = UserId::generate();
        for _ in 0..3 {
            unrecorded.note(action.clone(), "ada", Some(ada), "192.0.2.0/24".to_owned());
        }
        for n in 0..(NAMES_KEPT + 10) {
            unrecorded.note(
                action.clone(),
                &format!("guess-{n}"),
                None,
                format!("net-{n}"),
            );
        }
        for n in 0..(ACCOUNTS_KEPT + 5) {
            unrecorded.note(
                action.clone(),
                &format!("user-{n}"),
                Some(UserId::generate()),
                "192.0.2.0/24".to_owned(),
            );
        }
        let draft = unrecorded.draft().expect("a summary");
        let context = &draft.details.context;
        let attempts = 3 + NAMES_KEPT + 10 + ACCOUNTS_KEPT + 5;
        assert_eq!(context["attempts"], attempts.to_string());
        assert_eq!(context["names"], NAMES_KEPT.to_string(), "the names kept");
        // 1 + 266 + 69 distinct names, 256 kept.
        assert_eq!(
            context["more_names"],
            (1 + 10 + ACCOUNTS_KEPT + 5).to_string(),
            "the attempts with other names"
        );
        assert_eq!(context["networks"], NETWORKS_KEPT.to_string());
        assert!(
            context["accounts"].starts_with("ada, "),
            "{}",
            context["accounts"]
        );
        assert_eq!(
            context["more_accounts"], "6",
            "64 accounts named, 6 more counted"
        );
        assert_eq!(draft.objects.len(), ACCOUNTS_KEPT);
        assert!(
            !context["accounts"].contains("guess-"),
            "only existing accounts"
        );
    }
}
