//! Failed sign-ins the store refused for room. Below its margin the store takes the writes
//! of failed sign-ins within a small budget of bytes a minute, and none below its reserve
//! (`docs/cluster.md` section 12.12). A failure beyond that is counted here in memory, per
//! action and bounded, with the alarm rows it raised, and one summary record per action with
//! those rows is written once the store has room again. A crash in between loses them. The
//! protections against guessing do not wait for it: the waits and locks live in memory.

use std::collections::{BTreeMap, BTreeSet};

use tenko_core::{
    ObjectRef, Principal, SystemComponent, Timestamp, UserId, audit::AuditAction, audit::AuditDraft,
};
use tenko_store::{Mutation, WriteBatch};

use crate::error::AuthError;

/// The distinct names tried that a summary keeps; further ones are only counted.
pub(crate) const NAMES_KEPT: usize = 256;
/// The distinct source networks a summary names; further ones are only counted.
pub(crate) const NETWORKS_KEPT: usize = 256;
/// The existing accounts a summary names; further ones are only counted.
pub(crate) const ACCOUNTS_KEPT: usize = 64;
/// The alarm rows the summary writes; further ones are only counted.
pub(crate) const ALARMS_KEPT: usize = 64;

/// The failed sign-ins of one action.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Tally {
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

/// The failed sign-ins counted since the store last took their summary.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Unrecorded {
    by_action: BTreeMap<AuditAction, Tally>,
    /// The alarm rows the refused writes held.
    alarms: Vec<Mutation>,
    more_alarms: u64,
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

fn joined<'a>(items: impl Iterator<Item = &'a String>) -> String {
    items.map(String::as_str).collect::<Vec<_>>().join(", ")
}

impl Unrecorded {
    /// Counts one failed sign-in of `action` with the name `name` (empty: none; `account`:
    /// the existing account of that name) from `network`, whose refused writes held `alarms`.
    pub(crate) fn note(
        &mut self,
        action: AuditAction,
        (name, account): (&str, Option<UserId>),
        network: String,
        alarms: Vec<Mutation>,
    ) {
        let tally = self.by_action.entry(action).or_default();
        tally.attempts = tally.attempts.saturating_add(1);
        keep(
            &mut tally.networks,
            &mut tally.more_networks,
            NETWORKS_KEPT,
            network,
        );
        if !name.is_empty() {
            keep(
                &mut tally.names,
                &mut tally.more_names,
                NAMES_KEPT,
                name.to_owned(),
            );
            if let Some(account) = account
                && !tally.accounts.contains_key(name)
            {
                if tally.accounts.len() < ACCOUNTS_KEPT {
                    tally.accounts.insert(name.to_owned(), account);
                } else {
                    tally.more_accounts = tally.more_accounts.saturating_add(1);
                }
            }
        }
        for alarm in alarms {
            if self.alarms.len() < ALARMS_KEPT {
                self.alarms.push(alarm);
            } else {
                self.more_alarms = self.more_alarms.saturating_add(1);
            }
        }
    }

    /// One summary record per action and the alarm rows, or `None` when nothing was counted.
    pub(crate) fn batch(&self, now: Timestamp) -> Option<WriteBatch> {
        if self.by_action.is_empty() {
            return None;
        }
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), now);
        batch.mutations.clone_from(&self.alarms);
        for (action, tally) in &self.by_action {
            let objects = tally
                .accounts
                .values()
                .map(|id| ObjectRef::from(*id))
                .collect();
            batch.audit(
                AuditDraft::failed(action.clone(), objects, &AuthError::InvalidCredentials)
                    .with_context(
                        "summary",
                        "failed sign-ins the store refused while its disk was short of room",
                    )
                    .with_context("attempts", tally.attempts.to_string())
                    .with_context("names", tally.names.len().to_string())
                    .with_context("more_names", tally.more_names.to_string())
                    .with_context("networks", joined(tally.networks.iter()))
                    .with_context("more_networks", tally.more_networks.to_string())
                    .with_context("accounts", joined(tally.accounts.keys()))
                    .with_context("more_accounts", tally.more_accounts.to_string())
                    .with_context("more_alarms", self.more_alarms.to_string()),
            );
        }
        Some(batch)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    #[test]
    fn the_summary_counts_and_names_within_its_bounds_per_action() {
        let action = AuditAction::from_static("auth.login.password");
        assert_eq!(Unrecorded::default().batch(Timestamp::UNIX_EPOCH), None);
        let mut unrecorded = Unrecorded::default();
        let ada = UserId::generate();
        let alarm = Mutation::Put {
            table: crate::model::ALARMS.name().clone(),
            key: Bytes::from_static(b"a"),
            value: Bytes::from_static(b"alarm"),
        };
        for _ in 0..3 {
            unrecorded.note(
                action.clone(),
                ("ada", Some(ada)),
                "192.0.2.0/24".to_owned(),
                vec![alarm.clone()],
            );
        }
        for n in 0..(NAMES_KEPT + 10) {
            unrecorded.note(
                action.clone(),
                (&format!("guess-{n:03}"), None),
                format!("net-{n:03}"),
                Vec::new(),
            );
        }
        for n in 0..(ACCOUNTS_KEPT + 5) {
            unrecorded.note(
                action.clone(),
                (&format!("user-{n:03}"), Some(UserId::generate())),
                "192.0.2.0/24".to_owned(),
                vec![alarm.clone()],
            );
        }
        // Another action keeps its own counts.
        let renew = AuditAction::from_static("auth.token.renew");
        unrecorded.note(renew, ("", None), "198.51.100.0/24".to_owned(), Vec::new());
        let batch = unrecorded.batch(Timestamp::UNIX_EPOCH).expect("a summary");
        assert_eq!(batch.audit.len(), 2, "one record per action");
        let draft = batch
            .audit
            .iter()
            .find(|draft| draft.action == action)
            .expect("the password record");
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
        let networks: Vec<&str> = context["networks"].split(", ").collect();
        assert_eq!(networks.len(), NETWORKS_KEPT, "the networks named");
        assert_eq!(networks[0], "192.0.2.0/24");
        assert_eq!(context["more_networks"], "11", "the rest counted");
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
        let renewal = &batch.audit.iter().find(|draft| draft.action != action);
        let renewal = &renewal.expect("the renewal record").details.context;
        assert_eq!(renewal["attempts"], "1");
        assert_eq!(renewal["names"], "0");
        assert_eq!(renewal["networks"], "198.51.100.0/24");
        assert_eq!(batch.mutations.len(), ALARMS_KEPT, "the alarm rows kept");
        assert_eq!(
            context["more_alarms"],
            (3 + ACCOUNTS_KEPT + 5 - ALARMS_KEPT).to_string()
        );
    }
}
