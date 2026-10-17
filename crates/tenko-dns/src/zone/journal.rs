//! The journal of each zone scope (`dns.journal`): one entry per committed serial step,
//! what IXFR sends (RFC 1995, read by WP6.1).
//!
//! An entry holds the serial before and after, the time, and the records removed and
//! added; `removed` starts with the old SOA record and `added` with the new one, in the
//! order an IXFR answer carries them. The key is (zone, scope, revision) with the revision
//! the change was planned against, which grows with every step of a scope.
//!
//! The journal is bounded per scope by entries and by days ([`JournalLimits`]). Every
//! append drops, in the same batch, the oldest entries beyond the count and those older
//! than the age limit (at most [`DROP_PER_WRITE`] at a time, so a backlog shrinks over
//! the next writes). Two counters per scope, appended and dropped, give the count without
//! a scan. A request for a serial older than the first entry is answered with AXFR.

use std::time::Duration;

use tenko_core::{
    CounterKey, Revision, Timestamp,
    codec::key::encode_key,
    dns::{JournalEntry, ScopeName, ZoneId, tables::JOURNAL},
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, WriteBatch};

use super::ZoneResult;

/// Entries dropped by one append at most.
pub const DROP_PER_WRITE: usize = 32;

/// How long and how large the journal of one zone scope may grow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalLimits {
    /// Entries per scope.
    pub entries: u64,
    /// Days an entry is kept.
    pub days: u32,
}

impl Default for JournalLimits {
    fn default() -> Self {
        Self {
            entries: 1_000,
            days: 30,
        }
    }
}

fn appended(zone: ZoneId, scope: &ScopeName) -> CounterKey {
    CounterKey::with("dns.journal.appended", &(zone, scope.clone()))
}

fn dropped(zone: ZoneId, scope: &ScopeName) -> CounterKey {
    CounterKey::with("dns.journal.dropped", &(zone, scope.clone()))
}

/// The entries of a scope the view holds.
///
/// # Errors
///
/// The store's error.
pub fn count(view: &dyn ReadView, zone: ZoneId, scope: &ScopeName) -> ZoneResult<u64> {
    let added = view.counter(&appended(zone, scope))?;
    let gone = view.counter(&dropped(zone, scope))?;
    Ok(added.saturating_sub(gone))
}

fn scope_range(zone: ZoneId, scope: &ScopeName) -> KeyRange {
    KeyRange::prefix(encode_key(&(zone, scope.clone())))
}

/// Adds an entry to `batch` and drops what falls out of the limits.
///
/// # Errors
///
/// The store's error, or a codec error.
pub fn stage_append(
    batch: &mut WriteBatch,
    view: &dyn ReadView,
    limits: JournalLimits,
    entry: &JournalEntry,
) -> ZoneResult<()> {
    let key = (entry.zone, entry.scope.clone(), entry.revision);
    batch.expect_typed(&JOURNAL, &key, None);
    batch.put_typed(&JOURNAL, &key, entry)?;
    batch.bump(appended(entry.zone, &entry.scope));
    let held = count(view, entry.zone, &entry.scope)?.saturating_add(1);
    let mut excess = held.saturating_sub(limits.entries);
    let oldest_kept = entry
        .at
        .to_utc()
        .unix_nanos()
        .saturating_sub(i128::from(limits.days) * 86_400 * 1_000_000_000);
    let oldest = view.scan_typed(
        &JOURNAL,
        scope_range(entry.zone, &entry.scope),
        DROP_PER_WRITE,
        false,
    )?;
    for (old_key, old, _) in oldest {
        let expired = old.at.unix_nanos() < oldest_kept;
        if excess == 0 && !expired {
            break;
        }
        batch.delete_typed(&JOURNAL, &old_key);
        batch.bump(dropped(entry.zone, &entry.scope));
        excess = excess.saturating_sub(1);
    }
    Ok(())
}

/// Drops every entry of a scope: after an import too large for one entry and when the
/// scope or the zone goes. A transfer request for an older serial then gets AXFR.
///
/// # Errors
///
/// The store's error.
pub fn stage_reset(
    batch: &mut WriteBatch,
    view: &dyn ReadView,
    zone: ZoneId,
    scope: &ScopeName,
) -> ZoneResult<usize> {
    let entries = view.scan(JOURNAL.name(), scope_range(zone, scope), usize::MAX, false)?;
    for (key, _) in &entries {
        batch.delete(JOURNAL.name().clone(), key.clone());
        batch.bump(dropped(zone, scope));
    }
    Ok(entries.len())
}

/// Up to `limit` entries of a scope, newest first, before the revision `before`.
///
/// # Errors
///
/// The store's error.
pub fn list(
    view: &dyn ReadView,
    zone: ZoneId,
    scope: &ScopeName,
    before: Option<Revision>,
    limit: usize,
) -> ZoneResult<Vec<JournalEntry>> {
    let mut range = scope_range(zone, scope);
    if let Some(before) = before {
        range = range.before(encode_key(&(zone, scope.clone(), before)));
    }
    Ok(view
        .scan_typed(&JOURNAL, range, limit, true)?
        .into_iter()
        .map(|(_, entry, _)| entry)
        .collect())
}

/// The age limit as a duration.
pub fn max_age(limits: JournalLimits) -> Duration {
    Duration::from_secs(u64::from(limits.days) * 86_400)
}

/// Whether an entry at `at` is past the age limit at `now`.
pub fn expired(limits: JournalLimits, at: Timestamp, now: Timestamp) -> bool {
    now.saturating_since(at) > max_age(limits)
}
