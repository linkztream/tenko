# Upgrades

This document specifies how a Tenko DDI installation moves from one version to the next:
the format version of the data directory and its migrations (OPS-23), the rule that tells a
developer when a change needs a new format, the dry-run command `tenko upgrade check`, the
release artifacts and the release manifest, the operator's procedure for a manual upgrade and
a rollback, updates installed from the web UI with their probation and switch back (OPS-24,
TGL-23), the version layout that the service managers run from, and the module switch
(OPS-25). Requirements are cited by ID and defined in [REQUIREMENTS.md](REQUIREMENTS.md);
the profile toggle TGL-23 is defined in [SECURITY-PROFILES.md](SECURITY-PROFILES.md).

## Abstract

A Tenko DDI node has a binary and a data directory. The binary has a version, such as 0.2.0.
The data directory has a format, a whole number such as 1, which changes only when the stored
data changes. A binary migrates an older format when it starts and refuses a newer format
before it touches anything. The operator checks a new binary against a copy of the data with
`tenko upgrade check`, switches to it, and can go back, because the previous version stays
installed and the store is copied before it is migrated. An installation that runs from the
version layout can do the same from the web UI, with a verified download, a dry run, and an
automatic switch back when the new version does not become ready.

## Conventions

In this document "must" and "must not" mark a rule that the product, the developer or the
operator cannot skip without breaking an upgrade or losing data. "Should" marks a
recommendation that has a reason, given where it appears. "May" marks a free choice. Paths
use the Linux form (`/var/lib/tenko`) unless the text names Windows; on Windows the data
directory is the `data_dir` of the configuration, by default `C:\ProgramData\Tenko`.
Versions in examples (0.1.0, 0.2.0) and the host name `ddi.example.org` are examples. Where
this document and the code disagree, the code is right and the document has a defect.

## Contents

1. [Overview](#1-overview)
2. [Terminology](#2-terminology)
3. [Data-directory format](#3-data-directory-format)
4. [The migration convention](#4-the-migration-convention)
5. [`tenko upgrade check`](#5-tenko-upgrade-check)
6. [Releases](#6-releases)
7. [Manual upgrade and rollback](#7-manual-upgrade-and-rollback)
8. [Updates from the UI](#8-updates-from-the-ui)
9. [The layout and the service managers](#9-the-layout-and-the-service-managers)
10. [Modules](#10-modules)
11. [Open items](#11-open-items)

## 1 Overview

Three things change when an installation moves to a new version: the binary, the data on
disk, and what the operator has to do. Tenko keeps them apart.

- The **version** of the binary is a Semantic Versioning 2.0.0 number: `0.2.0`, or
  `0.3.0-rc.1` for a pre-release. Every release has one.
- The **format** of the data directory is a whole number: `1`, `2`, and so on. It is raised
  by a change to stored data and by nothing else, so many versions share one format.
- The **layout** is how binaries are placed on disk so that a version can be switched by
  moving a link (section 9). It is optional for manual upgrades and required for installs
  from the UI.

Two principles run through every part of the design.

1. **Never open data that is not understood.** A binary compares the format of the data
   directory with its own before it loads keys or opens the store. A newer format is
   refused with a clear error and nothing is touched (section 3.3).
2. **Always keep a way back.** The store is copied before it is migrated (section 3.4), the
   previous version stays installed, and a version installed from the UI that does not
   become ready is switched back (section 8.6).

| Part | What it does | Section | Requirement |
|---|---|---|---|
| Format records | Say which format a data directory has | 3 | OPS-23 |
| Migrations | Convert data from one format to the next at start | 3, 4 | OPS-23 |
| `tenko upgrade check` | Dry-runs the migrations on a copy and reports with an exit code | 5 | OPS-23 |
| Releases and manifest | Binaries, image, checksums and release notes for a tag | 6 | OPS-23, OPS-24 |
| Manual procedure | Stop, back up, check, switch, start, verify, roll back | 7 | OPS-23 |
| Updates from the UI | Notice, release notes, install job, probation, switch back | 8 | OPS-24, TGL-23 |
| Layout | `current` and `previous` links under `<data_dir>/updates` | 9 | OPS-24 |
| Modules | Which parts of the product an installation runs | 10 | OPS-25 |

Operators read sections 3, 5 and 7 to 9. Developers read sections 3 to 5. Whoever cuts a
release reads section 6. This document describes a single node, which is what Phase 1 runs;
clusters are covered in sections 8.10 and 11.

## 2 Terminology

| Term | Meaning |
|---|---|
| Data directory | The directory named by `data_dir` (`--data-dir`, `TENKO_DATA_DIR`). It holds `store/`, `kek/`, `tls/`, `logs/`, `upgrade-backups/` and `updates/`. |
| Store | The replicated store of a node, in `<data_dir>/store`: the Raft log `log.redb`, the state file that `sm.current` names (`sm.redb` before the first snapshot), `snapshots/` and the format marker. |
| Version | The release number of a binary (SemVer). `tenko --version` prints the version of the executable you ran. |
| Format | The version of the on-disk layout of the data directory, a whole number. The current format of a binary is printed by `tenko upgrade format`. |
| Marker | The file `<data_dir>/store/format`, which names the format. Read before the store is opened. |
| Stored record | The single row of the table `sys.format` inside the store, which also names the format. Replicated with the data. |
| Migration | The code that turns the data of format N-1 into format N. One file per format, `v<N>.rs`. |
| Registry | The list of migrations compiled into a binary (`MIGRATIONS`), the format table (`FORMATS`) and the number `CURRENT`. |
| Dry run | A migration run on a copy of the data that is thrown away, to find out whether the real run would pass. |
| Fixture | A small data directory of format N written by a binary of format N and kept in the repository, so that later binaries prove that they can open it. |
| Release | A tagged version with its binaries, image, checksums and notes. |
| Manifest | `releases.json`: the machine-readable list of releases that installations read (section 6.3). |
| Asset | One downloadable file of a release for one platform, such as `tenko-0.2.0-linux-x86_64`. |
| Platform | `<os>-<arch>` as Rust names them: `linux-x86_64`, `windows-x86_64`. |
| Layout | The directory `<data_dir>/updates` with one directory per installed version and the links `current` and `previous` (section 9). |
| `current`, `previous` | Links (symbolic links on Linux, directory junctions on Windows). The service manager starts the binary in the directory that `current` points at. |
| Bootstrap binary | The executable installed by hand (`/usr/local/bin/tenko`, or the file that ran `tenko service install`). It copies itself into the layout. |
| Install job | The job of kind `sys.update` that installs a version from the UI. |
| Attempt record | `<data_dir>/updates/attempt.json`: the state of the last install. |
| Probation | The period after an install in which the new version must become ready or be switched back. |
| Switch back | Pointing `current` at the previous version again and restarting. |
| Service manager | systemd, the Windows Service Control Manager, or another supervisor that restarts the server when it exits with status 12. |
| Step-up | A fresh sign-in: the session must have authenticated within the last 5 minutes. |
| Air-gapped | An installation that never contacts the release source (`updates.air_gapped = true`). |
| Module | A part of the product that an installation runs or not: `ipam`, `dns`, `dhcp`, `discovery` (OPS-25). |

## 3 Data-directory format

### 3.1 The two records

A data directory names its format in two places that must agree.

| Record | Where | Written | Read |
|---|---|---|---|
| Marker | `<data_dir>/store/format` | Atomically: written to `format.part`, synced, renamed over the old marker | Before the store is opened |
| Stored record | Table `sys.format`, one row, inside the store | In the same write batch as each migration | After the store is opened |

The marker is a text file. Only the first line counts; later lines are informational and
unknown ones are ignored, so a newer binary may add lines without breaking an older reader.

```text
tenko-data-format 1
written-by 0.1.0
```

The marker exists so that a binary that does not know a format can refuse the directory
without opening a single redb file. The stored record exists so that the format travels with
the data: it is replicated, and snapshots and copies of the store carry it. The current
format of a binary is printed by

```
tenko upgrade format
```

### 3.2 What `tenko serve` does at start

`tenko serve` compares the marker with its own format before it loads the key-encryption
keys, then settles the rest in the `store` start step.

| Found | What happens | If refused |
|---|---|---|
| No store | The directory is new. The store is created and both records say the current format. | |
| The current format | The server starts. A record that is missing is written. | |
| An older format, every migration present | The closed store is copied aside (section 3.4), the store is opened, and every migration runs in turn (below). | |
| An older format, a migration missing | The start is refused with `upgrade.migration_missing`. Upgrade through an intermediate release that has the missing step. | Exit 4 |
| A newer format | The start is refused with `upgrade.format_newer` (section 3.3). | Exit 3 |
| Records that disagree | The start is refused with `upgrade.format_mismatch` (section 3.5). | Exit 4 |

A migration step is one write batch. The batch holds the mutations of the migration, the
bump of the stored record and an audit record `sys.upgrade.migrate` whose context names
`from`, `to`, `summary` and `binary`. The data and its format number therefore change
together or not at all. The batch has a precondition on the stored record, so two writers
cannot both migrate. The marker follows each committed step. A migration from format 1 to
format 3 runs two steps and commits two batches.

The start log says what happened. The `store` step line carries the format in its summary:

```
step 2/9 store ready in 101 ms: opened at revision 15, audit head 17, data format 1, ...
step 2/9 store ready in 640 ms: opened at revision 15, audit head 18, data format 2 (migrated from format 1 in 1 step(s)), ...
```

A migration that fails does not commit its batch and does not move the marker. The start
stops at the `store` step with `upgrade.migration_failed` and exit status 4, and the log
names the copy that was taken before the migration. Steps that had committed earlier stay
committed: after a failure in step 2 of 2 the store is at format 2. The next start of the
same binary resumes from there and takes a new copy of the store as it is then. Because only
the newest three copies are kept, an operator who retries a failed migration more than twice
should first copy the original pre-migration copy out of `upgrade-backups`.

A migration runs before the server reports ready. On a large store it can take longer than
the 120 seconds that `TimeoutStartSec=` of the systemd unit allows. `tenko upgrade check`
runs the same migrations, so its run time is a good estimate; where it comes near a minute,
the operator should raise the limit before the first start with `systemctl edit tenko`
(`[Service]`, `TimeoutStartSec=600s`).

### 3.3 A newer format is refused

A binary whose format is older than the directory's refuses to start. It does so before it
loads keys or opens the store, so nothing is changed, and it exits with status 3 (a
deployment error that a restart cannot fix, which the systemd unit does not retry):

```
upgrade.format_newer: the data directory has format 2, newer than format 1 that tenko 0.0.1
reads: run the newer version, or restore the copy taken before the upgrade
(docs/upgrades.md)
```

There are two ways out: run a binary that knows the format, or restore a copy of the data
directory made before the format was raised (section 7.6). Starting an older binary on a
migrated directory is never a repair; the refusal protects the data.

### 3.4 Copies before a migration

When a migration is needed, `tenko serve` copies the closed store before it opens it:

```
<data_dir>/upgrade-backups/<UTC time>-format-<from>-to-<to>/store
```

for example `upgrade-backups/20261009T201502Z-format-1-to-2/store`. The names sort by time.
The newest 3 copies are kept and older ones are removed after a new copy succeeds.

A copy holds the Raft log `log.redb`, the state file that `sm.current` names, `sm.current`
itself, the marker, and `snapshots/` (unfinished `.part` files excluded). Every copied file
is synced. A copy is taken only from a store that no process has open, because redb files
are consistent only when closed; a store that is open elsewhere makes the copy fail with
`upgrade.in_use`.

The copy is a rollback point for the store, not a backup of the installation: it holds no
keys, certificates, logs or configuration. The operator's backup (section 7.2) is a copy of
the whole data directory and of the key-encryption key. The copy needs free space of about
the size of `<data_dir>/store`; the server does not check this before it starts to copy.

### 3.5 Records that disagree

The marker and the stored record may differ in one harmless way: a migration committed and
the process stopped before the marker followed. The store is then ahead of the marker by a
format the binary knows, and the next start repairs the marker and logs a warning. The other
disagreement that can occur is refused with `upgrade.format_mismatch` and exit status 4: the
marker names a newer format than the store holds. That means that the store files do not
belong to this data directory or that the marker was edited. Restore a matching copy; do not
edit the marker to make the message go away.

A stored record that names a format newer than the binary knows is the newer-format refusal
of section 3.3, whatever the marker says.

### 3.6 Directories from before format versions

A data directory without a marker and without a stored record was written before format
versions existed. It is format 1. The first start of a binary that knows formats writes both
records. `tenko upgrade check` reports such a directory with `"legacy": true`.

## 4 The migration convention

This section is for developers. It answers three questions: when does a change to stored
data need a new format, what does a format change consist of, and how is it proved to work.
The same rules are stated in the module comments of `crates/tenko/src/upgrade/migrations`
and in `crates/tenko-core/src/codec/mod.rs` (rules for stored types).

### 4.1 When a change needs a new format

The format number answers one question: can a binary that does not know a change open the
data safely? The question has two halves, and both must be asked.

1. **Forward.** Can the new binary read everything that earlier releases wrote? It always
   must. If the old bytes still decode as they are, nothing has to be converted. If they do
   not, the change needs a migration that converts them.
2. **Backward.** After the new binary has written data, does an older binary still work
   correctly on it? If the older binary ignores what it does not know and misreads nothing,
   the format number stays. If it would misread, fail on a request, or not find data that
   exists, the format number must go up, so that the older binary refuses the directory
   instead of working on it wrongly.

The result for common changes:

| Change | New binary reads old data as it is | Older binary works on data the new one wrote | New format |
|---|---|---|---|
| A field with `#[serde(default)]` is added to a stored type | Yes | Yes: it ignores the field and drops it when it rewrites the record | No |
| A table is added that no older code reads | Yes | Yes | No |
| The encoding of a key changes | No | No | Yes, with a migration that rewrites the keys |
| A table is renamed or split | No | No | Yes, with a migration |
| The encoding of a value changes | No | No | Yes, with a migration |
| A field is renamed or its type changes | No | No | Yes, with a migration (and avoid it: stored fields are never renamed or retyped) |
| A new variant of a stored enum is written into existing records | Yes | No: an older binary cannot decode the variant | Yes; the migration may be empty |
| The files of the store change (a new file, a different snapshot layout) | Depends | No | Yes; the copy code of `tenko-store` must learn the file |

Two examples show the judgment.

**An optional field: no new format.** A release adds `comment: Option<String>` with
`#[serde(default)]` to a stored type. Stored values are CBOR maps keyed by field name. The
new binary reads an old record and finds no `comment`, so the field is `None`. An older
binary reads a new record and meets a key it does not know; serde ignores it, unless the
type rejects unknown fields with `#[serde(deny_unknown_fields)]`, which a stored type should
not do for exactly this reason. If the older binary then rewrites the record, the comment
is gone. Nothing is misread; the only loss is the data of the new feature, and only
in the case of a rollback. A format number would do harm here: it would make the older
binary refuse a directory that it can work on, and take away the cheap rollback. The rules
for stored types make this case safe: new fields carry `#[serde(default)]`, and fields are
never renamed or retyped.

**A key encoding: new format.** A release stores the keys of a table in lower case so that
lookups ignore case. The new binary looks up `core` and finds nothing, because the old rows
sit under `Core`: the data appears to be missing, and no error says so. An older binary on
migrated data fails the other way round: it looks up `Core`, finds nothing, and may create a
`Core` row next to the `core` row. Both failures are silent. The change needs a new format
with a migration that rewrites the keys, and the format number makes the older binary refuse
the migrated directory. The only way back is the copy of the store taken before the
migration (section 3.4).

A test that settles doubtful cases: run the new binary on a copy of a data directory written
by the previous release, use the changed feature, stop it, and start the previous release on
the result. If the previous release works correctly, apart from not showing the new feature,
the format stays. If it shows wrong data, fails on a request, or cannot find data that
exists, raise the format.

A migration may be empty. When the new binary can read the old data as it is but an older
binary must be kept away from what the new one writes (the enum variant in the table), the
migration returns no mutations and only the bump of the format takes effect.

When the answer is not clear, the developer should raise the format. A needless raise costs
a rollback path: the older binary refuses the directory and the store must be restored from
a copy. A missing raise costs data. The pull request description must state the answer to
both halves of the question, even when it is "no new format".

### 4.2 What a format change consists of

Every change to stored data that needs a new format raises `CURRENT` by one and adds exactly
one migration, in the same pull request as the change itself:

1. the change to the stored data in the application code;
2. `CURRENT` raised by one in `crates/tenko/src/upgrade/migrations/mod.rs`;
3. one new file `crates/tenko/src/upgrade/migrations/v<N>.rs` with a type that implements
   `Migration` (`to()` returns N);
4. `mod v<N>;` and `&v<N>::V<N>` in `MIGRATIONS`, and a `FormatInfo` line in `FORMATS` with
   the version, the first release that writes it (`since`) and a one-line summary;
5. a unit test of the migration, built on `MemStore`;
6. the fixture `crates/tenko/tests/fixtures/datadir/v<N>/` (section 4.5);
7. an entry under `## [Unreleased]` in `CHANGELOG.md`: under `### Changed`, naming the
   format; under `### Action required` when the operator has to do something; saying that a
   return to the previous release needs the pre-migration copy;
8. a change to this document when the convention itself changes.

Unit tests in `migrations/mod.rs` fail when the registry has a gap (every format from the
initial one to `CURRENT` needs its migration) or when `FORMATS` does not list every format
once, in order. The compatibility test fails when the fixture of the current format is
missing.

A migration stays in the registry for as long as upgrades from the format it starts at are
supported. A binary that finds a format with a missing step refuses it with
`upgrade.migration_missing` and tells the operator to upgrade through an intermediate
release. Removing a migration is therefore a decision about which upgrade paths end; it
needs an entry under `### Action required` in the changelog of the release that does it.

### 4.3 The `Migration` trait

```rust
pub trait Migration: Send + Sync {
    /// The format this migration produces; it runs on a store at `to() - 1`.
    fn to(&self) -> u32;

    /// What the migration does, in English, for the log and `tenko upgrade check`.
    fn summary(&self) -> &'static str;

    /// The mutations that turn the data of `view` (at format `to() - 1`) into format
    /// `to()`. The runner commits them in one batch with the bump of the stored format.
    fn plan(&self, view: &dyn ReadView) -> Result<Vec<Mutation>, MigrationError>;
}
```

`plan` reads a consistent view of the store at the previous format and returns the
mutations (`Put`, `Delete`, `Bump`). It does not write: the runner adds the bump of the
stored format record and the audit record `sys.upgrade.migrate` to the same batch and
commits it. `MigrationError::Data(reason)` is the way to refuse data that cannot be
migrated; `StoreError` converts into `MigrationError` with `?`.

A migration must follow these rules:

- It must be self-contained. It names its tables and decodes its keys and values itself,
  not through the application types that later releases change. A migration that calls the
  current application code breaks the day that code moves on.
- It must be deterministic. It reads no clock, no random source, no file and no network.
- It must not lose data silently. Where the old data cannot be converted without choosing
  between two rows, it returns an error that names the rows (see the example) and the
  operator resolves the conflict before upgrading.
- It must keep its memory in proportion to the rows it changes, not to the whole table,
  where that is possible; for a large table it follows section 4.6.

### 4.4 Worked example: adding format 2

The example below predates the real format 2, which Slice 3 took for its contract types (an
empty migration, `crates/tenko/src/upgrade/migrations/v2.rs`, so that a Slice 2 binary
refuses a Slice 3 data directory). Read it as the next format: the steps are the same with
every number one higher.

Release 0.3.0 makes label names case-insensitive by storing them in lower case. The table
`ipam.labels` is an invented table for this example; it is not a table of the product. The
change satisfies neither half of the rule in section 4.1, so it needs format 2.

**Step 1: the migration.** The file `crates/tenko/src/upgrade/migrations/v2.rs`:

```rust
//! Format 2: the keys of `ipam.labels` are stored in lower case.

use std::collections::BTreeMap;

use tenko_core::{
    TableName,
    codec::{decode_key, encode_key},
};
use tenko_store::{KeyRange, Mutation, ReadView};

use super::{Migration, MigrationError};

/// The table whose keys change. The name is written out here and not taken from the
/// application code, which moves on while this migration must not.
const LABELS: TableName = TableName::from_static("ipam.labels");

/// The migration from format 1 to format 2.
pub struct V2;

impl Migration for V2 {
    fn to(&self) -> u32 {
        2
    }

    fn summary(&self) -> &'static str {
        "stores the keys of ipam.labels in lower case"
    }

    fn plan(&self, view: &dyn ReadView) -> Result<Vec<Mutation>, MigrationError> {
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        let mut mutations = Vec::new();
        for (key, row) in view.scan(&LABELS, KeyRange::all(), usize::MAX, false)? {
            let name: String = decode_key(&key).map_err(|error| {
                MigrationError::Data(format!("a key of ipam.labels does not decode: {error}"))
            })?;
            let lower = name.to_lowercase();
            if let Some(other) = seen.insert(lower.clone(), name.clone()) {
                return Err(MigrationError::Data(format!(
                    "the labels `{other}` and `{name}` differ only in case; rename one first"
                )));
            }
            if lower != name {
                mutations.push(Mutation::Delete { table: LABELS, key });
                mutations.push(Mutation::Put {
                    table: LABELS,
                    key: encode_key(&lower),
                    value: row.value,
                });
            }
        }
        Ok(mutations)
    }
}
```

Two labels that differ only in case are a conflict that the migration cannot resolve; it
returns an error, the start (or the dry run) fails, and nothing is changed.

**Step 2: the registry.** In `crates/tenko/src/upgrade/migrations/mod.rs`:

```rust
mod v2;

pub const CURRENT: u32 = 2;

pub const FORMATS: &[FormatInfo] = &[
    FormatInfo {
        version: 1,
        since: "0.1.0",
        summary: "the initial format: ...", // unchanged
    },
    FormatInfo {
        version: 2,
        since: "0.3.0",
        summary: "the keys of ipam.labels are stored in lower case",
    },
];

pub static MIGRATIONS: &[&dyn Migration] = &[&v2::V2];
```

**Step 3: the application change.** In the same pull request, the code that writes and looks
up label names uses lower case.

**Step 4: a unit test.** In `v2.rs`, build a `MemStore` in the old layout, run `plan`, commit
the result and read it back. The tests of `datadir.rs` show the pattern. At least these
cases are covered: the keys are rewritten and the values are kept (shown below), and two
rows that differ only in case are refused with `MigrationError::Data` (a second test of the
same shape).

```rust
#[cfg(test)]
mod tests {
    use tenko_core::{Principal, SystemComponent, Timestamp};
    use tenko_store::{MemStore, ReadConsistency, Store, WriteBatch};

    use super::*;

    fn batch(mutations: Vec<Mutation>) -> WriteBatch {
        let mut batch =
            WriteBatch::new(Principal::system(SystemComponent::Store), Timestamp::now());
        batch.mutations = mutations;
        batch
    }

    #[tokio::test]
    async fn keys_are_lower_cased_and_values_are_kept() {
        let key = |name: &str| encode_key(&name.to_owned());
        let store = MemStore::default();
        store
            .propose(batch(vec![Mutation::Put {
                table: LABELS,
                key: key("Core"),
                value: b"row".to_vec().into(),
            }]))
            .await
            .expect("seed the old layout");

        let view = store.read(ReadConsistency::Local).await.expect("view");
        let mutations = V2.plan(view.as_ref()).expect("plan");
        drop(view);
        store.propose(batch(mutations)).await.expect("migrate");

        let view = store.read(ReadConsistency::Local).await.expect("view");
        assert!(view.get(&LABELS, &key("Core")).expect("read").is_none());
        let row = view.get(&LABELS, &key("core")).expect("read").expect("row");
        assert_eq!(row.value.as_ref(), b"row");
    }
}
```

**Step 5: the fixture.** With the new binary:

```
export TENKO_UI_STUB=1
TENKO_REGENERATE_FIXTURES=1 cargo test -p tenko --test upgrade_compat
```

This writes `crates/tenko/tests/fixtures/datadir/v2/` (section 4.5). Before it, extend
`populate` and `objects` in `crates/tenko/tests/upgrade_compat.rs` so that the new fixture
holds data of the kind that changed, here a label. The comparison for the older fixtures
must keep ignoring objects that did not exist when they were written; adjust the helper
and never an old `expected.json`. Review the diff: `v2/` is new, `v1/` is unchanged.

**Step 6: run the checks.**

```
cargo nextest run -p tenko
cargo clippy --workspace --all-targets -- -D warnings
```

The compatibility test migrates the `v1` fixture with the new binary and finds its objects,
and opens the `v2` fixture without a migration.

**Step 7: look at the dry run.** Copy the `v1` fixture to a scratch directory and run the
new binary's check on it. The report names the step:

```
tenko 0.3.0 (data format 2) checked /tmp/tenko-v1
found: data format 1
  migrated to format 2: stores the keys of ipam.labels in lower case
result: a migration is needed and passed on a copy; tenko serve copies the store aside and migrates at its next start (exit 10)
```

**Step 8: the changelog.** Under `## [Unreleased]`:

```
### Changed

- Data format 2: label names are stored in lower case. The first start of this version
  copies the store to `upgrade-backups/` and migrates it; going back to 0.2.x needs that
  copy (docs/upgrades.md).
```

### 4.5 Fixtures and the compatibility test

The test `crates/tenko/tests/upgrade_compat.rs` opens a data directory of every earlier
format with the current binary and finds its objects. A fixture is the directory
`crates/tenko/tests/fixtures/datadir/v<N>/`:

| File | Contents |
|---|---|
| `store/` | The closed store written by a binary whose format is N, with its marker |
| `fixture-kek.hex` | The key-encryption key of the fixture, made for it and protecting nothing else |
| `expected.json` | The format, the version that wrote it, and the objects the test must find (prefixes, addresses, hosts, VLANs) |

For every fixture the test copies it to a fresh node, runs `tenko upgrade check --json` (the
verdict is `current` for the current format and `migration_needed` for an earlier one),
starts the server, signs in, lists the objects through the API and compares them with
`expected.json`, asks `/system/updates` for the format, stops the server, and checks that a
migrated start left a copy in `upgrade-backups` and that the marker names the current
format.

The rules for fixtures:

- The fixture of format N is written once, by the binary that introduces format N, and then
  never changed. Fixtures of earlier formats stay as they are for good; they are what proves
  that old directories still open. Regenerating the fixture of the current format while its
  release is not yet cut is allowed: the redb files differ at every generation (time
  stamps, identifiers), and the objects in `expected.json` must not.
- Every format has a fixture. The test fails when the fixture of the current format is
  missing.
- Fixtures use documentation data only: addresses from RFC 5737 and RFC 3849, MAC addresses
  from RFC 7042, host names under `example.com`, `example.net`, `example.org` or `.test`.
- Fixtures stay small. The test fails when all fixtures together exceed 4 MiB, and each
  fixture should stay under 1 MiB. The limit is a total over all formats and earlier
  fixtures cannot be regenerated, so a new fixture should hold only as much data as it
  needs.

### 4.6 Migrations larger than one batch

The runner commits the plan of a migration as one write batch, and the store limits a batch
to 16 MiB. A migration whose batch would exceed the limit must split its work into
idempotent batches and leave the bump of the format to the last one, so that a stop
between two batches is resumed by running the migration again. The `Migration` trait yields
one batch today and no existing migration needs more; the first migration that does extends
the trait and the runner in the same change.

### 4.7 Changes to the files of the store

A change to the on-disk files of the store itself (a new file, a different snapshot layout)
needs a new format like any other change, and the code that copies a closed store
(`copy_closed_store` in `crates/tenko-store/src/format.rs`) must learn the file, or the
copy before a migration and the dry run of `tenko upgrade check` would leave it out. A
change of redb's own file format, which a new major version of redb can bring, cannot be done
by a `Migration`, because a migration runs on a store that the current binary has already
opened. It needs a conversion step that runs offline, before the store is opened. That step
does not exist yet (section 11).

## 5 `tenko upgrade check`

### 5.1 Synopsis

```
tenko upgrade check [--config FILE] [--data-dir PATH] [--work-dir PATH] [--json]
tenko upgrade format
tenko upgrade layout [--config FILE] [--data-dir PATH]
```

| Option | Meaning |
|---|---|
| `--config FILE` | The configuration file (also `TENKO_CONFIG`). It names the data directory and the Raft node id (`node.id`) of the store. |
| `--data-dir PATH` | The data directory to check. It overrides `data_dir` of the configuration and `TENKO_DATA_DIR`. The server that uses it must be stopped. |
| `--work-dir PATH` | Where the copy for the dry run goes. The default is `<data_dir>/upgrade-check`. The copy is removed afterwards. |
| `--json` | Print the report as JSON. |

Two more options exist for the install job and are not part of the operator interface:
`--disposable` (the directory is itself a throw-away copy and is used in place) and
`--node-id`. `tenko upgrade version` prints the version the binary installs as; the install
job uses it to verify a downloaded file.

### 5.2 What the check does

The check answers one question: can this binary open this data directory, and do its
migrations pass? Run it with the **new** binary, with the server stopped, before switching.

1. It loads the configuration. An invalid one ends the check with exit status 3.
2. It reads the marker. A directory without a store is reported as new and the check ends.
3. It refuses a newer format and a missing migration at once, without copying anything.
4. It refuses a store that another process has open (`upgrade.in_use`, exit status 1),
   because the files of an open redb store are not consistent.
5. It copies the closed store into the work directory, opens the copy with this binary,
   reconciles the format records and runs every migration on the copy exactly as
   `tenko serve` would, closes the copy and removes it, also after a failure.

The check does not load keys and does not need the key-encryption key. It does not modify
any file of the data directory; the only thing it creates there is the work copy, which it
removes. It needs free space of about the size of the store in the work directory, and a
store of many gigabytes takes as long to copy as it takes to migrate. The run time is a
good estimate of the migration time at the real start (section 3.2).

### 5.3 Exit codes

| Status | Verdict | Meaning |
|---|---|---|
| 0 | `fresh` | There is no store yet. `tenko serve` creates it at this binary's format. |
| 0 | `current` | The directory is at this binary's format. Nothing to do. |
| 10 | `migration_needed` | The directory is older. Every migration exists and the dry run passed. `tenko serve` copies the store aside and migrates at its next start. |
| 11 | `refused` | This binary cannot use the directory: a newer format, a missing migration, records that disagree, a store that cannot be opened, or a migration that failed in the dry run. |
| 1 | `failed` | The check could not run: the store is open in a running server, a file operation failed, or the runtime could not start. |
| 3 | | The configuration is invalid. |
| 2 | | Usage: an unknown option. |

A script that gates an upgrade treats 0 and 10 as go and every other status as stop. Status
10 is not an error: it announces that the real start will migrate.

### 5.4 The report

The text report names the binary, the format it found, each migration of the dry run, the
result and, for a refusal or failure, the problem code and message. A refusal:

```
tenko 0.2.0 (data format 2) checked /var/lib/tenko
found: data format 3
result: refused (exit 11)
upgrade.format_newer: the data directory has format 3, newer than format 2 that tenko 0.2.0 reads: run the newer version, or restore the copy taken before the upgrade (docs/upgrades.md)
```

A directory from before format versions:

```
tenko 0.1.0 (data format 1) checked /var/lib/tenko
found: data format 1 (no format marker: a directory from before format versions)
result: the directory is at this binary's format, nothing to do (exit 0)
```

`--json` prints one JSON object with these fields:

| Field | Type | Meaning |
|---|---|---|
| `verdict` | string | `fresh`, `current`, `migration_needed`, `refused` or `failed` |
| `exit_code` | number | The exit status of the command |
| `binary_version` | string | The version of this binary |
| `binary_format` | number | The format this binary writes |
| `data_dir` | string | The directory that was checked |
| `found_format` | number or null | The format the directory has; `null` when there is no store or the check stopped before it could tell |
| `legacy` | boolean | The directory has no format marker (written before format versions existed) |
| `steps` | array | The migrations of the dry run, in order; each is `{ "to": <format>, "summary": "<text>" }` |
| `problem` | object or null | For `refused` and `failed`: `{ "code": "<code>", "message": "<text>" }` |

```json
{
  "verdict": "migration_needed",
  "exit_code": 10,
  "binary_version": "0.3.0",
  "binary_format": 2,
  "data_dir": "/var/lib/tenko",
  "found_format": 1,
  "legacy": false,
  "steps": [
    { "to": 2, "summary": "stores the keys of ipam.labels in lower case" }
  ],
  "problem": null
}
```

The problem codes:

| Code | Verdict | Meaning |
|---|---|---|
| `upgrade.format_newer` | `refused` | The directory has a newer format than this binary reads |
| `upgrade.migration_missing` | `refused` | A step between the directory's format and this binary's is missing; upgrade through an intermediate release |
| `upgrade.format_mismatch` | `refused` | The marker and the stored record disagree (section 3.5) |
| `upgrade.migration_failed` | `refused` | A migration returned an error; the message names the reason |
| `upgrade.open_failed` | `refused` | This binary cannot open the store files |
| `upgrade.marker_invalid` | `refused` | The marker cannot be read, or `sm.current` names a state file that does not exist |
| `upgrade.store` | `refused` | The store refused a read or a write of the format record |
| `upgrade.in_use` | `failed` | The store is open in another process; stop the server |
| `upgrade.io` | `failed` | A file operation failed; the message names the path |

## 6 Releases

### 6.1 Versions and tags

A release has a Semantic Versioning 2.0.0 version and a git tag `v<version>`: `v0.2.0`, or
`v0.3.0-rc.1` for a pre-release. The `v` belongs to the tag only. The changelog heading, the
manifest and every message use the version without it. Versions are ordered by SemVer
precedence: a pre-release ranks below its release, and build metadata after `+` is shown but
ignored in comparisons.

The version of the `tenko` crate (`crates/tenko/Cargo.toml`) must equal the tag without the
`v`. The binary reports the crate version, and the install job refuses a release file whose
binary reports another version than the manifest names (`update.version_mismatch`).

### 6.2 The release workflow

Pushing a tag `v*` runs `.github/workflows/release.yml`. It does these things:

1. **Verify.** The changelog has a section `## [<version>] - <date>` for the tag
   (`node scripts/changelog.mjs notes <version>` fails when it is missing).
2. **Build.** The web UI (`npm run build` in `ui/`) and then the binaries for Linux x86_64
   and Windows x86_64 with the real UI embedded. A release build refuses the placeholder
   page that `TENKO_UI_STUB=1` produces, so a release cannot ship without its UI.
3. **Image.** The container image from `deploy/Dockerfile`.
4. **Publish.** `SHA256SUMS` and the manifest `releases.json`
   (`scripts/release-manifest.mjs`), a release text taken from the changelog section, and the
   attachment of all of it to the release.

| Artifact | Name | Notes |
|---|---|---|
| Linux binary | `tenko-<version>-linux-x86_64` | |
| Windows binary | `tenko-<version>-windows-x86_64.exe` | |
| Container image | `ghcr.io/linkztream/tenko:<version>` | The tag `latest` moves only for releases without a pre-release part |
| Checksums | `SHA256SUMS` | `sha256sum` format, one line per binary of this release |
| Manifest | `releases.json` | Section 6.3 |

The manifest names each binary by `<base-url>/<file name>`, where the base URL is the
download URL of the release, `https://github.com/linkztream/tenko/releases/download/v<version>`.
The manifest of a release lists that release and, from the previous manifest, every earlier
release. The address `https://github.com/linkztream/tenko/releases/latest/download/releases.json`
therefore serves the manifest of the release that GitHub marks as the latest, with the
notes of all earlier releases.

### 6.3 The manifest

`releases.json` is JSON of schema 1. An installation treats it as untrusted input: it bounds
the size to 1 MiB, rejects an unknown schema or project, and validates every field before
anything else sees it. Unknown fields are ignored, so a newer manifest of the same schema
still parses. A manifest with a newer schema number is refused with a message that says it
was written for a newer Tenko.

```json
{
  "schema": 1,
  "project": "tenko",
  "releases": [
    {
      "version": "0.2.0",
      "date": "2026-10-09",
      "notes": "### Added\n\n- An entry.",
      "security": false,
      "requires_action": false,
      "format": 1,
      "assets": [
        {
          "platform": "linux-x86_64",
          "name": "tenko-0.2.0-linux-x86_64",
          "url": "https://github.com/linkztream/tenko/releases/download/v0.2.0/tenko-0.2.0-linux-x86_64",
          "sha256": "<64 lowercase hexadecimal digits>",
          "size": 12345678
        }
      ],
      "image": "ghcr.io/linkztream/tenko:0.2.0"
    }
  ]
}
```

The manifest:

| Field | Type | Rule |
|---|---|---|
| `schema` | number | Must be 1 |
| `project` | string | Must be `tenko` |
| `releases` | array | At most 1,000 releases with unique versions; the reader sorts them newest first |

A release:

| Field | Type | Rule |
|---|---|---|
| `version` | string | SemVer without a leading `v` |
| `date` | string | `YYYY-MM-DD` |
| `notes` | string | Markdown: the changelog section of the version; at most 64 KiB |
| `security` | boolean | True when the changelog section has a non-blank `### Security` subsection; default false |
| `requires_action` | boolean | True when it has a non-blank `### Action required` subsection; default false |
| `action` | string | Markdown: what the operator must do. Required when `requires_action` is true; at most 16 KiB |
| `format` | number | The data-directory format the release writes; optional, at least 1 |
| `assets` | array | The downloadable files, at most one per platform |
| `image` | string | The container image reference of the release; optional |

An asset:

| Field | Type | Rule |
|---|---|---|
| `platform` | string | `<os>-<arch>` in lower case, such as `linux-x86_64` |
| `name` | string | A plain file name of at most 200 characters, without separators, `..`, control characters or a leading dot |
| `url` | string | An absolute `http` or `https` URL, or a URL relative to the manifest's own URL; at most 2,048 characters |
| `sha256` | string | 64 lowercase hexadecimal digits |
| `size` | number | Bytes; from 1 to 512 MiB |
| `signature` | string | Reserved for signed releases (API-19); not checked yet |

### 6.4 The changelog rule

`CHANGELOG.md` follows Keep a Changelog 1.1.0 with Semantic Versioning, plus one addition:
a subsection `### Action required` under a release lists what an administrator must do
before or after upgrading to it. The other subsections are `### Added`, `### Changed`,
`### Deprecated`, `### Removed`, `### Fixed` and `### Security`. The notes of a release in the
manifest are its changelog section, and the two flags `security` and `requires_action` come
from the two subsections of those names. The grammar is in `scripts/README.md`; a second
parser in Rust (`crates/tenko-api/src/dto/release.rs`) reads the same file at runtime for the
"what's new" notes (section 8.2).

Every change to `crates/**` or `ui/src/**` must come with an entry under `## [Unreleased]`.
The CI job `changelog` runs `node scripts/changelog.mjs check --base <base>` and fails when a
product path changed and the Unreleased section did not. Tests, fixtures and generated
files do not count as product paths. A pull request that changes nothing a user can see
carries the label `no-changelog`, which skips the job; that is the only override. A change
that raises the data-directory format also needs an entry that says so (section 4.2).

### 6.5 Verifying a download by hand

Compare the SHA-256 of a downloaded file with `SHA256SUMS` before installing it. On Linux,
with both files in one directory:

```
sha256sum --check --ignore-missing SHA256SUMS
```

On Windows, in PowerShell:

```
Get-FileHash .\tenko-0.2.0-windows-x86_64.exe -Algorithm SHA256
Select-String tenko-0.2.0-windows-x86_64.exe .\SHA256SUMS
```

The two digests must be equal. A checksum that arrives from the same place as the file
shows that the file is whole and is the one the publisher listed. It does not show that the
publisher is who it claims to be; that is what signing is for (section 6.6).

### 6.6 Signing

Releases are not signed yet. Signing (Sigstore for the binaries and the image, Authenticode
for the Windows binary) and an SBOM arrive with API-19. The manifest field `signature` is
reserved for it. The build feature `release-signatures` already wires the check into the
install job and is off. With the feature on, every install is refused with
`update.signature_unverified` until signing exists, so a release build must not enable it
before API-19 delivers.

## 7 Manual upgrade and rollback

This section is the operator's procedure (OPS-23) for moving one node to a new version by
hand and for going back. It applies to every installation, with or without the layout of
section 9, and to installations that cannot or must not install from the UI. The steps are
the same on every platform:

| Step | What | Why |
|---|---|---|
| 1 | Read the release notes and get the files | An action may be required; the file must be the published one |
| 2 | Stop the server | The files of an open store are not consistent, so they cannot be copied or checked |
| 3 | Back up | The way back if everything else fails |
| 4 | Check with the new binary | Finds a refusal or a failing migration while nothing has changed |
| 5 | Switch to the new binary | The only step that changes what runs |
| 6 | Start | A needed migration runs now |
| 7 | Verify | Version, data format and readiness |

### 7.1 Before you start

- Read the changelog sections of every release between the running version and the target,
  with `### Action required` and `### Security` first. The UI shows the same notes on the
  page `/updates` while a manifest is known. The running version is in the status bar of the
  UI and is printed by `tenko health --live`; `tenko --version` prints the version of the
  executable you run in the shell, which on a layout installation can be the bootstrap
  binary and not the version the service runs (section 9.2).
- A binary migrates from any older format as long as every step exists. When one is
  missing the check says `upgrade.migration_missing`; upgrade through the intermediate
  release it names. The actions of the skipped releases still apply.
- The controller is down from step 2 to step 6. The API and the web UI are unavailable in
  that time. The data-plane roles of later phases keep serving from their local copies
  (OPS-02).
- This procedure is for one node. Cluster upgrades follow OPS-08 (section 8.10).

### 7.2 What to back up

A backup consists of two parts that must be kept in different places, because together they
open the vault.

1. **The data directory**, copied while the server is stopped: `store/` with the format
   marker, `kek/` where it is used, `tls/`, `updates/` and `upgrade-backups/`. A copy of
   the files of a running store is not consistent.
2. **The key-encryption key.** Where it lives depends on the provider:

| Installation | The key | What to keep |
|---|---|---|
| Linux, the shipped unit | `/etc/tenko/kek.cred`, an encrypted credential bound to the host | The offline copy of the key (64 hexadecimal digits) made at install, and `/etc/tenko`. A restore on another host needs `systemd-creds encrypt` run again with the same key. |
| Windows, the default provider | Key files in `<data_dir>\kek`, sealed with DPAPI to the service account | They travel with the data directory but unseal only under the same account on the same machine (`deploy/windows/README.md`). |
| Containers | A Docker secret, `TENKO_KEK__PATH` | The source of the secret. It is not on the data volume. |

A restored data directory without its key cannot open its secrets. Keep the copy of the
key, and the data backup, off the host that is being upgraded.

### 7.3 Linux with systemd

The commands are for the shipped unit, the data directory `/var/lib/tenko` and the
configuration `/etc/tenko/tenko.toml`. Run them as root. The new version is 0.2.0 and the
running one is 0.1.0.

**1. Get the files and verify them.**

```
curl -fLO https://github.com/linkztream/tenko/releases/download/v0.2.0/tenko-0.2.0-linux-x86_64
curl -fLO https://github.com/linkztream/tenko/releases/download/v0.2.0/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
install -m 0755 tenko-0.2.0-linux-x86_64 /usr/local/bin/tenko-0.2.0
```

The staged file `/usr/local/bin/tenko-0.2.0` lies next to the installed binary and replaces
nothing.

**2. Stop.**

```
systemctl stop tenko
```

**3. Back up.** Copy the stopped data directory to another disk, and make sure the offline
copy of the key exists (section 7.2).

```
cp -a /var/lib/tenko /srv/backup/tenko-20261009
cp -a /etc/tenko/tenko.toml /srv/backup/tenko-20261009.toml
```

**4. Check with the new binary.** Run it as the service account, so that nothing it
creates in the data directory belongs to root, and name the data directory: the unit sets
`TENKO_DATA_DIR`, a shell does not.

```
sudo -u tenko /usr/local/bin/tenko-0.2.0 upgrade check \
  --config /etc/tenko/tenko.toml --data-dir /var/lib/tenko
echo "exit status $?"
```

Status 0 and 10 mean go on (section 5.3). Anything else means stop: read the message,
and do not start the new version. Status 11 with `upgrade.format_newer` means that the
directory is newer than this binary; status 1 with `upgrade.in_use` means that a server
still has the store open. Add `--json` for a report that a script can read, and
`--work-dir` when the data volume lacks the free space for a copy of the store.

To keep the downtime short on a large store, start the old version again after step 3, run
the check against the backup copy (`--data-dir /srv/backup/tenko-20261009`, with any
configuration that names the same `node.id`), and then repeat steps 2 and 3 for the switch.

**5. Switch.** On a layout installation (the shipped unit), `tenko upgrade layout` run by
the new binary copies it to `/var/lib/tenko/updates/0.2.0/tenko`, points `previous` at the
version that ran and `current` at the new one:

```
sudo -u tenko /usr/local/bin/tenko-0.2.0 upgrade layout \
  --config /etc/tenko/tenko.toml --data-dir /var/lib/tenko
```

```
switched the layout from 0.1.0 to this binary, 0.2.0
run: /var/lib/tenko/updates/current/tenko
```

The bootstrap binary `/usr/local/bin/tenko` stays as it is, which keeps the rollback a
matter of moving one link (section 7.6). On an installation without the layout (a unit
with `ExecStart=/usr/local/bin/tenko serve`), replace the binary and keep the old one:

```
cp -p /usr/local/bin/tenko /usr/local/bin/tenko-0.1.0
install -m 0755 /usr/local/bin/tenko-0.2.0 /usr/local/bin/tenko
```

**6. Start.**

```
systemctl start tenko
```

**7. Verify.**

```
systemctl status tenko
journalctl -u tenko --since '10 minutes ago' | grep -E 'data format|migrat'
tenko health --live --url https://ddi.example.org:8443 --ca-file /var/lib/tenko/tls/ca-root.pem
tenko health --url https://ddi.example.org:8443 --ca-file /var/lib/tenko/tls/ca-root.pem
```

- The service is active and has not restarted.
- The log has the line `data format 2`, with `(migrated from format 1 in 1 step(s))` when
  a migration ran. A migration also leaves the audit record `sys.upgrade.migrate`.
- `tenko health --live` prints the new version, and `tenko health` reports the node as
  ready. The status bar of the UI shows the version too, and the first sign-in after the
  upgrade shows what is new.

Keep `/srv/backup/tenko-20261009` until the new version has run for as long as you need to
trust it. The staged file `/usr/local/bin/tenko-0.2.0` can be deleted.

### 7.4 Windows service

Run the commands in an elevated PowerShell. The service is `tenko`, the data directory is
`C:\ProgramData\Tenko` and the configuration is `C:\ProgramData\Tenko\tenko.toml`.

**1. Get the files and verify them.** Download `tenko-0.2.0-windows-x86_64.exe` and
`SHA256SUMS` from the release, compare the checksum (section 6.5), and put the file where
the administrators can run it, for example `C:\Program Files\Tenko\tenko-0.2.0.exe`.

**2. Stop.**

```
tenko service stop
```

**3. Back up.** Copy the stopped data directory with its access control lists. `/XJD`
leaves out the junctions `current` and `previous` under `updates`, so that the copy does not
hold the binaries twice. Robocopy exit statuses below 8 mean success.

```
robocopy C:\ProgramData\Tenko D:\Backup\Tenko-20261009 /E /SEC /XJD /R:1 /W:1
```

**4. Check with the new binary.** The data directory is readable for Administrators.

```
& "C:\Program Files\Tenko\tenko-0.2.0.exe" upgrade check --config C:\ProgramData\Tenko\tenko.toml
$LASTEXITCODE
```

Status 0 and 10 mean go on, anything else means stop (section 5.3).

**5. Switch.** The new binary copies itself to `updates\0.2.0\tenko.exe`, points the
junction `previous` at the version that ran and `current` at the new one:

```
& "C:\Program Files\Tenko\tenko-0.2.0.exe" upgrade layout --config C:\ProgramData\Tenko\tenko.toml
```

A service that was installed with `--no-update-layout` runs the executable it was
registered with. Rename that file to keep the old version (`tenko-0.1.0.exe`), and copy the
new one to the registered path.

**6. Start.**

```
tenko service start
```

**7. Verify.**

```
Select-String -Path C:\ProgramData\Tenko\logs\tenko.log -Pattern 'data format'
tenko health --live --url https://ddi.example.org:8443 --ca-file C:\ProgramData\Tenko\tls\ca-root.pem
sc.exe query tenko
```

The log line `data format 2` (with `(migrated from format 1 in 1 step(s))` after a migration),
the version printed by `tenko health --live`, and the service state RUNNING are the
evidence, as on Linux (section 7.3).

### 7.5 Containers

The commands use the container `tenko`, the volume `tenko-data` and the image
`ghcr.io/linkztream/tenko`. Pin the version in the tag (`:0.2.0`), not `:latest`: a pinned
tag makes the rollback exact.

**1. Get the image.**

```
docker pull ghcr.io/linkztream/tenko:0.2.0
```

**2. Stop.** Allow 30 seconds; the default of 10 is too short for the store to close.

```
docker stop --time 30 tenko
```

**3. Back up.** Archive the volume with any image that has `tar`, and make sure the source
of the key secret is safe (section 7.2).

```
docker run --rm -v tenko-data:/data:ro -v "$PWD":/backup alpine:3 \
  tar czf /backup/tenko-data-20261009.tgz -C /data .
```

**4. Check with the new image.** The image sets `TENKO_DATA_DIR`, so the check needs no
option. It runs as the image's user against the volume, and the volume needs free space for
the copy.

```
docker run --rm -v tenko-data:/var/lib/tenko --entrypoint /usr/local/bin/tenko \
  ghcr.io/linkztream/tenko:0.2.0 upgrade check
```

**5. Switch.** Create the container again from the new tag, with the options of the old
one (the published port, the key secret, the `TENKO_*` variables). The volume keeps the
data. With Compose, change the `image:` tag and run `docker compose up -d`.

```
docker rm tenko
docker run -d --name tenko -p 8443:8443 -v tenko-data:/var/lib/tenko \
  --stop-timeout 30 ghcr.io/linkztream/tenko:0.2.0
```

**6. Start.** `docker run -d` starts it. With Compose, `docker compose up -d` did.

**7. Verify.**

```
docker logs tenko 2>&1 | grep -E 'data format|migrat'
docker inspect --format '{{.State.Health.Status}}' tenko
docker exec tenko /usr/local/bin/tenko health --live --url https://localhost:8443 --ca-file /var/lib/tenko/tls/ca-root.pem
```

The log line, the health status `healthy` and the version printed by `tenko health --live`
are the evidence, as on Linux (section 7.3).

### 7.6 Rolling back

Going back means running the previous binary again, and, when the new version changed the
format, giving it the store as it was before. First find out which case this is. Compare
the marker with the format the previous binary writes:

```
head -n 1 /var/lib/tenko/store/format
/var/lib/tenko/updates/0.1.0/tenko upgrade format      # or the saved old binary
```

The marker line is `tenko-data-format N`. The log of the new version has the line
`migrated from format` and the directory `upgrade-backups` holds a copy named
`<UTC time>-format-<from>-to-<to>` when a migration ran.

| Situation | What to do |
|---|---|
| The format is the same | Switch back. The previous version opens the directory as it is. What the new version wrote stays; a field that the previous version does not know is dropped when it rewrites its record. |
| The format was raised | The previous binary refuses the directory (`upgrade.format_newer`, exit status 3). Switch back and restore the store from `upgrade-backups/<name>/store` or from your own backup. Changes made after the upgrade are lost. |
| The new version never became ready and the service manager gave up | Clear the failure state of the service manager first (section 9.7), then as above. |

**Linux.** The layout keeps the previous version in `updates/0.1.0`. Move the link back and,
if the format was raised, put the store back. `ln -sfn` replaces the link. Keep the failed
store for diagnosis.

```
systemctl stop tenko
sudo -u tenko ln -sfn 0.1.0 /var/lib/tenko/updates/current

mv /var/lib/tenko/store /var/lib/tenko/store.failed-20261009
cp -a /var/lib/tenko/upgrade-backups/20261009T201502Z-format-1-to-2/store /var/lib/tenko/store

systemctl start tenko
```

The second block is only for the case where the format was raised. The copy in
`upgrade-backups` was taken at the moment of the migration; the backup of step 3 holds the
same data (`cp -a /srv/backup/tenko-20261009/store /var/lib/tenko/store`). Keep the owner
and the mode of the directory, which `cp -a` does. Without the layout, put the old binary
back instead of moving the link: `install -m 0755 /usr/local/bin/tenko-0.1.0
/usr/local/bin/tenko`.

If you replaced the bootstrap binary `/usr/local/bin/tenko` with the new version, put the
old one back first (`install -m 0755 /var/lib/tenko/updates/0.1.0/tenko
/usr/local/bin/tenko`). Otherwise `ExecStartPre=` finds a bootstrap binary that is newer
than `current` at the next start and moves `current` forward again (section 9.2).

**Windows.** Use `cmd.exe` for the junction: `rmdir` without `/s` removes the junction and
leaves the version directory alone.

```
tenko service stop
cmd /c rmdir C:\ProgramData\Tenko\updates\current
cmd /c mklink /J C:\ProgramData\Tenko\updates\current C:\ProgramData\Tenko\updates\0.1.0

ren C:\ProgramData\Tenko\store store.failed-20261009
robocopy C:\ProgramData\Tenko\upgrade-backups\20261009T201502Z-format-1-to-2\store C:\ProgramData\Tenko\store /E /SEC

tenko service start
```

The second block is only for the case where the format was raised. Without the layout,
copy the renamed old executable back to the registered path.

**Containers.** Run the previous tag. When the format was raised, restore the archive of step
3 into a new volume and mount that one; the failed volume stays for diagnosis.

```
docker stop --time 30 tenko
docker rm tenko

docker volume create tenko-data-restored
docker run --rm -v tenko-data-restored:/data -v "$PWD":/backup alpine:3 \
  tar xzf /backup/tenko-data-20261009.tgz -C /data

docker run -d --name tenko -p 8443:8443 -v tenko-data-restored:/var/lib/tenko \
  --stop-timeout 30 ghcr.io/linkztream/tenko:0.1.0
```

Leave out the volume block when the format was not raised, and mount `tenko-data` again.

After a rollback, verify as in step 7: the log shows the previous version and its `data
format`. Keep the failed store and the output of `tenko upgrade check --json` of the new
binary when you report the failure.

## 8 Updates from the UI

Updates from the UI (OPS-24) are the manual procedure of section 7 done by the server
itself: fetch and verify the file, dry-run the migrations, switch the `current` link, and
restart through the service manager, with an automatic way back. They exist for single-node
installations that run natively from the layout of section 9, and they are governed by the
security toggle TGL-23.

### 8.1 The check

The controller asks the release source a minute after it starts and then every
`updates.check_interval_hours` hours. A check is one HTTPS request for `updates.source_url`
with the headers `Accept: application/json` and `User-Agent: tenko/<version>`. It carries no
cookie, no identifier and no query, so the source learns the running version and the address
the request comes from, and nothing else. The answer is limited to 1 MiB and validated
(section 6.3). A manifest that differs from the stored one is stored in the table
`sys.update_manifest`; the UI hears of it as one event.

The check is off when TGL-23 has the check off, and when `updates.air_gapped` is true.
`POST /api/v1/system/updates/check` (administrators) asks the source at once; it answers
409 `update.check_off` when the check is off. The `[updates]` section of `tenko.toml`
(`deploy/tenko.example.toml`):

| Key | Default | Meaning |
|---|---|---|
| `source_url` | The project's `releases.json` | The manifest. An `https` URL; plain `http` is accepted for a loopback host only, for tests. |
| `air_gapped` | `false` | Never contact the release source: no check, no download (section 8.8) |
| `check_interval_hours` | `24` | Hours between two checks, 1 to 720 |
| `prereleases` | `false` | Offer pre-release versions |
| `ready_timeout_secs` | `180` | Seconds a new version has to become ready, 30 to 3600 (section 8.6) |
| `keep_versions` | `2` | Versions kept in `<data_dir>/updates` besides the ones `current` and `previous` point at, 1 to 10; older ones are removed after a confirmed install |
| `container` | `false` | The server runs in a container (section 8.9); the image sets it |
| `image` | `ghcr.io/linkztream/tenko` | The image the pull command names |

Every key has an environment name: `TENKO_UPDATES__AIR_GAPPED`, `TENKO_UPDATES__SOURCE_URL`
and so on.

### 8.2 The notice and the release notes

When a release newer than the running version is in the stored manifest, administrators see
"update available" in the status bar, on a card on the dashboard, and on the page
`/updates`. The page lists the notes (Markdown) of every release between the running version
and the newest, newest first. A release with security fixes is marked, and a release that
requires an action is marked and shows the text of that action. Pre-releases appear only
when `updates.prereleases` is true.

After an upgrade, a user's first sign-in shows "what's new": the notes of the versions
between the one the user saw last and the one that runs. The notes come from the changelog
compiled into the binary, and from the stored manifest for versions the changelog lacks. The
user's acknowledgement is recorded per user (`POST /api/v1/system/updates/whats-new/seen`).
A user with no recorded version, such as a new account, sees nothing.

### 8.3 TGL-23 per profile

TGL-23 decides whether the check runs and how a new version may be installed
([SECURITY-PROFILES.md](SECURITY-PROFILES.md)).

| Profile | Check | Install |
|---|---|---|
| Home | Daily | From the UI |
| Standard | Daily | From the UI after a fresh sign-in (step-up) |
| Hardened | Daily; the request carries the version string only | Only an uploaded and verified release file, after a fresh sign-in |
| Lab | Daily | From the UI |

Installing needs an administrator of the system in every profile. A step-up means that the
session signed in within the last 5 minutes; the UI asks for a fresh sign-in when it has
not. A personal API token cannot satisfy a step-up, so an install under
Standard or Hardened is done in the UI.

### 8.4 When an install is possible

The update status (`GET /api/v1/system/updates`) says, for an install from the source and
for an upload, whether it would start and why not. A refused install answers 409
`update.install_blocked` with the parameter `reason`.

| Reason | Applies to | Meaning and remedy |
|---|---|---|
| `container` | both | The server runs in a container. Pull the new image (section 8.9). |
| `cluster` | both | The store has more than one voter. Notice only until OPS-08 (section 8.10). |
| `layout_missing` | both | The process does not run from `<data_dir>/updates/current`. Set the layout up (section 9). |
| `unsupervised` | both | No service manager restarts the server after the switch. Run it under systemd or as a Windows service, or declare another supervisor with `TENKO_SUPERVISED=1` (section 9.4). |
| `in_progress` | both | An install is running, or it waits for its restart or its confirmation. |
| `upload_only` | source | TGL-23 allows uploaded files only (Hardened). |
| `air_gapped` | source | `updates.air_gapped` is on. Upload the files (section 8.8). |
| `unsupported_platform` | source | No release of the manifest has a file for this platform. Install by hand (section 7). |
| `no_asset` | source | The newest release has no file for this platform, although earlier ones had. |
| `up_to_date` | source | The running version is the newest one. |

### 8.5 The install job

An install is a job of kind `sys.update`, one at a time, with a limit of 60 minutes. It is
submitted by `POST /api/v1/system/updates/install` with the version, after the TGL-23
checks (an administrator, step-up where required). The job engine records every transition
in the audit log (section 8.7). The steps:

| Step | What it does | Time limit |
|---|---|---|
| `sys.update.fetch` | Downloads the release file for this platform into `<data_dir>/updates/<version>/tenko.part`. The address must have the scheme, host and port of the source (section 8.11), and no more bytes are accepted than the manifest gives. Skipped for an uploaded file. | 30 minutes |
| `sys.update.verify` | Compares the size and the SHA-256 of the file with the manifest (and the signature when the feature `release-signatures` is on), marks it executable, renames it to `tenko` (`tenko.exe`) and writes the manifest entry beside it as `release.json`. A mismatch removes the file. | 5 minutes |
| `sys.update.check` | Runs the new binary and requires `tenko upgrade version` to print the version of the manifest. Then the running server copies its state from one read transaction to `<data_dir>/updates/check-<version>`, and the new binary runs `tenko upgrade check --disposable --json` on the copy. The verdicts `current` and `migration_needed` pass; anything else fails the step with `update.check_refused` and the code and message of the report. The copy is removed. | 12 minutes |
| `sys.update.switch` | Writes the attempt record (state `restarting`), points `previous` at the running version and `current` at the new one. | 1 minute |

A failed step fails the job, and the job engine undoes the earlier steps: the downloaded
file and the version directory are removed, and `current` is pointed back if it had moved.
Until the switch, nothing that the running server uses has changed.

When the job succeeds, the server waits two seconds so that the last event reaches the UI,
and then asks for a restart. It stops gracefully, with open requests finished and the store
closed, and exits with status 12. The service manager starts the binary that `current` now
points at. The new version runs on probation (section 8.6).

### 8.6 Probation and the switch back

Every start of `tenko serve` reads the attempt record `<data_dir>/updates/attempt.json`
before it checks the data format (section 3.2). The new version is ready when the API
listens; the moment it is, the attempt is confirmed.

| Record | This binary | What happens |
|---|---|---|
| `restarting` | The new version, first start | Probation. A watchdog switches back unless the version becomes ready within `updates.ready_timeout_secs` (180 by default). The time a migration of the data directory takes is not counted: the dry run of the install job has shown that it passes, and the start timeout of the service manager still bounds it. |
| `restarting` | The new version, a start step fails | It switches back at once and exits with status 12. |
| `restarting` | The new version, a second start | The first start did not confirm (the process crashed or was killed): it switches back at once. |
| `rolled_back`, with `restore` set | The previous version | It puts the pre-migration copy back before it opens the store (below). |
| `confirmed`, `failed`, `rolled_back` | Any | Nothing. The outcome is audited once. |

A switch back points `current` at the previous version and `previous` at the failed one,
records the state `rolled_back` and the reason, and stops with exit status 12 so that the
service manager starts the previous version. When the watchdog fires, it asks for a graceful
stop and ends the process with status 12 itself if that has not finished within 45 seconds.

If the new version had migrated the store, it took a copy first (section 3.4) and wrote its
path into the attempt record. The record then asks the previous version to restore the
copy: before the previous version opens the store, it replaces `<data_dir>/store` with the
copy. The replaced store is kept as `<data_dir>/store.failed-<unix time>`. Data written by
the new version is lost, but a version that never became ready has no data from users.

The attempt record is JSON:

| Field | Meaning |
|---|---|
| `from`, `to` | The version before and the version installed |
| `state` | `installing` (the install job runs), `restarting` (the switch is done and the restart is under way or on probation), `confirmed`, `rolled_back` or `failed` (the job failed before the switch and nothing changed) |
| `at` | When the record reached this state |
| `job_id` | The install job |
| `reason` | A stable code for `failed` and `rolled_back`: `upgrade.not_ready` (the watchdog fired), `upgrade.not_confirmed` (a second start), or the code of the start step that failed |
| `deadline_secs` | The time the new version has to become ready |
| `starts` | How many times the new version has started |
| `backup` | The pre-migration copy taken by the new version, if any |
| `restore` | The previous version must restore `backup` before it opens the store |
| `reported` | The outcome has been written to the audit log |

An attempt in state `restarting` blocks further installs (`in_progress`) until it settles.
The UI shows the last attempt on the page `/updates`.

The residual risk is a binary that passes the dry run but crashes in the service before it
can read the attempt record, for instance because the sandbox of the service blocks a
system call that the new version makes. It cannot switch itself back. The service manager
restarts it until it gives up:
systemd after five starts within 300 seconds (`StartLimitBurst=5`), the Windows service
after three restarts. The check step starts the new binary twice before the switch, which
makes this unlikely; if it happens, the recovery is a manual switch of the link (section
9.7).

### 8.7 Audit records

Every action of an update is attributable and recorded in the audit log, which is never off
(NEVER-02).

| Action | Written | Context |
|---|---|---|
| `sys.update.manifest` | When an administrator uploads a manifest that is stored | The newest version in it |
| `sys.update.upload` | When an uploaded release file matched the manifest | `version`, `sha256`, the source address |
| `sys.upgrade.migrate` | At start, for each migration step | `from`, `to`, `summary`, `binary` |
| `sys.update.confirm` | Once, by the new version, when the attempt is confirmed | `from`, `to`, `job` |
| `sys.update.rollback` | Once, by the previous version, after a switch back | `from`, `to`, `reason`, `job` |

The install job itself is a job of kind `sys.update` whose transitions are audited with the
principal that started it; its step kinds are the four of section 8.5. A manifest that the
scheduled check fetched is stored without an audit record, because no person acted.

### 8.8 Air-gapped installations

An installation that must not contact the internet sets `updates.air_gapped = true`. The
check is off, nothing is downloaded, and an install from the source is refused with
`air_gapped`. The Hardened profile also takes only uploaded files, whether the installation
is air-gapped or not. To update:

1. On a connected machine, download `releases.json`, `SHA256SUMS` and the release file for
   the platform, and verify the file (section 6.5).
2. In the UI, on the page `/updates`, upload `releases.json`
   (`PUT /api/v1/system/updates/manifest`). It is validated like a fetched manifest and
   audited as `sys.update.manifest`. The page then shows the notes.
3. Upload the release file for the version
   (`POST /api/v1/system/updates/upload?version=<version>`), with a fresh sign-in where
   TGL-23 asks for one. The body streams to disk, bounded by the size the manifest gives, and
   is verified against the manifest exactly as a download is; the upload is audited as
   `sys.update.upload`.
4. The install job runs without the fetch step: verify, check, switch (section 8.5).

The version must be in the stored manifest and newer than the running one, otherwise the
upload is refused with `update.version_unknown` or `update.not_newer`.

### 8.9 Containers

A container is recognised by `updates.container = true`, which the image sets with
`TENKO_UPDATES__CONTAINER=true`, and by the marker files `/.dockerenv` and
`/run/.containerenv`. The UI does not install in a container. It shows the command that
pulls the newest image, for example `docker pull ghcr.io/linkztream/tenko:0.2.0` (the image
name is `updates.image`), and the notes as usual. The image is the unit of deployment, and a
binary swapped inside a container would be lost when the container is created again. Update
a container as in section 7.5.

### 8.10 Clusters

When the store has more than one voter, the UI shows the notice and the notes and installs
nothing (`cluster`). The order in which the nodes of a cluster are upgraded, and the
negotiation between nodes of different versions, come with OPS-08 (section 11). Phase 1 runs
a single voter, so this case does not occur yet. A cluster must not run two versions until
OPS-08 defines how.

### 8.11 Why installing from the UI is acceptable (R17)

A network service that replaces its own binary is a supply-chain path (R17,
`docs/plans/phase-1-execution.md`). The design limits it in these ways:

- **A pinned source.** The manifest comes from `updates.source_url`. A release file is
  downloaded only from an address with the same scheme, host and port as that URL, whatever
  the manifest says; a file elsewhere is refused with `update.source_mismatch`. The download
  follows redirects, because release hosting redirects to its object storage. The manifest
  is bounded to 1 MiB and a file to the size the manifest gives, at most 512 MiB.
- **A checksum now, a signature later.** The size and the SHA-256 are verified before the
  file becomes executable. The checksum comes from the same origin as the file, so it
  shows that the file is whole and is the one listed; it does not protect against a
  compromised origin. Signatures arrive with API-19 (section 6.6). Until then the Hardened
  profile takes only files that an administrator uploaded after checking them through
  another channel.
- **An administrator with a fresh sign-in.** Installing needs the right to administer the
  system, and under Standard and Hardened a step-up. An API token cannot satisfy it.
- **A dry run before the switch.** The new binary must start, report the manifest's
  version, and migrate a copy of the real data.
- **An automatic way back.** A version that does not become ready is switched back, with
  its migration undone (section 8.6).
- **An audit trail.** Section 8.7.

The price is that the service account can write the binaries it runs: the install is done
by the server, so the server must be able to put a new executable in place. Hardened
profiles and administrators who do not want this keep the old layout, where the account
cannot write its own binary, and update by hand as in section 7.

## 9 The layout and the service managers

### 9.1 The layout

Installing from the UI is a switch of a link followed by a restart, so the service manager
must run the binary through a link. The layout under `<data_dir>/updates` is:

```text
<data_dir>/updates/
  0.1.0/tenko            a verified release; one directory per version (tenko.exe on Windows)
  0.2.0/tenko
  0.2.0/release.json     the manifest entry that the file was verified against
  current  -> 0.2.0      the version that the service manager starts
  previous -> 0.1.0      the version that ran before the last switch
  attempt.json           the last install attempt (section 8.6)
```

On Linux the links are symbolic links whose targets are the version names, and a switch is
a rename of a staged link, so `current` is never missing. On Windows they are directory
junctions made with `mklink /J`, which needs no privilege and so can be switched by the
virtual service account; the old junction is removed just before the new one is renamed
into place. Short-lived entries appear while an install runs: `<version>/tenko.part` (a
download in progress), `check-<version>` (the state copy of the dry run) and `current.new`
(a staged link).

A server runs from the layout when its executable lies in the directory that `current`
resolves to. Otherwise the UI shows notices and installs nothing (`layout_missing`).
`current` and `previous` are never removed when old versions are pruned (section 8.1,
`keep_versions`).

`tenko upgrade layout [--config FILE] [--data-dir PATH]` sets the layout up from the binary
that runs it:

| Found | What it does | Output |
|---|---|---|
| This binary already runs from the layout | Nothing | `this binary runs from the layout (...)` |
| No `current` link | Copies the binary to `updates/<version>/` and creates `current` | `created the layout with version 0.1.0` |
| `current` names an older version | Copies the binary in, points `previous` at the old version and `current` at this one | `switched the layout from 0.1.0 to this binary, 0.2.0` |
| `current` names this version or a newer one | Copies the binary in if it is missing and leaves `current` alone | `the layout runs 0.2.0; this binary (0.1.0) is not newer and was kept aside` |

It prints the path to run, `run: <data_dir>/updates/current/tenko`, and exits with status 0;
a failure to write exits with status 1 and an invalid configuration with status 3. It moves
`current` forward only. Going back is a move of the link by hand (section 7.6).

### 9.2 systemd

The shipped unit (`deploy/systemd/tenko.service`) runs from the layout:

```
ExecStartPre=/usr/local/bin/tenko upgrade layout --config /etc/tenko/tenko.toml
ExecStart=/var/lib/tenko/updates/current/tenko serve --config /etc/tenko/tenko.toml
Restart=on-failure
RestartForceExitStatus=12
RestartPreventExitStatus=2 3 4
StartLimitIntervalSec=300
StartLimitBurst=5
```

`ExecStartPre=` runs the bootstrap binary `/usr/local/bin/tenko`, as the service account,
before every start. It creates the layout on the first start and adopts a bootstrap binary
that an administrator, a package or a configuration tool has replaced by a newer one, so
that restarting the unit completes a manual upgrade (section 7.3, step 5). It never moves
`current` back.

Status 12 is a request for a restart (an installed update, a switch back, a changed
module set) and is always restarted. The unit sets `TENKO_SUPERVISED=1`, which tells tenko
that a restart after status 12 happens (section 9.4); tenko does not infer it from the
variables systemd passes to every process (`INVOCATION_ID`, `NOTIFY_SOCKET`), because a
shell or a CI runner inside another service inherits them. The statuses 2, 3 and 4 (usage, invalid configuration
or a newer data format, a failed start step) are not, because the same start would fail
again. At most five starts in 300 seconds are allowed, after which systemd leaves the unit
failed until `systemctl reset-failed tenko`.

`tenko --version` in a shell runs the bootstrap binary. After an update from the UI it can
report an older version than the one that runs. The running version is in the status bar of
the UI, in the start log and in the output of `tenko health --live`.

### 9.3 The Windows service

`tenko service install` sets the layout up unless it is given `--no-update-layout`. It
registers `<data_dir>\updates\current\tenko.exe` as the service executable, copies the
executable that ran the command to `<data_dir>\updates\<version>\tenko.exe`, and creates the
junction `current`. It prints the layout as the line `versions:`. With `--no-update-layout`
it registers the executable itself, as earlier versions did, and installs from the UI stay
off. The service account must be able to write `<data_dir>\updates`; the permissions that
`service install` sets on the data directory give it full control of everything below.

The failure actions of the service restart it after 10 seconds on each of the first three
failures and leave it stopped on the fourth. The count starts over after a day without a
failure. The actions apply to a stop with a non-zero exit status as well as to a crash.
This is how the SCM restarts the server after status 12, and it has two consequences:

- Each restart that the server asks for (an installed update, a module change) counts as a
  failure. A failed update that is switched back takes up to three of them: the switch, the
  failed start of the new version and the switch back. Three restarts therefore keep the
  previous version running after a failed update, but a fourth failure within a day, of
  any kind, leaves the service stopped. Start it with `tenko service start`.
- A new version that crashes before it can read the attempt record uses the restarts up and
  the service stops (section 9.7).

### 9.4 Other supervisors

A server under another supervisor (s6, runit, OpenRC) installs from the UI when it runs from
the layout, is declared with `TENKO_SUPERVISED=1`, and the supervisor does these things:

1. runs `tenko upgrade layout` before the server starts, at least once at install;
2. starts the server through the link, `<data_dir>/updates/current/tenko serve`, resolved at
   each start and not once;
3. starts it again at once when it exits with status 12, whatever its policy for other
   statuses;
4. should not restart it in a loop after status 2, 3 or 4.

A sketch for runit or s6, where the run script is executed again after every exit:

```
#!/bin/sh
export TENKO_SUPERVISED=1
/usr/local/bin/tenko upgrade layout --config /etc/tenko/tenko.toml
exec /var/lib/tenko/updates/current/tenko serve --config /etc/tenko/tenko.toml
```

Without `TENKO_SUPERVISED=1`, and outside the Windows service, the UI shows
`unsupervised`: a server that stopped itself for a switch would stay stopped. The variable
is a promise by the administrator that something restarts the process; the systemd unit of
`deploy/` sets it, and a custom unit must set it too.

### 9.5 Existing installations

An installation made before the layout existed runs the executable it was installed with and
shows notices only. It gets the layout when its unit or service is installed again. The data
is not touched.

On Linux, install the unit of this release and restart. The first start creates the layout
from `/usr/local/bin/tenko`:

```
install -m 0644 deploy/systemd/tenko.service /etc/systemd/system/tenko.service
systemctl daemon-reload
systemctl restart tenko
```

A unit with local changes keeps them in a drop-in (`systemctl edit tenko`). Add the three
lines that matter; the empty `ExecStart=` clears the old command first:

```
[Service]
ExecStartPre=/usr/local/bin/tenko upgrade layout --config /etc/tenko/tenko.toml
ExecStart=
ExecStart=/var/lib/tenko/updates/current/tenko serve --config /etc/tenko/tenko.toml
RestartForceExitStatus=12
```

On Windows, uninstall the service and install it again with the options it had (`--name`,
`--account`, `--manual`). Uninstalling leaves the data directory, its permissions and the
configuration in place:

```
tenko service stop
tenko service uninstall
tenko service install --config C:\ProgramData\Tenko\tenko.toml
tenko service start
```

Run the commands with the new `tenko.exe`: the executable that runs `service install` is the
one copied into the layout.

### 9.6 Disk use

Every installed version is one binary, so the layout is small. After an install is
confirmed, the server removes the oldest version directories until at most
`updates.keep_versions` remain besides the ones `current` and `previous` point at. The
copies in `upgrade-backups` (the newest 3) and the `store.failed-*` directories of a
restore are not pruned by the layout; remove a `store.failed-*` directory when the cause of
a failed upgrade is known.

### 9.7 Recovery when the new version crash-loops

When a new version cannot read the attempt record, it cannot switch back, and the service
manager eventually stops restarting it (section 8.6). The recovery is a move of the link.
The previous version is named by the link `previous` and by `from` in the attempt record.

On Linux, as root:

```
systemctl stop tenko                                    # if it is still restarting
readlink /var/lib/tenko/updates/previous                # the version to go back to, 0.1.0
systemctl reset-failed tenko                            # clears the start limit
sudo -u tenko ln -sfn 0.1.0 /var/lib/tenko/updates/current
rm /var/lib/tenko/updates/attempt.json
systemctl start tenko
```

On Windows, in an elevated prompt:

```
tenko service stop
cmd /c rmdir C:\ProgramData\Tenko\updates\current
cmd /c mklink /J C:\ProgramData\Tenko\updates\current C:\ProgramData\Tenko\updates\0.1.0
del C:\ProgramData\Tenko\updates\attempt.json
tenko service start
```

Two details decide whether this is enough.

- **The attempt record.** An attempt in state `restarting` blocks further installs
  (`in_progress`) for good. Delete the file, as above, or edit `"state"` to `"rolled_back"`
  to keep the record. The previous version ignores a record about another version.
- **The data format.** If the new version had already migrated the store, the previous
  version refuses the directory (`upgrade.format_newer`, exit status 3) and the store must
  be restored as in section 7.6. The record names the copy in its field `backup`. When it does,
  there is a shortcut: set `"state"` to `"rolled_back"` and `"restore"` to `true`, and the
  previous version puts that copy back by itself at its next start, keeping the replaced
  store as `store.failed-<unix time>`.

## 10 Modules

Modules (OPS-25) are the parts of the product that an installation has at all: `ipam`,
`dns`, `dhcp` and `discovery`. They are independent of roles, which say where a part runs
([ARCHITECTURE.md](ARCHITECTURE.md)). The set is decided once, at start, in this order:

| Order | Source |
|---|---|
| 1 | `modules` in `tenko.toml`, or `TENKO_MODULES=ipam,dns`, when set. It pins the set. |
| 2 | The installation's choice, stored by `PUT /api/v1/system/modules`. The first-run wizard asks what the installation is for, and the choice can be changed later. |
| 3 | Every module. |

A disabled module registers no API routes (they answer 404, like any unknown path), shows no
UI area, registers no job steps and starts no task. A change applies at the next start. A
server under a service manager restarts itself at once with exit status 12 (so a module
change uses one of the three restarts of a Windows service, section 9.3). Otherwise
`GET /api/v1/system/status` carries the warning `sys.modules.restart_required` until the
server is restarted. When `tenko.toml` pins the set, `PUT /api/v1/system/modules` answers
409 `modules.pinned`: change the file instead.

Modules and upgrades meet in two places. The module set is not part of the data format, and
migrations run on the whole store whatever modules are enabled, so a module that is switched
off still has its data migrated. In the first slice IPAM is the only module that exists,
with its import and move features; the other names are accepted in the configuration and
reserved.

## 11 Open items

| Item | What is missing | Tracked by |
|---|---|---|
| Signed releases | Signatures for the binaries and the image, Authenticode for the Windows binary, and an SBOM. The manifest field `signature` is reserved and the build feature `release-signatures` is wired into the install job and off. Until it exists the checksum comes from the same origin as the file (section 8.11). | API-19 |
| Cluster upgrades | The rolling order of nodes and the protocol negotiation between nodes of different versions. Until it exists the UI installs nothing on a cluster (section 8.10). | OPS-08 |
| Conversion of redb files | A step that runs offline, before the store is opened, for a release that moves to a redb version with another file format. A `Migration` cannot do it (section 4.7). A release should not move across such a change before the step exists. | |
| A fuzz target for the manifest | `ReleaseManifest::parse` reads input from the network and from uploads and needs a fuzz target under `fuzz/` (CONTRIBUTING rule 3); the fuzz harness has no targets yet. | API-15 |
| Migrations over 16 MiB | The `Migration` trait yields one batch. A migration that exceeds the batch limit needs idempotent batches with the bump in the last (section 4.6). | |
| Free space before the copy | The server does not check that the data volume has room for the copy of the store before it migrates (section 3.4). `tenko upgrade check` has the same need. | |
