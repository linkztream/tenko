# Backup and restore

This document describes how Tenko DDI backs up an installation and restores it: what a backup contains and how it is protected, the keys that open it, writing backups from the command line, the API and the schedule, checking a backup, restoring it on a new host or after the loss of a cluster, the status and its warnings, the API, the audit records and the error codes. It is for administrators who run Tenko and for reviewers. Requirements are cited by ID and defined in [REQUIREMENTS.md](REQUIREMENTS.md) (OPS-07); NEVER-01 is defined in [SECURITY-PROFILES.md](SECURITY-PROFILES.md). The decision and the byte layout are in [ADR 0016](adr/0016-backup-and-restore.md), the endpoints in the [OpenAPI document](api/openapi.json). Where this document and the code disagree, the code is right and the document has a defect.

Terms used below: a **backup** is one `.tkbk` file. A **recipient** is the public half of a backup key pair (`tkbr1:` and 43 base64url characters); the **backup key file** holds its private half. A **slot** is one way to open a backup: a passphrase or a recipient. **Restore** means creating a new data directory from a backup.

Contents:

1. [What a backup holds](#1-what-a-backup-holds)
2. [Keys](#2-keys)
3. [Writing backups](#3-writing-backups)
4. [Scheduled backups](#4-scheduled-backups)
5. [Checking a backup](#5-checking-a-backup)
6. [Restoring](#6-restoring)
7. [Clusters](#7-clusters)
8. [Status and warnings](#8-status-and-warnings)
9. [API](#9-api)
10. [Audit records](#10-audit-records)
11. [Error codes](#11-error-codes)
12. [Limits and open items](#12-limits-and-open-items)

## 1. What a backup holds

One file holds everything a new host needs, encrypted as a whole (owner decision S3-Q11):

| Part | Content |
|---|---|
| `store.snapshot` | The whole replicated store at one revision: IPAM, users and passkeys, settings, the audit chain, the vault envelopes, the internal CA and its key, the node registry, jobs |
| `kek.generations` | Every key-encryption key generation the vault needs, the active one last |
| `tls.certificate`, `tls.key` | The imported certificate chain and key of TLS mode b, when the server uses them |
| `config` | The `tenko.toml` the server runs with (scheduled and API backups: when the settings say so, the default; command line: unless `--no-config`) |
| `leases` | Empty; reserved for the DHCP leases of Phase 3, so that the format does not change when they arrive |

A manifest inside the encrypted part names the Tenko version, the data format, the node and the voters of the source, the revision, the audit head, a SHA-256 digest of every store table, the fingerprint of the internal CA and the SHA-256 of every part. The plain header of the file holds only what is needed to open the key: its slots. Nothing about the installation is readable without a slot's secret.

A backup is not a copy of the data directory. It leaves out the Raft log, the snapshots of the store, `logs/`, `updates/`, `upgrade-backups/`, the cluster identity under `node/` (a restored controller gets a new one from the restored CA) and the key files of the host (the restore seals the key generations with the provider of the new host).

There is no unencrypted backup (NEVER-01). Each file is written under a `.part` name, synced and renamed, with mode `0600` on Linux.

## 2. Keys

A backup opens with any one of its slots.

| Slot | Made from | Opens with | Use |
|---|---|---|---|
| `passphrase` | A passphrase of at least 12 characters through Argon2id (64 MiB, 3 passes, the Hardened parameters of the password hashes) | The passphrase | Backups made by hand |
| `recipient` | A recipient (X25519 public key) | The backup key file | Scheduled backups, and backups of a server that should not hold the means to read them |

Create a backup key pair once, on a machine that is not a controller:

```sh
tenko backup keygen --out tenko-backup.key
# prints the recipient, for example tkbr1:0dZq…
```

The key file is created with mode `0600` and is never overwritten. Keep it offline and keep a second copy apart from the first: it opens every backup made for its recipient, and without it (or the passphrase) a backup cannot be opened by anyone, Tenko included. Put the recipient into the backup settings (section 4); the server keeps only the recipient, so a stolen controller cannot read its own backups.

A passphrase is never stored. A wrong passphrase or key fails at the slot, before anything is written.

## 3. Writing backups

| Way | Command or call | Who | Where the file goes |
|---|---|---|---|
| Online, by hand | `POST /api/v1/system/backups`, or `tenko backup create --url …` | Administrators, with a sign-in within the last five minutes | The target directory of the controller that answers |
| Online, scheduled | The leader service `backup.schedule` | The system | The target directory of the leader |
| Online, before an update | "Backup now" in the install dialog (`POST /api/v1/system/backups` with `before_update`), or the first step `sys.update.backup` of an install asked to take one ([upgrades.md](upgrades.md) section 8.12) | The administrator who installs; the dialog needs a sign-in within the last five minutes | The target directory of the controller that answers |
| Offline | `tenko backup create --config tenko.toml` (or `--data-dir`) with the server stopped | The account that owns the data directory (`tenko` on a node installed by `deploy/install.sh`), which reads the store and the KEK | `--out`, else the target directory |

The **target directory** is the `target_dir` of the backup settings when set, else `[backup] target_dir` of the controller's `tenko.toml`, else `backups/` in its data directory. Prefer another disk: a backup next to the data it protects does not survive the loss of that disk.

Online, the controller copies its store state in one read transaction while writes go on, builds a snapshot of the copy in a work directory beside the target, writes the file and removes the work directory. The live store and its followers are not disturbed. Free space of about twice the store's data is needed in the target directory while a backup runs. One backup runs at a time per controller; a second request gets `409 backup.running`.

An online backup is encrypted to the configured recipient and, when the request carries one, to a passphrase as well; with neither it is refused (`422 backup.key.missing`). From the command line:

```sh
tenko backup create --url https://ddi.example.test:8443 --user admin
#   asks for the password (and the TOTP code); --password-stdin reads it from standard input
#   --passphrase-file FILE adds a passphrase slot
```

The command signs in for this request only (a backup needs a fresh sign-in, which a stored API token is not), asks for the backup, and signs out. Accounts that sign in with a passkey only write backups from the web UI.

Offline, with the server stopped, as the account that owns the data directory:

```sh
runuser -u tenko -- tenko backup create --config /etc/tenko/tenko.toml --out /srv/backup/
#   asks for a passphrase twice, unless --recipient tkbr1:… is given (repeatable);
#   --passphrase-file FILE or --passphrase-stdin read it instead
```

The command refuses a store that a running server holds open (`backup.in_use`), and prints the archive id and the SHA-256 of the file it wrote, which identify the file beyond its name (section 5). The UI offers no download of a backup in Phase 1 (owner decision S3-Q11): copy the files off the controller with the tools of the host.

**Who runs the offline commands.** `backup create` of a stopped node, `backup verify`, `backup restore`, `kek rotate`, `user unlock`, `upgrade check` and `upgrade layout` open the store or write under the data directory, and so do `tenko serve`, the node's own commands (`node enroll`, `node status`, `node renew`, `node scan`), `cluster join`, `setup token` and `plugin list`; `plugin test` executes the plugin it is given. They run as the account that owns these files ([ADR 0023](adr/0023-no-root-after-installation.md), I2): on a node installed by `deploy/install.sh` that is `tenko`, through `runuser -u tenko -- tenko …`, on Windows the service's virtual account through the service itself, whose token keeps `SeChangeNotifyPrivilege` alone and is therefore not privileged although the Service Control Manager gives it a high or system integrity label. Run as root (on Linux also as a process that holds a capability reaching other accounts' files, such as `CAP_DAC_OVERRIDE`, or whose `/proc/self/status` cannot be read; on Windows: as `SYSTEM`, from an elevated prompt of an administrator, or with a token that holds a privilege reaching beyond its account, such as `SeImpersonatePrivilege` or `SeBackupPrivilege`; a token that cannot be read, also when `whoami.exe` does not answer within 30 seconds, counts as privileged and the line says so) while this binary's file, the data directory, the directory the command writes into the plugin it executes or the backup it verifies belongs to another account or has an owner that cannot be read (a path that does not exist yet is judged by the nearest one that does), the command does not start: it exits with status 2 and prints one line with the code `exec.unsafe_owner`, the file and its owner, and the same command in the form that runs it as that account. On Windows the access list decides as well: a directory that Administrators own but whose list lets another account write it, as `service install` sets up the data directory for the service account, refuses every one of these commands but `setup token`, which only reads the token. An installed Windows node therefore has no way yet to run `backup restore`, `backup create` of a stopped node, `kek rotate`, `user unlock`, `upgrade check`, `upgrade layout`, the node commands or `cluster join` by hand over its data directory. There is no override and no profile setting; every other command (the API clients, `config`, `service`, `backup keygen`, an online `backup create`, `upgrade format`) writes and executes nothing of the account's, and for it only this binary's own file is checked, on Linux only ([ADR 0023](adr/0023-no-root-after-installation.md), implementation state); and `service run` is started by the Service Control Manager as the service's own account only. The `--out` directory of an offline backup and the `--work-dir` of a check are checked the same way. A data directory that root owns itself, as in a container that runs as root, passes.

A **backup before an update** is the restore point of that update (ADR 0023). It is an ordinary online backup with the reason `before_update` and the version the update is about to install, listed as "Before update 0.2.0" on the Backup page and in `GET /api/v1/system/backups` (`reason: before_update`, `before_update: "0.2.0"`); the archive's origin says `before_update`. The record is stored as a manual backup with the version beside it, so a previous release still reads it after a switch back. It does not count as a scheduled backup for the schedule. The step of an install job can take one only with a recipient, since a job never carries a passphrase; the install dialog asks for a passphrase when there is no recipient and writes the backup itself.

## 4. Scheduled backups

The backup settings are replicated and the same on every controller; they change through the API (`PUT /api/v1/system/backups/settings`) or the UI, with a fresh sign-in, and every change is audited.

| Setting | Default | Range | Meaning |
|---|---|---|---|
| `enabled` | off | | Scheduled backups run (off by default, S3-Q11) |
| `interval_hours` | 24 | 1 to 168 | Hours between scheduled backups |
| `keep` | 7 | 1 to 365 | Backup files the schedule keeps in its target directory |
| `target_dir` | none | an absolute path | The target directory on every controller; none: each controller's own default |
| `recipient` | none | `tkbr1:…` | The recipient every backup is encrypted to; needed to turn the schedule on |
| `include_config` | on | | Backups include the controller's `tenko.toml` |

The schedule is the leader service `backup.schedule` (it shows in `/system/status` under `leader.services`): the leader looks at the settings every minute and writes a backup when `interval_hours` have passed since the last good scheduled one, at once when there has never been one. A failed scheduled backup is tried again after an hour. After a good one, the oldest files named `tenko-backup-*.tkbk` beyond `keep` are deleted from the target directory; other files there are never touched. The record of a scheduled backup is written with the leader epoch as a precondition, so a controller that lost leadership while it wrote a backup cannot record it; that file is deleted.

## 5. Checking a backup

```sh
tenko backup verify tenko-backup-20261011T080000Z-n1.tkbk --key-file tenko-backup.key
#   or --passphrase-file FILE, --passphrase-stdin, or a prompt; --json for a report
```

`verify` does everything a restore does, in a scratch directory of its own (mode `0700`, created under `--work-dir`, default the system temporary directory, about twice the size of the backup) and removes it on every way out: it opens the slot, checks every chunk and every part hash, installs the snapshot into a fresh store, compares the store digest with the manifest, verifies the whole audit chain, opens every envelope of `vault.secrets` with the key generations of the backup (the values are wiped at once) and compares the CA fingerprint. A backup that passes restores. A changed byte anywhere in the file fails it (`backup.archive.corrupt`, exit status 9). The manifest bounds what the reader takes from a file: a part that declares more than its limit (64 KiB for the key generations, 1 MiB for the TLS files and the configuration, 64 GiB for the snapshot), a part name or a version with a control character, or a snapshot whose records expand to more than 64 times the size of its file (at least 1 GiB, at most 64 GiB) is refused as corrupt before anything is written.

The report names the **archive id** (the random identifier in the file's header) and the **SHA-256 of the file**. The node that wrote the backup recorded both in its `sys.backup.create` audit record (section 10), which the audit export delivers to an external sink ([audit-export.md](audit-export.md)). Before a restore from a node that may have been compromised, compare the two values with that record at the sink: a backup is encrypted, but the archive carries no proof of where it came from, and a node that was taken over could have written one. Text that comes out of an archive (part names, the version, key generation identifiers) is printed with control characters replaced, one line per item.

Check backups regularly on a machine that is not a controller; a restore drill on a spare host (section 6) is the best test. `verify` runs without a server and leaves no audit record; the comparison above is the operator's.

## 6. Restoring

A restore creates a new data directory; it never writes into a directory that holds a store (`backup.restore.target_not_empty`). Prepare the host as for a new installation: install Tenko, write the `tenko.toml` of this host (its own KEK provider, listen addresses and data directory; the restored copy of the old one in `restored/` helps), and with the `file` provider create its key file. The restore runs as the account that owns the data directory (section 3, "Who runs the offline commands"): on a node installed by `deploy/install.sh`, stop the unit and run it as `tenko`; the backup file must be readable by that account. Then:

```sh
systemctl stop tenko
runuser -u tenko -- tenko backup restore tenko-backup-20261011T080000Z-n1.tkbk --config /etc/tenko/tenko.toml --dry-run
runuser -u tenko -- tenko backup restore tenko-backup-20261011T080000Z-n1.tkbk --config /etc/tenko/tenko.toml
#   --key-file FILE or a passphrase as for verify; --data-dir overrides data_dir
```

Run as root while the data directory belongs to `tenko`, the command prints the `runuser` form and exits with status 2 (`exec.unsafe_owner`); nothing is written. Compare the archive id and the SHA-256 the dry run prints with the `sys.backup.create` record of the node that wrote the backup first (section 5).

`--dry-run` checks everything and writes nothing. The restore:

1. opens and checks the backup as `verify` does;
2. creates the store as a single voter under this host's `[node] id` and installs the snapshot into it; the restored store starts a new Raft term, whatever the membership of the source was;
3. compares the store digest, verifies the audit chain and opens every envelope;
4. seals the key generations with this host's KEK provider, keeping their identifiers (the same import a controller does when it joins a cluster);
5. writes the restore notice into the restored store (the row `backup.restore_pending`, after the digest was compared), then writes the format marker from the data format of the snapshot: a backup of an older format is migrated at the first start like any older data directory, a newer one is refused (`backup.format_newer`);
6. writes the imported TLS files and the configuration of the backup to `<data_dir>/restored/` (mode `0600`) for you to put in place; a configuration is never overwritten;
7. leaves `<data_dir>/restored.json`, the restore notice, with the archive id and the SHA-256 of the backup.

Everything the restore creates under the data directory it creates itself: directories in one step with mode `0700`, files as new files with mode `0600`, and a path that already exists as a symbolic link (`store`, `restored`, `restored.json`, the work directory) is refused with `backup.io` and the restore stops before it writes through it. The data directory itself may be the path the configuration names, a link an administrator made included; when it does not exist, the restore creates it with mode `0700`.

A data directory that still holds `restored.json` or a file under `restored/` from an earlier restore is refused before anything is written (`backup.io`, naming the file): move it away, then restore again. Any later failure removes the store the restore created and the files it wrote under `restored/`. Then start the server as usual. The first start records the restore (`backup.restore`, audit `sys.backup.restore` with the archive id and the SHA-256), deletes `restored.json` and the row in the store, and shows the warning `backup.restored` until the next good backup: take one. The notice is in two places so that the first start records the restore even when the file is gone: the audit record's `notice` says `file` (both found), `missing` (the row alone: the file was removed before the first start, which the log warns about) or `file_only` (a restore by a build before the row existed). A notice file that stays after the restore was recorded, because its removal failed, is recognized at the next start as the same restore and is not recorded again.

What carries over: every user, password, passkey and TOTP enrollment (sign in as before; passkeys need the same host name, which is in the restored settings), every secret (revealable as before), the audit chain, the internal CA with its key and fingerprint, the node registry and the certificates of enrolled nodes, and each person's saved table layouts (`auth.preferences`; a backup written before that table existed restores with it empty, so the tables show their default layouts). A probe or another node keeps trusting the controller because the CA is the same; it reconnects without a new enrollment once it reaches the restored controller at the address in its configuration. The controller's own certificate is issued anew by the restored CA. What does not carry over: the key files of the old host, `logs/`, the update layout and the connections that were open.

When the restored host has another `[node] id` than the source, the report says so; the controller records of the old id stay until an administrator removes them.

## 7. Clusters

A backup of any controller of a cluster restores to a single controller (decision S3-Q11): the restored store has one voter, this host, so it starts and takes writes on its own. The other controllers then join it with empty data directories, as when a cluster grows ([cluster.md](cluster.md), section 12): stop the old members, move their data directories aside, and run `tenko cluster join` against the restored controller. They receive the key generations through the sealed transfer. Never start an old member with its old data directory against the restored cluster: it belongs to the old Raft history.

The scheduled backups of a cluster are written by the leader, into its target directory; after a failover the new leader writes them into its own. Setting `target_dir` to a share mounted at the same path on every controller keeps them together.

## 8. Status and warnings

`GET /api/v1/system/backups` shows the settings, the newest good backup of any controller and its age, the newest failed one when it is newer, the next scheduled time, whether a backup runs on the answering controller, the 20 newest records, the restore notice and the warnings. `GET /api/v1/system/status` carries a short `backup` fragment (whether the schedule is on, the time and age of the last good backup, the last failure, the restore) and the same warnings:

| Warning | When |
|---|---|
| `backup.stale` | Standard and Hardened profiles: no good backup for more than 7 days, counted from the end of first-run setup when there never was one |
| `backup.failed` | The newest backup failed (its error code is a parameter) |
| `backup.restored` | The installation was started from a restore and no good backup has been made since |

## 9. API

| Endpoint | Operation | Who | Answer |
|---|---|---|---|
| `GET /api/v1/system/backups` | `get_backups` | `Read` on the system (viewers and up) | 200 `BackupStatusView` with `ETag` of the settings |
| `POST /api/v1/system/backups` | `create_backup` | Administrators, fresh sign-in | 201 `BackupRunView`; body `{"passphrase": "…", "before_update": "0.2.0"}`, both optional (`before_update` must be a version) |
| `PUT /api/v1/system/backups/settings` | `update_backup_settings` | Administrators, fresh sign-in | 200 `BackupSettingsView` with the new `ETag`; `If-Match` optional |

A personal API token never administers the system and is refused with `403 auth.forbidden`; an older session gets `403 auth.step_up_required` with `required: fresh`. `POST` returns when the file is complete; a backup of a home installation takes seconds, a store of a million records about the time M14 reports (`bench/phase1-backup`). The settings live in the table `backup.settings`, the records in `backup.runs` (the newest 100 are kept) and the restore in `backup.restore`; the event stream reports changes on the topic `system`.

## 10. Audit records

| Action | When | Details |
|---|---|---|
| `sys.backup.create` | Every backup written through the API or the schedule, also a failed one (outcome failed with its error) | `reason` (`manual`, `scheduled` or `before_update`), `before_update` (the version), `node`, `target_dir`, `file`, `revision`, `slots`; for a written file `archive_id` (the identifier in its header, hex) and `sha256` (of the whole file, hex), what `tenko backup verify` prints |
| `sys.backup.prune` | The schedule deleted backup files beyond `keep` | `node`, `target_dir`, `keep`, `removed` (the count), `files` (the names, comma separated) |
| `sys.backup.settings` | The settings changed | every setting, the recipient included (it is public) |
| `sys.backup.restore` | The first start after a restore | `file`, `archive_id`, `sha256`, `revision`, `source_node`, `backup_created_at`, `restored_at`, `notice` (`file`, `missing` or `file_only`, section 6) |

A backup through the API is the inline job `backup.create` with the step `backup.record`; the job, the record and the audit record commit in one write. The record of the deleted files is fenced by the leader epoch like the record of a scheduled backup. Offline backups, `verify` and the restore itself run without a server, so they write no audit record when they run; the restore leaves its notice in the data directory and in the restored store, and the first start records it, also when the file is gone (NEVER-02).

## 11. Error codes

| Code | HTTP | Exit status | Meaning |
|---|---|---|---|
| `backup.archive.not_a_backup` | 422 | 2 | The file is not a Tenko backup |
| `backup.archive.unsupported` | 422 | 2 | Another major format of the container or the manifest |
| `backup.archive.corrupt` | 422 | 9 | A changed, truncated or extended file, or a part that does not match its hash |
| `backup.key.refused` | 422 | 6 | The passphrase or key file does not open the backup |
| `backup.key.missing` | 422 | 2 | No recipient and no passphrase; or the schedule turned on without a recipient |
| `backup.key.invalid` | 422 | 2 | A recipient or key file that does not parse; the `file` KEK provider of the target has no key file |
| `backup.passphrase.weak` | 422 | 2 | A passphrase shorter than 12 characters (parameter `min`) |
| `backup.settings.invalid` | 422 | | A setting out of range, or a relative target directory |
| `backup.running` | 409 | | A backup runs on this controller |
| `backup.in_use` | 409 | 2 | Offline backup of a store a running server holds |
| `backup.restore.target_not_empty` | 409 | 2 | The data directory holds a store |
| `backup.format_newer` | 422 | 11 | The backup holds a data format newer than this build |
| `backup.digest_mismatch` | 422 | 9 | The installed store differs from the state the backup recorded |
| `backup.check_failed` | 422 | 9 | The audit chain, an envelope, the CA or the data format did not check (parameter `check`) |
| `backup.io` | 500 | 1 | A file could not be read or written; a restore met a symbolic link where it creates a directory or a file |
| `exec.unsafe_owner` | | 2 | An offline command run as root (Windows: `SYSTEM`, elevated, or a token holding a privilege beyond its account) while this binary, the data directory or the directory it writes into belongs to another account (section 3); the line names the command to run as that account |

## 12. Limits and open items

- A backup and its passphrase or key file together are a copy of every secret of the installation (R36). Keep the key file offline, use a long passphrase, and treat backup files as sensitive even though they are encrypted.
- Restoring needs the host to be stopped and a new data directory; there is no restore into a running installation and no partial restore.
- Parts are not compressed in format 1 (each part's `encoding` is `identity`); a later release may compress them without a format change.
- The server does not check its own backups again after writing them; run `tenko backup verify` on another machine.
- An archive carries no proof of origin: a recipient slot proves who can read it, not who wrote it. The archive id and the SHA-256 in the `sys.backup.create` record at the external audit sink are what an operator compares before a restore (section 5). A signature by the node, verified at restore, is a later package.
- `tenko backup verify` writes no audit record; it runs where there is no store to write it into.
- Old controller records stay in the store after a cluster is re-formed from a backup until an administrator removes them.
- Windows was not measured; M14 ran on Linux.
