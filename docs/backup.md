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
| Offline | `tenko backup create --config tenko.toml` (or `--data-dir`) with the server stopped | Whoever can read the data directory and the KEK | `--out`, else the target directory |

The **target directory** is the `target_dir` of the backup settings when set, else `[backup] target_dir` of the controller's `tenko.toml`, else `backups/` in its data directory. Prefer another disk: a backup next to the data it protects does not survive the loss of that disk.

Online, the controller copies its store state in one read transaction while writes go on, builds a snapshot of the copy in a work directory beside the target, writes the file and removes the work directory. The live store and its followers are not disturbed. Free space of about twice the store's data is needed in the target directory while a backup runs. One backup runs at a time per controller; a second request gets `409 backup.running`.

An online backup is encrypted to the configured recipient and, when the request carries one, to a passphrase as well; with neither it is refused (`422 backup.key.missing`). From the command line:

```sh
tenko backup create --url https://ddi.example.test:8443 --user admin
#   asks for the password (and the TOTP code); --password-stdin reads it from standard input
#   --passphrase-file FILE adds a passphrase slot
```

The command signs in for this request only (a backup needs a fresh sign-in, which a stored API token is not), asks for the backup, and signs out. Accounts that sign in with a passkey only write backups from the web UI.

Offline, with the server stopped:

```sh
tenko backup create --config /etc/tenko/tenko.toml --out /srv/backup/
#   asks for a passphrase twice, unless --recipient tkbr1:… is given (repeatable);
#   --passphrase-file FILE or --passphrase-stdin read it instead
```

The command refuses a store that a running server holds open (`backup.in_use`). The UI offers no download of a backup in Phase 1 (owner decision S3-Q11): copy the files off the controller with the tools of the host.

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

`verify` does everything a restore does, in a temporary directory (`--work-dir`, default the system temporary directory, about twice the size of the backup), and removes it: it opens the slot, checks every chunk and every part hash, installs the snapshot into a fresh store, compares the store digest with the manifest, verifies the whole audit chain, opens every envelope of `vault.secrets` with the key generations of the backup (the values are wiped at once) and compares the CA fingerprint. A backup that passes restores. A changed byte anywhere in the file fails it (`backup.archive.corrupt`, exit status 9).

Check backups regularly on a machine that is not a controller; a restore drill on a spare host (section 6) is the best test.

## 6. Restoring

A restore creates a new data directory; it never writes into a directory that holds a store (`backup.restore.target_not_empty`). Prepare the host as for a new installation: install Tenko, write the `tenko.toml` of this host (its own KEK provider, listen addresses and data directory; the restored copy of the old one in `restored/` helps), and with the `file` provider create its key file. Then:

```sh
tenko backup restore tenko-backup-20261011T080000Z-n1.tkbk --config /etc/tenko/tenko.toml --dry-run
tenko backup restore tenko-backup-20261011T080000Z-n1.tkbk --config /etc/tenko/tenko.toml
#   --key-file FILE or a passphrase as for verify; --data-dir overrides data_dir
```

`--dry-run` checks everything and writes nothing. The restore:

1. opens and checks the backup as `verify` does;
2. creates the store as a single voter under this host's `[node] id` and installs the snapshot into it; the restored store starts a new Raft term, whatever the membership of the source was;
3. compares the store digest, verifies the audit chain and opens every envelope;
4. seals the key generations with this host's KEK provider, keeping their identifiers (the same import a controller does when it joins a cluster);
5. writes the format marker from the data format of the snapshot: a backup of an older format is migrated at the first start like any older data directory, a newer one is refused (`backup.format_newer`);
6. writes the imported TLS files and the configuration of the backup to `<data_dir>/restored/` (mode `0600`) for you to put in place; a configuration is never overwritten;
7. leaves `<data_dir>/restored.json`, the restore notice.

Any failure removes the store the restore created. Then start the server as usual. The first start records the restore (`backup.restore`, audit `sys.backup.restore`), deletes `restored.json` and shows the warning `backup.restored` until the next good backup: take one.

What carries over: every user, password, passkey and TOTP enrolment (sign in as before; passkeys need the same host name, which is in the restored settings), every secret (revealable as before), the audit chain, the internal CA with its key and fingerprint, the node registry and the certificates of enrolled nodes. A probe or another node keeps trusting the controller because the CA is the same; it reconnects without a new enrolment once it reaches the restored controller at the address in its configuration. The controller's own certificate is issued anew by the restored CA. What does not carry over: the key files of the old host, `logs/`, the update layout and the connections that were open.

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
| `POST /api/v1/system/backups` | `create_backup` | Administrators, fresh sign-in | 201 `BackupRunView`; body `{"passphrase": "…"}`, optional |
| `PUT /api/v1/system/backups/settings` | `update_backup_settings` | Administrators, fresh sign-in | 200 `BackupSettingsView` with the new `ETag`; `If-Match` optional |

A personal API token never administers the system and is refused with `403 auth.forbidden`; an older session gets `403 auth.step_up_required` with `required: fresh`. `POST` returns when the file is complete; a backup of a home installation takes seconds, a store of a million records about the time M14 reports (`bench/phase1-backup`). The settings live in the table `backup.settings`, the records in `backup.runs` (the newest 100 are kept) and the restore in `backup.restore`; the event stream reports changes on the topic `system`.

## 10. Audit records

| Action | When | Details |
|---|---|---|
| `sys.backup.create` | Every backup written through the API or the schedule, also a failed one (outcome failed with its error) | `reason`, `node`, `target_dir`, `file`, `revision`, `slots` |
| `sys.backup.settings` | The settings changed | every setting, the recipient included (it is public) |
| `sys.backup.restore` | The first start after a restore | `file`, `revision`, `source_node`, `backup_created_at` |

A backup through the API is the inline job `backup.create` with the step `backup.record`; the job, the record and the audit record commit in one write. Offline backups and the restore itself run without a server, so they are not in the audit log; the first start records the restore.

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
| `backup.io` | 500 | 1 | A file could not be read or written |

## 12. Limits and open items

- A backup and its passphrase or key file together are a copy of every secret of the installation (R36). Keep the key file offline, use a long passphrase, and treat backup files as sensitive even though they are encrypted.
- Restoring needs the host to be stopped and a new data directory; there is no restore into a running installation and no partial restore.
- Parts are not compressed in format 1 (each part's `encoding` is `identity`); a later release may compress them without a format change.
- The server does not check its own backups again after writing them; run `tenko backup verify` on another machine.
- Old controller records stay in the store after a cluster is re-formed from a backup until an administrator removes them.
- Windows was not measured; M14 ran on Linux.
