# No-root plan: the node owns its binary

- Status: Accepted by the owner on 2026-10-24, with the decisions of section 6 (NR-Q1 to NR-Q4). The plan changes only through rule 2.8 of the execution plan.
- Date: 2026-10-24
- Scope: [ADR 0023](../adr/0023-no-root-after-installation.md), "No root after the first installation": the owner's principle of 2026-10-24 that root is never needed after the installation, the removal of the bootstrap binary `/usr/local/bin/tenko`, the backup before every update as the restore point, rollback and the restore of that backup as audited actions of the service, the node's CLI path for the group `tenko-cli`, the client on the administrator's machine, and the Windows service under the same invariants. Written against `main` at `354adeb`. Requirement IDs refer to [REQUIREMENTS.md](../REQUIREMENTS.md) (OPS-07, OPS-23, OPS-24, API-19), toggles to [SECURITY-PROFILES.md](../SECURITY-PROFILES.md) (TGL-21, TGL-23), the update model to [upgrades.md](../upgrades.md), backups to [backup.md](../backup.md) and [ADR 0016](../adr/0016-backup-and-restore.md).

The invariants I1 to I10, the threat model and the trust table are in the ADR and are not repeated here; every package names the invariants its acceptance proves. Sizes: S up to one builder-week, M one to three.

Contents:

1. [Goal and exit](#1-goal-and-exit)
2. [Starting point in the code](#2-starting-point-in-the-code)
3. [Work packages](#3-work-packages)
4. [Order, parallelism and merging](#4-order-parallelism-and-merging)
5. [Migration of existing nodes](#5-migration-of-existing-nodes)
6. [Owner decisions](#6-owner-decisions)
7. [Risks](#7-risks)
8. [Documents that change](#8-documents-that-change)

## 1. Goal and exit

### 1.1 Goal

After the installer exits, the node is operated, updated, rolled back, restored to the backup taken before an update, and recovered without root. The binary that runs is the only Tenko binary in the layout; the previous version waits in the rollback directory for one rollback; members of `tenko-cli` run it through the node's CLI path, root never does; `tenko` on an administrator's workstation is the client. A compromised service account gains nothing beyond its own radius.

### 1.2 Exit checks

| # | Check | Invariants | Package |
|---|---|---|---|
| NR-E1 | The shipped unit and every drop-in the installer writes contain no path under `/usr/local/bin`, no `ExecStart*=` or `ExecStop*=` line with a `+` or `!` prefix, and no file capability; the capabilities and address families are exactly those of the roles given to the installer; `install-sh-test.sh --unit` proves it from the unit text and the installer's embedded copy | I1, I5, I7 | NR3 |
| NR-E2 | The installer writes, deletes or changes the owner of nothing inside the data or log directory as root: a static check of `install.sh` in `--unit` (every command naming `$DATA_DIR` or `$LOG_DIR` is either a read, a creation of a missing directory, or runs through `as_tenko`), and in the systemd container run an `auditd` or `fanotify` trace of the installer shows no root write below the data directory | I2 | NR3 |
| NR-E3 | The lab round (NR7): after the installer exits, every step (update from the UI with its backup, rollback from the UI, rollback with the restore after a migration, the automatic switch back, the guard's switch back, a role change without new privileges, a restart, a backup, the CLI as a member of `tenko-cli`) runs with `id -u` not 0 for every Tenko process, and an audit rule on `execve` of any file below `/var/lib/tenko` with `euid=0` records nothing for the whole round | I1, I3, I10 | NR7 |
| NR-E4 | A version killed with SIGKILL before it confirms, three starts in a row, is switched back by the guard before systemd's start limit, with `sys.update.rollback` reason `upgrade.not_started` audited | I3, I9 | NR1, NR7 |
| NR-E5 | The update asks for a backup (default yes) in the UI, the client and the API; the install starts only after the backup's record is good; a failed backup fails the job before anything changed; Hardened refuses `backup: false` with `backup_required`; the restore point survives the schedule's pruning until a newer one replaces it | I3, I9 | NR2 |
| NR-E6 | Rollback from the UI and the API: same format succeeds as a switch; a raised format is refused with `restore_required` (or `no_restore_point`) and succeeds with the restore of the restore point after the second confirmation and a fresh sign-in; every refusal reason has a test; the audit records carry the principal; the dropped audit range is recorded | I3, I9 | NR2 |
| NR-E7 | The restore of the restore point runs as the service account from staging to swap: no step needs root, a failure at any staging step leaves the store as it was, the replaced store is kept and removable through the API, and it works under the `systemd_credential` and `file` providers on Linux and DPAPI on Windows | I2, I3, I9 | NR8 |
| NR-E8 | The layout holds exactly two versions after a confirmed install, a rollback and a switch back, with the modes and the group of the ADR's item 2 | I5, I6 | NR1 |
| NR-E9 | The layout's binary run as uid 0 while its file is not owned by root exits 2 with `exec.unsafe_owner` before it does anything else; run by a member of `tenko-cli` through `/opt/tenko/cli/tenko` it works; run by any other user it cannot be executed (mode 0750); `/opt/tenko/cli` is on no `PATH` of root after `su -`, `sudo -i` and a root login | I1, I10 | NR1, NR3 |
| NR-E10 | A node installed with the installer of the release before this plan (bootstrap binary, updated from the UI) is migrated by one run of the new installer as root; afterwards `/usr/local/bin/tenko` is gone, `current` and `previous` are intact, the CLI path and the group exist, and NR-E3 holds | I1 to I10 | NR3, NR7 |
| NR-E11 | Windows: the MSI's custom actions run no binary from the data directory and write nothing into it; an MSI upgrade is adopted by the service as `NT SERVICE\tenko` with its backup; `service install` refuses `LocalSystem`, `LocalService` and `NetworkService` with the layout; the layout's binary refuses an elevated token; a rollback with a restore from the UI works on the Windows smoke host | I1, I2, I5, I10 | NR4 |
| NR-E12 | The client installs and updates itself without root on Linux and Windows, refuses to update a file in a layout or one owned by another user, and warns on a version drift from the server | I5 | NR5 |
| NR-E13 | `docs/upgrades.md`, `docs/backup.md`, `docs/QUICKSTART.md`, `deploy/README.md`, the unit's header, the installer's help and summary, and `deploy/windows/README.md` contain no step after the installation that needs root, except the host reconfigurations of I4 | I3, I4 | NR6 |

## 2. Starting point in the code

| Area | Where | Today |
|---|---|---|
| Layout and links | `crates/tenko/src/upgrade/layout.rs` | `current`, `previous`, version directories, `tenko upgrade layout`, symbolic links and junctions |
| Install job | `crates/tenko/src/upgrade/updates.rs`, `steps.rs`, `source.rs` | fetch, verify, check, switch; pinned origin; feature `release-signatures` off |
| Probation and switch back | `crates/tenko/src/upgrade/probation.rs`, `restart.rs` | attempt record, watchdog, exit 12 |
| Backup and restore | `crates/tenko/src/backup/`, `docs/backup.md` | online backups (`backup.create` job), schedule with pruning, `verify`, and a restore that needs a stopped server and a data directory without a store (`backup.restore.target_not_empty`) |
| Routes | `crates/tenko-api/src/routes/system/updates.rs`, the backup routes | status, check, manifest, install, upload, what's new; no rollback |
| UI | `ui/src/updates/` | the `/updates` page, install and upload panels, restart follow (`restart.ts`) |
| Client | `crates/tenko/src/client/` | no update commands |
| Windows | `crates/tenko/src/platform/windows.rs`, `deploy/windows/wix/Package.wxs` | service install with the layout, `icacls` on the data directory, MSI actions as SYSTEM running `upgrade check` and `upgrade layout` |
| Installer | `deploy/install.sh` | `/usr/local/bin/tenko` (root), `as_tenko` for the layout, upgrade by rerun, `probe.conf` with the probe role |
| Unit | `deploy/systemd/tenko.service`, `probe.conf`, `dhcp-direct.conf` | the bootstrap `ExecStartPre=`, `StateDirectoryMode=0700`, the hardening listed in the ADR's threat model |
| Tests | `crates/tenko/tests/upgrade_install.rs`, `acceptance_deployment.rs`, `acceptance_backup.rs`, `deploy/proxmox/test/install-sh-test.sh` (`--unit`, the Docker runs, `--systemd`), `deploy/systemd/smoke.sh`, `deploy/windows/smoke.ps1`, `msi-smoke.ps1` | the update through the layout, the restart after 12, backup and restore |

## 3. Work packages

### NR0 Contracts and shared files (S)

The lead's package; everything else starts from it.

- **Deliverables.** The configuration key `updates.install` (default `true`) and the deprecation of `updates.keep_versions` (accepted, warned by `tenko config check`, ignored); the attempt record's new fields `kind` (`install` or `rollback`), `guard_starts` and `restore_point` (archive id, file, SHA-256, time), read by older binaries as unknown fields; the new fields of `restored.json` (the rollback's principal and job, the replaced audit head, the dropped audit range); the install request's `backup` and `passphrase` fields and the rollback request's `restore`; the error codes `update.rollback_blocked` with its reasons (`restore_required`, `no_restore_point`, `no_previous`, `cluster`, `container`, `layout_missing`, `unsupervised`, `in_progress`, `rollback_off`), the new `update.install_blocked` reason `backup_required`, `upgrade.not_started`, `exec.unsafe_owner`, `backup.restore.provider` and `service.account_shared`; the DTOs of `POST /system/updates/rollback`, `DELETE /system/updates/replaced-stores/{name}` and the rollback and restore-point fields of `GET /system/updates` (`utoipa::ToSchema`); the response header `Tenko-Version`; the subcommand stubs `tenko upgrade guard`, `tenko self-update` and `tenko system update rollback` registered in `main.rs` so that NR1, NR2 and NR5 do not touch the same lines.
- **Files.** `crates/tenko/src/config.rs`, `crates/tenko/src/upgrade/mod.rs` (the record type), `crates/tenko/src/backup/` (the `restored.json` type only), `crates/tenko/src/main.rs`, `crates/tenko-api/src/dto/` (update DTOs), the error catalogue, `deploy/tenko.example.toml`, `docs/api/openapi.json` (generated), `CHANGELOG.md`.
- **Tests.** Configuration parsing and the warning; serde round trips of the attempt record and of `restored.json` with and without the new fields, including files written by today's binary; the OpenAPI generation test.

### NR1 Layout, guard, probation and the uid-0 refusal (M)

- **Deliverables.** The two-version prune after every confirmed install, rollback and switch back (I6); the modes and the group of the ADR's item 2 on everything the service writes into `updates/` (0750 and `tenko-cli` on version directories and binaries, explicitly, since the unit's `UMask=0077` would make them 0700), and `upgrade layout --fix-modes` for the migration; the attempt record read before anything else in `main`; `tenko upgrade guard` (counts starts while the record is `restarting`, switches back at the third, exits 0 outside an attempt); the uid-0 refusal before anything else in `main`: as uid 0 refuse with `exec.unsafe_owner` when the executable's own file is not owned by root, naming the two safe ways (an account in `tenko-cli` on the node, the client on the administrator's machine), with no override in any profile; on Windows, under SYSTEM or an elevated token, refuse when the file's owner is not Administrators or SYSTEM; the start log names the uid and the SHA-256 of the executable.
- **Files.** `crates/tenko/src/upgrade/layout.rs`, `probation.rs`, `restart.rs`, a new `crates/tenko/src/upgrade/guard.rs`, a new `crates/tenko/src/platform/exec_check.rs` (Linux owner check; Windows owner and token elevation), the `main` entry in `crates/tenko/src/main.rs` (only the two calls NR0 left for it).
- **Tests.** Unit: prune with three, two and one version present and with dangling links; the modes and group after an install (with a test group when the build host has no `tenko-cli`); the guard's state machine (no record, `confirmed`, `restarting` with 0 to 3 starts, a record of another version, a missing `previous`); the owner check against temporary files owned by root and by another uid, run as root in the container job and skipped elsewhere, and its pure decision function for every combination; Windows behind `cfg(windows)`. Integration: `crates/tenko/tests/upgrade_install.rs` gains the kill-before-confirm loop that the guard ends.
- **Invariants.** I1, I3, I5, I6, I10.

### NR2 Backup prompt, rollback in the API, the UI and the client (M)

- **Deliverables.** The install job's first step `sys.update.backup`: an online backup ([ADR 0016](../adr/0016-backup-and-restore.md) item 5) to the recipient and the request's passphrase, the install continuing only after its record is good, the record marked as the attempt's restore point and protected from the schedule's pruning until a newer confirmed install has one; the backup question in the install dialog (default yes; under Hardened shown as required), in the client (`--no-backup`, and a passphrase prompt when no recipient is set) and in the API; `POST /api/v1/system/updates/rollback` as a `sys.update` job of kind rollback (verify against `release.json`, check, the restore staging of NR8 when `restore` is set, switch, restart, probation); the rollback and restore-point fields of the status; the TGL-23 columns of the ADR's item 8; the audit record `sys.update.rollback` with `reason: operator`; the "Roll back to <version>" button on `/updates` (sv, en) with the two-step confirmation and the fresh sign-in for a restore, following the restart like an install; `tenko system update rollback [--restore] [--passphrase-stdin | --key-file FILE]` in the client.
- **Files.** `crates/tenko-api/src/routes/system/updates.rs`, `crates/tenko/src/upgrade/steps.rs`, `crates/tenko/src/upgrade/updates.rs` (the job submission), the pruning of the backup schedule in `crates/tenko/src/backup/` (the restore-point exemption only; NR8 owns the restore code), `crates/tenko/src/client/system.rs`, `ui/src/updates/` (`InstallConfirm.tsx`, `RollbackPanel.tsx`, `api.ts`, `words.ts`, `UpdatesPage.tsx`), `docs/api/openapi.json` (generated).
- **Tests.** Route tests for every refusal reason, for `backup_required` under Hardened, and for the fresh sign-in on a rollback in every profile; a job test where the backup fails and nothing changes; a job test with the same format and with a raised format (refused, then with the restore); a pruning test with a protected restore point; UI tests of the backup question per profile, the button, both confirmations and the restart follow; an acceptance test install with backup, confirm, rollback with restore, confirm, with the audit records.
- **Invariants.** I3, I9.

### NR3 Unit and installer (M)

- **Deliverables.** The unit without the bootstrap, with the guard line, `StateDirectoryMode=0711`, `PrivateIPC=yes`, and `NoExecPaths=/` with `ExecPaths=` naming the layout and the programs the service starts (first an inventory of what the service spawns: `systemd-creds` for the TPM alternative, connector plugins, anything else; the line is added only if the inventory is complete). Capabilities per role: the installer writes the drop-in of each role that needs one (`probe.conf` with the `probe` role, `dhcp-direct.conf` when the configuration has a direct `[dhcp]` listener) and removes it with the role, and nothing else widens the unit. The node's CLI: the group `tenko-cli` (no members), `/opt/tenko/cli/` root:root 0755 with the link `tenko` to `updates/current/tenko`, `/etc/profile.d/tenko-cli.sh` that adds the directory to `PATH` only when `id -u` is not 0, and the summary line that says who may be added to the group and that such accounts have no `sudo`. The installer otherwise: no `/usr/local/bin/tenko`; its own verified copy in a root-owned temporary directory for `--version`, `config check`, `health` and `setup`; `as_tenko` with `setsid`, standard input from `/dev/null` and output through a pipe, so no process of the account holds root's terminal; `upgrade check` and `upgrade layout` as the account from a root-owned staging directory the account may read and execute; the migration of section 5; `--uninstall` that removes the layout as the account and the CLI directory and the `profile.d` entry as root; `--purge` after the account's processes have ended, with `rm --one-file-system`, and removing the group; a refusal of a `noexec` data directory; `tenko` added to `/etc/cron.deny` and `/etc/at.deny` where those files are in use; `--client` (with NR5); the help text and the final summary of section 8. Whether new entries of `updates/` get the group from the set-group-ID bit under `RestrictSUIDSGID=yes`, or whether the account needs `tenko-cli` as a supplementary group to set it, is settled first in the container run.
- **Files.** `deploy/systemd/tenko.service`, `deploy/systemd/dhcp-direct.conf` (its header), `deploy/install.sh` (its embedded unit text too), `deploy/proxmox/test/install-sh-test.sh`, `deploy/systemd/smoke.sh`, `deploy/proxmox/ct/tenko.sh` (`--update` keeps working), `deploy/README.md` (the installer sections only; the rest is NR6).
- **Tests.** `install-sh-test.sh --unit`: NR-E1 from the unit text, including a unit per role set (no `CAP_NET_RAW` without `probe` or a direct DHCP listener); NR-E2 as a static check of the installer; `as_tenko` uses `setsid` and never inherits a terminal; the `profile.d` entry adds nothing for uid 0 (run under `sh` with a faked `id`); the migration plan printed by `--dry-run` for a fixture of the old layout. The Docker runs: a fresh install leaves no `/usr/local/bin/tenko` and creates the group, the link and the entry; a rerun with the same version changes nothing; a rerun with a newer one upgrades through the account. `--systemd`: the whole life including the migration from the previous release's layout, an update through the layout, the guard after three killed starts, a member of `tenko-cli` running `tenko health`, root running the link refused, uninstall and purge, with the audit trace of NR-E2. `deploy/systemd/smoke.sh` gains the rollback.
- **Invariants.** I1, I2, I4, I5, I7, I10.

### NR4 The Windows service and the MSI (M)

- **Deliverables.** `service install` refuses `LocalSystem`, `LocalService` and `NetworkService` with the layout (`service.account_shared`); it sets the data directory's access list only on a directory it creates or that is empty, never recursively over existing content; the service adopts a newer MSI payload at start (reads `C:\Program Files\Tenko\tenko.exe`, verifies it, takes the restore-point backup, runs the install job's check and switch as its account, exits 12); the MSI drops `TenkoUpgradeCheck` and `TenkoUpgradeLayout`, starts the service and waits for `tenko health`, and reports a refused adoption; purge removes junctions without following them; a check whether the SCM's "run a program" failure action runs under the service's account, which decides whether the guard exists on Windows; firewall rules by port or service SID, not by a path in the layout.
- **Files.** `crates/tenko/src/platform/windows.rs`, the adoption path in `crates/tenko/src/upgrade/updates.rs` (coordinated with NR2, which owns `steps.rs`), `deploy/windows/wix/Package.wxs`, `deploy/windows/msi-smoke.ps1`, `deploy/windows/smoke.ps1`, `deploy/windows/README.md`.
- **Tests.** Unit tests of the account rule and the access-list decision; `msi-smoke.ps1`: a fresh install, an upgrade adopted by the service with its backup, a log of the MSI showing no custom action naming the data directory except the `service install` of a new directory; `smoke.ps1`: an update and a rollback with a restore through the layout, the elevated refusal, and the three restarts after a killed version.
- **Invariants.** I1, I2, I5, I10 (Windows terms).

### NR5 The client (S)

- **Deliverables.** `tenko self-update [--source URL] [--version V]` with the install job's verification (I8), the refusals of the ADR's item 10, and an atomic rename next to its own executable (on Windows: rename the running file aside, put the new one in place, remove the old at the next run); the `Tenko-Version` header on every API answer and the client's once-a-day drift warning; `install.sh --client` for the invoking user; the client sections of `docs/QUICKSTART.md` and `deploy/README.md`.
- **Files.** A new `crates/tenko/src/client/self_update.rs`, `crates/tenko/src/client/mod.rs`, the header middleware in `crates/tenko-api/src/` (one layer), `deploy/install.sh` (`--client` only, coordinated with NR3, which owns the file: NR5 hands its function to NR3), `docs/QUICKSTART.md`.
- **Tests.** Unit: the refusals (root, another owner, a file in a layout), the verification against a loopback manifest, a wrong digest; the header on every route (one router test); the drift warning's once-a-day state.
- **Invariants.** I5, I8.

### NR6 Documentation (S)

- **Deliverables.** Section 8 of this plan.
- **Files.** Those of section 8.
- **Tests.** The docs link check; NR-E13 as a review list: every `sudo`, `as root` and `/usr/local/bin` in the changed documents is either part of the installation or one of I4's host reconfigurations, and no document tells root to run `tenko` from the layout or the CLI path.

### NR7 The lab round (M, lead and owner)

- **Deliverables.** A recorded run on a lab node (a virtual machine or a Proxmox container with systemd) and on the Windows smoke host, with the shipped musl binary and release files built from the same source with bumped versions, served from a loopback or lab mirror (`updates.source_url`):
  1. Install the release before this plan with its installer, as root; update from the UI once, so the node has the bootstrap binary and a moved `current` (the lab finding).
  2. Turn on the audit rule: `auditctl -a always,exit -F arch=b64 -S execve,execveat -F dir=/var/lib/tenko -F euid=0 -k tenko-root-exec`, and record `ps -o uid=,pid=,args= -C tenko` after every step.
  3. Run the new installer once as root: the migration. This is the last root step; the trace of root's writes below the data directory (NR-E2) is empty. Add one ordinary account without `sudo` to `tenko-cli`.
  4. Update from the UI, answering yes to the backup: the backup's record is good before the fetch starts. Update again with a release that raises the data format.
  5. Roll back from the UI: refused with `restore_required`; then with the restore, through the second confirmation and the fresh sign-in; the store is the restore point's, the replaced store is on disk, the dropped audit range is recorded, and the external sink holds the dropped records.
  6. Update again with the backup declined, in the Home profile, then try a rollback across the format: `no_restore_point`. Switch the profile to Hardened (in `tenko.toml`, as root, a host reconfiguration) and try `backup: false`: `backup_required`.
  7. Kill the new version three times before it confirms and watch the guard switch back; change a role that needs no new privilege; restart; take a backup.
  8. A role that needs a new privilege (`probe`): the status finding `node.roles.privileges` appears, the unit has no `CAP_NET_RAW` until `install.sh --reconfigure --roles …` as root adds `probe.conf` (I4).
  9. The CLI: as the `tenko-cli` member, `tenko health` through `/opt/tenko/cli/tenko`; as another user, permission denied; as root after `su -`, `sudo -i` and a console login, `command -v tenko` finds nothing; root running the link directly gets `exec.unsafe_owner`.
  10. Each step prints `id -u` of every Tenko process (all not 0) and the audit rule stays empty.
  11. Hash the layout's binaries as root (`sha256sum`) and compare them with the lab release's `SHA256SUMS`: the read-only integrity check of the threat model.
  12. On Windows: the MSI upgrade adopted by the service with its backup, a rollback with a restore from the UI, the account refusal, the elevated refusal.
- **Files.** `docs/plans/no-root-status.md` (new, the record of the round), `deploy/proxmox/test/` (a script for steps 2 to 11 if it is reusable).

### NR8 Restore of the restore point by the service (M)

- **Deliverables.** The service-driven restore of the ADR's item 6: staging while the service runs (open with the request's secret held in memory only, verify as `tenko backup verify` does, install the snapshot into `<data_dir>/restore-<archive id>/store` as a single voter with this node's id, check digest, audit chain and envelopes, import the key generations into a staged key directory keeping identifiers and existing generations); the swap after the graceful stop has closed the store and before the exit with status 12 (`store` to `store.replaced-<UTC time>`, the staged store into place, the key directory likewise, `restored.json` with the new fields); the first-start records `sys.update.rollback` and the dropped audit range from `restored.json`; the provider check that refuses with `backup.restore.provider` where the account cannot seal, and its status finding before an update; `DELETE /api/v1/system/updates/replaced-stores/{name}` (administrators, audited). What changes from today so that no step needs root: the restore no longer needs a stopped server (the swap happens in the service's own shutdown, the restart is exit 12 under the service manager, not `systemctl`); it no longer needs an empty data directory (the staging directory is new and the swap renames the old store aside, the one exception to `backup.restore.target_not_empty`); it no longer needs an operator to run the command as the account (the service is the account); and the replaced store is removed through the API, not with `rm` as root. The restore onto a new host stays the command of [backup.md](../backup.md) section 6.
- **Files.** `crates/tenko/src/backup/` (a new `restore_point.rs` beside the existing restore, reusing its verify and install steps), the shutdown path of `crates/tenko/src/serve/` (one hook after the store closes), `crates/tenko/src/kek.rs` (the import that keeps existing generations), `crates/tenko-api/src/routes/system/updates.rs` (the replaced-store route only, coordinated with NR2, which owns the file), `docs/backup.md` (sections 6, 9, 10, 11, 12).
- **Tests.** Unit: staging fails cleanly at each step (wrong secret, a changed byte, a digest mismatch, a provider that cannot seal) and leaves the live store untouched; the swap's renames are crash-safe (a kill between renames is finished or undone at the next start); the key import with overlapping and missing generations. Integration in `crates/tenko/tests/acceptance_backup.rs`: a store migrated by a newer format restored to the restore point and opened by a binary of the older format (a fixture pair), the audit chain of the restored store verifies, and the dropped range is recorded. Under the `systemd_credential` provider in the `--systemd` container run of NR3.
- **Invariants.** I2, I3, I9.

## 4. Order, parallelism and merging

```text
NR0 ──┬── NR1 ──────────┐
      ├── NR2 ──────────┤
      ├── NR8 ──────────┤
      ├── NR3 ──────────┼── NR7
      ├── NR4 ──────────┤
      ├── NR5 ──────────┤
      └── NR6 ──────────┘  (NR6 finishes after NR1 to NR5 and NR8 merge)
```

| Step | Packages | In parallel? | Why the order |
|---|---|---|---|
| 1 | NR0 | Alone | The record fields, request fields, error codes, DTOs and subcommand stubs are what the others build against |
| 2 | NR1, NR2, NR3, NR4, NR5, NR8, NR6 (draft) | Yes, all seven | File ownership is disjoint as listed; the shared files have one owner each: `crates/tenko/src/upgrade/steps.rs` and `crates/tenko-api/src/routes/system/updates.rs` are NR2's (NR4 adds the adoption and NR8 the replaced-store route through functions NR2 exposes), `deploy/install.sh` is NR3's (NR5 hands `--client` to NR3), `crates/tenko/src/backup/` is NR8's except the pruning exemption, which NR2 adds in one function |
| 3 | NR6 (final) | After NR1 to NR5 and NR8 | The documents describe what merged |
| 4 | NR7 | Last | Needs everything on one build |

Merging: NR1 before NR2 when both are ready, since the rollback relies on the two-version prune; NR8 before NR2's rollback-with-restore tests are switched on (NR2 lands the restore path behind its NR8 call and enables the tests when NR8 merges); NR3 and NR4 independently. Every package compiles and passes `cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run --workspace` and, for NR3, `install-sh-test.sh --unit` at every commit. The release that ships it carries an `### Action required` entry (section 5).

## 5. Migration of existing nodes

| Node | What the operator does | Root |
|---|---|---|
| Linux, installed with `deploy/install.sh` | Run the installer of the release that ships this plan once more, as root (`bash install.sh`, or `deploy/proxmox/ct/tenko.sh --update <ctid>`). It performs the ADR's item 9: reads `current` without executing it, creates `tenko-cli`, the CLI path and the `profile.d` entry, upgrades through the account if the release is newer and sets the layout's modes as the account, writes the new unit, removes `/usr/local/bin/tenko`, starts and waits for health, records `layout = "owned"`. Then add the accounts that need `tenko` on the node to `tenko-cli` | This once, the last time |
| Linux, installed by hand with the shipped unit | The same installer run adopts it (it finds the unit, the configuration and the data directory), or by hand: install the new unit, `systemctl daemon-reload`, create the group, the link and the entry, run `upgrade layout --fix-modes` as the account, remove `/usr/local/bin/tenko`, restart | Once |
| Linux, without the layout (`ExecStart=/usr/local/bin/tenko serve`) | The installer run creates the layout as the account from its verified copy and changes the unit; the node shows notices only until then | Once |
| Windows, MSI | Install the MSI of the release; the service adopts it and, from then on, updates from the UI | The MSI, once, as an administrator |
| Windows, installed by hand with `LocalSystem` or a shared account | `service uninstall`, then `service install` with the virtual account; the vault keys sealed with DPAPI under the old account must be moved with a backup and restore ([ADR 0016](../adr/0016-backup-and-restore.md)), since DPAPI does not move between accounts | Once |
| Containers | Nothing: the image is the unit of deployment and the UI installs nothing in a container | No |

Until a node is migrated, an update from the UI keeps working as today and `tenko` on its `PATH` keeps falling behind. The release notes say so in `### Action required`, and the status carries a notice `update.layout_legacy` while the unit still runs the bootstrap (the service sees its own unit's `ExecStartPre=` through the environment systemd gives it, or the installer state; NR3 chooses the cheaper signal). The first update after the migration is also the first with a restore point; a rollback across a format raised before the migration has none.

## 6. Owner decisions

Decided by the owner on 2026-10-24.

| # | Question | Decision |
|---|---|---|
| NR-Q1 | **Capabilities.** Per role at installation, or `CAP_NET_RAW` with `AF_PACKET` and `AF_NETLINK` on every node up front? | **Per role.** The installer grants the capabilities of the roles it is given; switching on `probe` or the `dhcp` role in direct mode later is a host reconfiguration with the installer as root (I4), which the status finding `node.roles.privileges` names. NR3. |
| NR-Q2 | **A sealed mode for Hardened**, with a root-owned binary and updates only through the installer? | **No sealed mode.** Hardened gets `updates.install = false` for change control. NR0, NR2. |
| NR-Q3 | **Rollback across a raised data format.** | **A backup before every update is the restore point**, not a store copy taken by the migration. The UI, the client and the API ask whether to take a backup first, default yes; the update proceeds only after the backup is recorded good; Hardened requires it. A rollback after a data migration is a restore of that backup, performed by the service itself as an audited action behind a second confirmation and a fresh sign-in, so restore must work without root. NR2, NR8. |
| NR-Q4 | **The command line on the node.** | **A link for `tenko-cli`, never for root.** `/opt/tenko/cli/tenko` links to the layout's current binary; the directory is on the `PATH` of ordinary users only through `/etc/profile.d/tenko-cli.sh`, never on root's; the binary and its directory are 0750, owner `tenko`, group `tenko-cli`; the runbook says members have no `sudo`; the binary refuses to start as uid 0 when its own file is not owned by root, naming the two safe ways. No profile setting and no exception, Lab included (I10). A client generated from the OpenAPI document is the long-term answer and outside this plan. NR1, NR3. |

Also decided in the ADR: the layout keeps `updates/<version>` with the links `current` and `previous` (the rollback directory is the one `previous` names); the guard runs the previous binary before every start; the client updates itself with `tenko self-update`; `LocalSystem` and the shared accounts are refused on Windows with the layout.

## 7. Risks

| # | Risk | Mitigation |
|---|---|---|
| NR-R1 | A host mounts `/var` with `noexec` (some hardening baselines do), so the unit cannot start the layout's binary | The installer refuses with a message naming the mount and `--data-dir`; documented in `deploy/README.md` |
| NR-R2 | The guard runs the previous binary, which for the first update after this ships does not know `guard` | The `-` prefix ignores it; the protection starts with the second update; the release notes say so |
| NR-R3 | `NoExecPaths=/` breaks a key provider or a connector plugin that the service starts | The line is added only after the inventory in NR3, and the `--systemd` run covers every KEK provider the installer configures |
| NR-R4 | The MSI upgrade can no longer roll itself back when the dry run fails, because the check moved into the service | The service keeps running the old version and records the refusal; the MSI reports it from `tenko health` and the attempt record's state |
| NR-R5 | A process of the account attached to root's terminal injects input (`TIOCSTI`) during an installer run | `as_tenko` with `setsid` and no terminal (NR3); a test in `--unit` |
| NR-R6 | Root reaches the CLI path through a plain `su`, which keeps the member's `PATH` | The genuine binary refuses uid 0 (NR1); the runbook requires `su -` or `sudo -i`; NR7 step 9 checks the usual ways to become root |
| NR-R7 | A compromised service reaches the `tenko-cli` members the next time they run `tenko` | Members have no `sudo` and hold nothing beyond the service's reach (the runbook); the group has no members by default |
| NR-R8 | The set-group-ID bit on `updates/` does not survive `RestrictSUIDSGID=yes`, so new versions lose the group `tenko-cli` | NR3 settles it in the container run first; the fallback is `SupplementaryGroups=tenko-cli` for the service with an explicit `chown` of the group |
| NR-R9 | The backup before every update fills the target directory, or the default target shares the disk with the data | Only the newest restore point is protected; the schedule's keep count applies to the rest; the status warns when the target's free space is below twice the store's data before an update starts |
| NR-R10 | A restore drops the audit records written since the backup from the store | The replaced store is kept, the dropped range is recorded in the restored chain, and the external sink holds the records; the second confirmation says so |
| NR-R11 | The restore under a KEK provider where the account cannot seal | Refused at staging with `backup.restore.provider` and shown in the status before any update, so the administrator learns it before needing it |
| NR-R12 | A Windows site uses `LocalSystem` for its key provider today | The refusal message points at the migration of section 5 with a backup and restore; nothing changes for that node until it is installed again |

## 8. Documents that change

| Document | Change | Package |
|---|---|---|
| `docs/upgrades.md` | Terminology (no bootstrap binary; the rollback directory; the restore point); 7.3 and 7.6 without root after the installation, `upgrade check` and `upgrade layout` as the account from an administrator's staging directory; 8.3 the TGL-23 table with the backup and rollback columns; 8.4 the reasons; 8.5 the backup step; a new section for the rollback action and the restore of the restore point; 8.6 the guard and the reason `upgrade.not_started`; 8.11 rewritten around the threat model (no "old layout"); 9.1 two versions, modes and group, `keep_versions` gone; 9.2 the new unit, no `ExecStartPre=` bootstrap, the CLI path; 9.3 the account rule and the adoption; 9.4 other supervisors without the bootstrap; 9.5 the migration of section 5; 9.7 recovery without root, and root only for a node whose two versions fail | NR6 |
| `docs/backup.md` | The restore point of an update (section 3), the protection from pruning (section 4), the restore by the service beside the restore onto a new host (section 6), the new routes, audit records and error codes (sections 9 to 11), the limit "restoring needs the host to be stopped and a new data directory" narrowed to the restore onto a new host (section 12) | NR8 |
| `docs/QUICKSTART.md` | The client on the workstation, `self-update`; on the node, `tenko` for members of `tenko-cli` only | NR5, NR6 |
| `deploy/README.md` | "Install in one command": what the installer leaves on the host, the group `tenko-cli` and the runbook rule (members have no `sudo`; become root with `su -` or `sudo -i`; root never runs `tenko` on the node), the migration, `--client`, the `noexec` refusal, the host integrity check (`sha256sum` of the layout against `SHA256SUMS`, as root, read only) | NR3, NR6 |
| `deploy/systemd/tenko.service` (the header) | Install steps without `/usr/local/bin`; versions paragraph rewritten; the guard; `StateDirectoryMode=0711`; the note that no line may run with `+` or `!` | NR3 |
| `deploy/install.sh` (help and summary) | No `/usr/local/bin/tenko`; "root is not needed for updates from now on"; the CLI path and the group; `--client`; `--uninstall` and `--purge` texts | NR3 |
| `deploy/windows/README.md` | The account rule, the MSI adoption with its backup, Program Files as the installer's payload, the elevated refusal, the rollback | NR4 |
| `docs/SECURITY-PROFILES.md` | TGL-23 row: the backup before an update (required under Hardened), the rollback and `updates.install` | NR6 |
| `docs/REQUIREMENTS.md` | OPS-24: the backup before an update, the rollback action and "the previous version stays installed for one rollback"; OPS-23: "the previous version stays installed" points at ADR 0023 | NR6 |
| `docs/cluster.md` | 13.4: privileges stay the operator's, as I4, per role | NR6 |
| `deploy/tenko.example.toml` | `updates.install`; `keep_versions` removed | NR0 |
| `CHANGELOG.md` | Entries per package, and `### Action required`: run the installer once more as root; add the accounts that need `tenko` on the node to `tenko-cli`; install the client on workstations | each |
