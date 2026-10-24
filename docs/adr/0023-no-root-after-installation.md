# ADR 0023: No root after the first installation

- Status: Accepted
- Date: 2026-10-24

## Context

### The finding

A lab node installed with `deploy/install.sh` as version 0.0.1 and updated from the web UI to 0.0.4 still answered `tenko --version` with 0.0.1. The installer puts a bootstrap binary at `/usr/local/bin/tenko` (owned by root), creates the service account `tenko`, and installs a unit that runs `ExecStartPre=/usr/local/bin/tenko upgrade layout` and `ExecStart=/var/lib/tenko/updates/current/tenko serve` ([upgrades.md](../upgrades.md) sections 9.1 and 9.2). An update from the UI is done by the server as the service account: it writes the new version into `/var/lib/tenko/updates/<version>/`, moves the link `current` and restarts with exit status 12. It leaves the bootstrap binary alone, which is the documented rollback point and the reason the binary on `PATH` falls behind (section 9.2 says so). Every update after the first therefore leaves two binaries of different versions on the node, and the one an administrator runs is the older one.

### The withdrawn fix

A first fix made the bootstrap binary hand over to the layout's binary: `tenko` on `PATH` would `exec` `<data_dir>/updates/current/tenko`. It was withdrawn before merging. The layout belongs to the service account, because the server writes it when it installs an update. With the hand-over, root typing `tenko` would execute a file the service account can write, so whoever controls that account (through a bug in the server) plants a binary and waits for an administrator to run `tenko` as root. That is an escalation from the service account to root that the shipped design did not have: until then the only process that ran a file from the layout was the service itself, as `User=tenko`. Checking the file's owner and mode before the `exec` does not close it, since the owner is the account in question, and release files carry no signature yet (API-19), so nothing cryptographic can be checked before the `exec` either.

### The owner's principle and decisions

The owner decided on 2026-10-24: once the first installation is done, root must never be needed again. Installing may run as root or with `sudo`; the installation creates a `tenko` account with limited rights; and instead of installing into or changing `/usr/local/bin` to keep a way back, the old binary is kept in a rollback directory. The agreed direction: the node owns its binary in a directory the service account owns and the unit starts it directly; the service updates itself (download, verify, keep the previous binary, swap atomically, exit 12); rollback is an audited action of the UI and the API performed by the service; ports and capabilities are granted once in the unit at installation; `/usr/local/bin/tenko` and the bootstrap copy go away. The Windows MSI installs a service too and is covered by the same principle in its own terms.

The owner then decided the open questions of the plan ([no-root-plan.md](../plans/no-root-plan.md) section 6), the same day:

- **Capabilities per role.** The installer grants the capabilities of the roles it is given; switching on a role that needs another one later is a host reconfiguration with the installer.
- **No sealed mode.** The installer offers no mode with a root-owned binary; a Hardened site that wants change control sets `updates.install = false`.
- **A backup before every update is the restore point.** Before an update the UI, the client and the API ask whether to take a backup first, default yes; the update proceeds only after that backup is recorded good. A rollback after a data migration is a restore of that backup, performed by the service itself as an audited action behind a second confirmation and a fresh sign-in, so a restore must work without root, as an action of the service account over its own data directory. Hardened may require the backup instead of asking. A copy of the store taken by the migration itself is not the rollback point.
- **The command line on the node.** The node's CLI path is a symbolic link to the layout's current binary in a directory that the installer puts on the `PATH` of ordinary users only, through a `profile.d` entry, never on root's `PATH`. The binary and its directory are mode 0750, owner `tenko`, group `tenko-cli`, so only members of that group run it, and the runbook says those accounts have no `sudo`. The binary refuses to start as uid 0 when its own file is not owned by root. There is no profile setting and no exception for root running the service-owned binary, not even in Lab. The long-term answer, outside this ADR, is a client generated from the OpenAPI document, so that a root-owned client that is rarely updated is never out of date.

This ADR adds a second restore path to [ADR 0016](0016-backup-and-restore.md): ADR 0016's restore onto a new host with a stopped server stays as it is; the restore of a pre-update backup by the running service is new (item 6).

### Threat model

The owner's words: even if an attacker manages to break into Tenko, they must not get root for free and must not be able to carry out remote code execution beyond what they already have. The attacker this ADR defends against **fully controls the service account `tenko`** through a bug in the server: they run arbitrary code as that account, with its capabilities, inside its sandbox, and can read and write everything it can (the data directory, the store, the decrypted key-encryption key it holds in memory, its sockets). Four properties must hold against that attacker.

1. **No process running as root ever executes or loads a file that account can write.** That covers binaries, scripts, units, drop-ins, configuration that root parses, and the inputs of the installer when it runs again. Today: the unit's `ExecStartPre=` and `ExecStart=` run as `User=tenko`, and no line has the `+` or `!` prefix that would run it with full privileges. The installer runs the root-owned `/usr/local/bin/tenko` as root (`--version`, `config check`, `health`, `setup`) and the downloaded binary as root for `--version` from its own `mktemp` directory; it runs the layout's directory only through `as_tenko` (`upgrade check`, `setup token`), and reads the name of the version that `current` points at with `readlink`, without executing it. So the installer already keeps the rule, except for two things it does as root inside the account's directory: `--uninstall` removes `<data_dir>/updates` with `rm -rf`, and `as_tenko` keeps root's terminal attached to a process the account controls (the account could push input into root's shell with `TIOCSTI` on kernels that still allow it). Both are changed by this ADR. On a rerun as root the installer may touch: the unit and its drop-ins, `/etc/tenko`, `/etc/tenko/installer.state`, the host resolver files of `--use-self`, the account and the group `tenko-cli`, the CLI directory and its link, the `profile.d` entry, the files it downloaded into its own temporary directory, and `/usr/local/bin/tenko` to remove it. It does not write, delete, change the owner of, or follow a link inside the data directory or the log directory; whatever must happen there, it does as the account. The node's CLI path (item 3 of the decision) is a link into the layout, so the same property requires that it is never on root's `PATH` and that the binary refuses uid 0.
2. **The account's blast radius is the data directory, the log directory, the sockets it listens on, and the members of `tenko-cli` when they run the CLI.** It is a system account with no password, a shell of `nologin`, no `sudo` rule, no supplementary group, no `cron` or `at` entry and no lingering user manager. The unit confines it with what systemd offers. Read against the unit as it ships (`deploy/systemd/tenko.service`): `NoNewPrivileges=yes`, `ProtectSystem=strict` with the state and log directories as the only writable paths (`StateDirectory=`, `LogsDirectory=`, and `ReadWritePaths=` of the data-directory drop-in), `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectKernelTunables=`, `ProtectKernelModules=`, `ProtectKernelLogs=`, `ProtectControlGroups=`, `ProtectClock=`, `ProtectHostname=`, `ProtectProc=invisible`, `ProcSubset=pid`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `RestrictNamespaces=yes`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes` (the binary runs with it today), `RestrictRealtime=`, `RestrictSUIDSGID=`, `RemoveIPC=`, `SystemCallArchitectures=native`, `SystemCallFilter=@system-service` minus `@privileged @resources`, `UMask=0077`, `LimitCORE=0`, and `CapabilityBoundingSet=` with `AmbientCapabilities=` limited to `CAP_NET_BIND_SERVICE`. `CAP_NET_RAW` with `AF_PACKET` and `AF_NETLINK` come only from the drop-ins of the `probe` role (`probe.conf`) and of the `dhcp` role in direct mode (`dhcp-direct.conf`). Nothing on that list is missing. What is not there and is added by this ADR: `PrivateIPC=yes`, and `NoExecPaths=/` with `ExecPaths=` naming the version directories and the few system programs the service starts, so that nothing the account writes outside the layout can be executed by the service at all (the list of programs the service starts is checked first, see the plan). A member of `tenko-cli` who runs the CLI executes a file the account can write, so such accounts are inside the radius: they have no `sudo` and hold nothing the service account could not reach anyway.
3. **Updating itself does not widen the radius.** An attacker who controls the account already runs code as it; replacing the account's own binary gives them persistence across restarts inside the same radius, not more privileges. The radius stays the same only while nothing grants the file more than the unit grants the process: no root process runs it (property 1), no file capability can be set on it (setting one needs `CAP_SETFCAP`, which the bounding set excludes, and `NoNewPrivileges=` ignores file capabilities and set-user-ID bits anyway), and no unit, timer or failure handler outside the account's own unit runs a file from the layout. What must still hold for the update path is that a release the account fetches is the published one: the source is pinned (the release repository or a configured mirror, over TLS, files only from the origin of the manifest), the checksum comes from the release, and the signature of API-19 is verified once it exists. The Hardened profile may turn installing off entirely or require a signed release.
4. **Tamper evidence survives the compromise.** The attacker owns the store and holds the keys, so they can rewrite or truncate the local audit log, write a new chain that `GET /audit/verify` accepts, make `/system/status` and the version they report say anything, and stop the audit export from then on. They cannot recall records the audit export already delivered to an external sink ([audit-export.md](../audit-export.md): sequence numbers, hashes and chain checkpoints, so a receiver sees a rewritten or truncated chain and a stream that stops), cannot change the systemd journal, the unit, `/etc/tenko` or anything else outside their radius, and cannot change what root sees when it hashes the binaries in the layout (reading a file as root executes nothing) and compares them with the release's `SHA256SUMS`. Those are the controls that must stay outside the attacker's reach, and the documentation names them: an external audit sink with alerting on missing checkpoints at the receiver (TGL-21 requires an export under Hardened), and a host integrity check run by root that only reads. A backup the account wrote is no evidence against it; backups wrapped only to a recipient whose key is offline cannot be read by the attacker, but can be deleted.

The Windows service meets the same four points in its own terms, in item 11 of the decision.

## Decision

### 1. Invariants

A reviewer checks every change to the installer, the unit, the MSI, the updater, the backup restore and the service manager integration against these. A change that breaks one needs a new ADR.

| # | Invariant |
|---|---|
| I1 | No process running as root (on Windows: as SYSTEM or with an elevated administrator token) executes, loads or parses as code a file the service account can write. |
| I2 | No process running as root or SYSTEM writes, deletes, changes the owner or the access list of, or follows a link or junction inside a directory the service account can write. What must happen there is done as the service account. |
| I3 | After the installer exits, no step of operating, updating or rolling back the node needs root: installing a release, the backup before it, rolling back, restoring the pre-update backup, the automatic switch back, recovery from a version that does not start, a role or module change that needs no new privilege, a restart, backups, and every setting stored in the store. |
| I4 | Widening what the host grants the service needs root, by design, and only then: a capability or address family the unit does not grant, the configuration file `tenko.toml`, the data directory's location, the unit itself, membership of `tenko-cli`, uninstalling. These are done by running the installer again (`--reconfigure`) or with the host's own tools, never by the service. |
| I5 | Every Tenko process on the node executes a file in the layout and runs as the service account, or as a member of `tenko-cli` through the CLI path. The layout holds exactly two versions: the one `current` names, which runs, and the one `previous` names, the rollback directory. |
| I6 | The previous version is kept for exactly one rollback: a confirmed install, a rollback and a switch back each leave `current` and `previous` naming two versions and remove every other version directory. |
| I7 | The unit grants its capabilities once, at installation, for the roles the installer was given. A restart, an update, a rollback and the switch back never need more than the unit grants; no file capability, set-user-ID bit or root-run helper adds any. |
| I8 | A binary enters the layout only after its SHA-256 matched the release's published digest, fetched over TLS from the pinned source or uploaded by an administrator, and, once API-19 delivers, after its signature verified against a trust root compiled into the running binary. |
| I9 | Installing, the pre-update backup, rolling back, restoring and switching back are recorded in the audit log, which is never off (NEVER-02), and leave the store, the backup records and the attempt record in a state the next start can finish without an operator. |
| I10 | No process running as root executes the layout's binary; the CLI path is never on root's `PATH`. There is no profile setting and no exception, Lab included. |

### 2. The layout

The layout of [upgrades.md](../upgrades.md) section 9.1 stays, with two versions only (I5, I6) and with the group `tenko-cli` on what the CLI path reaches:

```text
/var/lib/tenko/                    the data directory, tenko:tenko 0711 (traverse only for others)
  updates/                         tenko:tenko-cli 2750 (new entries inherit the group)
    0.0.4/                         tenko:tenko-cli 0750
    0.0.4/tenko                    tenko:tenko-cli 0750, the running version
    0.0.4/release.json             tenko:tenko-cli 0640, the manifest entry it was verified against
    0.0.3/tenko                    the rollback directory: the version that ran before
    current  -> 0.0.4              what systemd starts
    previous -> 0.0.3              what a rollback or a switch back returns to
    attempt.json                   tenko 0600, the last install or rollback
  store/ kek/ tls/ backups/ ...    tenko 0700, as before
```

`updates.keep_versions` goes away: a file that still sets it is accepted with a warning from `tenko config check` and the value is ignored. The links stay symbolic links on Linux and directory junctions on Windows; the switch stays the rename of a staged link over `current`. The host must allow executing files under the data directory: the installer refuses a data directory on a file system mounted `noexec`, with a message that names the mount.

The unit loses the bootstrap and runs the layout directly:

```text
ExecStartPre=-/var/lib/tenko/updates/previous/tenko upgrade guard
ExecStart=/var/lib/tenko/updates/current/tenko serve --config /etc/tenko/tenko.toml
StateDirectoryMode=0711
```

Both lines run as `User=tenko` (no `+` or `!` prefix, I1). `upgrade guard` is the known-good binary watching an install that is on probation (item 4); the leading `-` makes its absence (a first installation, before any update) or its failure harmless.

### 3. The command line on the node

The installer puts the CLI path in place once:

```text
/opt/tenko/cli/                    root:root 0755, written by the installer only
/opt/tenko/cli/tenko -> /var/lib/tenko/updates/current/tenko
/etc/profile.d/tenko-cli.sh        root:root 0644: adds /opt/tenko/cli to PATH when id -u is not 0
```

The link names `current`, so it follows every update and rollback without being written again, and root never needs to touch it after the installation. Root's `PATH` never holds `/opt/tenko/cli`: the `profile.d` entry adds it only for a uid other than 0, the installer adds it nowhere else, and the runbook says to become root with `su -` or `sudo -i`, which do not inherit a user's `PATH` (a plain `su` keeps the caller's `PATH` unless `ALWAYS_SET_PATH` is set in `login.defs`; the binary's refusal below covers that slip for the genuine binary). The group `tenko-cli` is created by the installer, has no members until an administrator adds them (I4), and its members have no `sudo`.

The binary refuses to start as uid 0 when its own file is not owned by root, before anything else in `main`, with exit status 2 and the code `exec.unsafe_owner`, and names the two safe ways: run it from an account in `tenko-cli` on the node, or use the client on the administrator's machine. There is no override. It protects an administrator from a slip with the genuine binary; a binary the attacker replaced will not refuse, which is why I10 is also a rule for people, the runbook and scripts.

The trust table of the node's binaries:

| Object | Owner, group, mode | Written by | Executed by |
|---|---|---|---|
| `/opt/tenko/cli/` and the link `tenko` in it | root:root 0755, a link | The installer, once | Members of `tenko-cli`, through the link; never root (I10) |
| `/etc/profile.d/tenko-cli.sh` | root:root 0644 | The installer | Login shells of users other than root |
| `/var/lib/tenko` | tenko:tenko 0711 | systemd (`StateDirectory=`) | Nobody |
| `updates/` | tenko:tenko-cli 2750 | The service | Nobody |
| `current`, `previous` | tenko, links | The service (switch, rollback, guard) | Followed by systemd's start, the guard and the CLI link |
| `updates/<version>/tenko` | tenko:tenko-cli 0750 | The service (install job), the installer's run as the account | The service (`User=tenko`), the guard (`User=tenko`), members of `tenko-cli`; never root |
| The unit and its drop-ins | root:root 0644 | The installer | Read by systemd as root; every command runs as `User=tenko` |
| `/etc/tenko/tenko.toml` | root:tenko 0640 | The installer | Read by the service |
| The installer's downloaded release | root:root 0755, in its own temporary directory | The installer | Root (`--version`, `config check`, `health`, `setup`), and the account from a root-owned staging copy |

### 4. The update sequence

An update from the UI, the client or the API is the install job of [upgrades.md](../upgrades.md) section 8.5, run by the service as its account, with these rules:

1. **Backup.** Before anything else the request answers whether to take a backup first (`backup`: `true` by default in the UI and the client; the API takes the field and defaults to `true`). With `true`, the job's first step `sys.update.backup` writes an online backup ([ADR 0016](0016-backup-and-restore.md) item 5) to the target directory, wrapped to the configured recipient and, when the request carries one, to a passphrase. The install continues only once the backup's record in `backup.runs` is good; a failed backup fails the job before anything changed. The record is marked as the restore point of the attempt, which the attempt record names (archive id, file, SHA-256, time), and is kept by the schedule's pruning until a later confirmed install has a newer restore point. Without a recipient and without a passphrase the request is refused with 422 `backup.key.missing`, and the UI asks for a passphrase. Under Hardened the backup is required: `backup: false` is refused with 409 `update.install_blocked`, reason `backup_required`.
2. **Fetch.** The manifest and the release file come from `updates.source_url` over HTTPS (rustls, the platform's or the configured trust roots); the file only from the scheme, host and port of that URL (`update.source_mismatch`); no more bytes than the manifest gives, at most 512 MiB. A mirror is a `source_url` on another host that serves the same `releases.json` and files. The file is written to `updates/<version>/tenko.part`.
3. **Verify.** The size and the SHA-256 must equal the manifest's entry, which the release workflow writes from the same digests as `SHA256SUMS`; the installer, which reads `SHA256SUMS` itself, verifies against that. Both come from the same origin as the file, so they prove the file whole and the listed one, not that the origin is honest. When API-19 delivers, this step also verifies the release signature against a trust root compiled into the running binary (the identity of the release workflow for Sigstore, the publisher certificate for Authenticode) before the file becomes executable; the build feature `release-signatures` is turned on in the same change, and from then on an unsigned file is refused in every profile. Signing protects against a compromised origin; it cannot protect against a compromised node, whose running binary may already be the attacker's (threat model, property 3). The file becomes mode 0750, group `tenko-cli`.
4. **Check.** The new binary must report the manifest's version (`tenko upgrade version`) and pass `tenko upgrade check --disposable` on a state copy, as today.
5. **Switch.** The attempt record goes to `restarting`; `previous` is pointed at the running version and `current` at the new one, each by an atomic rename of a staged link.
6. **Restart.** The server stops gracefully and exits with status 12; systemd (`RestartForceExitStatus=12`) or the Windows SCM starts the binary `current` names.
7. **Probation.** The new version reads the attempt record before anything else in `main` and must become ready within `updates.ready_timeout_secs`; a failed start step, a second unconfirmed start or the watchdog switches back (swap the links, attempt `rolled_back`, exit 12). This automatic switch back is unchanged by this ADR ([upgrades.md](../upgrades.md) section 8.6).
8. **Prune.** After the confirmation, every version directory other than the two the links name is removed (I6).

**When the new binary fails before it can read the attempt record** (a crash in early start, a system call the sandbox refuses), it cannot switch itself back. Today that ends in a unit that systemd gives up on and a manual switch of the link as root ([upgrades.md](../upgrades.md) section 9.7), which I3 forbids. The guard closes it: `ExecStartPre=-…/previous/tenko upgrade guard` runs the previous, known-good binary before every start; while the attempt record is in `restarting` it counts the starts it has seen, and at the third one without a confirmation it switches back itself (the same transition as the watchdog, reason `upgrade.not_started`), so the start that follows runs the previous version. With `StartLimitBurst=5` the guard acts before systemd gives up. Outside an attempt it does nothing and exits 0. The one case left needing root is a node on which both versions fail to start, which is a broken node and not an update; the installer, run again, repairs it.

### 5. Rollback as an action of the UI and the API

A rollback switches back to the version `previous` names:

- `POST /api/v1/system/updates/rollback` (operation id `rollback_update`), body `{"version": "<previous>", "restore": null}` or with `"restore": {"backup": "<archive id>", "passphrase": "…"}` (or the backup key file in a multipart body instead of the passphrase); administrators of the system, with a fresh sign-in in every profile. It submits a job of kind `sys.update` with the steps `verify` (the previous binary's SHA-256 against its `release.json`, which catches corruption, not an attacker who owns the account), `check` (the previous binary's `upgrade check` on a state copy), the restore staging of item 6 when `restore` is set, and `switch`; the restart and the probation are those of an install, so a rolled-back version that does not become ready is switched forward again.
- **The data format is unchanged.** The previous version opens the store as it is; the rollback is a switch, and what the newer version wrote stays. `restore` may still be set to go back to the restore point.
- **The data format was raised.** The previous binary refuses the store, so the rollback is a restore of the restore point taken before the update: without `restore` the request is refused with 409 `update.rollback_blocked`, reason `restore_required`, and with no restore point (the update ran with `backup: false`) with reason `no_restore_point`. The UI asks twice: first which version and why, then, after a fresh sign-in, a second confirmation that names the restore point's time and states that everything written since is lost.
- Other reasons for 409 `update.rollback_blocked`: `no_previous`, `cluster`, `container`, `layout_missing`, `unsupervised`, `in_progress`, and `rollback_off` (item 8).
- `GET /api/v1/system/updates` reports the previous version, the restore point, whether a rollback would start, whether it needs the restore, and why not. The page `/updates` shows a "Roll back to <version>" button under the last attempt and follows the restart like an install. The client has `tenko system update rollback [--restore] [--passphrase-stdin | --key-file FILE]`.
- Audit: the job's transitions with the principal, and `sys.update.rollback` with `reason: operator`, `from`, `to` and the restore point when one was restored, written by the version that runs after the restart; a restore also writes `sys.backup.restore` (item 6). The automatic switch back keeps its reasons.

### 6. Restore of the restore point by the service

Restore today ([ADR 0016](0016-backup-and-restore.md) item 7, [backup.md](../backup.md) section 6) is a command run with the server stopped into a data directory without a store, which on a node means root stops the unit and runs the command as the account. For the restore point it becomes an action of the running service over its own data directory, with no step for root:

1. **Stage while the service runs.** The rollback job opens the backup with the secret of the request (the passphrase, or the key file, held in memory only and wiped after the step; never stored and never written to the attempt record), checks it as `tenko backup verify` does, installs its snapshot into a fresh store under `<data_dir>/restore-<archive id>/store` with this node's `[node] id` as the single voter, verifies the digest, the audit chain and every envelope, and imports the key generations of the backup into a staged key directory with the host's provider, keeping their identifiers; generations the ring already holds are kept as they are. The format marker comes from the backup's snapshot, so the staged store has the format the previous version writes. Any failure removes the staging directory and changes nothing.
2. **Swap after the store is closed.** After the switch of the links, the running (newer) binary stops gracefully, closes the store and then, before it exits with status 12, renames `store` to `store.replaced-<UTC time>` and the staged store into `store`, does the same for the key directory, and writes `restored.json` with the restore point, the rollback's principal and job, the audit head of the replaced store and the range of audit records that the restore drops. The previous version needs no restore code: it starts on a store of its own format.
3. **Record at the first start.** The first start after the swap records `backup.restore` and `sys.backup.restore` as today, and from the new fields of `restored.json` writes `sys.update.rollback` and a record that names the dropped audit range with the replaced store's head. The dropped records stay verifiable in `store.replaced-<UTC time>` and are in the external sink when one is configured. A previous version older than this ADR ignores the new fields; the first rollback that restores after this ships therefore runs a previous version that knows them only from the second update on, and the release notes say so.
4. **Keys and providers.** The account seals with the providers the installer configures: under `systemd_credential` the root key is the credential the service receives and later generations are wrapped under it in `<data_dir>/kek`; the `file` provider's key and the Windows DPAPI user key of the virtual account are the account's own. None needs root. A provider under which the account cannot seal (the `platform` provider without a usable TPM falls back to a plain file) is refused at staging with `backup.restore.provider` and named in the status before an update starts.
5. **What stays as ADR 0016 has it.** A restore onto a new host, after the loss of a cluster or of the disk, is an installation and stays the command with a stopped server; the service-driven restore is for the restore point of an update, on the node that wrote it, outside a cluster.

`store.replaced-*` directories are kept until an administrator removes them through `DELETE /api/v1/system/updates/replaced-stores/{name}` (administrators, audited), so their removal needs no root either.

### 7. Recovery without root

| Situation | What happens | Root? |
|---|---|---|
| The new version does not become ready | The watchdog or the second start switches back (item 4, step 7) | No |
| The new version dies before it reads the attempt record | The guard switches back at the third start (item 4) | No |
| The administrator wants the previous version, same data format | Rollback from the UI or the API (item 5) | No |
| The administrator wants the previous version after a data migration | Rollback with the restore of the restore point, losing what was written since the backup (items 5 and 6) | No |
| The update ran without a backup and migrated the data | Rollback refused (`no_restore_point`); the newer version keeps running; a scheduled or manual backup from before the update restores only onto a new data directory | Yes, as an installation |
| Both versions fail to start | The installer run again with a release that starts | Yes, a repair |

### 8. What each security profile allows

TGL-23 keeps its rows and gains the backup and the rollback:

| Profile | Check | Install | Backup first | Rollback |
|---|---|---|---|---|
| Home | Daily | From the source, from the UI | Asked, default yes | Fresh sign-in; a restore also needs the second confirmation |
| Standard | Daily | From the source, step-up | Asked, default yes | As Home |
| Hardened | Daily, version string only | Uploaded files only until API-19; with API-19, from the source when the release is signed. `updates.install = false` turns installing off: notices only, and updates by the installer as root, which is the site's choice to trade I3 for change control | Required | As Home; refused with `rollback_off` when installing is off |
| Lab | Daily | From the source | Asked, default yes | As Home |

`updates.install` (default `true`) is a new key of the `[updates]` section, set in `tenko.toml`, which the service cannot write (I4), so an attacker who owns the account cannot turn it on. No profile, Lab included, relaxes I10.

### 9. `/usr/local/bin/tenko` and the migration of existing nodes

The bootstrap binary is removed. On a node installed today the installer, run once more as root, is the last time root is used:

1. It finds the old layout: `/usr/local/bin/tenko`, a unit with the bootstrap `ExecStartPre=`, or both. It reads the running version from the name `current` points at (`readlink`) and never executes anything in the layout as root.
2. It gets the release to install into its own temporary directory, owned by root, verified against `SHA256SUMS`, and runs that copy as root only for `--version`, `config check` and the health and setup calls (I1: root runs a file only the installer wrote).
3. It creates the group `tenko-cli`, the CLI directory with its link and the `profile.d` entry (item 3).
4. If the release is newer than the running version, it stops the unit and runs, as the account, `upgrade check` and then `upgrade layout` from a copy in a root-owned directory the account can read and execute, so that the account copies the release into its own layout (I2). `upgrade layout`, run by the account, also sets the modes and the group of item 2 on the layout. If the release is not newer, the account still runs `upgrade layout --fix-modes` with it.
5. It writes the new unit (no bootstrap, the guard line, `StateDirectoryMode=0711`), reloads systemd, and removes `/usr/local/bin/tenko`. Staged files such as `/usr/local/bin/tenko-0.2.0` from the manual procedure are reported, not removed.
6. It starts the unit and waits for `tenko health`. The service prunes the layout to two versions at its first confirmed start.
7. It records `layout = "owned"` in `/etc/tenko/installer.state` and prints that updates, rollbacks and recovery need no root from now on, that members of `tenko-cli` run `tenko` on the node, and how to install the client on a workstation (item 10).

A rerun of the installer with a newer release still upgrades, as a convenience, by the same steps. `--uninstall` removes the layout as the account, then the unit, the CLI directory and the `profile.d` entry; `--purge` removes the data directory as root only after the unit is gone and the account's processes have ended, with `rm --one-file-system` and without following links, and removes the group. The manual procedure of [upgrades.md](../upgrades.md) section 7.3 changes to the same model: the staged binary goes into a directory the administrator owns, and `upgrade check` and `upgrade layout` run as the account.

### 10. The client on the administrator's machine

`tenko` is one binary that is both the server and the client of the HTTPS API. On a node, members of `tenko-cli` run the service's binary through the CLI path; elsewhere the client belongs on the administrator's machine.

- **Installing the client.** As the user who will run it, without root: `~/.local/bin/tenko` on Linux, `%LOCALAPPDATA%\Programs\Tenko\tenko.exe` with that directory on the user's `PATH` on Windows, from the release file of the platform verified against `SHA256SUMS` (the commands are in `docs/QUICKSTART.md` and `deploy/README.md`). `install.sh --client` does it for the invoking user and refuses to run as root.
- **Updating the client.** `tenko self-update` reads the same manifest as the server (`--source` for a mirror), verifies the file the way the install job does (I8), and replaces its own executable by a rename next to it. It refuses when it runs as root, when the file belongs to another user ("installed by another user or a package manager; update it there"), and when the executable lies in a Tenko layout.
- **Version drift.** The server answers with its version in the response header `Tenko-Version`; the client warns once a day on stderr when its version differs in major or minor from the server it talks to.
- **Later.** A client generated from the OpenAPI document, so that its commands follow the server it talks to rather than its own version, is the long-term answer to a client that is rarely updated; it is outside this ADR.

### 11. The Windows service

The MSI and `tenko service install` meet the same invariants in Windows terms:

- **The account.** The service runs as its virtual account `NT SERVICE\tenko`. With the layout, `service install` refuses `LocalSystem` and the shared accounts `LocalService` and `NetworkService` (`service.account_shared`): a binary that SYSTEM runs from a directory it lets the service write is no escalation but makes the radius the whole machine, and a binary another service's shared account can write is an escalation between services. The rights it needs are those of the data directory and the network; binding ports below 1024 needs no privilege on Windows, so there is no capability to grant.
- **The access lists.** `C:\Program Files\Tenko` stays writable by Administrators and SYSTEM only. The data directory gives the service account full control, with Administrators and SYSTEM. `service install` sets that list only on a data directory it creates or that is empty; it never applies an access list recursively to a tree the account already controls (I2), where a junction planted by the account would carry the change outside.
- **The command line.** The MSI puts nothing on `PATH`. An elevated administrator runs the MSI's payload, `C:\Program Files\Tenko\tenko.exe`, which only Administrators and SYSTEM can write, or the client of item 10. The layout's binary refuses to start under SYSTEM or an elevated token when its own file is not owned by Administrators or SYSTEM (`exec.unsafe_owner`), the Windows form of I10. A group like `tenko-cli` is not provided on Windows.
- **The installer.** The MSI's custom actions run as SYSTEM and execute only the MSI's payload. On an upgrade they no longer run `upgrade check` or `upgrade layout` against the data directory as SYSTEM (I2): the MSI replaces its payload, starts the service, and the running service adopts the payload as its own account (it reads a file in Program Files, which the account cannot write, verifies it, takes the restore-point backup as item 4 says, and runs the install job's check, switch and restart). The MSI waits for the outcome through `tenko health` and reports it. The payload is never run by the service after the adoption and may be older than the running version after an update from the UI; the client warns about that drift.
- **No SYSTEM helper.** No scheduled task, failure action ("run a program"), service or custom action running as SYSTEM or as an administrator executes or loads a file under the data directory. Windows has no `ExecStartPre=`; the guard of item 4 exists there only if the SCM's "run a program" failure action runs under the service's own account, which the plan verifies before using it. Without it, Windows relies on the new binary reading the attempt record before anything else in `main`, and on its three restarts (section 9.3 of upgrades.md).
- **Restore.** The restore of item 6 runs as the virtual account, which owns the DPAPI key it seals with.
- **Removal.** Uninstall stops the service first; purge removes the data directory with a function that removes a junction without following it.

## Consequences

- An administrator never needs root on a node after the installation: updates with their backup, rollbacks with or without a restore, the switch back, recovery from a version that does not start, roles and modules that need no new privilege, backups. The lab finding goes away with its cause: the binary on the node's CLI path is the one that runs.
- The privilege escalation of the withdrawn hand-over cannot come back by accident: I1, I2 and I10 are checkable rules for the installer, the unit and the MSI, the CLI path is never on root's `PATH`, and the binary refuses uid 0 when its file is not root's.
- A compromised service account can replace the service's own binary, which it could already do in effect under today's layout, where the server writes the binaries it runs (section 8.11 of upgrades.md). That is persistence inside the account's radius, not an escalation (threat model, property 3). The ADR does not prevent it; it relies on detection from outside the radius: the external audit sink and a root-run hash check of the layout against the release's `SHA256SUMS`. With no sealed mode, a site that needs an immutable binary has no supported way to get one; Hardened's `updates.install = false` gives change control but not immutability.
- Members of `tenko-cli` run a file the service account can write, so a compromise of the service reaches them the next time they run `tenko`. That is why they have no `sudo` and why the runbook keeps them free of credentials the service could not reach anyway. A plain `su` that keeps a member's `PATH` is a slip the genuine binary refuses and the runbook forbids.
- A role change that needs a new capability (the `probe` role, the `dhcp` role in direct mode) needs the installer as root (I4). That is deliberate: widening privileges is the privileged party's act, and the status finding `node.roles.privileges` names the command.
- Every update takes a backup first unless the administrator declines (or, under Hardened, always): the time and the disk space of one online backup ([backup.md](../backup.md) section 3: about twice the store's data in the target directory while it runs), and the restore point stays on disk until a newer one replaces it. A restore point in the default target directory, `<data_dir>/backups`, shares the disk with the data; the documentation recommends another disk, as it does for every backup.
- A rollback that restores loses everything written since the backup, including the audit records of that period from the store; they stay in the replaced store on disk and in the external sink. A rollback of an update that ran without a backup and migrated the data is not possible from the UI.
- The restore of item 6 is a second restore path beside ADR 0016's, with its own tests; the rule that restore never writes into a directory that holds a store now has one exception, the staged swap by the service.
- The administrator's workflow changes: `tenko` on the node is for members of `tenko-cli`; commands otherwise run from a workstation. `QUICKSTART.md`, `deploy/README.md`, the installer's help and its final summary say so, and the upgrade documentation loses its root steps.
- The data directory must be on a file system that allows executing files (not `noexec`), which some hardened host baselines forbid for `/var`; the installer refuses such a host with a message, and `--data-dir` moves it. The data directory becomes 0711 so the CLI path can reach the layout; everything with data in it stays 0700.
- One more process runs at every start (the guard), a few milliseconds. The guard depends on a previous binary that knows the `guard` command; for the first update after this ships, the previous version is older and the guard does nothing (the `-` prefix), so the protection starts with the second update.
- The MSI upgrade moves its check and switch from SYSTEM into the service; the MSI can no longer roll its upgrade back when the dry run fails, it reports the failure and the service keeps running the old version.
- `updates.keep_versions` is removed; installations that kept more versions lose them at the next confirmed install.

## Alternatives considered

- **A root-run update helper** (a root service or a `sudo` rule that installs what the server downloaded). Rejected: root would act on files and requests the account controls, which is I1 and I2 broken by design, and root stays needed.
- **The hand-over from the bootstrap binary to the layout's binary.** Rejected: root executes a file the service account can write (the withdrawn fix).
- **The bootstrap binary as the rollback point.** Rejected: it drifts behind the running version, it is a second binary of another version on `PATH`, and keeping it current needs root at every update.
- **A root-owned binary updated only by the installer (a sealed mode).** Rejected by the owner: root would be needed for every update; Hardened gets `updates.install = false` instead.
- **Granting every capability at installation so that no role change ever needs root.** Rejected by the owner: `CAP_NET_RAW` on every node widens the radius of a compromise to forging and capturing packets on the host's links for nodes that never probe.
- **The store copy taken before a migration as the rollback point.** Rejected by the owner: it covers only the migration step and not what else the new version changed, it lives beside the data, and the restore point should be one thing, a backup, whatever the new version does to the store.
- **A wrapper on `PATH` that runs the layout's binary as the service account** (`runuser -u tenko -- …`). Rejected: it needs `sudo` or root at every call, against I3, it hides that the client runs with the service's rights and the service's key within reach, and it attaches a process the account controls to the administrator's terminal.
- **A warning instead of a refusal when root runs the layout's binary, or a profile setting that allows it in Lab.** Rejected by the owner: a warning is printed after root has already executed the file, and an exception in one profile is an escalation path in that profile.
