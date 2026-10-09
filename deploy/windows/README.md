# Windows service

`tenko service` registers `tenko serve` as a Windows service and manages it through the
Service Control Manager (SCM). The configuration file is the same `tenko.toml` as for
`tenko serve`; `deploy/tenko.example.toml` documents every key.

```
tenko service install --config C:\ProgramData\Tenko\tenko.toml
tenko service start
tenko service stop
tenko service uninstall
```

All four commands need an elevated prompt (Run as administrator). Without one they stop
with `access denied; run this command from an elevated prompt` and exit status 1.

## Before you install

1. Put `tenko.exe` where the service account can read and run it, for example
   `C:\Program Files\Tenko\tenko.exe`. The service is registered with the path of the
   executable that ran `service install`. A copy in a user profile or in a build directory
   is not readable by the service account, and the service fails to start. If you move the
   executable later, uninstall the service and install it again.
2. Copy `deploy/tenko.example.toml` to `C:\ProgramData\Tenko\tenko.toml` and adapt it. Set
   `data_dir` and, if you use it, `log.file` to absolute paths. In TOML, write Windows
   paths as literal strings: `data_dir = 'C:\ProgramData\Tenko'`. A service does not start
   in your working directory, so `service install` refuses relative paths for these two
   keys.
3. Put the data directory on SSD or NVMe storage; the server warns at start when a
   durable commit is slow (OPS-19).
4. Check the file:

   ```
   tenko config check --config C:\ProgramData\Tenko\tenko.toml
   ```

## Install

```
tenko service install --config C:\ProgramData\Tenko\tenko.toml
```

| Option | Default | Meaning |
|---|---|---|
| `--config <FILE>` | required | The configuration file the service reads. It must exist. |
| `--data-dir <PATH>` | from the file | Overrides `data_dir` of the file; passed to the service. |
| `--name <NAME>` | `tenko` | The service name. Every other `service` command takes the same `--name`. |
| `--display-name <TEXT>` | `Tenko DDI` | The name in the Services console. |
| `--account <ACCOUNT>` | `NT SERVICE\<name>` | The account the service runs as, see below. |
| `--manual` | off | Manual start instead of automatic start at boot. |
| `--no-update-layout` | off | Register this executable itself instead of the version layout, see "Upgrades" below. Installing new versions from the UI then stays off. |

`service install` does these steps in order and reports each on standard output:

1. Makes the configuration path (and `--data-dir`) absolute, then loads and validates the
   configuration exactly as `tenko serve` does. A file that is missing or invalid is
   refused with exit status 3 before anything is registered.
2. Registers the service with the SCM: its own process, automatic start (`--manual`:
   manual), error control normal, the account below, and the description "Tenko DDI: DNS,
   DHCP and IPAM". The command line the SCM runs is
   `tenko.exe service run --name <name> --config <abs config> [--data-dir <abs dir>]`. With
   the version layout (the default) the executable is `<data_dir>\updates\current\tenko.exe`
   and not the file that ran the command.
3. Sets the failure actions: restart the service after 10 s on the first three failures,
   and leave it stopped on the fourth. The failure count starts over after a day without a
   failure. The actions also apply when the service stops with a non-zero exit status, not
   only when the process crashes.
4. Creates the data directory and restricts it (see below).
5. Sets up the version layout, unless `--no-update-layout` is given (see "Upgrades" below):
   copies the executable that ran the command to `<data_dir>\updates\<version>\tenko.exe`
   and creates the junction `<data_dir>\updates\current` that points at it. The output
   shows this as the line `versions:`.

Install does not start the service. Start it with `tenko service start`.

### Account

The default account is the virtual service account `NT SERVICE\tenko` (`NT SERVICE\<name>`
for another name). Windows manages it: it has no password, its own SID, and it is not an
administrator. `--account` accepts accounts that need no password: another virtual
account, `LocalSystem`, `NT AUTHORITY\LocalService` and `NT AUTHORITY\NetworkService`.
There is no password option on purpose; secrets do not belong on a command line.

The account matters for the vault. With the default `[kek] provider = "platform"` and
`scope = "user"`, the key-encryption keys in `<data_dir>\kek` are sealed with DPAPI to the
user key of the service account. Windows can unseal them only for a process that runs as
that account, and only with the account's profile loaded, which it does when the service
starts. Two consequences:

- No other account can unseal the keys through DPAPI, administrators included. Copying
  the data directory to another machine or restoring it under another account leaves the
  vault closed.
- Moving the service to another account later (`--account` at install, or a change in the
  Services console) makes the existing keys unreadable, and the server refuses to start at
  the `kek` or `vault` step. Plan the move: it needs a KEK rotation, or `scope = "machine"`
  in `[kek]`, chosen before the first start. The machine scope lets any process on the host
  unseal the keys, so it is the weaker choice.

### Data directory permissions

After the service is registered (the virtual account does not exist before that), install
creates the data directory and runs

```
icacls <data_dir> /inheritance:r /grant:r "<account>:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F"
```

so that only the service account, the local Administrators group and SYSTEM have access,
to the directory and to everything created in it later. Nobody else, including other
users, can read the store, the keys or the logs.

- The configuration file must be readable by the service account. Keep it in the data
  directory, or grant the account read access to its location.
- A `log.file` outside the data directory is not covered. Grant the account write access
  to that directory yourself.
- If the account changes, run the `icacls` command again for the new account.

## Logs and first-run setup

Under the SCM there is no console. The service writes its log, appended, to
`<data_dir>\logs\tenko.log`, or to `log.file` when the file sets one. `log.level` and
`log.format` apply as usual. The Windows Event Log comes in Slice 3.

At the first start the server has no administrator yet and opens first-run setup. The log
file then holds a line with `setup_token=`; use that token in the web UI or with
`tenko setup`:

```
findstr setup_token C:\ProgramData\Tenko\logs\tenko.log
```

The token is single-use and changes at every start until setup is complete. Treat the log
file as sensitive until then; the directory is limited to the service account and
administrators for this reason.

If the service cannot open its log, or its configuration stopped being valid after the
install, there is nowhere to write the reason. The SCM then shows only the exit status of
the service, see below.

## Start, stop, uninstall

```
tenko service start [--name <NAME>]
tenko service stop [--name <NAME>]
tenko service uninstall [--name <NAME>]
```

- `start` asks the SCM to start the service and waits up to 120 s until it runs, then
  prints ``service `tenko` is running``. If the service stops while it starts, the command
  fails and prints the exit status of the service.
- `stop` asks the service to stop and waits up to 60 s until the state is Stopped. The API
  lets open requests finish (`server.shutdown_grace_secs`), the job runner stops and the
  store makes its state durable before the process ends. A service that is not running is
  reported as such and is not an error. A system shutdown follows the same path.
- `uninstall` stops the service if it runs (the same 60 s limit), then deletes it from the
  SCM. It leaves the data directory, its permissions and the configuration file in place.

The usual tools work as well: `sc.exe query tenko`, `services.msc`, `Get-Service tenko`.

### Exit status of a stopped service

When the service stops with an error, the SCM records the tenko exit status as the
service-specific exit code (`sc.exe query tenko` shows it as `SERVICE_EXIT_CODE`; `start`
prints it with an explanation):

| Status | Meaning |
|---|---|
| 1 | An unexpected failure, or the log file could not be opened. |
| 2 | None of the configured roles runs in this version. |
| 3 | The configuration is invalid. Run `tenko config check --config <file>` in an elevated prompt. |
| 4 | A start step failed. The log names the step and its code. |
| 12 | Not an error: the server stopped itself so that it is started again (an installed update, a switch back to the previous version, or a changed module set). The failure actions start it again. |

The failure actions restart the service after such a stop, three times at most.

A restart that the server asks for with status 12 counts as a failure, like a crash. An
installed update uses one of the three restarts. A failed update that is switched back uses
up to three (the switch, the failed start of the new version, and the switch back), so it
leaves the previous version running. A fourth failure within a day, of any kind, leaves the
service stopped; start it with `tenko service start`.

## Upgrades

The service runs `<data_dir>\updates\current\tenko.exe`. `current` is a directory junction
(made with `mklink /J`, which needs no privilege) to the directory of the running version,
`<data_dir>\updates\<version>`, so a new version is a switch of the junction and a restart.
The web UI does this itself when the security profile allows it (Home and Lab; Standard after
a fresh sign-in; Hardened only for a release file that you upload) and switches back when the
new version does not become ready. The service account can write the binaries it runs, which
is what lets it install. `--no-update-layout` keeps the old behaviour: a service that runs the
executable it was registered with, and no installs from the UI. With the layout the file
that ran `service install` is copied, so it can be moved or deleted afterwards; the note
about moving the executable under "Before you install" applies to `--no-update-layout` only.

To upgrade by hand, run these commands in an elevated PowerShell, with the new
`tenko-0.2.0.exe` staged where administrators can run it and its checksum compared with the
`SHA256SUMS` of the release. The check refuses a store that a running service has open, so
the service must be stopped first.

```
tenko service stop
robocopy C:\ProgramData\Tenko D:\Backup\Tenko-20261009 /E /SEC /XJD /R:1 /W:1
& "C:\Program Files\Tenko\tenko-0.2.0.exe" upgrade check --config C:\ProgramData\Tenko\tenko.toml
$LASTEXITCODE
& "C:\Program Files\Tenko\tenko-0.2.0.exe" upgrade layout --config C:\ProgramData\Tenko\tenko.toml
tenko service start
Select-String -Path C:\ProgramData\Tenko\logs\tenko.log -Pattern 'data format'
```

- `robocopy` statuses below 8 mean success. The copy of the data directory holds the
  DPAPI-sealed key files, which unseal only under the same account on the same machine.
- `upgrade check` exits with 0 (nothing to do) or 10 (a migration is needed and its dry run
  passed) when it is safe to go on. Any other status means stop (11: this binary refuses the
  data directory; 1: the check could not run).
- `upgrade layout` run by the new binary copies it to `updates\0.2.0\tenko.exe`, points
  `previous` at the version that ran and `current` at the new one.
- The log line `data format 2`, with `(migrated from format 1 in 1 step(s))` after a
  migration, and `tenko health --live` (which prints the version) show what runs.

To roll back, stop the service and point the junction at the previous version. Use
`cmd.exe` for it: `rmdir` without `/s` removes the junction and leaves the version
directory alone.

```
tenko service stop
cmd /c rmdir C:\ProgramData\Tenko\updates\current
cmd /c mklink /J C:\ProgramData\Tenko\updates\current C:\ProgramData\Tenko\updates\0.1.0
tenko service start
```

If the new version raised the data format (`store\format` names a newer format than the
old executable writes), the old executable refuses the directory with exit status 3 and the
store must be restored first: rename `store` to `store.failed-20261009` and copy
`upgrade-backups\<name>\store`, the copy that the migration took, to `store`. A service
installed before the layout existed gets it with `tenko service uninstall` and a new
`tenko service install` (the data directory, its permissions and the configuration stay).
The full procedure, the rollback in detail, updates from the web UI and the recovery from a
version that crash-loops are in [../../docs/upgrades.md](../../docs/upgrades.md).

## Run in a console instead

`tenko serve --config C:\ProgramData\Tenko\tenko.toml` runs the same server in the
foreground, with log output on the console and the setup token printed there. The hidden
command `tenko service run` is the entry point of the SCM, not of a user: started from a
console it prints that and exits with status 2.

## Coexistence with Windows roles

- The DHCP role cannot run next to the Windows DHCP Server service on the same
  host: both bind UDP 67.
- The DNS role cannot run next to the Windows DNS Server service on the same
  addresses: both bind UDP/TCP 53.

Stop or uninstall those Windows roles first, or migrate with the planned
migration tooling.
