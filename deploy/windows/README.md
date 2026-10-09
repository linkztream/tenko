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

`service install` does these steps in order and reports each on standard output:

1. Makes the configuration path (and `--data-dir`) absolute, then loads and validates the
   configuration exactly as `tenko serve` does. A file that is missing or invalid is
   refused with exit status 3 before anything is registered.
2. Registers the service with the SCM: its own process, automatic start (`--manual`:
   manual), error control normal, the account below, and the description "Tenko DDI: DNS,
   DHCP and IPAM". The command line the SCM runs is
   `tenko.exe service run --name <name> --config <abs config> [--data-dir <abs dir>]`.
3. Sets the failure actions: restart the service after 10 s on the first two failures, and
   leave it stopped on the third. The failure count starts over after a day without a
   failure. The actions also apply when the service stops with a non-zero exit status, not
   only when the process crashes.
4. Creates the data directory and restricts it (see below).

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

The failure actions restart the service after such a stop, twice at most.

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
