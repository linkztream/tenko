# Windows service

`tenko service` registers `tenko serve` as a Windows service and manages it through the
Service Control Manager (SCM). The configuration file is the same `tenko.toml` as for
`tenko serve`; `deploy/tenko.example.toml` documents every key.

The MSI installer (next section) is the one-command install: it puts `tenko.exe` in place,
writes the configuration and runs the same `tenko service` commands. The sections after it
describe those commands for an installation by hand.

## MSI installer

`tenko-<version>-windows-x86_64.msi` is attached to every release. It installs per machine on
x64 Windows and leaves a running service and a browser setup to finish.

### Unattended

In an elevated prompt, with the MSI next to the prompt:

```
msiexec /i tenko-0.2.0-windows-x86_64.msi /qn /l*v tenko-install.log TENKO_ROLES=controller,dns TENKO_PROFILE=home TENKO_HOSTNAME=ddi.example.test TENKO_DNS_ADDRESS=192.0.2.53 TENKO_DNS_PORT=53 TENKO_DATA_DIR=C:\ProgramData\Tenko\data TENKO_START=1 TENKO_FIREWALL=1
```

Every property is optional; the line above spells out the defaults except the host name and
the DNS address. A value with spaces goes in double quotes (`TENKO_DATA_DIR="D:\Tenko data"`).
`msiexec` returns 0 on success and 1603 on a failure; `/l*v` writes the log that says why,
including the output of every `tenko` command the installer ran.

| Property | Default | Meaning |
|---|---|---|
| `TENKO_ROLES` | `controller` | `controller`, `controller,dns`, `controller,dhcp` or `controller,dns,dhcp` (any `roles` value of `tenko.toml` works; the dhcp role also needs `[dhcp] listen`): the roles the service starts with. Under `TENKO_PROFILE=hardened` also the roles the machine is prepared for (the firewall rules below); outside Hardened it is prepared for every role |
| `TENKO_MODULES` | not set | The modules, for example `ipam,dns`; not set lets the browser setup ask |
| `TENKO_PROFILE` | `home` | The security profile until setup: `home`, `standard`, `hardened` or `lab` |
| `TENKO_HOSTNAME` | not set | The certificate's name until setup stores the host name (`[tls] host_name`); `localhost` is added as an extra name. Not set: `localhost` |
| `TENKO_DNS_ADDRESS` | not set | With the dns role: the IP addresses DNS answers on, comma-separated. Not set: every address (`0.0.0.0` and `::`) |
| `TENKO_DNS_PORT` | `53` | With the dns role: the DNS port, also of the firewall rules |
| `TENKO_DATA_DIR` | `%ProgramData%\Tenko\data` | The data directory |
| `TENKO_START` | `1` | `1` starts the service at the end of the install, `0` leaves it stopped |
| `TENKO_FIREWALL` | `1` | `1` adds the firewall rules below, `0` adds none |
| `TENKO_RECONFIGURE` | not set | `1` replaces an existing `tenko.toml` with one written from the properties |
| `TENKO_PURGE` | not set | On removal: `1` also deletes the data directory, `tenko.toml` and the remembered properties |

There is no property for the administrator or a password: a password on a command line ends
up in logs. Setup finishes in the browser with the one-time setup token, or with
`tenko setup` afterwards (`deploy/README.md`, "First-run setup"); the UI language is asked
there as well.

The installer remembers the properties of an installation under
`HKLM\SOFTWARE\Tenko\Installer`. An upgrade, a repair and the removal use them again, a
property on the command line wins over the remembered value, and an uninstall keeps them
with the configuration and the data (so a later install picks them up); `TENKO_PURGE=1`
removes them.

On a host with Hyper-V's Default Switch, Internet Connection Sharing answers DNS on that
switch's address, and a DNS listener on every address may not start: set
`TENKO_DNS_ADDRESS` to the server's own addresses.

### The wizard

Double-click the MSI. After the license page, one dialog asks the same questions as the
properties: the roles (two buttons), the security profile, the host name, the data
directory, the DNS address (only with the dns role), whether to start the service and
whether to open the firewall. When a `tenko.toml` exists already, a box offers to replace it
(`TENKO_RECONFIGURE`). The last page names the URL and where the setup token is, and can open
the browser. Properties on the command line (`msiexec /i tenko.msi TENKO_ROLES=controller,dns`)
fill in the dialog.

### What it installs

| Path | What |
|---|---|
| `C:\Program Files\Tenko\tenko.exe` | The installer's file: the binary that ran `service install`, and the one the service adopts a newer version of at its start (see "Upgrade"). Only Administrators and SYSTEM can write it. Put it on `PATH` yourself if you want `tenko` in every prompt. |
| `C:\Program Files\Tenko\setup-token.cmd` | Prints the setup token in an elevated console |
| `%ProgramData%\Tenko\tenko.toml` | The configuration, written by `tenko config init` from the properties; kept on upgrade, repair and uninstall |
| `%ProgramData%\Tenko\data` | The data directory (`TENKO_DATA_DIR`), set up by `tenko service install` when it is new or empty, with the service in `updates\<version>\tenko.exe` behind the junction `updates\current`; from then on only the service writes in it |
| Start menu, Tenko DDI | "Open Tenko" (`https://localhost:8443/`) and "Tenko setup token" |
| The service `tenko` | Registered by `tenko service install --config %ProgramData%\Tenko\tenko.toml`: automatic start, the account `NT SERVICE\tenko`, a token that keeps `SeChangeNotifyPrivilege` alone, the failure actions and the Event Log source, as under "Install" below |

`%ProgramData%\Tenko` gets its own access control list: SYSTEM and Administrators have full
control and Users may read, instead of the ProgramData default that lets every user create
files. The installer also grants `NT SERVICE\tenko` read access to `tenko.toml`. The data
directory gets the stricter list of `tenko service install` (the service account,
Administrators and SYSTEM only).

Everything that touches the service runs as SYSTEM in the installer and is the binary's own
command: `tenko config init`, `tenko service install` and `tenko service start`, and on
upgrade `tenko service stop` and `tenko service start`. Nothing the installer runs reads,
writes or executes a file under the data directory once the service account controls it
(ADR 0023, item 11): `service install` writes the version layout only into a data directory
it creates or that is empty, before it grants the account access, and an upgrade is adopted
by the service itself at its start (see "Upgrade"). An install where a service named `tenko`
exists already (registered by hand) is refused before anything changes: remove that service
with `tenko service uninstall` first; its configuration and data directory stay and the
installer uses them (`TENKO_DATA_DIR` must then name the same directory as `data_dir` of the
kept file).

`tenko config init` writes a short file that holds only the keys from the properties; check
it, or the file you keep, with `tenko config check --config %ProgramData%\Tenko\tenko.toml`.
The command also works by hand (`tenko config init --help`).

### Firewall

With `TENKO_FIREWALL=1` the installer adds inbound rules for all firewall profiles, and
removes them with the product. Every rule is bound to the service `tenko` (its service SID,
`Get-NetFirewallServiceFilter` shows it), not to a program path: the service runs a file in
its own data directory, which it writes itself, so a rule by that path would open the port
for whatever runs there, while the service SID follows the service through every update and
names nothing the account can change. No other program on the host gets the ports. Which
rules follows the security profile, as on Linux ([../README.md](../README.md), "Roles and
the security profile"): outside Hardened the machine is prepared for every role, so the DNS
and DHCP rules are added whatever `TENKO_ROLES` says and a role switched on later from the
Nodes page finds its ports; under `TENKO_PROFILE=hardened` only the rules of the roles in
`TENKO_ROLES`:

| Rule | Port |
|---|---|
| Tenko DDI web UI and API (TCP 8443) | TCP 8443 |
| Tenko DDI DNS (UDP) | UDP `TENKO_DNS_PORT`; under Hardened with the dns role |
| Tenko DDI DNS (TCP) | TCP `TENKO_DNS_PORT`; under Hardened with the dns role |
| Tenko DDI DHCP (UDP) | UDP 67; under Hardened with the dhcp role |
| Tenko DDI DHCPv6 (UDP) | UDP 547; under Hardened with the dhcp role |

Narrow them to your networks in Windows Defender Firewall if the server is reachable from
networks that should not manage it. Under Hardened a role added later gets its rules from a
reinstall with the new role list, `msiexec /i tenko-<version>-windows-x86_64.msi
REINSTALL=ALL TENKO_ROLES=controller,dns,dhcp`; the Nodes page shows that command for a role
the machine is not prepared for.

The installer records what it prepared in `%ProgramData%\Tenko\prepared-roles` (the profile,
the roles, the firewall; an INI file the service only reads), which the node reports per
role on the Nodes page.

<!-- WP7.5 -->
The DHCP rules are for the dhcp role; they open UDP 67 and 547 only, so a `[dhcp] port` or a
`[dhcp.v6] port` of your own needs a rule of your own. On Windows the role answers clients by
broadcast, and the service needs no privilege for these ports.

**The raw methods on Windows.** The probe role's raw scan methods
([../../docs/scanning.md](../../docs/scanning.md), section 9) need Npcap, which the MSI does
not install: install it yourself; `tenko node scan status` then reports raw sockets as
available (the service looks for `System32\Npcap\wpcap.dll`). Without it those methods
answer `unsupported`, and ICMP works through the `ping` command, as does the dhcp role's
conflict probe on Windows. The systemd drop-ins and `CAP_NET_RAW` of Linux have no
counterpart here, so the Nodes page reports the probe role as prepared on Windows.

### First-run setup

Open "Open Tenko" in the Start menu, or `https://<host name>:8443` from another machine. The
browser warns about the certificate until the root of Tenko's internal CA is installed
(`tenko ca-root`, `deploy/README.md` "TLS"). Setup asks for the one-time setup token: "Tenko
setup token" in the Start menu prints it after a UAC prompt, or run, in an elevated prompt,

```
"C:\Program Files\Tenko\tenko.exe" setup token --config C:\ProgramData\Tenko\tenko.toml
```

### Upgrade

Run the MSI of the new release like the first one: `msiexec /i tenko-0.3.0-windows-x86_64.msi
/qn /l*v tenko-upgrade.log`, or double-click it. No properties are needed; the remembered ones
apply. The installer

1. stops the service (`tenko service stop`),
2. replaces `tenko.exe` in `C:\Program Files\Tenko`,
3. starts the service (`tenko service start`) and removes the old product entry.

The installer does nothing in the data directory. The service does the rest, as its own
account `NT SERVICE\tenko`, at that start (ADR 0023, item 11): the running version reads the
new `tenko.exe`, which only Administrators and SYSTEM can write, asks it for its version and,
when that is newer, runs the store check with it (`tenko upgrade check` on a copy of the
closed store, the same check and the same refusals as by hand), copies it to
`updates\<version>\tenko.exe`, points `previous` at the version that ran and `current` at
the new one, writes the attempt record and stops with exit status 12. The failure actions
start the service again after 10 s, and the new version runs on probation like a version
installed from the web UI (`docs/upgrades.md`, section 8.6): it migrates the data format at
its first start and is switched back when it does not become ready. `tenko service start`
waits through that restart and then reports `the service runs version 0.3.0`. The lines
`adopted the installer's file` (a Warning) and `tenko service starting` are in the
Application log, source `tenko`, and in `<data_dir>\logs\tenko.log`.

When the new version refuses the store (the check answers 11, for example
`upgrade.format_newer`), or the file cannot be read, the running version keeps running and
writes an Error to the Application log with the reason (`the installer's file was not
adopted`). `tenko service start` then sees that `updates\current` still names the older
version, fails with exit status 11 and the message `did not adopt this binary`, and the
installer rolls its files back and reports the failure (`msiexec` returns 1603; the log names
the step). Nothing in the data directory changed; the old version serves throughout.

A `tenko.exe` of the same version or an older one (a release candidate and its release, an
MSI of a version the web UI has already passed) is left alone: the layout only moves
forward, and the log says `the installer's file is not newer than the running version;
nothing to adopt`. With the remembered `TENKO_START=0` the installer does not start the
service, and the adoption happens at the next start you ask for. The configuration is not
touched unless `TENKO_RECONFIGURE=1` is given. Back up the data directory first as under
"Upgrades" below; the installer does not.

Updates installed from the web UI keep working after an MSI install, because the service runs
the version layout and not the file in Program Files. After such an update, `C:\Program
Files\Tenko\tenko.exe` is older than the running version; that is harmless. An MSI older
than the installed MSI is refused (uninstall first).

**Installations made before this adoption existed** (a version in `updates\current` that
does not look at the installer's file at its start) take one more step for their first
upgrade to a version that does: run the MSI, which replaces `tenko.exe` and starts the old
version again, then install the update once from the web UI (or upload the release file
there); from then on every MSI upgrade is adopted by the service. The old version in the
layout cannot be replaced by the installer, since that would mean SYSTEM writing into the
service's directory.

### Repair, uninstall and purge

`msiexec /fa tenko-0.2.0-windows-x86_64.msi` repairs the files; add `TENKO_RECONFIGURE=1` (with
the properties) to rewrite `tenko.toml`, then restart the service.

```
msiexec /x tenko-0.2.0-windows-x86_64.msi /qn
msiexec /x tenko-0.2.0-windows-x86_64.msi /qn TENKO_PURGE=1
```

Uninstall (also from Settings, Apps) stops and unregisters the service, removes the files,
the shortcuts and the firewall rules, and keeps `tenko.toml`, the data directory and the
remembered properties, so a later install continues where this one stopped. `TENKO_PURGE=1`
also deletes the data directory (only when it holds `updates\`, so a mistyped path deletes
nothing else), `tenko.toml` and the remembered properties. The keys of the vault are in the
data directory: a purged installation cannot be recovered without a backup.

### Signing and SmartScreen

The MSI and `tenko.exe` are not signed today. That was a decision (2026-10-19): an
Authenticode certificate costs a yearly fee plus a hardware token, and Azure Artifact Signing
is offered to organizations only, which a single-maintainer project is not yet. The release
workflow signs both as soon as a certificate is configured (below), so a certificate later is a
configuration change, not a code change.

What an unsigned MSI means in practice:

- A browser may warn that the file is not commonly downloaded; keep it.
- Windows SmartScreen shows "Windows protected your PC" when you open it. Click "More
  info", check that the file name is the one you downloaded, then "Run anyway". The UAC
  prompt shows "Publisher: Unknown".
- A file downloaded with a browser carries the mark of the web, which is what makes
  SmartScreen look at it; `Unblock-File .\tenko-0.2.0-windows-x86_64.msi` removes the mark
  once you have checked the file.

Check the file before you run it, against the `SHA256SUMS` of the same release, which lists
the MSI next to the binaries ([docs/upgrades.md](../../docs/upgrades.md), section 6.5):

```
Get-FileHash .\tenko-0.2.0-windows-x86_64.msi -Algorithm SHA256
Select-String tenko-0.2.0-windows-x86_64.msi .\SHA256SUMS
```

The two digests must be equal. A checksum from the same release page shows that the download
is whole; only a signature shows who made it.

When a certificate exists, configure the repository and nothing else:

| Setting | Kind | Value |
|---|---|---|
| `WINDOWS_SIGNING_CERT_PFX` | secret | The code-signing certificate with its private key, as a PFX file in base64 (`[Convert]::ToBase64String([IO.File]::ReadAllBytes('cert.pfx'))`) |
| `WINDOWS_SIGNING_PASSWORD` | secret | The PFX password |
| `WINDOWS_SIGNING_TIMESTAMP_URL` | variable, optional | An RFC 3161 time-stamp server; default `http://timestamp.digicert.com` |

`deploy/windows/sign.ps1` then signs `tenko.exe` in the build job, before it is uploaded (so
the release binary, the binary in the MSI and the binary that UI updates install are the
same signed file), and the MSI in the `msi` job, each with SHA-256, a time stamp and a
`signtool verify`. Without the secrets each step leaves the notice "is not signed" in the job
log and the release goes on unsigned. A certificate that lives on a hardware token (every OV
and EV certificate issued since June 2023) cannot be exported as a PFX: sign with a cloud
signing service then. Azure Artifact Signing (formerly Trusted Signing) fits the same two
places, with `azure/login` and `azure/trusted-signing-action` in place of `sign.ps1`; the
workflow names them in a comment.

### Build and test the MSI

`build-msi.ps1` builds the MSI with the WiX toolset v5, which the repository pins as a .NET
local tool (`.config/dotnet-tools.json`; it needs the .NET SDK 8 or newer). It takes a release
binary, checks that it reports the version, and runs WiX's validation:

```
cd ui; npm ci; npm run build; cd ..
cargo build -p tenko --release --locked
pwsh -File deploy\windows\build-msi.ps1 -Binary target\release\tenko.exe -Version 0.2.0 -Out dist
```

The sources are in `deploy/windows/wix/`: `Package.wxs` (the files, the properties, the
custom actions and their order) and `TenkoUI.wxs` (the wizard). The license page is the
repository's `LICENSE.md`, converted at build time. The `UpgradeCode` in `Package.wxs` must never
change: it is what makes a newer MSI an upgrade of an older one.

To look at the files without installing, extract them (no elevation needed):

```
msiexec /a dist\tenko-0.2.0-windows-x86_64.msi /qn TARGETDIR=C:\Temp\tenko-msi
```

`msi-smoke.ps1` installs, upgrades, uninstalls and purges the MSI for real: a silent install
with the dns role on port 15353 and a data directory of its own, the service running,
`tenko health --live`, the setup token, the firewall rules and that they are bound to the
service, the privileges of the token (`sc.exe qprivs tenko`: `SeChangeNotifyPrivilege`
alone), a silent upgrade to a second package of a higher version whose log shows no
`upgrade check` and no `upgrade layout` run by the installer, the service having looked at
the new `tenko.exe` at its start (`nothing to adopt`, since both packages carry the same
binary) and running again with the configuration and the data kept, a silent uninstall that
keeps both, an install over the kept data that leaves the directory as it is (no `icacls`
in its log), and the purge. The release workflow runs it on `windows-latest` before the MSI
is published. On a machine of
your own, run it only on a throw-away VM without Tenko, in an elevated PowerShell 7:

```
pwsh -File deploy\windows\build-msi.ps1 -Binary target\release\tenko.exe -Version 0.2.0 -Out dist
pwsh -File deploy\windows\build-msi.ps1 -Binary target\release\tenko.exe -Version 0.2.0 -MsiVersion 0.2.1 -Out upgrade-test
pwsh -File deploy\windows\msi-smoke.ps1 -Msi dist\tenko-0.2.0-windows-x86_64.msi -UpgradeMsi upgrade-test\tenko-0.2.0-windows-x86_64.msi
```

It refuses to run where Tenko is installed or a `tenko` service or `%ProgramData%\Tenko\tenko.toml`
exists. Each step prints a line that starts with `==>`; a failure prints the tail of the
installer log and of `tenko.log`, uninstalls with `TENKO_PURGE=1` (unless `-Keep`) and exits
with status 1.

## The service by hand

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
| `--account <ACCOUNT>` | `NT SERVICE\<name>` | The account the service runs as, see below. Another virtual account is accepted; `LocalSystem`, `LocalService` and `NetworkService` are refused. |
| `--manual` | off | Manual start instead of automatic start at boot. |
| `--no-update-layout` | off | Register this executable itself instead of the version layout, see "Upgrades" below. Installing new versions from the UI then stays off, and the service adopts no newer version of this file at its start. |

`service install` does these steps in order and reports each on standard output:

1. Refuses `LocalSystem`, `LocalService` and `NetworkService` as the account
   (`service.account_shared`, exit status 2), see "Account" below.
2. Makes the configuration path (and `--data-dir`) absolute, then loads and validates the
   configuration exactly as `tenko serve` does. A file that is missing or invalid is
   refused with exit status 3 before anything is registered.
3. Looks at the data directory without changing it (see "Data directory permissions"
   below): a directory that holds data is accepted only when its owner and its access list
   are already the ones this command sets, and refused otherwise, before anything is
   registered.
4. Registers the service with the SCM: its own process, automatic start (`--manual`:
   manual), error control normal, the account below, and the description "Tenko DDI: DNS,
   DHCP and IPAM". The command line the SCM runs is `tenko.exe service run --name <name>
   --config <abs config> [--data-dir <abs dir>] --payload <this file>`. With the version
   layout (the default) the executable is `<data_dir>\updates\current\tenko.exe` and not the
   file that ran the command; `--payload` names that file, the one the service adopts
   newer versions of at its start (see "Upgrade" above). The output shows it as the line
   `installer file:`, with a warning when it lies outside a Program Files directory.
5. Sets the required privileges of the service token with `sc.exe privs`: the token keeps
   `SeChangeNotifyPrivilege` and nothing else (the line `privileges:`). Tenko needs no
   other right: binding ports below 1024 needs no privilege on Windows, the probe role's raw
   sockets come from Npcap, whose driver access list decides, and the Event Log, DPAPI and
   the junctions of the layout need none. `sc.exe qprivs tenko` shows the list. A failure
   here fails the install.
6. Sets the failure actions: restart the service after 10 s on the first three failures,
   and leave it stopped on the fourth. The failure count starts over after a day without a
   failure. The actions also apply when the service stops with a non-zero exit status, not
   only when the process crashes.
7. Sets up the data directory. A new or empty directory is restricted to Administrators and
   SYSTEM first, the version layout is written into it (unless `--no-update-layout` is
   given: the executable that ran the command is copied to
   `<data_dir>\updates\<version>\tenko.exe` and the junction `<data_dir>\updates\current`
   is created, the line `versions:`), and the service account is granted access last. A
   directory that holds data is left as it is (the line `left as it is`).

Install does not start the service. Start it with `tenko service start`.

Install also registers the Event Log source of the service (see "Event Log" below), under
the service name, and uninstall removes it.

### Account

The default account is the virtual service account `NT SERVICE\tenko` (`NT SERVICE\<name>`
for another name). Windows manages it: it has no password, its own SID, and it is not an
administrator. `--account` accepts another virtual account. `LocalSystem`,
`NT AUTHORITY\LocalService` and `NT AUTHORITY\NetworkService` are refused with
`service.account_shared` and exit status 2 (ADR 0023, item 11): the service writes the
binary it runs, in its own data directory, and must be the only account that can; under
LocalSystem that binary would run with the rights of the whole machine, and the two shared
accounts are shared with other services. There is no password option on purpose; secrets do
not belong on a command line.

Nodes installed by hand under one of the three accounts before this rule existed keep
running until the service is installed again. Plan that move with a backup and a restore
([../../docs/backup.md](../../docs/backup.md)): the DPAPI-sealed keys of the vault do not
move between accounts (next paragraph).

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

What install does with the data directory depends on what it finds there, and it decides
before anything is registered:

- **Missing or empty.** After the service is registered (the virtual account does not
  exist before that), install creates the directory if needed and runs, in this order,

  ```
  icacls <data_dir> /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F"
  <writes updates\<version>\tenko.exe and the junction updates\current>
  icacls <data_dir> /grant:r "<account>:(OI)(CI)F"
  ```

  so that only the service account, the local Administrators group and SYSTEM have access,
  to the directory and to everything created in it later. Nobody else, including other
  users, can read the store, the keys or the logs. The layout is written while the account
  cannot write the directory yet, so no elevated process ever writes into a directory the
  account controls (ADR 0023, I2).
- **Holding data under that list.** The owner is Administrators or SYSTEM and the list is
  exactly the three entries above for this account (install reads it with `Get-Acl` and
  the account's SID with `sc.exe showsid`): install changes nothing in the directory and
  prints `left as it is`. This is a reinstall of the service over its own data, for example
  after `tenko service uninstall`. With the version layout the directory must already hold
  `updates\current\tenko.exe`; otherwise install refuses (`service.data_dir_no_layout`),
  since the installer writes no layout into a directory the account controls: register with
  `--no-update-layout`, or restore the data into a new directory.
- **Holding data under another list, or unreadable.** Refused with
  `service.data_dir_in_use` before anything is registered: install never changes the
  access list of a directory that holds data, where a change could reach beyond the
  directory through a junction the account made. Use the account the directory was set up
  for, or a new or empty directory. A path that is a link or a junction is refused with
  `service.data_dir_link`.

Also:

- The configuration file must be readable by the service account. Keep it in the data
  directory, or grant the account read access to its location.
- A `log.file` outside the data directory is not covered. Grant the account write access
  to that directory yourself.
- The account cannot change once the directory holds data: install refuses the directory
  for another account, and the DPAPI-sealed keys belong to the old one. Move the data with a
  backup and a restore into a new directory instead.

## Logs and first-run setup

Under the SCM there is no console. The service writes its log, appended, to
`<data_dir>\logs\tenko.log`, or to `log.file` when the file sets one. `log.level` and
`log.format` apply as usual. Important events also go to the Windows Event Log, see
"Event Log" below.

The file is rotated by size. When it would grow past `[log] max_file_mb` (default 64), the
server renames it to `tenko.log.1` and starts a new `tenko.log`. Older files move up
(`tenko.log.2`, `tenko.log.3`, and so on). `[log] keep_files` (default 5) is the number of
rotated files that are kept; the oldest is deleted. The disk use is therefore about
`max_file_mb` times `keep_files + 1`.

```
[log]
max_file_mb = 64
keep_files = 5
```

At the first start the server has no administrator yet and opens first-run setup. It keeps
the one-time setup token in the file `setup-token` of the data directory, never in the log;
print it in an administrator shell and use it in the web UI or with `tenko setup`:

```
tenko setup token --config C:\ProgramData\Tenko\tenko.toml
```

The token is single-use and changes at every start until setup is complete; the file is
removed when setup completes. It inherits the access control list of the data directory,
which is limited to the service account, Administrators and SYSTEM.

If the service cannot open its log, or its configuration stopped being valid after the
install, the reason goes to the Event Log as an Error, see below. The SCM also shows the
exit status of the service.

## Event Log

`tenko service install` registers an Event Log source in the Application log. The source
has the name of the service (`tenko` by default, the value of `--name` otherwise). The
registration is the registry key
`HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\<name>`. `tenko service
uninstall` removes it again.

What the running service writes:

- Two lines at every run, both with level Information: `tenko service starting` and
  `tenko service stopped`. They show when the service started and stopped, also when the
  SCM restarted it after an update (exit status 12).
- Every log event at or above the level `[log] event_log`. The default is `"warn"`, so
  warnings and errors are copied to the Event Log. The values are `error`, `warn`, `info`,
  `debug`, `trace` and `off`. `off` disables the sink; the two lifecycle lines are still
  written. Lower levels than `warn` can fill the Application log quickly. `log.level`
  decides which events exist at all, so `event_log = "debug"` needs `log.level = "debug"`.
- A failure before the file log is open, as an Error. This is the case that the file log
  cannot show: a configuration that stopped being valid after the install, or a log
  directory that cannot be written. The SCM shows the exit status, and the Event Log says
  why.

Read the entries in an elevated or ordinary PowerShell:

```
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'tenko' } -MaxEvents 50 |
    Format-Table TimeCreated, LevelDisplayName, Message -Wrap
```

Event Viewer shows the same entries under Windows Logs, Application, with the source
`tenko`. The source has no message file, so Windows may add a note that it cannot find the
description of the event. The text of the event is still shown after it, and
`$_.Properties[0].Value` holds it.

## Start, stop, uninstall

```
tenko service start [--name <NAME>]
tenko service stop [--name <NAME>]
tenko service uninstall [--name <NAME>]
```

- `start` asks the SCM to start the service and waits up to 120 s until it runs, then
  prints ``service `tenko` is running`` and which version the layout runs. A stop with exit
  status 12 while it starts is a restart the service asked for (an adopted installer's file,
  a switch back): `start` waits through the SCM's restart delay and on for the new version,
  up to three times. If the service stops with another status, the command fails and prints
  it. When the layout runs an older version than the `tenko.exe` that ran `start`, the
  service did not adopt that file: `start` fails with exit status 11 and `did not adopt this
  binary`, and the Application log names the reason (see "Upgrade" above).
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
is what lets it install. `--no-update-layout` keeps the old behavior: a service that runs the
executable it was registered with, and no installs from the UI. With the layout the file
that ran `service install` is copied, so it can be moved or deleted afterwards; the note
about moving the executable under "Before you install" applies to `--no-update-layout` only.

To upgrade by hand, stage the new release as the installer's file, the path `--payload` in
the image path names (`sc.exe qc tenko` shows it; `C:\Program Files\Tenko\tenko.exe` under
the MSI), and restart the service. The service does the rest as its own account, exactly as
after an MSI upgrade ("Upgrade" above): it asks the file for its version, runs the store
check with it, copies it into the layout, switches `current` and restarts into it. Nothing
elevated reads, writes or runs anything under the data directory; an administrator writes
only in Program Files, where the service account cannot. In an elevated PowerShell, after
the checksum of the download was compared with the `SHA256SUMS` of the release:

```
tenko service stop
robocopy C:\ProgramData\Tenko D:\Backup\Tenko-20261009 /E /SEC /XJD /R:1 /W:1
Copy-Item .\tenko-0.2.0-windows-x86_64.exe "C:\Program Files\Tenko\tenko.exe"
tenko service start
Select-String -Path C:\ProgramData\Tenko\logs\tenko.log -Pattern 'adopted the installer|data format'
```

- `robocopy` statuses below 8 mean success. The copy of the data directory holds the
  DPAPI-sealed key files, which unseal only under the same account on the same machine.
  `/XJD` leaves out the junctions `current` and `previous` under `updates`.
- `tenko service start` waits through the restart and prints `the service runs version
  0.2.0`. When the new version refuses the store, it fails with exit status 11 and `did not
  adopt this binary`; the Application log (source `tenko`) has the check's reason
  (`upgrade.format_newer` and the like), the old version keeps running, and the file in
  Program Files can be put back or left for a later release.
- The log lines `adopted the installer's file`, then `data format 2` with `(migrated from
  format 1 in 1 step(s))` after a migration, and `tenko health --live` (which prints the
  version) show what runs.
- Do not run `upgrade check` or `upgrade layout` in an elevated prompt against the data
  directory: both write there (`upgrade check` copies the store into
  `<data_dir>\upgrade-check` by default). The service runs the check for you at its start.

**Going back to the previous version.** A version that does not become ready is switched
back by the service itself (the probation of `docs/upgrades.md`, section 8.6: the watchdog
or the second start points `current` at `previous` and stops with exit status 12). A
deliberate return to the previous version is an action of the service too, from the web UI
and the API (ADR 0023, item 5: `POST /api/v1/system/updates/rollback`, with the restore of
the pre-update backup when the data format was raised); until that route ships, a return is
a restore of the backup taken before the upgrade onto a new data directory, as in
[../../docs/backup.md](../../docs/backup.md). Do not move the junction `updates\current` with
`rmdir` and `mklink /J` in an elevated prompt: that is an elevated process writing in the
service's directory, which ADR 0023 forbids, and an installer's file of an older version is
not adopted either (the layout moves forward only). A service installed before the layout
existed gets it with `tenko service uninstall` and a new `tenko service install` over a new
or empty data directory; over its old data directory install refuses
(`service.data_dir_no_layout`), so restore a backup into the new one. The full procedure,
updates from the web UI and the recovery from a version that crash-loops are in
[../../docs/upgrades.md](../../docs/upgrades.md).

## Smoke test

`deploy/windows/smoke.ps1` tests the whole service life on a real Windows host. The owner
runs it once, in an elevated PowerShell 7, before a release; the weekly CI job runs it on a
hosted runner. It needs a debug build, because only debug builds honor
`TENKO_TEST_VERSION_FROM_LAYOUT`, which lets one binary install itself as version 0.0.2.

```
cargo build -p tenko
pwsh -File deploy\windows\smoke.ps1 -Binary .\target\debug\tenko.exe
```

| Parameter | Default | Meaning |
|---|---|---|
| `-Binary <PATH>` | required | The `tenko.exe` to test. |
| `-Name <NAME>` | `tenko-smoke` | The service name and Event Log source. |
| `-Root <DIR>` | `%ProgramData%\TenkoSmoke` | The configuration, data directory and release files. |
| `-Keep` | off | Leave the service and the directory in place, to look at a failure. |

The script never touches an installed `tenko` service: it uses its own service name and its
own directory, and it refuses the name `tenko`. It refuses to start when it is not elevated,
when another service has the name, or when `-Root` holds files that it did not create. A
service and a directory left by an earlier smoke run are removed first. It talks to the
loopback address only.

Each step prints a line that starts with `==>`:

1. Writes a configuration with a loopback API port, the Home profile, the DPAPI key
   provider, `[log] event_log = "info"` and a loopback release source.
2. Installs the service and checks the service, the Event Log source, the image path
   `<data_dir>\updates\current\tenko.exe` with `--payload` naming the binary, and the
   privileges of the token (`sc.exe qprivs`: `SeChangeNotifyPrivilege` alone). Checks that
   `service install --account` refuses `LocalSystem`, `LocalService` and `NetworkService`
   with `service.account_shared` and registers nothing.
3. Sets `TENKO_TEST_VERSION_FROM_LAYOUT=1` in the service environment.
4. Starts the service and waits up to 120 s until `tenko health` answers.
5. Looks for the Event Log entry `tenko service starting`.
6. Checks that the file log exists and has content, and that a second service over the
   same data directory, now in use under the first account's list, is refused with
   `service.data_dir_in_use` and registers nothing.
7. Runs first-run setup through the API, offers this binary as version 0.0.2 from a small
   HTTP server on 127.0.0.1, installs it from the update API and waits until the service
   has exited with status 12, the SCM has started it again, version 0.0.2 runs, the
   `updates\current` junction points at `updates\0.0.2` and the update is confirmed.
8. Stops the service and checks the Event Log entry `tenko service stopped`.
9. Uninstalls the service and checks that the service and the source are gone; installs it
   again over the kept data directory, which install leaves as it is (`left as it is`), and
   uninstalls it again.

Then it stops the release server and removes the service and the directory, also after a
failure. A run takes about three to five minutes; the restart after the update alone waits
10 s for the SCM and then for the new version to become ready.

The exit status is 0 when all steps pass and 1 otherwise. On a failure the script prints the
failed step, the last 200 lines of `tenko.log`, the last 50 Event Log entries of the source
and the state of the service, and then cleans up. Read the output from the top: the first
line that starts with `FAILED` names the check that did not hold. Run again with `-Keep` to
keep the directory and the service for a closer look. Remove them afterwards with
`tenko service uninstall --name tenko-smoke` and by deleting the directory, or start the
script again, which removes them itself.

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
