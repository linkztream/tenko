# The Windows DHCP mirror

`Tenko-DhcpMirror.ps1` runs every minute on a Windows DHCP server, reads the DHCPv4
configuration and the active leases with the `DhcpServer` module, maps them onto Tenko's
migration IR and pushes the snapshot to a **mirror** on a Tenko controller. Nothing flows
the other way: Tenko opens no connection to the server, holds no Windows credential, and
the script acts on nothing but the HTTP status of the answer. The mirror feeds the diff,
the prepare and the takeover of a scope ([MIGRATION.md](../../../docs/MIGRATION.md),
[active-directory.md](../../../docs/active-directory.md); the design is
[docs/plans/windows-takeover-plan.md](../../../docs/plans/windows-takeover-plan.md),
sections 2.1 to 2.3).

Two files go to the server: the exporter and `Install-TenkoDhcpMirror.ps1`, which
registers the scheduled task. Both run on Windows PowerShell 5.1 and on PowerShell 7, use
the `DhcpServer` module and nothing else, and download nothing.

## Requirements

- Windows Server 2016 or later with the DHCP Server role, Windows PowerShell 5.1 (with
  .NET Framework 4.7.2 or later) or PowerShell 7.
- A Tenko controller with a mirror of kind `windows-dhcp` (created on the connectors
  page). The mirror card shows the three values the install needs: the mirror id, the
  token (shown once) and the SHA-256 fingerprint of the controller's certificate
  authority.
- An account for the task: a member of `DHCP Users` and of **no** privileged group. A group
  managed service account where the domain has a KDS root key (`CORP\gmsa-mirror$`, no
  password to keep), otherwise a user account with a long random password. The exporter
  refuses to push when its account is a member of `Domain Admins`, `Enterprise Admins`,
  `Administrators`, `DHCP Administrators` or `DnsAdmins`, or is SYSTEM, so a convenient
  misconfiguration fails loudly instead of running the task with rights it does not need.
  Registering the task grants the account the right to log on as a batch job.

## Installing

1. **Check the digests.** The two scripts are release assets, listed in `SHA256SUMS`
   of the release, which the owner's key signs ([SECURITY.md](../../../SECURITY.md),
   "Verifying a release"). Compare before copying:

   ```powershell
   Get-FileHash .\Tenko-DhcpMirror.ps1, .\Install-TenkoDhcpMirror.ps1 -Algorithm SHA256
   Select-String -Path .\SHA256SUMS -Pattern 'TenkoDhcpMirror|Tenko-DhcpMirror'
   ```

   Tenko never serves, generates or updates these files: what runs on the server is what
   you copied there (ADR 0023, the privilege boundary).

2. **Read the fingerprint from the mirror card**, not from anything sent over the network
   path the exporter will use. The install pins it; the exporter then accepts only a
   certificate chain that ends in that certificate authority, and adds nothing to the
   server's trust store.

3. **Install**, in an elevated PowerShell, from the directory holding both scripts:

   ```powershell
   .\Install-TenkoDhcpMirror.ps1 -Url https://tenko1.corp.example.test:8443 `
     -MirrorId 01JC3V9Q7E -Fingerprint 'AB:CD:...' -Account 'CORP\gmsa-mirror$' -PromptToken
   ```

   For a user account add `-Credential (Get-Credential CORP\svc-tenko-mirror)`. The
   install copies the exporter to `%ProgramFiles%\Tenko\mirror\` (administrators write,
   the task's account reads), writes `%ProgramData%\Tenko\mirror\config.json` with the URL,
   the mirror id and the fingerprint, creates the state directory
   `%ProgramData%\Tenko\mirror\state\` with an access list of SYSTEM, Administrators and the
   account only, runs one dry run under your own identity and prints the counts and the
   loss entries the first push will carry, registers the task `\Tenko\Tenko DHCP mirror`
   (every minute, "run whether the user is logged on or not", no highest privileges, a new
   instance is not started while one runs, five minutes at most), starts it once and
   prints the first log line.

   Run the install again to change the URL, the fingerprint or the token; it registers the
   task anew. Use `-PowerShell 'C:\Program Files\PowerShell\7\pwsh.exe'` to run the task
   under PowerShell 7 instead of Windows PowerShell.

## The token

The token is shown once on the mirror card. It can write this one mirror and nothing
else: every other operation of the API answers 403 to it, including reads of its own
mirror. It expires within the lifetime the profile allows and is replaced from the mirror
card; the old one stops at once.

The install never stores the token itself: it leaves it as `token.pending` in the state
directory, readable by the account and administrators only, and the exporter's first run
under the account stores it with DPAPI for that account (`ConvertFrom-SecureString`
without a key) as `token.dpapi` and deletes the plain file. No other account on the
server can decrypt it, administrators included. If the first run does not store it within
90 s, the install deletes the plain file and says so.

To replace the token, run the install again with `-PromptToken` (the other parameters as
before). The token never appears in the log, in the task's arguments or in the
configuration file.

## The fingerprint

The exporter accepts the controller only when the certificate chain it presents builds and
ends in the certificate whose SHA-256 fingerprint is pinned, and when the certificate
names the host of the URL. A chain to a publicly trusted root is refused as well: the pin
is the only trust. When the controller's certificate authority changes, the pushes fail
with the fingerprint the exporter saw in the log; compare it with the mirror card and run
the install again with the new one.

On Windows PowerShell 5.1 and on PowerShell 7 alike the check is a small C# class
compiled at start (`Add-Type`), because the TLS handshake calls back on a thread where a
PowerShell script block cannot run on PowerShell 7.

## The two commands at the takeover

The takeover of a scope in Tenko waits for a push that shows the Windows scope inactive
(plan section 2.7). The Windows side is one line per scope, run on the DHCP server:

```powershell
Set-DhcpServerv4Scope -ScopeId 192.0.2.0 -State InActive
```

The next push, within a minute, carries the leases Windows granted until it stopped
answering, and the takeover adopts them. The reverse, after Tenko's revert action:

```powershell
Set-DhcpServerv4Scope -ScopeId 192.0.2.0 -State Active
```

The mirror keeps running through the parallel period; a Windows scope that turns active
again while Tenko serves the network is an error finding on the mirror card.

## What is exported, and what is lost

Every minute, read-only, with these cmdlets and nothing else (the server's DNS credential
is never read):

| Cmdlet | Carried as |
|---|---|
| `Get-DhcpServerv4Scope` | `dhcp.scopes[]`: the network from `ScopeId` and `SubnetMask`, the name, the description, `active` from `State`, the lease time, the pool from `StartRange` and `EndRange`, `delay_ms` |
| `Get-DhcpServerv4ExclusionRange -ScopeId` | `exclusions[]` of the scope |
| `Get-DhcpServerv4Reservation -ScopeId` | `reservations[]`: the address, the client (a MAC address when `ClientId` is six octets, else the identifier octets), the name when it is a host name, the description, `bootp` |
| `Get-DhcpServerv4OptionValue -All`, `-ScopeId -All`, `-ReservedIP -All` | `server_options[]`, the scope's `options[]`, the reservation's `options[]`: code, vendor class, user class, the values as Windows writes them |
| `Get-DhcpServerv4OptionDefinition -All` | `option_defs[]`: the definitions of codes 128 to 254 and of vendor classes other than Microsoft's (the standard ones are Tenko's catalog) |
| `Get-DhcpServerv4Class` | `classes[]`, with `builtin` for the Microsoft and Default classes |
| `Get-DhcpServerv4DnsSetting -ScopeId` | `ddns` of the scope, by the table of [active-directory.md](../../../docs/active-directory.md) step 10 |
| `Get-DhcpServerv4Lease -ScopeId` | `leases[]` in the states `Active`, `ActiveReservation` and `Declined`, the expiry in UTC; `Expired` and `InactiveReservation` rows are left out |
| `Get-DhcpServerv4Policy`, `Get-DhcpServerv4Filter`, `Get-DhcpServerv4Superscope`, `Get-DhcpServerv4Failover` | The loss report only |

The envelope is `{format, sequence, taken_at, source, dhcp, losses}` (plan section 3.1).
`sequence` is the Unix time of the run, or one more than the last push when the clock went
back; the controller refuses an older or equal one. `taken_at` is the server's clock, in
UTC; the controller computes each lease's remaining time against it, so a clock difference
between the server and the controller does not change a lease. The source names the
server, the adapter and its version.

The **loss report** lists what Tenko does not take over, each entry with the cmdlet and the
object key it came from (`{sheet, column}`), so that nothing is dropped silently. The
mirror card shows it; an entry has to be acknowledged before a scope is prepared or taken
over, and the acknowledgment holds while the entry recurs unchanged.

| Code | Entry |
|---|---|
| `mirror.policy` | A policy, with its scope, order and conditions |
| `mirror.filter` | An allow or deny filter entry |
| `mirror.superscope` | A superscope and its member scopes; each scope is prepared alone |
| `mirror.failover` | A failover relationship (name, partner, mode, scopes); the shared secret is never read |
| `mirror.scope.delay` | A scope with an offer delay; Tenko has no offer delay |
| `mirror.scope.bootp`, `mirror.reservation.bootp` | A BOOTP-only scope or reservation |
| `mirror.reservation.name` | A reservation whose name is not a host name (a space, an apostrophe, a leading hyphen, a label above 63 characters); the name is kept as it is in the entry and the reservation is carried without one |
| `mirror.option.policy` | An option value a policy sets |
| `mirror.option.managed` | Option 58 or 59; Tenko computes T1 and T2 from the lease time (option 51 is carried as the lease time, not as an option) |
| `mirror.option_def.default`, `mirror.option_def.type` | A default value of a custom definition; a definition type Tenko has no kind for |
| `mirror.ddns.keep_on_expiry` | `DeleteDnsRROnLeaseExpiry` off; Tenko removes the records it wrote when the lease ends |
| `mirror.ddns.suffix` | A scope `DnsSuffix`; the IR carries none, set the forward zone in Tenko |
| `mirror.lease.state` | A lease in a state other than the three carried and the two left out |

## The dry run and the log

`.\Tenko-DhcpMirror.ps1 -Once` reads, maps and prints the whole snapshot as JSON on
standard output and pushes nothing; it needs no token and no configuration, and warns
instead of refusing when run by an administrator, since nothing leaves the server. Read it
to see exactly what the task will push:

```powershell
.\Tenko-DhcpMirror.ps1 -Once | Out-File snapshot.json -Encoding utf8
```

A task run writes one line to `%ProgramData%\Tenko\mirror\state\mirror-<date>.log` and
keeps seven days:

```text
2026-11-06T09:30:00Z seq=1794130200 scopes=1 reservations=30 leases=60 losses=13 hash=3f1a9c0b7e2d4a61 answer=200 changed=true duration_ms=812
```

`answer` is the HTTP status, `changed` what the controller decided (an unchanged snapshot
is pushed every minute and costs the controller nothing); a refusal adds `code` and
`detail` from the controller's answer (409 a replayed sequence, 413 above the bounds, 422
an IR that does not validate with the path of the first error, 429 faster than one push
per 10 s), and a failed connection adds `error`. The task's last result in Task Scheduler
is 0 for a push, 5 for a refusal, 6 for a failed connection or a controller error, 1 for a
failure before the push (the account, the configuration, the reads). The mirror card turns
stale after three missed minutes.

## Uninstalling

```powershell
.\Install-TenkoDhcpMirror.ps1 -Remove
```

unregisters the task and deletes `%ProgramFiles%\Tenko\mirror\` and
`%ProgramData%\Tenko\mirror\` (the configuration, the stored token, the state and the
log). Deleting the mirror in Tenko deletes its service account and token.

## Running the tests

The Pester 5 suites under `tests/` run on any host with PowerShell 5.1 or 7 and need no
DHCP server: the cmdlets are replaced by mocks that answer with the recorded output under
`tests/fixtures/` (one file per cmdlet and level, as `ConvertTo-Json -Depth 6` wrote it)
of the fictitious domain `corp.example.test` of plan section 3.4, with documentation
addresses only. The suites hold the mapping to `tests/fixtures/expected-snapshot.json`,
written from the types of `crates/tenko-core/src/ir.rs` and `ir/dhcp.rs`, push against a
local HTTP listener for every answer of the route, and check the account guard and the
certificate pin with certificates made in memory.

```powershell
Invoke-Pester -Path deploy/windows/mirror/tests -Output Detailed
deploy/windows/mirror/tests/Invoke-Analysis.ps1
```

`Invoke-Analysis.ps1` runs PSScriptAnalyzer with `PSScriptAnalyzerSettings.psd1` in two
passes, `PSUseCorrectCasing` apart from the other rules: in one pass, PSScriptAnalyzer
1.24.0 and 1.25.0 fail in about one call of two with an error of their own (a race between
that rule and the others in the analyzer's command cache), never with a finding. Exit code 1
means findings, exit code 2 a failure of the analyzer itself.

To record new fixtures from a lab server (never from a real one; nothing from a real
export enters the repository), run each cmdlet as the exporter does and write it with
`Select-Object -Property * -ExcludeProperty Cim*,PSComputerName | ConvertTo-Json -Depth 6`,
one file per call: `Get-DhcpServerv4Scope.json`, `Get-DhcpServerv4OptionValue.json` for the
server level, `Get-DhcpServerv4OptionValue-ScopeId-<scope>.json`,
`Get-DhcpServerv4OptionValue-ReservedIP-<address>.json`, and so on as `tests/Fixtures.ps1`
names them.
