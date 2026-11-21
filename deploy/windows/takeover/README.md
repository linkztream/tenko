# The Windows takeover script

`Tenko-Takeover.ps1` moves the DNS zones and the DHCP scopes of an Active Directory domain
from its Windows servers to Tenko DDI, one phase at a time, each phase reversible
(MIG-17, MIG-08; [ADR 0038](../../../docs/adr/0038-takeover-script-and-delegated-session.md)).
A domain administrator runs it, elevated, on a domain controller or on a privileged access
workstation of the domain. It uses the logon it runs under and asks for no credential. It
signs in to Tenko through an approval: it shows a code, and an administrator signed in to
Tenko's UI types that code on the page `https://<node>:8443/approve`, reads the plan the
script sent and approves it. Tenko never holds a Windows right, and the script never runs
text that Tenko sends: it checks every value against what Windows reports and uses it in
fixed commands.

The file comes from the release and nowhere else. No page of Tenko shows the script, a
command line or a digest to copy.

## Intake: a locked-down domain

A domain whose controllers and administrators' workstations do not reach the internet
brings the takeover files in with Tenko's own release, through the same intake:

1. On the connected intake machine, download from the release: `Tenko-Takeover.ps1`,
   `tenko-takeover-<version>.zip` and `SHA256SUMS`, with Tenko's own release files.
2. Run the intake check below in that folder (PowerShell 7 and the GitHub CLI `gh`). It
   verifies the release run's attestation of each file, compares each with `SHA256SUMS`,
   and only then writes the start line, with the verified digest built in, to
   `Start-Tenko.txt`.
3. Carry the files and `Start-Tenko.txt` in.

<!-- intake-check -->
```powershell
$version = (Get-ChildItem -Filter 'tenko-takeover-*.zip' | Select-Object -First 1).Name -replace '^tenko-takeover-|\.zip$', ''
$files = 'Tenko-Takeover.ps1', "tenko-takeover-$version.zip", 'SHA256SUMS'
foreach ($file in $files) {
    gh attestation verify $file --repo linkztream/tenko --signer-workflow linkztream/tenko/.github/workflows/release.yml
    if ($LASTEXITCODE -ne 0) { throw "the attestation of $file does not verify; nothing was written" }
}
$sums = @{}
foreach ($line in Get-Content -LiteralPath SHA256SUMS) { $hash, $name = $line -split '\s+', 2; $sums[$name.TrimStart('*')] = $hash }
foreach ($file in $files | Where-Object { $_ -ne 'SHA256SUMS' }) {
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $sums[$file]) { throw "$file does not match SHA256SUMS; nothing was written" }
}
$digest = (Get-FileHash -LiteralPath Tenko-Takeover.ps1 -Algorithm SHA256).Hash
$line = '$f="$env:ProgramFiles\Tenko\takeover\Tenko-Takeover.ps1"; if ((Get-FileHash $f -Algorithm SHA256).Hash -eq ''' + $digest + ''') { Unblock-File $f; powershell.exe -NoProfile -ExecutionPolicy Bypass -File $f } else { Write-Error (''Tenko-Takeover.ps1 does not match the release digest; nothing was run. Its SHA-256 is '' + (Get-FileHash $f -Algorithm SHA256).Hash) }'
Set-Content -LiteralPath Start-Tenko.txt -Value $line -Encoding ascii
$line
```
<!-- /intake-check -->

Inside the domain, on the controller or the workstation:

| Step | What you do |
|---|---|
| The file | Copy `Tenko-Takeover.ps1` to `%ProgramFiles%\Tenko\takeover` (only Administrators may write there; the script warns when its folder is writable by others). Through RDP's file redirection, or, where that is off, paste its text into Notepad and save it there: the file is ASCII with CRLF line ends, so the saved copy has the released bytes. |
| The start | In an elevated PowerShell, paste the line of `Start-Tenko.txt`. It hashes the file, compares the digest with the one it carries, and only then unblocks and starts it; otherwise it names the digest it found and runs nothing. |

For the archive, which an organization signs (below), check it first, with cmdlets only, so
that it runs in Constrained Language too:

```powershell
$z = 'tenko-takeover-<version>.zip'; if ((Get-FileHash $z).Hash -ne ((Select-String -Path SHA256SUMS -SimpleMatch $z).Line -split ' ')[0]) { throw 'digest differs' }; Expand-Archive $z -DestinationPath .\tenko-takeover
```

### Where application control enforces script rules

The scripts carry no Authenticode signature. Where AppLocker or App Control for Business
enforces script rules, PowerShell runs a script the policy does not allow in Constrained
Language, and this script then stops with exit 1 at its first line, because it needs Full
Language (it builds the TLS chain, signs with the run's key and hashes through .NET). Sign
the archive's three scripts with the organization's own code-signing certificate, so that
the policy allows them:

```powershell
Get-ChildItem .\tenko-takeover\*.ps1 | Set-AuthenticodeSignature -Certificate <the organization's certificate>
```

Then run `powershell.exe -NoProfile -File .\tenko-takeover\Tenko-Takeover.ps1` under the
domain's own execution policy. The script uses the signed exporter and installer beside it
when their text before the signature block is the release's (it carries their digests),
and its embedded copies otherwise; it refuses a copy beside it whose text differs.

Where a group policy sets the execution policy (**Turn on Script Execution**), it overrides
the line's `-ExecutionPolicy Bypass`: with **Allow only signed scripts** PowerShell says the
file is not digitally signed, with script execution off it says that running scripts is
disabled. Sign the scripts as above, or run on a host where the domain's policy allows
local scripts. The execution policy is not a security boundary; the digest check of the
line is what proves the file.

## Other ways the file arrives

| Way | Fit | What you do |
|---|---|---|
| The fetch, on a host that reaches the release page | A privileged access workstation with internet access | Paste the fetching form of the release notes: it creates the folder, downloads the file with `curl.exe` and then runs the start line. Windows Server 2016 has no `curl.exe`: use `Invoke-WebRequest -UseBasicParsing -OutFile` with the same URL, then the start line. |
| RDP from a connected everyday workstation | Not suitable for a domain administrator's session: the file and its digest both come from one ordinary workstation, and whatever can change that workstation's clipboard can change the line's digest with it | Download the file and copy the line from the release notes there, paste the file on the controller as above, then the line. |

On an open network the line from the release notes is as strong as the account that
publishes the releases. For the stronger check, on any machine:
`gh attestation verify Tenko-Takeover.ps1 --repo linkztream/tenko --signer-workflow linkztream/tenko/.github/workflows/release.yml`.

## What it needs

- Windows PowerShell 5.1 with .NET Framework 4.7.2 or later, elevated, as a member of the
  domain's Domain Admins. It sets its module path to the system's module directories only.
- WinRM (HTTP, port 5985) to every domain controller and to the member server the exporter
  runs on, with Kerberos. Every session goes to the host's name as Active Directory reports
  it, never to an address, never through a second hop; the script changes no WinRM,
  firewall or CredSSP setting. A privileged access workstation needs no Remote Server
  Administration Tools: every Windows cmdlet runs in a session on a server that has it.
- HTTPS to Tenko's own TLS on the API port (8443 unless written `host:port`). Behind a
  reverse proxy that ends TLS the code cannot match and the run does not start; the script
  says so when the root it reached is one this machine's own store trusts.
- Tenko of the same version as the script (`GET /api/v1/health`).

## What you type

Started without a parameter, the script asks for the domain (the joined one is offered),
for the member server the exporter runs on (from the domain's member servers), and for
Tenko's address, as a host name under the domain (`tenko.corp.example.test`), whose first
label is the node's name in the zones. A resumed run reads the domain and the address from
its state file. You confirm by typing the domain's name: the change list before the first
change, the window before phase 4 (the script shows who started it and when, according to
Tenko), the silence again when more than fifteen minutes have passed since, and the finish.

| Parameter | What it does |
|---|---|
| none | Runs or resumes the next phase; when a run exists, offers to reverse its latest phase instead |
| `-DryRun` | Discovers and prints the change list and the warnings; changes nothing on Windows and contacts no Tenko |
| `-Reverse` | Undoes the latest phase done or failed, both halves; run again to walk one more phase back |

## The phases

| Phase | Windows | Tenko | Reverse |
|---|---|---|---|
| 0. Discover | Reads only: the domain, the controllers, their zones with each server's transfer and notify lists and serials, the DHCP servers, scopes and failover relationship, the member computers that are DHCP clients, and the settings a compromised DNS authority could use (shown as warnings) | None | None |
| 1. Approval | None | The request with the plan and the run's key; the code; the delegated session | The session ends with the script |
| 2. Prepare, nothing served | Backups (`Export-DhcpServer -Leases`, `Export-DnsServerZone`) into the state directory; the exporter's account in `DHCP Users` and the exporter's task per DHCP server on the member server; Tenko added to the transfer and notify lists on the PDC emulator only; the DHCP DNS credential where the servers differ; Tenko's computer account where a zone takes secure updates; the group policy object `Tenko takeover: DNS client registration off` for the member computers | The mirrors first (within five minutes of the approval), the secondary zones (not served), the forwarding rules (inactive), the pairing, the first pushes, the prepare | Everything of the phase removed, the lists restored from the state file |
| 3. Review | None | You start the window on the run page; the script waits | None |
| 4. DNS window | Each DHCP server's configuration compared with the one the window bound (leases are not); replication forced; per zone, `_msdcs` last: the PDC emulator's copy converted to a secondary of Tenko and the other controllers' added at once, each set to refuse transfers; the controllers register | A transfer, the copy compared with every controller's records, then the flip, forward zones first | The PDC emulator's zone made directory-integrated again through a file-backed primary, its update setting set back and read back (a zone left open to unsigned updates fails the reverse); then each other controller loads the directory copy; Tenko's flip back |
| 5. DHCP window | The manual restore lines printed; the DHCP Server service (`DHCPServer`, never the DHCP client) stopped and disabled on both servers, the silence read back; both authorizations removed, replication forced, the removal read back on each controller's replica | The takeover of each scope: final pushes, adoption with Tenko's scopes off, then Tenko's scopes on after the script completes the job's task | Tenko's scopes silent first; the leases written into both servers (addresses, client identifiers and ends only, inside the pool, outside exclusions and others' reservations); the authorization added back and read back; conflict detection on; the service's start type restored and the service started |
| 6. Finish, after the parallel period | The DHCP role removed from both servers without starting the service, the database directory moved into the backup; the exporter, its tasks, account and batch logon right removed; the DNS credential user removed when the script created it; the plan's zone objects deleted from the directory partitions | The frozen names released; the mirrors deleted | The role back from the backup, its groups replicated, the relationship again; the authorization stays removed |

The DHCP window refuses while a DHCPv6 or multicast scope exists that Tenko does not take
over, while a group policy sets the start mode of `DHCPServer`, or while a scope's lease
time is under an hour. A domain with a zone that takes secure updates only is refused in
phase 0 until a release whose notes say the Kerberos line is complete.

To bring a Windows DHCP server back by hand, the script prints before the silence, and you
run for each server:

```powershell
Add-DhcpServerInDC -DnsName <server> -IPAddress <address>
Set-Service DHCPServer -StartupType Automatic; Start-Service DHCPServer
```

After the takeover every client's renewal ends in a broadcast that whichever server answers
first can take: DHCP snooping or a DHCP guard on the switches keeps a rogue server out.

## The state, the exit codes and a failed step

The state file is `%ProgramData%\Tenko\takeover\<domain>\state.json`, readable by SYSTEM
and Administrators only, beside the backups. It holds the plan, each step's state and the
values the reverse restores, and no password, token, session or code. The script holds it
locked while it runs, and records its run on the PDC emulator under
`HKLM\SOFTWARE\Tenko\Takeover`; a second run finds either and stops. The reverse restores a
value only when the discovery recorded it (exit 4 otherwise), and a later sitting compares
the DC locator's answer and the controllers' addresses with the discovery's before it opens
any session.

| Exit | Meaning |
|---|---|
| 0 | The phase is done |
| 1 | Refused before any change (a precondition, a right missing, you declined) |
| 2 | Stopped at a failed step, named in the state file: run again to resume there, or `-Reverse` |
| 3 | Waiting for the review or for the parallel period |
| 4 | A value from Tenko disagreed with Windows; nothing further was changed |
| 5 | Reversed |

When Tenko cannot be reached, `-Reverse` offers the Windows half alone, after a warning
that a node whose API is unreachable may still serve DHCP; Tenko's half is recorded in the
state file as pending.

## The tests

Pester 5.7.1 on Windows PowerShell 5.1 and PowerShell 7, with a fake domain and a fake
Tenko (`tests/Fake.ps1`), a TLS server on a loopback port (`tests/TestTls.ps1`) and the
approval's test vector (`tests/fixtures/approval-code.json`, the same as
`crates/tenko-auth/tests/fixtures/approval-code.json`):

```powershell
Invoke-Pester -Path deploy/windows/takeover/tests
deploy/windows/takeover/tests/Invoke-Analysis.ps1
```

`build/New-TakeoverRelease.ps1` makes the release files; CI runs it on every change to
refuse a script that is not ASCII with CRLF line ends.
