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
$line = '$f=[Environment]::GetFolderPath(''ProgramFiles'')+''\Tenko\takeover\Tenko-Takeover.ps1''; if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -eq ''' + $digest + ''') { Unblock-File -LiteralPath $f; & "$PSHOME\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $f } else { Write-Error (''Tenko-Takeover.ps1 does not match the release digest; nothing was run. Its SHA-256 is '' + (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash) }'
Set-Content -LiteralPath Start-Tenko.txt -Value $line -Encoding ascii
$line
```
<!-- /intake-check -->

Inside the domain, on the controller or the workstation:

| Step | What you do |
|---|---|
| The file | Copy `Tenko-Takeover.ps1` to `%ProgramFiles%\Tenko\takeover` (only Administrators may write there; the script warns when its folder is writable by others). Through RDP's file redirection, or, where that is off, paste its text into Notepad and save it there: the file is ASCII with CRLF line ends, so the saved copy has the released bytes. |
| The start | Open `powershell.exe -NoProfile` with **Run as administrator**, on a controller or a privileged access workstation that no ordinary account uses (code an ordinary account runs on the same host can reach an elevated process through its profile and its environment), and paste the line of `Start-Tenko.txt`. It hashes the file, compares the digest with the one it carries, and only then unblocks and starts it; otherwise it names the digest it found and runs nothing. The line names the folder and PowerShell as the platform names them, never through an environment variable. |

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
  domain's Domain Admins. Its first statement sets its module path to the system's module
  directories, as the platform names them, before any command can load a module.
- WinRM (HTTP, port 5985) to every domain controller and to the member server the exporter
  runs on, with Kerberos. Every session goes to the host's name as Active Directory reports
  it, never to an address, never through a second hop; the script changes no WinRM,
  firewall or CredSSP setting. A privileged access workstation needs no Remote Server
  Administration Tools: every Windows cmdlet runs in a session on a server that has it.
- HTTPS to Tenko's own TLS on the API port (8443 unless written `host:port`). Behind a
  reverse proxy that ends TLS the code cannot match and the run does not start; the script
  says so when the root it reached is one this machine's own store trusts.
- On both editions the pin and the code bind a chain that the platform verified by its
  signatures, from the node's leaf to the root the person approved: an interceptor's chain
  ends in another root and fails on both. That the node itself presented that root in the
  handshake holds on Windows PowerShell 5.1 only. PowerShell 7 hands the script the chain
  the platform built, which may take an authority from this machine's certificate stores;
  there no issuer is fetched from a URL the leaf names, while on 5.1 only a Group Policy
  setting stops that fetch. Windows PowerShell 5.1 is the supported and lab-tested runtime.
- Tenko of the same version as the script (`GET /api/v1/health`).

## What you type

Started without a parameter, the script asks for the domain (the joined one is offered);
shows the DHCP servers of that domain (only those whose computer object names the address
the authorization list gives; any other entry is shown as a warning and never contacted, and
a listed name whose computer object a domain user made under the machine account quota stops
the run) and asks you to confirm them with `y` before it opens a session to any (Enter
declines);
asks for the member server
the exporter runs on (from the domain's member servers), and for Tenko's address, as a host
name under the domain (`tenko.corp.example.test`), whose first label is the node's name in
the zones: a name no computer account or service principal name of the domain holds, and
that resolves to the node only. A resumed run reads the domain and the address from its
state file. You confirm by typing the domain's name: the change list before the first
change, the DNS window before phase 4 (the script shows who started the window and when,
according to Tenko), the finish, and, in the reverse of phase 4, the records Tenko added
(below). The DHCP window has its own one confirmation, right before anything is stopped: a
choice of Abort (the default, which changes nothing) or Continue, as a dialog where the host
has one, that says what happens next (the DHCP Server service stopped and disabled on the
named servers, Tenko answering their scopes at once, the authorizations removed right after
and reaching every controller within some minutes) and how to go back (`-Reverse`).

On Tenko's approval page the person types or pastes the code the script shows, once. An
approval that is denied or withdrawn, or whose approving administrator signed out everywhere,
was disabled or lost the administrator role before the script collected it, is never
collected: the script says so and offers a new approval with a new code (`y`; anything else
ends the sitting with nothing collected). Where a zone takes secure updates, the plan the
approval page shows names Tenko's computer account: the realm, `<NODE>$` and its service
principal name.

The first sitting, from the start to the parallel period, asks seven answers at the console:
three values (the domain, or Enter for the joined one; the mirror host's number; Tenko's
address) and four confirmations (`y` for the DHCP servers; the domain's name for the change
list and for the DNS window; Continue for the DHCP window), and the code once on Tenko's
approval page.

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
| 2. Prepare, nothing served | Refused before any change while the release's installer lacks the parameters of the scripted install (`-ComputerName`, `-SkipDryRun`); backups (`Export-DhcpServer -Leases`, `Export-DnsServerZone`) into the state directory; the exporter's account in `DHCP Users` and the exporter's task per DHCP server on the member server; Tenko added to the transfer and notify lists on the PDC emulator only; the DHCP DNS credential where the servers differ; Tenko's computer account where a zone takes secure updates; the group policy object `Tenko takeover: DNS client registration off` for the member computers | The mirrors first (within five minutes of the approval), the secondary zones (not served), the forwarding rules (inactive), the pairing, the first pushes, the prepare | Everything of the phase removed, the lists restored from the state file |
| 3. Review | None | You start the window on the run page; the script waits | None |
| 4. DNS window | Each DHCP server's configuration compared with the one the window bound (leases are not); replication forced; per zone, `_msdcs` last: the PDC emulator's copy converted to a secondary of Tenko and the other controllers' added at once, each set to refuse transfers; the controllers register | A transfer, the copy compared with every controller's records, then the flip, forward zones first | First each zone on the PDC emulator is cut loose from Tenko: its secondary becomes a file-backed primary that takes no transfer, notify or update. Then those copies are compared with the records read at the flip, counted per zone and type, and every difference is shown by name and type. Typing the domain's name keeps that version, except at the records that steer authentication or hand a subtree away (everything at or under `_msdcs`, `_tcp`, `_udp`, `_sites`, `DomainDnsZones` and `ForestDnsZones`, the `_kerberos`, `_kpasswd`, `_ldap` and `_gc` names, every NS and DNAME below the apex, the apex's A, AAAA, NS, CNAME and DNAME, every wildcard, the controllers' own addresses, and the A and AAAA of a name server the zone names or of a name below a delegation), which go back to their flip-time records unless each name is typed too; anything else, or a difference there in a type the script cannot write back, restores the export of phase 2 (put in place under its own name and checked by its SHA-256 first, so that a stop halfway is finished by the next reverse). The start of authority goes back to its flip-time names. What the copy then holds is compared record by record with what was shown, every time to live and the start of authority's timers included (they are not shown, and come as the copy held them), and only then is it made directory-integrated in the partition the discovery read (a zone that was not directory-integrated, or whose partition the script cannot name, is refused in phase 0), its update setting set back and read back (a zone left open to unsigned updates fails the reverse); then each other controller loads the directory copy; Tenko's flip back |
| 5. DHCP window | After the takeover's final pushes and adoption, the one confirmation (Abort or Continue); the manual restore lines printed; the DHCP Server service (`DHCPServer`, never the DHCP client) stopped and disabled on both servers and the silence read back on each (if it cannot be read back, both services are started again as they were and Tenko stays off); then the job's task completed, so Tenko answers at once; then both authorizations removed, replication forced, the removal read back on each controller's replica every 5 s for up to five minutes. A replica that has not caught up by then does not stop the run: the barrier is recorded as pending, a warning names the controllers, and the check step and every later sitting read it again until it holds (the services stay stopped and disabled meanwhile) | The takeover of each scope: final pushes, adoption with Tenko's scopes off, then Tenko's scopes on as soon as the script completes the job's task, right after the silence is read back | Tenko serves until Windows is ready: each service's start type restored and the service started while its server is still unauthorized (it serves nobody, its cmdlets answer); the leases written into both servers (addresses, client identifiers and ends only, inside the pool, outside exclusions and others' reservations) and read back; conflict detection on (at least 1, or the value the discovery read; it is not set back afterwards); the authorization added back, replicated and read back on each controller (each read-back repeats for up to five minutes); only then Tenko's scopes silent and each service restarted, event 1044 read back. A revert in Tenko or a restart that fails leaves one side for every scope: every Windows server the reverse started is stopped and disabled again and read back, and only then are Tenko's scopes on again. When Tenko does not answer that call (three tries), when the session has ended (the next sitting's approval opens a new one), or when Tenko refuses it for the takeover itself (that refusal stands: the next reverse brings Windows back without asking again), the script says that no server answers the scope and what to run next |
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

The state file is `%ProgramData%\Tenko\takeover\<domain>\state.json`, beside the backups.
Every level below `%ProgramData%` is created owned by Administrators with SYSTEM and
Administrators alone in its access list, set as it is created; a level another account owns
or may write, or a link, stops the script with exit 1. Inside the state folder a file may
also be owned by the elevated user that runs the script, as files are where the policy
"Default owner for objects created by members of the Administrators group" is "Object
creator". As owner that user may change those files' access lists, also from a process that
is not elevated: code that runs as the same account is out of the script's reach anyway,
which is why the host must be one only its administrators use. On the servers the script works only in `Tenko\takeover` below the Program Files
folder the server names in its own registry (`<drive>:\Program Files`, nothing else), under
the same rule: every level owned by SYSTEM or Administrators and written by them alone. A
payload is hashed again from its bytes right before it runs. The state holds the plan, each
step's state, the values the reverse restores, the record sets read at the flip, the
servers this run stopped, the secret of the run's marks, and the SID of every account the run
created; it holds no password, token, session or code. Each object the run creates carries
its own mark in its description: SHA-256 over that secret and the object's name, so that a
mark anyone can read fits no other name. The secret is recorded before the run creates its
first object, so that a sitting that ended between a creation and the record of its SID
knows the object as its own; but only while no one made it under the machine account quota,
the Domain Admins of the domain own it, and no one outside the closed list may write it. An
account, a computer account or a group policy object of the run's name that fails any of
this is refused with exit 1 and never removed; the reverse removes objects by their recorded
SID.
The script holds the state locked while it runs, and records its run on the PDC emulator
under `HKLM\SOFTWARE\Tenko\Takeover` before the approval, read back; a second run finds
either and stops. The reverse restores a value only when the discovery recorded it, and a
controller's address only when this sitting's own discovery reports it (exit 4 otherwise),
and a later sitting compares the DC locator's answer and the controllers' addresses with the
discovery's before it opens any session. A later sitting does not read a DHCP server whose
service this run stopped; it takes what the state file recorded of it.

The delegated session's secret and the passwords the script makes are held as SecureStrings
and never reach a cmdlet, so that module logging and transcription do not record them; while
they are used they are in the process's memory, which the page file or a crash dump of an
elevated process can hold.

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

## What the lab still has to confirm

- That the lease writes (`Add-DhcpServerv4Lease`) and `Set-DhcpServerSetting` work on a
  server whose DHCP Server service runs while it is not authorized, which the reverse of the
  DHCP window relies on; and that a running unauthorized server keeps serving nobody until
  its restart.
- That event 1044 is logged within a minute of the restart of an authorized server.
- That Windows PowerShell 5.1 hands the callback the certificates the server presented
  (`ChainPolicy.ExtraStore`). Where that list is empty on 5.1 the script refuses the
  connection with a sentence that says so; only PowerShell 7 takes the chain the platform
  built.
- Whether building the chain on 5.1 fetches an issuer from a URL in the leaf, and which
  policy stops it there.
- Which attributes the creator of a computer account made under the quota may write on
  Server 2025 (`description`, `msDS-SupportedEncryptionTypes`), and what
  `ConvertTo-DnsServerPrimaryZone -ReplicationScope -Force` does when a `dnsZone` object of
  that name already exists in the partition.
- The format of the `dhcpServers` values on each controller's replica, whose name field the
  read-back compares whole, and that `Add-DhcpServerInDC` and `Remove-DhcpServerInDC` are
  needed only once (the script reads `Get-DhcpServerInDC` first and acts only when needed).
- That `Select-String` reads the UTF-16 `GptTmpl.inf`, and the group names `DHCP Users`
  and `Authenticated Users` the cmdlets take on a localized controller.
- That `ConvertTo-DnsServerSecondaryZone` removes the zone object from the directory; that
  `ConvertTo-DnsServerPrimaryZone -ZoneFile` makes the secondary a file-backed primary that
  takes no transfer from Tenko; that `Add-DnsServerPrimaryZone -LoadExisting` loads the
  export of phase 2 under its new name and reports that name as `ZoneFile`; and that the
  start of authority is set with `Clone()` and `Set-DnsServerResourceRecord` in a remote
  session in Constrained Language.
- That `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion` `ProgramFilesDir` names the Program
  Files folder on every server, and the SDDL each server reports for the script's folders.

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
