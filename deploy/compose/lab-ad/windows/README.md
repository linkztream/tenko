# The Windows interop lab (E44)

Exit check E44 of the identity plan ([identity-plan.md](../../../../docs/plans/identity-plan.md)
section 1.2, API-18): Tenko DDI as the DNS server of a real Windows Server domain, with secure
dynamic updates (GSS-TSIG) from two domain controllers, a member server and a Windows 11
client. The container lab next to this directory proves the protocol against Samba; only real
Windows shows what Windows does (risks R120, R121 and R134). This lab is owner-run with the
lead: the owner runs each step, the lead reads the result with the owner and decides the next.

It is also the first run of the runbook end to end ([active-directory.md](../../../../docs/active-directory.md)
sections 4 to 6): the throwaway domain starts as an ordinary domain with the DNS Server role on
its first controller, and the steps move its zones to Tenko by a zone file import, as an
operator would. (Once the in-place flip of a secondary zone exists, the takeover plan replaces
the import by it; it does not exist yet, so this lab does not use it.)

Each step has what to run, what you should see, and what to keep. Every command block can be
pasted as it is into an elevated PowerShell (or a shell on the Tenko node, where marked). Write
each result into [RESULTS.md](RESULTS.md) and put each file named under **Keep** into
`results/` here; packet captures go to `captures/`. The lead commits them after reading them.

## The names, and why they are fixed

Build the throwaway domain with exactly these names and addresses. They are documentation
names (RFC 6761 `.test`, RFC 5737 `192.0.2.0/24`), so the captures, exports and logs of the
lab can be committed as they are, and nothing of a real domain ever reaches the repository.
Do not run any step against a real domain, and never commit a capture of one.

| What | Name | Address |
|---|---|---|
| The forest and its only domain | `corp.example.test`, NetBIOS `CORP`, realm `CORP.EXAMPLE.TEST` | |
| First domain controller, Windows Server 2022 or 2025 | `dc1.corp.example.test` | `192.0.2.5` |
| Second domain controller, never with the DNS Server role | `dc2.corp.example.test` | `192.0.2.6` |
| Member server with a static address | `srv1.corp.example.test` | `192.0.2.20` |
| Windows 11 client | `pc1.corp.example.test` | `192.0.2.30` (static, or a DHCP lease whose option 6 is `192.0.2.53`) |
| The Tenko node (Linux or Windows), roles `controller,dns` | `ns1.corp.example.test` | `192.0.2.53` |
| A static record created by an administrator | `printer1.corp.example.test` | `192.0.2.40` |
| The reverse zone | `2.0.192.in-addr.arpa` | |

One isolated virtual network, `192.0.2.0/24`, with no route to any other network except, if
you need it for updates, through a NAT of the hypervisor. The gateway is `192.0.2.1`. Every
machine's clock follows the first controller (Kerberos allows five minutes of skew): the
domain members do by default; give the Tenko node `dc1` as its NTP server.

## What you need

- Windows Server 2022 or 2025 installation media for two controllers and the member server,
  and Windows 11 Pro or Enterprise for the client (Home cannot join a domain).
- The Tenko node built from the commit under test (its version is the first line of
  RESULTS.md), set up with an administrator account, the `dns` module on, the profile
  **Standard** to begin with (step W9 moves it to Hardened). On the node, `tenko` on the
  PATH and a terminal with an administrator's session (`tenko login`).
- `pktmon` on the Windows machines (in the box); Wireshark on any machine where you read the
  captures (optional; the lead reads them too).
- A folder `C:\lab` on each Windows machine for what you keep.

## W0. The Tenko node

On the node, check its version, its profile and its roles, and that the DNS role answers on
`192.0.2.53`:

```
tenko --version
tenko system diagnostics
dig @192.0.2.53 ns1.corp.example.test A
```

**Expect:** the version of the commit under test; the diagnostics name the profile
`standard`, the roles `controller,dns` and the module `dns`, and no health finding; `dig`
answers (REFUSED or NXDOMAIN is fine before W4: the server answers). **Keep:** the outputs in
`results/w0-node.txt`.

## W1. The domain, as an operator has it before the takeover

On `dc1` (a fresh Windows Server, static address `192.0.2.5`, DNS client pointing at
itself), create the forest with the DNS Server role, as a domain is usually built:

```powershell
Rename-Computer -NewName dc1 -Restart
```

After the restart:

```powershell
Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools
Install-ADDSForest -DomainName corp.example.test -DomainNetbiosName CORP -InstallDns:$true `
  -SafeModeAdministratorPassword (Read-Host -AsSecureString 'Directory services restore password')
```

After the restart, sign in as `CORP\Administrator`. Create the reverse zone, turn aging on
for the three zones (the import of W4 reads the aging timestamps to tell dynamic records
from static ones), add one static record, and have the controller register again so that
its records carry a timestamp:

```powershell
Add-DnsServerPrimaryZone -NetworkId 192.0.2.0/24 -ReplicationScope Domain -DynamicUpdate Secure
foreach ($zone in 'corp.example.test', '_msdcs.corp.example.test', '2.0.192.in-addr.arpa') {
  Set-DnsServerZoneAging -Name $zone -Aging $true
}
Add-DnsServerResourceRecordA -ZoneName corp.example.test -Name printer1 -IPv4Address 192.0.2.40 -CreatePtr
ipconfig /registerdns
nltest /dsregdns
Start-Sleep -Seconds 60
```

Join `srv1` (static address `192.0.2.20`, DNS client `192.0.2.5`) to the domain now, so that
the takeover has a member server's dynamic records to carry over:

```powershell
# On srv1, as its local administrator.
Rename-Computer -NewName srv1 -Restart
# After the restart:
Add-Computer -DomainName corp.example.test -Credential CORP\Administrator -Restart
# After the restart, signed in as CORP\Administrator:
ipconfig /registerdns
```

**Expect:** `Resolve-DnsName srv1.corp.example.test -Server 192.0.2.5` answers `192.0.2.20`.

## W2. The starting state

On `dc1`:

```powershell
New-Item -ItemType Directory -Force C:\lab | Out-Null
Get-DnsServerZone | Format-Table ZoneName, ZoneType, IsDsIntegrated, ReplicationScope, DynamicUpdate -AutoSize |
  Out-File C:\lab\w2-zones.txt
foreach ($zone in 'corp.example.test', '_msdcs.corp.example.test', '2.0.192.in-addr.arpa') {
  Get-DnsServerResourceRecord -ZoneName $zone |
    Select-Object HostName, RecordType, Timestamp, TimeToLive, @{ n = 'Data'; e = { $_.RecordData | Out-String } } |
    Export-Csv -NoTypeInformation "C:\lab\w2-records-$zone.csv"
  dnscmd /ZoneExport $zone "$zone.dns"
  Copy-Item "$env:SystemRoot\System32\dns\$zone.dns" C:\lab\
}
Get-DnsServerDsSetting | Format-List TombstoneInterval, DirectoryPartitionAutoEnlistInterval | Out-File C:\lab\w2-ds.txt
Copy-Item "$env:SystemRoot\System32\config\netlogon.dns" C:\lab\w2-netlogon-dc1.dns
Select-String -Path C:\lab\*.dns -Pattern '\[AGE:' | Measure-Object | Select-Object Count
dcdiag /test:dns /v > C:\lab\w2-dcdiag-before.txt
```

**Expect:** the CSV files list the controller's records and `srv1` with a `Timestamp`, and
`printer1` without one (static); the export files hold lines with `[AGE:n]` (the count is
above zero). If no record has a timestamp, aging was not on when they registered: run
`ipconfig /registerdns` and `nltest /dsregdns` again, wait a minute and repeat this step.
**Keep:** everything in `C:\lab` (copy it to `results/w2/`). The export files are the first
real Windows zone files of the project; the tests of the import read them later.

**Answer in RESULTS.md (R121):** does a record registered while aging was off get a
timestamp at its next refresh once aging is on? What is `TombstoneInterval` (how long
Windows keeps a deleted name, and its owner, as a tombstone)?

## W3. Tenko's Kerberos account (the PowerShell block of WP13.3)

This is the run of the block of [active-directory.md](../../../../docs/active-directory.md)
section 4.1 that WP13.3 left to this lab. On a management host with the RSAT Active Directory
module, or on `dc1`, as `CORP\Administrator`:

1. Save the block from section 4.1 of the documentation **of the commit under test** as
   `C:\lab\New-TenkoAccount.ps1`, read it, and record its hash:

   ```powershell
   (Get-FileHash C:\lab\New-TenkoAccount.ps1 -Algorithm SHA256).Hash
   New-ADOrganizationalUnit -Name 'Service Accounts' -Path 'DC=corp,DC=example,DC=test'
   ```

2. Run it and type the values at its prompts (do not paste them): the account name
   `TENKO-DNS`, the organizational unit `OU=Service Accounts,DC=corp,DC=example,DC=test`, the
   SPN `DNS/ns1.corp.example.test`, then an empty line, and a one-time password twice.

   ```powershell
   powershell -NoProfile -File C:\lab\New-TenkoAccount.ps1
   ```

3. In Tenko: **DNS, Kerberos**, *Adopt a pre-staged account*: the realm
   `CORP.EXAMPLE.TEST`, the account `TENKO-DNS$`, the SPN `DNS/ns1.corp.example.test`, the KDCs
   `192.0.2.5`, and the one-time password. Or on the node:

   ```
   tenko dns kerberos adopt CORP.EXAMPLE.TEST 'TENKO-DNS$' --spn DNS/ns1.corp.example.test --kdc 192.0.2.5
   tenko dns kerberos status
   ```

4. The one-time password no longer works, on `dc1`:

   ```powershell
   Get-ADComputer TENKO-DNS -Properties msDS-KeyVersionNumber, msDS-SupportedEncryptionTypes, servicePrincipalName, PasswordLastSet |
     Format-List Name, msDS-KeyVersionNumber, msDS-SupportedEncryptionTypes, servicePrincipalName, PasswordLastSet
   ```

**Expect:** the block prints the realm, the account name, the SPN and encryption types `24`;
the adopt answers with the account, version `N+1` where `N` was the version the block set,
and no finding; `tenko dns kerberos status` shows the same version as
`msDS-KeyVersionNumber`; `PasswordLastSet` is the minute of the adopt. **Keep:** the hash,
the block's output, the status, in `results/w3-account.txt` (no password anywhere).

If the block refuses a value or stops with an error, write down the message: the block is
static and versioned, so a fix goes into the documentation and the lab runs it again.

## W4. The zones on Tenko, by import

The runbook's steps 2 to 4. On the node, copy the three export files of W2 to the node
(any way you like) and import each into a primary zone in the Windows dialect, first as a dry
run:

```
tenko dns zone create corp.example.test --kind primary --ns ns1.corp.example.test \
  --mname ns1.corp.example.test --rname hostmaster.corp.example.test --serial date_counter
tenko dns zone create _msdcs.corp.example.test --kind primary --ns ns1.corp.example.test \
  --mname ns1.corp.example.test --rname hostmaster.corp.example.test --serial date_counter
tenko dns zone create 2.0.192.in-addr.arpa --kind primary --ns ns1.corp.example.test \
  --mname ns1.corp.example.test --rname hostmaster.corp.example.test --serial date_counter
for zone in corp.example.test _msdcs.corp.example.test 2.0.192.in-addr.arpa; do
  tenko dns import "$zone" "$zone.dns" --windows --dry-run
done
```

**Expect** for each zone: the records per type, the list under `would become claimable by
their hosts (origin ad)`, one line per RRset with the computer account that may claim it, then
`approve exactly these with: --approve-claimable <digest>`, then the list under `kept static`
with the reason of each name, and as losses at most the SOA (kept as the zone's values) and
WINS records if any. In the domain zone the claimable names are the dynamic A records of the
members and the servers (`pc1`, `srv1` and the like); in the reverse zone, their PTR records;
in `_msdcs` the locator names are held back as `reserved`, and a name that is a name server of
the zone (`ns1`, or a controller's host name that is an NS host of the zone) is held back as
`name_server`: it comes in static, and a controller is privileged and still changes it. Read
each list and check that every name in it is a computer you expect, and that every name you
do not want claimed is in the held-back list (narrow the set with `--claimable-under`,
`--claimable-within` or `--claimable-except` and run the dry run again if not). Then import
for real, approving the list you read, and give the domain zone the name server's address and
the delegation of `_msdcs` to Tenko. The loop takes each zone's digest from its own dry run;
that is only safe after you have read the lists above:

```
for zone in corp.example.test _msdcs.corp.example.test 2.0.192.in-addr.arpa; do
  digest=$(tenko dns import "$zone" "$zone.dns" --windows --dry-run --json | jq -r .claimable_digest)
  tenko dns import "$zone" "$zone.dns" --windows --approve-claimable "$digest"
done
tenko dns record replace corp.example.test ns1 A 192.0.2.53
tenko dns record replace corp.example.test _msdcs NS ns1.corp.example.test.
tenko dns record replace corp.example.test @ NS ns1.corp.example.test.
tenko dns record replace _msdcs.corp.example.test @ NS ns1.corp.example.test.
tenko dns record replace 2.0.192.in-addr.arpa @ NS ns1.corp.example.test.
tenko dns record list corp.example.test --origin ad
tenko dns record list corp.example.test --origin manual
```

The import takes the file's SOA values, which name `dc1`; set `mname` back to the node on each
zone (a Windows client sends its update to the server the SOA names):

```
for zone in corp.example.test _msdcs.corp.example.test 2.0.192.in-addr.arpa; do
  tenko dns zone update "$zone" --mname ns1.corp.example.test --rname hostmaster.corp.example.test
done
```

Then the secure-only policy (runbook step 4): the SIDs come from `dc1`:

```powershell
(Get-ADDomain).DomainSID.Value
(Get-ADGroup DnsAdmins).SID.Value
(Get-ADGroup DnsUpdateProxy).SID.Value
```

In each zone's **Settings, Dynamic updates**: an access list `ad-corp` with one Kerberos entry
for `CORP.EXAMPLE.TEST`, *Require a signature* on, and **Secure updates (Kerberos)** on: the
realm, ownership *Windows rules*, owner hold 14 days, the privileged groups `<domain SID>-512`,
`-516`, `-519` (the *Domain SID* button adds the three) and the DnsAdmins SID, and the
DnsUpdateProxy SID. The same through the API:

```
POST /api/v1/dns/acls
{"name": "ad-corp", "entries": [{"kind": "kerberos", "realm": "CORP.EXAMPLE.TEST"}]}

PATCH /api/v1/dns/zones/{id}
{"update": {"allowed": ["<the list's id>"], "require_tsig": true, "may_replace_ipam": false,
  "kerberos": {"realms": ["CORP.EXAMPLE.TEST"], "ownership": "windows", "owner_hold_days": 14,
    "privileged": ["<domain SID>-512", "<domain SID>-516", "<domain SID>-519", "<DnsAdmins SID>"],
    "update_proxy": "<DnsUpdateProxy SID>"}}}
```

**Expect:** `record list --origin ad` shows exactly the names of the lists you approved
(`srv1` and the other members' and servers' records); `--origin manual` shows `printer1`, the
zone's apex records and the names held back with their reasons (the controller's host name when
it is an NS host of the zone, `wpad` and `isatap` if the zone has them). The zone's **Owners**
tab is empty: nothing is owned until a secure update claims it. **Keep:** the dry-run reports
and the two record lists in `results/w4-import.txt`, a screenshot of the update settings in
`results/w4-settings.png`.

## W5. The first controller registers with GSS-TSIG (the early probe of R120)

The first secure update a Windows controller sends to Tenko. On `dc1`, point the DNS client
at Tenko only, capture, and register:

```powershell
$adapter = (Get-NetIPAddress -IPAddress 192.0.2.5).InterfaceAlias
Set-DnsClientServerAddress -InterfaceAlias $adapter -ServerAddresses 192.0.2.53
Clear-DnsClientCache
pktmon filter remove
pktmon filter add -p 53
pktmon filter add -p 88
pktmon start --capture --pkt-size 0 -f C:\lab\w5-dc1.etl
ipconfig /registerdns
nltest /dsregdns
Restart-Service Netlogon
Start-Sleep -Seconds 120
pktmon stop
pktmon etl2pcap C:\lab\w5-dc1.etl -o C:\lab\w5-dc1.pcapng
nltest /dsquerydns
nltest /dsgetdc:corp.example.test /force
Get-WinEvent -LogName System -MaxEvents 200 |
  Where-Object { $_.ProviderName -in 'NETLOGON', 'Microsoft-Windows-DNS-Client' } |
  Format-List TimeCreated, Id, Message | Out-File C:\lab\w5-events.txt
```

Then check every record of the controller's `Netlogon.dns` against Tenko (this block reads
the file and asks Tenko for each record; it changes nothing):

```powershell
$server = '192.0.2.53'
$missing = @()
foreach ($line in Get-Content "$env:SystemRoot\System32\config\netlogon.dns") {
  $fields = $line -split '\s+'
  if ($fields.Count -lt 5 -or $fields[2] -ne 'IN') { continue }
  $name, $type = $fields[0].TrimEnd('.'), $fields[3]
  $want = ($fields[4..($fields.Count - 1)] -join ' ').TrimEnd('.')
  $got = Resolve-DnsName -Name $name -Type $type -Server $server -DnsOnly -NoHostsFile -ErrorAction SilentlyContinue
  $text = ($got | ForEach-Object {
      switch ($_.Type) {
        'SRV' { "$($_.Priority) $($_.Weight) $($_.Port) $($_.NameTarget)" }
        'A' { $_.IPAddress }
        'AAAA' { $_.IPAddress }
        'CNAME' { $_.NameHost }
        default { $_.ToString() }
      } }) -join '|'
  if (-not ($text -split '\|' | Where-Object { $_.TrimEnd('.') -eq $want })) { $missing += "$name $type $want" }
}
"records not in Tenko: $($missing.Count)"
$missing
```

In Tenko's **Audit log**, filter the actions `dns.update.apply`, `dns.update.refuse` and
`dns.gss.refuse` (or `GET /api/v1/audit?action=dns.update.apply&limit=50`, and the same for
the other two), and read the update counters on the node:

```
curl -s http://127.0.0.1:9100/metrics | grep -E 'tenko_dns_(tkey|updates)_total'
```

(The metrics address is the node's `[metrics] listen`; use yours.)

**Expect:** `records not in Tenko: 0`; `nltest /dsquerydns` reports success for every record;
no NETLOGON event 5774 or 5781 after the restart; `dns.update.apply` records with the
principal `DC1$@CORP.EXAMPLE.TEST`, its SID and the decision `privileged`; no refusal. The
zone's **Owners** tab lists `dc1.corp.example.test` owned by `DC1$` (`created`), and no
locator name. **Keep:** the capture `captures/w5-dc1.pcapng`, the events, the nltest outputs
and the audit lines in `results/w5/`.

**Answer in RESULTS.md (R120)**, from the capture and the node's counters:

| Question | Where it shows |
|---|---|
| Does Windows send TKEY over TCP only, and its updates over UDP or TCP? | The capture's transports |
| Which mechanisms does it offer in SPNEGO, and does the negotiation take one TKEY leg? | The TKEY query's key data; `tenko_dns_tkey_total{outcome="continue"}` |
| Does it accept the signed TKEY answer and sign its update on the same context? | An update follows the TKEY answer without a new TKEY |
| Does it reuse a context for several updates, and for how long? | Several updates under one key name |
| Is any update refused, and why? | `dns.update.refuse` and its reason |

## W6. The DNS Server role leaves the first controller

The runbook's step 9, once W5 passes: the domain no longer needs the role.

```powershell
Uninstall-WindowsFeature -Name DNS -Restart
```

After the restart:

```powershell
Get-Service DNS -ErrorAction SilentlyContinue
nltest /dsregdns
nltest /dsquerydns
dcdiag /test:dns /v > C:\lab\w6-dcdiag.txt
```

**Expect:** no DNS service; the registration and its check succeed against Tenko.
`dcdiag /test:dns`: the registration and delegation tests pass; the tests that ask the
Windows DNS Server service itself (its configuration, its forwarders) cannot pass without the
role; write down which fail and compare with `w2-dcdiag-before.txt`. **Keep:**
`results/w6-dcdiag.txt`.

## W7. A second controller, without the DNS Server role

`dc2` (static address `192.0.2.6`, DNS client `192.0.2.53` only) is promoted without the role:

```powershell
Rename-Computer -NewName dc2 -Restart
# After the restart:
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSDomainController -DomainName corp.example.test -InstallDns:$false `
  -Credential (Get-Credential CORP\Administrator) `
  -SafeModeAdministratorPassword (Read-Host -AsSecureString 'Directory services restore password')
```

After the restart, sign in as `CORP\Administrator` on `dc2` and run the capture and the
`Netlogon.dns` check of W5 with `dc2` in the file names (`C:\lab\w7-dc2.etl`).

**Expect:** the promotion succeeds through Tenko (it finds `dc1` by its SRV records);
`records not in Tenko: 0` for `dc2`; the audit has `DC2$@CORP.EXAMPLE.TEST`, decision
`privileged`; `dc2.corp.example.test` owned by `DC2$`. `nltest /dsgetdc:corp.example.test
/force` on `srv1` finds either controller. `repadmin /replsummary` on `dc1` shows no error.
**Keep:** `captures/w7-dc2.pcapng`, the outputs in `results/w7/`.

## W8. The hourly registration

Netlogon registers its records again every hour. Leave the lab running for at least 70
minutes with a capture on `dc1`, then look:

```powershell
pktmon filter remove
pktmon filter add -p 53
pktmon start --capture --pkt-size 0 -f C:\lab\w8-dc1.etl
Start-Sleep -Seconds 4200
pktmon stop
pktmon etl2pcap C:\lab\w8-dc1.etl -o C:\lab\w8-dc1.pcapng
```

On the node, the zones' serials (`tenko dns zone list`, before and after the hour), and in
the **Audit log** the `dns.update.apply` records of the last 75 minutes.

**Expect:** within the hour, each controller sends its updates again (in the capture: TKEY
when its context is gone, then the updates), every update is answered NOERROR, and an update
that re-sends the same records writes nothing: the serials of the zones do not move for a
pure refresh, and the audit holds no `dns.update.apply` for it. **Keep:**
`captures/w8-dc1.pcapng` (it may be large: keep the first ten minutes after the refresh if
so), `results/w8.txt`.

## W9. Secure only, by group policy, and the Hardened profile

On `dc1`, a group policy object linked to the domain that sets the DNS client's update
security level to *Only secure* (`UpdateSecurityLevel` = 256):

```powershell
New-GPO -Name 'Lab DNS secure only' | New-GPLink -Target 'DC=corp,DC=example,DC=test'
Set-GPRegistryValue -Name 'Lab DNS secure only' -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' `
  -ValueName UpdateSecurityLevel -Type DWord -Value 256
Invoke-GPUpdate -Computer dc1 -Force
Invoke-GPUpdate -Computer dc2 -Force
Invoke-GPUpdate -Computer srv1 -Force
```

On the node, the profile moves to **Hardened** (Settings, Security profile; read what it
changes first). Then on each controller and on `srv1`:

```powershell
gpresult /r /scope computer | Select-String 'Lab DNS secure only'
ipconfig /registerdns
nltest /dsregdns
nltest /dsquerydns
```

**Expect:** the policy is applied; every registration succeeds, as GSS-TSIG is what they use
already; under Hardened the zones' ownership is on whatever the zone says, and an unsigned
update is refused. **Keep:** `results/w9.txt`.

## W10. A Windows 11 client joins the domain through Tenko

`pc1` (Windows 11, address `192.0.2.30`, DNS server `192.0.2.53` only). Capture its join and
its first registration:

```powershell
Rename-Computer -NewName pc1 -Restart
# After the restart, in an elevated PowerShell:
New-Item -ItemType Directory -Force C:\lab | Out-Null
pktmon filter remove
pktmon filter add -p 53
pktmon filter add -p 88
pktmon start --capture --pkt-size 0 -f C:\lab\w10-pc1.etl
Add-Computer -DomainName corp.example.test -Credential CORP\Administrator
```

Do not restart from the prompt yet; restart from the Start menu, sign in as
`CORP\Administrator`, wait two minutes, then:

```powershell
pktmon stop
pktmon etl2pcap C:\lab\w10-pc1.etl -o C:\lab\w10-pc1.pcapng
ipconfig /all
nltest /dsgetdc:corp.example.test /force
Resolve-DnsName pc1.corp.example.test -Server 192.0.2.53
Resolve-DnsName 192.0.2.30 -Server 192.0.2.53
```

(The capture stops at the restart; `pktmon start` again right after the sign-in if the first
registration is to be in it, with `-f C:\lab\w10-pc1-after.etl`.)

**Expect:** the join finds a controller through Tenko and succeeds; after the restart `pc1`
registers its A record (and its PTR record when no DHCP server registers it) with GSS-TSIG as
`PC1$`; both answer; the **Owners** tab lists `pc1.corp.example.test` and
`30.2.0.192.in-addr.arpa` owned by `PC1$`. **Keep:** `captures/w10-pc1*.pcapng`, the outputs
in `results/w10.txt`.

## W11. The member server registers and refreshes its records

`srv1` carried its records over from Windows in W4 (origin `ad`, claimable by `SRV1$`, since
its name was in the list you approved there). Point
its DNS client at Tenko and register:

```powershell
$adapter = (Get-NetIPAddress -IPAddress 192.0.2.20).InterfaceAlias
Set-DnsClientServerAddress -InterfaceAlias $adapter -ServerAddresses 192.0.2.53
ipconfig /registerdns
Start-Sleep -Seconds 30
ipconfig /registerdns
```

On the node, and the last `dns.update.apply` records in the **Audit log**:

```
tenko dns record list corp.example.test --name srv1
tenko dns record list 2.0.192.in-addr.arpa --name 20
```

**Expect:** the first registration claims the imported names: `srv1.corp.example.test` and
`20.2.0.192.in-addr.arpa` are owned by `SRV1$`, `claimed` (the Owners tab); the second is a
refresh: NOERROR, nothing written, the owner unchanged. **Keep:** `results/w11.txt`.

## W12. Another computer cannot overwrite them

`pc1` takes `srv1`'s address while `srv1` is off, and tries to register:

```powershell
# On srv1:
Stop-Computer
# On pc1, elevated:
$adapter = (Get-NetIPAddress -IPAddress 192.0.2.30).InterfaceAlias
New-NetIPAddress -InterfaceAlias $adapter -IPAddress 192.0.2.20 -PrefixLength 24
ipconfig /registerdns
Start-Sleep -Seconds 30
Get-WinEvent -LogName System -MaxEvents 50 |
  Where-Object { $_.ProviderName -eq 'Microsoft-Windows-DNS-Client' } |
  Format-List TimeCreated, Id, Message
Remove-NetIPAddress -IPAddress 192.0.2.20 -Confirm:$false
```

On the node, and the last `dns.update.refuse` records in the **Audit log**:

```
tenko dns record list 2.0.192.in-addr.arpa --name 20
```

**Expect:** `pc1` adds `192.0.2.20` to its own name, which it owns; its update of the PTR name
`20.2.0.192.in-addr.arpa`, owned by `SRV1$`, is refused (`dns.update.refuse`, the owner named
in the reason), and the PTR record still points at `srv1`; the DNS client logs a
registration failure (event 8018 or 8020). Start `srv1` again afterwards. **Keep:**
`results/w12.txt`.

## W13. A restart of the Tenko node mid-day

Contexts live in memory: a restart drops them. With every machine registered, restart the
Tenko service on the node, then capture on `pc1` and `dc1` while they register:

```
sudo systemctl restart tenko          # Linux
Restart-Service Tenko                 # a Windows node, elevated
```

```powershell
pktmon filter remove
pktmon filter add -p 53
pktmon start --capture --pkt-size 0 -f C:\lab\w13.etl
ipconfig /registerdns
nltest /dsregdns     # on the controllers only
Start-Sleep -Seconds 60
pktmon stop
pktmon etl2pcap C:\lab\w13.etl -o C:\lab\w13-<machine>.pcapng
```

**Expect:** each machine's first update after the restart is answered NOTAUTH with BADKEY
(the context is gone); it negotiates again with TKEY, and the update succeeds; nothing is
refused for ownership (the owners are in the store, not in the contexts). **Keep:**
`captures/w13-dc1.pcapng`, `captures/w13-pc1.pcapng`, `results/w13.txt`.

## W14. The health of the domain

On `dc1` and `dc2`:

```powershell
dcdiag /test:dns /v > C:\lab\w14-dcdiag.txt
dcdiag > C:\lab\w14-dcdiag-all.txt
repadmin /replsummary > C:\lab\w14-repl.txt
```

**Expect:** `dcdiag /test:dns` passes its registration and delegation tests; any failure of a
test that needs the DNS Server role on a controller is listed by name in RESULTS.md as known.
The default tests and the replication summary show no error. **Keep:** the three files of
each controller in `results/w14/`.

## W15. Optional extensions

- **A child domain** (R134): a child domain `child.corp.example.test` with its own controller
  and its own zone on Tenko (its realm in the zone's Kerberos settings). Not part of the exit;
  record what you see.
- **DNS name scavenging**: Tenko does not scavenge yet (DNS-29); nothing to run.
- **A Windows DHCP server registering for its clients**: not part of this lab; the runbook
  says to give it a dedicated user account for its DNS credentials.

## Afterwards

Copy `C:\lab` of each machine into `results/` (one folder per machine) and the `.pcapng`
files into `captures/`, fill in RESULTS.md, and hand both to the lead. The lab domain is
thrown away afterwards; its keys never leave it, and its captures hold nothing that opens
anything else.
