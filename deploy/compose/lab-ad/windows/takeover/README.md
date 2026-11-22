# The Windows lab's takeover line (E77)

The rehearsal of the Windows takeover ([windows-takeover-plan.md](../../../../../docs/plans/windows-takeover-plan.md)
sections 2.13 and 2.15, exit check E77): the lab domain of [the counted line](../README.md) starts
as a Windows-first domain, with Windows DNS and Windows DHCP on both controllers and a failover
relationship between the DHCP servers, and moves to Tenko step by step, each step with its reverse:
by hand in phases 2 to 5, and by the takeover script of the plan's section 2.16 in phase 6, which
also measures what the operator must do (E146).
The counted line and its 43 entries are not touched; the two lines never run at the same time.

The names and addresses are those of the counted line, plus the admin workstation:

| What | Name | Address |
|---|---|---|
| Controllers, both with the DNS Server and DHCP Server roles in this line | `dc1`, `dc2` | `192.0.2.5`, `192.0.2.6` |
| Member server, static | `srv1` | `192.0.2.20` |
| Windows 11 client, by DHCP: a reservation for the first run, a pool lease later | `pc1` | `192.0.2.30` (reserved) |
| The admin workstation of the inside observer, outside the snapshots | `adm1` | `192.0.2.40` (the counted line's static record `printer1` names the same address; its PTR stays `printer1`) |
| The Tenko node | `ns1` | `192.0.2.53` |

## The actors and their channels

- **The operator** builds the machines, takes and restores snapshots, and runs step scripts on
  the lab machines and commands on `ns1`, as the counted line's job does.
- **The inside observer** is a session on `adm1` (Windows 11, joined, with the Remote Server
  Administration Tools for Active Directory, DHCP, DNS and group policy; WinRM to the lab's
  servers). Every entry it runs is a read. It makes a change only after its own user approves
  that change; the only changes in this manifest are those of phase 6, the scripted takeover. It
  never signs in to `ns1`'s API; in phase 6 its user signs in to the UI.
- **The lead** decides between entries and reads the evidence.

No secret travels on the channels between them. Passwords and tokens live in files that only
SYSTEM (Windows, `C:\lab\secrets\`) or root (`ns1`, `/root/lab/secrets/`, mode 600) reads, as in the
counted line; a mirror's token is made on `ns1` and reaches its controller as such a file through
the operator's tooling, never through a message.

Evidence: each entry's files go to `results/<entry>/` beside this file (the operator's step
directories, and the observer's files from `C:\lab\takeover\<entry>\` on `adm1`). Nothing secret,
nothing from any domain but the lab's.

## The start state

Snapshots are linear today: a rollback removes every later snapshot on all guests. The line
therefore starts from the counted line's snapshot taken before `08-w03-ns1-adopt` (it holds W0
to W2 and `07-w03-dc1-account`: `dc1` a controller with Windows DNS and the three AD-integrated
zones, `srv1` joined, `TENKO-DNS$` pre-staged, `dc2` and `pc1` neither promoted nor joined, `ns1`
under Standard with the roles `controller,dns`), builds forward with entries T03 to T10, and is
thrown away when the counted line rolls back. Switching lines costs about five minutes plus the
rebuild. The line's own snapshot `tk-start` (T13) spares the rebuild within the line; the next
counted run's rollback removes it, and T03 to T10 build it again.

The scope, made on `dc1` and replicated to `dc2` by the relationship:

| Setting | Value |
|---|---|
| Scope | `192.0.2.0/24`, range `192.0.2.10` to `192.0.2.250`, lease time 8 hours |
| Exclusions | `192.0.2.10` to `192.0.2.29` and `192.0.2.31` to `192.0.2.99` (the static hosts); the pool is `192.0.2.100` to `192.0.2.250` |
| Options | 3 `192.0.2.1`; 6 `192.0.2.5, 192.0.2.6` (after the flip `192.0.2.53, 192.0.2.5, 192.0.2.6`); 15 `corp.example.test` |
| Reservations | `pc1` at `192.0.2.30` by its MAC address; `nas01` at `192.0.2.100` and `Living Room TV` at `192.0.2.101`, both for documentation MAC addresses (`00-00-5e-00-53-01`, `-02`), so that the mirror carries a bare name and a name that is no host name |
| DNS | always update A and PTR, name protection on, records removed when a lease ends |
| Failover | `dc1-dc2`, load balance 50 percent, MCLT one hour, automatic state transition after one hour, no shared secret (the cmdlet takes it as a plain argument, which the lab's secret rule forbids; the exporter never reads it) |

The profile is Standard until T28 and Hardened from then on, as the owner's cutover will be.
Under Hardened an administrator signs in with a passkey only and no script acts as `admin`
(counted line, "Signing in to Tenko without a person"), so every entry after T28 that writes on
`ns1` needs the operator's passkey path (below). The takeover script of phase 6 acts on `ns1` only
through a session that an administrator approves with a passkey, not as a script signed in alone.

## The manifest

"When" says whether an entry runs with the first package as built (**now**: the exporter, the
mirror, the freshness, the diff, the loss report) or waits for a package of the plan (WP14.1a,
WP14.2, WP14.4) or for the operator's dynamic-lease tooling (**pool**). **B** marks the basic
set of the first run (sixteen entries). An entry ending in `r` is the reverse of the entry or
phase it names.

### Phase 0. Preconditions

| # | Actor | Action | Check, expected | Evidence | When |
|---|---|---|---|---|---|
| T01 | operator | On `ns1`: `ss -H -lunp 'sport = :67 or sport = :68 or sport = :547'` | Nothing listens (read on 2026-11-20: none) | `ports.txt` | now, B |
| T02 | operator | On `adm1`: `Get-NetIPInterface -AddressFamily IPv4 \| Select-Object InterfaceAlias, Forwarding` | `Disabled` on every adapter (read on 2026-11-20); repeated before T05 | `forwarding.txt` | now, B |

### Phase 1. The Windows-first start state

| # | Actor | Action | Check, expected | Evidence | When |
|---|---|---|---|---|---|
| T03 | operator | Restore the counted line's snapshot before `08-w03-ns1-adopt` | `Get-DnsServerZone` on `dc1`: the three zones AD-integrated; `Get-ADDomainController -Filter *`: `dc1` only; on `ns1` `tenko system diagnostics`: profile `standard`, roles `controller,dns` | `start.txt` | now, B |
| T04 | operator | On `dc2`: `Install-ADDSDomainController -DomainName corp.example.test -InstallDns:$true` (DNS client `192.0.2.5`, credentials from the secret files, `-NoRebootOnCompletion`), restart; DNS clients of both controllers: the partner first, then itself | `repadmin /replsummary`: no failure; `Get-DnsServerZone -ComputerName dc2`: the three zones, AD-integrated; `nltest /dsgetdc:corp.example.test /force` on `srv1` finds a controller | `promote.txt`, `replsummary.txt`, `zones-dc2.txt` | now, B |
| T05 | operator | On `dc1`: `Install-WindowsFeature DHCP -IncludeManagementTools` (about a minute, no restart, measured on 2026-11-20), `Add-DhcpServerSecurityGroup`, `Add-DhcpServerInDC` with the server's name and address, the role's configuration marked complete, the service restarted; then `repadmin /syncall /AdeP`, and only then the same on `dc2` (run on both at once, `Add-DhcpServerSecurityGroup` creates conflicting duplicate groups, measured) | `Get-DhcpServerInDC`: exactly `dc1` and `dc2`; `DHCP Users` and `DHCP Administrators` exist once each | `indc.txt`, `groups.txt` | now, B |
| T06 | operator | On `dc1`: the scope of the table above (`Add-DhcpServerv4Scope`, `Add-DhcpServerv4ExclusionRange` twice, `Set-DhcpServerv4OptionValue -Router -DnsServer -DnsDomain`, `Set-DhcpServerv4DnsSetting -DynamicUpdates Always -NameProtection $true -DeleteDnsRROnLeaseExpiry $true`, `Add-DhcpServerv4Reservation` three times, `pc1`'s MAC address read on `pc1` with `Get-NetAdapter`) | `Get-DhcpServerv4Scope`, `...ExclusionRange`, `...OptionValue -ScopeId 192.0.2.0`, `...Reservation`, `...DnsSetting` show the table | `scope-dc1.txt` | now, B |
| T07 | operator | On `dc1`: `Add-DhcpServerv4Failover -Name dc1-dc2 -PartnerServer dc2.corp.example.test -ScopeId 192.0.2.0 -LoadBalancePercent 50 -MaxClientLeadTime 01:00:00 -AutoStateTransition $true -StateSwitchInterval 01:00:00` | `Get-DhcpServerv4Failover` on both: `Normal`, `LoadBalance`; `Get-DhcpServerv4Scope -ComputerName dc2` and its reservations equal `dc1`'s (measured on 2026-11-20: the creation copies the scope, its options and reservations at once; later a state or a new reservation does not follow by itself, `Invoke-DhcpServerv4FailoverReplication -Force` carries both within about five seconds) | `failover.txt`, `scope-dc2.txt` | now, B |
| T08 | operator | On `pc1`: DHCP on (`Set-NetIPInterface -Dhcp Enabled`, the static address and gateway removed, `Set-DnsClientServerAddress -ResetServerAddresses`), `ipconfig /renew`, a capture of the exchange with `pktmon`; then `Add-Computer -DomainName corp.example.test`, restart | `ipconfig /all`: DHCP enabled, `192.0.2.30`, DHCP server `192.0.2.5` or `.6`, DNS servers `.5` and `.6`; after the restart `nltest /sc_query:corp.example.test` succeeds; `Get-DhcpServerv4Lease -IPAddress 192.0.2.30` on both: `ActiveReservation`; on `dc1` `pc1` has an A, a PTR and a DHCID record, and which of `pc1` and the DHCP server wrote the A record is noted | `ipconfig.txt`, `dora.pcapng`, `leases.txt`, `records.txt` | now, B |
| T09 | operator | On `adm1`: the repeatable domain join, the lab adapter up, and the name resolution policy for `corp.example.test` and `2.0.192.in-addr.arpa` (`Add-DnsClientNrptRule`) pointing at the phase's DNS target: `192.0.2.5, 192.0.2.6` until T34, `192.0.2.53` from then on (the parameter of this entry) | `Resolve-DnsName dc2.corp.example.test` answers `192.0.2.6` through the target | `nrpt.txt` | now, B |
| T10 | inside observer | The start-state reading: controllers, operation masters and global catalogs; per controller the zones and their SOA serials; `Get-DhcpServerInDC`; per DHCP server the scope, exclusions, options at server, scope and reservation level, reservations, DNS settings, `Get-DhcpServerDnsCredential` (the user name only), `Get-DhcpServerSetting`, the relationship, and `Get-DhcpServerv4Lease -AllLeases`; `Export-DhcpServer -Leases` of each server to `adm1` | The table above holds on both servers; the export files exist (the backup of the plan's step 1) | `inventory-*.txt`, `export-dc1.xml`, `export-dc2.xml` | now, B |
| T11 | operator | The DHCP servers' DNS credential as the plan's WT-Q13 decides: a dedicated lab user `dhcp-dns` as the DNS credential on both servers, from the secret `dhcp_dns_password`, set with `Set-DhcpServerDnsCredential` | `Get-DhcpServerDnsCredential` on both names `CORP\dhcp-dns`; `ipconfig /renew` on `pc1` and the DNS server's audit of the update (`Get-WinEvent` of the DNS server log) show the update under that account | `credential.txt` | now, B |
| T12 | operator | Optional: a second Windows client takes a pool lease | A lease in `192.0.2.100` to `.250` on both servers | `client2.txt` | pool |
| T13 | operator | Snapshot `tk-start` of every guest (the line's own, linear) | The snapshot exists; later entries return to it instead of rebuilding | `snapshot.txt` | now |
| T13r | operator | Reverse of phase 1: restore the counted line's snapshot or `tk-start` | T03's or T10's readings again | `restore.txt` | now |

### Phase 2. Tenko beside Windows, serving nothing

| # | Actor | Action | Check, expected | Evidence | When |
|---|---|---|---|---|---|
| T14 | operator | On `dc1`, for the three zones: `Set-DnsServerPrimaryZone -SecureSecondaries TransferToSecureServers -SecondaryServers 192.0.2.53 -Notify NotifyServers -NotifyServers 192.0.2.53` | The settings read on `dc1`; on `dc2` they stay as they were, since the lists are kept per server in its registry and never replicate (measured on 2026-11-20); only `dc1` is Tenko's primary | `transfer-allow.txt` | now, B |
| T15 | node | Three secondary zones with `source.primaries` `192.0.2.5` only (`POST /dns/zones`, plan section 2.15), then `tenko dns transfer now` | `tenko dns transfer status`: each serial equals `dc1`'s; the RRsets equal `dc1`'s `Get-DnsServerResourceRecord`; `pc1`'s A and DHCID with the origin `transfer` (the Windows half of E15, carried) | `zones.json`, `compare.txt` | now, B |
| T16 | inside observer | The SOA serial of each zone on `dc1` and on `dc2`, twice an hour apart | Recorded for R217: each server keeps its own serial and names itself as primary (measured on 2026-11-20) | `serials.txt` | now |
| T16a | operator, inside observer | After T14 and T15: a test record written on `dc2` only (`Add-DnsServerResourceRecordA -ComputerName dc2.corp.example.test`), no forced replication; `dc1`'s serial and `ns1`'s copy watched until the record is there, then the record removed | `dc1` raises its serial when it loads the record at its directory poll (expected about 180 s after the write, measured on 2026-11-20), and `ns1` holds it within that plus the zone's SOA `refresh` (NOTIFY not relied on); the time and whether `dc1` sent a NOTIFY (a capture on `ns1`) recorded for R217 | `replicated-write.txt`, `notify.pcapng` | now |
| T17 | node | Two mirrors: `tenko migrate mirror create dc1-dhcp --source 192.0.2.5/32` and `dc2-dhcp --source 192.0.2.6/32`; each token written by root to its secret file, never printed | `tenko migrate mirror list`: both enabled, never pushed; `migrate.mirror.create` audited twice; the certificate authority's fingerprint read from the card | `mirrors.json`, `fingerprint.txt` | now, B |
| T18 | operator | On `dc1` and `dc2`: the lab user `dhcp-mirror` (password from `dhcp_mirror_password`, a member of `DHCP Users` only, batch logon on the controllers by the Default Domain Controllers Policy); the scripts of `deploy/windows/mirror/` at the commit under test, their digests compared with `Get-FileHash` against the lead's list (the release does not ship them yet); `Tenko-DhcpMirror.ps1 -Once`; `Install-TenkoDhcpMirror.ps1 -Url https://192.0.2.53:8443 -MirrorId <id> -Fingerprint <fp> -Credential <dhcp-mirror> -Token <the token file as a SecureString>` | `-Once`: one scope, three reservations, `pc1`'s lease, the loss entries `mirror.failover` and `mirror.reservation.name`; on `ns1` within two minutes both mirrors fresh, `source.server` `dc1.corp.example.test` and `dc2.corp.example.test`, equal counts, one `migrate.mirror.push` each and none for unchanged pushes; the task logs `answer=200` | `once-dc1.json`, `once-dc2.json`, `cards.json`, `audit.json`, the tasks' logs | now, B |
| T19 | node | The losses of each mirror, then `tenko migrate mirror ack` of every entry with the printed sequence | The two entries per mirror; the failover entry belongs to every scope; `losses_open` 0 on both after the ack | `losses-*.json` | now |
| T20 | node | `tenko migrate diff dc1-dhcp 192.0.2.0/24` and the same for `dc2-dhcp` | Rows `create` for the prefix, the pool, both exclusions, options 3, 6 and 15, the three reservations and DDNS; the two diffs equal but for the mirror's id | `diff-*.json` | now, B |
| T21 | operator | On `dc2`: the exporter's task disabled (`Disable-ScheduledTask`) | After 180 s `dc2-dhcp` stale and `migrate.mirror.stale` names it; `dc1-dhcp` fresh | `stale.json` | now |
| T21r | operator | The task enabled again | `dc2-dhcp` fresh within two intervals; the finding gone | `fresh.json` | now |
| T22 | operator | On `dc1` only: `Add-DhcpServerv4Reservation` at `192.0.2.102` (a documentation MAC address) | `dc1-dhcp`'s push changes (audited), `dc2-dhcp`'s does not; the two diffs differ by that reservation; with WP14.1a the diff of each shows it as a `partner` row to decide | `drift.json` | now; the partner row WP14.1a |
| T22r | operator | The reservation removed on `dc1` | The diffs equal again | `drift-back.json` | now |
| T23 | operator | `dc2` shut down cleanly | On `dc1` the relationship goes to `CommunicationInterrupted` (read by the observer); `pc1`'s `ipconfig /renew` answered by `192.0.2.5`; `dc2-dhcp` stale after 180 s | `partner-down.txt` | now |
| T23r | operator | `dc2` started | `Normal` again; `dc2-dhcp` fresh; `pc1`'s lease on both servers | `partner-back.txt` | now |
| T24 | node | `tenko node roles set <ns1> --roles controller,dns,dhcp` with the `dhcp` module | `ns1` restarts; no enabled scope; `pc1`'s `ipconfig /renew` still answered by a controller; Tenko's DHCP counters show no offer; whether port 67 is bound is recorded | `roles.txt`, `metrics.txt` | now |
| T25 | operator | Both exporters installed with one mirror's id (a deliberate misconfiguration, R219) | The second server's pushes refused with `migrate.mirror.source` and audited | `source.json` | WP14.1a |
| T26 | operator, node | The counted entries `08-w03-ns1-adopt`, `09-w03-dc1-account-check` and `10-w04-dc1-sids`, unchanged | As in the counted line | their step directories | now |
| T27r | operator, node | Reverse of phase 2: `Install-TenkoDhcpMirror.ps1 -Remove` on both, the mirrors and the secondary zones deleted, the transfer permission removed on `dc1` | Nothing of Tenko on the controllers; no mirror, no zone on `ns1` | `removed.txt` | now |

### Phase 3. The Hardened profile and the DNS flip

| # | Actor | Action | Check, expected | Evidence | When |
|---|---|---|---|---|---|
| T28 | operator, node | The counted entries `26-w09-dc1-policy` and `27-w09-ns1-hardened`, unchanged | Their checks; the dry run names no mirror token; both mirrors keep pushing (bound to their /32), and no `migrate.mirror.unbound` | their step directories, `cards.json` | now |
| T29 | operator | The lease time on both servers left at 8 hours or raised back to it (`Set-DhcpServerv4Scope -ComputerName` each); the plan no longer lowers it, since the remaining lease time is the margin of the silent window (plan section 2.17) | Each mirror's push audited as a changed configuration when it changed; `pc1`'s lease follows at its renewal | `lease-time.txt` | now |
| T30 | operator, node | On `dc1` `repadmin /syncall /AdeP`; on `ns1` `tenko dns transfer now` | The serials on `ns1` equal `dc1`'s; `dc2`'s latest registrations are in the copy | `sync.txt` | now |
| T31 | node | `tenko dns zone flip corp.example.test --to primary` with `ns1`'s SOA and NS | The origins of plan section 2.6: `pc1`'s A and DHCID `transfer`, the locator records and both controllers' A records `ad`; `dns.zone.flip` with the counts | `flip-forward.json` | WP14.2 |
| T32 | node | The same for `_msdcs.corp.example.test`, then `2.0.192.in-addr.arpa` | `pc1`'s PTR `transfer`; the others `ad` | `flip-rest.json` | WP14.2 |
| T33 | operator | Per zone, `_msdcs` last: on `ns1` `transfer.allow` and `notify` naming both controllers first; on `dc1` `ConvertTo-DnsServerSecondaryZone -MasterServers 192.0.2.53`, and at once on `dc2` `Add-DnsServerSecondaryZone -MasterServers 192.0.2.53`; on both `dnscmd /ZoneResetSecondaries <zone> /NoXfr /NoNotify`, read back from the zone's registry values | Both controllers answer the zones from Tenko's serial; no moment in which neither answers a zone; `dc2`'s secondary loaded within about a second; the copies refuse a transfer (expected values measured on 2026-11-20: `dc2` would keep its loaded copy until about four and a half minutes after the deletion replicated, then log event 4005 and answer nothing; R142) | `convert.txt` | WP14.2 |
| T34 | operator | Both controllers' DNS clients `192.0.2.53` first, `nltest /dsregdns` and `ipconfig /registerdns`; option 6 on both servers `192.0.2.53, 192.0.2.5, 192.0.2.6`; T09 again with the target `192.0.2.53` (the manual path; the scripted path decides the DNS clients by T63 and leaves Windows' option 6) | `dns.update.apply` by `DC1$` and `DC2$` as privileged; `nltest /dsgetdc:corp.example.test /force` on `srv1` and `pc1` through Tenko | `register.txt`, `audit.json` | WP14.2 |
| T35 | operator | `ipconfig /renew` on `pc1` (answered by Windows) | The Windows DHCP server's update of `pc1`'s frozen name refused (`dns.update.refuse` with its principal); `pc1` keeps `192.0.2.30` and its name resolves | `frozen.json` | WP14.2 |
| T35r | operator, node | Reverse of the flip, per zone while `dc2` keeps answering from its secondary: first, with a test record added on `ns1` beforehand (a second A record for `dc1`'s name, and an `_ldap._tcp.dc._msdcs` SRV record to a lab address), `dc1`'s secondary compared with the record set read at the flip, the differences shown by name and type, those two kept at their flip-time records unless typed, and the rest taken after the domain's name is typed (and once declined, so that the export of phase 2 is restored instead); then on `dc1` `ConvertTo-DnsServerPrimaryZone -ZoneFile <zone>.dns`, then `ConvertTo-DnsServerPrimaryZone -ReplicationScope Domain` (`Forest` for `_msdcs`), then `Set-DnsServerPrimaryZone -DynamicUpdate Secure` and its transfer lists back; once `dc1` serves every zone from the directory, on `dc2` `Remove-DnsServerZone -Force` of its secondaries and a wait for its own directory poll; the controllers' DNS clients and T09 back; on `ns1` `tenko dns zone flip <zone> --to secondary` with `192.0.2.5` | Expected values measured on 2026-11-20: the direct conversion of a secondary fails; through the file a new zone object beside the tombstone; the update setting `NonsecureAndSecure` until it is set back, then `Secure` on both (a zone left open fails the entry); `dc2` loads the directory copy about 145 s after the removal and answers nothing for those zones meanwhile while `dc1` answers; the next transfer brings every record back as `transfer`; the RRsets equal the controllers' | `unflip.txt` | WP14.2 |
| T36 | operator, node | Forward again: T30 to T34 | As there | as there | WP14.2 |

### Phase 4. The DHCP takeover

| # | Actor | Action | Check, expected | Evidence | When |
|---|---|---|---|---|---|
| T37 | node | `tenko migrate prepare dc1-dhcp 192.0.2.0/24`, then again | A disabled scope, not authoritative, equal to both mirrors; both diffs empty, the partner rows included; the second run changes nothing | `prepare.json` | WP14.2, WP14.1a |
| T38 | node | With `dc2` shut down: `tenko migrate takeover dc1-dhcp 192.0.2.0/24`; then `dc2` started | Refused with `migrate.takeover.not_fresh` naming `dc2-dhcp`; nothing changed | `refused.json` | WP14.2, WP14.1a |
| T39 | node, operator | `tenko migrate takeover dc1-dhcp 192.0.2.0/24`; the exporters' tasks started on their host for the final pushes; before it, phase 0's reads (no DHCPv6 or multicast scope, no group policy on the start of `DHCPServer`, no lease time under an hour) and the manual restore lines noted; when the silence task opens and the stop is approved (in one sitting by the DNS window's confirmation within 15 minutes; once, in a split sitting, Abort, which changes nothing and exits 3, then Continue), on `dc1` and `dc2` `Stop-Service DHCPServer` (never `Dhcp`) and `Set-Service DHCPServer -StartupType Disabled`, the silence read back (`Get-Service`, `Get-NetUDPEndpoint -LocalPort 67` empty), the task completed at once, then `Remove-DhcpServerInDC` for both, `repadmin /syncall /AdeP`, the removal read back against `dc1`'s and `dc2`'s own replicas for up to 300 s (a lagging replica recorded as a pending barrier, also beside the run's marker on `dc1`); a capture on the client network from the first stop on | The job adopts from a push of each mirror accepted after its start; the audit line `01,...,Stopped` on both servers; its record names both mirrors with their sequences and the silencing; `pc1`'s lease adopted with its remaining time; its A, DHCID and PTR `dhcp` with Tenko's DHCID and no owner; the scope enabled, not authoritative; no DHCPNAK in the capture from any server; no moment in which two servers answer; the silent gap recorded (M93, under 30 s); the DHCID identifier type Windows used is recorded (R137) | `takeover.json`, `records.json`, `window.pcapng` | WP14.2, WP14.1a |
| T40 | operator | On `pc1`: its next renewal (T1), with no `ipconfig /renew`; then `ipconfig /all`, `nltest /dsgetdc:corp.example.test /force`, `Resolve-DnsName pc1.corp.example.test` | Expected from the measurement of 2026-11-20: two unicast REQUESTs to its Windows server unanswered, a broadcast REQUEST about 5 s in, ACKed by `ns1` from the adopted row (by unicast to `192.0.2.30`), no address change, no APIPA, the next renewal the same (R227); DHCP server `192.0.2.53` after it; a controller found; the name answers; no NAK in Tenko's counters | `renew.txt`, `renew.pcapng` | WP14.2 |
| T40a | operator | A client renewing during the seconds of silence (the window started while `pc1` is at its T1, with the lease time of 10 minutes on a second client only, T12) | The client keeps its address while nobody answers and is ACKed by `ns1` at its next broadcast; with no answer at all it keeps its address through T1, T2 and to the lease's end, retrying in rounds, then sends one INIT-REBOOT request and removes the address (measured on 2026-11-21, R226) | `gap.txt`, `gap.pcapng` | WP14.2, pool |
| T40b | operator | A repeat of T39 with the plan's method (b): an enabled, empty Allow list on both servers, the service running | Expected from the measurement of 2026-11-21: no answer and no NAK to any client, one event 20097 per dropped packet in the log `Microsoft-Windows-Dhcp-Server/FilterNotifications` and nothing in the DHCP audit log; the exporters keep pushing, and a push showing the list off is the alarm | `allow-list.txt`, `allow-list.pcapng` | WP14.2, WP14.1a |
| T39a | operator | In a repeat of T39 the script is stopped right after both servers are silent and before Tenko's scope is on | Both sides silent; the job does not roll back, shows "Windows silent since", raises `migrate.takeover.both_silent` at once and alerts within two minutes; the printed restore lines, run by hand, bring both servers back; `pc1` keeps its address throughout | `both-silent.txt` | WP14.2, WP14.5 |
| T39b | operator | Before a repeat of T39, `dc2`'s clock set 90 s ahead with its time service stopped; then, after the refusal, the clock and the service restored; separately, `ns1` paused and resumed as a virtual machine between the final pushes and the silence | Phase 0 warns about `dc2`'s time source; the job refuses the window naming both clocks (`dc2`'s and `ns1`'s, about 90 s apart); with the clocks restored, the adopted leases end at `ns1`'s reception plus each lease's own remaining time; after the pause the job measures again before the silence and refuses (R229) | `clock.txt` | WP14.2, WP14.5 |
| T41 | operator | `pc1` restarted | Its INIT-REBOOT answered by `ns1` with `192.0.2.30`, also when its adopted row is keyed by the other identity (T42's client); a second client Tenko holds no row for gets silence and then an offer of its old address, never a NAK | `reboot.pcapng` | WP14.2 |
| T42 | operator | A client on a pool lease (`pc1` moved off its reservation, or T12's client) through T39 to T41 | Its address and name kept; the identity guess and the rekey of plan section 2.8 in its lease row | `pool.json` | pool, WP14.2 |
| T43 | operator | On `dc2` only: the service started again, its authorization still removed; a capture of `pc1`'s next renewal | Expected from the measurement of 2026-11-21: system event 1046 and the audit line `56,...,Authorization failure, stopped servicing` within about 4 s of the start, no answer to `pc1`, while `Get-DhcpServerv4Scope` still reads active and failover reads normal; started before the removal replicated to `dc2`'s own controller it would log 1044 and serve (R228), which T39's read-back prevents; its mirror's next push is accepted and `migrate.mirror.scope_active` names `dc2-dhcp` as an error within one push (R218); before that, both mirrors stale with no finding | `scope-active.json`, `unauthorized.pcapng` | WP14.2, WP14.1a |
| T43r | operator | The service stopped again on `dc2` | No further push; the finding names the push that came after the silence | `scope-inactive.json` | WP14.2, WP14.1a |
| T44r | node, operator | Reverse of the takeover, in the plan's order (section 2.17): first, with the service still stopped, one DHCP read on `dc2` (expected to fail, R231); on both servers the start type `Automatic` and the service started while unauthorized (event 1046); the leases written in (`Add-DhcpServerv4Lease` with an address, a client identifier and an end only, the state active, never a name) and read back (R230); `Set-DhcpServerSetting -ConflictDetectionAttempts 1`; `Add-DhcpServerInDC`, `repadmin /syncall /AdeP` and the authorization read back on each controller, with the time a running server keeps logging 1046 recorded (R232); then `tenko migrate revert dc1-dhcp 192.0.2.0/24`, the service restarted on both and event 1044 read back; once with a node answer holding a host name, a reservation of another client and more leases than the pool, which the write-back refuses; `pc1`'s next renewal with no `ipconfig /renew` | `dhcp.scope.revert` recorded only after event 1044; Tenko's scope disabled, silent, with its leases and records; no moment in which two servers answer and no moment in which both are silent beyond the restart's seconds; `pc1`'s broadcast REQUEST ACKed by a controller with no address change and no NAK from any server; a client that got a new address from Tenko during the takeover keeps it (the written-back lease), and a renewal for a lease Windows does not hold gets an ACK with a new lease of one hour, the MCLT (audit event 10 Assign, measured on 2026-11-21); event 1044 on both servers at their start, never 1046 | `revert.json`, `renew.txt`, `revert.pcapng` | WP14.2 |
| T45 | node, operator | Forward again: T39 and T40 | As there | as there | WP14.2 |

### Phase 5. The parallel period and the end

| # | Actor | Action | Check, expected | Evidence | When |
|---|---|---|---|---|---|
| T46 | inside observer | Over at least two hours: both mirrors, the service on both servers, `pc1`'s renewals | The mirrors stale and no finding (the expected state), both services stopped and disabled, `pc1` renewed by `ns1` each time after the five seconds of R227 | `parallel.txt` | WP14.2 |
| T47 | operator, node | Without starting the service: `Uninstall-WindowsFeature DHCP` on both, each server's DHCP database directory moved into the backup; the exporters removed; the mirrors deleted; then, on a copy of `dc2`'s snapshot, the role installed again over a database left in place | `Get-DhcpServerInDC` empty (since T39); no mirror on `ns1`; `pc1` still served by `ns1`; on the copy, whether the reinstalled role revives the old scopes, leases and relationship recorded | `end.txt`, `revive.txt` | WP14.2 |
| T47r | operator | The way back: the role, the database directory restored from the backup or `Import-DhcpServer -Leases` of T10's export on `dc1`, `Add-DhcpServerv4Failover` as in T07, all with the authorization still removed, the service then stopped and disabled on both until a reverse of the takeover adds the authorization and makes Windows answer | The scope on both servers again, the servers serving nothing while unauthorized (R228); never a deactivated scope | `end-back.txt` | WP14.2 |
| T48 | inside observer | The controllers' secondary copies against Tenko's serials | Each follows Tenko within its refresh (WT-Q12) | `secondaries.txt` | WP14.2 |
| T49 | node | The rows `ad.mirror_token` (with a third mirror bound to `ns1`'s own address, its token on `ns1`), `ad.dhcid_takeover` (a client with another MAC address asks for `pc1`'s address and name) and `ad.delegation` (a run's delegated session walked through the served OpenAPI document) | As the plan's WP14.4 states | `rows.json` | WP14.4; `ad.dhcid_takeover` also pool; `ad.delegation` WP14.6 |

### Phase 6. The scripted takeover

The plan's section 2.16: one script from the release, run elevated as a domain administrator on
`adm1`, the line's administration workstation, or on `dc1` through RDP, approved in `ns1`'s UI. It
starts from `tk-start` and replaces, for E77, the manual entries T14, T15, T17 to T19, T27r, T29 to
T34, T35r, T36, T37, T39, T44r, T45, T47 and T47r; those stay as the manual path and are run once
each. The other entries of phases 2 to 5 are the inside observer's checks during this phase where
they apply (T16, T16a, T20, T21 to T23r, T35, T40 to T43r, T46, T48, T49). These are the manifest's
only changes made from `adm1`: each runs after the observer's user approves it, and that user, the
person at `adm1`, signs in as the domain administrator (the script asks for no credential, WT-Q18),
types the code into the UI, approves, starts the window and confirms it at the console, so that no
secret reaches the observer or a channel. The lab's zones take secure updates only, as Windows sets
them, and the script refuses such a domain until its release's Kerberos line is complete (T60a): the
entries after T52 wait for that release, or run on a copy of the line whose zones the operator set
to nonsecure and secure for the rehearsal, which the result names as a deviation. For each phase the observer writes `usability.json`: the actions
on Windows and on Tenko, the values typed, the pages of documentation open, restarts, and every
wrong turn with its cause.

| # | Actor | Action | Check, expected | Evidence | When |
|---|---|---|---|---|---|
| T50 | operator | Restore `tk-start`; the release candidate's archive `tenko-takeover-<version>.zip` and its `SHA256SUMS` carried to `adm1` as the intake path would (the lab has no intake of its own) | T10's readings; nothing of Tenko on any lab machine | `start-6.txt` | WP14.5, WP14.6 |
| T51 | inside observer | The intake's check command of the plan's section 2.16.1 on the operator's connected machine, which prints the start line, saved as `Start-Tenko.txt` and carried in with the files | Equal digests, the attestation verified, the printed line holding the file's digest; a file with one byte changed is refused and no line printed; at a commit under test without a release, the digests against the lead's list, named as a deviation | `verify.txt` | WP14.5 |
| T52 | inside observer | `Tenko-Takeover.ps1 -DryRun`, first unelevated, then elevated | Unelevated: exit 1, nothing read; elevated: the plan names `dc1` and `dc2`, the PDC emulator, the zones read on each controller with their serials, transfer and notify lists, aging and scavenging, both DHCP servers, `dc1-dc2`, the scope, `CORP\dhcp-dns` on both, `pc1` as a member on DHCP, `srv1` offered as the mirror host with its local Administrators, and the hardening warnings; T10's readings before and after equal; no request in `ns1`'s log; every session Kerberos by FQDN (the WinRM log on each host) | `dryrun.txt`, `inventory-before.txt`, `inventory-after.txt` | WP14.5 |
| T52a | operator, inside observer | Before a dry run: a stale authorization entry `old-dhcp.corp.example.test` added with `Add-DhcpServerInDC` for a name with no computer object, and a computer account `tenko-mirror` created by hand | The stale entry is listed as a warning and no session is opened to it; the DHCP server list is shown and confirmed before any session to a DHCP server; phase 2 refuses the existing `tenko-mirror` with exit 1, names it, and neither adopts nor deletes it; both removed by the operator afterwards | `scope-of-run.txt` | WP14.5 |
| T53 | inside observer | `Tenko-Takeover.ps1` to the end of phase 2, with `srv1` as the mirror host | The approval page shows the plan and the reported machine and user so labeled, and the code covers the plan; on Windows exactly the lines of the change list (T10's readings compared); on `ns1` the run with its plan, three secondary zones from `192.0.2.5` that answer nothing yet (`Resolve-DnsName -Server 192.0.2.53`), the forwarding rules off, two paired mirrors bound to `srv1`'s /32 and fresh, the scope prepared, every action audited with the approver and the run; nothing of Tenko on `dc1` or `dc2`; the state file and the module log and transcript of the run hold no token, code or password | `phase2.txt`, `state.json`, `audit.json`, `logs.txt`, `usability.json` | WP14.5, WP14.6 |
| T54 | inside observer | The script interrupted in phase 2 after the mirrors, then run again | It resumes at the next step after reading the state; no object twice on Windows or `ns1` | `resume.txt` | WP14.5 |
| T55 | inside observer | On the run page: the review and **Start the window**; then the console's confirmation | The loss entries acknowledged in one batch, the option 6 row decided, the bindings recorded; a passkey sign-in within five minutes asked (Hardened); the script waits for the console before phase 4 | `window.json` | WP14.6, WP14.5 |
| T56 | inside observer | Phases 4 and 5 | The configuration cross-check passes (and stops the window when the operator changed a reservation on `dc2` beforehand, while a changed lease does not); T31 to T33's and T39 to T41's checks, T33's expected values among them; Windows' option 6 and, until T63 decides, the controllers' DNS clients unchanged; the zones and the forwarding rules served from the flip on; `wpad` and `isatap` answered with nothing; M93 recorded | `window-run.txt`, `takeover.json`, `m93.txt` | WP14.2, WP14.5 |
| T57 | inside observer | `-Reverse` of phase 5, then of phase 4; then forward again | T44r's and T35r's checks; forward as T56 | `reverse.txt` | WP14.2, WP14.5 |
| T57a | inside observer | A second sitting after phase 4 with `dc2`'s address record changed on `ns1` beforehand by the operator | The script stops with exit 4 before opening any session, naming the difference from phase 0 | `locator.txt` | WP14.5 |
| T58 | operator, inside observer | During phase 5's wait the operator stops `tenko` on `ns1`; then `-Reverse` | Exit 2; the warning that the node may still serve DHCP, and the Windows half done only after the confirmation (both servers answering again, Tenko's leases written in); Tenko's half recorded as pending; after `tenko` starts, `-Reverse` finishes it | `tenko-down.txt` | WP14.5 |
| T59 | operator, inside observer | A TLS-intercepting proxy between `adm1` and `ns1`, first with a root of its own, then appending `ns1`'s real root to its own chain; the script run through it, its code typed in the UI | First case: the code matches nothing, `auth.approval.refuse` audited; second case: the script refuses the chain before it sends anything; nothing created (`ad.approval_code`) | `intercept.txt` | WP14.6 |
| T60 | inside observer | After T46: the second sitting, phase 6 | T47's checks; the plan's zone objects gone from `DomainDnsZones` and `ForestDnsZones`; the group policy object kept; no task, account, batch logon right, `token.pending` or mirror left on `srv1`; the run marker gone from `dc1`; Tenko's scope back to the server's `authoritative` setting; whether T10's `Export-DhcpServer` files hold the relationship's shared secret recorded | `finish.txt` | WP14.5 |
| T60a | inside observer | A domain with a zone that takes secure updates only, run with a release whose Kerberos line is not complete (the lab's zones are secure-only, so this is the line's state until E44) | Phase 0 prints the sentence of the plan's section 2.16.1, changes nothing on Windows or `ns1` and stops with exit 1 | `secure-only.txt` | WP14.5 |
| T60b | inside observer | Tenko's computer account created in phase 2 while `ns1` is kept from changing its password (the adoption answered but the rotation held by the operator) | Ten minutes after the adoption the script disables the account and says so; with the rotation allowed, the account in no privileged group, with no delegation and `msDS-SupportedEncryptionTypes` 24; `-Reverse` sets the zones back to `Secure`, reads it back, and only then removes the account | `account.txt` | WP14.5 |
| T60r | inside observer | `-Reverse` of the finish | T47r's checks | `finish-back.txt` | WP14.5 |
| T61 | inside observer | From after T56, `-Reverse` walked back through phase 2 | T13r's readings on Windows; on `ns1` no mirror and no zone, the run reversed | `full-reverse.txt` | WP14.5 |
| T62 | lead | The usability records of T51 to T61 and T64 against E146 | The numbers of the plan's section 2.16.6 for each form used, restarts counted, one page of documentation; each wrong turn filed as a finding | `usability.md` | WP14.4 |
| T63 | operator, inside observer | After T56, with the controllers' DNS clients left on their own servers first: `nltest /dsregdns` and `ipconfig /registerdns` on each controller, and a test registration | Whether each controller's updates reach `ns1` through its own secondary copy's `mname` (`dns.update.apply` by `DC1$` and `DC2$`); if they do, the scripted path never points the controllers at Tenko; if not, phase 4 does, and the result says so | `controller-updates.txt`, `audit.json` | WP14.2, WP14.5 |
| T64 | inside observer | The start on `dc1` through an RDP session from `adm1`: first the file copied by RDP's file redirection, then, with file redirection off, its text pasted into Notepad on `dc1` and saved; each time the start line pasted | The copied file: whether it carries a zone mark, and the line starts it; the Notepad file: the bytes Notepad saves on Windows Server 2025 (encoding, line ends, a byte order mark), and whether the line's digest matches, since the script is ASCII with CRLF; a file with one character changed is refused and nothing runs | `paste.txt`, `usability.json` | WP14.5 |
| T65 | operator, inside observer | On `adm1`, an App Control for Business policy that enforces script rules: the script as released, then signed with a lab code-signing certificate the policy trusts | Unsigned: the script stops at once with exit 1 because its language mode is not Full Language; signed: the run reaches the end of phase 0 unchanged | `app-control.txt` | WP14.5 |

## What the line needs from the operator's tooling

1. A file carried from `ns1`'s root-only directory to a controller's `C:\lab\secrets\` (each
   mirror's token, T17 and T18: `mirror_token_dc1` to `dc1` and `mirror_token_dc2` to `dc2`) without
   passing through any channel the lead or the observer reads.
2. New secret files: `dhcp_mirror_password` on both controllers (T18), `dhcp_dns_password` on both
   (T11).
3. Under Hardened (from T28), an administrator's passkey session on `ns1` for the writing entries
   (a transfer on demand, the flip, the acknowledgments, the prepare, the takeover, the revert).
   Without one, the line leaves T28 out, runs phases 3 to 5 under Standard, and the result names
   the deviation.
4. `pc1` on DHCP with its reservation (T08), and later a pool lease for T42 and T49, from a real
   client: a lease record made by hand on one server does not reach the partner (measured on
   2026-11-20).
5. Snapshot `tk-start` within the line (T13).
6. For phase 6: under Hardened a passkey of a lab administrator for the browser of the observer's
   user on `adm1`, registered by the operator; the DHCP management tools on `srv1`, or the script's
   own install of them recorded; a TLS-intercepting proxy for T59 in both of its modes; module
   logging and transcription turned on for `adm1` by the lab's group policy (T53); an App Control
   policy and a lab code-signing certificate for T65; RDP with text clipboard redirection from
   `adm1` to `dc1` (T64).
