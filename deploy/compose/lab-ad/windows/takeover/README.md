# The Windows lab's takeover line (E77)

The rehearsal of the Windows takeover ([windows-takeover-plan.md](../../../../../docs/plans/windows-takeover-plan.md)
sections 2.13 and 2.15, exit check E77): the lab domain of [the counted line](../README.md) starts
as a Windows-first domain, with Windows DNS and Windows DHCP on both controllers and a failover
relationship between the DHCP servers, and moves to Tenko step by step, each step with its reverse.
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
  that change, and none is in this manifest. It never signs in to `ns1`'s API.
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
rebuild. Once the hypervisor keeps branches, a kept Windows-first snapshot (T13) replaces T03 to
T10.

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
`ns1` needs the operator's passkey path (below).

## The manifest

"When" says whether an entry runs with the first package as built (**now**: the exporter, the
mirror, the freshness, the diff, the loss report) or waits for a package of the plan (WP14.1a,
WP14.2, WP14.4) or for the operator's dynamic-lease tooling (**pool**). **B** marks the basic
set of the first run (fifteen entries). An entry ending in `r` is the reverse of the entry or
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
| T05 | operator | On `dc1` and `dc2`: `Install-WindowsFeature DHCP -IncludeManagementTools`, `Add-DhcpServerSecurityGroup`, `Add-DhcpServerInDC` with the server's name and address, the role's configuration marked complete, the service restarted | `Get-DhcpServerInDC`: exactly `dc1` and `dc2` | `indc.txt` | now, B |
| T06 | operator | On `dc1`: the scope of the table above (`Add-DhcpServerv4Scope`, `Add-DhcpServerv4ExclusionRange` twice, `Set-DhcpServerv4OptionValue -Router -DnsServer -DnsDomain`, `Set-DhcpServerv4DnsSetting -DynamicUpdates Always -NameProtection $true -DeleteDnsRROnLeaseExpiry $true`, `Add-DhcpServerv4Reservation` three times, `pc1`'s MAC address read on `pc1` with `Get-NetAdapter`) | `Get-DhcpServerv4Scope`, `...ExclusionRange`, `...OptionValue -ScopeId 192.0.2.0`, `...Reservation`, `...DnsSetting` show the table | `scope-dc1.txt` | now, B |
| T07 | operator | On `dc1`: `Add-DhcpServerv4Failover -Name dc1-dc2 -PartnerServer dc2.corp.example.test -ScopeId 192.0.2.0 -LoadBalancePercent 50 -MaxClientLeadTime 01:00:00 -AutoStateTransition $true -StateSwitchInterval 01:00:00` | `Get-DhcpServerv4Failover` on both: `Normal`, `LoadBalance`; `Get-DhcpServerv4Scope -ComputerName dc2` and its reservations equal `dc1`'s | `failover.txt`, `scope-dc2.txt` | now, B |
| T08 | operator | On `pc1`: DHCP on (`Set-NetIPInterface -Dhcp Enabled`, the static address and gateway removed, `Set-DnsClientServerAddress -ResetServerAddresses`), `ipconfig /renew`, a capture of the exchange with `pktmon`; then `Add-Computer -DomainName corp.example.test`, restart | `ipconfig /all`: DHCP enabled, `192.0.2.30`, DHCP server `192.0.2.5` or `.6`, DNS servers `.5` and `.6`; after the restart `nltest /sc_query:corp.example.test` succeeds; `Get-DhcpServerv4Lease -IPAddress 192.0.2.30` on both: `ActiveReservation`; on `dc1` `pc1` has an A, a PTR and a DHCID record, and which of `pc1` and the DHCP server wrote the A record is noted | `ipconfig.txt`, `dora.pcapng`, `leases.txt`, `records.txt` | now, B |
| T09 | operator | On `adm1`: the repeatable domain join, the lab adapter up, and the name resolution policy for `corp.example.test` and `2.0.192.in-addr.arpa` (`Add-DnsClientNrptRule`) pointing at the phase's DNS target: `192.0.2.5, 192.0.2.6` until T34, `192.0.2.53` from then on (the parameter of this entry) | `Resolve-DnsName dc2.corp.example.test` answers `192.0.2.6` through the target | `nrpt.txt` | now, B |
| T10 | inside observer | The start-state reading: controllers, operation masters and global catalogs; per controller the zones and their SOA serials; `Get-DhcpServerInDC`; per DHCP server the scope, exclusions, options at server, scope and reservation level, reservations, DNS settings, `Get-DhcpServerDnsCredential` (the user name only), `Get-DhcpServerSetting`, the relationship, and `Get-DhcpServerv4Lease -AllLeases`; `Export-DhcpServer -Leases` of each server to `adm1` | The table above holds on both servers; the export files exist (the backup of the plan's step 1) | `inventory-*.txt`, `export-dc1.xml`, `export-dc2.xml` | now, B |
| T11 | operator | The DHCP servers' DNS credential as WT-Q13 is answered: a lab user `dhcp-dns` from the secret `dhcp_dns_password`, set on both with `Set-DhcpServerDnsCredential` | `Get-DhcpServerDnsCredential` on both names `CORP\dhcp-dns`; `ipconfig /renew` on `pc1` and the DNS server's audit of the update (`Get-WinEvent` of the DNS server log) show the update under that account | `credential.txt` | now, after WT-Q13 |
| T12 | operator | Optional: a second Windows client takes a pool lease | A lease in `192.0.2.100` to `.250` on both servers | `client2.txt` | pool |
| T13 | operator | Snapshot S1 of every guest (the line's own, linear) | The snapshot exists; later entries return to it instead of rebuilding | `snapshot.txt` | now |
| T13r | operator | Reverse of phase 1: restore the counted line's snapshot or S1 | T03's or T10's readings again | `restore.txt` | now |

### Phase 2. Tenko beside Windows, serving nothing

| # | Actor | Action | Check, expected | Evidence | When |
|---|---|---|---|---|---|
| T14 | operator | On `dc1`, for the three zones: `Set-DnsServerPrimaryZone -SecureSecondaries TransferToSecureServers -SecondaryServers 192.0.2.53 -Notify NotifyServers -NotifyServers 192.0.2.53` | The same settings read on `dc2` after replication (if not, run it on `dc2` too and note it) | `transfer-allow.txt` | now, B |
| T15 | node | Three secondary zones with `source.primaries` `192.0.2.5` only (`POST /dns/zones`, plan section 2.15), then `tenko dns transfer now` | `tenko dns transfer status`: each serial equals `dc1`'s; the RRsets equal `dc1`'s `Get-DnsServerResourceRecord`; `pc1`'s A and DHCID with the origin `transfer` (the Windows half of E15, carried) | `zones.json`, `compare.txt` | now, B |
| T16 | inside observer | The SOA serial of each zone on `dc1` and on `dc2`, twice an hour apart | Recorded for R217: whether the two servers' serials differ | `serials.txt` | now |
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
| T29 | operator | The lease time on both servers: one hour, then ten minutes the day before the window (`Set-DhcpServerv4Scope -ComputerName` each) | Each mirror's push audited as a changed configuration; `pc1`'s lease follows at its renewal | `lease-time.txt` | now |
| T30 | operator, node | On `dc1` `repadmin /syncall /AdeP`; on `ns1` `tenko dns transfer now` | The serials on `ns1` equal `dc1`'s; `dc2`'s latest registrations are in the copy | `sync.txt` | now |
| T31 | node | `tenko dns zone flip corp.example.test --to primary` with `ns1`'s SOA and NS | The origins of plan section 2.6: `pc1`'s A and DHCID `transfer`, the locator records and both controllers' A records `ad`; `dns.zone.flip` with the counts | `flip-forward.json` | WP14.2 |
| T32 | node | The same for `_msdcs.corp.example.test`, then `2.0.192.in-addr.arpa` | `pc1`'s PTR `transfer`; the others `ad` | `flip-rest.json` | WP14.2 |
| T33 | operator | Per zone, `_msdcs` last: on `dc1` `ConvertTo-DnsServerSecondaryZone -MasterServers 192.0.2.53`, replication, on `dc2` `Add-DnsServerSecondaryZone -MasterServers 192.0.2.53`; on `ns1` `transfer.allow` and `notify` name both controllers | Both controllers answer the zones from Tenko's serial; the time `dc2` answered nothing for a zone is measured (R142) | `convert.txt` | WP14.2 |
| T34 | operator | Both controllers' DNS clients `192.0.2.53` first, `nltest /dsregdns` and `ipconfig /registerdns`; option 6 on both servers `192.0.2.53, 192.0.2.5, 192.0.2.6`; T09 again with the target `192.0.2.53` | `dns.update.apply` by `DC1$` and `DC2$` as privileged; `nltest /dsgetdc:corp.example.test /force` on `srv1` and `pc1` through Tenko | `register.txt`, `audit.json` | WP14.2 |
| T35 | operator | `ipconfig /renew` on `pc1` (answered by Windows) | The Windows DHCP server's update of `pc1`'s frozen name refused (`dns.update.refuse` with its principal); `pc1` keeps `192.0.2.30` and its name resolves | `frozen.json` | WP14.2 |
| T35r | operator, node | Reverse of the flip: on `dc1` `ConvertTo-DnsServerPrimaryZone -ReplicationScope Domain` (`Forest` for `_msdcs`), on `dc2` its secondary removed so that it loads the directory's copy; the controllers' DNS clients and T09 back; on `ns1` `tenko dns zone flip <zone> --to secondary` with `192.0.2.5` | `dc2` serves the directory copy; the next transfer brings every record back as `transfer`; the RRsets equal the controllers' | `unflip.txt` | WP14.2 |
| T36 | operator, node | Forward again: T30 to T34 | As there | as there | WP14.2 |

### Phase 4. The DHCP takeover

| # | Actor | Action | Check, expected | Evidence | When |
|---|---|---|---|---|---|
| T37 | node | `tenko migrate prepare dc1-dhcp 192.0.2.0/24`, then again | A disabled scope equal to both mirrors; both diffs empty, the partner rows included; the second run changes nothing | `prepare.json` | WP14.2, WP14.1a |
| T38 | node | With `dc2` shut down: `tenko migrate takeover dc1-dhcp 192.0.2.0/24`; then `dc2` started | Refused with `migrate.takeover.not_fresh` naming `dc2-dhcp`; nothing changed | `refused.json` | WP14.2, WP14.1a |
| T39 | node, operator | `tenko migrate takeover dc1-dhcp 192.0.2.0/24`; the operator runs the job's two lines (`Set-DhcpServerv4Scope -ComputerName dc1.corp.example.test -ScopeId 192.0.2.0 -State InActive`, the same for `dc2`) | The job waits for a push of each mirror showing the scope inactive; its record names both mirrors with their sequences; `pc1`'s lease adopted with its remaining time; its A, DHCID and PTR `dhcp` with Tenko's DHCID and no owner; the scope enabled; the DHCID identifier type Windows used is recorded (R137) | `takeover.json`, `records.json` | WP14.2, WP14.1a |
| T40 | operator | On `pc1`: wait for its rebinding; `ipconfig /all`, `nltest /dsgetdc:corp.example.test /force`, `Resolve-DnsName pc1.corp.example.test` | DHCP server `192.0.2.53`, address `192.0.2.30`; a controller found; the name answers; no NAK in Tenko's counters; the time from the deactivation to the rebinding | `rebind.txt`, `rebind.pcapng` | WP14.2 |
| T41 | operator | `pc1` restarted | Its INIT-REBOOT answered by `ns1` with `192.0.2.30` | `reboot.pcapng` | WP14.2 |
| T42 | operator | A client on a pool lease (`pc1` moved off its reservation, or T12's client) through T39 to T41 | Its address and name kept; the identity guess and the rekey of plan section 2.8 in its lease row | `pool.json` | pool, WP14.2 |
| T43 | operator | On `dc2` only: the scope active again | `migrate.mirror.scope_active` names `dc2-dhcp` within one push (R218) | `scope-active.json` | WP14.2, WP14.1a |
| T43r | operator | The scope inactive again on `dc2` | The finding gone | `scope-inactive.json` | WP14.2, WP14.1a |
| T44r | node, operator | Reverse of the takeover: `tenko migrate revert dc1-dhcp 192.0.2.0/24`; on both servers `Set-DhcpServerSetting -ConflictDetectionAttempts 1` and the scope active; `ipconfig /renew` on `pc1` | `dhcp.scope.revert`; Tenko's scope disabled with its leases and records; `pc1` keeps `192.0.2.30` from a controller | `revert.json`, `renew.txt` | WP14.2 |
| T45 | node, operator | Forward again: T39 and T40 | As there | as there | WP14.2 |

### Phase 5. The parallel period and the end

| # | Actor | Action | Check, expected | Evidence | When |
|---|---|---|---|---|---|
| T46 | inside observer | Over at least two hours: both mirrors, the relationship, the scope's state on both servers, `pc1`'s renewals | The mirrors fresh and inactive, no finding, `pc1` renewed by `ns1` | `parallel.txt` | WP14.2 |
| T47 | operator, node | `Remove-DhcpServerv4Failover -Name dc1-dc2` on `dc1`; `Remove-DhcpServerInDC` for both; `Uninstall-WindowsFeature DHCP` on both; the exporters removed; the mirrors deleted | `Get-DhcpServerv4Scope -ComputerName dc2` empty after the removal; `Get-DhcpServerInDC` empty; no mirror on `ns1`; `pc1` still served by `ns1` | `end.txt` | WP14.2 |
| T47r | operator | The way back: the role, `Add-DhcpServerInDC` for both, `Import-DhcpServer -Leases` of T10's export on `dc1`, `Add-DhcpServerv4Failover` as in T07 (scope inactive) | The scope on both servers again, inactive | `end-back.txt` | WP14.2 |
| T48 | inside observer | The controllers' secondary copies against Tenko's serials | Each follows Tenko within its refresh (WT-Q12) | `secondaries.txt` | WP14.2 |
| T49 | node | The rows `ad.mirror_token` (with a third mirror bound to `ns1`'s own address, its token on `ns1`) and `ad.dhcid_takeover` (a client with another MAC address asks for `pc1`'s address and name) | As the plan's WP14.4 states | `rows.json` | WP14.4; `ad.dhcid_takeover` also pool |

## What the line needs from the operator's tooling

1. A file carried from `ns1`'s root-only directory to a controller's `C:\lab\secrets\` (each
   mirror's token, T17 and T18) without passing through any channel the lead or the observer reads.
2. New secret files: `dhcp_mirror_password` on both controllers (T18), `dhcp_dns_password` on both
   once WT-Q13 is answered (T11).
3. Under Hardened (from T28), an administrator's passkey session on `ns1` for the writing entries
   (a transfer on demand, the flip, the acknowledgments, the prepare, the takeover, the revert).
   Without one, the line leaves T28 out, runs phases 3 to 5 under Standard, and the result names
   the deviation.
4. `pc1` on DHCP with its reservation (T08), and later a pool lease for T42 and T49.
5. Snapshot S1 within the line (T13); later, a kept Windows-first branch.
