# Active Directory: taking over DNS and DHCP from the domain controllers

This page is the runbook for moving the DNS zones of an Active Directory domain and the DHCP service off the domain controllers and onto Tenko DDI. It is for an operator who runs a small domain with the DNS Server and DHCP Server roles on the controllers, wants those roles gone from them, and keeps the directory itself where it is. It covers what Active Directory needs from DNS, the `_msdcs` zone, how the controllers register their records, what the missing GSS-TSIG costs until Phase 4, the steps in order with a check and a way back for each, and the rollback for each phase. Tenko is not joined to the domain and holds no directory data (CON-11); the controllers stay controllers.

The migration pipeline of [MIGRATION.md](MIGRATION.md) (`tenko migrate plan`, `apply` and `verify` over the Windows adapter, MIG-06, MIG-08, MIG-17) ships in Phase 4, and so does GSS-TSIG (DNS-28, DNS-30). This runbook uses what ships today: a zone transfer in and a zone file import for the DNS data, RFC 2136 updates from the controllers' addresses, and scopes entered by hand from the Windows export for DHCP. Where the Phase 4 adapter will replace a manual step, the step says so. The commands are for Windows Server 2016 or later on the controllers.

Related: [dns.md](dns.md) (section 6 access lists, section 10.13 the transfer from Windows DNS, section 13 dynamic updates), [dnssec.md](dnssec.md), [dhcp.md](dhcp.md) (section 13 DDNS, section 17 the home cut-over), [SECURITY-PROFILES.md](SECURITY-PROFILES.md) (TGL-09, TGL-29), [dns-resolver.md](dns-resolver.md) (forwarding rules and the recursion access list), [MIGRATION.md](MIGRATION.md).

Contents:

1. [The goal and the end state](#1-the-goal-and-the-end-state)
2. [What Active Directory needs from DNS](#2-what-active-directory-needs-from-dns)
3. [The `_msdcs` zone](#3-the-_msdcs-zone)
4. [Unsecured updates, GSS-TSIG and the profiles](#4-unsecured-updates-gss-tsig-and-the-profiles)
5. [Prerequisites](#5-prerequisites)
6. [The DNS steps](#6-the-dns-steps)
7. [The DHCP steps](#7-the-dhcp-steps)
8. [Rollback by phase](#8-rollback-by-phase)
9. [The two verified answers](#9-the-two-verified-answers)
10. [Sources](#10-sources)

Every name and address below is a placeholder. Put in your own:

| Placeholder | Stands for |
|---|---|
| `corp.example.test` | The AD DNS domain, which is also the forest root (a single-domain forest is assumed), and the name of the zone |
| `_msdcs.corp.example.test` | The forest-wide locator zone (section 3) |
| `dc1.corp.example.test`, `dc2.corp.example.test` | The domain controllers, at `192.0.2.5` and `192.0.2.6`; both run the DNS Server and DHCP Server roles today |
| `tenko1.corp.example.test` | The Tenko node with the `dns` and `dhcp` roles, at `192.0.2.53` (one host for both, so the relay target of section 17 of [dhcp.md](dhcp.md) is `192.0.2.53` here) |
| `2.0.192.in-addr.arpa` | The reverse zone of `192.0.2.0/24` (an AD-integrated zone today) |
| `Default-First-Site-Name` | The AD site name |
| `192.0.2.0/26`, `192.0.2.64/26`, `198.51.100.0/24`, `203.0.113.0/25` | The four networks, as in [dhcp.md](dhcp.md) section 17 |
| `192.0.2.1`, `192.0.2.65`, `198.51.100.1`, `203.0.113.1` | The gateway in each network |

## 1. The goal and the end state

The goal is that nothing in the domain depends on the DNS Server or DHCP Server role of a controller, and that the controllers still do what controllers do: authenticate, replicate and be found.

| Area | End state |
|---|---|
| Zones | Tenko is the primary of `corp.example.test`, of `_msdcs.corp.example.test` (when AD has it as its own zone, section 3) and of the reverse zones. The DNS Server role is removed from both controllers |
| Records of the controllers | The controllers' Netlogon service registers its SRV, CNAME and A records in Tenko by RFC 2136 update, from the controllers' addresses only (section 4) |
| Clients | Every client and server, the controllers included, resolves through Tenko. Option 6 of every scope names Tenko. No forwarding rule sends the domain to a controller |
| DHCP | Tenko answers on all four networks. The Windows scopes are inactive, then the role is removed. Name protection is on (`conflict = protect`) |
| DNSSEC | Off by default in Home; on per zone if you choose, with the DS at the parent (step 6) |
| Left behind | The AD-integrated zone objects in the directory partitions, unless you delete them in step 9 |

The directory partitions `DomainDnsZones` and `ForestDnsZones` remain, because Microsoft does not let a DNS server leave them (section 6, step 9).

The profile is Home. Home and Standard can host an AD zone this way; the Hardened profile cannot yet, and section 4 says why.

## 2. What Active Directory needs from DNS

Active Directory needs a DNS server that answers the locator records of its controllers and, preferably, accepts the controllers' dynamic updates of them. It does not need that server to run on a controller, to store its zones in the directory, or to be Microsoft DNS. Microsoft states the minimum as support for the SRV record type and, to save work, for dynamic update (RFC 2136); a server without dynamic update works when the records are added by hand from `Netlogon.dns`. The two Microsoft pages that say this are written for Windows 2000 and 2003 and are archived; the Netlogon behaviour they describe is the one the current support articles in the Sources still describe.

The Netlogon service of each controller registers these records. `<site>` is `Default-First-Site-Name` here, `<guid>` is the domain GUID and `<dsa>` the GUID of the controller's directory service agent.

| Record | Type | Used for |
|---|---|---|
| `_ldap._tcp.corp.example.test`, `_ldap._tcp.<site>._sites.corp.example.test` | SRV | An LDAP server of the domain, and in a site |
| `_ldap._tcp.dc._msdcs.corp.example.test`, `_ldap._tcp.<site>._sites.dc._msdcs.corp.example.test` | SRV | A domain controller, and in a site (the DC locator) |
| `_ldap._tcp.pdc._msdcs.corp.example.test` | SRV | The PDC emulator (registered by that controller only) |
| `_ldap._tcp.gc._msdcs.corp.example.test`, `_ldap._tcp.<site>._sites.gc._msdcs.corp.example.test` | SRV | A global catalog server, and in a site |
| `_gc._tcp.corp.example.test`, `_gc._tcp.<site>._sites.corp.example.test` | SRV | A global catalog server (the generic form) |
| `_ldap._tcp.<guid>.domains._msdcs.corp.example.test` | SRV | A controller of a domain found by GUID (after a rename) |
| `_kerberos._tcp.corp.example.test`, `_kerberos._udp.corp.example.test`, `_kerberos._tcp.<site>._sites.corp.example.test` | SRV | A Kerberos KDC |
| `_kerberos._tcp.dc._msdcs.corp.example.test`, `_kerberos._tcp.<site>._sites.dc._msdcs.corp.example.test` | SRV | The Windows KDC of a controller |
| `_kpasswd._tcp.corp.example.test`, `_kpasswd._udp.corp.example.test` | SRV | The Kerberos password change service |
| `_ldap._tcp.DomainDnsZones.corp.example.test`, `_ldap._tcp.<site>._sites.DomainDnsZones.corp.example.test`, `_ldap._tcp.ForestDnsZones.corp.example.test` | SRV | A controller that holds a replica of an application partition (the DNS partitions) |
| `<dsa>._msdcs.corp.example.test` | CNAME | A controller by the GUID of its directory service agent, for replication |
| `corp.example.test`, `gc._msdcs.corp.example.test` | A | Clients that do not read SRV records |

Rows 1 to 9, the CNAME and the A records come from Microsoft's description of the records Netlogon registers; the partition row from its description of how a client finds the host of an application partition, which says that Netlogon registers `_ldap._tcp.<partition name>` and the site form. If your export holds A records at `DomainDnsZones.corp.example.test` and `ForestDnsZones.corp.example.test`, they came with the import; the pages read do not list them among the records Netlogon registers, so treat them as data of the DNS Server role and delete them in step 9 if nothing uses them. The host records of the controllers themselves (`dc1.corp.example.test`, A and PTR) are registered by the DNS client, not by Netlogon, in the same way as any client's.

What is not needed: a DNS Server role on any controller; zones stored in `DomainDnsZones` or `ForestDnsZones`; secure dynamic update as such; WINS (CON-12). What is needed from the neighbouring DNS: a delegation of `corp.example.test` in its parent zone when a parent exists that is not Tenko, and forwarders or recursion for names outside the domain, which Tenko's resolver provides ([dns-resolver.md](dns-resolver.md)).

## 3. The `_msdcs` zone

Since Windows Server 2003 the forest-wide locator records live in a zone of their own, `_msdcs.<forest root>`, created beside the domain zone when the first controller of a forest is promoted with DNS. It is stored in the forest-wide partition `ForestDnsZones`, which replicates to every DNS server in the forest, while the domain zone replicates only to the DNS servers of its domain. Microsoft gives the reason: the locator records let replication partners find each other and let clients find global catalog servers, so they must be available forest-wide. Microsoft says that the promotion creates and delegates the zone; the delegation is an NS set at the name `_msdcs` in the domain zone that names the DNS servers of the `_msdcs` zone (the check below shows yours). In a forest created on Windows 2000 and upgraded, `_msdcs` can still be a plain subdomain inside the domain zone without a zone of its own; the check below tells which you have.

Check on a controller:

```powershell
Get-DnsServerZone | Where-Object { $_.ZoneName -like "_msdcs.*" }
Get-DnsServerResourceRecord -ZoneName corp.example.test -Name _msdcs -RRType NS
```

A zone in the first list and NS records in the second mean the split design. An empty first list means `_msdcs` is inside the domain zone.

What this means for Tenko:

| Question | Answer |
|---|---|
| One zone or two | Mirror what AD has today. Split design: two primary zones, `corp.example.test` and `_msdcs.corp.example.test`. Unsplit design: one zone, and do not split during the migration |
| The delegation | In `corp.example.test`, the NS set at `_msdcs` names Tenko's name servers (`tenko1.corp.example.test`), and `tenko1.corp.example.test` has an A record in the domain zone. Only NS and glue may stand at a delegation point ([dns.md](dns.md) section 2). Tenko serves both zones itself, and a query is answered from the zone with the longest matching apex (check it, step 3), so the delegation is for other resolvers and for the structure AD expects |
| SOA of each | Each zone has its own SOA. `mname` is `tenko1.corp.example.test` in both, because a Windows client finds the server to update by asking for the SOA of its name and sending the update to the `mname`. Serial policy `date_counter` |
| NS of each | The apex NS set of both zones names Tenko's name server or servers and no controller. The import brings the controllers' NS records; step 3 replaces them |
| Updates | Both zones need the access list of step 4: the controllers register their SRV, CNAME and A records in `_msdcs`, and their locator A record and the `_ldap`, `_kerberos` and `_kpasswd` records in the domain zone |
| Child domains | A child domain's own `_msdcs.<child domain>` records live in the child's zone; the rest of this page assumes a single domain |

## 4. Unsecured updates, GSS-TSIG and the profiles

Windows secures a dynamic update with GSS-TSIG (RFC 3645) over TKEY, with Kerberos as the only mechanism Windows clients and servers use. A zone in Active Directory defaults to accepting secure updates only, and then each record belongs to the account that created it. Tenko does not support GSS-TSIG until Phase 4 (DNS-28; [dns.md](dns.md) section 13.9), and a static TSIG key cannot stand in for it, since a Windows dynamic update client cannot sign with one.

Until then the AD zone takes unsigned updates, which the zone's update policy allows in the Home and Standard profiles:

| Setting | Value for the AD zones |
|---|---|
| `allowed` | One access list that holds the controllers' addresses as `/32` prefixes (and the `/128` of any IPv6 address a controller registers from) |
| `require_tsig` | `false` |
| `may_replace_ipam` | `false`, unless IPAM manages a name a controller registers (then an update of that name is refused with `dns.update.refused`) |

Home and Standard allow this per zone. Hardened refuses an unsigned update whatever the zone says (TGL-09), so a Hardened installation cannot host an AD zone that takes dynamic updates until GSS-TSIG ships. A Hardened installation can still serve the zone with static records (the variant below), and the Lab profile accepts unsigned updates by its nature.

What the access list protects against, and what it does not:

- It protects the zone from updates sent from any other address. A workstation, a phone or an IoT device cannot register a name or overwrite a locator record; its update is REFUSED and audited as `dns.update.refuse`.
- It does not authenticate the sender. An update is accepted because of its source address, so a host on the same segment that sends from a controller's address (UDP is easy to forge) is accepted. GSS-TSIG signs each message with a Kerberos session key and does not have this weakness.
- It does not bind a record to its creator. Windows secure update gives each record an owner, and Microsoft's own description is that a DHCP server that registers a name becomes the only account that may update it. Tenko tracks ownership per RRset by origin (`manual`, `dynamic`, `dhcp`, `ipam`, `transfer`, `dnssec`), not by account; from an allowed address an update can change any RRset except the ones owned by IPAM (unless `may_replace_ipam`), a transfer or the signer. The per-RRset ownership of the Windows zones is not carried by the import (the ACLs are only in the directory, [MIGRATION.md](MIGRATION.md) Known non-exportable data).
- It does not stop a replay of a captured update, or a compromised controller.

Compensate by keeping the controllers on a network segment where source addresses cannot be forged (a VLAN with the gateway's anti-spoofing enabled), by keeping the list to the controllers, by not adding client networks to it, and by watching `dns.update.refuse` and `dns.update.apply` in the audit log ([dns.md](dns.md) section 13.7).

Member computers and servers with a static address cannot register themselves on this footing: their unsigned update is refused and their secure update cannot be negotiated. Tenko DHCP writes the names of DHCP clients itself, by the internal path that TGL-09 does not govern (TGL-29, [dhcp.md](dhcp.md) section 13), so those clients need nothing. Hosts with static addresses get their records by hand or from IPAM. Opening the list to the client networks would let them register, and would let every host in those networks overwrite any record of the zone, the locator records included; do not.

**Variant: static registration.** When the profile forbids unsigned updates, or you do not want them, switch the dynamic registration of the controllers off and keep the records in Tenko by hand. Setting `UseDynamicDns` to 0 in `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters` makes Netlogon stop registering, and Microsoft says the records in `%SystemRoot%\System32\Config\Netlogon.dns` must then be registered manually; that file lists the records a controller needs, in zone file format, and `tenko dns import` reads it. Delete `Netlogon.dnb` and restart Netlogon for the setting to take effect. Cost: nothing re-registers by itself, so a changed controller address, a new controller or a moved global catalog needs a new import, and `dcdiag /test:dns` may report the missing dynamic registration.

## 5. Prerequisites

| What | How | Checked by |
|---|---|---|
| The profile | Home or Standard. Settings, Security profile | The settings page names the profile |
| Tenko node | `roles = "controller,dns,dhcp"` (the `dhcp` role in relay mode, [dhcp.md](dhcp.md) section 17.1); a fixed address, `192.0.2.53`; UDP and TCP 53 and UDP 67 open from the networks that use it | `GET /api/v1/nodes/{id}/dns` and `/dhcp` report `serving` |
| Time | The node's clock is synchronized (OPS-09); Kerberos on the controllers tolerates five minutes of skew | `w32tm /stripchart /computer:192.0.2.5` against the controllers |
| The controllers' addresses | Every address a controller can send an update from: its IPv4 address on the network that reaches Tenko, and any IPv6 address it registers. A multi-homed controller sends from the address of the interface that routes to Tenko | `Get-NetIPAddress` on each controller |
| The state of AD DNS | The zones and their storage and replication scope, the forwarders, the aging settings, whether `_msdcs` is a zone of its own (section 3) | Output of the commands in step 1, saved |
| A health baseline | `dcdiag /test:dns /v` and `repadmin /replsummary` pass before you start, so that a failure afterwards is yours | The saved output |
| Backups | The exports of step 1, and a system state backup of one controller | The files exist and are not empty |
| Recursion access | Tenko's resolver answers the clients' networks: under Home the default is the prefixes known to IPAM (TGL-22), so each network must be an IPAM prefix | `dig @192.0.2.53 www.example.net` from a client network |
| A quiet window | No domain join, no controller promotion and no network change while steps 2 to 7 run | |

## 6. The DNS steps

Each step has what to do, how to check it, and the way back. Steps 2 to 4 change nothing the domain uses; step 5 is the first step that does.

### Step 1. Record the starting state and take the backups

On a controller:

```powershell
Get-DnsServerZone | Format-Table ZoneName, ZoneType, IsDsIntegrated, ReplicationScope, DynamicUpdate, SecureSecondaries
Get-DnsServerForwarder
Get-DnsServerZoneAging -Name corp.example.test
foreach ($z in 'corp.example.test','_msdcs.corp.example.test','2.0.192.in-addr.arpa') {
  Export-DnsServerZone -Name $z -FileName "$z.bak"
}
dnscmd /ZoneExport corp.example.test corp.example.test.dns
Export-DhcpServer -ComputerName dc1.corp.example.test -File C:\export\dhcp.xml -Leases
Get-DhcpServerv4Scope | Get-DhcpServerv4DnsSetting
```

`Export-DnsServerZone` and `dnscmd /ZoneExport` write into `%SystemRoot%\System32\dns` on the server and take a file name, not a path. Microsoft says the exported file is for troubleshooting and is not in the format of a file-backed zone file, so keep these as the backup and as the way back, and bring the data into Tenko by zone transfer (step 2), which does not depend on that format. Copy the files off the controller. Keep `dhcp.xml`: it holds the scopes, options, reservations and leases that step 10 reads. List every zone that is AD-integrated; reverse zones are zones too.

Check: the files exist and the `Get-DhcpServerv4DnsSetting` output shows `NameProtection` per scope, which step 10 needs.

Way back: none needed; nothing was changed.

### Step 2. Bring the zones into Tenko, and build the scopes without serving them

Tenko takes the zones by AXFR as secondary zones, exports them as zone files, and creates primary zones from the files. (A secondary zone cannot change kind; its records are read only.) The transfer has the access path and the limits of [dns.md](dns.md) section 10.13, and Windows DNS does not sign transfers, so the access rests on the address restriction on both sides.

On a controller, allow the transfer of each zone to the node and nothing else:

```powershell
foreach ($z in 'corp.example.test','_msdcs.corp.example.test','2.0.192.in-addr.arpa') {
  Set-DnsServerPrimaryZone -Name $z -SecureSecondaries TransferToSecureServers `
    -SecondaryServers 192.0.2.53 -Notify NotifyServers -NotifyServers 192.0.2.53
}
```

TCP 53 from the node to the controller must be open. On the Tenko node, one secondary zone per zone, with the controller as primary (the command line creates primary zones only):

```
POST /api/v1/dns/zones
{"name": "corp.example.test", "kind": "secondary",
 "soa": {"mname": "dc1.corp.example.test", "rname": "hostmaster.corp.example.test"},
 "source": {"primaries": [{"address": "192.0.2.5", "port": 53}]}}
```

Repeat for `_msdcs.corp.example.test` and each reverse zone. Then, for each zone, compare the serials, export, remove the secondary zone, create the primary zone and import:

```
tenko dns transfer status corp.example.test
dig @192.0.2.5 corp.example.test SOA +short
dig @192.0.2.53 corp.example.test SOA +short
tenko dns export corp.example.test --file corp.example.test.zone
tenko dns zone delete corp.example.test
tenko dns zone create corp.example.test --kind primary --ns tenko1.corp.example.test \
  --mname tenko1.corp.example.test --rname hostmaster.corp.example.test --serial date_counter
tenko dns import corp.example.test corp.example.test.zone --dry-run
tenko dns import corp.example.test corp.example.test.zone
```

The export route does not look at the zone kind. If a build refuses it, `dig @192.0.2.5 corp.example.test AXFR +noall +answer` gives the records; the second SOA that `dig` prints is reported as a loss (`dns.zonefile.soa`). Read the dry run: the records per type, and the losses. Records of a class other than IN, records outside the zone and names the model refuses (`dns.zonefile.class`, `.outside_zone`, `.data`) are listed and not imported; an AD zone should have none. WINS and WINS-R records, if the zone has them, are not served (CON-12). The import writes `manual` records. The SOA of the file becomes the zone's SOA (its `mname` is still `dc1` until step 3), and the NS set of the file replaces the zone's, so the apex NS names the controllers until step 3.

Remove the transfer permission afterwards, so the controller does not keep notifying a node that no longer needs it:

```powershell
foreach ($z in 'corp.example.test','_msdcs.corp.example.test','2.0.192.in-addr.arpa') {
  Set-DnsServerPrimaryZone -Name $z -SecureSecondaries NoTransfer -Notify NoNotify
}
```

Build the scopes now, so that step 10 is a switch and not an afternoon. A scope per network, its pool as an IPAM range of role `dhcp_pool` covering the same addresses as the Windows scope, the exclusions, the reservations as IPAM hosts of mode `reserved`, and the options of the Windows scope, exactly as in [dhcp.md](dhcp.md) section 17.1 (`Get-DhcpServerv4OptionValue -ScopeId 192.0.2.0 -All` lists them). The Windows adapter of Phase 4 (MIG-08) reads `dhcp.xml` and does this; until then it is manual. Option 6 is `192.0.2.53` and option 15 is `corp.example.test`:

```
tenko dhcp scope create <prefix-id>
tenko dhcp option set scope:<prefix-id> 3=c0000201 6=c0000235 15=636f72702e6578616d706c652e74657374
```

(`c0000201` is `192.0.2.1`, `c0000235` is `192.0.2.53`, the third value is `corp.example.test`.) A scope does not answer until the gateway relays to the node, so building them changes nothing on the networks. Leave DDNS for step 10.

Check: `tenko dns zone list` shows the primary zones with their record counts; for a few names, `dig @192.0.2.53 <name>` and `dig @192.0.2.5 <name>` give the same answer; the audit log has `dns.zone.transfer_in` for each secondary and `dns.zone.export` for each export.

Way back: delete the Tenko zones (`tenko dns zone delete`), and on the controllers set `-SecureSecondaries NoTransfer -Notify NoNotify`. The controllers' zones were never changed.

### Step 3. Make Tenko a correct primary of the AD zones

The imported zone still names the controllers as its servers. Set the SOA and replace the NS sets, give the name server an address, and make the delegation point at Tenko. Through the batch route (`POST /api/v1/dns/zones/{id}/records/batch`, [dns.md](dns.md) section 3), for the domain zone:

```
{"changes": [
  {"op": "set", "name": "corp.example.test", "type": "NS",
   "records": [{"type": "NS", "host": "tenko1.corp.example.test"}]},
  {"op": "set", "name": "tenko1.corp.example.test", "type": "A",
   "records": [{"type": "A", "address": "192.0.2.53"}]},
  {"op": "set", "name": "_msdcs.corp.example.test", "type": "NS",
   "records": [{"type": "NS", "host": "tenko1.corp.example.test"}]}]}
```

and for the `_msdcs` zone only the apex NS set. Leave the `_msdcs` change out of the domain zone's batch when AD has no zone of its own for it (section 3). Change the SOA `mname` of each zone to `tenko1.corp.example.test` with `PATCH /api/v1/dns/zones/{id}` (`{"soa": {"mname": "tenko1.corp.example.test", "rname": "hostmaster.corp.example.test"}}`). Leave the controllers' own A records (`dc1`, `dc2`) in the zone; they are ordinary hosts now. The aging timestamps of the Windows records are not carried (DNS-29 is Phase 4), so Tenko does not scavenge anything and the stale records of the old zone stay until you delete them.

Check, from a client or the node:

```
dig @192.0.2.53 corp.example.test SOA +short
dig @192.0.2.53 corp.example.test NS +short
dig @192.0.2.53 _msdcs.corp.example.test SOA +short
dig @192.0.2.53 _ldap._tcp.dc._msdcs.corp.example.test SRV +short
dig @192.0.2.53 _msdcs.corp.example.test NS +short
```

The SOA of `_msdcs.corp.example.test` must come from the `_msdcs` zone, not from the domain zone; if the domain zone answers, the zone does not exist or the name is wrong. The SRV query must list both controllers, as it did on the controllers.

Way back: the zones are not used yet; repeat step 2 for a fresh copy.

### Step 4. The access list and the update policy

Create the access list and switch the update policy of the domain zone, the `_msdcs` zone and the reverse zones to it ([dns.md](dns.md) sections 6 and 13.2):

```
tenko dns acl create ad-controllers --entry 192.0.2.5/32 --entry 192.0.2.6/32
```

```
PATCH /api/v1/dns/zones/{id}
{"update": {"allowed": ["<id of ad-controllers>"], "require_tsig": false, "may_replace_ipam": false}}
```

The settings tab of a primary zone has the same fields in "Dynamic updates", and shows the profile's rule beside the switch. The list names only the controllers. Under Hardened the unsigned update stays refused (section 4). Leave `update.dhcp` unset: under Home it follows the profile and lets Tenko DHCP write into the zone, and under Standard set it to `true` on the forward zone and the reverse zones when step 10 turns DDNS on.

Check: from a host that is not on the list, `nsupdate` of a test name is REFUSED and `dns.update.refuse` appears in the audit log. That the controllers' updates are accepted is checked in step 5.

```
nsupdate
> server 192.0.2.53 53
> zone corp.example.test
> update add updatetest.corp.example.test 60 IN A 192.0.2.250
> send
```

(`nsupdate` is the BIND tool; run it from a Linux host or WSL.)

Way back: `PATCH` the zones' `update` to `{"allowed": [], "require_tsig": true}`; the list can then be deleted (`tenko dns acl delete`).

### Step 5. Point the controllers at Tenko and have them register

A Windows client sends its update to the primary server named in the SOA it gets from its own configured DNS server. Today that is the controller's own DNS Server, which answers with itself, so nothing reaches Tenko until the controller asks Tenko. On each controller, one at a time, set Tenko as the preferred DNS server and keep the controller's own address as the alternate:

```powershell
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.0.2.53,192.0.2.5   # dc1; on dc2 the alternate is 192.0.2.6
Clear-DnsClientCache
nltest /dsregdns
ipconfig /registerdns
```

(`ipconfig /registerdns` is right here: a controller has a static address and no DHCP server to negotiate with.) `nltest /dsregdns` refreshes the registration of all DNS records that are specific to the controller; restarting the Netlogon service does the same. The records are also re-registered when the service starts and, Microsoft documents, every hour. Check what the service thinks happened:

```powershell
nltest /dsquerydns
```

Check in Tenko that the controllers' records arrived and who wrote them:

```
GET /api/v1/dns/zones/{id}/records?name=_ldap&origin=dynamic
dig @192.0.2.53 _ldap._tcp.dc._msdcs.corp.example.test SRV +short
dig @192.0.2.53 _ldap._tcp.gc._msdcs.corp.example.test SRV +short
dig @192.0.2.53 _gc._tcp.corp.example.test SRV +short
dig @192.0.2.53 _kerberos._tcp.corp.example.test SRV +short
dig @192.0.2.53 _kpasswd._tcp.corp.example.test SRV +short
dig @192.0.2.53 gc._msdcs.corp.example.test A +short
dig @192.0.2.53 _ldap._tcp.DomainDnsZones.corp.example.test SRV +short
```

or the same with `nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.example.test 192.0.2.53` or `Resolve-DnsName -Type SRV -Server 192.0.2.53 <name>`. Every query lists both controllers (the global catalog queries list the ones that are global catalog servers). The audit log has `dns.update.apply` with the controllers' addresses and `tenko_dns_updates_total{outcome="ok"}` rises; `refused` should not move. Then `nltest /dsgetdc:corp.example.test /force` and `nltest /dnsgetdc:corp.example.test /force` on a controller return a controller found through Tenko.

If the updates are refused or never arrive, `dns.update.refuse` names the reason (the address not on the list, an RRset owned by IPAM, a zone that is not primary here), and the DC's `Netlogon.log` in `%SystemRoot%\Debug` and event 5774 of the NETLOGON source say that a record could not be registered. A group policy that sets Update Security Level to secure only (value 256) stops the unsigned update; see section 9.

Do the second controller after the first checks out.

Way back: set each controller's DNS list back to its own address (`Set-DnsClientServerAddress ... -ServerAddresses 192.0.2.5`) and run `nltest /dsregdns` again; the controller's own DNS Server answers the SOA with itself again and registers in its own zone. The records the controllers wrote into Tenko are harmless and go with the zone.

### Step 6. DNSSEC on the AD zones (optional)

Windows clients are not validating resolvers by default, and an AD zone usually has a private name, so there is usually nothing to gain: the Home profile leaves new zones unsigned (TGL-13) and so should you. Sign the zones only when the domain name is a delegated public name whose parent you control and a validating resolver will ask for it, or because you want the practice.

If the Windows zones were signed, the private keys do not come over ([MIGRATION.md](MIGRATION.md) Known non-exportable data): Tenko signs with new keys, and the DS at the parent must be replaced. Remove the old DS first and wait out its TTL.

To sign:

```
tenko dns dnssec enable corp.example.test
tenko dns dnssec enable _msdcs.corp.example.test
tenko dns dnssec status corp.example.test
```

Then the chain, from the bottom: the DS of `_msdcs.corp.example.test` goes into the domain zone as an RRset at the delegation (a `set` change of type DS at `_msdcs.corp.example.test`, [dnssec.md](dnssec.md) section 3), and the DS of `corp.example.test` goes to its parent: your registrar when the name is public, the parent zone when Tenko serves it, or the trust anchor of the validating resolvers (`tenko dns trust-anchor add`) for a private name. Until the parent holds the DS the zone validates as insecure, which is the same as unsigned.

The controllers' updates keep working: Tenko signs every change again after it is written (an incremental pass over the changed RRsets, so a change shows as two serial steps on a secondary: the change and the signer's pass), and the types the signer writes (DNSKEY, RRSIG, NSEC, NSEC3, CDS and CDNSKEY) are the only ones refused from a client. The records of a controller (SRV, CNAME, A) are not among them. A signed answer with the locator SRV sets is larger and may be truncated to TCP, to which the resolver on the client falls back. Netlogon repeats its registration every hour: watch the zone's serial for a few hours after the first signing. A serial that moves every hour on an unchanged zone means each re-registration is written and signed again; report it if you see it.

Check: `tenko dns dnssec status` shows the keys and the DS; `dig @192.0.2.53 corp.example.test DNSKEY +dnssec` answers; with the DS at the parent, a validating resolver returns the AD flag.

Way back: remove the DS at the parent first, wait its TTL, then `tenko dns dnssec disable corp.example.test`. Turning signing off while the parent still holds a DS makes the zone fail validation (bogus) at validating resolvers.

### Step 7. Repoint the clients and remove the forwarding rule

Do this in one window with step 5, so that the old and the new copy of the zone do not drift apart, and change nothing in the old zones from step 2 on. If records were registered or edited there since the export, list them and add them in Tenko before clients move (dynamic records carry a timestamp: `Get-DnsServerResourceRecord -ZoneName corp.example.test | Where-Object { $_.Timestamp -gt (Get-Date "<time of the export>") }`).

1. **The scopes that still answer.** The Windows scopes serve DHCP until step 10, so set their DNS server option to Tenko; clients take it at their next renewal (shorten the lease time first, as in the preparation of step 10, or renew by hand with `ipconfig /renew`):

   ```powershell
   Set-DhcpServerv4OptionValue -ComputerName dc1.corp.example.test -DnsServer 192.0.2.53
   Set-DhcpServerv4OptionValue -ComputerName dc1.corp.example.test -ScopeId 192.0.2.0 -DnsServer 192.0.2.53
   ```

   The Tenko scopes already carry option 6 (step 2).
2. **Hosts with static DNS settings.** Servers, printers and the like, by hand or by group policy, one network at a time. The controllers' own adapters last: when every other client has moved, set each controller's list to Tenko only, one controller at a time: `Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.0.2.53`. A second Tenko node, when you run one, goes in the list beside the first.
3. **The forwarding rule for the domain.** Remove the rule that sends `corp.example.test` to a controller wherever it exists: on the gateway or another resolver (a conditional forward or a `server=/corp.example.test/` line), on Tenko if the parallel period used Forward mode (`tenko dns forwarder delete corp.example.test`), and the conditional forwarders on the controllers. A zone Tenko serves is answered before any rule ([dns-resolver.md](dns-resolver.md) section 1), so the rule on Tenko is harmless but misleading. If a parent zone delegates `corp.example.test` to the controllers' names, change that delegation to Tenko's name server and glue (Microsoft calls these the delegation records in the parent zone).
4. **Freeze the old copy.** Set the zones on the controllers to refuse updates, so a client that still points at a controller fails loudly instead of registering in a copy nobody reads:

   ```powershell
   foreach ($z in 'corp.example.test','_msdcs.corp.example.test','2.0.192.in-addr.arpa') {
     Set-DnsServerPrimaryZone -Name $z -DynamicUpdate None
   }
   ```

Check: `ipconfig /all` on a client shows `192.0.2.53` as its DNS server; the query log of Tenko (on for the parallel period, step 8) shows the clients' addresses and not the controllers' only; `nslookup corp.example.test` and `nltest /dsgetdc:corp.example.test /force` on a member server work.

Way back: option 6 back to the controllers on the Windows scopes, the static settings back, the controllers' own lists to their own addresses, the forwarding rule back, and `-DynamicUpdate Secure` on the zones.

### Step 8. The parallel period

Keep both servers for a week: the controllers' DNS Server roles are installed and answer, with their frozen zones, for any client you missed; Tenko is what everything uses. A week covers the hourly Netlogon registration, the refresh of the clients' host records (24 hours by default on one Microsoft page, seven days on another) and the lease time of the DHCP scopes several times over. What to watch:

| What | Where | Healthy |
|---|---|---|
| Who still asks the controllers | The query counters of the DNS Server service (Performance Monitor), or a packet capture on port 53 at a controller | Nothing from clients, only the controllers' own queries |
| Who asks Tenko | Switch the query log on for the period (TGL-15, `[dns]` settings, [dns.md](dns.md) section 8) and read the clients' addresses | Every network |
| Update refusals | The audit action `dns.update.refuse`, the metric `tenko_dns_updates_total{outcome="refused"}` | None from the controllers; one from a static host means that host tried to register (section 4) |
| Updates written | `dns.update.apply`, `outcome="ok"` | The controllers' hourly registration, a quiet zone otherwise |
| The locator | `nltest /dsgetdc:corp.example.test /force` and `nltest /dnsgetdc:corp.example.test /force` from a controller and a member | A controller is found |
| The health test | `dcdiag /test:dns /v` on each controller | The tests that read the zone data pass (see below) |
| Replication | `repadmin /replsummary` | No errors; DNS does not carry AD replication, but a failed SRV lookup would show here first |
| Event logs | NETLOGON events 5774 on the controllers; the Tenko system status | None |

`dcdiag /test:dns` runs its checks with DNS, RPC and WMI against the DNS server it finds. The record-registration and delegation tests read Tenko's data through DNS and should pass; the tests that ask the Windows DNS Server service itself (its configuration, its forwarders, whether the zone is AD-integrated) cannot pass once the role is gone and, because Tenko is not a Windows service, expect findings there that are not faults. Run the test before step 5 and keep the output, so that you know which findings were there already.

Way back: as step 7.

### Step 9. Remove the DNS Server role from the controllers

When the parallel period is clean and no client asks a controller for DNS:

1. Take a last export from Tenko of each zone (`tenko dns export`) and store it with the Windows exports of step 1.
2. Delete the AD-integrated zones, or leave them (see below).
3. On each controller, one at a time: `Uninstall-WindowsFeature -Name DNS`, restart if asked. Then set the controller's adapters to Tenko only (step 7, item 2, if you left the alternate in place until now).
4. Re-run `nltest /dsregdns` on both controllers and the checks of step 5.

The zone data the role leaves in the directory. The zones are objects in the directory partitions `DomainDnsZones` and `ForestDnsZones`. Microsoft documents that a DNS server cannot be removed from those two partitions, and the pages read for this page say that removing the role removes the service; none of them says that it deletes the zone objects, so expect them to stay and to go on replicating. They are inert without a DNS Server service, with one hazard to expect: a controller that later gets the role installed would load those zones and could serve them as authoritative, with a stale copy of your data. Two ways to deal with that:

- **Leave them.** Nothing breaks; write down that the stale zones exist, and check `Get-DnsServerZone` before the role is ever installed on a controller again.
- **Delete them first.** Before the uninstall and when the rollback window is over, run `Remove-DnsServerZone -Name corp.example.test -Force` on a controller that still has the role, for each zone including `_msdcs.corp.example.test` and the reverse zones. This deletes the zone's objects from the directory and the deletion replicates, so do it only with the exports stored and Tenko verified. Prefer the cmdlet to a directory editor.

Check: `Get-Service DNS` on the controllers says the service does not exist; the default tests of `dcdiag` pass; clients still log on, join and fetch group policy; the SRV queries of step 5 still answer.

Way back: reinstall the role (`Install-WindowsFeature DNS`). Zones that were not deleted come back with it, stale by the length of the parallel period. Zones that were deleted: load a stored Tenko export as a file-backed zone (`Add-DnsServerPrimaryZone -Name corp.example.test -ZoneFile corp.example.test.zone -LoadExisting`, with the file in `%SystemRoot%\System32\dns`) and convert it (`ConvertTo-DnsServerPrimaryZone -ReplicationScope Domain`), or restore the system state backup of step 1. Confirm both cmdlets with `Get-Help` on your version.

## 7. The DHCP steps

This part follows section 17 of [dhcp.md](dhcp.md), the home cut-over, step for step; read it first. What is particular to a Windows DHCP server on a domain controller is below. Windows DHCP failover between the controllers is not interoperable (CON-05): Tenko reads the relationship into the loss report in Phase 4, and the cut-over switches off both servers' scopes.

### Step 10. Switch the networks

**Prepare.** Step 2 built the scopes. Per section 17.1: shorten the lease time on the Windows scopes to an hour a lease time ahead (`Set-DhcpServerv4Scope -ScopeId 192.0.2.0 -LeaseDuration 01:00:00`), and know where each network's relay is set on the gateway.

**Name protection.** A Windows scope with Name Protection stores a DHCID record beside the name (RFC 4701) and refuses a registration from a client with another identifier (RFC 4703). The Phase 4 import carries the flag; until then read it in the step 1 output (`NameProtection`, `DynamicUpdates`) and set the same on the scope's DDNS tab, or with `PATCH /api/v1/dhcp/scopes/{prefix}` and its `ddns` object. The mapping the import uses ([dhcp-contracts.md](dhcp-contracts.md)):

| Windows (`Get-DhcpServerv4DnsSetting`) | Tenko (`ddns` of the scope) |
|---|---|
| `NameProtection` true | `conflict = protect` (the default; Hardened forces it) |
| `DynamicUpdates` Always | `enabled`, `client_may_update_a = false`: the server writes A and PTR |
| `DynamicUpdates` OnClientRequest | `enabled`, `client_may_update_a = true`: the client writes its A record and the server the PTR |
| `DynamicUpdates` Never | not `enabled` |
| `UpdateDnsRRForOlderClients` | `legacy_clients` |
| `DisableDnsPtrRRUpdate` | `reverse = false` |

Windows keeps its DNS credential for DHCP in the server, and its password is not carried; Tenko's DHCP writes through the zone service and needs none. The forward zone is the scope's domain name (option 15), which is `corp.example.test`. A zone takes DHCP updates by the zone's `update.dhcp`: unset follows the profile (Home yes, Standard no, [dhcp.md](dhcp.md) section 13.1).

**The records Windows DHCP wrote.** Tenko DHCP replaces only records it wrote itself: the origin rules ([dhcp.md](dhcp.md) section 13.4) refuse a name whose A record has the origin `manual` or `dynamic`. The A, DHCID and PTR records of DHCP clients that came over with the import are `manual`, and the ones Windows DHCP wrote during the parallel period are `dynamic`, so the first renewal of such a client would be refused. Before the first network is switched, delete them, so that Tenko writes them anew at the first renewal:

```
GET /api/v1/dns/zones/{id}/records?type=DHCID
POST /api/v1/dns/zones/{id}/records/batch
{"changes": [
  {"op": "delete", "name": "laptop.corp.example.test", "type": "A"},
  {"op": "delete", "name": "laptop.corp.example.test", "type": "DHCID"}]}
```

and the PTR records of the leased addresses in the reverse zones (`tenko dns record delete 2.0.192.in-addr.arpa 40 PTR` for `192.0.2.40`). Names without a DHCID are static and stay. A client is without a name until it renews; `ipconfig /renew` on the ones you care about. Reserved hosts whose names IPAM holds get their records from IPAM's DNS actuator with the origin `ipam`; a `manual` record of the same name left from the import is listed by the reconciler (`ipam.reconcile.*`), delete it there.

**Switch.** Per network, one at a time, the node's own network last, as in section 17.3: deactivate the Windows scope of the network on both controllers (`Set-DhcpServerv4Scope -ScopeId 192.0.2.0 -State InActive`), then set the gateway's DHCP for the network to relay to `192.0.2.53`. Two servers answering the same network give clients conflicting offers.

Check, per network, as in section 17.4: `ipconfig /release` and `/renew`, the address, `DHCP Server . . . : 192.0.2.53`, option 6 `192.0.2.53`; `dig @192.0.2.53 laptop.corp.example.test` for a client whose name DDNS writes, and the lease row's DDNS state in `GET /dhcp/leases/{addr}`; a second client that asks for the first one's name is refused, and the lease row says so. The DDNS tile of the start page counts names written.

Way back: section 17.6, below.

### Step 11. Remove the DHCP Server role

When the cut-over has held for a few days (E23's rows, [dhcp.md](dhcp.md) section 17.7): export the Windows configuration once more (`Export-DhcpServer`) and store it. Remove the authorization of each Windows DHCP server in the directory (`Get-DhcpServerInDC` lists them; `Remove-DhcpServerInDC` removes one), so that a reinstalled role does not start answering by itself; confirm the cmdlet names against `Get-Help` on your version. Then `Uninstall-WindowsFeature -Name DHCP` on each controller.

Way back: reinstall the role, authorize the server (`Add-DhcpServerInDC`), and `Import-DhcpServer -File dhcp.xml -Leases` from the export of step 1 (with `-BackupPath` as the cmdlet asks), then set the gateways back to relay or serve as in section 17.6.

## 8. Rollback by phase

Each phase can be undone alone until the one after it has begun; the later ones are listed first because they are the ones that end the rollback window.

| Phase | Changed | To roll back |
|---|---|---|
| Role removal (steps 9 and 11) | The DNS Server and DHCP Server roles are gone; the AD-integrated zones are perhaps deleted | Reinstall the roles. Zones not deleted come back stale. Zones deleted: recreate them from the exports of step 1 or restore the system state. Re-import the DHCP export and authorize the server. This is why the roles stay installed through steps 7 to 8 and 10 |
| DHCP switch (step 10) | The gateways relay to Tenko; the Windows scopes are inactive | Per network on the gateway: set DHCP back to the old server. On the controllers: `Set-DhcpServerv4Scope -ScopeId <id> -State Active`, and the lease time back. Renew the clients that matter; the others follow within half a lease time. Tenko keeps its leases; its scopes can be disabled so that a relay set by mistake gets no answer ([dhcp.md](dhcp.md) section 17.6). The names Tenko wrote stay in the zone with the origin `dhcp`; the Windows server's updates may change them as clients renew there, since an update of the origin `dynamic` may replace `dhcp` ([dns.md](dns.md) section 13.4) |
| Clients repointed (step 7) | Option 6 on the scopes, static DNS settings, the controllers' lists, forwarding rules, the frozen zones on the controllers | Reverse each item in the order of its list: the frozen zones first (`-DynamicUpdate Secure`), then the controllers' lists back to their own address, the static settings, option 6 and the forwarding rules. Records registered in Tenko since are lost to the old copy: a client re-registers into the controller's zone at its next refresh or with `ipconfig /registerdns` |
| Controllers registering in Tenko (step 5) | The controllers' DNS lists, and the records in Tenko | The controllers' own address back as the preferred server, then `nltest /dsregdns`. Nothing in the controllers' zones changed |
| DNSSEC (step 6) | Keys, DS at the parent | Remove the DS, wait its TTL, `tenko dns dnssec disable` |
| Zones and policy in Tenko (steps 2 to 4) | Only Tenko | Delete the zones in Tenko, delete the access list, remove the transfer permission on the controllers |

If the whole project is abandoned at any point before step 9, nothing is left to undo on the controllers but the settings above; their DNS zones were frozen and can be unfrozen in one command.

## 9. The two verified answers

These two were checked against Microsoft's pages (the Sources) because the steps depend on them. The pages for Windows 2000, 2003 and 2008 are archived, and where a statement rests on one of them alone, it says so.

### How the controllers register their records, and which setting governs the fallback

Netlogon registers the records of section 2 by dynamic update when the controller starts, when the Netlogon service starts and once an hour, and lists what it tries in `%SystemRoot%\System32\Config\Netlogon.dns`, which is also the list to register by hand after `UseDynamicDns` is set to 0; `nltest /dsregdns` refreshes the registration at once, `RegisterDnsARecords` and `DnsAvoidRegisterRecords` (or the group policy "Specify DC Locator DNS records not registered by the DCs") narrow it. The fallback from unsecured to secure update is the `UpdateSecurityLevel` value under `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters` (group policy "Update Security Level", one of the DNS Client policies): 0, the default, sends an unsecured update first and a secure one when it is refused, 16 sends unsecured only, 256 secure only. Microsoft documents that value as a setting of the DNS client, lists the Netlogon service's switches separately, and no page found says that Netlogon follows `UpdateSecurityLevel` or has a security level of its own, so this page does not rely on it: it relies on the default sequence being tried and accepted at the first (unsecured) step, and step 5 checks that an unsigned update reaches Tenko and is accepted.

What happens when the zone's server is not Microsoft DNS: it must support SRV records and should support dynamic update, and Microsoft says a server without dynamic update works when the records of `Netlogon.dns` are added by hand. Microsoft also says that with a third-party server you lose the DNS console, Active Directory integration, secure dynamic update and aging and scavenging. Dynamic update with Tenko is therefore unsecured by necessity until GSS-TSIG ships; where the update is refused, Netlogon logs event 5774 and retries at its next hourly registration.

### The `_msdcs.<forest root>` zone

Since Windows Server 2003 the first controller of a forest, promoted with DNS, creates `_msdcs.<forest root>` as a zone of its own in the forest-wide partition `ForestDnsZones`, so that the locator records that replication partners and global catalog clients need replicate to every DNS server of the forest and not only of the domain, and the domain zone is delegated to it with NS records at `_msdcs` (a forest upgraded from Windows 2000 may still keep `_msdcs` as a subdomain inside the domain zone). The zone holds the SRV records `_ldap._tcp.dc`, `_ldap._tcp.pdc`, `_ldap._tcp.gc`, `_kerberos._tcp.dc` and the `domains` GUID records under `_msdcs` (and their `_sites` forms), the `<dsa>` CNAME records and the `gc` A record. For Tenko that is two primary zones with their own SOA and NS (`mname` and NS naming Tenko), an NS delegation at `_msdcs` in the domain zone, the same update list on both, and one zone only when AD has only one.

## 10. Sources

Microsoft Learn pages, read for this page. The pages marked archived describe Windows 2000, 2003 or 2008 and are no longer updated; the current pages that say the same are listed beside them where they exist.

1. How DNS Support for Active Directory Works (Windows Server 2003, archived): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759550(v=ws.10)
2. Configuring Non-Windows 2000 DNS Servers to Support Active Directory (archived): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc959323(v=technet.10)
3. Dynamic Update and Secure Dynamic Update (Windows 2000 Server, archived): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc959275(v=technet.10)
4. Enable or disable DNS updates - Windows Server: https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/enable-disable-dns-dynamic-registration
5. Prevent domain controllers from dynamically registering DNS names - Windows Server: https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/prevent-domain-controllers-dns-names
6. Problems occur with DCs in AD integrated DNS zones - Windows Server: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/problems-with-dc-ad-integrated-dns-zones
7. Verify that SRV Domain Name System (DNS) records have been created - Windows Server: https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/verify-srv-dns-records-have-been-created
8. DNS Group Policy Settings (Windows Server 2008, archived): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd197486(v=ws.10)
9. Dynamic DNS Update in Windows and Windows Server: https://learn.microsoft.com/en-us/windows-server/networking/dns/dynamic-update
10. Configuring DNS for the Forest Root Domain (Windows Server 2008 R2, archived): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc771849(v=ws.10)
11. Locating an Application Directory Partition Host Server: https://learn.microsoft.com/en-us/windows/win32/ad/locating-an-application-directory-partition-host-server
12. Remove a DNS Server from a DNS Application Directory Partition (archived): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc772361(v=ws.11)
13. Remove Active Directory Domain Services (Level 100) (Windows Server 2012, archived): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh472163(v=ws.11)
14. Nltest (Windows Server 2008 R2, archived): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc731935(v=ws.10)
15. Event 5774, NETLOGON Error (Microsoft Q&A): https://learn.microsoft.com/en-us/answers/a/1976417
16. dcdiag: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dcdiag
17. Export-DnsServerZone: https://learn.microsoft.com/en-us/powershell/module/dnsserver/export-dnsserverzone
18. Back up a Zone File (`dnscmd /ZoneExport`, archived): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/ee649198(v=ws.10)
19. Export-DhcpServer: https://learn.microsoft.com/en-us/powershell/module/dhcpserver/export-dhcpserver
20. Configuring Name Protection (Windows Server 2008 R2, archived): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd759188(v=ws.11)

Not Microsoft, used only for the Windows 2000 layout of `_msdcs` and the commands that tell which layout a forest has:

21. DNS `_msdcs` zone modernization (AWS Directory Service Administration Guide): https://docs.aws.amazon.com/directoryservice/latest/admin-guide/hybrid_directory_msdcs.html

RFCs: 2136 (dynamic update), 3645 (GSS-TSIG), 4701 and 4703 (DHCID and name conflict resolution), 8945 (TSIG).
