# Tenko DDI Migration

Tenko DDI must take over from mixed sources without manual rework: AD-integrated and file-backed Windows DNS, Windows DHCP, BIND, OPNsense, dnsmasq and Pi-hole, Kea and ISC dhcpd, spreadsheets, and NetBox or phpIPAM. This document describes the migration framework: the connector model, the intermediate representation, the `plan` / `apply` / `verify` pipeline, the coexistence modes, the verification method, the exit strategy and the runbooks.

The migration framework ships in Phase 4 (AD integration and migration). Spreadsheet import ships earlier, in Phase 1 (IPAM-11). The requirements are MIG-01 to MIG-18 in [REQUIREMENTS.md](REQUIREMENTS.md); the architecture decision is [ADR 0006](adr/0006-connector-architecture.md). The views and policies model that DNS migration maps onto is described in [ARCHITECTURE.md](ARCHITECTURE.md).

## Principles

- **One connector architecture.** Migration sources, inventory sources and actuators share one framework (ADR 0006, CONN-01).
- **Canonical intermediate representation (IR) plus loss report.** Every source adapter produces the same IR and a report of everything it could not map (MIG-01).
- **AXFR as the universal baseline.** Any authoritative server can hand over its zones; adapters add only what AXFR loses (MIG-02).
- **One pipeline for every source:** `plan → apply → verify`. It runs on the same job engine as every other change in Tenko, so steps, timeouts, rollback and audit are identical (MIG-03, IPAM-17).
- **Coexistence before cut-over.** The old server keeps running while Tenko proves itself, per zone or scope (MIG-04).
- **Parity is proven, not assumed.** Verification replays live queries against both servers and diffs the answers (MIG-05).
- **No lock-in.** Everything Tenko holds can be exported in standard formats (MIG-14 to MIG-16).
- **No AD-backed zone storage mode.** The connector model makes it unnecessary (CON-11).

## Connector architecture

A migration source is an implementation of the `MigrationSource` trait defined in the `tenko-connect` crate (CONN-01). Each source family has an adapter crate following the `tenko-connect-*` pattern: `tenko-connect-windows` for Windows DNS and DHCP (PowerShell remoting plus LDAP), and one crate each for BIND, OPNsense, dnsmasq and Kea. The IR types live in `tenko-core`. The `plan` / `apply` / `verify` pipeline lives in `tenko-migrate` and is the only migration code that writes to Tenko. Adapters only read from their source.

| Component | Crate | Responsibility |
|---|---|---|
| Connector traits | `tenko-connect` | `MigrationSource`, alongside `InventorySource`, `Actuator` and `NetworkController` |
| Source adapters | `tenko-connect-*` | Read a source and produce IR plus a loss report |
| IR types | `tenko-core` | Canonical data model shared by all adapters |
| Pipeline | `tenko-migrate` | `plan`, `apply`, `verify` on top of the adapters |
| Job engine | `tenko-jobs` | Steps, status, timeouts and rollback for every stage |

All source adapters in the migration registry (MIG-06 to MIG-13) are delivered in Phase 4. Proxmox is the exception: it is an inventory source rather than a migration source, and its adapter ships in Phase 1 (CONN-03).

### What the IR carries

The IR must represent everything the sources in the Sources section can supply, so that adapters never have to drop data for lack of a place to put it.

| Area | IR content |
|---|---|
| DNS zones and records | Zones with type; RRsets with ownership (per RRset), aging timestamps (null means static) and tombstones |
| DNS server settings | Forwarders, conditional forwarders, root hints, recursion settings, aging and scavenging settings, Global Query Block List, Response Rate Limiting |
| Views and policies | Zone scopes, client subnets, recursion scopes, Query Resolution Policies (QRPs), BIND views and ACLs, mapped to the Tenko views and policies model (DNS-20) |
| DHCP | Scopes, pools, exclusions, reservations, options at all levels, classes and policies, filters, superscopes, DNS settings, failover relationships, leases |
| IPAM | Networks, VLANs, hosts |

Views and policies deserve a note. A Tenko view is a name, match rules, a zone scope and a weight (ARCHITECTURE.md). The match criteria of a Windows QRP (client subnet, transport protocol, server interface IP, query type, time of day, FQDN) correspond to the match rules of a view; Windows zone scopes map to the zone scope of a view, and BIND `view` and `acl` statements map to views and client subnets. This direct mapping is the reason the views model exists (DNS-20). Any construct without a direct equivalent goes to the loss report.

### Loss report

Every adapter emits, next to the IR, a loss report listing each item that could not be mapped. An entry names the source location (server, zone, scope, file and line, or object path) and the reason. Every loss-report entry must be acknowledged during plan review before `apply` can start. Nothing is dropped silently.

## AXFR as the universal baseline

All authoritative servers can transfer zones: Windows DNS, BIND, PowerDNS, Knot, NSD and Unbound auth zones. A zone transfer therefore gets the record data out of any source without a dedicated adapter (MIG-02).

AXFR alone loses what is not part of the zone data on the wire: record ownership, aging timestamps, forwarders, views and policies, and all DHCP data. Source adapters add exactly that. AXFR-in itself is a DNS-engine feature available from Phase 2 (DNS-09), so the baseline is ready before the Phase 4 adapters.

## Sources

| Source | Data path | Adapter adds | Requirement |
|---|---|---|---|
| Windows DNS, AD-integrated | AXFR, or `Get-DnsServerResourceRecord` | LDAP read of `dnsRecord` in `DomainDnsZones` and `ForestDnsZones`: ownership per RRset, aging timestamps, tombstones. PowerShell remoting (DnsServer module): forwarders, conditional forwarders, root hints, zone scopes, client subnets, recursion scopes, Query Resolution Policies, aging settings, Global Query Block List, RRL | MIG-06 |
| Windows DNS, file-backed | The same cmdlets (they do not distinguish storage), or `%SystemRoot%\System32\dns\*.dns` | The zone file parser understands the Windows comment `[AGE:n]`, so timestamps are preserved | MIG-07 |
| BIND | AXFR, or zone files (RFC 1035) | `named.conf` parser: `view` becomes Tenko views, `acl` becomes client subnets, plus `forwarders`, `also-notify`, `allow-transfer` and RPZ zones | MIG-09 |
| OPNsense | REST API, or `config.xml` backup | Unbound host and domain overrides, Dnsmasq, ISC dhcpd static maps, Kea subnets and reservations, interfaces and VLANs as IPAM networks, firewall aliases | MIG-10 |
| Proxmox VE | REST API | Proxmox runs no DNS of its own. A DNS server in a VM or container on Proxmox is imported through its own adapter (BIND, dnsmasq, Windows). Proxmox itself is an inventory source: VM and container names, MAC addresses, IP addresses via the guest agent, SDN vnets. Later, a NetBox-compatible API lets Proxmox SDN use Tenko as its IPAM plugin | CONN-03, CONN-17 |
| dnsmasq / Pi-hole | Config files and `/etc/hosts` | `dhcp-host`, `address=`, `host-record`, blocklists (imported as RPZ) | MIG-11 |
| Kea / ISC dhcpd | Kea JSON plus lease file or database; `dhcpd.conf` plus `dhcpd.leases` | Subnets, pools, reservations, classes, options | MIG-12 |
| Windows DHCP | `Export-DhcpServer -Leases` (XML) plus `Get-DhcpServerv4*` cmdlets | Scopes, reservations, options at all levels, policies, filters, superscopes, DNS settings, failover relationships (the shared secret is recreated, not exported) | MIG-08 |
| Generic | CSV or Excel (an existing IPAM spreadsheet, Phase 1), hosts files, NetBox and phpIPAM APIs | Hosts, networks and addresses from the foreign inventory | IPAM-11, MIG-13 |

### Windows DNS (both storage modes)

The `Get-DnsServer*` cmdlets do not distinguish between AD-integrated and file-backed zones, so the PowerShell path is identical for both and yields the same server settings, policies and records (Appendix A). The storage mode only changes what else is available:

- **AD-integrated zones** additionally expose, through LDAP, per-RRset ownership (record owner ACLs, which the cmdlets do not return; see Known non-exportable data), aging timestamps and tombstones. Ownership feeds the per-RRset ownership model used for secure updates (DNS-28).
- **File-backed zones** can be read either through the cmdlets or by parsing the `.dns` files directly. The parser reads `[AGE:n]` so that aging timestamps survive (MIG-07, DNS-29). File-backed zones have no per-record ACLs.

Query Resolution Policies require Windows Server 2016 or later. Older servers have no QRPs or zone scopes to migrate.

### Windows DHCP

Windows DHCP failover is a proprietary protocol and is not interoperable with any other implementation (CON-05). Tenko therefore cannot join a Windows failover relationship. During coexistence, Tenko and Windows DHCP serve split scopes: the address range of a scope is divided so that the two servers never offer the same address. The Windows failover relationship is read into the IR and re-created as a Tenko failover pair (DHCP-12); its shared secret is created anew and stored in the vault (IAM-16).

## Pipeline: plan, apply, verify

The same three stages run for every source (MIG-03). Each stage is a job on the job engine, so its steps, status, timeouts and rollback are visible in the UI and the API (IPAM-17, API-05). The CLI mirrors the stages: `tenko migrate plan`, `tenko migrate apply` and `tenko migrate verify`.

| Stage | Command | What it does | Output |
|---|---|---|---|
| `plan` | `tenko migrate plan` | Reads the source through its adapter into IR, then computes a dry-run diff of the IR against the current Tenko state | Diff, loss report |
| `apply` | `tenko migrate apply` | Writes the planned changes as jobs with steps, timeouts and rollback; refuses to start while loss-report entries are unacknowledged | Job status per step |
| `verify` | `tenko migrate verify` | Compares Tenko against the old server (parity check), using query replay for DNS | Parity report |

`plan` has no side effects on Tenko or on the source. Because `apply` is a set of ordinary jobs, a failed or interrupted run can be rolled back or resumed with the same tooling as any other change.

### Spreadsheet import: networks inside an existing network

The spreadsheet import (IPAM-11) follows the same shape: a preview (`GET /imports/{id}/preview`) with the IPAM plan's warnings, then `POST /imports/{id}/apply` as a job in chunks. A network of the sheet that lies inside an existing prefix of role `network` would overlap it (`ipam.prefix.overlap`, IPAM-23). Instead, the preview offers one step per existing network: it becomes a supernet, so that the networks of the sheet can be created inside it, and the addresses it holds move to them. The step is the warning `ipam.prefix.becomes_supernet` (parameters `cidr` and `networks`, the number of imported networks inside), shown in the preview as a plan row with its acknowledgement; the import applies once it is acknowledged (`{"acknowledge": ["ipam.prefix.becomes_supernet"]}` in the apply request), and a rollback of the job turns the supernet back into a network. A network that a DHCP scope serves (`dhcp.scope.attached`) or that has ranges cannot become a supernet: the networks of the sheet inside it are left out with the loss entry `import.prefix.in_network` (a warning), and their addresses go to the existing network.

## Coexistence modes

The mode is chosen per zone or scope in the UI (MIG-04). It controls who is authoritative while Tenko is being proven.

| Mode | Tenko role | Old server role | Notes |
|---|---|---|---|
| Secondary | AXFR secondary; stays in sync until the flip | Primary | A nightly parity diff compares the two copies. Lowest risk; no client points at Tenko yet. |
| Forward | Forwards selected zones to the old server while taking over others | Authoritative for the forwarded zones | Allows a zone-by-zone cut-over under a single resolver address. |
| Flip | Primary | Secondary to Tenko, or switched off after a rollback window | The cut-over. The rollback window keeps the old server available until Tenko is confirmed. |

For DHCP the equivalent is split scopes (CON-05), described under Windows DHCP above. DHCP scopes are moved in the same per-scope fashion: the range handed to Tenko grows while the range left on the old server shrinks.

During coexistence, changes made in IPAM must still reach the server that clients actually use. The external actuators for coexistence cover this: Windows DHCP via PowerShell and Kea via its Control Agent (CONN-12), and RFC 2136 or Windows DNS via PowerShell (CONN-13). Both ship in Phase 4.

## Verification by query replay

Verification for DNS is query replay (MIG-05). Tenko samples live queries from dnstap (DNS-26) or the query log, asks both the old server and Tenko, and diffs the RCODE and the answers. TTL drift is ignored, since the two servers' caches and clocks differ. This is what makes a hands-off migration credible: parity is measured against real client traffic, not against a list of records.

The samples come from query logs, and query logs are personal data. The query-log retention and pseudonymization settings apply to replay samples exactly as to any other query log (OPS-06).

## Exit strategy

Everything Tenko holds can be exported in standard formats, so leaving Tenko is never blocked by a proprietary format.

| Format | Requirement | Phase |
|---|---|---|
| CSV | MIG-14 | 1 |
| Standard zone files | MIG-15 | 2 |
| Kea-compatible JSON | MIG-16 | 3 |

The CSV export is the counterpart of the spreadsheet import, so the import/export round trip is testable from Phase 1 (IPAM-11).

## Non-goals

- **No AD-backed zone storage mode.** A Samba-style mode that keeps zone data in AD is not needed with the connector model and is not built (CON-11). AD Sites and Services is integrated as a site-to-subnet sync with IPAM (IPAM-22), not as a storage model.
- **No WINS lookup.** WINS and WINS-R records are not migrated or served (CON-12).
- **No DHCPv4 failover protocol interoperability** with Windows or ISC (CON-05).

## Acceptance

The migration framework is accepted when MIG-18 is met in the Windows interop lab (API-18):

1. A Windows Server test domain, version 2016 or later, is set up with Query Resolution Policies, zone scopes, aging and DHCP failover. Windows Server 2016 is the minimum because QRPs require it.
2. The domain is migrated in the lab without manual intervention: DNS zones, policies, aging state and DHCP scopes and failover relationship.
3. Domain join works against Tenko.
4. GPO retrieval works against Tenko.
5. The DC locator works against Tenko (DNS-30).
6. Netlogon re-registration of the DC locator SRV records works against Tenko using GSS-TSIG (DNS-28).
7. Windows DNS is switched off and clients notice nothing.

Criteria 3 to 6 are the AD verification of the lab; criteria 1, 2 and 7 are the migration verification. On Windows, Tenko runs as a gMSA or domain account so that Kerberos works (OPS-11); on Linux it uses a keytab for its computer account (CON-03).

## Runbooks

Runbooks are written and validated in Phase 4 against the interop lab (MIG-17). Until then, this section holds the generic procedure as a draft and the list of planned source-specific runbooks.

### Generic runbook (draft)

1. **Prerequisites.** Credentials for the source are stored in the Tenko vault (IAM-16). Network connectivity from a Tenko node to the source is in place, including zone transfer permission from the source to the Tenko node for the AXFR path. Time is synchronized on the Tenko node and the source (OPS-09); Kerberos tolerates 5 minutes of skew.
2. **Connect the source and inventory it.** Register the source in the UI or CLI and let the adapter read it into IR.
3. **Run `plan` and review.** Read the diff and the loss report. Acknowledge every loss-report entry, or fix the cause at the source and re-run `plan`.
4. **Choose a coexistence mode** per zone or scope: Secondary, Forward or Flip for DNS, split scopes for DHCP.
5. **Run `apply`.** Follow the jobs in the job panel; roll back any failed job.
6. **Run `verify`** with query replay over an agreed observation period, long enough to cover the periodic traffic of the environment (for example the 24-hour Netlogon re-registration cycle).
7. **Flip.** Move the zone or scope to Tenko and repoint clients (DHCP options, forwarders or glue as applicable).
8. **Keep the rollback window.** The old server stays available and reachable as a secondary until the window closes.
9. **Decommission the old server.**

### Source-specific runbooks

| Runbook | Status |
|---|---|
| Windows DNS and DHCP in an AD domain | Planned |
| BIND | Planned |
| OPNsense | Planned |
| Pi-hole and dnsmasq | Planned |
| Kea and ISC dhcpd | Planned |
| Spreadsheet import (Phase 1) | Planned |

## Appendix A: Windows cmdlet inventory

`tenko-connect-windows` collects data through PowerShell remoting and LDAP. All collection is read-only. The `Get-DnsServer*` family is used for both AD-integrated and file-backed zones.

### DNS (DnsServer module)

| Cmdlet | Data collected |
|---|---|
| `Get-DnsServerZone` | Zones with type and storage; conditional forwarders (zones of type Forwarder) |
| `Get-DnsServerResourceRecord` | Resource records per zone, with record timestamps |
| `Get-DnsServerForwarder` | Server-level forwarders |
| `Get-DnsServerRootHint` | Root hints |
| `Get-DnsServerRecursion` | Recursion settings |
| `Get-DnsServerRecursionScope` | Recursion scopes |
| `Get-DnsServerZoneScope` | Zone scopes per zone |
| `Get-DnsServerClientSubnet` | Client subnets |
| `Get-DnsServerQueryResolutionPolicy` | Query Resolution Policies |
| `Get-DnsServerZoneAging` | Aging settings per zone |
| `Get-DnsServerScavenging` | Scavenging settings |
| `Get-DnsServerGlobalQueryBlockList` | Global Query Block List |
| `Get-DnsServerGlobalNameZone` | GlobalNames zone settings |
| `Get-DnsServerResponseRateLimiting` | Response Rate Limiting settings |
| `Get-DnsServerResponseRateLimitingExceptionlist` | Response Rate Limiting exception lists |
| `Get-DnsServerZoneTransferPolicy` | Zone transfer policies |
| `Get-DnsServerSetting` | General server settings, including round robin and netmask ordering |
| `Get-DnsServerDnsSecZoneSetting` | DNSSEC settings per zone |
| `Get-DnsServerSigningKey` | DNSSEC signing key metadata |
| `Get-DnsServerTrustAnchor` | Trust anchors |

### DHCP (DhcpServer module)

| Cmdlet | Data collected |
|---|---|
| `Export-DhcpServer` | Full server configuration as XML; with `-Leases`, the leases as well |
| `Get-DhcpServerv4Scope` | Scopes |
| `Get-DhcpServerv4ExclusionRange` | Exclusion ranges |
| `Get-DhcpServerv4Reservation` | Reservations |
| `Get-DhcpServerv4OptionDefinition` | Custom option definitions |
| `Get-DhcpServerv4OptionValue` | Option values at server, scope, policy and reservation level |
| `Get-DhcpServerv4Class` | Vendor and user classes |
| `Get-DhcpServerv4Policy` | Policies |
| `Get-DhcpServerv4Filter` | MAC allow and deny entries |
| `Get-DhcpServerv4FilterList` | State of the allow and deny lists |
| `Get-DhcpServerv4Superscope` | Superscopes |
| `Get-DhcpServerv4DnsSetting` | Dynamic DNS update settings |
| `Get-DhcpServerv4Lease` | Leases |
| `Get-DhcpServerv4Failover` | Failover relationships |
| `Get-DhcpServerDnsCredential` | DNS credential (returns user name and domain only) |

The corresponding `Get-DhcpServerv6*` cmdlets are used where DHCPv6 is in use.

### LDAP

`dnsNode` objects and their `dnsRecord` attribute in the `DomainDnsZones` and `ForestDnsZones` application partitions. Record ownership is derived from the security descriptors of the `dnsNode` objects.

### Hyper-V inventory

Not a migration source; listed here because it uses the same WinRM and PowerShell transport (CONN-10).

| Cmdlet | Data collected |
|---|---|
| `Get-VM` | Virtual machines |
| `Get-VMNetworkAdapter` | Network adapters with MAC and IP (IP via integration services) |

### Known non-exportable data

| Item | Why | Handling |
|---|---|---|
| Record owner ACLs | Not exposed by the DnsServer cmdlets; only available through LDAP as security descriptors on `dnsNode` objects. File-backed zones have no per-record ACLs. | Read through LDAP and mapped to per-RRset ownership (DNS-28) |
| DNSSEC private keys | Not exportable from the Windows key storage | Tenko signs with new keys. A signed zone needs a planned key rollover and a DS update at the parent. |
| DHCP failover shared secret | Not exported | Recreated and stored in the vault (IAM-16) |
| DDNS credential password (the account the Windows DHCP server uses for dynamic DNS updates) | The password cannot be read back | Re-entered into the vault, or replaced by Tenko DHCP's own DDNS path (DHCP-13) |
