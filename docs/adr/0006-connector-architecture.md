# ADR 0006: Connector architecture

- Status: Accepted (the in-process boundary is refined by ADR 0012: connectors are plugins over a published protocol)
- Date: 2026-10-09

## Context

Tenko DDI has to integrate with many external systems that fall into four kinds of interaction:

- **Inventory:** hypervisors (Proxmox VE first, Hyper-V and VMware vSphere later, then Docker/Podman, Kubernetes and Incus/LXD) and Home Assistant supply observed hosts.
- **Actuation:** applying IPAM intent to systems Tenko does not own, such as Windows DHCP, Windows DNS or Kea during coexistence, and hypervisors setting guest IPs.
- **Migration:** importing from mixed sources: AD-integrated and file-backed Windows DNS, Windows DHCP, BIND, OPNsense, dnsmasq/Pi-hole, Kea/ISC dhcpd, NetBox, phpIPAM and spreadsheets.
- **Network control:** reading topology from, and writing VLANs, port profiles and per-client VLANs to, network controllers (UniFi first).

Writing a separate importer or integration for each system would produce N-by-M mappings with no common way to report what was lost, preview changes or roll them back.

## Decision

1. **One connector framework** (`tenko-connect`) defines four traits (CONN-01):

   | Trait | Purpose |
   |---|---|
   | `InventorySource` | Supplies observed hosts (name, MACs, IPs, OS, platform, parent host, tags), polled on a schedule, with webhooks where the source offers them |
   | `Actuator` | Applies IPAM intent to an external system as job steps (ADR 0005) |
   | `MigrationSource` | Produces the canonical intermediate representation plus a loss report |
   | `NetworkController` | Reads devices, clients, ports and LLDP; writes VLANs/networks, port profiles and per-client VLANs |

   Drivers live in `tenko-connect-*` crates and may implement several traits. Examples: `tenko-connect-windows` is a migration source and a coexistence actuator; `tenko-connect-proxmox` is an inventory source now and a hypervisor actuator later; `tenko-connect-unifi` is a network controller.
2. **Migration uses a canonical intermediate representation (IR)** defined in `tenko-core`. Every source adapter produces IR plus a **loss report** listing what could not be mapped (MIG-01).
3. **AXFR is the universal migration baseline** for DNS data: every authoritative server can transfer zones. Adapters add only what AXFR loses: ownership, aging timestamps, forwarders, views and policies, and DHCP (MIG-02).
4. **One pipeline for all sources:** `plan` (dry-run diff), `apply`, `verify` (parity against the old server, by query replay), implemented in `tenko-migrate` on the job engine (MIG-03, MIG-05). Coexistence modes (secondary, forward, flip) are chosen per zone or scope (MIG-04).
5. **Network-controller writes are guarded:** the connector never writes anything it has not first read back and diffed; every write is previewed, audited and available as a dry-run; the port or VLAN through which Tenko or the controller is reached, and uplinks, are never touched (CONN-08, CONN-09).
6. **Connector credentials live in the vault** (IAM-16).
7. **No AD-backed zone storage mode** is built. Zone data is not kept in AD in the style of Samba; AD-integrated zones are migrated through AXFR plus LDAP and PowerShell reads (CON-11).

## Consequences

- Each new system costs one adapter against stable traits, not a new pipeline.
- Loss reports make migration gaps explicit and reviewable before anything is applied.
- Migration, coexistence actuation and day-to-day changes share the job engine, so they share previews, rollback and audit.
- The IR must be rich enough to carry ownership, timestamps, views/policies and the full DHCP model; it lives in `tenko-core` and evolves with new sources.
- Data that the source cannot export (for example DNSSEC private keys or the Windows DHCP failover shared secret) must be recreated; MIGRATION.md lists these cases.
- Exit is symmetrical: Tenko exports to standard zone files, Kea-compatible JSON and CSV (MIG-14 to MIG-16).

## Alternatives considered

- **Bespoke importers per source.** Quick for the first source, but every additional source multiplies mapping code and there is no uniform loss reporting, preview or rollback.
- **Zone files and AXFR only.** Universal, but loses ownership, aging timestamps, views/policies, forwarders and all DHCP data, which makes a hands-off Windows migration impossible.
- **An AD-backed zone storage mode.** Would keep AD as a runtime dependency and tie Tenko to the AD schema and replication, which the connector model makes unnecessary.
