# Tenko DDI Documentation

Tenko DDI is a DNS, DHCP and IPAM stack written in Rust with an embedded web UI. It replaces Active Directory-integrated Windows DNS and DHCP and scales from a single home-lab box to enterprise deployments. This directory holds the project's living documentation.

## Documents

| Document | Contents |
|---|---|
| [REQUIREMENTS.md](REQUIREMENTS.md) | Living requirements specification: personas, design constraints (CON), and requirements by area with phase and priority |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Roles, data plane independence, storage and replication, IPAM as intent hub, move job, connectors, repository layout |
| [SECURITY-PROFILES.md](SECURITY-PROFILES.md) | Home, Standard, Hardened and Lab profiles as toggle bundles, the never-off list and the PIN coupling rule |
| [MIGRATION.md](MIGRATION.md) | Connector-based migration from mixed sources: IR and loss report, plan/apply/verify, coexistence modes, Windows cmdlet inventory |
| [plugins.md](plugins.md) | How to write a connector plugin: manifest, protocol, conformance suite, security expectations |
| [secrets.md](secrets.md) | Operator secrets: the model, who may reveal and how (TGL-24, the PIN rule), audit records, the clipboard path and what it does not protect, host credentials, the RDP and SSH hand-off, connectors and imports |
| [reconciliation.md](reconciliation.md) | Intent versus observation: observations per source, the reconciler's proposals, decisions and adoption policies |
| [upgrades.md](upgrades.md) | Data-directory format and migrations, `tenko upgrade check`, releases, manual upgrade and rollback, updates from the UI, the version layout, modules |
| [CONFORMANCE.md](CONFORMANCE.md) | RFC and specification matrix with target phase and status |
| [ROADMAP.md](ROADMAP.md) | Phases 0 to 5 with deliverables, spikes, "Done when" criteria, verification and open questions |
| [adr/README.md](adr/README.md) | Architecture Decision Records: process and index |

## Identifiers

Requirements, constraints and toggles carry stable IDs that are never reused or renumbered:

| Prefix | Defined in |
|---|---|
| DNS, DHCP, IPAM, SCAN, IAM, OPS, API, CONN, MIG | REQUIREMENTS.md (requirements) |
| CON | REQUIREMENTS.md (design constraints) |
| PER | REQUIREMENTS.md (personas) |
| TGL, NEVER | SECURITY-PROFILES.md |
| RFC numbers | CONFORMANCE.md |
| ADR NNNN | adr/ |

Cite IDs as plain text, for example DNS-20, CON-07 or ADR 0002.

## Rules for changing these documents

- **Add an ADR instead of editing an accepted one.** Accepted ADRs are frozen; a changed decision gets a new ADR that supersedes the old one (see adr/README.md).
- A requirement that is dropped stays in place, marked "Withdrawn" with a reason. New requirements take the next free number in their section.
- A change that implements or tests a specification updates its status in CONFORMANCE.md in the same change.
- All documentation is written in English, as if the repository were public.
