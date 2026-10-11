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
| [access.md](access.md) | Who may do what: the four roles, grants over VRFs, sites and prefixes with and without their subtree, anchors and the read-any, write-all rule, delegation, service accounts, scoped API tokens, the sign-in requirement per role, the auditor, what scoped principals see, the `/access` API, error codes and rollback |
| [secrets.md](secrets.md) | Operator secrets: the model, who may reveal and how (TGL-24, the PIN rule), audit records, the clipboard path and what it does not protect, host credentials, the RDP and SSH hand-off, connectors and imports |
| [reconciliation.md](reconciliation.md) | Intent versus observation: observations per source, the reconciler's proposals, decisions and adoption policies |
| [cluster.md](cluster.md) | Controllers and nodes on the cluster port: enrolment tokens, certificates and renewal, revocation, the gRPC protocol and its version negotiation, heartbeats, the disk buffer for probe observations, ports and settings, and the controller cluster (joining, membership, forwarded writes, quorum state, state digests) |
| [scanning.md](scanning.md) | The probe's discovery methods: what each one does, needs and reports, rate limits, blackout windows and the kill switch, `tenko node scan`, IDS and EDR allow-listing, the `[scan]` section |
| [topology.md](topology.md) | The topology map: its sources, how observations and intent are joined into devices, edges, the API with its filters and the node view, caching, the map in the UI and the choice of drawing library, and the VLAN provision job |
| [moves.md](moves.md) | Moving devices between networks: what moves, the preview and its fingerprint, the L2 step through the network controller (port profiles, per-client VLANs, manual steps and why), the guardrails, the job and its observation, rollback from the receipt, bulk moves and what stays manual in this phase |
| [connectors.md](connectors.md) | The Proxmox VE and Home Assistant inventory connectors: what each reads and how it maps to observations, the least-privilege API token and access token, settings, the certificate check shared with the UniFi connector, health checks, what is not read, troubleshooting and the live smoke tests |
| [connectors-unifi.md](connectors-unifi.md) | The UniFi Network connector: deployments and API families with the spike findings, what it reads and the facts it yields, its guarded writes with undo, the guardrails, least-privilege setup of the local account, API key and certificate pin, settings, health check, retries and troubleshooting |
| [upgrades.md](upgrades.md) | Data-directory format and migrations, `tenko upgrade check`, releases, manual upgrade and rollback, updates from the UI, the version layout, modules |
| [languages.md](languages.md) | Language packs: the XLIFF 2.0 format, validation and the report, upload, preview, activation and revert, the template for translators, the data-directory import, storage and caching, limits, the API, audit actions and error codes |
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
