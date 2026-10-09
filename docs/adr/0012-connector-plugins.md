# ADR 0012: Connectors as plugins over a published protocol

- Status: Accepted
- Date: 2026-10-09

## Context

ADR 0006 defined one connector framework with four interfaces (InventorySource, NetworkController, Actuator, MigrationSource) and assumed that every connector is compiled into the Tenko binary. The list of external systems is unbounded: hypervisors (Proxmox, Hyper-V, VMware), network controllers (UniFi, and every switch vendor), home automation, firewalls, DHCP and DNS servers for migration, ticketing. Building them all in makes the core larger, slower to build and more fragile, ties every integration to Tenko's release cycle, and leaves users of other systems with nothing. The owner decided on 2026-10-09 that connectors are plugins behind one published contract, so that third parties can write and share their own, with a plugin hub later.

## Decision

1. **The contract stays, the boundary moves.** The connector interfaces of ADR 0006 (Connector with info and health, InventorySource, NetworkController, Actuator, MigrationSource) are expressed as a versioned protocol (protobuf over gRPC) in `tenko-connect`, which becomes the plugin SDK: the protocol definitions, the host-side runner, a Rust helper library for plugin authors, the manifest schema and a conformance test suite (`tenko plugin test <path>`).
2. **Transport: one process per plugin instance.** Tenko starts the plugin executable (or a script through the interpreter its manifest declares), performs a handshake over stdio that exchanges the protocol version, the manifest and a per-launch token, then speaks gRPC over a local Unix socket or Windows named pipe. The host supervises the process: health checks, restart with backoff, timeouts on every call, and shutdown. A plugin crash never affects the data plane or the controller. Any language that speaks gRPC can implement a plugin.
3. **Manifest.** Name, version, supported protocol versions, capabilities (which interfaces it implements), a JSON Schema for its settings (the UI generates the settings form from it), the secret purposes it needs, the network targets it will contact, supported platforms, and a human description. Manifests are validated before the plugin is started.
4. **Secrets never reach the plugin store.** Plugins do not access the vault. The host resolves `SecretRef`s and injects the values into the call that needs them; the manifest declares which secret purposes a plugin may receive, every injection is audited, and the host wipes the values after the call.
5. **Policy lives in the host.** Verify-before-write, protected ports and uplinks, rate limits, retries, bulk parallelism and observation normalization are enforced by Tenko. A plugin returns facts (topology, inventory, read-back results) and performs the concrete calls; it never decides whether a write is allowed.
6. **Reference plugins are plugins.** UniFi, Proxmox and Home Assistant (later Windows DNS/DHCP, BIND, OPNsense, dnsmasq, Kea, Hyper-V, VMware) are built on the SDK and bundled in the `tenko` binary as `tenko plugin run <name>` entry points. The host launches them exactly like a third-party plugin, so the contract is exercised in every installation and the home user installs nothing extra.
7. **Later.** A WebAssembly component transport (Phase 5) for sandboxed distribution through a plugin hub with signed packages and `tenko plugin install <name>`; the protocol, SDK and conformance suite are published in a separate public repository when the product opens.
8. **Versioning.** The protocol carries a major version in the handshake; changes within a major are additive; a plugin declares the versions it supports and the host refuses a mismatch with a clear error.

## Consequences

- Slice 2 of Phase 1 starts with the SDK and the host runner, and UniFi becomes the first reference plugin, exercising InventorySource and NetworkController end to end before Proxmox and Home Assistant are ported to the same shape.
- The core stays small; integrations evolve on their own release cycles; a broken plugin degrades one connector, not Tenko.
- Each call crosses a process boundary (serialization and a local socket), which costs milliseconds and is irrelevant for connectors that poll every few minutes and write rarely.
- Plugin executables run with Tenko's identity on the host. Installation comes from trusted sources only; the manifest's declared permissions are enforced by the host where the platform allows (network allow-lists, no secrets beyond the declared purposes), and package signing arrives with the hub. This is recorded as a risk in the plan.
- The SDK and protocol become an API that must be versioned and documented with the same care as the REST API; the conformance suite is what lets third parties validate without reading Tenko's code.
- The crates `tenko-connect-proxmox`, `tenko-connect-unifi`, `tenko-connect-hass` and `tenko-connect-windows` become plugin crates built on the SDK and linked into the binary as entry points; they no longer expose in-process trait implementations to the controller.

## Alternatives considered

- **In-process connectors through the Rust traits only (ADR 0006 as written).** Fastest and simplest, but the core grows without bound, every integration requires a Tenko release, and third parties cannot contribute without the whole build.
- **Dynamic libraries.** No stable Rust ABI, requires `unsafe`, and a crash takes the controller down.
- **WebAssembly components from the start.** The right end state for a hub, but the component tooling for some languages and the host functions for SNMP and raw sockets are not mature enough to make it the only transport today; it is added as a second transport in Phase 5.
- **An embedded scripting language.** Easy for small scripts, but a second language runtime to maintain, limited for real connectors, and no path to a hub of signed packages.
