# ADR 0032: Plugins as processes from the `tenko-plugins` repository

- Status: Proposed (the owner decided the design on 2026-11-01; Accepted when the owner has read it)
- Date: 2026-11-01

## Context

[ADR 0012](0012-connector-plugins.md) made connectors plugins: separate processes that the host starts, hands a token over standard input, and calls over a versioned gRPC protocol (`tenko.connect.v1`) on a private local socket ([plugins.md](../plugins.md)). The reference connectors (Home Assistant, UniFi, Proxmox VE) are built on that SDK and bundled in the binary as `tenko plugin run <name>`. That part works and stays. A plugin from outside the binary has four gaps, which [plugins.md](../plugins.md) section 12 and risk R16 of the Phase 1 plan name: it runs as the service account, so a malicious plugin is a compromised Tenko (the store, the key material, every network the host reaches); there is no installer and no signature, only a directory copied "from a source they trust"; there is no install, update, rollback or index; and since the host is the client over a local socket, a plugin that must run elsewhere, such as the Windows DHCP exporter of the Windows takeover plan, cannot use the contract at all.

ADR 0012 decision 7 planned a WebAssembly transport and a hub with signed packages for Phase 5 (CONN-21); the first out-of-tree plugins, Hyper-V (CONN-10) and VMware vSphere (CONN-11), are now in view. The owner decided on 2026-11-01 how plugins from outside the binary work. This ADR supersedes ADR 0012 decision 7 and refines its decision 2 for out-of-tree plugins; ADR 0012's status line says so when this ADR is accepted. ADR 0012 decision 5 holds unchanged: policy lives in the server, a plugin reports facts.

### Threat model

The adversaries, in the order of the security audit plan ([security-audit-plan.md](../plans/security-audit-plan.md) section 1.2):

1. **A malicious or compromised plugin**, through its author, a dependency or hostile data from its remote system. It runs code on the node.
2. **The supply chain (A4)**: a stolen token or a compromised workflow changes a plugin release or the index.
3. **A compromised service account (A3, [ADR 0023](0023-no-root-after-installation.md))**, which must gain nothing through the plugin machinery: no root, no wider sandbox.

The goals the design must hold:

- A plugin does what its token's scopes allow through the API and nothing more: no store, vault, data directory or other plugin's state, never intent, settings, tokens or secrets.
- A plugin the node installs is the file the index names, verified the way a Tenko release is.
- No step after the installation needs root (ADR 0023 I3), and running plugins gives the service account no right its own unit does not give it.

## Decision

1. **Plugins are processes, and the contract is the HTTP API.** Not dynamic libraries and not WebAssembly (see the alternatives). A plugin is any process that holds a Tenko API token scoped to its own source and speaks the existing HTTPS API and the event stream (`GET /api/v1/events`). There are two kinds with the same contract:

   - a **managed** plugin is one that Tenko downloads, verifies, installs and runs on the node;
   - a **remote** plugin runs elsewhere, started by whoever runs that host, with a token an administrator mints for it (the Windows DHCP exporter is one).

   The direction of ADR 0012 is reversed for these plugins: the plugin is the client. That lets one contract serve both kinds and puts authorization, audit and validation in the machinery the API already has. The bundled connectors keep the gRPC contract of ADR 0012 until a later decision moves them (point 9). The contract is OS-neutral; supervision differs per OS behind one trait in the server (`PluginSupervisor`: install, start, stop, state, uninstall).

2. **Supervision on Linux: one transient user per plugin.** A managed plugin runs as an instance of a systemd template unit, `tenko-plugin@<name>.service`, with `DynamicUser=yes`: a user that exists only while the instance runs, its own `StateDirectory=`, a private `/tmp`, `NoNewPrivileges=yes`, and the hardening family of `tenko.service` (`ProtectSystem=strict`, the kernel and process protections, `MemoryDenyWriteExecute=yes`, the system-call filter, an empty `CapabilityBoundingSet=`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`). The rest of the data directory is hidden from it (`TemporaryFileSystem=` over it, with one read-only bind of the plugin's own release directory). The rule for the template, checked by the round's `unit.*` rows: **it grants a plugin nothing that `tenko.service` does not grant the service** (no capability, no address family, no system-call group, no writable path but its own state directory).

   The installer, as root, installs the template once, together with a polkit rule that lets the user `tenko` start, stop, restart, reset-failed and clean instances of exactly that template, for instance names of the manifest's name pattern (`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`), and nothing else. Reading a unit's state needs no privilege. The service calls `systemctl` as a child process (no D-Bus crate; `systemctl` joins the `ExecPaths=` of ADR 0023 item 2); the plan verifies the polkit verbs against systemd 250, the floor of `tenko.service`. This is root at installation, never after, as ADR 0023 allows (I4: widening what the host grants is the installer's act). The plugin's release files live in a directory under the data directory that the service writes and the plugin's user can only read and execute, so the less privileged account runs what the more privileged one wrote, never the reverse.

   **Supervision on Windows: a child process first.** The service starts a managed plugin as a child process with the host's existing supervision (backoff, circuit breaker, a job object that ends it with the service), as `NT SERVICE\tenko`: the Windows gap of the Consequences. A virtual account per plugin comes later; creating a Windows service needs an administrator, so how that fits I3 is the plan's question.

3. **Identity: a plugin principal and a token with the manifest's scopes.** Each managed or remote plugin is a service account of its own ([ADR 0015](0015-scoped-authorization.md)), kind `plugin`, with no role grants. Its token carries exactly the scopes of the manifest (point 5) that the operator approved: new special scopes beside `metrics` and `audit:read`, each bound to the plugin's own source, for example `inventory:read` and `observations:write:<source>`. It can never administer, reveal secrets, change settings or tokens, or confirm a manual step (`tenko_auth::roles::interactive_only`); TGL-05 caps its lifetime. A managed plugin's token is minted at every start, renewed through the API while it runs and revoked at the stop; a remote plugin's is minted by an administrator and shown once. Every call is audited under the plugin principal.

4. **Secrets: handed over once at start, through a descriptor, never through the environment.** The plugin's token, its secrets (the purposes its manifest declares, resolved from the vault) and the non-secret start data (the API address, the CA root of `tls/ca-root.pem`) reach a managed plugin at its start and at no other time:

   - on Linux as systemd credentials: the template's `LoadCredential=` names a Unix socket the service listens on; at the start systemd (PID 1) connects, the service checks that the peer is PID 1 and that the peer address names this unit and this credential, and writes the value. The plugin reads `$CREDENTIALS_DIRECTORY/<purpose>`, a RAM-backed directory only its transient user can read. Nothing touches the disk;
   - on Windows over the child's standard input, the anonymous pipe the host's handshake already uses.

   The environment is refused: it is readable in `/proc/<pid>/environ`, inherited by every child (a Hyper-V plugin starts PowerShell), lands in crash dumps and shows in `systemctl show`; [plugins.md](../plugins.md) section 9 already keeps secrets and tokens out of it. There is no API route through which a plugin token reads a secret, so a stolen token does not yield the credentials. A plugin never stores a secret; a changed secret restarts the plugin. A remote plugin's secrets are its host's business: Tenko does not send credentials over the network to a process it does not run.

5. **The manifest.** `plugin.json` gains a manifest version 2 that keeps the members, rules and settings-schema subset of [plugins.md](../plugins.md) section 5 (name, version, description, license, `platforms`, `settings`, `secrets`, `network`, `entry`) and adds:

   - `api`: the plugin API version range it speaks (`">=1.0, <2"`), in place of `protocol`;
   - `scopes`: the scopes its token needs, for example `["inventory:read", "observations:write"]`, bound to the instance's source by the server;
   - `network`: as today, and on Linux applied to the unit where that is possible (`RestrictAddressFamilies=` from the families it declares). A per-plugin `IPAddressAllow=` needs a drop-in only root can write, so until a root-less way exists the targets are declarations shown to the operator.

   At installation the operator sees and confirms the scopes, the network targets and the secret purposes, as an application's permissions; an update that widens any of them asks again.

6. **The repository `tenko-plugins`, its index, and verification.** A public repository beside `tenko` holds an index and the sources of verified plugins. The index is one JSON file: per plugin its name, description, tier, source repository, and per version the API range, the platforms, the release file of each platform with its size and SHA-256, and the attestation it carries. The repository's workflow publishes the index as a release asset with a provenance attestation, as for a Tenko release (L1.10, SA2 of the security audit plan).

   Tenko reads the index from a configured source (`plugins.index_url`, default the repository's latest index release, or a mirror), shows it on the connectors page, and fetches a release file and its `SHA256SUMS` only from the origin the index names. The node verifies size and SHA-256 against both before unpacking, as the install job does ([upgrades.md](../upgrades.md) section 8.5; ADR 0023 I8 in plugin terms). The provenance attestation is for the review and `gh attestation verify`; when API-19 delivers, the owner's key signs the index as it will sign a release's `SHA256SUMS` ([security-audit-plan.md](../plans/security-audit-plan.md) section 7.2), and the node refuses an index whose signature does not verify against the trust root compiled into it. The air-gapped path is the one updates have ([upgrades.md](../upgrades.md) section 8.8): upload the index, then the release file, verified the same way.

   Lifecycle, on the connectors page and in the CLI (`tenko plugin install | enable | disable | uninstall | update | rollback`): a plugin is a card like the bundled connectors', with its tier, version, scopes, settings form, health and last report; each action is audited, with step-up where TGL-40 asks.

7. **Three tiers.**

   - **Verified.** The source lives in `tenko-plugins`; the repository's workflow builds it from a reviewed commit and attests the result; authors never upload binaries. Becoming verified is a pull request and a review: easier than contributing to Tenko itself, not free.
   - **Community.** The index points at the author's repository and the author's attestation. Shown with a warning, off by default, never installable under Hardened.
   - **Local.** A file an administrator uploads, with its manifest.

   A new toggle, **TGL-40 "Plugin sources"**, for the lead to add to [SECURITY-PROFILES.md](../SECURITY-PROFILES.md):

   | Home | Standard | Hardened | Lab |
   |---|---|---|---|
   | Verified from the index; community after a warning, off by default; local with a warning | Verified with step-up; community off by default, step-up when on; local with step-up | Verified only, and until API-19 only as an uploaded file that matches the index (as TGL-23); community and local refused; managed plugins on Windows refused while they run as the service account | All three |

8. **Compatibility, health and updates.** The plugin API has a semantic version (additive within a major). The server refuses a plugin whose range excludes its version, before the start, with a message naming both (`plugin.api_mismatch`); the index shows only versions that fit. A plugin reports its version and health through the API; a managed plugin also has its unit's state, a remote plugin goes stale when its reports stop. An update is the flow of point 6; the release directory keeps the running and the previous version, as the layout keeps the previous binary (ADR 0023 I5, I6), so a rollback is a switch and a restart. In a controller cluster every controller verifies its own copy and only the leader runs the instance, as only the leader polls today.

9. **Bundled stays bundled; the first plugins are Hyper-V and vSphere.** Home Assistant, UniFi and Proxmox VE stay in the binary on the ADR 0012 contract. The first out-of-tree plugins are **Hyper-V** (CONN-10, WMI and PowerShell, so it runs on Windows, managed or remote) and **VMware vSphere** (CONN-11, REST, managed on Linux): read-only inventory sources with credentials, which exercise the secret hand-off and both supervisors. Moving a bundled connector out is a later decision, one at a time, once the plugin API has settled.

10. **Requirement rows.** The lead adds a PLUG- series to [REQUIREMENTS.md](../REQUIREMENTS.md); proposed:

    | ID | Requirement |
    |---|---|
    | PLUG-01 | Out-of-tree plugins, managed or remote, are processes that speak the HTTPS API and the event stream with a token scoped to their own source. |
    | PLUG-02 | Manifest version 2 (API range, platforms, scopes, network targets, settings, secrets), validated before install and start; the operator approves what it asks for at install and at a widening update. |
    | PLUG-03 | Linux: a managed plugin runs as an instance of `tenko-plugin@.service` with `DynamicUser=yes` and hardening no weaker than `tenko.service`; the installer installs the template and a polkit rule limited to it. |
    | PLUG-04 | Windows: a managed plugin runs as a supervised child process; a per-plugin virtual account follows. |
    | PLUG-05 | Token, secrets and start data reach a managed plugin once at start through systemd credentials or a pipe, never the environment, the command line or an API read. |
    | PLUG-06 | The `tenko-plugins` index and release files are fetched from a configured source or uploaded, and verified by size, SHA-256 and `SHA256SUMS` (with API-19, the owner's signature). |
    | PLUG-07 | Verified, community and local tiers, with TGL-40 per profile. |
    | PLUG-08 | Install, enable, disable, uninstall, update and rollback in the UI and the CLI; health and version through the API; a plugin outside the server's API range is refused. |

    CONN-21 (hub and WebAssembly transport) is replaced by these rows; CONN-10 and CONN-11 become the first plugins of the series.

## Consequences

- **What the API needs.** A plugin kind of service account and special scopes bound to a source; an observation write route with the batch semantics of a host poll (a complete batch expires the facts it no longer names, [connectors.md](../connectors.md) section 1) and the same normalization; a plugin registry in the store (name, version, tier, digest, manifest, approved scopes, state, previous version); a health route; an event stream filter so that a plugin token receives only the topics its scopes cover. Each is a public, documented route.
- **Two contracts for a while**, gRPC for bundled connectors and HTTP for the rest; the SDK, the conformance suite (`tenko plugin test` gains an API mode) and [plugins.md](../plugins.md) cover both. Secrets per call become secrets per run, and the plugin schedules itself; that buys an identity per plugin and the remote kind.
- **The installer gains a unit and a rule.** A new installation gets the template and the polkit rule (the installer checks that polkit is present). An existing installation gets them by running the installer again (`--reconfigure`), as ADR 0023 I4 says for anything that widens what the host grants: an update from the UI runs as the service account and cannot, and a `sudo tenko setup plugins` step is excluded by I10 (root never runs the service's binary). Until then the connectors page offers remote plugins only and names the command.
- **ADR 0023's invariants in plugin terms.** No root process runs a plugin file; systemd as root follows no link the service account can plant outside the plugin's release directory, for `ExecStart=` and the mounts (the plan proves it for systemd 250 and later); the template grants nothing `tenko.service` does not. With them, a compromised service account gains from the polkit rule only what it could already do: run code, now as a fresh user with less access than its own.
- **The Windows gap.** Until per-plugin virtual accounts exist, a managed plugin on Windows runs as `NT SERVICE\tenko` and can read the data directory and the DPAPI-sealed key material: a malicious one is a compromised Tenko, as an installed plugin is today. The connectors page says so, and Hardened refuses managed plugins there. A remote plugin under its own account is the contained way on Windows, and Hyper-V's on Hardened sites.
- **What Hardened allows.** Verified plugins only, as uploaded files matching the index until API-19, then from the index when it is signed; no community and no local plugins; no managed plugins on Windows; remote plugins with tokens an administrator mints, within TGL-05.
- **The repository is a second release path**: `tenko-plugins` needs the layer-1 checks of the security audit plan and its own tag ruleset before its first release, because its index decides what nodes install.
- **No review proves code harmless.** The containment is the token's scopes, the sandbox and the repository's layer-1 checks (dependency review, secret scanning, license checks per language): the review lowers the chance of harm, the containment bounds it. A plugin with a malicious dependency can still lie in the observations it may write (facts of its source, never intent) and reach the networks its unit allows; the documentation says so beside the tiers.

### Open for the owner

- **The key the node trusts for community plugins**: none (digest and the author's attestation shown), the author's key pinned at install, or the owner's countersignature after a lighter review.
- **Who reviews verified plugins**, with which checklist, and whether a plugin that holds credentials needs a second reviewer.
- **The content of plugin API 1.0**: inventory only (observations, health, settings events), or also the actuator and network-controller shapes; recommended: inventory only, which is all Hyper-V and vSphere need, with the writing shapes in a minor version with their first plugin.
- **The installed-directory path of [plugins.md](../plugins.md) section 10**, which runs third-party code as the service account: the recommendation is to close it to new installations once managed plugins ship, Lab excepted.
- **A root-less per-plugin address allow-list** (point 5), and whether the polkit rule may include `set-property` for it after its own review.

## Alternatives considered

Each option is weighed in the project's order: security, performance, usability, features.

- **Dynamic libraries.** The fastest calls, and the worst containment: a plugin shares the address space, the vault keys and the identity of the service, a crash takes it down, Rust has no stable ABI, and loading one needs `unsafe`, which the workspace forbids (API-16). Refused, as ADR 0012 already did.
- **WebAssembly (wasmtime or wasmer).** A good sandbox in principle, but wasmtime 50.0.1 declares 49 direct dependencies on crates.io (14 always, most of the rest for its default compiler) and wasmer 7.5.0 declares 39 (23 always): a large runtime for one job. Its JIT compiler must make memory executable, which `MemoryDenyWriteExecute=yes` of `tenko.service` forbids, so the unit would be weakened or an interpreter used at a cost in speed. Plugins would be bound to the runtime's interface and host functions; WMI and PowerShell have none, so Hyper-V could not be written. Refused; this supersedes ADR 0012 decision 7.
- **Feature-gated crates in Tenko's process only (what exists).** No new machinery, but every integration needs a Tenko release, third parties cannot ship anything, and an integration bug is a bug in the process that holds the vault. Kept for the bundled connectors, refused as the only way.
- **One shared `tenko-plugin` user for all plugins.** Simpler, but a compromised plugin reads the state and credentials of every other one. The owner chose one identity per plugin; `DynamicUser=` makes that free to manage.
- **Review-only trust without manifests.** Simpler for authors, but a plugin would hold a token as wide as the service's, the operator would see nothing before installing, and a missed flaw would be unbounded. Refused: the scopes contain, the review is a second line.
- **A central store Tenko hosts instead of a GitHub repository.** Full control, but a service to run and secure, author accounts, and a new target for A4. A public repository gives pull-request review, attestations, secret scanning and a transparency log at no cost, and its index can be mirrored and uploaded by hand. Revisited if its review does not scale.
- **The ADR 0012 gRPC contract for managed plugins, supervised by systemd.** Keeps one contract and secrets per call, but the host must be the client of a socket in another user's namespace, the stdio handshake does not exist for a unit systemd starts, and a remote plugin cannot use it. Refused for out-of-tree plugins; kept for the bundled ones.
