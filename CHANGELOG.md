# Changelog

All notable changes to Tenko DDI are recorded here, one section per release, in the format of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) 1.1.0 with Semantic Versioning 2.0.0. One addition: a `### Action required` subsection under a release lists what an administrator must do before or after upgrading to it. Every change to `crates/**` or `ui/src/**` adds an entry under Unreleased; CI checks this with `scripts/changelog.mjs`.

## [Unreleased]

### Added

- One binary, `tenko`: `tenko serve` runs the server with the web UI, and `setup`, `login`, `prefix`, `import`, `export`, `audit verify` and `ca-root` are the command-line client of its API.
- Configuration from built-in defaults, `tenko.toml`, `TENKO_*` environment variables and command-line flags, checked with `tenko config check`.
- The replicated store: an embedded key-value engine under a Raft log, with snapshots and crash-safe commits.
- The vault: secrets encrypted at rest under a key-encryption key held by the platform (DPAPI on Windows) or in a key file, rotated with `tenko kek rotate`.
- The internal certificate authority and three TLS modes: a certificate from the internal CA, an imported certificate reloaded on change, and plain HTTP behind a trusted reverse proxy.
- Sign-in with a password or a PIN as the security profile allows, with a breached-password check, TOTP, passkeys, recovery codes and personal API tokens.
- Four security profiles (Home, Standard, Hardened, Lab) and the toggles behind them, with insecure modes marked in the UI and in the log.
- The job engine: every change runs as a job with steps, timeouts, manual steps and rollback.
- IPAM objects: VRFs, tenants, sites, VLANs, prefixes, address ranges, addresses, hosts and their interfaces.
- The prefix tree with utilization per prefix and alarms at the configured levels.
- Tags and custom fields on IPAM objects.
- History of every IPAM object, with restore of an earlier revision.
- Bulk changes with a preview before anything is applied.
- Import of spreadsheets and CSV files with column mapping and a preview, and export of prefixes, addresses and hosts as CSV.
- Moving hosts to another network: a dry-run preview, then a job with manual steps for DHCP, DNS and the switch port, observation of the old address, and rollback.
- The audit log, protected by a hash chain that `tenko audit verify` and the UI check.
- Server-sent events, so the UI follows changes made elsewhere without reloading.
- The web UI, embedded in the binary, in English and Swedish, with a first-run setup wizard.
- The Windows service (`tenko service`) and a hardened systemd unit.
- The container image, with a health check and Compose examples.
- A data-directory format version with migrations at start-up, and `tenko upgrade check`, a dry run against a copy of the data directory (exit codes 0, 10 and 11).
- An in-app update notice with release notes, a what's-new page after an upgrade, and installation from the UI on single native nodes with an automatic switch back (security profile toggle TGL-23).
- A module switch: `modules` in `tenko.toml` and a first-run choice of what the installation is for.
- The release manifest `releases.json` with SHA-256 checksums, and this changelog checked in CI.
- A version layout under `<data_dir>/updates` with a `current` link: the systemd unit and `tenko service install` run the version it points at, `tenko upgrade layout` sets it up, and a restart requested with exit status 12 is restarted by both. A server counts as supervised only when the Windows service runs it or `TENKO_SUPERVISED=1` says so (the systemd unit sets it); variables that systemd passes to every process are not taken as a sign.
- Observations: what connectors report about devices (MAC and IP addresses, names, operating system, platform, hypervisor node, the switch port or wireless network a client uses) is kept per source, apart from the intended state, with first and last sighting, and can be viewed per device across all sources. Observations not seen for 30 days are removed.
- Proposals: Tenko compares the intended state with what it observes, every five minutes and shortly after every change, and proposes discovered hosts, the deprecation of addresses no source has seen for seven days, a host's address when the device is seen elsewhere, networks for addresses outside every known prefix, and conflicts (two devices on one address, one device in several networks, an address used by another device). A proposal shows its evidence and the changes it would make, and can be previewed, approved or rejected; a rejected proposal stays closed until its evidence changes. A locked host never gets a proposal that would change it, and an unmanaged host gets none.
- Adoption policies per prefix, inherited by the prefixes inside it, that approve discovered hosts without a person: optionally only inside DHCP pools, only for listed vendor prefixes of the MAC address, or only after a number of sightings.
- Operator secrets: passwords, API keys, SSH keys and tokens with a name, purpose tags, a user name and notes, kept encrypted in the vault, each under a key of its own. Administrators create, change, replace and delete them; operators see them and may reveal them. A secret that a host or a connector still uses cannot be deleted, and its references are listed.
- Revealing a secret shows it once and copies it to the clipboard, which is cleared again after 30 seconds; every reveal, and every refused one, is written to the audit log with the person, the host and the reason, never the value.
- Credentials of a host: secrets bound to a host as its administration, remote desktop, SSH or web login, with "Copy password" on the host page.
- Remote access from the host page: a Remote Desktop file or an SSH link for each address of a host, with the user name of its credential and no password in either.
- The security profile toggle TGL-24 decides what a reveal takes: the signed-in session (Home, Lab), a sign-in within the last five minutes (Standard), or a passkey sign-in within the last five minutes and only from the page of a host the secret is bound to (Hardened).
- Probe nodes: `tenko node enrol` enrols a node with a controller using a single-use enrolment token, which an administrator creates in the API or with `tenko node enrol-token`. The node checks the controller's CA fingerprint, keeps its key to itself and receives a certificate with its node id and roles; `tenko serve --roles probe` then runs it. The node connects to the controller over mutual TLS on the cluster port (8444 by default, opened once a node or a token exists), sends heartbeats, renews its certificate before it expires, and keeps its observations in a buffer on disk while no controller is reachable, sending them in order once one is. `tenko node status` shows the node and its connection, `tenko node renew` renews at once.
- The node registry: `GET /api/v1/nodes` lists the enrolled nodes with their roles, certificate, version and live connection, enrolment tokens can be listed and deleted, and revoking a node closes its connections and refuses its certificate from then on. `GET /api/v1/system/status` reports enrolled and connected nodes and their versions.
- Controllers and nodes agree on the protocol version, so they can be upgraded one at a time; a node that shares no version with its controller is refused with a clear error and shown as a warning in the system status.
- A `[cluster]` section in `tenko.toml`: the addresses of the cluster port, the endpoints nodes are told, the heartbeat interval, the token lifetime and the size of a node's buffer.

### Changed

- Credentials taken over by an import are operator secrets bound to their host; the login becomes the user name of the secret. Credentials imported earlier are taken over at the first start of this version.
- Operators may reveal operator secrets, so the PIN rule applies to operator accounts too: once the vault holds a secret, an operator signs in with a password, a second factor or a passkey.
- A move completes its observation step by itself when the device is seen at its new address from its own MAC address; a person can still confirm the step by hand.

### Security

- The cluster port accepts only node certificates of the installation's internal CA that are not revoked, and a node accepts only a controller of its own CA. Enrolment tokens are kept only as a digest, work once and expire after an hour by default; every enrolment, and every refused one, is written to the audit log. On Windows a node's private key is sealed with DPAPI.
- A PIN session never reveals a secret, and personal API tokens never do. The vault takes no operator secret while an account that may reveal secrets signs in with a PIN alone.
- Reveals are limited to ten a minute per person.
- Connectors can be given a secret only by people who may change secrets, so the reveal policy cannot be bypassed through a connector.
- Repeated requests with an idempotency key are recognised by a fingerprint keyed with a random secret that exists only in memory and changes at every start, so the stored fingerprints reveal nothing about the requests; sign-in, setup and password requests are never fingerprinted. A retry after a restart of a request sent before it is answered as already performed instead of being run again.
