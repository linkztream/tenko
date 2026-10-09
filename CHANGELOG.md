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

### Changed

- A move completes its observation step by itself when the device is seen at its new address from its own MAC address; a person can still confirm the step by hand.
