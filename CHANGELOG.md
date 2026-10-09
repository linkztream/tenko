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
- A version layout under `<data_dir>/updates` with a `current` link: the systemd unit and `tenko service install` run the version it points at, `tenko upgrade layout` sets it up, and a restart requested with exit status 12 is restarted by both.
