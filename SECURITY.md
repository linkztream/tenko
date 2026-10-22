# Security policy

Tenko DDI runs DNS, DHCP and IPAM for networks that depend on it, so a vulnerability in
it matters to everyone who runs it. Thank you for reporting what you find, privately,
so that a fix can ship before the details are public.

## Reporting a vulnerability

Report vulnerabilities privately. Do not open a public issue, a pull request or a
discussion for anything that could be a security problem.

1. **Preferred:** use GitHub's private vulnerability reporting on this repository
   ("Security" tab, "Report a vulnerability"). The report is visible only to the
   maintainers and to you, and the fix is coordinated in the same place.
2. **Fallback:** email linkztream@gmail.com (the contact of `LICENSE.md`) with
   "Tenko security" in the subject. Ask for a public key in a first message if you want
   to encrypt the report.

Please include what you can of the following:

- The version (`tenko --version`) or the commit, the roles the node runs (`controller`,
  `dns`, `dhcp`, `probe`), the security profile (Home, Standard, Hardened, Lab) and the
  platform (Linux distribution, Windows version, container).
- What the problem is and what an attacker gains from it (who, from where, with which
  access).
- Steps to reproduce, a proof of concept or a packet capture. Use documentation
  addresses (RFC 5737, RFC 3849) and names under `example.test` in anything you send;
  redact the addresses, names and accounts of your own network.
- Whether you want to be credited, and under which name.

## What to expect

- **Acknowledgement within 3 working days** of the report.
- **A fix or a mitigation plan within 30 days** for high and critical severity; lower
  severities are scheduled into the next release and you are told when.
- **Coordinated disclosure.** The details stay private until the fix has shipped. The
  release notes and a GitHub security advisory describe the problem, the affected
  versions and the fix; a CVE is requested through the advisory when one is warranted.
  If a fix needs more than 90 days, we agree a date with you.
- **Credit** in the advisory and the release notes, if you want it.

Reports made in good faith, within the scope below and without harming other people's
systems or data, are welcome; nobody is pursued for one.

## Supported versions

There is no tagged release yet. Until the first release, the latest commit on `main` is
the only supported version; a report against an older commit is checked against `main`
first.

| Version                | Supported |
|------------------------|-----------|
| `main` (latest commit) | Yes       |
| Anything older         | No        |

Once releases exist, this table lists which release lines receive security fixes.

## Scope

In scope:

- The server (`tenko serve`, every role) and its protocols: DNS, DHCP, the HTTP API,
  the cluster transport, the connector plugins that ship in the repository.
- The command-line client (every other `tenko` command).
- The web UI.
- The installers (`deploy/install.sh`, the Windows MSI, the Proxmox script) and the
  deployment templates (`deploy/`: the container image, Compose, systemd, the Windows
  service).
- The release workflow and the artefacts it publishes.

Out of scope:

- The lab and bench directories (`deploy/compose/*lab*`, `bench/`) and the test
  fixtures: they are for development and measurement, not for production, and they
  deliberately run insecure settings.
- The Lab security profile's permissive settings and every toggle the UI marks as
  insecure when the operator set it: these are documented choices, not vulnerabilities.
  A way to switch off one of the items that are never off (`NEVER-01` to `NEVER-03`)
  is in scope.
- Denial of service that needs more traffic than a single server on the same link can
  send. Amplification, cache poisoning and resource exhaustion from ordinary traffic are
  in scope.
- Findings in third-party dependencies that are already public; report those upstream.
  A dependency problem that Tenko makes reachable is in scope.

## Hardening an installation

The operator's side of security is documented in the repository:

- [`docs/SECURITY-PROFILES.md`](docs/SECURITY-PROFILES.md): the four profiles, the
  toggles behind them and the items that are never switched off. The **Hardened**
  profile is the one for regulated or exposed environments.
- [`docs/access.md`](docs/access.md): roles, scoped grants, service accounts and scoped
  tokens.
- [`docs/secrets.md`](docs/secrets.md): the vault and the key-encryption key.
- `deploy/`: the hardened systemd unit, the Windows service and the container image.
