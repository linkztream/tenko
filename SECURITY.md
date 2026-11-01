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

Tenko is released as the 0.0.x line, often (0.0.3 on 2026-10-22, 0.0.10 on 2026-10-31).
A security fix ships in the next 0.0.x release; there are no backports to earlier releases.
A report against an older release or commit is checked against the latest release and
`main` first.

| Version                                  | Supported                       |
|------------------------------------------|---------------------------------|
| The latest 0.0.x release (0.0.10 today)  | Yes                             |
| `main` (latest commit)                   | Yes; a fix lands here first     |
| Earlier 0.0.x releases                   | No; upgrade to the latest       |
| Commits that are no release              | No                              |

When a line with a support period exists (0.1 or 1.0), this table lists it.

## Verifying a release

Releases after 0.0.10 carry, besides the binaries, the MSI, `install.sh`,
`tenko-proxmox.sh`, `releases.json` and `SHA256SUMS`:

- **SBOMs** in CycloneDX JSON, one per published thing, listed in `SHA256SUMS`:

  | File | Describes |
  |---|---|
  | `tenko-<version>-linux-x86_64.cdx.json` | The crates of the Linux binary, from `Cargo.lock` |
  | `tenko-<version>-windows-x86_64.cdx.json` | The crates of the Windows binary, from `Cargo.lock` |
  | `tenko-<version>-ui.cdx.json` | The production dependencies of the web UI that both binaries embed, from `ui/package-lock.json` |
  | `tenko-<version>-image.cdx.json` | The container image `ghcr.io/linkztream/tenko:<version>` |

- **Attestations**, signed through Sigstore's public instance, recorded in its transparency
  log and stored with the repository (the image's also in the registry beside it): a SLSA
  build provenance attestation for every release file and for the image digest, and an SBOM
  attestation that binds each SBOM to its binary (the UI's to both binaries) or to the image.

The release workflow (`.github/workflows/release.yml`) makes them; its job `attest` is the
only one that can sign. To check a downloaded file with the
[GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify tenko-<version>-linux-x86_64 --repo linkztream/tenko \
  --signer-workflow github.com/linkztream/tenko/.github/workflows/release.yml \
  --deny-self-hosted-runners
```

The same command works for every file of the release (the `.exe`, the `.msi`,
`SHA256SUMS`, `releases.json`, the installers and the SBOMs). It succeeds only when the file's
SHA-256 is the subject of an attestation that the release workflow of this repository made
on a GitHub-hosted runner, and it prints the commit and the ref the run was built from; for a
release made by pushing its tag the ref is `refs/tags/v<version>` (a run started by hand
names the branch it was started from and builds the tag it was given). With `--format json`
the whole provenance statement is printed.

For the container image, verify the digest you run, not a tag that can move:

```sh
docker pull ghcr.io/linkztream/tenko:<version>
docker inspect --format '{{index .RepoDigests 0}}' ghcr.io/linkztream/tenko:<version>
gh attestation verify oci://ghcr.io/linkztream/tenko@sha256:<digest> --owner linkztream \
  --signer-workflow github.com/linkztream/tenko/.github/workflows/release.yml
```

Add `--bundle-from-oci` to read the attestation from the registry instead of from GitHub.

The SBOM attestations are verified with the predicate type of CycloneDX:

```sh
gh attestation verify tenko-<version>-linux-x86_64 --repo linkztream/tenko \
  --predicate-type https://cyclonedx.org/bom
```

It lists two for each binary, the crates and the web UI. The SBOM files are plain JSON;
`jq -r '.components[] | "\(.name) \(.version)"' tenko-<version>-linux-x86_64.cdx.json` lists
the components, and any tool that reads CycloneDX (a vulnerability scanner, a licence
checker) takes the file as it is.

What this does not prove (section 7.2 of
[docs/plans/security-audit-plan.md](docs/plans/security-audit-plan.md)):

- **The provenance proves where a file was built, not that the owner released it.** It says
  that the release workflow of this repository built the file from the commit it names.
  Anyone who can push a tag to the repository gets the same proof for their own release.
  What closes that is a signature with a key GitHub never holds, which a node checks before
  a binary enters its layout (requirement API-19, not built yet; the plan proposes that the
  owner's hardware key signs `SHA256SUMS` after the release's security round).
- **A node does not check attestations.** An installation that updates itself compares the
  binary with the SHA-256 of `releases.json`, which comes from the same release as the binary
  ([docs/upgrades.md](docs/upgrades.md) section 8.11). Check the attestation yourself before
  you install a release or upload it to a node.
- **The SBOMs list what the build was made from, with known edges.** The binaries' SBOMs list
  the crates `cargo tree` gives for the release build (build-time and test-only dependencies
  left out, procedural macros kept); C code that a crate compiles (`aws-lc-sys`, `ring`, the
  allocator) is listed as that crate, and the musl C library of the static Linux binary,
  which comes from the build runner's `musl-tools`, is not listed. The UI's SBOM lists the
  production dependencies of the lock file, which is more than the bundle includes. The
  image's SBOM lists the packages of its distroless base and what the scanner recognises;
  its binary is built from the same source and `Cargo.lock` as the Linux binary, so the
  crates are those of the Linux SBOM.
- Releases up to 0.0.10 carry neither SBOMs nor attestations.

## Checks at every release

Besides the deterministic CI checks, every release runs a **lab round `security`** on the
binary being released, before it is published: it installs a throwaway node from that binary,
looks at it from outside (the ports it answers on, its TLS, malformed DNS on the wire) and
from the host (the systemd unit and the service account), and leaves a report with stable
finding IDs. A review of the changes since the last reviewed release asks an attacker's
questions of the security-relevant diff. A public summary of what each release's checks found
is published under [`docs/security/`](docs/security/README.md) (`release-<version>.md`); the
full report and its evidence stay in a private repository, so an open weakness of a released
version is not disclosed before its fix. [`docs/plans/security-audit-plan.md`](docs/plans/security-audit-plan.md)
describes the layers; the round's scripts are in [`deploy/security/`](deploy/security/README.md).
A human penetration test is planned for the first external user or 1.0.

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

- The lab and bench directories (`deploy/compose/*lab*`, `deploy/security/`, `bench/`) and
  the test fixtures: they are for development and measurement, not for production, and they
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
