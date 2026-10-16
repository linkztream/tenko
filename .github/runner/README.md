# Self-hosted Linux runner

The Linux jobs of the `CI` and `Release` workflows run on GitHub's hosted runners by default
(`ubuntu-latest`). When the repository variable `LINUX_RUNNER` is set, they run on the
self-hosted runners that carry that label instead; the Windows jobs always stay on GitHub's
`windows-latest`. This directory holds the runbook for such a runner: one dedicated,
unprivileged Ubuntu 24.04 LXC container on a Proxmox VE host. The scripts that create and set
it up are in [../../deploy/proxmox/](../../deploy/proxmox/README.md).

Why: hosted minutes are limited on a private repository (Windows minutes count double), and
the weekly jobs (the cluster lab, the systemd and macvlan smokes, the fuzz smoke) take hours.
A self-hosted runner has no minute budget and keeps its caches warm between runs.

## What the jobs need from the runner

| Need | Used by | Provided by |
|---|---|---|
| C and C++ toolchain, `pkg-config`, `cmake` | `aws-lc-sys`, `libfuzzer-sys` | `build-essential`, `pkg-config`, `cmake` |
| `musl-tools` | the static Linux binary of the `Release` workflow | apt |
| Docker with the compose and buildx plugins | the macvlan smoke, the compose lab, the container image, the release smoke | Docker's apt repository |
| A `dummy` network link inside the container | the macvlan smoke (`deploy/compose/smoke-macvlan.sh`) | the `dummy` module loaded on the Proxmox host |
| systemd 250 or later with `systemd-creds` and `systemd-analyze` | the systemd smoke (`deploy/systemd/smoke.sh`) | Ubuntu 24.04 (systemd 255) |
| Passwordless `sudo` for the runner account | the systemd smoke, the macvlan smoke, `npx playwright install --with-deps` | the install script |
| `curl`, `openssl`, `python3`, `jq`, `file`, `iproute2` | the smokes, the release checks | apt |
| Rust and Node | every job | installed by the jobs themselves (`dtolnay/rust-toolchain`, `actions/setup-node`) into the runner account's home |
| Disk | the test build of the workspace is tens of gigabytes; `Swatinem/rust-cache` restores and saves it through GitHub's cache | a 120 GB root disk on SSD; see housekeeping |
| Memory | the test build links one binary per parallel job, about 2 GiB each, one job per core unless capped | about 2 GiB per core; the install script caps cargo's jobs to the memory through `CARGO_BUILD_JOBS` in the runner's `.env` (the memory in GiB divided by two, at most the core count) |

## The container

`deploy/proxmox/ct/tenko-ci-runner.sh` creates it with these values (Setup below); by hand,
create an unprivileged container on the Proxmox host (the names and addresses are yours; this
document uses placeholders):

- Template: Ubuntu 24.04 standard. Resources: 4 vCPU or more with about 2 GiB of RAM per
  vCPU (8 GiB for 4; 28 vCPU want 32 GiB and a few GiB of swap; with less memory the
  install script caps the build's parallel jobs to it), 120 GB root disk on SSD-backed
  storage, one bridged network interface with outbound access to github.com, crates.io, registry.npmjs.org,
  download.docker.com and the Ubuntu mirrors. The runner polls GitHub; nothing reaches the
  container from outside, so no port is forwarded to it.
- Options: `features: nesting=1,keyctl=1` (Docker needs both in an unprivileged container),
  `unprivileged: 1`. Leave the AppArmor profile at its default.
- On the Proxmox host, load the `dummy` module and keep it across reboots: `modprobe dummy`
  and `echo dummy > /etc/modules-load.d/tenko-runner.conf`. The container cannot load kernel
  modules itself; without the module the macvlan smoke fails at its first step.
- Snapshot the container after the setup below; a runner that collects state over months is
  easier to roll back than to clean.

## Setup

### Proxmox: one command

On the Proxmox host, `deploy/proxmox/ct/tenko-ci-runner.sh` creates the container described
above, sets it up and registers it, with a dialog for the settings and the registration
token: [../../deploy/proxmox/README.md](../../deploy/proxmox/README.md). Take the token of
step 1 first; step 4 below follows it. The steps 2 and 3 are the by-hand path.

### By hand

The install script `deploy/proxmox/install/tenko-ci-runner-install.sh` installs the
packages, Docker, the runner account and the runner service, and registers the runner with
the repository. It is written for a fresh container and is safe to run again. It needs
`deploy/proxmox/lib/container.sh` and `deploy/proxmox/lib/common.sh` next to it or in
`../lib`:

1. On your workstation, take a registration token (valid for one hour):

   ```bash
   gh api -X POST repos/linkztream/tenko/actions/runners/registration-token --jq .token
   ```

2. Optional, to pin the runner: in the repository settings, Actions, Runners, "New
   self-hosted runner", Linux x64, copy the runner version and the SHA-256 from the
   "Download" box (the `curl` line names the version, the `shasum` line the checksum).
   Without them the script takes the latest release and the checksum its release notes
   publish; it never unpacks a tarball that does not match.

3. Inside the container, as root, with the three files copied there (for example with
   `pct push <ctid> <file> /root/<file>` from the Proxmox host), the token on standard
   input:

   ```bash
   printf '%s\n' '<token from step 1>' | \
     RUNNER_VERSION=<version from step 2> RUNNER_SHA256=<checksum from step 2> \
     bash /root/tenko-ci-runner-install.sh
   ```

   Optional variables: `RUNNER_NAME` (default: the container's host name), `RUNNER_LABELS`
   (default `tenko-linux`), `RUNNER_USER` (default `runner`), `RUNNER_DIR` (default
   `/opt/actions-runner`), `REPO_URL` (default this repository).

4. Point the workflows at the runner and enable them, from your workstation:

   ```bash
   gh variable set LINUX_RUNNER --repo linkztream/tenko --body tenko-linux
   ```

   ```bash
   gh workflow enable CI --repo linkztream/tenko && gh workflow enable Release --repo linkztream/tenko
   ```

   ```bash
   gh workflow run CI --repo linkztream/tenko
   ```

   The first run installs the Rust toolchain, Node and Chromium with its system libraries
   into the runner account; later runs reuse them.

A second runner in the same container (two jobs at a time) is the install script run again
with `RUNNER_NAME=<name>-2 RUNNER_DIR=/opt/actions-runner-2` and a fresh registration token; both
carry the label, and GitHub spreads the queued jobs over them. Size the container for two
builds at once first.

## Operation

- Service: `systemctl status 'actions.runner.*'`; logs: `journalctl -u 'actions.runner.*'`
  and `<RUNNER_DIR>/_diag/`.
- The runner updates itself when GitHub releases a new version. To move it to another
  version by hand: stop the service (`<RUNNER_DIR>/svc.sh stop`), download and verify the
  new tarball as in the setup, extract it over the directory, start the service.
- Housekeeping: `docker system prune --all --force` removes the images the smokes built (the
  scripts clean their containers and networks themselves); `<RUNNER_DIR>/_work/` holds the
  checkouts and the target directories of the last run of every job and can be emptied while
  no job runs. `df -h /` and `docker system df` tell when.
- After a resize of the container: the cap `CARGO_BUILD_JOBS` in `<RUNNER_DIR>/.env`
  follows the memory at install time. Run the install script again in the container, as
  root and without a token (`bash deploy/proxmox/install/tenko-ci-runner-install.sh </dev/null`):
  it keeps the registration, rewrites the cap and starts the service again. Or edit the
  line and restart the service.
- Switching back to the hosted runners (for example while the container is down):
  `gh variable delete LINUX_RUNNER --repo linkztream/tenko`. The next run uses
  `ubuntu-latest` again; nothing else changes.
- Removing the runner: `<RUNNER_DIR>/svc.sh stop && <RUNNER_DIR>/svc.sh uninstall`, then as
  the runner account `./config.sh remove --token <a fresh registration token>`.

## Security notes

- The runner executes the workflows of this repository with the repository's `GITHUB_TOKEN`
  (read access, and `packages: write` in the release's image job). It is a private
  repository, so only its collaborators can start a workflow; pull requests from forks do not
  exist here. Keep it that way: GitHub advises against self-hosted runners on public
  repositories.
- The runner account has passwordless `sudo` because the smokes install a service, create a
  system user and manage Docker. The container is therefore dedicated to this one purpose,
  holds no other credentials or data, and is reachable only from the Proxmox host. Treat a
  compromise of the repository as a compromise of the container and rebuild it from the
  snapshot.
- The install script installs the runner only from a tarball that matches its SHA-256 (the
  one you copied from GitHub, or the one the release notes publish), and Docker only from
  Docker's signed apt repository. The registration token reaches it on standard input and
  never touches disk, an argument list or a log.
- Nothing in this directory or in the workflows names the host, the container, its address or
  the network; keep it so.
