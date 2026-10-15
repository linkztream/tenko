# Self-hosted Linux runner

The Linux jobs of the `CI` and `Release` workflows run on GitHub's hosted runners by default
(`ubuntu-latest`). When the repository variable `LINUX_RUNNER` is set, they run on the
self-hosted runners that carry that label instead; the Windows jobs always stay on GitHub's
`windows-latest`. This directory holds the runbook and the setup script for such a runner: one
dedicated, unprivileged Ubuntu 24.04 LXC container on a Proxmox VE host.

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
| Passwordless `sudo` for the runner account | the systemd smoke, the macvlan smoke, `npx playwright install --with-deps` | the setup script |
| `curl`, `openssl`, `python3`, `jq`, `file`, `iproute2` | the smokes, the release checks | apt |
| Rust and Node | every job | installed by the jobs themselves (`dtolnay/rust-toolchain`, `actions/setup-node`) into the runner account's home |
| Disk | the test build of the workspace is tens of gigabytes; `Swatinem/rust-cache` restores and saves it through GitHub's cache | a 120 GB root disk on SSD; see housekeeping |

## The container

Create an unprivileged container on the Proxmox host (the names and addresses are yours; this
document uses placeholders):

- Template: Ubuntu 24.04 standard. Resources: 4 vCPU or more, 8 GB RAM (16 GB makes the
  workspace test build comfortable), 120 GB root disk on SSD-backed storage, one bridged
  network interface with outbound access to github.com, crates.io, registry.npmjs.org,
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

The script installs the packages, Docker, the runner account and the runner service, and
registers the runner with the repository. It is written for a fresh container and is safe to
run again. Three values come from GitHub and are passed as environment variables, so that the
runner software is only ever installed from a checksum you took from GitHub yourself:

1. On your workstation, take a registration token (valid for one hour):

   ```bash
   gh api -X POST repos/linkztream/tenko/actions/runners/registration-token --jq .token
   ```

2. In the repository settings, Actions, Runners, "New self-hosted runner", Linux x64: copy
   the runner version and the SHA-256 from the "Download" box (the `curl` line names the
   version, the `shasum` line the checksum).

3. Inside the container, as root, with the script copied there (for example with `pct push`
   from the Proxmox host, or `scp` into the container):

   ```bash
   RUNNER_VERSION=<version from step 2> RUNNER_SHA256=<checksum from step 2> \
   RUNNER_TOKEN=<token from step 1> bash setup-lxc.sh
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

A second runner in the same container (two jobs at a time) is the same script run again with
`RUNNER_NAME=<name>-2 RUNNER_DIR=/opt/actions-runner-2` and a fresh registration token; both
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
- The setup script installs the runner only from a tarball whose SHA-256 you copied from
  GitHub, and Docker only from Docker's signed apt repository.
- Nothing in this directory or in the workflows names the host, the container, its address or
  the network; keep it so.
