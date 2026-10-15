# Proxmox VE container scripts

Scripts that create an LXC container on a Proxmox VE host and set it up for one purpose, in
one command. Today there is one: `ct/tenko-ci-runner.sh`, the self-hosted GitHub Actions
runner for the Linux jobs of this repository ([../../.github/runner/README.md](../../.github/runner/README.md)
is its runbook). The runner container is not a Tenko installation; that one is described by
hand in [../README.md](../README.md), section "LXC".

Everything that runs on the hypervisor is in this directory; nothing is fetched from
anywhere else. The only tools used on the host are the ones Proxmox VE ships (`pct`,
`pveam`, `pvesm`, `pvesh`, `whiptail`, `curl`).

| Path | What it is |
|---|---|
| `ct/tenko-ci-runner.sh` | The runner's host-side script: its defaults, hooks and final lines |
| `install/tenko-ci-runner-install.sh` | The runner's container-side install; also runs by hand |
| `lib/host.sh` | The generic host flow: settings and dialogs, template, `pct create`, wait, push and run, update mode, dry run |
| `lib/container.sh` | The generic container-side helpers of the install scripts |
| `lib/common.sh` | Messages, the quiet/verbose switch, the runner release lookup |
| `test/` | The checks; `bash deploy/proxmox/test/run.sh` runs them all |

## What the runner script creates

- An unprivileged Ubuntu 24.04 container (the newest `ubuntu-24.04-standard` template
  that `pveam available` lists, downloaded to the template storage when missing) with
  `features: nesting=1,keyctl=1` (Docker needs both), 4 cores, 8 GiB memory, 512 MiB swap,
  a 120 GB root disk, one bridged NIC (`eth0` on `vmbr0`, DHCP), start on boot, the tags
  `ci;runner`, a description with the app, the repository and the date. No root password
  unless you give one; the console is `pct enter <ctid>`.
- In it: the build packages (`build-essential pkg-config cmake musl-tools git curl
  ca-certificates gnupg jq file unzip xz-utils iproute2 openssl python3 sudo`), Docker CE
  with the compose and buildx plugins from Docker's apt repository (keyring in
  `/etc/apt/keyrings`, a deb822 `docker.sources`), the account `runner` in the `docker`
  group with passwordless sudo (`/etc/sudoers.d/90-runner`), the runner software in
  `/opt/actions-runner` (owned by the account, verified against its SHA-256 before it is
  unpacked) with its .NET dependencies, and, with a registration token, the registration
  (labels `tenko-linux`) and the service `actions.runner.<owner>-<repo>.<name>`.
- Checks at the end, as `ok`/`!!` lines: Docker runs, a `dummy` link can be created (the
  macvlan smoke), systemd 250 or later and `systemd-creds` (the systemd smoke), free disk,
  the runner service.

## Before the first run, on the Proxmox host

Load the `dummy` module and keep it across reboots; the container cannot load modules and
the macvlan smoke needs it:

```bash
modprobe dummy && echo dummy > /etc/modules-load.d/tenko-runner.conf
```

## Running it

Take a registration token on your workstation first; it is valid for one hour:

```bash
gh api -X POST repos/linkztream/tenko/actions/runners/registration-token --jq .token
```

Then, as root on the Proxmox host, one of:

```bash
# From a checkout of the repository on the host:
bash deploy/proxmox/ct/tenko-ci-runner.sh

# In one command, without a checkout. The repository is private: GITHUB_TOKEN is a
# fine-grained token with read access to its contents.
bash -c "$(curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" https://raw.githubusercontent.com/linkztream/tenko/main/deploy/proxmox/ct/tenko-ci-runner.sh)"
```

In the one-command form the script fetches `lib/` and its install script with the same
token into a temporary directory, removed on exit. It also uses the token for the GitHub
API lookup of the runner release, then drops it; it never reaches the container. A failed
fetch stops with a message that names the two ways above.

The script shows every setting with its default. "Create" takes them; "Advanced" asks for
each one in turn, prefilled (storages and bridges as a menu when there is more than one).
Then a password box asks for the registration token; leave it empty to register later. The
first run should show, in this order: the runner release found, the template found or
downloaded, the container created, started and up with an address, the install steps of
the container (packages, Docker, account, runner verified and installed, registered,
service started) and its checks, then a summary (CTID, host name, address, `pct enter`)
and the three commands for your workstation:

```bash
gh variable set LINUX_RUNNER --repo linkztream/tenko --body tenko-linux
gh workflow enable CI --repo linkztream/tenko && gh workflow enable Release --repo linkztream/tenko
gh workflow run CI --repo linkztream/tenko
```

The first CI run installs the Rust toolchain, Node and Chromium into the runner account;
later runs reuse them. Snapshot the container once it has run green.

Unattended, with everything from the environment and no dialog:

```bash
RUNNER_TOKEN=<token> var_unattended=yes var_storage=<storage> bash deploy/proxmox/ct/tenko-ci-runner.sh
```

## Settings

Every setting is a variable that the environment overrides. Generic ones (`lib/host.sh`):

| Variable | Default | Meaning |
|---|---|---|
| `var_ctid` | `pvesh get /cluster/nextid` | Container ID |
| `var_hostname` | `tenko-ci-runner` (generic: the slug of `APP`) | Host name, also the runner's name |
| `var_storage` | the only active `rootdir` storage, else asked | Root disk storage (`pvesm status --content rootdir`) |
| `var_template_storage` | the only active `vztmpl` storage, else asked | Where the template goes |
| `var_bridge` | `vmbr0` | Bridge of `eth0` (one of `ip -o link show type bridge`) |
| `var_ip` | `dhcp` | `dhcp` or `a.b.c.d/nn` |
| `var_gateway` | empty | Required with a static address |
| `var_dns` | empty | DNS servers, space or comma separated; empty: the host's |
| `var_cpu` | `4` (generic `1`) | Cores |
| `var_ram` | `8192` (generic `1024`) | Memory, MiB |
| `var_swap` | `512` | Swap, MiB |
| `var_disk` | `120` (generic `8`) | Root disk, GB |
| `var_os`, `var_version` | `ubuntu`, `24.04` | Template |
| `var_unprivileged` | `1` | Unprivileged container |
| `var_nesting`, `var_keyctl`, `var_fuse` | `1`, `1`, `0` | Container features |
| `var_onboot` | `1` | Start on boot |
| `var_tags` | `ci;runner` | Proxmox tags |
| `var_password` | empty | Root password (set with `chpasswd` on standard input); empty: none |
| `var_ssh_key` | empty | A public key, or the path of a file with keys, for root |
| `var_verbose` | `no` | `yes` shows the output of every step instead of logging it |
| `var_keep_on_failure` | `no` | `yes` keeps a container whose setup failed; otherwise the script offers to destroy it (unattended: destroys it) |
| `var_unattended` | `no` | `yes`: no dialogs; an invalid or missing setting stops the run |

The runner's own (`ct/tenko-ci-runner.sh`) and the environment:

| Variable | Default | Meaning |
|---|---|---|
| `var_runner_labels` | `tenko-linux` | Runner labels; the first is the value of the repository variable `LINUX_RUNNER` |
| `var_repo_url` | `https://github.com/linkztream/tenko` | Repository the runner registers with |
| `var_runner_version` | the latest release | Runner version, e.g. `2.330.0` |
| `var_runner_sha256` | from the release notes | SHA-256 of `actions-runner-linux-x64-<version>.tar.gz` |
| `RUNNER_TOKEN` | empty: a password box asks | Registration token; empty: register later by hand |
| `GITHUB_TOKEN` | empty | Fine-grained read token for the one-command form and the API lookup |
| `TENKO_SCRIPTS_URL` | `https://raw.githubusercontent.com/linkztream/tenko/main/deploy/proxmox` | Where the one-command form fetches `lib/` and `install/` |
| `TENKO_DRY_RUN` | `0` | `1`: print every `pct`, `pveam`, `pvesm` and `pvesh` command instead of running it, with canned answers; runs on any Linux |

The runner version and its checksum are resolved on the host before anything is created,
so the settings dialog shows them: `GET https://api.github.com/repos/actions/runner/releases/latest`
gives the version (`tag_name`) and, in the release notes, the checksum line of
`actions-runner-linux-x64-<version>.tar.gz`. When either cannot be parsed, or the API does
not answer, the script stops and asks for `var_runner_version` and `var_runner_sha256`,
which you take from the repository's Settings, Actions, Runners, "New self-hosted runner"
page. The install script checks the tarball with `sha256sum --check --strict` and unpacks
nothing that does not match.

Exit statuses: 2 usage or invalid settings, 3 not a Proxmox VE host, 4 dialog cancelled,
5 template, 6 `pct create`, 7 start or network, 8 install, 9 after the install, 233 update
mode in a container without the runner.

## The install script by hand

`install/tenko-ci-runner-install.sh` also runs in any Ubuntu 24.04 container as root, with
`lib/container.sh` and `lib/common.sh` in `../lib` (a checkout) or next to it. It replaces
the former `.github/runner/setup-lxc.sh`. Its settings come from the environment:
`RUNNER_VERSION` and `RUNNER_SHA256` (default: resolved from the GitHub API as above),
`RUNNER_LABELS` (`tenko-linux`), `RUNNER_NAME` (the host name), `REPO_URL` (this
repository), `RUNNER_USER` (`runner`), `RUNNER_DIR` (`/opt/actions-runner`). The token is
read from standard input:

```bash
printf '%s\n' '<registration token>' | bash deploy/proxmox/install/tenko-ci-runner-install.sh
```

Exit status 10 means installed, but the token was refused (they expire after an hour).

## Update mode

Run the same script inside the runner container (`pct enter <ctid>`, then the one-command
form, or the checkout path if the container has one). It creates nothing: it upgrades the
packages, offers `docker system prune --all --force` (default no), and prints the runner's
version and whether its service is active. The runner updates itself; the script does not
reinstall it. Run it while no job runs: an upgrade of Docker restarts the daemon. Inside a
container without the runner it stops with exit 233.

## A second runner

Either a second container (the script again, with another `var_hostname` and a fresh
token), or a second runner in the same container: the install script again, in it, with
`RUNNER_NAME=<name>-2 RUNNER_DIR=/opt/actions-runner-2` and a fresh token on standard
input. Both carry the label; GitHub spreads the queued jobs over them. Size the container
for two builds first.

## Removal

In the container, as the runner account, deregister with a fresh token, then destroy the
container on the host:

```bash
cd /opt/actions-runner && sudo ./svc.sh stop && sudo ./svc.sh uninstall
sudo -u runner ./config.sh remove    # asks for the token; or: --token <fresh token>
pct stop <ctid> && pct destroy <ctid>
```

Switch the workflows back to the hosted runners first if the container goes for good:
`gh variable delete LINUX_RUNNER --repo linkztream/tenko`.

## Security

The runner account has passwordless sudo because the systemd and macvlan smokes install a
service, create a system user and manage links and containers as root; the container is
therefore dedicated to this runner, holds no other credentials or data, and is rebuilt
rather than cleaned after a compromise of the repository. The registration token never
touches disk, an argument list or a log: the host sends it on the install script's
standard input, and the runner account's shell hands it to `config.sh` in
`ACTIONS_RUNNER_INPUT_TOKEN`, which the runner reads as its `--token` and removes from its
environment. The `GITHUB_TOKEN` of the one-command form goes to `curl` on standard input
(`-H @-`) and stays on the host. The runner software is installed only from a tarball that
matches its SHA-256, and Docker only from Docker's signed apt repository. More in
[../../.github/runner/README.md](../../.github/runner/README.md), "Security notes".

## Testing

```bash
bash deploy/proxmox/test/run.sh     # as root in WSL or on Linux with Docker; --no-container skips (c)
```

(a) `bash -n` and shellcheck over every script; (b) the host flow under `TENKO_DRY_RUN=1
var_unattended=yes` (`test/dry-run-test.sh`): the printed commands, the token and password
in none of them, the by-hand lines without a token, an invalid setting refused, the
one-command bootstrap against a loopback server; (c) the install script in a throwaway
`ubuntu:24.04` container (`test/container-test.sh`, with `TENKO_INSTALL_TEST=1`, since that
container has no systemd and no Docker daemon); (d) the parsers against the fixtures in
`test/fixtures/` (`test/unit-test.sh`). The real end-to-end run is the one on the Proxmox
host.

## Writing another ct script

A `ct/` script is the runner script with other values; `lib/host.sh` does the rest. It:

1. starts with the bootstrap block of `ct/tenko-ci-runner.sh`, unchanged except for
   `TENKO_CT_SCRIPT` (its own name without `.sh`) and `TENKO_INSTALL` (its install
   script's name without `.sh`), then sources `lib/host.sh`;
2. sets `APP` (the title; its slug is the default host name) and its `var_*` defaults as
   `var_x="${var_x:-value}"`, so that the environment still overrides them;
3. adds its own settings, if any, to `TENKO_APP_SETTINGS` with a label in
   `TENKO_LABEL[var_x]`; they appear in the dialog after the generic ones;
4. defines the hooks it needs, all optional: `prepare` (after the defaults, before the
   dialog: look things up so the dialog can show them), `validate_settings` (prints one
   line per invalid own setting), `before_create` (after the dialog: ask for secrets),
   `install_env` (prints the `KEY=value` settings for the install script), `install_stdin`
   (prints the secrets, which reach the install script on standard input),
   `after_install` (sees `TENKO_INSTALL_RC`), `final_lines` (what the owner does next),
   and `update_script` (update mode inside the container); `TENKO_INSTALL_OK_CODES` lists
   the install exit statuses that are not a failure (default `0`);
5. ends with `tenko_main "$@"`.

Its install script sources `container.sh` as the runner's does, calls
`tenko_container_init`, reads secrets with `tenko_read_secret`, fetches release assets with
`tenko_verified_download`, adds apt repositories with `tenko_deb822_repo`, and reports with
`msg_info`/`msg_ok`/`msg_warn`, quieting command output with `$STD`. A Tenko installer
(`ct/tenko.sh` with `install/tenko-install.sh`) is that copy with other defaults (fewer
cores, a smaller disk, no nesting needed) and an install that places the static binary and
the unit of `deploy/systemd/`.
