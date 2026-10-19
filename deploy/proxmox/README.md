# Proxmox VE container scripts

Scripts that create an LXC container on a Proxmox VE host and set it up for one purpose, in
one command. There are two: `ct/tenko.sh`, a Tenko DDI node (section "The Tenko container"
below), and `ct/tenko-ci-runner.sh`, the self-hosted GitHub Actions runner for the Linux
jobs of this repository ([../../.github/runner/README.md](../../.github/runner/README.md) is
its runbook), which is a build machine, not a Tenko installation.

Everything that runs on the hypervisor is in this directory and in `../install.sh`, which
the Tenko script pushes into its container. The only tools used on the host are the ones
Proxmox VE ships (`pct`, `pveam`, `pvesm`, `pvesh`, `whiptail`, `curl`).

| Path | What it is |
|---|---|
| `ct/tenko.sh` | The Tenko container's host-side script: its defaults, hooks, final lines and `--update` |
| `install/tenko-install.sh` | The Tenko container side: runs `../install.sh` unattended with the answers |
| `ct/tenko-ci-runner.sh` | The runner's host-side script: its defaults, hooks and final lines |
| `install/tenko-ci-runner-install.sh` | The runner's container-side install; also runs by hand |
| `lib/host.sh` | The generic host flow: settings and dialogs, template, `pct create`, wait, push and run, update mode, dry run |
| `lib/container.sh` | The generic container-side helpers of the install scripts |
| `lib/common.sh` | Messages, the quiet/verbose switch, the runner release lookup |
| `test/` | The checks; `bash deploy/proxmox/test/run.sh` runs them all |

## The Tenko container

`ct/tenko.sh` creates a container and installs a Tenko node in it with
[`../install.sh`](../README.md#install-in-one-command), unattended, from the answers given
on the host.

**What it creates.** An unprivileged Ubuntu 24.04 container (the newest
`ubuntu-24.04-standard` template, downloaded when missing) with 2 cores, 2 GiB memory,
512 MiB swap, an 8 GB root disk, one bridged NIC (`eth0` on `vmbr0`, DHCP, or `--ip` and
`--gw`), start on boot, the tag `tenko`, and `features: nesting=1`: the systemd 255 of
Ubuntu 24.04 and the unit's sandbox (`PrivateTmp=`, `ProtectSystem=`, its own mount
namespace) need nesting in an unprivileged container; `keyctl` is not needed. The node
idles at about 85 MiB; give the container more memory and cores for zones of a few hundred
thousand records, DNSSEC signing of large zones and big imports, and put the root disk on
SSD or NVMe storage (OPS-19). In it, `install/tenko-install.sh` runs `install.sh --yes` with
the answers: the binary, the account, `/etc/tenko`, the key-encryption key, the unit, the
start and, with an administrator, first-run setup. Inside an unprivileged container the
installer turns systemd-resolved's stub listener off when the dns role answers on every
address, and chooses the plain key file when the key cannot be sealed or does not reach the
service there (deploy/README.md, "The key-encryption key on each kind of host").

**Port 53.** The unit's `AmbientCapabilities=CAP_NET_BIND_SERVICE` works in an unprivileged
container: the capability counts in the container's user namespace, which owns its network
namespace, so the dns role binds port 53 on the container's addresses without a change of
`net.ipv4.ip_unprivileged_port_start`; the dns role has run this way in an unprivileged
Proxmox container. When the unit fails with status 226/NAMESPACE or 218/CAPABILITIES in a
container without nesting, ../README.md, "LXC", has the drop-in that relaxes only the
failing options.

**Running it**, as root on the Proxmox host. While the repository is private, copy the
binary to the host (a release asset or your musl build) and give it with `--binary`; it is
pushed into the container with `pct push`:

```bash
# From a checkout of the repository on the host:
bash deploy/proxmox/ct/tenko.sh --binary /root/tenko-0.2.0-linux-x86_64

# The same, unattended, with a static address and first-run setup (Home: a PIN):
read -rs TENKO_ADMIN_PASSWORD && export TENKO_ADMIN_PASSWORD     # type the PIN
bash deploy/proxmox/ct/tenko.sh --yes --binary /root/tenko-0.2.0-linux-x86_64 \
  --ip 192.0.2.60/24 --gw 192.0.2.1 --admin admin --storage local-lvm

# In one command, without a checkout: GITHUB_TOKEN is a fine-grained token that can read
# the contents; it fetches the scripts and, without --binary, the release in the container.
bash -c "$(curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" https://raw.githubusercontent.com/linkztream/tenko/main/deploy/proxmox/ct/tenko.sh)"

# Once the repository is public, from the release asset (pinned to the scripts of its tag):
bash -c "$(curl -fsSL https://github.com/linkztream/tenko/releases/latest/download/tenko-proxmox.sh)"
```

The dialog shows the container settings and the Tenko answers together; "Create" takes
them, "Advanced" asks each one. With an administrator named, a password box asks for the
password (or the PIN under Home); empty leaves setup to the browser. The last lines on the
host are the container ID, its address, the URL and the setup token (or the
administrator), and the commands to update and to snapshot. Snapshot the container before
every upgrade: `pct snapshot <ctid> <name>`.

| Option or variable | Default | Meaning |
|---|---|---|
| `--binary <file>` / `var_binary` | empty: download in the container | A binary on the host, pushed into the container |
| `--ip`, `--gw` / `var_ip`, `var_gateway` | `dhcp` | The container's address |
| `--ctid`, `--storage`, `--hostname` | the generic defaults below | The container's ID, root disk storage and host name (`tenko`) |
| `--admin <name>` / `var_admin` | empty | First-run setup with this administrator; the password from `TENKO_ADMIN_PASSWORD` or a password box |
| `--version` / `var_tenko_version` | `latest` | The release to download |
| `--yes` / `var_unattended=yes` | | No dialogs |
| `--dry-run` / `TENKO_DRY_RUN=1` | | Print the Proxmox commands instead of running them |
| `--update <ctid>` | | The installer again in that container (below) |
| `var_roles` | `controller,dns` | `install.sh --roles` |
| `var_modules` | `wizard` | `--modules` |
| `var_profile` | `home` | `--profile` |
| `var_tenko_host` | the container's host name | `--host-name` |
| `var_dns_address` | `all` | `--dns-address` |
| `var_forwarders` | empty: the container's resolvers | `--forwarders` |
| `var_language` | `en` | `--language` |
| `var_kek` | `auto` | `--kek` |
| `GITHUB_TOKEN` | empty | Fetches the scripts in the one-command form; without `--binary` it goes to the container on the install script's standard input for the download, and nowhere else |

The generic settings of `lib/host.sh` (section "Settings") apply too, with the Tenko
defaults `var_cpu=2`, `var_ram=2048`, `var_disk=8`, `var_tags=tenko`, `var_nesting=1`,
`var_keyctl=0`. Without `--binary`, without a token and with a private repository the
settings are refused before anything is created. The exit statuses are those of the
runner script; 9 from the container means the node runs but setup failed.

**Upgrade.** From the host, the installer again in the container, with a newer binary
pushed or a newer release downloaded; it keeps the container's configuration, key and data
and upgrades through the updates layout:

```bash
pct snapshot 120 before-0.3.0
bash deploy/proxmox/ct/tenko.sh --update 120 --binary /root/tenko-0.3.0-linux-x86_64
```

Inside the container, the same script (the one-command form, or a checkout there) runs
`install.sh` again instead of creating anything. Updates installed from the web UI work in
the container as on any systemd host.

**A virtual machine** needs no script here: create the VM, install Debian 12, Ubuntu 24.04
or a RHEL 9 compatible in it, and run `install.sh` (../README.md, "Install in one command").

## What the runner script creates

- An unprivileged Ubuntu 24.04 container (the newest `ubuntu-24.04-standard` template
  that `pveam available` lists, downloaded to the template storage when missing) with
  `features: nesting=1,keyctl=1` (Docker needs both), 4 cores with a CPU limit of half of
  them (`cpulimit`: the sustained load of a build stays at half the host's CPU time while
  short bursts may use every core; raise it for speed, lower it for a quieter host), 8 GiB
  memory (give about 2 GiB per core; with less, the build runs fewer jobs than cores,
  below), 512 MiB swap,
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
  (labels `tenko-linux`) and the service `actions.runner.<owner>-<repo>.<name>`. In
  `/opt/actions-runner/.env`, which the runner puts into the environment of every job,
  `CARGO_BUILD_JOBS`: the container's memory in GiB divided by two, at most the core count.
  The workspace test build links one binary per parallel job at about 2 GiB each; without
  the cap cargo starts one per core, and a container with many cores and little memory has
  the kernel kill the linkers and the runner with them.
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
| `var_cpulimit` | half of `var_cpu` (generic `0`: none) | Cores of CPU time the container may use on a sustained basis (`pct ... -cpulimit`), a number such as `2` or `1.5`, at most `var_cpu` |
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
| `CARGO_BUILD_JOBS` | empty: from the memory | Cap on cargo's parallel jobs in the runner's jobs (`/opt/actions-runner/.env`); empty: the memory in GiB divided by two, at most the core count |
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
repository), `RUNNER_USER` (`runner`), `RUNNER_DIR` (`/opt/actions-runner`),
`CARGO_BUILD_JOBS` (empty: from the container's memory, as above). The token is read from
standard input:

```bash
printf '%s\n' '<registration token>' | bash deploy/proxmox/install/tenko-ci-runner-install.sh
```

Exit status 10 means installed, but the token was refused (they expire after an hour).

## Update mode

Run the same script inside the runner container (`pct enter <ctid>`, then the one-command
form, or the checkout path if the container has one). It creates nothing: it upgrades the
packages, offers `docker system prune --all --force` (default no), and prints the runner's
version, whether its service is active, and the `CARGO_BUILD_JOBS` cap of `.env` next to
the memory the container has now. The runner updates itself; the script does not reinstall
it. Run it while no job runs: an upgrade of Docker restarts the daemon. Inside a container
without the runner it stops with exit 233.

## A CPU limit on an existing container

A runner that builds for an hour at full load on every core stresses the host more than any
other guest. For a container that exists already, set the limit on the host without a
restart; the number is cores of CPU time on a sustained basis, short bursts may still use
every core:

```bash
pct set <ctid> --cpulimit 14
```

## After a resize

The cap on the build's parallel jobs is derived at install time. When the container gets
more memory or cores, run the install script again in it, as root and without a token: it
keeps the registration, rewrites `CARGO_BUILD_JOBS` in `/opt/actions-runner/.env` and
starts the service again. Or set the line by hand and restart the service.

```bash
bash deploy/proxmox/install/tenko-ci-runner-install.sh </dev/null
```

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
bash deploy/proxmox/test/run.sh     # as root in WSL or on Linux with Docker; --no-container skips (c), (e) to (g)
TENKO_TEST_BINARY=<musl tenko> TENKO_TEST_NEWER=<the same, a higher version> \
  TENKO_TEST_IMAGE_VERSION=<x.y.z> bash deploy/proxmox/test/run.sh
```

(a) `bash -n` and shellcheck over every script and `../install.sh`; (b) the host flows of
both ct scripts under `TENKO_DRY_RUN=1 var_unattended=yes` (`test/dry-run-test.sh`): the
printed commands, the tokens and passwords in none of them, the by-hand lines without a
token, invalid settings refused, the one-command bootstrap against a loopback server, and
for `ct/tenko.sh` the container options, the pushed installer and binary, the answers
passed to the install script, the download with a token and `--update`; (c) the runner's
install script in a throwaway `ubuntu:24.04` container (`test/container-test.sh`, with
`TENKO_INSTALL_TEST=1`, since that container has no systemd and no Docker daemon); (d) the
parsers against the fixtures in `test/fixtures/` and the settings of `ct/tenko.sh`
(`test/unit-test.sh`); (e)
`test/install-sh-test.sh`: the parsers of `install.sh` always and, with a binary,
`install.sh --no-start` in `ubuntu:24.04`, `debian:12-slim` and
`rockylinux/rockylinux:9-minimal` with `tenko serve` started by hand until `tenko health`
answers, the rerun, `--reconfigure`, `--uninstall` and `--purge`, the downloads against a
loopback server (a wrong checksum refused, the token in no argument list), and with a newer
binary the whole life in a systemd container: setup, the stub listener of systemd-resolved
turned off and on again, the upgrade through the layout, the
plain-key fallback and an installation made by hand; (f) `install/tenko-install.sh` in a
throwaway container (`test/tenko-container-test.sh`); (g) the compose quick start
(`test/quickstart-test.sh`) on a local image tagged as the published name. The CI job
`deploy-scripts` runs `run.sh --no-container` on every push. The real end-to-end runs are
the ones on the Proxmox host and on a VM.

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
   the install exit statuses that are not a failure (default `0`), and
   `TENKO_PUSH_FILES` the extra files to push before the install script runs and to remove
   after it, as `<host path>|<container path>` (`ct/tenko.sh` pushes `../install.sh` and a
   binary given on the host);
5. ends with `tenko_main "$@"`.

Its install script sources `container.sh` as the runner's does, calls
`tenko_container_init`, reads secrets with `tenko_read_secret`, fetches release assets with
`tenko_verified_download`, adds apt repositories with `tenko_deb822_repo`, and reports with
`msg_info`/`msg_ok`/`msg_warn`, quieting command output with `$STD`. `ct/tenko.sh` with
`install/tenko-install.sh` is such a copy: other defaults (fewer cores, a smaller disk), an
extended bootstrap that also fetches `../install.sh`, `--update <ctid>` on the host, and an
install script that only maps the answers to the flags of `install.sh`. Its variables are
named `TENKO_INSTALL_*`: `tenko` reads `TENKO_ROLES`, `TENKO_KEK` and other names of its
configuration keys from the environment, so an install script must not export them.
