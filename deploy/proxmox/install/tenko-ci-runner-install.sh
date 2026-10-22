#!/usr/bin/env bash
# Tenko CI Runner, container side: sets up a dedicated Ubuntu 24.04 container as a
# self-hosted GitHub Actions runner for this repository. The build packages the Linux jobs
# need, Docker with the compose and buildx plugins, the runner account with passwordless
# sudo, the runner software (verified against its SHA-256 before it is unpacked), the
# registration and the runner service, and the checks the smokes depend on.
# ../ct/tenko-ci-runner.sh runs it in the container it creates; it also runs by hand, as
# root, in any Ubuntu 24.04 container, with lib/container.sh and lib/common.sh next to it
# or in ../lib. Safe to run again: packages and the account stay, the runner is registered
# again with --replace.
#
# Usage (by hand, in the container, as root):
#   printf '%s\n' "<registration token>" | RUNNER_LABELS=tenko-linux bash tenko-ci-runner-install.sh
# Settings, from the environment (ct/tenko-ci-runner.sh passes them as arguments to env):
#   RUNNER_VERSION  runner version, e.g. 2.330.0      default: the latest release
#   RUNNER_SHA256   SHA-256 of actions-runner-linux-x64-<version>.tar.gz
#                   default: from the release notes on GitHub (lib/common.sh)
#   RUNNER_LABELS   default: tenko-linux (the value of the repository variable LINUX_RUNNER)
#   RUNNER_NAME     default: the host name
#   REPO_URL        default: https://github.com/linkztream/tenko
#   RUNNER_USER     default: runner
#   RUNNER_DIR      default: /opt/actions-runner
#   RUNNER_TOKEN    the registration token; read from standard input when not set and
#                   standard input is not a terminal; empty: no registration
#   CARGO_BUILD_JOBS  cap on cargo's parallel jobs in the runner's jobs, written to
#                   <RUNNER_DIR>/.env; default: the container's memory in GiB divided by
#                   two, at most the core count (the test build links one binary per job,
#                   each about 2 GiB)
#   TENKO_INSTALL_TEST=1  under the container test: no systemctl, no Docker daemon
# Exit status: 0 done; 10 installed, but the registration was refused; anything else failed.
#
# License: Business Source License 1.1; see LICENSE.md at the repository root.

TENKO_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for TENKO_LIB in "${TENKO_HERE}/container.sh" "${TENKO_HERE}/../lib/container.sh"; do
  # shellcheck source=../lib/container.sh
  [[ -f "$TENKO_LIB" ]] && source "$TENKO_LIB" && break
done
if ! declare -F tenko_container_init >/dev/null; then
  echo "tenko-ci-runner-install: container.sh not found next to this script or in ../lib" >&2
  exit 2
fi
tenko_container_init

RUNNER_LABELS="${RUNNER_LABELS:-tenko-linux}"
RUNNER_NAME="${RUNNER_NAME:-$(hostname)}"
REPO_URL="${REPO_URL:-https://github.com/linkztream/tenko}"
RUNNER_USER="${RUNNER_USER:-runner}"
RUNNER_DIR="${RUNNER_DIR:-/opt/actions-runner}"
RUNNER_TOKEN="${RUNNER_TOKEN:-}"
tenko_read_secret RUNNER_TOKEN
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-}"
if [[ -n "$CARGO_BUILD_JOBS" && ! "$CARGO_BUILD_JOBS" =~ ^[1-9][0-9]*$ ]]; then
  msg_error "CARGO_BUILD_JOBS: a number of jobs from 1, not '${CARGO_BUILD_JOBS}'"
  exit 2
fi

if [[ "$(dpkg --print-architecture)" != "amd64" ]]; then
  msg_error "The runner container is built for amd64; this is $(dpkg --print-architecture)"
  exit 2
fi
if [[ -r /etc/os-release ]]; then
  # shellcheck source=/dev/null
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" ]]; then
    msg_warn "Written for Ubuntu 24.04; this is ${PRETTY_NAME:-unknown}, continuing"
  fi
fi

msg_info "Installing the build packages"
tenko_apt_install \
  build-essential pkg-config cmake musl-tools \
  git curl ca-certificates gnupg jq file unzip xz-utils \
  iproute2 openssl python3 sudo
msg_ok "Installed the build packages"

msg_info "Installing Docker with the compose and buildx plugins from Docker's apt repository"
tenko_deb822_repo docker \
  https://download.docker.com/linux/ubuntu/gpg https://download.docker.com/linux/ubuntu \
  "${UBUNTU_CODENAME:-${VERSION_CODENAME:-noble}}" stable
tenko_apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
if tenko_under_test; then
  msg_warn "Under the test: Docker's service is not started and not checked"
else
  systemctl enable --now docker >/dev/null 2>&1
  if ! docker info >/dev/null 2>&1; then
    msg_error "Docker does not run: an unprivileged container needs nesting and keyctl (features: nesting=1,keyctl=1)"
    exit 1
  fi
fi
msg_ok "Installed Docker ($(docker --version))"

msg_info "Setting up the runner account ${RUNNER_USER}"
if ! id -u "$RUNNER_USER" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "$RUNNER_USER"
fi
usermod -aG docker "$RUNNER_USER"
# Passwordless sudo: the systemd and macvlan smokes install a service, create a system user
# and manage links and containers as root, and `npx playwright install --with-deps` installs
# system packages. That is why the container is dedicated to this runner and holds nothing
# else.
printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$RUNNER_USER" >"/etc/sudoers.d/90-${RUNNER_USER}"
chmod 0440 "/etc/sudoers.d/90-${RUNNER_USER}"
visudo -cqf "/etc/sudoers.d/90-${RUNNER_USER}"
msg_ok "Set up the runner account ${RUNNER_USER} (docker group, passwordless sudo)"

msg_info "Resolving the runner release"
tenko_resolve_runner_release
msg_ok "Runner ${RUNNER_VERSION}, SHA-256 ${RUNNER_SHA256:0:12}... (${TENKO_RUNNER_SOURCE})"

msg_info "Installing the runner ${RUNNER_VERSION} into ${RUNNER_DIR}"
RUNNER_TARBALL="actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
RUNNER_TMP="$(mktemp -d)"
if ! tenko_verified_download \
  "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${RUNNER_TARBALL}" \
  "$RUNNER_SHA256" "${RUNNER_TMP}/${RUNNER_TARBALL}"; then
  rm -rf "$RUNNER_TMP"
  exit 1
fi
install -d -o "$RUNNER_USER" -g "$RUNNER_USER" "$RUNNER_DIR"
if [[ -f "${RUNNER_DIR}/.service" ]] && ! tenko_under_test; then
  (cd "$RUNNER_DIR" && ./svc.sh stop >/dev/null 2>&1) || true
fi
tar -xzf "${RUNNER_TMP}/${RUNNER_TARBALL}" -C "$RUNNER_DIR"
chown -R "${RUNNER_USER}:${RUNNER_USER}" "$RUNNER_DIR"
rm -rf "$RUNNER_TMP"
msg_ok "Installed the runner ${RUNNER_VERSION} into ${RUNNER_DIR} (SHA-256 verified)"

msg_info "Installing the runner's .NET dependencies"
# libicu and friends; the script ships with the runner and runs apt-get itself.
$STD "${RUNNER_DIR}/bin/installdependencies.sh"
msg_ok "Installed the runner's .NET dependencies"

# The runner puts every line of its .env into the environment of each job. The workspace
# test build links one binary per parallel job, each about 2 GiB; without a cap cargo
# starts one per core, and a container with many cores and little memory has the kernel
# kill the linkers and the runner with them.
msg_info "Capping cargo's parallel jobs by the container's memory"
MEM_KIB="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || true)"
CORES="$(nproc 2>/dev/null || echo 1)"
if [[ -z "$CARGO_BUILD_JOBS" ]]; then
  CARGO_BUILD_JOBS="$(tenko_jobs_for_memory 2048 "$MEM_KIB" "$CORES")"
  JOBS_SOURCE="from the memory"
else
  JOBS_SOURCE="given"
fi
tenko_env_file_set "${RUNNER_DIR}/.env" CARGO_BUILD_JOBS "$CARGO_BUILD_JOBS"
chown "${RUNNER_USER}:${RUNNER_USER}" "${RUNNER_DIR}/.env"
chmod 0644 "${RUNNER_DIR}/.env"
msg_ok "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS} in ${RUNNER_DIR}/.env (${JOBS_SOURCE}; $((${MEM_KIB:-0} / 1048576)) GiB memory, ${CORES} cores, about 2 GiB per job)"

if [[ -n "$RUNNER_TOKEN" ]]; then
  msg_info "Registering the runner as ${RUNNER_NAME} with the labels ${RUNNER_LABELS}"
  # The token goes to config.sh through ACTIONS_RUNNER_INPUT_TOKEN, which the runner reads
  # as its --token and removes from its environment; it reaches the account's shell on a
  # pipe, so it is in no argument list and no file.
  # A refused token (they expire after an hour) leaves a usable container: the script warns,
  # finishes its checks and exits with 10, which ct/tenko-ci-runner.sh reports as "installed,
  # not registered" instead of a failed install.
  # shellcheck disable=SC2016 # Expanded by the runner account's shell, not here.
  if printf '%s\n' "$RUNNER_TOKEN" | $STD sudo -u "$RUNNER_USER" -H bash -c '
    IFS= read -r ACTIONS_RUNNER_INPUT_TOKEN && export ACTIONS_RUNNER_INPUT_TOKEN
    cd "$1" && exec ./config.sh --unattended --replace --url "$2" --name "$3" --labels "$4" --work _work' \
    bash "$RUNNER_DIR" "$REPO_URL" "$RUNNER_NAME" "$RUNNER_LABELS"; then
    msg_ok "Registered the runner as ${RUNNER_NAME}"
    msg_info "Starting the runner service"
    if [[ ! -f "${RUNNER_DIR}/.service" ]]; then
      (cd "$RUNNER_DIR" && $STD ./svc.sh install "$RUNNER_USER")
    fi
    (cd "$RUNNER_DIR" && $STD ./svc.sh start)
    msg_ok "Started the runner service $(<"${RUNNER_DIR}/.service")"
  else
    msg_warn "The registration failed (an expired token?); the runner is installed but not registered"
    TENKO_EXIT=10
  fi
  RUNNER_TOKEN=""
elif [[ -f "${RUNNER_DIR}/.service" ]] && ! tenko_under_test; then
  # A run without a token on a registered runner: the service was stopped above for the
  # extraction and starts again here, with the fresh .env.
  msg_info "Starting the runner service again"
  (cd "$RUNNER_DIR" && $STD ./svc.sh start)
  msg_ok "Started the runner service $(<"${RUNNER_DIR}/.service") (registration kept)"
else
  msg_warn "No registration token: the runner is installed but not registered (deploy/proxmox/README.md)"
fi

# Checks: what the Linux jobs need from the container and from the Proxmox host. A failed
# check warns; the jobs that do not need it still run.
if ip link add tenkosetup0 type dummy 2>/dev/null; then
  ip link delete tenkosetup0
  msg_ok "dummy links: available (the macvlan smoke can run)"
else
  msg_warn "dummy links: not available; on the Proxmox host: modprobe dummy, and keep it in /etc/modules-load.d/"
fi
SYSTEMD_VERSION="$(systemctl --version 2>/dev/null | awk 'NR == 1 {print $2}' || true)"
if [[ "$SYSTEMD_VERSION" =~ ^[0-9]+$ ]] && ((SYSTEMD_VERSION >= 250)); then
  msg_ok "systemd ${SYSTEMD_VERSION}: ok for the systemd smoke"
else
  msg_warn "systemd ${SYSTEMD_VERSION:-not running}: the systemd smoke needs 250 or later"
fi
if command -v systemd-creds >/dev/null 2>&1; then
  msg_ok "systemd-creds: available"
else
  msg_warn "systemd-creds: missing (the systemd smoke needs it)"
fi
DISK_FREE_GB="$(df -P -BG / | awk 'NR == 2 {sub("G", "", $4); print $4}' || true)"
if [[ "$DISK_FREE_GB" =~ ^[0-9]+$ ]] && ((DISK_FREE_GB >= 60)); then
  msg_ok "disk: ${DISK_FREE_GB} GB free on /"
else
  msg_warn "disk: ${DISK_FREE_GB:-unknown} GB free on /; the workspace test build needs tens of gigabytes"
fi
if [[ -f "${RUNNER_DIR}/.service" ]] && ! tenko_under_test; then
  RUNNER_STATE="$(systemctl is-active "$(<"${RUNNER_DIR}/.service")" 2>/dev/null || true)"
  if [[ "$RUNNER_STATE" == "active" ]]; then
    msg_ok "runner service: active"
  else
    msg_warn "runner service: ${RUNNER_STATE:-unknown}; journalctl -u $(<"${RUNNER_DIR}/.service")"
  fi
else
  msg_warn "runner service: not installed (no registration yet)"
fi
exit "${TENKO_EXIT:-0}"
