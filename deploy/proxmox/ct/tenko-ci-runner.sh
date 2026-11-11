#!/usr/bin/env bash
# Tenko CI Runner: creates a dedicated, unprivileged Ubuntu 24.04 container on a Proxmox VE
# host, sets it up as the self-hosted GitHub Actions runner of this repository and
# registers it (install/tenko-ci-runner-install.sh, run inside it). Run inside an existing
# runner container, it updates that container instead. Everything it runs is in
# deploy/proxmox; deploy/proxmox/README.md has the details.
#
# Usage, as root on the Proxmox VE host, from a checkout of the repository at a commit you
# have reviewed (the runner it registers runs jobs as an account with passwordless sudo):
#   bash deploy/proxmox/ct/tenko-ci-runner.sh
# There is no one-command form: nothing pins a script fetched from a branch, and this one is
# not a release file.
# Settings: the var_* of lib/host.sh and below, RUNNER_TOKEN, GITHUB_TOKEN, TENKO_DRY_RUN=1
# (print the Proxmox commands instead of running them).
#
# License: Business Source License 1.1; see LICENSE.md at the repository root.

# Secrets stay variables of this shell: exported, they would reach every child process.
export -n RUNNER_TOKEN GITHUB_TOKEN 2>/dev/null || true

# >>> bootstrap: the scripts root, from a checkout only.
TENKO_CT_SCRIPT="tenko-ci-runner"
TENKO_INSTALL="tenko-ci-runner-install"
TENKO_BOOTSTRAP_TMP=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" && -r "${BASH_SOURCE[0]}" ]]; then
  # A checkout: ct/ and lib/ sit side by side in deploy/proxmox.
  TENKO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
else
  # Started as bash -c "$(curl ...)": the libraries it would source as root are not pinned
  # by any release, so it stops before fetching anything.
  printf '\nct/%s.sh runs from a checkout only (deploy/proxmox/README.md):\n' "$TENKO_CT_SCRIPT" >&2
  printf '  git clone https://github.com/linkztream/tenko && cd tenko && git checkout <a reviewed commit or tag>\n' >&2
  printf '  bash deploy/proxmox/ct/%s.sh\n' "$TENKO_CT_SCRIPT" >&2
  exit 2
fi
# <<< bootstrap

# shellcheck source=../lib/host.sh
source "${TENKO_ROOT}/lib/host.sh"

# ── The runner's defaults (each one overridable from the environment) ─────────────────────
APP="Tenko CI Runner"
var_cpu="${var_cpu:-4}"
# Half the cores of CPU time, so that a build that is busy for an hour never takes the whole
# host (the cores stay available for short bursts; the cap is on the sustained load).
var_cpulimit="${var_cpulimit:-$((var_cpu / 2 > 0 ? var_cpu / 2 : 1))}"
var_ram="${var_ram:-8192}"
var_disk="${var_disk:-120}"
var_hostname="${var_hostname:-tenko-ci-runner}"
var_tags="${var_tags:-ci;runner}"
var_unprivileged="${var_unprivileged:-1}"
var_nesting="${var_nesting:-1}"
var_keyctl="${var_keyctl:-1}"
var_runner_labels="${var_runner_labels:-tenko-linux}"
var_repo_url="${var_repo_url:-https://github.com/linkztream/tenko}"
var_runner_version="${var_runner_version:-}"
var_runner_sha256="${var_runner_sha256:-}"
RUNNER_TOKEN="${RUNNER_TOKEN:-}"
RUNNER_DIR="/opt/actions-runner"
TENKO_PROJECT_URL="$var_repo_url"
# shellcheck disable=SC2034 # Read by push_and_run in lib/host.sh: 10 is "installed, not registered".
TENKO_INSTALL_OK_CODES=(0 10)
TENKO_APP_SETTINGS=(var_runner_labels var_repo_url var_runner_version var_runner_sha256)
TENKO_LABEL[var_runner_labels]="Runner labels (LINUX_RUNNER)"
TENKO_LABEL[var_repo_url]="Repository URL"
TENKO_LABEL[var_runner_version]="Runner version"
TENKO_LABEL[var_runner_sha256]="Runner SHA-256"

# ── Hooks called by tenko_main (lib/host.sh) ───────────────────────────────────────────────
# prepare: the runner release, once, so that the settings dialog shows it.
prepare() {
  RUNNER_VERSION="$var_runner_version" RUNNER_SHA256="$var_runner_sha256"
  if [[ -z "$RUNNER_SHA256" ]]; then
    msg_info "Looking up the runner release on GitHub"
  fi
  tenko_resolve_runner_release || die "$TENKO_E_USAGE" "No verified runner release; nothing was created"
  var_runner_version="$RUNNER_VERSION" var_runner_sha256="$RUNNER_SHA256"
  TENKO_RESOLVED="${RUNNER_VERSION} ${RUNNER_SHA256}"
  msg_ok "Runner ${RUNNER_VERSION} (SHA-256 from ${TENKO_RUNNER_SOURCE})"
}

validate_settings() {
  [[ "$var_runner_labels" =~ ^[A-Za-z0-9._-]+(,[A-Za-z0-9._-]+)*$ ]] ||
    echo "var_runner_labels: labels separated by commas, not '${var_runner_labels}'"
  [[ "$var_repo_url" =~ ^https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] ||
    echo "var_repo_url: https://github.com/<owner>/<repository>, not '${var_repo_url}'"
  [[ "$var_runner_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    echo "var_runner_version: such as 2.330.0, not '${var_runner_version}'"
  [[ "$var_runner_sha256" =~ ^[0-9a-fA-F]{64}$ ]] ||
    echo "var_runner_sha256: 64 hexadecimal digits"
  return 0
}

# before_create: a version changed in the dialog gets its own checksum; then the
# registration token, from RUNNER_TOKEN or a password box (empty: register later).
before_create() {
  local answer
  if [[ "${var_runner_version} ${var_runner_sha256}" != "${TENKO_RESOLVED:-}" &&
    "${var_runner_sha256}" == "${TENKO_RESOLVED#* }" ]]; then
    var_runner_sha256=""
    prepare
  fi
  TENKO_PROJECT_URL="$var_repo_url"
  if [[ -z "$RUNNER_TOKEN" ]] && ! tenko_unattended; then
    if answer="$(tenko_whiptail --title "${APP}: registration" --passwordbox \
      "Registration token for ${var_repo_url}, valid for one hour. On your workstation:\n\ngh api -X POST repos/${var_repo_url#https://github.com/}/actions/runners/registration-token --jq .token\n\nEmpty: register later by hand." 16 78)"; then
      RUNNER_TOKEN="$answer"
    fi
  fi
}

install_env() {
  printf '%s\n' "RUNNER_VERSION=${var_runner_version}" "RUNNER_SHA256=${var_runner_sha256,,}" \
    "RUNNER_LABELS=${var_runner_labels}" "RUNNER_NAME=${var_hostname}" "REPO_URL=${var_repo_url}"
  # The cap on cargo's parallel jobs; empty: the install script derives it from the memory.
  if [[ -n "${CARGO_BUILD_JOBS:-}" ]]; then
    printf 'CARGO_BUILD_JOBS=%s\n' "$CARGO_BUILD_JOBS"
  fi
}

# install_stdin: the token, the only secret, on the install script's standard input.
install_stdin() { printf '%s\n' "$RUNNER_TOKEN"; }

after_install() {
  RUNNER_REGISTERED="no"
  if [[ "${TENKO_INSTALL_RC:-0}" == "10" ]]; then
    msg_warn "The runner is installed, but GitHub refused the registration token"
  elif [[ -n "$RUNNER_TOKEN" ]]; then
    RUNNER_REGISTERED="yes"
  fi
  RUNNER_TOKEN=""
}

final_lines() {
  local slug="${var_repo_url#https://github.com/}" label="${var_runner_labels%%,*}"
  if [[ "${RUNNER_REGISTERED:-no}" != "yes" ]]; then
    msg_bold "  Register the runner by hand"
    echo "    On your workstation, a token (valid for one hour):"
    echo "      gh api -X POST repos/${slug}/actions/runners/registration-token --jq .token"
    echo "    On this host, pct enter ${var_ctid}, then in the container (config.sh asks for the token):"
    echo "      cd ${RUNNER_DIR} && sudo -u runner ./config.sh --replace --url ${var_repo_url} --name ${var_hostname} --labels ${var_runner_labels} --work _work"
    echo "      cd ${RUNNER_DIR} && ./svc.sh install runner && ./svc.sh start"
    echo
  fi
  msg_bold "  Point the workflows at the runner, from your workstation"
  echo "    The repository variable LINUX_RUNNER carries the label ${label}:"
  echo "      gh variable set LINUX_RUNNER --repo ${slug} --body ${label}"
  echo "      gh workflow enable CI --repo ${slug} && gh workflow enable Release --repo ${slug}"
  echo "      gh workflow run CI --repo ${slug}"
  echo "    The first run installs the Rust toolchain, Node and Chromium into the runner account;"
  echo "    later runs reuse them."
}

# update_script: update mode, when this script runs inside the runner container.
update_script() {
  local version unit state jobs mem_gib
  if [[ ! -f "${RUNNER_DIR}/config.sh" ]]; then
    msg_error "No ${APP} installation found"
    exit 233
  fi
  export DEBIAN_FRONTEND=noninteractive
  msg_info "Updating the container's packages"
  $STD apt-get update
  $STD apt-get -y -o Dpkg::Options::=--force-confold upgrade
  msg_ok "Updated the container's packages"
  if [[ -t 0 ]] && command -v whiptail >/dev/null 2>&1 &&
    tenko_whiptail --title "${APP}: housekeeping" --defaultno --yesno \
      "Remove all Docker images, stopped containers and the build cache?\n\ndocker system prune --all --force" 12 70; then
    msg_info "Pruning Docker"
    $STD docker system prune --all --force
    msg_ok "Pruned Docker"
  fi
  version="$("${RUNNER_DIR}/bin/Runner.Listener" --version 2>/dev/null || true)"
  unit="$(cat "${RUNNER_DIR}/.service" 2>/dev/null || echo 'actions.runner.*')"
  state="$(systemctl is-active "$unit" 2>/dev/null | head -n 1 || true)"
  msg_ok "Runner ${version:-unknown} (it updates itself), service ${unit}: ${state:-unknown}"
  # The cap on cargo's parallel jobs follows the container's memory at install time; after
  # a resize the install script, run again without a token, rewrites it.
  jobs="$(sed -n 's/^CARGO_BUILD_JOBS=//p' "${RUNNER_DIR}/.env" 2>/dev/null | tail -n 1)"
  mem_gib="$(($(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0) / 1048576))"
  if [[ -z "$jobs" ]]; then
    msg_warn "No CARGO_BUILD_JOBS in ${RUNNER_DIR}/.env (${mem_gib} GiB memory, $(nproc) cores): run install/tenko-ci-runner-install.sh again to cap the build"
  else
    msg_ok "CARGO_BUILD_JOBS=${jobs} in ${RUNNER_DIR}/.env (${mem_gib} GiB memory, $(nproc) cores); run install/tenko-ci-runner-install.sh again after a resize"
  fi
}

tenko_main "$@"
