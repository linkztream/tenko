#!/usr/bin/env bash
# Sets up a dedicated Ubuntu 24.04 container as a self-hosted GitHub Actions runner for this
# repository: the build packages the jobs need, Docker with the compose and buildx plugins,
# the runner account with passwordless sudo, the runner software (verified against the
# SHA-256 you took from GitHub) and the runner service, registered with the repository.
# README.md next to this file is the runbook; run the script as root inside the container.
#
# Required environment:
#   RUNNER_VERSION  the runner version from the "New self-hosted runner" page, e.g. 2.330.0
#   RUNNER_SHA256   the SHA-256 of actions-runner-linux-x64-<version>.tar.gz from that page
#   RUNNER_TOKEN    a registration token (gh api -X POST repos/<owner>/<repo>/actions/runners/registration-token)
# Optional:
#   RUNNER_NAME     default: the host name
#   RUNNER_LABELS   default: tenko-linux (the value of the repository variable LINUX_RUNNER)
#   RUNNER_USER     default: runner
#   RUNNER_DIR      default: /opt/actions-runner
#   REPO_URL        default: https://github.com/linkztream/tenko
#
# Safe to run again: packages and the account are left as they are, the runner is
# re-registered with --replace.

set -euo pipefail

: "${RUNNER_VERSION:?set RUNNER_VERSION (see README.md, Setup step 2)}"
: "${RUNNER_SHA256:?set RUNNER_SHA256 (see README.md, Setup step 2)}"
: "${RUNNER_TOKEN:?set RUNNER_TOKEN (see README.md, Setup step 1)}"
RUNNER_NAME="${RUNNER_NAME:-$(hostname)}"
RUNNER_LABELS="${RUNNER_LABELS:-tenko-linux}"
RUNNER_USER="${RUNNER_USER:-runner}"
RUNNER_DIR="${RUNNER_DIR:-/opt/actions-runner}"
REPO_URL="${REPO_URL:-https://github.com/linkztream/tenko}"

log() { printf '==> %s\n' "$*"; }
die() { printf 'setup-lxc: %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" == 0 ]] || die "run as root"
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]] \
    || log "written for Ubuntu 24.04; this is ${PRETTY_NAME:-unknown}, continuing"
fi
export DEBIAN_FRONTEND=noninteractive

log "packages the jobs need"
apt-get update -q
apt-get install -y -q --no-install-recommends \
  build-essential pkg-config cmake musl-tools \
  git curl ca-certificates gnupg jq file unzip xz-utils \
  iproute2 openssl python3 sudo

log "Docker from Docker's apt repository (compose and buildx plugins included)"
if ! command -v docker > /dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  codename="$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")"
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $codename stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -q
  apt-get install -y -q --no-install-recommends \
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker
docker info > /dev/null || die "Docker does not run; an unprivileged container needs features: nesting=1,keyctl=1"

log "runner account $RUNNER_USER"
if ! id -u "$RUNNER_USER" > /dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "$RUNNER_USER"
fi
usermod -aG docker "$RUNNER_USER"
# The systemd and macvlan smokes install a service and manage links and containers as root.
echo "$RUNNER_USER ALL=(ALL) NOPASSWD: ALL" > "/etc/sudoers.d/90-$RUNNER_USER"
chmod 0440 "/etc/sudoers.d/90-$RUNNER_USER"

log "runner software $RUNNER_VERSION in $RUNNER_DIR"
install -d -o "$RUNNER_USER" -g "$RUNNER_USER" "$RUNNER_DIR"
tarball="actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$tarball" \
  "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${tarball}"
echo "${RUNNER_SHA256}  $tmp/$tarball" | sha256sum --check --strict \
  || die "the runner tarball does not match RUNNER_SHA256; nothing was installed"
if [[ -x "$RUNNER_DIR/svc.sh" ]]; then
  (cd "$RUNNER_DIR" && ./svc.sh stop > /dev/null 2>&1 || true)
fi
tar -xzf "$tmp/$tarball" -C "$RUNNER_DIR"
chown -R "$RUNNER_USER:$RUNNER_USER" "$RUNNER_DIR"
# .NET runtime libraries the runner needs (libicu and friends).
(cd "$RUNNER_DIR" && ./bin/installdependencies.sh > /dev/null)

log "registration as $RUNNER_NAME with the labels $RUNNER_LABELS"
sudo -u "$RUNNER_USER" -H bash -c "cd '$RUNNER_DIR' && ./config.sh --unattended --replace \
  --url '$REPO_URL' --token '$RUNNER_TOKEN' --name '$RUNNER_NAME' --labels '$RUNNER_LABELS' \
  --work _work"

log "service"
(cd "$RUNNER_DIR" && ./svc.sh install "$RUNNER_USER" > /dev/null && ./svc.sh start > /dev/null)

log "checks"
if ip link add tenkosetup0 type dummy 2> /dev/null; then
  ip link delete tenkosetup0
  echo "dummy links: ok (the macvlan smoke can run)"
else
  echo "dummy links: NOT available; load the dummy module on the Proxmox host (modprobe dummy) and keep it in /etc/modules-load.d/" >&2
fi
systemd_version="$(systemctl --version | head -1 | awk '{print $2}')"
[[ "${systemd_version:-0}" -ge 250 ]] && echo "systemd $systemd_version: ok" \
  || echo "systemd $systemd_version: the systemd smoke needs 250 or later" >&2
command -v systemd-creds > /dev/null && echo "systemd-creds: ok" || echo "systemd-creds: missing" >&2
df -h / | tail -1 | awk '{print "disk: " $4 " free on /"}'
systemctl is-active 'actions.runner.*' | head -1 | sed 's/^/runner service: /'
echo
echo "Next, from your workstation (README.md, Setup step 4):"
echo "  gh variable set LINUX_RUNNER --repo <owner>/<repo> --body $RUNNER_LABELS"
echo "  gh workflow enable CI --repo <owner>/<repo> && gh workflow enable Release --repo <owner>/<repo>"
