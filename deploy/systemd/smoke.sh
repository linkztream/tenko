#!/usr/bin/env bash
# Systemd smoke of Tenko DDI (OPS-13, exit criterion E10).
#
#   sudo bash deploy/systemd/smoke.sh /path/to/tenko
#
# Run it as root on a TEST host with systemd as PID 1 (a VM, or the hosted Linux runner of CI),
# never on a production host: it replaces /usr/local/bin/tenko, /etc/tenko/tenko.toml and
# /etc/tenko/kek.cred, and it deletes /var/lib/tenko and /var/log/tenko at the start. A host
# that has /var/lib/tenko from something other than this script is refused (set
# SMOKE_FORCE=1 to override that on a throwaway VM).
#
# Argument 1 is a debug build of tenko (only debug builds honour the test variable that lets
# the update install this same binary as the next version). What it does, in order:
#   1. installs the binary, the service account, a smoke tenko.toml, the unit from this
#      repository and a drop-in with TENKO_TEST_VERSION_FROM_LAYOUT=1;
#   2. creates the key-encryption key with `systemd-creds encrypt` (the root path);
#   3. starts the unit and waits until `tenko health` succeeds;
#   4. checks that the key was loaded from the systemd credential, without a plain-file warning;
#   5. checks LogsDirectory= (/var/log/tenko, owned by tenko, tenko.log written);
#   6. stops the unit (clean exit) and starts it again;
#   7. completes first-run setup through the API, installs this binary as the next version
#      from a release source on the loopback interface, and waits for systemd to restart the
#      service after exit status 12, for the new version to run and for its probation to end;
#   8. installs deploy/systemd/probe.conf and runs the roles controller,probe;
#   9. records `systemd-analyze security` (in $GITHUB_STEP_SUMMARY when set) and fails when
#      the exposure is 2.5 or higher.
# Each step prints "==> step". On failure the script prints the journal of the unit and the
# tenko log and exits non-zero. Unless KEEP=1 is set it stops and disables the unit, removes
# the drop-ins it added and stops the release source at the end; the data stays.
#
# Needs: bash, curl, openssl, python3, systemd 250 or later (systemd-creds, systemd-analyze,
# journalctl). It reads JSON with python3, not jq.
#
# With SMOKE_LIB_ONLY=1 the file only defines its functions (for tests of the API helpers).

set -euo pipefail

# ---- settings (the environment may override the ones that are not about the unit) --------

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UNIT_NAME="${UNIT_NAME:-tenko}"
INSTALLED_BIN="${INSTALLED_BIN:-/usr/local/bin/tenko}"
CONFIG_DIR="${CONFIG_DIR:-/etc/tenko}"
CONFIG_FILE="${CONFIG_FILE:-$CONFIG_DIR/tenko.toml}"
KEK_CRED="${KEK_CRED:-$CONFIG_DIR/kek.cred}"
DATA_DIR="${DATA_DIR:-/var/lib/tenko}"
LOG_DIR="${LOG_DIR:-/var/log/tenko}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/tenko.log}"
DROPIN_DIR="${DROPIN_DIR:-/etc/systemd/system/$UNIT_NAME.service.d}"
API_HOST="${API_HOST:-localhost}"
API_PORT="${API_PORT:-8443}"
API_BASE="https://$API_HOST:$API_PORT"
CA_FILE="${CA_FILE:-$DATA_DIR/tls/ca-root.pem}"
# The administrator of the smoke installation: the PIN preset of the Home profile takes digits.
ADMIN_NAME="${ADMIN_NAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-739153}"
MAX_EXPOSURE="${MAX_EXPOSURE:-2.5}"
WORK_DIR=""
COOKIE_JAR=""
RELEASE_PORT=""
RELEASE_PID=""
NEW_VERSION=""

# ---- output ------------------------------------------------------------------------------

step() { printf '\n==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

# Runs a command until it succeeds. wait_for SECONDS "what" command [arguments...]
wait_for() {
  local seconds="$1" what="$2" deadline
  shift 2
  deadline=$((SECONDS + seconds))
  until "$@" > /dev/null 2>&1; do
    if ((SECONDS >= deadline)); then
      die "timed out after ${seconds}s waiting for: $what"
    fi
    sleep 1
  done
  info "ok: $what"
}

# ---- JSON and the API --------------------------------------------------------------------

# Reads JSON on standard input and prints the value at a dotted path (list indexes are
# numbers): `jget releases.0.version`. Prints nothing for a missing key; booleans print as
# true and false.
jget() {
  python3 -c '
import json, sys
value = json.load(sys.stdin)
for key in sys.argv[1].split("."):
    if isinstance(value, list):
        try:
            value = value[int(key)]
        except (ValueError, IndexError):
            value = None
    elif isinstance(value, dict):
        value = value.get(key)
    else:
        value = None
    if value is None:
        break
if value is None:
    print("")
elif isinstance(value, (dict, list, bool)):
    print(json.dumps(value))
else:
    print(value)
' "$1"
}

new_uuid() { cat /proc/sys/kernel/random/uuid; }

# api METHOD PATH [JSON]: one request to /api/v1 against the loopback listener, trusting the
# internal CA root, with the session cookie kept in $COOKIE_JAR. Mutations carry the Origin
# of the listener (the CSRF guard), and the ones that are not setup or login an
# Idempotency-Key. Prints the body; on an HTTP error prints it to standard error and fails.
api() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS --fail-with-body --cacert "$CA_FILE"
    --resolve "$API_HOST:$API_PORT:127.0.0.1"
    --max-time 60 -b "$COOKIE_JAR" -c "$COOKIE_JAR" -X "$method")
  if [[ "$method" != GET ]]; then
    args+=(-H "Origin: $API_BASE" -H 'Content-Type: application/json')
    case "$path" in
      /setup | /auth/*) ;;
      *) args+=(-H "Idempotency-Key: $(new_uuid)") ;;
    esac
    args+=(--data "${body:-{\}}")
  fi
  curl "${args[@]}" "$API_BASE/api/v1$path"
}

# The one-time setup token, from the file the server writes while setup is open.
setup_token() { tr -d '\r\n' < "$DATA_DIR/setup-token"; }

# First-run setup through the API as the Home profile; the answer signs this client in.
api_setup() {
  local token body
  wait_for 30 "the setup token file" test -s "$DATA_DIR/setup-token"
  token="$(setup_token)"
  body="$(python3 -c '
import json, sys
print(json.dumps({
    "setup_token": sys.argv[1],
    "profile": "home",
    "admin": {"name": sys.argv[2], "display_name": "Smoke Admin", "password": sys.argv[3]},
    "host_name": "localhost",
    "language": "en",
}))' "$token" "$ADMIN_NAME" "$ADMIN_PASSWORD")"
  api POST /setup "$body" > /dev/null
  info "first-run setup done; signed in as $ADMIN_NAME"
}

# A new session with the password (after a restart).
api_login() {
  local body answer
  body="$(python3 -c '
import json, sys
print(json.dumps({"user_name": sys.argv[1], "password": sys.argv[2]}))' "$ADMIN_NAME" "$ADMIN_PASSWORD")"
  answer="$(api POST /auth/login/password "$body")"
  [[ "$(jget status <<< "$answer")" == authenticated ]] || die "login did not complete: $answer"
}

# The version the server reports on the liveness probe.
server_version() {
  "$INSTALLED_BIN" health --live --json --url "https://127.0.0.1:$API_PORT" \
    --ca-file "$CA_FILE" | jget version
}

# The next patch version of $1: 0.0.1 -> 0.0.2.
next_patch() {
  python3 -c '
import re, sys
m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", sys.argv[1])
if not m:
    sys.exit("not a plain SemVer version: " + sys.argv[1])
print("%s.%s.%d" % (m[1], m[2], int(m[3]) + 1))' "$1"
}

# The platform name of the release file, as the server computes it: <os>-<arch>.
release_platform() { printf 'linux-%s' "$(uname -m)"; }

# make_release DIR VERSION BINARY: DIR gets the release file (a copy of BINARY, named like
# scripts/release-manifest.mjs names assets) and releases.json that offers it.
make_release() {
  local dir="$1" version="$2" binary="$3" name platform sha size
  platform="$(release_platform)"
  name="tenko-$version-$platform"
  mkdir -p "$dir"
  cp "$binary" "$dir/$name"
  sha="$(sha256sum "$dir/$name" | cut -d' ' -f1)"
  size="$(stat -c %s "$dir/$name")"
  python3 - "$dir/releases.json" "$version" "$platform" "$name" "$sha" "$size" << 'PY'
import json, sys
path, version, platform, name, sha, size = sys.argv[1:7]
manifest = {
    "schema": 1,
    "project": "tenko",
    "releases": [{
        "version": version,
        "date": "2026-10-10",
        "notes": "### Fixed\n\n- A release for the systemd smoke.",
        "security": True,
        "assets": [{
            "platform": platform,
            "name": name,
            "url": name,
            "sha256": sha,
            "size": int(size),
        }],
    }],
}
with open(path, "w") as out:
    json.dump(manifest, out, indent=2)
PY
  info "release $version: $name ($size bytes, sha256 $sha)"
}

# A free TCP port on the loopback interface.
free_port() {
  python3 -c '
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

# Serves DIR on 127.0.0.1:PORT in the background; sets RELEASE_PID.
start_release_server() {
  local dir="$1" port="$2"
  python3 -m http.server "$port" --bind 127.0.0.1 --directory "$dir" \
    > "$WORK_DIR/release-server.log" 2>&1 &
  RELEASE_PID=$!
  wait_for 15 "the release source answers on 127.0.0.1:$port" \
    curl -sS --fail -o /dev/null "http://127.0.0.1:$port/releases.json"
}

stop_release_server() {
  if [[ -n "$RELEASE_PID" ]]; then
    kill "$RELEASE_PID" 2> /dev/null || true
    wait "$RELEASE_PID" 2> /dev/null || true
    RELEASE_PID=""
  fi
}

# Checks the release source and returns the update status; fails unless VERSION is offered
# and may be installed from the UI.
api_update_check() {
  local version="$1" status
  status="$(api POST /system/updates/check '{}')"
  [[ "$(jget latest <<< "$status")" == "$version" ]] || die "the update check offers $(jget latest <<< "$status"), not $version: $status"
  [[ "$(jget update_available <<< "$status")" == true ]] || die "no update available: $status"
  [[ "$(jget install.policy <<< "$status")" == ui ]] || die "updates are not installable from the UI: $(jget install <<< "$status")"
  [[ "$(jget install.from_source <<< "$status")" == true ]] || die "the install does not come from the source: $(jget install <<< "$status")"
  printf '%s\n' "$status"
}

# Starts the install of VERSION; prints the job id.
api_update_install() {
  local answer job
  answer="$(api POST /system/updates/install "{\"version\": \"$1\"}")"
  job="$(jget job_id <<< "$answer")"
  [[ -n "$job" ]] || die "the install returned no job id: $answer"
  printf '%s\n' "$job"
}

# Waits for the probation of the new version to end (the attempt is confirmed). Fails when
# the attempt ends in any other state.
api_wait_confirmed() {
  local seconds="$1" deadline state="" status
  deadline=$((SECONDS + seconds))
  while ((SECONDS < deadline)); do
    status="$(api GET /system/updates)" || status=""
    state="$(jget attempt.state <<< "${status:-{\}}")"
    case "$state" in
      confirmed)
        info "the new version is confirmed (probation over)"
        return 0
        ;;
      rolled_back | failed) die "the update attempt ended as $state: $status" ;;
    esac
    sleep 2
  done
  die "the update attempt is still '$state' after ${seconds}s"
}

# ---- systemd -----------------------------------------------------------------------------

svc() { systemctl show -p "$1" --value "$UNIT_NAME"; }
unit_active() { [[ "$(systemctl is-active "$UNIT_NAME" || true)" == active ]]; }
unit_inactive() { [[ "$(systemctl is-active "$UNIT_NAME" || true)" == inactive ]]; }
tenko_ready() {
  "$INSTALLED_BIN" health --url "https://127.0.0.1:$API_PORT" --ca-file "$CA_FILE"
}

# The unit starts at most five times within five minutes (StartLimitBurst=), manual ones
# included; the smoke starts it more often than that.
svc_start() {
  systemctl reset-failed "$UNIT_NAME" 2> /dev/null || true
  systemctl start "$UNIT_NAME"
}
svc_restart() {
  systemctl reset-failed "$UNIT_NAME" 2> /dev/null || true
  systemctl restart "$UNIT_NAME"
}

wait_ready() {
  wait_for "${1:-120}" "$UNIT_NAME is active" unit_active
  wait_for 60 "tenko health reports ready" tenko_ready
}

# The journal of the current invocation of the unit.
invocation_journal() {
  journalctl "_SYSTEMD_INVOCATION_ID=$(svc InvocationID)" --no-pager 2> /dev/null || true
}

# ---- diagnostics and cleanup -------------------------------------------------------------

dump_diagnostics() {
  {
    printf '\n---- systemctl status %s ----\n' "$UNIT_NAME"
    systemctl status "$UNIT_NAME" --no-pager -l || true
    printf '\n---- journalctl -u %s --no-pager -n 200 ----\n' "$UNIT_NAME"
    journalctl -u "$UNIT_NAME" --no-pager -n 200 || true
    printf '\n---- %s (last 200 lines) ----\n' "$LOG_FILE"
    tail -n 200 "$LOG_FILE" 2> /dev/null || printf '(no log file)\n'
    if [[ -n "$WORK_DIR" && -s "$WORK_DIR/release-server.log" ]]; then
      printf '\n---- release source log ----\n'
      tail -n 50 "$WORK_DIR/release-server.log"
    fi
  } >&2
}

cleanup() {
  local status=$?
  set +e
  trap - EXIT
  if ((status != 0)); then
    printf '\nThe smoke failed (exit status %d).\n' "$status" >&2
    dump_diagnostics
  fi
  if [[ "${KEEP:-}" == 1 ]]; then
    printf '\nKEEP=1: leaving the unit, its drop-ins and %s as they are.\n' "$WORK_DIR"
  else
    printf '\n==> clean up\n'
    stop_release_server
    systemctl stop "$UNIT_NAME" 2> /dev/null
    systemctl disable "$UNIT_NAME" 2> /dev/null
    rm -f "$DROPIN_DIR/smoke.conf" "$DROPIN_DIR/smoke-roles.conf" "$DROPIN_DIR/probe.conf"
    rmdir "$DROPIN_DIR" 2> /dev/null
    systemctl daemon-reload
    systemctl reset-failed "$UNIT_NAME" 2> /dev/null
    [[ -n "$WORK_DIR" ]] && rm -rf "$WORK_DIR"
  fi
  exit "$status"
}

# ---- steps -------------------------------------------------------------------------------

check_tools() {
  local tool
  for tool in curl openssl python3 systemctl systemd-creds systemd-analyze journalctl sha256sum; do
    command -v "$tool" > /dev/null || die "$tool is needed and not installed"
  done
  [[ "$(id -u)" == 0 ]] || die "run as root (sudo bash $0 /path/to/tenko)"
  [[ -d /run/systemd/system ]] || die "systemd is not PID 1 on this host"
}

write_smoke_config() {
  install -d -m 0750 -o root -g tenko "$CONFIG_DIR"
  cat > "$CONFIG_FILE" << EOF
# Written by deploy/systemd/smoke.sh. The key-encryption key comes from the unit
# (TENKO_KEK__PROVIDER=systemd_credential), not from this file.
data_dir = "$DATA_DIR"
roles = "controller"

[server]
listen = ["127.0.0.1:$API_PORT"]
workers = 1

[tls]
mode = "internal_ca"
host_name = "$API_HOST"
addresses = ["127.0.0.1"]

[hibp]
online = false

[log]
level = "info"
file = "$LOG_FILE"

[updates]
source_url = "http://127.0.0.1:$RELEASE_PORT/releases.json"
ready_timeout_secs = 60
EOF
  chown root:tenko "$CONFIG_FILE"
  chmod 0640 "$CONFIG_FILE"
}

step_install() {
  step "1. install the binary, the service account, the configuration and the unit"
  [[ -x "$TENKO_BUILD" ]] || die "$TENKO_BUILD is not an executable file"
  if [[ -e "$DATA_DIR" && ! -e "$CONFIG_DIR/.smoke-marker" && "${SMOKE_FORCE:-}" != 1 ]]; then
    die "$DATA_DIR exists and was not made by this script; refusing to delete it (SMOKE_FORCE=1 overrides)"
  fi
  systemctl stop "$UNIT_NAME" 2> /dev/null || true
  rm -rf "$DATA_DIR" "$LOG_DIR"
  install -m 0755 "$TENKO_BUILD" "$INSTALLED_BIN"
  if ! id -u tenko > /dev/null 2>&1; then
    useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin tenko
  fi
  install -d -m 0750 -o root -g tenko "$CONFIG_DIR"
  : > "$CONFIG_DIR/.smoke-marker"
  RELEASE_PORT="$(free_port)"
  write_smoke_config
  "$INSTALLED_BIN" config check --config "$CONFIG_FILE"
  install -m 0644 "$REPO_DIR/deploy/systemd/tenko.service" "/etc/systemd/system/$UNIT_NAME.service"
  install -d -m 0755 "$DROPIN_DIR"
  # Debug builds only: the version comes from the layout directory, so this binary can be
  # installed as the next version.
  cat > "$DROPIN_DIR/smoke.conf" << 'EOF'
[Service]
Environment=TENKO_TEST_VERSION_FROM_LAYOUT=1
EOF
  info "installed $INSTALLED_BIN, $CONFIG_FILE, the unit and $DROPIN_DIR/smoke.conf"
}

step_credential() {
  step "2. create the key-encryption key as an encrypted credential (root path)"
  (
    umask 077
    openssl rand -hex 32 | systemd-creds encrypt --name=tenko_kek - "$KEK_CRED"
  )
  chmod 0600 "$KEK_CRED"
  [[ -s "$KEK_CRED" ]] || die "$KEK_CRED is empty"
  info "$KEK_CRED: $(stat -c '%a %U:%G %s bytes' "$KEK_CRED")"
}

step_start() {
  step "3. start the unit and wait until it is ready"
  systemctl daemon-reload
  svc_start
  wait_ready 120
  info "unit state: $(svc ActiveState)/$(svc SubState), main pid $(svc MainPID)"
}

step_kek() {
  step "4. the key came from the systemd credential, not from a plain file"
  wait_for 30 "the journal shows the credential being loaded" \
    bash -c "journalctl '_SYSTEMD_INVOCATION_ID=$(svc InvocationID)' --no-pager | grep -q 'loaded the key-encryption key from a systemd credential'"
  if invocation_journal | grep -Eq 'PLAIN FILE|no OS protection'; then
    invocation_journal | grep -E 'PLAIN FILE|no OS protection' >&2
    die "the journal of this start warns about a plain key file"
  fi
  invocation_journal | grep 'systemd credential' | head -n 3
}

step_logs() {
  step "5. LogsDirectory= (/var/log/tenko) and the log file"
  [[ -d "$LOG_DIR" ]] || die "$LOG_DIR does not exist"
  [[ "$(stat -c %U "$LOG_DIR")" == tenko ]] || die "$LOG_DIR is owned by $(stat -c %U "$LOG_DIR"), not tenko"
  info "$LOG_DIR: $(stat -c '%a %U:%G' "$LOG_DIR")"
  wait_for 30 "$LOG_FILE is written" test -s "$LOG_FILE"
  info "$LOG_FILE: $(stat -c '%s bytes, owner %U' "$LOG_FILE")"
}

step_stop_start() {
  step "6. stop (clean exit), then start again"
  systemctl stop "$UNIT_NAME"
  unit_inactive || die "the unit is $(systemctl is-active "$UNIT_NAME") after stop"
  [[ "$(svc Result)" == success ]] || die "the stop ended with Result=$(svc Result)"
  [[ "$(svc ExecMainStatus)" == 0 ]] || die "the main process exited with status $(svc ExecMainStatus), not 0"
  info "stopped: Result=success, ExecMainStatus=0"
  svc_start
  wait_ready 120
}

step_upgrade() {
  step "7. first-run setup, then an update through the layout with exit status 12"
  local before_version restarts_before job
  COOKIE_JAR="$WORK_DIR/cookies.txt"
  : > "$COOKIE_JAR"
  api_setup
  before_version="$(server_version)"
  [[ -n "$before_version" ]] || die "tenko health --live reported no version"
  NEW_VERSION="$(next_patch "$before_version")"
  info "running $before_version; the release source will offer $NEW_VERSION"
  [[ "$(api GET /system/kek | jget provider)" == systemd_credential ]] \
    || die "the KEK provider is not systemd_credential: $(api GET /system/kek)"
  info "GET /system/kek: provider systemd_credential"

  make_release "$WORK_DIR/release" "$NEW_VERSION" "$INSTALLED_BIN"
  start_release_server "$WORK_DIR/release" "$RELEASE_PORT"
  api_update_check "$NEW_VERSION" > /dev/null
  info "the update check offers $NEW_VERSION (policy ui)"
  restarts_before="$(svc NRestarts)"
  job="$(api_update_install "$NEW_VERSION")"
  info "install started, job $job"

  wait_for 300 "systemd restarted the service (NRestarts above $restarts_before)" \
    bash -c "[[ \$(systemctl show -p NRestarts --value '$UNIT_NAME') -gt $restarts_before ]]"
  wait_for 60 "the journal records the exit with status 12" \
    bash -c "journalctl -u '$UNIT_NAME' --no-pager | grep -q 'status=12'"
  wait_ready 180
  [[ "$(server_version)" == "$NEW_VERSION" ]] || die "the service runs $(server_version), not $NEW_VERSION"
  info "the service runs $NEW_VERSION; NRestarts=$(svc NRestarts), ExecMainStatus=$(svc ExecMainStatus)"
  [[ "$(basename "$(readlink "$DATA_DIR/updates/current")")" == "$NEW_VERSION" ]] \
    || die "$DATA_DIR/updates/current points at $(readlink "$DATA_DIR/updates/current")"
  info "$DATA_DIR/updates/current -> $(readlink "$DATA_DIR/updates/current")"

  : > "$COOKIE_JAR"
  api_login
  api_wait_confirmed 180
  stop_release_server
}

step_probe() {
  step "8. the probe drop-in: CAP_NET_RAW and the roles controller,probe"
  local pid caps
  install -m 0644 "$REPO_DIR/deploy/systemd/probe.conf" "$DROPIN_DIR/probe.conf"
  cat > "$DROPIN_DIR/smoke-roles.conf" << 'EOF'
[Service]
Environment=TENKO_ROLES=controller,probe
EOF
  systemctl daemon-reload
  systemctl show -p AmbientCapabilities -p CapabilityBoundingSet "$UNIT_NAME" | tee "$WORK_DIR/caps.txt"
  grep -qi '^AmbientCapabilities=.*cap_net_raw' "$WORK_DIR/caps.txt" || die "AmbientCapabilities lacks cap_net_raw"
  grep -qi '^CapabilityBoundingSet=.*cap_net_raw' "$WORK_DIR/caps.txt" || die "CapabilityBoundingSet lacks cap_net_raw"
  svc_restart
  wait_ready 120
  pid="$(svc MainPID)"
  caps="$(awk '/^CapEff:/ {print $2}' "/proc/$pid/status")"
  info "main pid $pid, CapEff=0x$caps"
  (((16#$caps & 0x2000) != 0)) || die "CAP_NET_RAW (bit 13) is not in CapEff of the process"
  info "CAP_NET_RAW is in the effective set of the running process"
  rm -f "$DROPIN_DIR/probe.conf" "$DROPIN_DIR/smoke-roles.conf"
  systemctl daemon-reload
  svc_restart
  wait_ready 120
  info "drop-in removed; the controller runs as before"
}

step_security() {
  step "9. systemd-analyze security"
  local report="$WORK_DIR/security.txt" line score
  systemd-analyze security --no-pager "$UNIT_NAME.service" > "$report"
  cat "$report"
  line="$(grep 'Overall exposure level' "$report")" || die "systemd-analyze security printed no overall exposure level"
  score="$(sed -E 's/.*: ([0-9]+(\.[0-9]+)?).*/\1/' <<< "$line")"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "### systemd smoke: systemd-analyze security $UNIT_NAME.service"
      echo
      echo "$line"
      echo
      echo "Limit: $MAX_EXPOSURE"
      echo
      echo '```text'
      cat "$report"
      echo '```'
    } >> "$GITHUB_STEP_SUMMARY"
  fi
  if awk -v s="$score" -v m="$MAX_EXPOSURE" 'BEGIN { exit !(s >= m) }'; then
    die "the exposure level $score is not below $MAX_EXPOSURE"
  fi
  info "exposure $score is below $MAX_EXPOSURE"
}

main() {
  if (($# != 1)); then
    echo "usage: sudo bash $0 /path/to/tenko" >&2
    exit 2
  fi
  TENKO_BUILD="$(readlink -f "$1")"
  check_tools
  WORK_DIR="$(mktemp -d /tmp/tenko-smoke.XXXXXX)"
  trap cleanup EXIT
  step_install
  step_credential
  step_start
  step_kek
  step_logs
  step_stop_start
  step_upgrade
  step_probe
  step_security
  printf '\n==> the systemd smoke passed\n'
}

# Sourced with SMOKE_LIB_ONLY=1: the functions above only.
if [[ "${SMOKE_LIB_ONLY:-}" == 1 ]]; then
  # shellcheck disable=SC2317
  return 0 2> /dev/null || exit 0
fi
main "$@"
