#!/usr/bin/env bash
# Systemd smoke of Tenko DDI (OPS-13, exit criterion E10).
#
#   sudo bash deploy/systemd/smoke.sh /path/to/tenko
#
# Run it as root on a TEST host with systemd as PID 1 (a VM, or the hosted Linux runner of CI),
# never on a production host: it replaces /etc/tenko/tenko.toml, /etc/tenko/kek.cred and
# /opt/tenko/cli/tenko, and it deletes /var/lib/tenko and /var/log/tenko at the start. A host
# that has /var/lib/tenko from something other than this script is refused (set
# SMOKE_FORCE=1 to override that on a throwaway VM).
#
# Argument 1 is a debug build of tenko (only debug builds honor the test variable that lets
# the update install this same binary as the next version). What it does, in order:
#   1. installs as the header of deploy/systemd/tenko.service says: the service account, the
#      group tenko-cli, a smoke tenko.toml, the version layout laid out by the account from a
#      root-owned copy of the binary, the gate on updates/, the command line
#      /opt/tenko/cli/tenko, the unit from this repository and a drop-in with
#      TENKO_TEST_VERSION_FROM_LAYOUT=1; and an account in tenko-cli that runs the command
#      line;
#   2. creates the key-encryption key with `systemd-creds encrypt` (the root path);
#   3. starts the unit and waits until `tenko health` succeeds;
#   4. checks that the key was loaded from the systemd credential, without a plain-file warning;
#   5. checks LogsDirectory= (/var/log/tenko, owned by tenko, tenko.log written);
#   6. stops the unit (clean exit) and starts it again;
#   7. completes first-run setup through the API, puts a backup recipient into the backup
#      settings, and twice installs this binary as the next version from a release source on
#      the loopback interface with the answer `backup: "run"`: waits for systemd to restart
#      the service after exit status 12, for the new version to run and for its probation to
#      end; proves the backup of ADR 0023 (a good backup with the reason `before_update` for
#      the new version exists in its target directory, opens with the backup key, was the
#      first step of the install job, and was finished before the switch step replaced the
#      binary: the job's step times, and the file's time against the `current` link's); and
#      counts the versions the node runs (ADR 0023 item 3): the server's, the command line's
#      of a member of tenko-cli, and the start-up step's must be one. This binary is
#      installed under two version names, so each binary is asked `upgrade version` (the
#      version it runs as) rather than `--version` (the version it was built as);
#   8. installs deploy/systemd/probe.conf and runs the roles controller,probe;
#   9. runs deploy/install.sh unattended with --roles controller,dns,dhcp,probe (the installer
#      puts the probe drop-in in place, identical to deploy/systemd/probe.conf, the process
#      has CAP_NET_RAW and the log says which method the dhcp role probes an address with),
#      then with --roles controller (under Home every role stays prepared, so the drop-in
#      stays, and the node runs the controller alone). A node that has started keeps
#      its roles in the store (docs/cluster.md section 13.1), so steps 8 and 9 change the
#      stored set through PUT /nodes/1/roles, as an administrator does, and the node restarts
#      itself with exit status 12 to apply it;
#  10. records `systemd-analyze security` (in $GITHUB_STEP_SUMMARY when set) and fails when
#      the exposure is 2.5 or higher.
# Each step prints "==> step". On failure the script prints the journal of the unit and the
# tenko log and exits non-zero. Unless KEEP=1 is set it stops and disables the unit, removes
# the drop-ins it added and stops the release source at the end; the data stays.
#
# Needs: bash, curl, openssl, python3, systemd 250 or later (systemd-creds, systemd-analyze,
# journalctl), and what deploy/install.sh needs (ss of iproute2). It reads JSON with
# python3, not jq.
#
# With SMOKE_LIB_ONLY=1 the file only defines its functions (for tests of the API helpers).
#
# SMOKE_KEK_FILE=1 keeps the key-encryption key in a plain file (/etc/tenko/kek.key) instead
# of a systemd credential, for a host whose service manager does not hand encrypted
# credentials to services (a systemd container under Docker Desktop, for example); step 4
# then checks the file provider instead. CI never sets it.

set -euo pipefail

# ---- settings (the environment may override the ones that are not about the unit) --------

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UNIT_NAME="${UNIT_NAME:-tenko}"
# Root's own copy of the binary under test, in a root-owned directory the account may pass:
# root runs it (health, keygen) and the account lays the layout out from it, so that root
# never runs the layout's binary, which the binary refuses anyway.
INSTALLED_BIN=""
CLI_LINK=/opt/tenko/cli/tenko
# An account in tenko-cli that runs the command line, as an operator does.
MEMBER="${MEMBER:-tenko-smoke-member}"
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
# The administrator of the smoke installation. An administrator's password has at least 12
# characters and is not digits only, in every profile; one is generated per run unless given.
ADMIN_NAME="${ADMIN_NAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-Run-$(od -An -N9 -tx1 /dev/urandom | tr -d ' \n')-Aa1}"
MAX_EXPOSURE="${MAX_EXPOSURE:-2.5}"
KEK_FILE="${KEK_FILE:-$CONFIG_DIR/kek.key}"
SMOKE_KEK_FILE="${SMOKE_KEK_FILE:-}"
WORK_DIR=""
STAGE_DIR=""
VERIFY_DIR=""
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

# Starts the install of VERSION with the answer "run" to "take a backup first?" (ADR 0023):
# the job's first step takes the backup. Prints the job id.
api_update_install() {
  local answer job
  answer="$(api POST /system/updates/install "{\"version\": \"$1\", \"backup\": \"run\"}")"
  job="$(jget job_id <<< "$answer")"
  [[ -n "$job" ]] || die "the install returned no job id: $answer"
  printf '%s\n' "$job"
}

# Creates a backup key pair in DIR (the key file stays there) and puts its recipient into
# the backup settings, so that the install job can take its backup without a passphrase.
# Prints the key file.
api_backup_recipient() {
  local dir="$1" recipient body
  recipient="$("$INSTALLED_BIN" backup keygen --out "$dir/backup.key" 2> /dev/null | head -n 1)"
  [[ "$recipient" == tkbr1:* ]] || die "tenko backup keygen printed no recipient: $recipient"
  body="$(python3 -c '
import json, sys
print(json.dumps({"enabled": False, "interval_hours": 24, "keep": 7,
                  "include_config": True, "recipient": sys.argv[1]}))' "$recipient")"
  api PUT /system/backups/settings "$body" > /dev/null
  info "backup recipient $recipient in the backup settings" >&2
  printf '%s\n' "$dir/backup.key"
}

# Seconds since the epoch of an RFC 3339 time.
epoch_of() {
  python3 -c '
import datetime, sys
text = sys.argv[1].replace("Z", "+00:00")
print("%.6f" % datetime.datetime.fromisoformat(text).timestamp())' "$1"
}

# Proves the backup before the update of ADR 0023 for the install JOB of VERSION: its record
# (reason before_update, the version, good), its file in the target directory, that it opens
# with KEY_FILE, and that it was taken before the binary was replaced.
prove_backup_before_switch() {
  local job="$1" version="$2" key_file="$3" detail backups run file dir bytes
  local backup_kind backup_state backup_done switch_start finished file_time link_time size
  detail="$(api GET "/jobs/$job")"
  backup_kind="$(jget job.steps.0.kind <<< "$detail")"
  backup_state="$(jget job.steps.0.state.state <<< "$detail")"
  [[ "$backup_kind" == sys.update.backup && "$backup_state" == "done" ]] \
    || die "the first step of job $job is $backup_kind ($backup_state), not a finished sys.update.backup: $detail"
  backup_done="$(jget job.steps.0.finished <<< "$detail")"
  switch_start="$(python3 -c '
import json, sys
job = json.load(sys.stdin)["job"]
steps = [s for s in job["steps"] if s["kind"] == "sys.update.switch"]
print(steps[0].get("started") or "" if steps else "")' <<< "$detail")"
  [[ -n "$backup_done" && -n "$switch_start" ]] || die "job $job lacks the step times: $detail"
  awk -v b="$(epoch_of "$backup_done")" -v s="$(epoch_of "$switch_start")" 'BEGIN { exit !(b <= s) }' \
    || die "the backup step finished at $backup_done, after the switch step started at $switch_start"
  info "job $job: sys.update.backup finished $backup_done, sys.update.switch started $switch_start"

  backups="$(api GET /system/backups)"
  run="$(python3 -c '
import json, sys
status = json.load(sys.stdin)
runs = [r for r in status.get("recent", [])
        if r.get("reason") == "before_update" and r.get("before_update") == sys.argv[1]]
print(json.dumps(runs[0]) if runs else "")' "$version" <<< "$backups")"
  [[ -n "$run" ]] || die "no backup with the reason before_update for $version: $backups"
  [[ "$(jget outcome <<< "$run")" == succeeded ]] || die "the backup before the update did not succeed: $run"
  file="$(jget file <<< "$run")"
  dir="$(jget target_dir <<< "$run")"
  bytes="$(jget bytes <<< "$run")"
  finished="$(jget finished_at <<< "$run")"
  [[ -n "$file" && -n "$dir" ]] || die "the backup record names no file: $run"
  # The file and the link live where the service account writes: they are looked at as that
  # account, so that root follows no link it planted (ADR 0023, I2).
  as_tenko() { runuser -u tenko -- "$@" < /dev/null; }
  size="$(as_tenko stat -c %s "$dir/$file")" || die "the backup file $dir/$file does not exist"
  [[ "$size" == "$bytes" ]] || die "$dir/$file has $size bytes, the record says $bytes"
  awk -v b="$(epoch_of "$finished")" -v s="$(epoch_of "$switch_start")" 'BEGIN { exit !(b <= s) }' \
    || die "the backup was recorded at $finished, after the switch started at $switch_start"
  # The file was written before the link that names the new binary (lstat, not the target).
  file_time="$(as_tenko stat -c %Y "$dir/$file")"
  link_time="$(as_tenko stat -c %Y "$DATA_DIR/updates/current")"
  ((file_time <= link_time)) || die "$dir/$file ($file_time) is newer than $DATA_DIR/updates/current ($link_time)"
  info "backup $dir/$file: $bytes bytes, recorded $finished, before the switch"

  # The restore point opens: verify it as the service account, with a copy of the key file
  # in a directory that account creates, fills from standard input and removes itself.
  VERIFY_DIR="$(as_tenko mktemp -d /tmp/tenko-smoke-verify.XXXXXX)" || die "cannot create a directory as tenko"
  runuser -u tenko -- sh -c 'umask 077 && cat > "$1"' sh "$VERIFY_DIR/backup.key" < "$key_file"
  if ! as_tenko env TMPDIR="$VERIFY_DIR" "$INSTALLED_BIN" backup verify "$dir/$file" \
    --key-file "$VERIFY_DIR/backup.key" > "$WORK_DIR/verify.txt" 2>&1; then
    cat "$WORK_DIR/verify.txt" >&2
    die "tenko backup verify refused $dir/$file"
  fi
  info "tenko backup verify (as tenko): $(head -n 1 "$WORK_DIR/verify.txt")"
  as_tenko rm -rf "$VERIFY_DIR"
  VERIFY_DIR=""
}

# Sets the stored role set of this controller (node 1) through the API, as the web UI does,
# and waits for the restart that applies it: under systemd the node exits with status 12
# and is started again. The stored set decides over `roles` of tenko.toml and TENKO_ROLES.
api_set_roles() {
  local roles="$1" body restarts answer restart
  body="$(python3 -c '
import json, sys
print(json.dumps({"roles": sys.argv[1].split(",")}))' "$roles")"
  : > "$COOKIE_JAR"
  api_login
  restarts="$(svc NRestarts)"
  answer="$(api PUT /nodes/1/roles "$body")"
  restart="$(jget restart <<< "$answer")"
  case "$restart" in
    scheduled)
      wait_for 60 "the node restarted itself for the roles $roles" \
        bash -c "[[ \$(systemctl show -p NRestarts --value '$UNIT_NAME') -gt $restarts ]]"
      ;;
    none) ;;
    *) die "PUT /nodes/1/roles answered restart: $restart: $answer" ;;
  esac
  wait_ready 120
  wait_for 30 "the start log says the roles $roles come from the stored set" \
    bash -c "journalctl '_SYSTEMD_INVOCATION_ID=$(svc InvocationID)' --no-pager | grep -q 'roles $roles (the node.s stored set)'"
  info "the node runs the stored roles $roles"
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
    rm -f "$DROPIN_DIR/smoke.conf" "$DROPIN_DIR/smoke-roles.conf" "$DROPIN_DIR/probe.conf" \
      "$DROPIN_DIR/smoke-kek-file.conf"
    rmdir "$DROPIN_DIR" 2> /dev/null
    systemctl daemon-reload
    systemctl reset-failed "$UNIT_NAME" 2> /dev/null
    [[ -n "$WORK_DIR" ]] && rm -rf "$WORK_DIR"
  fi
  [[ -n "$VERIFY_DIR" ]] && runuser -u tenko -- rm -rf "$VERIFY_DIR" < /dev/null
  id -u "$MEMBER" > /dev/null 2>&1 && userdel "$MEMBER"
  [[ -n "$STAGE_DIR" ]] && rm -rf "$STAGE_DIR"
  exit "$status"
}

# ---- steps -------------------------------------------------------------------------------

check_tools() {
  local tool
  for tool in curl openssl python3 systemctl systemd-creds systemd-analyze journalctl sha256sum runuser; do
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
  if [[ "$SMOKE_KEK_FILE" == 1 ]]; then
    printf '\n[kek]\nprovider = "file"\npath = "%s"\n' "$KEK_FILE" >> "$CONFIG_FILE"
  fi
  chown root:tenko "$CONFIG_FILE"
  chmod 0640 "$CONFIG_FILE"
}

step_install() {
  step "1. install: the account, the configuration, the version layout, the command line and the unit"
  [[ -x "$TENKO_BUILD" ]] || die "$TENKO_BUILD is not an executable file"
  if [[ -e "$DATA_DIR" && ! -e "$CONFIG_DIR/.smoke-marker" && "${SMOKE_FORCE:-}" != 1 ]]; then
    die "$DATA_DIR exists and was not made by this script; refusing to delete it (SMOKE_FORCE=1 overrides)"
  fi
  systemctl stop "$UNIT_NAME" 2> /dev/null || true
  rm -rf "$DATA_DIR" "$LOG_DIR"
  STAGE_DIR="$(mktemp -d /tmp/tenko-smoke-stage.XXXXXX)"
  chmod 0711 "$STAGE_DIR"
  INSTALLED_BIN="$STAGE_DIR/tenko"
  install -m 0755 "$TENKO_BUILD" "$INSTALLED_BIN"
  if ! id -u tenko > /dev/null 2>&1; then
    useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin tenko
  fi
  getent group tenko-cli > /dev/null || groupadd --system tenko-cli
  install -d -m 0750 -o root -g tenko "$CONFIG_DIR"
  : > "$CONFIG_DIR/.smoke-marker"
  RELEASE_PORT="$(free_port)"
  write_smoke_config
  "$INSTALLED_BIN" config check --config "$CONFIG_FILE"
  # The version layout, laid out by the account from root's copy; the gate on updates/, set by
  # the account holding tenko-cli for that one command; the command line.
  install -d -m 0711 -o tenko -g tenko "$DATA_DIR"
  runuser -u tenko -- "$INSTALLED_BIN" upgrade layout --data-dir "$DATA_DIR" < /dev/null
  runuser -u tenko -g tenko -G tenko-cli -- chgrp tenko-cli "$DATA_DIR/updates" < /dev/null
  runuser -u tenko -- chmod 0750 "$DATA_DIR/updates" < /dev/null
  install -d -m 0755 /opt/tenko /opt/tenko/cli
  ln -sfn "$DATA_DIR/updates/current/tenko" "$CLI_LINK"
  id -u "$MEMBER" > /dev/null 2>&1 ||
    useradd --system --no-create-home --shell /usr/sbin/nologin -G tenko-cli "$MEMBER"
  install -m 0644 "$REPO_DIR/deploy/systemd/tenko.service" "/etc/systemd/system/$UNIT_NAME.service"
  install -d -m 0755 "$DROPIN_DIR"
  # Debug builds only: the version comes from the layout directory, so this binary can be
  # installed as the next version.
  cat > "$DROPIN_DIR/smoke.conf" << 'EOF'
[Service]
Environment=TENKO_TEST_VERSION_FROM_LAYOUT=1
EOF
  info "installed $CONFIG_FILE, $DATA_DIR/updates/current -> $(readlink "$DATA_DIR/updates/current"), $CLI_LINK, the unit and $DROPIN_DIR/smoke.conf"
}

step_credential() {
  if [[ "$SMOKE_KEK_FILE" == 1 ]]; then
    step "2. create the key-encryption key as a plain file (SMOKE_KEK_FILE=1)"
    (
      umask 027
      openssl rand -hex 32 > "$KEK_FILE"
    )
    chown root:tenko "$KEK_FILE"
    chmod 0640 "$KEK_FILE"
    # As the installer does where credentials are not delivered: no credential, and the
    # [kek] section of tenko.toml decides.
    cat > "$DROPIN_DIR/smoke-kek-file.conf" << 'EOF'
[Service]
LoadCredentialEncrypted=
UnsetEnvironment=TENKO_KEK__PROVIDER TENKO_KEK__CREDENTIAL
EOF
    info "$KEK_FILE: $(stat -c '%a %U:%G %s bytes' "$KEK_FILE"), drop-in smoke-kek-file.conf"
    return
  fi
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
  if [[ "$SMOKE_KEK_FILE" == 1 ]]; then
    step "4. the key came from the plain file (SMOKE_KEK_FILE=1: no credential check)"
    wait_for 30 "the journal names the plain key file" \
      bash -c "journalctl '_SYSTEMD_INVOCATION_ID=$(svc InvocationID)' --no-pager | grep -Eq 'PLAIN FILE|no OS protection'"
    return
  fi
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

# The version a binary runs as (`upgrade version`; the smoke's builds take it from their
# layout directory, TENKO_TEST_VERSION_FROM_LAYOUT=1, as the unit's drop-in sets it).
runs_as() { "$@" upgrade version < /dev/null 2> /dev/null | head -n 1; }

# assert_one_version VERSION: the node runs VERSION and nothing else (the measure of ADR 0023
# item 3: the versions of Tenko binaries a node runs after an update, from 2 to 1). Each of
# the three is asked on its own and must answer: the server (its liveness probe), the command
# line as a member of tenko-cli runs it, and the binary of the unit's start-up step, run as
# the unit runs it (as tenko). A binary that cannot be run answers nothing and fails.
assert_one_version() {
  local step_binary server cli step count
  step_binary="$(systemctl show -p ExecStartPre --value "$UNIT_NAME" | grep -oE 'path=[^ ;]+' | head -n 1)"
  step_binary="${step_binary#path=}"
  [[ -n "$step_binary" ]] || die "the unit has no start-up step to ask"
  server="$(server_version)"
  cli="$(runs_as runuser -u "$MEMBER" -- env TENKO_TEST_VERSION_FROM_LAYOUT=1 "$CLI_LINK")"
  step="$(runs_as runuser -u tenko -- env TENKO_TEST_VERSION_FROM_LAYOUT=1 "$step_binary")"
  count="$(printf '%s\n' "$server" "$cli" "$step" | sort -u | grep -c .)"
  [[ "$server" == "$1" && "$cli" == "$1" && "$step" == "$1" ]] ||
    die "the node does not run $1 alone: server '${server}', $CLI_LINK as $MEMBER '${cli}', start-up step '${step}'"
  info "versions of Tenko this node runs: $count ($1: the server, $CLI_LINK as $MEMBER, the start-up step)"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    echo "- after the update to $1: versions of Tenko the node runs: $count ($1)" >> "$GITHUB_STEP_SUMMARY"
  fi
}

# update_once: one update from the web UI's API to the next patch version, followed to the end
# of its probation, with the backup of ADR 0023 proved and the versions counted.
update_once() {
  local before_version restarts_before job key_file="$1"
  before_version="$(server_version)"
  [[ -n "$before_version" ]] || die "tenko health --live reported no version"
  NEW_VERSION="$(next_patch "$before_version")"
  info "running $before_version; the release source will offer $NEW_VERSION"
  make_release "$WORK_DIR/release-$NEW_VERSION" "$NEW_VERSION" "$INSTALLED_BIN"
  start_release_server "$WORK_DIR/release-$NEW_VERSION" "$RELEASE_PORT"
  api_update_check "$NEW_VERSION" > /dev/null
  info "the update check offers $NEW_VERSION (policy ui)"
  # The smoke starts the unit more often than StartLimitBurst= allows in five minutes.
  systemctl reset-failed "$UNIT_NAME" 2> /dev/null || true
  restarts_before="$(svc NRestarts)"
  job="$(api_update_install "$NEW_VERSION")"
  info "install started with backup \"run\", job $job"

  wait_for 300 "systemd restarted the service (NRestarts above $restarts_before)" \
    bash -c "[[ \$(systemctl show -p NRestarts --value '$UNIT_NAME') -gt $restarts_before ]]"
  # systemd logs the exit of a main process at debug level when SuccessExitStatus= counts
  # it as a success, as it does 12, so the journal has no "status=12" line by default; the
  # server says it on standard error before it exits.
  wait_for 60 "the journal records the exit for the restart with status 12" \
    bash -c "journalctl -u '$UNIT_NAME' --no-pager | grep -q 'stopped for a restart.*exit status 12'"
  wait_ready 180
  [[ "$(server_version)" == "$NEW_VERSION" ]] || die "the service runs $(server_version), not $NEW_VERSION"
  info "the service runs $NEW_VERSION; NRestarts=$(svc NRestarts), ExecMainStatus=$(svc ExecMainStatus)"
  [[ "$(basename "$(readlink "$DATA_DIR/updates/current")")" == "$NEW_VERSION" ]] \
    || die "$DATA_DIR/updates/current points at $(readlink "$DATA_DIR/updates/current")"
  info "$DATA_DIR/updates/current -> $(readlink "$DATA_DIR/updates/current")"

  : > "$COOKIE_JAR"
  api_login
  api_wait_confirmed 180
  prove_backup_before_switch "$job" "$NEW_VERSION" "$key_file"
  stop_release_server
  assert_one_version "$NEW_VERSION"
}

step_upgrade() {
  step "7. first-run setup, then two updates through the layout with exit status 12, one version on the node"
  local provider=systemd_credential key_file
  COOKIE_JAR="$WORK_DIR/cookies.txt"
  : > "$COOKIE_JAR"
  api_setup
  assert_one_version "$(server_version)"
  [[ "$SMOKE_KEK_FILE" == 1 ]] && provider="file"
  [[ "$(api GET /system/kek | jget provider)" == "$provider" ]] \
    || die "the KEK provider is not $provider: $(api GET /system/kek)"
  info "GET /system/kek: provider $provider"
  key_file="$(api_backup_recipient "$WORK_DIR")"
  update_once "$key_file"
  update_once "$key_file"
}

step_probe() {
  step "8. the probe drop-in: CAP_NET_RAW and the roles controller,probe"
  local pid caps
  install -m 0644 "$REPO_DIR/deploy/systemd/probe.conf" "$DROPIN_DIR/probe.conf"
  systemctl daemon-reload
  systemctl show -p AmbientCapabilities -p CapabilityBoundingSet "$UNIT_NAME" | tee "$WORK_DIR/caps.txt"
  grep -qi '^AmbientCapabilities=.*cap_net_raw' "$WORK_DIR/caps.txt" || die "AmbientCapabilities lacks cap_net_raw"
  grep -qi '^CapabilityBoundingSet=.*cap_net_raw' "$WORK_DIR/caps.txt" || die "CapabilityBoundingSet lacks cap_net_raw"
  api_set_roles controller,probe
  pid="$(svc MainPID)"
  caps="$(awk '/^CapEff:/ {print $2}' "/proc/$pid/status")"
  info "main pid $pid, CapEff=0x$caps"
  (((16#$caps & 0x2000) != 0)) || die "CAP_NET_RAW (bit 13) is not in CapEff of the process"
  info "CAP_NET_RAW is in the effective set of the running process"
  api_set_roles controller
  rm -f "$DROPIN_DIR/probe.conf"
  systemctl daemon-reload
  svc_restart
  wait_ready 120
  info "drop-in removed; the controller runs as before"
}

# installer LOG ARGUMENTS...: deploy/install.sh unattended, with this binary, its output in
# LOG (shown when it fails); the service must come up ready. The unit starts more often in
# this smoke than StartLimitBurst= allows, so the counter is reset first.
installer() {
  local log="$1"
  shift
  systemctl reset-failed "$UNIT_NAME" 2> /dev/null || true
  if ! bash "$REPO_DIR/deploy/install.sh" --yes --binary "$TENKO_BUILD" "$@" > "$log" 2>&1; then
    cat "$log" >&2
    die "deploy/install.sh $* failed"
  fi
  if ! grep -q 'The node is ready' "$log"; then
    cat "$log" >&2
    die "deploy/install.sh $* did not report the node ready"
  fi
  info "deploy/install.sh $*: $(grep -o 'The node is ready.*' "$log" | head -n 1)"
}

step_installer() {
  step "9. deploy/install.sh with the probe role: its drop-in, CAP_NET_RAW and the dhcp role's probe"
  local pid caps
  # The dns role on the loopback address only: systemd-resolved of a hosted runner keeps
  # 127.0.0.53:53. The dhcp role serves nothing without [dhcp] listen, but it starts and
  # says which probe it has.
  installer "$WORK_DIR/install-probe.log" --reconfigure --roles controller,dns,dhcp,probe \
    --modules all --dns-address 127.0.0.1 --forwarders none
  grep -qx 'roles = "controller,dns,dhcp,probe"' "$CONFIG_FILE" \
    || die "$CONFIG_FILE does not say roles = \"controller,dns,dhcp,probe\""
  [[ -f "$DROPIN_DIR/probe.conf" ]] || die "the installer did not put $DROPIN_DIR/probe.conf in place"
  cmp -s "$REPO_DIR/deploy/systemd/probe.conf" "$DROPIN_DIR/probe.conf" \
    || die "$DROPIN_DIR/probe.conf differs from deploy/systemd/probe.conf: the copy in install.sh is stale"
  info "$DROPIN_DIR/probe.conf is in place, identical to deploy/systemd/probe.conf"
  systemctl show -p AmbientCapabilities --value "$UNIT_NAME" | grep -qi cap_net_raw \
    || die "AmbientCapabilities lacks cap_net_raw with the drop-in in place"
  api_set_roles controller,dns,dhcp,probe
  pid="$(svc MainPID)"
  caps="$(awk '/^CapEff:/ {print $2}' "/proc/$pid/status")"
  (((16#$caps & 0x2000) != 0)) || die "CAP_NET_RAW (bit 13) is not in CapEff of the process (0x$caps)"
  info "main pid $pid, CapEff=0x$caps: CAP_NET_RAW is in the effective set"
  wait_for 30 "the log says which method the dhcp role probes an address with" \
    bash -c "journalctl '_SYSTEMD_INVOCATION_ID=$(svc InvocationID)' --no-pager | grep -q 'the dhcp role probes an address'"
  info "$(invocation_journal | grep -o 'the dhcp role probes an address.*' | head -n 1)"
  if invocation_journal | grep -q 'conflict detection is off'; then
    invocation_journal | grep 'conflict detection is off' >&2
    die "the log says conflict detection is off although the probe role runs"
  fi

  # Back to the controller alone before the installer takes the probe drop-in away.
  api_set_roles controller
  installer "$WORK_DIR/install-controller.log" --reconfigure --roles controller --modules all
  # Outside Hardened the installer prepares every role (install.sh, its header): the probe
  # drop-in stays, so that the probe role can be switched on again from the web interface,
  # and the node runs the stored set, the controller alone.
  cmp -s "$REPO_DIR/deploy/systemd/probe.conf" "$DROPIN_DIR/probe.conf" \
    || die "$DROPIN_DIR/probe.conf is gone or differs after --reconfigure --roles controller under the Home profile"
  invocation_journal | grep -q "roles controller (the node.s stored set)" \
    || die "the node does not run the stored roles controller after --reconfigure --roles controller"
  info "--reconfigure --roles controller keeps every role prepared (Home); the controller runs alone"
}

step_security() {
  step "10. systemd-analyze security"
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
  step_installer
  step_security
  printf '\n==> the systemd smoke passed\n'
}

# Sourced with SMOKE_LIB_ONLY=1: the functions above only.
if [[ "${SMOKE_LIB_ONLY:-}" == 1 ]]; then
  # shellcheck disable=SC2317
  return 0 2> /dev/null || exit 0
fi
main "$@"
