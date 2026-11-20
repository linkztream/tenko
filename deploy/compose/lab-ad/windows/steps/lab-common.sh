# shellcheck shell=bash
# What every step of the Windows interop lab on ns1 needs (README.md, "Running the steps
# unattended"). A step script sets nothing before it sources this file from the fixed path
# /root/lab/run/lab-common.sh, then calls `step "<what a pass means>"` once.
#
# - Strict mode; the entry's id is the script's file name (/root/lab/run/<id>.sh), and its
#   step directory /root/lab/<id>/ holds what the runbook keeps and nothing secret.
# - Everything the script prints goes to <step directory>/step.log; only the verdict, one
#   line `PASS <id>: ...` or `FAIL <id>: ...`, also reaches standard output. On a failure the
#   step directory gets verdict.txt and the node's journal since the step began.
# - Secrets are files under /root/lab/secrets/ (one value and a newline each); `secret <name>`
#   names the path and refuses to go on without the file. A secret travels only through a
#   file or a pipe, never as an argument or an environment variable.
# - Root runs its own verified copy of the release binary (/root/lab/media/tenko, checked by
#   W0), never the installed command line, which the service account can write
#   (docs/adr/0023-no-root-after-installation.md). It talks to the node's API on
#   https://localhost:8443 with root's copy of the node's CA root.

set -Eeuo pipefail
# A failing command inside $(...) stops the substitution, and so the step.
shopt -s inherit_errexit
umask 077

ID="$(basename "$0" .sh)"
LAB=/root/lab
SECRETS="$LAB/secrets"
STEP_DIR="$LAB/$ID"
MEDIA="$LAB/media"
CA="$LAB/ca-root.pem"
TENKO_URL=https://localhost:8443
export TENKO_URL TENKO_CA_FILE="$CA" TENKO_CREDENTIALS="$SECRETS/tenko-credentials.json"
START_EPOCH="$(date +%s)"
STARTED="$(date -u -d "@$START_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"
STAGE="starting"
WHY=""
VERDICT=""

mkdir -p "$STEP_DIR"
chmod 700 "$SECRETS" 2>/dev/null || true
exec 3>&1 >>"$STEP_DIR/step.log" 2>&1
printf '== %s started %s\n' "$ID" "$STARTED"

# say <stage>: logs what the script does now; a failure names the last stage.
say() {
  STAGE="$*"
  printf '== %s\n' "$*"
}

# fail <reason>: stops the step with this reason.
fail() {
  WHY="$*"
  printf 'reason: %s\n' "$*" >&2
  exit 1
}

finish() {
  local rc=$? line
  # errexit would end this handler at its first failing command, such as the grep below.
  set +e
  rm -f "$SECRETS/session.cookies"
  if ((rc == 0)); then
    line="PASS $ID: $VERDICT"
  else
    # A reason given inside a command substitution reaches the log only.
    [[ -n "$WHY" ]] || WHY="$(grep '^reason: ' "$STEP_DIR/step.log" | tail -n 1 | cut -c 9-)"
    line="FAIL $ID: ${WHY:-stopped with status $rc during: $STAGE}"
    journalctl -u tenko --since "@$START_EPOCH" --no-pager >"$STEP_DIR/journal-tenko.txt" 2>&1 || true
  fi
  printf '%s\n' "$line" | tee "$STEP_DIR/verdict.txt"
  printf '%s\n' "$line" >&3
}
trap finish EXIT

# step <pass text>: the verdict of a pass.
step() { VERDICT="$*"; }

# secret <name>: the path of a secret file; the step stops when it is missing or empty.
secret() {
  local path="$SECRETS/$1"
  [[ -s "$path" ]] || fail "the secret file $path is missing or empty; the job places it before this step"
  printf '%s' "$path"
}

# need_file <path> <where it comes from>: an input the job copies in, or an earlier step leaves.
need_file() {
  [[ -s "$1" ]] || fail "$1 is missing: $2"
}

# tenko ...: root's verified copy of the release binary.
tenko() {
  need_file "$MEDIA/tenko" "W0 places the verified release binary there"
  "$MEDIA/tenko" "$@"
}

# py <expression over v>: evaluates a Python expression over the JSON on standard input; a
# string is printed as it is, anything else as JSON.
py() {
  python3 -c "import json,sys
v=json.load(sys.stdin)
r=($1)
print(r if isinstance(r,str) else json.dumps(r, indent=1))"
}

# auth_config <admin|reader|session>: curl configuration lines with the credential, read on
# curl's standard input so that no secret is an argument.
auth_config() {
  case "$1" in
    admin)
      need_file "$TENKO_CREDENTIALS" "W0 signs the administrator in with tenko login"
      printf 'header = "Authorization: Bearer %s"\n' "$(py 'v["token"]' <"$TENKO_CREDENTIALS")"
      ;;
    reader)
      printf 'header = "Authorization: Bearer %s"\n' "$(<"$(secret tenko_reader_token)")"
      ;;
    session)
      printf 'cookie = "%s"\ncookie-jar = "%s"\n' "$SECRETS/session.cookies" "$SECRETS/session.cookies"
      ;;
    none) ;;
  esac
}

# api <auth> <method> <path> [<body file>]: one API request; the answer's body on standard
# output. An HTTP error prints the problem to the log and fails.
api() {
  local auth="$1" method="$2" path="$3" body="${4:-}" out
  local args=(-sS --fail-with-body --cacert "$CA" -K - -X "$method" -H "Origin: $TENKO_URL")
  [[ -z "$body" ]] || args+=(-H 'Content-Type: application/json' --data-binary "@$body")
  if ! out="$(auth_config "$auth" | curl "${args[@]}" "$TENKO_URL/api/v1$path")"; then
    printf 'API %s %s failed: %s\n' "$method" "$path" "$out" >&2
    return 1
  fi
  printf '%s' "$out"
}

# totp_code: a TOTP code of the administrator's seed for a time step after the last one used
# (the server refuses a step twice); waits up to 30 s for the next step.
totp_code() {
  local seed now last=0
  seed="$(secret tenko_admin_totp)"
  [[ -f "$LAB/totp-last-step" ]] && last="$(<"$LAB/totp-last-step")"
  now=$(($(date +%s) / 30))
  while ((now <= last)); do
    sleep 2
    now=$(($(date +%s) / 30))
  done
  printf '%s' "$now" >"$LAB/totp-last-step"
  python3 -c 'import base64,hashlib,hmac,struct,sys
seed=open(sys.argv[1]).read().strip().replace(" ","").upper()
key=base64.b32decode(seed+"="*(-len(seed)%8))
mac=hmac.new(key,struct.pack(">Q",int(sys.argv[2])),hashlib.sha1).digest()
o=mac[-1]&15
print("%06d"%((struct.unpack(">I",mac[o:o+4])[0]&0x7fffffff)%1000000))' "$seed" "$now"
}

# session_login: an interactive session of the administrator in the cookie jar: the password,
# then the TOTP code when the account has one. Routes that need an interactive session (the
# Kerberos adoption, the settings) use it; it ends with the step.
session_login() {
  local answer challenge code
  rm -f "$SECRETS/session.cookies"
  answer="$(api session POST /auth/login/password <(python3 -c 'import json,sys
print(json.dumps({"user_name":"admin","password":open(sys.argv[1]).read().rstrip("\n")}))' "$(secret tenko_admin_password)"))"
  [[ "$(py 'v["status"]' <<<"$answer")" == authenticated ]] && return 0
  challenge="$(py 'v["challenge_id"]' <<<"$answer")"
  [[ "$challenge" =~ ^[A-Za-z0-9_-]+$ ]] || fail "the sign-in answered an unexpected challenge id"
  [[ -s "$SECRETS/tenko_admin_totp" ]] ||
    fail "the administrator has a second factor, but $SECRETS/tenko_admin_totp (written by W0) is missing"
  code="$(totp_code)"
  answer="$(api session POST /auth/login/totp <(printf '{"challenge_id":"%s","code":"%s"}' "$challenge" "$code"))"
  [[ "$(py 'v["status"]' <<<"$answer")" == authenticated ]] || fail "the TOTP code was not accepted"
}

# tenko_read ...: a tenko command with the lab reader's token (a viewer service account with
# the metrics and audit:read scopes, created in W0), which still acts under Hardened.
tenko_read() {
  local token
  token="$(<"$(secret tenko_reader_token)")"
  TENKO_TOKEN="$token" tenko "$@"
}

# zone_id <zone>: the zone's identifier.
zone_id() { tenko_read dns zone get "$1" --json | py 'v["id"]'; }

# audit <action> <since> <file>: the audit records of one action since a time, newest first,
# written to the file.
audit() {
  api reader GET "/audit?action=$1&from=$2&limit=200" >"$3"
}

# audit_count <file>: how many records a page of audit records holds.
audit_count() { py 'str(len(v["items"]))' <"$1"; }

# signed_refusals <file>: how many refusal records are of a signed update. A Windows machine
# first sends each update unsigned and is refused, then negotiates a key and sends it again:
# only the unsigned refusal is expected. Its record has the key `none`; a refusal of an
# update signed with GSS-TSIG names the principal and has no key, one signed with TSIG names
# its key, so every record but those with the key `none` counts.
signed_refusals() {
  py 'str(len([i for i in v["items"] if (i.get("context") or {}).get("key") != "none"]))' <"$1"
}

# mentions <file> <text>...: how many audit records of the file contain every text.
mentions() {
  python3 - "$@" <<'EOF'
import json, sys
items = json.load(open(sys.argv[1]))["items"]
print(sum(all(t in json.dumps(i) for t in sys.argv[2:]) for i in items))
EOF
}

# owners <zone> <file>: the owners of the zone's names, written to the file.
owners() {
  api reader GET "/dns/zones/$(zone_id "$1")/owners?limit=1000" >"$2"
}

# owned_by <owners file> <name> <account> <how>: the name is owned by the account (DC1$),
# which got it this way (created, claimed, assigned, imported); fails with the reason.
owned_by() {
  python3 - "$@" <<'EOF' || fail "$2 is not owned by $3 ($4) ($(basename "$1"))"
import json, sys
path, name, account, how = sys.argv[1:5]
rows = [i for i in json.load(open(path))["items"] if i["name"].rstrip(".").lower() == name.lower()]
ok = any(i["principal"].split("@")[0].upper() == account.upper() and i["how"] == how for i in rows)
print("%s: %s" % (name, rows))
sys.exit(0 if ok else 1)
EOF
}

# assert_clock: ns1 follows dc1's clock (systemd-timesyncd with NTP=192.0.2.5, set by W0);
# Kerberos allows five minutes, so a node that is not synchronized to dc1 stops the step.
assert_clock() {
  local i
  # A try made before dc1 served time may be waiting out its backoff: ask again now.
  [[ "$(timedatectl show -p NTPSynchronized --value)" == yes ]] || systemctl restart systemd-timesyncd
  for ((i = 0; i < 24; i++)); do
    if [[ "$(timedatectl show -p NTPSynchronized --value)" == yes &&
      "$(timedatectl show-timesync -p ServerAddress --value 2>/dev/null)" == 192.0.2.5 ]]; then
      return 0
    fi
    sleep 5
  done
  timedatectl timesync-status >"$STEP_DIR/timesync.txt" 2>&1 || true
  journalctl -u systemd-timesyncd -b --no-pager -n 40 >>"$STEP_DIR/timesync.txt" 2>&1 || true
  fail "ns1 is not synchronized to dc1 (192.0.2.5) after two minutes; timesync.txt has the state"
}
