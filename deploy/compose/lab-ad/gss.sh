#!/usr/bin/env bash
# The round gss of the AD lab (E43; identity plan section 3.19): secure dynamic updates
# with GSS-TSIG against a Tenko node that is the primary of lab.example.test and
# _msdcs.lab.example.test, both set to secure only with the Windows ownership rules.
#
# What it does, printing one PASS or FAIL line per row and a summary at the end:
#   1. builds the image tenko:lab from the repository (docker build -f deploy/Dockerfile)
#      unless TENKO_IMAGE names an image that exists, and the images of the controller and
#      the client from this directory;
#   2. generates the secrets of the run into a work directory: the controller's
#      administrator password, the passwords of the users alice and bob, the key-encryption
#      key of the node; writes the lab's krb5.conf and the node's tenko.toml;
#   3. starts the node, sets it up through its API under the Lab profile (from the client
#      container: a Docker Desktop host does not reach the lab network), starts the
#      controller (Samba provisions LAB.EXAMPLE.TEST without its own DNS) and the client;
#   4. creates the users and Tenko's computer account TENKO-DNS$ with the SPN
#      DNS/ns1.lab.example.test and AES only, exports its keytab with samba-tool, and
#      imports it into the node (POST /dns/kerberos/import, what `tenko dns kerberos
#      import` sends; the route is interactive, so the round signs in rather than using a
#      token);
#   5. creates the access list of the realm and the two zones, secure only, ownership on,
#      the controllers' and the domain admins' groups privileged (their SIDs read from the
#      controller);
#   6. runs the rows of E43 (README.md lists them): the controller's samba_dnsupdate, the
#      client's nsupdate -g over UDP and TCP, and gss_client.py for mutual authentication,
#      the signatures of the answers, BADKEY on an unknown and an expired context, BADTIME,
#      a replay and an NTLM-only offer; then the rows of E46 that a Samba controller can
#      exercise: the controller owns its host name, a domain administrator changes a name
#      it does not own, a Windows zone file's dynamic record is claimed by its own host
#      and its static record is not, the owner view, a release and a reassignment;
#   7. tears everything down (containers, volumes, network, work directory), also when a
#      step fails, after printing the logs of the services. KEEP=1 leaves the lab running.
#
# Needs: bash, Docker with the compose plugin (and buildx for the image build), od, base64.
# Run it from the repository root:
#   bash deploy/compose/lab-ad/gss.sh
#   TENKO_IMAGE=tenko:lab bash deploy/compose/lab-ad/gss.sh     # skip the Tenko build
#   KEEP=1 bash deploy/compose/lab-ad/gss.sh                     # keep the lab
# On Windows (Git Bash with Docker Desktop) the work directory is passed to Docker in its
# Windows form; LAB_TMP chooses where it is made (default: the temporary directory).
#
# The containers talk to each other on the bridge network 198.51.100.0/24 and to nothing
# else; only the image builds reach out.
set -euo pipefail
export MSYS_NO_PATHCONV=1

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
compose_file="$here/compose.yml"
docker_repo="$repo"
# Git Bash: Docker takes Windows paths (MSYS_NO_PATHCONV keeps container paths as written).
if command -v cygpath >/dev/null 2>&1; then
  compose_file="$(cygpath -m "$compose_file")"
  docker_repo="$(cygpath -m "$repo")"
fi
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-tenkoadlab}"
keep="${KEEP:-0}"
wait_secs="${WAIT_SECS:-300}"
tenko_ip=198.51.100.3
realm=LAB.EXAMPLE.TEST
spn=DNS/ns1.lab.example.test
api_base="http://$tenko_ip:8443"

work=""
summary=()
failed=0

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'gss: %s\n' "$*" >&2; exit 1; }
compose() { docker compose -f "$compose_file" "$@"; }

cleanup() {
  local status=$?
  set +e
  trap - EXIT
  if ((status != 0 || failed != 0)); then
    printf '\n==> logs of the services\n' >&2
    for service in tenko samba client; do
      printf '\n--- %s ---\n' "$service" >&2
      compose logs --no-color --tail 150 "$service" >&2 2>&1
    done
  fi
  if ((${#summary[@]} > 0)); then
    printf '\n==> summary\n'
    printf '%s\n' "${summary[@]}"
  fi
  if ((status == 0 && failed != 0)); then
    status=1
  fi
  if [[ "$keep" == 1 ]]; then
    printf '\n==> KEEP=1: the lab keeps running; tear it down with:\n'
    printf '    LAB_DIR=%s docker compose -f %s down --volumes\n' "$LAB_DIR" "$compose_file"
    exit "$status"
  fi
  printf '\n==> tear down\n'
  compose down --volumes --remove-orphans --timeout 30 >/dev/null 2>&1
  [[ -n "$work" ]] && rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

# row <id> <description> <command...>: one PASS or FAIL line.
row() {
  local id="$1" what="$2" line
  shift 2
  if "$@"; then
    line="$(printf 'PASS  %-22s %s' "$id" "$what")"
  else
    line="$(printf 'FAIL  %-22s %s' "$id" "$what")"
    failed=1
  fi
  summary+=("$line")
  printf '%s\n' "$line"
}

# retry <seconds> <description> <command...>
retry() {
  local limit="$1" what="$2" waited=0
  shift 2
  until "$@" >/dev/null 2>&1; do
    ((waited >= limit)) && fail "timed out after ${limit}s waiting for: $what"
    sleep 2
    waited=$((waited + 2))
  done
}

random_digits() { od -An -N8 -tu8 /dev/urandom | tr -dc '0-9'; }
# A password Samba's default policy takes, generated per run.
random_password() { printf 'Lab-%s-Aa1' "$(od -An -N9 -tx1 /dev/urandom | tr -d ' \n')"; }

# --- 1. images -------------------------------------------------------------------------
step "images"
export TENKO_IMAGE="${TENKO_IMAGE:-tenko:lab}"
if ! docker image inspect "$TENKO_IMAGE" >/dev/null 2>&1; then
  docker build -f "$docker_repo/deploy/Dockerfile" -t "$TENKO_IMAGE" "$docker_repo"
fi

# --- 2. the work directory -------------------------------------------------------------
step "the work directory"
work="$(mktemp -d "${LAB_TMP:-${TMPDIR:-/tmp}}/tenko-adlab.XXXXXX")"
LAB_DIR="$work"
if command -v cygpath >/dev/null 2>&1; then
  LAB_DIR="$(cygpath -m "$work")"
fi
export LAB_DIR
mkdir -p "$work/secrets" "$work/out"
random_password >"$work/secrets/admin"
random_password >"$work/secrets/alice"
random_password >"$work/secrets/bob"
# WP13.4: the computer accounts of the E46 rows: WSBOB$ (a dynamic record of the Windows
# file) and SRV01$ (a static one).
random_password >"$work/secrets/wsbob"
random_password >"$work/secrets/srv01"
head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n' >"$work/secrets/kek"
chmod 0444 "$work/secrets/"*
cat >"$work/secrets/krb5.conf" <<'KRB5'
# The lab's Kerberos configuration (written by gss.sh): the controller as the KDC by
# address, no reverse lookups, TCP for the tickets with a PAC.
[libdefaults]
    default_realm = LAB.EXAMPLE.TEST
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
    dns_canonicalize_hostname = false
    udp_preference_limit = 1
[realms]
    LAB.EXAMPLE.TEST = {
        kdc = 198.51.100.2
        admin_server = 198.51.100.2
        kpasswd_server = 198.51.100.2
    }
[domain_realm]
    .lab.example.test = LAB.EXAMPLE.TEST
    lab.example.test = LAB.EXAMPLE.TEST
KRB5
cat >"$work/tenko.toml" <<'TOML'
# The configuration of the round gss (written by gss.sh).
roles = "controller,dns"
modules = ["ipam", "dns"]

[profile]
# The Lab profile: plain HTTP for the API on the lab network.
name = "lab"

[tls]
mode = "plain"

[server]
listen = ["0.0.0.0:8443"]

[dns]
listen = ["0.0.0.0:53"]

[dns.recursion]
enabled = false

[dns.gss]
# The shortest lifetime, so that the row of an expired context runs in a minute.
context_max_secs = 60
TOML
chmod 0444 "$work/secrets/krb5.conf" "$work/tenko.toml"

# --- 3. the node, its setup, the controller and the client ------------------------------
step "the node"
compose build samba client
compose up -d tenko client
healthy() { [[ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q tenko)")" == healthy ]]; }
retry "$wait_secs" "tenko to become healthy" healthy

cookie=""
# in_client <command...>: runs a command in the client container.
in_client() { compose exec -T client "$@"; }
# The client's Kerberos configuration is the lab's (the controller reads the same file).
in_client sh -c 'cat >/etc/krb5.conf' <"$work/secrets/krb5.conf"
# api <method> <path> [<json>]: a request to the node's API from the client container with
# the session; prints the body, returns 0 for a 2xx status, leaves the status in $api_status.
api() {
  local method="$1" path="$2" body="${3:-}" out
  out="$(in_client sh -c 'cat >/tmp/body; curl -sS -o /tmp/out -w "%{http_code}" "$@"; echo; cat /tmp/out' curl \
    -X "$method" -H "Origin: $api_base" -H "Idempotency-Key: $(cat /proc/sys/kernel/random/uuid 2>/dev/null || random_digits)" \
    ${cookie:+-H "Cookie: $cookie"} ${body:+-H "Content-Type: application/json" --data @/tmp/body} \
    "$api_base/api/v1$path" <<<"$body")"
  api_status="$(head -n 1 <<<"$out")"
  api_body="$(tail -n +2 <<<"$out")"
  printf '%s' "$api_body"
  [[ "$api_status" == 2* ]]
}
json_field() { in_client python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

token="$(compose exec -T tenko /usr/local/bin/tenko setup token --data-dir /var/lib/tenko | tr -d '\r\n')"
[[ -n "$token" ]] || fail "no setup token"
admin_pin="$(random_digits)"
setup="{\"setup_token\": \"$token\", \"profile\": \"lab\", \"admin\": {\"name\": \"labadmin\", \"display_name\": \"Lab Admin\", \"password\": \"$admin_pin\"}, \"host_name\": \"ns1.lab.example.test\", \"language\": \"en\"}"
cookie="$(in_client curl -sS -D - -o /dev/null -H "Origin: $api_base" -H "Content-Type: application/json" \
  --data "$setup" "$api_base/api/v1/setup" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \(tenko_session=[^;]*\).*/\1/p' | head -n 1)"
[[ -n "$cookie" ]] || fail "the setup did not sign in"
printf 'the node is set up under the Lab profile\n'

step "the controller"
compose up -d samba
kdc_up() { compose exec -T samba bash -c 'exec 3<>/dev/tcp/127.0.0.1/88'; }
retry "$wait_secs" "the controller's KDC" kdc_up
samba() { compose exec -T samba "$@"; }
samba samba-tool domain passwordsettings set --complexity=off --min-pwd-age=0 --history-length=0 >/dev/null
samba samba-tool user create alice "$(cat "$work/secrets/alice")" >/dev/null
samba samba-tool user create bob "$(cat "$work/secrets/bob")" >/dev/null
samba samba-tool computer create TENKO-DNS >/dev/null
for host in wsbob srv01; do
  samba samba-tool computer create "${host^^}" >/dev/null
  samba samba-tool user setpassword "${host^^}\$" --newpassword="$(cat "$work/secrets/$host")" >/dev/null
done
samba samba-tool spn add "$spn" 'TENKO-DNS$' >/dev/null
samba bash -c 'base=$(ldbsearch -H /var/lib/samba/private/sam.ldb "(sAMAccountName=TENKO-DNS\$)" dn | sed -n "s/^dn: //p")
printf "dn: %s\nchangetype: modify\nreplace: msDS-SupportedEncryptionTypes\nmsDS-SupportedEncryptionTypes: 24\n" "$base" | ldbmodify -H /var/lib/samba/private/sam.ldb >/dev/null'
samba samba-tool user setpassword 'TENKO-DNS$' --newpassword="$(random_password)" >/dev/null
samba samba-tool domain exportkeytab /lab/out/tenko.keytab --principal='TENKO-DNS$' >/dev/null
[[ -s "$work/out/tenko.keytab" ]] || fail "the controller wrote no keytab"
sid_of() { samba samba-tool group show "$1" --attributes=objectSid | sed -n 's/^objectSid: //p' | tr -d '\r'; }
dc_sid="$(sid_of 'Domain Controllers')"
admins_sid="$(sid_of 'Domain Admins')"
[[ "$dc_sid" == S-1-5-21-*-516 && "$admins_sid" == S-1-5-21-*-512 ]] || fail "the group SIDs ($dc_sid, $admins_sid)"
printf 'the controller is up; Domain Controllers %s\n' "$dc_sid"

# --- 4. the account's keys on the node -------------------------------------------------
step "the account's keys"
keytab="$(base64 -w0 <"$work/out/tenko.keytab" | tr '+/' '-_' | tr -d '=')"
if api POST /dns/kerberos/import "{\"realm\": \"$realm\", \"keytab\": \"$keytab\", \"spns\": [\"$spn\"]}" >/dev/null; then
  printf 'the keytab of TENKO-DNS$ is imported\n'
else
  row gss.keys "the account's keytab is imported (POST /dns/kerberos/import answered $api_status)" false
  fail "the node takes no account keys yet (the route answered $api_status); the rows need them"
fi

# --- 5. the zones ----------------------------------------------------------------------
step "the zones"
api POST /dns/acls "{\"name\": \"ad-lab\", \"entries\": [{\"kind\": \"kerberos\", \"realm\": \"$realm\"}]}" >/dev/null ||
  fail "the access list ($api_status: $api_body)"
acl="$(json_field "d['id']" <<<"$api_body")"
kerberos="{\"realms\": [\"$realm\"], \"ownership\": \"windows\", \"privileged\": [\"$dc_sid\", \"$admins_sid\"]}"
soa='{"mname": "ns1.lab.example.test", "rname": "hostmaster.lab.example.test", "refresh": 900, "retry": 300, "expire": 86400, "minimum": 60, "ttl": 3600}'
for zone in lab.example.test _msdcs.lab.example.test; do
  api POST /dns/zones "{\"name\": \"$zone\", \"kind\": \"primary\", \"serial\": \"counter\", \"soa\": $soa, \"name_servers\": [\"ns1.lab.example.test\"], \"update\": {\"allowed\": [\"$acl\"], \"require_tsig\": true, \"may_replace_ipam\": false, \"kerberos\": $kerberos}}" >/dev/null ||
    fail "the zone $zone ($api_status: $api_body)"
  [[ "$zone" == lab.example.test ]] && zone_id="$(json_field "d['id']" <<<"$api_body")"
done
api POST "/dns/zones/$zone_id/records/batch" '{"changes": [{"op": "set", "name": "ns1.lab.example.test", "type": "A", "ttl": 3600, "records": [{"type": "A", "address": "198.51.100.3"}]}]}' >/dev/null ||
  fail "the name server's address ($api_status: $api_body)"

# --- 6. the rows -----------------------------------------------------------------------
step "the rows of E43"
dig_short() { in_client dig "@$tenko_ip" +time=3 +tries=1 +short "$@"; }
rcode_of() { in_client dig "@$tenko_ip" +time=3 +tries=1 "$@" | sed -n 's/^;; ->>HEADER<<- .*status: \([A-Z]*\),.*/\1/p' | head -n 1; }
kinit_as() { in_client sh -c "kinit $1 </lab/secrets/$1 >/dev/null"; }
# nsupdate_g <commands> [<options>]: nsupdate -g in the client with its ticket; the server
# comes from the zone's SOA, as a Windows client finds it.
nsupdate_g() {
  local commands="$1"
  shift
  printf 'zone lab.example.test\n%s\nsend\n' "$commands" | in_client nsupdate "$@" 2>&1
}
gss_client() { in_client python3 /lab/gss_client.py "$@" 2>&1; }

dc_registers() {
  samba samba_dnsupdate --verbose --all-names >"$work/dnsupdate.log" 2>&1 &&
    [[ -n "$(dig_short _ldap._tcp.lab.example.test SRV)" ]] &&
    [[ -n "$(dig_short dc01.lab.example.test A)" ]]
}
negotiates() { [[ "$(gss_client negotiate)" == "established=1 legs=1 mutual=1 verified=1" ]]; }
adds_udp() {
  nsupdate_g "update add ws-alice.lab.example.test 60 IN A 198.51.100.41" -g >/dev/null &&
    [[ "$(dig_short ws-alice.lab.example.test A)" == 198.51.100.41 ]]
}
replaces() {
  nsupdate_g "prereq yxrrset ws-alice.lab.example.test A
update delete ws-alice.lab.example.test A
update add ws-alice.lab.example.test 60 IN A 198.51.100.42" -g >/dev/null &&
    [[ "$(dig_short ws-alice.lab.example.test A)" == 198.51.100.42 ]]
}
adds_tcp() {
  nsupdate_g "update add ws-tcp.lab.example.test 60 IN A 198.51.100.43" -g -v >/dev/null &&
    [[ "$(dig_short ws-tcp.lab.example.test A)" == 198.51.100.43 ]]
}
deletes() {
  nsupdate_g "update delete ws-tcp.lab.example.test" -g >/dev/null &&
    [[ "$(rcode_of ws-tcp.lab.example.test A)" == NXDOMAIN ]]
}
unsigned_refused() {
  grep -q REFUSED <<<"$(nsupdate_g "update add anon.lab.example.test 60 IN A 198.51.100.50" || true)" &&
    [[ -z "$(dig_short anon.lab.example.test A)" ]]
}
second_refused() {
  kinit_as bob &&
    grep -q REFUSED <<<"$(nsupdate_g "update add ws-alice.lab.example.test 60 IN A 198.51.100.44" -g || true)" &&
    ! grep -q 198.51.100.44 <<<"$(dig_short ws-alice.lab.example.test A)"
}
expect_client() { local want="$1"; shift; [[ "$(gss_client "$@")" == "$want" ]]; }

row gss.dc "the controller's samba_dnsupdate registers its records with nsupdate -g (the SRV and A records answer)" dc_registers
kinit_as alice
row gss.mutual "TKEY completes with mutual authentication; the answer is signed and verifies at the client" negotiates
row gss.add.udp "nsupdate -g adds ws-alice over UDP; the next query answers it" adds_udp
row gss.replace "prereq yxrrset, delete and add in one signed update replace the address" replaces
row gss.add.tcp "nsupdate -g -v adds ws-tcp over TCP" adds_tcp
row gss.delete "a signed update deletes ws-tcp: NXDOMAIN at once" deletes
row gss.unsigned "an unsigned update is REFUSED" unsigned_refused
row gss.badkey "an update signed on a context the node never held is NOTAUTH with BADKEY" \
  expect_client "rcode=9 tsig_error=17 verified=0" update ws-alice.lab.example.test 198.51.100.45 --key-name unknown.lab.example.test
row gss.badtime "an update signed 600 s in the past is NOTAUTH with BADTIME" \
  expect_client "rcode=9 tsig_error=18 verified=1" update ws-alice.lab.example.test 198.51.100.45 --skew -600
row gss.replay "a signed update sent twice is applied once; the replay is NOTAUTH with BADSIG" \
  expect_client "rcode=0 tsig_error=0 verified=1 | rcode=9 tsig_error=16 verified=0" update ws-alice.lab.example.test 198.51.100.46 --twice
row gss.expired "an update on a context past its lifetime (60 s) is NOTAUTH with BADKEY" \
  expect_client "rcode=9 tsig_error=17 verified=0" update ws-alice.lab.example.test 198.51.100.47 --wait 65
row gss.second "a second principal (bob) is REFUSED on the name alice owns" second_refused
row gss.ntlm "a TKEY offer of NTLM alone is refused (BADKEY)" expect_client "rcode=0 tkey_error=17" ntlm

# --- 7. the rows of E46 (WP13.4) -------------------------------------------------------
step "the rows of E46"
# kinit_computer <host>: a ticket as the computer account HOST$ with its password.
kinit_computer() { in_client sh -c "kinit '${1^^}\$@$realm' </lab/secrets/$1 >/dev/null"; }
kinit_admin() { in_client sh -c "kinit administrator@$realm </lab/secrets/admin >/dev/null"; }
refused_update() { grep -q REFUSED <<<"$(nsupdate_g "$1" -g || true)"; }
owners() { api GET "/dns/zones/$zone_id/owners" >/dev/null && printf '%s' "$api_body"; }
# owner_of <name>: "principal how" of the name's owner, or nothing.
owner_of() {
  owners | json_field "' '.join(next(((i['principal'] + ' ' + i['how']) for i in d['items'] if i['name'] == '$1'), '').split())"
}
sid_of_user() { samba samba-tool user show "$1" --attributes=objectSid | sed -n 's/^objectSid: //p' | tr -d '\r'; }

dc_owns_its_host() { [[ "$(owner_of dc01.lab.example.test)" == "DC01\$@$realm created" ]]; }
dc_refreshes() { samba samba_dnsupdate --all-names >"$work/dnsupdate2.log" 2>&1 && dc_owns_its_host; }
user_refused_on_dc() {
  kinit_as alice && refused_update "update add dc01.lab.example.test 60 IN A 198.51.100.66" &&
    [[ "$(dig_short dc01.lab.example.test A)" != *198.51.100.66* ]]
}
user_refused_on_locator() {
  kinit_as alice && refused_update "update add _ldap._tcp.lab.example.test 600 IN SRV 0 100 389 ws-alice.lab.example.test."
}
admin_changes() {
  kinit_admin && nsupdate_g "update add ws-alice.lab.example.test 60 IN A 198.51.100.48" -g >/dev/null &&
    grep -q 198.51.100.48 <<<"$(dig_short ws-alice.lab.example.test A)" &&
    [[ "$(owner_of ws-alice.lab.example.test)" == "alice@$realm created" ]]
}
# The Windows file: wsbob dynamic (an aging mark), srv01 static.
windows_file='wsbob [AGE:3660412] 60 A 198.51.100.61\nsrv01 60 A 198.51.100.62\n'
imports_windows() {
  api POST "/dns/zones/$zone_id/records/import" "{\"zone_file\": \"$windows_file\", \"dialect\": \"windows\"}" >/dev/null &&
    for _ in $(seq 1 30); do
      [[ "$(dig_short wsbob.lab.example.test A)" == 198.51.100.61 && "$(dig_short srv01.lab.example.test A)" == 198.51.100.62 ]] && return 0
      sleep 1
    done
  return 1
}
other_cannot_claim() { kinit_as bob && refused_update "update add wsbob.lab.example.test 60 IN A 198.51.100.66"; }
host_claims() {
  kinit_computer wsbob && nsupdate_g "update add wsbob.lab.example.test 60 IN A 198.51.100.63" -g >/dev/null &&
    [[ "$(owner_of wsbob.lab.example.test)" == "WSBOB\$@$realm claimed" ]]
}
static_not_claimed() { kinit_computer srv01 && refused_update "update add srv01.lab.example.test 60 IN A 198.51.100.64"; }
releases() {
  api DELETE "/dns/zones/$zone_id/owners/ws-alice.lab.example.test" >/dev/null &&
    [[ -z "$(owner_of ws-alice.lab.example.test)" ]] &&
    kinit_as bob && refused_update "update add ws-alice.lab.example.test 60 IN A 198.51.100.65"
}
reassigns() {
  local bob_sid
  bob_sid="$(sid_of_user bob)"
  api PUT "/dns/zones/$zone_id/owners/ws-alice.lab.example.test" "{\"principal\": \"bob@$realm\", \"sid\": \"$bob_sid\"}" >/dev/null &&
    kinit_as bob && nsupdate_g "update add ws-alice.lab.example.test 60 IN A 198.51.100.65" -g >/dev/null &&
    [[ "$(owner_of ws-alice.lab.example.test)" == "bob@$realm assigned" ]]
}

row own.dc_host "the controller owns the host name it registered (the owner view: DC01\$, created)" dc_owns_its_host
row own.dc_refresh "the controller's next registration refreshes its names; the owner stays" dc_refreshes
row own.dc_refused "a user cannot change the controller's host record" user_refused_on_dc
row own.locator "a user cannot write a locator name (_ldap._tcp)" user_refused_on_locator
row own.admin "a domain administrator changes a name it does not own; the owner stays alice" admin_changes
row own.import "a Windows zone file imports: wsbob (aging mark) and srv01 (static) answer" imports_windows
row own.claim_other "another principal cannot claim the imported dynamic name" other_cannot_claim
row own.claim "WSBOB\$ claims its own imported name and owns it (claimed)" host_claims
row own.static "SRV01\$ cannot claim its static record" static_not_claimed
row own.release "a released name is not open to another principal" releases
row own.assign "the name reassigned to bob with his SID: bob changes it and owns it (assigned)" reassigns
