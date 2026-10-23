#!/usr/bin/env bash
# Smoke test of the compose DNS lab (deploy/compose/lab-dns, WP5.1 deliverable 6: BIND 9
# as the upstream of one Tenko node over plain DNS, DNS over TLS and DNS over HTTPS).
#
# What it does, printing one summary line per step at the end:
#   1. builds the image tenko:lab from the repository (docker build -f deploy/Dockerfile),
#      unless IMAGE=<tag> names an image that exists already;
#   2. generates a lab CA and the BIND certificate (bind.example.test, 203.0.113.2) with
#      openssl, and a key-encryption key, into a temporary work directory;
#   3. starts BIND and the client, and asks BIND directly over plain DNS, DNS over TLS and
#      DNS over HTTPS (dig +tls and dig +https from the client container);
#   4. three rounds, one per transport (plain, dot, doh): writes the configuration file of
#      the round (the default forwarder is BIND over that transport), recreates the tenko
#      container on it with the same data volume, waits for it to answer, and checks
#        - www.example.test resolves to 192.0.2.10, and the second answer, two seconds
#          later, has a lower TTL while BIND saw one query only: it came from the cache;
#        - nohost.example.test is NXDOMAIN twice, the second from the cache;
#        - BIND saw the queries of Tenko over UDP (plain) or over a stream (dot, doh);
#   5. in the doh round: lets the cached entry expire, cuts BIND off the lab network with
#      docker network disconnect, checks that Tenko still answers www.example.test within
#      3 s with the stale TTL of RFC 8767 (30 s), connects BIND again and checks that a
#      fresh answer (TTL of at most 5 s) comes back;
#   5b. the round xfr (WP6.1): sets Tenko up through its API, and checks the zone transfers
#      both ways, one PASS or FAIL line per row (README.md lists them): BIND as the
#      secondary of Tenko's zones (AXFR with TSIG, dig -y, NOTIFY and IXFR, XoT, the catalog
#      zone) and Tenko as the secondary of BIND's (the same, plus the read-only rule and
#      the transfer state of the API);
#   5c. the round update (WP6.2): nsupdate from the client container changes a zone of
#      Tenko with TSIG (add, prerequisites, replace, TCP, delete) and dig sees each change at
#      once; an update without the key, one with a wrong secret and one of an address IPAM
#      manages are refused; one PASS or FAIL line per row (README.md lists them);
#   5d. the round recursion (WP10.1, recursion.sh; ROUNDS=recursion): a second Tenko node
#      serves the lab's own root, the TLD test and the zones under it, the quirk responders
#      misbehave beside it, and the node under test resolves iteratively from the lab root,
#      one PASS or FAIL line per row of E36 and E41 with the queries sent per case (M40);
#   6. tears everything down (containers, volumes, network, work directory), also when a
#      step fails, after printing the logs of every service. KEEP=1 leaves the lab running.
#
# Needs: bash, Docker with the compose plugin (and buildx for the build), and openssl on the
# host; the round xfr also curl and python3 on the host (the host reaches the lab network).
# Run it from the repository root without arguments:
#   bash deploy/compose/lab-dns/smoke.sh
#   IMAGE=tenko:lab bash deploy/compose/lab-dns/smoke.sh     # skip the build
#   KEEP=1 bash deploy/compose/lab-dns/smoke.sh              # keep the lab for hand tests
#
# The containers talk to each other on the bridge network 203.0.113.0/24 (documentation
# addresses) and to nothing else; nothing is published on the host. Only the image build and
# the first pull of the BIND image reach out.
#
# Settings (environment, all optional):
#   IMAGE           an existing Tenko image to test; default: build tenko:lab
#   BIND_IMAGE      the BIND image, for the server and for dig (default
#                   internetsystemsconsortium/bind9:9.20)
#   ROUNDS          the rounds to run, in order (default "plain dot doh xfr update"); the
#                   serve-stale steps run after the round doh, the transfer rows in xfr,
#                   the update rows in update (alone, it sets Tenko up itself); the round
#                   recursion (WP10.1) runs only when named, best alone
#   QUIRK_IMAGE     an existing image of the quirk responders for the round recursion;
#                   default: build tenko-quirk:lab from deploy/compose/lab-dns/quirk.Dockerfile
#   WAIT_SECS       how long to wait for Tenko to become healthy (default 300)
#   KEEP            1: do not tear the lab down at the end, also after a failure
#                   (README.md says how to later)

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
compose_file="$here/compose.yml"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-tenkodnslab}"
if [[ -n "${BIND_IMAGE:-}" ]]; then
  export BIND_IMAGE
fi
rounds="${ROUNDS:-plain dot doh xfr update}"
wait_secs="${WAIT_SECS:-300}"
keep="${KEEP:-0}"
network="${COMPOSE_PROJECT_NAME}_lab"
bind_ip=203.0.113.2
tenko_ip=203.0.113.3
dns_port=5300
# The TTL of every record in the zone, which is also its negative TTL.
zone_ttl=5
# The stale TTL of RFC 8767, and how long a client may wait for a stale answer.
stale_ttl=30
stale_limit_ms=3000
# The round xfr: Tenko's DoT and XoT port, the TSIG key of the run, the API.
xot_port=8530
xfr_key=xfr.example.test
# The round update (WP6.2): the TSIG key of nsupdate.
upd_key=update.example.test
api_base="http://$tenko_ip:8443"

built_here=0
if [[ -n "${IMAGE:-}" ]]; then
  export TENKO_IMAGE="$IMAGE"
else
  export TENKO_IMAGE=tenko:lab
  built_here=1
fi

work=""
status=0
summary=()

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'smoke: %s\n' "$*" >&2; exit 1; }
ok() {
  local line
  line="$(printf 'ok  %-30s %s' "$1" "$2")"
  summary+=("$line")
  printf '%s\n' "$line"
}
compose() { docker compose -f "$compose_file" "$@"; }
# WP10.1: the round recursion.
# shellcheck source=deploy/compose/lab-dns/recursion.sh
source "$here/recursion.sh"
# WP10.2: the validation rows of the round recursion (E33) and the round rfc5011 (E34).
# shellcheck source=deploy/compose/lab-dns/validation.sh
source "$here/validation.sh"

# retry <seconds> <description> <command...>: runs the command every 2 seconds until it
# succeeds or the time is up.
retry() {
  local limit="$1" what="$2" waited=0
  shift 2
  until "$@" >/dev/null 2>&1; do
    if ((waited >= limit)); then
      fail "timed out after ${limit}s waiting for: $what"
    fi
    sleep 2
    waited=$((waited + 2))
  done
}

cleanup() {
  status=$?
  set +e
  trap - EXIT
  if ((status != 0)); then
    printf '\n==> FAILED (status %s): logs of the services\n' "$status" >&2
    for service in bind tenko client authority quirk-noedns quirk-case quirk-tc quirk-slow quirk-spoof quirk-oob quirk-sub; do
      printf '\n--- %s ---\n' "$service" >&2
      compose logs --no-color --tail 200 "$service" >&2 2>&1
    done
    docker ps -a --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" >&2 2>&1
    if [[ -n "$work" && -f "$work/tenko.toml" ]]; then
      printf '\n--- tenko.toml of the last round ---\n' >&2
      cat "$work/tenko.toml" >&2
    fi
  fi
  if ((${#summary[@]} > 0)); then
    printf '\n==> summary\n'
    printf '%s\n' "${summary[@]}"
  fi
  if [[ "$keep" == 1 ]]; then
    printf '\n==> KEEP=1: the lab keeps running; ask Tenko with\n'
    printf '    LAB_DIR=%s docker compose -f %s exec client dig @%s -p %s www.example.test\n' \
      "$work" "$compose_file" "$tenko_ip" "$dns_port"
    printf 'tear it down with: LAB_DIR=%s docker compose -f %s down --volumes\n' \
      "$work" "$compose_file"
    exit "$status"
  fi
  printf '\n==> tear down\n'
  compose --profile recursion down --volumes --remove-orphans --timeout 30 >/dev/null 2>&1
  if [[ -n "$work" ]]; then
    rm -rf "$work"
  fi
  exit "$status"
}
trap cleanup EXIT

# make_certificates <work dir>: the lab CA (ca.pem) and the certificate of BIND (bind.pem
# and bind.key) for bind.example.test and 203.0.113.2, in <work dir>/tls.
make_certificates() {
  local dir="$1"
  (
    cd "$dir/tls"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
      -subj "/CN=Tenko DNS lab CA" -keyout ca.key -out ca.pem \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -subj "/CN=bind.example.test" -keyout bind.key -out bind.csr 2>/dev/null
    printf '%s\n' \
      "subjectAltName=DNS:bind.example.test,IP:203.0.113.2" \
      "basicConstraints=critical,CA:FALSE" \
      "keyUsage=critical,digitalSignature" \
      "extendedKeyUsage=serverAuth" >bind.ext
    openssl x509 -req -in bind.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
      -extfile bind.ext -out bind.pem 2>/dev/null
    # Tenko's certificate for DoT and XoT in the round xfr.
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -subj "/CN=tenko.example.test" -keyout tenko.key -out tenko.csr 2>/dev/null
    printf '%s\n' \
      "subjectAltName=DNS:tenko.example.test,IP:203.0.113.3" \
      "basicConstraints=critical,CA:FALSE" \
      "keyUsage=critical,digitalSignature" \
      "extendedKeyUsage=serverAuth" >tenko.ext
    openssl x509 -req -in tenko.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
      -extfile tenko.ext -out tenko.pem 2>/dev/null
    rm -f ca.key bind.csr bind.ext tenko.csr tenko.ext ca.srl
    # named drops to the user bind and Tenko runs as 65532; neither is the owner. The work
    # directory itself is private to this user.
    chmod 0444 ca.pem bind.pem bind.key tenko.pem tenko.key
  )
}

# write_config <plain|dot|doh>: tenko.toml of a round in the work directory. The default
# forwarder is BIND over one transport; the cache is the default one, except that prefetch
# is off, so that an entry really expires and the serve-stale step has something to do.
write_config() {
  local forwarder tls=""
  case "$1" in
    plain) forwarder="{ address = \"$bind_ip\", transport = \"udp\" }" ;;
    xfr)
      forwarder="{ address = \"$bind_ip\", transport = \"udp\" }"
      tls="
[dns.tls]
# DNS over TLS and zone transfers over TLS (XoT) with the lab certificate.
dot = true
dot_listen = [\"0.0.0.0:$xot_port\"]
certificate = \"/lab/tenko.pem\"
key = \"/lab/tenko.key\""
      ;;
    dot) forwarder="{ address = \"$bind_ip\", transport = \"dot\", tls_name = \"bind.example.test\" }" ;;
    doh) forwarder="{ address = \"$bind_ip\", transport = \"doh\", tls_name = \"bind.example.test\", path = \"/dns-query\" }" ;;
    *) fail "unknown transport $1 (plain, dot or doh)" ;;
  esac
  rm -f "$work/tenko.toml"
  cat >"$work/tenko.toml" <<TOML
# The configuration of the round "$1" (written by smoke.sh).
roles = "controller,dns"
modules = ["ipam", "dns"]

[profile]
# The Lab profile: recursion is open to every client, and plain HTTP is allowed.
name = "lab"

[tls]
mode = "plain"

[server]
listen = ["0.0.0.0:8443"]

[dns]
# Above 1024, so that the container needs no capability.
listen = ["0.0.0.0:$dns_port"]
upstream_ca = "/lab/ca.pem"
forwarders = [$forwarder]
forward_timeout_ms = 2000
forward_retries = 1

[dns.cache]
stale_secs = 3600
stale_answer_ms = 1800
prefetch = false

[dns.recursion]
# These rounds forward to BIND through [dns] forwarders, which a recursing node uses only
# where a view says forward (WP10.1).
enabled = false
$tls
TOML
  chmod 0444 "$work/tenko.toml"
}

# dig from the client container.
dig_client() { compose exec -T client dig "$@"; }
# ask <name>: one query to Tenko, printing the sections smoke.sh reads (the header, the
# answer, the authority section and the statistics).
ask() { dig_client "@$tenko_ip" -p "$dns_port" +time=5 +tries=1 +noall +comments +answer +authority +stats "$@"; }
# What to read from the output of ask, on standard input.
rcode_of() { sed -n 's/^;; ->>HEADER<<- .*status: \([A-Z]*\),.*/\1/p' | head -n 1; }
a_ttl() { awk '!/^;/ && $4 == "A" { print $2; exit }'; }
a_address() { awk '!/^;/ && $4 == "A" { print $5; exit }'; }
soa_ttl() { awk '!/^;/ && $4 == "SOA" { print $2; exit }'; }
query_msec() { sed -n 's/^;; Query time: \([0-9][0-9]*\) msec.*/\1/p' | head -n 1; }

is_number() { [[ "$1" =~ ^[0-9]+$ ]]; }

healthy() { [[ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q "$1")")" == healthy ]]; }
tenko_answers() {
  [[ "$(dig_client "@$tenko_ip" -p "$dns_port" +time=2 +tries=1 +short api.example.test)" == 192.0.2.11 ]]
}
bind_answers() {
  [[ "$(dig_client "@$bind_ip" +time=2 +tries=1 +short api.example.test)" == 192.0.2.11 ]]
}

# The query log of BIND. bind_log_mark sets $mark to the lines so far; tenko_queries
# [<name>] prints "<name> <flags>" for each query Tenko sent since the mark (for <name>
# only, when given, in any case: Tenko asks plain upstreams in a random case, 0x20). A T
# among the flags means a stream: TCP, TLS or HTTPS.
bind_log() { compose logs --no-color --no-log-prefix bind 2>&1; }
bind_log_mark() { mark="$(bind_log | wc -l)"; }
tenko_queries() {
  bind_log | tail -n +"$((mark + 1))" | awk -v ip="$tenko_ip" -v name="${1:-}" '
    index($0, " " ip "#") {
      for (i = 1; i < NF; i++) {
        if ($i == "query:" && (name == "" || tolower($(i + 1)) == tolower(name))) { print $(i + 1), $(i + 4) }
      }
    }'
}
count_queries() { tenko_queries "${1:-}" | grep -c . || true; }

step "check the tools"
for tool in docker openssl; do
  command -v "$tool" >/dev/null || fail "$tool not found"
done
docker compose version >/dev/null 2>&1 || fail "the docker compose plugin is missing"
docker info >/dev/null 2>&1 || fail "cannot talk to the Docker daemon"

if ((built_here)); then
  step "build the image $TENKO_IMAGE (UI bundle and release binary; this takes a while)"
  docker build -f "$repo/deploy/Dockerfile" -t "$TENKO_IMAGE" "$repo"
else
  step "use the existing image $TENKO_IMAGE"
  docker image inspect "$TENKO_IMAGE" >/dev/null 2>&1 || fail "image $TENKO_IMAGE not found"
fi
ok "image" "$TENKO_IMAGE"

step "generate the lab certificate and the key-encryption key"
work="$(mktemp -d)"
export LAB_DIR="$work"
mkdir -p "$work/tls" "$work/secrets"
make_certificates "$work"
head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n' >"$work/secrets/kek"
chmod 0444 "$work/secrets/kek"
# The TSIG key of the zone transfers (round xfr), for BIND's configuration and Tenko's API;
# the primary zone files of BIND, writable for nsupdate (named runs as the user bind).
xfr_secret="$(head -c 32 /dev/urandom | base64)"
upd_secret="$(head -c 32 /dev/urandom | base64)"
mkdir -p "$work/bind" "$work/zones"
printf 'key "%s" { algorithm hmac-sha256; secret "%s"; };\n' "$xfr_key" "$xfr_secret" >"$work/bind/keys.conf"
chmod 0444 "$work/bind/keys.conf"
# WP10.2: the zones BIND signs for the recursion round; empty until the round writes it.
printf '// WP10.2: no BIND-signed zones in this round.\n' >"$work/bind/recursion.conf"
chmod 0644 "$work/bind/recursion.conf"
mkdir -p "$work/delv"
chmod 0755 "$work/delv"
cp "$here"/zones/*.zone "$work/zones/"
chmod 0777 "$work/zones"
chmod 0666 "$work"/zones/*.zone
chmod 0755 "$work"
# WP10.1: the lab root's hints, mounted into the node under test in every round.
cp "$here/recursion/root.hints" "$work/root.hints"
chmod 0444 "$work/root.hints"
write_config plain
compose config --quiet
# A lab left over from an interrupted run (its data volume holds secrets under another
# key-encryption key) goes first.
compose --profile recursion down --volumes --remove-orphans --timeout 10 >/dev/null 2>&1 || true
ok "certificate" "lab CA and the BIND certificate for bind.example.test and $bind_ip"

step "start BIND and the client; ask BIND over its three transports"
compose up -d bind client
retry 60 "BIND to answer on port 53" bind_answers
tls_options="+tls-ca=/lab/ca.pem +tls-hostname=bind.example.test"
for form in "plain:" "dot:+tls $tls_options" "doh:+https=/dns-query $tls_options"; do
  name="${form%%:*}"
  options="${form#*:}"
  # shellcheck disable=SC2086 # the options are words
  answer="$(dig_client "@$bind_ip" +time=3 +tries=1 +short $options www.example.test)" ||
    fail "BIND did not answer over $name"
  [[ "$answer" == 192.0.2.10 ]] || fail "BIND gave '$answer' over $name, expected 192.0.2.10"
done
ok "bind" "answers over plain DNS, DNS over TLS and DNS over HTTPS"

# One round: Tenko forwards to BIND over <transport>.
round() {
  local transport="$1" out ttl1 ttl2 address soa1 soa2 count udp stream mark flags
  step "round $transport: Tenko forwards to BIND over $transport"
  write_config "$transport"
  bind_log_mark
  compose up -d --no-build --force-recreate tenko
  retry "$wait_secs" "tenko to become healthy" healthy tenko
  retry 60 "Tenko to answer api.example.test" tenko_answers
  ok "$transport: up" "tenko answers on $tenko_ip:$dns_port"

  out="$(ask www.example.test)" || fail "$transport: no answer for www.example.test"
  address="$(a_address <<<"$out")"
  ttl1="$(a_ttl <<<"$out")"
  [[ "$address" == 192.0.2.10 ]] ||
    fail "$transport: www.example.test gave '$address' ($(rcode_of <<<"$out")), expected 192.0.2.10"
  is_number "$ttl1" || fail "$transport: no TTL in the answer for www.example.test"
  sleep 2
  out="$(ask www.example.test)" || fail "$transport: no second answer for www.example.test"
  ttl2="$(a_ttl <<<"$out")"
  is_number "$ttl2" || fail "$transport: no TTL in the second answer"
  ((ttl2 < ttl1)) ||
    fail "$transport: the TTL did not go down ($ttl1 s, then $ttl2 s): not from the cache"
  count="$(count_queries www.example.test)"
  ((count == 1)) || fail "$transport: BIND saw $count queries for www.example.test, expected 1"
  ok "$transport: resolve and cache" "192.0.2.10, TTL $ttl1 s then $ttl2 s, one query to BIND"

  out="$(ask nohost.example.test)" || fail "$transport: no answer for nohost.example.test"
  [[ "$(rcode_of <<<"$out")" == NXDOMAIN ]] ||
    fail "$transport: nohost.example.test gave '$(rcode_of <<<"$out")', expected NXDOMAIN"
  soa1="$(soa_ttl <<<"$out")"
  is_number "$soa1" || fail "$transport: no SOA in the negative answer"
  sleep 2
  out="$(ask nohost.example.test)" || fail "$transport: no second answer for nohost.example.test"
  [[ "$(rcode_of <<<"$out")" == NXDOMAIN ]] ||
    fail "$transport: the second answer for nohost.example.test was '$(rcode_of <<<"$out")'"
  soa2="$(soa_ttl <<<"$out")"
  is_number "$soa2" || fail "$transport: no SOA in the second negative answer"
  ((soa2 < soa1)) || fail "$transport: the negative TTL did not go down ($soa1 s, then $soa2 s)"
  count="$(count_queries nohost.example.test)"
  ((count == 1)) || fail "$transport: BIND saw $count queries for nohost.example.test, expected 1"
  ok "$transport: negative cache" "NXDOMAIN twice, SOA TTL $soa1 s then $soa2 s, one query to BIND"

  flags="$(tenko_queries)"
  udp="$(awk '$2 !~ /T/' <<<"$flags" | grep -c . || true)"
  stream="$(awk '$2 ~ /T/' <<<"$flags" | grep -c . || true)"
  if [[ "$transport" == plain ]]; then
    ((udp > 0 && stream == 0)) ||
      fail "$transport: BIND saw $udp UDP and $stream stream queries from Tenko, expected UDP only"
    ok "$transport: transport" "BIND saw $udp queries from Tenko over UDP"
  else
    ((stream > 0 && udp == 0)) ||
      fail "$transport: BIND saw $udp UDP and $stream stream queries from Tenko, expected streams only"
    ok "$transport: transport" "BIND saw $stream queries from Tenko over a stream"
  fi
}

# The serve-stale steps, after the doh round.
stale() {
  local out ttl="" msec address container elapsed=0
  step "serve-stale: cut BIND off the lab network"
  # A cached entry, then wait until its TTL has passed.
  ask www.example.test >/dev/null || fail "no answer for www.example.test before the cut"
  sleep $((zone_ttl + 1))
  container="$(compose ps -q bind)"
  docker network disconnect "$network" "$container"
  out="$(ask www.example.test)" || fail "no answer for www.example.test with BIND cut off"
  address="$(a_address <<<"$out")"
  ttl="$(a_ttl <<<"$out")"
  msec="$(query_msec <<<"$out")"
  [[ "$address" == 192.0.2.10 ]] ||
    fail "with BIND cut off, www.example.test gave '$address' ($(rcode_of <<<"$out"))"
  [[ "$ttl" == "$stale_ttl" ]] ||
    fail "with BIND cut off the answer had TTL '$ttl', expected the stale TTL $stale_ttl"
  is_number "$msec" && ((msec <= stale_limit_ms)) ||
    fail "the stale answer took '$msec' ms, expected at most $stale_limit_ms"
  ok "stale answer" "192.0.2.10 with TTL $ttl after $msec ms, BIND cut off"

  step "serve-stale: connect BIND again"
  docker network connect --alias bind --ip "$bind_ip" "$network" "$container"
  retry 30 "BIND to answer again" bind_answers
  # Tenko may keep an upstream out of rotation for a few seconds after failures.
  until out="$(ask www.example.test)" && ttl="$(a_ttl <<<"$out")" &&
    is_number "$ttl" && ((ttl <= zone_ttl)); do
    if ((elapsed >= 30)); then
      fail "no fresh answer for www.example.test 30 s after BIND came back (last TTL '${ttl:-none}')"
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  ok "refresh" "fresh answer, TTL $ttl, within ${elapsed}s of BIND coming back"
}

# ---------------------------------------------------------------------------------------
# The round xfr (WP6.1): zone transfers with BIND both ways.

rows_failed=0
# row <name> <description> <command...>: one PASS or FAIL line of the transfer round.
row() {
  local name="$1" what="$2" line
  shift 2
  if "$@"; then
    line="$(printf 'PASS %-22s %s' "$name" "$what")"
  else
    line="$(printf 'FAIL %-22s %s' "$name" "$what")"
    rows_failed=$((rows_failed + 1))
    # The check once more with a trace, for the log.
    (set -x; "$@") >&2 2>&1 || true
  fi
  summary+=("$line")
  printf '%s\n' "$line"
}

# within <seconds> <command...>: retries the command every half second; true when it
# succeeded in time, with the time it took in $took_ms.
within() {
  local limit_ms=$(($1 * 1000)) began now
  shift
  began="$(date +%s%3N)"
  while true; do
    if "$@" >/dev/null 2>&1; then
      now="$(date +%s%3N)"
      took_ms=$((now - began))
      return 0
    fi
    now="$(date +%s%3N)"
    ((now - began >= limit_ms)) && return 1
    sleep 0.5
  done
}

cookie=""
# api <method> <path> [<json>]: a request to Tenko's API with the session; prints the body,
# returns 0 for a 2xx status, and leaves the status in $api_status.
api() {
  local method="$1" path="$2" body="${3:-}" out
  out="$work/api.out"
  local args=(-sS -o "$out" -w '%{http_code}' -X "$method" -H "Origin: $api_base"
    -H "Idempotency-Key: $(cat /proc/sys/kernel/random/uuid)")
  [[ -n "$cookie" ]] && args+=(-H "Cookie: $cookie")
  [[ -n "$body" ]] && args+=(-H "Content-Type: application/json" --data "$body")
  api_status="$(curl "${args[@]}" "$api_base/api/v1$path")" || api_status=000
  cat "$out"
  [[ "$api_status" == 2* ]]
}
# field <expression>: a value of the JSON on standard input, as Python reads it (`d` is the
# document), printed as text.
field() { python3 -c "import json,sys; d=json.load(sys.stdin); v=($1); print('' if v is None else v)"; }

# The answer of <server> [<port>] for <name> <type>, short form.
short_at() { dig_client "@$1" -p "$2" +time=2 +tries=1 +short "$3" "${4:-A}"; }
bind_has() { [[ "$(short_at "$bind_ip" 53 "$1")" == "$2" ]]; }
tenko_has() { [[ "$(short_at "$tenko_ip" "$dns_port" "$1")" == "$2" ]]; }
tenko_lacks_zone() {
  api GET /dns/zones >/dev/null || return 1
  ! python3 -c "import json,sys; d=json.load(open('$work/api.out')); sys.exit(0 if any(z['name']=='$1' for z in d['items']) else 1)"
}
zone_id() { api GET /dns/zones >/dev/null && python3 -c "import json; d=json.load(open('$work/api.out')); print(next(z['id'] for z in d['items'] if z['name']=='$1'))"; }

soa_json() { printf '{"mname": "ns.example.test", "rname": "hostmaster.example.test", "refresh": %s, "retry": 10, "expire": 3600, "minimum": 5, "ttl": 60}' "${1:-60}"; }
notify_bind="[{\"address\": \"$bind_ip\", \"port\": 53, \"key\": \"$xfr_key\"}]"

# primary_zone <name> <xot> <catalog>: a primary zone on Tenko that the access list of the
# key may transfer, notifying BIND.
primary_zone() {
  api POST /dns/zones "{\"name\": \"$1\", \"kind\": \"primary\", \"serial\": \"counter\", \"soa\": $(soa_json), \"name_servers\": [\"ns.example.test\"], \"transfer\": {\"allow\": [\"$acl\"], \"notify\": $notify_bind, \"require_tsig\": true, \"xot\": $2}, \"catalog\": $3}" >/dev/null ||
    fail "xfr: zone $1 could not be created on Tenko ($api_status: $(cat "$work/api.out"))"
  field "d['id']" <"$work/api.out"
}
# secondary_zone <name> <port> <xot> <catalog>: a secondary zone on Tenko from BIND.
secondary_zone() {
  local tls=""
  [[ "$3" == true ]] && tls=", \"xot\": true, \"tls_name\": \"bind.example.test\""
  api POST /dns/zones "{\"name\": \"$1\", \"kind\": \"secondary\", \"soa\": $(soa_json), \"source\": {\"primaries\": [{\"address\": \"$bind_ip\", \"port\": $2, \"key\": \"$xfr_key\"$tls}]}, \"catalog\": $4}" >/dev/null ||
    fail "xfr: secondary zone $1 could not be created on Tenko ($api_status: $(cat "$work/api.out"))"
  field "d['id']" <"$work/api.out"
}
# set_a <zone id> <name> <address>
set_a() {
  api POST "/dns/zones/$1/records/batch" "{\"changes\": [{\"op\": \"set\", \"name\": \"$2\", \"type\": \"A\", \"ttl\": 60, \"records\": [{\"type\": \"A\", \"address\": \"$3\"}]}]}" >/dev/null
}
# nsupdate_bind <commands>: a signed dynamic update of BIND from the client container.
nsupdate_bind() {
  printf 'server %s 53\n%s\nsend\n' "$bind_ip" "$1" |
    compose exec -T client nsupdate -y "hmac-sha256:$xfr_key:$xfr_secret"
}
axfr_unsigned_refused() {
  local out
  out="$(dig_client "@$tenko_ip" -p "$dns_port" +time=3 +tries=1 AXFR out.example.test 2>&1 || true)"
  grep -q "Transfer failed" <<<"$out" && ! grep -q "^www.out.example.test" <<<"$out"
}
axfr_signed() {
  local out
  out="$(dig_client "@$tenko_ip" -p "$dns_port" +time=3 +tries=1 -y "hmac-sha256:$xfr_key:$xfr_secret" AXFR out.example.test 2>&1)" || return 1
  grep -q "^www.out.example.test" <<<"$out" && ! grep -qi "couldn't verify\|tsig verify failure\|Transfer failed" <<<"$out" &&
    (($(grep -c "^bulk[0-9]*.out.example.test" <<<"$out") == 300))
}
xot_plain_refused() {
  local out
  out="$(dig_client "@$tenko_ip" -p "$dns_port" +time=3 +tries=1 -y "hmac-sha256:$xfr_key:$xfr_secret" AXFR xot.example.test 2>&1 || true)"
  grep -q "Transfer failed" <<<"$out"
}
out_tsig_ok() { axfr_unsigned_refused && axfr_signed; }
out_xot_ok() { within 60 bind_has www.xot.example.test 192.0.2.32 && xot_plain_refused; }
# The records of the last transfer of out.example.test BIND completed since the mark: the
# zone holds 304, an IXFR of one added record carries 5 (the new SOA, the old SOA, the new
# SOA again, the record, the new SOA), so fewer than 20 is the delta only.
bind_ixfr_seen() {
  local records
  records="$(bind_log | tail -n +"$((mark + 1))" |
    sed -n "s/.*transfer of 'out.example.test\/IN' from .*Transfer completed: [0-9]* messages, \([0-9]*\) records.*/\1/p" | tail -n 1)"
  ixfr_records="$records"
  is_number "$records" && ((records < 20))
}
tenko_journal_step() {
  api GET "/dns/zones/$1/journal" >/dev/null &&
    python3 -c "import json,sys; d=json.load(open('$work/api.out')); sys.exit(0 if any(i['added']==1 and i['removed']==0 for i in d['items']) else 1)"
}
read_only_refused() {
  ! api POST "/dns/zones/$1/records/batch" '{"changes": [{"op": "set", "name": "x.in.example.test", "type": "A", "ttl": 60, "records": [{"type": "A", "address": "192.0.2.1"}]}]}' >/dev/null &&
    [[ "$api_status" == 409 ]] && grep -q "dns.zone.secondary" "$work/api.out"
}
transfer_state_ok() {
  api GET "/dns/zones/$1/transfer" >/dev/null &&
    python3 -c "import json,sys; d=json.load(open('$work/api.out')); p=d['primaries'][0]; sys.exit(0 if d.get('serial') and p.get('last_success') and not p.get('last_error') else 1)"
}

xfr() {
  local out_id xot_id member_id in_id inxot_id catalog_id bulk changes
  step "round xfr: zone transfers with BIND both ways (TSIG, NOTIFY, IXFR, XoT, catalog zones)"
  write_config xfr
  compose up -d --no-build --force-recreate tenko
  retry "$wait_secs" "tenko to become healthy" healthy tenko
  retry 60 "Tenko to answer api.example.test" tenko_answers
  # BIND's secondary zones of Tenko failed to reach port 8530 in the earlier rounds, and
  # BIND keeps a primary that refused it as unreachable for minutes: start it afresh.
  compose restart bind >/dev/null
  retry 60 "BIND to answer again" bind_answers
  ok "xfr: up" "tenko answers on $tenko_ip:$dns_port, DoT and XoT on $xot_port"

  # First-run setup through the API under the Lab profile; the session cookie signs in.
  lab_setup xfr

  api POST /dns/keys "{\"name\": \"$xfr_key\", \"secret\": \"$xfr_secret\"}" >/dev/null ||
    fail "xfr: the TSIG key could not be imported ($api_status: $(cat "$work/api.out"))"
  api POST /dns/acls "{\"name\": \"lab-secondaries\", \"entries\": [{\"kind\": \"key\", \"name\": \"$xfr_key\"}]}" >/dev/null ||
    fail "xfr: the access list could not be created ($api_status: $(cat "$work/api.out"))"
  acl="$(field "d['id']" <"$work/api.out")"
  # For hand tests and the measurement M19 on a kept lab (KEEP=1).
  printf 'cookie=%q\nxfr_key=%q\nxfr_secret=%q\nacl=%q\napi_base=%q\n' \
    "$cookie" "$xfr_key" "$xfr_secret" "$acl" "$api_base" >"$work/session.env"
  chmod 0600 "$work/session.env"

  # Tenko as the primary: out (TCP), xot (TLS only), the catalog and its member.
  bind_log_mark
  out_id="$(primary_zone out.example.test false false)"
  set_a "$out_id" www.out.example.test 192.0.2.30
  changes=""
  for bulk in $(seq 1 300); do
    changes+="${changes:+, }{\"op\": \"set\", \"name\": \"bulk$bulk.out.example.test\", \"type\": \"TXT\", \"ttl\": 60, \"records\": [{\"type\": \"TXT\", \"strings\": [\"$(printf 'x%.0s' $(seq 1 100))\"]}]}"
  done
  api POST "/dns/zones/$out_id/records/batch" "{\"changes\": [$changes]}" >/dev/null ||
    fail "xfr: the bulk records could not be written ($api_status)"
  xot_id="$(primary_zone xot.example.test true false)"
  set_a "$xot_id" www.xot.example.test 192.0.2.32
  primary_zone catalog.tenko.test false true >/dev/null
  member_id="$(primary_zone member.tenko.test false false)"
  set_a "$member_id" www.member.tenko.test 192.0.2.40

  # Tenko as the secondary of BIND: in (TCP), inxot (TLS), BIND's catalog.
  in_id="$(secondary_zone in.example.test 53 false false)"
  inxot_id="$(secondary_zone inxot.example.test 853 true false)"
  catalog_id="$(secondary_zone catalog.bind.test 53 false true)"
  : "$catalog_id"

  row out.axfr "BIND transfers out.example.test from Tenko with TSIG" within 60 bind_has www.out.example.test 192.0.2.30
  row out.tsig "dig AXFR without the key is refused, with -y it verifies (300 records, several messages)" out_tsig_ok
  bind_log_mark
  set_a "$out_id" new.out.example.test 192.0.2.31
  if within 5 bind_has new.out.example.test 192.0.2.31; then
    row out.notify_ixfr "a change on Tenko reaches BIND in ${took_ms} ms by NOTIFY and IXFR" bind_ixfr_seen
  else
    row out.notify_ixfr "a change on Tenko did not reach BIND within 5 s" false
  fi
  row out.xot "BIND transfers xot.example.test over TLS; plain AXFR of it is refused" out_xot_ok
  row out.catalog "BIND makes member.tenko.test a zone from Tenko's catalog zone" within 60 bind_has www.member.tenko.test 192.0.2.40

  row in.axfr "Tenko transfers in.example.test from BIND with TSIG" within 60 tenko_has www.in.example.test 192.0.2.50
  nsupdate_bind "zone in.example.test
update add new.in.example.test 60 IN A 192.0.2.51" || fail "xfr: nsupdate of BIND failed"
  if within 5 tenko_has new.in.example.test 192.0.2.51; then
    row in.notify_ixfr "a change on BIND reaches Tenko in ${took_ms} ms by NOTIFY and IXFR (one journal step)" tenko_journal_step "$in_id"
  else
    row in.notify_ixfr "a change on BIND did not reach Tenko within 5 s" false
  fi
  row in.xot "Tenko transfers inxot.example.test from BIND over TLS" within 60 tenko_has www.inxot.example.test 192.0.2.60
  if within 60 tenko_has www.member.bind.test 192.0.2.70; then
    nsupdate_bind "zone catalog.bind.test
update delete m1.zones.catalog.bind.test PTR" || fail "xfr: nsupdate of BIND's catalog failed"
    row in.catalog "Tenko adds member.bind.test from BIND's catalog and deletes it when it leaves" within 30 tenko_lacks_zone member.bind.test
  else
    row in.catalog "Tenko did not make member.bind.test a zone from BIND's catalog" false
  fi
  row in.read_only "a record change on Tenko's secondary zone is refused (409 dns.zone.secondary)" read_only_refused "$in_id"
  row in.status "the transfer route shows the serial and the primary's last success" transfer_state_ok "$inxot_id"
  ((rows_failed == 0)) || fail "xfr: $rows_failed row(s) failed"
}


# ---------------------------------------------------------------------------------------
# The round update (WP6.2): RFC 2136 dynamic updates of a zone of Tenko from nsupdate in the
# client container, with TSIG, prerequisites, over UDP and TCP, and the refusals.

# nsupdate_tenko <commands> [<nsupdate options>...]: one update of Tenko's zone
# dyn.example.test from the client container; prints what nsupdate said.
nsupdate_tenko() {
  local commands="$1"
  shift
  printf 'server %s %s\nzone dyn.example.test\n%s\nsend\n' "$tenko_ip" "$dns_port" "$commands" |
    compose exec -T client nsupdate "$@" 2>&1
}
signed_update() { nsupdate_tenko "$1" -y "hmac-sha256:$upd_key:$upd_secret" "${@:2}"; }
# The answer of Tenko for <name> right after an update was answered: no retry, since Tenko
# answers NOERROR only once its index holds the change.
tenko_now() { short_at "$tenko_ip" "$dns_port" "$1" "${2:-A}"; }
rcode_at_tenko() { dig_client "@$tenko_ip" -p "$dns_port" +time=2 +tries=1 "$1" A | rcode_of; }

update_add_ok() {
  signed_update "update add host1.dyn.example.test 60 IN A 192.0.2.81" >/dev/null &&
    [[ "$(tenko_now host1.dyn.example.test)" == 192.0.2.81 ]]
}
update_prereq_ok() {
  local out
  out="$(signed_update "prereq nxdomain host1.dyn.example.test
update add host1.dyn.example.test 60 IN A 192.0.2.99" || true)"
  grep -q "YXDOMAIN" <<<"$out" && [[ "$(tenko_now host1.dyn.example.test)" == 192.0.2.81 ]]
}
update_replace_ok() {
  signed_update "prereq yxrrset host1.dyn.example.test A
update delete host1.dyn.example.test A
update add host1.dyn.example.test 60 IN A 192.0.2.82" >/dev/null &&
    [[ "$(tenko_now host1.dyn.example.test)" == 192.0.2.82 ]]
}
update_tcp_ok() {
  signed_update "update add host2.dyn.example.test 60 IN A 192.0.2.83" -v >/dev/null &&
    [[ "$(tenko_now host2.dyn.example.test)" == 192.0.2.83 ]]
}
update_delete_ok() {
  signed_update "update delete host1.dyn.example.test" >/dev/null &&
    [[ "$(rcode_at_tenko host1.dyn.example.test)" == NXDOMAIN ]]
}
update_unsigned_refused() {
  local out
  out="$(nsupdate_tenko "update add host3.dyn.example.test 60 IN A 192.0.2.84" || true)"
  grep -q "REFUSED" <<<"$out" && [[ -z "$(tenko_now host3.dyn.example.test)" ]]
}
update_badsig_refused() {
  local out
  out="$(nsupdate_tenko "update add host3.dyn.example.test 60 IN A 192.0.2.84" -y "hmac-sha256:$upd_key:$(head -c 32 /dev/urandom | base64)" || true)"
  grep -Eqi "NOTAUTH|BADSIG|tsig" <<<"$out" && [[ -z "$(tenko_now host3.dyn.example.test)" ]]
}
update_origin_ok() {
  api GET "/dns/zones/$1/records" >/dev/null &&
    python3 -c "import json,sys; d=json.load(open('$work/api.out')); s=[r for r in d['items'] if r['name']=='host2.dyn.example.test' and r['type']=='A']; sys.exit(0 if s and s[0]['origin']=='dynamic' and s[0].get('key')=='$upd_key' else 1)"
}
update_ipam_refused() {
  local out
  out="$(signed_update "update delete cam.dyn.example.test A" || true)"
  grep -q "REFUSED" <<<"$out" && [[ "$(tenko_now cam.dyn.example.test)" == 192.0.2.90 ]]
}

# lab_setup <round>: the first-run setup through the API under the Lab profile, once per
# run; the session cookie signs the later requests in.
lab_setup() {
  [[ -n "$cookie" ]] && return 0
  local token password setup
  token="$(compose exec -T tenko /usr/local/bin/tenko setup token --data-dir /var/lib/tenko | tr -d '\r\n')"
  [[ -n "$token" ]] || fail "$1: no setup token"
  # The Lab profile's password policy is a PIN of digits.
  password="$(od -An -N4 -tu4 /dev/urandom | tr -dc '0-9')"
  setup="{\"setup_token\": \"$token\", \"profile\": \"lab\", \"admin\": {\"name\": \"labadmin\", \"display_name\": \"Lab Admin\", \"password\": \"$password\"}, \"host_name\": \"tenko.example.test\", \"language\": \"en\"}"
  cookie="$(curl -sS -D - -o "$work/api.out" -H "Origin: $api_base" -H "Content-Type: application/json" \
    --data "$setup" "$api_base/api/v1/setup" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \(tenko_session=[^;]*\).*/\1/p' | head -n 1)"
  [[ -n "$cookie" ]] || fail "$1: the setup did not sign in: $(cat "$work/api.out")"
  ok "$1: setup" "Tenko is set up under the Lab profile"
}

update() {
  local zone_id
  step "round update: RFC 2136 updates from nsupdate (TSIG, prerequisites, UDP and TCP, refusals)"
  if [[ -z "$cookie" ]]; then
    write_config xfr
    compose up -d --no-build --force-recreate tenko
    retry "$wait_secs" "tenko to become healthy" healthy tenko
    retry 60 "Tenko to answer api.example.test" tenko_answers
    lab_setup update
  fi
  api POST /dns/keys "{\"name\": \"$upd_key\", \"secret\": \"$upd_secret\"}" >/dev/null ||
    fail "update: the TSIG key could not be imported ($api_status: $(cat "$work/api.out"))"
  # A list with the key only: under the Lab profile an unsigned update from an address a
  # list allows would pass, so the list names no address.
  api POST /dns/acls "{\"name\": \"lab-updaters\", \"entries\": [{\"kind\": \"key\", \"name\": \"$upd_key\"}]}" >/dev/null ||
    fail "update: the access list could not be created ($api_status: $(cat "$work/api.out"))"
  upd_acl="$(field "d['id']" <"$work/api.out")"
  api POST /dns/zones "{\"name\": \"dyn.example.test\", \"kind\": \"primary\", \"serial\": \"counter\", \"soa\": $(soa_json), \"name_servers\": [\"ns.example.test\"], \"update\": {\"allowed\": [\"$upd_acl\"], \"require_tsig\": true, \"may_replace_ipam\": false}}" >/dev/null ||
    fail "update: the zone could not be created ($api_status: $(cat "$work/api.out"))"
  zone_id="$(field "d['id']" <"$work/api.out")"
  # An address IPAM manages in the zone, written by the actuator (origin ipam).
  api POST /prefixes '{"cidr": "192.0.2.0/24"}' >/dev/null || true
  api POST /addresses '{"ip": "192.0.2.90", "dns_name": "cam.dyn.example.test"}' >/dev/null ||
    fail "update: the address could not be created ($api_status: $(cat "$work/api.out"))"
  api POST /proposals/reconcile '{}' >/dev/null || fail "update: the reconcile did not run ($api_status)"
  printf 'upd_key=%q\nupd_secret=%q\nupd_acl=%q\nupd_zone=%q\n' "$upd_key" "$upd_secret" "$upd_acl" "$zone_id" >>"$work/session.env"
  chmod 0600 "$work/session.env"

  # The first update waits until the update path knows the new key and zone.
  row upd.add "nsupdate -y adds host1.dyn.example.test; the next query is answered with it" within 15 update_add_ok
  row upd.prereq "a prerequisite that fails (prereq nxdomain) answers YXDOMAIN and changes nothing" update_prereq_ok
  row upd.replace "prereq yxrrset, delete and add in one update replace the address" update_replace_ok
  row upd.tcp "nsupdate -v adds host2.dyn.example.test over TCP" update_tcp_ok
  row upd.delete "update delete removes the name: NXDOMAIN at once" update_delete_ok
  row upd.unsigned "an update without the key is refused (REFUSED)" update_unsigned_refused
  row upd.badsig "an update signed with a wrong secret is refused (NOTAUTH, BADSIG)" update_badsig_refused
  row upd.origin "the RRset carries the origin dynamic and the key's name (API)" update_origin_ok "$zone_id"
  if within 30 tenko_has cam.dyn.example.test 192.0.2.90; then
    row upd.ipam "an update of the address IPAM manages is refused (REFUSED, origin ipam)" update_ipam_refused
  else
    row upd.ipam "IPAM did not write cam.dyn.example.test" false
  fi
  ((rows_failed == 0)) || fail "update: $rows_failed row(s) failed"
}

for transport in $rounds; do
  if [[ "$transport" == xfr ]]; then
    xfr
    continue
  fi
  # WP6.2: the dynamic updates.
  if [[ "$transport" == update ]]; then
    update
    continue
  fi
  # WP10.1: the recursive resolver against the lab root.
  if [[ "$transport" == recursion ]]; then
    recursion
    continue
  fi
  # WP10.2: the RFC 5011 roll of the lab root's KSK.
  if [[ "$transport" == rfc5011 ]]; then
    rfc5011
    continue
  fi
  round "$transport"
  if [[ "$transport" == doh ]]; then
    stale
  fi
done

step "OK: the DNS lab passed"
