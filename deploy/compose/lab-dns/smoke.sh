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
#   6. tears everything down (containers, volumes, network, work directory), also when a
#      step fails, after printing the logs of every service. KEEP=1 leaves the lab running.
#
# Needs: bash, Docker with the compose plugin (and buildx for the build), and openssl on the
# host. Run it from the repository root without arguments:
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
#   ROUNDS          the transports to run, in order (default "plain dot doh"); the
#                   serve-stale steps run after the round doh
#   WAIT_SECS       how long to wait for Tenko to become healthy (default 300)
#   KEEP            1: do not tear the lab down at the end (README.md says how to later)

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
compose_file="$here/compose.yml"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-tenkodnslab}"
if [[ -n "${BIND_IMAGE:-}" ]]; then
  export BIND_IMAGE
fi
rounds="${ROUNDS:-plain dot doh}"
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
    for service in bind tenko client; do
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
  if [[ "$keep" == 1 && $status -eq 0 ]]; then
    printf '\n==> KEEP=1: the lab keeps running; ask Tenko with\n'
    printf '    LAB_DIR=%s docker compose -f %s exec client dig @%s -p %s www.example.test\n' \
      "$work" "$compose_file" "$tenko_ip" "$dns_port"
    printf 'tear it down with: LAB_DIR=%s docker compose -f %s down --volumes\n' \
      "$work" "$compose_file"
    exit "$status"
  fi
  printf '\n==> tear down\n'
  compose down --volumes --remove-orphans --timeout 30 >/dev/null 2>&1
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
    rm -f ca.key bind.csr bind.ext ca.srl
    # named drops to the user bind and Tenko runs as 65532; neither is the owner. The work
    # directory itself is private to this user.
    chmod 0444 ca.pem bind.pem bind.key
  )
}

# write_config <plain|dot|doh>: tenko.toml of a round in the work directory. The default
# forwarder is BIND over one transport; the cache is the default one, except that prefetch
# is off, so that an entry really expires and the serve-stale step has something to do.
write_config() {
  local forwarder
  case "$1" in
    plain) forwarder="{ address = \"$bind_ip\", transport = \"udp\" }" ;;
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
chmod 0755 "$work"
write_config plain
compose config --quiet
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

for transport in $rounds; do
  round "$transport"
  if [[ "$transport" == doh ]]; then
    stale
  fi
done

step "OK: the DNS lab passed"
