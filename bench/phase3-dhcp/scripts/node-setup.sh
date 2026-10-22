#!/usr/bin/env bash
# The node side of run-perfdhcp.sh --kind tenko: starts a fresh tenko instance as the ssh
# user from <dir> (its own data directory, never a Tenko service installed on the host),
# sets it up through its API under the Lab profile and creates the bench scope, then
# returns with the server running and its pid in <dir>/server.pid.
#
#   node-setup.sh start <dir> <addr> <port> <relay-port> <api-port> <workers> <log>
#   node-setup.sh metrics <dir> <api-port> <file>
#
# The scope is 198.18.0.0/15 (RFC 2544's benchmarking range) with one dhcp_pool range,
# 198.18.0.10 to 198.19.255.250, lease 3,600 s; perfdhcp selects it with option 118. The
# dhcp role listens in relay mode on <addr>:<port> and answers relays on <relay-port>.
# Needs curl and python3 on the node; the binary is <dir>/bin/server.
set -eu

cmd="$1"
dir="$2"

api() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS -o "$dir/api.out" -w '%{http_code}' -X "$method" -H "Origin: $base")
  [ -n "${cookie:-}" ] && args+=(-H "Cookie: $cookie")
  [ -n "$body" ] && args+=(-H "Content-Type: application/json" --data "$body")
  status="$(curl "${args[@]}" "$base/api/v1$path")" || status=000
  case "$status" in
    2*) return 0 ;;
    *) echo "node-setup: $method $path: $status $(cat "$dir/api.out")" >&2; return 1 ;;
  esac
}
field() { python3 -c "import json,sys; d=json.load(open('$dir/api.out')); print($1)"; }

case "$cmd" in
  start)
    addr="$3" port="$4" relay_port="$5" api_port="$6" workers="$7" log="$8"
    base="http://127.0.0.1:$api_port"
    rm -rf "$dir/data"
    mkdir -p "$dir/data"
    [ -f "$dir/kek" ] || head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n' >"$dir/kek"
    chmod 0600 "$dir/kek"
    cat >"$dir/tenko.toml" <<TOML
# run-perfdhcp.sh's node (written by node-setup.sh).
roles = "controller,dhcp"
modules = ["ipam", "dhcp"]
data_dir = "$dir/data"

[profile]
name = "lab"

[tls]
mode = "plain"

[server]
listen = ["127.0.0.1:$api_port"]

[metrics]
# The plain loopback listener (no authentication), one port above the API.
listen = "127.0.0.1:$((api_port + 1))"

[dhcp]
listen = [{ address = "$addr", mode = "relay" }]
port = $port
relay_port = $relay_port
workers = $workers
TOML
    cd "$dir"
    TENKO_KEK__PROVIDER=file TENKO_KEK__PATH="$dir/kek" TENKO_HIBP__ONLINE=false \
      TENKO_UPDATES__AIR_GAPPED=true \
      nohup bin/server serve --config "$dir/tenko.toml" >"$dir/$log" 2>&1 </dev/null &
    echo $! >"$dir/server.pid"
    for _ in $(seq 1 120); do
      curl -fsS "$base/api/v1/health/ready" >/dev/null 2>&1 && break
      sleep 1
    done
    curl -fsS "$base/api/v1/health/ready" >/dev/null || { echo "node-setup: not ready" >&2; exit 1; }
    token="$(bin/server setup token --data-dir "$dir/data" | tr -d '\r\n')"
    password="$(od -An -N4 -tu4 /dev/urandom | tr -dc '0-9')"
    cookie="$(curl -sS -D - -o "$dir/api.out" -H "Origin: $base" -H "Content-Type: application/json" \
      --data "{\"setup_token\": \"$token\", \"profile\": \"lab\", \"admin\": {\"name\": \"benchadmin\", \"display_name\": \"Bench\", \"password\": \"$password\"}, \"host_name\": \"node.example.test\", \"language\": \"en\"}" \
      "$base/api/v1/setup" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \(tenko_session=[^;]*\).*/\1/p' | head -n 1)"
    [ -n "$cookie" ] || { echo "node-setup: setup failed: $(cat "$dir/api.out")" >&2; exit 1; }
    printf '%s\n' "$cookie" >"$dir/cookie"
    api POST /prefixes '{"cidr": "198.18.0.0/15", "description": "bench"}'
    prefix="$(field "d['item']['id']")"
    api POST "/prefixes/$prefix/ranges" '{"first": "198.18.0.10", "last": "198.19.255.250", "role": "dhcp_pool"}'
    api POST /dhcp/scopes "{\"prefix\": \"$prefix\", \"lease\": {\"default_secs\": 3600, \"min_secs\": 600, \"max_secs\": 7200}}"
    # The role takes the scope from the feed; give it a moment.
    sleep 3
    ;;
  metrics)
    api_port="$3" file="$4"
    curl -sS "http://127.0.0.1:$((api_port + 1))/metrics" 2>/dev/null | grep '^tenko_dhcp' >"$dir/$file" || true
    ;;
  *)
    echo "usage: node-setup.sh start|metrics ..." >&2
    exit 2
    ;;
esac
