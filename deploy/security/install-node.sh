#!/usr/bin/env bash
# The node under test of the security round (deploy/security/README.md), installed as a
# user installs it: deploy/install.sh with the binary under test, unattended, the Standard
# profile, the roles controller and dns; then DNS over TLS on 853 with a certificate of the
# round's lab CA (the one change of tenko.toml a user makes by hand for DoT), and first-run
# setup through the API with a fresh administrator, who enrols an authenticator because the
# Standard profile requires a second factor for administrators (TGL-02). Last, a zone with
# one name that the probes of fuzz.dns_wire ask for.
#
# Usage, as root, from round.sh (or by hand on a throwaway machine):
#   BINARY=<path> WORK=<dir> EVIDENCE=<dir> bash deploy/security/install-node.sh
#
# In:  BINARY (the tenko binary under test), WORK (the round's private directory: the setup
#      token, the API session and the lab CA's key live here and never in the bundle),
#      EVIDENCE (the bundle directory: the installer's output goes to node/install.log),
#      PLANT (optional; "listener" also turns on DNS over HTTPS on port 443, a listener the
#      net rows must report).
# Out: WORK/node.env with the values the rows read (API_URL, API_CA, API_STATE, NODE_CONFIG,
#      DATA_DIR, DOT_CA), WORK/in/ (the CA files the scanner containers read).
#
# Exit status: 0 when the node runs and setup is complete; otherwise the status of the
# installer, or 1, with the reason on standard error.

set -Eeuo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
: "${BINARY:?BINARY names the binary under test}"
: "${WORK:?WORK names the private work directory of the round}"
: "${EVIDENCE:?EVIDENCE names the bundle directory}"
plant="${PLANT:-}"

readonly HOST_NAME=tenko.example.test
readonly CONFIG=/etc/tenko/tenko.toml
readonly DATA_DIR=/var/lib/tenko
readonly BIN=/usr/local/bin/tenko
readonly API_PORT=8443

die() { printf 'install-node: %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" == 0 ]] || die "run as root (the installer is root's)"
mkdir -p "$WORK/in" "$EVIDENCE/node"
chmod 0700 "$WORK"

# 1. The installer, as a user runs it unattended. Its summary prints the setup token, which
#    stays out of the bundle.
rc=0
bash "$repo/deploy/install.sh" --yes --profile standard --roles controller,dns --modules ipam,dns \
  --binary "$BINARY" --host-name "$HOST_NAME" >"$WORK/install.log" 2>&1 || rc=$?
sed -E 's/^( *Setup token: *).*/\1(removed by the round)/' "$WORK/install.log" >"$EVIDENCE/node/install.log"
((rc == 0)) || die "deploy/install.sh exited with status $rc (node/install.log in the bundle)"

# wait_ready: the API answers `tenko health` with the internal CA.
wait_ready() {
  for _ in $(seq 1 90); do
    if [[ -f "$DATA_DIR/tls/ca-root.pem" ]] &&
      "$BIN" health --url "https://localhost:${API_PORT}" --ca-file "$DATA_DIR/tls/ca-root.pem" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  journalctl -u tenko -n 50 --no-pager >"$EVIDENCE/node/journal-not-ready.txt" 2>&1 || true
  die "the node did not become ready after the change of $CONFIG"
}

# 2. DoT with a certificate of the lab CA, as the DNS lab's round xfr makes one: an EC P-256
#    CA and a leaf for the host name, valid 30 days. The CA's key stays in WORK.
ca_dir="$WORK/lab-ca"
mkdir -p "$ca_dir"
openssl ecparam -name prime256v1 -genkey -noout -out "$ca_dir/ca.key" 2>/dev/null
openssl req -x509 -new -key "$ca_dir/ca.key" -sha256 -days 30 -subj "/CN=Tenko security round lab CA" \
  -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$ca_dir/ca.pem" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$ca_dir/dot.key" 2>/dev/null
openssl req -new -key "$ca_dir/dot.key" -subj "/CN=$HOST_NAME" -out "$ca_dir/dot.csr" 2>/dev/null
printf 'subjectAltName=DNS:%s\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' \
  "$HOST_NAME" >"$ca_dir/dot.ext"
openssl x509 -req -in "$ca_dir/dot.csr" -CA "$ca_dir/ca.pem" -CAkey "$ca_dir/ca.key" -CAcreateserial \
  -days 30 -sha256 -extfile "$ca_dir/dot.ext" -out "$ca_dir/dot.pem" 2>/dev/null
install -m 0640 -o root -g tenko "$ca_dir/dot.pem" /etc/tenko/dot.pem
install -m 0640 -o root -g tenko "$ca_dir/dot.key" /etc/tenko/dot.key
if grep -q '^\[dns\.tls\]' "$CONFIG"; then
  die "$CONFIG has a [dns.tls] section already; the round expects the installer's file"
fi
{
  printf '\n[dns.tls]\n'
  printf '# Written by deploy/security/install-node.sh: DNS over TLS on 853 with the round'"'"'s lab CA.\n'
  printf 'dot = true\n'
  printf 'certificate = "/etc/tenko/dot.pem"\n'
  printf 'key = "/etc/tenko/dot.key"\n'
  if [[ "$plant" == listener ]]; then
    printf '# PLANT=listener: DNS over HTTPS on 443, a listener the net rows must report.\n'
    printf 'doh = true\n'
  fi
} >>"$CONFIG"
"$BIN" config check --config "$CONFIG" >"$EVIDENCE/node/config-check.txt" 2>&1 ||
  die "tenko config check refused the DoT section (node/config-check.txt in the bundle)"
systemctl restart tenko
wait_ready

# 3. First-run setup through the API, under the Standard profile.
install -m 0644 "$DATA_DIR/tls/ca-root.pem" "$WORK/in/ca-root.pem"
install -m 0644 "$ca_dir/ca.pem" "$WORK/in/lab-ca.pem"
(umask 077 && runuser -u tenko -- "$BIN" setup token --config "$CONFIG" --data-dir "$DATA_DIR" >"$WORK/setup-token") ||
  die "no setup token: setup is not open on the fresh node"
api=(python3 -I "$here/nodeapi.py" --state "$WORK/api-state.json")
"${api[@]}" --url "https://${HOST_NAME}:${API_PORT}" --connect 127.0.0.1 --ca "$WORK/in/ca-root.pem" \
  setup --token-file "$WORK/setup-token" --profile standard --host-name "$HOST_NAME" >"$EVIDENCE/node/setup.json" ||
  die "first-run setup through the API failed"
rm -f "$WORK/setup-token"

# 4. The zone the probes ask: probe.security.example.test A 192.0.2.53.
"${api[@]}" post /dns/zones '{"name": "security.example.test", "kind": "primary", "soa": {"mname": "ns.security.example.test", "rname": "hostmaster.example.test", "refresh": 3600, "retry": 600, "expire": 86400, "minimum": 60, "ttl": 60}, "name_servers": ["ns.security.example.test"]}' \
  >"$WORK/zone.json" || die "the probe zone could not be created"
zone_id="$(jq -r .id "$WORK/zone.json")"
"${api[@]}" post "/dns/zones/$zone_id/records/batch" '{"changes": [{"op": "set", "name": "probe.security.example.test", "type": "A", "ttl": 60, "records": [{"type": "A", "address": "192.0.2.53"}]}]}' \
  >/dev/null || die "the probe record could not be written"

cp "$CONFIG" "$EVIDENCE/node/tenko.toml"
cat >"$WORK/node.env" <<EOF
API_URL=https://${HOST_NAME}:${API_PORT}
API_CA=$WORK/in/ca-root.pem
API_STATE=$WORK/api-state.json
NODE_CONFIG=$CONFIG
DATA_DIR=$DATA_DIR
DOT_CA=$WORK/in/lab-ca.pem
EOF
echo "install-node: the node runs, setup is complete under the Standard profile"
