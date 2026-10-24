#!/usr/bin/env bash
# Checks of deploy/install.sh, the Linux installer that install/tenko-install.sh runs in a
# Proxmox container:
#   (1) its parsers and validators, sourced, against test/fixtures/tenko-release.json, and its
#       refusal of a file that is not the binary (a script, an empty file, a text file);
#   (2) a dry run in ubuntu:24.04 that changes nothing;
#   (3) an unattended --no-start install of a local binary in ubuntu:24.04, debian:12-slim and
#       rockylinux/rockylinux:9-minimal (the release workflow's smoke images): the files and
#       their modes, `tenko config check`, `tenko serve` started by hand as the service account
#       until `tenko health` answers, the setup token, the rerun that changes nothing,
#       --reconfigure, --uninstall that keeps the data and the key, a reinstall that keeps the
#       key, --uninstall --purge;
#   (4) the download paths against a loopback server: a release directory (--release-url)
#       with SHA256SUMS, a wrong checksum refused with exit 5, and the GitHub API path with a
#       token (TENKO_GITHUB_API), whose Authorization header must arrive and whose token must
#       appear in no argument list;
#   (5) with --systemd <newer binary>: the whole life in a systemd container: the sealed key,
#       first-run setup with --admin, the rerun, the upgrade to the newer binary through the
#       updates layout, the fallback to a plain key file when systemd-creds cannot seal, an
#       installation made by hand without a credential, uninstall and purge.
#
# Usage, as root where Docker runs (WSL or Linux):
#   bash deploy/proxmox/test/install-sh-test.sh <tenko musl binary> [--systemd <newer binary>]
#   bash deploy/proxmox/test/install-sh-test.sh --unit     (1) only, no Docker
# The binaries are static musl builds of the same source; the newer one reports a higher
# version (bump crates/tenko/Cargo.toml in a copy of the tree to build it).
#
# License: Business Source License 1.1; see LICENSE.md at the repository root.

set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "${here}/../../.." && pwd)"
installer="${repo}/deploy/install.sh"
unit="${repo}/deploy/systemd/tenko.service"
failures=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() {
  printf 'FAIL  %s\n' "$*"
  failures=$((failures + 1))
}
expect() { if [[ "$3" == "$2" ]]; then pass "$1: $3"; else fail "$1: want \"$2\", got \"$3\""; fi; }
has() { if grep -qF -- "$2" <<<"$1"; then pass "$3"; else fail "$3 (missing: $2)"; fi; }
lacks() { if grep -qF -- "$2" <<<"$1"; then fail "$3 (found: $2)"; else pass "$3"; fi; }

# ── (1) unit checks ─────────────────────────────────────────────────────────────────────────
unit_checks() {
  echo "== (1) parsers and validators"
  (
    # shellcheck source=../../install.sh
    source "$installer"
    set +eE
    trap - ERR
    expect "the embedded unit is deploy/systemd/tenko.service" "same" \
      "$(cmp -s <(unit_text) "$unit" && echo same || echo differs)"
    expect "version_cmp 0.2.0 0.10.0" "-1" "$(version_cmp 0.2.0 0.10.0)"
    expect "version_cmp 0.3.0 0.3.0-rc.1" "1" "$(version_cmp 0.3.0 0.3.0-rc.1)"
    expect "version_cmp 0.3.0-rc.2 0.3.0-rc.10" "-1" "$(version_cmp 0.3.0-rc.2 0.3.0-rc.10)"
    expect "version_cmp 1.0.0 1.0.0" "0" "$(version_cmp 1.0.0 1.0.0)"
    expect "dns_listen all" '"0.0.0.0:53", "[::]:53"' "$(dns_listen all)"
    expect "dns_listen with ports and IPv6" '"192.0.2.53:53", "198.51.100.1:5353", "[2001:db8::53]:53", "[2001:db8::1]:53"' \
      "$(dns_listen '192.0.2.53, 198.51.100.1:5353,2001:db8::53,[2001:db8::1]')"
    expect "dns_listen refuses a name" "1" "$(dns_listen tenko.example.test >/dev/null; echo $?)"
    expect "dns_listen refuses 192.0.2.300" "1" "$(dns_listen 192.0.2.300 >/dev/null; echo $?)"
    expect "forwarder_list" '"192.0.2.1", "192.0.2.2:5353", "2001:db8::1"' "$(forwarder_list 192.0.2.1,192.0.2.2:5353,2001:db8::1)"
    expect "forwarder_list none" "" "$(forwarder_list none)"
    expect "sums_version" "0.2.0-rc.1" "$(printf '%s  tenko-0.2.0-rc.1-windows-x86_64.exe\n%s  tenko-0.2.0-rc.1-linux-x86_64\n%s  install.sh\n' aa bb cc | sums_version)"
    for mode in jq no-jq; do
      if [[ "$mode" == jq ]] && ! command -v jq >/dev/null 2>&1; then
        echo "SKIP  jq is not installed here"
        continue
      fi
      if [[ "$mode" == no-jq ]]; then have() { [[ "$1" != jq ]] && command -v "$1" >/dev/null 2>&1; }; fi
      expect "release_tag (${mode})" "v0.0.1" "$(release_tag <"${here}/fixtures/tenko-release.json")"
      expect "release_asset_id of the binary (${mode})" "102" "$(release_asset_id tenko-0.0.1-linux-x86_64 <"${here}/fixtures/tenko-release.json")"
      expect "release_asset_id of SHA256SUMS (${mode})" "101" "$(release_asset_id SHA256SUMS <"${here}/fixtures/tenko-release.json")"
      expect "release_asset_id of a missing asset (${mode})" "" "$(release_asset_id tenko-9.9.9-linux-x86_64 <"${here}/fixtures/tenko-release.json")"
      expect "release_asset_id of compact JSON (${mode})" "102" \
        "$(tr -d '\n ' <"${here}/fixtures/tenko-release.json" | release_asset_id tenko-0.0.1-linux-x86_64)"
    done
    # check_binary_case <what> <file> <exit> <message part> <message part>: check_binary refuses
    # the file with that status and says why.
    check_binary_case() {
      local out rc=0
      out="$(check_binary "$2" "$2" 2>&1)" || rc=$?
      expect "check_binary refuses ${1}: exit" "$3" "$rc"
      has "$out" "$4" "check_binary refuses ${1}: says why"
      has "$out" "$5" "check_binary refuses ${1}: shows what it is"
    }
    local v tmp
    tmp="$(mktemp -d)"
    cp "$installer" "${tmp}/tenko"
    check_binary_case "install.sh copied as tenko" "${tmp}/tenko" 5 "bytes, far too small for the Tenko binary" "starts with: #!/usr/bin/env bash"
    : >"${tmp}/empty"
    check_binary_case "an empty file" "${tmp}/empty" 5 "is empty (0 bytes)" "not the Tenko binary"
    printf 'this is not a program\n' >"${tmp}/text"
    check_binary_case "a text file" "${tmp}/text" 5 "is 22 bytes" "starts with: this is not a program"
    if command -v file >/dev/null 2>&1; then
      head -c 2097152 /dev/zero >"${tmp}/zeros"
      check_binary_case "2 MiB of zeros" "${tmp}/zeros" 5 "is not an ELF x86_64 executable" "file says:"
      if [[ -x /usr/sbin/nologin ]] && file -b /usr/sbin/nologin | grep -q 'ELF 64-bit LSB.*x86-64'; then
        cp /usr/sbin/nologin "${tmp}/nologin"
        head -c 2097152 /dev/zero >>"${tmp}/nologin"
        chmod 0755 "${tmp}/nologin"
        check_binary_case "an ELF that exits with a message" "${tmp}/nologin" 5 "does not run here (exit 1)" "not available"
      fi
    else
      echo "SKIP  file is not installed here: the ELF checks"
    fi
    rm -rf "$tmp"
    expect "--help lists --use-self" "yes" "$(bash "$installer" --help | grep -q -- '--use-self' && echo yes)"
    for v in tenko tenko.example.test a-b.example.test; do expect "valid_hostname ${v}" 0 "$(valid_hostname "$v"; echo $?)"; done
    for v in 192.0.2.1 -tenko "two words" tenko_1 ""; do expect "valid_hostname refuses '${v}'" 1 "$(valid_hostname "$v"; echo $?)"; done
    for v in /var/lib/tenko /srv/tenko-data /data/tenko; do expect "valid_data_dir ${v}" 0 "$(valid_data_dir "$v"; echo $?)"; done
    for v in / relative /home/user/tenko /tmp/x "/srv/with space" /srv/../etc; do expect "valid_data_dir refuses '${v}'" 1 "$(valid_data_dir "$v"; echo $?)"; done
    for v in controller controller,dns controller,dhcp,probe controller,dns,dhcp,probe controller,probe,dns; do expect "valid_roles ${v}" 0 "$(valid_roles "$v"; echo $?)"; done
    for v in dns probe "controller, dns" "controller," controller,dns,dns controller,scan; do expect "valid_roles refuses '${v}'" 1 "$(valid_roles "$v"; echo $?)"; done
    for v in wizard all ipam ipam,dns,discovery; do expect "valid_modules ${v}" 0 "$(valid_modules "$v"; echo $?)"; done
    for v in "" ipam,foo "ipam dns"; do expect "valid_modules refuses '${v}'" 1 "$(valid_modules "$v"; echo $?)"; done
    echo "== (1b) the shipped drop-ins, the toml helpers and the rerun of a configuration"
    expect "the embedded probe drop-in is deploy/systemd/probe.conf" "same" \
      "$(cmp -s <(probe_dropin_text) "${repo}/deploy/systemd/probe.conf" && echo same || echo differs)"
    expect "the embedded dhcp drop-in is deploy/systemd/dhcp-direct.conf" "same" \
      "$(cmp -s <(dhcp_direct_dropin_text) "${repo}/deploy/systemd/dhcp-direct.conf" && echo same || echo differs)"
    work="$(mktemp -d)"
    TMP="$work"
    cfg="${work}/tenko.toml"
    cat >"$cfg" <<'CFG_END'
# Tenko DDI node configuration, hand edited
data_dir = "/var/lib/tenko"
roles = "controller,dns"
# modules = ["ipam", "dns", "dhcp", "discovery"]   # not set

[profile]
name = "standard"

[server]
listen = ["0.0.0.0:9443", "[::]:9443"]

[tls]
mode = "internal_ca"
host_name = "tenko.example.test"
addresses = ["127.0.0.1", "192.0.2.10"]

[kek]
provider = "file"
path = "/etc/tenko/kek.key"

[dns]
# Held by hand: the resolved stub keeps 127.0.0.53:53
listen = [
  "192.0.2.10:53", # the one address of the node
]
forwarders = ["192.0.2.1"]

[dns.recursion]
enabled = true
roots = [
  ["a", "b"],
]
CFG_END
    expect "toml_get of a multi-line array" '[ "192.0.2.10:53", ]' \
      "$(toml_get "$cfg" dns listen | tr -s ' ')"
    expect "toml_get of a key in a section" '["192.0.2.1"]' "$(toml_get "$cfg" dns forwarders)"
    expect "toml_get of a top-level key" '"controller,dns"' "$(toml_get "$cfg" "" roles)"
    expect "toml_get of a key the file lacks" "" "$(toml_get "$cfg" "" modules)"
    expect "toml_sections" "(top level) profile server tls kek dns dns.recursion" "$(toml_sections "$cfg" | paste -sd' ' -)"
    expect "toml_set replaces a multi-line array and nothing else" "same" \
      "$(toml_set dns listen '["198.51.100.7:53"]' <"$cfg" | diff <(sed '/^listen = \[$/,/^\]$/c listen = ["198.51.100.7:53"]' "$cfg") - >/dev/null && echo same || echo differs)"
    expect "toml_set keeps the file when the value is the same" "same" \
      "$(toml_set dns forwarders '["192.0.2.1"]' <"$cfg" | cmp -s - "$cfg" && echo same || echo differs)"
    expect "toml_set drops a key" "0" "$(toml_set dns forwarders '' <"$cfg" | grep -c '^forwarders')"

    # The answers of an installer run, as answers() leaves them before the file is read.
    rerun_defaults() {
      ROLES=controller,dns MODULES=wizard PROFILE=home HOST_NAME=default.example.test
      DNS_ADDRESS=all FORWARDERS=198.51.100.1 API_PORT=8443
      OPT_ROLES="" OPT_MODULES="" OPT_PROFILE="" OPT_HOST="" OPT_DATA_DIR="" OPT_DNS_ADDRESS="" OPT_FORWARDERS=""
      SET_ROLES=0 SET_MODULES=0 SET_FORWARDERS=0 SET_DNS_ADDRESS=0
      HAVE_CONFIG=1 OPT_RECONFIGURE=1 KEK_TARGET=file DATA_DIR=/var/lib/tenko
    }
    # --reconfigure --roles controller,dns,dhcp,probe, nothing else given.
    rerun_defaults
    OPT_ROLES=controller,dns,dhcp,probe SET_ROLES=1 ROLES=controller,dns,dhcp,probe
    seed_from_config "$cfg"
    config_carry "$cfg" >"${work}/carry.out"
    carried="$(cat "$CARRY_FILE")"
    out="$(cat "${work}/carry.out")"
    has "$carried" 'roles = "controller,dns,dhcp,probe"' "reconfigure: the roles are the ones given"
    has "$carried" '  "192.0.2.10:53", # the one address of the node' "reconfigure: [dns] listen is carried over, comment and all"
    lacks "$carried" '0.0.0.0:53' "reconfigure: [dns] listen is not reset to every address"
    has "$carried" 'forwarders = ["192.0.2.1"]' "reconfigure: the forwarders are carried over, not the host's resolvers"
    has "$carried" 'listen = ["0.0.0.0:9443", "[::]:9443"]' "reconfigure: [server] listen is carried over"
    has "$carried" 'host_name = "tenko.example.test"' "reconfigure: [tls] is carried over"
    has "$carried" 'name = "standard"' "reconfigure: the profile is carried over"
    has "$carried" 'roots = [' "reconfigure: [dns.recursion] is carried over"
    expect "reconfigure: one [kek] section" "1" "$(grep -c '^\[kek\]' <<<"$carried")"
    expect "reconfigure: the dhcp role adds [dhcp] once" "1" "$(grep -c '^\[dhcp\]' <<<"$carried")"
    expect "reconfigure: the API port follows [server] listen" "9443" "$API_PORT"
    expect "reconfigure: the host name is the file's" "tenko.example.test" "$HOST_NAME"
    for sec in "the top-level keys" "[profile]" "[server]" "[tls]" "[kek]" "[dns]" "[dns.recursion]"; do
      has "$out" "..  Carried over ${sec} of" "reconfigure: says that ${sec} is carried over"
    done
    has "$out" "Carried over the top-level keys of ${CONFIG}, except roles (your answer)" "reconfigure: names the answer that replaced a top-level key"
    has "$out" "Added [dhcp]" "reconfigure: says that [dhcp] is new"
    lacks "$out" "Added [dns]" "reconfigure: [dns] is not added again"
    # Only the dns address given: the rest, the forwarders included, stays.
    rerun_defaults
    OPT_DNS_ADDRESS=198.51.100.7 SET_DNS_ADDRESS=1 DNS_ADDRESS=198.51.100.7
    seed_from_config "$cfg"
    config_carry "$cfg" >"${work}/carry.out"
    carried="$(cat "$CARRY_FILE")"
    has "$carried" 'listen = ["198.51.100.7:53"]' "reconfigure: --dns-address replaces [dns] listen"
    lacks "$carried" '192.0.2.10:53' "reconfigure: the multi-line listen is gone, not duplicated"
    has "$carried" 'forwarders = ["192.0.2.1"]' "reconfigure: --dns-address leaves the forwarders"
    has "$(cat "${work}/carry.out")" "Carried over [dns] of ${CONFIG}, except listen (your answer)" "reconfigure: names the key the flag replaced"
    # Nothing given: the file comes out as it went in.
    rerun_defaults
    seed_from_config "$cfg"
    config_carry "$cfg" >"${work}/carry.out"
    expect "reconfigure with no answers changes nothing" "same" "$(cmp -s "$CARRY_FILE" "$cfg" && echo same || echo differs)"
    expect "the dns answer is the file's own listen" "192.0.2.10:53" "$DNS_ADDRESS"

    # The stub of systemd-resolved: the dns role on every address is refused with --keep-resolved-stub.
    ss() {
      case "$*" in
      *-Hlnup*"sport = :53"*) echo 'UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=1,fd=13))' ;;
      esac
      return 0
    }
    stub_case() { # <active> <dns address> <keep stub>: step_ports in a subshell, its output and status
      rerun_defaults
      ACTIVE="$1" DNS_ADDRESS="$2" OPT_KEEP_STUB="$3"
      (step_ports 2>&1)
      echo "rc=$?"
    }
    out="$(stub_case 1 all 1)"
    has "$out" "rc=4" "stub: the dns role on every address with --keep-resolved-stub exits 4 on a rerun of a running node"
    has "$out" "--keep-resolved-stub was given" "stub: says why"
    has "$out" "--dns-address <addr>[,<addr>], or [dns] listen in" "stub: says what to do"
    out="$(stub_case 0 all 1)"
    has "$out" "rc=4" "stub: the same on a first start"
    out="$(stub_case 1 192.0.2.10 1)"
    has "$out" "rc=0" "stub: the node's own address is fine with --keep-resolved-stub"
    has "$out" "answers on 192.0.2.10" "stub: says where the dns role answers"
    out="$(stub_case 1 '0.0.0.0:53' 1)"
    has "$out" "rc=4" "stub: 0.0.0.0:53 is every address too"
    unset -f ss stub_case

    # --roles on a node that has started before.
    rerun_defaults
    DATA_DIR="${work}/data"
    ROLES=controller,dns,dhcp,probe SET_ROLES=1
    expect "roles: nothing to say on a node that has not started" "" "$(warn_roles_in_store)"
    mkdir -p "${DATA_DIR}/store"
    out="$(warn_roles_in_store)"
    has "$out" "!!" "roles: a warning line when the store exists"
    expect "roles: exactly one line" "1" "$(wc -l <<<"$out")"
    has "$out" "nodes page of the web UI" "roles: names the web UI"
    has "$out" "tenko node roles set <id> --roles controller,dns,dhcp,probe" "roles: names the command"
    has "$out" "PUT /api/v1/nodes/{id}/roles" "roles: names the API"
    OPT_RECONFIGURE=0
    expect "roles: silent without --reconfigure" "" "$(warn_roles_in_store)"
    expect "--help says it too" "yes" "$(bash "$installer" --help | tr -s ' \n' '  ' | grep -q 'tenko node roles set <id> --roles ...' && echo yes)"

    # The dhcp role's direct mode brings its drop-in.
    cat >"${work}/direct.toml" <<'CFG_END'
[dhcp]
# listen = [{ address = "192.0.2.10", mode = "relay" }]
listen = [{ address = "192.0.2.10", mode = "direct", interface = "eth0" }]
CFG_END
    ROLES=controller,dhcp
    expect "dhcp_direct_wanted with a direct listener" 0 "$(dhcp_direct_wanted "${work}/direct.toml"; echo $?)"
    ROLES=controller
    expect "dhcp_direct_wanted without the dhcp role" 1 "$(dhcp_direct_wanted "${work}/direct.toml"; echo $?)"
    ROLES=controller,dhcp
    expect "dhcp_direct_wanted without a direct listener" 1 "$(dhcp_direct_wanted "$cfg"; echo $?)"
    printf '[dhcp]\n# listen = [{ address = "192.0.2.10", mode = "direct", interface = "eth0" }]\n' >"${work}/commented.toml"
    expect "dhcp_direct_wanted ignores a comment" 1 "$(dhcp_direct_wanted "${work}/commented.toml"; echo $?)"
    rm -rf "$work"
    exit "$failures"
  )
  failures=$((failures + $?))
}

unit_checks
if [[ "${1:-}" == "--unit" ]]; then
  ((failures == 0)) && echo "== install.sh checks: all passed" || echo "== install.sh checks: ${failures} failed"
  exit $((failures > 0))
fi

binary="${1:?usage: install-sh-test.sh <tenko musl binary> [--systemd <newer binary>]}"
[[ -x "$binary" ]] || {
  echo "not an executable: ${binary}" >&2
  exit 2
}
binary="$(cd "$(dirname "$binary")" && pwd)/$(basename "$binary")"
version="$("$binary" --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[^ ]*' | head -n 1)"
newer=""
if [[ "${2:-}" == "--systemd" ]]; then
  newer="${3:?--systemd needs the newer binary}"
  newer="$(cd "$(dirname "$newer")" && pwd)/$(basename "$newer")"
fi
work="$(mktemp -d)"
server_pid=""
containers=()
cleanup() {
  [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null
  local c
  for c in "${containers[@]}"; do docker rm -f "$c" >/dev/null 2>&1; done
  rm -rf "$work"
}
trap cleanup EXIT
chmod 0755 "$work"
cp "$installer" "${work}/install.sh"
cp "$binary" "${work}/tenko"
cp "$unit" "${work}/tenko.service"
[[ -n "$newer" ]] && cp "$newer" "${work}/tenko-next"

# The script that runs in each container: POSIX tools only (the minimal images lack most).
cat >"${work}/inside.sh" <<'INSIDE_END'
#!/bin/bash
set -uo pipefail
failures=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; failures=$((failures + 1)); }
check() { local what="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi; }
mode() { stat -c '%a %U:%G' "$1" 2>/dev/null; }
as_tenko() {
  # setpriv runs the command in place (runuser forks), so a signal reaches tenko itself.
  if command -v setpriv >/dev/null 2>&1; then setpriv --reuid=tenko --regid=tenko --init-groups -- "$@"; else runuser -u tenko -- "$@"; fi
}
cd /tmp
install_args=(--yes --no-start --binary /i/tenko --host-name tenko.example.test --forwarders 192.0.2.1)

echo "-- install"
out="$(bash /i/install.sh "${install_args[@]}" 2>&1)"; rc=$?
printf '%s\n' "$out" | sed 's/^/      /'
[ "$rc" = 0 ] && pass "install exit 0" || fail "install exit ${rc}"
[ "$(mode /usr/local/bin/tenko)" = "755 root:root" ] && pass "binary 0755 root" || fail "binary: $(mode /usr/local/bin/tenko)"
[ "$(mode /etc/tenko)" = "750 root:tenko" ] && pass "/etc/tenko 0750 root:tenko" || fail "/etc/tenko: $(mode /etc/tenko)"
[ "$(mode /etc/tenko/tenko.toml)" = "640 root:tenko" ] && pass "tenko.toml 0640 root:tenko" || fail "tenko.toml: $(mode /etc/tenko/tenko.toml)"
[ "$(mode /etc/tenko/kek.key)" = "640 root:tenko" ] && pass "kek.key 0640 root:tenko (no systemd-creds here)" || fail "kek.key: $(mode /etc/tenko/kek.key)"
[ "$(mode /var/lib/tenko)" = "700 tenko:tenko" ] && pass "data directory 0700 tenko" || fail "data directory: $(mode /var/lib/tenko)"
check "the unit is deploy/systemd/tenko.service" sh -c '[ "$(sha256sum </etc/systemd/system/tenko.service)" = "$(sha256sum </i/tenko.service)" ]'
check "the KEK drop-in resets the credential" grep -qx 'LoadCredentialEncrypted=' /etc/systemd/system/tenko.service.d/kek-file.conf
check "tenko.toml: roles controller,dns" grep -qx 'roles = "controller,dns"' /etc/tenko/tenko.toml
check "tenko.toml: the file provider" grep -qx 'provider = "file"' /etc/tenko/tenko.toml
check "tenko.toml: forwarders" grep -qx 'forwarders = \["192.0.2.1"\]' /etc/tenko/tenko.toml
check "tenko.toml: the API listens on IPv4 and IPv6" grep -qx 'listen = \["0.0.0.0:8443", "\[::\]:8443"\]' /etc/tenko/tenko.toml
check "tenko config check" /usr/local/bin/tenko config check --config /etc/tenko/tenko.toml
key_before="$(sha256sum </etc/tenko/kek.key)"

echo "-- tenko serve by hand, as tenko"
# Started directly, not through the as_tenko function: a function in the background runs in a
# subshell, and the signal below would reach that shell instead of tenko.
if command -v setpriv >/dev/null 2>&1; then
  setpriv --reuid=tenko --regid=tenko --init-groups -- env TENKO_DATA_DIR=/var/lib/tenko /usr/local/bin/tenko serve --config /etc/tenko/tenko.toml >/tmp/serve.log 2>&1 &
else
  su -s /bin/sh tenko -c 'exec env TENKO_DATA_DIR=/var/lib/tenko /usr/local/bin/tenko serve --config /etc/tenko/tenko.toml' >/tmp/serve.log 2>&1 &
fi
pid=$!
ready=0
for _ in $(seq 90); do
  kill -0 "$pid" 2>/dev/null || break
  if [ -f /var/lib/tenko/tls/ca-root.pem ] &&
    /usr/local/bin/tenko health --url https://localhost:8443 --ca-file /var/lib/tenko/tls/ca-root.pem >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" = 1 ]; then pass "tenko health: ready at https://localhost:8443"; else fail "not ready"; sed 's/^/      /' /tmp/serve.log | tail -n 30; fi
for _ in $(seq 20); do grep -q 'dns role answering' /tmp/serve.log && break; sleep 1; done
grep -q 'dns role answering' /tmp/serve.log && pass "the dns role answers on port 53 (as the tenko account)" || fail "no dns role line"
grep -q 'THE KEY-ENCRYPTION KEY IS A PLAIN FILE' /tmp/serve.log && pass "the file provider warns, as documented" || fail "no file-provider warning"
token="$(as_tenko /usr/local/bin/tenko setup token --config /etc/tenko/tenko.toml --data-dir /var/lib/tenko 2>/dev/null)"
[ -n "$token" ] && pass "tenko setup token prints a token" || fail "no setup token"
kill -TERM "$pid"; status=0; wait "$pid" || status=$?
[ "$status" = 0 ] && pass "SIGTERM: exit 0" || fail "serve exit ${status}"

echo "-- the same version again"
out="$(bash /i/install.sh "${install_args[@]}" 2>&1)"; rc=$?
[ "$rc" = 0 ] && pass "rerun exit 0" || fail "rerun exit ${rc}"
printf '%s\n' "$out" | grep -q 'nothing was changed' && pass "rerun: nothing was changed" || { fail "rerun changed something"; printf '%s\n' "$out" | sed 's/^/      /'; }

echo "-- --reconfigure --roles controller"
out="$(bash /i/install.sh "${install_args[@]}" --reconfigure --roles controller 2>&1)"; rc=$?
[ "$rc" = 0 ] && pass "reconfigure exit 0" || { fail "reconfigure exit ${rc}"; printf '%s\n' "$out" | sed 's/^/      /'; }
check "roles = controller" grep -qx 'roles = "controller"' /etc/tenko/tenko.toml
check "no [dns] section" sh -c '! grep -q "^\[dns\]" /etc/tenko/tenko.toml'
check "the old file is kept as .bak" sh -c 'ls /etc/tenko/tenko.toml.*.bak'
check "the key is unchanged" sh -c '[ "$(sha256sum </etc/tenko/kek.key)" = "'"$key_before"'" ]'

echo "-- --uninstall keeps the data and the key, removes the updates layout"
# round2: a layout as a running node leaves it (binaries and the two links), next to the store.
mkdir -p /var/lib/tenko/updates/0.0.1 /var/lib/tenko/updates/0.0.2
printf 'binary' >/var/lib/tenko/updates/0.0.1/tenko
printf 'binary' >/var/lib/tenko/updates/0.0.2/tenko
ln -sfn /var/lib/tenko/updates/0.0.2 /var/lib/tenko/updates/current
ln -sfn /var/lib/tenko/updates/0.0.1 /var/lib/tenko/updates/previous
out="$(bash /i/install.sh --yes --uninstall 2>&1)"; rc=$?
[ "$rc" = 0 ] && pass "uninstall exit 0" || { fail "uninstall exit ${rc}"; printf '%s\n' "$out" | sed 's/^/      /'; }
check "updates/ removed" test ! -e /var/lib/tenko/updates
printf '%s\n' "$out" | grep -q 'Removed /var/lib/tenko/updates' && pass "the closing lines say so" || fail "no updates line in the output"
check "binary removed" test ! -e /usr/local/bin/tenko
check "unit removed" test ! -e /etc/systemd/system/tenko.service
check "drop-ins removed" test ! -e /etc/systemd/system/tenko.service.d
check "data kept" test -d /var/lib/tenko/store
check "key kept" test -f /etc/tenko/kek.key

echo "-- install again: the key and the configuration are kept"
out="$(bash /i/install.sh "${install_args[@]}" 2>&1)"; rc=$?
[ "$rc" = 0 ] && pass "reinstall exit 0" || { fail "reinstall exit ${rc}"; printf '%s\n' "$out" | sed 's/^/      /'; }
printf '%s\n' "$out" | grep -q 'Keeping the key-encryption key file' && pass "the key file is kept" || fail "key not kept"
check "the key is unchanged" sh -c '[ "$(sha256sum </etc/tenko/kek.key)" = "'"$key_before"'" ]'

echo "-- --uninstall --purge"
out="$(bash /i/install.sh --yes --uninstall --purge 2>&1)"; rc=$?
[ "$rc" = 0 ] && pass "purge exit 0" || { fail "purge exit ${rc}"; printf '%s\n' "$out" | sed 's/^/      /'; }
check "data removed" test ! -e /var/lib/tenko
check "/etc/tenko removed" test ! -e /etc/tenko
check "account removed" sh -c '! id tenko'
exit "$failures"
INSIDE_END

# run_inside <image> [docker options]: inside.sh in a throwaway container of the image.
run_inside() {
  local image="$1" name rc=0 prep=""
  shift
  name="tenko-install-test-$$-${#containers[@]}"
  containers+=("$name")
  case "$image" in
  # The minimal image has no useradd; a RHEL 9 host has it (shadow-utils).
  rockylinux*) prep="microdnf install -y -q shadow-utils util-linux >/dev/null 2>&1 || microdnf install -y shadow-utils util-linux;" ;;
  esac
  docker run --rm --name "$name" -v "${work}:/i:ro" "$@" "$image" bash -c "${prep} bash /i/inside.sh" || rc=$?
  return "$rc"
}

for image in ubuntu:24.04 debian:12-slim rockylinux/rockylinux:9-minimal; do
  echo
  echo "== (3) install.sh --no-start in ${image}"
  if run_inside "$image"; then pass "${image}: every check"; else fail "${image}: see the FAIL lines above"; fi
done

echo
echo "== (2) dry run in ubuntu:24.04"
out="$(docker run --rm -v "${work}:/i:ro" ubuntu:24.04 bash -c \
  'bash /i/install.sh --dry-run --yes --no-start --binary /i/tenko --host-name tenko.example.test 2>&1; echo "EXIT=$?"; for p in /etc/tenko /usr/local/bin/tenko /var/lib/tenko /etc/systemd/system/tenko.service; do [ -e "$p" ] && echo "EXISTS $p"; done; id tenko >/dev/null 2>&1 && echo "EXISTS user"; true')"
printf '%s\n' "$out" | grep -E '\[dry-run\]|EXIT|EXISTS' | sed 's/^/      /'
has "$out" "EXIT=0" "dry run exit 0"
has "$out" "[dry-run] useradd --system" "dry run: the account"
has "$out" "[dry-run] install -m 0755 -o root -g root" "dry run: the binary"
has "$out" "[dry-run] write /etc/tenko/tenko.toml" "dry run: the configuration"
has "$out" "[dry-run] create the key-encryption key: /etc/tenko/kek.key" "dry run: the key"
has "$out" "[dry-run] write /etc/systemd/system/tenko.service" "dry run: the unit"
lacks "$out" "EXISTS" "the dry run changed nothing"
out="$(docker run --rm -v "${work}:/i:ro" ubuntu:24.04 bash -c \
  'bash /i/install.sh --dry-run --yes --no-start --use-self --binary /i/tenko --host-name tenko.example.test 2>&1; echo "EXIT=$?"')"
has "$out" "EXIT=0" "dry run --use-self: exit 0"
has "$out" "--use-self: the node is not started (--no-start)" "dry run --use-self: says that --no-start leaves the resolver"
out="$(docker run --rm -v "${work}:/i:ro" ubuntu:24.04 bash -c \
  'bash /i/install.sh --dry-run --yes --no-start --use-self --roles controller --binary /i/tenko 2>&1; echo "EXIT=$?"; bash /i/install.sh --dry-run --yes --no-start --use-self --dns-address 192.0.2.53 --binary /i/tenko 2>&1; echo "EXIT=$?"')"
has "$out" "--use-self needs the dns role (--roles controller,dns)" "--use-self without the dns role is refused"
has "$out" "--use-self needs the dns role to answer on 127.0.0.1 port 53" "--use-self with a dns address that excludes loopback is refused"
expect "both refusals exit 2" "2 2" "$(grep -o 'EXIT=[0-9]*' <<<"$out" | sed 's/EXIT=//' | paste -sd' ')"

echo
echo "== (4) downloads from a loopback server"
mkdir -p "${work}/srv/good" "${work}/srv/bad" "${work}/srv/api/repos/linkztream/tenko/releases/assets"
cp "$binary" "${work}/srv/good/tenko-${version}-linux-x86_64"
(cd "${work}/srv/good" && sha256sum "tenko-${version}-linux-x86_64" >SHA256SUMS && printf '%064d  install.sh\n' 0 >>SHA256SUMS)
cp "$binary" "${work}/srv/bad/tenko-${version}-linux-x86_64"
printf '%064d  tenko-%s-linux-x86_64\n' 0 "$version" >"${work}/srv/bad/SHA256SUMS"
sed "s/0\.0\.1/${version}/g" "${here}/fixtures/tenko-release.json" >"${work}/srv/api/repos/linkztream/tenko/releases/latest"
cp "${work}/srv/good/SHA256SUMS" "${work}/srv/api/repos/linkztream/tenko/releases/assets/101"
cp "$binary" "${work}/srv/api/repos/linkztream/tenko/releases/assets/102"
token="test-token-for-the-loopback-server-4c1e"
cat >"${work}/server.py" <<'EOF'
import functools, http.server, sys
directory, port_file, auth_log, expected = sys.argv[1:5]
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        got = self.headers.get("Authorization")
        state = "absent" if got is None else ("matching" if got == "Bearer " + expected else "wrong")
        with open(auth_log, "a") as f:
            f.write(f"{self.path} authorization={state} accept={self.headers.get('Accept')}\n")
        super().do_GET()
    def log_message(self, *args):
        pass
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=directory))
with open(port_file, "w") as f:
    f.write(str(server.server_address[1]))
server.serve_forever()
EOF
python3 "${work}/server.py" "${work}/srv" "${work}/port" "${work}/auth.log" "$token" &
server_pid=$!
for _ in $(seq 50); do [[ -s "${work}/port" ]] && break; sleep 0.1; done
url="http://127.0.0.1:$(cat "${work}/port")"
# curl is not in the image; a wrapper records every curl argument list.
cat >"${work}/download.sh" <<'EOF'
#!/bin/bash
set -u
apt-get update -q >/dev/null 2>&1 && apt-get install -y -q --no-install-recommends curl ca-certificates >/dev/null 2>&1
real="$(command -v curl)"
mkdir -p /opt/wrap
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >>/tmp/curl-args.log\nexec %s "$@"\n' "$real" >/opt/wrap/curl
chmod 0755 /opt/wrap/curl
export PATH="/opt/wrap:$PATH"
base="$1" token="$2"
echo "-- a wrong checksum"
bash /i/install.sh --yes --no-start --release-url "${base}/bad" --version "$3" --host-name tenko.example.test >/tmp/bad.log 2>&1
echo "BAD_EXIT=$?"
grep -o 'does not match SHA256SUMS[^;]*' /tmp/bad.log
[ -e /usr/local/bin/tenko ] && echo "BAD_INSTALLED"
echo "-- a release directory, latest from SHA256SUMS"
bash /i/install.sh --yes --no-start --release-url "${base}/good" --host-name tenko.example.test >/tmp/good.log 2>&1
echo "GOOD_EXIT=$?"
grep -o 'SHA-256 verified against SHA256SUMS' /tmp/good.log
/usr/local/bin/tenko --version
bash /i/install.sh --yes --uninstall --purge >/dev/null 2>&1
echo "-- the GitHub API with a token"
TENKO_GITHUB_API="${base}/api" GITHUB_TOKEN="$token" bash /i/install.sh --yes --no-start --host-name tenko.example.test >/tmp/api.log 2>&1
echo "API_EXIT=$?"
grep -o 'SHA-256 verified against SHA256SUMS' /tmp/api.log
grep -c . /tmp/curl-args.log | sed 's/^/CURL_CALLS=/'
grep -qF "$token" /tmp/curl-args.log /tmp/api.log && echo "TOKEN_LEAKED"
true
EOF
out="$(docker run --rm --network host -v "${work}:/i:ro" ubuntu:24.04 bash /i/download.sh "$url" "$token" "$version" 2>&1)"
printf '%s\n' "$out" | sed 's/^/      /'
has "$out" "BAD_EXIT=5" "a wrong checksum: exit 5"
has "$out" "does not match SHA256SUMS" "a wrong checksum: the message"
lacks "$out" "BAD_INSTALLED" "a wrong checksum: nothing installed"
has "$out" "GOOD_EXIT=0" "release directory: exit 0"
has "$out" "tenko ${version}" "release directory: the binary installed"
has "$out" "API_EXIT=0" "GitHub API with a token: exit 0"
lacks "$out" "TOKEN_LEAKED" "the token is in no curl argument list and not in the output"
for path in /api/repos/linkztream/tenko/releases/latest /api/repos/linkztream/tenko/releases/assets/101 /api/repos/linkztream/tenko/releases/assets/102; do
  grep -q "^${path} authorization=matching" "${work}/auth.log" && pass "GET ${path} with the Authorization header" ||
    fail "GET ${path}: $(grep -F "$path" "${work}/auth.log" | head -n 1)"
done
grep -q '^/api/repos/linkztream/tenko/releases/assets/102 .*accept=application/octet-stream' "${work}/auth.log" &&
  pass "the asset is asked for as application/octet-stream" || fail "asset Accept header"
grep -q '^/good/.* authorization=absent' "${work}/auth.log" && pass "the release directory gets no token" ||
  fail "release directory: $(grep -F /good/ "${work}/auth.log" | head -n 1)"

# ── (5) systemd ─────────────────────────────────────────────────────────────────────────────
if [[ -n "$newer" ]]; then
  echo
  echo "== (5) the whole life in a systemd container"
  if [[ -d /run/systemd/system ]] && command -v systemd-creds >/dev/null 2>&1; then
    # The check install.sh runs before it trusts a sealed key, against this host's service
    # manager (a transient unit as nobody; nothing is installed).
    delivery() {
      (
        # shellcheck source=../../install.sh
        source "$installer"
        set +eE
        trap - ERR
        TMP="$(mktemp -d)"
        NEW_KEY="$(openssl rand -hex 32)"
        printf '%s' "$NEW_KEY" | systemd-creds encrypt --name=tenko_kek - "${TMP}/k.cred" >/dev/null 2>&1
        [[ "$1" == wrong ]] && NEW_KEY="$(openssl rand -hex 32)"
        if credential_delivered "${TMP}/k.cred" nobody; then echo delivered; else echo "not delivered"; fi
        rm -rf "$TMP"
      )
    }
    expect "this host: credential_delivered" delivered "$(delivery right)"
    expect "this host: credential_delivered compares the content" "not delivered" "$(delivery wrong)"
  fi
  docker build -q -t tenko-install-test-systemd - >/dev/null <<'EOF'
FROM ubuntu:24.04
RUN apt-get update -q && apt-get install -y -q --no-install-recommends systemd systemd-sysv dbus \
      iproute2 openssl ca-certificates systemd-resolved && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
  sysname="tenko-install-test-systemd-$$"
  containers+=("$sysname")
  docker run -d --name "$sysname" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --tmpfs /run --tmpfs /run/lock -v "${work}:/i:ro" --hostname tenko tenko-install-test-systemd >/dev/null
  in_sys() { docker exec -i "$sysname" bash -c "$1"; }
  for _ in $(seq 60); do
    state="$(in_sys 'systemctl is-system-running 2>/dev/null' || true)"
    [[ "$state" == running || "$state" == degraded ]] && break
    sleep 1
  done
  pass "systemd in the container: ${state}"
  # As on Ubuntu and Debian with systemd-resolved: /etc/resolv.conf is the link to the stub's
  # file (Docker mounts a plain file there, which the installer could not replace by a link).
  in_sys 'umount /etc/resolv.conf 2>/dev/null; ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf'
  expect "/etc/resolv.conf is the stub's link" "../run/systemd/resolve/stub-resolv.conf" "$(in_sys 'readlink /etc/resolv.conf')"
  # The Home profile signs in with a PIN: digits only, four or more, no simple pattern.
  password="48213907"
  args="--yes --binary /i/tenko --host-name tenko.example.test --forwarders 192.0.2.1"

  # Whether this container's service manager hands encrypted credentials to services (a
  # Docker container under WSL does not, although systemd-creds seals): the installer must
  # notice that by itself and fall back to a plain key file.
  delivers="$(in_sys 'openssl rand -hex 32 | systemd-creds encrypt --name=probe - /root/probe.cred >/dev/null 2>&1 &&
    systemd-run --quiet --wait --pipe --collect -p LoadCredentialEncrypted=probe:/root/probe.cred /bin/sh -c "test -s \"\$CREDENTIALS_DIRECTORY/probe\"" </dev/null >/dev/null 2>&1 && echo yes || echo no; rm -f /root/probe.cred')"
  echo "      the container's service manager delivers encrypted credentials: ${delivers}"

  echo "-- install, start, setup"
  rc=0
  out="$(printf '%s\n' "$password" | in_sys "bash /i/install.sh ${args} --admin admin --password-stdin 2>&1")" || rc=$?
  printf '%s\n' "$out" | sed 's/^/      /'
  expect "install exit" 0 "$rc"
  if [[ "$delivers" == yes ]]; then
    has "$out" "sealed with systemd-creds" "the key is sealed with systemd-creds"
    has "$(in_sys 'journalctl -u tenko --no-pager')" "loaded the key-encryption key from a systemd credential" "the server reads the credential"
  else
    has "$out" "because the service manager does not hand encrypted credentials to services here" "no delivery: the installer notices and says why"
    expect "no delivery: a plain key file instead" "file" "$(in_sys 'test -f /etc/tenko/kek.key && ! test -e /etc/tenko/kek.cred && echo file')"
  fi
  has "$out" "The node is ready" "the node is ready"
  has "$out" "First-run setup is complete" "setup with --admin"
  lacks "$out" "$password" "the password appears nowhere"
  expect "the service" active "$(in_sys 'systemctl is-active tenko')"
  expect "the setup token is gone" none "$(in_sys 'test -e /var/lib/tenko/setup-token && echo present || echo none')"
  expect "the layout runs" "${version}" "$(in_sys 'readlink /var/lib/tenko/updates/current')"
  # systemd-resolved holds 127.0.0.53:53; the dns role on every address needs the port.
  has "$out" "systemd-resolved no longer listens on port 53" "the stub listener is turned off (--yes)"
  expect "the drop-in of systemd-resolved" present "$(in_sys 'test -f /etc/systemd/resolved.conf.d/tenko.conf && echo present')"
  has "$(in_sys 'ss -Hlnup "sport = :53"')" "tenko" "tenko holds UDP port 53"

  echo "-- the same version again"
  out="$(in_sys "bash /i/install.sh ${args} 2>&1")"
  has "$out" "nothing was changed" "rerun: nothing was changed"

  echo "-- --use-self, systemd-resolved"
  out="$(in_sys "bash /i/install.sh ${args} --use-self --dry-run 2>&1")"
  has "$out" "[dry-run] write /etc/systemd/resolved.conf.d/tenko.conf" "dry run --use-self: the drop-in of systemd-resolved"
  has "$out" "[dry-run] systemctl restart systemd-resolved" "dry run --use-self: resolved restarts"
  expect "the dry run wrote no DNS=" "stub only" "$(in_sys 'grep -q "^DNS=" /etc/systemd/resolved.conf.d/tenko.conf && echo has DNS || echo stub only')"
  rc=0
  out="$(in_sys "bash /i/install.sh ${args} --use-self 2>&1")" || rc=$?
  printf '%s\n' "$out" | grep -E '!!|ok  The host|xx' | sed 's/^/      /'
  expect "--use-self exit" 0 "$rc"
  has "$out" "The host resolves through Tenko: DNS=127.0.0.1" "--use-self: systemd-resolved is pointed at Tenko"
  expect "the drop-in" "DNS=127.0.0.1" "$(in_sys 'grep "^DNS=" /etc/systemd/resolved.conf.d/tenko.conf')"
  expect "the drop-in keeps the stub off" "DNSStubListener=no" "$(in_sys 'grep "^DNSStubListener=" /etc/systemd/resolved.conf.d/tenko.conf')"
  has "$(in_sys 'resolvectl dns 2>&1')" "127.0.0.1" "systemd-resolved lists 127.0.0.1 as a DNS server"
  expect "/etc/tenko keeps its group" "750 root:tenko" "$(in_sys 'stat -c "%a %U:%G" /etc/tenko')"
  expect "the state records it" "resolved" "$(in_sys "sed -n 's/^use_self=//p' /etc/tenko/installer.state")"
  out="$(in_sys "bash /i/install.sh ${args} --use-self 2>&1")"
  has "$out" "nothing was changed" "--use-self again: nothing was changed"

  echo "-- upgrade to the newer binary"
  next="$("${work}/tenko-next" --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[^ ]*' | head -n 1)"
  rc=0
  out="$(in_sys "bash /i/install.sh --yes --binary /i/tenko-next 2>&1")" || rc=$?
  printf '%s\n' "$out" | sed 's/^/      /'
  expect "upgrade exit" 0 "$rc"
  has "$out" "Upgrading ${version} to ${next}" "upgrade announced"
  has "$out" "The data directory needs" "tenko upgrade check ran"
  expect "the layout runs" "$next" "$(in_sys 'readlink /var/lib/tenko/updates/current')"
  expect "previous" "$version" "$(in_sys 'readlink /var/lib/tenko/updates/previous')"
  has "$(in_sys 'tenko health --live --url https://localhost:8443 --ca-file /var/lib/tenko/tls/ca-root.pem')" "$next" "health --live reports ${next}"
  expect "setup is still complete" none "$(in_sys 'test -e /var/lib/tenko/setup-token && echo present || echo none')"
  out="$(in_sys "bash /i/install.sh --yes --binary /i/tenko 2>&1")"
  has "$out" "newer than ${version}; the binary is kept" "an older binary does not downgrade"

  echo "-- uninstall keeps the data and the key, purge removes them"
  in_sys 'bash /i/install.sh --yes --uninstall >/dev/null 2>&1'
  expect "after uninstall" "no unit, data, key" "$(in_sys 'test -e /etc/systemd/system/tenko.service || printf "no unit, "; test -d /var/lib/tenko/store && printf "data, "; { test -f /etc/tenko/kek.cred || test -f /etc/tenko/kek.key; } && echo key')"
  expect "systemd-resolved listens on 127.0.0.53 again" stub "$(in_sys 'test ! -e /etc/systemd/resolved.conf.d/tenko.conf && ss -Hlnup "sport = :53" | grep -q systemd-resolve && echo stub')"
  in_sys 'bash /i/install.sh --yes --uninstall --purge >/dev/null 2>&1'
  expect "after purge" "gone" "$(in_sys 'test -e /var/lib/tenko || test -e /etc/tenko || id tenko >/dev/null 2>&1 || echo gone')"

  echo "-- --use-self without systemd-resolved: /etc/resolv.conf, restored by --uninstall"
  in_sys 'systemctl stop systemd-resolved'
  before="$(in_sys 'readlink /etc/resolv.conf || sha256sum </etc/resolv.conf')"
  rc=0
  out="$(in_sys "bash /i/install.sh ${args} --use-self 2>&1")" || rc=$?
  printf '%s\n' "$out" | grep -E '!!|ok  The host|xx' | sed 's/^/      /'
  expect "--use-self exit" 0 "$rc"
  has "$out" "/etc/resolv.conf lists 127.0.0.1 only" "--use-self: /etc/resolv.conf is pointed at Tenko"
  expect "resolv.conf names Tenko" "nameserver 127.0.0.1" "$(in_sys 'grep ^nameserver /etc/resolv.conf')"
  has "$(in_sys 'cat /etc/resolv.conf')" "Written by the Tenko installer (--use-self)" "resolv.conf says who wrote it"
  expect "the state records the link it replaced" "present" "$(in_sys 'grep -q "^use_self=resolv_conf" /etc/tenko/installer.state && grep -q "^use_self_resolv_link=" /etc/tenko/installer.state && echo present')"
  in_sys 'bash /i/install.sh --yes --uninstall >/dev/null 2>&1'
  expect "--uninstall restores resolv.conf" "$before" "$(in_sys 'readlink /etc/resolv.conf || sha256sum </etc/resolv.conf')"
  in_sys 'bash /i/install.sh --yes --uninstall --purge >/dev/null 2>&1; systemctl start systemd-resolved'

  echo "-- systemd-creds cannot seal: a plain key file and the drop-in"
  in_sys 'mkdir -p /opt/shim && printf "#!/bin/sh\necho \"Failed to determine local credential key: Operation not permitted\" >&2\nexit 1\n" >/opt/shim/systemd-creds && chmod 0755 /opt/shim/systemd-creds'
  rc=0
  out="$(in_sys "PATH=/opt/shim:\$PATH bash /i/install.sh ${args} 2>&1")" || rc=$?
  printf '%s\n' "$out" | grep -E '!!|ok  (The node|Created|Wrote)' | sed 's/^/      /'
  expect "fallback install exit" 0 "$rc"
  has "$out" "The key-encryption key is a plain file, /etc/tenko/kek.key, because systemd-creds cannot seal a key here" "the warning says why"
  has "$out" "Seal a plain key later" "the warning says how to seal it later"
  expect "the service with the drop-in" active "$(in_sys 'systemctl is-active tenko')"
  has "$(in_sys 'systemctl show -p DropInPaths --value tenko')" "kek-file.conf" "the drop-in is loaded"
  has "$(in_sys 'journalctl -u tenko --no-pager')" "THE KEY-ENCRYPTION KEY IS A PLAIN FILE" "the server uses the key file"
  in_sys 'bash /i/install.sh --yes --uninstall --purge >/dev/null 2>&1'

  echo "-- an installation made by hand without a credential (the default provider)"
  in_sys 'install -m 0755 /i/tenko /usr/local/bin/tenko && useradd --system --home-dir /var/lib/tenko --no-create-home --shell /usr/sbin/nologin tenko &&
    install -d -m 0750 -o root -g tenko /etc/tenko && install -d -m 0700 -o tenko -g tenko /var/lib/tenko &&
    printf "data_dir = \"/var/lib/tenko\"\nroles = \"controller\"\n[tls]\nalt_names = [\"localhost\"]\n" >/etc/tenko/tenko.toml && chmod 0640 /etc/tenko/tenko.toml && chgrp tenko /etc/tenko/tenko.toml &&
    sed -e "s/^LoadCredentialEncrypted=/# LoadCredentialEncrypted=/" -e "s/^Environment=TENKO_KEK__/# Environment=TENKO_KEK__/" /i/tenko.service >/etc/systemd/system/tenko.service &&
    systemctl daemon-reload && systemctl start tenko && sleep 8 && systemctl is-active tenko && test -d /var/lib/tenko/store'
  rc=0
  out="$(in_sys "bash /i/install.sh --yes --binary /i/tenko-next 2>&1")" || rc=$?
  printf '%s\n' "$out" | grep -E '!!|ok  (The node|Installed)' | sed 's/^/      /'
  expect "hand-made install upgraded, exit" 0 "$rc"
  has "$out" "No key in /etc/tenko: the [kek] section" "the hand-made key is kept"
  expect "the service after the upgrade" active "$(in_sys 'systemctl is-active tenko')"
  expect "the layout runs" "$next" "$(in_sys 'readlink /var/lib/tenko/updates/current')"
  expect "no new key file" none "$(in_sys 'test -e /etc/tenko/kek.key -o -e /etc/tenko/kek.cred && echo present || echo none')"
fi

echo
if ((failures > 0)); then
  echo "== install.sh checks: ${failures} failed"
  exit 1
fi
echo "== install.sh checks: all passed"
