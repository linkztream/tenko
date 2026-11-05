#!/bin/bash
# One exchange between MIT's GSS-API (peer/gss-peer.c) and a spike acceptor, recorded.
#
#   KRB5_CONFIG=/opt/mitlab/krb5.conf bash scripts/run-interop.sh <acceptor> <mech> <spn> <out-prefix> --key 18:2:<hex> [--key ...]
#
# acceptor: own | sspi; mech: krb5 | ms-krb5 | spnego; spn: DNS/tenko.corp.example.test.
# A ticket cache for the client must exist (kinit). Exit 0 when the peer printed RESULT PASS.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
ACCEPTOR=$1; MECH=$2; SPN=$3; PREFIX=$4; shift 4
PORT=${SPIKE_PORT:-5353}
[ -x "$HERE/target/debug/spike-krb" ] || (cd "$HERE" && cargo build)
[ -x "$HERE/target/gss-peer" ] || gcc -O2 -Wall -o "$HERE/target/gss-peer" "$HERE/peer/gss-peer.c" -lgssapi_krb5
"$HERE/target/debug/spike-krb" serve --acceptor "$ACCEPTOR" "$@" --spn "$SPN" --listen "127.0.0.1:$PORT" --once > "$PREFIX.server.log" 2>&1 &
SERVER=$!
sleep 0.5
"$HERE/target/gss-peer" --mech "$MECH" --target "DNS@${SPN#DNS/}" --port "$PORT" --record "$PREFIX" > "$PREFIX.peer.log" 2>&1
RC=$?
wait $SERVER
echo "$ACCEPTOR $MECH $SPN: peer exit $RC"
grep -E 'context:|session:' "$PREFIX.server.log"
grep -E 'RESULT|verified|failed|supplementary' "$PREFIX.peer.log"
exit $RC
