#!/bin/bash
# Replays each recorded fixture through sspi's acceptor under libfaketime, since sspi reads
# the system clock and a recorded authenticator is outside the skew after five minutes.
# Needs the faketime command (package faketime). The test binary runs directly under
# faketime; cargo itself does not, or it would rebuild on every faked timestamp. The
# ms-krb5 fixtures are skipped: sspi answers them under the other OID (RESULT.md, S3),
# which this check does not measure.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE" || exit 1
BIN=$(cargo test --no-run --message-format=json 2>/dev/null | sed -n 's/.*"executable":"\([^"]*spike_krb-[^"]*\)".*/\1/p' | head -1)
[ -x "$BIN" ] || { echo "test binary not found"; exit 1; }
for d in fixtures/*/; do
  name=$(basename "$d")
  case $name in *ms-krb5*) continue;; esac
  when=$(sed -n 's/^recorded_unix=//p' "$d/meta.txt")
  at=$(date -u -d "@$((when + 1))" '+%Y-%m-%d %H:%M:%S')
  out=$(SPIKE_FIXTURE=$name faketime "$at" "$BIN" --ignored --exact fixtures_test::sspi_acceptor_replays_the_recorded_exchange_named_in_env --nocapture 2>&1)
  if echo "$out" | grep -q 'test result: ok. 1 passed'; then
    echo "$name: sspi accepted ($(echo "$out" | grep -o 'client [^,]*, key [A-Za-z0-9]*'))"
  else
    echo "$name: sspi FAILED"; echo "$out" | grep -E 'panicked|Error|invalid' | head -3
  fi
done
