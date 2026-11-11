#!/bin/bash
# Tenko's API from inside the lab network, for round.sh (the host of a Docker Desktop cannot
# reach the bridge network's addresses). Usage, with the request body on standard input:
#
#   api.sh setup                 the first-run setup under the Lab profile; the session cookie
#                                goes to /lab/out/cookie (0600)
#   api.sh <METHOD> <path>       a request with that cookie; prints the body, then the status
#                                on a line of its own
#
# A body whose `password` is "@OTP@" gets the one-time password of the run from
# /lab/secrets/otp, and the setup gets the administrator's password from /lab/secrets/tenko, so
# that no secret is ever in an argument list or in the round's output.
set -euo pipefail

base=http://198.51.100.3:8443
body="$(cat)"
out="$(mktemp)"
trap 'rm -f "$out"' EXIT

if [[ "$1" == setup ]]; then
  body="$(printf '%s' "$body" | jq -c --rawfile password /lab/secrets/tenko '.admin.password = ($password | rtrimstr("\n"))')"
  headers="$(mktemp)"
  status="$(printf '%s' "$body" | curl -sS -D "$headers" -o "$out" -w '%{http_code}' \
    -H "Origin: $base" -H 'Content-Type: application/json' --data-binary @- "$base/api/v1/setup")"
  umask 077
  tr -d '\r' <"$headers" | sed -n 's/^[Ss]et-[Cc]ookie: \(\(__Host-\)\{0,1\}tenko_session=[^;]*\).*/\1/p' | head -n 1 >/lab/out/cookie
  rm -f "$headers"
  cat "$out"
  printf '\n%s\n' "$status"
  exit 0
fi

method="$1" path="$2"
args=(-sS -o "$out" -w '%{http_code}' -X "$method" -H "Origin: $base"
  -H "Idempotency-Key: $(cat /proc/sys/kernel/random/uuid)" -H "@/lab/out/cookie.header")
printf 'Cookie: %s\n' "$(cat /lab/out/cookie)" >/lab/out/cookie.header
chmod 0600 /lab/out/cookie.header
if [[ -n "$body" ]]; then
  body="$(printf '%s' "$body" | jq -c --rawfile otp /lab/secrets/otp 'if .password == "@OTP@" then .password = ($otp | rtrimstr("\n")) else . end')"
  status="$(printf '%s' "$body" | curl "${args[@]}" -H 'Content-Type: application/json' --data-binary @- "$base/api/v1$path")" || status=000
else
  status="$(curl "${args[@]}" "$base/api/v1$path")" || status=000
fi
cat "$out"
printf '\n%s\n' "$status"
