#!/usr/bin/env bash
# Brings up deploy/compose/quickstart.example.yml once, as its header tells a user to: a
# copy of the file as compose.yml in an empty directory, TENKO_VERSION in .env, the key as a
# secret owned by uid 65532, `docker compose up -d`, then waits for the image's HEALTHCHECK,
# reads the setup token, asks `tenko health` inside the container, checks that the dns role
# answers, and removes everything again (`docker compose down -v`), also on failure.
#
# Usage, as root where Docker runs:
#   bash deploy/proxmox/test/quickstart-test.sh <version>
# The image ghcr.io/linkztream/tenko:<version> must exist locally or be pullable; to test an
# unpublished tree, build it under that name first:
#   docker build -f deploy/Dockerfile -t ghcr.io/linkztream/tenko:<version> .
# Port 53 is published on 127.0.0.1 only (TENKO_DNS_BIND), 8443 on every address.
#
# License: Copyright (c) 2026. All rights reserved. See LICENSE at the repository root.

set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "${here}/../../.." && pwd)"
version="${1:?usage: quickstart-test.sh <version>}"
work="$(mktemp -d)"
project="tenko-quickstart-test-$$"
compose() { docker compose -p "$project" --project-directory "$work" -f "${work}/compose.yml" "$@"; }
cleanup() {
  compose down -v --timeout 30 >/dev/null 2>&1
  rm -rf "$work"
}
trap cleanup EXIT
failures=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() {
  printf 'FAIL  %s\n' "$*"
  failures=$((failures + 1))
}

cp "${repo}/deploy/compose/quickstart.example.yml" "${work}/compose.yml"
printf 'TENKO_VERSION=%s\nTENKO_DNS_BIND=127.0.0.1\n' "$version" >"${work}/.env"
(umask 077 && mkdir -p "${work}/secrets" && openssl rand -hex 32 >"${work}/secrets/tenko_kek")
chown 65532:65532 "${work}/secrets/tenko_kek"
chmod 0400 "${work}/secrets/tenko_kek"

echo "== docker compose config"
if compose config --quiet; then pass "the file is valid"; else fail "docker compose config"; fi
mkdir -p "${work}/bare"
cp "${work}/compose.yml" "${work}/bare/compose.yml"
# docker compose fails here, so its output is kept first (pipefail would fail a pipe).
bare_out="$(cd "${work}/bare" && env -u TENKO_VERSION docker compose config --quiet 2>&1)"
if grep -q 'set TENKO_VERSION' <<<"$bare_out"; then
  pass "without TENKO_VERSION the file names what is missing"
else
  fail "no message without TENKO_VERSION"
fi

echo "== docker compose up -d"
compose up -d || fail "compose up"
state=""
for _ in $(seq 90); do
  state="$(docker inspect --format '{{.State.Health.Status}}' "$(compose ps -q tenko)" 2>/dev/null || true)"
  [[ "$state" == healthy || "$state" == unhealthy ]] && break
  sleep 2
done
[[ "$state" == healthy ]] && pass "the HEALTHCHECK reports healthy" || {
  fail "health: ${state:-none}"
  compose logs --tail 40 tenko
}
token="$(compose exec -T tenko tenko setup token 2>/dev/null)"
[[ "$token" =~ ^[A-Za-z0-9_-]{16,}$ ]] && pass "docker compose exec tenko tenko setup token prints the token" ||
  fail "setup token: '${token}'"
out="$(compose exec -T tenko tenko health --live --url https://localhost:8443 --ca-file /var/lib/tenko/tls/ca-root.pem 2>&1)"
grep -qF "$version" <<<"$out" && pass "tenko health --live: ${out//$'\n'/ }" || fail "health --live: ${out}"
logs="$(compose logs tenko 2>&1)"
grep -q 'dns role answering' <<<"$logs" && pass "the dns role answers in the container" || fail "no dns role line"
grep -q 'THE KEY-ENCRYPTION KEY IS A PLAIN FILE' <<<"$logs" && pass "the key comes from the secret file" || fail "no key-file line"
grep -qF "$token" <<<"$logs" && fail "the setup token is in the container log" || pass "the setup token is not in the container log"
if command -v curl >/dev/null 2>&1; then
  code="$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/api/v1/health/ready || true)"
  [[ "$code" == 200 ]] && pass "the published port 8443 answers ready" || fail "published 8443: HTTP ${code}"
fi

echo "== docker compose down -v"
compose down -v --timeout 30 >/dev/null 2>&1 && pass "down" || fail "down"
if ((failures > 0)); then
  echo "== quick start: ${failures} failed"
  exit 1
fi
echo "== quick start: all passed"
