#!/usr/bin/env bash
# Smoke test of the compose DNS lab (deploy/compose/lab-dns, WP5.1 deliverable 6: BIND 9
# as the upstream of one Tenko node over plain DNS, DNS over TLS and DNS over HTTPS).
#
# This is the host side. It builds the images, starts the lab's driver (the service
# `client`, deploy/compose/driver) and runs driver.sh in it: driver.sh does every step that
# talks to the lab, from inside the lab network, and asks this script for each container
# operation (driver/host.sh). What driver.sh does, printing one summary line per step at
# the end:
#   1. (here) builds the image tenko:lab from the repository (docker build -f
#      deploy/Dockerfile), unless IMAGE=<tag> names an image that exists already, and the
#      driver's image (and the quirk responders' for the round recursion);
#   2. generates a lab CA and the BIND certificate (bind.example.test, 203.0.113.2) with
#      openssl, and a key-encryption key, into the lab volume;
#   3. starts BIND, and asks it directly over plain DNS, DNS over TLS and DNS over HTTPS
#      (dig +tls and dig +https);
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
#   5c. the round update (WP6.2): nsupdate changes a zone of Tenko with TSIG (add,
#      prerequisites, replace, TCP, delete) and dig sees each change at once; an update
#      without the key, one with a wrong secret and one of an address IPAM manages are
#      refused; one PASS or FAIL line per row (README.md lists them);
#   5d. the round recursion (WP10.1, recursion.sh; ROUNDS=recursion): a second Tenko node
#      serves the lab's own root, the TLD test and the zones under it, the quirk responders
#      misbehave beside it, and the node under test resolves iteratively from the lab root,
#      one PASS or FAIL line per row of E36 and E41 with the queries sent per case (M40);
#   6. (here) tears everything down (containers, volumes, network), also when a step fails,
#      after printing the logs of every service. KEEP=1 leaves the lab running.
#
# Needs: bash and Docker with the compose plugin (and buildx for the builds), nothing else on
# the host: no route to the lab network (Docker Desktop has none), no openssl, curl or
# python3. Run it from the repository root without arguments (Git Bash on Windows too):
#   bash deploy/compose/lab-dns/smoke.sh
#   IMAGE=tenko:lab bash deploy/compose/lab-dns/smoke.sh     # skip the build
#   KEEP=1 bash deploy/compose/lab-dns/smoke.sh              # keep the lab for hand tests
#
# The containers talk to each other on the bridge network 203.0.113.0/24 (documentation
# addresses) and to nothing else; nothing is published on the host. Only the image builds
# and the first pull of the BIND image reach out.
#
# Settings (environment, all optional):
#   IMAGE           an existing Tenko image to test; default: build tenko:lab
#   BIND_IMAGE      the BIND image of the server (default internetsystemsconsortium/bind9:9.20)
#   DRIVER_IMAGE    an existing image of the lab driver; default: build tenko-lab-driver:local
#                   from deploy/compose/driver/Dockerfile
#   ROUNDS          the rounds to run, in order (default "plain dot doh xfr update"); the
#                   serve-stale steps run after the round doh, the transfer rows in xfr,
#                   the update rows in update (alone, it sets Tenko up itself); the round
#                   recursion (WP10.1) runs only when named, best alone
#   QUIRK_IMAGE     an existing image of the quirk responders for the round recursion;
#                   default: build tenko-quirk:lab from deploy/compose/lab-dns/quirk.Dockerfile
#   WAIT_SECS       how long to wait for Tenko to become healthy (default 300)
#   M42             1: the round recursion also measures M42 (the denial cache's effect,
#                   denial.sh; bench/phase2-dns/scripts/run-m42-denial.sh)
#   KEEP            1: do not tear the lab down at the end, also after a failure
#                   (README.md says how to later)

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
# shellcheck source=deploy/compose/driver/host.sh
source "$here/../driver/host.sh"
compose_file="$(host_path "$here/compose.yml")"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-tenkodnslab}"
if [[ -n "${BIND_IMAGE:-}" ]]; then
  export BIND_IMAGE
fi
rounds="${ROUNDS:-plain dot doh xfr update}"
keep="${KEEP:-0}"
TENKO_IMAGE="${IMAGE:-}"

compose() { docker compose -f "$compose_file" --profile recursion "$@"; }
# What driver.sh may ask for (driver/host.sh lab_op).
lab_services=(bind tenko client authority bind-resolver quirk-noedns quirk-case quirk-tc
  quirk-slow quirk-spoof quirk-oob quirk-sub quirk-strip quirk-ent)
lab_volumes=(tenko-data authority-data tenko-backup)
lab_networks=(lab)

status=0
cleanup() {
  status=$?
  set +e
  trap - EXIT
  if ((status != 0)); then
    printf '\n==> FAILED (status %s): logs of the services\n' "$status" >&2
    for service in bind tenko client authority quirk-noedns quirk-case quirk-tc quirk-slow quirk-spoof quirk-oob quirk-sub quirk-ent; do
      printf '\n--- %s ---\n' "$service" >&2
      compose logs --no-color --tail 200 "$service" >&2 2>&1
    done
    docker ps -a --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" >&2 2>&1
  fi
  lab_print_summary
  if [[ "$keep" == 1 ]]; then
    printf '\n==> KEEP=1: the lab keeps running; ask Tenko with\n'
    printf '    docker compose -f %s exec client dig @203.0.113.3 -p 5300 www.example.test\n' "$compose_file"
    printf 'the files of the run are in the lab volume, at /work in the client container;\n'
    printf 'tear it down with: docker compose -f %s --profile recursion down --volumes\n' "$compose_file"
    exit "$status"
  fi
  printf '\n==> tear down\n'
  compose down --volumes --remove-orphans --timeout 30 >/dev/null 2>&1
  docker volume rm "${COMPOSE_PROJECT_NAME}_tenko-backup" >/dev/null 2>&1
  exit "$status"
}
trap cleanup EXIT

printf '\n==> check the tools\n'
docker compose version >/dev/null 2>&1 || { echo "smoke: the docker compose plugin is missing" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "smoke: cannot talk to the Docker daemon" >&2; exit 1; }

# The build's cargo cache belongs to this checkout alone (deploy/Dockerfile says why).
tree="$(lab_build_tree "$repo")"
lab_image TENKO_IMAGE tenko:lab "$repo/deploy/Dockerfile" "$repo" --build-arg "TENKO_BUILD_TREE=$tree"
lab_driver_image "$repo"
if [[ " $rounds " == *" recursion "* ]]; then
  lab_image QUIRK_IMAGE tenko-quirk:lab "$here/quirk.Dockerfile" "$repo" --build-arg "TENKO_BUILD_TREE=$tree"
fi

compose config --quiet
# A lab left over from an interrupted run (its volumes hold secrets under another
# key-encryption key) goes first.
compose down --volumes --remove-orphans --timeout 10 >/dev/null 2>&1 || true
docker volume rm "${COMPOSE_PROJECT_NAME}_tenko-backup" >/dev/null 2>&1 || true
compose up -d --no-build client

lab_run /src/lab-dns/driver.sh -e "ROUNDS=$rounds" -e "WAIT_SECS=${WAIT_SECS:-300}" \
  -e "M42=${M42:-0}" -e "TENKO_IMAGE=$TENKO_IMAGE"
