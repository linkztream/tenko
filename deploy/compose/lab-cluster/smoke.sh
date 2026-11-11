#!/usr/bin/env bash
# Smoke test of the compose cluster lab (deploy/compose/lab-cluster, WP3.1c, E9 on one
# Docker host).
#
# This is the host side. It builds the images, starts the lab's driver (the service
# `client`, deploy/compose/driver) and runs driver.sh in it: driver.sh does every step that
# talks to the lab, from inside the lab network, and asks this script for each container
# operation (driver/host.sh). What driver.sh does, printing one summary line per step at
# the end:
#   1. (here) builds the image tenko:lab from the repository (docker build -f
#      deploy/Dockerfile), unless IMAGE=<tag> names an image that exists already, and the
#      driver's image;
#   2. generates a lab CA and the HAProxy certificate with openssl, and one key-encryption
#      key per controller, into the lab volume;
#   3. starts controller-1 and HAProxy, runs first-run setup through HAProxy and signs in;
#   4. creates two controller tokens and joins controller-2 and controller-3 with
#      `tenko cluster join` in their own containers before their first start, then waits
#      until the cluster has three voters;
#   5. enrolls the two probes and starts them;
#   6. writes 100 addresses per second through HAProxy, kills the leader with
#      `docker compose kill` during the load, checks that writes resume within 15 s and that
#      the surviving controllers' state digests agree, restarts the killed controller and
#      checks that all three agree and both probes are connected;
#   7. disconnects a follower from the lab network (`docker network disconnect`, run here),
#      checks through its own port that it lost its quorum and that the majority keeps
#      taking writes, connects it again and checks the digests;
#   8. checks that a renewal before its window is refused, that 30 enrollments with an
#      invalid token give 10 audit records and one summary, and that a revoked probe is cut
#      off by the controller it is connected to (the installation's first revocation);
#   9. (here) tears everything down (containers, volumes, network), also when a step fails,
#      after printing the logs of every service. KEEP=1 leaves the lab running.
#
# Needs: bash and Docker with the compose plugin (and buildx for the builds), nothing else on
# the host: no curl, openssl or python3. Run it from the repository root without arguments
# (Git Bash on Windows too):
#   bash deploy/compose/lab-cluster/smoke.sh
#   IMAGE=tenko:lab bash deploy/compose/lab-cluster/smoke.sh     # skip the build
#   KEEP=1 bash deploy/compose/lab-cluster/smoke.sh              # keep the lab for hand tests
#
# The lab's containers talk to each other on the bridge network 198.51.100.0/24
# (documentation addresses) and to nothing else; HAProxy is published on 127.0.0.1 only, for
# hand tests (the driver reaches it on the lab network). Only the image builds and the first
# pull of haproxy reach out, to the registries and package mirrors.
#
# Settings (environment, all optional):
#   IMAGE           an existing image to test; default: build tenko:lab
#   DRIVER_IMAGE    an existing image of the lab driver; default: build tenko-lab-driver:local
#   LAB_PORT        the loopback port of HAProxy (default 28443)
#   RATE, SECONDS_UNDER_LOAD   the write load (default 100 writes/s for 30 s around the kill)
#   WAIT_SECS       how long to wait for a controller to become healthy (default 300)
#   KEEP            1: do not tear the lab down at the end (README.md says how to later)

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
# shellcheck source=deploy/compose/driver/host.sh
source "$here/../driver/host.sh"
compose_file="$(host_path "$here/compose.yml")"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-tenkolab}"
export LAB_PORT="${LAB_PORT:-28443}"
keep="${KEEP:-0}"
TENKO_IMAGE="${IMAGE:-}"

compose() { docker compose -f "$compose_file" --profile probes "$@"; }
# What driver.sh may ask for (driver/host.sh lab_op): the services, and the command lines
# inside the controllers and probes (setup, join, enroll, status, renew).
lab_services=(controller-1 controller-2 controller-3 probe-1 probe-2 haproxy client)
lab_exec_services=(controller-1 controller-2 controller-3 probe-1 probe-2)
lab_networks=(lab)

status=0
cleanup() {
  status=$?
  set +e
  trap - EXIT
  if ((status != 0)); then
    printf '\n==> FAILED (status %s): logs of the services\n' "$status" >&2
    for service in controller-1 controller-2 controller-3 probe-1 probe-2 haproxy; do
      printf '\n--- %s ---\n' "$service" >&2
      compose logs --no-color --tail 150 "$service" >&2 2>&1
    done
    docker ps -a --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" >&2 2>&1
  fi
  lab_print_summary
  if [[ "$keep" == 1 && $status -eq 0 ]]; then
    printf '\n==> KEEP=1: the lab keeps running at https://localhost:%s\n' "$LAB_PORT"
    printf 'the lab CA and the administrator'"'"'s password are /work/tls/ca.pem and /work/admin-password in the client container:\n'
    printf '    docker compose -f %s exec client cat /work/tls/ca.pem\n' "$compose_file"
    printf 'tear it down with: docker compose -f %s --profile probes down --volumes\n' "$compose_file"
    exit "$status"
  fi
  printf '\n==> tear down\n'
  compose down --volumes --remove-orphans --timeout 30 >/dev/null 2>&1
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

compose config --quiet
# A lab left over from an interrupted run goes first.
compose down --volumes --remove-orphans --timeout 10 >/dev/null 2>&1 || true
compose up -d --no-build client

lab_run /src/lab-cluster/driver.sh -e "LAB_PORT=$LAB_PORT" -e "RATE=${RATE:-100}" \
  -e "SECONDS_UNDER_LOAD=${SECONDS_UNDER_LOAD:-30}" -e "WAIT_SECS=${WAIT_SECS:-300}" \
  -e "KEEP=$keep" -e "TENKO_IMAGE=$TENKO_IMAGE"
