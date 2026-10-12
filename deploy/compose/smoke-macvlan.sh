#!/usr/bin/env bash
# Smoke test of deploy/compose/macvlan.example.yml on a dummy parent interface.
#
# What it does:
#   1. creates a `dummy` link (tenkosmoke0) and brings it up, as the macvlan parent;
#   2. builds the image from the repository (docker build -f deploy/Dockerfile), unless
#      IMAGE=<tag> names an image that exists already;
#   3. starts the controller of the macvlan example with the parent, subnet and addresses
#      below (documentation addresses, RFC 5737) and waits until its HEALTHCHECK passes;
#   4. from a throwaway container on the same macvlan network (the Docker host cannot reach
#      macvlan children directly) asks GET /api/v1/health/ready with `tenko health`;
#   5. runs first-run setup, creates an enrolment token, enrols the probe service with it,
#      starts it and checks that it runs and that its node status is healthy;
#   6. tears everything down (containers, volumes, network, temporary files, the dummy link),
#      also when a step fails. On failure the logs of both containers are printed first.
#
# Needs: bash, Docker with the compose and buildx plugins (the Dockerfile uses BuildKit cache
# mounts), iproute2 (`ip`), and root for `ip` (the script uses sudo when it is not root).
# Nothing else. It touches only the dummy link, the Docker project `tenkosmoke` and the image
# it builds; its containers talk to each other on the private macvlan segment of 192.0.2.0/24
# (documentation addresses) and to nothing else.
# Only the image build reaches out, to the registries and package mirrors of the Dockerfile.
#
# Usage, from anywhere:
#   deploy/compose/smoke-macvlan.sh
#   IMAGE=tenko:smoke deploy/compose/smoke-macvlan.sh     # skip the build
#
# Settings (environment, all optional):
#   IMAGE          an existing image to test; default: build tenko:smoke
#   TENKO_PARENT   the dummy link name (default tenkosmoke0); it is deleted at the end, so
#                  never name a real interface
#   TENKO_SUBNET, TENKO_GATEWAY, TENKO_IP_RANGE, TENKO_CONTROLLER_IP, TENKO_PROBE_IP
#                  as in macvlan.example.yml (defaults: the documentation values)
#   WAIT_SECS      how long to wait for the controller to become healthy (default 300)

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
compose_file="$here/macvlan.example.yml"

export COMPOSE_PROJECT_NAME=tenkosmoke
export TENKO_PARENT="${TENKO_PARENT:-tenkosmoke0}"
export TENKO_SUBNET="${TENKO_SUBNET:-192.0.2.0/24}"
export TENKO_GATEWAY="${TENKO_GATEWAY:-192.0.2.1}"
export TENKO_IP_RANGE="${TENKO_IP_RANGE:-192.0.2.8/29}"
export TENKO_CONTROLLER_IP="${TENKO_CONTROLLER_IP:-192.0.2.10}"
export TENKO_PROBE_IP="${TENKO_PROBE_IP:-192.0.2.11}"
# The throwaway client; inside TENKO_IP_RANGE as well.
client_ip="${TENKO_CLIENT_IP:-192.0.2.12}"
wait_secs="${WAIT_SECS:-300}"
network="${COMPOSE_PROJECT_NAME}_lan"
tenko_bin=/usr/local/bin/tenko
ca_in_controller=/var/lib/tenko/tls/ca-root.pem

built_here=0
if [[ -n "${IMAGE:-}" ]]; then
  export TENKO_IMAGE="$IMAGE"
else
  export TENKO_IMAGE=tenko:smoke
  built_here=1
fi

sudo_cmd=()
if [[ "$(id -u)" -ne 0 ]]; then
  sudo_cmd=(sudo)
fi

work=""
link_created=0
status=0

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'smoke: %s\n' "$*" >&2; exit 1; }
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
    printf '\n==> FAILED (status %s): logs of the containers\n' "$status" >&2
    for service in tenko probe; do
      printf '\n--- %s ---\n' "$service" >&2
      compose --profile probe logs --no-color --tail 200 "$service" >&2 2>&1
    done
    docker ps -a --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" >&2 2>&1
  fi
  printf '\n==> tear down\n'
  compose --profile probe down --volumes --remove-orphans --timeout 30 >/dev/null 2>&1
  docker network rm "$network" >/dev/null 2>&1
  if [[ -n "$work" ]]; then
    rm -rf "$work"
  fi
  if ((link_created)); then
    "${sudo_cmd[@]}" ip link delete "$TENKO_PARENT" >/dev/null 2>&1
  fi
  exit "$status"
}
trap cleanup EXIT

step "check the tools"
command -v docker >/dev/null || fail "docker not found"
docker compose version >/dev/null 2>&1 || fail "the docker compose plugin is missing"
command -v ip >/dev/null || fail "ip (iproute2) not found"
docker info >/dev/null 2>&1 || fail "cannot talk to the Docker daemon"

step "create the dummy parent interface $TENKO_PARENT"
if ip link show "$TENKO_PARENT" >/dev/null 2>&1; then
  fail "$TENKO_PARENT exists already; the script deletes it at the end, so it will not reuse it"
fi
"${sudo_cmd[@]}" ip link add "$TENKO_PARENT" type dummy
link_created=1
"${sudo_cmd[@]}" ip link set "$TENKO_PARENT" up
ip -brief link show "$TENKO_PARENT"

if ((built_here)); then
  step "build the image $TENKO_IMAGE (UI bundle and release binary; this takes a while)"
  docker build -f "$repo/deploy/Dockerfile" -t "$TENKO_IMAGE" "$repo"
else
  step "use the existing image $TENKO_IMAGE"
  docker image inspect "$TENKO_IMAGE" >/dev/null 2>&1 || fail "image $TENKO_IMAGE not found"
fi

step "prepare the key, the configuration file and the work directory"
work="$(mktemp -d)"
mkdir -p "$work/secrets"
# A throwaway key-encryption key. 0444 because the container user (65532) is not the
# owner; the directory is private to this user.
head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n' >"$work/secrets/tenko_kek"
chmod 0444 "$work/secrets/tenko_kek"
# The defaults, except that the breached-password check stays offline: the macvlan segment
# has no route out, and the online check would only time out. The example mounts the file
# for the --config option.
printf '# Smoke test: the defaults, without the online breach check.\n[hibp]\nonline = false\n' >"$work/tenko.toml"
chmod 0444 "$work/tenko.toml"
export TENKO_KEK_FILE="$work/secrets/tenko_kek"
export TENKO_CONFIG_FILE="$work/tenko.toml"
compose --profile probe config --quiet

step "start the controller on the macvlan network $network (parent $TENKO_PARENT)"
compose up -d --no-build tenko
controller="$(compose ps -q tenko)"
[[ -n "$controller" ]] || fail "the controller container was not created"

step "wait for the controller to be healthy (HEALTHCHECK, up to ${wait_secs}s)"
health() { [[ "$(docker inspect -f '{{.State.Health.Status}}' "$controller")" == healthy ]]; }
retry "$wait_secs" "the controller to become healthy" health
docker inspect -f 'controller {{.Name}} is {{.State.Health.Status}}' "$controller"

step "check /api/v1/health/ready from a throwaway container on the macvlan network"
docker cp "$controller:$ca_in_controller" "$work/ca-root.pem"
chmod 0444 "$work/ca-root.pem"
client_health() {
  docker run --rm --network "$network" --ip "$client_ip" \
    -v "$work/ca-root.pem:/ca-root.pem:ro" \
    --entrypoint "$tenko_bin" "$TENKO_IMAGE" \
    health --url "https://$TENKO_CONTROLLER_IP:8443" --ca-file /ca-root.pem
}
client_health

step "first-run setup and an enrolment token for the probe (commands run inside the controller)"
url="https://$TENKO_CONTROLLER_IP:8443"
# The defaults keep the Home profile, whose password preset is the PIN: digits only, 4 to 64
# of them. A random PIN of 8 to 12 digits.
password="$(od -An -N8 -tu1 /dev/urandom | tr -d ' \n' | cut -c1-12)"
setup_token="$(compose exec -T tenko "$tenko_bin" setup token | tr -d '\r\n')"
[[ -n "$setup_token" ]] || fail "no setup token"
printf '%s\n' "$password" | compose exec -T -e "TENKO_SETUP_TOKEN=$setup_token" tenko \
  "$tenko_bin" setup --url "$url" --ca-file "$ca_in_controller" \
  --admin smoke-admin --host-name tenko.example.test --password-stdin
printf '%s\n' "$password" | compose exec -T -e TENKO_CREDENTIALS=/tmp/smoke-credentials.json tenko \
  "$tenko_bin" login --url "$url" --ca-file "$ca_in_controller" \
  --user smoke-admin --password-stdin
# The token is the only line on standard output; the notes (fingerprint) go to standard error.
enrol_token="$(compose exec -T -e TENKO_CREDENTIALS=/tmp/smoke-credentials.json tenko \
  "$tenko_bin" node enrol-token --roles probe --name probe-smoke --expires-in 600 \
  2>"$work/enrol-token.notes" | tr -d '\r\n')"
cat "$work/enrol-token.notes"
[[ -n "$enrol_token" ]] || fail "no enrolment token"
fingerprint="$(grep -Eio '[0-9a-f]{64}' "$work/enrol-token.notes" | head -n 1 || true)"
enrol_args=(--controller "$url" --name probe-smoke --address "$TENKO_PROBE_IP" --data-dir /var/lib/tenko)
if [[ -n "$fingerprint" ]]; then
  enrol_args+=(--ca-fingerprint "$fingerprint")
else
  printf 'smoke: no CA fingerprint in the notes; enrolling with trust on first use\n' >&2
fi

step "enrol the probe service into its volume"
compose --profile probe run --rm -T --no-deps -e "TENKO_ENROL_TOKEN=$enrol_token" \
  --entrypoint "$tenko_bin" probe node enrol "${enrol_args[@]}"

step "start the probe and check that it runs"
compose --profile probe up -d --no-build probe
probe="$(compose --profile probe ps -q probe)"
[[ -n "$probe" ]] || fail "the probe container was not created"
running() { [[ "$(docker inspect -f '{{.State.Running}}' "$probe")" == true ]]; }
retry 30 "the probe container to run" running
# A node process that cannot start (not enrolled, no controller) exits within seconds.
sleep 10
running || fail "the probe container stopped"
node_ok() { compose --profile probe exec -T probe "$tenko_bin" node status --check --data-dir /var/lib/tenko; }
retry 90 "tenko node status --check of the probe" node_ok
compose --profile probe exec -T probe "$tenko_bin" node status --data-dir /var/lib/tenko || true

step "OK: the controller is healthy and ready on $TENKO_CONTROLLER_IP, the probe is enrolled and running at $TENKO_PROBE_IP"
