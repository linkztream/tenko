#!/usr/bin/env bash
# Smoke test of the compose DHCP lab (deploy/compose/lab-dhcp, WP7.6): four client
# networks behind one gateway (ISC's dhcrelay) that relays every one of them to one Tenko
# node, the topology of E23.
#
# What it does, printing one PASS, FAIL or SKIP line per row (README.md lists the rows):
#   1. builds the tools image (Debian's dhcrelay, dhclient, perfdhcp, udhcpc) and the node's
#      image: tenko:lab from deploy/Dockerfile (the static musl binary), or with NODE=example
#      the engine's example server from example.Dockerfile, unless IMAGE=<tag> or
#      EXAMPLE_IMAGE=<tag> names an image that exists already;
#   2. starts the gateway, the node's namespace, the node, the four clients and the tester;
#   3. with the binary (NODE=tenko, the default): the first-run setup through the API under
#      the Lab profile; the four networks as IPAM prefixes with a dhcp_pool range each and
#      a scope each (lease 60 s, so that T1 comes after 30 s), option 3 per scope (the
#      gateway's address on the network) and options 6, 15 and 42 for the server, the
#      gateway as the one trusted relay agent; then the rows: a lease on each network
#      through the relay from the right scope with options 3, 6 and 42; option 82 on the
#      lease row (giaddr and the circuit-id dhcrelay adds); the tester, not yet trusted, is
#      refused and named in the health view, then trusted; the link selection sub-option
#      choosing another network's scope; perfdhcp; an offer rate that holds back a burst
#      of new clients and is named in the health view; udhcpc;
#      every client renews at T1 (unicast through the gateway); a reservation wins over the
#      dynamic lease; a deny filter refuses a client and its removal admits it again; a
#      release reaches the lease row; a restart of the node keeps the leases and the
#      clients keep their addresses;
#      WP8.4, E27's class and PXE rows: a vendor-class, a MAC-wildcard and a user-class
#      policy select their range and option 15 for dhclient clients; QEMU in BIOS mode
#      with its iPXE ROM and in UEFI mode with OVMF boot to an iPXE menu from the lab's
#      TFTP and HTTP server (the pxe profile, pxe.Dockerfile), with their architecture on
#      their lease rows; a UEFI HTTP boot client gets its URL; the proxy DHCP listener
#      answers the boot server discovery on port 4011;
#   3'. with NODE=example: the rows the example server can answer (it serves one scope,
#      198.18.0.0/15, selected by option 118 or link selection, with the in-memory
#      reference store): relay-test.py with option 118 (offer, ack, renewal, release) and
#      with the link selection sub-option, and perfdhcp; the other rows are SKIP lines;
#   4. tears everything down (containers, volumes, networks), also when a step fails, after
#      printing the logs of every service. KEEP=1 leaves the lab running.
#
# This is the host side: it builds the images (1.) and runs the steps 2. and 3. as driver.sh
# in the lab's driver (the service `driver`, deploy/compose/driver), from inside the lab
# network, answering the container operations it asks for (driver/host.sh); the round dhcp6
# runs the same way in its own project.
#
# Needs: bash and Docker with the compose plugin (and buildx for the builds), nothing else on
# the host: no curl or python3, no route to the lab networks. Run it from the repository
# root without arguments (Git Bash on Windows too):
#   bash deploy/compose/lab-dhcp/smoke.sh
#   IMAGE=tenko:lab bash deploy/compose/lab-dhcp/smoke.sh          # skip the build
#   NODE=example bash deploy/compose/lab-dhcp/smoke.sh             # the example server
#   KEEP=1 bash deploy/compose/lab-dhcp/smoke.sh                   # keep the lab
#
# The containers talk on four bridge networks inside 192.0.2.0/24 (documentation addresses)
# and to nothing else; nothing is published on the host. Only the image builds and the
# first pull of the base images reach out.
#
# Settings (environment, all optional):
#   NODE            tenko (the binary, default) or example (the engine's example server)
#   IMAGE           an existing Tenko image to test; default: build tenko:lab
#   EXAMPLE_IMAGE   an existing example server image; default: build
#                   tenko-dhcp-lab-example:latest (NODE=example only)
#   TOOLS_IMAGE     an existing tools image; default: build tenko-dhcp-lab-tools:latest
#   WAIT_SECS       how long to wait for Tenko to become healthy (default 300)
#   KEEP            1: do not tear the lab down at the end, also after a failure
#   PXE             0: leave E27's PXE rows out (WP8.4; they build the pxe image and run
#                   QEMU, with KVM where /dev/kvm exists)
#   PXE_IMAGE       an existing pxe image (with PXE_IMAGE_PREBUILT=1); default: build
#                   tenko-dhcp-lab-pxe:latest
#   PXE_WAIT_SECS   how long a machine may take to boot to the menu (default 300)
#   KEA             0: leave E30's Kea export rows out (WP9.3; they build the kea image,
#                   stop the node and start Kea from the export)
#   KEA_IMAGE       an existing kea image (with KEA_IMAGE_PREBUILT=1); default: build
#                   tenko-dhcp-lab-kea:latest
#   ROUNDS          the rounds to run: "default" (the rows above, as ever), "dhcp6" or both
#                   (dhcp6 runs first). The round dhcp6 (WP9.1, dhcp6.sh, README.md) brings
#                   its own compose project (compose.dhcp6.yml, tenkodhcp6lab) and
#                   networks, sets the node up itself, runs the DHCPv6 rows and tears down
#                   what it started; ROUNDS=dhcp6 runs nothing else.
#   NETWORKD_IMAGE  an existing image of the networkd client of the round dhcp6 (with
#                   NETWORKD_IMAGE_PREBUILT=1); default: build tenko-dhcp-lab-networkd:latest
#   TENKO_PROBE_IMAGE  the node image of the round dhcp6, built from the Tenko image by
#                   probe.Dockerfile (its binary with the file capability cap_net_raw+ep,
#                   WP9.2); default: tenko-dhcp-lab-probe:latest

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
# shellcheck source=deploy/compose/driver/host.sh
source "$here/../driver/host.sh"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-tenkodhcplab}"
node="${NODE:-tenko}"
keep="${KEEP:-0}"
# WP9.1: the rounds. "default" is every row of the other sections; "dhcp6" is the round of
# dhcp6.sh, which needs the binary.
rounds="${ROUNDS:-default}"
run_default=0
run_dhcp6=0
for round in $rounds; do
  case "$round" in
    default) run_default=1 ;;
    dhcp6) run_dhcp6=1 ;;
    *) printf 'smoke: ROUNDS holds default and dhcp6, not %s\n' "$round" >&2; exit 2 ;;
  esac
done
((run_default + run_dhcp6 > 0)) || { printf 'smoke: ROUNDS names no round\n' >&2; exit 2; }
case "$node" in
  tenko | example) ;;
  *) printf 'smoke: NODE must be tenko or example, not %s\n' "$node" >&2; exit 2 ;;
esac
if ((run_dhcp6)) && [[ "$node" != tenko ]]; then
  printf 'smoke: the round dhcp6 needs the binary (NODE=tenko)\n' >&2
  exit 2
fi
TENKO_IMAGE="${IMAGE:-}"
export TOOLS_IMAGE="${TOOLS_IMAGE:-tenko-dhcp-lab-tools:latest}"
export NETWORKD_IMAGE="${NETWORKD_IMAGE:-tenko-dhcp-lab-networkd:latest}"
export TENKO_PROBE_IMAGE="${TENKO_PROBE_IMAGE:-tenko-dhcp-lab-probe:latest}"
export PXE_IMAGE="${PXE_IMAGE:-tenko-dhcp-lab-pxe:latest}"
export KEA_IMAGE="${KEA_IMAGE:-tenko-dhcp-lab-kea:latest}"
pxe_rows="${PXE:-1}"
kea_rows="${KEA:-1}"

default_file="$(host_path "$here/compose.yml")"
v6_file="$(host_path "$here/compose.dhcp6.yml")"
v6_project=tenkodhcp6lab
# The machines of the PXE rows run with KVM where the host has it.
default_files=(-f "$default_file")
if [[ -e /dev/kvm ]]; then
  default_files+=(-f "$(host_path "$here/compose.kvm.yml")")
fi
# The project the current round runs in: compose talks to it, and lab_op's volumes and
# networks are its own.
round_project=default
compose() {
  if [[ "$round_project" == dhcp6 ]]; then
    docker compose -p "$v6_project" -f "$v6_file" --profile networkd --profile kea "$@"
  else
    docker compose "${default_files[@]}" --profile "$node" --profile pxe --profile kea "$@"
  fi
}
lab_driver=driver
# What driver.sh may ask for (driver/host.sh lab_op): the services of both projects, and the
# command lines in the clients (dhclient, udhcpc, networkd's state), the tester (relay-test,
# perfdhcp), the gateway, the node's namespace, the boot server and radvd.
lab_services=(relay netns tenko node-example client-servers client-lan client-iot client-guest
  tester bootsrv pxe-bios pxe-uefi kea driver client-dhclient6 client-networkd client-iot6
  client-pd6 router6 kea6)
lab_exec_services=(relay netns client-servers client-lan client-iot client-guest tester
  bootsrv client-dhclient6 client-networkd client-iot6 client-pd6 router6)
lab_networks=(servers)

# lab_extra_op: the Kea checks of E30, in containers of the Kea image (driver/host.sh).
#   kea-version <4|6>        the version line of kea-dhcp4 or kea-dhcp6
#   kea-check 4              kea-dhcp4 -t on the lab volume's kea/kea-dhcp4.json, no network
#   kea-check 6 export       kea-dhcp6 -t on kea/kea-dhcp6.json, in the node's namespace
#   kea-check 6 golden       the same on the golden file of the unit tests
lab_extra_op() {
  local op="$1" volume
  shift
  volume="$(lab_project_name)_lab"
  case "$op:${1:-}:${2:-}" in
    kea-version:4: | kea-version:6:)
      docker run --rm --network none "$KEA_IMAGE" "kea-dhcp$1" -V 2>/dev/null
      ;;
    kea-check:4:)
      docker run --rm --network none \
        --mount "type=volume,source=$volume,target=/lab/kea,volume-subpath=kea,readonly" \
        "$KEA_IMAGE" kea-dhcp4 -t /lab/kea/kea-dhcp4.json
      ;;
    kea-check:6:export)
      docker run --rm --network "container:$(lab_container netns)" \
        --mount "type=volume,source=$volume,target=/check,volume-subpath=kea,readonly" \
        "$KEA_IMAGE" kea-dhcp6 -t /check/kea-dhcp6.json
      ;;
    kea-check:6:golden)
      docker run --rm --network "container:$(lab_container netns)" \
        -v "$(host_path "$repo/crates/tenko-dhcp/src/export/kea/fixtures"):/check:ro" \
        "$KEA_IMAGE" kea-dhcp6 -t /check/kea-dhcp6.json
      ;;
    *)
      printf 'lab: unknown operation %s\n' "$op" >&2
      return 2
      ;;
  esac
}
lab_project_name() {
  if [[ "$round_project" == dhcp6 ]]; then
    printf '%s\n' "$v6_project"
  else
    printf '%s\n' "$COMPOSE_PROJECT_NAME"
  fi
}

v6_started=0
default_started=0
status=0

# The logs of the round dhcp6 (its own project), for a round that failed.
v6_logs() {
  local service
  printf '\n==> FAILED: logs of the round dhcp6\n' >&2
  for service in relay netns tenko tester client-dhclient6 client-networkd client-iot6 client-pd6 router6 kea6; do
    printf '\n--- %s ---\n' "$service" >&2
    compose logs --no-color --tail 200 "$service" >&2 2>&1
  done
  for service in client-dhclient6 client-iot6 client-networkd client-pd6; do
    printf '\n--- %s: /run/lab ---\n' "$service" >&2
    compose exec -T "$service" sh -c 'tail -n 20 /run/lab/events6 /run/lab/events 2>&1; ls /run/lab /run/systemd/netif/links 2>&1' >&2 2>&1
  done
  docker ps -a --filter "label=com.docker.compose.project=$v6_project" >&2 2>&1
}

# The logs of the default round's project.
default_logs() {
  local service
  printf '\n==> FAILED (status %s): logs of the services\n' "$status" >&2
  for service in relay netns tenko node-example tester client-servers client-lan client-iot client-guest; do
    printf '\n--- %s ---\n' "$service" >&2
    compose logs --no-color --tail 200 "$service" >&2 2>&1
  done
  # WP8.4: the boot server's and the machines' logs.
  for service in bootsrv pxe-bios pxe-uefi; do
    printf '\n--- %s ---\n' "$service" >&2
    compose logs --no-color --tail 100 "$service" >&2 2>&1
  done
  compose exec -T bootsrv sh -c 'tail -n 50 /run/lab/*.log' >&2 2>&1
  # WP9.3: the Kea server's log.
  printf '\n--- kea ---\n' >&2
  compose logs --no-color --tail 100 kea >&2 2>&1
  docker ps -a --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" >&2 2>&1
}

cleanup() {
  status=$?
  set +e
  trap - EXIT
  if ((status != 0)) && ((default_started)); then
    round_project=default
    default_logs
  fi
  if ((status != 0 && v6_started && !v6_logged)); then
    round_project=dhcp6
    v6_logs
  fi
  if ((${#lab_summary[@]} > 0)); then
    printf '\n==> summary (node: %s)\n' "$node"
    printf '%s\n' "${lab_summary[@]}"
  fi
  if [[ "$keep" == 1 ]]; then
    if ((default_started)); then
      printf '\n==> KEEP=1: the lab keeps running; for example\n'
      printf '    docker compose -f %s --profile %s exec client-lan dhclient -v -1 -cf /lab/dhclient.conf -sf /lab/client-script.sh eth0\n' \
        "$default_file" "$node"
      printf 'tear it down with: docker compose -f %s --profile %s --profile pxe --profile kea down --volumes\n' \
        "$default_file" "$node"
    fi
    if ((v6_started)); then
      printf '\n==> KEEP=1: the round dhcp6 keeps running; for example\n'
      printf '    docker compose -p %s -f %s --profile networkd exec client-dhclient6 dhclient -6 -D LL -v -1 -cf /lab/dhclient6.conf -sf /lab/client6-script.sh eth0\n' \
        "$v6_project" "$v6_file"
      printf 'tear it down with: docker compose -p %s -f %s --profile networkd --profile kea down --volumes\n' \
        "$v6_project" "$v6_file"
    fi
    exit "$status"
  fi
  printf '\n==> tear down\n'
  round_project=default
  compose down --volumes --remove-orphans --timeout 30 >/dev/null 2>&1
  round_project=dhcp6
  compose down --volumes --remove-orphans --timeout 10 >/dev/null 2>&1
  exit "$status"
}
trap cleanup EXIT

printf '\n==> check the tools\n'
docker compose version >/dev/null 2>&1 || { echo "smoke: the docker compose plugin is missing" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "smoke: cannot talk to the Docker daemon" >&2; exit 1; }

# The images: every one this run needs, before any round starts.
tree="$(lab_build_tree "$repo")"
if [[ -n "${TOOLS_IMAGE_PREBUILT:-}" ]]; then
  docker image inspect "$TOOLS_IMAGE" >/dev/null 2>&1 || { echo "smoke: image $TOOLS_IMAGE not found" >&2; exit 1; }
else
  printf '\n==> build the tools image %s\n' "$TOOLS_IMAGE"
  docker build -f "$(host_path "$here/tools.Dockerfile")" -t "$TOOLS_IMAGE" "$(host_path "$here")"
fi
lab_driver_image "$repo"
if [[ "$node" == tenko ]]; then
  lab_image TENKO_IMAGE tenko:lab "$repo/deploy/Dockerfile" "$repo" --build-arg "TENKO_BUILD_TREE=$tree"
else
  lab_image EXAMPLE_IMAGE tenko-dhcp-lab-example:latest "$here/example.Dockerfile" "$repo" \
    --build-arg "TENKO_BUILD_TREE=$tree"
fi
export TENKO_IMAGE
if ((run_dhcp6)); then
  if [[ -z "${NETWORKD_IMAGE_PREBUILT:-}" ]]; then
    printf '\n==> build the networkd image %s\n' "$NETWORKD_IMAGE"
    docker build -f "$(host_path "$here/networkd.Dockerfile")" -t "$NETWORKD_IMAGE" "$(host_path "$here")"
  fi
  docker image inspect "$NETWORKD_IMAGE" >/dev/null 2>&1 || { echo "smoke: image $NETWORKD_IMAGE not found" >&2; exit 1; }
  # WP9.2: the same binary with the probe's file capability (probe.Dockerfile).
  printf '\n==> build %s from %s (cap_net_raw on the binary)\n' "$TENKO_PROBE_IMAGE" "$TENKO_IMAGE"
  docker build -f "$(host_path "$here/probe.Dockerfile")" --build-arg "TENKO_IMAGE=$TENKO_IMAGE" \
    -t "$TENKO_PROBE_IMAGE" "$(host_path "$here")"
fi
if [[ "$node" == tenko && "$kea_rows" == 1 && -z "${KEA_IMAGE_PREBUILT:-}" ]]; then
  printf '\n==> build the kea image %s\n' "$KEA_IMAGE"
  docker build -f "$(host_path "$here/kea.Dockerfile")" -t "$KEA_IMAGE" "$(host_path "$here")"
fi
if [[ "$node" == tenko && "$pxe_rows" == 1 && "$run_default" == 1 && -z "${PXE_IMAGE_PREBUILT:-}" ]]; then
  printf '\n==> build the pxe image %s\n' "$PXE_IMAGE"
  docker build -f "$(host_path "$here/pxe.Dockerfile")" -t "$PXE_IMAGE" "$(host_path "$here")"
fi

# driver_env: what driver.sh reads from its environment.
driver_env=(-e "NODE=$node" -e "WAIT_SECS=${WAIT_SECS:-300}" -e "PXE=$pxe_rows"
  -e "PXE_WAIT_SECS=${PXE_WAIT_SECS:-300}" -e "KEA=$kea_rows"
  -e "TOOLS_IMAGE=$TOOLS_IMAGE" -e "TENKO_IMAGE=$TENKO_IMAGE" -e "EXAMPLE_IMAGE=${EXAMPLE_IMAGE:-}"
  -e "NETWORKD_IMAGE=$NETWORKD_IMAGE" -e "TENKO_PROBE_IMAGE=$TENKO_PROBE_IMAGE")
v6_logged=0

# WP9.1: the round dhcp6 runs first, in its own compose project, with a driver of its own.
# A round whose rows failed but that ran to its end (it reports them, lab_rows_failed) lets
# the other round run, as when both ran in one script; the smoke fails at the end.
if ((run_dhcp6)); then
  round_project=dhcp6
  lab_networks=(servers6)
  compose config --quiet
  # A lab left over from an interrupted run goes first.
  compose down --volumes --remove-orphans --timeout 10 >/dev/null 2>&1 || true
  v6_started=1
  compose up -d --no-build driver
  lab_run /src/lab-dhcp/driver.sh "${driver_env[@]}" -e ROUNDS=dhcp6
  if ((lab_rows_failed > 0)); then
    v6_logs
    v6_logged=1
  fi
  if [[ "$keep" != 1 ]]; then
    printf '\n==> tear down the round dhcp6\n'
    compose down --volumes --remove-orphans --timeout 10 >/dev/null 2>&1
    v6_started=0
  fi
fi

if ((run_default)); then
  round_project=default
  lab_networks=(servers)
  compose config --quiet
  compose down --volumes --remove-orphans --timeout 10 >/dev/null 2>&1 || true
  default_started=1
  compose up -d --no-build driver
  tools_line=1
  ((run_dhcp6)) && tools_line=0
  lab_run /src/lab-dhcp/driver.sh "${driver_env[@]}" -e ROUNDS=default -e "TOOLS_LINE=$tools_line"
fi

if ((lab_rows_failed > 0)); then
  printf 'smoke: %s row(s) of the round dhcp6 failed\n' "$lab_rows_failed" >&2
  exit 1
fi
