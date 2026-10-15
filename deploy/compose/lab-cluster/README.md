# The compose cluster lab

Three controllers of Tenko DDI, two probes and HAProxy in front of them on one Docker host:
the cluster of [docs/cluster.md](../../../docs/cluster.md) section 12 with a real proxy and
real networks, for the E9 check of WP3.1c and for trying things by hand. It is a lab, not a
deployment example: `smoke.sh` generates every key and certificate for one run, and every
name and address is a documentation value (`198.51.100.0/24`, `example.test`).

It is a Linux Docker host lab. It runs on Docker Desktop too; the maintainer's host is WSL
Ubuntu 24.04 with Docker as root. It needs Docker with the compose and buildx plugins, and
`curl`, `openssl` and `python3` on the host.

## What runs

| Service | What | Reached at |
|---|---|---|
| `haproxy` | Ends TLS with the lab certificate, checks every controller on `GET /api/v1/health/ready` every 2 s, keeps a client on one controller with the cookie `TENKOSRV`, holds `/api/v1/events` open for an hour (`haproxy.cfg`) | `https://localhost:28443` (`LAB_PORT`), on the loopback only; `https://haproxy:8443` on the lab network |
| `controller-1` to `-3` | The controller role in TLS mode `reverse_proxy` (HAProxy at `198.51.100.2` and the loopback are the trusted proxies), the cluster port 8444 on the lab network, each advertising its service name | Through HAProxy; the cluster port as `controller-N:8444` |
| `probe-1`, `probe-2` | Probe nodes (profile `probes`); they dial the controllers' cluster ports directly, because mutual TLS cannot pass a proxy that ends TLS | No port |
| `fault` | The Docker command line with the Docker socket (profile `fault`), for `docker network disconnect` and `connect`: the lab's partition | No port |

The lab network is the bridge `tenkolab_lab`, `198.51.100.0/24`. Each controller has its own
key-encryption key as a Docker secret (`[kek] provider = "file"`), its own data volume, a
read-only root file system and no capabilities. Breach lookups, update checks and the rate
limiter are off: the lab has no route out, and the load generator is one client.

## The smoke

From the repository root, without arguments:

```sh
bash deploy/compose/lab-cluster/smoke.sh                     # builds tenko:lab first
IMAGE=tenko:lab bash deploy/compose/lab-cluster/smoke.sh     # reuses an image
```

It builds the image from `deploy/Dockerfile` (a while: the web UI bundle and a release
binary), generates a lab CA and the HAProxy certificate with `openssl` and three keys into a
temporary directory, starts `controller-1` and HAProxy, runs first-run setup through HAProxy,
creates two controller tokens and joins `controller-2` and `controller-3` with
`tenko cluster join` in their own containers before their first start, waits for three
voters, enrols and starts the probes, writes 100 addresses per second through HAProxy with
`curl`, kills the leader with `docker compose kill`, checks that writes resume within 15
seconds and that the survivors' digests agree, restarts the killed controller, partitions a
follower with `docker network disconnect`, checks through its own port that it lost its
quorum and that the majority keeps taking writes, connects it again, checks that all three
digests agree, and tears everything down. It prints a summary line per step; on a failure it
prints the logs of every service first. The weekly CI job `cluster-lab` runs it.

Settings: `IMAGE`, `LAB_PORT` (28443), `RATE` and `SECONDS_UNDER_LOAD` (100 writes per
second for 30 seconds around the kill), `WAIT_SECS` (300), `KEEP`.

## Keeping the lab for hand tests

`KEEP=1` leaves the lab running after a successful smoke and prints the work directory and
the command that tears it down:

```sh
KEEP=1 IMAGE=tenko:lab bash deploy/compose/lab-cluster/smoke.sh
# open https://localhost:28443 and trust <work>/tls/ca.pem (the lab CA), or:
curl --cacert <work>/tls/ca.pem https://localhost:28443/api/v1/health/ready
# the administrator is lab-admin, with the PIN in <work>/admin-password (KEEP=1 only)
LAB_DIR=<work> docker compose -f deploy/compose/lab-cluster/compose.yml \
  --profile probes --profile fault down --volumes
```

With the lab up, the faults are one command each:

```sh
cd deploy/compose/lab-cluster
export LAB_DIR=<work>
docker compose kill controller-2                       # a crash
docker compose up -d controller-2                      # back
docker compose run --rm fault network disconnect tenkolab_lab "$(docker compose ps -q controller-3)"
docker compose run --rm fault network connect --alias controller-3 tenkolab_lab "$(docker compose ps -q controller-3)"
```

Reconnect with `--alias` and the service name, so the other controllers find it again.

## Mixed versions

Every controller can run its own image: `TENKO_IMAGE_1` to `TENKO_IMAGE_3` override
`TENKO_IMAGE` per controller. With an older release as `TENKO_OLD_IMAGE`, a rolling upgrade
by hand follows [docs/upgrades.md](../../../docs/upgrades.md): start on the old image, then
replace the followers one at a time and the leader last, after a step-down.

```sh
export TENKO_OLD_IMAGE=ghcr.io/linkztream/tenko:<older release>
KEEP=1 IMAGE="$TENKO_OLD_IMAGE" bash deploy/compose/lab-cluster/smoke.sh
cd deploy/compose/lab-cluster && export LAB_DIR=<work> TENKO_IMAGE="$TENKO_OLD_IMAGE"
docker compose exec controller-1 tenko cluster upgrade-check --url http://127.0.0.1:8443   # after tenko login there
TENKO_IMAGE_2=tenko:lab docker compose up -d controller-2    # a follower first
TENKO_IMAGE_3=tenko:lab docker compose up -d controller-3
# step the leader down (tenko cluster step-down), then the last one:
TENKO_IMAGE_1=tenko:lab docker compose up -d controller-1
```

The same order runs in-process with two binaries in `crates/tenko/tests/cluster_mixed_versions.rs`
(`TENKO_OLD_BIN=<path of an older tenko>`), which the weekly lab job skips until a second
binary exists.

## What the lab does not show

One Docker host shares one disk and one kernel: a power cut (M2), a 1 Gbit link (M4) and the
UI over two hosts (M7) wait for the three VMs of WP3.8. The measurements of the lab on one
machine are in [bench/phase1-cluster](../../../bench/phase1-cluster/README.md).
