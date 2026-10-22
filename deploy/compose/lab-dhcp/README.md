# The compose DHCP lab

Four client networks behind one gateway that relays every one of them to one Tenko DDI node,
on one Docker host: the topology of E23 ([phase-3-plan.md](../../../docs/plans/phase-3-plan.md)
section 2.5) with real clients, for the weekly check of the dhcp role (WP7.6) and for trying
things by hand. It is a lab, not a deployment example: every address is a documentation
value (`192.0.2.0/24`, RFC 5737), every MAC one of RFC 7042 (`00:00:5e:00:53:xx`), and
nothing in it reaches out.

It is a Linux Docker host lab. It runs on Docker Desktop too; the maintainer's host is WSL
Ubuntu 24.04 with Docker as root. It needs Docker 28 or later with the compose plugin (and
buildx to build the images), and with the binary as the node `curl` and `python3` on the
host, which reaches the node's API on the lab network.

The gateway is a container that routes between the bridges, so the node's reply to
`giaddr`, the gateway's address on a client network, comes in on the servers bridge. Docker
28 drops a packet for a container's address that arrives from another bridge (its raw-table
rules against reaching unpublished containers from outside); the lab's networks set
`com.docker.network.bridge.gateway_mode_ipv4: nat-unprotected`, which leaves those rules out.
The lab publishes nothing, so nothing is exposed by it.

## The topology

```text
            servers 192.0.2.0/26          lan 192.0.2.64/26
   node .10 ──┐  tester .20                 ┌── client-lan (00:00:5e:00:53:45)
client-servers┤                             │
              └──── .2 ┌─────────┐ .66 ─────┘
                       │  relay  │  dhcrelay -a, IP forwarding
              ┌──── .130└─────────┘ .194 ───┐
   client-iot ┘                             └── client-guest (00:00:5e:00:53:c5)
            iot 192.0.2.128/26           guest 192.0.2.192/26
```

| Service | What | Address |
|---|---|---|
| `relay` | The gateway: ISC's `dhcrelay` (Debian's `isc-dhcp-relay` 4.4) relays all four networks to the node, the node's own network included, so that the node runs in relay mode and never sees a broadcast (plan section 2.5, risk R56). It renames its interfaces after their networks and adds option 82 with that name as the circuit-id (`-a`); it routes between the networks, so that a renewal, a unicast from the client to the node, finds its way | `.2`, `.66`, `.130`, `.194` |
| `netns` | Owns the node's network namespace: the node's address, the route to the other networks through the gateway (replies to a relay go to `giaddr`), and `net.ipv4.ip_unprivileged_port_start=0`, so that the node binds port 67 without a capability | `192.0.2.10` |
| `tenko` (profile `tenko`) | The node: the image of `deploy/Dockerfile` (the static musl binary) with `--roles controller,dhcp`, the DHCP module on, the Lab profile, `[dhcp] listen = [{ address = "192.0.2.10", mode = "relay" }]`, the API in plain HTTP on 8443. Read-only root file system, no capability, the key-encryption key as a Docker secret | in `netns` |
| `node-example` (profile `example`) | Until the binary has the dhcp role: the engine's example server (`crates/tenko-dhcp/examples/dhcp_server.rs`, built by `example.Dockerfile` with the builder of `deploy/Dockerfile` for musl) with the in-memory reference store `MemLeaseStore`. It serves one scope, `198.18.0.0/15`, selected only by option 118 or the link selection sub-option, so the clients' rows cannot run against it | in `netns` |
| `client-servers`, `client-lan`, `client-iot`, `client-guest` | One client per network with a fixed MAC: ISC's `dhclient` with `scripts/dhclient.conf` and `scripts/client-script.sh` (which puts the address on the interface and writes one line per event to `/run/lab/events`), and BusyBox's `udhcpc` | `.5`, `.69`, `.133`, `.197` before their lease |
| `tester` | Kea's `perfdhcp` (Debian's `kea-admin` 2.2) and `scripts/relay-test.py`, a relay agent written against RFC 2131 that sends option 82 with a circuit-id and, when asked, the link selection sub-option or option 118, and checks the echo | `192.0.2.20` |

Everything except the node comes from the tools image (`tools.Dockerfile`, Debian 12 packages
only), so nothing on the other side of the wire shares code with Tenko.

## The smoke

From the repository root, without arguments:

```sh
bash deploy/compose/lab-dhcp/smoke.sh                    # builds tenko:lab, NODE=tenko
IMAGE=tenko:lab bash deploy/compose/lab-dhcp/smoke.sh    # reuses an image
NODE=example bash deploy/compose/lab-dhcp/smoke.sh       # the example server as the node
KEEP=1 bash deploy/compose/lab-dhcp/smoke.sh             # leaves the lab running
```

With the binary, the smoke sets the node up through the API under the Lab profile and
configures it: the four networks as IPAM prefixes, a `dhcp_pool` range in each (`.30` to
`.59` of each /26), a scope on each with a 60-second lease (T1 after 30 seconds), option 3
per scope (the gateway's address on the network) and options 6, 15 and 42 for the server.
Then the rows, one `PASS`, `FAIL` or `SKIP` line each:

| Row | Checks |
|---|---|
| `lease.<network>` | `dhclient` on each network gets an address of that network's pool through the relay, with option 3 the gateway, option 6 `192.0.2.53` and option 42 `192.0.2.123` (the options of E23) |
| `relay.<network>` | the lease row (`GET /dhcp/leases/{addr}`) holds `giaddr`, the gateway's address on the network, and the circuit-id `dhcrelay` added (the network's name): option 82 reaches the scope and the lease |
| `link-selection` | `relay-test.py` on servers sends option 82 with the link selection sub-option (RFC 3527) of iot: the offer and the ack come from the iot scope, option 82 back unchanged |
| `perfdhcp` | perfdhcp as a relay: 10 4-way exchanges, no drops |
| `udhcpc` | BusyBox's `udhcpc` on servers gets an address of the pool |
| `renew.<network>` | every `dhclient` renews its address at T1, a unicast through the gateway |
| `reservation` | an IPAM host of mode `reserved` with client-lan's MAC at `192.0.2.80`: after a release client-lan gets `192.0.2.80`, not its dynamic address |
| `filter.deny`, `filter.removed` | a deny filter for client-guest's MAC: no lease; the filter deleted: a lease again |
| `release` | `dhclient -r` on iot: the lease row is `released` |
| `restart.leases`, `restart.client` | `docker compose restart tenko`: the node lists the same active leases, and client-lan asking again (INIT-REBOOT) keeps `192.0.2.80` |

With `NODE=example` the rows the example server can answer run: `relay-test.py` with option
118 (offer, ack, a renewal, a release in `198.18.0.0/15`, option 82 echoed), with the link
selection sub-option, and perfdhcp with option 118 (50 exchanges, no drops). The client rows
are `SKIP` lines that say why.

The smoke tears everything down at the end (containers, the data volume, the networks, the
work directory), also after a failure, after printing the logs of every service; `KEEP=1`
leaves the lab running and prints the commands.

## By hand

With `KEEP=1` the lab stays up; the work directory the smoke prints holds `tenko.toml` and
the key file. For example:

```sh
export LAB_DIR=/tmp/tmp.XXXXXX
docker compose -f deploy/compose/lab-dhcp/compose.yml --profile tenko exec client-iot \
  dhclient -v -1 -cf /lab/dhclient.conf -sf /lab/client-script.sh -lf /run/lab/dhclient.leases eth0
docker compose -f deploy/compose/lab-dhcp/compose.yml --profile tenko exec client-iot cat /run/lab/events
docker compose -f deploy/compose/lab-dhcp/compose.yml --profile tenko exec tester \
  python3 /lab/relay-test.py --server 192.0.2.10 --giaddr 192.0.2.20 --mac 00:00:5e:00:53:21 \
  --expect 192.0.2.192/26 --link 192.0.2.192 --release
docker compose -f deploy/compose/lab-dhcp/compose.yml --profile tenko logs relay
docker compose -f deploy/compose/lab-dhcp/compose.yml --profile tenko down --volumes
```

The API is at `http://192.0.2.10:8443` from the host (the Lab profile allows plain HTTP); the
first-run setup token comes from `docker compose ... exec tenko /usr/local/bin/tenko setup
token --data-dir /var/lib/tenko`.

## CI

The weekly job `dhcp-lab` in `.github/workflows/ci.yml` runs the smoke with the binary
(it builds `tenko:lab` from `deploy/Dockerfile`, the static musl binary) on the self-hosted
Linux runner, next to the cluster and DNS labs. The measurements (M26 to M28) are not part of
the lab: they run on a host or between the two lab VMs ([bench/phase3-dhcp](../../../bench/phase3-dhcp/README.md)),
since bridge networks and containers on one host say nothing about a real link.
