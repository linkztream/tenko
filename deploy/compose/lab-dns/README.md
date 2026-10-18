# The compose DNS lab

BIND 9 as the authoritative upstream of one Tenko DDI node, over plain DNS, DNS over TLS and
DNS over HTTPS, on one Docker host: the upstream transports, the cache, the negative cache
and serve-stale of the resolver of [docs/dns.md](../../../docs/dns.md) (WP5.1) against a real
server, for the check of deliverable 6 of the plan and for trying things by hand. It is a
lab, not a deployment example: `smoke.sh` generates the certificate for one run, the Lab
profile makes the resolver open to every client, and every name and address is a
documentation value (`203.0.113.0/24`, `example.test`).

It is a Linux Docker host lab. It runs on Docker Desktop too; the maintainer's host is WSL
Ubuntu 24.04 with Docker as root. It needs Docker with the compose plugin (and buildx to
build the image) and `openssl` on the host. `dig` comes from the BIND image.

## What runs

| Service | What | Reached at |
|---|---|---|
| `bind` | The official ISC image (`internetsystemsconsortium/bind9:9.20`), authoritative for `example.test` (`named.conf`, `example.test.zone`), no recursion. Plain DNS on 53, DNS over TLS on 853, DNS over HTTPS on 443 (`/dns-query`), the last two with the lab certificate for `bind.example.test` and `203.0.113.2`. The query log goes to its standard error | `203.0.113.2`; `bind` on the lab network |
| `tenko` | One node with `--roles controller,dns`, the DNS module on and the Lab profile. The default forwarder is BIND over the transport of the round. The DNS role listens on `0.0.0.0:5300` (above 1024, so the container has no capability); the API is plain HTTP on 8443 (the Lab profile allows it), on the lab network only | `203.0.113.3:5300` (UDP and TCP) |
| `client` | The BIND image again, for `dig`; it asks Tenko and BIND | `docker compose exec client dig ...` |

The zone has `www.example.test A 192.0.2.10`, `api.example.test A 192.0.2.11`, the apex SOA
and NS, and `ns` and `bind` at `203.0.113.2`. Every TTL is 5 seconds, the SOA's negative
TTL too, so that an entry expires, and serve-stale has something to do, within seconds.

The lab network is the bridge `tenkodnslab_lab`, `203.0.113.0/24`, with fixed addresses for
the three containers. Nothing is published on the host. Tenko runs with a read-only root file
system and no capabilities, its key-encryption key is a Docker secret
(`[kek] provider = "file"`), and breach lookups and update checks are off: the lab has no
route out.

The configuration of a round is `tenko.toml` in the work directory, mounted into the
container. The part that changes is the default forwarder:

```toml
[dns]
listen = ["0.0.0.0:5300"]
upstream_ca = "/lab/ca.pem"                 # the lab CA, for dot and doh
forwarders = [{ address = "203.0.113.2", transport = "doh", tls_name = "bind.example.test", path = "/dns-query" }]
# plain: { address = "203.0.113.2", transport = "udp" }
# dot:   { address = "203.0.113.2", transport = "dot", tls_name = "bind.example.test" }

[dns.cache]
stale_secs = 3600
stale_answer_ms = 1800      # a stale answer after 1.8 s of waiting for the upstream
prefetch = false            # so that an entry really expires
```

## The smoke

From the repository root, without arguments:

```sh
bash deploy/compose/lab-dns/smoke.sh                     # builds tenko:lab first
IMAGE=tenko:lab bash deploy/compose/lab-dns/smoke.sh     # reuses an image
```

It builds the image from `deploy/Dockerfile` (a while: the web UI bundle and a release
binary), generates a lab CA, the BIND certificate and a key-encryption key with `openssl`
into a temporary directory, starts BIND and the client, and asks BIND over its three
transports (`dig`, `dig +tls`, `dig +https`) before Tenko is involved. Then three rounds,
`plain`, `dot` and `doh`. Each writes `tenko.toml`, recreates the `tenko` container on it
(`docker compose up -d --force-recreate tenko`, the data volume stays), waits until it
answers, and checks:

- `www.example.test` resolves to `192.0.2.10`; the same query two seconds later has a lower
  TTL, and BIND's query log shows one query for the name in the round: the second answer came
  from the cache;
- `nohost.example.test` is NXDOMAIN twice, the SOA TTL in the second answer is lower and BIND
  saw one query: the negative cache;
- BIND saw the queries of Tenko over UDP in the plain round and over a stream (the `T` flag
  of the query log) in the dot and doh rounds. BIND does not tell DNS over TLS from DNS over
  HTTPS in its log; which of the two Tenko used follows from the one forwarder of the round.

After the doh round, the serve-stale steps: wait until the cached entry's 5 second TTL has
passed, cut BIND off the lab network with `docker network disconnect`, query
`www.example.test` and check that an answer with the stale TTL of RFC 8767 (30 seconds)
comes back in at most 3 seconds, connect BIND again (`docker network connect --alias bind
--ip 203.0.113.2`) and check that within 30 seconds an answer with a TTL of at most 5 comes
back: the refresh. It prints a summary line per step, tears everything down (containers,
volume, network, work directory), also when a step fails, after printing the logs of every
service and the last `tenko.toml`.

Settings: `IMAGE`, `BIND_IMAGE` (the BIND image, for the server and for `dig`), `ROUNDS`
(default `plain dot doh`; the serve-stale steps run after `doh`), `WAIT_SECS` (300),
`KEEP`. The lab network is fixed at `203.0.113.0/24`, so two labs, or this one and a
leftover of an earlier run, cannot run at the same time unless `COMPOSE_PROJECT_NAME`
differs and the network of the other is gone.

## Keeping the lab for hand tests

`KEEP=1` leaves the lab running after a successful smoke (with the configuration of the last
round) and prints the work directory and the command that tears it down:

```sh
KEEP=1 IMAGE=tenko:lab bash deploy/compose/lab-dns/smoke.sh
cd deploy/compose/lab-dns && export LAB_DIR=<work>
docker compose exec client dig @203.0.113.3 -p 5300 www.example.test
docker compose exec client dig @203.0.113.2 +tls +tls-ca=/lab/ca.pem +tls-hostname=bind.example.test www.example.test
docker compose logs bind                                # the queries Tenko sent
docker compose down --volumes
```

To change the transport or the cache settings, edit `<work>/tenko.toml` (the smoke made it
read-only: `chmod u+w` first) and recreate the container:
`docker compose up -d --force-recreate tenko`. The settings are read at start. The faults
are one command each:

```sh
docker network disconnect tenkodnslab_lab "$(docker compose ps -q bind)"               # BIND gone
docker network connect --alias bind --ip 203.0.113.2 tenkodnslab_lab "$(docker compose ps -q bind)"
docker compose kill bind; docker compose up -d bind                                    # BIND restarted
```

Reconnect with `--ip`: the fixed address is how Tenko finds BIND. With a public resolver as
a different default forwarder, for example DNS over TLS to a well-known provider, replace
the entry of `forwarders` by its address, `transport = "dot"` and `tls_name`, and remove
`upstream_ca` so that the system's root certificates apply; that needs a route out, which
the lab network does not have.

## What the lab does not show

It does not measure throughput or latency (the benchmarks under [bench/](../../../bench/)
do), and a 5 second TTL is not what a zone has. One upstream means no
upstream health memory, no round robin and no failover between transports. BIND does not
sign the zone, so DNSSEC validation is not exercised, and nothing here talks to the root
servers or to an authority outside the lab. The certificate is the lab's and
valid for two days. A host with a resolver of its own and Tenko on port 53 is a deployment
matter, [deploy/README.md](../../README.md).
