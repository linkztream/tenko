# The compose DNS lab

BIND 9 as the authoritative upstream of one Tenko DDI node, over plain DNS, DNS over TLS and
DNS over HTTPS, on one Docker host: the upstream transports, the cache, the negative cache
and serve-stale of the resolver of [docs/dns.md](../../../docs/dns.md) (WP5.1) against a real
server, for the check of deliverable 6 of the plan and for trying things by hand. A fourth
round, `xfr` (WP6.1), has BIND and Tenko transfer zones to each other, with TSIG, NOTIFY,
IXFR, XoT and catalog zones, and a fifth, `update` (WP6.2), changes a zone of Tenko with
`nsupdate`. It is a
lab, not a deployment example: `smoke.sh` generates the certificate for one run, the Lab
profile makes the resolver open to every client, and every name and address is a
documentation value (`203.0.113.0/24`, `example.test`).

It is a Linux Docker host lab. It runs on Docker Desktop too; the maintainer's host is WSL
Ubuntu 24.04 with Docker as root. It needs Docker with the compose plugin (and buildx to
build the image) and `openssl` on the host; the round `xfr` also needs `curl` and `python3`
on the host (see the transfer round below). `dig` and `nsupdate` come from the BIND image.

## What runs

| Service | What | Reached at |
|---|---|---|
| `bind` | The official ISC image (`internetsystemsconsortium/bind9:9.20`), authoritative for `example.test` (`named.conf`, `example.test.zone`), no recursion. Plain DNS on 53, DNS over TLS on 853, DNS over HTTPS on 443 (`/dns-query`), the last two with the lab certificate for `bind.example.test` and `203.0.113.2`. For the round `xfr` it is also the secondary and the primary of the zones in `transfer.conf`, with the TSIG key of the run in `keys.conf` and the primary zone files from `zones/`. The query log goes to its standard error | `203.0.113.2`; `bind` on the lab network |
| `tenko` | One node with `--roles controller,dns`, the DNS module on and the Lab profile. The default forwarder is BIND over the transport of the round. The DNS role listens on `0.0.0.0:5300` (above 1024, so the container has no capability); the API is plain HTTP on 8443 (the Lab profile allows it), on the lab network only. In the round `xfr` it also serves DNS over TLS and zone transfers over TLS (XoT) on 8530, with the lab certificate for `tenko.example.test` | `203.0.113.3:5300` (UDP and TCP), `203.0.113.3:8530` (TLS, round `xfr`) |
| `client` | The BIND image again, for `dig` and `nsupdate`; it asks Tenko and BIND, and changes BIND's zones in the round `xfr` | `docker compose exec client dig ...` |

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
`plain`, `dot` and `doh` (the fourth, `xfr`, is described below). Each writes `tenko.toml`, recreates the `tenko` container on it
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
(default `plain dot doh xfr update`; the serve-stale steps run after `doh`, the transfer rows in
`xfr`, the update rows in `update`), `WAIT_SECS` (300), `KEEP`. The lab network is fixed at `203.0.113.0/24`, so two labs, or this one and a
leftover of an earlier run, cannot run at the same time unless `COMPOSE_PROJECT_NAME`
differs and the network of the other is gone.

## The transfer round (WP6.1)

The round `xfr` checks the zone transfers of [docs/dns.md](../../../docs/dns.md) section 10 against BIND in both directions: BIND as the secondary of zones Tenko holds as primary zones, and Tenko as the secondary of zones BIND holds as primary zones. Besides the tools above it needs `curl` and `python3` on the host, and a host that reaches the lab network `203.0.113.0/24` (a Linux Docker host does; Docker Desktop usually does not route to container addresses, so the round wants a Linux Docker host; it was run on WSL Ubuntu 24.04 with Docker as root). The host uses Tenko's API only; `dig` and `nsupdate` run in the `client` container.

What it sets up:

- **Tenko.** The configuration of the round is the one of the plain round plus `[dns.tls]`: DNS over TLS, and with it zone transfers over TLS (XoT), on `0.0.0.0:8530` with the lab certificate for `tenko.example.test` (`tenko.pem` and `tenko.key` in the work directory, signed by the lab CA). Port 8530 is above 1024, so the container still needs no capability.
- **The API.** The first-run setup under the Lab profile runs through the API with curl from the host (`POST /api/v1/setup` with the token that `tenko setup token` prints in the container), and the session cookie of the new administrator signs the later requests.
- **The key.** A TSIG key `xfr.example.test` (`hmac-sha256`) is generated for the run. Its secret is written to `LAB_DIR/bind/keys.conf`, which `named.conf` includes, and imported into Tenko (`POST /dns/keys` with the secret). Nothing of it is in the repository.
- **The access list.** `lab-secondaries` has one entry, the key `xfr.example.test`. The primary zones of Tenko name it in `transfer.allow` with `require_tsig`, and name BIND (`203.0.113.2`, port 53, the key) as the NOTIFY target.
- **The zones.** Tenko holds the primary zones `out.example.test` (with 300 records of about 100 octets, so that a transfer spans several messages), `xot.example.test` (`xot` on: TLS only), `catalog.tenko.test` (a catalog zone) and `member.tenko.test`; and the secondary zones `in.example.test` (from BIND, port 53), `inxot.example.test` (from BIND's DNS over TLS port 853, with `xot` and the `tls_name` `bind.example.test`) and `catalog.bind.test` (a catalog zone). BIND holds the other side.
- **BIND.** `transfer.conf` (included by `named.conf`) lists the zones of the round: the secondary zones of Tenko's, with the key and a `tls` block for XoT; the primary zones `in.example.test`, `inxot.example.test`, `catalog.bind.test` and `member.bind.test`, with `allow-transfer` for the key, `allow-update` for the key (so that the smoke can change them with `nsupdate`) and NOTIFY to Tenko, signed; and the secondary zone `big.example.test` of the measurement M19. The zone files of the primary zones are in `zones/`; the smoke copies them to `LAB_DIR/zones`, writable for BIND, which runs as an unprivileged user. `named.conf` also lists Tenko's catalog zone under `catalog-zones`.

The round prints one `PASS` or `FAIL` line per row and fails the smoke when a row fails (the check is repeated with a trace in the log):

| Row | What is checked | How |
|---|---|---|
| `out.axfr` | BIND takes `out.example.test` from Tenko with TSIG | BIND answers `www.out.example.test` with `192.0.2.30` within 60 s |
| `out.tsig` | Tenko refuses an unsigned AXFR and serves a signed one in the MAC chain | `dig AXFR` without a key fails and lists no record; with `-y` it verifies and lists all 300 records |
| `out.notify_ixfr` | A change on Tenko reaches BIND by NOTIFY and IXFR | A record added through the API is answered by BIND within 5 s (the time is printed), and BIND's log shows a transfer of fewer than 20 records, the delta only |
| `out.xot` | BIND takes `xot.example.test` over TLS, and plain TCP is refused | BIND answers `www.xot.example.test` with `192.0.2.32` within 60 s; a signed `dig AXFR` over plain TCP fails |
| `out.catalog` | BIND makes a zone of a member of Tenko's catalog zone | BIND answers `www.member.tenko.test` with `192.0.2.40` within 60 s |
| `in.axfr` | Tenko takes `in.example.test` from BIND with TSIG | Tenko answers `www.in.example.test` with `192.0.2.50` within 60 s |
| `in.notify_ixfr` | A change on BIND reaches Tenko by NOTIFY and IXFR | A signed `nsupdate` adds a record on BIND, Tenko answers it within 5 s (the time is printed), and the zone's journal on Tenko holds an entry that adds one record and removes none |
| `in.xot` | Tenko takes `inxot.example.test` from BIND over TLS | Tenko answers `www.inxot.example.test` with `192.0.2.60` within 60 s |
| `in.catalog` | Tenko makes a zone of a member of BIND's catalog zone, and deletes it when it leaves | Tenko answers `www.member.bind.test` with `192.0.2.70` within 60 s; after `nsupdate` removes the member from the catalog, the zone is gone from Tenko's list within 30 s |
| `in.read_only` | A secondary zone refuses record changes | A batch change of `in.example.test` answers 409 `dns.zone.secondary` |
| `in.status` | The transfer state of the API shows a successful transfer | `GET /dns/zones/{id}/transfer` of `inxot.example.test` has a `serial`, a `last_success` for the primary and no `last_error` |

The measurement M19 (a change of 100 records on a zone of 100,000 records reaches BIND within 5 seconds, and only the change is transferred) runs on the same lab: `bench/phase2-dns/scripts/run-m19-xfr.sh` starts the smoke with `KEEP=1` and reads `LAB_DIR/session.env` (below). Its results are in `bench/phase2-dns/results/2026-10-18-m19-xfr.md`.

## The update round (WP6.2)

The round `update` checks the dynamic updates of [docs/dns.md](../../../docs/dns.md) section 13 with BIND's `nsupdate` from the `client` container against a zone of Tenko. It needs what the round `xfr` needs (`curl` and `python3` on the host, a host that reaches the lab network). After the round `xfr` it uses the node and the session that round set up; alone (`ROUNDS=update`) it starts Tenko with the configuration of the round `xfr` and runs the first-run setup itself.

What it sets up, through the API:

- **The key.** A TSIG key `update.example.test` (`hmac-sha256`), generated for the run and imported into Tenko (`POST /dns/keys` with the secret); `nsupdate -y` signs with it.
- **The access list.** `lab-updaters` with one entry, the key. It names no address on purpose: under the Lab profile an unsigned update from an address a list allows would pass (TGL-09), so a list of keys only is what makes the unsigned update below a refusal.
- **The zone.** The primary zone `dyn.example.test` with `update.allowed` naming the list, `require_tsig` and `may_replace_ipam` off.
- **IPAM.** The prefix `192.0.2.0/24` and the address `192.0.2.90` with the DNS name `cam.dyn.example.test`, written into the zone by the actuator (`POST /proposals/reconcile`), so an RRset of origin `ipam` is there.

The round prints one `PASS` or `FAIL` line per row and fails the smoke when a row fails. Every check of an answer asks Tenko once, right after `nsupdate` returned: Tenko answers an update only once its index holds the change, so there is nothing to wait for.

| Row | What is checked | How |
|---|---|---|
| `upd.add` | A signed update adds a record | `nsupdate -y` adds `host1.dyn.example.test A 192.0.2.81`; the next `dig` answers it (retried for 15 s only until the update path knows the new key and zone) |
| `upd.prereq` | A prerequisite that fails stops the update | `prereq nxdomain host1...` with an add: `nsupdate` reports YXDOMAIN, and the address is unchanged |
| `upd.replace` | Prerequisite, delete and add in one update | `prereq yxrrset host1... A`, `update delete host1... A`, `update add host1... 192.0.2.82`: `dig` answers only the new address |
| `upd.tcp` | An update over TCP | `nsupdate -v` adds `host2.dyn.example.test A 192.0.2.83` |
| `upd.delete` | Deleting a name | `update delete host1.dyn.example.test`: `dig` answers NXDOMAIN |
| `upd.unsigned` | No key, no update | An unsigned `nsupdate` is answered REFUSED and nothing is added |
| `upd.badsig` | A wrong secret | `nsupdate -y` with the key's name and another secret: NOTAUTH (BADSIG), nothing is added |
| `upd.origin` | What the update wrote | The records of the zone through the API: `host2` has the origin `dynamic` and the key's name |
| `upd.ipam` | The origin rule | Deleting `cam.dyn.example.test A`, which IPAM manages, is REFUSED and the address stays |

With `KEEP=1` the work directory's `session.env` also holds `upd_key`, `upd_secret`, `upd_acl` and `upd_zone` for hand tests:

```sh
. "$LAB_DIR/session.env"
printf 'server 203.0.113.3 5300\nzone dyn.example.test\nupdate add printer.dyn.example.test 60 IN A 192.0.2.30\nsend\n' |
  docker compose exec -T client nsupdate -y "hmac-sha256:$upd_key:$upd_secret"
docker compose exec client dig @203.0.113.3 -p 5300 printer.dyn.example.test
```

The measurement M21 (the update rate end to end) does not run on the lab: `bench/phase2-dns/scripts/run-m21-update.sh` starts a node of its own and drives it with the load generator of `tenko-dns` (`examples/update_load.rs`); its results are in `bench/phase2-dns/results/2026-10-19-m21-update.md`.

## Keeping the lab for hand tests

`KEEP=1` leaves the lab running after the smoke, also after a failure (with the configuration of
the last round), and prints the work directory and the command that tears it down. After the
round `xfr` the work directory also holds `session.env` (mode 0600), which a shell reads with
`. "$LAB_DIR/session.env"`: the session `cookie` of the API, the name of the TSIG key (`xfr_key`)
and its secret (`xfr_secret`), the identifier of the access list (`acl`) and the address of
the API (`api_base`), for hand tests and for the measurement M19:

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

## The recursion sandbox (Slice 10)

For the recursive resolver ([docs/plans/dns-recursion-plan.md](../../../docs/plans/dns-recursion-plan.md)
section 2.12) the lab gains a root of its own, so that no check touches the real root
servers. Three services, under the compose profile `recursion` (the other rounds and
`smoke.sh` start none of them):

| Service | What | Reached at |
|---|---|---|
| `authority` | A second Tenko node (`--roles controller,dns`, the Lab profile, its own data volume `authority-data`, configuration `LAB_DIR/authority/authority.toml`). It will serve the lab root `.` (glue `a.root.test` at `203.0.113.10`), the TLD `test` and the signed test zones under it | `203.0.113.10:53` |
| `quirk` | The engine's example authoritative server with the misbehaviours of E36 as flags (no EDNS, broken 0x20, TC on everything, delayed answers, wrong source address), authoritative for `quirk.example.test` | `203.0.113.11:53` |
| `delv` | The BIND image idling, like `client`; `docker compose exec delv delv ...` validates independently of Tenko with the lab root's trust anchor (the second validator of E33) | `203.0.113.12` |

`bind` stays as it is; WP10.2 gives it `bind.example.test` (signed by BIND), `optout.example.test`
and `expired.example.test`.

They are shells until WP10.1 (the lab root zone and the quirk responder) and WP10.2 (the
signed zones, the BIND zones and the rounds `recursion` and `rfc5011` of `smoke.sh`) fill
them: `authority` needs its configuration file and `quirk` its binary, so only `delv` starts
today. Once both packages are in:

```sh
docker compose --profile recursion up -d authority quirk delv
docker compose exec delv delv @203.0.113.3 www.example.test A
```

## What the lab does not show

It does not measure throughput or latency (the benchmarks under [bench/](../../../bench/)
do), and a 5 second TTL is not what a zone has. One upstream means no
upstream health memory, no round robin and no failover between transports. BIND does not
sign the zone, so DNSSEC validation is not exercised, and nothing here talks to the root
servers or to an authority outside the lab. The certificate is the lab's and
valid for two days. A host with a resolver of its own and Tenko on port 53 is a deployment
matter, [deploy/README.md](../../README.md).
