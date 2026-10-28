# Phase 3 DHCP measurements

The measurements of the DHCP role in [phase-3-plan.md](../../docs/plans/phase-3-plan.md) section 6 (M26 to M35), with their scripts and results. WP7.3 wrote the loopback procedure for M26 to M28; WP7.6 adds perfdhcp on Linux (loopback and from the load VM, `scripts/run-perfdhcp.sh`) and the lab. Every figure is a single-node figure (plan section 2.12): one Tenko process, the load generator on the same host (loopback, an upper bound, labelled so) or on the load VM. Linux figures come from the static musl build, the target that ships; Windows figures from the release build.

## The server

`crates/tenko-dhcp/examples/dhcp_server.rs` serves the engine of WP7.3 (`docs/dhcp.md` section 8) until `tenko serve --roles controller,dhcp` runs the role (WP7.5):

```text
dhcp_server serve --listen 127.0.0.1:6767 --relay-port 6868 --workers 4 --store queue \
  --seconds 600 --idle-exit 3
```

- One relay-mode listener and one scope, `198.18.0.0/15` (the benchmarking range of RFC 2544), pool `198.18.0.10` to `198.19.255.250` (131,053 addresses), lease time `--lease-secs` (3,600), routers, DNS servers and domain name set. A request selects the scope by option 118 or by a `giaddr` inside the range; replies go to the relay's address on `--relay-port`.
- `--store mem` is `MemLeaseStore`, the contracts' in-memory reference: its commit walks the scope's rows to keep the client index, so its cost grows with the leases; use it with about 10,000 clients. `--store queue` is the same hand-off and completion with no rows kept (the lease table holds them): it measures the engine, the workers and the commit hand-off without a store behind them. Neither is the store of WP7.2, which commits through the coalescer; M26 and M28 with the store are WP7.6's, with `tenko serve`.
- The lease table is a hash table, as WP7.2's production table is.
- It prints its counters when it stops: packets answered, NAKs, drops by reason, the leases, and the bucket of the median and the 99th percentile of DISCOVER to OFFER, REQUEST to ACK and the commit.

## The load client

The same example's `load` subcommand acts as a relay agent at `--bind` (its address is `giaddr`, option 118 selects the scope, option 61 tells the clients apart, `chaddr` uses the documentation MACs of RFC 7042):

```text
dhcp_server load --server 127.0.0.1:6767 --bind 127.0.0.1:6868 --mode dora \
  --clients 100000 --window 64            # closed loop: the ceiling (M26)
dhcp_server load ... --mode dora --clients 20000 --rate 1000 --seconds 25   # open loop (M28)
dhcp_server load ... --mode renew --clients 100000 --window 64 --seconds 20 # after a fill (M27)
```

`dora` runs DISCOVER, OFFER, REQUEST, ACK once per client; `renew` gives every client a lease first (not measured) and then renews (REQUEST with `ciaddr`, ACK) round after round. `--rate 0` keeps `--window` exchanges in flight; a rate paces new exchanges. An exchange without its ACK after two seconds is lost. The latency is from the first message of the exchange to its ACK.

## The loopback run

```text
bench/phase3-dhcp/scripts/run-loopback.sh --binary <path to dhcp_server> \
  --workers "1 2 4 8" --stores "queue mem" --clients 100000 --mem-clients 10000 \
  --rates "1000 5000" --renew-seconds 20 --out bench/phase3-dhcp/results/raw/<name>.log
```

Build the binary first: on Windows `cargo build -p tenko-dhcp --release --locked --example dhcp_server`; on Linux the musl target (`--target x86_64-unknown-linux-musl`), which the script checks. Per store it runs M26 per worker count, M27 at the largest worker count and M28 per rate, each against a fresh server, and appends the client's and the server's lines to the log. The results go to `results/` in the shape of the Phase 2 files: the question, the setup, a summary table, the rows, the caveats.

## perfdhcp (Linux, WP7.6)

ISC's perfdhcp (Kea; the `kea-admin` package of Debian and Ubuntu, 2.2 and 2.4) sends as a relay agent: its local address is `giaddr`, and option 118 (`-o 118,c6120000`, 198.18.0.0) selects the bench scope whatever that address is. `-L` and `-N` move its own port and the server's off 67, so neither side needs privileges; the server answers relays on `--relay-port` (the example) or `[dhcp] relay_port` (the binary). `-R` is the number of simulated clients (with `-s 1` the same clients in every run), `-r` the rate of new 4-way exchanges, `-f` the rate of renewals of the leases perfdhcp holds, `-p` the period; its report gives sent, received and dropped packets and the delays per exchange, and `-x t` every packet's timestamps, from which the percentiles come.

`scripts/run-perfdhcp.sh` runs the measurements, one fresh server per run, every rung twice, the better run the figure (the higher achieved rate, then the fewer drops):

| | What | perfdhcp |
|---|---|---|
| M26 | a ladder of offered rates per worker count (default 1, 2, 4; rates 1,000 to 40,000); the ceiling is the highest rung answered with at most 0.1 percent drops, and the ladder stops at the first rung that loses more than 1 percent; with `--client` also the own client's closed loop (64 exchanges in flight), since perfdhcp on a small host saturates first | `-r RATE -R 100000 -p 20` |
| M27 | a ladder of renewal rates, each beside new 4-way exchanges at the same rate (perfdhcp renews only leases it got in the run, at most at `-r`), at the largest worker count; with `--client` also pure renewals after a fill of 100,000 leases from the own client, closed loop | `-r RATE -f RATE -R 100000 -p 20` |
| M28 | 1,000 and 5,000 exchanges per second: p50 and p99 of DISCOVER to OFFER and of REQUEST to ACK from the timestamps; DISCOVER to ACK from the example's own load client at the same rate (`--client`); the server's commit time (the example prints its histograms, the binary serves `tenko_dhcp_commit_duration_seconds`) | `-r RATE -R 100000 -p 20 -x t` |

The server is `--kind tenko`, the binary with the roles controller and dhcp (`scripts/node-setup.sh` starts it as the ssh user from `~/dhcp` with its own data directory and the API on `--api-port`, sets it up under the Lab profile and creates the scope `198.18.0.0/15` with one pool through the API; every lease is committed to the store before the ACK), or `--kind example` with `--store queue|mem`, the engine without the store, for the comparison with WP7.3's rows. A Tenko service installed on the node is never touched: other ports, another data directory, the instance stopped by the pid it wrote.

### Loopback

Server and perfdhcp on one Linux host, `127.0.0.1`: an upper bound, labelled so. On the node VM (from a host that reaches it by ssh, or with `--node local --load local` on the host itself):

```sh
cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl
cargo build -p tenko-dhcp --release --locked --example dhcp_server --target x86_64-unknown-linux-musl
bench/phase3-dhcp/scripts/run-perfdhcp.sh --kind tenko \
  --binary target/x86_64-unknown-linux-musl/release/tenko \
  --client target/x86_64-unknown-linux-musl/release/examples/dhcp_server \
  --node USER@node --load USER@node --node-addr 127.0.0.1
```

WSL2 loses datagrams on loopback under load (risk R68, as M24 did for DNS): Linux figures come from the lab VMs, the workstation gives functional runs.

### Two hosts

The server on the node VM, perfdhcp on the load VM, over the link between them (a bridge or VLAN with no other DHCP server on it):

```sh
bench/phase3-dhcp/scripts/run-perfdhcp.sh --kind tenko --binary ... --client ... \
  --node USER@node --node-addr 198.51.100.34 --load USER@load --load-addr 198.51.100.35 --tune
```

`--tune` raises the load host's UDP sysctls for the run with `bench/phase2-dns/scripts/tune-udp.sh` and restores them at the end; the node's are recorded, not changed (they are part of what is measured).

### From a workstation

Two VMs on one hypervisor share its CPU, so the load can instead come from the Windows workstation: perfdhcp in WSL2 (Ubuntu 24.04, `networkingMode=mirrored` so that its address, which is `giaddr`, is the workstation's own on the LAN) against the node VM, with `--load local --load-addr <the workstation's address>`. The steps in order, with the firewall rule on the node, the smoke run, the ladder, what the result file's header says, the five power-offs of M32 with the workstation holding the ACK log, and M34 and M30 on the node VM, are in [phase-3-exit.md](../../docs/plans/phase-3-exit.md) section 6.1, "E22 with the load from the workstation". `scripts/crash-test.sh` has no lab mode (it kills a local child); the lab variant of M32 is the manual procedure of `results/2026-10-22-m32-crash.md`.

### The rules

- **The shipped binary.** Linux figures come from the static musl build, the target that ships; `run-perfdhcp.sh` refuses a dynamically linked binary (`check_linkage` of `bench/phase2-dns/scripts/lib.sh`; `--allow-dynamic` overrides and marks the run not publishable). Windows figures come from the release build.
- **One node.** Every figure is a single-node figure (plan section 2.12): one server process on the node, perfdhcp on the same host (loopback) or on the load VM.
- **The record.** `meta.txt` in the raw directory holds the machines (CPU, cores, memory, OS, kernel), perfdhcp's version, the binary's hash, the node's sysctls and the load host's before and after; `summary.tsv` one line per run; `report.md` the tables for the results file, written by `scripts/perfdhcp-report.py`, which also rebuilds them alone from a finished raw directory (`perfdhcp-report.py DIR/summary.tsv DIR`). For M28 the better run is the one with the lower p99 from REQUEST to ACK, and the report adds the server's own view: the bucket of the 50th and 99th percentile of REQUEST to ACK and of the commit, from `tenko_dhcp_exchange_duration_seconds` and `tenko_dhcp_commit_duration_seconds` on the node's loopback metrics listener (`[metrics] listen`). Raw output stays out of the repository.

### Comparison caveats (plan section 6)

ISC publishes performance reports per Kea release (reports.kea.isc.org) with DORA and SARR rates per lease backend; WP9.5 records the figure of the release current then beside Tenko's. They are not like for like: other hardware, Kea's multi-threading settings, other perfdhcp options, and Kea's memfile backend, whose lease file write is not a replicated commit and whose durability depends on its settings, while Tenko commits every lease to the Raft store before the ACK. An old figure from the Kea developers' list (2014, Kea 0.9: about 4,100 leases per second with the memfile on a RAM disk, 4,900 without persistence) shows the order of magnitude only. ISC dhcpd writes its lease file before the ACK and is the closer durability model; Windows DHCP publishes no comparable figure. The DNS-side reference points of Phase 2 do not apply, and loopback figures are upper bounds that no link reaches.

### The lab

`deploy/compose/lab-dhcp` runs perfdhcp too, as one functional row among real clients behind a real relay; it measures nothing.

## E32 on the workstation (WP9.5)

Three measurements of E32 need no lab VM; their results are in `results/2026-10-26-e32-rss-leases-metrics.md`:

- **M34, idle RSS with every role** (Windows): `scripts/m34-idle-rss.ps1 -Binary <tenko.exe> -LoadClient <dhcp_server.exe>` runs the M9 procedure of `bench/phase1-server/m9-idle-rss.ps1` with the roles `controller,dns,dhcp,probe`, the three home scopes on the documentation networks and 200 leases from the example's load client (`dhcp_server load --subnet <network>` selects a scope of `tenko serve` with option 118). `-Roles` without `dhcp` gives the baselines, `-Prefixes 200` adds the M9 data set; the port options let several runs go at once. The musl figure comes from `scripts/m34-idle-rss.sh`, the Linux equivalent (bash, `curl` and `python3`): the same roles, scopes and leases, the memory read from `/proc/<pid>/status` (`VmRSS`, `VmHWM`) the way `bench/phase1-server/m9-idle-rss.sh` does, `--binary` and `--load-client` the musl `tenko` and `dhcp_server`, `--roles`, `--prefixes`, `--kek file` and the port options as in the PowerShell script; run it on the node VM (section 6.1, step 6 of `docs/plans/phase-3-exit.md`).
- **M30, the memory of 100,000 leases**: `scripts/m30-lease-memory.ps1 -TestBinary <lease_rebuild-<hash>.exe>` runs the ignored test `e32_ops_15_the_memory_of_100000_leases_by_stage` of `crates/tenko-dhcp/tests/lease_rebuild.rs` and reads the process's memory at each stage of the fill, the restart and the rebuild.
- **M33, the metrics cost**: neither `tenko serve` nor the example server can turn the DHCP metrics off, so M33 by its method (M26 with the metrics on and off) cannot run; the ignored test `e32_ops_21_the_metrics_of_one_dora_exchange_cost_in_isolation` of `crates/tenko-dhcp/tests/metrics_cost.rs` times the metrics work of one exchange in isolation as a stand-in.
