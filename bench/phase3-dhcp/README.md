# Phase 3 DHCP measurements

The measurements of the DHCP role in [phase-3-plan.md](../../docs/plans/phase-3-plan.md) section 6 (M26 to M35), with their scripts and results. WP7.3 wrote the loopback procedure for M26 to M28; WP7.6 adds perfdhcp on Linux, the load VM and the lab. Every figure is a single-node figure (plan section 2.12): one Tenko process, the load generator on the same host (loopback, an upper bound, labelled so) or on the load VM. Linux figures come from the static musl build, the target that ships; Windows figures from the release build.

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

ISC's perfdhcp (Kea) sends as a relay from port 67, so the server runs with `--relay-port 67`. Its relay address must select the scope: add an address of the range to the loopback interface and use it as the local address, or add option 118 to every packet:

```text
perfdhcp -4 -l 198.18.0.2 -r 1000 -R 100000 -p 60 127.0.0.1             # 4-way at 1,000/s
perfdhcp -4 -l 127.0.0.1 -o 118,c6120000 -r 0 -R 100000 -p 60 127.0.0.1 # as fast as it goes
perfdhcp -4 -l 198.18.0.2 -r 1000 -f 500 -R 100000 -p 60 127.0.0.1      # with renewals
```

`-r` is the rate of new exchanges, `-R` the number of simulated clients, `-p` the test period, `-f` the renewal rate; its report gives the drops and the delays per exchange. WP7.6 runs it against `tenko serve` with the store and records the rows beside the own client's.
