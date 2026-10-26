# M26 before and after the short lease of moves (Windows release, loopback, one node)

Verdict: PASS (the DORA ceiling with the queue store and four workers is unchanged within the run-to-run noise: 93,326 per second after against 92,783 and 89,450 before; the renewal rate 98,799 against 101,589 and 99,851)

ADR 0027 adds two reads to the DORA path of the DHCPv4 engine: after the scope selection, an empty-check of the image's moving clients (and, with moves, a binary search by MAC address and two relaxed atomic stores), and in the REQUEST and DISCOVER paths a map lookup of the old lease when any moving client names one (`docs/dhcp.md` section 12.5). The package's boundary is that nothing on the DORA path allocates (`crates/tenko-dhcp/tests/alloc.rs`, section `moving_section`, and `tests/lease_alloc.rs`, both pass) and that M26 holds. This file holds the M26 rows of `bench/phase3-dhcp/scripts/run-loopback.sh` before and after, on the same machine and the same day. The example server's image has no moving clients, so the rows measure the cost every request pays; the path with moving clients is bounded by the allocation test and the engine tests.

Machine: Intel Core i9-13900K (24 cores, 32 threads), 63.7 GiB RAM, Windows 11 Enterprise 10.0.26300. Build: `cargo build -p tenko-dhcp --release --locked --example dhcp_server`; "before" from `main` at `ec3b1165`, "after" from the branch `moves-lease`. Command: `run-loopback.sh --binary <exe> --workers 4 --stores queue` (100,000 clients, window 64; the renewal run 20 s; the open-loop run 1,000 per second). Order: before, after, before again. Loopback figures are upper bounds; the musl figures are the lab's.

| Run | DORA closed loop (per second) | p99 (us) | Fill (per second) | Renewals (per second) | p99 (us) | 1,000 per second: p99 (us) |
|---|---|---|---|---|---|---|
| Before (1) | 92,783 | 795 | 93,091 | 101,589 | 903 | 304 |
| After | 93,326 | 829 | 94,120 | 98,799 | 1,182 | 516 |
| Before (2) | 89,450 | 1,156 | 90,943 | 99,851 | 1,117 | 300 |

No request was lost and no NAK was sent in any run. The spread between the two runs of the same "before" binary (3.6 percent on the DORA ceiling, 1.7 percent on renewals) is larger than any difference between before and after.
