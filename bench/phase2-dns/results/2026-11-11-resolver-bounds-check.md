# The resolver's work bounds and the RPZ delegation: a regression check (Windows)

Verdict: PASS, as a regression check on a shared workstation, not a measurement. M24 shows no cost on the worker's path: the hit ratio is the same to the fourth digit (0.8371), the paced p99 of the changed build is lower in both pairs, and its closed-loop throughput is inside the spread between two runs of the same binary. On the validation and referral paths, the key table's insert at its bound went from about 10 µs to 0.2 µs, and a referral of 250 name servers costs a third of what it did. A referral of four name servers costs the same within the spread.

What changed between the two builds:

- The recursive resolver carries the delegation an answer came through into its answers while an RPZ zone has NSDNAME or NSIP triggers, deciding per resolution. The denial cache keeps that delegation beside each zone's denials, and under the carry it synthesizes only with a fresh delegation. On the worker, every cache miss now asks whether the catalog has such triggers before the denial cache is looked up.
- One query quota and one wall clock per client query, shared by the fetches of its validation.
- A referral is followed with at most 13 name servers and 4 addresses of glue for each; a name server keeps at most 4 addresses.
- The NSEC3 hash cap counts hash work.
- The validator's table of zones evicts through an index by last use.
- The unwanted-answer flush is off by default.

## M24, both builds, alternating

`scripts/run-m24-cache.sh --entries 100000` with its other defaults, four times in a row from 10:53 to 11:10: base, changed, base, changed. Other sessions' compilers were active on the host throughout.

| Run | Closed loop QPS | Closed p99 us | Paced p50 us | Paced p99 us | Paced p99.9 us | Hit ratio (paced) | Timeouts, errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| base | 171,035 | 1,136.6 | 782.3 | 1,338.4 | 7,942.1 | 0.8371 | 0, 0 |
| changed | 156,691 | 1,167.4 | 634.4 | 1,180.7 | 1,354.8 | 0.8371 | 0, 0 |
| base | 137,583 | 1,194.0 | 810.5 | 1,224.7 | 1,423.4 | 0.8368 | 0, 0 |
| changed | 148,444 | 1,173.5 | 689.7 | 1,197.1 | 1,340.4 | 0.8371 | 0, 0 |

Closed-loop throughput averages 154,309 queries per second for base and 152,568 for changed; the two base runs alone differ by 33,452. M24 forwards to its upstream, so the engine does not run, but the denial cache exists beside the answer cache: every miss (16 percent of the queries) passes the new check.

## The key table and referrals

A release test compiled into both trees from the same source (not part of the repository), run three times in alternation, in nanoseconds per operation:

- **Key table put.** 20,000 inserts of new zones into a key table full at its Standard bound of 10,000, each evicting one.
- **Key table get.** 20,000 reads.
- **Referral of 4.** 50,000 parses and classifications of a referral with 4 name servers and 2 addresses each.
- **Referral of 250.** 500 of a referral with 250 name servers and one address each.

| Run | Key table put | Key table get | Referral of 4 | Referral of 250 |
| --- | ---: | ---: | ---: | ---: |
| base | 9,118 | 43 | 1,886 | 159,155 |
| changed | 207 | 68 | 2,461 | 48,696 |
| base | 9,945 | 45 | 2,578 | 181,573 |
| changed | 181 | 76 | 2,701 | 71,614 |
| base | 11,332 | 104 | 2,305 | 136,738 |
| changed | 174 | 66 | 2,321 | 60,819 |

- **Key table get.** A read now moves the zone in the index by last use, about 25 ns more. That is paid once per zone per validation, beside signature verifications that cost tens of microseconds.
- **Referral of 4.** 2,256 ns against 2,494 ns on average, inside the spread of the base runs (1,886 to 2,578). Each referral is preceded by a network exchange with an authority.

## Not measured here

- **Linux and the musl binary.** For the reason of M37.
- **The engine's resolution path under load.** Each resolution's queries go to authority servers, which dominate its time. The quota adds one atomic operation per query sent and one allocation per client query.
- **The lab rounds.** They do not run on this workstation (the host has no `python3` for Git Bash, and from WSL the lab bridge inside Docker Desktop's VM is unreachable). Their query counts per case, M40, are bound by the engine's tests (`recurse::tests`) and are unchanged.

## Method

| Item | Value |
| --- | --- |
| Machine | Intel Core i9-13900K (24 cores, 32 threads), 64 GiB RAM; Windows 11 Enterprise 10.0.26300; other builders' compilers active |
| Binaries | `cargo build -p tenko --release --locked` with the web UI built first, for `main` at `cbe6c27a` (from `git archive`) and for the changed tree; `tenko --version` prints `tenko 0.0.11 (root anchors 20326, 38696; root hints 2026-10-21)` for both. The upstream for every run is the `authoritative` example of the base tree; the harness is `bench/phase2-dns` release |
| Commands | `bash scripts/run-m24-cache.sh --server-binary <bins>/<build>/tenko.exe --upstream-binary <bins>/base/authoritative.exe --harness <bins>/phase2-dns.exe --data <data dir> --entries 100000 --out <file>` |
| Loopback | 127.0.0.1; the resolver on port 5300, the upstream on 5400, the resolver's metrics listener on 19464 |
