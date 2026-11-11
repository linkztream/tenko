# Relay trust, client limits and the renewal cache: regression check (2026-11-11)

**Question.** Do the trusted relay list, the limits per client and per scope and the renewal cache (`docs/dhcp.md` sections 9.8 and 14.9) cost the DORA path or renewals anything, and how many store writes does the renewal cache save?

**This is a regression check, not a measurement.** It ran on a shared Windows workstation with nine other build sessions, so the figures move with their load; base and changed runs were interleaved so that both saw the same load.

## Setup

- **Binaries.** `crates/tenko-dhcp/examples/dhcp_server.rs`, release build (`lto = "fat"`, Windows), of the base commit `cbe6c27a` and of the change, before the follow-ups of its review (the follow-ups touch new-binding and RELEASE paths only, not the four-way exchange of a client with an offer nor a renewal). Not the shipped musl binary: the comparison is of the engine between two builds of the same kind.
- **Server.** `serve --workers 4 --store queue` on loopback (the engine and the commit hand-off without a store behind them), lease 3,600 s. The changed server runs under the Lab profile (its limits are off for the load client, which sends 100,000 clients from 256 MAC addresses) with the trusted relay list `0.0.0.0/0`, so that the trust check walks a list as on a node with one.
- **Load.** The example's own client: `dora` with 50,000 clients and 64 in flight (M26's closed loop), and `renew` with 20,000 clients, 64 in flight, for 15 s (M27's renewals after a fill).
- **Rounds.** Three interleaved rounds of base `dora`, changed `dora`, base `renew`, changed `renew` with `--renew-cache-percent 25`, changed `renew` with `0`; then three more pairs of changed `renew` at 0 and base `renew`, the changed one first. One base `renew` of the first round collided with a server left over from an aborted run and is not counted.

## Summary

| | Base | Changed |
|---|---|---|
| Four-way exchanges per second (`dora`, two clean rounds) | 58,605, 50,514 | 59,370, 55,030 |
| Renewals per second, cache off (`renew`; base five runs, changed six) | 50,461, 49,536, 51,566, 53,050, 54,434 | 47,135, 41,536, 52,882, 54,261, 49,348, 57,586 |
| Renewals per second, cache 25 % | | 77,492, 62,778, 50,739 |
| Store commits per renewal | 1 | 0 with the cache (the 20,000 commits of a run are the fill's grants); 1 without it |

- **No regression is visible beyond the machine's noise.** The four-way exchange ran at the same rate. With the cache off, the changed renewals ran 7 and 16 percent below base in rounds two and three, where they ran last of five, and level with base (49,348 to 54,261 against 51,566 to 54,434) in the three pairs where they ran first; the first round's 57,586 has no base beside it.
- **Store writes.** With the cache at 25 percent every renewal of these runs, 761,236 to 1,162,483 of them, was answered from the stored lease: 20,000 commits per run (the grants of the fill) against one commit per renewal without the cache (643,261 to 883,855). In production a commit is the lease row and a history row; a renewal answered from the cache writes neither.

## How fast early renewals would fill a disk

One commit of a renewal rewrites the lease row (262 octets of CBOR for a lease with a host name and an FQDN, measured on the engine's row) and adds a history row of 50 octets under a key of 46, before the store's own overhead. At the 4,912 renewals per second of M27 on the lab node, one looping client set adds about 470 kB of history a second, about 40 GB a day, kept for the retention (7 to 90 days by profile). With the renewal cache, a client that renews within the first quarter of its lease writes nothing, so one identity looping renewals no longer grows the store; a client that releases and requests again is held to ten RELEASEs an hour.

## Caveats

- Loopback, one host, a loaded shared machine: compare the columns of one table only.
- The cache's rate gain (renewals answered without a commit hand-off) is a property of the engine without a store; with the store the saved work is the commit itself.
