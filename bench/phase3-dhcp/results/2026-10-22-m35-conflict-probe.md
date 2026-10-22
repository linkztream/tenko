# M35 (E27's conflict rows): the conflict probe's cost and a squatter detected before the offer (Windows release and the lab VMs)

Verdict: PASS (the offer delay for an address never leased before is at most the 300 ms cap: on Windows 90 new clients with a probe that never answers took 287.9 to 299.0 ms from DISCOVER to OFFER, on the lab node through `tenko serve` 80 new clients took 295.1 to 297.0 ms with ARP and 295.6 to 299.1 ms with ICMP; renewals are not probed and not delayed: p99 0.17 ms on Windows with conflict detection against 0.19 ms without, p99 1.93 ms on the lab node; a squatter on the node's link was detected in 20 of 20 tries by ARP, with its MAC address, and 20 of 20 by ICMP, and no client was offered a squatted address)

This run measures WP8.5 of `docs/plans/phase-3-plan.md` (section 2.7, P3-Q7, DHCP-06, TGL-16): the probe before an OFFER of an address with no lease history for the client, the pending table outside the workers, the cap, the conflict mark, and the DECLINE hold. M35 of plan section 6: "Offer delay at most the 300 ms cap for new addresses, none for renewals; a squatter detected in 20 of 20 tries". Every figure is a single-node figure (plan section 2.12). The compose rows of E27 wait for WP7.6's lab.

## The two halves

**Windows** (`crates/tenko-dhcp/tests/conflict.rs`, `m35_offer_delay_and_renewals`, release profile, `TENKO_M35_CLIENTS=90`): the crate's own relay client against the listeners and workers of `tenko_dhcp::server` on loopback (the server the example of `crates/tenko-dhcp/examples` runs), one worker, the in-memory lease store, and a fake probe that never answers, so every new address waits for the cap. 90 new clients run DISCOVER, OFFER, REQUEST and ACK one after another (the time from the DISCOVER sent to the OFFER received), then each renews (REQUEST with `ciaddr` to the ACK); the same renewals on a server without a probe are the baseline. The test fails when an OFFER arrives later than the cap plus 60 ms or a renewal takes 100 ms.

**The lab** (the node VM and the load VM, Ubuntu 24.04, kernel 6.8, 4 and 8 vCPU, one L2 segment): the shipped binary, `tenko serve` of the static musl release build (`cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl` of this branch with the web UI built), run as an unprivileged user from a directory of its own on high ports, with `roles = "controller,dhcp,probe"`, the Home profile, a relay listener on loopback and the API on loopback. Through the API: the IPAM network 198.51.100.0/24 (TEST-NET-2, RFC 5737), a `dhcp_pool` range .50 to .149 and its scope. The node has 198.51.100.1/24 on its interface; the load VM, the squatter, holds every fifth address of the pool (.50, .55, ... .145: 20 addresses) on its interface, so its kernel answers ARP and ICMP for them as a host that took them without DHCP would. The relay client is the ignored test `lab_m35_squatters_are_skipped` of `tests/conflict.rs` on the node (giaddr 127.0.0.1, option 118): 80 new clients run DORA one after another, each OFFER timed and checked against the squatted addresses, then each renews, then the first client declines its address. After the client, `GET /dhcp/leases` gives the rows, `GET /audit` the audit records, `GET /metrics` the counters.

- **ARP**: the binary with the file capability `cap_net_raw+ep`, so the probe sends ARP requests through `tenko-scan`'s raw link on the interface that holds 198.51.100.0/24.
- **ICMP**: the same binary without the capability; `net.ipv4.ping_group_range` is `1 0` on the VMs, so the probe runs the `ping` command.
- **No probe role**: `roles = "controller,dhcp"`.

## Results

M35, the offer delay of a new address and the renewals:

| Run | Probe | New clients | DISCOVER to OFFER min / p50 / p99 / max (ms) | Renewals p50 / p99 / max (ms) | Renewals without conflict detection p50 / p99 / max (ms) |
|---|---|---:|---|---|---|
| Windows release, loopback | never answers | 90 | 287.9 / 295.2 / 298.0 / **299.0** | 0.073 / 0.174 / 0.203 | 0.040 / 0.193 / 0.203 |
| Lab node, `tenko serve` musl | ARP | 80 | 295.1 / 295.8 / 296.9 / **297.0** | 1.09 / 1.93 / 1.97 | see the row without a probe role |
| Lab node, `tenko serve` musl | ICMP (`ping`) | 80 | 295.6 / 296.3 / 297.3 / **299.1** | 1.74 / 6.54 / 9.60 | |
| Lab node, `tenko serve` musl | none (no probe role) | 80 | 0.018 / 0.033 / 0.298 / 0.432 | 1.82 / 4.07 / 4.52 | |

A clean address waits for the whole cap, since only the cap says that nobody answered; the dispatcher takes one timer tick off it (`conflict::TIMER_TICK`, 16 ms on Windows, whose system timer ticks at 15.6 ms, 5 ms elsewhere), so the OFFER leaves within 300 ms of the DISCOVER's arrival. Renewals go to the ACK after the commit with no probe (the lab's renewals include the Raft commit, the Windows ones the in-memory store's); the difference to the baseline is within the noise. An earlier lab run without the 5 ms tick off the cap on Linux gave a maximum of 304.4 ms, which is why the tick applies on Linux too.

E27's conflict rows on the lab:

| Run | Squatted addresses abandoned before an offer | Offers of a squatted address | MAC address on the abandoned rows | `tenko_dhcp_conflicts_total` | DECLINE |
|---|---:|---:|---|---:|---|
| ARP | **20 of 20** | 0 | the load VM's (all 20) | 20 | the address abandoned for 86,400 s, audit record `dhcp.decline` by `system:dhcp` with the address, the client's MAC and the hold |
| ICMP | 20 of 20 | 0 | none (ICMP gives no MAC) | 20 | as with ARP |
| none | 0 (no probe) | **14** (the control: without the probe, 14 of the 80 clients were offered a squatted address) | | 0 | as with ARP (the first client had a squatted address and declined it) |

With ARP, 100 probes ran (80 clean addresses cut at the cap and 20 answers); their sum, 23.65 s, less the 80 cut probes at about 295.6 ms each, leaves a few milliseconds for the 20 answers together, so an ARP answer on the segment came back within about a millisecond and the next address was offered within the same cap. Every squatted address was hit by some client's allocation (the pool order is hashed per client) and found in use, abandoned with the squatter's MAC address for the hold time, and skipped by every later client; the server logged one line per conflict. With ICMP the same 20 addresses were found in use, abandoned without a MAC address (an echo reply names none); the 100 probes summed 23.69 s, nearly all of it the 80 probes cut at the cap. Without a probe role the server logged once at start that conflict detection is off for want of a probe role (`conflict detection is off: no probe role runs in this process, so the dhcp role offers addresses without a probe`), every OFFER went out at once, and the relay client failed on the 14 offers of squatted addresses, as it should. The health row `dhcp.probe.missing` belongs to the Hardened profile (TGL-16) and is tested at the role and API level (`tests/role.rs`, `dhcp_role_warnings`); the lab runs used the Home profile.

## Reproduce

Windows: `TENKO_M35_CLIENTS=90 cargo nextest run --release -p tenko-dhcp --test conflict --no-capture -E 'test(m35)'`.

The lab, from WSL: build the musl binary and the test binary of `tests/conflict.rs` (`cargo test -p tenko-dhcp --test conflict --no-run`), copy both to the node; on the load VM add the squatted addresses (`ip addr add 198.51.100.<n>/24 dev <if>` for n = 50, 55, ... 145); on the node add 198.51.100.1/24, write a `tenko.toml` with the roles, `[server] listen` and `[cluster] listen` on loopback high ports, `[tls] mode = "reverse_proxy"` with `trusted_proxies = ["127.0.0.1"]`, a file KEK, and `[dhcp] listen = [{ address = "127.0.0.1", mode = "relay" }]` with a high `port` and `relay_port`; for the ARP run `setcap cap_net_raw+ep` on the copy of the binary; start `tenko serve`, complete `POST /setup`, create the prefix, the range and the scope through the API, and run `TENKO_LAB_SERVER=127.0.0.1:<port> TENKO_LAB_RELAY_PORT=<relay_port> TENKO_LAB_SUBNET=198.51.100.0 TENKO_LAB_SQUATTERS=<the 20 addresses> TENKO_LAB_CLIENTS=80 ./conflict-<hash> --ignored --exact lab_m35_squatters_are_skipped --nocapture`; then `GET /api/v1/dhcp/leases?limit=1000`, `GET /api/v1/audit` and `GET /api/v1/metrics`. Remove the addresses afterwards.

Machines: the workstation of the earlier results (Intel Core i9-13900K, Windows 11 Enterprise 10.0.26300, rustc 1.99.0); the lab VMs as above. Branch of WP8.5 from `main` at `2c0f794`.
