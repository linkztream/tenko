# M15 configuration sync controller to probe: 2026-10-11 (Linux, loopback)

Measurement M15 of the Slice 3 plan (`docs/plans/slice-3-plan.md`, section 5): a configuration change made through the API reaches a connected probe within 5 seconds, and the bandwidth cap `[cluster] sync_kbps` holds within 10 percent (OPS-28). The numbers come from `bench/phase1-node-sync/m15-config-sync.mjs`, run against a release build.

## Summary

| Threshold | Measured | Result |
|---|---|---|
| API change reaches a connected probe within 5 s (30 changes) | min 7.6 ms / median 19.5 ms / p95 41.2 ms / max 109.1 ms | **PASS** (max is 2.2 percent of the limit) |
| `sync_kbps = 64` holds within 10 percent (5 runs, about 110 kB each) | burst-corrected rate 96.4 to 99.8 percent of the cap (raw 100.1 to 103.7 percent) | **PASS** |
| `sync_kbps = 256` holds within 10 percent (5 runs, about 415 kB each) | burst-corrected rate 98.5 to 99.9 percent of the cap (raw 99.4 to 100.9 percent) | **PASS** |

## Machine and toolchain

| Item | Value |
|---|---|
| CPU | Intel Xeon Processor @ 2.80GHz, 4 logical CPUs (virtual machine) |
| RAM | 15.7 GiB |
| OS | Linux, `uname -r` 6.18.44-fc-v114 |
| Rust | `rustc 1.99.0 (b940084d7 2026-09-28)`, `cargo 1.99.0 (5f94df478 2026-08-27)`, workspace `release` profile |
| Node | v22.22.0 (the driver) |
| Data directory | `$TMP/tenko-m15-*` (`/tmp`), removed after each run |

## Source and build

- Git commit: the build started at `2f0864d1617365d42cb40d438dfad2d787553ab9`; the runs were done with HEAD at `1c8e8f0d21923090c3a2d2292777e9d587f5e4d4` (latency and cap runs, recorded in the raw `result.json`) and later `41a442507a740cabef648f68e0996a9797ae0bce` (the two extra runs). The working tree was shared with other builders. The commits made between the start of the build and the runs touch tests and documents only under `crates/` (`git diff --stat 2f0864d HEAD -- crates` lists test files of `tenko-cluster`), and the tree had no uncommitted change in product code besides the deletion of `crates/tenko-scan/src/control/tests.rs` in favour of a `tests/` directory, so the binary is the code of those commits; this was not proven by a rebuild.
- Build: `cd ui && npm ci && npm run build`, then `cargo build -p tenko --release --locked` (24 min 12 s on 4 shared cores). `ui/dist` was built first, `TENKO_UI_STUB` was not set. It is a release build.
- Binary: `target/release/tenko`, 106,706,136 bytes, `tenko 0.0.1`.

## Method

Everything runs on 127.0.0.1. Two processes started by the driver:

```
tenko serve --config $TMP/tenko-m15-*/controller/tenko.toml --stop-on-eof          controller
tenko node enrol --controller https://localhost:<port> --token <token> --ca-fingerprint <sha256> --name probe-m15.example.test --address 192.0.2.20 --data-dir $TMP/tenko-m15-*/probe/data
TENKO_LOG__LEVEL=info tenko serve --roles probe --stop-on-eof --data-dir $TMP/tenko-m15-*/probe/data     probe
node bench/phase1-node-sync/m15-config-sync.mjs --changes 30                                              driver (latency and both caps)
node bench/phase1-node-sync/m15-config-sync.mjs --only cap --caps 256 --cap-runs 1 --prefixes 256=46000   largest valid configuration
node bench/phase1-node-sync/m15-config-sync.mjs --only cap --caps 0 --cap-runs 3 --prefixes 0=9500        no cap, for comparison
```

Controller configuration: `roles = "controller"`, profile `home`, `[tls] mode = "internal_ca"`, `[kek] provider = "file"`, `[hibp] online = false`, `[rate_limit] enabled = false`, `[cluster] listen = ["127.0.0.1:<port>"]` with `sync_kbps` 0 (latency) or the cap, `[updates] air_gapped = true`; the default heartbeat of 10 s.

Nothing is scanned. Every stored configuration is `enabled = false`, `active = false` with every method off; prefixes are random `2001:db8:...::/128` addresses. At the end of each run the probe's only socket was the connection to the cluster port of the controller on loopback (read from `/proc/<pid>/net/tcp`).

Latency: 30 `PUT /api/v1/nodes/{id}/scan-config` calls one after the other, each with a changed `concurrency`, `per_host_interval_ms` and prefix. Start: the time just before the request is written to the kept-alive TLS connection. End: the timestamp in the probe's log line `configuration revision N applied` (microseconds). 1.5 s between calls. Each call produced exactly one apply line.

Cap: for each cap, the controller was restarted with `sync_kbps`; then five times: stop the probe, `PUT` a new random configuration (the probe is offline), start the probe. Start of the transfer: the timestamp of `connected to the controller`; end: the timestamp of the apply line, whose `bytes=` is the wire size (`snapshot=false` in every run: the probe caught up with a delta). Bucket from `rate.rs`: `R = sync_kbps x 125` B/s, `B0 = max(R / 10, 4096)`, full at the start, chunks of 16 KiB. The formula applied: the bytes that can pass in `T` seconds are at most `B0 + R x T`, so the rate compared with the cap is `(bytes - B0) / T`; the expected time is `(bytes - B0) / R`.

## Results

### Latency (ms, 30 changes, timestamp of the probe's log line)

| min | median | p95 | max | mean |
|---|---|---|---|---|
| 7.6 | 19.5 | 41.2 | 109.1 | 21.8 |

Measured to the moment the script read the line from the probe's output instead: 7.8 / 20.0 / 41.4 / 109.4 ms. All 30 changes arrived; none was merged with another. A first trial of 5 changes (run when the machine was quieter) gave 6.3 / 7.0 / 9.7 / 10.1 ms; the 30-change run is the one reported because the other builders were running jobs (load average 4 to 5 at the start).

The change is on the probe before the 10 s heartbeat could matter: the configuration travels on the `Config.Watch` stream the controller keeps open.

### Bandwidth cap

`sync_kbps = 64`: R = 8,000 B/s, B0 = 4,096 B (R / 10 = 800 is below the minimum).

| Run | Wire bytes | Time (s) | Expected (s) | Raw rate (B/s) | Corrected rate (B/s) | Corrected / cap |
|---|---|---|---|---|---|---|
| 1 | 109,941 | 13.346 | 13.231 | 8,238 | 7,931 | 0.991 |
| 2 | 109,972 | 13.256 | 13.235 | 8,296 | 7,987 | 0.998 |
| 3 | 110,033 | 13.610 | 13.242 | 8,085 | 7,784 | 0.973 |
| 4 | 109,980 | 13.275 | 13.236 | 8,284 | 7,976 | 0.997 |
| 5 | 109,978 | 13.731 | 13.235 | 8,010 | 7,711 | 0.964 |

`sync_kbps = 256`: R = 32,000 B/s, B0 = 4,096 B (R / 10 = 3,200 is below the minimum).

| Run | Wire bytes | Time (s) | Expected (s) | Raw rate (B/s) | Corrected rate (B/s) | Corrected / cap |
|---|---|---|---|---|---|---|
| 1 | 415,237 | 12.867 | 12.848 | 32,271 | 31,953 | 0.999 |
| 2 | 415,315 | 13.052 | 12.851 | 31,819 | 31,505 | 0.985 |
| 3 | 415,258 | 12.866 | 12.849 | 32,275 | 31,956 | 0.999 |
| 4 | 415,102 | 12.947 | 12.844 | 32,062 | 31,746 | 0.992 |
| 5 | 415,149 | 12.872 | 12.845 | 32,252 | 31,933 | 0.998 |

The corrected rate never exceeds the cap (largest ratio 0.999), so the cap is never overrun; the raw rate is 0.1 to 3.7 percent above the cap because of the 4,096-byte burst. The shortfall (at most 3.6 percent) is the part of the time before the first chunk and after the last one (connect to watch request, store read, decode and write on the probe). The measured interval starts at the `connected` line, a few milliseconds before the watch request.

Reference runs:

| Run | Wire bytes | Time | Rate |
|---|---|---|---|
| Largest valid configuration (46,000 prefixes, 2,051,871 B of JSON), 256 kbps | 2,006,607 | 62.634 s (expected 62.578 s) | raw 32,037 B/s, corrected 31,972 B/s, ratio 0.999 |
| No cap (`sync_kbps = 0`), 9,500 prefixes, 3 runs | about 415,200 | 0.016 / 0.026 / 0.021 s | about 16 to 26 MB/s |

The largest valid configuration: the API refuses a body above 2 MiB with `413 sys.body_too_large` (a body of 2,052,109 bytes with 46,000 prefixes was accepted, 2,141,331 bytes with 48,000 was refused), and no count limit on prefixes stops it first. Its transfer takes 250 s at 64 kbps and 63 s at 256 kbps, too long for five runs, so the cap series use smaller configurations (2,500 and 9,500 prefixes), chosen so that a transfer takes 13 s (inside the 5 to 20 s window). The JSON of random documentation addresses does not compress: wire bytes are 98 to 99 percent of the JSON size.

## Caveats

- Latency is end-to-end on the loopback, between two processes on one machine, with a sub-millisecond clock shared by both (the same host clock). A real network adds its round trip time; the margin to 5 s is large, but the figure is not a WAN figure. The endpoint of the measurement is the probe's apply line (the new configuration is kept on disk and published to the node's other components); the scanner then restarts on it, which was not timed.
- Latency was measured with the controller uncapped and one probe connected. Several probes, a loaded store or a follower controller (a follower must first apply the revision) were not measured.
- The machine is a 4-core virtual machine that was also compiling and testing for other builders, so the p95 and max of the latency series (41 and 109 ms) are noisier than the 5-change trial (10 ms).
- The start of the cap transfer is taken from the `connected to the controller` log line, because the probe does not log the watch request. It is early by a few milliseconds, which is the shortfall in the tables.
- The probe caught up through a delta (`snapshot=false`) in every run. The snapshot path (a gap of more than 50,000 change sets in the journal) was not measured; it goes through the same pacer.
- Only a probe with a configuration of 1 row was measured (the `scan.probe_config` table). Other roles' tables (`tables_for`) add rows but not payload that this benchmark exercises.
- The cap series used one stream at a time; the cap is per stream (`rate.rs`), so the total of several nodes is not capped by this measurement.
- Each series was run once (30 changes, 5 runs per cap), plus the reference runs.
- The release build was made from a shared working tree (see Source and build).

## Conclusion

M15 is met. A configuration change made through the API reaches a connected probe in 19.5 ms at the median and 109 ms at the worst of 30 changes, against the limit of 5 s. The bandwidth cap holds: at 64 and 256 kbps the burst-corrected rate is 96.4 to 99.9 percent of the cap in all ten runs and never above it; the raw rate is at most 3.7 percent above because of the initial burst of 4,096 bytes.

## Raw output

In `bench/phase1-node-sync/results/raw/` (git-ignored), per run `m15-<stamp>-result.json` (every sample), `m15-<stamp>-probe.log` and `m15-<stamp>-controller.log` (setup token redacted).

| Run | Files |
|---|---|
| Latency (30 changes) and both caps | `m15-20261011T130623Z-*` |
| Largest valid configuration, 256 kbps | `m15-20261011T130937Z-*` |
| No cap, 9,500 prefixes | `m15-20261011T131047Z-*` |
