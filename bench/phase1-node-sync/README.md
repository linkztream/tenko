# Phase 1 node sync benchmark (M15)

Measurement M15 of the Slice 3 plan (`docs/plans/slice-3-plan.md`, section 5), configuration sync from a controller to a probe (OPS-28):

1. **Latency.** A scan-configuration change made with `PUT /api/v1/nodes/{id}/scan-config` reaches a connected probe within 5 seconds. Measured from just before the HTTP request is sent to the moment the probe logs `configuration revision N applied`.
2. **Bandwidth cap.** `[cluster] sync_kbps` holds within 10 percent. A stopped probe misses a large configuration, is started again and catches up; the bytes it reports (`bytes=` in the apply line) are divided by the transfer time and compared with the cap, with the initial burst of the token bucket (`crates/tenko-cluster/src/node_sync/rate.rs`) taken out.

## What the driver does

`m15-config-sync.mjs` (Node 22, no dependencies) starts two local processes, both on loopback:

- a controller: `tenko serve --config <file> --stop-on-eof` with the internal CA, the API on `127.0.0.1:<port>`, the cluster port on `127.0.0.1:<port>`, `[cluster] sync_kbps` (0 for the latency series, the cap for the cap series), air-gapped updates, no online breach check;
- a probe: `tenko node enrol` with a token from `POST /api/v1/nodes/enrolments` and the CA fingerprint, then `tenko serve --roles probe --stop-on-eof` with `TENKO_LOG__LEVEL=info`.

It bootstraps the administrator through `POST /api/v1/setup` (random PIN, never printed), signs in with a session cookie and keeps one TLS connection to the API open, so a measured request does not include a TLS handshake.

Every configuration the script stores has the scanner switched off (`enabled = false`, `active = false`, every method `enabled = false`), and the prefixes in it are random addresses under the documentation prefix `2001:db8::/32`. The probe therefore scans nothing and sends nothing beyond loopback; at the end the script lists the probe's sockets from `/proc/<pid>/net` and warns about any that is not loopback. The test node is `probe-m15.example.test`, address `192.0.2.20`.

Data directories are created under the system temporary directory (`$TMP/tenko-m15-*`) and removed at the end (`--keep` keeps them).

### Latency series

`--changes` (default 25) changes of the configuration, one at a time: each one changes `concurrency`, `per_host_interval_ms` and one prefix, so every change is a real change. For each, the script takes the time just before the request is written (`performance.timeOrigin + performance.now()`, sub-millisecond), waits for the probe's apply line, and uses the **timestamp printed in the probe's log line** (microseconds, UTC, the same clock) as the end. The time at which the script read the line from the probe's pipe is recorded as a cross-check (it is about 0.3 ms later). 1.5 s pass between changes. Polling `tenko node status --json` was not chosen: every poll starts a process and the interval would dominate the result.

### Cap series

For each cap in `--caps` (default `64,256`), the controller is restarted with that `sync_kbps`, and `--cap-runs` (default 5) times: stop the probe, `PUT` a large configuration (a new random one each run, `--prefixes` sets how many `/128` prefixes), start the probe, and read from its log

- the start of the transfer: the timestamp of `connected to the controller` (the probe opens the `Config.Watch` stream right after it; this is the closest point the log gives to the watch request, and a few milliseconds early);
- the end: the timestamp of `configuration revision N applied`, with `bytes=` (wire bytes of the payload, after compression, as the pacer counts them) and `snapshot=`.

The bucket (`rate.rs`): rate `R = sync_kbps x 125` bytes per second, burst `B0 = max(R / 10, 4096)` bytes, the bucket starts full, chunks of 16 KiB, each chunk waits until the bucket is out of debt before it is sent. Over a transfer of `T` seconds at most `B0 + R x T` bytes pass, so the script reports

- raw rate `bytes / T`,
- burst-corrected rate `(bytes - B0) / T`, which is compared with `R` (ratio 1.00 means the cap holds exactly),
- expected time `(bytes - B0) / R`.

The cap is read as held when the burst-corrected rate is within 10 percent of the cap, and the raw rate does not exceed it by more than 10 percent.

The size of a transfer is chosen so that it takes 5 to 20 seconds. The largest valid configuration is about 2 MiB (see the result file), which takes 250 s at 64 kbps: too long for five runs, so smaller ones are used (defaults: 2,500 prefixes at 64 kbps, 9,500 at 256 kbps).

## Prerequisites

- Linux (the socket check reads `/proc`), Node 22.
- A `tenko` binary that embeds the real web UI. From the repository root:

```
cd ui && npm ci && npm run build && cd ..
cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl
```

  (a release build refuses the placeholder UI; do not set `TENKO_UI_STUB`). This is the static musl binary that the release workflow ships for Linux, so the measurement runs on the binary that ships (it needs `rustup target add x86_64-unknown-linux-musl` and `musl-gcc` from `musl-tools`). The driver uses `target/x86_64-unknown-linux-musl/release/tenko`, or `TENKO_BIN`, or `--binary PATH`.
- Free loopback ports (the driver picks them), `jq` is not needed.

## Run

```
node bench/phase1-node-sync/m15-config-sync.mjs --changes 30
```

Options: `--binary PATH`, `--changes N`, `--caps 64,256`, `--cap-runs N`, `--prefixes 64=2500,256=9500`, `--only all|latency|cap`, `--raw-dir DIR`, `--keep`. The Markdown tables in the result file are made from the printed lines and `results/raw/m15-<stamp>-result.json`.

An uncapped comparison (`--only cap --caps 0 --prefixes 0=9500`) shows how fast the same transfer is without a cap. The largest valid configuration: `--only cap --caps 256 --cap-runs 1 --prefixes 256=46000`.

## Output

- stdout: latency statistics, one line per cap run, the verdicts.
- `results/raw/m15-<stamp>-{result.json,controller.log,probe.log}`: every sample, both process logs (the setup token is redacted). `results/raw/` is git-ignored (root `.gitignore`, `bench/**/results/raw/`).
- Results are written up in `results/<date>-m15-config-sync.md`.
