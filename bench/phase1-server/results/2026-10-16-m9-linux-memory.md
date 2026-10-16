# M9 idle RSS on Linux: where the memory of the Slice 3 build lives, 2026-10-16 (Linux)

Verdict: PASS (the static musl release binary, 76.05 MiB at most over 600 s; the glibc build of the same source fails at 123 to 127 MiB)

Measurement M9 of the Phase 1 plan (section 8), run again on Linux to explain the failure of the [first Slice 3 run](2026-10-16-m9-idle-rss.md) (idle VmRSS 120.9 MiB against 75.1 MiB on [2026-10-09](2026-10-09-m9-idle-rss.md)). Three binaries of the same source were measured with `m9-idle-rss.sh`: the glibc release build that the procedure in [../README.md](../README.md) describes, the same binary stripped, and the static musl binary built the way the release workflow builds it (`.github/workflows/release.yml`, deviation 30 of [phase-1-exit.md](../../../docs/plans/phase-1-exit.md)). The musl binary is the Linux release binary, and it passes; the glibc build fails. Further runs with glibc tunables, a heap profile and a link-time-optimised build say where the memory lives.

## Summary

100 MB is read as 100,000,000 bytes, which is 95.37 MiB. Memory figures are MiB. "Ready" is the sample the script takes when the server is ready, before setup; "end" is the last idle sample.

| Binary | Ready: VmRSS / RssAnon / RssFile | End of idle: VmRSS / RssAnon / RssFile | Largest idle VmRSS | OPS-15 |
|---|---|---|---|---|
| (a) glibc release, run 1 | 93.72 / 34.00 / 59.72 | 126.95 / 59.71 / 67.23 | 126.95 | **FAIL** |
| (a) glibc release, run 2 | 88.24 / 34.03 / 54.21 | 123.08 / 60.16 / 62.92 | 123.14 | **FAIL** |
| (b) glibc, stripped, run 1 | 88.37 / 34.03 / 54.34 | 123.04 / 60.34 / 62.70 | 123.04 | **FAIL** |
| (b) glibc, stripped, run 2 | 100.11 / 34.04 / 66.06 | 130.52 / 60.37 / 70.14 | 130.88 | **FAIL** |
| (c) static musl, run 1 | 61.90 / 8.96 / 52.94 | 76.06 / 15.18 / 60.88 | 76.06 | **PASS** |
| (c) static musl, run 2 | 62.06 / 8.95 / 53.11 | 75.93 / 15.07 / 60.86 | 75.93 | **PASS** |
| (c) static musl, 600 s idle | 62.08 / 8.97 / 53.11 | 76.04 / 15.12 / 60.93 | 76.05 (79.7 MB) | **PASS**, 19.3 MiB under the limit |

The rows above "600 s idle" ran with 120 s of idle instead of 600 s (see Caveats); the readings are flat after 60 s in every run, and the 600 s run of (c) confirms it (21 samples, 74.96 to 76.05 MiB, the last 20 within 0.01 MiB).

In short:

- **Anonymous memory is the allocator.** The same code holds 15.1 MiB of anonymous memory at the end of idle with musl's allocator and 59.7 to 60.4 MiB with glibc malloc. The rise against 2026-10-09 (47.18 MiB, glibc) comes from start-up: Slice 3 parses the embedded language packs at start, which raises the start-up peak of live heap blocks from 20.3 to 31.2 MiB, and glibc's main heap stays at that peak although only 5.2 MiB are still live when the server is ready.
- **File-backed memory is the larger program.** The resident pages of the binary rose with its code: `.text` grew from 28.2 to 70.5 MB and `.rodata` from 2.8 to 12.0 MB, and RssFile with them, to about 61 MiB at the end of idle for every build, musl included. Stripping does not change it (the symbol table is never paged in); fat LTO with one codegen unit saves about 10 MiB.
- **No release-profile change brings the glibc build under the limit** (the best, fat LTO, gives 112.16 MiB), so the workspace profile is unchanged. glibc gets under the limit only with allocator settings that need code or the environment (79.63 MiB with a fixed mmap threshold and periodic `malloc_trim`).

## Machine and toolchain

| Item | Value |
|---|---|
| CPU | 13th Gen Intel Core i9-13900K, 32 logical CPUs |
| RAM | the WSL2 VM sees 51.0 GiB |
| WSL | kernel 6.18.33.2-microsoft-standard-WSL2, Ubuntu 24.04.3 LTS, glibc 2.39 (`GLIBC 2.39-0ubuntu8.9`) |
| Rust | `rustc 1.99.0 (b940084d7 2026-09-28)`, `cargo 1.99.0 (5f94df478 2026-08-27)`, targets `x86_64-unknown-linux-gnu` and `x86_64-unknown-linux-musl` (the musl target was added for this run, with `musl-tools` 1.2.4-2 for `musl-gcc`) |
| Data directory | `/tmp` in WSL2 (ext4 on the virtual disk) |

## Source and build

- Source: `git archive 9ac10789e916494cccab821b394efa78ffdbdab7` (main), extracted to `/home/plm/m9mem/src` (ext4), with the `ui/dist` built from the same commit (`npm run build`) copied in. SHA-256 of the archive `5c229ae8771239e2`, of the `ui/dist` tar `00c4d309d2d11ed9` (prefixes). The working tree was clean.
- (a) glibc: `CARGO_TARGET_DIR=/home/plm/target/m9mem cargo build -p tenko --release --locked` (108 s). 127,822,160 bytes, not stripped, SHA-256 `11534295ad21e9a1`.
- (b) stripped: `strip` on a copy of (a) (the same as `CARGO_PROFILE_RELEASE_STRIP=symbols`; the release profile has no debug information to remove). 97,360,248 bytes, SHA-256 `f5de5fbaec13fe6b`.
- (c) static musl, as in the release workflow: `CARGO_TARGET_DIR=/home/plm/target/m9mem cargo build --release --locked -p tenko --target x86_64-unknown-linux-musl` (109 s). 124,389,360 bytes, `static-pie linked`, not stripped, SHA-256 `b462dff20f0cc8df`. Its allocator is musl's own malloc from the musl libc that the Rust target bundles; the workspace sets no `#[global_allocator]`.
- (d) for comparison only: (a) with `CARGO_PROFILE_RELEASE_LTO=fat CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_STRIP=symbols` in `CARGO_TARGET_DIR=/home/plm/target/m9mem-lto` (592 s). 85,022,632 bytes, SHA-256 `ecfac411214418f6`.
- Also used: the two binaries of the earlier runs, kept in WSL: `/home/plm/m9-bin/tenko` (the 2026-10-09 build, 49,194,720 bytes) and `/home/plm/m9-bin/tenko-64e337d` (the first Slice 3 run, 127,669,528 bytes).

| Binary | `.text` | `.rodata` | `.eh_frame` |
|---|---|---|---|
| 2026-10-09 build | 28.2 MB | 2.8 MB | 2.4 MB |
| `64e337d` and (a), (b) | 70.5 MB | 12.0 MB | 6.1 MB |
| (c) musl | 70.6 MB | 12.0 MB | 6.1 MB |
| (d) fat LTO | 64.8 MB | 11.9 MB | 2.9 MB |

## Method

M9 as in [../README.md](../README.md) (fresh data directory, shipped defaults, `hibp.online = false`, setup and login with the CLI, 200 prefixes, then idle and `SIGTERM`), inside WSL as user `plm`, the raw output in `/home/plm/m9mem/raw` instead of `results/raw`:

```
bash bench/phase1-server/m9-idle-rss.sh --binary /home/plm/m9mem/bin/tenko-gnu          --idle-secs 120 --outdir /home/plm/m9mem/raw
bash bench/phase1-server/m9-idle-rss.sh --binary /home/plm/m9mem/bin/tenko-gnu-stripped --idle-secs 120 --outdir /home/plm/m9mem/raw
bash bench/phase1-server/m9-idle-rss.sh --binary /home/plm/m9mem/bin/tenko-musl         --idle-secs 120 --outdir /home/plm/m9mem/raw
bash bench/phase1-server/m9-idle-rss.sh --binary /home/plm/m9mem/bin/tenko-musl --port 18445 --outdir /home/plm/m9mem/raw     (600 s)
```

Experiments on the glibc build, each a full M9 run with 120 s of idle (the script passes its environment to the server):

```
MALLOC_MMAP_THRESHOLD_=131072 bash bench/phase1-server/m9-idle-rss.sh --binary /home/plm/m9mem/bin/tenko-gnu --idle-secs 120
MALLOC_ARENA_MAX=1            bash bench/phase1-server/m9-idle-rss.sh --binary /home/plm/m9mem/bin/tenko-gnu --idle-secs 120
MALLOC_MMAP_THRESHOLD_=131072 MALLOC_TRIM_THRESHOLD_=131072 MALLOC_ARENA_MAX=1 bash bench/phase1-server/m9-idle-rss.sh --binary /home/plm/m9mem/bin/tenko-gnu --idle-secs 120
gcc -O2 -shared -fPIC -o /home/plm/m9mem/heap/trimshim.so bench/phase1-server/tools/trimshim.c -lpthread
LD_PRELOAD=/home/plm/m9mem/heap/trimshim.so bash bench/phase1-server/m9-idle-rss.sh --binary /home/plm/m9mem/bin/tenko-gnu --port 18446 --idle-secs 120
LD_PRELOAD=/home/plm/m9mem/heap/trimshim.so MALLOC_MMAP_THRESHOLD_=131072 bash bench/phase1-server/m9-idle-rss.sh --binary /home/plm/m9mem/bin/tenko-gnu --port 18446 --idle-secs 120
bash bench/phase1-server/m9-idle-rss.sh --binary /home/plm/m9mem/bin/tenko-gnu-lto --idle-secs 120
```

Memory by mapping 10 s after ready, with the tools added in `bench/phase1-server/tools/` for this run (they are standalone measurement aids, outside the Cargo workspace; no dependency was added):

```
PROBE_OUT=/home/plm/m9mem/probe bash bench/phase1-server/tools/ready-probe.sh <binary> 18461 <label> 10
MALLOC_ARENA_MAX=1 | MALLOC_TRIM_THRESHOLD_=131072 | MALLOC_MMAP_THRESHOLD_=131072  (prefixed to the same command)
HEAP_OUT=/home/plm/m9mem/heap bash bench/phase1-server/tools/heap-ready.sh <binary> 18465 <label>
```

`ready-probe.sh` sums `Rss` and `Anonymous` of `/proc/<pid>/smaps` by kind of mapping and lists the threads. `heap-ready.sh` runs the server under `heapshim.c`, an `LD_PRELOAD` interposer of the glibc allocation functions that records, per call stack, the live bytes and the bytes allocated since the start, dumps them at ready and symbolises them with `heapsym.py` (`addr2line` on the unstripped binary). `trimshim.c` calls `malloc_trim(0)` every 10 s from its own thread. No tool was installed for these; gcc, python3 and binutils were already in the WSL image.

## Results

Every M9 run created 200 of 200 prefixes without failures (15.6 to 16.3 s), and every server stopped on `SIGTERM` with exit status 0. Server logs as in the first Slice 3 run.

### Where the memory lives at ready

Memory by mapping 10 s after ready, before setup (`ready-probe.sh`), MiB:

| Mapping | 2026-10-09 build, glibc | `64e337d`, glibc | (a) glibc | (c) musl |
|---|---|---|---|---|
| VmRSS | 44.64 | 86.05 | 86.48 | 59.79 |
| glibc main heap (`[heap]`) | 19.56 | 31.14 | 31.18 | 0.19 (musl does not use it for most blocks) |
| other anonymous mappings (thread arenas, thread stacks, musl's mmap'd groups) | 0.77 | 1.12 | 1.12 | 7.07 |
| binary, code (`r-xp`) | 17.84 | 39.67 | 40.09 | 40.77 |
| binary, read-only data and relocations (`r--p`, `rw-p`) | 3.93 | 11.55 | 11.50 | 11.58 |
| shared libraries (libc, libm, libgcc_s, ld.so) | 2.40 | 2.40 | 2.40 | none (static) |
| Threads | 8 | 8 | 8 | 8 |
| VmHWM at this point | 44.64 | 86.05 | 86.48 | 81.24 |

The thread count did not change (3 core workers, 2 API workers, the API, the log writer and the main thread), and the seven 64 MiB arena reservations are there in both glibc builds with nothing resident in them. The anonymous rise at ready is the main heap: 19.56 to 31.14 MiB.

glibc tunables do not shrink that heap at ready (`64e337d`; the 2026-10-09 build in brackets): `MALLOC_ARENA_MAX=1` 31.57 (19.96), `MALLOC_TRIM_THRESHOLD_=131072` 30.03 (18.44), `MALLOC_MMAP_THRESHOLD_=131072` 30.04 (18.42) MiB. So the heap is not large freed blocks at its top waiting for a trim; it is freed space between small blocks that are still live.

The heap profile (`heap-ready.sh`, sizes as requested from the allocator) shows what start-up does:

| | 2026-10-09 build | `64e337d` |
|---|---|---|
| Allocations from start to ready | 1,061,578 | 1,761,807 |
| Peak of live blocks during start-up | 20.32 MiB | 31.18 MiB |
| Live blocks at ready | 1.43 MiB | 5.16 MiB |
| glibc main heap resident at ready (table above) | 19.56 MiB | 31.14 MiB |

The resident main heap equals the start-up peak in both builds: glibc does not give the freed space back, because live blocks allocated during and after the peak sit above it. musl's allocator returns freed groups to the kernel, which is why the musl binary has a VmHWM of 81 to 84 MiB but only 9 MiB of anonymous memory at ready.

Bytes allocated from start to ready, by subsystem (the first frame of each stack outside the allocator and the standard library; a `realloc` counts at its new size, so these are churn, not live memory):

| Subsystem | 2026-10-09 build | `64e337d` | Live at ready (`64e337d`) |
|---|---|---|---|
| OpenAPI document (`utoipa` `ToSchema::schemas` and `OpenApiRouter::nest`, while the API router is built) | 58.2 MiB | 64.1 MiB | none |
| Language packs (`tenko_api::i18n`: XLIFF parsing in `xliff::TreeBuilder::text`, `xliff::collect_units`, `xliff::read`, the ICU parser, `Languages::embedded`, `KeySet::from_source_documents`) | none | 39.1 MiB | 2.1 MiB |
| API router and middleware (`axum`, `matchit`, `tower` layers per route) | 0.2 MiB | 0.6 MiB | 0.8 MiB |
| Metrics registry (`CounterVec::seal_with_shards`, histograms, gauges, route table) | none | 0.4 MiB | 0.5 MiB |
| Store (`redb`, `openraft`) | 0.9 MiB | 1.2 MiB | 0.8 MiB |

The candidates the brief listed and what became of them: the language packs are the new start-up cost (they are parsed from the embedded XLIFF at start); the metrics registry and histograms of WP3.5 hold 0.5 MiB; the embedded UI is not decompressed (its table points at static slices, 0.01 MiB); tracing and the OTLP pipeline, the cluster and reconciler state and the connector supervisor are below 0.05 MiB each; the threads and their stacks did not change.

### The anonymous rise from 2026-10-09, step by step

RssAnon in MiB (the 2026-10-09 run; the first Slice 3 run of `64e337d`, whose phases the summary of (a) matches within 0.2 MiB):

| Phase | 2026-10-09 | Step | Slice 3 | Step |
|---|---|---|---|---|
| Ready | 21.38 | | 34.04 | |
| After setup and login | 40.79 | +19.41 | 53.59 | +19.55 |
| End of idle, 200 prefixes | 47.18 | +6.39 | 60.37 | +6.78 |

Setup, login and the prefixes add the same in both builds: one Argon2id hash at 19 MiB that glibc keeps in a thread arena (observation 2 of 2026-10-09) and about 6.5 MiB for the requests and the data. The whole difference is there at ready, +12.7 MiB: +11.6 MiB in the main heap, which follows the start-up peak of live blocks (+10.9 MiB), and about 1 MiB of relocated data and small mappings. So the 13.2 MiB of anonymous rise in the first Slice 3 run are the higher start-up peak that glibc keeps (most of it the language packs) plus about 4 MiB of new live data at ready (the language catalogue, the metrics registry, more routes), of which part sits inside the retained heap.

### Where the file-backed rise lives

At ready, the resident code of the binary rose from 17.84 to 39.67 MiB and its read-only data from 3.93 to 11.55 MiB, together 29.5 MiB; the rise of RssFile at the end of idle in the first Slice 3 run was 32.3 MiB. That is the code and data that start-up and the first requests touch, in a binary whose `.text` is 2.5 times and `.rodata` 4.3 times the size of the 2026-10-09 build. musl does not help here (RssFile 60.9 MiB at the end of idle, against 62.7 to 67.2 MiB for glibc, which also maps its shared libraries).

RssFile varies by up to 8 MiB between runs of the same binary (62.92 and 67.23 MiB for (a), 62.70 and 70.14 MiB for (b)); the kernel maps file pages around each fault, and what it maps depends on the page cache. The stripped binary is therefore not measurably smaller in memory: its two runs lie on both sides of the glibc runs.

### Experiments on the glibc build

Full M9 runs, 120 s idle, MiB:

| Setting | Ready VmRSS / RssAnon | End VmRSS / RssAnon / RssFile | Largest idle VmRSS | OPS-15 |
|---|---|---|---|---|
| none ((a), two runs) | 88.24 to 93.72 / 34.0 | 123.08 to 126.95 / 59.7 to 60.2 / 62.9 to 67.2 | 123.14 to 126.95 | FAIL |
| `MALLOC_ARENA_MAX=1` | 88.21 / 33.85 | 115.73 / 53.24 / 62.48 | 115.73 | FAIL |
| `MALLOC_MMAP_THRESHOLD_=131072` | 85.99 / 33.33 | 101.58 / 40.27 / 61.30 | 101.58 | FAIL |
| mmap and trim threshold 131072, `MALLOC_ARENA_MAX=1` | 87.45 / 33.18 | 95.39 / 33.56 / 61.83 | 95.39 | FAIL by 0.02 MiB |
| `malloc_trim(0)` every 10 s (`trimshim.c`) | 88.73 / 34.05 | 98.93 / 35.77 / 63.16 | 98.94 | FAIL |
| `malloc_trim(0)` every 10 s and `MALLOC_MMAP_THRESHOLD_=131072` | 88.11 / 33.32 | 79.63 / 16.48 / 63.16 | 79.63 | **PASS** |
| (d) fat LTO, one codegen unit, stripped | 88.35 / 33.46 | 112.16 / 59.73 / 52.43 | 112.16 | FAIL |

A fixed mmap threshold sends the Argon2 block and the other large blocks to `mmap`, so they go back to the kernel when freed (about 20 MiB less RssAnon at the end of idle); `malloc_trim(0)` then returns the free pages inside the main heap (about 24 MiB more). Without the fixed threshold, the trim alone does little, because the Argon2 block stays in a thread arena. Together they bring glibc to the level of musl (RssAnon 16.5 against 15.1 MiB). Fat LTO shrinks the code by 8 percent and RssFile by about 10 MiB, but leaves the glibc build at 112 MiB.

## Verdict

M9 is met on Linux by the Linux release binary: the static musl build of `9ac1078` idles at 76.05 MiB at most over 600 s (79.7 MB), 19.3 MiB under 95.37 MiB. The glibc build of the same source fails at 123 to 127 MiB, as the first Slice 3 run did, and no setting of the release profile changes that. The workspace profile was not changed.

## Caveats and leads

- Idle length: the runs except the last one used 120 s of idle (5 samples) instead of 600 s, a deviation from the procedure; every run was flat after 60 s, and the 600 s run of the musl binary was flat from 60 s to 600 s within 0.01 MiB.
- The procedure in [../README.md](../README.md) builds the glibc binary (`cargo build -p tenko --release`). The Linux release binary is the musl build, so M9 on Linux as written measures a binary that is not shipped as a file. The container image is: `deploy/Dockerfile` builds with `rust:1-slim-bookworm` and runs on `distroless/cc-debian12`, a glibc build (glibc 2.36). It was not measured here; with glibc malloc it should behave like (a), so the image very likely fails OPS-15 today.
- S3-Q10 (deviation 30) falls back to a glibc release binary if M5 on musl drops more than 10 percent. With that fallback, M9 on Linux fails again unless the allocator behaviour changes.
- The heap profile ran with glibc only and slows the server by orders of magnitude (start-up takes minutes); the sizes are requested sizes, not allocator chunks. It accounts for the anonymous memory at ready and the start-up peak; it was not taken after setup or after the prefixes.
- WSL2, not bare metal; one machine; the workstation was building and measuring other binaries at the same time (memory figures are not sensitive to that, timings are).
- The data set is CLI-created prefixes, not an import, and only the controller role exists, as in every M9 run so far.
- Raw output (CSV, summaries, redacted server logs) is in `/home/plm/m9mem/raw`, the probe and heap reports in `/home/plm/m9mem/probe` and `/home/plm/m9mem/heap`, inside WSL; they are not committed.
