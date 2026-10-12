# Phase 1 backup benchmark (M14)

Measurement M14 of the slice 3 plan (`docs/plans/slice-3-plan.md`, section 5): backup and restore
(OPS-07, WP3.4b).

| Threshold | Limit (proposed) |
|---|---|
| Create a backup of 1 M records | below 2 min |
| Restore and verify a backup of 1 M records | below 5 min |

The harness is a standalone crate (its own empty `[workspace]`, path dependencies on the
workspace crates, its own `target/`). It calls the library behind `tenko backup`
(`tenko::backup::{create, restore}`) directly, so it times the same code as the commands without
process start-up or terminal output.

All data is synthetic. Nothing leaves the process and nothing touches a network; the only I/O
is the scratch directory.

## The data

The M6 data set of `bench/phase1-store`: 1,000,000 RRset-like records in the table
`ipam.bench_rrsets`, a 22 byte key and a 128 byte value (150 bytes together), loaded in batches
of 10,000 records with one audit draft each, four proposals in flight. `src/data.rs` is a copy of
the record shape and the batch builder of `bench/phase1-store/src/data.rs`; the crate does not
depend on `phase1-store`. Five vault secrets are added (as in the end-to-end test of the backup
library) so that the envelope checks of `verify` have work to do.

## What is measured

Per run, on a fresh single-voter `RaftStore` (`fsync_probe_samples = 0`):

| Step | Call | Command |
|---|---|---|
| load | batches of 10,000 | (setup) |
| create live, recipient | `create::from_live`, recipient key lock | `tenko backup create --url ...` |
| create live, passphrase | `create::from_live`, passphrase lock with `KdfParams::HARDENED` | the same with a passphrase |
| create closed, recipient | `create::from_closed` after the store is shut down | `tenko backup create --data-dir ...` |
| verify | `restore::check` | `tenko backup verify` |
| restore | `restore::restore`, no dry run, plain-file KEK provider | `tenko backup restore` |

A first, separate step creates a backup of a store without records with each lock, to isolate the
fixed cost of the Argon2id passphrase slot. Per step the harness records wall time, the peak
resident set of the process and the peak allocated size of the run directory (source store,
backups and restored store together, sampled every 100 ms).

## Run

```
cd bench/phase1-backup
CARGO_INCREMENTAL=0 TENKO_UI_DIST=<dir with an index.html> cargo run --release -- \
    --records 1000000 --runs 3 --out-name m14
```

| Option | Default | Meaning |
|---|---|---|
| `--records` | 1,000,000 | records to load |
| `--runs` | 3 | runs, each on a fresh store |
| `--scratch` | `<tmp>/phase1-backup` | scratch directory (needs a few GB for the full set) |
| `--out-name` | `m14` | raw output `results/raw/<out-name>.json` |

Raw output goes to `results/raw/` (git-ignored). The result write-ups are in `results/*.md`.

`TENKO_UI_STUB=1` is refused by `tenko-api` in release builds (it builds in debug). Point
`TENKO_UI_DIST` at any directory that holds an `index.html` instead; the UI is not on the
measured path.
