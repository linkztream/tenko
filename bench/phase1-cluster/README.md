# Phase 1 cluster lab measurements

The measurements of the cluster lab of WP3.1c on one machine. The lab starts three or four
`tenko serve` processes on the loopback and joins them with `tenko cluster join`. A TCP relay
sits on every link between two members, so a test can cut or delay a link. The harness is in
`crates/tenko/tests/cluster_support/`.

This is not a Cargo package of its own. The measurements are `#[ignore]` integration tests of
the `tenko` package: `crates/tenko/tests/cluster_measure.rs` (M1, M3, M4, M12, and a summary
test) and the M6 scenario in `crates/tenko/tests/cluster_membership.rs`. The scripts here
build them, run them one after another and collect the results.

## The measurements

| Measurement | What | Threshold | Here (one host) | Final run |
|---|---|---|---|---|
| M1 | Reads on a follower during the snapshot install of a joining learner | No empty reads; read p99 below 2x the baseline | IPAM list reads instead of the 6 M RRset test index | WP3.8, three VMs |
| M3 | `kill -9` of the leader at 100 writes/s, 20 runs | Writes resume within 15 s; no committed write is lost (digests agree, every committed create is present) | Yes (WP3.1c) | WP3.8, three VMs |
| M4 | 1,000 writes/s for 60 s on the leader, then an empty fourth controller joins and its catch-up time is measured | Write p99 below 250 ms; catch-up of 6 M RRsets below 5 min on 1 Gbit | The catch-up is a stand-in: the data set is not 6 M RRsets (that needs the DNS module) and the link is the loopback | WP3.8, three VMs |
| M6 | Disk growth after a rejoin with an empty data directory | The rejoined member's state file `store/sm.redb` is below 2x the raw size at rest; raw is the leader's state file after a churn | Measured by the membership scenario | WP3.8, three VMs |
| M12 | Forwarded write latency: 60 s at 100 writes/s on the leader, then the same on a follower | Follower p99 at most the leader's p99 plus 20 ms | Yes | WP3.8, three VMs |

## Run

`cargo` must be on the PATH. The scripts find the repository root from their own location, so
they run from any directory. They run the tests one at a time, never in parallel (they share
the machine and its disk, so parallel runs would disturb each other's numbers). The order is M12, M4, M1, M6, M3: the long M3 runs
last, so a failure in a short measurement shows up early. The first failing test stops the
run; the summary is still written for the results that exist and the script exits with the
failed test's status.

Windows (PowerShell 7):

```powershell
pwsh -File bench\phase1-cluster\run.ps1
pwsh -File bench\phase1-cluster\run.ps1 -Only M12,M4 -OutDir F:\lab\run1
```

Linux (also inside WSL):

```sh
bench/phase1-cluster/run.sh
bench/phase1-cluster/run.sh --only M12,M4 --out /var/tmp/lab/run1
```

| Option (sh / ps1) | Default | Meaning |
|---|---|---|
| `--out` / `-OutDir` | `results/raw/<yyyy-MM-dd-HHmm>` next to the script | where the raw JSON, `environment.txt` and `summary.md` go |
| `--only` / `-Only` | all | comma-separated list among `M1,M3,M4,M6,M12` |
| `--seconds` / `-Seconds` | the full phases | shorten the timed phases to this many seconds (`TENKO_LAB_SECONDS`) |
| `--m3-runs` / `-M3Runs` | 20 | number of M3 failover runs (`TENKO_LAB_M3_RUNS`) |

The quick check (a few minutes, to see that everything works; the numbers are not results):

```powershell
pwsh -File bench\phase1-cluster\run.ps1 -Seconds 10 -M3Runs 2
```

```sh
bench/phase1-cluster/run.sh --seconds 10 --m3-runs 2
```

The scripts set `TENKO_LAB_RESULTS` to the output directory and `TENKO_UI_STUB=1` (unless it is
already set), because the tests do not need the built web UI. They print the machine, the
`rustc` version and the git commit first, and write the same text to `environment.txt`. To run
one test by hand:

```sh
TENKO_LAB_RESULTS=/var/tmp/lab TENKO_UI_STUB=1 \
  cargo test -p tenko --locked --test cluster_measure -- --ignored --exact --nocapture m12_forwarded_write_latency
```

(`--test cluster_membership` and `a_member_rejoins_with_an_empty_data_directory` for M6.) Run the
test `summary_of_the_results` last to write `summary.md`.

## Output

In `results/raw/<date>/` (git-ignored): one JSON file per measurement (`m1-snapshot-install.json`,
`m3-failover.json`, `m4-one-host.json`, `m6-rejoin.json`, `m12-forwarded-writes.json`),
`environment.txt` and `summary.md`, a table of the verdicts and numbers that the summary test
writes from the JSON files.

The written-up results are Markdown files in `results/`, one per run set, named
`<date>-cluster-lab.md`, in the format `bench/README.md` describes: hardware, OS and toolchain,
the exact command line, the numbers, the conclusion. Record the commit, and say so when the
working tree had uncommitted changes.

## How long it takes

About 20 minutes for M3 (20 runs, each a kill, an election, a restart and a rejoin), 2 minutes
each for M12, M4 and M1, 1 minute for M6, plus the build. A full run is about half an hour.

## Things to know

- The tests run in the debug build of the test profile. Release numbers will be better.
- Everything runs on one machine and one disk, and the links are the loopback with a user-space
  relay. The numbers say something about the software path (consensus, forwarding, snapshot
  install, the state store), not about a 1 Gbit network or about three separate machines. The
  disk matters: keep the repository's target directory and the temp directory on a fast disk.
- M1 and M4 use IPAM data in place of the 6 M RRset test index, so their data volumes are much
  smaller than the thresholds assume. Read their results as a check of behavior, not of the
  5 minute catch-up threshold.
- The weekly CI job `cluster-lab` runs these tests without `TENKO_LAB_RESULTS`, so they skip
  there and print why.
- The final runs happen in WP3.8 on three VMs. Those results, not these, are the ones the
  thresholds apply to.
