# Phase 2 status

- Date: 2026-10-17
- Scope: the execution state of [phase-2-plan.md](phase-2-plan.md). Whoever continues reads this file first, then the plan, then the ADRs. The Phase 1 state stays in [phase-1-status.md](phase-1-status.md).

## Slice 4 work packages

| WP | State | Where | Notes |
|---|---|---|---|
| WP4.0 Contracts and shared files | Building | a local Opus builder in its own worktree, branch `claude/youthful-rosalind-f577f1` from `eed7057` | Brief: the model `tenko_core::dns`, the `dns` namespace and tables, the node-sync declaration for the role, the `tenko-dns` traits with the codec from Spike B and reference implementations, the API stubs with scopes, topic, error codes and audit actions, the UI route stub, the trace script's phase parameter, the format-bump decision, ADR 0017 |
| WP4.6a Bench harness and baseline | Merged, pushed | `13763cc` on `origin/main` | `bench/phase2-dns` (standalone): the load generator, result record, report renderer and process stats from Spike B with a CLI for UDP and TCP; `zonegen` for 100,000, 1,000,000 and 6,000,000 records with reverse zones and a query file; the M16, M17 and M24 scripts, refusing a dynamic server binary on Linux; the Spike B baseline on loopback ([results](../../bench/phase2-dns/results/2026-10-17-baseline-spike-b.md): one worker 145,062 QPS on Windows and 165,188 in WSL2 on musl, eight workers 703,781 and 1,721,045; p99 2.4 ms and 2.2 ms at one worker). Built by a local Sonnet builder; 39 tests; dnsperf and flamethrower not installed, so their scripts are unrun. The fuzz half of WP4.6 waits for the codec of WP4.0 |

## Conventions

- Every figure is a single-node figure (plan section 2.10); Linux figures come from the static musl binary.
- Builders run as in Slice 3: local Opus or Sonnet agents in their own worktrees with their own `CARGO_TARGET_DIR` under `F:\`, briefed by the lead; the lead gates in `F:\tenko-verify` and squashes onto `main`. A package that changes nothing in the workspace (`bench/` only) is checked inside its own package and squashed without the workspace gate.
- After a squash the builder's target directory under `F:\` is deleted; the gate's test target directory is deleted when it passes a few hundred gigabytes (the Windows debug information of the test binaries accumulates, one pair of files per build).

## Push state

`main` moved from `701a5ef` (the Phase 1 state) to `f2e4766` (the Phase 2 plan draft), `f602a02` (the musl squash), `99fd225` (the glibc clean-up), `edfa4d5` (single node first), `eed7057` (the decisions P2-Q1 to P2-Q16 and deviation 74) and `13763cc` (WP4.6a) on 2026-10-17.
