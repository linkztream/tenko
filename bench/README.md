# Benchmarks and spikes

## Spikes

A spike is a time-boxed experiment that answers an architectural question,
for example the choice of Raft library or embedded key-value store.

- Each spike is a standalone crate under `bench/spike-<name>/`.
- Spikes are excluded from the main Cargo workspace, so they can pull in
  candidate dependencies freely.
- The conclusion of a spike is recorded as an ADR in `docs/adr/`.

## Benchmarks

Benchmarks live under `bench/<name>/`.

- `bench/phase2-dns/`: the Phase 2 DNS harness (load generator for any DNS server, zone and query file generator, report renderer, M16 to M24 procedure scripts) and the single-node baseline.

## Results

Results are written up as Markdown in `bench/<name>/results/*.md`. Each file
records:

- hardware, OS and toolchain version
- the exact command line
- the numbers
- the conclusion

A results file carries one line `Verdict: PASS` or `Verdict: FAIL`, optionally followed
by ` (<short qualifier>)`, right below its title, matching the conclusion the file states.
The acceptance test `crates/tenko/tests/acceptance_observability.rs` reads the newest file
of each measurement (M8, M9) and platform (Windows, Linux) by the date prefix of its name
and the platform named in the parenthesis at the end of its title, and asserts the verdict.

Raw output goes in `bench/<name>/results/raw/`, which is git-ignored.

## Rule

Measure before optimizing. A performance claim in a pull request links to a
result file here.

Linux measurements run on the static musl release binary (`cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl`), the binary that ships; a host-target release build on Linux is a glibc binary that is neither shipped nor measured. Linux results dated before 2026-10-17 (M8, M13, M14, M15 and the M9 runs that say so) were glibc host builds and are read as such.
