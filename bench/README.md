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

## Results

Results are written up as Markdown in `bench/<name>/results/*.md`. Each file
records:

- hardware, OS and toolchain version
- the exact command line
- the numbers
- the conclusion

Raw output goes in `bench/<name>/results/raw/`, which is git-ignored.

## Rule

Measure before optimizing. A performance claim in a pull request links to a
result file here.
