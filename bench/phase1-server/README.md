# Phase 1 server benchmarks

Measurements of the Phase 1 plan that need the whole `tenko serve` process. They are standalone
scripts: this directory is outside the Cargo workspace and builds nothing.

## M9: idle memory (OPS-15)

OPS-15 asks for an idle resident set below 100 MB for the controller role after an import. The
scripts start a fresh single-node controller, complete first-run setup and sign in with the CLI,
create a small IPAM data set with `tenko prefix create` (the import command is not available
yet, so the data set is CLI-created prefixes), leave the server idle and sample the memory of
the server process. They then stop the server gracefully and check that it exits with status 0.

| Script | Platform | Memory counters |
|---|---|---|
| `m9-idle-rss.ps1` | Windows (PowerShell 7, `pwsh`) | working set and private bytes (`Get-Process`), with the kernel's peak counters |
| `m9-idle-rss.sh` | Linux (bash, GNU coreutils, awk) | `VmRSS`, `VmHWM`, `RssAnon`, `RssFile` from `/proc/<pid>/status` |

Both do the same thing, in the same order:

1. Write a configuration file (loopback listener, `hibp.online = false`, everything else at its
   default: internal CA TLS, the platform key-encryption-key provider) and start
   `tenko serve --roles controller --config <file>` with a fresh data directory.
2. Read the setup token from the server console (it is passed to the CLI through the
   environment, never written to the results), run `tenko setup` and `tenko login` with a
   password generated for the run (a six-digit PIN for the Home profile, passed on standard
   input).
3. Create the data set: one /8 and four /16 supernets and /24 networks under them, 200
   prefixes in total by default.
4. Idle for 600 s, sampling every 30 s (21 samples, the first at the start of the idle phase).
5. Stop the server (Windows: close its standard input, the hidden `--stop-on-eof` flag; Linux:
   `SIGTERM`) and report its exit status.

The peak is the kernel's own high-water mark (`PeakWorkingSet64` and `PeakPagedMemorySize64` on
Windows, `VmHWM` on Linux), read at the end of the data creation and again at the end of the
idle phase.

### Run

Build the release binary first (it embeds the web UI from `ui/dist`). On Linux build the
static musl binary, the one the release workflow ships; a glibc build of the same source keeps
glibc malloc's start-up peak and fails OPS-15 where the shipped binary passes
([results/2026-10-16-m9-linux-memory.md](results/2026-10-16-m9-linux-memory.md)). It needs the
musl target and `musl-gcc` (`rustup target add x86_64-unknown-linux-musl`, the `musl-tools`
package):

```sh
cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl   # Linux
cargo build -p tenko --release --locked                                      # Windows
```

Windows:

```powershell
pwsh -File bench\phase1-server\m9-idle-rss.ps1 -Binary C:\path\to\target\release\tenko.exe
```

Linux (also inside WSL):

```sh
bench/phase1-server/m9-idle-rss.sh --binary /path/to/target/x86_64-unknown-linux-musl/release/tenko
```

The Linux script records whether the binary is statically linked and prints a warning for a
dynamically linked one.

Options (the Windows parameter names are the same with a leading dash and CamelCase):

| Option | Default | Meaning |
|---|---|---|
| `--port` / `-Port` | 18444 (sh), 18443 (ps1) | loopback port of the API; use different ports to run both at once |
| `--prefixes` / `-Prefixes` | 200 | prefixes to create (at least 6) |
| `--idle-secs` / `-IdleSeconds` | 600 | length of the idle phase |
| `--interval-secs` / `-IntervalSeconds` | 30 | seconds between idle samples |
| `--workdir` / `-WorkDir` | new directory under the OS temp directory | data directory, configuration, credentials, raw server log |
| `--outdir` / `-OutDir` | `results/raw` | CSV, summary and redacted server log |
| `--kek` / `-KekProvider` | `platform` | `platform` (DPAPI, `systemd-creds`) or `file` |
| `--keep-data` / `-KeepData` | off | keep the work directory |
| `--roles` (sh only) | `controller` | the roles to run, for example `controller,probe,dns` (every Phase 1 role and the dns role, as in `results/2026-10-19-m9-idle-rss.md`) |
| `--dns-port` (sh only) | 15353 | loopback port of the dns role when `--roles` names it (port 53 needs privileges) |

Keep the work directory on a fast disk. The default (the OS temp directory) is not on the
repository drive: the fsync probe of the server warns on rotating disks (OPS-19), and the
repository drive of the development machine is an SMR disk.

### Output

In `results/raw/` (git-ignored): `m9-<platform>-<timestamp>.csv` with every sample,
`...-summary.txt` with the lines the script printed, and the server's standard output and
error with the setup token replaced by `<redacted>`. The written-up results are the Markdown
files in `results/`.

### Things to know

- The measured process is the server only; the CLI processes are separate and have exited
  before the idle phase starts, so no client connection is open while it is sampled.
- Windows "working set" is the closest counterpart of Linux `VmRSS`; it includes the pages of
  the executable image that are in memory. "Private bytes" is committed private memory.
  Linux `RssAnon` is the closest counterpart of private memory; `RssFile` is mostly the
  executable.
- Run the scripts from a build of the commit you want to describe, and record the commit in the
  result file. When the working tree has uncommitted changes, say so.
- The verdict line reads OPS-15's 100 MB as 100,000,000 bytes (95.37 MiB) and compares the
  largest idle sample with it.
- On a machine where other jobs clean up stray `tenko` processes by name, run the Windows script
  on a copy of the binary with another file name; the script finds the server process by the
  file name it was given.
- Results are written up in `results/`, one Markdown file per run set, as `bench/README.md`
  describes.
