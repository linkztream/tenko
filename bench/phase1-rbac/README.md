# Phase 1 access-control benchmarks (M13)

Measurement M13 of the slice 3 plan (`docs/plans/slice-3-plan.md`, section 5): the cost of scope
filtering (IAM-01, WP3.2).

| Threshold | Limit |
|---|---|
| A list of 10,000 hosts for a scoped principal | at most 1.5 times the unscoped time |
| Server-sent events: 100 events/s to 1,000 scoped subscribers (proposed) | below one core |

The harness is a standalone crate (its own empty `[workspace]`, path dependencies on the
workspace crates, its own `target/`). It builds the stack in process, the way `tenko serve`
wires it: store (`MemStore` or `RaftStore`), vault, `AuthService`, the `ScopeIndex` anchors
index registered on the store and given to auth, `IpamService` over a job engine, the HTTP
router `tenko_api::api(state)` with the scoped event filter. It uses public APIs only.

All data is synthetic and uses documentation values: IPv6 under `2001:db8:100::/48` and names
under `example.test`. Nothing leaves the process (no network at all; requests go through
`tower::ServiceExt::oneshot`).

## The data

One VRF, one /48 supernet, 100 /56 prefixes (role supernet) and 5 /64 leaf prefixes under each
(500 leaves), 20 hosts per leaf: 10,000 hosts, each with one interface and one address.

Setup uses the Home profile (PIN passwords, no second factor for administration): the Standard
profile asks administrators for a step-up that a benchmark cannot give. Scoped principals are
users without a global role that hold only scoped grants (`subtree: true`), and sign in with a
session cookie.

## `list`

Lists all hosts (and, as a second series, all addresses) page by page (`limit=1000`, following
`next_cursor`) through the router: `GET /api/v1/hosts?limit=1000&cursor=...`, as an
administrator and as three scoped principals, each with 50 grants:

| Principal | Grants | Share of the hosts it can read |
|---|---|---|
| few | operator on 50 leaf /64 prefixes | about 10% |
| half | viewer on 50 of the 100 /56 prefixes | about 50% |
| all | operator on the supernet plus 49 leaves | 100% (the worst case for the filter: the same rows as the administrator, plus the work of deciding) |

Each case does 3 untimed warm-up listings and 30 timed ones. Administrator and scoped listings
are interleaved in every iteration (the order alternates), so both see the same machine load.
The report gives median and p95 per full listing and the ratio scoped over unscoped. After the
timing, a profile pass times the scope machinery outside the router for one pass over the 10,000
hosts: `Authorizer::scope` (once per request), `ScopeIndex::anchors` (per object) and
`ScopeFilter::admits` (per object).

## `sse`

Two parts, on `MemStore`:

1. The filter alone: `EventFilter::select(principal, Topic::Ipam, &[host])` for 1,000
   subscribers per event, 100 events per second. 50 scoped principals (50 grants each, on a
   random half of the /56 prefixes) are shared round robin by the 1,000 subscribers; an
   administrator run is the control.
2. Real streams: 1,000 `GET /api/v1/events?topics=ipam` streams through the router, each
   drained by a task, 50 sessions shared round robin; the event hub is fed from the store
   journal (`Store::watch`, the loop of `EventHub::spawn_tasks`, which is crate-private) and
   100 `UpdateHost` commands per second change random hosts. Runs: no subscribers (publisher
   and feeder only), 1,000 administrator streams (fan-out without filtering), 1,000 scoped
   streams. Process CPU time over the publishing window (via `sysinfo`), divided by wall time,
   gives cores used. The drain tasks (counting frames) run in the same process and are part of
   the CPU figure.

Delivered counts events received by the streams; dropped counts `reset` events and streams that
ended (a subscriber that fell behind).

## Run

```sh
export CARGO_INCREMENTAL=0
cd bench/phase1-rbac
cargo build --release --target x86_64-unknown-linux-musl
mkdir -p results/raw
BIN=./target/x86_64-unknown-linux-musl/release/phase1-rbac
$BIN list --store mem  --out results/raw/m13-list-mem.json
$BIN list --store raft --data-dir /path/to/scratch --out results/raw/m13-list-raft.json
$BIN sse  --store mem  --out results/raw/m13-sse-mem.json
```

On Linux the harness is built for the musl target, as the shipped `tenko` binary is (the
release workflow, S3-Q10), so the measured code runs on the same C library and allocator
(`rustup target add x86_64-unknown-linux-musl`, `musl-gcc` from `musl-tools`). On Windows
build without `--target` and run `target/release/phase1-rbac`.

Options: `--iterations` (30), `--warmup` (3), `--limit` (1000), `--mids` (100),
`--leaves-per-mid` (5), `--hosts-per-leaf` (20), `--grants` (50), `--seconds` (30),
`--rate` (100), `--subscribers` (1000), `--principals` (50). `RaftStore` runs in a scratch
directory under `--data-dir` that is removed at exit. Check `cat /proc/loadavg` before a run
and do not run other builds next to it.

Quality gates: `cargo clippy --all-targets -- -D warnings` and
`cargo fmt --manifest-path bench/phase1-rbac/Cargo.toml`.

Results are written up in `results/`; raw output goes to `results/raw/` (git-ignored).
