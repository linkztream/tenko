# DDI

DDI is a DNS + DHCP + IPAM stack. It is built to replace Active Directory-integrated
Windows DNS and DHCP, and to scale from a single home-lab node to a multi-site
enterprise deployment. It ships as one Rust binary that runs any combination of four
roles: `controller` (API, UI, replicated store, job engine), `dns`, `dhcp`, and `probe`
(network discovery). The web UI is a SolidJS application embedded in the binary.

**Status:** pre-alpha, Phase 0 (foundation and spikes). Nothing here is ready for use.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): system architecture
- [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md): requirements
- [`docs/ROADMAP.md`](docs/ROADMAP.md): phases and milestones
- [`docs/adr/`](docs/adr/): architecture decision records

## Repository layout

| Path       | Contents                                                       |
|------------|----------------------------------------------------------------|
| `crates/`  | Rust workspace crates, one per subsystem                       |
| `ui/`      | SolidJS + TypeScript web UI, built with Vite into `ui/dist`    |
| `fuzz/`    | `cargo-fuzz` targets, one per parser of network input          |
| `bench/`   | Spikes and benchmarks, excluded from the workspace             |
| `deploy/`  | Dockerfile, Compose, systemd and Windows service templates     |
| `docs/`    | Architecture, requirements, roadmap, ADRs                      |

## Development

Requirements: the stable Rust toolchain (pinned by `rust-toolchain.toml`) and Node.js 22.

```sh
cargo build --workspace
cargo nextest run --workspace        # or: cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny check
cargo audit
cd ui && npm ci && npm run build
```

Run the server with a subset of roles:

```sh
cargo run -p ddi-server -- --roles controller,dns
```

## Licence

Not decided yet; see [`LICENSE`](LICENSE).
