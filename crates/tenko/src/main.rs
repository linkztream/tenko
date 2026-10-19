//! Entry point of the `tenko` binary. The exit statuses are documented in [`tenko::exit`].

#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;

/// jemalloc instead of musl's own malloc in the static Linux binary that ships. musl's
/// allocator serialises the many small allocations of the replicated store's write path
/// across threads, which made zone imports and DNSSEC signing four to seven times slower than
/// on Windows (M18, M20 in `bench/phase2-dns/results`). Its options, fixed at build time in
/// `.cargo/config.toml`, return freed memory from a background thread, so the idle memory
/// stays under OPS-15. Windows and glibc builds keep the system allocator; glibc's is not a
/// supported Linux binary (`deploy/README.md`).
#[cfg(all(target_os = "linux", target_env = "musl"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() -> ExitCode {
    let cli = tenko::Cli::parse();
    // Unlocked handles: the server writes to both from other threads while this one waits.
    let status = tenko::execute(&cli, &mut std::io::stdout(), &mut std::io::stderr());
    ExitCode::from(status)
}
