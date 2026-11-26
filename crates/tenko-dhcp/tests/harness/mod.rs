//! The harness of an allocation test binary (`harness = false` in Cargo.toml): the test runs
//! on the main thread, the only one of the process, because the counting allocator counts
//! every thread and libtest's main thread allocates right after it has spawned the test
//! thread. It speaks what nextest and `cargo test` send: `--list --format terse` names the
//! test (none with `--ignored`), `--exact <name>` or a name filter and `--nocapture` run it.

/// Flags of libtest that take a value, which is not a name filter.
const VALUED_FLAGS: [&str; 5] = ["--format", "--test-threads", "--color", "--skip", "-Z"];

/// Lists or runs `test`, named `name`, as the command line asks.
pub fn run(name: &str, test: fn()) {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--list") {
        if !args.iter().any(|arg| arg == "--ignored") {
            println!("{name}: test");
        }
        return;
    }
    let exact = args.iter().any(|arg| arg == "--exact");
    let mut after_valued = false;
    let mut filters = Vec::new();
    for arg in &args {
        if after_valued {
            after_valued = false;
        } else if arg.starts_with('-') {
            after_valued = VALUED_FLAGS.contains(&arg.as_str());
        } else {
            filters.push(arg.as_str());
        }
    }
    let selected = filters.is_empty()
        || filters
            .iter()
            .any(|filter| (exact && *filter == name) || (!exact && name.contains(filter)));
    if !selected {
        println!("\nrunning 0 tests\n\ntest result: ok. 0 passed; 1 filtered out\n");
        return;
    }
    println!("\nrunning 1 test");
    test();
    println!("test {name} ... ok\n\ntest result: ok. 1 passed; 0 failed\n");
}
