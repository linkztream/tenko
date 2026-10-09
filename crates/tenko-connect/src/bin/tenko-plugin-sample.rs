//! The sample plugin as a standalone executable, for the conformance suite and the host
//! tests: `tenko-plugin-sample [--mode <mode>]` (see `tenko_connect::sample::Mode`).

fn main() -> std::process::ExitCode {
    tenko_connect::sample::main()
}
