//! The UniFi plugin as a standalone executable: for `tenko plugin test <path>`, an installed
//! plugin directory, and the conformance test of this crate. The `tenko` binary bundles the
//! same plugin as `tenko plugin run unifi`.

fn main() -> std::process::ExitCode {
    tenko_connect_unifi::main()
}
