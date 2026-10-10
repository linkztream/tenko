//! The Proxmox VE plugin as a standalone executable (the `tenko` binary bundles it as
//! `tenko plugin run proxmox`).

fn main() -> std::process::ExitCode {
    tenko_connect_proxmox::main()
}
