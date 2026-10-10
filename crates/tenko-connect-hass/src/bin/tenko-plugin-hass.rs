//! The Home Assistant plugin as a standalone executable (the `tenko` binary bundles it as
//! `tenko plugin run hass`).

fn main() -> std::process::ExitCode {
    tenko_connect_hass::main()
}
