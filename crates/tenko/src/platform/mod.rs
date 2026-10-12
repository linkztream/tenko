//! Integration with the service managers: `sd_notify` readiness for systemd units
//! (`Type=notify`, OPS-13) and the Windows Service Control Manager (`tenko service`,
//! OPS-10).

#[cfg(target_os = "linux")]
mod systemd;
#[cfg(windows)]
mod windows;

use std::{io::Write, path::PathBuf};

use clap::{Args, Subcommand};

use crate::serve::Hooks;

/// The default name of the Windows service.
pub const DEFAULT_SERVICE_NAME: &str = "tenko";

/// Readiness and stop notifications for the service manager this process runs under:
/// `READY=1` and `STOPPING=1` for a systemd unit with `Type=notify`; nothing elsewhere.
pub fn notify_hooks() -> Hooks {
    #[cfg(target_os = "linux")]
    {
        systemd::hooks()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Hooks::default()
    }
}

/// Keeps the service manager from timing out a slow start step while it lives: a systemd
/// unit gets `EXTEND_TIMEOUT_USEC` now and every 30 s (OPS-13); elsewhere it does nothing.
#[must_use = "the extension ends when the guard is dropped"]
pub struct StartExtension {
    #[cfg(target_os = "linux")]
    _systemd: Option<systemd::Extension>,
}

impl std::fmt::Debug for StartExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartExtension").finish_non_exhaustive()
    }
}

/// Extends the start timeout of the service manager while the returned guard lives;
/// `reason` becomes the unit's status text.
pub fn extend_start(reason: &str) -> StartExtension {
    #[cfg(target_os = "linux")]
    {
        StartExtension {
            _systemd: systemd::extend(reason),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = reason;
        StartExtension {}
    }
}

/// Subcommands of `tenko service` (Windows only).
#[derive(Debug, Clone, Subcommand)]
pub enum ServiceCommand {
    /// Register `tenko serve` as a Windows service (run as Administrator).
    Install(InstallArgs),
    /// Remove the Windows service (run as Administrator).
    Uninstall(NameArgs),
    /// Start the Windows service.
    Start(NameArgs),
    /// Stop the Windows service and wait until it has stopped.
    Stop(NameArgs),
    /// The entry point the Service Control Manager starts; not for interactive use.
    #[command(hide = true)]
    Run(RunArgs),
}

impl ServiceCommand {
    /// The command as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Install(_) => "service install",
            Self::Uninstall(_) => "service uninstall",
            Self::Start(_) => "service start",
            Self::Stop(_) => "service stop",
            Self::Run(_) => "service run",
        }
    }
}

/// The service name.
#[derive(Debug, Clone, Args)]
pub struct NameArgs {
    /// The service name.
    #[arg(long, value_name = "NAME", default_value = DEFAULT_SERVICE_NAME)]
    pub name: String,
}

/// Arguments of `tenko service install`.
#[derive(Debug, Clone, Args)]
pub struct InstallArgs {
    /// The service name.
    #[arg(long, value_name = "NAME", default_value = DEFAULT_SERVICE_NAME)]
    pub name: String,

    /// The display name in the Services console.
    #[arg(long, value_name = "TEXT", default_value = "Tenko DDI")]
    pub display_name: String,

    /// The configuration file the service reads; it must exist.
    #[arg(long, value_name = "FILE")]
    pub config: PathBuf,

    /// The data directory, when the configuration file does not name one.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,

    /// The account the service runs as; default the virtual account `NT SERVICE\<name>`,
    /// whose profile holds the DPAPI-sealed key-encryption key.
    #[arg(long, value_name = "ACCOUNT")]
    pub account: Option<String>,

    /// Register with manual start instead of automatic start at boot.
    #[arg(long)]
    pub manual: bool,

    /// Register this executable itself instead of `<data_dir>/updates/current/tenko.exe`;
    /// installing new versions from the UI then stays off (OPS-24).
    #[arg(long)]
    pub no_update_layout: bool,
}

/// Arguments of `tenko service run`.
#[derive(Debug, Clone, Args)]
pub struct RunArgs {
    /// The service name the SCM started.
    #[arg(long, value_name = "NAME", default_value = DEFAULT_SERVICE_NAME)]
    pub name: String,

    /// The configuration file.
    #[arg(long, value_name = "FILE")]
    pub config: PathBuf,

    /// The data directory, when the configuration file does not name one.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,
}

/// Runs `tenko service …`.
pub fn command(command: &ServiceCommand, out: &mut impl Write, err: &mut impl Write) -> u8 {
    #[cfg(windows)]
    {
        windows::command(command, out, err)
    }
    #[cfg(not(windows))]
    {
        let _ = out;
        let _ = writeln!(
            err,
            "tenko {}: the Windows service exists on Windows only; on Linux install \
             deploy/systemd/tenko.service",
            command.name()
        );
        crate::exit::USAGE
    }
}
