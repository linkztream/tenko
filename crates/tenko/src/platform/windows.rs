//! The Windows service (OPS-10): `tenko service install|uninstall|start|stop` and the
//! service entry point the Service Control Manager (SCM) starts.
//!
//! `service install` checks the account and the configuration first, so a shared account or
//! a bad file is refused before anything is registered. It then registers the service, cuts
//! the privileges of its token down to [`service_policy::REQUIRED_PRIVILEGES`] with
//! `sc.exe privs`, and sets up the data directory: a new or empty directory is restricted
//! to Administrators and SYSTEM with `icacls`, the version layout is written into it while
//! the service account cannot write it yet, and the account is granted last; a directory
//! that holds data is left alone when its owner and its list are already the ones this
//! command sets, and refused otherwise (ADR 0023, item 11, [`service_policy`]). Every
//! Windows call goes through the `windows-service` crate or an external tool, which keeps
//! this crate free of `unsafe` code.
//!
//! The SCM starts the image path `tenko service run --name <name> --config <file>
//! [--data-dir <dir>] [--payload <file>]`. At its start the service looks at the installer's
//! file named by `--payload` and, when it is a newer version, adopts it as its own account
//! ([`crate::upgrade::adopt_payload`]): the store check, the copy into the layout and the
//! switch of `current`, followed by exit status 12 so that the SCM starts the new version.
//! `run_dispatcher` hands the process to the service dispatcher,
//! which calls `ffi_service_main` on a thread of its own. That function is written by hand
//! because the `define_windows_service!` macro expands to an `unsafe` block. It reads the
//! arguments that `run_dispatcher` stored (the arguments the SCM passes carry nothing this
//! service needs), registers the control handler and moves the service through
//! `START_PENDING`, `RUNNING`, `STOP_PENDING` and `STOPPED` around [`serve::run_on`].
//!
//! There is no console under the SCM, so the service logs to a file (rotated by size) and to
//! the Application Event Log under the service name (`[log] event_log`, OPS-10). `service
//! install` registers that event source with `reg.exe` and `service uninstall` removes it.
//! A failure before the log is open (a configuration that stopped being valid, an
//! unwritable log directory) goes to the Event Log as an error and shows up as the
//! service-specific exit status of the stopped service.

use std::{
    any::Any,
    ffi::OsString,
    io::{self, Write},
    panic::{self, AssertUnwindSafe},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        OnceLock,
        atomic::{AtomicU8, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use tokio::sync::oneshot;
use windows_service::{
    Error as ScmError,
    service::{
        Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceControl,
        ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceFailureActions,
        ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

use super::{
    InstallArgs, NameArgs, RunArgs, ServiceCommand,
    service_policy::{self, DataDirFound, DataDirPlan},
};
use crate::{
    config::{self, Config, ConfigError, Resolved, Sources},
    exec, exit,
    logging::{self, Sink},
    serve::{self, Hooks, Ready, Shutdown},
    upgrade::{self, Adoption, layout::Layout},
};

/// The description shown in the Services console.
const DESCRIPTION: &str = "Tenko DDI: DNS, DHCP and IPAM";

/// How long the SCM waits before it restarts a failed service.
const RESTART_DELAY: Duration = Duration::from_secs(10);

/// How long the service must run without a failure before the failure count starts over.
const FAILURE_RESET: Duration = Duration::from_secs(24 * 60 * 60);

/// The time the SCM allows for the start before it assumes the service hangs.
const START_WAIT_HINT: Duration = Duration::from_secs(120);

/// The time the SCM allows for the stop before it assumes the service hangs.
const STOP_WAIT_HINT: Duration = Duration::from_secs(60);

/// How long `service start` waits for the service to run.
const START_TIMEOUT: Duration = Duration::from_secs(120);

/// How long `service stop` and `service uninstall` wait for the service to stop.
const STOP_TIMEOUT: Duration = Duration::from_secs(60);

/// The interval between two queries of the service state.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// How long `service start` waits, after the service stopped with exit status 12, for the
/// SCM to start it again (the failure actions wait [`RESTART_DELAY`] first).
const RESTART_WAIT: Duration = Duration::from_secs(40);

/// Windows error: access is denied (the prompt is not elevated).
const ERROR_ACCESS_DENIED: i32 = 5;

/// Windows error: the service does not exist.
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

/// Windows error: the service is already running.
const ERROR_SERVICE_ALREADY_RUNNING: i32 = 1056;

/// Windows error: the service cannot accept control messages at this time.
const ERROR_SERVICE_CANNOT_ACCEPT_CTRL: i32 = 1061;

/// Windows error: the service has not been started.
const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;

/// Windows error: the process was not started by the SCM (it runs in a console).
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;

/// Windows error: the service is marked for deletion.
const ERROR_SERVICE_MARKED_FOR_DELETE: i32 = 1072;

/// Windows error: a service with this name exists.
const ERROR_SERVICE_EXISTS: i32 = 1073;

/// The arguments of `tenko service run`, kept for `ffi_service_main`, which the SCM calls
/// without them.
static RUN_ARGS: OnceLock<RunArgs> = OnceLock::new();

/// The exit status of the service run, for the process exit code.
static EXIT_STATUS: AtomicU8 = AtomicU8::new(exit::OK);

/// A failed command: the exit status and the message for standard error.
#[derive(Debug)]
struct Failure {
    /// The exit status of the process.
    status: u8,
    /// What went wrong, in English.
    message: String,
}

impl Failure {
    /// A failure with an exit status.
    fn new(status: u8, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    /// A general failure ([`exit::FAILURE`]).
    fn general(message: impl Into<String>) -> Self {
        Self::new(exit::FAILURE, message)
    }

    /// A failed SCM call; `what` names the operation.
    fn scm(what: &str, error: &ScmError) -> Self {
        Self::general(scm_message(what, error))
    }
}

/// The result of a step of a command.
type Outcome = Result<(), Failure>;

/// Runs `tenko service …` on Windows.
pub(super) fn command(command: &ServiceCommand, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let result = match command {
        ServiceCommand::Install(args) => install_service(args, out, err),
        ServiceCommand::Uninstall(args) => uninstall_service(args, out),
        ServiceCommand::Start(args) => start_service(args, out),
        ServiceCommand::Stop(args) => stop_service(args, out),
        ServiceCommand::Run(args) => return run_dispatcher(args, err),
    };
    match result {
        Ok(()) => exit::OK,
        Err(failure) => {
            let _ = writeln!(err, "tenko {}: {}", command.name(), failure.message);
            failure.status
        }
    }
}

// ---------------------------------------------------------------------------------------
// Messages for failed Windows calls
// ---------------------------------------------------------------------------------------

/// The Windows error code behind an SCM error, if it has one.
fn os_code(error: &ScmError) -> Option<i32> {
    match error {
        ScmError::Winapi(source) => source.raw_os_error(),
        _ => None,
    }
}

/// The text of an SCM error, with the Windows message when there is one.
fn error_text(error: &ScmError) -> String {
    match error {
        ScmError::Winapi(source) => source.to_string(),
        other => other.to_string(),
    }
}

/// An error message for a failed SCM call; `what` names the operation.
fn scm_message(what: &str, error: &ScmError) -> String {
    let reason = match os_code(error) {
        Some(ERROR_ACCESS_DENIED) => {
            "access denied; run this command from an elevated prompt (Run as administrator)"
                .to_owned()
        }
        Some(ERROR_SERVICE_DOES_NOT_EXIST) => "the service is not installed".to_owned(),
        Some(ERROR_SERVICE_EXISTS) => "a service with this name exists; remove it with \
             `tenko service uninstall` or choose another --name"
            .to_owned(),
        Some(ERROR_SERVICE_MARKED_FOR_DELETE) => {
            "the service is marked for deletion; close the Services console and retry".to_owned()
        }
        Some(ERROR_SERVICE_CANNOT_ACCEPT_CTRL) => "the service is starting or stopping and \
             cannot accept the request now; retry in a moment"
            .to_owned(),
        _ => error_text(error),
    };
    format!("{what}: {reason}")
}

/// The name of a service state, for messages.
const fn state_name(state: ServiceState) -> &'static str {
    match state {
        ServiceState::Stopped => "stopped",
        ServiceState::StartPending => "start pending",
        ServiceState::StopPending => "stop pending",
        ServiceState::Running => "running",
        ServiceState::ContinuePending => "continue pending",
        ServiceState::PausePending => "pause pending",
        ServiceState::Paused => "paused",
    }
}

/// What a tenko exit status means, for a service that stopped with it.
fn status_meaning(status: u32) -> &'static str {
    match u8::try_from(status) {
        Ok(exit::FAILURE) => "an unexpected failure; the service log has the details",
        Ok(exit::USAGE) => "none of the configured roles can run in this version",
        Ok(exit::CONFIG) => {
            "the configuration is invalid; run `tenko config check --config <file>`"
        }
        Ok(exit::START) => "a start step failed; the service log names the step",
        Ok(exit::RESTART) => {
            "it stopped to be restarted (an update, a module change or a switch back); the \
             failure actions start it again"
        }
        _ => "see the service log",
    }
}

/// A description of the exit code a stopped service reports.
fn describe_exit(code: ServiceExitCode) -> String {
    match code {
        ServiceExitCode::Win32(0) => "it reported no error".to_owned(),
        ServiceExitCode::Win32(code) => {
            let error = io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX));
            format!("Windows error {code}: {error}")
        }
        ServiceExitCode::ServiceSpecific(status) => {
            format!("tenko exit status {status}: {}", status_meaning(status))
        }
    }
}

// ---------------------------------------------------------------------------------------
// Connecting, opening and waiting
// ---------------------------------------------------------------------------------------

/// Connects to the SCM of this computer.
fn connect(access: ServiceManagerAccess) -> Result<ServiceManager, Failure> {
    ServiceManager::local_computer(None::<&str>, access)
        .map_err(|error| Failure::scm("cannot connect to the Service Control Manager", &error))
}

/// Opens an installed service.
fn open(manager: &ServiceManager, name: &str, access: ServiceAccess) -> Result<Service, Failure> {
    manager
        .open_service(name, access)
        .map_err(|error| Failure::scm(&format!("cannot open service `{name}`"), &error))
}

/// How a wait for a service state ended.
#[derive(Debug)]
enum Wait {
    /// The state was reached.
    Done(ServiceStatus),
    /// The time ran out first; the last status seen.
    TimedOut(ServiceStatus),
}

/// Queries the status until `done` accepts it or `timeout` has passed.
fn wait_for(
    mut query: impl FnMut() -> Result<ServiceStatus, ScmError>,
    done: impl Fn(&ServiceStatus) -> bool,
    timeout: Duration,
    interval: Duration,
) -> Result<Wait, ScmError> {
    let started = Instant::now();
    loop {
        let status = query()?;
        if done(&status) {
            return Ok(Wait::Done(status));
        }
        if started.elapsed() >= timeout {
            return Ok(Wait::TimedOut(status));
        }
        thread::sleep(interval);
    }
}

/// Stops the service if it runs and waits until it has stopped. Returns whether it was
/// running.
fn stop_and_wait(service: &Service, name: &str) -> Result<bool, Failure> {
    let query_failed = |error: &ScmError| Failure::scm(&format!("cannot query `{name}`"), error);
    let current = service
        .query_status()
        .map_err(|error| query_failed(&error))?;
    match current.current_state {
        ServiceState::Stopped => return Ok(false),
        ServiceState::StopPending => {}
        _ => match service.stop() {
            Ok(_) => {}
            Err(error) if os_code(&error) == Some(ERROR_SERVICE_NOT_ACTIVE) => return Ok(false),
            Err(error) => {
                return Err(Failure::scm(
                    &format!("cannot stop service `{name}`"),
                    &error,
                ));
            }
        },
    }
    let stopped = |status: &ServiceStatus| status.current_state == ServiceState::Stopped;
    let waited = wait_for(
        || service.query_status(),
        stopped,
        STOP_TIMEOUT,
        POLL_INTERVAL,
    )
    .map_err(|error| query_failed(&error))?;
    match waited {
        Wait::Done(_) => Ok(true),
        Wait::TimedOut(status) => Err(Failure::general(format!(
            "service `{name}` did not stop within {} s; it is {}",
            STOP_TIMEOUT.as_secs(),
            state_name(status.current_state)
        ))),
    }
}

// ---------------------------------------------------------------------------------------
// service install
// ---------------------------------------------------------------------------------------

/// The account the service runs as: `--account`, else the virtual account of the service.
fn account(args: &InstallArgs) -> String {
    args.account
        .clone()
        .unwrap_or_else(|| default_account(&args.name))
}

/// The virtual service account `NT SERVICE\<name>`.
fn default_account(name: &str) -> String {
    format!(r"NT SERVICE\{name}")
}

/// The arguments the SCM appends to the executable path: `service run` with the paths the
/// service reads its configuration from and, with the layout, the installer's file it
/// adopts newer versions of.
fn launch_arguments(
    name: &str,
    config: &Path,
    data_dir: Option<&Path>,
    payload: Option<&Path>,
) -> Vec<OsString> {
    let mut arguments: Vec<OsString> = vec![
        "service".into(),
        "run".into(),
        "--name".into(),
        name.into(),
        "--config".into(),
        config.into(),
    ];
    if let Some(dir) = data_dir {
        arguments.push("--data-dir".into());
        arguments.push(dir.into());
    }
    if let Some(payload) = payload {
        arguments.push("--payload".into());
        arguments.push(payload.into());
    }
    arguments
}

/// What the SCM registers for the service.
fn service_info(
    args: &InstallArgs,
    executable: PathBuf,
    launch_arguments: Vec<OsString>,
    account: &str,
) -> ServiceInfo {
    ServiceInfo {
        name: OsString::from(&args.name),
        display_name: OsString::from(&args.display_name),
        service_type: ServiceType::OWN_PROCESS,
        start_type: if args.manual {
            ServiceStartType::OnDemand
        } else {
            ServiceStartType::AutoStart
        },
        error_control: ServiceErrorControl::Normal,
        executable_path: executable,
        launch_arguments,
        dependencies: Vec::new(),
        account_name: Some(OsString::from(account)),
        account_password: None,
    }
}

/// What the SCM does when the service fails: restart it after 10 s on the first three
/// failures and leave it stopped on the fourth; the count starts over after a day without a
/// failure. A restart the server asks for (exit status 12: an installed update, a module
/// change) counts as a failure too, and an update that is switched back takes up to three
/// (the switch, a failed start of the new version, the switch back), so three restarts keep
/// the previous version running after a failed update.
fn failure_actions() -> ServiceFailureActions {
    let restart = ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: RESTART_DELAY,
    };
    let give_up = ServiceAction {
        action_type: ServiceActionType::None,
        delay: Duration::ZERO,
    };
    ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(FAILURE_RESET),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart.clone(), restart, give_up]),
    }
}

/// The absolute form of a path, which the service needs: it starts in the Windows system
/// directory.
fn absolute(path: &Path) -> Result<PathBuf, Failure> {
    std::path::absolute(path).map_err(|error| {
        Failure::general(format!("cannot make {} absolute: {error}", path.display()))
    })
}

/// Loads and validates the configuration the way `tenko serve` does.
fn load_config(config: &Path, data_dir: Option<&Path>) -> Result<Resolved, ConfigError> {
    let sources = Sources {
        file: Some(config.to_path_buf()),
        data_dir: data_dir.map(Path::to_path_buf),
        roles: None,
    };
    let mut resolved = config::load(&sources, std::env::vars())?.config.resolve()?;
    resolved.config_file = Some(config.to_path_buf());
    Ok(resolved)
}

/// Refuses relative paths that the service would resolve against its own working directory.
fn require_absolute_paths(config: &Config) -> Outcome {
    let paths = [
        ("data_dir", config.data_dir.as_deref()),
        ("log.file", config.log.file.as_deref()),
    ];
    for (key, path) in paths {
        if let Some(path) = path
            && !path.is_absolute()
        {
            return Err(Failure::new(
                exit::CONFIG,
                format!(
                    "{key} must be an absolute path: a service does not start in your \
                     working directory ({})",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

/// `tenko service install`.
fn install_service(args: &InstallArgs, out: &mut impl Write, err: &mut impl Write) -> Outcome {
    let name = args.name.as_str();
    let account = account(args);
    service_policy::check_account(&account)
        .map_err(|message| Failure::new(exit::USAGE, message))?;
    let config = absolute(&args.config)?;
    let data_dir = args.data_dir.as_deref().map(absolute).transpose()?;
    let resolved = load_config(&config, data_dir.as_deref())
        .map_err(|error| Failure::new(exit::CONFIG, error.to_string()))?;
    require_absolute_paths(&resolved.config)?;
    let own = std::env::current_exe().map_err(|error| {
        Failure::general(format!("cannot find the path of this executable: {error}"))
    })?;
    // The `current` link layout (OPS-24): the service runs the version that `current` points
    // at, so that an update installed from the UI is a switch of the link and a restart, and
    // adopts a newer version of this file, the installer's, at its start (ADR 0023, item 11).
    let with_layout = !args.no_update_layout;
    let layout = Layout::new(&resolved.data_dir);
    let executable = if with_layout {
        layout.current_binary()
    } else {
        own.clone()
    };
    let payload = with_layout.then_some(own.as_path());
    // What the data directory holds decides before anything is registered.
    let found = inspect_data_dir(&resolved.data_dir, &account, &layout, err)?;
    let plan = service_policy::data_dir_plan(&resolved.data_dir, &found, with_layout);
    if let DataDirPlan::Refuse(message) = &plan {
        return Err(Failure::general(message.clone()));
    }
    let info = service_info(
        args,
        executable.clone(),
        launch_arguments(name, &config, data_dir.as_deref(), payload),
        &account,
    );
    register(&info, out, err)?;
    let registered = |failure: Failure| Failure {
        message: format!(
            "{}; the service is registered, remove it with `tenko service uninstall --name \
             {name}` or fix it by hand",
            failure.message
        ),
        ..failure
    };
    set_required_privileges(name, out).map_err(registered)?;
    register_event_source(name, out, err);
    let _ = writeln!(out, "  account:       {account}");
    let _ = writeln!(out, "  executable:    {}", executable.display());
    let _ = writeln!(out, "  configuration: {}", config.display());
    if let Some(payload) = payload {
        let _ = writeln!(out, "  installer file: {}", payload.display());
        if let Some(note) = service_policy::payload_location_note(payload, &program_files()) {
            let _ = writeln!(err, "tenko service install: warning: {note}");
        }
    }
    match plan {
        DataDirPlan::Create | DataDirPlan::Restrict => {
            if plan == DataDirPlan::Create {
                std::fs::create_dir_all(&resolved.data_dir)
                    .map_err(|error| {
                        Failure::general(format!(
                            "cannot create the data directory {}: {error}",
                            resolved.data_dir.display()
                        ))
                    })
                    .map_err(registered)?;
            }
            restrict_data_dir(&resolved.data_dir, out).map_err(registered)?;
            if with_layout {
                let note =
                    upgrade::ensure_layout(&resolved.data_dir, &own, &upgrade::running_version())
                        .map_err(|error| {
                            Failure::general(format!(
                                "cannot set up the version layout in {}: {error}; the service \
                             cannot start",
                                layout.root().display()
                            ))
                        })
                        .map_err(registered)?;
                let _ = writeln!(out, "  versions:      {note}");
            }
            grant_data_dir(&resolved.data_dir, &account, out).map_err(registered)?;
        }
        DataDirPlan::Keep => {
            let _ = writeln!(
                out,
                "data directory {}: holds data under the access list of {account}, \
                 Administrators and SYSTEM; left as it is",
                resolved.data_dir.display()
            );
        }
        DataDirPlan::Refuse(message) => return Err(registered(Failure::general(message))),
    }
    let _ = writeln!(out, "start it with: tenko service start --name {name}");
    Ok(())
}

/// Looks at the data directory path without changing or following anything: missing, a
/// link or a junction, an empty directory, or a directory with entries, whose owner and
/// access list are then compared with the ones this command sets for `account`. A
/// comparison that cannot be made is reported on `err` and leaves `matching` unset.
fn inspect_data_dir(
    dir: &Path,
    account: &str,
    layout: &Layout,
    err: &mut impl Write,
) -> Result<DataDirFound, Failure> {
    let metadata = match std::fs::symlink_metadata(dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(DataDirFound::Missing),
        Err(error) => {
            return Err(Failure::general(format!(
                "cannot read the data directory {}: {error}",
                dir.display()
            )));
        }
    };
    if metadata.file_type().is_symlink() {
        return Ok(DataDirFound::Link);
    }
    if !metadata.is_dir() {
        return Err(Failure::general(format!(
            "the data directory {} is not a directory",
            dir.display()
        )));
    }
    let mut entries = std::fs::read_dir(dir).map_err(|error| {
        Failure::general(format!(
            "cannot list the data directory {}: {error}",
            dir.display()
        ))
    })?;
    if entries.next().is_none() {
        return Ok(DataDirFound::Empty);
    }
    // `current` is read as a link, never followed: the version it names must have its
    // binary under its own directory.
    let layout_present = layout
        .current()
        .is_some_and(|version| layout.binary(&version).is_file());
    let matching = match account_sid(account).and_then(|sid| {
        read_descriptor(dir)
            .map(|descriptor| service_policy::matches_secured_list(&descriptor, &sid))
    }) {
        Ok(matching) => Some(matching),
        Err(reason) => {
            let _ = writeln!(
                err,
                "tenko service install: warning: cannot compare the access list of {}: {reason}",
                dir.display()
            );
            None
        }
    };
    Ok(DataDirFound::InUse {
        matching,
        layout_present,
    })
}

/// Runs a system tool as [`exec::system_command`] starts one (its full path in the system
/// directory, an environment of fixed values) and returns what it printed; a failure is
/// the tool's output.
fn run_tool(tool: &str, arguments: &[OsString]) -> Result<String, String> {
    let mut command = exec::system_command(tool)?;
    command.args(arguments);
    run_command(command, tool)
}

/// Runs a command of [`exec::system_command`] and returns what it printed; a failure is
/// the tool's output.
fn run_command(mut command: Command, tool: &str) -> Result<String, String> {
    let output = command
        .output()
        .map_err(|error| format!("cannot run {tool}: {error}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(format!("{tool}: {}", tool_output(&output)))
    }
}

/// The SID of a virtual service account, from `sc.exe showsid`.
fn account_sid(account: &str) -> Result<String, String> {
    let service = service_policy::virtual_account_service(account)
        .ok_or_else(|| format!("{account} is not a virtual service account"))?;
    let output = run_tool("sc.exe", &service_policy::sc_showsid_arguments(service))?;
    service_policy::parse_showsid(&output)
        .ok_or_else(|| format!("sc.exe showsid printed no service SID for {service}"))
}

/// The owner and the access list of `dir`, read by Windows PowerShell through .NET (see
/// [`service_policy::powershell_sddl_arguments`]).
fn read_descriptor(dir: &Path) -> Result<service_policy::Descriptor, String> {
    let mut command = exec::system_command(POWERSHELL)?;
    command
        .args(service_policy::powershell_acl_arguments())
        .env(service_policy::ACL_PATH_VARIABLE, dir);
    let output = run_command(command, "powershell.exe")?;
    let sddl = output.lines().next().unwrap_or_default();
    service_policy::parse_sddl(sddl).ok_or_else(|| {
        format!(
            "powershell.exe printed `{}`, which is not an SDDL string",
            sddl.trim()
        )
    })
}

/// Windows PowerShell, below the system directory.
const POWERSHELL: &str = r"WindowsPowerShell\v1.0\powershell.exe";

/// The Program Files directories of this machine, where only administrators write.
fn program_files() -> Vec<PathBuf> {
    ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .collect()
}

/// Cuts the privileges of the service token down to [`service_policy::REQUIRED_PRIVILEGES`].
fn set_required_privileges(name: &str, out: &mut impl Write) -> Outcome {
    run_tool("sc.exe", &service_policy::sc_privs_arguments(name)).map_err(|reason| {
        Failure::general(format!(
            "cannot set the required privileges of service `{name}`: {reason}"
        ))
    })?;
    let _ = writeln!(
        out,
        "  privileges:    {}",
        service_policy::REQUIRED_PRIVILEGES.join(", ")
    );
    Ok(())
}

/// Registers the service and sets its description and failure actions.
fn register(info: &ServiceInfo, out: &mut impl Write, err: &mut impl Write) -> Outcome {
    let name = info.name.to_string_lossy();
    let manager = connect(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    // Failure actions with a restart need the start right on the handle besides the
    // right to change the configuration; without it `ChangeServiceConfig2` refuses them.
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::CHANGE_CONFIG | ServiceAccess::START;
    let service = manager
        .create_service(info, access)
        .map_err(|error| Failure::scm(&format!("cannot register service `{name}`"), &error))?;
    let start = match info.start_type {
        ServiceStartType::AutoStart => "automatic",
        _ => "manual",
    };
    let _ = writeln!(out, "registered service `{name}` (start type: {start})");
    configure(&service, out, err);
    Ok(())
}

/// Sets the description and the failure actions. A failure here leaves a working service,
/// so it is a warning.
fn configure(service: &Service, out: &mut impl Write, err: &mut impl Write) {
    if let Err(error) = service.set_description(DESCRIPTION) {
        let _ = writeln!(
            err,
            "tenko service install: warning: cannot set the description: {}",
            error_text(&error)
        );
    }
    // Failure actions also apply when the service stops with a non-zero exit status, not
    // only when the process crashes.
    let actions = service
        .update_failure_actions(failure_actions())
        .and_then(|()| service.set_failure_actions_on_non_crash_failures(true));
    match actions {
        Ok(()) => {
            let _ = writeln!(
                out,
                "  on failure:    restart after {} s, up to three times",
                RESTART_DELAY.as_secs()
            );
        }
        Err(error) => {
            let _ = writeln!(
                err,
                "tenko service install: warning: cannot set the failure actions: {}; the service will not be started again after a failure or an update",
                error_text(&error)
            );
        }
    }
}

/// `%SystemRoot%`, where the event message file is looked for.
fn system_root() -> PathBuf {
    std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from)
}

/// The `reg.exe` calls that register the event source `name` in the Application log: the
/// event types it writes (error, warning, information) and, when it exists, the message file
/// that renders an event as the text it was written with.
fn event_source_arguments(name: &str, message_file: Option<&Path>) -> Vec<Vec<OsString>> {
    let key = OsString::from(logging::event_log::source_key(name));
    let mut calls = vec![vec![
        "add".into(),
        key.clone(),
        "/v".into(),
        "TypesSupported".into(),
        "/t".into(),
        "REG_DWORD".into(),
        "/d".into(),
        "7".into(),
        "/f".into(),
    ]];
    if let Some(file) = message_file {
        calls.push(vec![
            "add".into(),
            key,
            "/v".into(),
            "EventMessageFile".into(),
            "/t".into(),
            "REG_EXPAND_SZ".into(),
            "/d".into(),
            file.into(),
            "/f".into(),
        ]);
    }
    calls
}

/// Registers the event source of the service. A failure leaves a working service whose
/// events show without their text in the Event Viewer, so it is a warning.
fn register_event_source(name: &str, out: &mut impl Write, err: &mut impl Write) {
    let message_file = logging::event_log::message_file(&system_root());
    let message_file = message_file.is_file().then_some(message_file);
    for arguments in event_source_arguments(name, message_file.as_deref()) {
        let Err(problem) = run_tool("reg.exe", &arguments) else {
            continue;
        };
        let _ = writeln!(
            err,
            "tenko service install: warning: cannot register the event source `{name}`:              {problem}; the service logs to its file only"
        );
        return;
    }
    let _ = writeln!(out, "  event log:     Application, source `{name}`");
    if message_file.is_none() {
        let _ = writeln!(
            err,
            "tenko service install: warning: the .NET Framework message file is missing; events are written but the Event Viewer shows them without their text"
        );
    }
}

/// Removes the event source of the service; a source that is not registered is fine.
fn remove_event_source(name: &str, out: &mut impl Write) {
    let key = logging::event_log::source_key(name);
    let arguments: [OsString; 3] = ["delete".into(), key.into(), "/f".into()];
    if run_tool("reg.exe", &arguments).is_ok() {
        let _ = writeln!(out, "removed the event source `{name}`");
    }
}

/// The text a tool printed, on one line.
fn tool_output(output: &std::process::Output) -> String {
    let text = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.is_empty() {
        format!("exit status {}", output.status)
    } else {
        line
    }
}

/// The first step on a new or empty data directory: the inherited list goes, and
/// Administrators and SYSTEM alone have access, so that what the installer writes next is
/// written into a directory the service account cannot write.
fn restrict_data_dir(dir: &Path, out: &mut impl Write) -> Outcome {
    run_tool(
        "icacls.exe",
        &service_policy::icacls_restrict_arguments(dir),
    )
    .map_err(|reason| Failure::general(format!("cannot restrict {}: {reason}", dir.display())))?;
    let _ = writeln!(
        out,
        "data directory {}: access limited to Administrators and SYSTEM",
        dir.display()
    );
    Ok(())
}

/// The last step: the service account gets full control of the directory and of everything
/// in it, which everything created in it later inherits.
fn grant_data_dir(dir: &Path, account: &str, out: &mut impl Write) -> Outcome {
    run_tool(
        "icacls.exe",
        &service_policy::icacls_grant_arguments(dir, account),
    )
    .map_err(|reason| {
        Failure::general(format!(
            "cannot grant {account} access to {}: {reason}",
            dir.display()
        ))
    })?;
    let _ = writeln!(
        out,
        "data directory {}: access limited to {account}, Administrators and SYSTEM",
        dir.display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------
// service uninstall, start and stop
// ---------------------------------------------------------------------------------------

/// `tenko service uninstall`: stops the service if it runs, then deletes it.
fn uninstall_service(args: &NameArgs, out: &mut impl Write) -> Outcome {
    let name = args.name.as_str();
    let manager = connect(ServiceManagerAccess::CONNECT)?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = open(&manager, name, access)?;
    if stop_and_wait(&service, name)? {
        let _ = writeln!(out, "service `{name}` stopped");
    }
    match service.delete() {
        Ok(()) => {}
        Err(error) if os_code(&error) == Some(ERROR_SERVICE_MARKED_FOR_DELETE) => {}
        Err(error) => {
            return Err(Failure::scm(
                &format!("cannot remove service `{name}`"),
                &error,
            ));
        }
    }
    remove_event_source(name, out);
    let _ = writeln!(
        out,
        "removed service `{name}`; the data directory and the configuration file are untouched"
    );
    Ok(())
}

/// `tenko service start`: starts the service and waits until it runs, through the restart
/// that follows an adopted installer's file (exit status 12). It then says which version the
/// layout runs, and fails when the layout runs an older version than this binary: the
/// installer's file was not adopted, and the Application log names the reason.
fn start_service(args: &NameArgs, out: &mut impl Write) -> Outcome {
    let name = args.name.as_str();
    let manager = connect(ServiceManagerAccess::CONNECT)?;
    let service = open(
        &manager,
        name,
        ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::QUERY_CONFIG,
    )?;
    match service.start::<&str>(&[]) {
        Ok(()) => {}
        Err(error) if os_code(&error) == Some(ERROR_SERVICE_ALREADY_RUNNING) => {}
        Err(error) => {
            return Err(Failure::scm(
                &format!("cannot start service `{name}`"),
                &error,
            ));
        }
    }
    wait_started(
        || service.query_status(),
        name,
        START_TIMEOUT,
        RESTART_WAIT,
        POLL_INTERVAL,
    )?;
    let _ = writeln!(out, "service `{name}` is running");
    let registered = service.query_config().map_err(|error| {
        Failure::scm(
            &format!("cannot read the configuration of `{name}`"),
            &error,
        )
    })?;
    let executable =
        service_policy::registered_executable(&registered.executable_path.to_string_lossy());
    if let Some(data_dir) = service_policy::layout_data_dir(&executable) {
        let current = Layout::new(&data_dir).current();
        let line = service_policy::adoption_outcome(&upgrade::running_version(), current.as_ref())
            .map_err(|message| Failure::new(exit::UPGRADE_REFUSED, message))?;
        let _ = writeln!(out, "{line}");
    }
    Ok(())
}

/// Waits until the service runs. A stop with exit status 12 while it starts is a restart
/// the service asked for (an adopted installer's file, a switch back): the wait goes on
/// through the SCM's restart delay, up to three times, as the failure actions allow.
fn wait_started(
    mut query: impl FnMut() -> Result<ServiceStatus, ScmError>,
    name: &str,
    timeout: Duration,
    restart_wait: Duration,
    interval: Duration,
) -> Outcome {
    let query_failed = |error: &ScmError| Failure::scm(&format!("cannot query `{name}`"), error);
    let settled = |status: &ServiceStatus| {
        matches!(
            status.current_state,
            ServiceState::Running | ServiceState::Stopped
        )
    };
    let restart = ServiceExitCode::ServiceSpecific(u32::from(exit::RESTART));
    let mut restarts = 0;
    loop {
        let waited = wait_for(&mut query, settled, timeout, interval)
            .map_err(|error| query_failed(&error))?;
        match waited {
            Wait::Done(status) if status.current_state == ServiceState::Running => return Ok(()),
            Wait::Done(status) if status.exit_code == restart && restarts < 3 => {
                restarts += 1;
                let left_stopped =
                    |status: &ServiceStatus| status.current_state != ServiceState::Stopped;
                match wait_for(&mut query, left_stopped, restart_wait, interval)
                    .map_err(|error| query_failed(&error))?
                {
                    Wait::Done(_) => {}
                    Wait::TimedOut(_) => {
                        return Err(Failure::general(format!(
                            "service `{name}` stopped to be started again (exit status 12) \
                             but the SCM did not start it within {} s; check its failure \
                             actions",
                            restart_wait.as_secs()
                        )));
                    }
                }
            }
            Wait::Done(status) => {
                return Err(Failure::general(format!(
                    "service `{name}` stopped while starting ({})",
                    describe_exit(status.exit_code)
                )));
            }
            Wait::TimedOut(status) => {
                return Err(Failure::general(format!(
                    "service `{name}` is still {} after {} s",
                    state_name(status.current_state),
                    timeout.as_secs()
                )));
            }
        }
    }
}

/// `tenko service stop`: stops the service and waits until it has stopped.
fn stop_service(args: &NameArgs, out: &mut impl Write) -> Outcome {
    let name = args.name.as_str();
    let manager = connect(ServiceManagerAccess::CONNECT)?;
    let service = open(
        &manager,
        name,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
    )?;
    if stop_and_wait(&service, name)? {
        let _ = writeln!(out, "service `{name}` stopped");
    } else {
        let _ = writeln!(out, "service `{name}` is not running");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// service run: the entry point the SCM starts
// ---------------------------------------------------------------------------------------

/// A service status for the SCM. Pending states carry a checkpoint and a wait hint; the
/// other states carry neither.
fn make_status(
    state: ServiceState,
    accepted: ServiceControlAccept,
    exit_code: ServiceExitCode,
    wait_hint: Duration,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accepted,
        exit_code,
        checkpoint: u32::from(!wait_hint.is_zero()),
        wait_hint,
        process_id: None,
    }
}

/// The service is starting; it accepts no control request yet.
fn start_pending() -> ServiceStatus {
    make_status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::NO_ERROR,
        START_WAIT_HINT,
    )
}

/// The service runs and accepts stop and system shutdown.
fn running() -> ServiceStatus {
    make_status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::NO_ERROR,
        Duration::ZERO,
    )
}

/// The service is shutting down; it accepts no further request.
fn stop_pending() -> ServiceStatus {
    make_status(
        ServiceState::StopPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::NO_ERROR,
        STOP_WAIT_HINT,
    )
}

/// The service has stopped; a non-zero tenko exit status is the service-specific exit code.
fn stopped(status: u8) -> ServiceStatus {
    let exit_code = if status == exit::OK {
        ServiceExitCode::NO_ERROR
    } else {
        ServiceExitCode::ServiceSpecific(u32::from(status))
    };
    make_status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
        Duration::ZERO,
    )
}

/// Reports a status to the SCM.
fn report(handle: ServiceStatusHandle, status: ServiceStatus) {
    let state = state_name(status.current_state);
    if let Err(error) = handle.set_service_status(status) {
        tracing::warn!(state, error = %error_text(&error), "cannot report the state to the SCM");
    }
}

/// Answers a control request of the SCM: stop and system shutdown start the shutdown, and
/// interrogation is acknowledged.
fn handle_control(
    control: ServiceControl,
    stop: &mut Option<oneshot::Sender<()>>,
) -> ServiceControlHandlerResult {
    match control {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown => {
            tracing::info!(?control, "the SCM asked the service to stop");
            if let Some(stop) = stop.take() {
                let _ = stop.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    }
}

/// Registers the control handler. The service stops when `stop` receives a value or its
/// sender is dropped.
fn register_handler(
    name: &str,
    stop: oneshot::Sender<()>,
) -> Result<ServiceStatusHandle, ScmError> {
    let mut stop = Some(stop);
    service_control_handler::register(name, move |control| handle_control(control, &mut stop))
}

/// The log file of the service: `log.file`, else `<data_dir>\logs\tenko.log`.
fn log_path(resolved: &Resolved) -> PathBuf {
    resolved
        .config
        .log
        .file
        .clone()
        .unwrap_or_else(|| resolved.layout().logs().join("tenko.log"))
}

/// Logs what `check_roles` wrote, and returns the exit status when no role can run.
fn check_roles(resolved: &Resolved) -> Option<u8> {
    let mut note = Vec::new();
    let refusal = serve::check_roles(resolved.roles, &mut note);
    let text = String::from_utf8_lossy(&note);
    let text = text.trim();
    if !text.is_empty() {
        if refusal.is_some() {
            tracing::error!("{text}");
        } else {
            tracing::warn!("{text}");
        }
    }
    refusal
}

/// The callbacks that report readiness and the start of the shutdown to the SCM.
fn hooks(handle: ServiceStatusHandle) -> Hooks {
    Hooks {
        ready: Some(Box::new(move |_ready: &Ready| report(handle, running()))),
        stopping: Some(Box::new(move || report(handle, stop_pending()))),
    }
}

/// A configuration that cannot be used: the Event Log says why, and a newly installed
/// version switches back to the previous one (`serve::config_refused`). The log is not open
/// yet, so the Event Log and the exit status are all there is.
fn config_failed(args: &RunArgs, error: &ConfigError) -> u8 {
    let sources = Sources {
        file: Some(args.config.clone()),
        data_dir: args.data_dir.clone(),
        roles: None,
    };
    let mut switched = Vec::new();
    let status = serve::config_refused(&sources, &mut switched);
    logging::event_log::report_early(
        &args.name,
        &format!(
            "tenko service {}: the configuration {} cannot be used: {error}\n{}",
            args.name,
            args.config.display(),
            String::from_utf8_lossy(&switched).trim_end()
        ),
    );
    status
}

/// Loads the configuration, opens the log and runs the server until `stop` fires. Returns
/// the exit status.
fn serve_until_stopped(
    args: &RunArgs,
    handle: ServiceStatusHandle,
    stop: oneshot::Receiver<()>,
) -> u8 {
    let resolved = match load_config(&args.config, args.data_dir.as_deref()) {
        Ok(resolved) => resolved,
        Err(error) => return config_failed(args, &error),
    };
    // A restart request (exit status 12) relies on the failure actions below.
    crate::upgrade::restart::set_windows_service();
    let path = log_path(&resolved);
    let controller = resolved.roles.contains(tenko_core::Role::Controller);
    // A controller's runtime comes first: the trace exporter's channel runs on it, so the
    // layer is built and the subscriber installed inside it. A node without the controller
    // role does not trace.
    let runtime = if controller {
        match serve::runtime(&resolved) {
            Ok(runtime) => Some(runtime),
            Err(error) => {
                logging::event_log::report_early(
                    &args.name,
                    &format!("tenko service {}: {error}", args.name),
                );
                return exit::FAILURE;
            }
        }
    } else {
        None
    };
    let entered = runtime.as_ref().map(tokio::runtime::Runtime::enter);
    let (extra, telemetry) = if controller {
        match crate::telemetry::layer(
            &resolved.config.telemetry,
            resolved.node_id,
            tenko_api::version(),
        ) {
            Ok(Some((layer, telemetry))) => (Some(layer), Some(telemetry)),
            Ok(None) => (None, None),
            Err(error) => {
                logging::event_log::report_early(
                    &args.name,
                    &format!("tenko service {}: {error}", args.name),
                );
                return exit::FAILURE;
            }
        }
    } else {
        (None, None)
    };
    let layers = logging::Layers {
        event_log: logging::event_log::layer(&args.name, resolved.config.log.event_log).ok(),
        extra,
    };
    if let Err(error) =
        logging::init_server_with(&resolved.config.log, Some(&path), Sink::FileOnly, layers)
    {
        logging::event_log::report_early(
            &args.name,
            &format!("tenko service {}: cannot open the log: {error}", args.name),
        );
        return exit::FAILURE;
    }
    tracing::info!(
        target: logging::event_log::SERVICE_TARGET,
        service = %args.name,
        config = %args.config.display(),
        log = %path.display(),
        "tenko service starting"
    );
    if adopts_installer_file(args, &resolved, handle) {
        return exit::RESTART;
    }
    if let Some(status) = check_roles(&resolved) {
        return status;
    }
    let shutdown = move || -> Shutdown {
        Box::pin(async move {
            // A dropped sender also means stop: the SCM released the control handler.
            let _ = stop.await;
        })
    };
    drop(entered);
    // A node without the controller role runs the node process (WP2.2).
    let Some(runtime) = runtime else {
        return crate::node::agent::serve(resolved, shutdown, hooks(handle));
    };
    match serve::run_on(runtime, resolved, shutdown, hooks(handle), telemetry) {
        Ok(()) => exit::OK,
        Err(error) => {
            tracing::error!(%error, "tenko service ended with an error");
            error.exit_code()
        }
    }
}

/// With `--payload`, looks at the installer's file and returns whether the service must stop
/// to be started again as the adopted version.
fn adopts_installer_file(args: &RunArgs, resolved: &Resolved, handle: ServiceStatusHandle) -> bool {
    let Some(path) = args.payload.as_deref() else {
        return false;
    };
    // The check copies the closed store and may take a while: a fresh wait hint first.
    report(handle, start_pending());
    let payload = upgrade::Payload {
        path,
        config: Some(&args.config),
        data_dir: args.data_dir.as_deref(),
        deadline_secs: resolved.config.updates.ready_timeout_secs,
    };
    adopt_installer_file(resolved, &payload)
}

/// Looks at the installer's file at the start of the service (ADR 0023, item 11) and logs
/// the outcome, the lines that matter in the Application log too. Returns whether the layout
/// was switched, in which case the service stops with exit status 12 and the SCM starts the
/// adopted version. A file that refuses the store or cannot be read leaves the running
/// version running; it is looked at again at the next start.
fn adopt_installer_file(resolved: &Resolved, payload: &upgrade::Payload<'_>) -> bool {
    let running = upgrade::running_version();
    let file = payload.path.display().to_string();
    match upgrade::adopt_payload(&resolved.data_dir, &running, payload) {
        Adoption::Adopted { from, to, report } => {
            tracing::warn!(
                target: logging::event_log::SERVICE_TARGET,
                %file,
                %from,
                %to,
                migrations = report.steps.len(),
                "adopted the installer's file: the store check passed and the layout now \
                 runs the new version; stopping to be started again"
            );
            true
        }
        Adoption::Refused { version, report } => {
            tracing::error!(
                target: logging::event_log::SERVICE_TARGET,
                %file,
                %version,
                %running,
                reason = %upgrade::problem_text(&report),
                "the installer's file was not adopted: its version refuses the store; the \
                 running version keeps running"
            );
            false
        }
        Adoption::Failed(error) => {
            tracing::error!(
                target: logging::event_log::SERVICE_TARGET,
                %file,
                %running,
                error,
                "the installer's file was not adopted; the running version keeps running"
            );
            false
        }
        Adoption::NotNewer { payload, running } => {
            tracing::info!(
                %file,
                version = %payload,
                %running,
                "the installer's file is not newer than the running version; nothing to adopt"
            );
            false
        }
        Adoption::Busy => {
            tracing::info!(
                %file,
                "an install attempt is under way; the installer's file is looked at again at \
                 a later start"
            );
            false
        }
    }
}

/// The message of a panic payload.
fn panic_message(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("unknown panic")
}

/// The service: registers the control handler, runs the server and reports every state to
/// the SCM. Returns the exit status.
fn service_main(args: &RunArgs) -> u8 {
    let (stop_tx, stop_rx) = oneshot::channel();
    let Ok(handle) = register_handler(&args.name, stop_tx) else {
        // Without a status handle nothing can be reported; the SCM sees the process end.
        return exit::FAILURE;
    };
    report(handle, start_pending());
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        serve_until_stopped(args, handle, stop_rx)
    }));
    let status = outcome.unwrap_or_else(|payload| {
        tracing::error!(
            target: logging::event_log::SERVICE_TARGET,
            panic = panic_message(payload.as_ref()),
            "the service panicked"
        );
        exit::FAILURE
    });
    tracing::info!(
        target: logging::event_log::SERVICE_TARGET,
        status,
        "tenko service stopped"
    );
    report(handle, stopped(status));
    status
}

/// The service main function the dispatcher calls on a thread of its own. It is written out
/// instead of generated by `define_windows_service!`, whose expansion is an `unsafe` block.
/// The raw arguments of the SCM are ignored: the service reads the command line of its
/// image path, which `run_dispatcher` stored.
extern "system" fn ffi_service_main(_argc: u32, _argv: *mut *mut u16) {
    if let Some(args) = RUN_ARGS.get() {
        EXIT_STATUS.store(service_main(args), Ordering::SeqCst);
    }
}

/// `tenko service run`: connects to the SCM and blocks until the service has stopped.
fn run_dispatcher(args: &RunArgs, err: &mut impl Write) -> u8 {
    let _ = RUN_ARGS.set(args.clone());
    match service_dispatcher::start(&args.name, ffi_service_main) {
        Ok(()) => EXIT_STATUS.load(Ordering::SeqCst),
        Err(error) if os_code(&error) == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) => {
            let _ = writeln!(
                err,
                "tenko service run is started by the Service Control Manager; run `tenko serve` \
                 in a console"
            );
            exit::USAGE
        }
        Err(error) => {
            let _ = writeln!(
                err,
                "tenko service run: cannot connect to the Service Control Manager: {}",
                error_text(&error)
            );
            exit::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;

    fn text(arguments: &[OsString]) -> Vec<String> {
        arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    fn install_args(config: PathBuf) -> InstallArgs {
        InstallArgs {
            name: "tenko-test-never-registered".to_owned(),
            display_name: "Tenko test".to_owned(),
            config,
            data_dir: None,
            account: None,
            manual: false,
            no_update_layout: false,
        }
    }

    fn run_command(command: &ServiceCommand) -> (u8, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let status = super::command(command, &mut out, &mut err);
        (
            status,
            String::from_utf8(out).expect("UTF-8 output"),
            String::from_utf8(err).expect("UTF-8 output"),
        )
    }

    fn access_denied() -> ScmError {
        ScmError::Winapi(io::Error::from_raw_os_error(ERROR_ACCESS_DENIED))
    }

    /// The installer's tools, started as the installer starts them: the access list of a
    /// directory through Windows PowerShell, a service SID through `sc.exe`, an access list
    /// through `icacls.exe` and a value through `reg.exe` (each read only). Also run by
    /// [`the_installer_tools_ignore_a_module_planted_in_the_callers_module_path`].
    #[test]
    fn the_installer_tools_run_as_the_installer_runs_them() {
        let dir = tempfile::tempdir().expect("dir");
        // PowerShell takes the typographic quotation marks for `'` as well.
        let quoted = dir.path().join("it's \u{2019}data\u{2018} $x");
        std::fs::create_dir(&quoted).expect("dir");
        let descriptor = read_descriptor(&quoted).expect("the access list is read");
        assert!(descriptor.owner.starts_with("S-1-"), "{descriptor:?}");
        assert!(!descriptor.entries.is_empty(), "{descriptor:?}");
        let sid = account_sid(r"NT SERVICE\tenko-test-never-registered").expect("sc.exe showsid");
        assert!(sid.starts_with("S-1-5-80-"), "{sid}");
        let listed =
            run_tool("icacls.exe", &[quoted.clone().into_os_string()]).expect("icacls.exe");
        assert!(listed.contains("it's"), "{listed}");
        let value = run_tool(
            "reg.exe",
            &[
                r"query".into(),
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion".into(),
                "/v".into(),
                "SystemRoot".into(),
            ],
        )
        .expect("reg.exe query");
        assert!(value.contains("SystemRoot"), "{value}");
    }

    /// The access-list comparison of `service install` works when the caller's
    /// `PSModulePath` names a planted `Microsoft.PowerShell.Security` first, as a
    /// PowerShell 7 caller's names its own copy, which Windows PowerShell cannot load.
    #[test]
    fn the_installer_tools_ignore_a_module_planted_in_the_callers_module_path() {
        crate::exec::planted_module::run_under_planted_module_path(
            "platform::windows::tests::the_installer_tools_run_as_the_installer_runs_them",
        );
    }

    #[test]
    fn launch_arguments_without_a_data_directory() {
        let arguments = launch_arguments(
            "tenko",
            Path::new(r"C:\ProgramData\Tenko\tenko.toml"),
            None,
            None,
        );
        assert_eq!(
            text(&arguments),
            [
                "service",
                "run",
                "--name",
                "tenko",
                "--config",
                r"C:\ProgramData\Tenko\tenko.toml"
            ]
        );
    }

    #[test]
    fn launch_arguments_with_a_data_directory_and_the_installer_file() {
        let arguments = launch_arguments(
            "tenko",
            Path::new(r"C:\ProgramData\Tenko\tenko.toml"),
            Some(Path::new(r"D:\Tenko Data")),
            Some(Path::new(r"C:\Program Files\Tenko\tenko.exe")),
        );
        assert_eq!(
            text(&arguments),
            [
                "service",
                "run",
                "--name",
                "tenko",
                "--config",
                r"C:\ProgramData\Tenko\tenko.toml",
                "--data-dir",
                r"D:\Tenko Data",
                "--payload",
                r"C:\Program Files\Tenko\tenko.exe"
            ]
        );
    }

    #[test]
    fn launch_arguments_parse_as_service_run() {
        let arguments = launch_arguments(
            "tenko-b",
            Path::new(r"C:\Program Data\Tenko\tenko.toml"),
            Some(Path::new(r"D:\Tenko Data")),
            Some(Path::new(r"C:\Program Files\Tenko\tenko.exe")),
        );
        let cli =
            crate::Cli::try_parse_from(std::iter::once(OsString::from("tenko")).chain(arguments))
                .expect("the launch arguments parse");
        let crate::Command::Service {
            action: ServiceCommand::Run(run),
        } = cli.command
        else {
            panic!("not `service run`");
        };
        assert_eq!(run.name, "tenko-b");
        assert_eq!(run.config, Path::new(r"C:\Program Data\Tenko\tenko.toml"));
        assert_eq!(run.data_dir.as_deref(), Some(Path::new(r"D:\Tenko Data")));
        assert_eq!(
            run.payload.as_deref(),
            Some(Path::new(r"C:\Program Files\Tenko\tenko.exe"))
        );
    }

    #[test]
    fn default_account_is_the_virtual_service_account() {
        assert_eq!(default_account("tenko"), r"NT SERVICE\tenko");
        let mut args = install_args(PathBuf::from("tenko.toml"));
        args.name = "tenko-lab".to_owned();
        assert_eq!(account(&args), r"NT SERVICE\tenko-lab");
        args.account = Some(r"NT SERVICE\other".to_owned());
        assert_eq!(account(&args), r"NT SERVICE\other");
        service_policy::check_account(&account(&args)).expect("a virtual account");
    }

    #[test]
    fn install_refuses_the_shared_accounts_before_anything_else() {
        for shared in [
            "LocalSystem",
            r"NT AUTHORITY\LocalService",
            "NetworkService",
        ] {
            let mut args = install_args(PathBuf::from(r"C:\does\not\exist\tenko.toml"));
            args.account = Some(shared.to_owned());
            let (status, out, err) = run_command(&ServiceCommand::Install(args));
            assert_eq!(status, exit::USAGE, "{shared}: {err}");
            assert_eq!(out, "", "{shared}");
            assert!(
                err.contains(service_policy::ACCOUNT_SHARED),
                "{shared}: {err}"
            );
            assert!(err.contains(shared), "{shared}: {err}");
        }
    }

    #[test]
    fn service_info_follows_the_arguments() {
        let mut args = install_args(PathBuf::from("tenko.toml"));
        let info = service_info(
            &args,
            PathBuf::from(r"C:\Program Files\Tenko\tenko.exe"),
            vec!["service".into()],
            r"NT SERVICE\tenko",
        );
        assert_eq!(info.service_type, ServiceType::OWN_PROCESS);
        assert_eq!(info.start_type, ServiceStartType::AutoStart);
        assert_eq!(info.error_control, ServiceErrorControl::Normal);
        assert_eq!(info.account_name, Some(OsString::from(r"NT SERVICE\tenko")));
        assert_eq!(info.account_password, None);
        args.manual = true;
        let info = service_info(&args, PathBuf::from("tenko.exe"), Vec::new(), "LocalSystem");
        assert_eq!(info.start_type, ServiceStartType::OnDemand);
    }

    #[test]
    fn failure_actions_restart_three_times_then_stop() {
        let actions = failure_actions().actions.expect("actions");
        let kinds: Vec<_> = actions.iter().map(|action| action.action_type).collect();
        assert_eq!(
            kinds,
            [
                ServiceActionType::Restart,
                ServiceActionType::Restart,
                ServiceActionType::Restart,
                ServiceActionType::None
            ]
        );
        assert_eq!(actions[0].delay, Duration::from_secs(10));
        assert_eq!(actions[2].delay, Duration::from_secs(10));
    }

    #[test]
    fn the_event_source_is_registered_in_the_application_log() {
        let file =
            PathBuf::from(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll");
        let calls = event_source_arguments("tenko", Some(&file));
        let key = r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\tenko";
        assert_eq!(
            text(&calls[0]),
            [
                "add",
                key,
                "/v",
                "TypesSupported",
                "/t",
                "REG_DWORD",
                "/d",
                "7",
                "/f"
            ]
        );
        assert_eq!(
            text(&calls[1]),
            [
                "add",
                key,
                "/v",
                "EventMessageFile",
                "/t",
                "REG_EXPAND_SZ",
                "/d",
                file.to_str().expect("utf-8"),
                "/f"
            ]
        );
        assert_eq!(event_source_arguments("other", None).len(), 1);
    }

    #[test]
    fn statuses_follow_the_scm_rules() {
        let pending = start_pending();
        assert_eq!(pending.current_state, ServiceState::StartPending);
        assert_eq!(pending.wait_hint, Duration::from_secs(120));
        assert!(pending.controls_accepted.is_empty());
        assert_ne!(pending.checkpoint, 0);

        let up = running();
        assert_eq!(up.current_state, ServiceState::Running);
        assert_eq!(
            up.controls_accepted,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        );
        assert_eq!((up.checkpoint, up.wait_hint), (0, Duration::ZERO));

        let stopping = stop_pending();
        assert_eq!(stopping.current_state, ServiceState::StopPending);
        assert_eq!(stopping.wait_hint, Duration::from_secs(60));
        assert!(stopping.controls_accepted.is_empty());

        assert_eq!(stopped(exit::OK).exit_code, ServiceExitCode::Win32(0));
        assert_eq!(
            stopped(exit::START).exit_code,
            ServiceExitCode::ServiceSpecific(u32::from(exit::START))
        );
        assert_eq!(stopped(exit::START).current_state, ServiceState::Stopped);
    }

    #[test]
    fn stop_and_shutdown_controls_start_the_shutdown() {
        for control in [ServiceControl::Stop, ServiceControl::Shutdown] {
            let (tx, mut rx) = oneshot::channel();
            let mut stop = Some(tx);
            let result = handle_control(control, &mut stop);
            assert_eq!(
                result.to_raw(),
                ServiceControlHandlerResult::NoError.to_raw()
            );
            assert!(stop.is_none());
            assert_eq!(rx.try_recv(), Ok(()));
        }
    }

    #[test]
    fn other_controls_leave_the_service_running() {
        let (tx, mut rx) = oneshot::channel();
        let mut stop = Some(tx);
        let interrogate = handle_control(ServiceControl::Interrogate, &mut stop);
        assert_eq!(
            interrogate.to_raw(),
            ServiceControlHandlerResult::NoError.to_raw()
        );
        let pause = handle_control(ServiceControl::Pause, &mut stop);
        assert_eq!(
            pause.to_raw(),
            ServiceControlHandlerResult::NotImplemented.to_raw()
        );
        assert!(stop.is_some());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn access_denied_asks_for_an_elevated_prompt() {
        let message = scm_message("cannot register service `tenko`", &access_denied());
        assert!(message.starts_with("cannot register service `tenko`: access denied"));
        assert!(message.contains("elevated prompt"), "{message}");
    }

    #[test]
    fn known_errors_get_a_plain_message() {
        let missing = ScmError::Winapi(io::Error::from_raw_os_error(ERROR_SERVICE_DOES_NOT_EXIST));
        assert!(scm_message("open", &missing).contains("not installed"));
        let exists = ScmError::Winapi(io::Error::from_raw_os_error(ERROR_SERVICE_EXISTS));
        assert!(scm_message("register", &exists).contains("tenko service uninstall"));
        let other = ScmError::Winapi(io::Error::from_raw_os_error(1053));
        assert!(scm_message("start", &other).contains("1053"));
    }

    #[test]
    fn exit_codes_are_explained() {
        let config = describe_exit(ServiceExitCode::ServiceSpecific(u32::from(exit::CONFIG)));
        assert!(config.contains("tenko config check"), "{config}");
        let win32 = describe_exit(ServiceExitCode::Win32(5));
        assert!(win32.starts_with("Windows error 5"), "{win32}");
        let unknown = describe_exit(ServiceExitCode::ServiceSpecific(200));
        assert!(unknown.contains("service log"), "{unknown}");
    }

    #[test]
    fn wait_for_returns_when_the_state_is_reached() {
        let mut sequence = vec![
            ServiceState::StopPending,
            ServiceState::StopPending,
            ServiceState::Stopped,
        ]
        .into_iter();
        let mut queries = 0;
        let result = wait_for(
            || {
                queries += 1;
                let state = sequence.next().expect("no query after the last state");
                Ok(make_status(
                    state,
                    ServiceControlAccept::empty(),
                    ServiceExitCode::NO_ERROR,
                    Duration::ZERO,
                ))
            },
            |status| status.current_state == ServiceState::Stopped,
            Duration::from_secs(30),
            Duration::ZERO,
        )
        .expect("no query error");
        assert!(
            matches!(result, Wait::Done(status) if status.current_state == ServiceState::Stopped)
        );
        assert_eq!(queries, 3);
    }

    #[test]
    fn wait_for_gives_up_at_the_timeout() {
        let result = wait_for(
            || Ok(running()),
            |status| status.current_state == ServiceState::Stopped,
            Duration::from_millis(30),
            Duration::from_millis(5),
        )
        .expect("no query error");
        assert!(
            matches!(result, Wait::TimedOut(status) if status.current_state == ServiceState::Running)
        );
    }

    #[test]
    fn wait_for_passes_a_query_error_on() {
        let result = wait_for(
            || Err(access_denied()),
            |_| true,
            Duration::ZERO,
            Duration::ZERO,
        );
        assert_eq!(
            result.map(|_| ()).map_err(|error| os_code(&error)),
            Err(Some(ERROR_ACCESS_DENIED))
        );
    }

    fn scripted(
        states: Vec<(ServiceState, ServiceExitCode)>,
    ) -> impl FnMut() -> Result<ServiceStatus, ScmError> {
        let mut states = states.into_iter();
        let mut last = None;
        move || {
            let next = states.next().or(last).expect("a state");
            last = Some(next);
            Ok(make_status(
                next.0,
                ServiceControlAccept::empty(),
                next.1,
                Duration::ZERO,
            ))
        }
    }

    #[test]
    fn a_start_waits_through_the_restart_an_update_asks_for() {
        let restart = ServiceExitCode::ServiceSpecific(u32::from(exit::RESTART));
        let query = scripted(vec![
            (ServiceState::StartPending, ServiceExitCode::NO_ERROR),
            (ServiceState::Stopped, restart),
            (ServiceState::Stopped, restart),
            (ServiceState::StartPending, ServiceExitCode::NO_ERROR),
            (ServiceState::Running, ServiceExitCode::NO_ERROR),
        ]);
        wait_started(
            query,
            "tenko",
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::ZERO,
        )
        .expect("running after the restart");
    }

    #[test]
    fn a_start_that_ends_with_another_status_or_without_a_restart_fails() {
        let failed = scripted(vec![(
            ServiceState::Stopped,
            ServiceExitCode::ServiceSpecific(u32::from(exit::START)),
        )]);
        let error = wait_started(
            failed,
            "tenko",
            Duration::from_secs(5),
            Duration::ZERO,
            Duration::ZERO,
        )
        .expect_err("a failed start");
        assert!(
            error.message.contains("stopped while starting"),
            "{}",
            error.message
        );
        assert!(
            error.message.contains("a start step failed"),
            "{}",
            error.message
        );

        let restart = ServiceExitCode::ServiceSpecific(u32::from(exit::RESTART));
        let never_restarted = scripted(vec![(ServiceState::Stopped, restart)]);
        let error = wait_started(
            never_restarted,
            "tenko",
            Duration::from_secs(5),
            Duration::from_millis(20),
            Duration::from_millis(5),
        )
        .expect_err("no restart");
        assert!(
            error.message.contains("did not start it"),
            "{}",
            error.message
        );
    }

    #[test]
    fn service_run_from_a_console_is_a_usage_error() {
        let args = RunArgs {
            name: "tenko-test-console".to_owned(),
            config: PathBuf::from(r"C:\does\not\exist\tenko.toml"),
            data_dir: None,
            payload: None,
        };
        let (status, out, err) = run_command(&ServiceCommand::Run(args));
        assert_eq!(status, exit::USAGE, "{err}");
        assert_eq!(out, "");
        assert!(
            err.contains("started by the Service Control Manager"),
            "{err}"
        );
        assert!(err.contains("tenko serve"), "{err}");
    }

    #[test]
    fn install_refuses_a_missing_configuration() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let args = install_args(dir.path().join("missing.toml"));
        let (status, out, err) = run_command(&ServiceCommand::Install(args));
        assert_eq!(status, exit::CONFIG, "{err}");
        assert_eq!(out, "");
        assert!(err.contains("config.read"), "{err}");
    }

    #[test]
    fn install_refuses_an_invalid_configuration() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("tenko.toml");
        std::fs::write(&path, "[tls]\nmode = \"carrier_pigeon\"\n").expect("write");
        let (status, out, err) = run_command(&ServiceCommand::Install(install_args(path)));
        assert_eq!(status, exit::CONFIG, "{err}");
        assert_eq!(out, "");
        assert!(err.contains("config.parse"), "{err}");
    }

    #[test]
    fn install_refuses_a_relative_data_directory() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("tenko.toml");
        std::fs::write(&path, "data_dir = 'state\\tenko'\n").expect("write");
        let (status, out, err) = run_command(&ServiceCommand::Install(install_args(path)));
        assert_eq!(status, exit::CONFIG, "{err}");
        assert_eq!(out, "");
        assert!(err.contains("data_dir must be an absolute path"), "{err}");
    }

    #[test]
    fn commands_on_an_unknown_service_fail_cleanly() {
        let name = NameArgs {
            name: "tenko-test-no-such-service".to_owned(),
        };
        for command in [
            ServiceCommand::Start(name.clone()),
            ServiceCommand::Stop(name.clone()),
            ServiceCommand::Uninstall(name.clone()),
        ] {
            let label = command.name();
            let (status, out, err) = run_command(&command);
            assert_eq!(status, exit::FAILURE, "{label}: {err}");
            assert_eq!(out, "", "{label}");
            assert!(err.starts_with(&format!("tenko {label}: ")), "{err}");
            assert!(err.contains("not installed"), "{label}: {err}");
        }
    }
}
