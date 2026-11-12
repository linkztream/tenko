//! The privilege check of ADR 0023 (`exec.unsafe_owner`, items 3 and 11, invariants I1, I2
//! and I10): a command that reads, writes or executes anything under the data directory
//! never runs with full privileges over files that belong to another account.
//!
//! Before [`crate::execute`] runs one of the commands that [`guarded_paths`] covers, `main`
//! asks this module whether the process runs as root (on Windows: as `SYSTEM`, as an
//! elevated member of Administrators, or with a token that holds a privilege acting beyond
//! its account, see the module `token`; a Windows token that cannot be read in time counts
//! as privileged) and whether this binary's own file, the data directory or another
//! directory the command uses belongs to an account other than the privileged ones. When both
//! hold, the command does not run: the process exits with status 2 (`exit::USAGE`) and
//! prints one line that names the code, the file and its owner, and the same command in
//! the form that runs it as that account (`runuser -u <account> -- tenko …` on Linux).
//! There is no override, no profile setting and no exception for Lab (ADR 0023 item 3).
//!
//! What the check needs to know about the process and the files comes through [`Facts`],
//! so that the decision is tested with two accounts without being root: [`Host`] reads
//! the real process and file system.
//!
//! [`guarded_paths`] decides for every command, with no catch-all arm: `serve`, the
//! offline store commands (`backup restore`, `backup create` of a stopped node, `backup
//! verify` with its work directory, `kek rotate`, `user unlock`, `upgrade check`, `upgrade
//! layout`), the node's own commands (`node enroll`, `status`, `renew`, `inject`, `node
//! scan …`), `cluster join`, `setup token`, `plugin list` and `plugin test` (the plugin it
//! executes) are covered. The unit and a container run `serve` as the owner of its files,
//! which passes; `service run` is started by the Service Control Manager as the service's
//! virtual account only.

use std::{
    fmt,
    path::{Path, PathBuf},
};

use crate::{
    Cli, Command, ConfigCommand, RolesCommand,
    backup::BackupCommand,
    client::{audit::AuditCommand, hibp::HibpCommand, login::SetupCommand},
    cluster::ClusterCommand,
    config,
    kek::KekCommand,
    node::{NodeCommand, NodeDirArgs, scan::cli::ScanCommand},
    platform::ServiceCommand,
    plugin::PluginCommand,
    upgrade::UpgradeCommand,
    user::UserCommand,
};

/// The error code of the refusal.
pub const CODE: &str = "exec.unsafe_owner";

#[cfg(windows)]
pub(crate) use host::system_command;

/// The owner of a file or directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    /// The account's identifier: the uid in decimal on Unix, the SID on Windows.
    pub id: String,
    /// The account's name, when it is known.
    pub name: Option<String>,
    /// Whether the account is one that may own what a privileged process uses: root on
    /// Unix; `SYSTEM`, Administrators or the trusted installer on Windows.
    pub privileged: bool,
}

impl Owner {
    /// The account as `runuser -u` takes it: the name, else the identifier.
    pub fn account(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.id)
    }
}

impl fmt::Display for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            Some(name) => write!(f, "{name} ({})", self.id),
            None => f.write_str(&self.id),
        }
    }
}

/// What the process may do beyond its own account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Privilege {
    /// Nothing beyond its own account.
    Unprivileged,
    /// It cannot be told (Unix other than Linux); the check does not refuse.
    Unknown,
    /// What it may do could not be read, also when the tool that reads it did not end in
    /// time; the check counts it as privileged (fail closed) and says why.
    Unreadable {
        /// Why: "its token could not be read (…)".
        why: String,
    },
    /// More than its own account.
    Privileged {
        /// Why, for the refusal: "the effective uid is 0", "its token holds …".
        why: String,
        /// What to do instead, when it is not the platform's usual advice.
        advice: Option<String>,
    },
}

/// What the check reads from the process and the file system.
pub trait Facts {
    /// Whether this process runs with full privileges. On Linux: the effective uid is 0;
    /// elsewhere on Unix it is not known, and the check does not refuse (it protects against
    /// a slip with the genuine binary, ADR 0023 item 3, and cannot do more than the facts it
    /// gets). On Windows: the token is `SYSTEM`, an elevated member of Administrators, or
    /// holds a privilege that acts beyond its account; a token that cannot be read counts
    /// as privileged.
    fn privilege(&self) -> Privilege;

    /// The owner of `path`, following links an administrator made; `Ok(None)` when the
    /// path does not exist, an error when it exists and its owner cannot be read. A
    /// privileged process refuses a path whose owner cannot be read.
    ///
    /// # Errors
    ///
    /// Why the owner of an existing path cannot be read.
    fn owner(&self, path: &Path) -> Result<Option<Owner>, String>;

    /// This binary's own file.
    fn exe(&self) -> Option<PathBuf>;
}

/// Why a command does not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The command as typed, such as `backup restore`.
    pub command: &'static str,
    /// The file or directory that belongs to another account.
    pub path: PathBuf,
    /// Whether `path` is this binary's own file.
    pub binary: bool,
    /// Its owner, or why it could not be read.
    pub owner: Result<Owner, String>,
    /// The arguments of the command line after the program name.
    pub arguments: Vec<String>,
    /// Why the process counts as privileged.
    pub why: String,
    /// Whether it counts as privileged only because its privileges could not be read.
    pub unread: bool,
    /// What to do instead, when it is not the platform's usual advice.
    pub advice: Option<String>,
}

impl Refusal {
    /// The same command run as the owner: `runuser -u <account> -- tenko …`.
    pub fn as_owner(&self) -> String {
        let account = self.owner.as_ref().map_or("<owner>", Owner::account);
        let mut line = format!("runuser -u {} -- tenko", shell_word(account));
        for argument in &self.arguments {
            line.push(' ');
            line.push_str(&shell_word(argument));
        }
        line
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = if self.binary {
            "this executable"
        } else {
            "the directory"
        };
        if self.unread {
            write!(
                f,
                "tenko {}: [{CODE}] refusing to run because {}, and a process whose privileges \
                 cannot be read counts as privileged: ",
                self.command, self.why
            )?;
        } else if cfg!(windows) {
            write!(
                f,
                "tenko {}: [{CODE}] refusing to run with a privileged token ({}): ",
                self.command, self.why
            )?;
        } else {
            write!(
                f,
                "tenko {}: [{CODE}] refusing to run as root: ",
                self.command
            )?;
        }
        match &self.owner {
            Ok(owner) => write!(f, "{what} {} belongs to {owner}; ", self.path.display())?,
            Err(error) => write!(
                f,
                "{what} {} has an owner that could not be read ({error}); ",
                self.path.display()
            )?,
        }
        if let Some(advice) = &self.advice {
            f.write_str(advice)
        } else if cfg!(windows) && self.command == "serve" {
            f.write_str(
                "start the server as its service instead (`tenko service start`), which runs \
                 it as the service account",
            )
        } else if cfg!(windows) {
            f.write_str(
                "run the MSI's payload C:\\Program Files\\Tenko\\tenko.exe from the elevated \
                 prompt instead; the service account's own files are changed by the service",
            )
        } else if self.command == "serve" {
            write!(
                f,
                "start the server as its service instead (`systemctl start tenko`), or run it \
                 as that account: {}",
                self.as_owner()
            )
        } else {
            write!(f, "run it as that account: {}", self.as_owner())
        }
    }
}

/// Quotes `word` for a POSIX shell when it needs it.
fn shell_word(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./:=,@%+".contains(c));
    if plain {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// The directories and files a command reads, writes, executes or opens the store under,
/// or `None` for a command that touches nothing of the service account's: an API client,
/// a command that prints a constant, or one that only writes where its flags say.
///
/// The match names every command and has no catch-all arm, so that a new command does not
/// compile until it is decided here. The data directory comes from the configuration as
/// the command itself would read it. When the file does not load, it is resolved again
/// without the file, as a command that creates its configuration does (`cluster join`),
/// and else `--data-dir` is taken as given, so that a configuration that fails does not
/// leave the data directory unchecked; with neither, the list is empty and the binary is
/// still checked.
#[allow(
    clippy::too_many_lines,
    clippy::match_same_arms,
    reason = "one arm per command of the binary, each with why it is or is not covered"
)]
pub fn guarded_paths(cli: &Cli) -> Option<Vec<PathBuf>> {
    let resolve = |file: &Option<PathBuf>, dir: &Option<PathBuf>| {
        let sources = config::Sources {
            file: file.clone(),
            data_dir: dir.clone(),
            roles: None,
        };
        config::load(&sources, std::env::vars())
            .and_then(|loaded| loaded.config.resolve())
            .ok()
    };
    let data_dir = |file: &Option<PathBuf>, dir: &Option<PathBuf>| {
        resolve(file, dir)
            .or_else(|| resolve(&None, dir))
            .map(|resolved| resolved.data_dir)
            .or_else(|| dir.clone())
    };
    let node_dir = |node: &NodeDirArgs| data_dir(&node.config, &node.data_dir);
    let paths: Vec<PathBuf> = match &cli.command {
        // The server writes all of the data directory. The unit and a container run it as
        // the owner of its files, which passes; root over the account's files is refused.
        Command::Serve(args) => data_dir(&args.config, &args.data_dir).into_iter().collect(),
        Command::Backup { action } => match action {
            BackupCommand::Restore(args) => {
                data_dir(&args.config, &args.data_dir).into_iter().collect()
            }
            BackupCommand::Create(args) if args.config.is_some() || args.data_dir.is_some() => {
                match resolve(&args.config, &args.data_dir) {
                    Some(resolved) => vec![
                        args.out.clone().unwrap_or_else(|| resolved.backup_dir()),
                        resolved.data_dir,
                    ],
                    None => args
                        .out
                        .iter()
                        .cloned()
                        .chain(data_dir(&args.config, &args.data_dir))
                        .collect(),
                }
            }
            // Online: the server writes the file.
            BackupCommand::Create(_) => return None,
            // Unpacks the archive it reads into its work directory.
            BackupCommand::Verify(args) => std::iter::once(args.file.clone())
                .chain(args.work_dir.iter().cloned())
                .collect(),
            // Creates a new file where `--out` says and refuses an existing path.
            BackupCommand::Keygen(_) => return None,
        },
        Command::Kek {
            action: KekCommand::Rotate(args),
        } => data_dir(&args.config, &args.data_dir).into_iter().collect(),
        Command::User {
            action: UserCommand::Unlock(args),
        } => data_dir(&args.config, &args.data_dir).into_iter().collect(),
        Command::Upgrade { action } => match action {
            UpgradeCommand::Check(args) => args
                .work_dir
                .iter()
                .cloned()
                .chain(data_dir(&args.config, &args.data_dir))
                .collect(),
            UpgradeCommand::Layout(args) => {
                data_dir(&args.config, &args.data_dir).into_iter().collect()
            }
            UpgradeCommand::Format | UpgradeCommand::Version => return None,
        },
        Command::Node { action } => match action {
            // The node's identity, key, buffer and scanner files under `<data_dir>/node`
            // and `<data_dir>/scan`, read and written.
            NodeCommand::Enroll(args) => node_dir(&args.node).into_iter().collect(),
            NodeCommand::Status(args) => node_dir(&args.node).into_iter().collect(),
            NodeCommand::Renew(args) => node_dir(&args.node).into_iter().collect(),
            NodeCommand::Inject(args) => node_dir(&args.node).into_iter().collect(),
            NodeCommand::Scan(args) => match &args.action {
                ScanCommand::Status(args) | ScanCommand::Resume(args) => {
                    node_dir(&args.node).into_iter().collect()
                }
                ScanCommand::Run(args) => node_dir(&args.node).into_iter().collect(),
                ScanCommand::Stop(args) => node_dir(&args.node).into_iter().collect(),
            },
            NodeCommand::EnrollToken(_) | NodeCommand::Roles(_) => return None,
        },
        Command::Cluster { action } => match action {
            // Enrolls, imports key generations and copies the store into the data directory.
            ClusterCommand::Join(args) => node_dir(&args.node).into_iter().collect(),
            ClusterCommand::Status(_)
            | ClusterCommand::Members(_)
            | ClusterCommand::Promote(_)
            | ClusterCommand::Remove(_)
            | ClusterCommand::StepDown(_)
            | ClusterCommand::Verify(_)
            | ClusterCommand::UpgradeCheck(_) => return None,
        },
        Command::Setup(args) => match &args.action {
            // Reads `<data_dir>/setup-token`.
            Some(SetupCommand::Token(args)) => {
                data_dir(&args.config, &args.data_dir).into_iter().collect()
            }
            None => return None,
        },
        Command::Plugin { action } => match action {
            // Reads the manifests under `<data_dir>/plugins` or `--plugins-dir`.
            PluginCommand::List(args) => args
                .plugins_dir
                .iter()
                .cloned()
                .chain(data_dir(&args.config, &args.data_dir))
                .collect(),
            // Executes the plugin it is given.
            PluginCommand::Test(args) => vec![args.target.clone()],
            // A bundled plugin runs inside this process.
            PluginCommand::Run(_) => return None,
        },
        Command::Service { action } => match action {
            // Only the Service Control Manager starts it, as the service's virtual account,
            // the only account `service install` accepts.
            ServiceCommand::Run(_) => return None,
            // Elevated by design: it restricts a data directory before the account gets it
            // and refuses one that holds data under another access list.
            ServiceCommand::Install(_) => return None,
            // The Service Control Manager and the registry only.
            ServiceCommand::Uninstall(_) | ServiceCommand::Start(_) | ServiceCommand::Stop(_) => {
                return None;
            }
        },
        Command::Config { action } => match action {
            // Reads the file it is given.
            ConfigCommand::Check(_) => return None,
            // Writes the file `--out` names, which root owns when root writes it.
            ConfigCommand::Init(_) => return None,
        },
        // Read the files their flags name, write where `--output` says.
        Command::Hibp {
            action: HibpCommand::Build(_),
        }
        | Command::Import(_)
        | Command::Export(_) => return None,
        Command::Audit { action } => match action {
            // A file it is given, or the API; writes where `--output` says.
            AuditCommand::Verify(_) | AuditCommand::Export(_) => return None,
        },
        // Constants.
        Command::Roles {
            action: RolesCommand::List,
        }
        | Command::Openapi => return None,
        // API clients, whose modules under `client/` open no file of the data directory but
        // the node's CA root: they read the caller's own credentials and write where their
        // flags say.
        Command::Login(_)
        | Command::Logout(_)
        | Command::Prefix { .. }
        | Command::Ipam { .. }
        | Command::Dns { .. }
        | Command::Dhcp { .. }
        | Command::Migrate { .. }
        | Command::Auth { .. }
        | Command::Access { .. }
        | Command::CaRoot(_)
        | Command::Health(_)
        | Command::System { .. } => return None,
    };
    Some(paths)
}

/// Decides whether `cli` may run: `None` when it may, else the refusal to print.
///
/// `arguments` are the command-line arguments after the program name, repeated in the
/// refusal as the command to run as the owner.
///
/// On Unix this binary's own file is checked for every command, as ADR 0023 item 3 says.
/// On Windows it is checked for the commands [`guarded_paths`] covers only: reading what
/// the token may do runs `whoami.exe`, with a limit of 30 seconds, and doing that before
/// every client command would slow each one and refuse it whenever the machine is too
/// loaded to answer in time.
pub fn check(cli: &Cli, facts: &dyn Facts, arguments: &[String]) -> Option<Refusal> {
    check_with(cli, facts, arguments, cfg!(not(windows)))
}

/// [`check`], with whether the binary is checked for the commands that are not covered.
fn check_with(
    cli: &Cli,
    facts: &dyn Facts,
    arguments: &[String],
    binary_always: bool,
) -> Option<Refusal> {
    let paths = guarded_paths(cli);
    if paths.is_none() && !binary_always {
        return None;
    }
    let paths = paths.unwrap_or_default();
    let (why, advice, unread) = match facts.privilege() {
        Privilege::Privileged { why, advice } => (why, advice, false),
        Privilege::Unreadable { why } => (why, None, true),
        Privilege::Unprivileged | Privilege::Unknown => return None,
    };
    let command = cli.command.name();
    let refusal = |path: PathBuf, binary: bool, owner: Result<Owner, String>| Refusal {
        command,
        path,
        binary,
        owner,
        arguments: arguments.to_vec(),
        why: why.clone(),
        unread,
        advice: advice.clone(),
    };
    // Another account's file, or one whose owner cannot be read, refuses (fail closed). A
    // path that does not exist yet would be created in its nearest existing ancestor, which
    // decides in its place.
    let unsafe_owner = |path: &Path| {
        for candidate in path.ancestors() {
            match facts.owner(candidate) {
                Ok(None) => {}
                Ok(Some(owner)) if owner.privileged => return None,
                Ok(Some(owner)) => return Some((candidate.to_path_buf(), Ok(owner))),
                Err(error) => return Some((candidate.to_path_buf(), Err(error))),
            }
        }
        None
    };
    if let Some(exe) = facts.exe()
        && let Some((path, owner)) = unsafe_owner(&exe)
    {
        return Some(refusal(path, true, owner));
    }
    for path in paths {
        if let Some((path, owner)) = unsafe_owner(&path) {
            return Some(refusal(path, false, owner));
        }
    }
    None
}

/// The facts of the running process.
#[derive(Debug, Clone, Copy, Default)]
pub struct Host;

impl Facts for Host {
    fn privilege(&self) -> Privilege {
        host::privilege()
    }

    fn owner(&self, path: &Path) -> Result<Option<Owner>, String> {
        host::owner(path)
    }

    fn exe(&self) -> Option<PathBuf> {
        std::env::current_exe().ok()
    }
}

#[cfg(unix)]
mod host {
    use std::{os::unix::fs::MetadataExt as _, path::Path};

    use super::{Owner, Privilege};

    /// The effective uid and capabilities from `/proc/self/status`, which needs no library;
    /// elsewhere than Linux they are not known. A status that cannot be read counts as
    /// privileged (fail closed).
    pub(super) fn privilege() -> Privilege {
        if !cfg!(target_os = "linux") {
            return Privilege::Unknown;
        }
        match std::fs::read_to_string("/proc/self/status") {
            Ok(status) => super::linux::classify(&status),
            Err(error) => super::linux::unreadable(&error.to_string()),
        }
    }

    pub(super) fn owner(path: &Path) -> Result<Option<Owner>, String> {
        let uid = match std::fs::metadata(path) {
            Ok(metadata) => metadata.uid(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
        let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
        Ok(Some(Owner {
            id: uid.to_string(),
            name: account_name(&passwd, uid),
            privileged: uid == 0,
        }))
    }

    /// The name of `uid` in a `passwd` text (`name:x:uid:gid:…`).
    pub(super) fn account_name(passwd: &str, uid: u32) -> Option<String> {
        passwd.lines().find_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            let id: u32 = fields.nth(1)?.parse().ok()?;
            (id == uid && !name.is_empty()).then(|| name.to_owned())
        })
    }
}

#[cfg(windows)]
mod host {
    use std::{
        io::Read as _,
        path::{Component, Path, PathBuf, Prefix},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    use super::{Owner, Privilege, token};
    use crate::platform::service_policy;

    /// The well-known SIDs that may own what a privileged process uses: `SYSTEM`, the
    /// Administrators group and the trusted installer.
    const PRIVILEGED_SIDS: [&str; 3] = [
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    ];

    /// How long a system tool may take before the check gives up on it.
    const TOOL_LIMIT: Duration = Duration::from_secs(30);

    /// The system directory: `%SystemRoot%\System32`, when `SystemRoot` is an absolute path
    /// on a drive letter (not a share) with nothing but plain names after it. A privileged process runs nothing
    /// else (ADR 0023 I1), and never a program found through `PATH` or the current
    /// directory.
    pub(super) fn system_dir(root: Option<&std::ffi::OsStr>) -> Result<PathBuf, String> {
        let root = PathBuf::from(root.ok_or_else(|| "SystemRoot is not set".to_owned())?);
        let mut components = root.components();
        let plain = matches!(components.next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)))
            && matches!(components.next(), Some(Component::RootDir))
            && components.all(|component| matches!(component, Component::Normal(_)));
        if !plain {
            return Err(format!(
                "SystemRoot `{}` is not a plain absolute path",
                root.display()
            ));
        }
        Ok(root.join("System32"))
    }

    /// The command that starts `tool` (a path below the system directory) the way a
    /// privileged process starts one (ADR 0023 I1): by its full path under
    /// `%SystemRoot%\System32`, never through `PATH` or the current directory, with no
    /// standard input, the system directory as its working directory (a path argument must
    /// be absolute), and with an environment of fixed values only. `SystemRoot` is the
    /// validated one, and `PSModulePath` names the system module directory and nothing
    /// else.
    ///
    /// Nothing of the caller's environment reaches the tool. An inherited `PSModulePath`
    /// decides which module Windows PowerShell loads for a command: started from PowerShell 7,
    /// it names PowerShell 7's own `Microsoft.PowerShell.Security` first, which Windows
    /// PowerShell cannot load, so `Get-Acl` failed. A module planted in a directory of the
    /// caller's would load the same way. With no `PSModulePath` at all, Windows PowerShell
    /// builds one that begins with the user's Documents folder. With this one it adds only
    /// `Program Files\WindowsPowerShell\Modules`, where only administrators write.
    ///
    /// # Errors
    ///
    /// `SystemRoot` is not set or is not a plain absolute path on a drive.
    pub(crate) fn system_command(tool: &str) -> Result<Command, String> {
        let root = std::env::var_os("SystemRoot");
        let dir = system_dir(root.as_deref())?;
        let modules = dir.join("WindowsPowerShell").join("v1.0").join("Modules");
        let mut command = Command::new(dir.join(tool));
        command
            .env_clear()
            .env("SystemRoot", root.unwrap_or_default())
            .env("PSModulePath", modules)
            .current_dir(&dir)
            .stdin(Stdio::null());
        Ok(command)
    }

    /// Runs `tool` (a path below the system directory) with `arguments`, started by
    /// [`system_command`], for at most [`TOOL_LIMIT`]; returns its standard output when it
    /// exits with status 0.
    fn run(tool: &str, arguments: &[&str]) -> Result<String, String> {
        run_within(tool, arguments, TOOL_LIMIT)
    }

    /// [`run`] with the time limit as an argument.
    pub(super) fn run_within(
        tool: &str,
        arguments: &[&str],
        limit: Duration,
    ) -> Result<String, String> {
        let mut command = system_command(tool)?;
        command.args(arguments);
        run_command(command, limit)
    }

    /// Runs a command of [`system_command`] for at most `limit`; returns its standard
    /// output when it exits with status 0.
    fn run_command(mut command: Command, limit: Duration) -> Result<String, String> {
        let path = PathBuf::from(command.get_program());
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("cannot run {}: {error}", path.display()))?;
        // Read while the tool runs, so that a full pipe cannot hold it.
        let mut stdout = child.stdout.take();
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(stdout) = stdout.as_mut() {
                let _ = stdout.read_to_end(&mut bytes);
            }
            bytes
        });
        let deadline = Instant::now() + limit;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => {
                    // The check refuses rather than run unchecked; the line says what to try.
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "{} did not end within {} s and was stopped; run the command again, \
                         and if this repeats, find what holds up that program on this machine \
                         (it should take well under a second)",
                        path.display(),
                        limit.as_secs()
                    ));
                }
                Err(error) => {
                    return Err(format!("cannot wait for {}: {error}", path.display()));
                }
            }
        };
        let bytes = reader
            .join()
            .map_err(|_| format!("cannot read the output of {}", path.display()))?;
        if !status.success() {
            return Err(format!("{} ended with {status}", path.display()));
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// What the token may do, from `whoami /user /groups /priv /fo csv /nh`; a token that
    /// cannot be read counts as privileged (fail closed).
    pub(super) fn privilege() -> Privilege {
        match run(
            "whoami.exe",
            &["/user", "/groups", "/priv", "/fo", "csv", "/nh"],
        ) {
            Ok(output) => token::classify(&output),
            Err(error) => token::unreadable(&error),
        }
    }

    /// The owner through the access list of the path, as a SID and a name.
    pub(super) fn owner(path: &Path) -> Result<Option<Owner>, String> {
        match std::fs::metadata(path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.to_string()),
        }
        // The path goes to the script through the environment, never into its text, and the
        // owner's SID is read from the SDDL line (see `powershell_acl_arguments`). The
        // tool's working directory is the system directory, so the path is made absolute.
        let absolute = std::path::absolute(path).map_err(|error| error.to_string())?;
        let mut command = system_command(r"WindowsPowerShell\v1.0\powershell.exe")?;
        command
            .args(service_policy::powershell_acl_arguments())
            .env(service_policy::ACL_PATH_VARIABLE, &absolute);
        let output = run_command(command, TOOL_LIMIT)?;
        let mut lines = output
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty());
        let id = lines
            .next()
            .and_then(service_policy::parse_sddl)
            .map(|descriptor| descriptor.owner)
            .ok_or_else(|| "powershell.exe printed no security descriptor".to_owned())?;
        let name = lines.next().map(str::to_owned);
        Ok(Some(Owner {
            privileged: PRIVILEGED_SIDS.contains(&id.as_str()),
            id,
            name,
        }))
    }
}

#[cfg(not(any(unix, windows)))]
mod host {
    use std::path::Path;

    use super::{Owner, Privilege};

    pub(super) fn privilege() -> Privilege {
        Privilege::Unknown
    }

    pub(super) fn owner(_path: &Path) -> Result<Option<Owner>, String> {
        Ok(None)
    }
}

/// What a Linux process may do beyond its own account, read from `/proc/self/status`: the
/// effective uid (`Uid: real effective saved fs`) and the effective capabilities (`CapEff:`,
/// a hexadecimal mask). A process that is not root but holds a capability that reaches
/// another account's files or processes counts as privileged; the capabilities the unit
/// grants the service (`CAP_NET_BIND_SERVICE`, and `CAP_NET_RAW` for some roles) do not.
#[cfg(any(unix, test))]
mod linux {
    use super::Privilege;

    /// The capabilities that act beyond the account, by their bit number.
    pub(super) const BEYOND_THE_ACCOUNT: [(u32, &str); 15] = [
        // Change the owner of any file.
        (0, "CAP_CHOWN"),
        // Read, write and execute any file.
        (1, "CAP_DAC_OVERRIDE"),
        // Read any file and search any directory.
        (2, "CAP_DAC_READ_SEARCH"),
        // Act as the owner of any file: modes, access lists, links in sticky directories.
        (3, "CAP_FOWNER"),
        // Become any group or user.
        (6, "CAP_SETGID"),
        (7, "CAP_SETUID"),
        // Grant capabilities to other processes and files.
        (8, "CAP_SETPCAP"),
        // Load kernel modules: code in the kernel.
        (16, "CAP_SYS_MODULE"),
        // Raw access to devices and memory.
        (17, "CAP_SYS_RAWIO"),
        // Trace any process, read and write its memory.
        (19, "CAP_SYS_PTRACE"),
        // Mount, namespaces and much else that reaches root.
        (21, "CAP_SYS_ADMIN"),
        // Set file capabilities.
        (31, "CAP_SETFCAP"),
        // Override or change the mandatory access control policy.
        (32, "CAP_MAC_OVERRIDE"),
        (33, "CAP_MAC_ADMIN"),
        // Load programs into the kernel.
        (39, "CAP_BPF"),
    ];

    /// A status that could not be read: counted as privileged, so that the check fails
    /// closed.
    pub(super) fn unreadable(reason: &str) -> Privilege {
        Privilege::Unreadable {
            why: format!("/proc/self/status could not be read ({reason})"),
        }
    }

    fn field<'a>(status: &'a str, name: &str) -> Option<&'a str> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
    }

    pub(super) fn effective_uid(status: &str) -> Option<u32> {
        field(status, "Uid:")
            .and_then(|fields| fields.split_whitespace().nth(1))
            .and_then(|uid| uid.parse().ok())
    }

    /// Classifies the text of `/proc/self/status`.
    pub(super) fn classify(status: &str) -> Privilege {
        let Some(uid) = effective_uid(status) else {
            return unreadable("no effective uid in it");
        };
        if uid == 0 {
            return Privilege::Privileged {
                why: "the effective uid is 0".to_owned(),
                advice: None,
            };
        }
        let Some(mask) = field(status, "CapEff:").and_then(|hex| u64::from_str_radix(hex, 16).ok())
        else {
            return unreadable("no effective capabilities in it");
        };
        let held: Vec<&str> = BEYOND_THE_ACCOUNT
            .iter()
            .filter(|(bit, _)| mask & (1 << bit) != 0)
            .map(|(_, name)| *name)
            .collect();
        if held.is_empty() {
            Privilege::Unprivileged
        } else {
            Privilege::Privileged {
                why: format!("its effective capabilities hold {}", held.join(", ")),
                advice: None,
            }
        }
    }
}

/// What a Windows token may do beyond its own account, read from the output of
/// `whoami /user /groups /priv /fo csv /nh`. Only what Windows does not translate is read:
/// the SIDs (the user, the groups, the integrity label) and the constant names of the
/// privileges. The names of accounts and groups, the attributes of a group and the state
/// and description of a privilege are translated, and the decision never reads them. A
/// privilege counts when the token holds it, enabled or not: the process can enable it.
///
/// The integrity label alone does not make a token privileged: the Service Control Manager
/// gives every service a high or system label, also the virtual account of a Tenko service
/// whose token keeps `SeChangeNotifyPrivilege` alone and can do nothing beyond its account.
#[cfg(any(windows, test))]
mod token {
    use super::Privilege;

    /// `SYSTEM`.
    const SYSTEM: &str = "S-1-5-18";
    /// `BUILTIN\Administrators`.
    const ADMINISTRATORS: &str = "S-1-5-32-544";
    /// `NT AUTHORITY\SERVICE`: in the token of every service the Service Control Manager
    /// starts.
    const SERVICE: &str = "S-1-5-6";
    /// The prefix of a virtual service account, `NT SERVICE\<name>`.
    const VIRTUAL_ACCOUNT: &str = "S-1-5-80-";
    /// The integrity label of an elevated token (`High`); `System` is above it.
    const HIGH_INTEGRITY: u32 = 12288;

    /// The privileges that let a token act beyond its own account: read, write or take any
    /// file, act as or impersonate another account, change what another account's process
    /// runs, or run code in the kernel or below it.
    pub(super) const BEYOND_THE_ACCOUNT: [&str; 17] = [
        // Start a process with another account's token.
        "SeAssignPrimaryTokenPrivilege",
        // Read any file whatever its access list.
        "SeBackupPrivilege",
        // Write any file and set any owner.
        "SeRestorePrivilege",
        // Take the ownership of any object.
        "SeTakeOwnershipPrivilege",
        // Open any process, SYSTEM's included.
        "SeDebugPrivilege",
        // Act as part of the operating system: make tokens for any account.
        "SeTcbPrivilege",
        // Impersonate any token it gets a handle to: the usual way to SYSTEM.
        "SeImpersonatePrivilege",
        // Get an impersonation token of another user in the same session.
        "SeDelegateSessionUserImpersonatePrivilege",
        // Make a token from nothing.
        "SeCreateTokenPrivilege",
        // Load a driver: code in the kernel.
        "SeLoadDriverPrivilege",
        // Open a volume raw: read and write every file on it.
        "SeManageVolumePrivilege",
        // Change the integrity labels of objects it does not own.
        "SeRelabelPrivilege",
        // Manage the security log: clear the evidence.
        "SeSecurityPrivilege",
        // Change firmware variables: code before the operating system.
        "SeSystemEnvironmentPrivilege",
        // Read the stored credentials of other accounts as a trusted caller.
        "SeTrustedCredManAccessPrivilege",
        // Read every object of the directory whatever its access list.
        "SeSyncAgentPrivilege",
        // Mark accounts as trusted for delegation in the directory.
        "SeEnableDelegationPrivilege",
    ];

    /// One line of `whoami /fo csv` as its fields, or nothing for a line that is not one.
    fn fields(line: &str) -> Option<Vec<&str>> {
        let inner = line.trim().strip_prefix('"')?.strip_suffix('"')?;
        Some(inner.split("\",\"").collect())
    }

    fn is_sid(field: &str) -> bool {
        field.strip_prefix("S-1-").is_some_and(|rest| {
            rest.split('-')
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        })
    }

    fn is_privilege(field: &str) -> bool {
        field.len() > "SePrivilege".len()
            && field.starts_with("Se")
            && field.ends_with("Privilege")
            && field.bytes().all(|byte| byte.is_ascii_alphabetic())
    }

    /// A token that could not be read: counted as privileged, so that the check fails
    /// closed.
    pub(super) fn unreadable(reason: &str) -> Privilege {
        Privilege::Unreadable {
            why: format!("its token could not be read ({reason})"),
        }
    }

    /// Classifies the output of `whoami /user /groups /priv /fo csv /nh`.
    pub(super) fn classify(output: &str) -> Privilege {
        let rows: Vec<Vec<&str>> = output.lines().filter_map(fields).collect();
        // The user's row comes first and has two fields: the name and the SID.
        let Some((user_name, user)) = rows
            .first()
            .filter(|row| row.len() == 2 && is_sid(row[1]))
            .map(|row| (row[0], row[1]))
        else {
            return unreadable("whoami printed no user");
        };
        let sids: Vec<&str> = rows
            .iter()
            .flatten()
            .copied()
            .filter(|field| is_sid(field))
            .collect();
        let mut labels: Vec<u32> = sids
            .iter()
            .filter_map(|sid| sid.strip_prefix("S-1-16-"))
            .filter_map(|rid| rid.parse().ok())
            .collect();
        // The same label printed twice is one label; two different labels are not read.
        labels.sort_unstable();
        labels.dedup();
        let [label] = labels[..] else {
            return unreadable("whoami printed no single integrity label");
        };
        let held: Vec<&str> = rows
            .iter()
            .flatten()
            .copied()
            .filter(|field| is_privilege(field))
            .collect();
        // Every token holds SeChangeNotifyPrivilege at least: no privilege means whoami did
        // not print the privileges.
        if held.is_empty() {
            return unreadable("whoami printed no privileges");
        }
        if user == SYSTEM {
            return Privilege::Privileged {
                why: "it runs as SYSTEM".to_owned(),
                advice: None,
            };
        }
        if label >= HIGH_INTEGRITY && sids.contains(&ADMINISTRATORS) {
            return Privilege::Privileged {
                why: "its token is an elevated member of Administrators".to_owned(),
                advice: None,
            };
        }
        let beyond: Vec<&str> = BEYOND_THE_ACCOUNT
            .iter()
            .copied()
            .filter(|privilege| held.contains(privilege))
            .collect();
        if beyond.is_empty() {
            return Privilege::Unprivileged;
        }
        let why = format!("its token holds {}", beyond.join(", "));
        let advice = (sids.contains(&SERVICE) && user.starts_with(VIRTUAL_ACCOUNT)).then(|| {
            let service = user_name.rsplit('\\').next().unwrap_or("<service>");
            format!(
                "a Tenko service keeps SeChangeNotifyPrivilege alone: from an elevated prompt \
                 run `sc.exe privs {service} SeChangeNotifyPrivilege` and restart the service, \
                 or install it with `tenko service install`, which narrows it"
            )
        });
        Privilege::Privileged { why, advice }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use clap::Parser as _;

    use super::*;

    /// Facts built by hand: who runs, who owns what.
    struct Fixed {
        privileged: Privilege,
        exe: PathBuf,
        owners: BTreeMap<PathBuf, Owner>,
        /// Paths whose owner cannot be read.
        unreadable: Vec<PathBuf>,
    }

    impl Facts for Fixed {
        fn privilege(&self) -> Privilege {
            self.privileged.clone()
        }

        fn owner(&self, path: &Path) -> Result<Option<Owner>, String> {
            if self.unreadable.iter().any(|unreadable| unreadable == path) {
                return Err("access denied".to_owned());
            }
            Ok(self.owners.get(path).cloned())
        }

        fn exe(&self) -> Option<PathBuf> {
            Some(self.exe.clone())
        }
    }

    fn root() -> Owner {
        Owner {
            id: "0".to_owned(),
            name: Some("root".to_owned()),
            privileged: true,
        }
    }

    fn account() -> Owner {
        Owner {
            id: "998".to_owned(),
            name: Some("tenko".to_owned()),
            privileged: false,
        }
    }

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("tenko").chain(args.iter().copied()))
            .expect("valid arguments")
    }

    fn arguments(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    /// A data directory that exists, so that the configuration resolves to it.
    fn data_dir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("dir");
        let data = dir.path().join("data");
        std::fs::create_dir(&data).expect("data dir");
        // The absolute, resolved form the configuration reports.
        let data = std::path::absolute(&data).expect("absolute");
        (dir, data)
    }

    /// `Some(true)`: privileged; `Some(false)`: not; `None`: not known.
    fn privilege(privileged: Option<bool>) -> Privilege {
        match privileged {
            Some(true) => Privilege::Privileged {
                why: "the test says so".to_owned(),
                advice: None,
            },
            Some(false) => Privilege::Unprivileged,
            None => Privilege::Unknown,
        }
    }

    fn facts(privileged: Option<bool>, exe_owner: Owner, data: &Path, owner: Owner) -> Fixed {
        let exe = PathBuf::from("/var/lib/tenko/updates/0.0.12/tenko");
        Fixed {
            privileged: privilege(privileged),
            owners: BTreeMap::from([(exe.clone(), exe_owner), (data.to_path_buf(), owner)]),
            unreadable: Vec::new(),
            exe,
        }
    }

    #[test]
    fn root_over_the_accounts_data_directory_is_refused_with_the_runuser_line() {
        let (_dir, data) = data_dir();
        let data_arg = data.to_str().expect("UTF-8");
        let args = ["backup", "restore", "a backup.tkbk", "--data-dir", data_arg];
        let cli = parse(&args);
        let refusal = check(
            &cli,
            &facts(Some(true), root(), &data, account()),
            &arguments(&args),
        )
        .expect("refused");
        assert_eq!(refusal.command, "backup restore");
        assert_eq!(refusal.path, data);
        assert!(!refusal.binary);
        assert_eq!(refusal.owner, Ok(account()));
        assert_eq!(
            refusal.as_owner(),
            format!(
                "runuser -u tenko -- tenko backup restore 'a backup.tkbk' --data-dir {}",
                shell_word(data_arg)
            )
        );
        let line = refusal.to_string();
        assert!(
            line.starts_with("tenko backup restore: [exec.unsafe_owner] "),
            "{line}"
        );
        assert!(line.contains("tenko (998)"), "{line}");
        assert_eq!(line.lines().count(), 1, "{line}");
        #[cfg(unix)]
        assert!(line.contains(&refusal.as_owner()), "{line}");
    }

    #[test]
    fn the_offline_unlock_runs_as_the_account_never_as_root_over_its_files() {
        let (_dir, data) = data_dir();
        let data_arg = data.to_str().expect("UTF-8");
        let args = ["user", "unlock", "admin", "--data-dir", data_arg];
        let cli = parse(&args);
        let refusal = check(
            &cli,
            &facts(Some(true), root(), &data, account()),
            &arguments(&args),
        )
        .expect("refused as root");
        assert_eq!(refusal.command, "user unlock");
        assert_eq!(refusal.path, data);
        assert_eq!(
            refusal.as_owner(),
            format!(
                "runuser -u tenko -- tenko user unlock admin --data-dir {}",
                shell_word(data_arg)
            )
        );
        // The account itself runs it.
        assert!(
            check(
                &cli,
                &facts(Some(false), account(), &data, account()),
                &arguments(&args)
            )
            .is_none()
        );
    }

    #[test]
    fn a_binary_of_another_account_is_refused_before_the_data_directory() {
        let (_dir, data) = data_dir();
        let args = ["kek", "rotate", "--data-dir", data.to_str().expect("UTF-8")];
        let cli = parse(&args);
        let refusal = check(
            &cli,
            &facts(Some(true), account(), &data, root()),
            &arguments(&args),
        )
        .expect("refused");
        assert!(refusal.binary);
        assert_eq!(
            refusal.path,
            Path::new("/var/lib/tenko/updates/0.0.12/tenko")
        );
        assert!(refusal.to_string().contains("this executable"));
    }

    #[test]
    fn root_over_roots_own_files_and_other_accounts_run() {
        let (_dir, data) = data_dir();
        let args = [
            "upgrade",
            "layout",
            "--data-dir",
            data.to_str().expect("UTF-8"),
        ];
        let cli = parse(&args);
        assert!(
            check(
                &cli,
                &facts(Some(true), root(), &data, root()),
                &arguments(&args)
            )
            .is_none(),
            "root over root-owned files"
        );
        assert!(
            check(
                &cli,
                &facts(Some(false), account(), &data, account()),
                &arguments(&args)
            )
            .is_none(),
            "the account over its own files"
        );
        assert!(
            check(
                &cli,
                &facts(None, account(), &data, account()),
                &arguments(&args)
            )
            .is_none(),
            "unknown privileges do not refuse"
        );
    }

    #[test]
    fn every_command_over_the_data_directory_is_covered_and_nothing_else() {
        let (_dir, data) = data_dir();
        let data_arg = data.to_str().expect("UTF-8");
        let covered: [&[&str]; 21] = [
            &["serve", "--data-dir", data_arg],
            &["user", "unlock", "admin", "--data-dir", data_arg],
            &[
                "node",
                "enroll",
                "--controller",
                "https://ddi.example.test:8443",
                "--data-dir",
                data_arg,
            ],
            &["node", "status", "--data-dir", data_arg],
            &["node", "renew", "--data-dir", data_arg],
            &[
                "node",
                "inject",
                "--file",
                "batch.json",
                "--data-dir",
                data_arg,
            ],
            &["node", "scan", "status", "--data-dir", data_arg],
            &["node", "scan", "run", "icmp", "--data-dir", data_arg],
            &["node", "scan", "stop", "--data-dir", data_arg],
            &["node", "scan", "resume", "--data-dir", data_arg],
            &[
                "cluster",
                "join",
                "--controller",
                "https://ddi.example.test:8443",
                "--address",
                "192.0.2.10",
                "--data-dir",
                data_arg,
            ],
            &["setup", "token", "--data-dir", data_arg],
            &["plugin", "list", "--data-dir", data_arg],
            &["plugin", "test", data_arg],
            &["backup", "restore", "f.tkbk", "--data-dir", data_arg],
            &[
                "backup",
                "restore",
                "f.tkbk",
                "--dry-run",
                "--data-dir",
                data_arg,
            ],
            &["backup", "create", "--data-dir", data_arg],
            &["backup", "verify", "f.tkbk", "--work-dir", data_arg],
            &["kek", "rotate", "--data-dir", data_arg],
            &["upgrade", "check", "--data-dir", data_arg],
            &["upgrade", "layout", "--data-dir", data_arg],
        ];
        for args in covered {
            let cli = parse(args);
            let paths = guarded_paths(&cli).expect("covered");
            assert!(paths.contains(&data), "{args:?}: {paths:?}");
            assert!(
                check(
                    &cli,
                    &facts(Some(true), root(), &data, account()),
                    &arguments(args)
                )
                .is_some(),
                "{args:?}"
            );
        }
    }

    #[test]
    fn the_commands_that_touch_nothing_of_the_account_are_not_covered() {
        let (_dir, data) = data_dir();
        let data_arg = data.to_str().expect("UTF-8");
        let not_covered: [&[&str]; 10] = [
            &["backup", "create", "--url", "https://ddi.example.test:8443"],
            &["backup", "keygen", "--out", "k"],
            &["upgrade", "format"],
            &["config", "check", "--data-dir", data_arg],
            &["roles", "list"],
            &["health"],
            &["node", "enroll-token", "--roles", "probe"],
            &["cluster", "status"],
            &["plugin", "run", "sample"],
            &[
                "setup",
                "--admin",
                "admin",
                "--host-name",
                "ddi.example.test",
            ],
        ];
        for args in not_covered {
            let cli = parse(args);
            assert!(guarded_paths(&cli).is_none(), "{args:?}");
            let facts = facts(Some(true), account(), &data, account());
            // Windows: an uncovered command is not checked at all.
            assert!(
                check_with(&cli, &facts, &arguments(args), false).is_none(),
                "{args:?}"
            );
            // Unix: the binary is checked for every command, and nothing else.
            let refusal = check_with(&cli, &facts, &arguments(args), true)
                .unwrap_or_else(|| panic!("{args:?}: the binary is the account's"));
            assert!(refusal.binary, "{args:?}");
            assert!(
                check_with(
                    &cli,
                    &self::facts(Some(true), root(), &data, account()),
                    &arguments(args),
                    true
                )
                .is_none(),
                "{args:?}"
            );
        }
    }

    /// Root over the account's data directory does not serve; root over its own files, as
    /// in a container that runs as root, does.
    #[test]
    fn root_serves_only_over_its_own_files() {
        let (_dir, data) = data_dir();
        let data_arg = data.to_str().expect("UTF-8");
        let args = ["serve", "--data-dir", data_arg];
        let cli = parse(&args);
        let refusal = check(
            &cli,
            &facts(Some(true), root(), &data, account()),
            &arguments(&args),
        )
        .expect("refused");
        assert_eq!(refusal.path, data);
        let line = refusal.to_string();
        #[cfg(unix)]
        assert!(
            line.contains("`systemctl start tenko`")
                && line.contains(&format!(
                    "runuser -u tenko -- tenko serve --data-dir {}",
                    shell_word(data_arg)
                )),
            "{line}"
        );
        #[cfg(windows)]
        assert!(line.contains("`tenko service start`"), "{line}");
        assert!(
            check(
                &cli,
                &facts(Some(true), root(), &data, root()),
                &arguments(&args)
            )
            .is_none()
        );
    }

    #[test]
    fn an_offline_create_checks_where_the_backup_goes() {
        let (_dir, data) = data_dir();
        let out = data.parent().expect("parent").join("out");
        std::fs::create_dir(&out).expect("out dir");
        let args = [
            "backup",
            "create",
            "--data-dir",
            data.to_str().expect("UTF-8"),
            "--out",
            out.to_str().expect("UTF-8"),
        ];
        let cli = parse(&args);
        let paths = guarded_paths(&cli).expect("covered");
        assert_eq!(paths, vec![out.clone(), data.clone()]);
        let mut facts = facts(Some(true), root(), &data, root());
        facts.owners.insert(out.clone(), account());
        let refusal = check(&cli, &facts, &arguments(&args)).expect("refused");
        assert_eq!(refusal.path, out);
    }

    /// A configuration file that does not load leaves neither the data directory a command
    /// would create it beside (`cluster join`) nor the one `--data-dir` names unchecked.
    #[test]
    fn a_configuration_that_does_not_load_still_checks_the_data_directory() {
        let (_dir, data) = data_dir();
        let data_arg = data.to_str().expect("UTF-8");
        let args = [
            "cluster",
            "join",
            "--config",
            "/no/such/tenko.toml",
            "--controller",
            "https://ddi.example.test:8443",
            "--address",
            "192.0.2.10",
            "--data-dir",
            data_arg,
        ];
        let cli = parse(&args);
        assert_eq!(guarded_paths(&cli), Some(vec![data.clone()]));
        let refusal = check(
            &cli,
            &facts(Some(true), root(), &data, account()),
            &arguments(&args),
        )
        .expect("refused");
        assert_eq!(refusal.path, data);
    }

    /// A directory that does not exist yet is decided by the nearest one that does, where
    /// the command would create it.
    #[test]
    fn a_missing_directory_is_decided_by_its_nearest_existing_ancestor() {
        let (_dir, data) = data_dir();
        let below = data.join("not-yet").join("data");
        let args = ["serve", "--data-dir", below.to_str().expect("UTF-8")];
        let cli = parse(&args);
        let refusal = check(
            &cli,
            &facts(Some(true), root(), &data, account()),
            &arguments(&args),
        )
        .expect("refused");
        assert_eq!(refusal.path, data);
        assert!(!refusal.binary);
    }

    #[test]
    fn a_configuration_that_does_not_resolve_still_checks_the_binary() {
        let args = [
            "backup",
            "restore",
            "f.tkbk",
            "--config",
            "/no/such/tenko.toml",
        ];
        let cli = parse(&args);
        let facts = Fixed {
            privileged: privilege(Some(true)),
            exe: PathBuf::from("/opt/tenko/cli/tenko"),
            owners: BTreeMap::from([(PathBuf::from("/opt/tenko/cli/tenko"), account())]),
            unreadable: Vec::new(),
        };
        assert!(check(&cli, &facts, &arguments(&args)).is_some());
    }

    /// `/proc/self/status` of a process: root, the service with the capabilities its unit
    /// grants, a process holding a capability beyond its account, and a status that cannot be
    /// read, which counts as privileged.
    #[test]
    fn the_linux_status_decides_by_the_effective_uid_and_capabilities() {
        let status = |uid: &str, caps: &str| {
            format!(
                "Name:\ttenko\nUid:\t1000\t{uid}\t{uid}\t{uid}\nCapInh:\t0000000000000000\n\
                 CapEff:\t{caps}\n"
            )
        };
        assert_eq!(linux::effective_uid(&status("0", "0")), Some(0));
        assert_eq!(
            linux::classify(&status("0", "0000000000000000")),
            Privilege::Privileged {
                why: "the effective uid is 0".to_owned(),
                advice: None
            }
        );
        // CAP_NET_BIND_SERVICE (10) and CAP_NET_RAW (13): the service's own.
        assert_eq!(
            linux::classify(&status("998", "0000000000002400")),
            Privilege::Unprivileged
        );
        // CAP_DAC_OVERRIDE (1) and CAP_SYS_ADMIN (21).
        assert_eq!(
            linux::classify(&status("998", "0000000000200002")),
            Privilege::Privileged {
                why: "its effective capabilities hold CAP_DAC_OVERRIDE, CAP_SYS_ADMIN".to_owned(),
                advice: None
            }
        );
        for unread in [
            "Name:\ttenko\n".to_owned(),
            "Uid:\t998\t998\t998\t998\n".to_owned(),
            status("998", "not-hex"),
        ] {
            let privilege = linux::classify(&unread);
            let Privilege::Unreadable { why } = &privilege else {
                panic!("{unread:?} is read as {privilege:?}");
            };
            assert!(
                why.starts_with("/proc/self/status could not be read"),
                "{why}"
            );
        }
    }

    #[test]
    fn shell_words_are_quoted_when_needed() {
        assert_eq!(shell_word("plain-file.tkbk"), "plain-file.tkbk");
        assert_eq!(shell_word("/etc/tenko/tenko.toml"), "/etc/tenko/tenko.toml");
        assert_eq!(shell_word("with space"), "'with space'");
        assert_eq!(shell_word("it's"), "'it'\\''s'");
        assert_eq!(shell_word(""), "''");
        assert_eq!(shell_word("$HOME"), "'$HOME'");
    }

    #[cfg(unix)]
    #[test]
    fn the_effective_uid_and_the_account_name_are_read_from_the_host_files() {
        let passwd =
            "root:x:0:0:root:/root:/bin/bash\ntenko:x:998:998::/var/lib/tenko:/usr/sbin/nologin\n";
        assert_eq!(host::account_name(passwd, 998).as_deref(), Some("tenko"));
        assert_eq!(host::account_name(passwd, 0).as_deref(), Some("root"));
        assert_eq!(host::account_name(passwd, 7), None);
        // The real files: this process owns what it created.
        let dir = tempfile::tempdir().expect("dir");
        let owner = Host.owner(dir.path()).expect("readable").expect("owner");
        assert_eq!(owner.privileged, owner.id == "0");
        assert_eq!(Host.owner(&dir.path().join("missing")), Ok(None));
    }

    // The outputs of `whoami /user /groups /priv /fo csv /nh` below keep the shape and the
    // well-known SIDs of real tokens; where a sample is not a real token, account names and
    // the SIDs of accounts are placeholders.

    /// The Windows service as `tenko service install` and the MSI set it up: a virtual
    /// account whose token keeps `SeChangeNotifyPrivilege` alone, with the high label the
    /// Service Control Manager gives a service. The real token of the smoke's service on a
    /// hosted runner (2026-11-11), read from the running service with `OpenProcessToken` by
    /// `deploy/windows/smoke.ps1` and printed in whoami's shape, the attributes as numbers.
    /// The user's SID is the one Windows derives from the service name `tenko-smoke`.
    const NARROWED_SERVICE: &str = r#""nt service\tenko-smoke","S-1-5-80-3479874966-2534006701-744376333-3032499961-207429074"

"Everyone","Group","S-1-1-0","0x7"
"BUILTIN\Users","Group","S-1-5-32-545","0x7"
"NT AUTHORITY\SERVICE","Group","S-1-5-6","0x7"
"CONSOLE LOGON","Group","S-1-2-1","0x7"
"NT AUTHORITY\Authenticated Users","Group","S-1-5-11","0x7"
"NT AUTHORITY\This Organization","Group","S-1-5-15","0x7"
"LOCAL","Group","S-1-2-0","0x7"
"S-1-5-5-0-4971674","Group","S-1-5-5-0-4971674","0xc0000007"
"NT SERVICE\ALL SERVICES","Group","S-1-5-80-0","0x7"
"S-1-16-12288","Label","S-1-16-12288",""

"SeChangeNotifyPrivilege","","Enabled"
"#;

    /// A service created by hand (`sc create`) under a virtual account: the token keeps the
    /// default privileges of a service, `SeImpersonatePrivilege` among them.
    const UNNARROWED_SERVICE: &str = r#""nt service\tenko-hand","S-1-5-80-6666666666-7777777777-8888888888-9999999999-111111111"

"Mandatory Label\High Mandatory Level","Label","S-1-16-12288",""
"Everyone","Well-known group","S-1-1-0","Mandatory group, Enabled by default, Enabled group"
"BUILTIN\Users","Alias","S-1-5-32-545","Mandatory group, Enabled by default, Enabled group"
"NT AUTHORITY\SERVICE","Well-known group","S-1-5-6","Mandatory group, Enabled by default, Enabled group"
"NT AUTHORITY\Authenticated Users","Well-known group","S-1-5-11","Mandatory group, Enabled by default, Enabled group"
"LOCAL","Well-known group","S-1-2-0","Mandatory group, Enabled by default, Enabled group"

"SeAssignPrimaryTokenPrivilege","Replace a process level token","Disabled"
"SeIncreaseQuotaPrivilege","Adjust memory quotas for a process","Disabled"
"SeChangeNotifyPrivilege","Bypass traverse checking","Enabled"
"SeCreateGlobalPrivilege","Create global objects","Enabled"
"SeImpersonatePrivilege","Impersonate a client after authentication","Enabled"
"#;

    /// An administrator in an elevated prompt: the token of the Windows service smoke on a
    /// hosted runner (2026-11-11), as `whoami` printed it; the machine name is replaced.
    const ELEVATED_ADMINISTRATOR: &str = r#""runnervmm7ud1\runneradmin","S-1-5-21-3289802278-1561746829-1498425070-500"

"Everyone","Well-known group","S-1-1-0","Mandatory group, Enabled by default, Enabled group"
"NT AUTHORITY\Local account and member of Administrators group","Well-known group","S-1-5-114","Mandatory group, Enabled by default, Enabled group"
"BUILTIN\Administrators","Alias","S-1-5-32-544","Mandatory group, Enabled by default, Enabled group, Group owner"
"BUILTIN\Users","Alias","S-1-5-32-545","Mandatory group, Enabled by default, Enabled group"
"NT AUTHORITY\INTERACTIVE","Well-known group","S-1-5-4","Mandatory group, Enabled by default, Enabled group"
"CONSOLE LOGON","Well-known group","S-1-2-1","Mandatory group, Enabled by default, Enabled group"
"NT AUTHORITY\Authenticated Users","Well-known group","S-1-5-11","Mandatory group, Enabled by default, Enabled group"
"NT AUTHORITY\This Organization","Well-known group","S-1-5-15","Mandatory group, Enabled by default, Enabled group"
"NT AUTHORITY\Local account","Well-known group","S-1-5-113","Mandatory group, Enabled by default, Enabled group"
"LOCAL","Well-known group","S-1-2-0","Mandatory group, Enabled by default, Enabled group"
"NT AUTHORITY\NTLM Authentication","Well-known group","S-1-5-64-10","Mandatory group, Enabled by default, Enabled group"
"Mandatory Label\High Mandatory Level","Label","S-1-16-12288",""

"SeIncreaseQuotaPrivilege","Adjust memory quotas for a process","Disabled"
"SeSecurityPrivilege","Manage auditing and security log","Disabled"
"SeTakeOwnershipPrivilege","Take ownership of files or other objects","Disabled"
"SeLoadDriverPrivilege","Load and unload device drivers","Disabled"
"SeSystemProfilePrivilege","Profile system performance","Disabled"
"SeSystemtimePrivilege","Change the system time","Disabled"
"SeProfileSingleProcessPrivilege","Profile single process","Disabled"
"SeIncreaseBasePriorityPrivilege","Increase scheduling priority","Disabled"
"SeCreatePagefilePrivilege","Create a pagefile","Disabled"
"SeBackupPrivilege","Back up files and directories","Disabled"
"SeRestorePrivilege","Restore files and directories","Disabled"
"SeShutdownPrivilege","Shut down the system","Disabled"
"SeDebugPrivilege","Debug programs","Enabled"
"SeSystemEnvironmentPrivilege","Modify firmware environment values","Disabled"
"SeChangeNotifyPrivilege","Bypass traverse checking","Enabled"
"SeRemoteShutdownPrivilege","Force shutdown from a remote system","Disabled"
"SeUndockPrivilege","Remove computer from docking station","Disabled"
"SeManageVolumePrivilege","Perform volume maintenance tasks","Disabled"
"SeImpersonatePrivilege","Impersonate a client after authentication","Enabled"
"SeCreateGlobalPrivilege","Create global objects","Enabled"
"SeIncreaseWorkingSetPrivilege","Increase a process working set","Disabled"
"SeTimeZonePrivilege","Change the time zone","Disabled"
"SeCreateSymbolicLinkPrivilege","Create symbolic links","Disabled"
"SeDelegateSessionUserImpersonatePrivilege","Obtain an impersonation token for another user in the same session","Disabled"
"#;

    /// The same administrator without elevation, on a Swedish Windows: Administrators is a
    /// deny-only group, the label is medium, the names and descriptions are translated.
    const FILTERED_ADMINISTRATOR_SWEDISH: &str = r#""exempel\admin","S-1-5-21-1000000001-1000000002-1000000003-1001"

"Alla","Well-known group","S-1-1-0","Mandatory group, Enabled by default, Enabled group"
"BUILTIN\Administratörer","Alias","S-1-5-32-544","Group used for deny only"
"BUILTIN\Användare","Alias","S-1-5-32-545","Mandatory group, Enabled by default, Enabled group"
"NT instans\Interaktiv","Well-known group","S-1-5-4","Mandatory group, Enabled by default, Enabled group"
"NT instans\Autentiserade användare","Well-known group","S-1-5-11","Mandatory group, Enabled by default, Enabled group"
"Obligatorisk etikett\Medelhög obligatorisk nivå","Label","S-1-16-8192",""

"SeShutdownPrivilege","Avsluta datorn","Disabled"
"SeChangeNotifyPrivilege","Kringgå bläddringskontroll","Enabled"
"SeUndockPrivilege","Ta bort datorn från dockningsstationen","Disabled"
"SeIncreaseWorkingSetPrivilege","Öka allokerat minne för en process","Disabled"
"SeTimeZonePrivilege","Ändra tidszon","Disabled"
"#;

    /// `LocalSystem`.
    const SYSTEM: &str = r#""nt authority\system","S-1-5-18"

"BUILTIN\Administrators","Alias","S-1-5-32-544","Enabled by default, Enabled group, Group owner"
"Everyone","Well-known group","S-1-1-0","Mandatory group, Enabled by default, Enabled group"
"NT AUTHORITY\Authenticated Users","Well-known group","S-1-5-11","Mandatory group, Enabled by default, Enabled group"
"Mandatory Label\System Mandatory Level","Label","S-1-16-16384",""

"SeAssignPrimaryTokenPrivilege","Replace a process level token","Disabled"
"SeTcbPrivilege","Act as part of the operating system","Enabled"
"SeChangeNotifyPrivilege","Bypass traverse checking","Enabled"
"#;

    /// A member of Backup Operators in an elevated prompt: not an administrator, and still
    /// able to read and write every file.
    const ELEVATED_BACKUP_OPERATOR: &str = r#""example\backup","S-1-5-21-1000000001-1000000002-1000000003-1002"

"BUILTIN\Backup Operators","Alias","S-1-5-32-551","Mandatory group, Enabled by default, Enabled group"
"BUILTIN\Users","Alias","S-1-5-32-545","Mandatory group, Enabled by default, Enabled group"
"Mandatory Label\High Mandatory Level","Label","S-1-16-12288",""

"SeBackupPrivilege","Back up files and directories","Disabled"
"SeRestorePrivilege","Restore files and directories","Disabled"
"SeChangeNotifyPrivilege","Bypass traverse checking","Enabled"
"#;

    /// The lines of `text` that `keep` accepts, each with its line end.
    fn lines_where(text: &str, keep: impl Fn(&str) -> bool) -> String {
        text.lines()
            .filter(|line| keep(line))
            .flat_map(|line| {
                [
                    line, "
",
                ]
            })
            .collect()
    }

    /// Whether the check refuses a process with `privilege`: a privileged one, and one whose
    /// privileges could not be read.
    fn is_privileged(privilege: &Privilege) -> bool {
        matches!(
            privilege,
            Privilege::Privileged { .. } | Privilege::Unreadable { .. }
        )
    }

    #[test]
    fn the_narrowed_service_is_not_privileged_whatever_its_label() {
        assert_eq!(token::classify(NARROWED_SERVICE), Privilege::Unprivileged);
        let system_label = NARROWED_SERVICE.replace(
            r#""S-1-16-12288","Label","S-1-16-12288",""#,
            r#""S-1-16-16384","Label","S-1-16-16384",""#,
        );
        assert_ne!(system_label, NARROWED_SERVICE);
        assert_eq!(token::classify(&system_label), Privilege::Unprivileged);
    }

    #[test]
    fn a_service_that_keeps_its_default_privileges_is_privileged_and_told_what_to_narrow() {
        let Privilege::Privileged { why, advice } = token::classify(UNNARROWED_SERVICE) else {
            panic!("a service holding SeImpersonatePrivilege is privileged");
        };
        assert_eq!(
            why,
            "its token holds SeAssignPrimaryTokenPrivilege, SeImpersonatePrivilege"
        );
        let advice = advice.expect("advice for a service");
        assert!(
            advice.contains("sc.exe privs tenko-hand SeChangeNotifyPrivilege"),
            "{advice}"
        );
        assert!(advice.contains("tenko service install"), "{advice}");
    }

    #[test]
    fn administrators_system_and_backup_operators_are_privileged() {
        for (output, why) in [
            (
                ELEVATED_ADMINISTRATOR,
                "its token is an elevated member of Administrators",
            ),
            (SYSTEM, "it runs as SYSTEM"),
            (
                ELEVATED_BACKUP_OPERATOR,
                "its token holds SeBackupPrivilege, SeRestorePrivilege",
            ),
        ] {
            assert_eq!(
                token::classify(output),
                Privilege::Privileged {
                    why: why.to_owned(),
                    advice: None
                }
            );
        }
        // An elevated administrator stays privileged with every privilege removed.
        let stripped = lines_where(ELEVATED_ADMINISTRATOR, |line| !line.starts_with("\"Se"));
        assert!(is_privileged(&token::classify(&stripped)));
    }

    #[test]
    fn a_filtered_administrator_on_a_translated_windows_is_not_privileged() {
        assert_eq!(
            token::classify(FILTERED_ADMINISTRATOR_SWEDISH),
            Privilege::Unprivileged
        );
    }

    #[test]
    fn a_token_that_cannot_be_read_counts_as_privileged() {
        let no_label = lines_where(NARROWED_SERVICE, |line| !line.contains("S-1-16-"));
        let two_labels = format!(
            "{NARROWED_SERVICE}\"Mandatory Label\\Low Mandatory Level\",\"Label\",\"S-1-16-4096\",\"\"\n"
        );
        let no_user = lines_where(NARROWED_SERVICE, |line| !line.contains("S-1-5-80-"));
        let no_privileges = lines_where(NARROWED_SERVICE, |line| !line.starts_with("\"Se"));
        for output in [
            "",
            "ERROR: Access is denied.\n",
            no_label.as_str(),
            two_labels.as_str(),
            no_user.as_str(),
            no_privileges.as_str(),
        ] {
            let privilege = token::classify(output);
            let Privilege::Unreadable { why } = &privilege else {
                panic!("{output:?} is read as {privilege:?}");
            };
            assert!(why.starts_with("its token could not be read"), "{why}");
        }
    }

    /// A token read that timed out refuses, and the line says that the token could not be
    /// read in time, not that the caller is privileged.
    #[test]
    fn a_token_read_that_timed_out_refuses_and_says_so() {
        let (_dir, data) = data_dir();
        let args = ["serve", "--data-dir", data.to_str().expect("UTF-8")];
        let cli = parse(&args);
        let mut facts = facts(None, account(), &data, account());
        facts.privileged = token::unreadable(
            "C:\\Windows\\System32\\whoami.exe did not end within 30 s and was stopped; run \
             the command again",
        );
        let refusal = check(&cli, &facts, &arguments(&args)).expect("refused");
        assert!(refusal.unread);
        let line = refusal.to_string();
        assert!(
            line.contains("refusing to run because its token could not be read (")
                && line.contains("did not end within 30 s"),
            "{line}"
        );
        assert!(!line.contains("privileged token ("), "{line}");
        assert_eq!(line.lines().count(), 1, "{line}");
    }

    /// The privileges a token holds that do not reach beyond its account, and why: these
    /// never make a token privileged on their own.
    #[test]
    fn the_privileges_left_out_reach_no_further_than_the_account() {
        let left_out = [
            // Creates symbolic links; following one still checks the target's access list,
            // and Developer Mode gives it to every user.
            "SeCreateSymbolicLinkPrivilege",
            // Creates named objects in the global namespace; opens nothing of another
            // account's. Every service holds it by default.
            "SeCreateGlobalPrivilege",
            // Sets the memory quotas of a process; starting a process as another account
            // needs SeAssignPrimaryTokenPrivilege as well, which is on the list.
            "SeIncreaseQuotaPrivilege",
            // Writes events into the security log; reads and clears nothing.
            "SeAuditPrivilege",
            // The traversal of directories: every token holds it.
            "SeChangeNotifyPrivilege",
            "SeShutdownPrivilege",
            "SeUndockPrivilege",
            "SeIncreaseWorkingSetPrivilege",
            "SeTimeZonePrivilege",
            "SeSystemtimePrivilege",
            "SeIncreaseBasePriorityPrivilege",
            "SeCreatePagefilePrivilege",
            "SeCreatePermanentPrivilege",
            "SeLockMemoryPrivilege",
            "SeProfileSingleProcessPrivilege",
            "SeSystemProfilePrivilege",
            "SeRemoteShutdownPrivilege",
            "SeMachineAccountPrivilege",
        ];
        for privilege in left_out {
            assert!(
                !token::BEYOND_THE_ACCOUNT.contains(&privilege),
                "{privilege}"
            );
            let output = NARROWED_SERVICE.replace(
                "\"SeChangeNotifyPrivilege\",\"\",\"Enabled\"",
                &format!("\"{privilege}\",\"\",\"Disabled\""),
            );
            assert_ne!(output, NARROWED_SERVICE);
            assert_eq!(
                token::classify(&output),
                Privilege::Unprivileged,
                "{privilege}"
            );
        }
        for privilege in token::BEYOND_THE_ACCOUNT {
            let output = NARROWED_SERVICE.replace(
                "\"SeChangeNotifyPrivilege\",\"\",\"Enabled\"",
                &format!("\"{privilege}\",\"\",\"Disabled\""),
            );
            assert_ne!(output, NARROWED_SERVICE);
            assert!(is_privileged(&token::classify(&output)), "{privilege}");
        }
    }

    /// The owner of what the service writes: its virtual account.
    fn service_account() -> Owner {
        Owner {
            id: "S-1-5-80-1111111111-2222222222-3333333333-4444444444-555555555".to_owned(),
            name: Some("NT SERVICE\\tenko-smoke".to_owned()),
            privileged: false,
        }
    }

    fn token_facts(output: &str, data: &Path) -> Fixed {
        let exe = PathBuf::from("C:/ProgramData/Tenko/data/updates/0.0.12/tenko.exe");
        Fixed {
            privileged: token::classify(output),
            owners: BTreeMap::from([
                (exe.clone(), service_account()),
                (data.to_path_buf(), service_account()),
            ]),
            unreadable: Vec::new(),
            exe,
        }
    }

    /// The update's dry run: the service runs the new binary's `upgrade check` over a copy of
    /// its own state, the binary and the copy both its own.
    #[test]
    fn the_narrowed_service_runs_the_dry_run_over_its_own_files() {
        let (_dir, data) = data_dir();
        let data_arg = data.to_str().expect("UTF-8");
        let args = [
            "upgrade",
            "check",
            "--data-dir",
            data_arg,
            "--disposable",
            "--node-id",
            "1",
            "--json",
        ];
        let cli = parse(&args);
        assert!(
            check(
                &cli,
                &token_facts(NARROWED_SERVICE, &data),
                &arguments(&args)
            )
            .is_none()
        );
        let refusal = check(
            &cli,
            &token_facts(UNNARROWED_SERVICE, &data),
            &arguments(&args),
        )
        .expect("an unnarrowed service is refused");
        let line = refusal.to_string();
        assert!(
            line.contains("sc.exe privs tenko-hand SeChangeNotifyPrivilege"),
            "{line}"
        );
        assert_eq!(line.lines().count(), 1, "{line}");
    }

    /// The offline commands an administrator runs from an elevated prompt over the service
    /// account's files are refused as before, and so is SYSTEM.
    #[test]
    fn an_elevated_administrator_and_system_are_still_refused_over_the_service_accounts_files() {
        let (_dir, data) = data_dir();
        let data_arg = data.to_str().expect("UTF-8");
        let commands: [&[&str]; 9] = [
            &["backup", "restore", "f.tkbk", "--data-dir", data_arg],
            &["user", "unlock", "admin", "--data-dir", data_arg],
            &["kek", "rotate", "--data-dir", data_arg],
            &["upgrade", "check", "--data-dir", data_arg],
            &["upgrade", "layout", "--data-dir", data_arg],
            &["serve", "--data-dir", data_arg],
            &["node", "renew", "--data-dir", data_arg],
            &["setup", "token", "--data-dir", data_arg],
            &[
                "cluster",
                "join",
                "--controller",
                "https://ddi.example.test:8443",
                "--address",
                "192.0.2.10",
                "--data-dir",
                data_arg,
            ],
        ];
        for output in [ELEVATED_ADMINISTRATOR, SYSTEM] {
            for args in commands {
                let cli = parse(args);
                let refusal = check(&cli, &token_facts(output, &data), &arguments(args))
                    .unwrap_or_else(|| panic!("{args:?} is refused"));
                assert!(
                    refusal.binary,
                    "the binary is the service account's: {args:?}"
                );
                assert!(refusal.advice.is_none());
                #[cfg(windows)]
                {
                    let line = refusal.to_string();
                    assert!(
                        line.contains("refusing to run with a privileged token ("),
                        "{line}"
                    );
                    let advice = if args[0] == "serve" {
                        "`tenko service start`"
                    } else {
                        "C:\\Program Files\\Tenko\\tenko.exe"
                    };
                    assert!(line.contains(advice), "{line}");
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn the_system_directory_comes_from_a_plain_system_root_only() {
        use std::ffi::OsStr;
        assert_eq!(
            host::system_dir(Some(OsStr::new("C:\\Windows"))),
            Ok(PathBuf::from("C:\\Windows\\System32"))
        );
        for root in [
            "Windows",
            "C:Windows",
            "C:\\Windows\\..\\Users\\x",
            "\\\\server\\share\\Windows",
            "\\\\?\\C:\\Windows",
            "",
        ] {
            assert!(host::system_dir(Some(OsStr::new(root))).is_err(), "{root}");
        }
        assert!(host::system_dir(None).is_err());
    }

    /// The real token of this process is read and classified: whoami.exe runs from the
    /// system directory with a cleared environment.
    #[cfg(windows)]
    #[test]
    fn the_token_of_this_process_is_read() {
        let privilege = Host.privilege();
        assert!(
            !matches!(privilege, Privilege::Unreadable { .. } | Privilege::Unknown),
            "{privilege:?}"
        );
    }

    /// A privileged process refuses a file whose owner it cannot read; an unprivileged one
    /// does not look.
    #[test]
    fn an_owner_that_cannot_be_read_refuses_a_privileged_process() {
        let (_dir, data) = data_dir();
        let args = ["kek", "rotate", "--data-dir", data.to_str().expect("UTF-8")];
        let cli = parse(&args);
        let mut facts = facts(Some(true), root(), &data, root());
        facts.unreadable.push(data.clone());
        let refusal = check(&cli, &facts, &arguments(&args)).expect("refused");
        assert_eq!(refusal.path, data);
        assert_eq!(refusal.owner, Err("access denied".to_owned()));
        let line = refusal.to_string();
        assert!(
            line.contains("has an owner that could not be read (access denied)"),
            "{line}"
        );
        facts.unreadable = vec![facts.exe.clone()];
        let refusal = check(&cli, &facts, &arguments(&args)).expect("refused");
        assert!(refusal.binary);
        facts.privileged = Privilege::Unprivileged;
        assert!(check(&cli, &facts, &arguments(&args)).is_none());
    }

    /// The tool runner fails on a missing tool, a status other than 0 and a tool over its
    /// limit, and each of these makes the token unreadable, so privileged.
    #[cfg(windows)]
    #[test]
    fn the_tool_runner_fails_on_a_missing_tool_a_bad_status_and_a_slow_tool() {
        use std::time::Duration;
        let missing = host::run_within("no-such-tool.exe", &[], Duration::from_secs(5));
        assert!(missing.is_err(), "{missing:?}");
        let status = host::run_within("cmd.exe", &["/c", "exit", "3"], Duration::from_secs(10));
        assert!(status.is_err(), "{status:?}");
        let started = std::time::Instant::now();
        let slow = host::run_within(
            "ping.exe",
            &["-n", "30", "127.0.0.1"],
            Duration::from_secs(1),
        );
        assert!(
            slow.as_ref()
                .is_err_and(|error| error.contains("did not end within 1 s")
                    && error.contains("run the command again")),
            "{slow:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(20));
        let ok = host::run_within("cmd.exe", &["/c", "echo", "fine"], Duration::from_secs(10));
        assert_eq!(ok.as_deref().map(str::trim), Ok("fine"));
    }

    /// Windows PowerShell started by the guard sees a module path of the system's module
    /// directories alone: not the user's Documents folder, which it adds itself when the
    /// variable is missing, and not what the caller's environment names.
    #[cfg(windows)]
    #[test]
    fn windows_powershell_gets_the_system_module_path_alone() {
        let printed = host::run_within(
            r"WindowsPowerShell\v1.0\powershell.exe",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$env:PSModulePath",
            ],
            std::time::Duration::from_secs(30),
        )
        .expect("powershell.exe runs");
        let root = std::env::var("SystemRoot").expect("SystemRoot");
        let program_files = std::env::var("ProgramFiles").expect("ProgramFiles");
        let allowed = [
            format!(r"{root}\System32\WindowsPowerShell\v1.0\Modules"),
            format!(r"{program_files}\WindowsPowerShell\Modules"),
        ];
        let entries: Vec<&str> = printed
            .trim()
            .split(';')
            .filter(|entry| !entry.is_empty())
            .collect();
        assert!(!entries.is_empty(), "{printed}");
        for entry in entries {
            assert!(
                allowed
                    .iter()
                    .any(|dir| dir.eq_ignore_ascii_case(entry.trim_end_matches('\\'))),
                "{entry} in {printed}"
            );
        }
    }

    /// The owner of a file and of a directory is read as the guard reads it; a missing
    /// path has none, and quotation marks, `$` and backticks in the name are taken
    /// literally.
    #[cfg(windows)]
    #[test]
    fn the_owner_of_a_file_and_of_a_directory_is_read() {
        let root = std::env::var("SystemRoot").expect("SystemRoot");
        let whoami = Path::new(&root).join("System32").join("whoami.exe");
        let owner = Host
            .owner(&whoami)
            .expect("readable")
            .expect("whoami.exe exists");
        assert!(owner.privileged, "{owner:?}");
        assert_eq!(
            owner.id,
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        );
        assert!(owner.name.is_some(), "{owner:?}");
        // PowerShell takes the typographic quotation marks for `'` as well.
        let dir = tempfile::tempdir().expect("dir");
        for name in [
            "it's data",
            "Per\u{2019}s \u{2018}data\u{201a}\u{201b} $x `y",
        ] {
            let quoted = dir.path().join(name);
            std::fs::create_dir(&quoted).expect("dir");
            let owner = Host.owner(&quoted).expect("readable").expect("exists");
            assert!(owner.id.starts_with("S-1-"), "{name}: {owner:?}");
            assert_eq!(Host.owner(&quoted.join("missing")), Ok(None));
        }
    }

    /// The guard's tools read the token and the owner of a directory; also run by
    /// [`the_tools_ignore_a_module_planted_in_the_callers_module_path`] under a planted
    /// module path.
    #[cfg(windows)]
    #[test]
    fn the_guard_reads_token_and_owner_under_a_planted_module_path() {
        let privilege = Host.privilege();
        assert!(
            !matches!(privilege, Privilege::Unreadable { .. }),
            "{privilege:?}"
        );
        let dir = tempfile::tempdir().expect("dir");
        let owner = Host.owner(dir.path()).expect("readable").expect("exists");
        assert!(owner.id.starts_with("S-1-"), "{owner:?}");
    }

    /// A `PSModulePath` in the caller's environment that names a planted
    /// `Microsoft.PowerShell.Security` reaches neither the guard's tools nor the service
    /// installer's: PowerShell 7 hands such a path to every program it starts, with its own
    /// copy of the module first, and a planted one would load the same way.
    #[cfg(windows)]
    #[test]
    fn the_tools_ignore_a_module_planted_in_the_callers_module_path() {
        planted_module::run_under_planted_module_path(
            "exec::tests::the_guard_reads_token_and_owner_under_a_planted_module_path",
        );
    }
}

/// Runs one test of this test binary in a child whose environment names a planted
/// `Microsoft.PowerShell.Security` first in `PSModulePath`, as a caller could: the module
/// writes a marker when it loads and replaces `Get-Acl`. The test must pass and the marker
/// must not be written.
#[cfg(all(test, windows))]
pub(crate) mod planted_module {
    pub(crate) fn run_under_planted_module_path(test: &str) {
        let dir = tempfile::tempdir().expect("dir");
        let modules = dir.path().join("Modules");
        let module = modules.join("Microsoft.PowerShell.Security");
        std::fs::create_dir_all(&module).expect("module dir");
        let marker = dir.path().join("loaded.txt");
        let script = format!(
            "[System.IO.File]::WriteAllText('{}', 'loaded')\nfunction Get-Acl {{ 'planted' }}\n",
            marker.display()
        );
        std::fs::write(module.join("Microsoft.PowerShell.Security.psm1"), script)
            .expect("planted module");
        let mut path = std::ffi::OsString::from(modules.as_os_str());
        if let Some(inherited) = std::env::var_os("PSModulePath") {
            path.push(";");
            path.push(inherited);
        }
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", test, "--test-threads", "1"])
            .env("PSModulePath", path)
            .output()
            .expect("the test binary runs");
        let printed = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success() && printed.contains("1 passed"),
            "{printed}"
        );
        assert!(!marker.exists(), "the planted module was loaded: {printed}");
    }
}
