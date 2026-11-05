//! The privilege check of ADR 0023 (`exec.unsafe_owner`, items 3 and 11, invariants I1, I2
//! and I10): an offline command that opens the store or writes under the data directory
//! never runs with full privileges over files that belong to another account.
//!
//! Before [`crate::execute`] runs one of the commands in [`offline_paths`], `main` asks this
//! module whether the process runs as root (on Windows: as `SYSTEM` or with an elevated
//! token) and whether this binary's own file, the data directory or another directory the
//! command writes into belongs to an account other than the privileged ones. When both
//! hold, the command does not run: the process exits with status 2 (`exit::USAGE`) and
//! prints one line that names the code, the file and its owner, and the same command in
//! the form that runs it as that account (`runuser -u <account> -- tenko …` on Linux).
//! There is no override, no profile setting and no exception for Lab (ADR 0023 item 3).
//!
//! What the check needs to know about the process and the files comes through [`Facts`],
//! so that the decision is tested with two accounts without being root: [`Host`] reads
//! the real process and file system.
//!
//! The commands covered are the ones that open the store or write under the data
//! directory with the server stopped: `backup restore`, `backup create` of a stopped node
//! (`--config` or `--data-dir`), `backup verify` (its work directory), `kek rotate`,
//! `upgrade check` and `upgrade layout`. `tenko serve` is not among them: the unit and
//! the Windows service run it as the service account, and a container runs it as the
//! owner of its own files.

use std::{
    fmt,
    path::{Path, PathBuf},
};

use crate::{
    Cli, Command, backup::BackupCommand, config, kek::KekCommand, upgrade::UpgradeCommand,
};

/// The error code of the refusal.
pub const CODE: &str = "exec.unsafe_owner";

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

/// What the check reads from the process and the file system.
pub trait Facts {
    /// Whether this process runs with full privileges: the effective uid is 0, or on
    /// Windows the token is `SYSTEM` or elevated. `None` when it cannot be told; the check
    /// then does not refuse (it protects against a slip with the genuine binary, ADR 0023
    /// item 3, and cannot do more than the facts it gets).
    fn privileged(&self) -> Option<bool>;

    /// The owner of `path`, following links an administrator made; `None` when the path
    /// does not exist or cannot be examined.
    fn owner(&self, path: &Path) -> Option<Owner>;

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
    /// Its owner.
    pub owner: Owner,
    /// The arguments of the command line after the program name.
    pub arguments: Vec<String>,
}

impl Refusal {
    /// The same command run as the owner: `runuser -u <account> -- tenko …`.
    pub fn as_owner(&self) -> String {
        let mut line = format!("runuser -u {} -- tenko", shell_word(self.owner.account()));
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
        write!(
            f,
            "tenko {}: [{CODE}] refusing to run {}: {what} {} belongs to {}; ",
            self.command,
            if cfg!(windows) {
                "with an elevated token"
            } else {
                "as root"
            },
            self.path.display(),
            self.owner
        )?;
        if cfg!(windows) {
            f.write_str(
                "run the MSI's payload C:\\Program Files\\Tenko\\tenko.exe from the elevated \
                 prompt instead; the service account's own files are changed by the service",
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

/// The directories an offline command writes into or opens the store under, or `None` for
/// a command this check does not cover. The data directory comes from the configuration
/// as the command itself would read it; when that fails, the command reports it and the
/// list is empty (the binary is still checked).
pub fn offline_paths(cli: &Cli) -> Option<Vec<PathBuf>> {
    let data_dir = |file: &Option<PathBuf>, dir: &Option<PathBuf>| {
        let sources = config::Sources {
            file: file.clone(),
            data_dir: dir.clone(),
            roles: None,
        };
        config::load(&sources, std::env::vars())
            .and_then(|loaded| loaded.config.resolve())
            .ok()
    };
    let mut paths = Vec::new();
    match &cli.command {
        Command::Backup {
            action: BackupCommand::Restore(args),
        } => {
            if let Some(resolved) = data_dir(&args.config, &args.data_dir) {
                paths.push(resolved.data_dir);
            }
        }
        Command::Backup {
            action: BackupCommand::Create(args),
        } if args.config.is_some() || args.data_dir.is_some() => {
            if let Some(resolved) = data_dir(&args.config, &args.data_dir) {
                paths.push(args.out.clone().unwrap_or_else(|| resolved.backup_dir()));
                paths.push(resolved.data_dir);
            } else if let Some(out) = &args.out {
                paths.push(out.clone());
            }
        }
        Command::Backup {
            action: BackupCommand::Verify(args),
        } => paths.extend(args.work_dir.clone()),
        Command::Kek {
            action: KekCommand::Rotate(args),
        } => {
            if let Some(resolved) = data_dir(&args.config, &args.data_dir) {
                paths.push(resolved.data_dir);
            }
        }
        Command::Upgrade {
            action: UpgradeCommand::Check(args),
        } => {
            paths.extend(args.work_dir.clone());
            if let Some(resolved) = data_dir(&args.config, &args.data_dir) {
                paths.push(resolved.data_dir);
            }
        }
        Command::Upgrade {
            action: UpgradeCommand::Layout(args),
        } => {
            if let Some(resolved) = data_dir(&args.config, &args.data_dir) {
                paths.push(resolved.data_dir);
            }
        }
        _ => return None,
    }
    Some(paths)
}

/// Decides whether `cli` may run: `None` when it may, else the refusal to print.
///
/// `arguments` are the command-line arguments after the program name, repeated in the
/// refusal as the command to run as the owner.
pub fn check(cli: &Cli, facts: &dyn Facts, arguments: &[String]) -> Option<Refusal> {
    let paths = offline_paths(cli)?;
    if facts.privileged() != Some(true) {
        return None;
    }
    let command = cli.command.name();
    let refusal = |path: PathBuf, binary: bool, owner: Owner| Refusal {
        command,
        path,
        binary,
        owner,
        arguments: arguments.to_vec(),
    };
    if let Some(exe) = facts.exe()
        && let Some(owner) = facts.owner(&exe)
        && !owner.privileged
    {
        return Some(refusal(exe, true, owner));
    }
    for path in paths {
        if let Some(owner) = facts.owner(&path)
            && !owner.privileged
        {
            return Some(refusal(path, false, owner));
        }
    }
    None
}

/// The facts of the running process.
#[derive(Debug, Clone, Copy, Default)]
pub struct Host;

impl Facts for Host {
    fn privileged(&self) -> Option<bool> {
        host::privileged()
    }

    fn owner(&self, path: &Path) -> Option<Owner> {
        host::owner(path)
    }

    fn exe(&self) -> Option<PathBuf> {
        std::env::current_exe().ok()
    }
}

#[cfg(unix)]
mod host {
    use std::{os::unix::fs::MetadataExt as _, path::Path};

    use super::Owner;

    /// The effective uid from `/proc/self/status` (`Uid: real effective saved fs`), which
    /// needs no library; elsewhere than Linux it is not known.
    pub(super) fn privileged() -> Option<bool> {
        if !cfg!(target_os = "linux") {
            return None;
        }
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        effective_uid(&status).map(|uid| uid == 0)
    }

    pub(super) fn effective_uid(status: &str) -> Option<u32> {
        status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|fields| fields.split_whitespace().nth(1))
            .and_then(|uid| uid.parse().ok())
    }

    pub(super) fn owner(path: &Path) -> Option<Owner> {
        let uid = std::fs::metadata(path).ok()?.uid();
        let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
        Some(Owner {
            id: uid.to_string(),
            name: account_name(&passwd, uid),
            privileged: uid == 0,
        })
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
    use std::{path::Path, process::Command};

    use super::Owner;

    /// The well-known SIDs that may own what a privileged process uses: `SYSTEM`, the
    /// Administrators group and the trusted installer.
    const PRIVILEGED_SIDS: [&str; 3] = [
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    ];
    /// The mandatory integrity labels of an elevated token and of `SYSTEM`.
    const ELEVATED_LABELS: [&str; 2] = ["S-1-16-12288", "S-1-16-16384"];

    /// The path of a tool in the system directory (a privileged process runs nothing else,
    /// ADR 0023 I1).
    fn system_tool(name: &str) -> std::path::PathBuf {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        Path::new(&root).join("System32").join(name)
    }

    fn run(tool: &str, arguments: &[&str]) -> Option<String> {
        let output = Command::new(system_tool(tool))
            .args(arguments)
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Whether the token carries the high or system integrity label (`whoami /groups`).
    pub(super) fn privileged() -> Option<bool> {
        let groups = run("whoami.exe", &["/groups", "/fo", "csv", "/nh"])?;
        Some(ELEVATED_LABELS.iter().any(|label| groups.contains(label)))
    }

    /// The owner through the access list of the path, as a SID and a name.
    pub(super) fn owner(path: &Path) -> Option<Owner> {
        if !path.exists() {
            return None;
        }
        let literal = path.to_string_lossy().replace('\'', "''");
        let script = format!(
            "$acl = Get-Acl -LiteralPath '{literal}'; \
             $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; $acl.Owner"
        );
        let output = run(
            "WindowsPowerShell\\v1.0\\powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
        )?;
        let mut lines = output
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty());
        let id = lines.next()?.to_owned();
        let name = lines.next().map(str::to_owned);
        Some(Owner {
            privileged: PRIVILEGED_SIDS.contains(&id.as_str()),
            id,
            name,
        })
    }
}

#[cfg(not(any(unix, windows)))]
mod host {
    use std::path::Path;

    use super::Owner;

    pub(super) fn privileged() -> Option<bool> {
        None
    }

    pub(super) fn owner(_path: &Path) -> Option<Owner> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use clap::Parser as _;

    use super::*;

    /// Facts built by hand: who runs, who owns what.
    struct Fixed {
        privileged: Option<bool>,
        exe: PathBuf,
        owners: BTreeMap<PathBuf, Owner>,
    }

    impl Facts for Fixed {
        fn privileged(&self) -> Option<bool> {
            self.privileged
        }

        fn owner(&self, path: &Path) -> Option<Owner> {
            self.owners.get(path).cloned()
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

    fn facts(privileged: Option<bool>, exe_owner: Owner, data: &Path, owner: Owner) -> Fixed {
        let exe = PathBuf::from("/var/lib/tenko/updates/0.0.12/tenko");
        Fixed {
            privileged,
            owners: BTreeMap::from([(exe.clone(), exe_owner), (data.to_path_buf(), owner)]),
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
        assert_eq!(refusal.owner, account());
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
    fn every_offline_command_is_covered_and_nothing_else() {
        let (_dir, data) = data_dir();
        let data_arg = data.to_str().expect("UTF-8");
        let covered: [&[&str]; 7] = [
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
            let paths = offline_paths(&cli).expect("covered");
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
        let not_covered: [&[&str]; 6] = [
            &["backup", "create", "--url", "https://ddi.example.test:8443"],
            &["backup", "keygen", "--out", "k"],
            &["upgrade", "format"],
            &["config", "check", "--data-dir", data_arg],
            &["roles", "list"],
            &["health"],
        ];
        for args in not_covered {
            let cli = parse(args);
            assert!(offline_paths(&cli).is_none(), "{args:?}");
            assert!(
                check(
                    &cli,
                    &facts(Some(true), account(), &data, account()),
                    &arguments(args)
                )
                .is_none(),
                "{args:?}"
            );
        }
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
        let paths = offline_paths(&cli).expect("covered");
        assert_eq!(paths, vec![out.clone(), data.clone()]);
        let mut facts = facts(Some(true), root(), &data, root());
        facts.owners.insert(out.clone(), account());
        let refusal = check(&cli, &facts, &arguments(&args)).expect("refused");
        assert_eq!(refusal.path, out);
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
        assert_eq!(offline_paths(&cli), Some(Vec::new()));
        let facts = Fixed {
            privileged: Some(true),
            exe: PathBuf::from("/opt/tenko/cli/tenko"),
            owners: BTreeMap::from([(PathBuf::from("/opt/tenko/cli/tenko"), account())]),
        };
        assert!(check(&cli, &facts, &arguments(&args)).is_some());
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
        let status = "Name:\ttenko\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(host::effective_uid(status), Some(0));
        assert_eq!(host::effective_uid("Name:\ttenko\n"), None);
        let passwd =
            "root:x:0:0:root:/root:/bin/bash\ntenko:x:998:998::/var/lib/tenko:/usr/sbin/nologin\n";
        assert_eq!(host::account_name(passwd, 998).as_deref(), Some("tenko"));
        assert_eq!(host::account_name(passwd, 0).as_deref(), Some("root"));
        assert_eq!(host::account_name(passwd, 7), None);
        // The real files: this process owns what it created.
        let dir = tempfile::tempdir().expect("dir");
        let owner = Host.owner(dir.path()).expect("owner");
        assert_eq!(owner.privileged, owner.id == "0");
        assert!(Host.owner(&dir.path().join("missing")).is_none());
    }
}
