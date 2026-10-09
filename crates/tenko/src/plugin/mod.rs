//! `tenko plugin`: connector plugins (ADR 0012, CONN-19, CONN-20).
//!
//! | Command | What it does |
//! |---|---|
//! | `tenko plugin list` | the bundled plugins and the plugins installed under `<data_dir>/plugins`, with manifest summaries |
//! | `tenko plugin run <name>` | runs a bundled plugin; the host starts it this way, exactly like a third-party plugin |
//! | `tenko plugin test <path>` | runs the conformance suite against any plugin executable or plugin directory |
//!
//! The controller's connector service is started by [`start`] during `tenko serve`.
//!
//! Exit statuses: 0 on success, 1 when a conformance check fails or a plugin ends with an
//! error, 2 for usage errors (an unknown bundled plugin, an unreadable settings file, a
//! missing secret variable, a target that is not a plugin).

pub mod bundled;
mod serve;

use std::{
    ffi::OsString,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use clap::{Args, Subcommand};
use tenko_connect::{
    Secrets,
    conformance::{self, SuiteOptions},
    host::{launch::LaunchSpec, registry::PluginInfo},
    manifest::{MANIFEST_FILE, Manifest},
};

pub use self::serve::{Connectors, PLUGINS_DIR, registry, start};
use crate::{config, exit};

/// Subcommands of `tenko plugin`.
#[derive(Debug, Subcommand)]
pub enum PluginCommand {
    /// List the bundled and installed plugins with their manifests.
    List(ListArgs),
    /// Run a bundled plugin (the host starts plugins this way; standard input and output
    /// carry the plugin handshake).
    Run(RunArgs),
    /// Run the conformance suite against a plugin executable or plugin directory.
    Test(TestArgs),
}

impl PluginCommand {
    /// The command as typed on the command line.
    pub fn name(&self) -> &'static str {
        match self {
            PluginCommand::List(_) => "plugin list",
            PluginCommand::Run(_) => "plugin run",
            PluginCommand::Test(_) => "plugin test",
        }
    }
}

/// Arguments of `tenko plugin list`.
#[derive(Debug, Clone, Args)]
pub struct ListArgs {
    /// The configuration file; its `data_dir` locates the installed plugins.
    #[arg(long, value_name = "FILE", env = "TENKO_CONFIG")]
    pub config: Option<PathBuf>,

    /// The data directory; installed plugins live in its `plugins` directory.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,

    /// The directory of installed plugins; overrides `<data_dir>/plugins`.
    #[arg(long, value_name = "PATH")]
    pub plugins_dir: Option<PathBuf>,

    /// Print JSON instead of a table.
    #[arg(long)]
    pub json: bool,
}

/// Arguments of `tenko plugin run`.
#[derive(Debug, Clone, Args)]
pub struct RunArgs {
    /// The bundled plugin.
    #[arg(value_name = "NAME")]
    pub name: String,
}

/// Arguments of `tenko plugin test`.
#[derive(Debug, Clone, Args)]
pub struct TestArgs {
    /// A plugin executable, a plugin directory with a `plugin.json`, or a `plugin.json`;
    /// with `--bundled`, the name of a bundled plugin.
    #[arg(value_name = "PATH")]
    pub target: PathBuf,

    /// Treat the target as the name of a bundled plugin.
    #[arg(long)]
    pub bundled: bool,

    /// A JSON file with settings for the checks that reach the remote system; without it
    /// those checks only require a timely, well-formed answer.
    #[arg(long, value_name = "FILE")]
    pub settings: Option<PathBuf>,

    /// A secret for the remote checks, read from an environment variable:
    /// `--secret api_key=PLUGIN_API_KEY`. Secrets are never taken from the command line.
    #[arg(long, value_name = "PURPOSE=VARIABLE")]
    pub secret: Vec<String>,

    /// Timeout of one call in seconds.
    #[arg(long, value_name = "SECONDS", default_value_t = 30)]
    pub timeout: u64,

    /// Print the results as JSON.
    #[arg(long)]
    pub json: bool,
}

/// Runs a `tenko plugin` command and returns the exit status.
pub fn command(action: &PluginCommand, out: &mut impl Write, err: &mut impl Write) -> u8 {
    match action {
        // Standard input and output belong to the handshake: nothing else is printed there.
        PluginCommand::Run(args) => run(args, err),
        PluginCommand::List(args) => {
            crate::logging::init_client();
            list(args, out, err)
        }
        PluginCommand::Test(args) => {
            crate::logging::init_client();
            test(args, out, err)
        }
    }
}

/// `tenko plugin run <name>`.
fn run(args: &RunArgs, err: &mut impl Write) -> u8 {
    let Some(entry) = bundled::find(&args.name) else {
        let names: Vec<&str> = bundled::BUNDLED.iter().map(|entry| entry.name).collect();
        let _ = writeln!(
            err,
            "tenko plugin run: no bundled plugin `{}`; bundled are: {}",
            args.name,
            names.join(", ")
        );
        return exit::USAGE;
    };
    // 0 after a shutdown, 2 for a refused handshake, 1 for other errors (the SDK's codes,
    // which match the usage and failure statuses of this binary).
    (entry.run)()
}

/// `tenko plugin list`.
fn list(args: &ListArgs, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let plugins_dir = if let Some(dir) = &args.plugins_dir {
        Some(dir.clone())
    } else {
        let sources = config::Sources {
            file: args.config.clone(),
            data_dir: args.data_dir.clone(),
            roles: None,
        };
        match config::load(&sources, std::env::vars()) {
            Ok(loaded) => loaded.config.data_dir.map(|dir| dir.join(PLUGINS_DIR)),
            Err(error) => {
                let _ = writeln!(err, "tenko plugin list: {error}");
                return exit::CONFIG;
            }
        }
    };
    let registry = match registry(plugins_dir.clone()) {
        Ok(registry) => registry,
        Err(message) => {
            let _ = writeln!(err, "tenko plugin list: {message}");
            return exit::FAILURE;
        }
    };
    let plugins = registry.list();
    if args.json {
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&plugins).unwrap_or_default()
        );
        return exit::OK;
    }
    let _ = write!(out, "{}", render_list(&plugins));
    match plugins_dir {
        Some(dir) => {
            let _ = writeln!(out, "installed plugins: {}", dir.display());
        }
        None => {
            let _ = writeln!(
                out,
                "installed plugins: none listed (no data directory; give --data-dir or --plugins-dir)"
            );
        }
    }
    exit::OK
}

/// The table of `tenko plugin list`.
pub fn render_list(plugins: &[PluginInfo]) -> String {
    let rows: Vec<[String; 5]> = plugins
        .iter()
        .map(|plugin| {
            let source = match plugin.source {
                tenko_connect::host::registry::PluginSource::Bundled => "bundled",
                tenko_connect::host::registry::PluginSource::Installed => "installed",
            };
            let (version, capabilities) = plugin.manifest.as_ref().map_or_else(
                || ("-".to_owned(), "-".to_owned()),
                |manifest| {
                    (
                        manifest.version.clone(),
                        manifest
                            .capabilities
                            .iter()
                            .map(|capability| capability.as_str())
                            .collect::<Vec<_>>()
                            .join(","),
                    )
                },
            );
            let status = if plugin.usable {
                "usable".to_owned()
            } else {
                format!(
                    "not usable: {}",
                    plugin
                        .problems
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("; ")
                )
            };
            [
                plugin.name.clone(),
                source.to_owned(),
                version,
                capabilities,
                status,
            ]
        })
        .collect();
    let header = [
        "NAME".to_owned(),
        "SOURCE".to_owned(),
        "VERSION".to_owned(),
        "CAPABILITIES".to_owned(),
        "STATUS".to_owned(),
    ];
    let mut widths = [0usize; 4];
    for row in std::iter::once(&header).chain(rows.iter()) {
        for (width, cell) in widths.iter_mut().zip(row.iter()) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let mut text = String::new();
    for row in std::iter::once(&header).chain(rows.iter()) {
        let line = format!(
            "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  {}",
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2],
            w3 = widths[3],
        );
        text.push_str(line.trim_end());
        text.push('\n');
    }
    text
}

/// `tenko plugin test`.
fn test(args: &TestArgs, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let spec = match test_target(args) {
        Ok(spec) => spec,
        Err(message) => {
            let _ = writeln!(err, "tenko plugin test: {message}");
            return exit::USAGE;
        }
    };
    let options = match suite_options(args, std::env::vars_os()) {
        Ok(options) => options,
        Err(message) => {
            let _ = writeln!(err, "tenko plugin test: {message}");
            return exit::USAGE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = writeln!(err, "tenko plugin test: cannot start a runtime: {error}");
            return exit::FAILURE;
        }
    };
    let report = runtime.block_on(conformance::run(&spec, &options));
    if args.json {
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        let _ = writeln!(out, "{report}");
    }
    if report.passed() {
        exit::OK
    } else {
        exit::FAILURE
    }
}

/// What `tenko plugin test` starts.
fn test_target(args: &TestArgs) -> Result<LaunchSpec, String> {
    if args.bundled {
        let name = args.target.to_string_lossy();
        let entry = bundled::find(&name).ok_or_else(|| format!("no bundled plugin `{name}`"))?;
        let exe = std::env::current_exe()
            .map_err(|error| format!("the path of this executable is unknown: {error}"))?;
        return Ok(LaunchSpec::bundled((entry.manifest)(), exe));
    }
    let target = &args.target;
    let dir = if target.is_dir() {
        Some(target.clone())
    } else if target.file_name().is_some_and(|name| name == MANIFEST_FILE) {
        target.parent().map(Path::to_path_buf)
    } else {
        None
    };
    let Some(dir) = dir else {
        if !target.is_file() {
            return Err(format!(
                "{} is neither a plugin directory, a {MANIFEST_FILE} nor an executable",
                target.display()
            ));
        }
        return Ok(LaunchSpec::executable(
            target.clone(),
            Vec::<OsString>::new(),
        ));
    };
    let path = dir.join(MANIFEST_FILE);
    let bytes =
        std::fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let manifest =
        Manifest::parse(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    LaunchSpec::installed(manifest, &dir).map_err(|error| format!("{}: {error}", path.display()))
}

/// The options of the suite: the settings file and the secrets from the environment.
fn suite_options(
    args: &TestArgs,
    env: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<SuiteOptions, String> {
    let settings = match &args.settings {
        None => None,
        Some(path) => {
            let bytes = std::fs::read(path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            let value: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|error| format!("{} is not JSON: {error}", path.display()))?;
            if !value.is_object() {
                return Err(format!("{} is not a JSON object", path.display()));
            }
            Some(value)
        }
    };
    let env: Vec<(OsString, OsString)> = env.into_iter().collect();
    let mut secrets = Secrets::new();
    for entry in &args.secret {
        let (purpose, variable) = entry
            .split_once('=')
            .filter(|(purpose, variable)| !purpose.is_empty() && !variable.is_empty())
            .ok_or_else(|| format!("`--secret {entry}` is not PURPOSE=VARIABLE"))?;
        let value = env
            .iter()
            .find(|(name, _)| name.to_str() == Some(variable))
            .map(|(_, value)| value.clone())
            .ok_or_else(|| format!("the environment variable {variable} is not set"))?;
        let value = value
            .into_string()
            .map_err(|_| format!("the environment variable {variable} is not UTF-8"))?;
        secrets.insert_bytes(purpose, value.into_bytes());
    }
    Ok(SuiteOptions {
        settings,
        secrets,
        call_timeout: Duration::from_secs(args.timeout.clamp(1, 600)),
        ..SuiteOptions::default()
    })
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::*;

    #[derive(Debug, Parser)]
    struct Cli {
        #[command(subcommand)]
        action: PluginCommand,
    }

    fn parse(args: &[&str]) -> PluginCommand {
        Cli::try_parse_from(std::iter::once("plugin").chain(args.iter().copied()))
            .expect("arguments")
            .action
    }

    #[test]
    fn the_commands_parse() {
        Cli::command().debug_assert();
        assert_eq!(
            parse(&["test", "plugins/sample", "--secret", "api_key=KEY"]).name(),
            "plugin test"
        );
        assert_eq!(parse(&["run", "sample"]).name(), "plugin run");
        assert_eq!(parse(&["list", "--json"]).name(), "plugin list");
    }

    #[test]
    fn running_an_unknown_bundled_plugin_is_a_usage_error() {
        let mut err = Vec::new();
        let status = run(
            &RunArgs {
                name: "nope".to_owned(),
            },
            &mut err,
        );
        assert_eq!(status, exit::USAGE);
        let err = String::from_utf8(err).expect("utf-8");
        assert!(err.contains("bundled are: sample"), "{err}");
    }

    #[test]
    fn the_list_shows_bundled_and_installed_plugins() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::create_dir_all(dir.path().join("broken")).expect("dir");
        std::fs::write(dir.path().join("broken").join(MANIFEST_FILE), b"{").expect("file");
        let args = ListArgs {
            config: None,
            data_dir: None,
            plugins_dir: Some(dir.path().to_path_buf()),
            json: false,
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(list(&args, &mut out, &mut err), exit::OK);
        let out = String::from_utf8(out).expect("utf-8");
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("NAME"), "{out}");
        assert!(
            lines[1].starts_with("sample") && lines[1].contains("bundled"),
            "{out}"
        );
        assert!(lines[1].ends_with("usable"), "{out}");
        assert!(
            lines[2].starts_with("broken") && lines[2].contains("not usable"),
            "{out}"
        );

        let json = ListArgs { json: true, ..args };
        let mut out = Vec::new();
        assert_eq!(list(&json, &mut out, &mut Vec::new()), exit::OK);
        let parsed: serde_json::Value = serde_json::from_slice(&out).expect("json");
        assert_eq!(parsed[0]["name"], "sample");
        assert_eq!(parsed[0]["source"], "bundled");
        assert_eq!(parsed[0]["manifest"]["capabilities"][0], "inventory");
    }

    #[test]
    fn secrets_come_from_the_environment_only() {
        let args = TestArgs {
            target: PathBuf::from("x"),
            bundled: false,
            settings: None,
            secret: vec!["api_key=SAMPLE_KEY".to_owned()],
            timeout: 5,
            json: false,
        };
        let env = vec![(OsString::from("SAMPLE_KEY"), OsString::from("k"))];
        let options = suite_options(&args, env).expect("options");
        assert_eq!(options.secrets.get("api_key"), Some(&b"k"[..]));
        assert!(suite_options(&args, Vec::new()).is_err());
        let bad = TestArgs {
            secret: vec!["api_key".to_owned()],
            ..args
        };
        assert!(suite_options(&bad, Vec::new()).is_err());
    }

    #[test]
    fn test_targets_are_resolved() {
        let dir = tempfile::tempdir().expect("dir");
        let args = |target: PathBuf, bundled: bool| TestArgs {
            target,
            bundled,
            settings: None,
            secret: Vec::new(),
            timeout: 5,
            json: false,
        };
        let spec = test_target(&args(PathBuf::from("sample"), true)).expect("bundled");
        assert_eq!(spec.args, ["plugin", "run", "sample"]);
        assert!(test_target(&args(PathBuf::from("nope"), true)).is_err());
        assert!(test_target(&args(dir.path().join("missing"), false)).is_err());
        // A directory without a manifest.
        assert!(test_target(&args(dir.path().to_path_buf(), false)).is_err());
    }
}
