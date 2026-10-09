//! The `tenko` binary: one executable that runs the server roles (`tenko serve`) and acts
//! as the command-line client of the public API (`tenko login`, `prefix`, `import`,
//! `export`, `audit verify`), as decided in ADR 0004.
//!
//! | Module | Contents |
//! |---|---|
//! | [`config`] | `tenko.toml`: the bootstrap settings, environment overrides, validation |
//! | [`serve`] | `tenko serve`: the start order of the controller role, readiness, shutdown |
//! | [`platform`] | systemd `sd_notify` and the Windows service |
//! | [`client`] | the client commands over the public API |
//! | [`kek`] | `tenko kek rotate`: key-encryption key rotation with the server stopped |
//! | [`modules`] | the module switch of OPS-25 |
//! | [`upgrade`] | `tenko upgrade`, the data-directory format and its migrations, in-app updates (OPS-23, OPS-24) |
//! | [`plugin`] | `tenko plugin`: list, run a bundled plugin, conformance test; the connector service of `tenko serve` |
//! | [`logging`] | `tracing` to standard error or a file, as text or JSON |
//! | [`exit`] | the exit statuses |

#![forbid(unsafe_code)]

use std::io::Write;

use clap::{Args, Parser, Subcommand};

pub mod client;
pub mod config;
pub mod exit;
pub mod kek;
pub mod logging;
pub mod modules;
pub mod platform;
pub mod plugin;
pub mod serve;
pub mod upgrade;

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko";

/// Returns the version of this crate as declared in its manifest.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Tenko DDI: DNS, DHCP and IPAM in one binary, server and command-line client alike.
#[derive(Debug, Parser)]
#[command(
    name = "tenko",
    bin_name = "tenko",
    version,
    arg_required_else_help = true
)]
pub struct Cli {
    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands of the `tenko` binary.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the server roles of this node in the foreground.
    Serve(serve::ServeArgs),

    /// Check the configuration.
    Config {
        /// The `config` subcommand to run.
        #[command(subcommand)]
        action: ConfigCommand,
    },

    /// Key-encryption key maintenance (run with the server stopped).
    Kek {
        /// The `kek` subcommand to run.
        #[command(subcommand)]
        action: kek::KekCommand,
    },

    /// Data-directory format checks and upgrades (run `check` before switching binaries).
    Upgrade {
        /// The `upgrade` subcommand to run.
        #[command(subcommand)]
        action: upgrade::UpgradeCommand,
    },

    /// Manage the Windows service (Windows only).
    Service {
        /// The `service` subcommand to run.
        #[command(subcommand)]
        action: platform::ServiceCommand,
    },

    /// Inspect node roles.
    Roles {
        /// The `roles` subcommand to run.
        #[command(subcommand)]
        action: RolesCommand,
    },

    /// Complete first-run setup without a browser: profile, first administrator, host name.
    Setup(client::login::SetupArgs),

    /// Sign in to a controller and store an API token for the other commands.
    Login(client::login::LoginArgs),

    /// Revoke the stored API token and forget it.
    Logout(client::login::LogoutArgs),

    /// List, show and create prefixes.
    Prefix {
        /// The `prefix` subcommand to run.
        #[command(subcommand)]
        action: client::prefix::PrefixCommand,
    },

    /// Import a spreadsheet or CSV file: upload, mapping, preview, apply.
    Import(client::import::ImportArgs),

    /// Export prefixes, addresses or hosts as CSV.
    Export(client::export::ExportArgs),

    /// Audit log commands.
    Audit {
        /// The `audit` subcommand to run.
        #[command(subcommand)]
        action: client::audit::AuditCommand,
    },

    /// Download the root certificate of the internal CA, to install on admin clients.
    CaRoot(client::ca_root::CaRootArgs),

    /// Ask a node whether it is ready (container health checks); no sign-in needed.
    Health(client::health::HealthArgs),

    /// Breached-password corpus commands.
    Hibp {
        /// The `hibp` subcommand to run.
        #[command(subcommand)]
        action: client::hibp::HibpCommand,
    },

    /// Connector plugins: list them, run a bundled one, test any plugin.
    Plugin {
        /// The `plugin` subcommand to run.
        #[command(subcommand)]
        action: plugin::PluginCommand,
    },

    /// Print the OpenAPI document of the API (CI compares it with `docs/api/openapi.json`).
    #[command(hide = true)]
    Openapi,
}

/// Subcommands of `tenko roles`.
#[derive(Debug, Subcommand)]
pub enum RolesCommand {
    /// List the roles a Tenko node can run.
    List,
}

/// Subcommands of `tenko config`.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Validate the configuration and print the effective settings (no secrets).
    Check(ConfigCheckArgs),
}

/// Arguments of `tenko config check`.
#[derive(Debug, Clone, Args)]
pub struct ConfigCheckArgs {
    /// The configuration file.
    #[arg(long, value_name = "FILE", env = "TENKO_CONFIG")]
    pub config: Option<std::path::PathBuf>,

    /// The data directory; overrides `data_dir` of the file.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<std::path::PathBuf>,

    /// The roles; overrides `roles` of the file.
    #[arg(long, value_name = "ROLES")]
    pub roles: Option<String>,
}

impl Command {
    /// Returns the command as typed on the command line, such as `import` or `audit verify`.
    pub fn name(&self) -> &'static str {
        match self {
            Command::Serve(_) => "serve",
            Command::Config {
                action: ConfigCommand::Check(_),
            } => "config check",
            Command::Kek {
                action: kek::KekCommand::Rotate(_),
            } => "kek rotate",
            Command::Upgrade { action } => action.name(),
            Command::Service { action } => action.name(),
            Command::Roles {
                action: RolesCommand::List,
            } => "roles list",
            Command::Setup(_) => "setup",
            Command::Login(_) => "login",
            Command::Logout(_) => "logout",
            Command::Prefix { action } => action.name(),
            Command::CaRoot(_) => "ca-root",
            Command::Health(_) => "health",
            Command::Import(_) => "import",
            Command::Export(_) => "export",
            Command::Audit {
                action: client::audit::AuditCommand::Verify(_),
            } => "audit verify",
            Command::Hibp {
                action: client::hibp::HibpCommand::Build(_),
            } => "hibp build",
            Command::Plugin { action } => action.name(),
            Command::Openapi => "openapi",
        }
    }
}

/// Runs a parsed command, writing regular output to `out` and diagnostics to `err`, and
/// returns the exit status of [`exit`].
///
/// `tenko serve` and `tenko service run` install their own logging from the
/// configuration; every other command logs warnings to standard error.
pub fn execute(cli: &Cli, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let name = cli.command.name();
    match &cli.command {
        Command::Serve(args) => serve::command(args, err),
        Command::Config {
            action: ConfigCommand::Check(args),
        } => config_check(args, out, err),
        Command::Kek {
            action: kek::KekCommand::Rotate(args),
        } => kek::rotate(args, out, err),
        Command::Upgrade { action } => upgrade::command(action, out, err),
        Command::Service { action } => platform::command(action, out, err),
        Command::Roles {
            action: RolesCommand::List,
        } => {
            let _ = write!(out, "{}", client::render_roles());
            exit::OK
        }
        Command::Plugin { action } => plugin::command(action, out, err),
        Command::Openapi => {
            let _ = write!(out, "{}", tenko_api::openapi_json());
            exit::OK
        }
        Command::Hibp {
            action: client::hibp::HibpCommand::Build(args),
        } => match client::hibp::build(args) {
            Ok(output) => {
                let _ = out.write_all(output.stdout.as_bytes());
                let _ = err.write_all(output.stderr.as_bytes());
                output.status
            }
            Err(failure) => failure.report(name, false, out, err),
        },
        Command::Setup(args) => {
            logging::init_client();
            client::block_on(name, args.client.json, out, err, client::login::setup(args))
        }
        Command::Login(args) => {
            logging::init_client();
            client::block_on(name, args.client.json, out, err, client::login::login(args))
        }
        Command::Logout(args) => {
            logging::init_client();
            client::block_on(
                name,
                args.client.json,
                out,
                err,
                client::login::logout(args),
            )
        }
        Command::Prefix { action } => {
            logging::init_client();
            let json = action.client().json;
            client::block_on(name, json, out, err, client::prefix::run(action))
        }
        Command::CaRoot(args) => {
            logging::init_client();
            client::block_on(name, args.client.json, out, err, client::ca_root::run(args))
        }
        Command::Health(args) => {
            logging::init_client();
            client::block_on(name, args.client.json, out, err, client::health::run(args))
        }
        Command::Import(args) => {
            logging::init_client();
            client::block_on(name, args.client.json, out, err, client::import::run(args))
        }
        Command::Export(args) => {
            logging::init_client();
            client::block_on(name, args.client.json, out, err, client::export::run(args))
        }
        Command::Audit {
            action: client::audit::AuditCommand::Verify(args),
        } => {
            logging::init_client();
            client::block_on(
                name,
                args.client.json,
                out,
                err,
                client::audit::verify(args),
            )
        }
    }
}

/// `tenko config check`: validates and prints the effective configuration as TOML, with the
/// derived settings as comments. Exit status 3 when it is invalid.
fn config_check(args: &ConfigCheckArgs, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let sources = config::Sources {
        file: args.config.clone(),
        data_dir: args.data_dir.clone(),
        roles: args.roles.clone(),
    };
    let loaded = match config::load(&sources, std::env::vars()) {
        Ok(loaded) => loaded,
        Err(error) => {
            let _ = writeln!(err, "tenko config check: {error}");
            return exit::CONFIG;
        }
    };
    let resolved = match loaded.config.resolve() {
        Ok(resolved) => resolved,
        Err(error) => {
            let _ = writeln!(err, "tenko config check: {error}");
            return exit::CONFIG;
        }
    };
    let mut config = resolved.config.clone();
    config.data_dir = Some(resolved.data_dir.clone());
    let text = match config.to_toml() {
        Ok(text) => text,
        Err(error) => {
            let _ = writeln!(
                err,
                "tenko config check: cannot print the configuration: {error}"
            );
            return exit::FAILURE;
        }
    };
    let file = loaded
        .file
        .as_ref()
        .map_or_else(|| "(none)".to_owned(), |path| path.display().to_string());
    let env = if loaded.env_overrides.is_empty() {
        "(none)".to_owned()
    } else {
        loaded.env_overrides.join(", ")
    };
    let layout = resolved.layout();
    let _ = writeln!(out, "# tenko config check: the configuration is valid");
    let _ = writeln!(out, "# file: {file}");
    let _ = writeln!(out, "# environment overrides: {env}");
    let _ = writeln!(out, "# roles: {}", resolved.roles);
    let _ = writeln!(out, "# store: {}", layout.store().display());
    let _ = writeln!(
        out,
        "# key-encryption keys: {}",
        describe_kek(&resolved.kek)
    );
    let _ = writeln!(out, "# TLS: {}", describe_tls(&resolved.tls));
    let _ = writeln!(out);
    let _ = write!(out, "{text}");
    // Roles Phase 1 does not implement are a note here, not an error.
    let _ = serve::check_roles(resolved.roles, err);
    exit::OK
}

fn describe_kek(kek: &tenko_vault::KekConfig) -> String {
    match kek {
        tenko_vault::KekConfig::Dpapi { dir, scope } => {
            let scope = match scope {
                tenko_vault::kek::DpapiScope::Machine => "machine",
                tenko_vault::kek::DpapiScope::User => "user",
            };
            format!("DPAPI ({scope} scope) in {}", dir.display())
        }
        tenko_vault::KekConfig::SystemdCreds { dir, .. } => {
            format!("systemd-creds in {}", dir.display())
        }
        tenko_vault::KekConfig::File { path, retired } => format!(
            "key file {} (no OS protection){}",
            path.display(),
            if retired.is_empty() {
                String::new()
            } else {
                format!(", {} retired", retired.len())
            }
        ),
        _ => "another provider".to_owned(),
    }
}

fn describe_tls(tls: &config::TlsSpec) -> String {
    match tls {
        config::TlsSpec::InternalCa { host_name, .. } => {
            format!("internal CA, certificate for {host_name} until setup names the host")
        }
        config::TlsSpec::Imported {
            cert_path,
            key_path,
        } => format!(
            "imported certificate {} with key {}",
            cert_path.display(),
            key_path.display()
        ),
        config::TlsSpec::ReverseProxy { public_host, .. } => {
            format!("reverse proxy for {public_host}")
        }
        config::TlsSpec::Plain => "plain HTTP (Lab)".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, error::ErrorKind};
    use tenko_core::Role;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("tenko").chain(args.iter().copied()))
    }

    fn run(args: &[&str]) -> (u8, String, String) {
        let cli = parse(args).expect("valid arguments");
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let status = execute(&cli, &mut out, &mut err);
        (
            status,
            String::from_utf8(out).expect("UTF-8 output"),
            String::from_utf8(err).expect("UTF-8 output"),
        )
    }

    #[test]
    fn metadata_matches_manifest() {
        assert_eq!(CRATE_NAME, env!("CARGO_PKG_NAME"));
        assert!(version().starts_with(|c: char| c.is_ascii_digit()));
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn version_flag_is_supported() {
        let err = parse(&["--version"]).expect_err("--version exits early");
        assert_eq!(err.kind(), ErrorKind::DisplayVersion);
        assert!(err.to_string().starts_with("tenko "), "output: {err}");
    }

    #[test]
    fn bare_invocation_shows_help() {
        let err = parse(&[]).expect_err("a command is required");
        assert_eq!(
            err.kind(),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }

    #[test]
    fn roles_list_prints_every_role() {
        let (status, output, _) = run(&["roles", "list"]);
        assert_eq!(status, 0);
        assert_eq!(output.lines().count(), Role::ALL.len());
        for role in Role::ALL {
            assert!(output.contains(role.as_str()), "missing role {role}");
        }
    }

    #[test]
    fn openapi_prints_the_generated_document() {
        let (status, output, _) = run(&["openapi"]);
        assert_eq!(status, 0);
        assert_eq!(output, tenko_api::openapi_json());
    }

    #[test]
    fn serve_without_the_controller_exits_with_status_2() {
        let dir = std::env::temp_dir().join("tenko-lib-test-serve");
        let dir = dir.to_str().expect("UTF-8 temp path");
        let (status, _, err) = run(&["serve", "--roles", "probe", "--data-dir", dir]);
        assert_eq!(status, exit::USAGE);
        assert!(err.contains("probe: not implemented in Phase 1"), "{err}");
        assert!(!std::path::Path::new(dir).exists());
    }

    #[test]
    fn serve_with_a_bad_configuration_exits_with_status_3() {
        let (status, _, err) = run(&["serve", "--config", "does/not/exist/tenko.toml"]);
        assert_eq!(status, exit::CONFIG);
        assert!(err.contains("config.read"), "{err}");
    }

    #[test]
    fn config_check_prints_the_effective_configuration() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let data = dir.path().join("data");
        let (status, output, err) = run(&[
            "config",
            "check",
            "--data-dir",
            data.to_str().expect("UTF-8"),
        ]);
        assert_eq!(status, exit::OK, "{err}");
        assert!(output.starts_with("# tenko config check: the configuration is valid"));
        let parsed: config::Config = toml::from_str(&output).expect("the output is TOML");
        assert_eq!(parsed.data_dir.as_deref(), Some(data.as_path()));
        assert_eq!(parsed.roles, "controller");
    }

    #[test]
    fn config_check_rejects_bad_files() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("tenko.toml");
        std::fs::write(
            &path,
            "data_dir = \"/d\"\n[tls]\nmode = \"carrier_pigeon\"\n",
        )
        .expect("write");
        let (status, output, err) =
            run(&["config", "check", "--config", path.to_str().expect("UTF-8")]);
        assert_eq!(status, exit::CONFIG);
        assert_eq!(output, "");
        assert!(err.contains("config.parse"), "{err}");
    }

    #[test]
    fn command_names_match_the_command_line() {
        let cases: [(&[&str], &str); 18] = [
            (&["kek", "rotate"], "kek rotate"),
            (&["plugin", "list"], "plugin list"),
            (&["upgrade", "check"], "upgrade check"),
            (&["health"], "health"),
            (&["ca-root"], "ca-root"),
            (&["openapi"], "openapi"),
            (&["serve", "--data-dir", "d"], "serve"),
            (&["config", "check"], "config check"),
            (&["roles", "list"], "roles list"),
            (&["login"], "login"),
            (&["logout"], "logout"),
            (&["prefix", "list"], "prefix list"),
            (&["prefix", "create", "192.0.2.0/24"], "prefix create"),
            (&["import", "file.csv"], "import"),
            (&["export", "prefixes"], "export"),
            (&["audit", "verify"], "audit verify"),
            (&["hibp", "build", "in", "out"], "hibp build"),
            (&["service", "stop"], "service stop"),
        ];
        for (args, name) in cases {
            let cli = parse(args).expect("valid arguments");
            assert_eq!(cli.command.name(), name);
        }
    }

    #[test]
    fn secrets_are_not_flags() {
        assert!(parse(&["login", "--password", "x"]).is_err());
        assert!(parse(&["login", "--token", "x"]).is_err());
    }
}
