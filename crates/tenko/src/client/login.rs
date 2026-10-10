//! `tenko setup`, `tenko setup token`, `tenko login` and `tenko logout`.

use std::{io::Write, path::PathBuf};

use clap::{Args, Subcommand};
use serde::Serialize;
use tenko_auth::{
    service::{
        CodeLogin, CreatedToken, LoginResponse, PasswordLogin, SecondFactorMethod, SessionInfo,
        SetupAdmin, SetupRequest, TokenCreate,
    },
    settings::Profile,
};

use super::{
    ClientOpts, Credentials, Failure, Output, Raw, Secret, Target, load_credentials, read_line,
    read_secret, store_credentials,
};
use crate::{config, exit, serve::setup_token};

/// Arguments of `tenko setup`. With the subcommand `token` the other options do not apply
/// and are not required.
#[derive(Debug, Clone, Args)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
pub struct SetupArgs {
    /// What to do instead of completing setup.
    #[command(subcommand)]
    pub action: Option<SetupCommand>,

    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,

    /// The one-time setup token of the server while setup is open; `tenko setup token`
    /// prints it on the server. Asked for when not given.
    #[arg(
        long,
        value_name = "TOKEN",
        env = "TENKO_SETUP_TOKEN",
        hide_env_values = true
    )]
    pub setup_token: Option<String>,

    /// Login name of the first administrator.
    #[arg(long, value_name = "NAME", required = true)]
    pub admin: Option<String>,

    /// Display name of the first administrator.
    #[arg(long, value_name = "TEXT")]
    pub display_name: Option<String>,

    /// The host name clients use: TLS subject and passkey relying-party ID; not an IP
    /// address.
    #[arg(long, value_name = "HOST", required = true)]
    pub host_name: Option<String>,

    /// The security profile: home, standard, hardened or lab.
    #[arg(long, value_name = "PROFILE", default_value = "home", value_parser = parse_profile)]
    pub profile: Profile,

    /// The default UI language: en or sv.
    #[arg(long, value_name = "LANG", default_value = "en")]
    pub language: String,

    /// Read the administrator's password from the first line of standard input instead of
    /// asking for it.
    #[arg(long)]
    pub password_stdin: bool,
}

/// Subcommands of `tenko setup`.
#[derive(Debug, Clone, Subcommand)]
pub enum SetupCommand {
    /// Print the one-time setup token of this node (run it on the server, as the account
    /// that runs `tenko serve`).
    Token(SetupTokenArgs),
}

impl SetupCommand {
    /// The command as typed on the command line.
    pub fn name(&self) -> &'static str {
        match self {
            SetupCommand::Token(_) => "setup token",
        }
    }
}

/// Arguments of `tenko setup token`: they find the data directory like `tenko serve` does.
#[derive(Debug, Clone, Args)]
pub struct SetupTokenArgs {
    /// The configuration file (`tenko.toml`), for its `data_dir`.
    #[arg(long, value_name = "FILE", env = "TENKO_CONFIG")]
    pub config: Option<PathBuf>,

    /// The data directory of the server; overrides `data_dir` of the file and
    /// `TENKO_DATA_DIR`.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,
}

fn parse_profile(text: &str) -> Result<Profile, String> {
    Profile::ALL
        .into_iter()
        .find(|profile| profile.as_str().eq_ignore_ascii_case(text.trim()))
        .ok_or_else(|| format!("unknown profile `{text}` (home, standard, hardened, lab)"))
}

/// Arguments of `tenko login`.
#[derive(Debug, Clone, Args)]
pub struct LoginArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,

    /// The account; asked for when not given.
    #[arg(long, short = 'u', value_name = "NAME")]
    pub user: Option<String>,

    /// Read the password from the first line of standard input instead of asking for it.
    #[arg(long)]
    pub password_stdin: bool,

    /// The TOTP code, when the account has a second factor; asked for when needed.
    #[arg(long, value_name = "CODE")]
    pub totp_code: Option<String>,

    /// Name of the personal API token this login creates.
    #[arg(long, value_name = "NAME")]
    pub token_name: Option<String>,

    /// Lifetime of the token in days; default the longest the profile allows (TGL-05).
    #[arg(long, value_name = "DAYS")]
    pub token_days: Option<u32>,
}

/// Arguments of `tenko logout`.
#[derive(Debug, Clone, Args)]
pub struct LogoutArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
}

/// `tenko setup`: completes first-run setup (API-10) without a browser.
///
/// # Errors
///
/// The [`Failure`] of the first step that failed.
pub async fn setup(args: &SetupArgs) -> Result<Output, Failure> {
    // Clap requires both options unless the subcommand `token` is given.
    let (Some(admin), Some(host_name)) = (&args.admin, &args.host_name) else {
        return Err(Failure::new(
            exit::USAGE,
            "--admin and --host-name are required",
        ));
    };
    let target = Target::resolve(&args.client, false)?;
    let raw = target.raw()?;
    let token = match &args.setup_token {
        Some(token) => Secret::new(token.clone()),
        None => read_secret(
            "Setup token (print it on the server with `tenko setup token`): ",
            false,
        )?,
    };
    let password = read_secret(&format!("Password for {admin}: "), args.password_stdin)?;
    let request = SetupRequest {
        setup_token: token.to_dto(),
        profile: args.profile,
        admin: SetupAdmin {
            name: admin.clone(),
            display_name: args.display_name.clone(),
            password: password.to_dto(),
        },
        host_name: host_name.clone(),
        language: args.language.clone(),
    };
    let response = raw.post_json("/setup", &request, None).await?;
    let session: SessionInfo = response.json()?;
    // Setup signs the administrator in; the command line uses tokens, so end that session.
    if let Some(cookie) = response.session_cookie() {
        let _ = raw
            .post_json("/auth/logout", &Empty {}, Some(&cookie))
            .await;
    }
    if target.json {
        return Ok(Output::json(&session));
    }
    Ok(Output::text(format!(
        "setup complete: profile {}, administrator {}, host name {}\n",
        session.profile.as_str(),
        session.user.name,
        host_name
    ))
    .note(format!(
        "sign in with: tenko login --url {} --user {}",
        target.url, session.user.name
    )))
}

/// `tenko setup token`: prints the setup token that the running server wrote to
/// `<data_dir>/setup-token`: the token and a newline on standard output, nothing else.
///
/// The data directory is found like `tenko serve` finds it: `--data-dir`, else
/// `TENKO_DATA_DIR`, else `data_dir` of the file named by `--config` or `TENKO_CONFIG`. The
/// exit status is 0 when the token was printed, 3 when the configuration names no valid
/// data directory, and 1 when there is no token to print (setup is complete or the server
/// has not started yet) or the file cannot be read.
pub fn token(args: &SetupTokenArgs, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let sources = config::Sources {
        file: args.config.clone(),
        data_dir: args.data_dir.clone(),
        roles: None,
    };
    let resolved =
        match config::load(&sources, std::env::vars()).and_then(|loaded| loaded.config.resolve()) {
            Ok(resolved) => resolved,
            Err(error) => {
                let _ = writeln!(err, "tenko setup token: {error}");
                return exit::CONFIG;
            }
        };
    let path = resolved.layout().setup_token();
    match setup_token::read(&path) {
        Ok(Some(token)) => {
            let _ = writeln!(out, "{token}");
            exit::OK
        }
        Ok(None) => {
            let _ = writeln!(
                err,
                "tenko setup token: there is no setup token in {}: first-run setup is complete, \
                 or the server has not been started on this data directory yet",
                path.display()
            );
            exit::FAILURE
        }
        Err(error) => {
            let _ = writeln!(
                err,
                "tenko setup token: cannot read {}: {error}; run it as the account that runs \
                 `tenko serve`",
                path.display()
            );
            exit::FAILURE
        }
    }
}

#[derive(Serialize)]
struct Empty {}

/// `tenko login`: password, then a second factor when the account needs one; the session
/// creates a personal token that is stored for the other commands, then ends.
///
/// # Errors
///
/// The [`Failure`] of the first step that failed.
pub async fn login(args: &LoginArgs) -> Result<Output, Failure> {
    let target = Target::resolve(&args.client, false)?;
    let previous = load_credentials()
        .map_err(Failure::other)?
        .filter(|stored| super::same_url(&stored.url, &target.url));
    let raw = target.raw()?;
    let user = match (&args.user, &previous) {
        (Some(user), _) => user.clone(),
        (None, Some(stored)) => stored.user.clone(),
        (None, None) => read_line("User: ")?,
    };
    if user.is_empty() {
        return Err(Failure::new(exit::USAGE, "no user name"));
    }
    let password = read_secret(&format!("Password for {user}: "), args.password_stdin)?;
    let first = raw
        .post_json(
            "/auth/login/password",
            &PasswordLogin {
                user_name: user.clone(),
                password: password.to_dto(),
            },
            None,
        )
        .await?;
    drop(password);
    let (response, cookie) = match first.json::<LoginResponse>()? {
        authenticated @ LoginResponse::Authenticated { .. } => {
            (authenticated, first.session_cookie())
        }
        LoginResponse::SecondFactor {
            challenge_id,
            methods,
            ..
        } => {
            let second =
                second_factor(&raw, args.totp_code.as_ref(), challenge_id, &methods).await?;
            (second.json::<LoginResponse>()?, second.session_cookie())
        }
    };
    let LoginResponse::Authenticated { session } = response else {
        return Err(Failure::new(
            exit::AUTH,
            "the second factor was not accepted",
        ));
    };
    let cookie =
        cookie.ok_or_else(|| Failure::other("the server signed in but set no session cookie"))?;
    let token = create_token(&raw, &cookie, args).await;
    // The session was only needed to create the token.
    let _ = raw
        .post_json("/auth/logout", &Empty {}, Some(&cookie))
        .await;
    let created = token?;
    let credentials = Credentials {
        url: target.url.clone(),
        ca_file: target.ca_file.clone(),
        user: session.user.name.clone(),
        token: created.token.expose().to_owned(),
        token_id: created.info.id.to_string(),
    };
    let path = store_credentials(&credentials).map_err(Failure::other)?;
    if let Some(previous) = previous.filter(|stored| stored.token_id != credentials.token_id) {
        // Best effort: the token of the previous login is no longer stored anywhere.
        let _ = raw
            .delete_with_token(
                &format!("/auth/tokens/{}", previous.token_id),
                &credentials.token,
            )
            .await;
    }
    let expiry = created.info.expires_at.map_or_else(
        || "does not expire".to_owned(),
        |at| format!("expires {at}"),
    );
    if target.json {
        return Ok(Output::json(&session));
    }
    Ok(Output::text(format!(
        "signed in to {} as {}\n",
        target.url, session.user.name
    ))
    .note(format!(
        "NOTE: the API token `{}` ({expiry}) is stored in {}, readable by your account only. \
         Anyone who can read that file can act as {} until `tenko logout` revokes it.",
        created.info.name,
        path.display(),
        session.user.name
    )))
}

async fn second_factor(
    raw: &Raw,
    totp_code: Option<&String>,
    challenge_id: String,
    methods: &[SecondFactorMethod],
) -> Result<super::RawResponse, Failure> {
    if methods.contains(&SecondFactorMethod::Totp) {
        let code = match totp_code {
            Some(code) => code.clone(),
            None => read_line("TOTP code: ")?,
        };
        let body = CodeLogin {
            challenge_id,
            code: Secret::new(code).to_dto(),
        };
        return raw.post_json("/auth/login/totp", &body, None).await;
    }
    if methods.contains(&SecondFactorMethod::Recovery) {
        let code = read_secret("Recovery code: ", false)?;
        let body = CodeLogin {
            challenge_id,
            code: code.to_dto(),
        };
        return raw.post_json("/auth/login/recovery", &body, None).await;
    }
    Err(Failure::new(
        exit::AUTH,
        "this account signs in with a passkey, which the command line cannot use: create a \
         personal API token in the web UI and set TENKO_TOKEN",
    ))
}

async fn create_token(raw: &Raw, cookie: &str, args: &LoginArgs) -> Result<CreatedToken, Failure> {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "this host".to_owned());
    let request = TokenCreate {
        name: args
            .token_name
            .clone()
            .unwrap_or_else(|| format!("tenko command line on {host}")),
        expires_in_days: args.token_days,
    };
    raw.post_json("/auth/tokens", &request, Some(cookie))
        .await?
        .json()
}

/// `tenko logout`: revokes the stored token and deletes the credentials file.
///
/// # Errors
///
/// The [`Failure`] of the revocation; the file is deleted anyway.
pub async fn logout(args: &LogoutArgs) -> Result<Output, Failure> {
    let stored = load_credentials().map_err(Failure::other)?;
    let Some(stored) = stored else {
        return Ok(Output::text("not signed in\n"));
    };
    let mut opts = args.client.clone();
    opts.url.get_or_insert_with(|| stored.url.clone());
    let target = Target::resolve(&opts, false)?;
    let revoked = match target.raw() {
        Ok(raw) => raw
            .delete_with_token(&format!("/auth/tokens/{}", stored.token_id), &stored.token)
            .await
            .and_then(|response| response.check()),
        Err(error) => Err(error),
    };
    super::delete_credentials().map_err(Failure::other)?;
    match revoked {
        Ok(()) => Ok(Output::text(format!(
            "signed out of {}: token revoked, credentials removed\n",
            stored.url
        ))),
        // A token that is already gone (expired, revoked in the UI) is fine.
        Err(failure)
            if failure
                .problem
                .as_ref()
                .is_some_and(|problem| matches!(problem.status, 401 | 404)) =>
        {
            Ok(Output::text(format!(
                "signed out of {}: credentials removed (the token was no longer valid)\n",
                stored.url
            )))
        }
        Err(failure) => Err(Failure {
            message: format!(
                "credentials removed, but the token could not be revoked; revoke it in the web \
                 UI: {}",
                failure.message
            ),
            ..failure
        }),
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::{Cli, Command};

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("tenko").chain(args.iter().copied()))
    }

    fn setup_args(args: &[&str]) -> SetupArgs {
        match parse(args).expect("valid arguments").command {
            Command::Setup(args) => args,
            other => panic!("not a setup command: {other:?}"),
        }
    }

    fn run_token(args: &[&str]) -> (u8, String, String) {
        let SetupArgs {
            action: Some(SetupCommand::Token(args)),
            ..
        } = setup_args(args)
        else {
            panic!("not `setup token`");
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let status = token(&args, &mut out, &mut err);
        (
            status,
            String::from_utf8(out).expect("UTF-8"),
            String::from_utf8(err).expect("UTF-8"),
        )
    }

    #[test]
    fn setup_keeps_its_options_and_needs_the_administrator() {
        let args = setup_args(&[
            "setup",
            "--url",
            "https://ddi.example.org",
            "--admin",
            "alice",
            "--host-name",
            "ddi.example.org",
            "--setup-token",
            "X",
        ]);
        assert!(args.action.is_none());
        assert_eq!(args.admin.as_deref(), Some("alice"));
        assert_eq!(args.host_name.as_deref(), Some("ddi.example.org"));
        assert!(parse(&["setup"]).is_err());
        assert!(parse(&["setup", "--admin", "alice"]).is_err());
        assert!(parse(&["setup", "--host-name", "h"]).is_err());
    }

    #[test]
    fn the_token_subcommand_needs_none_of_the_setup_options() {
        let args = setup_args(&["setup", "token", "--data-dir", "d"]);
        let Some(SetupCommand::Token(token)) = args.action else {
            panic!("not `setup token`");
        };
        assert_eq!(token.data_dir.as_deref(), Some(std::path::Path::new("d")));
        assert!(token.config.is_none());
        // The options of `tenko setup` do not mix with the subcommand.
        assert!(parse(&["setup", "--admin", "alice", "token"]).is_err());
        assert!(parse(&["setup", "--url", "https://x", "token"]).is_err());
    }

    #[test]
    fn the_token_is_printed_alone_with_a_newline() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let data = dir.path().to_str().expect("UTF-8");
        setup_token::write(&dir.path().join("setup-token"), "ABCDE-FGHIJ-KLMNO-PQRST")
            .expect("write the token");
        let (status, out, err) = run_token(&["setup", "token", "--data-dir", data]);
        assert_eq!(status, exit::OK, "{err}");
        assert_eq!(out, "ABCDE-FGHIJ-KLMNO-PQRST\n");
        assert_eq!(err, "");
    }

    #[test]
    fn the_data_directory_can_come_from_the_file() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let data = dir.path().join("data");
        std::fs::create_dir(&data).expect("data directory");
        setup_token::write(&data.join("setup-token"), "ABCDE-FGHIJ-KLMNO-PQRST")
            .expect("write the token");
        let file = dir.path().join("tenko.toml");
        std::fs::write(&file, format!("data_dir = '{}'\n", data.display())).expect("config");
        let (status, out, err) =
            run_token(&["setup", "token", "--config", file.to_str().expect("UTF-8")]);
        assert_eq!(status, exit::OK, "{err}");
        assert_eq!(out, "ABCDE-FGHIJ-KLMNO-PQRST\n");
    }

    #[test]
    fn without_a_file_the_status_is_1_and_the_message_says_why() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let data = dir.path().to_str().expect("UTF-8");
        let (status, out, err) = run_token(&["setup", "token", "--data-dir", data]);
        assert_eq!(status, exit::FAILURE);
        assert_eq!(out, "");
        assert!(
            err.contains("first-run setup is complete") && err.contains("not been started"),
            "{err}"
        );
    }

    #[test]
    fn a_bad_configuration_is_status_3() {
        let (status, out, err) = run_token(&["setup", "token", "--config", "does/not/exist.toml"]);
        assert_eq!(status, exit::CONFIG);
        assert_eq!(out, "");
        assert!(err.contains("config.read"), "{err}");
    }
}
