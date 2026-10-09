//! `tenko setup`, `tenko login` and `tenko logout`.

use clap::Args;
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
use crate::exit;

/// Arguments of `tenko setup`.
#[derive(Debug, Clone, Args)]
pub struct SetupArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,

    /// The one-time setup token the server prints at start while setup is open. Asked for
    /// when not given.
    #[arg(
        long,
        value_name = "TOKEN",
        env = "TENKO_SETUP_TOKEN",
        hide_env_values = true
    )]
    pub setup_token: Option<String>,

    /// Login name of the first administrator.
    #[arg(long, value_name = "NAME")]
    pub admin: String,

    /// Display name of the first administrator.
    #[arg(long, value_name = "TEXT")]
    pub display_name: Option<String>,

    /// The host name clients use: TLS subject and passkey relying-party ID; not an IP
    /// address.
    #[arg(long, value_name = "HOST")]
    pub host_name: String,

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
    let target = Target::resolve(&args.client, false)?;
    let raw = target.raw()?;
    let token = match &args.setup_token {
        Some(token) => Secret::new(token.clone()),
        None => read_secret("Setup token: ", false)?,
    };
    let password = read_secret(
        &format!("Password for {}: ", args.admin),
        args.password_stdin,
    )?;
    let request = SetupRequest {
        setup_token: token.to_dto(),
        profile: args.profile,
        admin: SetupAdmin {
            name: args.admin.clone(),
            display_name: args.display_name.clone(),
            password: password.to_dto(),
        },
        host_name: args.host_name.clone(),
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
        args.host_name
    ))
    .note(format!(
        "sign in with: tenko login --url {} --user {}",
        target.url, session.user.name
    )))
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
