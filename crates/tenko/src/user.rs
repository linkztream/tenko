//! `tenko user unlock`: lifts the sign-in locks of an account on a stopped single controller
//! (IAM-05, TGL-07).
//!
//! The command is the way back for an account the network locked, or whose PIN from before
//! the six-digit minimum passed the end of its period, when no other administrator can sign
//! in to unlock it from the web UI. It opens the store of the stopped controller, removes
//! every stored lock of the account, records the unlock (so a controller forgets the
//! account's waits and locks in memory when it starts) and, for such a PIN, starts a new
//! period after which the PIN must be changed at the next sign-in. The change is one audited
//! batch (`auth.user.unlock`, `via: offline`).
//!
//! It gains no privilege: it runs as the account that owns the data directory (the service
//! account), and `main` refuses it as root over another account's files before it starts
//! ([`crate::exec`], ADR 0023). Whoever can run it can already read and write the store.
//! A member of a cluster of controllers is refused: an administrator on another controller
//! unlocks from the web UI (`POST /users/{id}/unlock`) instead.

use std::{io::Write, sync::Arc, time::Duration};

use clap::{Args, Subcommand};
use tenko_auth::clock::{Clock, SystemClock};
use tenko_store::{Store, raft::RaftStore};

use crate::{config, exit, logging, serve};

/// Subcommands of `tenko user`.
#[derive(Debug, Clone, Subcommand)]
pub enum UserCommand {
    /// Lift the sign-in locks of an account, and give a PIN that expired a new period. Run
    /// as the service account with `tenko serve` stopped.
    Unlock(UnlockArgs),
}

impl UserCommand {
    /// The command as typed.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unlock(_) => "user unlock",
        }
    }
}

/// Arguments of `tenko user unlock`.
#[derive(Debug, Clone, Args)]
pub struct UnlockArgs {
    /// The sign-in name of the account (any case).
    #[arg(value_name = "NAME")]
    pub name: String,

    /// The configuration file of the node.
    #[arg(long, value_name = "FILE", env = "TENKO_CONFIG")]
    pub config: Option<std::path::PathBuf>,

    /// The data directory; overrides `data_dir` of the file.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<std::path::PathBuf>,
}

/// Runs a `tenko user` command.
pub fn command(action: &UserCommand, out: &mut impl Write, err: &mut impl Write) -> u8 {
    match action {
        UserCommand::Unlock(args) => unlock(args, out, err),
    }
}

/// Runs `tenko user unlock`.
pub fn unlock(args: &UnlockArgs, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let sources = config::Sources {
        file: args.config.clone(),
        data_dir: args.data_dir.clone(),
        roles: None,
    };
    let resolved =
        match config::load(&sources, std::env::vars()).and_then(|loaded| loaded.config.resolve()) {
            Ok(resolved) => resolved,
            Err(error) => {
                let _ = writeln!(err, "tenko user unlock: {error}");
                return exit::CONFIG;
            }
        };
    if resolved.layout().is_fresh() {
        let _ = writeln!(
            err,
            "tenko user unlock: {} holds no store yet; there is no account to unlock",
            resolved.data_dir.display()
        );
        return exit::USAGE;
    }
    if let Err(error) = logging::init_server(&resolved.config.log, None, logging::Sink::Console) {
        let _ = writeln!(err, "tenko user unlock: {error}");
        return exit::FAILURE;
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = writeln!(err, "tenko user unlock: runtime: {error}");
            return exit::FAILURE;
        }
    };
    let result = runtime.block_on(run(&resolved, &args.name));
    runtime.shutdown_timeout(Duration::from_secs(5));
    match result {
        Ok(report) => {
            let _ = write!(out, "{report}");
            exit::OK
        }
        Err((status, message)) => {
            let _ = writeln!(err, "tenko user unlock: {message}");
            status
        }
    }
}

async fn run(resolved: &config::Resolved, name: &str) -> Result<String, (u8, String)> {
    let store = RaftStore::open(serve::store_config(resolved))
        .await
        .map_err(|error| {
            (
                exit::START,
                format!(
                    "opening the store (is `tenko serve` still running? stop it first): {error}"
                ),
            )
        })?;
    let members = {
        let metrics = store.raft().metrics();
        let metrics = metrics.borrow();
        let membership = metrics.membership_config.membership();
        membership.voter_ids().count() + membership.learner_ids().count()
    };
    let result = if members > 1 {
        Err((
            exit::USAGE,
            format!(
                "this controller is a member of a cluster of {members} controllers; an \
                 administrator unlocks the account from the web UI on any controller. `tenko \
                 user unlock` is for a stopped single controller"
            ),
        ))
    } else {
        let shared: Arc<dyn Store> = Arc::new(store.clone());
        report(tenko_auth::service::unlock_offline(shared.as_ref(), name, SystemClock.now()).await)
    };
    if let Err(error) = store.shutdown().await {
        tracing::error!(%error, "store shutdown failed");
    }
    result
}

/// The text of the outcome, or the status and message of a failure.
fn report(
    outcome: Result<tenko_auth::service::OfflineUnlock, tenko_auth::AuthError>,
) -> Result<String, (u8, String)> {
    match outcome {
        Ok(done) => {
            let mut text = format!(
                "unlocked {}: {} lock(s) lifted; its waits end when the server starts\n",
                done.name, done.lifted
            );
            if done.pin_renewed {
                text.push_str(
                    "its PIN from before the six-digit minimum had expired: it signs in again \
                     for a new period and must be changed at the next sign-in\n",
                );
            }
            Ok(text)
        }
        Err(tenko_auth::AuthError::NotFound { .. }) => {
            Err((exit::USAGE, "no account has that name".to_owned()))
        }
        Err(error) => Err((exit::FAILURE, error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_names_the_account_and_a_renewed_pin() {
        let text = report(Ok(tenko_auth::service::OfflineUnlock {
            name: "admin".to_owned(),
            lifted: 2,
            pin_renewed: true,
        }))
        .expect("a report");
        assert!(text.starts_with("unlocked admin: 2 lock(s) lifted"));
        assert!(text.contains("must be changed at the next sign-in"));
        let unknown = report(Err(tenko_auth::AuthError::NotFound { kind: "user" }));
        assert_eq!(
            unknown,
            Err((exit::USAGE, "no account has that name".to_owned()))
        );
    }
}
