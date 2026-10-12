//! `tenko health`: the readiness probe (`GET /health/ready`) or, with `--live`, the
//! liveness probe (`GET /health`), for container health checks and scripts. It needs no
//! credentials: exit status 0 when the node answers, 5 when it answers that it is not
//! ready, 7 when it cannot be reached.

use clap::Args;

use super::{ClientOpts, Failure, Output, Target};

/// Arguments of `tenko health`.
#[derive(Debug, Clone, Args)]
pub struct HealthArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,

    /// Ask the liveness probe instead of the readiness probe.
    #[arg(long)]
    pub live: bool,
}

/// Runs `tenko health`.
///
/// # Errors
///
/// The [`Failure`] of the probe.
pub async fn run(args: &HealthArgs) -> Result<Output, Failure> {
    let target = Target::resolve(&args.client, false)?;
    let client = target.connect().await?;
    if args.live {
        let health = client.health().await?;
        if target.json {
            return Ok(Output::json(&health));
        }
        return Ok(Output::text(format!(
            "{}: {} (version {})\n",
            target.url, health.status, health.version
        )));
    }
    let ready = client.ready().await?;
    if target.json {
        return Ok(Output::json(&ready));
    }
    Ok(Output::text(format!(
        "{}: {} at revision {}\n",
        target.url, ready.status, ready.revision
    )))
}
