//! `tenko node enrol-token`: creates an enrolment token on a controller through the API
//! (`POST /nodes/enrolments`), with the credentials of `tenko login`.

use clap::Args;
use tenko_cluster::model::{CreatedEnrolment, NewEnrolment};
use tenko_core::VrfId;

use crate::{
    client::{ClientOpts, Failure, Output, Target},
    exit,
};

/// Arguments of `tenko node enrol-token`.
#[derive(Debug, Clone, Args)]
pub struct EnrolTokenArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,

    /// The roles the node may take, comma-separated (`probe`, `dns`, `dhcp`); default
    /// `probe`.
    #[arg(long, value_name = "ROLES")]
    pub roles: Option<String>,

    /// The name the node gets; without it the node chooses one.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// The VRF of the node's observations (its id); default the default VRF.
    #[arg(long, value_name = "UUID")]
    pub vrf: Option<VrfId>,

    /// Seconds until the token expires: 60 to 604800; default the controller's setting
    /// (one hour).
    #[arg(long, value_name = "SECONDS")]
    pub expires_in: Option<u64>,
}

/// Runs `tenko node enrol-token`.
///
/// # Errors
///
/// Not signed in, or the controller refuses.
pub async fn run(args: &EnrolTokenArgs) -> Result<Output, Failure> {
    let target = Target::resolve(&args.client, true)?;
    let roles = match &args.roles {
        Some(text) => text
            .parse::<tenko_core::RoleSet>()
            .map_err(|error| Failure::new(exit::USAGE, format!("--roles: {error}")))?
            .roles()
            .collect(),
        None => Vec::new(),
    };
    let request = NewEnrolment {
        roles,
        name: args.name.clone(),
        vrf: args.vrf,
        expires_in_secs: args.expires_in,
    };
    let created: CreatedEnrolment = target
        .client()?
        .post("/nodes/enrolments", &request, None)
        .await
        .map_err(|error| Failure::from_client(&error))?;
    if target.json {
        return Ok(Output::json(&created));
    }
    // The token is the one secret this command prints, by design: it is single-use and
    // expires, and the node needs it.
    let roles = created
        .enrolment
        .roles
        .iter()
        .map(|role| role.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let command = created.command.replace(
        "https://<controller>:8443",
        target.url.trim_end_matches('/'),
    );
    Ok(Output::text(format!("{}\n", created.token)).note(format!(
        "enrolment token {} for role(s) {roles}, valid until {}; it works once\n\
         CA root SHA-256: {}\n\
         on the node, run:\n  {command}",
        created.enrolment.id, created.enrolment.expires_at, created.ca_fingerprint
    )))
}
