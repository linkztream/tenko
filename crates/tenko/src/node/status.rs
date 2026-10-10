//! `tenko node status` and `tenko node renew`.

use std::fmt::Write as _;

use clap::Args;
use serde_json::json;
use tenko_cluster::{
    client,
    identity::{AgentStatus, Credentials, NodePaths},
    version,
};
use tenko_core::Timestamp;

use super::{NodeDirArgs, failure};
use crate::{
    client::{Failure, Output},
    exit,
};

/// Arguments of `tenko node status`.
#[derive(Debug, Clone, Args)]
pub struct StatusArgs {
    /// Where this node keeps its files.
    #[command(flatten)]
    pub node: NodeDirArgs,

    /// Also connect to the controller and say hello (checks the certificate, the CA and
    /// the protocol versions); exit status 7 when that fails.
    #[arg(long)]
    pub check: bool,
}

/// Arguments of `tenko node renew`.
#[derive(Debug, Clone, Args)]
pub struct RenewArgs {
    /// Where this node keeps its files.
    #[command(flatten)]
    pub node: NodeDirArgs,
}

fn load(node: &NodeDirArgs) -> Result<(NodePaths, Credentials), Failure> {
    let resolved = node.resolve()?;
    let paths = NodePaths::new(&resolved.data_dir);
    let credentials = Credentials::load(&paths).map_err(|error| {
        let status = if error.code() == "cluster.node.not_enrolled" {
            exit::USAGE
        } else {
            exit::FAILURE
        };
        failure(status, &error)
    })?;
    Ok((paths, credentials))
}

/// Runs `tenko node status`.
///
/// # Errors
///
/// The node is not enrolled or its files are unreadable.
#[allow(
    clippy::too_many_lines,
    reason = "the text and the JSON form side by side"
)]
pub async fn status(args: &StatusArgs) -> Result<Output, Failure> {
    let (paths, credentials) = load(&args.node)?;
    let running = AgentStatus::load(&paths).map_err(|error| failure(exit::FAILURE, &error))?;
    let check = if args.check {
        Some(client::check(&credentials, crate::version(), version::SUPPORTED_MAJORS).await)
    } else {
        None
    };
    let identity = &credentials.identity;
    let expiry = credentials.info.expiry(Timestamp::now());
    let check_failed = matches!(check, Some(Err(_)));
    let mut output = if args.node.json {
        let check = check.as_ref().map(|result| match result {
            Ok(agreed) => json!({
                "ok": true,
                "endpoint": agreed.endpoint,
                "major": agreed.major,
                "controller_version": agreed.controller_version,
            }),
            Err((state, error)) => json!({
                "ok": false,
                "state": state,
                "code": error.code,
                "detail": error.detail,
            }),
        });
        Output::json(&json!({
            "node": identity.node,
            "name": identity.name,
            "roles": identity.roles,
            "controller": identity.controller,
            "endpoints": identity.dial_targets(),
            "certificate": {
                "serial": credentials.info.serial,
                "not_after": credentials.info.not_after,
                "days_left": expiry.days_left,
                "state": expiry.state,
                "renewal_due": credentials.needs_renewal(Timestamp::now()),
            },
            "ca_sha256": identity.ca_sha256,
            "process": running,
            "check": check,
        }))
    } else {
        let mut text = String::new();
        let roles = identity
            .roles
            .iter()
            .map(|role| role.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let _ = writeln!(
            text,
            "node {} ({}), role(s) {roles}",
            identity.node, identity.name
        );
        let _ = writeln!(text, "controller: {}", identity.controller);
        let _ = writeln!(
            text,
            "cluster endpoint(s): {}",
            identity.dial_targets().join(", ")
        );
        let _ = writeln!(
            text,
            "certificate: serial {}, valid until {} ({} days left{})",
            credentials.info.serial,
            credentials.info.not_after,
            expiry.days_left,
            if credentials.needs_renewal(Timestamp::now()) {
                ", renewal due"
            } else {
                ""
            }
        );
        let _ = writeln!(text, "CA root SHA-256: {}", identity.ca_sha256);
        match &running {
            Some(status) => {
                let state = serde_json::to_value(status.state)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_default();
                let _ = writeln!(
                    text,
                    "node process: {state} since {} (pid {}, updated {})",
                    status.since, status.pid, status.updated_at
                );
                if let Some(buffer) = &status.buffer {
                    let _ = writeln!(
                        text,
                        "buffer: {} batch(es), {} bytes waiting, {} dropped",
                        buffer.batches, buffer.bytes, buffer.dropped
                    );
                }
                if let Some(error) = &status.last_error {
                    let _ = writeln!(
                        text,
                        "last error: [{}] {} ({})",
                        error.code, error.detail, error.at
                    );
                }
            }
            None => text.push_str("node process: has not run yet\n"),
        }
        match &check {
            Some(Ok(agreed)) => {
                let _ = writeln!(
                    text,
                    "check: connected to {} (controller {}, protocol major {})",
                    agreed.endpoint, agreed.controller_version, agreed.major
                );
            }
            Some(Err((_, error))) => {
                let _ = writeln!(text, "check: failed [{}] {}", error.code, error.detail);
            }
            None => {}
        }
        Output::text(text)
    };
    if check_failed {
        output.status = exit::UNREACHABLE;
    }
    Ok(output)
}

/// Runs `tenko node renew`.
///
/// # Errors
///
/// The node is not enrolled, the controller cannot be reached or refuses.
pub async fn renew(args: &RenewArgs) -> Result<Output, Failure> {
    let (paths, before) = load(&args.node)?;
    let renewed = client::renew_once(&paths, crate::version())
        .await
        .map_err(|error| failure(exit::UNREACHABLE, &error))?;
    if args.node.json {
        return Ok(Output::json(&json!({
            "node": renewed.identity.node,
            "previous_serial": before.info.serial,
            "serial": renewed.info.serial,
            "not_after": renewed.info.not_after,
        })));
    }
    Ok(Output::text(format!(
        "renewed the certificate of node {}: serial {}, valid until {}\n\
         a running node process uses it from its next connection\n",
        renewed.identity.node, renewed.info.serial, renewed.info.not_after
    )))
}
