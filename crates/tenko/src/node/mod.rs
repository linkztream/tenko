//! `tenko node`: the data-plane side of the cluster (OPS-04, OPS-08, OPS-28).
//!
//! | Module | Contents |
//! |---|---|
//! | [`controller`] | the `cluster` start step of `tenko serve` on a controller |
//! | [`agent`] | `tenko serve` without the controller role: the node process of a data-plane node |
//! | [`enrol`] | `tenko node enrol`: the enrolment ceremony on the node |
//! | [`status`] | `tenko node status` and `tenko node renew` |
//! | [`token`] | `tenko node enrol-token`: a token from a controller, for scripts |
//! | [`inject`] | `tenko node inject`: queue a batch of observations from a file (diagnostics) |
//!
//! docs/cluster.md describes the ceremony, certificates, revocation and the ports.

use std::{io::Write, path::PathBuf};

use clap::{Args, Subcommand};

pub mod agent;
pub mod controller;
pub mod enrol;
pub mod inject;
pub mod status;
pub mod token;

use crate::{
    client::{self, Failure},
    config::{self, Resolved},
    exit,
};

/// Subcommands of `tenko node`.
#[derive(Debug, Subcommand)]
pub enum NodeCommand {
    /// Enrol this node with a controller: get a node certificate with an enrolment token.
    Enrol(enrol::EnrolArgs),
    /// Show this node's identity, certificate and connection.
    Status(status::StatusArgs),
    /// Renew this node's certificate now, over the mutual TLS channel.
    Renew(status::RenewArgs),
    /// Create a single-use enrolment token on a controller (administrators).
    EnrolToken(token::EnrolTokenArgs),
    /// Queue a batch of observations from a JSON file for the controller (diagnostics).
    #[command(hide = true)]
    Inject(inject::InjectArgs),
}

impl NodeCommand {
    /// The command as typed on the command line, such as `node enrol`.
    pub fn name(&self) -> &'static str {
        match self {
            NodeCommand::Enrol(_) => "node enrol",
            NodeCommand::Status(_) => "node status",
            NodeCommand::Renew(_) => "node renew",
            NodeCommand::EnrolToken(_) => "node enrol-token",
            NodeCommand::Inject(_) => "node inject",
        }
    }

    fn json(&self) -> bool {
        match self {
            NodeCommand::Enrol(args) => args.node.json,
            NodeCommand::Status(args) => args.node.json,
            NodeCommand::Renew(args) => args.node.json,
            NodeCommand::EnrolToken(args) => args.client.json,
            NodeCommand::Inject(args) => args.node.json,
        }
    }
}

/// Where a node keeps its files: the data directory of the configuration.
#[derive(Debug, Clone, Args)]
pub struct NodeDirArgs {
    /// The configuration file (`tenko.toml`).
    #[arg(long, value_name = "FILE", env = "TENKO_CONFIG")]
    pub config: Option<PathBuf>,

    /// The data directory of this node; overrides `data_dir` of the file.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,

    /// Print JSON.
    #[arg(long)]
    pub json: bool,
}

impl NodeDirArgs {
    /// The validated configuration these flags name.
    ///
    /// # Errors
    ///
    /// A configuration failure (exit status 3).
    pub fn resolve(&self) -> Result<Resolved, Failure> {
        let sources = config::Sources {
            file: self.config.clone(),
            data_dir: self.data_dir.clone(),
            roles: None,
        };
        config::load(&sources, std::env::vars())
            .and_then(|loaded| loaded.config.resolve())
            .map_err(|error| Failure::new(exit::CONFIG, error.to_string()))
    }
}

/// The failure of a cluster error, with its code.
pub fn failure(status: u8, error: &tenko_cluster::error::ClusterError) -> Failure {
    Failure::new(status, format!("[{}] {}", error.code(), error.detail()))
}

/// Runs a `tenko node` subcommand and returns the exit status.
pub fn command(action: &NodeCommand, out: &mut impl Write, err: &mut impl Write) -> u8 {
    crate::logging::init_client();
    let name = action.name();
    let json = action.json();
    match action {
        NodeCommand::Enrol(args) => client::block_on(name, json, out, err, enrol::run(args)),
        NodeCommand::Status(args) => client::block_on(name, json, out, err, status::status(args)),
        NodeCommand::Renew(args) => client::block_on(name, json, out, err, status::renew(args)),
        NodeCommand::EnrolToken(args) => client::block_on(name, json, out, err, token::run(args)),
        NodeCommand::Inject(args) => {
            client::block_on(name, json, out, err, async { inject::run(args) })
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use crate::{Cli, Command};

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("tenko").chain(args.iter().copied()))
    }

    #[test]
    fn node_commands_parse_and_name_themselves() {
        let cases: [(&[&str], &str); 5] = [
            (
                &[
                    "node",
                    "enrol",
                    "--controller",
                    "https://ddi.example.net:8443",
                    "--token",
                    "tnk1.x.y",
                ],
                "node enrol",
            ),
            (&["node", "status", "--check"], "node status"),
            (&["node", "renew"], "node renew"),
            (
                &["node", "enrol-token", "--roles", "probe"],
                "node enrol-token",
            ),
            (&["node", "inject", "--file", "batch.json"], "node inject"),
        ];
        for (args, name) in cases {
            let cli = parse(args).expect("valid arguments");
            let Command::Node { action } = &cli.command else {
                panic!("not a node command");
            };
            assert_eq!(action.name(), name);
            assert_eq!(cli.command.name(), name);
        }
    }

    #[test]
    fn enrol_needs_a_controller() {
        assert!(parse(&["node", "enrol", "--token", "tnk1.x.y"]).is_err());
    }
}
