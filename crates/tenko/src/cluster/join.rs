//! `tenko cluster join`: a host becomes a controller of an existing cluster (OPS-03,
//! WP3.1a deliverable 3).
//!
//! 1. The host enrols like a node (`tenko node enrol`) with a controller token: it checks
//!    the controller's CA root against `--ca-fingerprint`, generates its key, and receives a
//!    certificate with the role `controller` and a node id (1001 and up), which is also its
//!    Raft id. The identity lives in `<data_dir>/node/`, the key sealed like a probe's.
//! 2. It asks the controller for the installation's key encryption keys
//!    (`Cluster.TransferKek`, sealed to a one-time key of this host, S3-Q5) and seals them
//!    with its own KEK provider.
//! 3. It opens an empty store marked as joining (never initialized as a cluster of its
//!    own), opens its cluster port, asks to join (`Cluster.Join`: the leader adds it as a
//!    learner) and waits until it has copied the cluster's data, from the log or a snapshot.
//! 4. It writes the data format marker from the format record it received, closes the
//!    store and writes the configuration: `[node] id` and `address`, `[cluster] listen`.
//!
//! `tenko serve` with that configuration then starts as a member; the leader promotes the
//! learner once it stays caught up, and only to an odd number of voters.

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use clap::Args;
use serde_json::json;
use tenko_cluster::{
    ca::{CertSource, TlsMaterial, TlsResolver},
    error::ClusterError,
    identity::{Credentials, NodePaths, split_host_port},
    kek::{TransferSink, join_context},
    mtls::RevocationSet,
    peers::{NodeDirIdentity, PeerNetwork, PeerTimings, Peers},
    proto::v1,
    server::{ClusterListener, NodeServices, Port, code_of},
    session::Sessions,
    token::EnrolmentToken,
};
use tenko_core::{NodeId, Role};
use tenko_store::{
    Store as _,
    format::{self, Marker},
    raft::{RaftStore, clear_joining, mark_joining},
};
use tokio::sync::watch;

use super::start::{catch_up, peer_config};
use crate::{
    client::{Failure, Output},
    config::Resolved,
    exit,
    node::{
        NodeDirArgs,
        enrol::{EnrolArgs, TOKEN_ENV},
        failure,
    },
};

/// Arguments of `tenko cluster join`.
#[derive(Debug, Clone, Args)]
pub struct JoinArgs {
    /// The configuration file to read and to write the cluster settings into (created
    /// when missing; default `<data_dir>/tenko.toml`), and the data directory.
    #[command(flatten)]
    pub node: NodeDirArgs,

    /// The URL of a controller of the cluster, as administrators open it, for example
    /// `https://ddi.example.net:8443`.
    #[arg(long, value_name = "URL")]
    pub controller: String,

    /// The controller enrolment token (role `controller`, single use, at most an hour);
    /// also from `TENKO_ENROL_TOKEN` or `--token-file`.
    #[arg(long, value_name = "TOKEN", env = TOKEN_ENV, hide_env_values = true)]
    pub token: Option<String>,

    /// A file whose first line is the token.
    #[arg(long, value_name = "FILE", conflicts_with = "token")]
    pub token_file: Option<PathBuf>,

    /// The SHA-256 fingerprint of the cluster's CA root, as the token's page shows it.
    #[arg(long, value_name = "SHA256")]
    pub ca_fingerprint: Option<String>,

    /// The cluster port of this host as the other controllers reach it, `host:port`.
    #[arg(long, value_name = "HOST:PORT")]
    pub address: String,

    /// Where this host's cluster port listens; default all addresses on the port of
    /// `--address`.
    #[arg(long, value_name = "ADDR:PORT")]
    pub listen: Option<String>,

    /// This controller's name in the node registry; default the token's, else the host
    /// name.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// How long to wait for the copy of the cluster's data, in seconds.
    #[arg(long, value_name = "SECS", default_value_t = 600)]
    pub timeout_secs: u64,
}

fn cluster_failure(status: u8, error: &ClusterError) -> Failure {
    failure(status, error)
}

fn read_token(args: &JoinArgs) -> Result<String, Failure> {
    let text = match (&args.token, &args.token_file) {
        (Some(token), _) => token.clone(),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map_err(|error| {
                Failure::new(
                    exit::USAGE,
                    format!("cannot read the token file {}: {error}", path.display()),
                )
            })?
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned(),
        (None, None) => {
            return Err(Failure::new(
                exit::USAGE,
                format!("no enrolment token: pass --token, --token-file or set {TOKEN_ENV}"),
            ));
        }
    };
    EnrolmentToken::parse(&text).map_err(|error| {
        Failure::new(
            exit::USAGE,
            format!("{error}; copy the token exactly as the controller showed it"),
        )
    })?;
    Ok(text)
}

/// The configuration this command reads: the file when it exists, else the defaults.
fn resolve(args: &JoinArgs) -> Result<(Resolved, PathBuf), Failure> {
    let file = args.node.config.clone();
    let reads = NodeDirArgs {
        config: file.clone().filter(|path| path.exists()),
        data_dir: args.node.data_dir.clone(),
        json: args.node.json,
    };
    let resolved = reads.resolve()?;
    let target = file.unwrap_or_else(|| resolved.data_dir.join("tenko.toml"));
    Ok((resolved, target))
}

/// The name a controller enrols with when `--name` is absent: its cluster port's host and
/// port, so several controllers on one host do not collide.
fn default_name(host: &str, port: u16) -> String {
    let host: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let host = host.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    let suffix = format!("-{port}");
    let keep = 63usize.saturating_sub(suffix.len());
    let host: String = host.chars().take(keep).collect();
    if host.is_empty() {
        format!("controller{suffix}")
    } else {
        format!("{host}{suffix}")
    }
}

/// The lines `tenko serve` needs to start as a member.
fn fragment(node: NodeId, address: &str, listen: &str) -> String {
    let quote = |text: &str| toml::Value::String(text.to_owned()).to_string();
    format!(
        "[node]\nid = {}\naddress = {}\n\n[cluster]\nlisten = [{}]\n",
        node.0,
        quote(address),
        quote(listen)
    )
}

/// Writes the cluster settings: into a new file with the data directory, or appended to an
/// existing one that has no `[node]` and `[cluster]` tables yet.
fn write_config(
    target: &Path,
    data_dir: &Path,
    node: NodeId,
    address: &str,
    listen: &str,
) -> Result<String, Failure> {
    let lines = fragment(node, address, listen);
    let failed = |error: std::io::Error| {
        Failure::new(
            exit::FAILURE,
            format!(
                "cannot write {}: {error}; add these lines yourself:\n{lines}",
                target.display()
            ),
        )
    };
    if target.exists() {
        let current = std::fs::read_to_string(target).map_err(failed)?;
        let has_table = |name: &str| {
            current
                .lines()
                .any(|line| line.trim_start().starts_with(&format!("[{name}]")))
        };
        if has_table("node") || has_table("cluster") {
            return Err(Failure::new(
                exit::USAGE,
                format!(
                    "{} has a [node] or [cluster] table already; set these values there:\n{lines}",
                    target.display()
                ),
            ));
        }
        let mut text = current;
        if !text.ends_with('\n') {
            text.push('\n');
        }
        let _ = write!(text, "\n# Written by `tenko cluster join`.\n{lines}");
        std::fs::write(target, text).map_err(failed)?;
    } else {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(failed)?;
        }
        let data_dir = toml::Value::String(data_dir.display().to_string()).to_string();
        let text = format!(
            "# Written by `tenko cluster join`.\ndata_dir = {data_dir}\nroles = \"controller\"\n\n{lines}"
        );
        std::fs::write(target, text).map_err(failed)?;
    }
    Ok(lines)
}

/// Runs `tenko cluster join`.
///
/// # Errors
///
/// The [`Failure`] of the step that failed.
#[allow(
    clippy::too_many_lines,
    reason = "the ceremony reads best as one sequence"
)]
pub async fn run(args: &JoinArgs) -> Result<Output, Failure> {
    let (resolved, target) = resolve(args)?;
    let store_dir = resolved.layout().store();
    if store_dir.join("log.redb").exists() && !tenko_store::raft::is_joining(&store_dir) {
        return Err(Failure::new(
            exit::USAGE,
            format!(
                "{} holds a store already; a controller joins with an empty data directory",
                resolved.data_dir.display()
            ),
        ));
    }
    let (host, port) =
        split_host_port(&args.address).map_err(|error| cluster_failure(exit::USAGE, &error))?;
    let listen = args
        .listen
        .clone()
        .unwrap_or_else(|| format!("0.0.0.0:{port}"));
    let listen_addr: std::net::SocketAddr = listen.parse().map_err(|_| {
        Failure::new(
            exit::USAGE,
            format!("--listen `{listen}` is not an address with a port"),
        )
    })?;
    let token = read_token(args)?;
    let token_id = EnrolmentToken::parse(&token)
        .map_err(|error| Failure::new(exit::USAGE, error.to_string()))?
        .id();

    // 1. Enrolment with the role controller.
    let paths = NodePaths::new(&resolved.data_dir);
    let mut notes = Vec::new();
    if !paths.is_enrolled() {
        let enrolled = crate::node::enrol::run(&EnrolArgs {
            node: NodeDirArgs {
                config: None,
                data_dir: Some(resolved.data_dir.clone()),
                json: false,
            },
            controller: args.controller.clone(),
            token: Some(token),
            token_file: None,
            ca_fingerprint: args.ca_fingerprint.clone(),
            name: Some(
                args.name
                    .clone()
                    .unwrap_or_else(|| default_name(&host, port)),
            ),
            roles: Some(Role::Controller.as_str().to_owned()),
            address: Some(host),
            force: false,
        })
        .await?;
        notes.extend(enrolled.stderr.lines().map(str::to_owned));
    }
    let credentials =
        Credentials::load(&paths).map_err(|error| cluster_failure(exit::FAILURE, &error))?;
    if !credentials.certificate_roles().contains(Role::Controller) {
        return Err(Failure::new(
            exit::USAGE,
            format!(
                "{} holds the identity of a node without the role controller; use an empty \
                 data directory",
                paths.root().display()
            ),
        ));
    }
    let node = credentials.identity.node;
    let network = PeerNetwork::new(node, PeerTimings::default());
    network.set_tls(
        credentials
            .client_config()
            .map_err(|error| cluster_failure(exit::FAILURE, &error))?,
    );
    let seeds = credentials.identity.dial_targets();
    let mut seed = None;
    let mut last = String::from("the enrolment named no cluster endpoint");
    for endpoint in &seeds {
        match network.cluster_client_at(endpoint).await {
            Ok(client) => {
                seed = Some((endpoint.clone(), client));
                break;
            }
            Err(error) => error.detail().clone_into(&mut last),
        }
    }
    let Some((_, mut client)) = seed else {
        return Err(Failure::new(
            exit::UNREACHABLE,
            format!("cannot reach the cluster port of the controller: {last}"),
        ));
    };

    // 2. The key encryption keys.
    let sink = TransferSink::generate().map_err(|error| cluster_failure(exit::FAILURE, &error))?;
    match client
        .transfer_kek(v1::TransferKekRequest {
            ephemeral_public_key: sink.public_key().to_vec(),
            join_token_id: token_id.to_string(),
        })
        .await
    {
        Ok(answer) => {
            let answer = answer.into_inner();
            let ids = sink
                .import(
                    &answer,
                    &join_context(node, token_id),
                    &resolved.kek,
                    &resolved.kek_options,
                )
                .map_err(|error| cluster_failure(exit::FAILURE, &error))?;
            notes.push(format!(
                "received {} key generation(s): {}",
                ids.len(),
                ids.join(", ")
            ));
        }
        Err(status) if code_of(&status) == Some("vault.kek.transfer.used") => {
            notes.push(
                "the keys were transferred with this token before; using the generations \
                 this host holds"
                    .to_owned(),
            );
        }
        Err(status) => {
            return Err(Failure::new(
                exit::API,
                format!(
                    "the controller did not hand over the key encryption keys: [{}] {}",
                    code_of(&status).unwrap_or("cluster.peer.call"),
                    status.message()
                ),
            ));
        }
    }

    // 3. An empty store, the cluster port, the join and the copy.
    mark_joining(&store_dir).map_err(|error| {
        Failure::new(
            exit::FAILURE,
            format!("cannot prepare {}: {error}", store_dir.display()),
        )
    })?;
    let mut config = crate::serve::store_config(&resolved);
    config.node_id = node;
    config.bootstrap = false;
    config.address.clone_from(&args.address);
    config.fsync_probe_samples = 0;
    let store = RaftStore::open(config)
        .await
        .map_err(|error| Failure::new(exit::FAILURE, format!("the store: {error}")))?;
    let mut peers_config = peer_config(&resolved);
    peers_config.local = node;
    peers_config.address.clone_from(&args.address);
    let peers = Peers::new(store.clone(), network.clone(), peers_config);
    peers.attach_identity(Arc::new(NodeDirIdentity::new(&credentials)));
    let listener = ClusterListener::bind(&[listen_addr])
        .await
        .map_err(|error| cluster_failure(exit::FAILURE, &error))?;
    let certificate = Arc::new(TlsResolver::default());
    certificate.set(Some(
        TlsMaterial::from_der(
            credentials.chain.clone(),
            &credentials.key,
            CertSource::Inline,
        )
        .map_err(|error| Failure::other(error.to_string()))?,
    ));
    let (stop, stopped) = watch::channel(false);
    let port = listener
        .serve_port(
            Port {
                ca_root: credentials.ca_root.clone(),
                resolver: certificate,
                revocations: Arc::new(RevocationSet::new()),
                sessions: Sessions::new(),
                nodes: NodeServices::new(),
                peers: Some(peers.clone()),
            },
            stopped,
            || {},
        )
        .map_err(|error| cluster_failure(exit::FAILURE, &error))?;
    let joined = client
        .join(v1::JoinRequest {
            node_id: node.0,
            address: args.address.clone(),
            version: crate::version().to_owned(),
            capabilities: Vec::new(),
            data_format: crate::upgrade::migrations::CURRENT,
        })
        .await;
    let outcome = match joined {
        Ok(answer) => {
            let answer = answer.into_inner();
            // Until the member records arrive with the data, the answer names the ports.
            for member in &answer.members {
                if !member.address.is_empty() && member.node_id != node.0 {
                    network.pin(NodeId(member.node_id), member.address.clone());
                }
            }
            copy(&store, node, Duration::from_secs(args.timeout_secs)).await
        }
        Err(status) => Err(Failure::new(
            if code_of(&status) == Some("cluster.join.format_newer") {
                exit::UPGRADE_REFUSED
            } else {
                exit::API
            },
            format!(
                "the cluster refused the join: [{}] {}",
                code_of(&status).unwrap_or("cluster.peer.call"),
                status.message()
            ),
        )),
    };
    let _ = stop.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(10), port).await;
    let _ = store.shutdown().await;
    drop(peers);
    let (revision, format) = outcome?;

    // 4. The format marker and the configuration.
    format::write_marker(&store_dir, &Marker::new(format, crate::version()))
        .map_err(|error| Failure::other(error.to_string()))?;
    let _ = clear_joining(&store_dir);
    let lines = write_config(&target, &resolved.data_dir, node, &args.address, &listen)?;
    if args.node.json {
        let mut output = Output::json(&json!({
            "node": node,
            "revision": revision,
            "data_format": format,
            "config": target,
        }));
        for note in notes {
            output = output.note(note);
        }
        return Ok(output);
    }
    let mut text = String::new();
    let _ = writeln!(
        text,
        "joined the controller cluster as node {node}, a learner with the cluster's data up to revision {revision}"
    );
    let _ = writeln!(text, "configuration: {}", target.display());
    let _ = write!(text, "{lines}");
    let _ = writeln!(
        text,
        "start it with `tenko serve --config {}`; the leader promotes it to a voter once it stays caught up",
        target.display()
    );
    let mut output = Output::text(text);
    for note in notes {
        output = output.note(note);
    }
    Ok(output)
}

/// Waits until this learner holds the cluster's data and returns the revision and the data
/// format it copied.
async fn copy(store: &RaftStore, node: NodeId, timeout: Duration) -> Result<(u64, u32), Failure> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let membership = store.membership();
        let known = membership.learners.contains(&node) || membership.voters.contains(&node);
        if known && catch_up(store, Duration::from_secs(5)).await {
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err(Failure::new(
                exit::UNREACHABLE,
                format!(
                    "the cluster's data did not arrive within {} s; check that the other \
                     controllers reach this host's cluster port, then run the command again",
                    timeout.as_secs()
                ),
            ));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let view = store
        .read(tenko_store::ReadConsistency::Local)
        .await
        .map_err(|error| Failure::other(error.to_string()))?;
    let stored = format::read_stored(view.as_ref())
        .map_err(|error| Failure::other(error.to_string()))?
        .map_or(crate::upgrade::migrations::CURRENT, |(stored, _)| {
            stored.version
        });
    let revision = view.revision().0;
    drop(view);
    if stored > crate::upgrade::migrations::CURRENT {
        return Err(Failure::new(
            exit::UPGRADE_REFUSED,
            format!(
                "[cluster.join.format_newer] the cluster's data is in format {stored}, which \
                 this binary (format {}) does not know; upgrade it first",
                crate::upgrade::migrations::CURRENT
            ),
        ));
    }
    Ok((revision, stored))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_names_are_valid_and_distinct_per_port() {
        assert_eq!(default_name("127.0.0.1", 18452), "127.0.0.1-18452");
        assert_eq!(default_name("[2001:db8::2]", 8444), "2001-db8--2-8444");
        assert_eq!(
            default_name("Controller-2.Example.test", 8444),
            "controller-2.example.test-8444"
        );
        let long = default_name(&"a".repeat(100), 8444);
        assert!(long.len() <= 63);
        assert!(tenko_cluster::registry::check_name(&long).is_ok());
    }

    #[test]
    fn the_fragment_names_the_node_and_its_port() {
        let lines = fragment(
            NodeId(1001),
            "controller-2.example.test:8444",
            "0.0.0.0:8444",
        );
        let parsed: toml::Value = toml::from_str(&lines).expect("valid TOML");
        assert_eq!(parsed["node"]["id"].as_integer(), Some(1001));
        assert_eq!(
            parsed["node"]["address"].as_str(),
            Some("controller-2.example.test:8444")
        );
        assert_eq!(
            parsed["cluster"]["listen"][0].as_str(),
            Some("0.0.0.0:8444")
        );
    }

    #[test]
    fn the_configuration_is_created_or_extended_once() {
        let dir = std::env::temp_dir().join(format!(
            "tenko-join-config-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
        ));
        let file = dir.join("tenko.toml");
        write_config(&file, &dir, NodeId(1001), "192.0.2.12:8444", "0.0.0.0:8444")
            .expect("created");
        let text = std::fs::read_to_string(&file).expect("read");
        let parsed: toml::Value = toml::from_str(&text).expect("valid TOML");
        assert_eq!(parsed["node"]["id"].as_integer(), Some(1001));
        assert!(parsed["data_dir"].as_str().is_some());
        // `tenko serve --config` reads the new file as it is.
        let config: crate::config::Config =
            toml::from_str(&text).expect("a configuration tenko serve reads");
        assert_eq!(config.roles, "controller");
        let again = write_config(&file, &dir, NodeId(1001), "192.0.2.12:8444", "0.0.0.0:8444")
            .expect_err("a second time");
        assert_eq!(again.status, exit::USAGE);
        let other = dir.join("other.toml");
        std::fs::write(&other, "roles = [\"controller\"]").expect("write");
        write_config(
            &other,
            &dir,
            NodeId(1002),
            "192.0.2.13:8444",
            "0.0.0.0:8444",
        )
        .expect("appended");
        let parsed: toml::Value =
            toml::from_str(&std::fs::read_to_string(&other).expect("read")).expect("valid TOML");
        assert_eq!(parsed["node"]["id"].as_integer(), Some(1002));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
