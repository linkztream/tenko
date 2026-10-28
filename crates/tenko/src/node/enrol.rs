//! `tenko node enrol`: the enrolment ceremony on a data-plane node (OPS-04).
//!
//! 1. The node reads the token (flag, `TENKO_ENROL_TOKEN` or a file) and checks its form.
//! 2. It fetches the CA root from `GET /system/ca-root` without trusting the server yet,
//!    and compares its SHA-256 with `--ca-fingerprint` when given (the fingerprint the
//!    controller printed at start and shows with every token). From then on the API
//!    connection trusts that root only. A controller whose API certificate does not come
//!    from the internal CA (an imported certificate, a reverse proxy) answers 404, and the
//!    system roots verify the API connection instead.
//! 3. It generates its key pair (the key never leaves the node) and posts a certificate
//!    request with the token to `POST /nodes/enrol`.
//! 4. It checks the CA root of the answer against the fingerprint and the root of step 2,
//!    and writes its identity, certificate, key and CA root to `<data_dir>/node/`.

use std::{path::PathBuf, time::Duration};

use std::fmt::Write as _;

use clap::Args;
use serde_json::json;
use tenko_cluster::{
    ca::{CertInfo, generate_csr, pem_block},
    identity::{Credentials, NodeIdentity, NodePaths, url_host},
    model::{EnrolRequest, EnrolResponse},
    token::EnrolmentToken,
    version,
};
use tenko_core::{Role, Timestamp};

use super::{NodeDirArgs, failure};
use crate::{
    client::{Failure, Output},
    exit,
};

/// The environment variable that may carry the token instead of `--token`.
pub const TOKEN_ENV: &str = "TENKO_ENROL_TOKEN";

const TIMEOUT: Duration = Duration::from_secs(30);

/// Arguments of `tenko node enrol`.
#[derive(Debug, Clone, Args)]
pub struct EnrolArgs {
    /// Where this node keeps its files.
    #[command(flatten)]
    pub node: NodeDirArgs,

    /// The controller's URL, as administrators open it, for example
    /// `https://ddi.example.net:8443`.
    #[arg(long, value_name = "URL")]
    pub controller: String,

    /// The enrolment token. It is single-use and expires; it can also come from
    /// `TENKO_ENROL_TOKEN` or `--token-file`.
    #[arg(long, value_name = "TOKEN", env = TOKEN_ENV, hide_env_values = true)]
    pub token: Option<String>,

    /// A file whose first line is the enrolment token.
    #[arg(long, value_name = "FILE", conflicts_with = "token")]
    pub token_file: Option<PathBuf>,

    /// The SHA-256 fingerprint of the controller's CA root (hexadecimal, colons allowed),
    /// as the controller printed it at start and shows with every token. Without it the
    /// root is trusted on first use.
    #[arg(long, value_name = "SHA256")]
    pub ca_fingerprint: Option<String>,

    /// The node's name; the token's name wins when it has one. Default: the host name.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// The roles this node runs, comma-separated; default the token's roles.
    #[arg(long, value_name = "ROLES")]
    pub roles: Option<String>,

    /// The node's address as the controller should show it; default the address the
    /// controller sees.
    #[arg(long, value_name = "ADDRESS")]
    pub address: Option<String>,

    /// Enrol again although this node is enrolled: the old identity is replaced.
    #[arg(long)]
    pub force: bool,
}

/// A SHA-256 fingerprint in lower-case hexadecimal.
///
/// # Errors
///
/// A usage failure when it is not 64 hexadecimal digits.
pub fn normalize_fingerprint(text: &str) -> Result<String, Failure> {
    let hex: String = text
        .chars()
        .filter(|c| !matches!(c, ':' | ' ' | '-'))
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(hex)
    } else {
        Err(Failure::new(
            exit::USAGE,
            "--ca-fingerprint must be a SHA-256: 64 hexadecimal digits, colons allowed",
        ))
    }
}

fn read_token(args: &EnrolArgs) -> Result<EnrolmentToken, Failure> {
    let parse = |text: &str| {
        EnrolmentToken::parse(text).map_err(|error| {
            Failure::new(
                exit::USAGE,
                format!("{error}; copy the token exactly as the controller showed it"),
            )
        })
    };
    match (&args.token, &args.token_file) {
        (Some(token), _) => parse(token),
        (None, Some(path)) => {
            let content = std::fs::read_to_string(path).map_err(|error| {
                Failure::new(
                    exit::USAGE,
                    format!("cannot read the token file {}: {error}", path.display()),
                )
            })?;
            parse(content.lines().next().unwrap_or_default())
        }
        (None, None) => Err(Failure::new(
            exit::USAGE,
            format!("no enrolment token: pass --token, --token-file or set {TOKEN_ENV}"),
        )),
    }
}

fn root_of(pem: &str) -> Result<CertInfo, Failure> {
    let certificates = crate::serve::pem_certificates(pem.as_bytes());
    let [der] = certificates.as_slice() else {
        return Err(Failure::other(format!(
            "the controller sent {} certificates as its CA root instead of one",
            certificates.len()
        )));
    };
    let info = CertInfo::from_der(der)
        .map_err(|error| Failure::other(format!("the CA root is unreadable: {error}")))?;
    if !info.is_ca {
        return Err(Failure::other(
            "the certificate the controller sent as its CA root is not a CA certificate",
        ));
    }
    Ok(info)
}

fn http_client(root: Option<&str>) -> Result<reqwest::Client, Failure> {
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(TIMEOUT)
        .user_agent(format!("tenko/{}", crate::version()));
    if let Some(pem) = root {
        let certificate = reqwest::Certificate::from_pem(pem.as_bytes())
            .map_err(|error| Failure::other(format!("the CA root is not PEM: {error}")))?;
        builder = builder
            .tls_built_in_root_certs(false)
            .add_root_certificate(certificate);
    }
    builder
        .build()
        .map_err(|error| Failure::other(format!("HTTP client: {error}")))
}

fn unreachable(controller: &str, error: &reqwest::Error) -> Failure {
    let mut detail = error.to_string();
    let mut cause = std::error::Error::source(error);
    while let Some(inner) = cause {
        detail = format!("{detail}: {inner}");
        cause = inner.source();
    }
    let hint = if detail.contains("NotValidForName") || detail.contains("not valid for") {
        "; the controller's certificate does not name this host: use the host name the \
         controller was set up with"
    } else {
        ""
    };
    Failure::new(
        exit::UNREACHABLE,
        format!("cannot reach {controller}: {detail}{hint}"),
    )
}

/// Fetches the CA root without verifying the server; `None` when the API does not use the
/// internal CA (404).
async fn fetch_root(controller: &str) -> Result<Option<String>, Failure> {
    let http = reqwest::Client::builder()
        .use_rustls_tls()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(TIMEOUT)
        .user_agent(format!("tenko/{}", crate::version()))
        .build()
        .map_err(|error| Failure::other(format!("HTTP client: {error}")))?;
    let url = format!("{controller}{}/system/ca-root", tenko_api::API_BASE);
    let response = http
        .get(&url)
        .send()
        .await
        .map_err(|error| unreachable(controller, &error))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| unreachable(controller, &error))?;
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(Failure::new(
            exit::API,
            format!("the controller answered HTTP {status} for its CA root"),
        ));
    }
    Ok(Some(body))
}

/// The machine's host name as a node registry name: lower case, every character other than a
/// letter, a digit or a hyphen replaced by a hyphen; `None` when it cannot be read or is not a
/// valid name. The enrolment proposes it, and the start page shows it (U3).
pub(crate) fn host_name() -> Option<String> {
    let name = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|text| text.trim().to_owned())
        })?;
    let name: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let name = name.trim_matches('-').to_owned();
    (!name.is_empty() && tenko_cluster::registry::check_name(&name).is_ok()).then_some(name)
}

/// Runs `tenko node enrol`.
///
/// # Errors
///
/// The [`Failure`] of the ceremony.
#[allow(
    clippy::too_many_lines,
    reason = "the ceremony reads best as one sequence"
)]
pub async fn run(args: &EnrolArgs) -> Result<Output, Failure> {
    let resolved = args.node.resolve()?;
    let paths = NodePaths::new(&resolved.data_dir);
    if paths.is_enrolled() && !args.force {
        return Err(Failure::new(
            exit::USAGE,
            format!(
                "this node is enrolled already ({}); pass --force to enrol it again",
                paths.identity().display()
            ),
        ));
    }
    let controller = args.controller.trim().trim_end_matches('/').to_owned();
    if url_host(&controller).is_none() {
        return Err(Failure::new(
            exit::USAGE,
            format!("`{controller}` is not an http(s) URL such as https://ddi.example.net:8443"),
        ));
    }
    let wanted = args
        .ca_fingerprint
        .as_deref()
        .map(normalize_fingerprint)
        .transpose()?;
    if controller.starts_with("http://") && wanted.is_none() {
        return Err(Failure::new(
            exit::USAGE,
            "a controller on plain HTTP needs --ca-fingerprint: nothing else protects the token",
        ));
    }
    let token = read_token(args)?;
    let roles: Vec<Role> = match &args.roles {
        Some(text) => text
            .parse::<tenko_core::RoleSet>()
            .map_err(|error| Failure::new(exit::USAGE, format!("--roles: {error}")))?
            .roles()
            .collect(),
        None => Vec::new(),
    };

    // Step 2: the CA root, checked against the fingerprint.
    let mut notes = Vec::new();
    let fetched = fetch_root(&controller).await?;
    let api_root = match &fetched {
        Some(pem) => {
            let info = root_of(pem)?;
            match &wanted {
                Some(wanted) if *wanted != info.sha256 => {
                    return Err(Failure::new(
                        exit::INTEGRITY,
                        format!(
                            "the controller's CA root has SHA-256 {}, not {wanted}: do not \
                             trust it; check the fingerprint the controller printed at start",
                            info.sha256
                        ),
                    ));
                }
                Some(_) => {}
                None => notes.push(format!(
                    "warning: no --ca-fingerprint given; trusting the CA root {} with SHA-256 \
                     {} on first use; compare it with the fingerprint the controller printed",
                    info.subject, info.sha256
                )),
            }
            Some(pem.clone())
        }
        None => None,
    };

    // Step 3: the key and the request.
    let (key, csr) = generate_csr().map_err(|error| Failure::other(error.to_string()))?;
    let request = EnrolRequest {
        token: token.to_text().to_string(),
        csr: pem_block("CERTIFICATE REQUEST", &csr),
        name: args.name.clone().or_else(host_name),
        roles,
        address: args.address.clone(),
        version: crate::version().to_owned(),
        majors: version::SUPPORTED_MAJORS.to_vec(),
    };
    drop(token);
    let http = http_client(api_root.as_deref())?;
    let url = format!("{controller}{}/nodes/enrol", tenko_api::API_BASE);
    let response = http
        .post(&url)
        .json(&request)
        .send()
        .await
        .map_err(|error| unreachable(&controller, &error))?;
    drop(request);
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|error| unreachable(&controller, &error))?;
    if !status.is_success() {
        return Err(
            match serde_json::from_slice::<tenko_api::problem::ProblemDetails>(&body) {
                Ok(problem) => {
                    let mut failure = Failure::problem(problem);
                    failure.status = if status.as_u16() == 401 {
                        exit::AUTH
                    } else {
                        exit::API
                    };
                    failure
                }
                Err(_) => Failure::new(exit::API, format!("unexpected HTTP status {status}")),
            },
        );
    }
    let answer: EnrolResponse = serde_json::from_slice(&body)
        .map_err(|error| Failure::other(format!("unexpected answer: {error}")))?;

    // Step 4: the CA root of the answer is the one the fingerprint names.
    let ca = root_of(&answer.ca_root)?;
    if let Some(wanted) = &wanted
        && *wanted != ca.sha256
    {
        return Err(Failure::new(
            exit::INTEGRITY,
            format!(
                "the controller's cluster CA root has SHA-256 {}, not {wanted}: the node was \
                 registered but is not configured; revoke it on the controller",
                ca.sha256
            ),
        ));
    }
    if let Some(pem) = &api_root
        && root_of(pem)?.sha256 != ca.sha256
    {
        return Err(Failure::new(
            exit::INTEGRITY,
            "the controller's cluster CA root differs from its API CA root; revoke the node on \
             the controller",
        ));
    }
    let identity = NodeIdentity {
        node: answer.node.id,
        name: answer.node.name.clone(),
        roles: answer.node.roles.clone(),
        controller: controller.clone(),
        endpoints: answer.endpoints.clone(),
        cluster_port: answer.cluster_port,
        heartbeat_secs: answer.heartbeat_secs,
        enrolled_at: Timestamp::now(),
        ca_sha256: ca.sha256.clone(),
    };
    let credentials = Credentials::from_pem(identity, &answer.certificate, key, &answer.ca_root)
        .map_err(|error| failure(exit::FAILURE, &error))?;
    credentials
        .save(&paths)
        .map_err(|error| failure(exit::FAILURE, &error))?;
    let targets = credentials.identity.dial_targets();
    let roles = answer
        .node
        .roles
        .iter()
        .map(|role| role.as_str())
        .collect::<Vec<_>>()
        .join(",");
    if args.node.json {
        let mut output = Output::json(&json!({
            "node": answer.node.id,
            "name": answer.node.name,
            "roles": answer.node.roles,
            "endpoints": targets,
            "not_after": credentials.info.not_after,
            "ca_sha256": ca.sha256,
            "files": paths.root(),
        }));
        for note in notes {
            output = output.note(note);
        }
        return Ok(output);
    }
    let mut text = String::new();
    let _ = writeln!(
        text,
        "enrolled as node {} ({}) with role(s) {roles}",
        answer.node.id, answer.node.name
    );
    let _ = writeln!(text, "cluster endpoint(s): {}", targets.join(", "));
    let _ = writeln!(
        text,
        "certificate valid until {}; CA root SHA-256 {}",
        credentials.info.not_after, ca.sha256
    );
    let _ = writeln!(text, "files: {}", paths.root().display());
    let _ = writeln!(
        text,
        "start the node with `tenko serve --roles {roles} --data-dir {}`",
        resolved.data_dir.display()
    );
    let mut output = Output::text(text);
    for note in notes {
        output = output.note(note);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_normalized() {
        let hex = "AB:".repeat(31) + "AB";
        assert_eq!(normalize_fingerprint(&hex).expect("valid"), "ab".repeat(32));
        assert!(normalize_fingerprint("abc").is_err());
    }
}
