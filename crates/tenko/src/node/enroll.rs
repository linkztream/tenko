//! `tenko node enroll`: the enrollment ceremony on a data-plane node (OPS-04).
//!
//! 0. A controller URL with plain `http://` is refused before the token is read, unless
//!    `--insecure-plain-http` names the choice; the command then warns what a listener on
//!    the path obtains, and the controller accepts it only under the Lab profile.
//! 1. The node reads the token (flag, `TENKO_ENROLL_TOKEN` or a file) and checks its form.
//!    A `tnk2` token carries the SHA-256 fingerprint of the controller's CA root;
//!    `--ca-fingerprint`, when given as well, must agree with it, else the command stops
//!    here, before any network call.
//! 2. It fetches the CA root from `GET /system/ca-root` without trusting the server yet,
//!    and compares its SHA-256 with the token's fingerprint, or with `--ca-fingerprint` for
//!    a `tnk1` token (the fingerprint the controller printed at start and shows with every
//!    token). A `tnk1` token without the flag trusts the root on first use, with a warning,
//!    until 0.0.13. From then on the API connection trusts that root only. A controller whose
//!    API certificate does not come from the internal CA (an imported certificate, a reverse
//!    proxy) answers 404, and the system roots verify the API connection instead.
//! 3. It generates its key pair (the key never leaves the node) and posts a certificate
//!    request with the token to `POST /nodes/enroll`.
//! 4. It checks the CA root of the answer against the fingerprint and the root of step 2,
//!    and writes its identity, certificate, key and CA root to `<data_dir>/node/`.

use std::{path::PathBuf, time::Duration};

use std::fmt::Write as _;

use clap::Args;
use serde_json::json;
use tenko_cluster::{
    ca::{CertInfo, generate_csr, pem_block},
    identity::{Credentials, NodeIdentity, NodePaths, url_host},
    model::{EnrollRequest, EnrollResponse},
    token::EnrollmentToken,
    version,
};
use tenko_core::{Role, Timestamp};

use super::{NodeDirArgs, failure};
use crate::{
    client::{Failure, Output},
    exit,
};

/// The environment variable that may carry the token instead of `--token`.
pub const TOKEN_ENV: &str = "TENKO_ENROLL_TOKEN";

/// The name of [`TOKEN_ENV`] before 0.0.12, read when neither `--token`, [`TOKEN_ENV`] nor
/// `--token-file` gives a token.
pub const OLD_TOKEN_ENV: &str = "TENKO_ENROL_TOKEN"; // spelling: alias until 0.0.13

/// The token in [`OLD_TOKEN_ENV`], when it is set and not empty.
pub fn old_env_token() -> Option<String> {
    std::env::var(OLD_TOKEN_ENV)
        .ok()
        .filter(|token| !token.trim().is_empty())
}

const TIMEOUT: Duration = Duration::from_secs(30);

/// The flag that allows a plain `http://` controller URL.
pub const PLAIN_HTTP_FLAG: &str = "--insecure-plain-http";

/// What the command prints when the token goes over plain HTTP: what a listener on the path
/// obtains. `docs/cluster.md` section 1.2 has the same text.
pub const PLAIN_HTTP_WARNING: &str = "warning: --insecure-plain-http: the enrollment token \
     travels in clear text. Anyone who can read the traffic between this node and the \
     controller obtains the token and can enroll before this node does: they get a node \
     certificate with the token's roles, and with a controller token (tenko cluster join) \
     every key-encryption key of the cluster, which opens every secret in its vault. The \
     controller accepts this only under the Lab profile";

/// Checks the scheme of the controller URL before anything else: a plain `http://` URL
/// needs `--insecure-plain-http`; with it, the warning to print.
///
/// # Errors
///
/// A usage failure for a plain `http://` URL without the flag. It comes before the token is
/// read and before any network call.
pub fn check_transport(
    controller: &str,
    insecure_plain_http: bool,
) -> Result<Option<String>, Failure> {
    if !controller.starts_with("http://") {
        return Ok(None);
    }
    if insecure_plain_http {
        return Ok(Some(PLAIN_HTTP_WARNING.to_owned()));
    }
    Err(Failure::new(
        exit::USAGE,
        format!(
            "`{controller}` is plain HTTP: the enrollment token would travel in clear text, \
             and anyone on the path could enroll with it first. Use the https:// URL of the \
             controller; only for a Lab controller, which accepts nothing else over plain \
             HTTP, pass {PLAIN_HTTP_FLAG}"
        ),
    ))
}

/// Arguments of `tenko node enroll`.
#[derive(Debug, Clone, Args)]
pub struct EnrollArgs {
    /// Where this node keeps its files.
    #[command(flatten)]
    pub node: NodeDirArgs,

    /// The controller's URL, as administrators open it, for example
    /// `https://ddi.example.net:8443`.
    #[arg(long, value_name = "URL")]
    pub controller: String,

    /// The enrollment token. It is single-use and expires; it can also come from
    /// `TENKO_ENROLL_TOKEN` or `--token-file`.
    #[arg(long, value_name = "TOKEN", env = TOKEN_ENV, hide_env_values = true)]
    pub token: Option<String>,

    /// A file whose first line is the enrollment token.
    #[arg(long, value_name = "FILE", conflicts_with = "token")]
    pub token_file: Option<PathBuf>,

    /// The SHA-256 fingerprint of the controller's CA root (hexadecimal, colons allowed),
    /// as the controller printed it at start and shows with every token. A token of this
    /// version carries it already, and the flag must then agree with it; with a token of
    /// 0.0.11 and no flag the root is trusted on first use.
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

    /// Enroll again although this node is enrolled: the old identity is replaced.
    #[arg(long)]
    pub force: bool,

    /// Send the token to a plain `http://` controller URL. A listener on the path then
    /// obtains the token and can enroll first with its roles; a Lab controller accepts it,
    /// any other refuses it. Without this flag an `http://` URL is refused.
    #[arg(long)]
    pub insecure_plain_http: bool,
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

fn read_token(args: &EnrollArgs) -> Result<EnrollmentToken, Failure> {
    let parse = |text: &str| {
        EnrollmentToken::parse(text).map_err(|error| {
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
        (None, None) => match old_env_token() {
            Some(token) => parse(&token),
            None => Err(Failure::new(
                exit::USAGE,
                format!("no enrollment token: pass --token, --token-file or set {TOKEN_ENV}"),
            )),
        },
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

/// How step 2 trusts the CA root the controller sends.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RootTrust {
    /// The fingerprint a `tnk2` token carries (`--ca-fingerprint` may repeat it).
    Token(String),
    /// The fingerprint of `--ca-fingerprint`, with a `tnk1` token.
    Flag(String),
    /// Neither: a `tnk1` token without the flag trusts the root on first use (until 0.0.13).
    FirstUse,
}

impl RootTrust {
    /// The fingerprint the CA root must have, lower-case hexadecimal; `None` on first use.
    fn fingerprint(&self) -> Option<&str> {
        match self {
            Self::Token(fingerprint) | Self::Flag(fingerprint) => Some(fingerprint),
            Self::FirstUse => None,
        }
    }
}

/// The first eight characters of a fingerprint, for a message that names two.
fn short(fingerprint: &str) -> &str {
    fingerprint.get(..8).unwrap_or(fingerprint)
}

/// Where the trust in the CA root comes from: the token's fingerprint, the flag, or neither.
///
/// # Errors
///
/// A usage failure for a malformed flag; an integrity failure when the flag and the token's
/// fingerprint disagree. Both come before any network call.
fn root_trust(
    token: Option<tenko_cluster::token::CaFingerprint>,
    flag: Option<&str>,
) -> Result<RootTrust, Failure> {
    let flag = flag.map(normalize_fingerprint).transpose()?;
    match (token.map(|fingerprint| fingerprint.to_hex()), flag) {
        (Some(carried), Some(given)) if carried != given => Err(Failure::new(
            exit::INTEGRITY,
            format!(
                "the token names the CA root {}…, but --ca-fingerprint names {}…: they must \
                 agree; take both from the same controller, or leave out --ca-fingerprint, \
                 since the token carries the fingerprint",
                short(&carried),
                short(&given)
            ),
        )),
        (Some(carried), _) => Ok(RootTrust::Token(carried)),
        (None, Some(given)) => Ok(RootTrust::Flag(given)),
        (None, None) => Ok(RootTrust::FirstUse),
    }
}

/// Checks the CA root of step 2 against `trust`; the warning to print on first use.
///
/// # Errors
///
/// An integrity failure when the root does not have the expected fingerprint.
fn check_root(info: &CertInfo, trust: &RootTrust) -> Result<Option<String>, Failure> {
    match trust {
        RootTrust::Token(wanted) if *wanted != info.sha256 => Err(Failure::new(
            exit::INTEGRITY,
            format!(
                "the controller's CA root has SHA-256 {}…, but the token names {}…: do not \
                 trust it; the token comes from another controller, or something between \
                 this node and the controller answers in its place",
                short(&info.sha256),
                short(wanted)
            ),
        )),
        RootTrust::Flag(wanted) if *wanted != info.sha256 => Err(Failure::new(
            exit::INTEGRITY,
            format!(
                "the controller's CA root has SHA-256 {}, not {wanted}: do not trust it; check \
                 the fingerprint the controller printed at start",
                info.sha256
            ),
        )),
        RootTrust::Token(_) | RootTrust::Flag(_) => Ok(None),
        RootTrust::FirstUse => Ok(Some(format!(
            "warning: the token carries no CA fingerprint and no --ca-fingerprint was given; \
             trusting the CA root {} with SHA-256 {} on first use; compare it with the \
             fingerprint the controller printed. A token from a controller of version {} \
             carries the fingerprint and needs no comparison",
            info.subject,
            info.sha256,
            crate::version()
        ))),
    }
}

/// Fetches the CA root and checks it against `trust` before returning it: the PEM and, on
/// first use, the warning to print; `None` when the API does not use the internal CA (404).
///
/// The connection accepts any server certificate, because this is how the node obtains the
/// root before it can trust anything; nothing but the root's PEM is read from it, and the
/// token is not sent. The root is returned only once its SHA-256 matches the fingerprint
/// of `trust` (the token's or the flag's), so only the first use of a `tnk1` token without
/// `--ca-fingerprint` trusts an unverified root, and says so.
async fn fetch_root(
    controller: &str,
    trust: &RootTrust,
) -> Result<Option<(String, Option<String>)>, Failure> {
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
    let note = check_root(&root_of(&body)?, trust)?;
    Ok(Some((body, note)))
}

/// The machine's host name as a node registry name: lower case, every character other than a
/// letter, a digit or a hyphen replaced by a hyphen; `None` when it cannot be read or is not a
/// valid name. The enrollment proposes it, and the start page shows it (U3).
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

/// Runs `tenko node enroll`.
///
/// # Errors
///
/// The [`Failure`] of the ceremony.
#[allow(
    clippy::too_many_lines,
    reason = "the ceremony reads best as one sequence"
)]
pub async fn run(args: &EnrollArgs) -> Result<Output, Failure> {
    let resolved = args.node.resolve()?;
    let paths = NodePaths::new(&resolved.data_dir);
    if paths.is_enrolled() && !args.force {
        return Err(Failure::new(
            exit::USAGE,
            format!(
                "this node is enrolled already ({}); pass --force to enroll it again",
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
    let plain_http = check_transport(&controller, args.insecure_plain_http)?;
    let token = read_token(args)?;
    let trust = root_trust(token.ca_fingerprint(), args.ca_fingerprint.as_deref())?;
    if controller.starts_with("http://") && trust == RootTrust::FirstUse {
        return Err(Failure::new(
            exit::USAGE,
            "a controller on plain HTTP needs a token with a CA fingerprint or \
             --ca-fingerprint: nothing else protects the token",
        ));
    }
    let wanted = trust.fingerprint().map(str::to_owned);
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
    notes.extend(plain_http);
    let api_root = match fetch_root(&controller, &trust).await? {
        Some((pem, note)) => {
            notes.extend(note);
            Some(pem)
        }
        None => None,
    };

    // Step 3: the key and the request.
    let (key, csr) = generate_csr().map_err(|error| Failure::other(error.to_string()))?;
    let request = EnrollRequest {
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
    let url = format!("{controller}{}/nodes/enroll", tenko_api::API_BASE);
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
    let answer: EnrollResponse = serde_json::from_slice(&body)
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

    use tenko_cluster::token::CaFingerprint;

    #[test]
    fn fingerprints_are_normalized() {
        let hex = "AB:".repeat(31) + "AB";
        assert_eq!(normalize_fingerprint(&hex).expect("valid"), "ab".repeat(32));
        assert!(normalize_fingerprint("abc").is_err());
    }

    /// A CA root as step 2 reads it, with the fingerprint of `der`.
    fn root(der: &[u8]) -> CertInfo {
        CertInfo {
            subject: "CN=Tenko internal CA".to_owned(),
            issuer: "CN=Tenko internal CA".to_owned(),
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            uris: Vec::new(),
            serial: "01".to_owned(),
            not_before: Timestamp::now(),
            not_after: Timestamp::now(),
            sha256: CaFingerprint::of_der(der).to_hex(),
            is_ca: true,
        }
    }

    /// `tenko node enroll` arguments for `controller` with `token` and `flag`.
    fn args(
        dir: &std::path::Path,
        controller: &str,
        token: &str,
        flag: Option<&str>,
    ) -> EnrollArgs {
        EnrollArgs {
            node: NodeDirArgs {
                config: None,
                data_dir: Some(dir.to_path_buf()),
                json: false,
            },
            controller: controller.to_owned(),
            token: Some(token.to_owned()),
            token_file: None,
            ca_fingerprint: flag.map(str::to_owned),
            name: None,
            roles: None,
            address: None,
            force: false,
            insecure_plain_http: false,
        }
    }

    /// A `tnk2` token issued by the controller whose CA root is `der`.
    fn tnk2(der: &[u8]) -> EnrollmentToken {
        EnrollmentToken::generate(uuid::Uuid::now_v7())
            .expect("a token")
            .with_ca_fingerprint(CaFingerprint::of_der(der))
    }

    #[test]
    fn a_tnk2_token_trusts_its_own_fingerprint_without_a_warning() {
        let token = tnk2(b"our root");
        let trust = root_trust(token.ca_fingerprint(), None).expect("trust");
        assert_eq!(
            trust,
            RootTrust::Token(CaFingerprint::of_der(b"our root").to_hex())
        );
        assert_eq!(
            check_root(&root(b"our root"), &trust).expect("trusted"),
            None
        );
        // The same fingerprint in the flag agrees, in any spelling.
        let upper = CaFingerprint::of_der(b"our root")
            .to_hex()
            .to_ascii_uppercase();
        assert_eq!(
            root_trust(token.ca_fingerprint(), Some(&upper)).expect("trust"),
            trust
        );
    }

    #[test]
    fn a_controller_whose_root_does_not_match_the_token_is_refused() {
        let token = tnk2(b"our root");
        let trust = root_trust(token.ca_fingerprint(), None).expect("trust");
        let failure = check_root(&root(b"another root"), &trust).expect_err("refused");
        assert_eq!(failure.status, exit::INTEGRITY);
        let ours = CaFingerprint::of_der(b"our root").to_hex();
        let theirs = CaFingerprint::of_der(b"another root").to_hex();
        assert!(failure.message.contains(&ours[..8]), "{}", failure.message);
        assert!(
            failure.message.contains(&theirs[..8]),
            "{}",
            failure.message
        );
        assert!(
            failure.message.contains("do not trust it"),
            "{}",
            failure.message
        );
    }

    #[tokio::test]
    async fn a_flag_that_disagrees_with_the_token_stops_before_the_network() {
        let dir = tempfile::tempdir().expect("a directory");
        let token = tnk2(b"our root");
        let other = CaFingerprint::of_der(b"another root").to_hex();
        // Nothing listens on port 9: a network call would fail with UNREACHABLE.
        let failure = run(&args(
            dir.path(),
            "https://127.0.0.1:9",
            &token.to_text(),
            Some(&other),
        ))
        .await
        .expect_err("refused");
        assert_eq!(failure.status, exit::INTEGRITY, "{}", failure.message);
        assert!(
            failure.message.contains("must agree"),
            "{}",
            failure.message
        );
        assert!(failure.message.contains(&other[..8]), "{}", failure.message);
    }

    #[tokio::test]
    async fn plain_http_is_refused_before_the_token_unless_the_flag_names_the_choice() {
        let dir = tempfile::tempdir().expect("a directory");
        let token = tnk2(b"our root");
        // Without the flag: refused before the token is read (a token that does not parse
        // would otherwise be the failure) and before any network call.
        let mut plain = args(dir.path(), "http://127.0.0.1:9", "not a token", None);
        let failure = run(&plain).await.expect_err("refused");
        assert_eq!(failure.status, exit::USAGE, "{}", failure.message);
        assert!(
            failure.message.contains(PLAIN_HTTP_FLAG),
            "{}",
            failure.message
        );
        assert!(
            failure.message.contains("clear text"),
            "{}",
            failure.message
        );
        // With the flag the command goes on (and here fails to connect).
        plain.token = Some(token.to_text().to_string());
        plain.insecure_plain_http = true;
        let failure = run(&plain).await.expect_err("unreachable");
        assert_eq!(failure.status, exit::UNREACHABLE, "{}", failure.message);
        // The warning says what a listener on the path obtains.
        let warning = check_transport("http://192.0.2.10:8443", true)
            .expect("allowed")
            .expect("a warning");
        for part in [
            "clear text",
            "node certificate",
            "key-encryption key",
            "Lab profile",
        ] {
            assert!(warning.contains(part), "{part}: {warning}");
        }
        // HTTPS needs no flag and prints nothing.
        assert_eq!(
            check_transport("https://192.0.2.10:8443", false).expect("https"),
            None
        );
    }

    #[tokio::test]
    async fn a_tnk1_token_is_trusted_on_first_use_with_the_warning() {
        let token = EnrollmentToken::generate(uuid::Uuid::now_v7()).expect("a token");
        assert!(token.to_text().starts_with("tnk1."));
        let trust = root_trust(token.ca_fingerprint(), None).expect("trust");
        assert_eq!(trust, RootTrust::FirstUse);
        let warning = check_root(&root(b"our root"), &trust)
            .expect("trusted")
            .expect("a warning");
        assert!(warning.starts_with("warning: "), "{warning}");
        assert!(
            warning.contains(&CaFingerprint::of_der(b"our root").to_hex()),
            "{warning}"
        );
        assert!(warning.contains("carries the fingerprint"), "{warning}");
        // With the flag a tnk1 token is checked as before.
        let flag = CaFingerprint::of_der(b"our root").to_hex();
        let trust = root_trust(None, Some(&flag)).expect("trust");
        assert_eq!(trust, RootTrust::Flag(flag));
        assert_eq!(
            check_root(&root(b"our root"), &trust).expect("trusted"),
            None
        );
        assert!(check_root(&root(b"another root"), &trust).is_err());
        // A tnk1 token without the fingerprint flag is refused on plain HTTP, before the
        // network, even with --insecure-plain-http.
        let dir = tempfile::tempdir().expect("a directory");
        let mut plain = args(dir.path(), "http://127.0.0.1:9", &token.to_text(), None);
        plain.insecure_plain_http = true;
        let failure = run(&plain).await.expect_err("refused");
        assert_eq!(failure.status, exit::USAGE, "{}", failure.message);
        assert!(
            failure.message.contains("CA fingerprint"),
            "{}",
            failure.message
        );
    }
}
