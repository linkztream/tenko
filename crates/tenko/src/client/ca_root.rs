//! `tenko ca-root`: downloads the root certificate of the internal CA
//! (`GET /system/ca-root`) for installation on admin clients (Q5, OPS-22 mode a).
//!
//! The client does not trust the internal CA yet, which is the point of the download. So
//! the request first verifies the server as usual (system roots, `--ca-file`); when that
//! fails and `--fingerprint` gives the SHA-256 the server printed at start (console and log),
//! the root is fetched once without verification by [`fetch_unverified`], which returns it
//! only when its fingerprint matches. Without a fingerprint an untrusted server is refused.

use std::path::PathBuf;

use clap::Args;
use serde_json::json;
use tenko_api::client::ClientError;
use tenko_cluster::ca::CertInfo;

use super::{ClientOpts, Failure, Output, Target};
use crate::exit;

/// The download path below the API base.
const PATH: &str = "/system/ca-root";

/// Arguments of `tenko ca-root`.
#[derive(Debug, Clone, Args)]
pub struct CaRootArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,

    /// Write the PEM to this file instead of standard output.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// The SHA-256 fingerprint of the root as the server printed it at start (hexadecimal,
    /// colons optional). Required when the server is not trusted yet.
    #[arg(long, value_name = "SHA256")]
    pub fingerprint: Option<String>,
}

/// Runs `tenko ca-root`.
///
/// # Errors
///
/// The [`Failure`] of the download or of the fingerprint check.
pub async fn run(args: &CaRootArgs) -> Result<Output, Failure> {
    let target = Target::resolve(&args.client, false)?;
    let wanted = args
        .fingerprint
        .as_deref()
        .map(normalize_fingerprint)
        .transpose()?;
    let (pem, info) = match target.client()?.get_text(PATH).await {
        Ok(pem) => {
            let info = root_info(&pem)?;
            if let Some(wanted) = &wanted {
                expect_fingerprint(&info, wanted)?;
            }
            (pem, info)
        }
        Err(ClientError::Transport(error)) => match &wanted {
            Some(wanted) => fetch_unverified(&target, wanted).await?,
            None => {
                return Err(Failure::new(
                    exit::UNREACHABLE,
                    format!(
                        "{}; if the server is not trusted yet, pass --fingerprint with the \
                         SHA-256 it printed at start",
                        Failure::from_client(&ClientError::Transport(error)).message
                    ),
                ));
            }
        },
        Err(error) => return Err(error.into()),
    };
    let note = format!(
        "internal CA root {} (SHA-256 {}), valid until {}; install it as a trusted root on admin \
         clients",
        info.subject, info.sha256, info.not_after
    );
    if target.json {
        return Ok(Output::json(&json!({
            "subject": info.subject,
            "sha256": info.sha256,
            "not_after": info.not_after,
            "pem": pem,
        })));
    }
    match &args.output {
        Some(path) => {
            std::fs::write(path, pem.as_bytes()).map_err(|error| {
                Failure::other(format!("cannot write {}: {error}", path.display()))
            })?;
            Ok(Output::default().note(format!("{note}\nwritten to {}", path.display())))
        }
        None => Ok(Output::text(pem).note(note)),
    }
}

/// Fetches the root from a server the client cannot verify yet, and returns it, with what it
/// holds, only when its SHA-256 is `wanted`, the fingerprint the operator passed.
///
/// The connection accepts any server certificate, because this is how a client obtains the
/// root before it can trust anything; nothing but the root's PEM is read from it, and no
/// credential is sent. A root with another fingerprint is refused here, so no caller holds an
/// unverified root.
async fn fetch_unverified(target: &Target, wanted: &str) -> Result<(String, CertInfo), Failure> {
    let http = reqwest::Client::builder()
        .use_rustls_tls()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(format!("tenko/{}", crate::version()))
        .build()
        .map_err(|error| Failure::other(format!("HTTP client: {error}")))?;
    let url = format!(
        "{}{}{PATH}",
        target.url.trim_end_matches('/'),
        tenko_api::API_BASE
    );
    let response = http.get(&url).send().await.map_err(|error| {
        Failure::new(
            exit::UNREACHABLE,
            format!("cannot reach {}: {error}", target.url),
        )
    })?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| Failure::new(exit::UNREACHABLE, format!("reading the answer: {error}")))?;
    if !status.is_success() {
        return Err(
            match serde_json::from_str::<tenko_api::problem::ProblemDetails>(&body) {
                Ok(problem) => Failure::problem(problem),
                Err(_) => Failure::new(exit::API, format!("unexpected HTTP status {status}")),
            },
        );
    }
    let info = root_info(&body)?;
    expect_fingerprint(&info, wanted)?;
    Ok((body, info))
}

/// Refuses a root whose SHA-256 is not `wanted`.
fn expect_fingerprint(info: &CertInfo, wanted: &str) -> Result<(), Failure> {
    if info.sha256 == wanted {
        return Ok(());
    }
    Err(Failure::new(
        exit::INTEGRITY,
        format!(
            "the root the server sent has SHA-256 {}, not {wanted}: do not trust it",
            info.sha256
        ),
    ))
}

/// What the PEM holds: exactly one CA certificate.
fn root_info(pem: &str) -> Result<CertInfo, Failure> {
    let certificates = crate::serve::pem_certificates(pem.as_bytes());
    let [der] = certificates.as_slice() else {
        return Err(Failure::other(format!(
            "the answer holds {} certificates instead of one",
            certificates.len()
        )));
    };
    let info = CertInfo::from_der(der)
        .map_err(|error| Failure::other(format!("the answer is not a certificate: {error}")))?;
    if !info.is_ca {
        return Err(Failure::other("the answer is not a CA certificate"));
    }
    Ok(info)
}

/// A fingerprint as lowercase hexadecimal without separators.
fn normalize_fingerprint(text: &str) -> Result<String, Failure> {
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
            "--fingerprint must be a SHA-256: 64 hexadecimal digits, colons allowed",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_normalized() {
        let hex = "AB".repeat(32);
        let colons = vec!["AB"; 32].join(":");
        assert_eq!(normalize_fingerprint(&hex).expect("valid"), "ab".repeat(32));
        assert_eq!(
            normalize_fingerprint(&colons).expect("valid"),
            "ab".repeat(32)
        );
        assert_eq!(
            normalize_fingerprint("abc").expect_err("too short").status,
            exit::USAGE
        );
        assert_eq!(
            normalize_fingerprint(&"zz".repeat(32))
                .expect_err("not hex")
                .status,
            exit::USAGE
        );
    }

    #[test]
    fn a_root_with_another_fingerprint_is_refused() {
        let info = CertInfo {
            subject: "CN=Tenko internal CA".to_owned(),
            issuer: "CN=Tenko internal CA".to_owned(),
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            uris: Vec::new(),
            serial: "01".to_owned(),
            not_before: tenko_core::Timestamp::now(),
            not_after: tenko_core::Timestamp::now(),
            sha256: "ab".repeat(32),
            is_ca: true,
        };
        expect_fingerprint(&info, &"ab".repeat(32)).expect("the fingerprint matches");
        let failure = expect_fingerprint(&info, &"cd".repeat(32)).expect_err("refused");
        assert_eq!(failure.status, exit::INTEGRITY);
        assert!(
            failure.message.contains("do not trust it"),
            "{}",
            failure.message
        );
    }

    #[test]
    fn answers_without_one_certificate_are_refused() {
        assert!(root_info("no certificate").is_err());
        let two = "-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n".repeat(2);
        assert!(root_info(&two).is_err());
        let garbage = "-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n";
        assert!(root_info(garbage).is_err());
    }
}
