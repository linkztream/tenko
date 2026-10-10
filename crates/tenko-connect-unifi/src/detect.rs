//! Deployment detection (CONN-07) and the paths of each deployment.
//!
//! | Deployment | `GET /` | Classic API | Login | Integration API |
//! |---|---|---|---|---|
//! | Self-hosted Network Application | 302 to `/manage` | `/api/s/{site}/...` | `POST /api/login` | `/integration/v1` |
//! | UniFi OS console | 200 (the console page) | `/proxy/network/api/s/{site}/...` | `POST /api/auth/login` | `/proxy/network/integration/v1` |
//!
//! A self-hosted application also answers `GET /status` without authentication with
//! `meta.server_version`; a UniFi OS console answers `/proxy/network/status`. Detection reads
//! nothing else and needs no credentials.

use tenko_connect::ConnectorError;
use tenko_connect::sdk::http::reqwest::{self, Method};

use crate::{
    http::{Effect, Http},
    settings::Deployment,
};

/// The paths of one deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Paths {
    /// The deployment.
    pub deployment: Deployment,
    /// The prefix of the Network application's classic API.
    pub network: &'static str,
    /// The login of a local account.
    pub login: &'static str,
    /// The logout.
    pub logout: &'static str,
    /// The Integration API.
    pub integration: &'static str,
}

impl Paths {
    /// The paths of a self-hosted Network Application.
    pub const SELF_HOSTED: Paths = Paths {
        deployment: Deployment::SelfHosted,
        network: "",
        login: "/api/login",
        logout: "/api/logout",
        integration: "/integration/v1",
    };

    /// The paths of a UniFi OS console.
    pub const UNIFI_OS: Paths = Paths {
        deployment: Deployment::UnifiOs,
        network: "/proxy/network",
        login: "/api/auth/login",
        logout: "/api/auth/logout",
        integration: "/proxy/network/integration/v1",
    };

    /// A name for the health check.
    pub fn describe(&self) -> &'static str {
        match self.deployment {
            Deployment::UnifiOs => "UniFi OS console",
            Deployment::SelfHosted | Deployment::Auto => "self-hosted Network Application",
        }
    }
}

/// What detection found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detected {
    /// The paths.
    pub paths: Paths,
    /// The version of the Network application when it says so without authentication.
    pub version: Option<String>,
}

/// The paths of the configured deployment, detecting it when it is `auto`.
///
/// # Errors
///
/// [`ConnectorError::Unreachable`] when the controller does not answer, or
/// [`ConnectorError::Protocol`] when it is not a UniFi Network application.
pub async fn detect(http: &Http, deployment: Deployment) -> Result<Detected, ConnectorError> {
    match deployment {
        Deployment::SelfHosted => Ok(Detected {
            paths: Paths::SELF_HOSTED,
            version: status_version(http, "/status").await,
        }),
        Deployment::UnifiOs => Ok(Detected {
            paths: Paths::UNIFI_OS,
            version: status_version(http, "/proxy/network/status").await,
        }),
        Deployment::Auto => {
            let root = http.send(Method::GET, "/", &[], None, Effect::Read).await?;
            let location = root.header("location").unwrap_or_default();
            if root.status.is_redirection() && location.contains("/manage") {
                return Ok(Detected {
                    paths: Paths::SELF_HOSTED,
                    version: status_version(http, "/status").await,
                });
            }
            if root.status.is_success() {
                let proxied = http
                    .send(
                        Method::GET,
                        "/proxy/network/status",
                        &[],
                        None,
                        Effect::Read,
                    )
                    .await?;
                if proxied.status != reqwest::StatusCode::NOT_FOUND {
                    return Ok(Detected {
                        paths: Paths::UNIFI_OS,
                        version: version_of(proxied.json().as_ref()),
                    });
                }
            }
            if let Some(version) = status_version(http, "/status").await {
                return Ok(Detected {
                    paths: Paths::SELF_HOSTED,
                    version: Some(version),
                });
            }
            Err(ConnectorError::protocol(
                "the address does not answer like a UniFi Network application; set `deployment` if it is one",
            ))
        }
    }
}

async fn status_version(http: &Http, path: &str) -> Option<String> {
    let response = http
        .send(Method::GET, path, &[], None, Effect::Read)
        .await
        .ok()?;
    if !response.status.is_success() {
        return None;
    }
    version_of(response.json().as_ref())
}

fn version_of(json: Option<&serde_json::Value>) -> Option<String> {
    let version = json?.pointer("/meta/server_version")?.as_str()?.trim();
    (!version.is_empty() && version.len() <= 64 && version.chars().all(|c| c.is_ascii_graphic()))
        .then(|| version.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_come_from_the_status_meta() {
        assert_eq!(
            version_of(Some(&serde_json::json!({
                "meta": { "rc": "ok", "up": true, "server_version": "9.2.87" }, "data": []
            }))),
            Some("9.2.87".to_owned())
        );
        assert_eq!(version_of(Some(&serde_json::json!({ "meta": {} }))), None);
        assert_eq!(version_of(None), None);
        assert_eq!(Paths::UNIFI_OS.network, "/proxy/network");
        assert_eq!(Paths::SELF_HOSTED.integration, "/integration/v1");
    }
}
