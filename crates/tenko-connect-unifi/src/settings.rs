//! The settings of an instance and the credentials of a call.
//!
//! The settings schema lives in the manifest ([`crate::manifest`]); the TLS properties
//! (`tls`, `tls_fingerprint`, `tls_ca`, `connect_address`) are the SDK's
//! ([`tenko_connect::sdk::http::settings_schema`]). The host validates an instance's
//! settings against the schema and fills in the defaults before they reach the plugin; the
//! plugin still treats them as untrusted input and applies its own defaults.

use std::fmt;

use serde::Deserialize;
use tenko_connect::{
    CallContext, ConnectorError,
    sdk::http::{TlsMode, TlsSettings, parse_base_url},
};
use zeroize::Zeroizing;

/// The secret purpose of the local account's password.
pub const PASSWORD: &str = "password";

/// The secret purpose of a local Integration API key.
pub const API_KEY: &str = "api_key";

/// How the controller is deployed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Deployment {
    /// Detect it on every call.
    #[default]
    Auto,
    /// A self-hosted Network Application: no path prefix, login at `/api/login`.
    SelfHosted,
    /// A UniFi OS console (UDM, UCG, Cloud Key Gen2 and later): the Network application
    /// behind `/proxy/network`, login at `/api/auth/login`.
    UnifiOs,
}

/// The settings of an instance.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// The controller's base URL, such as `https://unifi.example.net:8443`.
    pub url: String,
    /// How the controller is deployed.
    #[serde(default)]
    pub deployment: Deployment,
    /// The site's short name (`default` for the first site), not its description.
    #[serde(default = "default_site")]
    pub site: String,
    /// The local account's user name (its password is the `password` secret).
    #[serde(default)]
    pub username: Option<String>,
    /// How the TLS certificate is checked.
    #[serde(default)]
    pub tls: TlsMode,
    /// The SHA-256 fingerprint of the controller certificate (`tls = fingerprint`).
    #[serde(default)]
    pub tls_fingerprint: Option<String>,
    /// The PEM of the CA (`tls = ca`).
    #[serde(default)]
    pub tls_ca: Option<String>,
    /// An address to connect to instead of resolving the URL's host.
    #[serde(default)]
    pub connect_address: Option<String>,
}

fn default_site() -> String {
    "default".to_owned()
}

/// The parsed and checked settings of a call.
#[derive(Debug, Clone)]
pub struct Config {
    /// The base URL.
    pub base: crate::http::Url,
    /// How the controller is deployed.
    pub deployment: Deployment,
    /// The site's short name.
    pub site: String,
    /// TLS checking.
    pub tls: TlsSettings,
}

impl Config {
    /// Whether the fingerprint mode lacks its fingerprint.
    pub fn fingerprint_missing(&self) -> bool {
        self.tls.mode == TlsMode::Fingerprint
            && self
                .tls
                .fingerprint
                .as_deref()
                .is_none_or(|text| text.trim().is_empty())
    }

    /// Whether calls go out without a certificate check or without encryption.
    pub fn insecure(&self) -> bool {
        self.base.scheme() == "http" || self.tls.mode == TlsMode::Insecure
    }
}

/// The credentials of one call. Wiped when dropped; never printed.
pub enum Credentials {
    /// A local account for the classic API.
    Account {
        /// The user name.
        username: Zeroizing<String>,
        /// The password.
        password: Zeroizing<String>,
    },
    /// A local Integration API key.
    ApiKey(Zeroizing<String>),
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Credentials::Account { .. } => f.write_str("Account(<redacted>)"),
            Credentials::ApiKey(_) => f.write_str("ApiKey(<redacted>)"),
        }
    }
}

impl Credentials {
    /// Whether these credentials reach the classic API.
    pub fn is_account(&self) -> bool {
        matches!(self, Credentials::Account { .. })
    }
}

/// The settings of a call.
///
/// # Errors
///
/// [`ConnectorError::InvalidSettings`] for settings that do not fit.
pub fn config(ctx: &CallContext) -> Result<Config, ConnectorError> {
    let settings: Settings = ctx.settings()?;
    parse(&settings)
}

/// Checks settings.
///
/// # Errors
///
/// [`ConnectorError::InvalidSettings`] for settings that do not fit.
pub fn parse(settings: &Settings) -> Result<Config, ConnectorError> {
    let base = parse_base_url(settings.url.trim().trim_end_matches('/'))?;
    let site = settings.site.trim();
    if site.is_empty()
        || site.len() > 64
        || !site
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ConnectorError::invalid_settings(
            "`site` is the site's short name: letters, digits, `_` and `-`",
        ));
    }
    Ok(Config {
        base,
        deployment: settings.deployment,
        site: site.to_owned(),
        tls: TlsSettings {
            mode: settings.tls,
            fingerprint: settings.tls_fingerprint.clone(),
            ca: settings.tls_ca.clone(),
            connect_address: settings.connect_address.clone(),
        },
    })
}

/// The credentials of a call: the local account when the `password` secret is present,
/// else the local Integration API key.
///
/// # Errors
///
/// [`ConnectorError::InvalidSettings`] when neither is configured, or the account lacks a
/// user name. Messages name purposes, never values.
pub fn credentials(ctx: &CallContext) -> Result<Credentials, ConnectorError> {
    let settings: Settings = ctx.settings()?;
    let configured_user = || {
        settings
            .username
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
    };
    let no_user =
        || ConnectorError::invalid_settings("the local account needs a user name (`username`)");
    if let Some(raw) = ctx.secret(PASSWORD).filter(|value| !value.is_empty()) {
        let text = Zeroizing::new(
            std::str::from_utf8(raw)
                .map_err(|_| {
                    ConnectorError::invalid_settings("the secret `password` is not UTF-8 text")
                })?
                .to_owned(),
        );
        // A login imported with a password is stored as {"login": ..., "password": ...}.
        if text.trim_start().starts_with('{')
            && let Ok(serde_json::Value::Object(map)) = serde_json::from_str(&text)
            && let Some(password) = map.get("password").and_then(serde_json::Value::as_str)
        {
            let field = |name: &str| map.get(name).and_then(serde_json::Value::as_str);
            let username = field("login")
                .or_else(|| field("username"))
                .map(|name| name.trim().to_owned())
                .filter(|name| !name.is_empty())
                .or_else(configured_user)
                .ok_or_else(no_user)?;
            return Ok(Credentials::Account {
                username: Zeroizing::new(username),
                password: Zeroizing::new(password.to_owned()),
            });
        }
        return Ok(Credentials::Account {
            username: Zeroizing::new(configured_user().ok_or_else(no_user)?),
            password: text,
        });
    }
    if let Some(raw) = ctx.secret(API_KEY).filter(|value| !value.is_empty()) {
        let key = std::str::from_utf8(raw)
            .map_err(|_| {
                ConnectorError::invalid_settings("the secret `api_key` is not UTF-8 text")
            })?
            .trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_graphic()) {
            return Err(ConnectorError::invalid_settings(
                "the secret `api_key` is not an API key",
            ));
        }
        return Ok(Credentials::ApiKey(Zeroizing::new(key.to_owned())));
    }
    Err(ConnectorError::invalid_settings(
        "configure the local account (`username` and the secret `password`) or a local Integration API key (the secret `api_key`)",
    ))
}

#[cfg(test)]
mod tests {
    use tenko_connect::Secrets;

    use super::*;

    fn ctx(settings: serde_json::Value, secrets: &[(&str, &str)]) -> CallContext {
        let mut all = Secrets::new();
        for (purpose, value) in secrets {
            all.insert_bytes(*purpose, value.as_bytes().to_vec());
        }
        CallContext {
            settings,
            secrets: all,
            ..CallContext::default()
        }
    }

    fn settings(url: &str, site: &str) -> Settings {
        serde_json::from_value(serde_json::json!({ "url": url, "site": site })).expect("settings")
    }

    #[test]
    fn settings_are_checked() {
        let config =
            parse(&settings("https://unifi.example.test:8443/", "default")).expect("valid");
        assert_eq!(config.base.host_str(), Some("unifi.example.test"));
        assert_eq!(config.site, "default");
        assert!(!config.insecure());
        assert!(!config.fingerprint_missing());
        for (url, site) in [
            ("ftp://unifi.example.test", "default"),
            ("https://user:pw@unifi.example.test", "default"),
            ("not a url", "default"),
            ("https://unifi.example.test", "bad site"),
        ] {
            assert!(
                matches!(
                    parse(&settings(url, site)),
                    Err(ConnectorError::InvalidSettings(_))
                ),
                "{url} {site}"
            );
        }
        let pinned: Settings = serde_json::from_value(
            serde_json::json!({ "url": "https://unifi.example.test:8443", "tls": "fingerprint" }),
        )
        .expect("settings");
        assert!(parse(&pinned).expect("valid").fingerprint_missing());
        assert!(
            parse(&settings("http://unifi.example.test", "default"))
                .expect("valid")
                .insecure()
        );
    }

    #[test]
    fn credentials_prefer_the_local_account_and_never_print() {
        let settings =
            serde_json::json!({ "url": "https://unifi.example.test:8443", "username": "tenko-ro" });
        let account = credentials(&ctx(
            settings.clone(),
            &[(PASSWORD, "pw-marker-1"), (API_KEY, "key-marker-1")],
        ))
        .expect("account");
        assert!(account.is_account());
        assert!(!format!("{account:?}").contains("marker"));
        let key = credentials(&ctx(settings.clone(), &[(API_KEY, "key-marker-1")])).expect("key");
        assert!(!key.is_account());
        let imported = credentials(&ctx(
            serde_json::json!({ "url": "https://unifi.example.test:8443" }),
            &[(PASSWORD, r#"{"login":"ops","password":"pw-marker-2"}"#)],
        ))
        .expect("imported login");
        let Credentials::Account { username, password } = imported else {
            panic!("an account");
        };
        assert_eq!(
            (username.as_str(), password.as_str()),
            ("ops", "pw-marker-2")
        );
        let error = credentials(&ctx(settings, &[])).expect_err("nothing configured");
        assert!(!error.to_string().contains("marker"));
        let no_user = credentials(&ctx(
            serde_json::json!({ "url": "https://unifi.example.test:8443" }),
            &[(PASSWORD, "pw-marker-1")],
        ))
        .expect_err("no user name");
        assert!(no_user.to_string().contains("username"));
    }
}
