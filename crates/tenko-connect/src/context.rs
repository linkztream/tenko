//! The context of one plugin call: the instance, its settings and the injected secrets.

use std::{collections::BTreeMap, fmt};

use serde::de::DeserializeOwned;
use tenko_core::ConnectorId;
use zeroize::Zeroizing;

use crate::ConnectorError;

/// What a plugin receives with every call that may reach the remote system.
///
/// The host builds it per call from the connector instance: the settings (validated against
/// the settings schema of the manifest) and the secrets whose purposes the manifest
/// declares, resolved from the vault for this call only. A plugin keeps nothing of it
/// beyond the call; the secret values are wiped when the context is dropped.
#[derive(Clone, Default)]
pub struct CallContext {
    /// The connector instance; `None` when the conformance suite calls.
    pub instance: Option<ConnectorId>,
    /// The settings of the instance as a JSON object.
    pub settings: serde_json::Value,
    /// The secrets, by purpose.
    pub secrets: Secrets,
    /// Correlation identifier for log lines.
    pub request_id: String,
}

impl CallContext {
    /// A context with the given settings and no secrets.
    pub fn with_settings(settings: serde_json::Value) -> Self {
        Self {
            settings,
            ..Self::default()
        }
    }

    /// Deserializes the settings into the plugin's own settings type.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::InvalidSettings`] when the settings do not fit the type.
    pub fn settings<T: DeserializeOwned>(&self) -> Result<T, ConnectorError> {
        serde_json::from_value(self.settings.clone())
            .map_err(|error| ConnectorError::invalid_settings(error.to_string()))
    }

    /// The secret of a purpose, if the host injected one.
    pub fn secret(&self, purpose: &str) -> Option<&[u8]> {
        self.secrets.get(purpose)
    }

    /// The secret of a purpose as UTF-8 text.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::InvalidSettings`] when the secret is missing or not UTF-8. The
    /// message names the purpose, never the value.
    pub fn secret_str(&self, purpose: &str) -> Result<&str, ConnectorError> {
        let value = self.secret(purpose).ok_or_else(|| {
            ConnectorError::invalid_settings(format!("the secret `{purpose}` is not configured"))
        })?;
        std::str::from_utf8(value).map_err(|_| {
            ConnectorError::invalid_settings(format!("the secret `{purpose}` is not UTF-8 text"))
        })
    }
}

impl fmt::Debug for CallContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallContext")
            .field("instance", &self.instance)
            .field("settings", &self.settings)
            .field("secrets", &self.secrets)
            .field("request_id", &self.request_id)
            .finish()
    }
}

/// Secret values by purpose. The values are wiped on drop and never printed.
#[derive(Clone, Default)]
pub struct Secrets(BTreeMap<String, Zeroizing<Vec<u8>>>);

impl Secrets {
    /// No secrets.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces the value of a purpose.
    pub fn insert(&mut self, purpose: impl Into<String>, value: Zeroizing<Vec<u8>>) {
        self.0.insert(purpose.into(), value);
    }

    /// Adds or replaces the value of a purpose from a plain buffer, which is wiped when the
    /// secrets are dropped.
    pub fn insert_bytes(&mut self, purpose: impl Into<String>, value: Vec<u8>) {
        self.insert(purpose, Zeroizing::new(value));
    }

    /// The value of a purpose.
    pub fn get(&self, purpose: &str) -> Option<&[u8]> {
        self.0.get(purpose).map(|value| value.as_slice())
    }

    /// The purposes present.
    pub fn purposes(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }

    /// The purposes and values.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.0
            .iter()
            .map(|(purpose, value)| (purpose.as_str(), value.as_slice()))
    }

    /// The number of secrets.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no secrets.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set()
            .entries(self.0.keys().map(|purpose| format!("{purpose}=<redacted>")))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Settings {
        url: String,
        #[serde(default)]
        verify_tls: bool,
    }

    #[test]
    fn settings_and_secrets_are_read_and_never_printed() {
        let mut secrets = Secrets::new();
        secrets.insert("password", Zeroizing::new(b"marker-value-1".to_vec()));
        let ctx = CallContext {
            instance: None,
            settings: serde_json::json!({ "url": "https://controller.example.net:8443" }),
            secrets,
            request_id: "r1".to_owned(),
        };
        assert_eq!(
            ctx.settings::<Settings>().expect("settings"),
            Settings {
                url: "https://controller.example.net:8443".to_owned(),
                verify_tls: false
            }
        );
        assert_eq!(
            ctx.secret_str("password").expect("secret"),
            "marker-value-1"
        );
        assert!(ctx.secret("api_key").is_none());
        let missing = ctx.secret_str("api_key").expect_err("missing");
        assert!(missing.to_string().contains("api_key"));
        let printed = format!("{ctx:?}");
        assert!(!printed.contains("marker-value-1"), "{printed}");
        assert!(printed.contains("password=<redacted>"), "{printed}");
    }

    #[test]
    fn settings_of_the_wrong_shape_are_invalid_settings() {
        let ctx = CallContext::with_settings(serde_json::json!({ "url": 7 }));
        assert!(matches!(
            ctx.settings::<Settings>(),
            Err(ConnectorError::InvalidSettings(_))
        ));
    }
}
