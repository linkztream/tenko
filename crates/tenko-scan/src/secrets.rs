//! Vault secrets of the SNMP devices (SCAN-05, IAM-16, S3-Q19).
//!
//! A configuration held by the controllers names the SNMP passwords as operator secrets of
//! the vault (`auth_secret`, `privacy_secret`). The probe fetches their values from the
//! controllers over its mutual TLS connection each time it polls ([`SecretSource`]); every
//! fetch is audited on the controller. The values live in memory only: a [`VaultSecrets`]
//! map wipes them when it is dropped, and nothing here writes to disk. While no controller
//! answers, the source hands back the values of its last fetch in this process; after a
//! restart without a reachable controller SNMP waits and the other methods run.

use std::{collections::BTreeMap, fmt};

use async_trait::async_trait;
use tenko_core::SecretId;

use crate::{config::SecretText, error::ScanError};

/// Secret values by secret id, wiped when dropped.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct VaultSecrets(BTreeMap<SecretId, SecretText>);

impl fmt::Debug for VaultSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultSecrets")
            .field("count", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl VaultSecrets {
    /// No secrets.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a value.
    pub fn insert(&mut self, secret: SecretId, value: SecretText) {
        self.0.insert(secret, value);
    }

    /// The value of `secret`.
    pub fn get(&self, secret: SecretId) -> Option<&SecretText> {
        self.0.get(&secret)
    }

    /// How many values are held.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether none are held.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Where a probe gets the values of vault secrets: the controllers, through the node agent.
#[async_trait]
pub trait SecretSource: Send + Sync + fmt::Debug {
    /// The values of `secrets` that the probe may have; ids the controllers do not hand
    /// out are absent.
    ///
    /// # Errors
    ///
    /// `scan.unavailable` when no controller answered and nothing was fetched before.
    async fn fetch(&self, secrets: &[SecretId]) -> Result<VaultSecrets, ScanError>;
}

/// A source with fixed values (tests and the in-process probe of a controller in tests).
#[derive(Debug, Clone, Default)]
pub struct StaticSecrets(pub VaultSecrets);

#[async_trait]
impl SecretSource for StaticSecrets {
    async fn fetch(&self, secrets: &[SecretId]) -> Result<VaultSecrets, ScanError> {
        let mut out = VaultSecrets::new();
        for secret in secrets {
            if let Some(value) = self.0.get(*secret) {
                out.insert(*secret, value.clone());
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_static_source_hands_out_only_what_is_asked() {
        let (a, b) = (SecretId::generate(), SecretId::generate());
        let mut values = VaultSecrets::new();
        values.insert(a, SecretText::new("example-auth-secret"));
        values.insert(b, SecretText::new("example-priv-secret"));
        let source = StaticSecrets(values);
        let fetched = source.fetch(&[a]).await.expect("fetch");
        assert_eq!(fetched.len(), 1);
        assert_eq!(
            fetched.get(a).map(SecretText::expose),
            Some("example-auth-secret")
        );
        assert!(fetched.get(b).is_none());
        assert!(!format!("{fetched:?}").contains("example"));
    }
}
