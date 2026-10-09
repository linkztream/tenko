//! Secret values, specifications and metadata.

use std::fmt;

use serde::{Deserialize, Serialize};
use tenko_core::{ObjectRef, SecretId, Timestamp, secret::SecretClass};
use zeroize::{ZeroizeOnDrop, Zeroizing};

tenko_core::namespaced_name! {
    /// What a secret is for, namespaced by the owning package: `auth.totp`,
    /// `cluster.ca_key`, `cluster.tls_key`, `connect.proxmox_token`.
    SecretPurpose, "secret purpose"
}

/// A plaintext secret value. Zeroized on drop; `Debug` prints only the length; no
/// `Display`, no serde; equality runs in constant time for equal lengths.
#[derive(Clone, Default)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        aws_lc_rs::constant_time::verify_slices_are_equal(&self.0, &other.0).is_ok()
    }
}

impl Eq for SecretBytes {}

impl SecretBytes {
    /// Wraps a value, taking ownership of the buffer.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Copies a value from a slice.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }

    /// The plaintext. Keep the borrow short and never log it.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the value is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The zeroizing buffer, for callers that hand the value on without copying.
    pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        // `SecretBytes` has no `Drop` of its own, so moving the field out is allowed and
        // the buffer keeps its zeroize-on-drop wrapper.
        self.0
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<String> for SecretBytes {
    fn from(text: String) -> Self {
        Self::new(text.into_bytes())
    }
}

impl From<Zeroizing<Vec<u8>>> for SecretBytes {
    fn from(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(<{} bytes redacted>)", self.0.len())
    }
}

impl ZeroizeOnDrop for SecretBytes {}

/// What to store with a new secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretSpec {
    /// What the secret is for.
    pub purpose: SecretPurpose,
    /// The object the secret belongs to (the user of a TOTP seed, the connector of a
    /// token), if any.
    pub owner: Option<ObjectRef>,
    /// A label an operator chose (operator secrets).
    pub label: Option<String>,
}

impl SecretSpec {
    /// A secret for a purpose, without owner or label.
    pub fn new(purpose: SecretPurpose) -> Self {
        Self {
            purpose,
            owner: None,
            label: None,
        }
    }

    /// Sets the owning object.
    #[must_use]
    pub fn owned_by(mut self, owner: ObjectRef) -> Self {
        self.owner = Some(owner);
        self
    }

    /// Sets the label.
    #[must_use]
    pub fn labelled(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

/// Non-secret metadata of a secret, stored in `vault.secret_meta`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretMeta {
    /// The secret.
    pub id: SecretId,
    /// Its class.
    pub class: SecretClass,
    /// What it is for.
    pub purpose: SecretPurpose,
    /// The owning object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<ObjectRef>,
    /// The operator's label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// When it was created.
    pub created_at: Timestamp,
    /// When its value was last written (creation, replacement or DEK rotation).
    pub updated_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_value() {
        let secret = SecretBytes::from(b"hunter2-marker".to_vec());
        let printed = format!("{secret:?}");
        assert!(!printed.contains("hunter2"));
        assert!(printed.contains("14 bytes"));
    }

    #[test]
    fn purposes_are_namespaced() {
        assert!(SecretPurpose::new("auth.totp").is_ok());
        assert!(SecretPurpose::new("nope.totp").is_err());
        assert_eq!(
            SecretPurpose::from_static("cluster.ca_key").namespace(),
            "cluster"
        );
    }
}
