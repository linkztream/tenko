//! Node secrets (SCAN-05, IAM-16, S3-Q19): the vault secrets a node's configuration names,
//! handed to that node per request over its mutual TLS connection.
//!
//! A node configuration row names the secrets it needs in a field `secrets`, a list of
//! [`SecretUse`] (purpose and operator secret). `Config.Secrets` answers a node with the
//! secrets of the purposes it asks for, and only those its own configuration names, only
//! operator secrets, and only purposes its roles use ([`PURPOSES`]). The controller writes
//! the audit record `cluster.node.secrets` (the node, the purposes, the secret references,
//! never a value) before it opens a single envelope; when the record cannot be written, no
//! secret leaves. The node keeps the values in memory and never writes them to disk.

use serde::{Deserialize, Serialize};
use tenko_core::{
    NodeId, ObjectRef, Principal, RequestCtx, Role, SecretId, Timestamp,
    audit::{AuditAction, AuditDraft},
    codec::from_cbor,
    codec::key::encode_key,
    secret::{SecretClass, SecretRef},
};
use tenko_store::{ReadConsistency, ReadView, StoreError, WriteBatch};
use tenko_vault::SecretBytes;
use zeroize::Zeroizing;

use super::{NodeSync, codes, store_error, tables::tables_for};
use crate::{error::ClusterError, model::NodeRecord, proto::v1};

/// The audit action of secrets handed to a node.
pub const SECRETS_ACTION: AuditAction = AuditAction::from_static("cluster.node.secrets");

/// The secret purposes and the role that uses each.
pub const PURPOSES: [(&str, Role); 1] = [("snmp", Role::Probe)];

/// A vault secret a node configuration names for one purpose.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecretUse {
    /// The purpose (`snmp`).
    pub purpose: String,
    /// The operator secret.
    pub secret: SecretId,
}

/// The `secrets` field every node configuration row may carry; other fields are ignored.
#[derive(Debug, Default, Deserialize)]
struct RowSecrets {
    #[serde(default)]
    secrets: Vec<SecretUse>,
}

/// A secret value for a node, wiped when dropped.
pub struct NodeSecretValue {
    /// The purpose.
    pub purpose: String,
    /// The secret.
    pub secret: SecretId,
    /// The value.
    pub value: SecretBytes,
}

impl std::fmt::Debug for NodeSecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeSecretValue")
            .field("purpose", &self.purpose)
            .field("secret", &self.secret)
            .finish_non_exhaustive()
    }
}

impl NodeSecretValue {
    /// The value as the node receives it; the name is the secret id.
    pub fn to_proto(&self) -> v1::NodeSecret {
        v1::NodeSecret {
            purpose: self.purpose.clone(),
            name: self.secret.to_string(),
            value: self.value.expose().to_vec(),
        }
    }
}

/// Whether a node with `roles` may ask for `purpose`.
pub fn purpose_allowed(purpose: &str, roles: &[Role]) -> bool {
    PURPOSES
        .iter()
        .any(|(name, role)| *name == purpose && roles.contains(role))
}

/// Every secret use named by the configuration rows of `node`.
///
/// # Errors
///
/// A store error.
pub fn uses_of(
    view: &dyn ReadView,
    node: NodeId,
    roles: &[Role],
) -> Result<Vec<SecretUse>, StoreError> {
    let mut uses = Vec::new();
    let key = encode_key(&node.0);
    for table in tables_for(roles) {
        let Some(row) = view.get(&table, &key)? else {
            continue;
        };
        match from_cbor::<RowSecrets>(&row.value) {
            Ok(row) => uses.extend(row.secrets),
            Err(error) => {
                tracing::warn!(%table, node = %node, %error, "a node configuration row does not decode its secrets");
            }
        }
    }
    uses.sort();
    uses.dedup();
    Ok(uses)
}

/// The secrets of `purposes` that the configuration of `node` names, resolved from the
/// vault after the audit record committed.
///
/// # Errors
///
/// `node.config.secrets_purpose` (403) for a purpose the node's roles do not use,
/// `node.config.secrets_unavailable` (503) without a vault, `cluster.no_quorum` (503) when
/// the audit record cannot be written because the controller cannot write, or a vault or
/// store error.
pub async fn resolve(
    sync: &NodeSync,
    node: &NodeRecord,
    purposes: &[String],
) -> Result<Vec<NodeSecretValue>, ClusterError> {
    resolve_for(sync, node.id, &node.name, &node.roles, purposes).await
}

/// As [`resolve`], for a node given by its id, name and roles: the in-process probe of a
/// controller, which has no record in the node registry, resolves its secrets this way.
///
/// # Errors
///
/// As [`resolve`].
pub async fn resolve_for(
    sync: &NodeSync,
    id: NodeId,
    name: &str,
    roles: &[Role],
    purposes: &[String],
) -> Result<Vec<NodeSecretValue>, ClusterError> {
    let node = NodeRef { id, name, roles };
    for purpose in purposes {
        if !purpose_allowed(purpose, node.roles) {
            return Err(ClusterError::new(
                codes::SECRETS_PURPOSE,
                403,
                format!(
                    "node {} does not use secrets of the purpose `{}`",
                    node.id,
                    purpose.chars().take(40).collect::<String>()
                ),
            ));
        }
    }
    let view = sync
        .store()
        .read(ReadConsistency::Local)
        .await
        .map_err(store_error)?;
    let wanted: Vec<SecretUse> = uses_of(view.as_ref(), node.id, node.roles)?
        .into_iter()
        .filter(|used| purposes.contains(&used.purpose))
        .collect();
    drop(view);
    if wanted.is_empty() {
        return Ok(Vec::new());
    }
    let vault = sync.vault().ok_or_else(|| {
        ClusterError::new(
            codes::SECRETS_UNAVAILABLE,
            503,
            "this controller has no vault; node secrets cannot be served",
        )
    })?;
    let mut allowed = Vec::with_capacity(wanted.len());
    for used in wanted {
        match vault
            .meta(SecretRef {
                secret: used.secret,
            })
            .await?
        {
            Some(meta) if meta.class == SecretClass::Operator => allowed.push(used),
            Some(_) => {
                tracing::warn!(node = %node.id, secret = %used.secret, "a node configuration names a system secret; it is not handed out");
            }
            None => {
                tracing::warn!(node = %node.id, secret = %used.secret, "a node configuration names a secret that does not exist");
            }
        }
    }
    if allowed.is_empty() {
        return Ok(Vec::new());
    }
    let principal = Principal::Node { id: node.id };
    let mut objects = vec![ObjectRef::node(node.id)];
    objects.extend(allowed.iter().map(|used| ObjectRef::from(used.secret)));
    let mut purposes_used: Vec<&str> = allowed.iter().map(|used| used.purpose.as_str()).collect();
    purposes_used.dedup();
    let mut audit = WriteBatch::new(principal.clone(), Timestamp::now());
    audit.audit(
        AuditDraft::success(SECRETS_ACTION, objects)
            .with_context("node", node.name.to_owned())
            .with_context("purposes", purposes_used.join(",")),
    );
    if let Err(error) = sync.store().propose(audit).await {
        return Err(match error {
            StoreError::NoQuorum => store_error(error),
            other => ClusterError::new(
                codes::SECRETS_UNAVAILABLE,
                503,
                format!("the secret hand-over could not be audited, so it did not happen: {other}"),
            ),
        });
    }
    let ctx = RequestCtx::new(principal);
    let mut values = Vec::with_capacity(allowed.len());
    for used in allowed {
        let value = vault
            .get_system(
                &ctx,
                SecretRef {
                    secret: used.secret,
                },
            )
            .await?;
        values.push(NodeSecretValue {
            purpose: used.purpose,
            secret: used.secret,
            value,
        });
    }
    Ok(values)
}

/// The node a resolution is for.
struct NodeRef<'a> {
    id: NodeId,
    name: &'a str,
    roles: &'a [Role],
}

/// Secrets a node received, held in memory: by purpose and secret id.
#[derive(Default, Clone)]
pub struct HeldSecrets {
    values: std::collections::BTreeMap<(String, SecretId), Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for HeldSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldSecrets")
            .field("count", &self.values.len())
            .finish_non_exhaustive()
    }
}

impl HeldSecrets {
    /// The secrets of a response; entries whose name is not a secret id are skipped.
    pub fn from_proto(response: v1::SecretsResponse) -> Self {
        let mut values = std::collections::BTreeMap::new();
        for secret in response.secrets {
            let Ok(id) = secret.name.parse::<SecretId>() else {
                continue;
            };
            values.insert((secret.purpose, id), Zeroizing::new(secret.value));
        }
        Self { values }
    }

    /// The value of `secret` for `purpose`.
    pub fn get(&self, purpose: &str, secret: SecretId) -> Option<&[u8]> {
        self.values
            .get(&(purpose.to_owned(), secret))
            .map(|value| value.as_slice())
    }

    /// How many secrets are held.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether none are held.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purposes_follow_roles() {
        assert!(purpose_allowed("snmp", &[Role::Probe]));
        assert!(!purpose_allowed("snmp", &[Role::Dns]));
        assert!(!purpose_allowed("tsig", &[Role::Probe]));
    }

    #[test]
    fn a_row_names_its_secrets_beside_other_fields() {
        #[derive(Serialize)]
        struct Row {
            config: u32,
            secrets: Vec<SecretUse>,
        }
        let secret = SecretId::generate();
        let bytes = tenko_core::codec::to_cbor(&Row {
            config: 7,
            secrets: vec![SecretUse {
                purpose: "snmp".to_owned(),
                secret,
            }],
        })
        .expect("encode");
        let row: RowSecrets = from_cbor(&bytes).expect("decode");
        assert_eq!(row.secrets.len(), 1);
        assert_eq!(row.secrets[0].secret, secret);
        // A row without the field names none.
        let bytes = tenko_core::codec::to_cbor(&7u32).expect("encode");
        assert!(from_cbor::<RowSecrets>(&bytes).is_err());
        let bytes = tenko_core::codec::to_cbor(&std::collections::BTreeMap::from([(
            "config".to_owned(),
            7u32,
        )]))
        .expect("encode");
        assert_eq!(
            from_cbor::<RowSecrets>(&bytes)
                .expect("decode")
                .secrets
                .len(),
            0
        );
    }

    #[test]
    fn held_secrets_are_found_by_purpose_and_id() {
        let secret = SecretId::generate();
        let held = HeldSecrets::from_proto(v1::SecretsResponse {
            secrets: vec![
                v1::NodeSecret {
                    purpose: "snmp".to_owned(),
                    name: secret.to_string(),
                    value: b"example-auth-secret".to_vec(),
                },
                v1::NodeSecret {
                    purpose: "snmp".to_owned(),
                    name: "not-an-id".to_owned(),
                    value: Vec::new(),
                },
            ],
        });
        assert_eq!(held.len(), 1);
        assert_eq!(held.get("snmp", secret), Some(&b"example-auth-secret"[..]));
        assert_eq!(held.get("tsig", secret), None);
        assert!(!format!("{held:?}").contains("example"));
    }
}
