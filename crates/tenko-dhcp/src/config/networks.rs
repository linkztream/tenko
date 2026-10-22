//! Shared networks (`dhcp.shared_networks`): several scopes on one link (Windows
//! superscopes, Kea shared networks; DHCP-01, DHCP-04). A name is unique; a shared network
//! that scopes still name refuses deletion (`dhcp.shared_network.in_use`). Shared networks
//! are server-wide configuration and are audited on the server object.

use tenko_core::{
    PrefixId, RequestCtx, Revision,
    audit::AuditDraft,
    dhcp::{
        OptionOwner, Scope, SharedNetwork, SharedNetworkId, audit, codes, server_object,
        tables::{SCOPES, SHARED_NETWORKS},
    },
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, WriteBatch};

use super::{
    ConfigError, ConfigResult, ConfigService, Planned, Written, check_expect, delete_option_set,
    stamp, text,
};

/// A shared network as read, with its scopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedNetworkRow {
    /// The shared network.
    pub shared_network: SharedNetwork,
    /// The scopes that name it, by prefix id.
    pub scopes: Vec<PrefixId>,
    /// The revision of the row.
    pub revision: Revision,
}

/// Changes to a shared network.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharedNetworkChange {
    /// The name.
    pub name: Option<String>,
    /// The interface; an empty string clears it.
    pub interface: Option<String>,
    /// Free text; an empty string clears it.
    pub description: Option<String>,
}

fn not_found(id: SharedNetworkId) -> ConfigError {
    ConfigError::not_found(codes::SHARED_NETWORK_NOT_FOUND, "shared network", id)
}

fn all_scopes(view: &dyn ReadView) -> ConfigResult<Vec<(PrefixId, Scope, Revision)>> {
    Ok(view.scan_typed(&SCOPES, KeyRange::all(), usize::MAX, false)?)
}

fn members(scopes: &[(PrefixId, Scope, Revision)], id: SharedNetworkId) -> Vec<PrefixId> {
    scopes
        .iter()
        .filter(|(_, scope, _)| scope.shared_network == Some(id))
        .map(|(prefix, _, _)| *prefix)
        .collect()
}

fn unique_name(view: &dyn ReadView, network: &SharedNetwork) -> ConfigResult<()> {
    let taken = view
        .scan_typed(&SHARED_NETWORKS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .any(|(id, other, _)| id != network.id && other.name == network.name);
    if taken {
        return Err(ConfigError::invalid(
            codes::SHARED_NETWORK_INVALID,
            "name",
            "a shared network of this name exists",
        ));
    }
    Ok(())
}

impl ConfigService {
    /// Every shared network, by name.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn shared_networks(view: &dyn ReadView) -> ConfigResult<Vec<SharedNetworkRow>> {
        let scopes = all_scopes(view)?;
        let mut rows: Vec<SharedNetworkRow> = view
            .scan_typed(&SHARED_NETWORKS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(id, shared_network, revision)| SharedNetworkRow {
                scopes: members(&scopes, id),
                shared_network,
                revision,
            })
            .collect();
        rows.sort_by(|a, b| {
            a.shared_network
                .name
                .cmp(&b.shared_network.name)
                .then(a.shared_network.id.cmp(&b.shared_network.id))
        });
        Ok(rows)
    }

    /// One shared network.
    ///
    /// # Errors
    ///
    /// `dhcp.shared_network.not_found`, or the store's error.
    pub fn shared_network(
        view: &dyn ReadView,
        id: SharedNetworkId,
    ) -> ConfigResult<SharedNetworkRow> {
        let (shared_network, revision) = view
            .get_typed(&SHARED_NETWORKS, &id)?
            .ok_or_else(|| not_found(id))?;
        Ok(SharedNetworkRow {
            scopes: members(&all_scopes(view)?, id),
            shared_network,
            revision,
        })
    }

    /// Creates a shared network.
    ///
    /// # Errors
    ///
    /// `dhcp.shared_network.invalid` (also for a taken name), or a store or job error.
    pub async fn create_shared_network(
        &self,
        cx: &RequestCtx,
        name: String,
        interface: Option<String>,
        description: Option<String>,
    ) -> ConfigResult<(SharedNetwork, Written)> {
        let now = stamp(cx);
        let network = SharedNetwork {
            id: SharedNetworkId::generate(),
            name,
            interface: text(interface.as_deref()),
            description: text(description.as_deref()),
            created: now.clone(),
            updated: now,
        };
        network.validate()?;
        self.execute_write(cx, |view| {
            unique_name(view, &network)?;
            let mut batch = WriteBatch::for_request(cx);
            batch.expect_typed(&SHARED_NETWORKS, &network.id, None);
            batch.put_typed(&SHARED_NETWORKS, &network.id, &network)?;
            batch.audit(
                AuditDraft::success(audit::SHARED_NETWORK_CREATE, vec![server_object()])
                    .with_source_ip(cx.source_ip)
                    .with_context("shared_network", network.id.to_string())
                    .with_context("name", network.name.clone()),
            );
            Ok(Planned::write(
                network.clone(),
                batch,
                format!("create the shared network {}", network.name),
                vec![server_object()],
            ))
        })
        .await
    }

    /// Changes a shared network.
    ///
    /// # Errors
    ///
    /// `dhcp.shared_network.not_found`, `dhcp.shared_network.invalid`, 412 when `expect` is
    /// stale, or a store or job error.
    pub async fn update_shared_network(
        &self,
        cx: &RequestCtx,
        id: SharedNetworkId,
        change: SharedNetworkChange,
        expect: Option<Revision>,
    ) -> ConfigResult<(SharedNetwork, Option<Written>)> {
        self.execute(cx, |view| {
            let (before, revision) = view
                .get_typed(&SHARED_NETWORKS, &id)?
                .ok_or_else(|| not_found(id))?;
            check_expect(expect, revision)?;
            let mut after = before.clone();
            if let Some(name) = &change.name {
                after.name.clone_from(name);
            }
            if let Some(interface) = &change.interface {
                after.interface = text(Some(interface));
            }
            if let Some(description) = &change.description {
                after.description = text(Some(description));
            }
            after.validate()?;
            if after == before {
                return Ok(Planned::nothing(after));
            }
            unique_name(view, &after)?;
            after.updated = stamp(cx);
            let mut batch = WriteBatch::for_request(cx);
            batch.expect_typed(&SHARED_NETWORKS, &id, Some(revision));
            batch.put_typed(&SHARED_NETWORKS, &id, &after)?;
            batch.audit(
                AuditDraft::success(audit::SHARED_NETWORK_UPDATE, vec![server_object()])
                    .with_source_ip(cx.source_ip)
                    .with_context("shared_network", id.to_string())
                    .with_context("name", after.name.clone()),
            );
            Ok(Planned::write(
                after.clone(),
                batch,
                format!("change the shared network {}", after.name),
                vec![server_object()],
            ))
        })
        .await
    }

    /// Deletes a shared network no scope names, with its option set.
    ///
    /// # Errors
    ///
    /// `dhcp.shared_network.not_found`, `dhcp.shared_network.in_use`, 412 when `expect` is
    /// stale, or a store or job error.
    pub async fn delete_shared_network(
        &self,
        cx: &RequestCtx,
        id: SharedNetworkId,
        expect: Option<Revision>,
    ) -> ConfigResult<Written> {
        let ((), written) = self
            .execute_write(cx, |view| {
                let (network, revision) = view
                    .get_typed(&SHARED_NETWORKS, &id)?
                    .ok_or_else(|| not_found(id))?;
                check_expect(expect, revision)?;
                let scopes = all_scopes(view)?;
                let using = members(&scopes, id);
                if !using.is_empty() {
                    return Err(ConfigError::new(
                        codes::SHARED_NETWORK_IN_USE,
                        409,
                        format!(
                            "{} scope(s) belong to the shared network {}",
                            using.len(),
                            network.name
                        ),
                    )
                    .param("id", id.to_string())
                    .param("count", using.len().to_string()));
                }
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&SHARED_NETWORKS, &id, Some(revision));
                batch.delete_typed(&SHARED_NETWORKS, &id);
                // A scope that joins the network meanwhile makes the batch stale.
                for (prefix, _, revision) in &scopes {
                    batch.expect_typed(&SCOPES, prefix, Some(*revision));
                }
                delete_option_set(view, &mut batch, OptionOwner::SharedNetwork(id))?;
                batch.audit(
                    AuditDraft::success(audit::SHARED_NETWORK_DELETE, vec![server_object()])
                        .with_source_ip(cx.source_ip)
                        .with_context("shared_network", id.to_string())
                        .with_context("name", network.name.clone()),
                );
                Ok(Planned::write(
                    (),
                    batch,
                    format!("delete the shared network {}", network.name),
                    vec![server_object()],
                ))
            })
            .await?;
        Ok(written)
    }
}
