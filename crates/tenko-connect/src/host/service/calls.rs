//! Typed calls of the connector service for other packages, with the host's policy:
//! network-controller writes are planned against a fresh topology and checked against the
//! guardrails, applied only from a recent plan of the same instance and only when writes are
//! enabled, and verified by planning the same change again (CONN-08, CONN-09, TGL-20).

use tenko_core::{
    ConnectorId, Timestamp, UserId,
    ir::{Ir, LossReport},
};

use super::{ConnectorHost, HostError};
use crate::{
    ActuatorIntent, ActuatorPlan, ActuatorReceipt, Capability, ConnectorError, Guardrails, Health,
    HealthReport, L2Change, L2Plan, L2Receipt, MigrationScope, TopologySnapshot, WriteMode,
};

/// A remote system that answers a check with an error is a report about it: unreachable for
/// `connect.unreachable`, degraded for rejected credentials, missing permissions, rate
/// limits and settings the plugin cannot use. A plugin that cannot be asked stays an error.
pub(super) fn fold_into_report(error: ConnectorError) -> Result<HealthReport, ConnectorError> {
    let health = match &error {
        ConnectorError::Unreachable => Health::Unreachable,
        ConnectorError::Unauthorized
        | ConnectorError::Forbidden
        | ConnectorError::RateLimited { .. }
        | ConnectorError::InvalidSettings(_) => Health::Degraded,
        _ => return Err(error),
    };
    Ok(HealthReport {
        health,
        checked_at: Timestamp::now(),
        latency_ms: None,
        remote_version: None,
        detail: Some(format!("{} ({})", error, tenko_core::Coded::code(&error))),
    })
}

fn capability(
    host: &ConnectorHost,
    id: ConnectorId,
    capability: Capability,
) -> Result<(), HostError> {
    let runtime = host.runtime(id).ok_or_else(|| {
        HostError::new(
            "connect.instance.disabled",
            409,
            format!("connector {id} is not enabled on this node"),
        )
    })?;
    if runtime.has(capability) {
        Ok(())
    } else {
        Err(ConnectorError::Unsupported.into())
    }
}

impl ConnectorHost {
    /// The topology of a network-controller instance.
    ///
    /// # Errors
    ///
    /// `connect.unsupported` for an instance without the capability, the plugin's error,
    /// or the errors of a call (unavailable, timeout, secrets).
    pub async fn topology(
        &self,
        id: ConnectorId,
        on_behalf_of: Option<UserId>,
    ) -> Result<TopologySnapshot, HostError> {
        capability(self, id, Capability::NetworkController)?;
        let (runtime, client) = self.client(id).await?;
        let _slot = runtime.calls.acquire().await;
        let ctx = self.context(&runtime, "topology", on_behalf_of).await?;
        Ok(client.topology(&ctx, runtime.call_timeout()).await?)
    }

    /// Plans an L2 change: reads the topology, checks the guardrails (uplinks and
    /// management networks always), then asks the plugin to read back and diff.
    ///
    /// # Errors
    ///
    /// `connect.guardrail.*` when a guardrail refuses the change, `connect.protocol` when
    /// the plugin planned another change, or the errors of [`topology`](Self::topology).
    pub async fn plan_l2(
        &self,
        id: ConnectorId,
        change: &L2Change,
        guardrails: &Guardrails,
        on_behalf_of: Option<UserId>,
    ) -> Result<L2Plan, HostError> {
        capability(self, id, Capability::NetworkController)?;
        let (runtime, client) = self.client(id).await?;
        let _slot = runtime.calls.acquire().await;
        let timeout = runtime.call_timeout();
        let ctx = self.context(&runtime, "plan", on_behalf_of).await?;
        let topology = client.topology(&ctx, timeout).await?;
        guardrails.check(change, &topology)?;
        let plan = client.plan(&ctx, change, timeout).await?;
        if plan.change != *change {
            return Err(ConnectorError::protocol("the plugin planned another change").into());
        }
        Ok(plan)
    }

    /// Applies an L2 plan of this instance: only a plan younger than the configured age,
    /// only with writes enabled for a real write, after checking the guardrails against a
    /// fresh topology; after a real write the host plans the same change again and expects
    /// an empty diff.
    ///
    /// # Errors
    ///
    /// `connect.writes_disabled`, `connect.verify_mismatch` (a stale plan, a read-back
    /// that differs, or a plugin that reports no verification), `connect.guardrail.*`, or
    /// the errors of [`topology`](Self::topology).
    pub async fn apply_l2(
        &self,
        id: ConnectorId,
        plan: &L2Plan,
        mode: WriteMode,
        guardrails: &Guardrails,
        on_behalf_of: Option<UserId>,
    ) -> Result<L2Receipt, HostError> {
        capability(self, id, Capability::NetworkController)?;
        let (runtime, client) = self.client(id).await?;
        if mode == WriteMode::Apply && !runtime.instance().writes_enabled {
            return Err(ConnectorError::WritesDisabled.into());
        }
        if Timestamp::now().saturating_since(plan.read_at) > self.config.plan_max_age {
            return Err(ConnectorError::VerifyMismatch {
                diff: format!(
                    "the plan is older than {} s; plan the change again",
                    self.config.plan_max_age.as_secs()
                ),
            }
            .into());
        }
        let _slot = runtime.calls.acquire().await;
        let timeout = runtime.call_timeout();
        let ctx = self.context(&runtime, "apply", on_behalf_of).await?;
        let topology = client.topology(&ctx, timeout).await?;
        guardrails.check(&plan.change, &topology)?;
        let receipt = client.apply(&ctx, plan, mode, timeout).await?;
        if receipt.plan.change != plan.change || receipt.plan.fingerprint != plan.fingerprint {
            return Err(ConnectorError::protocol("the receipt names another plan").into());
        }
        if mode == WriteMode::Apply {
            if !receipt.verified {
                return Err(ConnectorError::VerifyMismatch {
                    diff: "the plugin reports that the read-back differs from the plan".to_owned(),
                }
                .into());
            }
            let again = client.plan(&ctx, &plan.change, timeout).await?;
            if let Some(line) = again.diff.first() {
                return Err(ConnectorError::VerifyMismatch {
                    diff: format!(
                        "after the write `{}` is {} instead of {}",
                        line.path,
                        line.before.as_deref().unwrap_or("absent"),
                        line.after.as_deref().unwrap_or("absent")
                    ),
                }
                .into());
            }
        }
        Ok(receipt)
    }

    /// Undoes an applied L2 change.
    ///
    /// # Errors
    ///
    /// `connect.writes_disabled`, or the errors of [`topology`](Self::topology).
    pub async fn revert_l2(
        &self,
        id: ConnectorId,
        receipt: &L2Receipt,
        on_behalf_of: Option<UserId>,
    ) -> Result<(), HostError> {
        capability(self, id, Capability::NetworkController)?;
        let (runtime, client) = self.client(id).await?;
        if !runtime.instance().writes_enabled {
            return Err(ConnectorError::WritesDisabled.into());
        }
        let _slot = runtime.calls.acquire().await;
        let ctx = self.context(&runtime, "revert", on_behalf_of).await?;
        Ok(client.revert(&ctx, receipt, runtime.call_timeout()).await?)
    }

    /// Plans an actuation (no write).
    ///
    /// # Errors
    ///
    /// `connect.unsupported`, the plugin's error, or the errors of a call.
    pub async fn plan_actuation(
        &self,
        id: ConnectorId,
        intent: &ActuatorIntent,
        on_behalf_of: Option<UserId>,
    ) -> Result<ActuatorPlan, HostError> {
        capability(self, id, Capability::Actuator)?;
        let (runtime, client) = self.client(id).await?;
        let _slot = runtime.calls.acquire().await;
        let ctx = self
            .context(&runtime, "actuator_plan", on_behalf_of)
            .await?;
        Ok(client
            .actuator_plan(&ctx, intent, runtime.call_timeout())
            .await?)
    }

    /// Applies an actuation plan, with the same age and write rules as L2 plans.
    ///
    /// # Errors
    ///
    /// `connect.writes_disabled`, `connect.verify_mismatch`, or the errors of a call.
    pub async fn apply_actuation(
        &self,
        id: ConnectorId,
        plan: &ActuatorPlan,
        mode: WriteMode,
        on_behalf_of: Option<UserId>,
    ) -> Result<ActuatorReceipt, HostError> {
        capability(self, id, Capability::Actuator)?;
        let (runtime, client) = self.client(id).await?;
        if mode == WriteMode::Apply && !runtime.instance().writes_enabled {
            return Err(ConnectorError::WritesDisabled.into());
        }
        if Timestamp::now().saturating_since(plan.read_at) > self.config.plan_max_age {
            return Err(ConnectorError::VerifyMismatch {
                diff: "the plan is too old; plan the change again".to_owned(),
            }
            .into());
        }
        let _slot = runtime.calls.acquire().await;
        let ctx = self
            .context(&runtime, "actuator_apply", on_behalf_of)
            .await?;
        let receipt = client
            .actuator_apply(&ctx, plan, mode, runtime.call_timeout())
            .await?;
        if mode == WriteMode::Apply && !receipt.verified {
            return Err(ConnectorError::VerifyMismatch {
                diff: "the plugin reports that the read-back differs from the plan".to_owned(),
            }
            .into());
        }
        Ok(receipt)
    }

    /// Reads a migration source into IR and a loss report.
    ///
    /// # Errors
    ///
    /// `connect.unsupported`, the plugin's error, or the errors of a call.
    pub async fn migration_read(
        &self,
        id: ConnectorId,
        scope: &MigrationScope,
        on_behalf_of: Option<UserId>,
    ) -> Result<(Ir, LossReport), HostError> {
        capability(self, id, Capability::Migration)?;
        let (runtime, client) = self.client(id).await?;
        let _slot = runtime.calls.acquire().await;
        let ctx = self
            .context(&runtime, "migration_read", on_behalf_of)
            .await?;
        // A whole migration read gets twenty call timeouts.
        let timeout = runtime.call_timeout().saturating_mul(20);
        Ok(client.migration_read(&ctx, scope, timeout).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_errors_become_reports_and_plugin_errors_stay_errors() {
        let report = fold_into_report(ConnectorError::Unreachable).expect("report");
        assert_eq!(report.health, Health::Unreachable);
        let report = fold_into_report(ConnectorError::Unauthorized).expect("report");
        assert_eq!(report.health, Health::Degraded);
        assert!(
            report
                .detail
                .expect("detail")
                .contains("connect.unauthorized")
        );
        assert!(
            fold_into_report(ConnectorError::Timeout(std::time::Duration::from_secs(1))).is_err()
        );
    }
}
