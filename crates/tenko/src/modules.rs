//! The module switch of `tenko serve` (OPS-25): which product modules this installation
//! runs.
//!
//! The set is decided once, at start, in this order:
//!
//! 1. `modules` in `tenko.toml` (or `TENKO_MODULES`), when set: it pins the set;
//! 2. else the installation's choice, stored by `PUT /system/modules` (the first-run
//!    wizard asks what the installation is for) in the table `sys.modules`;
//! 3. else every module.
//!
//! A disabled module registers no routes (`tenko_api::routes::router_for`), shows no UI
//! area (the UI reads `modules` from `GET /system/status`), registers no job steps, starts
//! no background task and builds nothing in memory. A changed choice applies at the next
//! start: a server under a service manager restarts itself at once
//! ([`crate::upgrade::restart`]); otherwise `/system/status` says a restart is required.

#![allow(
    clippy::result_large_err,
    reason = "the errors are the CodedError of the API, handed on to problem details as they are"
)]

use std::{sync::Arc, time::Duration};

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tenko_api::{routes::system::modules::ModuleService, state::AppState};
use tenko_core::{
    CodedError, ObjectKind, ObjectRef, RequestCtx, Timestamp,
    audit::{AuditAction, AuditDetails, AuditDraft, FieldChange},
    table::TableDef,
};
use tenko_store::{ReadConsistency, ReadViewExt as _, Store, StoreError, WriteBatch};

pub use tenko_api::modules::{Module, ModuleRestart, ModuleSet, ModuleSettings};

use crate::upgrade::restart::{self, Restart};

/// The installation's choice of modules, under the key `()`.
pub const TABLE: TableDef<(), StoredModules> = TableDef::new("sys.modules");

/// The status warning while a module change waits for a restart.
pub const RESTART_NOTICE: &str = "sys.modules.restart_required";

/// How long a scheduled restart waits, so that the answer of the request reaches the client.
const RESTART_DELAY: Duration = Duration::from_secs(2);

/// The stored choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredModules {
    /// The modules.
    pub modules: ModuleSet,
    /// When they were chosen.
    pub changed_at: Timestamp,
}

/// The module set of a start: the pinned one, else the stored one, else every module.
pub fn effective(pinned: Option<ModuleSet>, stored: Option<ModuleSet>) -> ModuleSet {
    pinned.or(stored).unwrap_or(ModuleSet::ALL)
}

/// Reads the installation's choice.
///
/// # Errors
///
/// The store's error.
pub async fn stored(store: &dyn Store) -> Result<Option<ModuleSet>, StoreError> {
    let view = store.read(ReadConsistency::Local).await?;
    Ok(view
        .get_typed(&TABLE, &())?
        .map(|(stored, _)| stored.modules))
}

/// One line for the start log.
pub fn describe(running: ModuleSet, pinned: Option<ModuleSet>) -> String {
    let source = if pinned.is_some() {
        "set in tenko.toml"
    } else {
        "the installation's choice"
    };
    format!("modules {running} ({source})")
}

/// The module service behind `/system/modules`.
pub struct ModuleSwitch {
    store: Arc<dyn Store>,
    state: AppState,
    running: ModuleSet,
    pinned: Option<ModuleSet>,
    restart: Restart,
    supervised: bool,
}

impl std::fmt::Debug for ModuleSwitch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModuleSwitch")
            .field("running", &self.running)
            .field("pinned", &self.pinned)
            .field("supervised", &self.supervised)
            .finish_non_exhaustive()
    }
}

impl ModuleSwitch {
    /// The service for a server that runs `running`; `pinned` is the set of `tenko.toml`.
    pub fn new(
        store: Arc<dyn Store>,
        state: AppState,
        running: ModuleSet,
        pinned: Option<ModuleSet>,
        restart: Restart,
    ) -> Self {
        Self {
            store,
            state,
            running,
            pinned,
            restart,
            supervised: restart::supervised(),
        }
    }

    /// The same with an explicit answer to "does a service manager restart us" (tests).
    #[must_use]
    pub fn with_supervised(mut self, supervised: bool) -> Self {
        self.supervised = supervised;
        self
    }

    async fn configured(&self) -> Result<ModuleSet, CodedError> {
        let stored = stored(self.store.as_ref())
            .await
            .map_err(|error| store_error(&error))?;
        Ok(effective(self.pinned, stored))
    }

    fn settings_for(&self, configured: ModuleSet) -> ModuleSettings {
        let restart = if configured == self.running {
            ModuleRestart::None
        } else if self.restart.reason().is_some() || self.supervised {
            ModuleRestart::Scheduled
        } else {
            ModuleRestart::Required
        };
        ModuleSettings {
            running: self.running,
            configured,
            pinned: self.pinned.is_some(),
            restart,
        }
    }

    /// Publishes the restart notice of `/system/status` for `configured`.
    pub fn publish_notice(&self, configured: ModuleSet) {
        if configured == self.running {
            self.state.clear_notice(RESTART_NOTICE);
        } else {
            self.state
                .set_notice(tenko_api::dto::system::StatusWarning {
                    code: RESTART_NOTICE.to_owned(),
                    detail: format!(
                        "the installation's modules changed to {configured}; restart the server to \
                     apply the change (running: {})",
                        self.running
                    ),
                    params: [
                        ("configured".to_owned(), configured.to_string()),
                        ("running".to_owned(), self.running.to_string()),
                    ]
                    .into_iter()
                    .collect(),
                });
        }
    }

    async fn store_choice(&self, ctx: &RequestCtx, modules: ModuleSet) -> Result<(), CodedError> {
        let view = self
            .store
            .read(ReadConsistency::Local)
            .await
            .map_err(|error| store_error(&error))?;
        let current = view
            .get_typed(&TABLE, &())
            .map_err(|error| store_error(&error))?;
        drop(view);
        let before = current.as_ref().map(|(stored, _)| stored.modules);
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&TABLE, &(), current.as_ref().map(|(_, revision)| *revision));
        batch
            .put_typed(
                &TABLE,
                &(),
                &StoredModules {
                    modules,
                    changed_at: ctx.now,
                },
            )
            .map_err(|error| store_error(&error))?;
        let mut details = AuditDetails::default();
        details.changes.push(FieldChange {
            object: None,
            field: "modules".to_owned(),
            old: Some(before.unwrap_or(ModuleSet::ALL).to_string()),
            new: Some(modules.to_string()),
        });
        batch.audit(AuditDraft {
            details,
            source_ip: ctx.source_ip,
            ..AuditDraft::success(
                AuditAction::from_static("sys.modules.update"),
                vec![ObjectRef::singleton(ObjectKind::System)],
            )
        });
        self.store
            .propose(batch)
            .await
            .map(drop)
            .map_err(|error| match error {
                StoreError::PreconditionFailed(_) => CodedError::new(
                    "modules.conflict",
                    409,
                    "the modules changed meanwhile; read them again",
                ),
                other => store_error(&other),
            })
    }
}

fn store_error(error: &StoreError) -> CodedError {
    CodedError::new(
        "modules.store",
        503,
        format!("the store is unavailable: {error}"),
    )
}

impl ModuleService for ModuleSwitch {
    fn settings<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
    ) -> BoxFuture<'a, Result<ModuleSettings, CodedError>> {
        Box::pin(async move { Ok(self.settings_for(self.configured().await?)) })
    }

    fn set<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        modules: ModuleSet,
    ) -> BoxFuture<'a, Result<ModuleSettings, CodedError>> {
        Box::pin(async move {
            if let Some(pinned) = self.pinned {
                return Err(CodedError::new(
                    "modules.pinned",
                    409,
                    format!(
                        "modules = [{pinned}] in tenko.toml decides the modules of this server; \
                         change it there"
                    ),
                )
                .with_param("pinned", pinned.to_string()));
            }
            self.store_choice(ctx, modules).await?;
            if modules != self.running && self.supervised {
                let restart = self.restart.clone();
                let reason = format!("the modules changed to {modules}");
                tokio::spawn(async move {
                    tokio::time::sleep(RESTART_DELAY).await;
                    restart.request(reason);
                });
            }
            self.publish_notice(modules);
            Ok(self.settings_for(modules))
        })
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::{Principal, SystemComponent};
    use tenko_store::MemStore;

    use super::*;

    fn ctx() -> RequestCtx {
        RequestCtx::new(Principal::system(SystemComponent::Api))
    }

    fn switch(
        store: Arc<dyn Store>,
        running: ModuleSet,
        pinned: Option<ModuleSet>,
    ) -> ModuleSwitch {
        let state = AppState::new(Arc::clone(&store));
        ModuleSwitch::new(store, state, running, pinned, Restart::new())
    }

    #[test]
    fn the_file_pins_then_the_choice_then_all() {
        let ipam = ModuleSet::only(Module::Ipam);
        let dns = ModuleSet::only(Module::Dns);
        assert_eq!(effective(Some(ipam), Some(dns)), ipam);
        assert_eq!(effective(None, Some(dns)), dns);
        assert_eq!(effective(None, None), ModuleSet::ALL);
        assert_eq!(
            describe(ipam, Some(ipam)),
            "modules ipam (set in tenko.toml)"
        );
    }

    #[tokio::test]
    async fn a_choice_is_stored_audited_and_needs_a_restart() {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let service = switch(Arc::clone(&store), ModuleSet::ALL, None).with_supervised(false);
        let before = service.settings(&ctx()).await.expect("settings");
        assert_eq!(before.configured, ModuleSet::ALL);
        assert_eq!(before.restart, ModuleRestart::None);
        let mut without_ipam = ModuleSet::ALL;
        without_ipam.remove(Module::Ipam);
        let after = service.set(&ctx(), without_ipam).await.expect("set");
        assert_eq!(after.running, ModuleSet::ALL);
        assert_eq!(after.configured, without_ipam);
        assert_eq!(after.restart, ModuleRestart::Required);
        assert_eq!(
            stored(store.as_ref()).await.expect("read"),
            Some(without_ipam)
        );
        let notices = service.state.notices_list();
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].code, RESTART_NOTICE);
        // Back to the running set: nothing pending.
        let again = service.set(&ctx(), ModuleSet::ALL).await.expect("set");
        assert_eq!(again.restart, ModuleRestart::None);
        assert_eq!(service.state.notices_list(), Vec::new());
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let audit = view
            .scan(
                tenko_store::tables::AUDIT.name(),
                tenko_store::KeyRange::all(),
                10,
                false,
            )
            .expect("audit");
        assert_eq!(audit.len(), 2);
    }

    #[tokio::test]
    async fn a_supervised_server_restarts_itself() {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let service = switch(store, ModuleSet::ALL, None).with_supervised(true);
        let restart = service.restart.clone();
        let settings = service
            .set(&ctx(), ModuleSet::only(Module::Ipam))
            .await
            .expect("set");
        assert_eq!(settings.restart, ModuleRestart::Scheduled);
        let reason = tokio::time::timeout(Duration::from_secs(10), restart.requested())
            .await
            .expect("the restart is requested");
        assert!(reason.contains("ipam"), "{reason}");
    }

    #[tokio::test]
    async fn a_pinned_set_cannot_be_changed() {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let pinned = ModuleSet::only(Module::Ipam);
        let service = switch(store, pinned, Some(pinned));
        let error = service
            .set(&ctx(), ModuleSet::ALL)
            .await
            .expect_err("pinned");
        assert_eq!(error.code, "modules.pinned");
        assert_eq!(error.status, 409);
        let settings = service.settings(&ctx()).await.expect("settings");
        assert!(settings.pinned);
        assert_eq!(settings.configured, pinned);
    }
}
