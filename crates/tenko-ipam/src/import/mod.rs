//! Import of spreadsheets and CSV files (WP1.5, IPAM-11, MIG-01): the readers, the
//! mapping, the translation into the import model with its loss report, the
//! reconciliation with the store, and the apply job.
//!
//! # Pipeline
//!
//! | Step | Module | Output |
//! |---|---|---|
//! | read | [`read`] | [`read::SourceFile`]s: sheets of cells, CSV decoded and sniffed |
//! | analyze | [`mapping`] | per sheet: kind, network, header row, column shapes and samples, a suggested [`mapping::Mapping`] |
//! | translate | [`translate`] | the [`model::ImportModel`] (the IR of MIG-01 with interfaces and credentials by reference), the loss report, row outcomes and proposed prefixes |
//! | reconcile | [`reconcile`] | IPAM commands for what is missing or different, item outcomes |
//! | plan and apply | [`service`], [`job`] | the preview; the `import.apply` job in chunks |
//!
//! The rules follow `docs/plans/import-fixtures.md`; the loss codes are in [`codes`] and
//! the column vocabulary, shared with the CSV export, in [`vocab`].
//!
//! # Wiring (server)
//!
//! ```ignore
//! let imports = ImportService::new(ipam.clone(), engine.clone(), Some(vault), ImportConfig {
//!     staging_dir: data_dir.join("imports"),
//!     ..ImportConfig::default()
//! })?;
//! let router = router.layer(axum::Extension(imports.clone()));
//! // now and then: imports.purge_expired().await
//! ```

pub mod codes;
pub mod dto;
pub mod job;
pub mod mapping;
pub mod model;
pub mod read;
pub mod reconcile;
pub mod service;
pub mod shape;
pub mod staging;
pub mod transform;
pub mod translate;
pub mod vocab;

pub use dto::{ApplyAccepted, ApplyRequest, ImportPreview, ImportState, ImportView};
pub use mapping::{ImportOptions, Mapping};
pub use model::ImportModel;
pub use service::{CredentialGate, ImportConfig, ImportService, Upload, credential_gate};
