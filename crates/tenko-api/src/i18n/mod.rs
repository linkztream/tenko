//! Language packs (API-21, owner decisions S3-Q8).
//!
//! English and Swedish are compiled into the web UI. Further languages are XLIFF 2.0 packs
//! that an administrator uploads; a pack with the tag of a built-in language overrides its
//! messages key by key until it is removed again. The modules:
//!
//! - [`xliff`]: the XLIFF 2.0 subset of packs, read with `quick-xml`;
//! - [`icu`]: a checker for ICU `MessageFormat` text, following the parser the UI uses;
//! - [`tag`]: well-formed BCP 47 tags in canonical case;
//! - [`validate`]: a pack against the key set of the running UI, with its report;
//! - [`template`]: the key set as an XLIFF pack, for translators;
//! - [`dto`]: the request and response types of `/i18n`;
//! - `service` (server): packs in the replicated store, their life cycle (uploaded,
//!   previewed, active) and the import of `<data_dir>/i18n/*.xlf` at start.
//!
//! The validation is the boundary against packs as an injection path (R32): a pack is at most
//! [`MAX_PACK_BYTES`], has no DOCTYPE and no inline markup, every message is valid ICU within
//! the limits of [`icu`], uses no argument its English text lacks, and has no control
//! characters or unbalanced bidirectional formatting; the UI renders every message as text.
//!
//! Owner: WP3.7.

pub mod dto;
pub mod icu;
#[cfg(feature = "server")]
pub mod service;
pub mod tag;
pub mod template;
pub mod validate;
pub mod xliff;

/// The largest pack, in bytes (2 MiB).
pub const MAX_PACK_BYTES: usize = 2 * 1024 * 1024;
