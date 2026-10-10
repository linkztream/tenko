//! The vault of Tenko DDI: envelope encryption of secrets at rest (IAM-15, IAM-16,
//! NEVER-01) with pluggable key-encryption-key (KEK) providers.
//!
//! # Model
//!
//! - Every write of a secret draws a fresh 256-bit data-encryption key (DEK) and encrypts
//!   the value with AES-256-GCM (`aws-lc-rs`). The DEK is wrapped by the active KEK and
//!   stored next to the ciphertext in a [`VaultEnvelope`]; see [`envelope`] for the byte
//!   layout and the additional authenticated data that binds an envelope to its table,
//!   key and class.
//! - The KEK never leaves the process unprotected. [`kek`] holds the [`KekProvider`]
//!   trait and the providers: DPAPI (Windows), `systemd-creds` (Linux, TPM2 where
//!   available), an explicit file (containers and CI, with a loud warning) and memory
//!   (tests). [`KekConfig::load`] fails when no usable KEK exists, and
//!   [`StoreVault::open`] fails when the store holds envelopes no loaded KEK can open, so
//!   the server does not start without its KEK.
//! - Secrets live in the store table `vault.secrets` (secret-bearing, so the store
//!   refuses anything but envelopes), with non-secret metadata in `vault.secret_meta`.
//!   Every write is a [`WriteBatch`] proposed through the [`Store`](tenko_store::Store)
//!   with an audit draft; plaintext never enters a batch (ADR 0011 decision 10).
//! - Classes (Q3, accepted): [`SecretClass::System`] secrets (TOTP seeds, CA and TLS keys)
//!   are used by Tenko and never revealed; [`SecretClass::Operator`] secrets (connector
//!   credentials, host credentials, imported logins) are revealable with an audit record.
//!   Only operator secrets count for the PIN coupling rule (IAM-07): see
//!   [`Vault::has_operator_secrets`]. Their metadata, host bindings and reveal stamps are
//!   the model of [`operator`] (WP2.1).
//! - Plaintext is held in [`SecretBytes`], which zeroizes on drop and never prints.
//!
//! # Use
//!
//! ```no_run
//! # async fn demo(vault: &dyn tenko_vault::Vault) -> Result<(), tenko_vault::VaultError> {
//! use tenko_core::{RequestCtx, principal::SystemComponent};
//! use tenko_vault::{SecretBytes, SecretPurpose, SecretSpec};
//!
//! let ctx = RequestCtx::system(SystemComponent::Auth);
//! let seed = SecretBytes::from(b"12345678901234567890".to_vec());
//! let secret = vault
//!     .put_system(&ctx, SecretSpec::new(SecretPurpose::from_static("auth.totp")), seed)
//!     .await?;
//! let again = vault.get_system(&ctx, secret).await?;
//! assert_eq!(again.expose().len(), 20);
//! # Ok(()) }
//! ```
//!
//! A package that must write a secret atomically with its own rows stages it into its
//! batch with [`Vault::stage_put`] and proposes the batch itself.

pub mod envelope;
pub mod error;
pub mod kek;
pub mod operator;
mod secret;
mod store_vault;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use error::VaultError;
#[cfg(any(test, feature = "testing"))]
pub use kek::MemKek;
pub use kek::{DataKey, KekConfig, KekInit, KekProtection, KekProvider, KekRing, KekSealer};
pub use secret::{RevealAudit, SecretBytes, SecretMeta, SecretPurpose, SecretSpec};
pub use store_vault::{KEK_EPOCH, KekRotation, StoreVault, actions, tables};
pub use tenko_core::secret::{SecretClass, SecretRef, VaultEnvelope};
#[cfg(any(test, feature = "testing"))]
pub use testing::MemVault;

use tenko_core::RequestCtx;
use tenko_store::WriteBatch;

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-vault";

/// Returns the version of this crate as declared in its manifest.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Largest secret the vault accepts, in bytes.
pub const MAX_SECRET_LEN: usize = 64 * 1024;

/// The vault: stores, resolves, reveals and rotates secrets.
///
/// Writes produce one write batch each, with an audit draft that names the secret but
/// never its value. Reads decrypt on every call; nothing is cached in plaintext.
///
/// Authorization is the caller's job: the API checks [`Action::Reveal`], the PIN coupling
/// rule (IAM-07) and the reveal policy (TGL-24) before calling
/// [`reveal_with`](Vault::reveal_with) through [`operator::OperatorSecrets`].
///
/// [`Action::Reveal`]: tenko_core::Action::Reveal
#[async_trait::async_trait]
pub trait Vault: Send + Sync + 'static {
    /// Encrypts and stores a new [`SecretClass::System`] secret (never revealable).
    ///
    /// # Errors
    ///
    /// [`VaultError::TooLarge`], a KEK failure or the store's error.
    async fn put_system(
        &self,
        ctx: &RequestCtx,
        spec: SecretSpec,
        value: SecretBytes,
    ) -> Result<SecretRef, VaultError>;

    /// Decrypts a secret of either class for use by Tenko itself (a TOTP check, a TLS
    /// key, a connector call). The value must never be returned to a client; use
    /// [`reveal`](Vault::reveal) for that. Not audited: the caller's own action is.
    ///
    /// # Errors
    ///
    /// [`VaultError::NotFound`], [`VaultError::Integrity`] when the envelope fails
    /// authentication, [`VaultError::UnknownKek`], or the store's error.
    async fn get_system(
        &self,
        ctx: &RequestCtx,
        secret: SecretRef,
    ) -> Result<SecretBytes, VaultError>;

    /// Encrypts and stores a new [`SecretClass::Operator`] secret (revealable with audit,
    /// counts for IAM-07).
    ///
    /// # Errors
    ///
    /// As [`put_system`](Vault::put_system).
    async fn put_operator(
        &self,
        ctx: &RequestCtx,
        spec: SecretSpec,
        value: SecretBytes,
    ) -> Result<SecretRef, VaultError>;

    /// Reveals an operator secret to a person and records the reveal in the audit log
    /// before returning it (IAM-16). System secrets are refused with
    /// [`VaultError::NotRevealable`] and the refusal is audited too.
    ///
    /// # Errors
    ///
    /// [`VaultError::NotRevealable`], [`VaultError::NotFound`], a decryption failure, or
    /// the store's error (no value is returned when the audit record cannot be written).
    async fn reveal(&self, ctx: &RequestCtx, secret: SecretRef) -> Result<SecretBytes, VaultError>;

    /// Reveals an operator secret as [`reveal`](Vault::reveal) does, and commits `batch`
    /// (the caller's own rows, such as a last-revealed stamp) in the same write as the
    /// audit record of the reveal, which also names `audit.objects` and carries
    /// `audit.context` (the host, the reason). The value is returned only after that write
    /// committed; a failed or refused reveal is audited with the same context.
    ///
    /// # Errors
    ///
    /// As [`reveal`](Vault::reveal), plus the store's precondition failure of `batch`.
    async fn reveal_with(
        &self,
        ctx: &RequestCtx,
        secret: SecretRef,
        batch: WriteBatch,
        audit: RevealAudit,
    ) -> Result<SecretBytes, VaultError>;

    /// Re-encrypts a secret under a fresh DEK wrapped by the active KEK.
    ///
    /// # Errors
    ///
    /// As [`get_system`](Vault::get_system), plus the store's precondition failure when
    /// the secret changed concurrently.
    async fn rotate_dek(&self, ctx: &RequestCtx, secret: SecretRef) -> Result<(), VaultError>;

    /// Replaces the value of an existing secret under a fresh DEK, keeping its class,
    /// purpose and reference.
    ///
    /// # Errors
    ///
    /// [`VaultError::NotFound`], [`VaultError::TooLarge`], a KEK failure or the store's
    /// error.
    async fn replace(
        &self,
        ctx: &RequestCtx,
        secret: SecretRef,
        value: SecretBytes,
    ) -> Result<(), VaultError>;

    /// Deletes a secret. Deleting an absent secret is a no-op.
    ///
    /// # Errors
    ///
    /// The store's error.
    async fn delete(&self, ctx: &RequestCtx, secret: SecretRef) -> Result<(), VaultError>;

    /// The non-secret metadata of a secret.
    ///
    /// # Errors
    ///
    /// The store's error.
    async fn meta(&self, secret: SecretRef) -> Result<Option<SecretMeta>, VaultError>;

    /// Whether the vault holds at least one operator secret: the condition of the PIN
    /// coupling rule (IAM-07, Q3). System secrets do not count.
    ///
    /// # Errors
    ///
    /// The store's error.
    async fn has_operator_secrets(&self) -> Result<bool, VaultError>;

    /// Encrypts a new secret and adds its rows, a version precondition and an audit draft
    /// to the caller's batch, so the secret commits atomically with the caller's own
    /// mutations. Nothing is written until the caller proposes the batch.
    ///
    /// The batch also expects the current [`KEK_EPOCH`]: when a KEK rotation starts between
    /// staging and proposing, the store refuses the batch with a precondition failure on
    /// that counter and the caller stages again. The envelope holds random keys and nonces,
    /// so a batch with a staged secret never replays under an idempotency key; clear
    /// `batch.idempotency` or treat `IdempotencyMismatch` as a new request.
    ///
    /// # Errors
    ///
    /// [`VaultError::TooLarge`] or a KEK failure.
    fn stage_put(
        &self,
        batch: &mut WriteBatch,
        ctx: &RequestCtx,
        class: SecretClass,
        spec: SecretSpec,
        value: &SecretBytes,
    ) -> Result<SecretRef, VaultError>;

    /// Adds the deletion of a secret and an audit draft to the caller's batch.
    fn stage_delete(&self, batch: &mut WriteBatch, ctx: &RequestCtx, secret: SecretRef);

    /// Encrypts a new value of an existing secret under a fresh DEK and adds the write, a
    /// version precondition on the current envelope, the new `updated_at` of its metadata
    /// and an audit draft (`vault.secret.replace`) to the caller's batch, so the value
    /// changes atomically with the caller's own rows. Reads (and opens) the current
    /// envelope for its class and DEK generation; the batch expects the current
    /// [`KEK_EPOCH`] as [`stage_put`](Vault::stage_put) does.
    ///
    /// # Errors
    ///
    /// [`VaultError::NotFound`], [`VaultError::TooLarge`], a decryption or KEK failure, or
    /// the store's error.
    async fn stage_replace(
        &self,
        batch: &mut WriteBatch,
        ctx: &RequestCtx,
        secret: SecretRef,
        value: &SecretBytes,
    ) -> Result<(), VaultError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_matches_manifest() {
        assert_eq!(CRATE_NAME, env!("CARGO_PKG_NAME"));
        assert!(version().starts_with(|c: char| c.is_ascii_digit()));
    }
}
