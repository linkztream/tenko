//! Shared helpers of the vault integration tests.

#![allow(dead_code)]

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
};

use bytes::Bytes;
use tenko_core::{
    ObjectRef, RequestCtx, Revision, SecretId, SystemComponent, TableName, Timestamp,
    audit::{AuditOutcome, AuditRecord},
    codec::{encode_key, to_cbor},
    secret::{SecretRef, VaultEnvelope},
};
use tenko_store::{
    KeyRange, MemStore, ReadConsistency, ReadView, ReadViewExt, Store, Versioned, WriteBatch,
    tables,
};
use tenko_vault::{SecretBytes, SecretPurpose, SecretSpec, tables as vault_tables};

/// A system context at a fixed, whole-second time.
pub fn ctx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Vault).at(at("2026-10-09T12:00:00Z"))
}

/// A system context at the given time.
pub fn ctx_at(time: &str) -> RequestCtx {
    RequestCtx::system(SystemComponent::Vault).at(at(time))
}

/// Parses an RFC 3339 timestamp.
pub fn at(time: &str) -> Timestamp {
    time.parse().expect("timestamp")
}

/// A spec with only a purpose.
pub fn spec(purpose: &'static str) -> SecretSpec {
    SecretSpec::new(SecretPurpose::from_static(purpose))
}

/// A secret value from text.
pub fn value(text: &str) -> SecretBytes {
    SecretBytes::from(text.as_bytes().to_vec())
}

/// The reference object of a secret, as audit records name it.
pub fn object(secret: SecretRef) -> ObjectRef {
    ObjectRef::from(secret.secret)
}

/// A unique scratch directory under the system temp directory (not created).
pub fn scratch_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("tenko-vault-it-{name}-{}", SecretId::generate()))
}

/// Removes a scratch directory, ignoring errors.
pub fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

/// A fresh read view of the store.
pub async fn view(store: &(impl Store + ?Sized)) -> Arc<dyn ReadView> {
    store.read(ReadConsistency::Local).await.expect("read view")
}

/// Every audit record in `sys.audit`, in sequence order.
pub async fn audit_records(store: &(impl Store + ?Sized)) -> Vec<AuditRecord> {
    view(store)
        .await
        .scan_typed(&tables::AUDIT, KeyRange::all(), usize::MAX, false)
        .expect("scan sys.audit")
        .into_iter()
        .map(|(_, record, _)| record)
        .collect()
}

/// The audit records of one action.
pub async fn audit_of(store: &(impl Store + ?Sized), action: &str) -> Vec<AuditRecord> {
    audit_records(store)
        .await
        .into_iter()
        .filter(|record| record.draft.action.as_str() == action)
        .collect()
}

/// The audit records of one action that name `secret`.
pub async fn audit_for(
    store: &(impl Store + ?Sized),
    action: &str,
    secret: SecretRef,
) -> Vec<AuditRecord> {
    audit_of(store, action)
        .await
        .into_iter()
        .filter(|record| record.draft.objects.contains(&object(secret)))
        .collect()
}

/// The outcome of a record is `Success`.
pub fn is_success(record: &AuditRecord) -> bool {
    record.draft.outcome == AuditOutcome::Success
}

/// The stored row of a secret in `vault.secrets`.
pub async fn stored(store: &(impl Store + ?Sized), secret: SecretRef) -> Option<Versioned> {
    view(store)
        .await
        .get(&vault_tables::SECRETS, &encode_key(&secret.secret))
        .expect("get vault.secrets")
}

/// The stored row of a secret; panics when absent.
pub async fn stored_row(store: &(impl Store + ?Sized), secret: SecretRef) -> Versioned {
    stored(store, secret).await.expect("secret row")
}

/// The decoded envelope of a stored secret.
pub async fn envelope_of(store: &(impl Store + ?Sized), secret: SecretRef) -> VaultEnvelope {
    VaultEnvelope::from_bytes(&stored_row(store, secret).await.value).expect("envelope")
}

/// Overwrites the row of `target` in `vault.secrets` with raw bytes, bypassing the vault.
pub async fn put_raw(
    store: &(impl Store + ?Sized),
    target: SecretRef,
    bytes: impl Into<Bytes>,
) -> Result<(), tenko_store::StoreError> {
    let mut batch = WriteBatch::for_request(&ctx());
    batch.put(
        vault_tables::SECRETS.clone(),
        encode_key(&target.secret),
        bytes,
    );
    store.propose(batch).await.map(drop)
}

/// Overwrites the envelope of `target` with an envelope value, bypassing the vault.
pub async fn put_envelope(
    store: &(impl Store + ?Sized),
    target: SecretRef,
    envelope: &VaultEnvelope,
) {
    put_raw(store, target, envelope.to_bytes().expect("encode"))
        .await
        .expect("store accepts an envelope");
}

/// Every key and value of a table, scanned completely.
pub fn scan_all(view: &dyn ReadView, table: &TableName) -> Vec<(Bytes, Versioned)> {
    view.scan(table, KeyRange::all(), usize::MAX, false)
        .expect("scan table")
}

/// Every table the journal ever recorded a change for, plus the store's own tables.
pub fn written_tables(view: &dyn ReadView) -> BTreeSet<TableName> {
    let mut found: BTreeSet<TableName> = [
        tables::AUDIT.name().clone(),
        tables::JOURNAL.name().clone(),
        tables::COUNTERS,
        tables::IDEMPOTENCY,
    ]
    .into();
    for (_, change_set, _) in view
        .scan_typed(&tables::JOURNAL, KeyRange::all(), usize::MAX, false)
        .expect("scan sys.journal")
    {
        found.extend(change_set.changes.into_iter().map(|change| change.table));
    }
    found
}

/// Tables in which a key or value contains `needle`, with the number of hits.
pub fn tables_containing(view: &dyn ReadView, needle: &[u8]) -> Vec<(TableName, usize)> {
    let mut hits = Vec::new();
    for table in written_tables(view) {
        let count = scan_all(view, &table)
            .iter()
            .filter(|(key, versioned)| contains(key, needle) || contains(&versioned.value, needle))
            .count();
        if count > 0 {
            hits.push((table, count));
        }
    }
    hits
}

/// Whether `haystack` contains `needle`.
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// A store of the `MemStore` kind that the tests also hand to the vault as `dyn Store`.
pub fn mem_store() -> Arc<MemStore> {
    Arc::new(MemStore::default())
}

/// The CBOR encoding of a value, for byte-level searches.
pub fn cbor<T: serde::Serialize>(value: &T) -> Bytes {
    to_cbor(value).expect("cbor")
}

/// The revision of the store right now.
pub async fn revision(store: &(impl Store + ?Sized)) -> Revision {
    view(store).await.revision()
}

/// The prefix of every plaintext marker.
pub const MARKER_PREFIX: &str = "TENKO-PLAINTEXT-MARKER-";

/// A marker unique to one test run, to embed in secret values and search for afterwards.
pub fn unique_marker() -> String {
    format!("{MARKER_PREFIX}{}", SecretId::generate())
}

/// Asserts that a list is empty, printing it otherwise.
pub fn assert_none<T: std::fmt::Debug>(items: &[T], what: &str) {
    assert!(items.is_empty(), "unexpected {what}: {items:?}");
}

/// Asserts that a list is not empty.
pub fn assert_some<T>(items: &[T], what: &str) {
    assert!(!items.is_empty(), "expected some {what}, found none");
}
