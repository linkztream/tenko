//! Renewal of integration certificates and the first presentation of a successor (ADR 0035,
//! decision 6).
//!
//! - A renewal is accepted in the last third of the current certificate's lifetime and at
//!   most once an hour; before that it answers "not due" with the time it will be.
//! - Within a lineage there is one current certificate and at most one pending successor. A
//!   renewal from the current certificate while its successor is unseen (the answer was lost)
//!   withdraws that successor and issues a new one.
//! - The successor's first presentation makes it current and its predecessor replaced.
//!   A renewal from a replaced certificate is reuse: someone else holds a key of the lineage,
//!   and the lineage is revoked.

use std::time::Duration;

use tenko_core::{RequestCtx, Timestamp, UserId};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt as _, WriteBatch};

use super::{
    ClientCertError, ClientCerts, actions, audit,
    enroll::usable_account,
    model::{CLIENT_CERT_KEYS, CLIENT_CERTS, CertState, ClientCertRecord, KeyRecord},
};
use crate::encoding::hex_encode;

/// The least time between two renewals of a lineage.
pub const RENEW_INTERVAL: Duration = Duration::from_secs(3600);

/// What a renewal answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Renewal {
    /// A new certificate, pending until it is first presented.
    Renewed {
        /// The certificate, PEM.
        pem: String,
        /// Its serial.
        serial: String,
    },
    /// Not due yet.
    NotDue {
        /// From when a renewal is accepted.
        renew_after: Timestamp,
    },
}

/// From when a certificate may renew: the start of the last third of its lifetime.
pub fn renew_after(record: &ClientCertRecord) -> Timestamp {
    let lifetime = record.not_after.saturating_since(record.not_before);
    Timestamp(record.not_before.0 + lifetime.mul_f64(2.0 / 3.0))
}

/// From when a lineage that has not renewed raises the expiry alarm: the last sixth of its
/// certificate's lifetime.
pub fn alarm_after(record: &ClientCertRecord) -> Timestamp {
    let lifetime = record.not_after.saturating_since(record.not_before);
    Timestamp(record.not_before.0 + lifetime.mul_f64(5.0 / 6.0))
}

impl ClientCerts {
    /// `POST /integrations/certificate/renew`: renews the certificate `serial` of `account`
    /// that the connection presented, over the key of `csr`: a new key, or the same key (a
    /// key a TPM holds); a key of another lineage or a revoked one is refused.
    ///
    /// # Errors
    ///
    /// [`ClientCertError::Certificate`] for a certificate that does not pass,
    /// [`ClientCertError::Reuse`] (the lineage is revoked), [`ClientCertError::TooSoon`],
    /// [`ClientCertError::KeyUsed`], an invalid request, or a store or CA error.
    pub async fn renew(
        &self,
        ctx: &RequestCtx,
        serial: &str,
        account: UserId,
        csr: &[u8],
    ) -> Result<Renewal, ClientCertError> {
        let view = self.store.read(ReadConsistency::Linearizable).await?;
        let Some(Due {
            record,
            revision,
            user,
            user_revision,
            unseen,
        }) = self.due(ctx, view.as_ref(), serial, account).await?
        else {
            let record = view
                .get_typed(&CLIENT_CERTS, &serial.to_owned())?
                .ok_or(ClientCertError::Certificate)?
                .0;
            return Ok(Renewal::NotDue {
                renew_after: renew_after(&record),
            });
        };
        let spki = self.issuer.request_key(csr)?;
        let key_sha256 =
            hex_encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &spki).as_ref());
        let new_key = key_sha256 != record.key_sha256;
        if new_key && view.get_typed(&CLIENT_CERT_KEYS, &key_sha256)?.is_some() {
            return Err(ClientCertError::KeyUsed);
        }
        let policy = Self::policy(view.as_ref())?;
        let issued = self
            .issuer
            .issue(ctx, account, csr, policy.lifetime_days)
            .await?;
        if issued.key_sha256 != key_sha256 {
            return Err(ClientCertError::Issuing {
                reason: "the issued certificate does not carry the requested key".to_owned(),
            });
        }
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&CLIENT_CERTS, &record.serial, Some(revision));
        // Written unchanged so that its revision moves: a revocation, a presentation or a
        // second renewal that read the lineage before this commit conflicts with it instead
        // of missing the new successor, and a lineage never holds two pending certificates.
        batch.put_typed(&CLIENT_CERTS, &record.serial, &record)?;
        batch.expect_typed(&crate::model::USERS, &account, Some(user_revision));
        batch.expect_typed(&CLIENT_CERTS, &issued.serial, None);
        let mut withdrawn = Vec::new();
        for (key, mut other, other_revision) in unseen {
            batch.expect_typed(&CLIENT_CERTS, &key, Some(other_revision));
            other.state = CertState::Withdrawn;
            other.ended_at = Some(ctx.now);
            other.reason = Some("replaced by another renewal before it was presented".to_owned());
            batch.put_typed(&CLIENT_CERTS, &key, &other)?;
            withdrawn.push(key);
        }
        if new_key {
            batch.expect_typed(&CLIENT_CERT_KEYS, &key_sha256, None);
            batch.put_typed(
                &CLIENT_CERT_KEYS,
                &key_sha256,
                &KeyRecord {
                    account,
                    lineage: record.lineage,
                },
            )?;
        }
        batch.put_typed(
            &CLIENT_CERTS,
            &issued.serial,
            &ClientCertRecord {
                serial: issued.serial.clone(),
                generation: user.tokens_generation,
                key_sha256,
                not_before: issued.not_before,
                not_after: issued.not_after,
                issued_at: ctx.now,
                state: CertState::Pending,
                presented_at: None,
                ended_at: None,
                reason: None,
                ..record.clone()
            },
        )?;
        let mut draft = audit(actions::RENEW, account, ctx)
            .with_context("serial", record.serial.clone())
            .with_context("new_serial", issued.serial.clone())
            .with_context("lineage", record.lineage.to_string())
            .with_context("key_changed", new_key.to_string());
        if !withdrawn.is_empty() {
            draft = draft.with_context("withdrawn", withdrawn.join(","));
        }
        batch.audit(draft);
        self.commit(batch).await?;
        Ok(Renewal::Renewed {
            pem: issued.pem,
            serial: issued.serial,
        })
    }

    /// Records the first presentation of a pending successor: it becomes current and the
    /// certificate it replaces becomes replaced. Nothing happens for any other state.
    ///
    /// # Errors
    ///
    /// [`ClientCertError::Conflict`] when the lineage changed meanwhile, or a store error.
    pub async fn note_presented(
        &self,
        ctx: &RequestCtx,
        serial: &str,
    ) -> Result<(), ClientCertError> {
        let view = self.store.read(ReadConsistency::Linearizable).await?;
        let Some((mut record, revision)) = view.get_typed(&CLIENT_CERTS, &serial.to_owned())?
        else {
            return Ok(());
        };
        if record.state != CertState::Pending {
            return Ok(());
        }
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&CLIENT_CERTS, &record.serial, Some(revision));
        let mut replaced = Vec::new();
        for (key, mut other, other_revision) in
            view.scan_typed(&CLIENT_CERTS, KeyRange::all(), usize::MAX, false)?
        {
            if other.lineage == record.lineage && other.state == CertState::Current {
                batch.expect_typed(&CLIENT_CERTS, &key, Some(other_revision));
                other.state = CertState::Replaced;
                other.ended_at = Some(ctx.now);
                batch.put_typed(&CLIENT_CERTS, &key, &other)?;
                replaced.push(key);
            }
        }
        record.state = CertState::Current;
        record.presented_at = Some(ctx.now);
        batch.put_typed(&CLIENT_CERTS, &record.serial, &record)?;
        batch.audit(
            audit(actions::PRESENT, record.account, ctx)
                .with_context("serial", record.serial.clone())
                .with_context("lineage", record.lineage.to_string())
                .with_context("replaced", replaced.join(",")),
        );
        self.commit(batch).await
    }
}

/// A current certificate whose renewal is due, with what the renewal writes against.
struct Due {
    record: ClientCertRecord,
    revision: tenko_core::Revision,
    user: crate::model::UserRecord,
    user_revision: tenko_core::Revision,
    /// The lineage's pending successors, which the renewal withdraws.
    unseen: Vec<(String, ClientCertRecord, tenko_core::Revision)>,
}

impl ClientCerts {
    /// The certificate `serial` of `account` when it may renew now, `None` when it is not due
    /// yet; a renewal from a replaced certificate revokes its lineage.
    async fn due(
        &self,
        ctx: &RequestCtx,
        view: &dyn tenko_store::ReadView,
        serial: &str,
        account: UserId,
    ) -> Result<Option<Due>, ClientCertError> {
        let (record, revision) = view
            .get_typed(&CLIENT_CERTS, &serial.to_owned())?
            .filter(|(record, _)| record.account == account)
            .ok_or(ClientCertError::Certificate)?;
        let (user, user_revision) =
            usable_account(view, account).map_err(|_| ClientCertError::Certificate)?;
        if user.tokens_generation > record.generation
            || ctx.now.0 < record.not_before.0
            || ctx.now.0 >= record.not_after.0
        {
            return Err(ClientCertError::Certificate);
        }
        match record.state {
            CertState::Current => {}
            CertState::Replaced => {
                // Its successor has been presented: another key of the lineage is in use.
                self.revoke(
                    ctx,
                    serial,
                    "a renewal came from a certificate its lineage had already replaced",
                )
                .await?;
                return Err(ClientCertError::Reuse);
            }
            // A successor that was never presented is new: nothing to renew yet.
            CertState::Pending => return Ok(None),
            CertState::Withdrawn | CertState::Revoked => return Err(ClientCertError::Certificate),
        }
        if ctx.now.0 < renew_after(&record).0 {
            return Ok(None);
        }
        let unseen: Vec<_> = view
            .scan_typed(&CLIENT_CERTS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .filter(|(_, other, _)| {
                other.lineage == record.lineage && other.state == CertState::Pending
            })
            .collect();
        if unseen
            .iter()
            .any(|(_, other, _)| ctx.now.saturating_since(other.issued_at) < RENEW_INTERVAL)
        {
            return Err(ClientCertError::TooSoon);
        }
        Ok(Some(Due {
            record,
            revision,
            user,
            user_revision,
            unseen,
        }))
    }
}
