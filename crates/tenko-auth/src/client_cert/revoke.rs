//! Listing and revoking integration certificates, and what a lineage's end does to the
//! tokens bound to it (ADR 0035, decisions 7 to 9).

use std::collections::HashSet;

use tenko_core::{RequestCtx, Timestamp, UserId, audit::AuditDraft};
use tenko_store::{KeyRange, ReadConsistency, ReadView, ReadViewExt as _, WriteBatch};
use uuid::Uuid;

use super::{
    ClientCertError, ClientCerts, actions, audit,
    model::{CLIENT_CERTS, CertState, ClientCertRecord},
};
use crate::model::{SCOPED_TOKENS, USER_SCOPED_TOKENS, USERS};

/// What the list says of a certificate whose account's access ended (the account was
/// deleted, or its tokens ended since): such a certificate passes nowhere, whatever its
/// record says.
const ACCESS_ENDED: &str = "the access of its service account ended";

/// How often a revocation is decided again after a write of the lineage got in between.
const REVOKE_TRIES: u32 = 3;

/// Stages the revocation of every certificate of `lineage` that has not ended, with
/// `reason`; returns their serials.
///
/// # Errors
///
/// A store or codec error.
pub(crate) fn stage_lineage_revocation(
    view: &dyn ReadView,
    batch: &mut WriteBatch,
    lineage: Uuid,
    reason: &str,
    now: Timestamp,
) -> Result<Vec<String>, tenko_store::StoreError> {
    let mut revoked = Vec::new();
    for (key, mut record, revision) in
        view.scan_typed(&CLIENT_CERTS, KeyRange::all(), usize::MAX, false)?
    {
        if record.lineage != lineage
            || matches!(record.state, CertState::Withdrawn | CertState::Revoked)
        {
            continue;
        }
        batch.expect_typed(&CLIENT_CERTS, &key, Some(revision));
        record.state = CertState::Revoked;
        record.ended_at = Some(now);
        record.reason = Some(reason.to_owned());
        batch.put_typed(&CLIENT_CERTS, &key, &record)?;
        revoked.push(key);
    }
    Ok(revoked)
}

/// Stages the removal of every token of `account` bound to `lineage`, live or retired;
/// returns how many.
///
/// # Errors
///
/// A store or codec error.
pub(crate) fn stage_bound_token_removal(
    view: &dyn ReadView,
    batch: &mut WriteBatch,
    account: UserId,
    lineage: Uuid,
) -> Result<usize, tenko_store::StoreError> {
    let mut removed = 0;
    for (index_key, hash, revision) in view.scan_typed(
        &USER_SCOPED_TOKENS,
        KeyRange::prefix(tenko_core::codec::encode_key(&(account,))),
        usize::MAX,
        false,
    )? {
        let Some((record, record_revision)) = view.get_typed(&SCOPED_TOKENS, &hash)? else {
            continue;
        };
        if record.lineage != Some(lineage) {
            continue;
        }
        batch.expect_typed(&SCOPED_TOKENS, &hash, Some(record_revision));
        batch.expect_typed(&USER_SCOPED_TOKENS, &index_key, Some(revision));
        batch.delete_typed(&SCOPED_TOKENS, &hash);
        batch.delete_typed(&USER_SCOPED_TOKENS, &index_key);
        removed += 1;
    }
    Ok(removed)
}

impl ClientCerts {
    /// `GET /integrations/certificates`: the certificates, of one account or of all, by
    /// serial. A certificate of an account whose access ended is listed as revoked.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn list(
        &self,
        account: Option<UserId>,
    ) -> Result<Vec<ClientCertRecord>, ClientCertError> {
        let view = self.view().await?;
        let mut records = Vec::new();
        for (_, mut record, _) in
            view.scan_typed(&CLIENT_CERTS, KeyRange::all(), usize::MAX, false)?
        {
            if account.is_some_and(|account| record.account != account) {
                continue;
            }
            let ended = view
                .get_typed(&USERS, &record.account)?
                .is_none_or(|(user, _)| user.tokens_generation > record.generation);
            if ended && !matches!(record.state, CertState::Revoked | CertState::Withdrawn) {
                record.state = CertState::Revoked;
                record.reason = Some(ACCESS_ENDED.to_owned());
            }
            records.push(record);
        }
        Ok(records)
    }

    /// `DELETE /integrations/certificates/{serial}`: revokes the lineage the certificate
    /// belongs to, every certificate of it that has not ended yet, and removes the tokens
    /// bound to it. Revoking an ended lineage changes nothing and succeeds.
    ///
    /// # Errors
    ///
    /// [`ClientCertError::NotFound`], [`ClientCertError::Conflict`] when the lineage changed
    /// meanwhile, or a store error.
    pub async fn revoke(
        &self,
        ctx: &RequestCtx,
        serial: &str,
        reason: &str,
    ) -> Result<(), ClientCertError> {
        // A renewal or presentation committed in between moves a record of the lineage; the
        // revocation is decided again on the newer state, so no new successor escapes it.
        for attempt in 1..=REVOKE_TRIES {
            match self.try_revoke(ctx, serial, reason).await {
                Err(ClientCertError::Conflict) if attempt < REVOKE_TRIES => {}
                result => return result,
            }
        }
        Err(ClientCertError::Conflict)
    }

    async fn try_revoke(
        &self,
        ctx: &RequestCtx,
        serial: &str,
        reason: &str,
    ) -> Result<(), ClientCertError> {
        let view = self.store.read(ReadConsistency::Linearizable).await?;
        let (target, _) = view
            .get_typed(&CLIENT_CERTS, &serial.to_owned())?
            .ok_or(ClientCertError::NotFound("certificate"))?;
        let mut batch = WriteBatch::for_request(ctx);
        let revoked =
            stage_lineage_revocation(view.as_ref(), &mut batch, target.lineage, reason, ctx.now)?;
        if revoked.is_empty() {
            return Ok(());
        }
        let tokens =
            stage_bound_token_removal(view.as_ref(), &mut batch, target.account, target.lineage)?;
        batch.audit(
            audit(actions::REVOKE, target.account, ctx)
                .with_context("lineage", target.lineage.to_string())
                .with_context("serials", revoked.join(","))
                .with_context("tokens", tokens.to_string())
                .with_context("reason", reason.to_owned()),
        );
        self.commit(batch).await
    }

    /// Removes the tokens bound to lineages that lapsed (no certificate of theirs passes
    /// any more by time): their recovery is a new enrollment and new tokens (ADR 0035,
    /// decision 7). Also deletes the records of ended certificates past their validity; the
    /// key records stay, so that a key still never enrolls twice. Returns how many tokens
    /// were removed; the expiry alarm calls it every hour and after every change of the index.
    /// Nothing is removed while the clock guard holds issuing
    /// ([`tenko_core::clock::plausible_now`]): the clock may still be wrong after the wait for
    /// destruction ended, and a lapsed lineage never comes back.
    ///
    /// # Errors
    ///
    /// A store error; [`ClientCertError::Conflict`] when a record changed meanwhile.
    pub async fn remove_lapsed_tokens(&self, now: Timestamp) -> Result<usize, ClientCertError> {
        if tenko_core::clock::plausible_now().is_err() {
            return Ok(0);
        }
        // Work found in this copy is decided again at the leader: a lagging copy can miss the
        // renewal that keeps a lineage alive, and a lapsed lineage never comes back, so the
        // leader's view makes the removal final.
        let (local, _) = Self::stage_sweep(self.view().await?.as_ref(), now)?;
        if local.is_empty() {
            return Ok(0);
        }
        let view = self.store.read(ReadConsistency::Linearizable).await?;
        let (batch, removed) = Self::stage_sweep(view.as_ref(), now)?;
        if !batch.is_empty() {
            self.commit(batch).await?;
        }
        Ok(removed)
    }

    /// The batch of [`ClientCerts::remove_lapsed_tokens`] decided in `view`, and how many
    /// tokens it removes.
    fn stage_sweep(
        view: &dyn ReadView,
        now: Timestamp,
    ) -> Result<(WriteBatch, usize), ClientCertError> {
        let certs = view.scan_typed(&CLIENT_CERTS, KeyRange::all(), usize::MAX, false)?;
        let living: HashSet<Uuid> = certs
            .iter()
            .filter(|(_, record, _)| {
                matches!(record.state, CertState::Current | CertState::Pending)
                    && now.0 < record.not_after.0
            })
            .map(|(_, record, _)| record.lineage)
            .collect();
        let lapsed: HashSet<(UserId, Uuid)> = certs
            .iter()
            .filter(|(_, record, _)| !living.contains(&record.lineage))
            .map(|(_, record, _)| (record.account, record.lineage))
            .collect();
        let ctx = RequestCtx::system(tenko_core::SystemComponent::Auth).at(now);
        let mut batch = WriteBatch::for_request(&ctx);
        let mut removed = 0;
        for (account, lineage) in lapsed {
            let count = stage_bound_token_removal(view, &mut batch, account, lineage)?;
            if count > 0 {
                batch.audit(
                    AuditDraft::success(actions::LAPSE, vec![tenko_core::ObjectRef::from(account)])
                        .with_context("lineage", lineage.to_string())
                        .with_context("tokens", count.to_string()),
                );
                removed += count;
            }
        }
        for (serial, record, revision) in &certs {
            // The overlap is a margin for the clocks of the other controllers.
            if !matches!(record.state, CertState::Current | CertState::Pending)
                && now.0 >= record.not_after.0 + super::OVERLAP
            {
                batch.expect_typed(&CLIENT_CERTS, serial, Some(*revision));
                batch.delete_typed(&CLIENT_CERTS, serial);
            }
        }
        Ok((batch, removed))
    }
}
