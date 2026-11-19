//! Listing and revoking integration certificates (ADR 0035, decision 9).

use tenko_core::{RequestCtx, UserId};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt as _, WriteBatch};

use super::{
    ClientCertError, ClientCerts, actions, audit,
    model::{CLIENT_CERTS, CertState, ClientCertRecord},
};

impl ClientCerts {
    /// `GET /integrations/certificates`: the certificates, of one account or of all, by
    /// serial.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn list(
        &self,
        account: Option<UserId>,
    ) -> Result<Vec<ClientCertRecord>, ClientCertError> {
        let view = self.view().await?;
        Ok(view
            .scan_typed(&CLIENT_CERTS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, record, _)| record)
            .filter(|record| account.is_none_or(|account| record.account == account))
            .collect())
    }

    /// `DELETE /integrations/certificates/{serial}`: revokes the lineage the certificate
    /// belongs to, every certificate of it that has not ended yet. Revoking an ended lineage
    /// changes nothing and succeeds.
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
        let view = self.store.read(ReadConsistency::Linearizable).await?;
        let (target, _) = view
            .get_typed(&CLIENT_CERTS, &serial.to_owned())?
            .ok_or(ClientCertError::NotFound("certificate"))?;
        let mut batch = WriteBatch::for_request(ctx);
        let mut revoked = Vec::new();
        for (key, mut record, revision) in
            view.scan_typed(&CLIENT_CERTS, KeyRange::all(), usize::MAX, false)?
        {
            if record.lineage != target.lineage
                || matches!(record.state, CertState::Withdrawn | CertState::Revoked)
            {
                continue;
            }
            batch.expect_typed(&CLIENT_CERTS, &key, Some(revision));
            record.state = CertState::Revoked;
            record.ended_at = Some(ctx.now);
            record.reason = Some(reason.to_owned());
            batch.put_typed(&CLIENT_CERTS, &key, &record)?;
            revoked.push(key);
        }
        if revoked.is_empty() {
            return Ok(());
        }
        batch.audit(
            audit(actions::REVOKE, target.account, ctx)
                .with_context("lineage", target.lineage.to_string())
                .with_context("serials", revoked.join(","))
                .with_context("reason", reason.to_owned()),
        );
        self.commit(batch).await
    }
}
