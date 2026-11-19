//! Enrollment codes and enrollment (ADR 0035, decision 5).
//!
//! The code's secret never travels at enrollment: the integrator proves it with an
//! HMAC-SHA-256 over [`PROOF_LABEL`], the code id, the account id and the canonical
//! `SubjectPublicKeyInfo` of its request ([`enrollment_proof`]). The controller keeps the
//! secret in the vault while the code can be used, since it needs it to check the proof.

use std::net::IpAddr;

use aws_lc_rs::hmac;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::Revision;
use tenko_core::{
    ObjectRef, RequestCtx, Timestamp, UserId, audit::AuditDraft, secret::SecretClass,
};
use tenko_store::{KeyRange, ReadConsistency, ReadView, ReadViewExt as _, WriteBatch};
use tenko_vault::{SecretBytes, SecretSpec};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{
    CODE_KEPT_SECS, CODE_LIFETIME_SECS, CODE_PREFIX, CODE_SECRET_PURPOSE, ClientCertError,
    ClientCerts, MAX_LINEAGES, PROOF_LABEL, actions, audit,
    model::{
        CLIENT_CERT_KEYS, CLIENT_CERTS, CertState, ClientCertRecord, CodeState, ENROLLMENT_CODES,
        EnrollmentCode, EnrollmentCodeView, KeyRecord,
    },
};
use crate::{encoding::hex_encode, model::USERS, model::UserRecord};

/// The longest label of an enrolled host, in characters.
const MAX_LABEL: usize = 64;

/// `POST /integrations/enrollments`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NewCode {
    /// The service account to enroll.
    pub account: UserId,
    /// Seconds until the code expires, 60 to 3600; one hour when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime_secs: Option<u64>,
    /// The only network the enrollment may come from, in CIDR notation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub source: Option<IpNet>,
}

/// The answer of `POST /integrations/enrollments`: the code's text, shown once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CreatedCode {
    /// The code as it is listed.
    pub enrollment: EnrollmentCodeView,
    /// `tnki.<code id>.<account id>.<secret>.<fingerprint>`, shown once.
    pub code: String,
    /// SHA-256 of the internal root, which the integration listener's server certificate
    /// chains to, lower-case hex (the code's last part).
    pub server_root_sha256: String,
}

/// What an enrollment request carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollInput {
    /// The code id.
    pub code: Uuid,
    /// The HMAC of [`enrollment_proof`].
    pub proof: Vec<u8>,
    /// The PKCS#10 request, DER.
    pub csr: Vec<u8>,
    /// The integrator's label of the host.
    pub label: String,
    /// The client's address, when known.
    pub source: Option<IpAddr>,
}

/// The HMAC-SHA-256 an integrator sends to enroll: keyed with the code's secret, over
/// `tenko-integration-enroll-v1\n<code id>\n<account id>\n` and the canonical DER of the
/// request's `SubjectPublicKeyInfo`. The ids are in their hyphenated lower-case form.
pub fn enrollment_proof(secret: &[u8], code: Uuid, account: UserId, spki: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    hmac::sign(&key, &proof_message(code, account, spki))
        .as_ref()
        .to_vec()
}

fn proof_message(code: Uuid, account: UserId, spki: &[u8]) -> Vec<u8> {
    let mut message = format!("{PROOF_LABEL}\n{code}\n{account}\n").into_bytes();
    message.extend_from_slice(spki);
    message
}

/// An enabled service account, with the revision of its record.
fn usable_account(
    view: &dyn ReadView,
    id: UserId,
) -> Result<(UserRecord, Revision), ClientCertError> {
    view.get_typed(&USERS, &id)?
        .filter(|(user, _)| user.is_service() && !user.disabled)
        .ok_or(ClientCertError::Account)
}

impl ClientCerts {
    /// `POST /integrations/enrollments`: a single-use code for one service account. The
    /// route has checked the administrator's right and the sign-in within five minutes.
    ///
    /// # Errors
    ///
    /// [`ClientCertError::Lifetime`], [`ClientCertError::Account`], or a store, vault or CA
    /// error.
    pub async fn create_code(
        &self,
        ctx: &RequestCtx,
        creator: UserId,
        request: &NewCode,
    ) -> Result<CreatedCode, ClientCertError> {
        let lifetime = request.lifetime_secs.unwrap_or(*CODE_LIFETIME_SECS.end());
        if !CODE_LIFETIME_SECS.contains(&lifetime) {
            return Err(ClientCertError::Lifetime);
        }
        let view = self.view().await?;
        let (account, revision) = usable_account(view.as_ref(), request.account)?;
        // The listener's trust anchor exists before the first certificate is asked for.
        self.issuer.ensure_root(ctx).await?;
        let mut secret = [0u8; 32];
        aws_lc_rs::rand::fill(&mut secret).map_err(|_| ClientCertError::Issuing {
            reason: "random number generator failed".to_owned(),
        })?;
        let secret = SecretBytes::from_slice(&secret);
        let id = Uuid::now_v7();
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&USERS, &account.id, Some(revision));
        let secret_ref = self.vault.stage_put(
            &mut batch,
            ctx,
            SecretClass::System,
            SecretSpec::new(CODE_SECRET_PURPOSE).labeled(id.to_string()),
            &secret,
        )?;
        let record = EnrollmentCode {
            id,
            account: account.id,
            generation: account.tokens_generation,
            created_by: creator,
            created_at: ctx.now,
            expires_at: Timestamp(ctx.now.0 + time::Duration::seconds(lifetime.cast_signed())),
            source: request.source,
            secret: Some(secret_ref),
            state: CodeState::Pending,
        };
        batch.put_typed(&ENROLLMENT_CODES, &id, &record)?;
        let mut draft = audit(actions::CODE_CREATE, account.id, ctx)
            .with_context("code", id.to_string())
            .with_context("expires_at", record.expires_at.to_rfc3339());
        if let Some(source) = request.source {
            draft = draft.with_context("source", source.to_string());
        }
        batch.audit(draft);
        self.commit(batch).await?;
        self.prune_codes(ctx).await;
        let server_root_sha256 = self.issuer.server_root_sha256();
        Ok(CreatedCode {
            enrollment: record.view(ctx.now),
            code: format!(
                "{CODE_PREFIX}.{id}.{}.{}.{server_root_sha256}",
                account.id,
                hex_encode(secret.expose())
            ),
            server_root_sha256,
        })
    }

    /// `GET /integrations/enrollments`: every code, newest first, never a secret.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn list_codes(
        &self,
        now: Timestamp,
    ) -> Result<Vec<EnrollmentCodeView>, ClientCertError> {
        let view = self.view().await?;
        Ok(view
            .scan_typed(&ENROLLMENT_CODES, KeyRange::all(), usize::MAX, true)?
            .into_iter()
            .map(|(_, code, _)| code.view(now))
            .collect())
    }

    /// `DELETE /integrations/enrollments/{id}`: a waiting code can no longer be used.
    ///
    /// # Errors
    ///
    /// [`ClientCertError::NotFound`], or a store error.
    pub async fn withdraw_code(&self, ctx: &RequestCtx, id: Uuid) -> Result<(), ClientCertError> {
        self.end_code(ctx, id, "withdrawn").await
    }

    /// Withdraws a code that arrived over plain HTTP, as node enrollment does with its token
    /// (ADR 0035, decision 5), and answers the refusal. Nothing happens to an unknown code.
    ///
    /// The refusal is [`ClientCertError::Transport`] with `why`, or the store error that kept
    /// the code from being withdrawn.
    pub async fn refuse_plain_http(
        &self,
        ctx: &RequestCtx,
        id: Uuid,
        why: &'static str,
    ) -> ClientCertError {
        match self.end_code(ctx, id, "plain_http").await {
            Ok(()) | Err(ClientCertError::NotFound(_)) => ClientCertError::Transport(why),
            Err(error) => error,
        }
    }

    async fn end_code(
        &self,
        ctx: &RequestCtx,
        id: Uuid,
        reason: &str,
    ) -> Result<(), ClientCertError> {
        let view = self.store.read(ReadConsistency::Linearizable).await?;
        let (mut code, revision) = view
            .get_typed(&ENROLLMENT_CODES, &id)?
            .ok_or(ClientCertError::NotFound("enrollment code"))?;
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&ENROLLMENT_CODES, &id, Some(revision));
        if code.state == CodeState::Pending {
            code.state = CodeState::Withdrawn;
        }
        if let Some(secret) = code.secret.take() {
            self.vault.stage_delete(&mut batch, ctx, secret);
        }
        batch.put_typed(&ENROLLMENT_CODES, &id, &code)?;
        batch.audit(
            audit(actions::CODE_WITHDRAW, code.account, ctx)
                .with_context("code", id.to_string())
                .with_context("reason", reason.to_owned()),
        );
        self.commit(batch).await
    }

    /// Deletes the secrets of expired codes and the records of codes past
    /// [`CODE_KEPT_SECS`]; best effort, after a code is created.
    async fn prune_codes(&self, ctx: &RequestCtx) {
        let Ok(view) = self.view().await else { return };
        let Ok(codes) = view.scan_typed(&ENROLLMENT_CODES, KeyRange::all(), usize::MAX, false)
        else {
            return;
        };
        let mut batch = WriteBatch::for_request(ctx);
        let mut changed = false;
        for (id, mut code, revision) in codes {
            let done = code.state != CodeState::Pending || ctx.now.0 >= code.expires_at.0;
            if !done {
                continue;
            }
            let ended = code.expires_at.0.min(ctx.now.0);
            if (ctx.now.0 - ended).whole_seconds() > CODE_KEPT_SECS {
                batch.expect_typed(&ENROLLMENT_CODES, &id, Some(revision));
                if let Some(secret) = code.secret {
                    self.vault.stage_delete(&mut batch, ctx, secret);
                }
                batch.delete_typed(&ENROLLMENT_CODES, &id);
                changed = true;
            } else if let Some(secret) = code.secret.take() {
                batch.expect_typed(&ENROLLMENT_CODES, &id, Some(revision));
                self.vault.stage_delete(&mut batch, ctx, secret);
                if batch.put_typed(&ENROLLMENT_CODES, &id, &code).is_err() {
                    return;
                }
                changed = true;
            }
        }
        if changed && let Err(error) = self.commit(batch).await {
            tracing::debug!("enrollment codes not pruned: {error}");
        }
    }

    /// `POST /integrations/enroll`: checks the code, its proof and the account, issues the
    /// certificate and records it in the write that uses the code. The certificate is
    /// answered only after that write; every refusal is audited.
    ///
    /// # Errors
    ///
    /// Every [`ClientCertError`] of ADR 0035 decision 5.
    pub async fn enroll(
        &self,
        ctx: &RequestCtx,
        input: EnrollInput,
    ) -> Result<String, ClientCertError> {
        match self.try_enroll(ctx, &input).await {
            Ok(pem) => Ok(pem),
            Err(error) => {
                if !matches!(error, ClientCertError::Store(_) | ClientCertError::Vault(_)) {
                    let draft = AuditDraft::denied(actions::ISSUE, Vec::<ObjectRef>::new())
                        .with_context("code", input.code.to_string())
                        .with_context("reason", tenko_core::Coded::code(&error).to_owned());
                    self.audit_refusal(ctx, draft).await;
                }
                Err(error)
            }
        }
    }

    /// The waiting code of `input` whose proof verifies, with the view it was read in and
    /// the canonical key of the request.
    async fn proven_code(
        &self,
        ctx: &RequestCtx,
        input: &EnrollInput,
    ) -> Result<
        (
            std::sync::Arc<dyn ReadView>,
            EnrollmentCode,
            Revision,
            Vec<u8>,
        ),
        ClientCertError,
    > {
        // A code made a moment ago on another controller may not be here yet.
        let mut view = self.view().await?;
        if view.get_typed(&ENROLLMENT_CODES, &input.code)?.is_none() {
            view = self.store.read(ReadConsistency::Linearizable).await?;
        }
        let (code, code_revision) = view
            .get_typed(&ENROLLMENT_CODES, &input.code)?
            .ok_or(ClientCertError::CodeInvalid)?;
        match code.state {
            CodeState::Pending => {}
            CodeState::Used { .. } => return Err(ClientCertError::CodeUsed),
            CodeState::Withdrawn => return Err(ClientCertError::CodeInvalid),
        }
        if ctx.now.0 >= code.expires_at.0 {
            return Err(ClientCertError::CodeExpired);
        }
        let secret_ref = code.secret.ok_or(ClientCertError::CodeInvalid)?;
        let spki = self.issuer.request_key(&input.csr)?;
        let secret = self.vault.get_system(ctx, secret_ref).await?;
        // A constant-time comparison: a wrong proof tells nothing about the secret.
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.expose());
        hmac::verify(
            &key,
            &proof_message(code.id, code.account, &spki),
            &input.proof,
        )
        .map_err(|_| ClientCertError::CodeInvalid)?;
        if let Some(network) = code.source
            && !input
                .source
                .is_some_and(|address| network.contains(&address))
        {
            return Err(ClientCertError::CodeSource);
        }
        Ok((view, code, code_revision, spki))
    }

    async fn try_enroll(
        &self,
        ctx: &RequestCtx,
        input: &EnrollInput,
    ) -> Result<String, ClientCertError> {
        let label = input.label.trim();
        if label.is_empty()
            || label.chars().count() > MAX_LABEL
            || label.chars().any(char::is_control)
        {
            return Err(ClientCertError::Label);
        }
        let (view, mut code, code_revision, spki) = self.proven_code(ctx, input).await?;
        let secret_ref = code.secret.ok_or(ClientCertError::CodeInvalid)?;
        let (account, account_revision, key_sha256) = checked_account(view.as_ref(), &code, &spki)?;
        let policy = Self::policy(view.as_ref())?;
        let issued = self
            .issuer
            .issue(ctx, account.id, &input.csr, policy.lifetime_days)
            .await?;
        if issued.key_sha256 != key_sha256 {
            return Err(ClientCertError::Issuing {
                reason: "the issued certificate does not carry the requested key".to_owned(),
            });
        }
        let lineage = Uuid::now_v7();
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&ENROLLMENT_CODES, &code.id, Some(code_revision));
        batch.expect_typed(&USERS, &account.id, Some(account_revision));
        batch.expect_typed(&CLIENT_CERT_KEYS, &key_sha256, None);
        batch.expect_typed(&CLIENT_CERTS, &issued.serial, None);
        self.vault.stage_delete(&mut batch, ctx, secret_ref);
        code.secret = None;
        code.state = CodeState::Used {
            serial: issued.serial.clone(),
        };
        batch.put_typed(&ENROLLMENT_CODES, &code.id, &code)?;
        batch.put_typed(
            &CLIENT_CERT_KEYS,
            &key_sha256,
            &KeyRecord {
                account: account.id,
                lineage,
            },
        )?;
        batch.put_typed(
            &CLIENT_CERTS,
            &issued.serial,
            &ClientCertRecord {
                serial: issued.serial.clone(),
                account: account.id,
                generation: account.tokens_generation,
                lineage,
                label: label.to_owned(),
                key_sha256: key_sha256.clone(),
                not_before: issued.not_before,
                not_after: issued.not_after,
                issued_at: ctx.now,
                state: CertState::Current,
                presented_at: None,
                ended_at: None,
                reason: None,
            },
        )?;
        batch.audit(
            audit(actions::ISSUE, account.id, ctx)
                .with_context("code", code.id.to_string())
                .with_context("serial", issued.serial.clone())
                .with_context("lineage", lineage.to_string())
                .with_context("key_sha256", key_sha256)
                .with_context("label", label.to_owned())
                .with_context("not_after", issued.not_after.to_rfc3339()),
        );
        match self.commit(batch).await {
            Err(ClientCertError::Conflict) => {
                // Find out what came first: the code was used, or the account changed.
                let view = self.store.read(ReadConsistency::Linearizable).await?;
                Err(match view.get_typed(&ENROLLMENT_CODES, &code.id)? {
                    Some((
                        EnrollmentCode {
                            state: CodeState::Used { .. },
                            ..
                        },
                        _,
                    )) => ClientCertError::CodeUsed,
                    _ => ClientCertError::Conflict,
                })
            }
            Err(error) => Err(error),
            Ok(()) => Ok(issued.pem),
        }
    }
}

/// The code's account, still enabled and of the code's generation, and the digest of a key
/// that never enrolled, when the account has room for another lineage.
fn checked_account(
    view: &dyn ReadView,
    code: &EnrollmentCode,
    spki: &[u8],
) -> Result<(UserRecord, Revision, String), ClientCertError> {
    let (account, account_revision) = usable_account(view, code.account)?;
    if account.tokens_generation != code.generation {
        return Err(ClientCertError::Account);
    }
    let key_sha256 =
        hex_encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, spki).as_ref());
    if view.get_typed(&CLIENT_CERT_KEYS, &key_sha256)?.is_some() {
        return Err(ClientCertError::KeyUsed);
    }
    let lineages: std::collections::HashSet<Uuid> = view
        .scan_typed(&CLIENT_CERTS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .filter(|(_, cert, _)| {
            cert.account == account.id
                && matches!(cert.state, CertState::Current | CertState::Pending)
        })
        .map(|(_, cert, _)| cert.lineage)
        .collect();
    if lineages.len() >= MAX_LINEAGES {
        return Err(ClientCertError::Lineages);
    }
    Ok((account, account_revision, key_sha256))
}
