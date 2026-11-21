//! The service account and the token of a mirrored source (ADR 0033 decision 3, Windows
//! takeover plan section 2.1 rule 2).
//!
//! The mirror service of `tenko-migrate` stages these into the batch that writes the mirror's
//! row, so a mirror, its account and its token appear and go together. The account
//! `mirror-<id>` holds no role and no grant; its one token carries the scope `mirror:<id>`
//! and no grant, which `crate::authz` lets reach the push of that mirror and nothing else.
//! The token may be bound to source prefixes, by the source binding every scoped token has
//! (IAM-21): a push from elsewhere is refused like an unknown token. Minting needs an
//! interactive session that signed in within the last five minutes, as every scoped token of
//! a service account does: the token outlives the session. A takeover script's delegated
//! session creates one within five minutes of its approval instead (ADR 0038).

use tenko_core::{ApiTokenId, MirrorId, ObjectRef, Principal, RequestCtx, UserId};
use tenko_store::{KeyRange, ReadView, ReadViewExt, WriteBatch};

use super::{
    AuthService, LIST_LIMIT, actions,
    admin::valid_user_name,
    types::{CreatedToken, TokenRequest},
};
use crate::{
    authz::TokenAuthz,
    error::AuthError,
    model::{
        SCOPED_TOKENS, ScopedTokenRecord, TokenScope, USER_NAMES, USER_SCOPED_TOKENS, USERS,
        UserKind, UserRecord,
    },
};

/// What the creation of a mirror's credentials returns: the account and the token, shown
/// once.
#[derive(Debug)]
pub struct MirrorCredentials {
    /// The service account `mirror-<id>`.
    pub account: UserId,
    /// The token with the scope `mirror:<id>`.
    pub token: CreatedToken,
}

/// What a mirror's token is minted with.
#[derive(Debug, Clone, Default)]
pub struct MirrorTokenTerms {
    /// The lifetime in days; the profile's maximum when absent (TGL-05).
    pub expires_in_days: Option<u32>,
    /// The client prefixes the token is accepted from (IAM-21); empty for anywhere.
    pub source_prefixes: Vec<String>,
}

impl AuthService {
    /// Stages the service account `mirror-<id>` and its token into `batch`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`] without a session, [`AuthError::StepUpRequired`] for a
    /// session older than five minutes, [`AuthError::UserNameTaken`] when an account of that
    /// name exists, and the token's errors (TGL-05, the source prefixes).
    pub async fn stage_mirror_account(
        &self,
        ctx: &RequestCtx,
        view: &dyn ReadView,
        batch: &mut WriteBatch,
        mirror: MirrorId,
        terms: &MirrorTokenTerms,
    ) -> Result<MirrorCredentials, AuthError> {
        let (creator, _, strength) = Self::session_principal(ctx)?;
        // ADR 0038: a delegated session within five minutes of its approval, one mirror per
        // DHCP server of its plan; anyone else signed in within the last five minutes.
        if !Self::stage_delegated_mirror(ctx, view, batch, mirror)? {
            self.require_fresh_session(ctx).await?;
        }
        let name = valid_user_name(&tenko_core::migrate::Mirror::account_name(mirror))?;
        let key = UserRecord::name_key(&name);
        if view.get_typed(&USER_NAMES, &key)?.is_some() {
            return Err(AuthError::UserNameTaken);
        }
        let account = UserRecord {
            kind: UserKind::Service,
            owner: Some(creator),
            ..UserRecord::new(name.clone(), name, Vec::new(), ctx.now)
        };
        batch.expect_typed(&USER_NAMES, &key, None);
        batch.put_typed(&USER_NAMES, &key, &account.id)?;
        batch.put_typed(&USERS, &account.id, &account)?;
        batch.audit(
            Self::audit(
                actions::SERVICE_ACCOUNT_CREATE,
                vec![ObjectRef::from(account.id)],
                ctx,
            )
            .with_context("name", account.name.clone())
            .with_context("mirror", mirror.to_string()),
        );
        let token = self.stage_mirror_token_of(
            ctx,
            view,
            batch,
            &account,
            (creator, strength),
            mirror,
            terms,
        )?;
        Ok(MirrorCredentials {
            account: account.id,
            token,
        })
    }

    /// Stages a new token of the mirror's account and the removal of `old`, which stops at
    /// the commit.
    ///
    /// # Errors
    ///
    /// As [`AuthService::stage_mirror_account`], and [`AuthError::NotFound`] when the account
    /// is gone.
    pub async fn stage_mirror_token(
        &self,
        ctx: &RequestCtx,
        view: &dyn ReadView,
        batch: &mut WriteBatch,
        account: UserId,
        mirror: MirrorId,
        old: ApiTokenId,
        terms: &MirrorTokenTerms,
    ) -> Result<CreatedToken, AuthError> {
        let (creator, _, strength) = Self::session_principal(ctx)?;
        self.require_fresh_session(ctx).await?;
        let (account, _) = view
            .get_typed(&USERS, &account)?
            .filter(|(user, _)| user.is_service())
            .ok_or(AuthError::NotFound {
                kind: "service_account",
            })?;
        if let Some(key) = Self::scoped_token_hash(view, account.id, old)? {
            Self::stage_token_removal(view, batch, account.id, old, key)?;
            batch.audit(Self::audit(
                actions::TOKEN_REVOKE,
                vec![ObjectRef::from(account.id), ObjectRef::from(old)],
                ctx,
            ));
        }
        self.stage_mirror_token_of(
            ctx,
            view,
            batch,
            &account,
            (creator, strength),
            mirror,
            terms,
        )
    }

    fn stage_mirror_token_of(
        &self,
        ctx: &RequestCtx,
        view: &dyn ReadView,
        batch: &mut WriteBatch,
        account: &UserRecord,
        (creator, strength): (UserId, tenko_core::AuthStrength),
        mirror: MirrorId,
        terms: &MirrorTokenTerms,
    ) -> Result<CreatedToken, AuthError> {
        let request = TokenRequest {
            name: format!("mirror {mirror}"),
            expires_in_days: terms.expires_in_days,
            source_prefixes: terms.source_prefixes.clone(),
            ..TokenRequest::default()
        };
        self.stage_scoped_token(
            ctx,
            view,
            batch,
            account,
            creator,
            strength,
            &request,
            Some(TokenScope::Mirror(mirror)),
        )
    }

    /// Stages the removal of the mirror's account with every token and grant it holds; an
    /// account that is gone already stages nothing.
    ///
    /// # Errors
    ///
    /// A store or codec error.
    pub fn stage_mirror_account_removal(
        &self,
        ctx: &RequestCtx,
        view: &dyn ReadView,
        batch: &mut WriteBatch,
        account: UserId,
    ) -> Result<(), AuthError> {
        let Some((user, revision)) = view.get_typed(&USERS, &account)? else {
            return Ok(());
        };
        batch.expect_typed(&USERS, &account, Some(revision));
        batch.delete_typed(&USERS, &account);
        batch.delete_typed(&USER_NAMES, &UserRecord::name_key(&user.name));
        for ((_, token), key, _) in view.scan_typed(
            &USER_SCOPED_TOKENS,
            KeyRange::prefix(tenko_core::codec::encode_key(&(account,))),
            LIST_LIMIT,
            false,
        )? {
            Self::stage_token_removal(view, batch, account, token, key)?;
        }
        Self::stage_grant_removal(view, batch, account)?;
        batch.audit(
            Self::audit(actions::USER_DELETE, vec![ObjectRef::from(account)], ctx)
                .with_context("name", user.name),
        );
        Ok(())
    }

    /// The mirror whose push a principal's token is for, if it is a mirror token: the API
    /// refuses such a token on every request but that push, also where a route reads no
    /// right (the calling token's own description, a list a scope filters to nothing).
    pub fn token_mirror(&self, principal: &Principal) -> Option<MirrorId> {
        let Principal::Token { id, .. } = principal else {
            return None;
        };
        match self.index.image().token(*id)? {
            TokenAuthz::Scoped { scopes, .. } => scopes.iter().find_map(|scope| scope.mirror()),
            TokenAuthz::Personal { .. } => None,
        }
    }

    /// The record of the scoped token `token` of `account` (its expiry and its source
    /// prefixes among it); `None` when it is gone.
    ///
    /// # Errors
    ///
    /// A store or codec error.
    pub fn scoped_token(
        view: &dyn ReadView,
        account: UserId,
        token: ApiTokenId,
    ) -> Result<Option<ScopedTokenRecord>, AuthError> {
        let Some(key) = Self::scoped_token_hash(view, account, token)? else {
            return Ok(None);
        };
        Ok(view
            .get_typed(&SCOPED_TOKENS, &key)?
            .map(|(record, _)| record))
    }
}
