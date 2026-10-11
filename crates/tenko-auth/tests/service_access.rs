//! Scoped access through the service (IAM-01, IAM-06, IAM-10): grants and their delegation,
//! service accounts, scoped tokens, the MFA policy per role, and the unlock watch.
//!
//! The service is called directly, not through HTTP. Anchors come from a fixed in-memory
//! resolver, since `tenko-auth` cannot depend on `tenko-ipam`:
//!
//! ```text
//! VRF V1:  P1 192.0.2.0/24 (site S1) > P2 192.0.2.0/25 (site S2, a child of S1)
//! VRF V2:  P3 198.51.100.0/24 (site S3)
//! hosts:   HOST_P2 in P2, HOST_P1 in P1, HOST_P3 in P3
//! ```

use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
    time::Duration,
};

use tenko_auth::{
    AuthConfig, AuthError, AuthService, LoginOutcome, NewSession,
    authz::{AUDIT_OBJECT, METRICS_OBJECT, anywhere},
    lockout::LockoutMode,
    model::{GrantId, RoleMfa, TOKENS, TokenGrant, TokenRecord, TokenScope, USER_TOKENS},
    roles::{RoleName, default_policy, required_strength},
    secret::{TOKEN_PREFIX, hash_secret},
    service::{
        GrantCreate, GrantView, PasswordLogin, RolePolicyUpdate, ServiceAccountCreate, TokenCreate,
        TokenRequest, UserCreate, UserInfo, types::SecretString,
    },
    settings::{Profile, SettingsPatch, TokenMaxLifetime},
    testing::TestEnv,
};
use tenko_core::{
    Action, Anchors, ApiTokenId, AuthStrength, Coded, Credentials, Denied, DenyReason, ObjectKind,
    ObjectRef, PrefixId, Principal, RequestCtx, ScopeFilter, ScopeRule, SessionId, SiteId,
    SystemComponent, UserId, VrfId,
    audit::{AuditOutcome, AuditRecord},
};
use tenko_store::{
    AnchorResolver, KeyRange, ReadConsistency, ReadView, ReadViewExt, Store, StoreError,
    WriteBatch, tables,
};
use uuid::Uuid;

const V1: VrfId = VrfId::from_uuid(Uuid::from_u128(0x01));
const V2: VrfId = VrfId::from_uuid(Uuid::from_u128(0x02));
const S1: SiteId = SiteId::from_uuid(Uuid::from_u128(0x11));
const S2: SiteId = SiteId::from_uuid(Uuid::from_u128(0x12));
const S3: SiteId = SiteId::from_uuid(Uuid::from_u128(0x13));
/// 192.0.2.0/24.
const P1: PrefixId = PrefixId::from_uuid(Uuid::from_u128(0x21));
/// 192.0.2.0/25, inside P1.
const P2: PrefixId = PrefixId::from_uuid(Uuid::from_u128(0x22));
/// 198.51.100.0/24, in another VRF.
const P3: PrefixId = PrefixId::from_uuid(Uuid::from_u128(0x23));

const HOST_P2: ObjectRef = ObjectRef::new(ObjectKind::Host, Uuid::from_u128(0x31));
const HOST_P1: ObjectRef = ObjectRef::new(ObjectKind::Host, Uuid::from_u128(0x32));
const HOST_P3: ObjectRef = ObjectRef::new(ObjectKind::Host, Uuid::from_u128(0x33));

// Documentation PINs for the Home profile (all unlike each other, none sequential).
const PIN_DANA: &str = "7391";
const PIN_ERIN: &str = "6402";
const PIN_FINN: &str = "5827";
const PIN_GUS: &str = "3159";

fn prefix(id: PrefixId, subtree: bool) -> ScopeRule {
    ScopeRule::Prefix { id, subtree }
}

fn site(id: SiteId, subtree: bool) -> ScopeRule {
    ScopeRule::Site { id, subtree }
}

// ---------------------------------------------------------------------------------------
// The anchors
// ---------------------------------------------------------------------------------------

/// A fixed map from object to anchors. Prefix chains start with the prefix itself and list
/// its ancestors; site lists start with the object's own site and list its ancestors.
struct FixedAnchors(HashMap<ObjectRef, Anchors>);

impl FixedAnchors {
    fn new() -> Self {
        let mut map = HashMap::new();
        let mut put = |object: ObjectRef, anchors: Anchors| {
            map.insert(
                object,
                Anchors {
                    object: Some(object),
                    ..anchors
                },
            );
        };
        put(
            ObjectRef::from(V1),
            Anchors {
                vrf: Some(V1),
                ..Anchors::default()
            },
        );
        put(
            ObjectRef::from(V2),
            Anchors {
                vrf: Some(V2),
                ..Anchors::default()
            },
        );
        put(
            ObjectRef::from(S1),
            Anchors {
                sites: vec![S1],
                ..Anchors::default()
            },
        );
        put(
            ObjectRef::from(S2),
            Anchors {
                sites: vec![S2, S1],
                ..Anchors::default()
            },
        );
        put(
            ObjectRef::from(S3),
            Anchors {
                sites: vec![S3],
                ..Anchors::default()
            },
        );
        let p1 = Anchors {
            vrf: Some(V1),
            sites: vec![S1],
            prefixes: vec![vec![P1]],
            ..Anchors::default()
        };
        let p2 = Anchors {
            vrf: Some(V1),
            sites: vec![S2, S1],
            prefixes: vec![vec![P2, P1]],
            ..Anchors::default()
        };
        let p3 = Anchors {
            vrf: Some(V2),
            sites: vec![S3],
            prefixes: vec![vec![P3]],
            ..Anchors::default()
        };
        put(HOST_P1, p1.clone());
        put(HOST_P2, p2.clone());
        put(HOST_P3, p3.clone());
        put(ObjectRef::from(P1), p1);
        put(ObjectRef::from(P2), p2);
        put(ObjectRef::from(P3), p3);
        Self(map)
    }
}

impl AnchorResolver for FixedAnchors {
    fn anchors(&self, _view: &dyn ReadView, object: &ObjectRef) -> Result<Anchors, StoreError> {
        self.0
            .get(object)
            .cloned()
            .ok_or_else(|| StoreError::Storage(format!("no anchors for {object}")))
    }
}

// ---------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------

/// An installation under the Home profile (PIN passwords, so every session meets every
/// requirement unless a test raises one) with the anchors wired.
struct Lab {
    env: TestEnv,
    admin_session: NewSession,
    admin_id: UserId,
}

impl Lab {
    async fn new() -> Lab {
        let lab = Lab::unwired().await;
        lab.env
            .service
            .set_anchor_resolver(Arc::new(FixedAnchors::new()));
        lab
    }

    async fn unwired() -> Lab {
        let (env, admin_session) = TestEnv::installed(Profile::Home).await;
        let admin_id = admin_session.info.user.id;
        Lab {
            env,
            admin_session,
            admin_id,
        }
    }

    async fn admin(&self) -> RequestCtx {
        self.env
            .session_ctx(&self.admin_session)
            .await
            .expect("the administrator's context")
    }

    /// A person created by the administrator.
    async fn user(&self, name: &str, pin: Option<&str>, roles: &[RoleName]) -> UserInfo {
        self.env
            .service
            .create_user(
                &self.admin().await,
                &UserCreate {
                    name: name.to_owned(),
                    display_name: None,
                    password: pin.map(SecretString::new),
                    roles: roles.to_vec(),
                    language: None,
                },
            )
            .await
            .expect("the user is created")
    }

    /// Signs a user in and returns the context of the session.
    async fn sign_in(&self, name: &str, pin: &str) -> RequestCtx {
        let outcome = self
            .env
            .service
            .login_password(
                &self.env.public_ctx(),
                Some("test-agent"),
                &PasswordLogin {
                    user_name: name.to_owned(),
                    password: SecretString::new(pin),
                },
            )
            .await
            .expect("the login");
        let LoginOutcome::Session(session) = outcome else {
            panic!("expected a session");
        };
        self.env.accept_password(session.info.user.id).await;
        self.env.session_ctx(&session).await.expect("a context")
    }

    /// A grant created by the administrator.
    async fn grant(
        &self,
        subject: UserId,
        role: RoleName,
        scope: ScopeRule,
        delegable: bool,
    ) -> GrantView {
        self.try_grant(&self.admin().await, subject, role, scope, delegable)
            .await
            .expect("the grant is created")
    }

    async fn try_grant(
        &self,
        ctx: &RequestCtx,
        subject: UserId,
        role: RoleName,
        scope: ScopeRule,
        delegable: bool,
    ) -> Result<GrantView, AuthError> {
        self.env
            .service
            .create_grant(
                ctx,
                &GrantCreate {
                    subject,
                    role,
                    scope,
                    delegable,
                },
            )
            .await
    }

    /// The decision of the authorizer as its stable code: `ok` or the code of the refusal.
    fn code(&self, principal: &Principal, action: Action, object: ObjectRef) -> &'static str {
        self.env
            .service
            .authorizer()
            .check(principal, action, &object)
            .map_or_else(|denied| denied.code(), |()| "ok")
    }

    /// The refusal reason of a decision.
    fn refusal(
        &self,
        principal: &Principal,
        action: Action,
        object: ObjectRef,
    ) -> Option<DenyReason> {
        self.env
            .service
            .authorizer()
            .check(principal, action, &object)
            .err()
            .map(|Denied { reason, .. }| reason)
    }

    /// The context of a bearer token.
    async fn token_ctx(&self, token: &str) -> RequestCtx {
        self.env
            .ctx_for(&Credentials::Bearer(token.to_owned()))
            .await
            .expect("the token authenticates")
    }

    async fn audit(&self, action: &str) -> Vec<AuditRecord> {
        let view = self
            .env
            .store
            .read(ReadConsistency::Local)
            .await
            .expect("a view");
        view.scan_typed(&tables::AUDIT, KeyRange::all(), 100_000, false)
            .expect("the audit log")
            .into_iter()
            .map(|(_, record, _)| record)
            .filter(|record| record.draft.action.as_str() == action)
            .collect()
    }
}

/// A session principal of the given strength. The authorizer decides on the principal
/// alone, so every strength can be tried without a login.
fn person(id: UserId, strength: AuthStrength) -> Principal {
    Principal::User {
        id,
        session: SessionId::generate(),
        strength,
    }
}

fn grant_ids(grants: &[GrantView]) -> BTreeSet<GrantId> {
    grants.iter().map(|grant| grant.id).collect()
}

fn code_of<T: std::fmt::Debug>(result: Result<T, AuthError>) -> &'static str {
    match result {
        Err(error) => error.code(),
        Ok(value) => panic!("expected an error, got {value:?}"),
    }
}

fn denied_reason<T: std::fmt::Debug>(result: Result<T, AuthError>) -> DenyReason {
    match result {
        Err(AuthError::Denied(denied)) => denied.reason,
        other => panic!("expected a denial, got {other:?}"),
    }
}

fn scoped(role: RoleName, scope: ScopeRule) -> TokenRequest {
    TokenRequest {
        name: "ci".to_owned(),
        expires_in_days: None,
        grants: Some(vec![TokenGrant {
            role,
            scope: Some(scope),
        }]),
        scopes: Vec::new(),
    }
}

fn with_scopes(scopes: &[TokenScope]) -> TokenRequest {
    TokenRequest {
        name: "monitoring".to_owned(),
        expires_in_days: None,
        grants: None,
        scopes: scopes.to_vec(),
    }
}

// ---------------------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn an_administrator_grants_a_role_over_a_scope_and_the_holder_has_it_at_once() {
    let lab = Lab::new().await;
    let ines = lab.user("ines", None, &[]).await;
    let nobody = person(ines.id, AuthStrength::Pin);
    assert_eq!(lab.code(&nobody, Action::Read, HOST_P2), "auth.forbidden");

    let granted = lab
        .grant(ines.id, RoleName::Viewer, prefix(P1, true), false)
        .await;
    assert_eq!(granted.subject.id, ines.id);
    assert_eq!(granted.subject.name, "ines");
    assert_eq!(granted.role, RoleName::Viewer);
    assert_eq!(granted.scope, prefix(P1, true));
    assert!(!granted.delegable);
    assert_eq!(granted.granted_by, Some(lab.admin_id));
    assert_eq!(granted.parent, None);

    assert_eq!(lab.code(&nobody, Action::Read, HOST_P2), "ok");
    assert_eq!(
        lab.code(&nobody, Action::Read, HOST_P3),
        "auth.out_of_scope"
    );
    assert_eq!(lab.code(&nobody, Action::Update, HOST_P2), "auth.forbidden");
    let audit = lab.audit("auth.grant.create").await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].draft.outcome, AuditOutcome::Success);
    assert!(audit[0].draft.objects.contains(&ObjectRef::from(ines.id)));
    assert_eq!(
        audit[0].draft.details.context.get("grant"),
        Some(&granted.id.to_string())
    );
}

#[tokio::test]
async fn the_same_grant_twice_is_a_duplicate_and_a_different_scope_or_role_is_not() {
    let lab = Lab::new().await;
    let ines = lab.user("ines", None, &[]).await;
    lab.grant(ines.id, RoleName::Viewer, site(S1, true), false)
        .await;
    let again = lab
        .try_grant(
            &lab.admin().await,
            ines.id,
            RoleName::Viewer,
            site(S1, true),
            true,
        )
        .await;
    assert_eq!(code_of(again), "auth.grant.duplicate");
    for (role, scope) in [
        (RoleName::Operator, site(S1, true)),
        (RoleName::Viewer, site(S1, false)),
        (RoleName::Viewer, ScopeRule::Vrf(V2)),
    ] {
        lab.grant(ines.id, role, scope, false).await;
    }
    assert_eq!(
        lab.env
            .service
            .list_grants(&lab.admin().await, Some(ines.id))
            .await
            .expect("the list")
            .len(),
        4
    );
}

#[tokio::test]
async fn roles_that_are_global_only_cannot_be_granted_over_a_scope() {
    let lab = Lab::new().await;
    let ines = lab.user("ines", None, &[]).await;
    for role in [RoleName::Admin, RoleName::Auditor] {
        let result = lab
            .try_grant(&lab.admin().await, ines.id, role, ScopeRule::Vrf(V1), false)
            .await;
        assert_eq!(
            result.expect_err("refused"),
            AuthError::GrantInvalidRole {
                role: role.as_str()
            }
        );
    }
    assert_eq!(
        code_of(
            lab.try_grant(
                &lab.admin().await,
                ines.id,
                RoleName::Admin,
                ScopeRule::Vrf(V1),
                false
            )
            .await
        ),
        "auth.grant.invalid_role"
    );
}

#[tokio::test]
async fn scopes_that_cannot_be_granted_or_do_not_exist_are_refused() {
    let lab = Lab::new().await;
    let ines = lab.user("ines", None, &[]).await;
    let refused = [
        // Tenant and object rules exist in the model but are not granted in Phase 1.
        ScopeRule::Tenant(tenko_core::TenantId::generate()),
        ScopeRule::Object(HOST_P2),
        // Rules that name nothing.
        ScopeRule::Vrf(VrfId::generate()),
        site(SiteId::generate(), true),
        prefix(PrefixId::generate(), false),
        // An identifier of another kind is not the object the rule names.
        prefix(PrefixId::from_uuid(Uuid::from_u128(0x11)), true),
    ];
    for scope in refused {
        let result = lab
            .try_grant(
                &lab.admin().await,
                ines.id,
                RoleName::Viewer,
                scope.clone(),
                false,
            )
            .await;
        assert!(
            matches!(result, Err(AuthError::GrantInvalidScope(_))),
            "{scope:?}: {result:?}"
        );
        assert_eq!(code_of(result), "auth.grant.invalid_scope");
    }
}

#[tokio::test]
async fn a_grant_for_an_unknown_subject_is_not_found() {
    let lab = Lab::new().await;
    let result = lab
        .try_grant(
            &lab.admin().await,
            UserId::generate(),
            RoleName::Viewer,
            ScopeRule::Vrf(V1),
            false,
        )
        .await;
    assert_eq!(
        result.expect_err("refused"),
        AuthError::NotFound { kind: "user" }
    );
}

#[tokio::test]
async fn without_a_resolver_of_anchors_no_scope_can_be_granted() {
    let lab = Lab::unwired().await;
    let ines = lab.user("ines", None, &[]).await;
    let result = lab
        .try_grant(
            &lab.admin().await,
            ines.id,
            RoleName::Viewer,
            ScopeRule::Vrf(V1),
            false,
        )
        .await;
    assert_eq!(result.expect_err("refused"), AuthError::ScopeUnavailable);
    // A rule that can never be granted is refused as such, resolver or not.
    let result = lab
        .try_grant(
            &lab.admin().await,
            ines.id,
            RoleName::Viewer,
            ScopeRule::Object(HOST_P2),
            false,
        )
        .await;
    assert_eq!(code_of(result), "auth.grant.invalid_scope");
}

#[tokio::test]
async fn an_administrator_lists_every_grant_and_a_holder_its_own_and_those_issued_under_them() {
    let lab = Lab::new().await;
    let dana = lab.user("dana", Some(PIN_DANA), &[]).await;
    let erin = lab.user("erin", Some(PIN_ERIN), &[]).await;
    let finn = lab.user("finn", Some(PIN_FINN), &[]).await;
    lab.user("gus", Some(PIN_GUS), &[]).await;
    let delegable = lab
        .grant(dana.id, RoleName::Operator, prefix(P1, true), true)
        .await;
    let dana_ctx = lab.sign_in("dana", PIN_DANA).await;
    let issued = lab
        .try_grant(
            &dana_ctx,
            erin.id,
            RoleName::Viewer,
            prefix(P2, true),
            false,
        )
        .await
        .expect("a delegation");
    let separate = lab
        .grant(finn.id, RoleName::Viewer, ScopeRule::Vrf(V2), false)
        .await;

    let list = |ctx: RequestCtx, subject: Option<UserId>| {
        let service = Arc::clone(&lab.env.service);
        async move { service.list_grants(&ctx, subject).await.expect("the list") }
    };
    let admin = lab.admin().await;
    let all = list(admin.clone(), None).await;
    assert_eq!(
        grant_ids(&all),
        BTreeSet::from([delegable.id, issued.id, separate.id])
    );
    assert_eq!(
        grant_ids(&list(admin, Some(erin.id)).await),
        BTreeSet::from([issued.id])
    );
    assert_eq!(
        grant_ids(&list(dana_ctx.clone(), None).await),
        BTreeSet::from([delegable.id, issued.id]),
        "the holder sees its grant and the one issued under it, not finn's"
    );
    assert_eq!(
        list(dana_ctx, Some(finn.id)).await,
        Vec::new(),
        "the subject filter does not widen what the holder sees"
    );
    let erin_ctx = lab.sign_in("erin", PIN_ERIN).await;
    assert_eq!(
        grant_ids(&list(erin_ctx, None).await),
        BTreeSet::from([issued.id])
    );
    let gus_ctx = lab.sign_in("gus", PIN_GUS).await;
    assert_eq!(list(gus_ctx, None).await, Vec::new());
}

// ---------------------------------------------------------------------------------------
// Delegation
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn the_holder_of_a_delegable_grant_grants_a_role_no_higher_over_a_scope_inside() {
    let lab = Lab::new().await;
    let dana = lab.user("dana", Some(PIN_DANA), &[]).await;
    let erin = lab.user("erin", None, &[]).await;
    let parent = lab
        .grant(dana.id, RoleName::Operator, prefix(P1, true), true)
        .await;
    let dana_ctx = lab.sign_in("dana", PIN_DANA).await;
    let reader = person(erin.id, AuthStrength::Pin);

    for (role, scope, delegable) in [
        (RoleName::Viewer, prefix(P2, true), false),
        (RoleName::Operator, prefix(P2, true), true),
        (RoleName::Viewer, prefix(P1, false), false),
    ] {
        let granted = lab
            .try_grant(&dana_ctx, erin.id, role, scope.clone(), delegable)
            .await
            .unwrap_or_else(|error| panic!("{role} {scope:?}: {error}"));
        assert_eq!(granted.parent, Some(parent.id), "{role} {scope:?}");
        assert_eq!(granted.granted_by, Some(dana.id));
        assert_eq!(granted.delegable, delegable);
    }
    assert_eq!(lab.code(&reader, Action::Update, HOST_P2), "ok");
    assert_eq!(
        lab.code(&reader, Action::Read, HOST_P3),
        "auth.out_of_scope"
    );
    let audit = lab.audit("auth.grant.create").await;
    assert_eq!(audit.len(), 4, "the administrator's grant and three more");
    assert_eq!(
        audit[3].draft.details.context.get("parent"),
        Some(&parent.id.to_string())
    );
}

#[tokio::test]
async fn a_delegation_beyond_the_holders_own_grant_is_refused_and_audited() {
    let lab = Lab::new().await;
    let dana = lab.user("dana", Some(PIN_DANA), &[]).await;
    let hal = lab.user("hal", Some(PIN_ERIN), &[]).await;
    lab.user("gil", Some(PIN_FINN), &[RoleName::Operator]).await;
    let erin = lab.user("erin", None, &[]).await;
    lab.grant(dana.id, RoleName::Operator, prefix(P2, true), true)
        .await;
    lab.grant(hal.id, RoleName::Viewer, prefix(P1, true), true)
        .await;
    let dana_ctx = lab.sign_in("dana", PIN_DANA).await;
    let hal_ctx = lab.sign_in("hal", PIN_ERIN).await;
    let gil_ctx = lab.sign_in("gil", PIN_FINN).await;

    let mut refusals = 0;
    // A wider scope: the parent of the holder's prefix, another prefix, the VRF, a site.
    for scope in [
        prefix(P1, true),
        prefix(P3, false),
        ScopeRule::Vrf(V1),
        site(S1, true),
    ] {
        let result = lab
            .try_grant(&dana_ctx, erin.id, RoleName::Viewer, scope.clone(), false)
            .await;
        assert_eq!(
            result.expect_err(&format!("{scope:?} is wider")),
            AuthError::GrantExceedsOwn
        );
        refusals += 1;
    }
    // A higher role over a scope inside.
    let result = lab
        .try_grant(
            &hal_ctx,
            erin.id,
            RoleName::Operator,
            prefix(P2, true),
            false,
        )
        .await;
    assert_eq!(code_of(result), "auth.grant.exceeds_own");
    refusals += 1;
    // A global role is not a delegable grant.
    let result = lab
        .try_grant(&gil_ctx, erin.id, RoleName::Viewer, prefix(P2, true), false)
        .await;
    assert_eq!(code_of(result), "auth.grant.exceeds_own");
    refusals += 1;

    let failed: Vec<_> = lab
        .audit("auth.grant.create")
        .await
        .into_iter()
        .filter(|record| {
            matches!(&record.draft.outcome, AuditOutcome::Failed { code } if code == "auth.grant.exceeds_own")
        })
        .collect();
    assert_eq!(failed.len(), refusals, "every refusal is on record");
}

#[tokio::test]
async fn a_grant_that_is_not_delegable_cannot_be_passed_on() {
    let lab = Lab::new().await;
    let dana = lab.user("dana", Some(PIN_DANA), &[]).await;
    let erin = lab.user("erin", None, &[]).await;
    lab.grant(dana.id, RoleName::Operator, prefix(P1, true), false)
        .await;
    let dana_ctx = lab.sign_in("dana", PIN_DANA).await;
    let result = lab
        .try_grant(
            &dana_ctx,
            erin.id,
            RoleName::Viewer,
            prefix(P2, true),
            false,
        )
        .await;
    assert_eq!(result.expect_err("refused"), AuthError::GrantExceedsOwn);
}

#[tokio::test]
async fn revoking_a_delegable_grant_revokes_every_level_in_one_batch() {
    let lab = Lab::new().await;
    let dana = lab.user("dana", Some(PIN_DANA), &[]).await;
    let erin = lab.user("erin", Some(PIN_ERIN), &[]).await;
    let finn = lab.user("finn", None, &[]).await;
    let top = lab
        .grant(dana.id, RoleName::Operator, prefix(P1, true), true)
        .await;
    let dana_ctx = lab.sign_in("dana", PIN_DANA).await;
    let middle = lab
        .try_grant(
            &dana_ctx,
            erin.id,
            RoleName::Operator,
            prefix(P2, true),
            true,
        )
        .await
        .expect("level two");
    let erin_ctx = lab.sign_in("erin", PIN_ERIN).await;
    let bottom = lab
        .try_grant(
            &erin_ctx,
            finn.id,
            RoleName::Viewer,
            prefix(P2, true),
            false,
        )
        .await
        .expect("level three");
    let unrelated = lab
        .grant(finn.id, RoleName::Viewer, ScopeRule::Vrf(V2), false)
        .await;
    let finn_principal = person(finn.id, AuthStrength::Pin);
    assert_eq!(lab.code(&finn_principal, Action::Read, HOST_P2), "ok");

    let revoked = lab
        .env
        .service
        .revoke_grant(&lab.admin().await, top.id)
        .await
        .expect("the cascade");
    assert_eq!(
        revoked.revoked.first(),
        Some(&top.id),
        "the requested one first"
    );
    assert_eq!(
        revoked.revoked.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([top.id, middle.id, bottom.id])
    );
    assert_eq!(revoked.revoked.len(), 3);

    let left = lab
        .env
        .service
        .list_grants(&lab.admin().await, None)
        .await
        .expect("the list");
    assert_eq!(grant_ids(&left), BTreeSet::from([unrelated.id]));
    assert_eq!(
        lab.code(&finn_principal, Action::Read, HOST_P2),
        "auth.out_of_scope"
    );
    assert_eq!(
        lab.code(&person(erin.id, AuthStrength::Pin), Action::Read, HOST_P2),
        "auth.forbidden"
    );
    let audit = lab.audit("auth.grant.revoke").await;
    assert_eq!(audit.len(), 1, "one batch, one record");
    let context = &audit[0].draft.details.context;
    assert_eq!(context.get("grant"), Some(&top.id.to_string()));
    for id in [top.id, middle.id, bottom.id] {
        assert!(
            context["revoked"].contains(&id.to_string()),
            "{id} is listed"
        );
    }
}

#[tokio::test]
async fn a_holder_revokes_grants_issued_under_its_own_and_finds_no_others() {
    let lab = Lab::new().await;
    let dana = lab.user("dana", Some(PIN_DANA), &[]).await;
    let erin = lab.user("erin", Some(PIN_ERIN), &[]).await;
    let own = lab
        .grant(dana.id, RoleName::Operator, prefix(P1, true), true)
        .await;
    let other = lab
        .grant(erin.id, RoleName::Viewer, ScopeRule::Vrf(V2), false)
        .await;
    let dana_ctx = lab.sign_in("dana", PIN_DANA).await;
    let issued = lab
        .try_grant(
            &dana_ctx,
            erin.id,
            RoleName::Viewer,
            prefix(P2, true),
            false,
        )
        .await
        .expect("a delegation");

    let erin_ctx = lab.sign_in("erin", PIN_ERIN).await;
    assert_eq!(
        lab.env
            .service
            .revoke_grant(&erin_ctx, own.id)
            .await
            .expect_err("not hers"),
        AuthError::NotFound { kind: "grant" },
        "a grant outside the caller's reach looks like a missing one"
    );
    assert_eq!(
        lab.env
            .service
            .revoke_grant(&dana_ctx, other.id)
            .await
            .expect_err("not under hers"),
        AuthError::NotFound { kind: "grant" }
    );
    let revoked = lab
        .env
        .service
        .revoke_grant(&dana_ctx, issued.id)
        .await
        .expect("her delegation");
    assert_eq!(revoked.revoked, [issued.id]);
}

#[tokio::test]
async fn a_token_cannot_create_or_revoke_grants_even_for_an_administrator() {
    let lab = Lab::new().await;
    let dana = lab.user("dana", Some(PIN_DANA), &[]).await;
    let erin = lab.user("erin", None, &[]).await;
    let held = lab
        .grant(dana.id, RoleName::Operator, prefix(P1, true), true)
        .await;
    let dana_ctx = lab.sign_in("dana", PIN_DANA).await;
    let admin = lab.admin().await;
    for session in [&dana_ctx, &admin] {
        let created = lab
            .env
            .service
            .create_token(
                session,
                &TokenCreate {
                    name: "automation".to_owned(),
                    expires_in_days: None,
                },
            )
            .await
            .expect("a personal token");
        let token_ctx = lab.token_ctx(created.token.expose()).await;
        assert!(matches!(token_ctx.principal, Principal::Token { .. }));
        assert_eq!(
            denied_reason(
                lab.try_grant(
                    &token_ctx,
                    erin.id,
                    RoleName::Viewer,
                    prefix(P2, true),
                    false
                )
                .await
            ),
            DenyReason::MissingPermission
        );
        assert_eq!(
            denied_reason(lab.env.service.revoke_grant(&token_ctx, held.id).await),
            DenyReason::MissingPermission
        );
    }
    let still = lab
        .env
        .service
        .list_grants(&lab.admin().await, None)
        .await
        .expect("the list");
    assert_eq!(grant_ids(&still), BTreeSet::from([held.id]));
}

// ---------------------------------------------------------------------------------------
// Service accounts
// ---------------------------------------------------------------------------------------

async fn service_account(lab: &Lab, name: &str, roles: &[RoleName]) -> UserInfo {
    lab.env
        .service
        .create_service_account(
            &lab.admin().await,
            &ServiceAccountCreate {
                name: name.to_owned(),
                display_name: None,
                roles: roles.to_vec(),
            },
        )
        .await
        .expect("the service account is created")
}

#[tokio::test]
async fn an_administrator_creates_a_service_account_without_a_password_owned_by_itself() {
    let lab = Lab::new().await;
    let account = service_account(&lab, "svc-ipam", &[]).await;
    assert_eq!(account.kind, tenko_auth::model::UserKind::Service);
    assert_eq!(account.owner, Some(lab.admin_id));
    assert_eq!(account.roles, Vec::<RoleName>::new());
    assert!(!account.factors.password && account.factors.webauthn == 0);

    let listed = lab
        .env
        .service
        .list_service_accounts(&lab.admin().await)
        .await
        .expect("the list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, account.id);
    assert_eq!(lab.audit("auth.service_account.create").await.len(), 1);

    let again = lab
        .env
        .service
        .create_service_account(
            &lab.admin().await,
            &ServiceAccountCreate {
                name: "svc-ipam".to_owned(),
                display_name: None,
                roles: Vec::new(),
            },
        )
        .await;
    assert_eq!(again.expect_err("taken"), AuthError::UserNameTaken);

    let olga = lab
        .user("olga", Some(PIN_DANA), &[RoleName::Operator])
        .await;
    let olga_ctx = lab.sign_in("olga", PIN_DANA).await;
    let by_operator = lab
        .env
        .service
        .create_service_account(
            &olga_ctx,
            &ServiceAccountCreate {
                name: "svc-other".to_owned(),
                display_name: None,
                roles: Vec::new(),
            },
        )
        .await;
    assert_eq!(denied_reason(by_operator), DenyReason::MissingPermission);
    assert_ne!(olga.id, lab.admin_id);
}

#[tokio::test]
async fn a_service_account_cannot_sign_in_with_a_password() {
    let lab = Lab::new().await;
    service_account(&lab, "svc-ipam", &[RoleName::Viewer]).await;
    for password in [PIN_DANA, "", "svc-ipam"] {
        let result = lab
            .env
            .service
            .login_password(
                &lab.env.public_ctx(),
                None,
                &PasswordLogin {
                    user_name: "svc-ipam".to_owned(),
                    password: SecretString::new(password),
                },
            )
            .await;
        assert_eq!(
            result.expect_err("no password, no session"),
            AuthError::InvalidCredentials
        );
    }
}

#[tokio::test]
async fn a_personal_token_of_a_service_account_authenticates_nowhere() {
    let lab = Lab::new().await;
    let account = service_account(&lab, "svc-ipam", &[RoleName::Viewer]).await;
    // No route creates one (a personal token is made in a session, and the account has
    // none), so the record is written the way a damaged or hand-edited store would hold it.
    let secret = format!("{TOKEN_PREFIX}{}", "q".repeat(43));
    let hash = hash_secret(&secret);
    let record = TokenRecord {
        id: ApiTokenId::generate(),
        owner: account.id,
        name: "stray".to_owned(),
        created_at: lab.env.now(),
        expires_at: None,
        last_used_at: None,
        issued_with: AuthStrength::Password,
        prefix: secret.chars().take(12).collect(),
    };
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), lab.env.now());
    batch.put_typed(&TOKENS, &hash, &record).expect("encode");
    batch
        .put_typed(&USER_TOKENS, &(account.id, record.id), &hash)
        .expect("encode");
    lab.env.store.propose(batch).await.expect("commit");

    let result = lab
        .env
        .service
        .authenticate_credentials(&Credentials::Bearer(secret), lab.env.now())
        .await;
    assert_eq!(
        result.expect_err("refused"),
        AuthError::Unauthenticated,
        "authentication refuses it"
    );
    let principal = Principal::Token {
        id: record.id,
        owner: account.id,
    };
    assert_eq!(
        lab.refusal(&principal, Action::Read, HOST_P2),
        Some(DenyReason::Unauthenticated),
        "and so does the authorizer"
    );
}

#[tokio::test]
async fn scoped_tokens_of_a_service_account_are_created_listed_and_revoked() {
    let lab = Lab::new().await;
    let account = service_account(&lab, "svc-ipam", &[]).await;
    lab.grant(account.id, RoleName::Viewer, ScopeRule::Vrf(V1), false)
        .await;
    let admin = lab.admin().await;
    let created = lab
        .env
        .service
        .create_account_token(
            &admin,
            account.id,
            &scoped(RoleName::Viewer, ScopeRule::Vrf(V1)),
        )
        .await
        .expect("a scoped token");
    assert!(created.token.expose().starts_with(TOKEN_PREFIX));
    assert!(created.info.scoped);

    let listed = lab
        .env
        .service
        .list_account_tokens(&admin, account.id)
        .await
        .expect("the list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, created.info.id);
    assert_eq!(
        listed[0].grants,
        [TokenGrant {
            role: RoleName::Viewer,
            scope: Some(ScopeRule::Vrf(V1))
        }]
    );
    assert!(
        listed[0].prefix.len() < created.token.expose().len(),
        "only a prefix is listed"
    );
    let authenticated = lab
        .env
        .service
        .authenticate_credentials(
            &Credentials::Bearer(created.token.expose().to_owned()),
            lab.env.now(),
        )
        .await
        .expect("the token authenticates");
    assert_eq!(authenticated.user, Some(account.id));

    // Neither a person nor an unknown account has service-account tokens.
    let person_id = lab.user("ines", None, &[]).await.id;
    for id in [person_id, UserId::generate()] {
        let result = lab
            .env
            .service
            .create_account_token(&admin, id, &scoped(RoleName::Viewer, ScopeRule::Vrf(V1)))
            .await;
        assert_eq!(
            result.expect_err("not a service account"),
            AuthError::NotFound {
                kind: "service_account"
            }
        );
    }

    lab.env
        .service
        .revoke_account_token(&admin, account.id, created.info.id)
        .await
        .expect("the revocation");
    assert_eq!(
        lab.env
            .service
            .list_account_tokens(&admin, account.id)
            .await
            .expect("the list")
            .len(),
        0
    );
    let result = lab
        .env
        .service
        .authenticate_credentials(
            &Credentials::Bearer(created.token.expose().to_owned()),
            lab.env.now(),
        )
        .await;
    assert_eq!(result.expect_err("revoked"), AuthError::Unauthenticated);
    let again = lab
        .env
        .service
        .revoke_account_token(&admin, account.id, created.info.id)
        .await;
    assert_eq!(
        again.expect_err("gone"),
        AuthError::NotFound { kind: "token" }
    );
}

#[tokio::test]
async fn a_service_account_token_acts_within_the_grants_of_its_account() {
    let lab = Lab::new().await;
    let account = service_account(&lab, "svc-ipam", &[]).await;
    lab.grant(account.id, RoleName::Viewer, ScopeRule::Vrf(V1), false)
        .await;
    let admin = lab.admin().await;
    let created = lab
        .env
        .service
        .create_account_token(
            &admin,
            account.id,
            &scoped(RoleName::Viewer, ScopeRule::Vrf(V1)),
        )
        .await
        .expect("a scoped token");
    let ctx = lab.token_ctx(created.token.expose()).await;
    let token = ctx.principal.clone();
    assert_eq!(
        token,
        Principal::Token {
            id: created.info.id,
            owner: account.id
        }
    );
    assert_eq!(lab.code(&token, Action::Read, HOST_P2), "ok");
    assert_eq!(lab.code(&token, Action::Read, HOST_P3), "auth.out_of_scope");
    assert_eq!(lab.code(&token, Action::Update, HOST_P2), "auth.forbidden");
    assert_eq!(
        lab.code(&token, Action::Read, ObjectRef::singleton(ObjectKind::User)),
        "auth.forbidden"
    );

    // The account holds only a viewer grant, so a token cannot be an operator.
    let result = lab
        .env
        .service
        .create_account_token(
            &admin,
            account.id,
            &scoped(RoleName::Operator, ScopeRule::Vrf(V1)),
        )
        .await;
    assert_eq!(
        result.expect_err("beyond the account"),
        AuthError::GrantExceedsOwn
    );
    // A request for nothing at all is a malformed one.
    let nothing = TokenRequest {
        name: "empty".to_owned(),
        expires_in_days: None,
        grants: Some(Vec::new()),
        scopes: Vec::new(),
    };
    let result = lab
        .env
        .service
        .create_account_token(&admin, account.id, &nothing)
        .await;
    assert!(
        matches!(
            result,
            Err(AuthError::Invalid {
                field: "grants",
                ..
            })
        ),
        "{result:?}"
    );
}

// ---------------------------------------------------------------------------------------
// Scoped tokens
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_scoped_token_must_lie_inside_the_grants_of_its_owner() {
    let lab = Lab::new().await;
    let ines = lab.user("ines", Some(PIN_DANA), &[]).await;
    lab.grant(ines.id, RoleName::Viewer, prefix(P1, true), false)
        .await;
    let ctx = lab.sign_in("ines", PIN_DANA).await;
    let create = |request: TokenRequest| {
        let service = Arc::clone(&lab.env.service);
        let ctx = ctx.clone();
        async move { service.create_token_with(&ctx, &request).await }
    };

    for (role, scope) in [
        (RoleName::Viewer, prefix(P2, true)),
        (RoleName::Viewer, prefix(P1, false)),
        (RoleName::Viewer, prefix(P1, true)),
    ] {
        let created = create(scoped(role, scope.clone()))
            .await
            .unwrap_or_else(|error| panic!("{role} {scope:?}: {error}"));
        assert!(created.info.scoped);
    }
    for (role, scope) in [
        (RoleName::Operator, prefix(P2, true)),
        (RoleName::Viewer, prefix(P3, true)),
        (RoleName::Viewer, ScopeRule::Vrf(V1)),
        (RoleName::Viewer, site(S1, true)),
    ] {
        let result = create(scoped(role, scope.clone())).await;
        assert_eq!(
            result.expect_err(&format!("{role} {scope:?} is beyond the owner")),
            AuthError::GrantExceedsOwn
        );
    }
    // Nothing global without a global role.
    let global = TokenRequest {
        grants: Some(vec![TokenGrant {
            role: RoleName::Viewer,
            scope: None,
        }]),
        ..scoped(RoleName::Viewer, ScopeRule::Vrf(V1))
    };
    assert_eq!(
        create(global).await.expect_err("global"),
        AuthError::GrantExceedsOwn
    );
    // Scopes that cannot exist are invalid, whatever the owner holds.
    for scope in [
        ScopeRule::Vrf(VrfId::generate()),
        ScopeRule::Tenant(tenko_core::TenantId::generate()),
    ] {
        let result = create(scoped(RoleName::Viewer, scope)).await;
        assert_eq!(code_of(result), "auth.grant.invalid_scope");
    }
    let result = create(scoped(RoleName::Admin, prefix(P2, true))).await;
    assert_eq!(code_of(result), "auth.grant.invalid_role");
}

#[tokio::test]
async fn a_token_acts_with_the_intersection_of_its_grants_and_those_of_its_owner() {
    let lab = Lab::new().await;
    // An operator over the whole installation with a token that reads one VRF.
    lab.user("olga", Some(PIN_DANA), &[RoleName::Operator])
        .await;
    let olga = lab.sign_in("olga", PIN_DANA).await;
    let narrow = lab
        .env
        .service
        .create_token_with(&olga, &scoped(RoleName::Viewer, ScopeRule::Vrf(V1)))
        .await
        .expect("a narrower token");
    let narrow = lab.token_ctx(narrow.token.expose()).await.principal;
    assert_eq!(lab.code(&narrow, Action::Read, HOST_P2), "ok");
    assert_eq!(
        lab.code(&narrow, Action::Read, HOST_P3),
        "auth.out_of_scope",
        "the owner reaches P3, the token does not"
    );
    assert_eq!(
        lab.code(&narrow, Action::Update, HOST_P2),
        "auth.forbidden",
        "the owner may update, the token has no such grant"
    );
    assert_eq!(
        lab.env
            .service
            .authorizer()
            .scope(&narrow, Action::Read, ObjectKind::Host),
        ScopeFilter::Only(vec![ScopeRule::Vrf(V1)])
    );

    // A scoped owner with a token inside the grant: the scope answers narrow to the token.
    let ines = lab.user("ines", Some(PIN_ERIN), &[]).await;
    let owner_grant = lab
        .grant(ines.id, RoleName::Operator, prefix(P1, true), false)
        .await;
    let ines_ctx = lab.sign_in("ines", PIN_ERIN).await;
    let created = lab
        .env
        .service
        .create_token_with(&ines_ctx, &scoped(RoleName::Viewer, prefix(P2, true)))
        .await
        .expect("a token inside the grant");
    let token = lab.token_ctx(created.token.expose()).await.principal;
    assert_eq!(lab.code(&token, Action::Read, HOST_P2), "ok");
    assert_eq!(lab.code(&token, Action::Read, HOST_P1), "auth.out_of_scope");
    assert_eq!(lab.code(&token, Action::Update, HOST_P2), "auth.forbidden");
    let authorizer = lab.env.service.authorizer();
    assert_eq!(
        authorizer.scope(&token, Action::Read, ObjectKind::Host),
        ScopeFilter::Only(vec![prefix(P2, true)])
    );
    assert_eq!(
        authorizer.scope(&token, Action::Update, ObjectKind::Host),
        ScopeFilter::Nothing
    );

    // The owner's grant is replaced by one the token does not lie in: nothing is left.
    lab.env
        .service
        .revoke_grant(&lab.admin().await, owner_grant.id)
        .await
        .expect("the revocation");
    lab.grant(ines.id, RoleName::Operator, prefix(P3, true), false)
        .await;
    assert_eq!(lab.code(&token, Action::Read, HOST_P2), "auth.out_of_scope");
    assert_eq!(
        authorizer.scope(&token, Action::Read, ObjectKind::Host),
        ScopeFilter::Nothing
    );
}

#[tokio::test]
async fn a_token_loses_its_right_at_once_when_the_grant_of_its_owner_is_revoked() {
    let lab = Lab::new().await;
    let ines = lab.user("ines", Some(PIN_DANA), &[]).await;
    let owner_grant = lab
        .grant(ines.id, RoleName::Operator, prefix(P1, true), false)
        .await;
    let ctx = lab.sign_in("ines", PIN_DANA).await;
    let created = lab
        .env
        .service
        .create_token_with(&ctx, &scoped(RoleName::Operator, prefix(P2, true)))
        .await
        .expect("a token");
    let token_ctx = lab.token_ctx(created.token.expose()).await;
    let token = token_ctx.principal.clone();
    assert_eq!(lab.code(&token, Action::Update, HOST_P2), "ok");

    lab.env
        .service
        .revoke_grant(&lab.admin().await, owner_grant.id)
        .await
        .expect("the revocation");
    assert_eq!(lab.code(&token, Action::Update, HOST_P2), "auth.forbidden");
    assert_eq!(lab.code(&token, Action::Read, HOST_P2), "auth.forbidden");
    assert_eq!(
        lab.env
            .service
            .authorizer()
            .scope(&token, Action::Read, ObjectKind::Host),
        ScopeFilter::Nothing
    );
    // The token itself still authenticates; it just reaches nothing.
    lab.env
        .service
        .authenticate_credentials(
            &Credentials::Bearer(created.token.expose().to_owned()),
            lab.env.now(),
        )
        .await
        .expect("still a token of a live account");
}

#[tokio::test]
async fn the_special_scopes_read_the_metrics_or_the_audit_log_and_nothing_else() {
    let lab = Lab::new().await;
    lab.user("mona", Some(PIN_DANA), &[RoleName::Viewer]).await;
    let ctx = lab.sign_in("mona", PIN_DANA).await;
    let token = |scopes: &[TokenScope]| {
        let service = Arc::clone(&lab.env.service);
        let ctx = ctx.clone();
        let request = with_scopes(scopes);
        async move {
            service
                .create_token_with(&ctx, &request)
                .await
                .expect("a token")
        }
    };

    let metrics = token(&[TokenScope::Metrics]).await;
    let metrics = lab.token_ctx(metrics.token.expose()).await.principal;
    assert_eq!(lab.code(&metrics, Action::Read, METRICS_OBJECT), "ok");
    for (action, object) in [
        (Action::Read, AUDIT_OBJECT),
        (Action::Read, ObjectRef::singleton(ObjectKind::System)),
        (Action::Update, METRICS_OBJECT),
        (Action::Read, HOST_P2),
        (Action::Read, anywhere(ObjectKind::Prefix)),
    ] {
        assert_eq!(
            lab.code(&metrics, action, object),
            "auth.forbidden",
            "{action:?} {object}"
        );
    }

    let audit = token(&[TokenScope::AuditRead]).await;
    let audit = lab.token_ctx(audit.token.expose()).await.principal;
    assert_eq!(lab.code(&audit, Action::Read, AUDIT_OBJECT), "ok");
    assert_eq!(
        lab.code(&audit, Action::Read, METRICS_OBJECT),
        "auth.forbidden"
    );
    assert_eq!(
        lab.code(&audit, Action::Delete, AUDIT_OBJECT),
        "auth.forbidden"
    );

    let both = token(&[TokenScope::Metrics, TokenScope::AuditRead]).await;
    let both = lab.token_ctx(both.token.expose()).await.principal;
    assert_eq!(lab.code(&both, Action::Read, METRICS_OBJECT), "ok");
    assert_eq!(lab.code(&both, Action::Read, AUDIT_OBJECT), "ok");
}

#[tokio::test]
async fn special_scopes_need_an_owner_who_reads_the_system_or_a_service_account() {
    let lab = Lab::new().await;
    let ines = lab.user("ines", Some(PIN_DANA), &[]).await;
    lab.grant(ines.id, RoleName::Viewer, prefix(P1, true), false)
        .await;
    let ctx = lab.sign_in("ines", PIN_DANA).await;
    let result = lab
        .env
        .service
        .create_token_with(&ctx, &with_scopes(&[TokenScope::Metrics]))
        .await;
    assert_eq!(
        result.expect_err("a scoped viewer does not read the system"),
        AuthError::GrantExceedsOwn
    );

    let account = service_account(&lab, "svc-metrics", &[]).await;
    let created = lab
        .env
        .service
        .create_account_token(
            &lab.admin().await,
            account.id,
            &with_scopes(&[TokenScope::Metrics]),
        )
        .await
        .expect("a service account scrapes metrics");
    let token = lab.token_ctx(created.token.expose()).await.principal;
    assert_eq!(lab.code(&token, Action::Read, METRICS_OBJECT), "ok");
    assert_eq!(
        lab.code(&token, Action::Read, AUDIT_OBJECT),
        "auth.forbidden"
    );
}

#[tokio::test]
async fn a_tightened_lifetime_cap_ends_a_scoped_token_that_would_outlive_it() {
    let lab = Lab::new().await;
    let ines = lab.user("ines", Some(PIN_DANA), &[]).await;
    lab.grant(ines.id, RoleName::Viewer, prefix(P1, true), false)
        .await;
    let ctx = lab.sign_in("ines", PIN_DANA).await;
    let created = lab
        .env
        .service
        .create_token_with(&ctx, &scoped(RoleName::Viewer, prefix(P2, true)))
        .await
        .expect("a token with the Home default life");
    let issued = created.info.created_at;
    assert_eq!(
        created.info.expires_at,
        issued.checked_add(Duration::from_secs(365 * 86_400)),
        "TGL-05 Home: a year"
    );
    lab.env
        .service
        .update_security_settings(
            &lab.admin().await,
            &SettingsPatch {
                token_max_lifetime: Some(TokenMaxLifetime::Days(7)),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("a week at most");

    let bearer = Credentials::Bearer(created.token.expose().to_owned());
    lab.env.clock.advance(Duration::from_secs(6 * 86_400));
    let still = lab
        .env
        .service
        .authenticate_credentials(&bearer, lab.env.now())
        .await
        .expect("day six is within the new cap");
    assert_eq!(
        still.expires_at,
        issued.checked_add(Duration::from_secs(7 * 86_400)),
        "the end moved up to the cap"
    );
    lab.env.clock.advance(Duration::from_secs(2 * 86_400));
    let result = lab
        .env
        .service
        .authenticate_credentials(&bearer, lab.env.now())
        .await;
    assert_eq!(
        result.expect_err("past the new cap"),
        AuthError::SessionExpired
    );
}

// ---------------------------------------------------------------------------------------
// The MFA policy per role
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn role_policies_default_to_what_the_profile_already_requires() {
    for profile in Profile::ALL {
        let (env, _session) = TestEnv::installed(profile).await;
        let views = env
            .service
            .role_policies(&env.public_ctx())
            .await
            .expect("the policies");
        let settings = profile.defaults();
        assert_eq!(views.len(), RoleName::ALL.len());
        for view in views {
            let want = default_policy(view.role, &settings);
            assert_eq!(view.profile_default, want, "{profile:?} {}", view.role);
            assert_eq!(view.mfa, want, "{profile:?} {}", view.role);
            assert_eq!(view.stored, None);
            assert_eq!(
                view.mfa.strength(),
                required_strength(&[view.role], &settings, Action::Read, false),
                "{profile:?} {}: TGL-02 and TGL-03",
                view.role
            );
        }
    }
}

#[tokio::test]
async fn a_passkey_policy_on_operator_forces_step_up_for_that_role_only() {
    let lab = Lab::new().await;
    let olga = lab.user("olga", Some(PIN_DANA), &[]).await;
    let vera = lab.user("vera", None, &[]).await;
    lab.grant(olga.id, RoleName::Operator, prefix(P1, true), false)
        .await;
    lab.grant(vera.id, RoleName::Viewer, prefix(P1, true), false)
        .await;
    // Olga holds the operator role through a scoped grant only.
    let olga_ctx = lab.sign_in("olga", PIN_DANA).await;
    let before = lab
        .env
        .service
        .current_session(&olga_ctx)
        .await
        .expect("the session");
    assert!(!before.flags.mfa_enrolment_required);
    assert_eq!(lab.code(&olga_ctx.principal, Action::Update, HOST_P2), "ok");

    let set = lab
        .env
        .service
        .set_role_policy(
            &lab.admin().await,
            RoleName::Operator,
            &RolePolicyUpdate {
                mfa: RoleMfa::Passkey,
            },
        )
        .await
        .expect("the policy is stored");
    assert_eq!(set.mfa, RoleMfa::Passkey);
    assert_eq!(set.profile_default, RoleMfa::Optional);
    assert_eq!(set.stored, Some(RoleMfa::Passkey));

    let step_up = Some(DenyReason::StepUpRequired {
        required: AuthStrength::Passkey,
    });
    for action in [Action::Read, Action::Update] {
        assert_eq!(
            lab.refusal(&olga_ctx.principal, action, HOST_P2),
            step_up,
            "{action:?}: a PIN session no longer serves the operator"
        );
        assert_eq!(
            lab.refusal(
                &person(olga.id, AuthStrength::PasswordTotp),
                action,
                HOST_P2
            ),
            step_up,
            "{action:?}: a second factor is not a passkey"
        );
        assert_eq!(
            lab.refusal(&person(olga.id, AuthStrength::Passkey), action, HOST_P2),
            None
        );
    }
    let viewer = person(vera.id, AuthStrength::Pin);
    assert_eq!(lab.code(&viewer, Action::Read, HOST_P2), "ok");
    // The session of the operator is told what it lacks.
    let after = lab
        .env
        .service
        .current_session(&olga_ctx)
        .await
        .expect("the session");
    assert_eq!(after.required_strength, AuthStrength::Passkey);
    assert!(after.flags.mfa_enrolment_required);
    // Changing policies is a settings update, which a scoped operator does not hold.
    let result = lab
        .env
        .service
        .set_role_policy(
            &olga_ctx,
            RoleName::Viewer,
            &RolePolicyUpdate {
                mfa: RoleMfa::Passkey,
            },
        )
        .await;
    assert_eq!(denied_reason(result), DenyReason::MissingPermission);
}

#[tokio::test]
async fn clearing_a_role_policy_restores_the_default() {
    let lab = Lab::new().await;
    let olga = lab.user("olga", None, &[]).await;
    lab.grant(olga.id, RoleName::Operator, prefix(P1, true), false)
        .await;
    let password = person(olga.id, AuthStrength::Password);
    let admin = lab.admin().await;
    lab.env
        .service
        .set_role_policy(
            &admin,
            RoleName::Operator,
            &RolePolicyUpdate {
                mfa: RoleMfa::TotpOrStronger,
            },
        )
        .await
        .expect("stored");
    assert_eq!(
        lab.refusal(&password, Action::Read, HOST_P2),
        Some(DenyReason::StepUpRequired {
            required: AuthStrength::PasswordTotp
        })
    );

    let cleared = lab
        .env
        .service
        .clear_role_policy(&admin, RoleName::Operator)
        .await
        .expect("cleared");
    assert_eq!((cleared.mfa, cleared.stored), (RoleMfa::Optional, None));
    assert_eq!(lab.code(&password, Action::Read, HOST_P2), "ok");
    // Clearing a policy that is not stored changes and records nothing.
    lab.env
        .service
        .clear_role_policy(&admin, RoleName::Operator)
        .await
        .expect("idempotent");
    assert_eq!(lab.audit("auth.role_policy.update").await.len(), 2);
}

#[tokio::test]
async fn a_weaker_role_policy_never_lowers_the_profile_requirement() {
    let lab = Lab::new().await;
    lab.env
        .service
        .update_security_settings(
            &lab.env.public_ctx(),
            &SettingsPatch {
                profile: Some(Profile::Standard),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("the Standard profile");
    let ctx = lab.env.public_ctx();
    let admin_policy = lab
        .env
        .service
        .set_role_policy(
            &ctx,
            RoleName::Admin,
            &RolePolicyUpdate {
                mfa: RoleMfa::Optional,
            },
        )
        .await
        .expect("stored");
    assert_eq!(admin_policy.stored, Some(RoleMfa::Optional));
    assert_eq!(admin_policy.profile_default, RoleMfa::TotpOrStronger);
    assert_eq!(admin_policy.mfa, RoleMfa::TotpOrStronger, "TGL-02 holds");
    assert_eq!(
        lab.refusal(
            &person(lab.admin_id, AuthStrength::Password),
            Action::Read,
            HOST_P2
        ),
        Some(DenyReason::StepUpRequired {
            required: AuthStrength::PasswordTotp
        })
    );

    // A stricter policy than the profile's does apply.
    let viewer = lab
        .env
        .service
        .set_role_policy(
            &ctx,
            RoleName::Viewer,
            &RolePolicyUpdate {
                mfa: RoleMfa::Passkey,
            },
        )
        .await
        .expect("stored");
    assert_eq!(
        (viewer.profile_default, viewer.mfa),
        (RoleMfa::Optional, RoleMfa::Passkey)
    );
}

// ---------------------------------------------------------------------------------------
// The unlock watch
// ---------------------------------------------------------------------------------------

/// Fails logins for `name` on `service` until the account carries a persisted lock.
async fn lock_account(lab: &Lab, service: &AuthService, id: UserId, name: &str) {
    for _ in 0..40 {
        let result = service
            .login_password(
                &lab.env.public_ctx(),
                None,
                &PasswordLogin {
                    user_name: name.to_owned(),
                    password: SecretString::new("0000 not the password"),
                },
            )
            .await;
        match result {
            Err(AuthError::InvalidCredentials) => {}
            Err(AuthError::Throttled { retry_after }) => {
                lab.env
                    .clock
                    .advance(Duration::from_secs(retry_after.unwrap_or(60)));
            }
            other => panic!("unexpected {other:?}"),
        }
        let info = service
            .get_user(&lab.env.public_ctx(), id)
            .await
            .expect("the user");
        if info.lock.is_some() {
            return;
        }
    }
    panic!("the account was not locked after forty failures");
}

async fn lock_until_unlock(lab: &Lab) {
    lab.env
        .service
        .update_security_settings(
            &lab.admin().await,
            &SettingsPatch {
                lockout: Some(LockoutMode::LockUntilUnlock),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("an administrator unlocks");
}

async fn login_result(
    lab: &Lab,
    service: &AuthService,
    name: &str,
    pin: &str,
) -> Result<(), AuthError> {
    service
        .login_password(
            &lab.env.public_ctx(),
            None,
            &PasswordLogin {
                user_name: name.to_owned(),
                password: SecretString::new(pin),
            },
        )
        .await
        .map(|_| ())
}

#[tokio::test]
async fn unlocking_a_locked_user_lets_the_next_correct_login_succeed() {
    let lab = Lab::new().await;
    lock_until_unlock(&lab).await;
    let dana = lab.user("dana", Some(PIN_DANA), &[RoleName::Viewer]).await;
    lock_account(&lab, &lab.env.service, dana.id, "dana").await;
    assert!(
        matches!(
            login_result(&lab, &lab.env.service, "dana", PIN_DANA).await,
            Err(AuthError::Throttled { .. })
        ),
        "the right PIN does not help while the account is locked"
    );

    lab.env
        .service
        .unlock_user(&lab.admin().await, dana.id)
        .await
        .expect("the unlock");
    login_result(&lab, &lab.env.service, "dana", PIN_DANA)
        .await
        .expect("the next correct login succeeds");
}

#[tokio::test]
async fn an_unlock_on_one_service_clears_the_throttle_of_another_over_the_same_store() {
    let lab = Lab::new().await;
    lock_until_unlock(&lab).await;
    let dana = lab.user("dana", Some(PIN_DANA), &[RoleName::Viewer]).await;
    // A second controller: its own service, throttle and watch over the same store.
    let other = AuthService::new(
        lab.env.store.clone(),
        lab.env.vault.clone(),
        AuthConfig::default(),
    )
    .await
    .expect("a second service");
    tokio::time::sleep(Duration::from_millis(100)).await;

    lock_account(&lab, &other, dana.id, "dana").await;
    assert!(
        matches!(
            login_result(&lab, &other, "dana", PIN_DANA).await,
            Err(AuthError::Throttled { .. })
        ),
        "the second service holds the throttle"
    );

    // The administrator unlocks on the first service; the second one sees the write.
    lab.env
        .service
        .unlock_user(&lab.admin().await, dana.id)
        .await
        .expect("the unlock");
    let mut outcome = login_result(&lab, &other, "dana", PIN_DANA).await;
    for _ in 0..100 {
        if outcome.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        outcome = login_result(&lab, &other, "dana", PIN_DANA).await;
    }
    outcome.expect("the second service cleared its throttle after the unlock");
}
