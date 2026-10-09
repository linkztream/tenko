//! The authorizer against the requirements: roles, actions and object kinds (IAM-01 Slice 1),
//! the strength rules of TGL-02 and TGL-03, the PIN coupling rule (IAM-07, CON-07), personal
//! tokens, disabled accounts, system and node principals, and the scope answers.

use std::sync::Arc;

use tenko_auth::{
    AuthConfig, AuthError, AuthService, LoginOutcome, NewSession,
    roles::RoleName,
    service::{PasswordLogin, TokenCreate, UserCreate, UserUpdate, types::SecretString},
    settings::{MfaRequirement, Profile, SettingsPatch},
    testing::TestEnv,
};
use tenko_core::{
    Action, AuthStrength, Authorizer, Coded, Credentials, Denied, DenyReason, NodeId, ObjectKind,
    ObjectRef, Principal, ScopeFilter, SessionId, SystemComponent, UserId,
};
use tenko_vault::{SecretBytes, SecretPurpose, SecretSpec, Vault};

const PASSPHRASE: &str = "marble comet violin saffron";
const PIN: &str = "7391";

const ACTIONS: [Action; 8] = [
    Action::Read,
    Action::Create,
    Action::Update,
    Action::Delete,
    Action::Execute,
    Action::Approve,
    Action::Reveal,
    Action::Administer,
];

const STRENGTHS: [AuthStrength; 5] = [
    AuthStrength::Pin,
    AuthStrength::Password,
    AuthStrength::PasswordTotp,
    AuthStrength::Passkey,
    AuthStrength::HardwareKey,
];

/// One object kind in the permission table. Administrators may do everything; viewers read
/// the kinds marked `viewer_reads`; operators may do the actions in `operator`: `R` read,
/// `C` create, `U` update, `D` delete, `X` execute, `A` approve.
struct Row {
    kind: ObjectKind,
    viewer_reads: bool,
    operator: &'static str,
}

const fn row(kind: ObjectKind, viewer_reads: bool, operator: &'static str) -> Row {
    Row {
        kind,
        viewer_reads,
        operator,
    }
}

const TABLE: [Row; 22] = [
    row(ObjectKind::Tenant, true, "RCUD"),
    row(ObjectKind::Vrf, true, "RCUD"),
    row(ObjectKind::Site, true, "RCUD"),
    row(ObjectKind::Vlan, true, "RCUD"),
    row(ObjectKind::Prefix, true, "RCUDX"),
    row(ObjectKind::Range, true, "RCUD"),
    row(ObjectKind::Address, true, "RCUDX"),
    row(ObjectKind::Host, true, "RCUDX"),
    row(ObjectKind::Interface, true, "RCUD"),
    row(ObjectKind::CustomField, true, "R"),
    row(ObjectKind::User, false, "R"),
    row(ObjectKind::Session, false, ""),
    row(ObjectKind::ApiToken, false, ""),
    row(ObjectKind::Job, true, "RX"),
    row(ObjectKind::Observation, true, "R"),
    row(ObjectKind::Proposal, true, "RA"),
    row(ObjectKind::Import, true, "RCUDX"),
    row(ObjectKind::Connector, true, "R"),
    row(ObjectKind::Secret, false, ""),
    row(ObjectKind::Node, true, "R"),
    row(ObjectKind::Settings, false, "R"),
    row(ObjectKind::System, true, "R"),
];

/// The table letter of an action; administration and reveal belong to administrators only.
const fn letter(action: Action) -> Option<char> {
    match action {
        Action::Read => Some('R'),
        Action::Create => Some('C'),
        Action::Update => Some('U'),
        Action::Delete => Some('D'),
        Action::Execute => Some('X'),
        Action::Approve => Some('A'),
        Action::Reveal | Action::Administer => None,
    }
}

fn password_for(profile: Profile) -> &'static str {
    if profile.defaults().password_policy.is_pin() {
        PIN
    } else {
        PASSPHRASE
    }
}

struct Fixture {
    env: TestEnv,
    authorizer: Arc<dyn Authorizer>,
    admin_session: NewSession,
    operator_session: NewSession,
    viewer_session: NewSession,
    admin: Principal,
    operator: Principal,
    viewer: Principal,
}

async fn add_user(env: &TestEnv, name: &str, role: RoleName, password: &str) {
    add_user_with_roles(env, name, &[role], password).await;
}

async fn add_user_with_roles(env: &TestEnv, name: &str, roles: &[RoleName], password: &str) {
    env.service
        .create_user(
            &env.public_ctx(),
            &UserCreate {
                name: name.to_owned(),
                display_name: None,
                password: Some(SecretString::new(password)),
                roles: roles.to_vec(),
                language: None,
            },
        )
        .await
        .expect("the user is created");
}

async fn login(env: &TestEnv, name: &str, password: &str) -> NewSession {
    let outcome = env
        .service
        .login_password(
            &env.public_ctx(),
            None,
            &PasswordLogin {
                user_name: name.to_owned(),
                password: SecretString::new(password),
            },
        )
        .await
        .expect("login");
    match outcome {
        LoginOutcome::Session(session) => session,
        LoginOutcome::SecondFactor { .. } => panic!("expected a session"),
    }
}

async fn principal_of(env: &TestEnv, session: &NewSession) -> Principal {
    env.session_ctx(session).await.expect("ctx").principal
}

/// An installation under `profile` with the administrator `admin`, the operator `olga` and
/// the viewer `vera`, each logged in with a password.
async fn fixture(profile: Profile) -> Fixture {
    let (env, admin_session) = TestEnv::installed(profile).await;
    let password = password_for(profile);
    add_user(&env, "olga", RoleName::Operator, password).await;
    add_user(&env, "vera", RoleName::Viewer, password).await;
    let operator_session = login(&env, "olga", password).await;
    let viewer_session = login(&env, "vera", password).await;
    let admin = principal_of(&env, &admin_session).await;
    let operator = principal_of(&env, &operator_session).await;
    let viewer = principal_of(&env, &viewer_session).await;
    Fixture {
        authorizer: env.service.authorizer(),
        env,
        admin_session,
        operator_session,
        viewer_session,
        admin,
        operator,
        viewer,
    }
}

/// The same user and session with another strength: the authorizer decides on the principal
/// alone, so every strength can be tried without a login ceremony for each.
fn with_strength(principal: &Principal, strength: AuthStrength) -> Principal {
    match principal {
        Principal::User { id, session, .. } => Principal::User {
            id: *id,
            session: *session,
            strength,
        },
        other => other.clone(),
    }
}

fn user_id(principal: &Principal) -> UserId {
    principal.user().expect("a principal with a user")
}

fn decide(
    f: &Fixture,
    principal: &Principal,
    action: Action,
    kind: ObjectKind,
) -> Result<(), Denied> {
    f.authorizer
        .check(principal, action, &ObjectRef::singleton(kind))
}

fn reason(result: Result<(), Denied>) -> Option<DenyReason> {
    result.err().map(|denied| denied.reason)
}

/// Asserts a decision and that `scope` agrees with it. A refusal for a missing permission
/// names the action and the object.
fn assert_decision(
    f: &Fixture,
    who: &str,
    principal: &Principal,
    action: Action,
    kind: ObjectKind,
    allowed: bool,
) {
    let object = ObjectRef::singleton(kind);
    let result = f.authorizer.check(principal, action, &object);
    let scope = f.authorizer.scope(principal, action, kind);
    if allowed {
        assert!(result.is_ok(), "{who} {action:?} {kind}: {result:?}");
        assert_eq!(scope, ScopeFilter::All, "{who} {action:?} {kind}");
    } else {
        let denied = result.expect_err(&format!("{who} {action:?} {kind} must be refused"));
        assert_eq!(
            denied.reason,
            DenyReason::MissingPermission,
            "{who} {action:?} {kind}"
        );
        assert_eq!(denied.action, action);
        assert_eq!(denied.object, object);
        assert_eq!(scope, ScopeFilter::Nothing, "{who} {action:?} {kind}");
    }
}

/// The weakest strength the profile asks of a role (TGL-02, TGL-03), with an empty vault.
fn required(profile: Profile, role: RoleName) -> AuthStrength {
    match (profile, role) {
        (Profile::Hardened, RoleName::Admin) => AuthStrength::Passkey,
        (Profile::Standard, RoleName::Admin) | (Profile::Hardened, _) => AuthStrength::PasswordTotp,
        (Profile::Home | Profile::Lab, _)
        | (Profile::Standard, RoleName::Operator | RoleName::Viewer) => AuthStrength::Pin,
    }
}

async fn token_principal(f: &Fixture, session: &NewSession) -> Principal {
    let ctx = f.env.session_ctx(session).await.expect("ctx");
    let created = f
        .env
        .service
        .create_token(
            &ctx,
            &TokenCreate {
                name: "matrix".to_owned(),
                expires_in_days: None,
            },
        )
        .await
        .expect("a token");
    f.env
        .ctx_for(&Credentials::Bearer(created.token.expose().to_owned()))
        .await
        .expect("a token context")
        .principal
}

async fn set_disabled(f: &Fixture, id: UserId, disabled: bool) {
    let admin = f.env.session_ctx(&f.admin_session).await.expect("ctx");
    f.env
        .service
        .update_user(
            &admin,
            id,
            &UserUpdate {
                disabled: Some(disabled),
                ..UserUpdate::default()
            },
            None,
        )
        .await
        .expect("the account is updated");
}

async fn put_operator_secret(f: &Fixture) -> tenko_core::secret::SecretRef {
    f.env
        .vault
        .put_operator(
            &f.env.public_ctx(),
            SecretSpec::new(SecretPurpose::from_static("connect.test")),
            SecretBytes::from(b"fake".to_vec()),
        )
        .await
        .expect("an operator secret")
}

// ---------------------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------------------

#[test]
fn the_permission_table_covers_every_object_kind_once() {
    assert_eq!(TABLE.len(), ObjectKind::ALL.len());
    for &kind in ObjectKind::ALL {
        let rows = TABLE.iter().filter(|row| row.kind == kind).count();
        assert_eq!(rows, 1, "{kind} must have exactly one row");
    }
    for row in &TABLE {
        assert!(
            row.operator.chars().all(|c| "RCUDXA".contains(c)),
            "{}",
            row.kind
        );
    }
}

#[tokio::test]
async fn roles_follow_the_permission_table() {
    let f = fixture(Profile::Home).await;
    // The strongest session isolates the role rules from the strength rules.
    let admin = with_strength(&f.admin, AuthStrength::HardwareKey);
    let operator = with_strength(&f.operator, AuthStrength::HardwareKey);
    let viewer = with_strength(&f.viewer, AuthStrength::HardwareKey);
    for row in &TABLE {
        for action in ACTIONS {
            assert_decision(&f, "admin", &admin, action, row.kind, true);
            let operator_allowed =
                letter(action).is_some_and(|letter| row.operator.contains(letter));
            assert_decision(
                &f,
                "operator",
                &operator,
                action,
                row.kind,
                operator_allowed,
            );
            let viewer_allowed = action == Action::Read && row.viewer_reads;
            assert_decision(&f, "viewer", &viewer, action, row.kind, viewer_allowed);
        }
    }
}

#[tokio::test]
async fn nobody_but_administrators_administers_or_reveals() {
    let f = fixture(Profile::Home).await;
    for strength in STRENGTHS {
        for &kind in ObjectKind::ALL {
            for action in [Action::Administer, Action::Reveal] {
                for (who, base) in [("operator", &f.operator), ("viewer", &f.viewer)] {
                    let principal = with_strength(base, strength);
                    assert_decision(&f, who, &principal, action, kind, false);
                }
            }
        }
    }
}

#[tokio::test]
async fn operators_may_read_users_and_settings_but_viewers_may_not() {
    let f = fixture(Profile::Home).await;
    for kind in [ObjectKind::User, ObjectKind::Settings] {
        assert_decision(&f, "operator", &f.operator, Action::Read, kind, true);
        assert_decision(&f, "viewer", &f.viewer, Action::Read, kind, false);
        for action in [
            Action::Create,
            Action::Update,
            Action::Delete,
            Action::Administer,
        ] {
            assert_decision(&f, "operator", &f.operator, action, kind, false);
        }
    }
}

// ---------------------------------------------------------------------------------------
// Strength (TGL-02, TGL-03)
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn the_required_strength_follows_the_profile_and_the_role() {
    for profile in Profile::ALL {
        let f = fixture(profile).await;
        let roles = [
            (RoleName::Admin, &f.admin),
            (RoleName::Operator, &f.operator),
            (RoleName::Viewer, &f.viewer),
        ];
        for (role, base) in roles {
            let needed = required(profile, role);
            for strength in STRENGTHS {
                let principal = with_strength(base, strength);
                let result = decide(&f, &principal, Action::Read, ObjectKind::Prefix);
                if strength >= needed {
                    assert!(
                        result.is_ok(),
                        "{profile:?} {role} {strength:?}: {result:?}"
                    );
                } else {
                    assert_eq!(
                        reason(result),
                        Some(DenyReason::StepUpRequired { required: needed }),
                        "{profile:?} {role} {strength:?}"
                    );
                }
            }
        }
        // Administration needs the same strength as everything else of an administrator.
        let weak = with_strength(&f.admin, AuthStrength::Pin);
        let result = decide(&f, &weak, Action::Administer, ObjectKind::User);
        match required(profile, RoleName::Admin) {
            AuthStrength::Pin => assert!(result.is_ok(), "{profile:?}"),
            needed => assert_eq!(
                reason(result),
                Some(DenyReason::StepUpRequired { required: needed }),
                "{profile:?}"
            ),
        }
    }
}

#[tokio::test]
async fn real_password_sessions_meet_or_miss_the_profile() {
    let standard = fixture(Profile::Standard).await;
    assert_eq!(standard.admin.strength(), Some(AuthStrength::Password));
    assert_eq!(
        reason(decide(
            &standard,
            &standard.admin,
            Action::Read,
            ObjectKind::Prefix
        )),
        Some(DenyReason::StepUpRequired {
            required: AuthStrength::PasswordTotp
        })
    );
    assert!(
        decide(
            &standard,
            &standard.viewer,
            Action::Read,
            ObjectKind::Prefix
        )
        .is_ok()
    );
    assert!(
        decide(
            &standard,
            &standard.operator,
            Action::Update,
            ObjectKind::Prefix
        )
        .is_ok()
    );

    let hardened = fixture(Profile::Hardened).await;
    assert_eq!(
        reason(decide(
            &hardened,
            &hardened.admin,
            Action::Read,
            ObjectKind::Prefix
        )),
        Some(DenyReason::StepUpRequired {
            required: AuthStrength::Passkey
        })
    );
    assert_eq!(
        reason(decide(
            &hardened,
            &hardened.viewer,
            Action::Read,
            ObjectKind::Prefix
        )),
        Some(DenyReason::StepUpRequired {
            required: AuthStrength::PasswordTotp
        })
    );

    let home = fixture(Profile::Home).await;
    assert_eq!(home.admin.strength(), Some(AuthStrength::Pin));
    for principal in [&home.admin, &home.operator, &home.viewer] {
        assert!(decide(&home, principal, Action::Read, ObjectKind::Prefix).is_ok());
    }
}

#[tokio::test]
async fn a_passkey_satisfies_a_two_factor_requirement() {
    let f = fixture(Profile::Standard).await;
    for strength in [AuthStrength::Passkey, AuthStrength::HardwareKey] {
        let admin = with_strength(&f.admin, strength);
        assert!(decide(&f, &admin, Action::Administer, ObjectKind::User).is_ok());
    }
}

// ---------------------------------------------------------------------------------------
// IAM-07: the PIN coupling rule
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn an_operator_secret_ends_pin_only_administration_in_home_and_lab() {
    for profile in [Profile::Home, Profile::Lab] {
        let f = fixture(profile).await;
        let pin_admin = with_strength(&f.admin, AuthStrength::Pin);
        assert!(
            decide(&f, &pin_admin, Action::Administer, ObjectKind::User).is_ok(),
            "{profile:?}: allowed while the vault holds no operator secret"
        );

        // A system secret (a TOTP seed, a TLS key) does not count (Q3).
        f.env
            .vault
            .put_system(
                &f.env.public_ctx(),
                SecretSpec::new(SecretPurpose::from_static("auth.test")),
                SecretBytes::from(b"fake".to_vec()),
            )
            .await
            .expect("a system secret");
        assert!(decide(&f, &pin_admin, Action::Administer, ObjectKind::User).is_ok());

        let secret = put_operator_secret(&f).await;
        assert_eq!(
            reason(decide(&f, &pin_admin, Action::Read, ObjectKind::Prefix)),
            Some(DenyReason::StepUpRequired {
                required: AuthStrength::Password
            }),
            "{profile:?}"
        );
        // The accounts that cannot reach the vault are unaffected.
        assert!(decide(&f, &f.operator, Action::Update, ObjectKind::Prefix).is_ok());
        assert!(decide(&f, &f.viewer, Action::Read, ObjectKind::Prefix).is_ok());
        // A password (not a PIN) is enough for the administrator.
        let password_admin = with_strength(&f.admin, AuthStrength::Password);
        assert!(decide(&f, &password_admin, Action::Administer, ObjectKind::Secret).is_ok());

        // The authorizer follows the vault: without the secret the PIN works again.
        f.env
            .vault
            .delete(&f.env.public_ctx(), secret)
            .await
            .expect("delete the secret");
        assert!(decide(&f, &pin_admin, Action::Administer, ObjectKind::User).is_ok());
    }
}

#[tokio::test]
async fn the_real_service_refuses_a_pin_administrator_once_the_vault_holds_a_secret() {
    let f = fixture(Profile::Home).await;
    let ctx = f.env.session_ctx(&f.admin_session).await.expect("ctx");
    f.env.service.list_users(&ctx).await.expect("allowed first");
    put_operator_secret(&f).await;
    match f.env.service.list_users(&ctx).await {
        Err(AuthError::Denied(denied)) => assert_eq!(
            denied.reason,
            DenyReason::StepUpRequired {
                required: AuthStrength::Password
            }
        ),
        other => panic!("expected a step-up refusal, got {other:?}"),
    }
    // Operators keep reading users.
    let operator = f.env.session_ctx(&f.operator_session).await.expect("ctx");
    f.env
        .service
        .list_users(&operator)
        .await
        .expect("operators still read");
}

#[tokio::test]
async fn stronger_profiles_keep_their_higher_bar_with_operator_secrets() {
    let standard = fixture(Profile::Standard).await;
    put_operator_secret(&standard).await;
    let password_admin = with_strength(&standard.admin, AuthStrength::Password);
    assert_eq!(
        reason(decide(
            &standard,
            &password_admin,
            Action::Read,
            ObjectKind::Prefix
        )),
        Some(DenyReason::StepUpRequired {
            required: AuthStrength::PasswordTotp
        })
    );
    let two_factor = with_strength(&standard.admin, AuthStrength::PasswordTotp);
    assert!(decide(&standard, &two_factor, Action::Reveal, ObjectKind::Secret).is_ok());
}

#[tokio::test]
async fn revealing_a_secret_never_works_with_a_pin() {
    for profile in Profile::ALL {
        let f = fixture(profile).await;
        let pin = with_strength(&f.admin, AuthStrength::Pin);
        let denied = reason(decide(&f, &pin, Action::Reveal, ObjectKind::Secret));
        assert!(
            matches!(
                denied,
                Some(DenyReason::StepUpRequired { required }) if required >= AuthStrength::Password
            ),
            "{profile:?}: {denied:?}"
        );
        assert_eq!(
            f.authorizer.scope(&pin, Action::Reveal, ObjectKind::Secret),
            ScopeFilter::Nothing
        );
        // A password session reveals where the profile asks no more than that.
        let password = with_strength(&f.admin, AuthStrength::Password);
        let result = decide(&f, &password, Action::Reveal, ObjectKind::Secret);
        if required(profile, RoleName::Admin) <= AuthStrength::Password {
            assert!(result.is_ok(), "{profile:?}: {result:?}");
        } else {
            assert!(matches!(
                reason(result),
                Some(DenyReason::StepUpRequired { .. })
            ));
        }
        let strong = with_strength(&f.admin, AuthStrength::HardwareKey);
        assert!(decide(&f, &strong, Action::Reveal, ObjectKind::Secret).is_ok());
    }
}

// ---------------------------------------------------------------------------------------
// Tokens, disabled accounts, system and node principals
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn token_principals_never_administer_or_reveal() {
    let f = fixture(Profile::Home).await;
    let admin_token = token_principal(&f, &f.admin_session).await;
    let operator_token = token_principal(&f, &f.operator_session).await;
    assert!(matches!(admin_token, Principal::Token { .. }));
    for (who, token) in [
        ("admin token", &admin_token),
        ("operator token", &operator_token),
    ] {
        for &kind in ObjectKind::ALL {
            for action in [Action::Administer, Action::Reveal] {
                assert_decision(&f, who, token, action, kind, false);
            }
        }
    }
    // Changing users, settings, tokens, sessions, secrets or the system needs a session.
    for kind in [
        ObjectKind::User,
        ObjectKind::Settings,
        ObjectKind::System,
        ObjectKind::ApiToken,
        ObjectKind::Session,
        ObjectKind::Secret,
    ] {
        for action in [Action::Create, Action::Update, Action::Delete] {
            assert_decision(&f, "admin token", &admin_token, action, kind, false);
        }
    }
    // An administrator's token still reads and works with the inventory.
    for (action, kind) in [
        (Action::Read, ObjectKind::User),
        (Action::Read, ObjectKind::Settings),
        (Action::Update, ObjectKind::Prefix),
        (Action::Create, ObjectKind::CustomField),
        (Action::Execute, ObjectKind::Job),
        (Action::Approve, ObjectKind::Proposal),
    ] {
        assert_decision(&f, "admin token", &admin_token, action, kind, true);
    }
    // An operator's token has the operator's grants and no more.
    assert_decision(
        &f,
        "operator token",
        &operator_token,
        Action::Update,
        ObjectKind::Prefix,
        true,
    );
    assert_decision(
        &f,
        "operator token",
        &operator_token,
        Action::Read,
        ObjectKind::Settings,
        true,
    );
    assert_decision(
        &f,
        "operator token",
        &operator_token,
        Action::Create,
        ObjectKind::CustomField,
        false,
    );
}

#[tokio::test]
async fn a_disabled_account_is_refused_as_unauthenticated() {
    let f = fixture(Profile::Home).await;
    let operator_token = token_principal(&f, &f.operator_session).await;
    set_disabled(&f, user_id(&f.operator), true).await;
    for principal in [&f.operator, &operator_token] {
        for action in ACTIONS {
            for kind in [ObjectKind::Prefix, ObjectKind::User, ObjectKind::Settings] {
                assert_eq!(
                    reason(decide(&f, principal, action, kind)),
                    Some(DenyReason::Unauthenticated),
                    "{action:?} {kind}"
                );
                assert_eq!(
                    f.authorizer.scope(principal, action, kind),
                    ScopeFilter::Nothing
                );
            }
        }
    }
    // Other accounts are unaffected, and enabling restores the grants at once.
    assert!(decide(&f, &f.viewer, Action::Read, ObjectKind::Prefix).is_ok());
    set_disabled(&f, user_id(&f.operator), false).await;
    assert!(decide(&f, &f.operator, Action::Update, ObjectKind::Prefix).is_ok());
}

#[tokio::test]
async fn a_deleted_account_is_refused_as_unauthenticated() {
    let f = fixture(Profile::Home).await;
    let admin = f.env.session_ctx(&f.admin_session).await.expect("ctx");
    f.env
        .service
        .delete_user(&admin, user_id(&f.viewer))
        .await
        .expect("delete");
    assert_eq!(
        reason(decide(&f, &f.viewer, Action::Read, ObjectKind::Prefix)),
        Some(DenyReason::Unauthenticated)
    );
    let stranger = Principal::User {
        id: UserId::generate(),
        session: SessionId::generate(),
        strength: AuthStrength::HardwareKey,
    };
    assert_eq!(
        reason(decide(&f, &stranger, Action::Read, ObjectKind::Prefix)),
        Some(DenyReason::Unauthenticated)
    );
}

#[tokio::test]
async fn system_principals_pass_and_node_principals_are_refused() {
    let f = fixture(Profile::Standard).await;
    let systems = [
        Principal::system(SystemComponent::Api),
        Principal::system(SystemComponent::Setup),
        Principal::system(SystemComponent::Jobs),
        Principal::System {
            component: SystemComponent::Auth,
            on_behalf_of: Some(UserId::generate()),
        },
    ];
    let node = Principal::Node { id: NodeId(7) };
    for &kind in ObjectKind::ALL {
        for action in ACTIONS {
            for system in &systems {
                assert_decision(&f, "system", system, action, kind, true);
            }
            assert_decision(&f, "node", &node, action, kind, false);
        }
    }
}

// ---------------------------------------------------------------------------------------
// The index follows the store
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_role_change_takes_effect_with_its_commit() {
    let f = fixture(Profile::Home).await;
    let admin = f.env.session_ctx(&f.admin_session).await.expect("ctx");
    let id = user_id(&f.operator);
    assert_decision(
        &f,
        "operator",
        &f.operator,
        Action::Update,
        ObjectKind::Prefix,
        true,
    );
    f.env
        .service
        .set_user_roles(&admin, id, &[RoleName::Viewer], None)
        .await
        .expect("demote");
    assert_decision(
        &f,
        "demoted",
        &f.operator,
        Action::Update,
        ObjectKind::Prefix,
        false,
    );
    assert_decision(
        &f,
        "demoted",
        &f.operator,
        Action::Read,
        ObjectKind::Prefix,
        true,
    );
    f.env
        .service
        .set_user_roles(&admin, id, &[RoleName::Admin], None)
        .await
        .expect("promote");
    let strong = with_strength(&f.operator, AuthStrength::HardwareKey);
    assert_decision(
        &f,
        "promoted",
        &strong,
        Action::Administer,
        ObjectKind::User,
        true,
    );
}

#[tokio::test]
async fn a_settings_change_takes_effect_with_its_commit() {
    let f = fixture(Profile::Home).await;
    let admin = f.env.session_ctx(&f.admin_session).await.expect("ctx");
    assert!(decide(&f, &f.viewer, Action::Read, ObjectKind::Prefix).is_ok());
    f.env
        .service
        .update_security_settings(
            &admin,
            &SettingsPatch {
                mfa: Some(MfaRequirement::Everyone),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("require two factors for everyone");
    for principal in [&f.admin, &f.operator, &f.viewer] {
        assert_eq!(
            reason(decide(&f, principal, Action::Read, ObjectKind::Prefix)),
            Some(DenyReason::StepUpRequired {
                required: AuthStrength::PasswordTotp
            })
        );
    }
    f.env
        .service
        .update_security_settings(
            &f.env.public_ctx(),
            &SettingsPatch {
                mfa: Some(MfaRequirement::Optional),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("relax again");
    assert!(decide(&f, &f.viewer, Action::Read, ObjectKind::Prefix).is_ok());
}

#[tokio::test]
async fn scope_agrees_with_check_for_every_principal_action_and_kind() {
    let f = fixture(Profile::Standard).await;
    let token = token_principal(&f, &f.operator_session).await;
    let principals = [
        ("admin", f.admin.clone()),
        (
            "admin, two factors",
            with_strength(&f.admin, AuthStrength::PasswordTotp),
        ),
        ("operator", f.operator.clone()),
        ("viewer", f.viewer.clone()),
        ("operator token", token),
        ("system", Principal::system(SystemComponent::Api)),
        ("node", Principal::Node { id: NodeId(1) }),
        (
            "unknown user",
            Principal::User {
                id: UserId::generate(),
                session: SessionId::generate(),
                strength: AuthStrength::HardwareKey,
            },
        ),
    ];
    for (who, principal) in &principals {
        for &kind in ObjectKind::ALL {
            for action in ACTIONS {
                let allowed = decide(&f, principal, action, kind).is_ok();
                let scope = f.authorizer.scope(principal, action, kind);
                let expected = if allowed {
                    ScopeFilter::All
                } else {
                    ScopeFilter::Nothing
                };
                assert_eq!(scope, expected, "{who} {action:?} {kind}");
            }
        }
    }
}

#[tokio::test]
async fn roles_combine_and_the_strictest_requirement_applies() {
    let f = fixture(Profile::Standard).await;
    add_user_with_roles(
        &f.env,
        "mixed",
        &[RoleName::Admin, RoleName::Viewer],
        PASSPHRASE,
    )
    .await;
    add_user_with_roles(
        &f.env,
        "dual",
        &[RoleName::Operator, RoleName::Viewer],
        PASSPHRASE,
    )
    .await;
    let mixed = principal_of(&f.env, &login(&f.env, "mixed", PASSPHRASE).await).await;
    let dual = principal_of(&f.env, &login(&f.env, "dual", PASSPHRASE).await).await;
    // An administrator role among the roles brings the administrators' requirement.
    assert_eq!(
        reason(decide(&f, &mixed, Action::Read, ObjectKind::Prefix)),
        Some(DenyReason::StepUpRequired {
            required: AuthStrength::PasswordTotp
        })
    );
    let two_factors = with_strength(&mixed, AuthStrength::PasswordTotp);
    assert_decision(
        &f,
        "mixed",
        &two_factors,
        Action::Administer,
        ObjectKind::User,
        true,
    );
    // Permissions are the union of the roles.
    assert_decision(&f, "dual", &dual, Action::Update, ObjectKind::Prefix, true);
    assert_decision(&f, "dual", &dual, Action::Read, ObjectKind::Job, true);
    assert_decision(
        &f,
        "dual",
        &dual,
        Action::Administer,
        ObjectKind::User,
        false,
    );
    assert_decision(
        &f,
        "dual",
        &dual,
        Action::Create,
        ObjectKind::CustomField,
        false,
    );
}

#[tokio::test]
async fn a_restarted_service_rebuilds_the_same_authorization_state() {
    let f = fixture(Profile::Home).await;
    let operator_id = user_id(&f.operator);
    let operator_token = token_principal(&f, &f.operator_session).await;
    // A disabled account, a stricter setting and an operator secret all have to survive.
    set_disabled(&f, operator_id, true).await;
    f.env
        .service
        .update_security_settings(
            &f.env.public_ctx(),
            &SettingsPatch {
                passkey_for_admins: Some(true),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("settings");
    put_operator_secret(&f).await;

    let restarted = AuthService::new(
        f.env.store.clone(),
        f.env.vault.clone(),
        AuthConfig::default(),
    )
    .await
    .expect("the service restarts over the same store");
    assert_eq!(restarted.settings(), f.env.service.settings());
    let rebuilt = restarted.authorizer();
    let principals = [
        ("admin", f.admin.clone()),
        (
            "admin, password",
            with_strength(&f.admin, AuthStrength::Password),
        ),
        (
            "admin, passkey",
            with_strength(&f.admin, AuthStrength::Passkey),
        ),
        ("disabled operator", f.operator.clone()),
        ("operator token", operator_token),
        ("viewer", f.viewer.clone()),
        ("system", Principal::system(SystemComponent::Api)),
        ("node", Principal::Node { id: NodeId(3) }),
    ];
    for (who, principal) in &principals {
        for &kind in ObjectKind::ALL {
            for action in ACTIONS {
                let object = ObjectRef::singleton(kind);
                assert_eq!(
                    rebuilt.check(principal, action, &object),
                    f.authorizer.check(principal, action, &object),
                    "{who} {action:?} {kind}"
                );
                assert_eq!(
                    rebuilt.scope(principal, action, kind),
                    f.authorizer.scope(principal, action, kind),
                    "{who} {action:?} {kind}"
                );
            }
        }
    }
    // Sessions live in the store, so a restart does not log anybody out.
    let cookie = Credentials::Session(f.viewer_session.secret.expose().to_owned());
    restarted
        .authenticate_credentials(&cookie, f.env.now())
        .await
        .expect("the viewer's session survives the restart");
    assert!(
        restarted
            .authenticate_credentials(
                &Credentials::Session(f.operator_session.secret.expose().to_owned()),
                f.env.now()
            )
            .await
            .is_err(),
        "the disabled operator stays locked out"
    );
}

#[tokio::test]
async fn step_up_refusals_name_the_required_strength_in_one_form() {
    let f = fixture(Profile::Standard).await;
    let denied = decide(&f, &f.admin, Action::Read, ObjectKind::Prefix)
        .expect_err("a password session is not enough for an administrator");
    let from_the_authorizer = AuthError::Denied(denied).params()["required"].clone();
    let from_the_service = AuthError::StepUpRequired {
        required: "password_totp",
    }
    .params()["required"]
        .clone();
    assert_eq!(from_the_authorizer, from_the_service);
}
