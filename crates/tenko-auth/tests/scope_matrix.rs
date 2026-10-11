//! The scope matrix of IAM-01: role by scope by action by object kind, against the in-memory
//! store and a single-voter Raft store.
//!
//! Users without a global role hold one grant (a viewer or an operator over a VRF, a site
//! with or without its subtree, a prefix with or without its subtree). For every scoped
//! object kind and every action, the authorizer is asked about an object inside the scope,
//! one outside it, one that lies half inside (a host in two prefixes), the kind as a whole
//! ([`anywhere`]) and the nil identifier. The expected answers come from three small tables
//! that do not call the code under test: what each role may do ([`role_allows`]), which
//! objects each scope covers ([`cases`]) and which kinds every scoped principal may read
//! as context ([`CONTEXT_KINDS`]).
//!
//! Anchors come from a fixed in-memory resolver (`tenko-auth` cannot depend on `tenko-ipam`):
//!
//! ```text
//! VRF V1:  P1 192.0.2.0/24 (site S1) > P2 192.0.2.0/25 (site S2, a child of S1)
//! VRF V2:  P3 198.51.100.0/24 (site S3)
//! ```

use std::{collections::HashMap, net::IpAddr, sync::Arc};

use tenko_auth::{
    AuthConfig, AuthService,
    authz::{AUDIT_OBJECT, METRICS_OBJECT, anywhere},
    clock::{Clock, MockClock},
    roles::RoleName,
    service::{GrantCreate, SetupAdmin, SetupRequest, UserCreate, types::SecretString},
    settings::Profile,
    testing::{
        TestEnv,
        env::{ADMIN, ADMIN_PIN, HOST},
    },
};
use tenko_core::{
    Action, Anchors, AuthStrength, Coded, Credentials, Denied, DenyReason, ObjectKind, ObjectRef,
    PrefixId, Principal, RequestCtx, ScopeFilter, ScopeRule, SessionId, SiteId, SystemComponent,
    UserId, VrfId,
};
use tenko_store::{
    AnchorResolver, ReadView, Store, StoreError,
    raft::{RaftStore, RaftStoreConfig},
};
use tenko_vault::{KekRing, MemKek, StoreVault, Vault};
use uuid::Uuid;

// ---------------------------------------------------------------------------------------
// The world: objects and their anchors
// ---------------------------------------------------------------------------------------

const V1: VrfId = VrfId::from_uuid(Uuid::from_u128(0x01));
const V2: VrfId = VrfId::from_uuid(Uuid::from_u128(0x02));
const S1: SiteId = SiteId::from_uuid(Uuid::from_u128(0x11));
const S2: SiteId = SiteId::from_uuid(Uuid::from_u128(0x12));
const S3: SiteId = SiteId::from_uuid(Uuid::from_u128(0x13));
/// 192.0.2.0/24.
const P1: PrefixId = PrefixId::from_uuid(Uuid::from_u128(0x21));
/// 192.0.2.0/25, inside P1.
const P2: PrefixId = PrefixId::from_uuid(Uuid::from_u128(0x22));
/// 198.51.100.0/24, a sibling of P1 in another VRF.
const P3: PrefixId = PrefixId::from_uuid(Uuid::from_u128(0x23));

/// Every kind that scoped grants reach.
const SCOPED_KINDS: [ObjectKind; 13] = [
    ObjectKind::Tenant,
    ObjectKind::Vrf,
    ObjectKind::Site,
    ObjectKind::Vlan,
    ObjectKind::Prefix,
    ObjectKind::Range,
    ObjectKind::Address,
    ObjectKind::Host,
    ObjectKind::Interface,
    ObjectKind::CustomField,
    ObjectKind::Job,
    ObjectKind::Observation,
    ObjectKind::Proposal,
];

/// Kinds no scope reaches, whatever role the grant carries.
const GLOBAL_ONLY_KINDS: [ObjectKind; 9] = [
    ObjectKind::Import,
    ObjectKind::Connector,
    ObjectKind::Node,
    ObjectKind::Secret,
    ObjectKind::Settings,
    ObjectKind::User,
    ObjectKind::System,
    ObjectKind::Session,
    ObjectKind::ApiToken,
];

/// Kinds every scoped principal may read, wherever the object lies.
const CONTEXT_KINDS: [ObjectKind; 4] = [
    ObjectKind::Tenant,
    ObjectKind::Vrf,
    ObjectKind::Site,
    ObjectKind::CustomField,
];

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

/// Where an object of a checked kind lies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    /// In P2 (and so in P1), VRF V1, site S2 (and so below S1).
    InP2,
    /// Directly in P1, VRF V1, site S1.
    InP1,
    /// In P3, VRF V2, site S3.
    Outside,
    /// In two prefix chains, P2 under P1 and P3, and in no VRF or site (a host with two
    /// addresses).
    Straddling,
    /// The kind as a whole.
    Anywhere,
    /// The nil identifier.
    Nil,
}

impl Slot {
    /// The slots that are objects with anchors.
    const OBJECTS: [Slot; 4] = [Slot::InP2, Slot::InP1, Slot::Outside, Slot::Straddling];
    const ALL: [Slot; 6] = [
        Slot::InP2,
        Slot::InP1,
        Slot::Outside,
        Slot::Straddling,
        Slot::Anywhere,
        Slot::Nil,
    ];

    fn index(self) -> usize {
        match self {
            Slot::InP2 => 0,
            Slot::InP1 => 1,
            Slot::Outside => 2,
            Slot::Straddling => 3,
            Slot::Anywhere | Slot::Nil => usize::MAX,
        }
    }

    fn anchors(self, object: ObjectRef) -> Anchors {
        let base = Anchors::of(object);
        match self {
            Slot::InP2 => Anchors {
                vrf: Some(V1),
                sites: vec![S2, S1],
                prefixes: vec![vec![P2, P1]],
                ..base
            },
            Slot::InP1 => Anchors {
                vrf: Some(V1),
                sites: vec![S1],
                prefixes: vec![vec![P1]],
                ..base
            },
            Slot::Outside => Anchors {
                vrf: Some(V2),
                sites: vec![S3],
                prefixes: vec![vec![P3]],
                ..base
            },
            Slot::Straddling => Anchors {
                prefixes: vec![vec![P2, P1], vec![P3]],
                ..base
            },
            Slot::Anywhere | Slot::Nil => base,
        }
    }
}

/// The object of `kind` in `slot`: a fixed identifier per kind and slot.
fn object(kind: ObjectKind, slot: Slot) -> ObjectRef {
    let kind_number = SCOPED_KINDS
        .iter()
        .position(|candidate| *candidate == kind)
        .map_or(0xff, |position| position as u128);
    match slot {
        Slot::Anywhere => anywhere(kind),
        Slot::Nil => ObjectRef::new(kind, Uuid::nil()),
        slot => ObjectRef::new(
            kind,
            Uuid::from_u128(0x1000 + (kind_number << 8) + slot.index() as u128),
        ),
    }
}

/// The resolver of anchors: the scope targets themselves and an object of every scoped
/// kind in every slot, as the prefix tree of IPAM would answer. Conventions of `Anchors`:
/// a prefix chain starts with the prefix itself and lists its ancestors, a site list
/// starts with the object's own site and lists its ancestors.
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
        let nothing = Anchors::default;
        put(
            ObjectRef::from(V1),
            Anchors {
                vrf: Some(V1),
                ..nothing()
            },
        );
        put(
            ObjectRef::from(V2),
            Anchors {
                vrf: Some(V2),
                ..nothing()
            },
        );
        put(
            ObjectRef::from(S1),
            Anchors {
                sites: vec![S1],
                ..nothing()
            },
        );
        put(
            ObjectRef::from(S2),
            Anchors {
                sites: vec![S2, S1],
                ..nothing()
            },
        );
        put(
            ObjectRef::from(S3),
            Anchors {
                sites: vec![S3],
                ..nothing()
            },
        );
        put(
            ObjectRef::from(P1),
            Anchors {
                vrf: Some(V1),
                sites: vec![S1],
                prefixes: vec![vec![P1]],
                ..nothing()
            },
        );
        put(
            ObjectRef::from(P2),
            Anchors {
                vrf: Some(V1),
                sites: vec![S2, S1],
                prefixes: vec![vec![P2, P1]],
                ..nothing()
            },
        );
        put(
            ObjectRef::from(P3),
            Anchors {
                vrf: Some(V2),
                sites: vec![S3],
                prefixes: vec![vec![P3]],
                ..nothing()
            },
        );
        for kind in SCOPED_KINDS {
            for slot in Slot::OBJECTS {
                let thing = object(kind, slot);
                map.insert(thing, slot.anchors(thing));
            }
        }
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
// The expectations
// ---------------------------------------------------------------------------------------

/// What a role may do with an object of a scoped kind: the viewer reads, the operator reads
/// and works with the inventory (`R` read, `C` create, `U` update, `D` delete, `X` execute,
/// `A` approve).
fn role_allows(role: RoleName, action: Action, kind: ObjectKind) -> bool {
    let letters = match role {
        RoleName::Viewer => "R",
        RoleName::Operator => match kind {
            ObjectKind::Tenant
            | ObjectKind::Vrf
            | ObjectKind::Site
            | ObjectKind::Vlan
            | ObjectKind::Range
            | ObjectKind::Interface => "RCUD",
            ObjectKind::Prefix | ObjectKind::Address | ObjectKind::Host => "RCUDX",
            ObjectKind::CustomField | ObjectKind::Observation => "R",
            ObjectKind::Job => "RX",
            ObjectKind::Proposal => "RA",
            _ => "",
        },
        RoleName::Admin | RoleName::Auditor => "",
    };
    let letter = match action {
        Action::Read => 'R',
        Action::Create => 'C',
        Action::Update => 'U',
        Action::Delete => 'D',
        Action::Execute => 'X',
        Action::Approve => 'A',
        Action::Reveal => 'V',
        Action::Administer => 'M',
    };
    letters.contains(letter)
}

/// Whether a rule covers the objects of the four slots, for a read (some anchor) and for a
/// write (every anchor).
#[derive(Debug, Clone, Copy)]
struct Covers {
    read: bool,
    write: bool,
}

const BOTH: Covers = Covers {
    read: true,
    write: true,
};
const NEITHER: Covers = Covers {
    read: false,
    write: false,
};
const READ_ONLY: Covers = Covers {
    read: true,
    write: false,
};

struct Case {
    key: &'static str,
    rule: ScopeRule,
    /// Indexed by [`Slot::index`].
    covers: [Covers; 4],
}

fn cases() -> Vec<Case> {
    let site = |id, subtree| ScopeRule::Site { id, subtree };
    let prefix = |id, subtree| ScopeRule::Prefix { id, subtree };
    vec![
        // The VRF holds P1 and P2 and not P3; the straddling host belongs to no VRF.
        Case {
            key: "vrf",
            rule: ScopeRule::Vrf(V1),
            covers: [BOTH, BOTH, NEITHER, NEITHER],
        },
        // S2 is a child of S1.
        Case {
            key: "site-subtree",
            rule: site(S1, true),
            covers: [BOTH, BOTH, NEITHER, NEITHER],
        },
        Case {
            key: "site-only",
            rule: site(S1, false),
            covers: [NEITHER, BOTH, NEITHER, NEITHER],
        },
        Case {
            key: "child-site-only",
            rule: site(S2, false),
            covers: [BOTH, NEITHER, NEITHER, NEITHER],
        },
        // A read needs one covered chain, a write needs every chain covered.
        Case {
            key: "prefix-subtree",
            rule: prefix(P1, true),
            covers: [BOTH, BOTH, NEITHER, READ_ONLY],
        },
        Case {
            key: "prefix-only",
            rule: prefix(P1, false),
            covers: [NEITHER, BOTH, NEITHER, NEITHER],
        },
        Case {
            key: "child-prefix-only",
            rule: prefix(P2, false),
            covers: [BOTH, NEITHER, NEITHER, READ_ONLY],
        },
    ]
}

/// The three answers of the authorizer in this matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Allowed,
    /// `auth.forbidden`: no role of the principal allows this action on this kind.
    Forbidden,
    /// `auth.out_of_scope`: a role allows it, the object is not covered.
    OutOfScope,
}

impl Answer {
    fn of(result: Result<(), Denied>) -> Answer {
        match result {
            Ok(()) => Answer::Allowed,
            Err(denied) => match denied.reason {
                DenyReason::MissingPermission => {
                    assert_eq!(denied.code(), "auth.forbidden");
                    Answer::Forbidden
                }
                DenyReason::OutOfScope => {
                    assert_eq!(denied.code(), "auth.out_of_scope");
                    Answer::OutOfScope
                }
                other => panic!("an unexpected refusal: {other:?}"),
            },
        }
    }
}

/// The answer for a holder of `role` over `case`.
fn expected(role: RoleName, case: &Case, action: Action, kind: ObjectKind, slot: Slot) -> Answer {
    if !role_allows(role, action, kind) {
        return Answer::Forbidden;
    }
    match slot {
        Slot::Anywhere => Answer::Allowed,
        _ if action == Action::Read && CONTEXT_KINDS.contains(&kind) => Answer::Allowed,
        Slot::Nil => Answer::OutOfScope,
        slot => {
            let covers = case.covers[slot.index()];
            let covered = if action == Action::Read {
                covers.read
            } else {
                covers.write
            };
            if covered {
                Answer::Allowed
            } else {
                Answer::OutOfScope
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// The installation under test
// ---------------------------------------------------------------------------------------

/// An installed service over one of the two stores, with an administrator's context.
struct Rig {
    label: &'static str,
    service: Arc<AuthService>,
    admin: RequestCtx,
    raft: Option<RaftStore>,
}

impl Rig {
    /// The in-memory store through the test environment.
    async fn mem() -> Rig {
        let (env, session) = TestEnv::installed(Profile::Home).await;
        let admin = env.session_ctx(&session).await.expect("the administrator");
        Rig {
            label: "MemStore",
            service: Arc::clone(&env.service),
            admin,
            raft: None,
        }
    }

    /// A single-voter Raft store in a scratch directory (removed when the store is
    /// dropped), with a vault over it and the same first-run setup as the test environment.
    async fn raft() -> Rig {
        let mut config = RaftStoreConfig::new("unused");
        config.fsync_probe_samples = 0;
        let raft = RaftStore::open_temp(config)
            .await
            .expect("the Raft store opens");
        let store: Arc<dyn Store> = Arc::new(raft.clone());
        let ring = KekRing::new(Arc::new(MemKek::generate("matrix-1")));
        let vault: Arc<dyn Vault> = Arc::new(
            StoreVault::open(Arc::clone(&store), ring)
                .await
                .expect("the vault opens"),
        );
        let service = AuthService::new(store, vault, AuthConfig::default())
            .await
            .expect("the service starts");
        let now = MockClock::fixed().now();
        let client = IpAddr::from([192, 0, 2, 10]);
        let public = RequestCtx::system(SystemComponent::Api)
            .at(now)
            .with_source_ip(client);
        let token = service
            .prepare_setup()
            .await
            .expect("the setup state")
            .expect("setup is open");
        let session = service
            .complete_setup(
                &public,
                Some("test-agent"),
                &SetupRequest {
                    setup_token: SecretString::new(token.expose()),
                    profile: Profile::Home,
                    admin: SetupAdmin {
                        name: ADMIN.to_owned(),
                        display_name: None,
                        password: SecretString::new(ADMIN_PIN),
                    },
                    host_name: HOST.to_owned(),
                    language: "en".to_owned(),
                },
            )
            .await
            .expect("setup completes");
        let authenticated = service
            .authenticate_credentials(
                &Credentials::Session(session.secret.expose().to_owned()),
                now,
            )
            .await
            .expect("the administrator's session");
        let admin = RequestCtx::new(authenticated.principal)
            .at(now)
            .with_source_ip(client);
        Rig {
            label: "RaftStore",
            service,
            admin,
            raft: Some(raft),
        }
    }

    /// Wires the anchors of the fixed world.
    fn wire(&self) {
        self.service
            .set_anchor_resolver(Arc::new(FixedAnchors::new()));
    }

    /// A person without a global role.
    async fn user(&self, name: &str) -> UserId {
        self.service
            .create_user(
                &self.admin,
                &UserCreate {
                    name: name.to_owned(),
                    display_name: None,
                    password: None,
                    roles: Vec::new(),
                    language: None,
                },
            )
            .await
            .expect("the user is created")
            .id
    }

    /// A user with one grant, and the principal of its session (any strength passes: the
    /// matrix is about reach, not about step-up).
    async fn holder(&self, name: &str, role: RoleName, over: &ScopeRule) -> Principal {
        let id = self.user(name).await;
        self.grant(id, role, over).await;
        principal(id)
    }

    async fn grant(
        &self,
        subject: UserId,
        role: RoleName,
        over: &ScopeRule,
    ) -> tenko_auth::model::GrantId {
        self.service
            .create_grant(
                &self.admin,
                &GrantCreate {
                    subject,
                    role,
                    scope: over.clone(),
                    delegable: false,
                },
            )
            .await
            .expect("the grant is created")
            .id
    }

    async fn finish(self) {
        if let Some(raft) = self.raft {
            raft.shutdown().await.expect("the store shuts down");
        }
    }
}

fn principal(id: UserId) -> Principal {
    Principal::User {
        id,
        session: SessionId::generate(),
        strength: AuthStrength::HardwareKey,
    }
}

// ---------------------------------------------------------------------------------------
// The matrix
// ---------------------------------------------------------------------------------------

/// Role by scope by action by kind by object, and the `scope` answer for each role, scope,
/// action and kind.
async fn run_matrix(rig: &Rig) {
    rig.wire();
    let authorizer = rig.service.authorizer();
    let mut failures: Vec<String> = Vec::new();
    let mut checks = 0_usize;
    for case in cases() {
        for role in [RoleName::Viewer, RoleName::Operator] {
            let who = format!("{} {role}", case.key);
            let holder = rig
                .holder(&format!("{}-{role}", case.key), role, &case.rule)
                .await;
            for kind in SCOPED_KINDS {
                for action in ACTIONS {
                    for slot in Slot::ALL {
                        let thing = object(kind, slot);
                        let want = expected(role, &case, action, kind, slot);
                        let got = Answer::of(authorizer.check(&holder, action, &thing));
                        checks += 1;
                        if got != want {
                            failures.push(format!(
                                "{who} {action:?} {kind} {slot:?}: expected {want:?}, got {got:?}"
                            ));
                        }
                    }
                    let want = if role_allows(role, action, kind) {
                        ScopeFilter::Only(vec![case.rule.clone()])
                    } else {
                        ScopeFilter::Nothing
                    };
                    let got = authorizer.scope(&holder, action, kind);
                    if got != want {
                        failures.push(format!(
                            "{who} {action:?} {kind} scope: expected {want:?}, got {got:?}"
                        ));
                    }
                }
            }
        }
    }
    assert_eq!(
        failures,
        Vec::<String>::new(),
        "{}: {} of {checks} checks differ",
        rig.label,
        failures.len()
    );
    // Seven scopes, two roles, thirteen kinds, eight actions, six objects.
    assert_eq!(checks, 7 * 2 * 13 * 8 * 6);
}

/// Imports, connectors, nodes, secrets, settings, users, the system, sessions and tokens
/// are global only: no scoped holder reaches them, not even the special objects of the
/// metrics endpoint and the audit log.
async fn run_global_only(rig: &Rig) {
    rig.wire();
    let authorizer = rig.service.authorizer();
    let mut failures: Vec<String> = Vec::new();
    for case in cases() {
        for role in [RoleName::Viewer, RoleName::Operator] {
            let holder = rig
                .holder(&format!("{}-{role}", case.key), role, &case.rule)
                .await;
            for kind in GLOBAL_ONLY_KINDS {
                for action in ACTIONS {
                    let mut objects = vec![
                        ObjectRef::singleton(kind),
                        anywhere(kind),
                        ObjectRef::new(kind, Uuid::from_u128(0x77)),
                    ];
                    if kind == ObjectKind::System {
                        objects.extend([METRICS_OBJECT, AUDIT_OBJECT]);
                    }
                    for thing in objects {
                        let got = Answer::of(authorizer.check(&holder, action, &thing));
                        if got != Answer::Forbidden {
                            failures.push(format!(
                                "{} {role} {action:?} {thing}: expected Forbidden, got {got:?}",
                                case.key
                            ));
                        }
                    }
                    let scope = authorizer.scope(&holder, action, kind);
                    if scope != ScopeFilter::Nothing {
                        failures.push(format!(
                            "{} {role} {action:?} {kind} scope: expected Nothing, got {scope:?}",
                            case.key
                        ));
                    }
                }
            }
        }
    }
    assert_eq!(failures, Vec::<String>::new(), "{}", rig.label);
}

/// A user without any grant is refused everywhere, and an administrator reaches everything.
async fn run_no_grant_and_admin(rig: &Rig) {
    rig.wire();
    let authorizer = rig.service.authorizer();
    let nobody = principal(rig.user("nobody").await);
    // The strongest session: revealing a secret asks an administrator for more than a PIN.
    let admin = principal(rig.admin.principal.user().expect("the administrator"));
    for &kind in ObjectKind::ALL {
        for action in ACTIONS {
            for slot in Slot::ALL {
                let thing = if SCOPED_KINDS.contains(&kind) {
                    object(kind, slot)
                } else {
                    ObjectRef::singleton(kind)
                };
                assert_eq!(
                    Answer::of(authorizer.check(&nobody, action, &thing)),
                    Answer::Forbidden,
                    "{}: no grant, {action:?} {thing}",
                    rig.label
                );
                assert_eq!(
                    authorizer.check(&admin, action, &thing),
                    Ok(()),
                    "{}: admin {action:?} {thing}",
                    rig.label
                );
            }
            assert_eq!(
                authorizer.scope(&nobody, action, kind),
                ScopeFilter::Nothing
            );
            assert_eq!(authorizer.scope(&admin, action, kind), ScopeFilter::All);
        }
    }
}

/// The reach of several grants adds up, a read needs one anchor and a write all of them, and
/// revoking a grant takes its reach away with the commit.
async fn run_union_and_revocation(rig: &Rig) {
    rig.wire();
    let authorizer = rig.service.authorizer();
    let id = rig.user("dual").await;
    let me = principal(id);
    let by_vrf = rig.grant(id, RoleName::Viewer, &ScopeRule::Vrf(V1)).await;
    let p3_only = ScopeRule::Prefix {
        id: P3,
        subtree: true,
    };
    rig.grant(id, RoleName::Operator, &p3_only).await;

    let answer =
        |action, slot| Answer::of(authorizer.check(&me, action, &object(ObjectKind::Host, slot)));
    // Reads: the viewer grant covers V1, the operator grant covers P3.
    assert_eq!(answer(Action::Read, Slot::InP2), Answer::Allowed);
    assert_eq!(answer(Action::Read, Slot::Outside), Answer::Allowed);
    assert_eq!(answer(Action::Read, Slot::Straddling), Answer::Allowed);
    // Writes: only the operator grant writes, and only over P3.
    assert_eq!(answer(Action::Update, Slot::Outside), Answer::Allowed);
    assert_eq!(answer(Action::Update, Slot::InP2), Answer::OutOfScope);
    assert_eq!(
        answer(Action::Update, Slot::Straddling),
        Answer::OutOfScope,
        "one of the two prefixes of the host is outside the operator's scope"
    );
    // The scope of a read lists both rules, the scope of a write only the operator's.
    match authorizer.scope(&me, Action::Read, ObjectKind::Host) {
        ScopeFilter::Only(rules) => {
            assert_eq!(rules.len(), 2, "{rules:?}");
            assert!(rules.contains(&ScopeRule::Vrf(V1)) && rules.contains(&p3_only));
        }
        other => panic!("{}: expected two rules, got {other:?}", rig.label),
    }
    assert_eq!(
        authorizer.scope(&me, Action::Update, ObjectKind::Host),
        ScopeFilter::Only(vec![p3_only.clone()])
    );

    // Revoking the viewer grant removes the reads it gave.
    let revoked = rig
        .service
        .revoke_grant(&rig.admin, by_vrf)
        .await
        .expect("the grant is revoked");
    assert_eq!(revoked.revoked, [by_vrf]);
    assert_eq!(answer(Action::Read, Slot::InP2), Answer::OutOfScope);
    assert_eq!(answer(Action::Read, Slot::Outside), Answer::Allowed);
}

// ---------------------------------------------------------------------------------------
// Both stores
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn the_scope_matrix_holds_on_the_in_memory_store() {
    let rig = Rig::mem().await;
    run_matrix(&rig).await;
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_scope_matrix_holds_on_the_raft_store() {
    let rig = Rig::raft().await;
    run_matrix(&rig).await;
    rig.finish().await;
}

#[tokio::test]
async fn global_only_kinds_are_refused_to_every_scoped_holder_in_memory() {
    let rig = Rig::mem().await;
    run_global_only(&rig).await;
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_only_kinds_are_refused_to_every_scoped_holder_on_raft() {
    let rig = Rig::raft().await;
    run_global_only(&rig).await;
    rig.finish().await;
}

#[tokio::test]
async fn a_user_without_grants_reaches_nothing_and_an_administrator_everything_in_memory() {
    let rig = Rig::mem().await;
    run_no_grant_and_admin(&rig).await;
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_user_without_grants_reaches_nothing_and_an_administrator_everything_on_raft() {
    let rig = Rig::raft().await;
    run_no_grant_and_admin(&rig).await;
    rig.finish().await;
}

#[tokio::test]
async fn grants_add_up_and_a_revocation_takes_effect_at_once_in_memory() {
    let rig = Rig::mem().await;
    run_union_and_revocation(&rig).await;
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grants_add_up_and_a_revocation_takes_effect_at_once_on_raft() {
    let rig = Rig::raft().await;
    run_union_and_revocation(&rig).await;
    rig.finish().await;
}

// ---------------------------------------------------------------------------------------
// The tables themselves
// ---------------------------------------------------------------------------------------

#[test]
fn the_kind_tables_cover_every_object_kind_once() {
    for &kind in ObjectKind::ALL {
        let scoped = SCOPED_KINDS.contains(&kind);
        let global = GLOBAL_ONLY_KINDS.contains(&kind);
        assert!(scoped ^ global, "{kind} belongs to exactly one table");
    }
    for kind in CONTEXT_KINDS {
        assert!(SCOPED_KINDS.contains(&kind), "{kind}");
    }
}

#[test]
fn the_fixed_anchors_follow_the_documented_conventions() {
    let anchors = FixedAnchors::new().0;
    let p2 = &anchors[&ObjectRef::from(P2)];
    assert_eq!(p2.prefixes, vec![vec![P2, P1]], "most specific first");
    assert_eq!(p2.sites, [S2, S1], "own site first, then ancestors");
    let host = &anchors[&object(ObjectKind::Host, Slot::Straddling)];
    assert_eq!(host.prefixes.len(), 2, "one chain per prefix of the host");
}
