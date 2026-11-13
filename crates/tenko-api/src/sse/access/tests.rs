//! An open stream ends with the access it was opened with: for every kind of credential a
//! stream can be opened with and every kind of end, the stream delivers no event after the
//! end, sends a final `end` event and closes, and a new stream with the credential is refused
//! as any request is. The installation is wired as the server wires it: the authentication
//! service, the scoped event filter and the journal feeder of the hub.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Extension, Router,
    body::{Body, BodyDataStream},
    http::{Request, header},
};
use futures::{StreamExt as _, future::BoxFuture};
use serde_json::{Value, json};
use tenko_auth::{
    AuthConfig, AuthError, AuthService,
    model::{SCOPED_TOKENS, SESSIONS, TOKENS, USERS},
    secret::hash_secret,
    settings::Profile,
    testing::TestEnv,
};
use tenko_core::{
    Principal, Revision, SystemComponent, TableName, Timestamp, UserId, testing::WAIT_LIMIT,
};
use tenko_ipam::{IpamService, scope::ScopeIndex};
use tenko_store::{ReadConsistency, ReadViewExt, Store, WriteBatch};
use tokio::sync::watch;
use tower::ServiceExt as _;

use super::Held;
use crate::{
    API_BASE,
    dto::events::TopicSet,
    routes::auth::testkit::{Credential::*, Harness, Reply},
    sse::{EventHub, EventRoutes, SseConfig, event_stream, filter::ScopedEvents},
};

const PIN: &str = "739158";
const NEW_PIN: &str = "720459";

/// The kinds of credential a stream can be opened with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A person's browser session (the cookie).
    Session,
    /// A person's personal token.
    Personal,
    /// A person's scoped token.
    Scoped,
    /// A service account's (scoped) token.
    Service,
}

impl Kind {
    const ALL: [Self; 4] = [Self::Session, Self::Personal, Self::Scoped, Self::Service];
}

/// The kinds of end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    /// The person changes the password (from another session).
    PasswordChange,
    /// An administrator sets a new password.
    PasswordReset,
    /// An administrator signs the person out everywhere: sessions end, tokens stay.
    SignOutEverywhere,
    /// The one session signs out, or the one token is revoked.
    SignOut,
    /// An administrator disables the account.
    Disable,
    /// An administrator deletes the account.
    Delete,
    /// The session or token reaches its end by time.
    Expiry,
    /// A role or grant change takes away the read of the stream's topic.
    Permission,
}

/// A credential and what is needed to end it.
struct Holder {
    kind: Kind,
    user: String,
    /// The session cookie or bearer token the stream is opened with.
    secret: String,
    /// The token's id.
    token: Option<String>,
    /// The scoped grant of a service account.
    grant: Option<String>,
    /// Another session of the person, from which they act on their own account.
    own: Option<String>,
}

impl Holder {
    fn credential(&self) -> crate::routes::auth::testkit::Credential<'_> {
        match self.kind {
            Kind::Session => Cookie(&self.secret),
            _ => Bearer(&self.secret),
        }
    }
}

/// The installation: an administrator and one prefix whose changes are the probe events.
struct Lab {
    harness: Harness,
    admin: String,
    prefix: String,
    touched: AtomicUsize,
    _stop: watch::Sender<bool>,
}

/// The router of an installation over `env`, wired as the server wires it.
fn wired(env: TestEnv, scope: Arc<ScopeIndex>) -> (Harness, watch::Sender<bool>) {
    let store: Arc<dyn Store> = env.store.clone();
    let ipam = IpamService::with_direct_jobs(Arc::clone(&store)).expect("ipam");
    let (stop, stopped) = watch::channel(false);
    let authorizer = env.service.authorizer();
    let harness = Harness::wired(env, move |state| {
        state.events().set_filter(Box::new(ScopedEvents::new(
            authorizer,
            Arc::clone(&scope),
            Arc::clone(&store),
        )));
        state.events().spawn_tasks(Arc::clone(&store), stopped);
        crate::api(state)
            .0
            .layer(Extension(ipam))
            .layer(Extension(scope))
    });
    (harness, stop)
}

impl Lab {
    async fn new() -> Self {
        let env = TestEnv::new().await;
        env.clock.set(Timestamp::now());
        let admin = env
            .setup(Profile::Home)
            .await
            .expect("setup succeeds")
            .secret
            .expose()
            .to_owned();
        let scope = Arc::new(ScopeIndex::new());
        env.store
            .register_index(Arc::clone(&scope) as _)
            .expect("register the anchors index");
        env.service.set_anchor_resolver(Arc::clone(&scope) as _);
        let (harness, stop) = wired(env, scope);
        let created = harness
            .call(
                "POST",
                "/prefixes",
                Cookie(&admin),
                Some(&json!({ "cidr": "192.0.2.0/24" })),
            )
            .await;
        created.assert_status(201);
        let prefix = created.body["item"]["id"]
            .as_str()
            .expect("an id")
            .to_owned();
        Self {
            harness,
            admin,
            prefix,
            touched: AtomicUsize::new(0),
            _stop: stop,
        }
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        credential: crate::routes::auth::testkit::Credential<'_>,
        body: Option<&Value>,
    ) -> Reply {
        self.harness.call(method, path, credential, body).await
    }

    /// Changes the prefix as the administrator: an `ipam` event for every reader.
    async fn touch(&self) {
        let n = self.touched.fetch_add(1, Ordering::SeqCst);
        self.call(
            "PATCH",
            &format!("/prefixes/{}", self.prefix),
            Cookie(&self.admin),
            Some(&json!({ "description": format!("touched {n}") })),
        )
        .await
        .assert_status(200);
    }

    /// A credential of `kind` whose holder reads IPAM, for an account named `name`.
    async fn holder(&self, kind: Kind, name: &str) -> Holder {
        if kind == Kind::Service {
            let created = self
                .call(
                    "POST",
                    "/access/service-accounts",
                    Cookie(&self.admin),
                    Some(&json!({ "name": name, "display_name": name })),
                )
                .await;
            created.assert_status(201);
            let user = created.body["id"].as_str().expect("an id").to_owned();
            let scope =
                json!({ "kind": "prefix", "value": { "id": self.prefix, "subtree": true } });
            let grant = self
                .call(
                    "POST",
                    "/access/grants",
                    Cookie(&self.admin),
                    Some(&json!({ "subject": user, "role": "viewer", "scope": scope, "delegable": false })),
                )
                .await;
            grant.assert_status(201);
            let token = self
                .call(
                    "POST",
                    &format!("/access/service-accounts/{user}/tokens"),
                    Cookie(&self.admin),
                    Some(&json!({ "name": "stream", "grants": [{ "role": "viewer", "scope": scope }] })),
                )
                .await;
            token.assert_status(201);
            return Holder {
                kind,
                user,
                secret: token.body["token"].as_str().expect("a secret").to_owned(),
                token: token.body["info"]["id"].as_str().map(str::to_owned),
                grant: grant.body["id"].as_str().map(str::to_owned),
                own: None,
            };
        }
        let created = self
            .harness
            .create_user(&self.admin, name, PIN, &["viewer"])
            .await;
        let user = created["id"].as_str().expect("an id").to_owned();
        let session = self.harness.login(name, PIN).await;
        let own = self.harness.login(name, PIN).await;
        let (secret, token) = if kind == Kind::Session {
            (session, None)
        } else {
            let mut body = json!({ "name": "stream" });
            if kind == Kind::Scoped {
                body["grants"] = json!([{ "role": "viewer" }]);
            }
            let token = self
                .call("POST", "/auth/tokens", Cookie(&own), Some(&body))
                .await;
            token.assert_status(201);
            (
                token.body["token"].as_str().expect("a secret").to_owned(),
                token.body["info"]["id"].as_str().map(str::to_owned),
            )
        };
        Holder {
            kind,
            user,
            secret,
            token,
            grant: None,
            own: Some(own),
        }
    }

    /// Opens the stream of `holder` on the `ipam` topic: the stream, or the refusal.
    async fn open(&self, holder: &Holder) -> Result<Events, Box<Reply>> {
        open_on(&self.harness.router(), holder).await
    }

    /// Ends the access of `holder` the way `end` says.
    async fn end(&self, holder: &Holder, end: End) {
        let user = &holder.user;
        let admin = Cookie(&self.admin);
        let own = holder.own.as_deref().map(Cookie);
        let reply = match end {
            End::PasswordChange => {
                self.call(
                    "POST",
                    "/auth/password",
                    own.expect("a person"),
                    Some(&json!({ "current_password": PIN, "new_password": NEW_PIN })),
                )
                .await
            }
            End::PasswordReset => {
                self.call(
                    "PATCH",
                    &format!("/users/{user}"),
                    admin,
                    Some(&json!({ "password": NEW_PIN })),
                )
                .await
            }
            End::SignOutEverywhere => {
                self.call("DELETE", &format!("/users/{user}/sessions"), admin, None)
                    .await
            }
            End::SignOut => match (holder.kind, &holder.token) {
                (Kind::Session, _) => {
                    self.call("POST", "/auth/logout", holder.credential(), None)
                        .await
                }
                (Kind::Service, Some(token)) => {
                    self.call(
                        "DELETE",
                        &format!("/access/service-accounts/{user}/tokens/{token}"),
                        admin,
                        None,
                    )
                    .await
                }
                (_, Some(token)) => {
                    self.call(
                        "DELETE",
                        &format!("/auth/tokens/{token}"),
                        own.expect("a person"),
                        None,
                    )
                    .await
                }
                (_, None) => unreachable!("a token holder has a token id"),
            },
            End::Disable => {
                self.call(
                    "PATCH",
                    &format!("/users/{user}"),
                    admin,
                    Some(&json!({ "disabled": true })),
                )
                .await
            }
            End::Delete => {
                self.call("DELETE", &format!("/users/{user}"), admin, None)
                    .await
            }
            End::Expiry => {
                expire_soon(&self.harness.env.store, holder).await;
                return;
            }
            End::Permission => match &holder.grant {
                Some(grant) => {
                    self.call("DELETE", &format!("/access/grants/{grant}"), admin, None)
                        .await
                }
                None => {
                    self.call(
                        "PUT",
                        &format!("/users/{user}/roles"),
                        admin,
                        Some(&json!({ "roles": [] })),
                    )
                    .await
                }
            },
        };
        assert!(
            reply.status.is_success(),
            "{end:?} of {:?}: {} {}",
            holder.kind,
            reply.status,
            reply.body
        );
    }

    /// For every kind of credential `end` applies to: the stream is live before the end; after
    /// it, it delivers no further event, ends with `reason` and closes; a new stream is
    /// refused with `refusal` (`None`: it opens, with what the credential may read now).
    async fn ends_streams(&self, end: End, kinds: &[Kind], reason: &str, refusal: Option<&str>) {
        for (n, kind) in kinds.iter().enumerate() {
            let holder = self.holder(*kind, &format!("holder-{n}")).await;
            let mut events = self.open(&holder).await.expect("the stream opens");
            self.touch().await;
            events.read_until(|text| text.contains("event: ipam")).await;
            assert!(
                events.text.contains("event: ipam") && !events.closed,
                "{kind:?}: the stream is live before the end: {}",
                events.text
            );
            let before = events.text.len();
            self.end(&holder, end).await;
            // A change after the end: an event no stream of the ended credential may carry.
            if end != End::Expiry {
                self.touch().await;
            }
            events.read_until(|_| false).await;
            let after = &events.text[before..];
            assert!(
                events.closed,
                "{kind:?} after {end:?}: the stream is still open after {WAIT_LIMIT:?}: {after}"
            );
            assert!(
                !after.contains("event: ipam"),
                "{kind:?} after {end:?}: an event after the end: {after}"
            );
            assert!(
                after.ends_with(&format!(
                    "event: end\ndata: {{\"reason\":\"{reason}\"}}\n\n"
                )),
                "{kind:?} after {end:?}: the last event says why the stream ended: {after}"
            );
            match (self.open(&holder).await, refusal) {
                (Err(reply), Some(code)) => {
                    reply.assert_problem(401, code);
                }
                (Ok(_), None) => {}
                (Ok(_), Some(code)) => panic!("{kind:?} after {end:?}: reopened, not {code}"),
                (Err(reply), None) => panic!("{kind:?} after {end:?}: refused: {}", reply.body),
            }
        }
    }
}

/// An open event stream as a client reads it.
struct Events {
    body: BodyDataStream,
    text: String,
    closed: bool,
}

impl Events {
    /// Reads until `done` holds for the text read so far, the stream closes or the wait
    /// limit passes.
    async fn read_until(&mut self, done: impl Fn(&str) -> bool) {
        let deadline = tokio::time::Instant::now() + WAIT_LIMIT;
        while !self.closed && !done(&self.text) {
            match tokio::time::timeout_at(deadline, self.body.next()).await {
                Ok(Some(Ok(chunk))) => self.text.push_str(&String::from_utf8_lossy(&chunk)),
                Ok(Some(Err(error))) => panic!("the stream failed: {error}"),
                Ok(None) => self.closed = true,
                Err(_) => break,
            }
        }
    }
}

/// Opens the `ipam` stream of `holder` on `router`.
async fn open_on(router: &Router, holder: &Holder) -> Result<Events, Box<Reply>> {
    let request = Request::builder().uri(format!("{API_BASE}/events?topics=ipam"));
    let request = match holder.kind {
        Kind::Session => request.header(
            header::COOKIE,
            format!(
                "{}={}",
                tenko_auth::service::session_cookie_name(false),
                holder.secret
            ),
        ),
        _ => request.header(header::AUTHORIZATION, format!("Bearer {}", holder.secret)),
    };
    let response = router
        .clone()
        .oneshot(request.body(Body::empty()).expect("a request"))
        .await
        .expect("a response");
    if !response.status().is_success() {
        return Err(Box::new(Reply::read(response).await));
    }
    let mut events = Events {
        body: response.into_body().into_data_stream(),
        text: String::new(),
        closed: false,
    };
    events.read_until(|text| text.contains(": connected")).await;
    Ok(events)
}

/// Makes the session or token of `holder` expire two seconds from now, as a shorter lifetime
/// would: no later commit tells the stream of the end.
async fn expire_soon(store: &Arc<tenko_store::MemStore>, holder: &Holder) {
    let soon = Timestamp::now()
        .checked_add(Duration::from_secs(2))
        .expect("a time");
    let hash = hash_secret(&holder.secret);
    let view = store.read(ReadConsistency::Local).await.expect("a view");
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), Timestamp::now());
    match holder.kind {
        Kind::Session => {
            let (mut session, _) = view
                .get_typed(&SESSIONS, &hash)
                .expect("a read")
                .expect("the session");
            session.expires_at = soon;
            batch.put_typed(&SESSIONS, &hash, &session).expect("encode");
        }
        Kind::Personal => {
            let (mut token, _) = view
                .get_typed(&TOKENS, &hash)
                .expect("a read")
                .expect("the token");
            token.expires_at = Some(soon);
            batch.put_typed(&TOKENS, &hash, &token).expect("encode");
        }
        Kind::Scoped | Kind::Service => {
            let (mut token, _) = view
                .get_typed(&SCOPED_TOKENS, &hash)
                .expect("a read")
                .expect("the token");
            token.expires_at = Some(soon);
            batch
                .put_typed(&SCOPED_TOKENS, &hash, &token)
                .expect("encode");
        }
    }
    store.propose(batch).await.expect("commit");
}

const PEOPLE: [Kind; 3] = [Kind::Session, Kind::Personal, Kind::Scoped];

#[tokio::test]
async fn a_password_change_ends_the_streams_of_other_sessions_and_tokens() {
    Lab::new()
        .await
        .ends_streams(
            End::PasswordChange,
            &PEOPLE,
            "access_ended",
            Some("auth.unauthenticated"),
        )
        .await;
}

/// The session that changes the password stays, and so does the stream it opened (the tab
/// in which a person changes the password).
#[tokio::test]
async fn the_session_that_changes_the_password_keeps_its_stream() {
    let lab = Lab::new().await;
    let mut holder = lab.holder(Kind::Session, "changer").await;
    holder.secret = holder.own.clone().expect("a person");
    let mut events = lab.open(&holder).await.expect("the stream opens");
    lab.end(&holder, End::PasswordChange).await;
    lab.touch().await;
    events.read_until(|text| text.contains("event: ipam")).await;
    assert!(
        events.text.contains("event: ipam") && !events.text.contains("event: end"),
        "{}",
        events.text
    );
}

#[tokio::test]
async fn a_password_reset_ends_every_stream_of_the_account() {
    Lab::new()
        .await
        .ends_streams(
            End::PasswordReset,
            &PEOPLE,
            "access_ended",
            Some("auth.unauthenticated"),
        )
        .await;
}

#[tokio::test]
async fn signing_out_everywhere_ends_the_streams_of_sessions_and_not_of_tokens() {
    let lab = Lab::new().await;
    lab.ends_streams(
        End::SignOutEverywhere,
        &[Kind::Session],
        "access_ended",
        Some("auth.unauthenticated"),
    )
    .await;
    // Tokens outlive "sign out everywhere" (the settings text promises sessions and known
    // devices): their streams go on.
    for kind in [Kind::Personal, Kind::Scoped] {
        let holder = lab.holder(kind, &format!("keeps-{kind:?}")).await;
        let mut events = lab.open(&holder).await.expect("the stream opens");
        lab.end(&holder, End::SignOutEverywhere).await;
        lab.touch().await;
        events.read_until(|text| text.contains("event: ipam")).await;
        assert!(
            events.text.contains("event: ipam") && !events.text.contains("event: end"),
            "{kind:?}: {}",
            events.text
        );
    }
}

#[tokio::test]
async fn signing_out_or_revoking_ends_the_stream_of_that_session_or_token() {
    Lab::new()
        .await
        .ends_streams(
            End::SignOut,
            &Kind::ALL,
            "access_ended",
            Some("auth.unauthenticated"),
        )
        .await;
}

#[tokio::test]
async fn disabling_the_account_ends_its_streams() {
    Lab::new()
        .await
        .ends_streams(
            End::Disable,
            &Kind::ALL,
            "access_ended",
            Some("auth.unauthenticated"),
        )
        .await;
}

#[tokio::test]
async fn deleting_the_account_ends_its_streams() {
    Lab::new()
        .await
        .ends_streams(
            End::Delete,
            &Kind::ALL,
            "access_ended",
            Some("auth.unauthenticated"),
        )
        .await;
}

#[tokio::test]
async fn a_stream_ends_when_its_session_or_token_expires() {
    Lab::new()
        .await
        .ends_streams(
            End::Expiry,
            &Kind::ALL,
            "access_ended",
            Some("auth.session_expired"),
        )
        .await;
}

/// A session whose account must change its password may make no request but the change: its
/// stream ends too. A token is not refused for it, and its stream goes on.
#[tokio::test]
async fn a_required_password_change_ends_the_streams_of_sessions() {
    let lab = Lab::new().await;
    let session = lab.holder(Kind::Session, "must-change").await;
    let token = lab.holder(Kind::Personal, "must-change-too").await;
    let mut session_events = lab.open(&session).await.expect("the stream opens");
    let mut token_events = lab.open(&token).await.expect("the stream opens");
    for holder in [&session, &token] {
        let id: UserId = serde_json::from_value(json!(holder.user)).expect("an id");
        let store = &lab.harness.env.store;
        let view = store.read(ReadConsistency::Local).await.expect("a view");
        let (mut user, _) = view
            .get_typed(&USERS, &id)
            .expect("a read")
            .expect("the account");
        user.password_change_required = true;
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), Timestamp::now());
        batch.put_typed(&USERS, &id, &user).expect("encode");
        store.propose(batch).await.expect("commit");
    }
    lab.touch().await;
    session_events.read_until(|_| false).await;
    assert!(
        session_events.closed
            && session_events
                .text
                .ends_with("event: end\ndata: {\"reason\":\"access_ended\"}\n\n"),
        "{}",
        session_events.text
    );
    token_events
        .read_until(|text| text.contains("event: ipam"))
        .await;
    assert!(
        !token_events.closed && token_events.text.contains("event: ipam"),
        "{}",
        token_events.text
    );
}

#[tokio::test]
async fn losing_the_read_of_the_topic_ends_the_stream_and_a_new_one_opens() {
    Lab::new()
        .await
        .ends_streams(End::Permission, &Kind::ALL, "access_changed", None)
        .await;
}

/// The controller that serves a stream is not the one through which the end is committed:
/// two controllers with their own authentication service, hub and memory over one store,
/// as two members of a cluster share one replicated journal.
#[tokio::test]
async fn an_end_committed_through_another_controller_ends_the_stream() {
    let lab = Lab::new().await;
    let store = lab.harness.env.store.clone();
    let vault = lab.harness.env.vault.clone();
    let other = AuthService::new(store.clone(), vault, AuthConfig::default())
        .await
        .expect("a second controller's service");
    let scope = Arc::new(ScopeIndex::new());
    store
        .register_index(Arc::clone(&scope) as _)
        .expect("register the anchors index");
    other.set_anchor_resolver(Arc::clone(&scope) as _);
    let env = TestEnv {
        store,
        vault: lab.harness.env.vault.clone(),
        clock: lab.harness.env.clock.clone(),
        service: other,
    };
    let (second, _stop) = wired(env, scope);
    for (n, end) in [End::PasswordReset, End::SignOut, End::Disable]
        .into_iter()
        .enumerate()
    {
        let holder = lab.holder(Kind::Session, &format!("roaming-{n}")).await;
        let mut events = open_on(&second.router(), &holder)
            .await
            .expect("the stream opens on the second controller");
        lab.end(&holder, end).await;
        lab.touch().await;
        events.read_until(|_| false).await;
        assert!(
            events.closed && !events.text.contains("event: ipam"),
            "{end:?}: {}",
            events.text
        );
        assert!(
            events
                .text
                .ends_with("event: end\ndata: {\"reason\":\"access_ended\"}\n\n"),
            "{end:?}: {}",
            events.text
        );
    }
}

/// A credential whose answers a test sets: it holds, until `until` if set, while `ended` is
/// false; its first check can publish a commit to the hub, as an end committed between the
/// request's authentication and the stream's first byte would be.
struct Fake {
    rows: [(TableName, bytes::Bytes); 2],
    ended: AtomicBool,
    until: Option<Timestamp>,
    /// Publish this change set to the hub during the first check.
    during_check: std::sync::Mutex<Option<(EventHub, tenko_store::ChangeSet)>>,
}

impl Held for Fake {
    fn rows(&self) -> &[(TableName, bytes::Bytes)] {
        &self.rows
    }

    fn standing(
        &self,
        _at: Revision,
        _now: Timestamp,
    ) -> BoxFuture<'_, Result<Option<Timestamp>, AuthError>> {
        let publish = self
            .during_check
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let ended = if let Some((hub, changes)) = publish {
            // The end commits while this check reads a view from before it.
            hub.publish_change_set(&changes);
            self.ended.swap(true, Ordering::SeqCst)
        } else {
            self.ended.load(Ordering::SeqCst)
        };
        let until = self.until;
        Box::pin(async move {
            if ended {
                Err(AuthError::Unauthenticated)
            } else {
                Ok(until)
            }
        })
    }
}

fn fake(user: UserId) -> Fake {
    Fake {
        rows: [
            (USERS.name().clone(), USERS.key(&user)),
            (SESSIONS.name().clone(), SESSIONS.key(&b"hash".to_vec())),
        ],
        ended: AtomicBool::new(false),
        until: None,
        during_check: std::sync::Mutex::new(None),
    }
}

fn change_set(revision: u64, changes: Vec<tenko_store::Change>) -> tenko_store::ChangeSet {
    tenko_store::ChangeSet {
        revision: Revision(revision),
        principal: Principal::system(SystemComponent::Auth),
        at: Timestamp::UNIX_EPOCH,
        changes,
    }
}

fn user_row(user: UserId) -> tenko_store::Change {
    tenko_store::Change {
        table: USERS.name().clone(),
        key: USERS.key(&user),
        deleted: false,
    }
}

fn prefix_row() -> tenko_store::Change {
    tenko_store::Change {
        table: TableName::from_static("ipam.prefixes"),
        key: tenko_core::codec::encode_key(&uuid::Uuid::from_u128(7)),
        deleted: false,
    }
}

const END: &[u8] = b"event: end\ndata: {\"reason\":\"access_ended\"}\n\n";

type Chunks = std::pin::Pin<
    Box<dyn futures::Stream<Item = Result<bytes::Bytes, std::convert::Infallible>> + Send>,
>;

/// A stream of `ipam` events over `hub`, opened with `held`, past its hello.
async fn opened(hub: &EventHub, held: Arc<dyn Held>) -> Chunks {
    let store = tenko_store::MemStore::default();
    let mut stream: Chunks = Box::pin(
        event_stream(
            hub,
            &store,
            None,
            TopicSet::parse("ipam").expect("topics"),
            Principal::system(SystemComponent::Api),
            Some(held),
        )
        .await
        .expect("opens"),
    );
    let hello = next(&mut stream).await.expect("hello");
    assert!(hello.starts_with(b"retry: "));
    stream
}

/// The next chunk of a stream within the wait limit; `None` when it closed.
async fn next(stream: &mut Chunks) -> Option<bytes::Bytes> {
    tokio::time::timeout(WAIT_LIMIT, stream.next())
        .await
        .expect("a chunk or the end within the wait limit")
        .map(|chunk| chunk.expect("ok"))
}

#[tokio::test]
async fn a_stream_is_refused_when_its_credential_ended_before_the_subscription() {
    let hub = EventHub::new(SseConfig::default(), EventRoutes::default(), Revision(10));
    let store = tenko_store::MemStore::default();
    let held = fake(UserId::generate());
    held.ended.store(true, Ordering::SeqCst);
    let opened = event_stream(
        &hub,
        &store,
        None,
        TopicSet::ALL,
        Principal::system(SystemComponent::Api),
        Some(Arc::new(held)),
    )
    .await;
    assert!(
        matches!(opened, Err(AuthError::Unauthenticated)),
        "refused as a request is"
    );
}

/// The end commits after the subscription, while the stream's first check still reads the
/// view before it: the stream learns of it through the hub and ends before its first event.
#[tokio::test]
async fn an_end_during_the_first_check_reaches_the_stream() {
    let hub = EventHub::new(SseConfig::default(), EventRoutes::default(), Revision(10));
    let user = UserId::generate();
    let held = fake(user);
    *held
        .during_check
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((
        hub.clone(),
        change_set(11, vec![user_row(user), prefix_row()]),
    ));
    let mut stream = opened(&hub, Arc::new(held)).await;
    assert_eq!(next(&mut stream).await.as_deref(), Some(END));
    assert!(next(&mut stream).await.is_none(), "the stream closes");
}

/// The commit that ends the access also changes an object the stream reads: the stream ends
/// without that commit's event, with and without coalescing.
#[tokio::test]
async fn no_event_of_the_commit_that_ends_the_access_reaches_the_stream() {
    for coalesce in [None, Some(Duration::from_millis(10))] {
        let config = SseConfig {
            coalesce,
            ..SseConfig::default()
        };
        let hub = EventHub::new(config, EventRoutes::default(), Revision(10));
        let user = UserId::generate();
        let held = Arc::new(fake(user));
        let mut stream = opened(&hub, Arc::clone(&held) as Arc<dyn Held>).await;
        held.ended.store(true, Ordering::SeqCst);
        hub.publish_change_set(&change_set(11, vec![user_row(user), prefix_row()]));
        hub.publish_change_set(&change_set(12, vec![prefix_row()]));
        hub.flush();
        assert_eq!(
            next(&mut stream).await.as_deref(),
            Some(END),
            "coalesce {coalesce:?}"
        );
        assert!(next(&mut stream).await.is_none(), "coalesce {coalesce:?}");
    }
}

/// An event waiting for a slow reader when the credential expires is not delivered.
#[tokio::test(start_paused = true)]
async fn nothing_waiting_is_delivered_after_the_expiry() {
    let hub = EventHub::new(SseConfig::default(), EventRoutes::default(), Revision(10));
    let mut held = fake(UserId::generate());
    held.until = Timestamp::now().checked_add(Duration::from_secs(1));
    let held = Arc::new(held);
    let mut stream = opened(&hub, Arc::clone(&held) as Arc<dyn Held>).await;
    hub.publish_change_set(&change_set(11, vec![prefix_row()]));
    held.ended.store(true, Ordering::SeqCst);
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(next(&mut stream).await.as_deref(), Some(END));
}

/// Only a commit that names the stream's rows, or a shared table, makes it check: another
/// account's change does not.
#[tokio::test]
async fn a_change_of_another_account_does_not_end_the_stream() {
    let hub = EventHub::new(SseConfig::default(), EventRoutes::default(), Revision(10));
    let held = Arc::new(fake(UserId::generate()));
    let mut stream = opened(&hub, Arc::clone(&held) as Arc<dyn Held>).await;
    held.ended.store(true, Ordering::SeqCst);
    hub.publish_change_set(&change_set(11, vec![user_row(UserId::generate())]));
    hub.keepalive();
    assert_eq!(
        next(&mut stream).await.as_deref(),
        Some(&b": keep-alive\n\n"[..]),
        "another account's change is not this stream's end"
    );
}
