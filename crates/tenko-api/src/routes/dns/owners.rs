//! The owners of a zone's names (identity plan section 3.6, WP13.4): the owner view.
//!
//! Area: dns. Owner: WP13.4. Requirements: DNS-28, MIG-06.
//!
//! In a zone with ownership on, a name belongs to the principal whose secure update created
//! or claimed it ([`tenko_dns::zone::ownership`]). These routes show those owners and let an
//! administrator release a name or hand it to another principal, for example after a
//! computer was rebuilt under a new account. They act on the zone like a record change
//! does, so they take the zone's scopes: reading with `dns.read`, changing with
//! `dns.write`. A change never touches what the zone serves.
//!
//! | Endpoint | Scope | Purpose |
//! |---|---|---|
//! | `GET /dns/zones/{id}/owners` | `dns.read` | The owners of a scope's names, paged, by subtree and by owner |
//! | `PUT /dns/zones/{id}/owners/{name}` | `dns.write` | Give the name an owner (replacing the one it had) |
//! | `DELETE /dns/zones/{id}/owners/{name}` | `dns.write` | Release the name: its owner goes, its dynamic records become claimable again |

use axum::{
    Json,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tenko_core::{
    Action, ObjectRef, Revision, Timestamp,
    dns::{DnsName, NameOwner, OwnerSource, PrincipalName, ScopeName, Sid, ZoneId},
};
use tenko_dns::zone::{
    ZoneError, ZoneService,
    ownership::{OwnerAssignment, OwnerFilter, OwnerRow},
};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{Zones, parse_id};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{CursorScope, PageParams, encode_key_cursor},
    problem::{ApiError, ProblemDetails},
    routes::auth::{ApiJson, if_match},
    state::AppState,
};

/// The routes of the owner view.
pub(super) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_dns_zone_owners))
        .routes(routes!(assign_dns_zone_owner, release_dns_zone_owner))
}

/// Filters of `GET /dns/zones/{id}/owners`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct OwnerParams {
    /// The zone scope; `default` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeName>,
    /// Only the names at or below this name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<DnsName>,
    /// Only the names of this owner, by SID or principal (without regard to case).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Page size, 1 to 1,000 (default 100).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Opaque cursor from the previous page's `next_cursor`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// The scope of a change of one name.
#[derive(Debug, Clone, Default, Deserialize, Serialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct OwnerScopeParams {
    /// The zone scope; `default` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeName>,
}

/// The owner of one name (identity plan section 3.6).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NameOwnerItem {
    /// The zone scope.
    pub scope: ScopeName,
    /// The name.
    pub name: DnsName,
    /// The owner's SID, when the ticket carried a PAC or the assignment named one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<Sid>,
    /// The owner's principal.
    pub principal: PrincipalName,
    /// Since when.
    pub since: Timestamp,
    /// How the owner got the name: `created` by its secure update, `claimed` (a name
    /// imported without an owner, of its own host), `assigned` by an administrator, or
    /// `imported` from the source of a migration.
    pub how: OwnerSource,
    /// Until when the name is held for its owner: after its last record went, or for an
    /// assignment to a name without records; absent while the name has records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_until: Option<Timestamp>,
    /// The revision of the owner row, for `If-Match`.
    pub revision: Revision,
}

impl NameOwnerItem {
    fn of(scope: ScopeName, name: DnsName, owner: NameOwner, revision: Revision) -> Self {
        Self {
            scope,
            name,
            sid: owner.sid,
            principal: owner.principal,
            since: owner.since,
            how: owner.how,
            hold_until: owner.hold_until,
            revision,
        }
    }

    fn of_row(row: OwnerRow) -> Self {
        Self::of(row.key.scope, row.key.name, row.owner, row.revision)
    }
}

/// Body of `PUT /dns/zones/{id}/owners/{name}`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NameOwnerAssign {
    /// The zone scope; `default` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeName>,
    /// The new owner, a principal of one of the zone's realms (`PC07$@CORP.EXAMPLE.TEST`).
    pub principal: PrincipalName,
    /// Its SID (`(Get-ADComputer PC07).SID.Value`). With a SID the owner is matched by
    /// it, so a renamed account keeps the name; without one, by the principal's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<Sid>,
}

/// The answer of `DELETE /dns/zones/{id}/owners/{name}`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NameOwnerReleased {
    /// The owner that was removed.
    pub owner: NameOwnerItem,
    /// The dynamic RRsets of the name that are claimable again (origin `ad`).
    pub claimable: u64,
    /// The store revision of the write.
    pub revision: Revision,
}

fn name_of(raw: &str) -> Result<DnsName, ApiError> {
    DnsName::new(raw).map_err(|error| {
        ZoneError::new(
            tenko_core::dns::codes::OWNER_INVALID,
            400,
            format!("name: {}", error.reason),
        )
        .param("field", "name")
        .param("reason", error.reason)
        .into()
    })
}

#[utoipa::path(
    get,
    path = "/dns/zones/{id}/owners",
    tag = "dns",
    operation_id = "list_dns_zone_owners",
    summary = "List the owners of a zone's names",
    description = "Scope: `dns.read`. One row per name with an owner (identity plan section 3.6), in name order: the SID when the ticket carried a PAC, the principal, since when, how the owner got the name (`created`, `claimed`, `assigned`, `imported`), and the hold after the name's last record went. `name` keeps the names at or below it, `owner` those of one owner by SID or principal. Empty for a zone without ownership.",
    params(("id" = String, Path, description = "Zone identifier (UUID)"), OwnerParams),
    responses(
        (status = 200, description = "A page of owners by name", body = Page<NameOwnerItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_query`, `sys.invalid_cursor`), or the scope does not exist (`dns.zone.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The zone does not exist (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DNS module does not run on this server (`dns.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dns_zone_owners(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path(id): Path<String>,
    Query(filters): Query<OwnerParams>,
) -> Result<Response, ApiError> {
    let id: ZoneId = parse_id(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    let service = zones.get()?;
    let page = PageParams {
        limit: filters.limit,
        cursor: filters.cursor.clone(),
        at_least: None,
    };
    let limit = page.limit()?;
    let filter = OwnerFilter {
        scope: filters.scope.clone().unwrap_or_default(),
        below: filters.name.clone(),
        owner: filters.owner.clone(),
    };
    let cursor_scope = CursorScope::new("dns.owners")
        .with(&id.to_string())
        .with(filter.scope.as_str())
        .with(
            filter
                .below
                .as_ref()
                .map(DnsName::as_str)
                .unwrap_or_default(),
        )
        .with(filter.owner.as_deref().unwrap_or_default());
    let after = page.key_cursor(cursor_scope)?;
    let view = service.view(None).await?;
    let zone = ZoneService::zone(view.as_ref(), id)?.zone;
    if !zone.has_scope(&filter.scope) {
        return Err(ZoneError::zone_invalid("scope", "the zone has no such scope").into());
    }
    let (rows, next) = ZoneService::owners(view.as_ref(), &zone, &filter, after.as_deref(), limit)?;
    let items = rows.into_iter().map(NameOwnerItem::of_row).collect();
    let next = next.map(|key| encode_key_cursor(cursor_scope, &key));
    Ok(Json(Page::new(items, next, view.revision())).into_response())
}

#[utoipa::path(
    put,
    path = "/dns/zones/{id}/owners/{name}",
    tag = "dns",
    operation_id = "assign_dns_zone_owner",
    summary = "Give a name of a zone an owner",
    description = "Scope: `dns.write`. The name (absolute, inside the zone) gets the principal as its owner, replacing the owner it had (`If-Match` with the row's revision makes the change conditional); audited as `dns.owner.assign`. A name with records is owned from now; a name without records is held for the new owner for the zone's owner hold, so that it may create it. Locator and wildcard names keep no owner (`dns.owner.protected`); a zone without Kerberos settings keeps none (`dns.owner.off`).",
    params(("id" = String, Path, description = "Zone identifier (UUID)"), ("name" = String, Path, description = "The name, absolute")),
    request_body(content = NameOwnerAssign, content_type = "application/json"),
    responses(
        (status = 200, description = "The owner now", body = NameOwnerItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`), the scope does not exist (`dns.zone.invalid`), or the owner is invalid: a name outside the zone, a realm the zone does not accept (`dns.owner.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The zone does not exist (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The zone keeps no owners (`dns.owner.off`), the name keeps none (`dns.owner.protected`), or the DNS module does not run (`dns.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is not the owner row's revision", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn assign_dns_zone_owner(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path((id, name)): Path<(String, String)>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<NameOwnerAssign>,
) -> Result<Response, ApiError> {
    let id: ZoneId = parse_id(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    let name = name_of(&name)?;
    let expect = if_match(&headers)?;
    let service = zones.get()?;
    let scope = body.scope.unwrap_or_default();
    let assigned = service
        .assign_owner(
            &cx,
            id,
            &OwnerAssignment {
                scope: scope.clone(),
                name: name.clone(),
                principal: body.principal,
                sid: body.sid,
                expect,
            },
        )
        .await?;
    Ok(Json(NameOwnerItem::of(
        scope,
        name,
        assigned.owner,
        assigned.written.revision,
    ))
    .into_response())
}

#[utoipa::path(
    delete,
    path = "/dns/zones/{id}/owners/{name}",
    tag = "dns",
    operation_id = "release_dns_zone_owner",
    summary = "Release a name of a zone from its owner",
    description = "Scope: `dns.write`. The name's owner goes (`If-Match` with the row's revision makes the change conditional) and its dynamic records return to the origin `ad`: the next secure update that changes the name is held to the claim rule (the host the name carries, or a privileged principal), never taken by any principal the lists allow. To hand the name to a given principal, assign it instead. Audited as `dns.owner.release`; the records served do not change.",
    params(("id" = String, Path, description = "Zone identifier (UUID)"), ("name" = String, Path, description = "The name, absolute"), OwnerScopeParams),
    responses(
        (status = 200, description = "The owner removed and the RRsets made claimable", body = NameOwnerReleased),
        (status = 400, description = "The request is malformed, the scope does not exist (`dns.zone.invalid`), or the name is outside the zone (`dns.owner.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.write`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The zone does not exist (`dns.zone.not_found`), or the name has no owner (`dns.owner.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The zone keeps no owners (`dns.owner.off`), the name keeps none (`dns.owner.protected`), or the DNS module does not run (`dns.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is not the owner row's revision", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn release_dns_zone_owner(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    zones: Zones,
    Path((id, name)): Path<(String, String)>,
    Query(query): Query<OwnerScopeParams>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id: ZoneId = parse_id(&id)?;
    app.authorize(&cx.principal, Action::Update, &ObjectRef::from(id))?;
    let name = name_of(&name)?;
    let expect = if_match(&headers)?;
    let service = zones.get()?;
    let scope = query.scope.unwrap_or_default();
    let released = service
        .release_owner(&cx, id, &scope, &name, expect)
        .await?;
    let revision = released.written.revision;
    Ok(Json(NameOwnerReleased {
        owner: NameOwnerItem::of(scope, name, released.owner, revision),
        claimable: u64::try_from(released.claimable).unwrap_or(u64::MAX),
        revision,
    })
    .into_response())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        http::{Request, header},
    };
    use serde_json::{Value, json};
    use tenko_core::{
        Action, Authorizer, ObjectRef, RequestCtx, SystemComponent,
        dns::{
            DnsName, KerberosUpdate, NameOwner, NameOwnerKey, OwnerSource, PrincipalName, Realm,
            SerialPolicy, Sid, SoaDefaults, UpdatePolicy, ZoneId, ZoneKind, tables::NAME_OWNERS,
        },
    };
    use tenko_dns::zone::{NewZone, ZoneConfig, ZoneService};
    use tenko_store::{MemStore, Store, WriteBatch};
    use tower::ServiceExt;
    use utoipa_axum::router::OpenApiRouter;

    use super::routes;
    use crate::{
        API_BASE,
        routes::tenancy::testkit::{Policy, Reply},
        state::AppState,
    };

    const OTHER: &str = "0190d1c2-0000-7000-8000-000000000001";

    fn name(text: &str) -> DnsName {
        DnsName::new(text).expect("name")
    }

    async fn setup(policy: Arc<Policy>, kerberos: bool) -> (Router, Arc<MemStore>, ZoneId) {
        let store = Arc::new(MemStore::default());
        let zones = ZoneService::with_direct_jobs(
            Arc::clone(&store) as Arc<dyn Store>,
            None,
            ZoneConfig::default(),
        );
        let cx = RequestCtx::system(SystemComponent::Dns);
        let realm = Realm::new("CORP.EXAMPLE.TEST").expect("realm");
        let zone = zones
            .create(
                &cx,
                NewZone {
                    name: name("corp.example.test"),
                    kind: ZoneKind::Primary,
                    tenant: None,
                    scopes: Vec::new(),
                    serial: SerialPolicy::Counter,
                    soa: SoaDefaults::new(
                        name("ns1.corp.example.test"),
                        name("hostmaster.corp.example.test"),
                    ),
                    name_servers: vec![name("ns1.corp.example.test")],
                    transfer: tenko_core::dns::TransferPolicy::default(),
                    update: UpdatePolicy {
                        kerberos: kerberos.then(|| KerberosUpdate::for_realm(realm)),
                        ..UpdatePolicy::default()
                    },
                    dnssec: tenko_core::dns::DnssecPolicy::default(),
                    source: None,
                    description: None,
                    reverse_of: None,
                    catalog: false,
                },
            )
            .await
            .expect("zone")
            .zone;
        let mut batch = WriteBatch::for_request(&cx);
        batch
            .put_typed(
                &NAME_OWNERS,
                &NameOwnerKey {
                    zone: zone.id,
                    scope: tenko_core::dns::ScopeName::DEFAULT,
                    name: name("pc01.corp.example.test"),
                },
                &NameOwner {
                    sid: Some(Sid::parse("S-1-5-21-1-2-3-1001").expect("sid")),
                    principal: PrincipalName::parse("PC01$@CORP.EXAMPLE.TEST").expect("p"),
                    since: cx.now,
                    hold_until: None,
                    how: OwnerSource::Created,
                },
            )
            .expect("row");
        store.propose(batch).await.expect("write");
        let state = AppState {
            authorizer: Some(policy as Arc<dyn Authorizer>),
            ..AppState::new(Arc::clone(&store) as Arc<dyn Store>)
        };
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        let router = router.with_state(state).layer(Extension(zones));
        (router, store, zone.id)
    }

    async fn send(router: &Router, method: &str, path: &str, body: Option<Value>) -> Reply {
        let builder = Request::builder()
            .method(method)
            .uri(format!("{API_BASE}{path}"));
        let request = match body {
            Some(body) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => builder.body(Body::empty()),
        }
        .expect("request");
        let response = router.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|value| value.to_str().expect("text").to_owned())
            .unwrap_or_default();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        Reply {
            status,
            content_type,
            etag: None,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        }
    }

    /// DNS-28: the scope is checked before anything else, reading with `dns.read` and
    /// changing with `dns.write` on the zone.
    #[tokio::test]
    async fn dns_28_the_owner_routes_check_the_zone_scope_first() {
        let policy = Policy::new(false, false);
        let (router, _, _) = setup(Arc::clone(&policy), true).await;
        let zone: ZoneId = OTHER.parse().expect("id");
        for (method, path, body) in [
            ("GET", format!("/dns/zones/{OTHER}/owners"), None),
            (
                "PUT",
                format!("/dns/zones/{OTHER}/owners/pc01.corp.example.test"),
                Some(json!({"principal": "PC01$@CORP.EXAMPLE.TEST"})),
            ),
            (
                "DELETE",
                format!("/dns/zones/{OTHER}/owners/pc01.corp.example.test"),
                None,
            ),
        ] {
            send(&router, method, &path, body)
                .await
                .assert_problem(403, "auth.forbidden");
        }
        assert_eq!(
            policy.asked(),
            [
                (Action::Read, ObjectRef::from(zone)),
                (Action::Update, ObjectRef::from(zone)),
                (Action::Update, ObjectRef::from(zone)),
            ]
        );
    }

    /// DNS-28: the view lists, assigns and releases; a reader may list only.
    #[tokio::test]
    async fn dns_28_the_owner_view_lists_assigns_and_releases() {
        let (router, _, zone) = setup(Policy::new(true, true), true).await;
        let reply = send(&router, "GET", &format!("/dns/zones/{zone}/owners"), None).await;
        assert_eq!(reply.status.as_u16(), 200, "{}", reply.body);
        assert_eq!(reply.body["items"][0]["name"], "pc01.corp.example.test");
        assert_eq!(reply.body["items"][0]["how"], "created");
        assert_eq!(reply.body["items"][0]["sid"], "S-1-5-21-1-2-3-1001");
        let filtered = send(
            &router,
            "GET",
            &format!("/dns/zones/{zone}/owners?owner=s-1-5-21-1-2-3-1002"),
            None,
        )
        .await;
        assert_eq!(filtered.body["items"].as_array().map(Vec::len), Some(0));

        let reply = send(
            &router,
            "PUT",
            &format!("/dns/zones/{zone}/owners/pc01.corp.example.test"),
            Some(json!({"principal": "PC07$@CORP.EXAMPLE.TEST", "sid": "S-1-5-21-1-2-3-1007"})),
        )
        .await;
        assert_eq!(reply.status.as_u16(), 200, "{}", reply.body);
        assert_eq!(reply.body["how"], "assigned");
        assert!(
            reply.body["hold_until"].is_string(),
            "a name without records is held for the new owner"
        );
        // Another realm, a locator name, a name outside the zone.
        send(
            &router,
            "PUT",
            &format!("/dns/zones/{zone}/owners/pc01.corp.example.test"),
            Some(json!({"principal": "PC07$@OTHER.EXAMPLE.TEST"})),
        )
        .await
        .assert_problem(400, "dns.owner.invalid");
        send(
            &router,
            "PUT",
            &format!("/dns/zones/{zone}/owners/_ldap._tcp.corp.example.test"),
            Some(json!({"principal": "PC07$@CORP.EXAMPLE.TEST"})),
        )
        .await
        .assert_problem(409, "dns.owner.protected");
        send(
            &router,
            "PUT",
            &format!("/dns/zones/{zone}/owners/www.example.net"),
            Some(json!({"principal": "PC07$@CORP.EXAMPLE.TEST"})),
        )
        .await
        .assert_problem(400, "dns.owner.invalid");

        let reply = send(
            &router,
            "DELETE",
            &format!("/dns/zones/{zone}/owners/pc01.corp.example.test"),
            None,
        )
        .await;
        assert_eq!(reply.status.as_u16(), 200, "{}", reply.body);
        assert_eq!(reply.body["owner"]["principal"], "PC07$@CORP.EXAMPLE.TEST");
        send(
            &router,
            "DELETE",
            &format!("/dns/zones/{zone}/owners/pc01.corp.example.test"),
            None,
        )
        .await
        .assert_problem(404, "dns.owner.not_found");
    }

    /// DNS-28: a cursor whose key lies outside the zone's owners is refused, not read from:
    /// a key below the zone's prefix would start the scan in another zone.
    #[tokio::test]
    async fn dns_28_a_cursor_outside_the_zone_is_refused() {
        let (router, _, zone) = setup(Policy::new(true, true), true).await;
        let scope = crate::list::CursorScope::new("dns.owners")
            .with(&zone.to_string())
            .with("default")
            .with("")
            .with("");
        let cursor = crate::list::encode_key_cursor(scope, &[0_u8]);
        send(
            &router,
            "GET",
            &format!("/dns/zones/{zone}/owners?cursor={cursor}"),
            None,
        )
        .await
        .assert_problem(400, "sys.invalid_cursor");
    }

    /// DNS-28: a zone without Kerberos settings keeps no owners.
    #[tokio::test]
    async fn dns_28_a_zone_without_kerberos_keeps_no_owners() {
        let (router, _, zone) = setup(Policy::new(true, true), false).await;
        send(
            &router,
            "PUT",
            &format!("/dns/zones/{zone}/owners/pc02.corp.example.test"),
            Some(json!({"principal": "PC02$@CORP.EXAMPLE.TEST"})),
        )
        .await
        .assert_problem(409, "dns.owner.off");
    }
}
