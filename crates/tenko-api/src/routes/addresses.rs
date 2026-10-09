//! Addresses.
//!
//! Area: addresses. Owner: WP1.4. Requirements: IPAM-05, IPAM-07.
//!
//! Create, read, update and soft-delete for addresses, with their status, interface, DNS
//! name, tags and custom fields. History, restore and bulk changes are in [`super::common`],
//! which also documents the conventions every endpoint here follows: the IPAM service as a
//! request extension (503 `ipam.unavailable` without it), the list parameters, `ETag` and
//! `If-Match`, `Idempotency-Key`, `dry_run` and `acknowledge`, and the authorization checks.
//! The next free address of a prefix is allocated by `POST /prefixes/{id}/next-free-address`
//! (see [`super::prefixes`]).
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /addresses` | 200 page of addresses | 400 `sys.invalid_query`, `sys.invalid_cursor` |
//! | `POST /addresses` | 201 write response, 200 for a dry run or a replay | 400, 403, 409 `ipam.address.duplicate`, `ipam.address.no_prefix`, `ipam.address.network_or_broadcast`, `ipam.address.in_dhcp_pool`, `ipam.reference_missing`, 422 `ipam.idempotency_mismatch`, 423 `ipam.host.locked` |
//! | `GET /addresses/{id}` | 200 address with `ETag` | 404 `ipam.not_found` |
//! | `PATCH /addresses/{id}` | 200 write response | 404, 409 (as for create, plus `ipam.status.transition`), 412 `ipam.revision_mismatch`, 423 |
//! | `DELETE /addresses/{id}` | 200 write response with the deleted address | 404, 409 `ipam.object_deleted`, 412, 423 |
//!
//! # Placement
//!
//! An address lives in a VRF (the default VRF when `vrf` is left out) and belongs to the most
//! specific prefix of that VRF that contains it; the answer's `prefix` says which. A new IPv4
//! address may not be the network or broadcast address of a network prefix, and an address
//! directly in a supernet is allowed with the warning `ipam.address.in_supernet`. Changing
//! `ip` moves the address and recomputes its prefix; the VRF cannot change.
//!
//! # Lists
//!
//! `GET /addresses` filters by `status`, `vrf`, `within` (a network such as `192.0.2.0/24`),
//! `prefix` (the owning prefix), `interface`, `host` (the addresses of the host's
//! interfaces), `tag` and `q` (text over the address, the DNS name, the description and the
//! tags). It sorts by `ip` (the default; VRF first, then numerically), `dns_name`, `status`,
//! `created` and `updated`.

use axum::{Json, extract::State, http::HeaderMap, response::Response};
use tenko_core::{Action, AddressId, ObjectKind, ObjectRef, ipam::Address};
use tenko_ipam::{
    IpamCommand,
    command::{AddressInput, AddressPatch, UpdateAddress},
};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::common::{
    Filter, IdempotencyKeyHeader, IfMatch, Ipam, IpamJson, IpamPath, ReadParams, WriteParams,
    WriteResponse, authorize, get_one, if_match, list_args, list_collection, new_of, write_args,
    write_one,
};
use crate::{
    dto::Page,
    extract::Ctx,
    list::{Filters, PageParams},
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_addresses, create_address))
        .routes(routes!(get_address, update_address, delete_address))
}

/// Lists addresses, by VRF and address unless `sort` says otherwise.
#[utoipa::path(
    get,
    path = "/addresses",
    tag = "addresses",
    operation_id = "list_addresses",
    summary = "List addresses",
    params(
        PageParams,
        ("status" = Option<String>, Query, description = "Only addresses with one of these statuses: `planned`, `active`, `reserved` or `deprecated`. Repeat the parameter or separate the values with commas."),
        ("vrf" = Option<String>, Query, description = "Only addresses of this VRF (identifier)."),
        ("within" = Option<String>, Query, description = "Only addresses inside this network, for example `192.0.2.0/24`. A bare address is a host network. Host bits must be zero."),
        ("prefix" = Option<String>, Query, description = "Only addresses whose most specific prefix is this prefix (identifier)."),
        ("interface" = Option<String>, Query, description = "Only addresses assigned to this interface (identifier)."),
        ("host" = Option<String>, Query, description = "Only addresses assigned to an interface of this host (identifier)."),
        ("tag" = Option<String>, Query, description = "Only addresses that carry every one of these tags. Repeat the parameter or separate the tags with commas."),
        ("q" = Option<String>, Query, description = "Case-insensitive text search over the address, the DNS name, the description and the tags."),
        ("sort" = Option<String>, Query, description = "Sort order: comma-separated fields, `-` in front for descending, for example `-updated,ip`. Fields: `ip` (the default), `dns_name`, `status`, `created`, `updated`."),
        ("deleted" = Option<String>, Query, description = "Deleted addresses: `exclude` (the default), `include` or `only` (the restore view).")
    ),
    responses(
        (status = 200, description = "A page of addresses", body = Page<Address>),
        (status = 400, description = "Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_addresses(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
) -> Result<Json<Page<Address>>, ApiError> {
    let args = list_args::<Address>(
        &filters,
        "ipam.addresses",
        &[
            Filter::Status,
            Filter::Vrf,
            Filter::Within,
            Filter::Prefix,
            Filter::Interface,
            Filter::Host,
            Filter::Tag,
            Filter::Q,
            Filter::Sort,
            Filter::Deleted,
        ],
    )?;
    list_collection::<Address>(&app, &cx, &ipam, args).await
}

/// Creates an address in a VRF. The most specific prefix of the VRF that contains it becomes
/// its prefix; the IPv4 network and broadcast addresses of a network prefix are refused.
#[utoipa::path(
    post,
    path = "/addresses",
    tag = "addresses",
    operation_id = "create_address",
    summary = "Create an address",
    params(WriteParams, IdempotencyKeyHeader),
    request_body = AddressInput,
    responses(
        (status = 201, description = "The new address, with `ETag`", body = WriteResponse<Address>),
        (status = 200, description = "The plan of a dry run, or the first result again for a repeated `Idempotency-Key` (`replayed` is true)", body = WriteResponse<Address>),
        (status = 400, description = "Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The address exists in the VRF, no prefix contains it, it is a network or broadcast address, a DHCP pool covers it for a reserved host, the VRF or interface is missing, or the identifier is in use (`ipam.address.duplicate`, `ipam.address.no_prefix`, `ipam.address.network_or_broadcast`, `ipam.address.in_dhcp_pool`, `ipam.reference_missing`, `ipam.id_taken`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The `Idempotency-Key` was used for a different request (`ipam.idempotency_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 423, description = "The host of the interface is locked against automation (`ipam.host.locked`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_address(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
    IpamJson(input): IpamJson<AddressInput>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    authorize(&app, &cx, Action::Create, new_of(ObjectKind::Address))?;
    let command = IpamCommand::CreateAddress(input);
    write_one::<Address>(&ipam, &cx, vec![command], &args, true).await
}

/// Shows one address with its `ETag`. A deleted address is shown too: it carries
/// `meta.deleted`.
#[utoipa::path(
    get,
    path = "/addresses/{id}",
    tag = "addresses",
    operation_id = "get_address",
    summary = "Get one address",
    params(("id" = String, Path, description = "Address identifier"), ReadParams),
    responses(
        (status = 200, description = "The address, with `ETag`", body = Address),
        (status = 400, description = "Invalid parameter (`sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such address (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_address(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<AddressId>,
    filters: Filters,
) -> Result<Response, ApiError> {
    get_one::<Address>(&app, &cx, &ipam, id, &filters).await
}

/// Changes an address: the address itself (a move, which recomputes its prefix), the status
/// (IPAM-05 transitions apply), the interface (`null` unassigns it), the DNS name (`null`
/// clears it), the tags, the custom fields and the description.
#[utoipa::path(
    patch,
    path = "/addresses/{id}",
    tag = "addresses",
    operation_id = "update_address",
    summary = "Update an address",
    params(("id" = String, Path, description = "Address identifier"), WriteParams, IfMatch),
    request_body = AddressPatch,
    responses(
        (status = 200, description = "The changed address, with `ETag`, or the plan of a dry run", body = WriteResponse<Address>),
        (status = 400, description = "Invalid body or parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such address (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The new address exists in the VRF or no prefix contains it, the status change is not allowed, the interface is missing, or the address is deleted (`ipam.address.duplicate`, `ipam.address.no_prefix`, `ipam.status.transition`, `ipam.reference_missing`, `ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 423, description = "The host of the interface is locked against automation (`ipam.host.locked`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_address(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<AddressId>,
    headers: HeaderMap,
    filters: Filters,
    IpamJson(patch): IpamJson<AddressPatch>,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    authorize(&app, &cx, Action::Update, id.into())?;
    let command = IpamCommand::UpdateAddress(UpdateAddress {
        id,
        expected,
        patch,
    });
    write_one::<Address>(&ipam, &cx, vec![command], &args, false).await
}

/// Soft-deletes an address and frees its place in the prefix. The answer carries the deleted
/// address.
#[utoipa::path(
    delete,
    path = "/addresses/{id}",
    tag = "addresses",
    operation_id = "delete_address",
    summary = "Delete an address",
    params(("id" = String, Path, description = "Address identifier"), WriteParams, IfMatch),
    responses(
        (status = 200, description = "The deleted address (`meta.deleted` is set), or the plan of a dry run", body = WriteResponse<Address>),
        (status = 400, description = "Invalid parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such address (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The address is deleted already (`ipam.object_deleted`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is stale (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 423, description = "The host of the interface is locked against automation (`ipam.host.locked`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_address(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    IpamPath(id): IpamPath<AddressId>,
    headers: HeaderMap,
    filters: Filters,
) -> Result<Response, ApiError> {
    let args = write_args(&filters, false)?;
    let expected = if_match(&headers)?;
    let object: ObjectRef = id.into();
    authorize(&app, &cx, Action::Delete, object)?;
    let command = IpamCommand::Delete {
        object,
        expected,
        cascade: false,
    };
    write_one::<Address>(&ipam, &cx, vec![command], &args, false).await
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use tenko_core::{
        Action, AddressId, ObjectKind, ObjectRef,
        ipam::{PrefixRole, RangeRole},
    };

    use super::super::tenancy::testkit::{Api, Policy, Reply, ip4, label, unknown_id};
    use crate::state::AppState;

    /// The body of an address in `192.0.2.0/24`.
    fn body(host_part: usize) -> Value {
        json!({ "ip": ip4(host_part) })
    }

    fn id_of(value: &Value) -> String {
        value["id"].as_str().expect("id").to_owned()
    }

    /// The API with the network `192.0.2.0/24` in the default VRF; the prefix is returned.
    async fn api_with_network() -> (Api, String) {
        let api = Api::new();
        let prefix = api.make_prefix(None, "192.0.2.0/24").await;
        (api, prefix.to_string())
    }

    /// Creates the address `192.0.2.<host_part>` and returns its identifier.
    async fn make_address(api: &Api, host_part: usize) -> String {
        id_of(&api.create("/addresses", &body(host_part)).await)
    }

    /// Creates a host with the given interfaces and returns the host and the interfaces.
    async fn make_host(api: &Api, n: usize, interfaces: &[&str]) -> (String, Vec<String>) {
        let interfaces: Vec<Value> = interfaces
            .iter()
            .map(|name| json!({ "name": name }))
            .collect();
        let body = json!({ "name": label("host", n), "interfaces": interfaces });
        let host = id_of(&api.create("/hosts", &body).await);
        let created = api.get(&format!("/hosts/{host}/interfaces")).await;
        (host, created.ids())
    }

    /// The addresses (`ip`) that a list answers.
    async fn ips_at(api: &Api, query: &str) -> Vec<String> {
        let reply = api.get(&format!("/addresses{query}")).await;
        reply.assert_json(200);
        reply.texts("ip")
    }

    // Create and read.

    #[tokio::test]
    async fn create_answers_201_with_the_address_its_prefix_and_an_etag() {
        let (api, prefix) = api_with_network().await;
        let reply = api.post("/addresses", &body(10)).await;
        reply.assert_write(201);
        let item = reply.item();
        assert_eq!(item["ip"], "192.0.2.10");
        assert_eq!(item["prefix"], prefix);
        assert_eq!(item["status"], "active");
        assert_eq!(item["interface"], Value::Null);
        assert_eq!(item["dns_name"], Value::Null);
        assert_eq!(item["meta"]["deleted"], Value::Null);
        // The default VRF came with the prefix.
        let vrf = item["vrf"].as_str().expect("vrf");
        assert_eq!(
            api.get(&format!("/vrfs/{vrf}")).await.body["name"],
            "default"
        );
    }

    #[tokio::test]
    async fn create_keeps_the_given_members() {
        let (api, _) = api_with_network().await;
        let (_, interfaces) = make_host(&api, 1, &["eth0"]).await;
        let input = json!({
            "ip": "192.0.2.20",
            "status": "reserved",
            "interface": interfaces[0],
            "dns_name": "Printer.Example.Test.",
            "tags": ["office"],
            "description": "Floor printer",
        });
        let reply = api.post("/addresses", &input).await;
        reply.assert_write(201);
        let item = reply.item();
        assert_eq!(item["status"], "reserved");
        assert_eq!(item["interface"], interfaces[0]);
        assert_eq!(item["dns_name"], "printer.example.test");
        assert_eq!(item["meta"]["tags"], json!(["office"]));
        assert_eq!(item["meta"]["description"], "Floor printer");
    }

    #[tokio::test]
    async fn an_ipv6_address_lands_in_its_prefix() {
        let api = Api::new();
        let prefix = api.make_prefix(None, "2001:db8::/64").await;
        let reply = api
            .post("/addresses", &json!({ "ip": "2001:db8::10" }))
            .await;
        reply.assert_write(201);
        assert_eq!(reply.item()["ip"], "2001:db8::10");
        assert_eq!(reply.item()["prefix"], prefix.to_string());
        assert_eq!(
            ips_at(&api, "?within=2001:db8::/32").await,
            ["2001:db8::10"]
        );
        assert_eq!(
            ips_at(&api, "?within=192.0.2.0/24").await,
            Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn get_returns_the_address_with_the_etag_of_the_write() {
        let (api, _) = api_with_network().await;
        let created = api.post("/addresses", &body(10)).await;
        let reply = api.get(&format!("/addresses/{}", created.item_id())).await;
        reply.assert_json(200);
        assert_eq!(&reply.body, created.item());
        assert_eq!(reply.etag, created.etag);
        let at = api
            .get(&format!(
                "/addresses/{}?at_least={}",
                created.item_id(),
                created.revision()
            ))
            .await;
        at.assert_json(200);
    }

    #[tokio::test]
    async fn an_unknown_address_is_a_404_problem_on_get_patch_and_delete() {
        let (api, _) = api_with_network().await;
        let id = unknown_id();
        let path = format!("/addresses/{id}");
        let replies = [
            api.get(&path).await,
            api.patch(&path, None, &json!({ "dns_name": null })).await,
            api.delete(&path, None).await,
        ];
        for reply in replies {
            reply.assert_problem(404, "ipam.not_found");
            assert_eq!(reply.body["params"]["kind"], "address");
            assert_eq!(reply.body["params"]["id"], id);
        }
        let malformed = api.get("/addresses/not-a-uuid").await;
        malformed.assert_problem(400, "sys.invalid_request");
        assert_eq!(malformed.body["params"]["part"], "path");
    }

    // Lists.

    #[tokio::test]
    async fn addresses_are_ordered_numerically_by_default() {
        let (api, _) = api_with_network().await;
        for host_part in [100, 9, 10] {
            make_address(&api, host_part).await;
        }
        let reply = api.get("/addresses").await;
        reply.assert_json(200);
        assert_eq!(
            reply.texts("ip"),
            ["192.0.2.9", "192.0.2.10", "192.0.2.100"]
        );
        assert_eq!(
            ips_at(&api, "?sort=-ip").await,
            ["192.0.2.100", "192.0.2.10", "192.0.2.9"]
        );
        assert_eq!(api.get("/addresses?sort=ip").await.items().len(), 3);
        let empty = Api::new().get("/addresses").await;
        assert_eq!(empty.body["items"], json!([]));
        assert_eq!(empty.body["next_cursor"], Value::Null);
    }

    #[tokio::test]
    async fn addresses_page_with_limit_and_cursor() {
        let (api, _) = api_with_network().await;
        let mut created = Vec::new();
        for host_part in 11..=15 {
            created.push(make_address(&api, host_part).await);
        }
        let pages = api.pages("/addresses", 2).await;
        let sizes: Vec<usize> = pages.iter().map(|page| page.items().len()).collect();
        assert_eq!(sizes, [2, 2, 1]);
        assert!(pages[0].body["next_cursor"].is_string());
        assert_eq!(pages[2].body["next_cursor"], Value::Null);
        let seen: Vec<String> = pages.iter().flat_map(Reply::ids).collect();
        assert_eq!(seen, created);
        // A filter on the same cursor is a different query.
        let cursor = pages[0].body["next_cursor"].as_str().expect("cursor");
        api.get(&format!("/addresses?limit=2&cursor={cursor}&status=active"))
            .await
            .assert_problem(400, "sys.invalid_cursor");
        let descending = api.pages("/addresses?sort=-ip", 2).await;
        let mut expected = created.clone();
        expected.reverse();
        let seen: Vec<String> = descending.iter().flat_map(Reply::ids).collect();
        assert_eq!(seen, expected);
    }

    #[tokio::test]
    async fn addresses_filter_by_status() {
        let (api, _) = api_with_network().await;
        let planned = json!({ "ip": ip4(10), "status": "planned" });
        let reserved = json!({ "ip": ip4(11), "status": "reserved" });
        api.create("/addresses", &planned).await;
        api.create("/addresses", &reserved).await;
        make_address(&api, 12).await;
        assert_eq!(ips_at(&api, "?status=planned").await, ["192.0.2.10"]);
        assert_eq!(ips_at(&api, "?status=active").await, ["192.0.2.12"]);
        assert_eq!(ips_at(&api, "?status=planned,reserved").await.len(), 2);
        assert_eq!(ips_at(&api, "?status=planned&status=active").await.len(), 2);
        assert_eq!(
            ips_at(&api, "?status=deprecated").await,
            Vec::<String>::new()
        );
        api.get("/addresses?status=sleeping")
            .await
            .assert_problem(400, "sys.invalid_query");
    }

    #[tokio::test]
    async fn addresses_filter_by_vrf() {
        let api = Api::new();
        let mut vrfs = Vec::new();
        for n in 1..=2 {
            let vrf = api
                .create("/vrfs", &json!({ "name": label("vrf", n) }))
                .await;
            vrfs.push(id_of(&vrf));
            api.make_prefix(Some(&vrfs[n - 1]), "192.0.2.0/24").await;
        }
        // The same address in two VRFs is two addresses.
        let first = api
            .create("/addresses", &json!({ "ip": ip4(10), "vrf": vrfs[0] }))
            .await;
        let second = api
            .create("/addresses", &json!({ "ip": ip4(10), "vrf": vrfs[1] }))
            .await;
        assert_ne!(first["id"], second["id"]);
        let in_first = api.get(&format!("/addresses?vrf={}", vrfs[0])).await;
        assert_eq!(in_first.ids(), [id_of(&first)]);
        assert_eq!(in_first.items()[0]["vrf"], vrfs[0]);
        let in_second = api.get(&format!("/addresses?vrf={}", vrfs[1])).await;
        assert_eq!(in_second.ids(), [id_of(&second)]);
        assert_eq!(api.get("/addresses").await.items().len(), 2);
        api.get("/addresses?vrf=default")
            .await
            .assert_problem(400, "sys.invalid_query");
    }

    #[tokio::test]
    async fn addresses_filter_by_within_and_prefix() {
        let api = Api::new();
        api.make_prefix_as(None, "192.0.2.0/24", Some(PrefixRole::Supernet))
            .await;
        let low = api.make_prefix(None, "192.0.2.0/25").await.to_string();
        let high = api.make_prefix(None, "192.0.2.128/25").await.to_string();
        let in_low = make_address(&api, 10).await;
        let in_high = make_address(&api, 200).await;
        assert_eq!(ips_at(&api, "?within=192.0.2.0/25").await, ["192.0.2.10"]);
        assert_eq!(
            ips_at(&api, "?within=192.0.2.128/25").await,
            ["192.0.2.200"]
        );
        assert_eq!(ips_at(&api, "?within=192.0.2.0/24").await.len(), 2);
        assert_eq!(ips_at(&api, "?within=192.0.2.200").await, ["192.0.2.200"]);
        assert_eq!(
            ips_at(&api, "?within=198.51.100.0/24").await,
            Vec::<String>::new()
        );
        assert_eq!(
            ips_at(&api, "?within=2001:db8::/32").await,
            Vec::<String>::new()
        );
        for bad in [
            "?within=192.0.2.1/24",
            "?within=nowhere",
            "?within=192.0.2.0/24&within=192.0.2.0/25",
        ] {
            api.get(&format!("/addresses{bad}"))
                .await
                .assert_problem(400, "sys.invalid_query");
        }
        let by_low = api.get(&format!("/addresses?prefix={low}")).await;
        assert_eq!(by_low.ids(), [in_low]);
        assert_eq!(by_low.items()[0]["prefix"], low);
        let by_high = api.get(&format!("/addresses?prefix={high}")).await;
        assert_eq!(by_high.ids(), [in_high]);
        assert_eq!(
            api.get(&format!("/addresses?prefix={high}&within=192.0.2.0/25"))
                .await
                .items()
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn addresses_filter_by_interface_and_host() {
        let (api, _) = api_with_network().await;
        let (host, interfaces) = make_host(&api, 1, &["eth0", "eth1"]).await;
        let (_, others) = make_host(&api, 2, &["eth0"]).await;
        let on_eth0 = api
            .create(
                "/addresses",
                &json!({ "ip": ip4(10), "interface": interfaces[0] }),
            )
            .await;
        let on_eth1 = api
            .create(
                "/addresses",
                &json!({ "ip": ip4(11), "interface": interfaces[1] }),
            )
            .await;
        api.create(
            "/addresses",
            &json!({ "ip": ip4(12), "interface": others[0] }),
        )
        .await;
        make_address(&api, 13).await;
        let by_interface = api
            .get(&format!("/addresses?interface={}", interfaces[0]))
            .await;
        assert_eq!(by_interface.ids(), [id_of(&on_eth0)]);
        let by_host = api.get(&format!("/addresses?host={host}")).await;
        assert_eq!(by_host.ids(), [id_of(&on_eth0), id_of(&on_eth1)]);
        let both = api
            .get(&format!(
                "/addresses?host={host}&interface={}",
                interfaces[1]
            ))
            .await;
        assert_eq!(both.ids(), [id_of(&on_eth1)]);
        assert_eq!(api.get("/addresses").await.items().len(), 4);
        assert_eq!(
            ips_at(&api, &format!("?host={}", unknown_id())).await,
            Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn addresses_filter_by_tag_and_text() {
        let (api, _) = api_with_network().await;
        let red = json!({ "ip": ip4(10), "tags": ["red"], "dns_name": "alpha.example.test" });
        let both = json!({
            "ip": ip4(11),
            "tags": ["blue", "red"],
            "description": "Core switch",
        });
        api.create("/addresses", &red).await;
        api.create("/addresses", &both).await;
        make_address(&api, 12).await;
        assert_eq!(ips_at(&api, "?tag=red").await, ["192.0.2.10", "192.0.2.11"]);
        assert_eq!(ips_at(&api, "?tag=red,blue").await, ["192.0.2.11"]);
        assert_eq!(ips_at(&api, "?tag=red&tag=blue").await, ["192.0.2.11"]);
        assert_eq!(ips_at(&api, "?tag=green").await, Vec::<String>::new());
        assert_eq!(ips_at(&api, "?q=ALPHA").await, ["192.0.2.10"]);
        assert_eq!(ips_at(&api, "?q=core+switch").await, ["192.0.2.11"]);
        assert_eq!(ips_at(&api, "?q=192.0.2.12").await, ["192.0.2.12"]);
        let by_name = ips_at(&api, "?sort=-dns_name").await;
        assert_eq!(by_name[0], "192.0.2.10");
        api.get("/addresses?sort=vrf")
            .await
            .assert_problem(400, "sys.invalid_query");
    }

    #[tokio::test]
    async fn deleted_addresses_show_with_deleted_only_or_include() {
        let (api, _) = api_with_network().await;
        let mut ids = Vec::new();
        for host_part in 10..=12 {
            ids.push(make_address(&api, host_part).await);
        }
        api.delete(&format!("/addresses/{}", ids[1]), None)
            .await
            .assert_write(200);
        assert_eq!(ips_at(&api, "").await, ["192.0.2.10", "192.0.2.12"]);
        let only = api.get("/addresses?deleted=only").await;
        assert_eq!(only.ids(), [ids[1].clone()]);
        assert!(only.items()[0]["meta"]["deleted"]["at"].is_string());
        assert_eq!(api.get("/addresses?deleted=include").await.ids(), ids);
        assert_eq!(ips_at(&api, "?deleted=exclude").await.len(), 2);
        api.get("/addresses?deleted=maybe")
            .await
            .assert_problem(400, "sys.invalid_query");
    }

    #[tokio::test]
    async fn parameters_that_an_endpoint_does_not_take_are_refused() {
        let (api, _) = api_with_network().await;
        let id = make_address(&api, 10).await;
        let path = format!("/addresses/{id}");
        let replies = [
            (api.get("/addresses?bogus=1").await, "bogus"),
            (api.get("/addresses?mode=static").await, "mode"),
            (api.get("/addresses?limit=0").await, "limit"),
            (api.get("/addresses?at_least=x").await, "at_least"),
            (api.get(&format!("{path}?bogus=1")).await, "bogus"),
            (api.get(&format!("{path}?deleted=only")).await, "deleted"),
            (api.post("/addresses?bogus=1", &body(11)).await, "bogus"),
            (
                api.post("/addresses?cascade=true", &body(11)).await,
                "cascade",
            ),
            (
                api.patch(&format!("{path}?cascade=true"), None, &json!({}))
                    .await,
                "cascade",
            ),
            (
                api.delete(&format!("{path}?cascade=true"), None).await,
                "cascade",
            ),
            (
                api.delete(&format!("{path}?dry_run=maybe"), None).await,
                "dry_run",
            ),
        ];
        for (reply, parameter) in replies {
            reply.assert_problem(400, "sys.invalid_query");
            assert_eq!(reply.body["params"]["parameter"], parameter);
        }
        assert_eq!(api.get("/addresses").await.items().len(), 1);
        assert_eq!(api.get(&path).await.body["meta"]["deleted"], Value::Null);
    }

    // Updates.

    #[tokio::test]
    async fn patch_changes_the_address_and_moves_the_etag() {
        let (api, _) = api_with_network().await;
        let created = api.post("/addresses", &body(10)).await;
        let path = format!("/addresses/{}", created.item_id());
        let changes = json!({
            "status": "deprecated",
            "dns_name": "Gateway.Example.Test",
            "tags": ["edge"],
            "description": "Old gateway",
        });
        let reply = api.patch(&path, created.etag.as_deref(), &changes).await;
        reply.assert_write(200);
        let item = reply.item();
        assert_eq!(item["status"], "deprecated");
        assert_eq!(item["dns_name"], "gateway.example.test");
        assert_eq!(item["meta"]["tags"], json!(["edge"]));
        assert_eq!(item["meta"]["description"], "Old gateway");
        assert_eq!(item["ip"], "192.0.2.10");
        assert!(reply.revision() > created.revision());
        assert_eq!(api.get(&path).await.etag, reply.etag);
        let cleared = api
            .patch(
                &path,
                None,
                &json!({ "dns_name": null, "description": null }),
            )
            .await;
        assert_eq!(cleared.item()["dns_name"], Value::Null);
        assert_eq!(cleared.item()["meta"]["description"], Value::Null);
        assert_eq!(cleared.item()["status"], "deprecated");
        // Nothing to change: the revision stays.
        let same = api
            .patch(&path, None, &json!({ "status": "deprecated" }))
            .await;
        same.assert_json(200);
        assert_eq!(same.body["job_id"], Value::Null);
        assert_eq!(same.etag, cleared.etag);
    }

    #[tokio::test]
    async fn patch_moves_an_address_to_another_ip_and_prefix() {
        let api = Api::new();
        api.make_prefix_as(None, "192.0.2.0/24", Some(PrefixRole::Supernet))
            .await;
        let low = api.make_prefix(None, "192.0.2.0/25").await.to_string();
        let high = api.make_prefix(None, "192.0.2.128/25").await.to_string();
        let created = api.post("/addresses", &body(10)).await;
        assert_eq!(created.item()["prefix"], low);
        let path = format!("/addresses/{}", created.item_id());
        let moved = api.patch(&path, None, &json!({ "ip": ip4(200) })).await;
        moved.assert_write(200);
        assert_eq!(moved.item()["ip"], "192.0.2.200");
        assert_eq!(moved.item()["prefix"], high);
        // The old address is free again.
        api.create("/addresses", &body(10)).await;
    }

    #[tokio::test]
    async fn patch_assigns_and_unassigns_an_interface() {
        let (api, _) = api_with_network().await;
        let (_, interfaces) = make_host(&api, 1, &["eth0"]).await;
        let created = api.post("/addresses", &body(10)).await;
        let path = format!("/addresses/{}", created.item_id());
        let assigned = api
            .patch(&path, None, &json!({ "interface": interfaces[0] }))
            .await;
        assert_eq!(assigned.item()["interface"], interfaces[0]);
        let listed = api
            .get(&format!("/addresses?interface={}", interfaces[0]))
            .await;
        assert_eq!(listed.ids(), [created.item_id()]);
        let missing = api
            .patch(&path, None, &json!({ "interface": unknown_id() }))
            .await;
        missing.assert_problem(409, "ipam.reference_missing");
        assert_eq!(missing.body["params"]["field"], "interface");
        let unassigned = api.patch(&path, None, &json!({ "interface": null })).await;
        assert_eq!(unassigned.item()["interface"], Value::Null);
        let listed = api
            .get(&format!("/addresses?interface={}", interfaces[0]))
            .await;
        listed.assert_no_items();
    }

    #[tokio::test]
    async fn patch_honors_if_match() {
        let (api, _) = api_with_network().await;
        let created = api.post("/addresses", &body(10)).await;
        let path = format!("/addresses/{}", created.item_id());
        let first = api
            .patch(
                &path,
                created.etag.as_deref(),
                &json!({ "dns_name": "one.example.test" }),
            )
            .await;
        first.assert_write(200);
        let stale = api
            .patch(
                &path,
                created.etag.as_deref(),
                &json!({ "dns_name": "two.example.test" }),
            )
            .await;
        stale.assert_problem(412, "ipam.revision_mismatch");
        assert_eq!(stale.body["params"]["kind"], "address");
        assert_eq!(
            stale.body["params"]["expected"],
            created.revision().to_string()
        );
        assert_eq!(stale.body["params"]["actual"], first.revision().to_string());
        api.delete(&path, created.etag.as_deref())
            .await
            .assert_problem(412, "ipam.revision_mismatch");
        for value in ["abc", "\"x\"", "1.5", ""] {
            let reply = api.patch(&path, Some(value), &json!({})).await;
            reply.assert_problem(400, "ipam.validation");
            assert_eq!(reply.body["params"]["field"], "If-Match");
            api.delete(&path, Some(value))
                .await
                .assert_problem(400, "ipam.validation");
        }
        let got = api.get(&path).await;
        assert_eq!(got.etag, first.etag);
        assert_eq!(got.body["dns_name"], "one.example.test");
        assert_eq!(got.body["meta"]["deleted"], Value::Null);
        let weak = format!("W/\"{}\"", first.revision());
        api.patch(
            &path,
            Some(&weak),
            &json!({ "dns_name": "three.example.test" }),
        )
        .await
        .assert_write(200);
    }

    // Dry runs.

    #[tokio::test]
    async fn dry_runs_answer_the_plan_and_write_nothing() {
        let (api, _) = api_with_network().await;
        let create = api.post("/addresses?dry_run=true", &body(10)).await;
        create.assert_dry_run();
        assert_eq!(create.summary_lines(), ["1 address created"]);
        assert_eq!(create.item()["ip"], "192.0.2.10");
        assert_eq!(create.body["plan"]["changes"][0]["action"], "create");
        api.get(&format!("/addresses/{}", create.item_id()))
            .await
            .assert_problem(404, "ipam.not_found");
        api.get("/addresses").await.assert_no_items();

        let created = api.post("/addresses", &body(10)).await;
        let path = format!("/addresses/{}", created.item_id());
        let update = api
            .patch(
                &format!("{path}?dry_run=true"),
                created.etag.as_deref(),
                &json!({ "status": "deprecated" }),
            )
            .await;
        update.assert_dry_run();
        assert_eq!(update.item()["status"], "deprecated");
        assert_eq!(update.summary_lines(), ["1 address updated"]);
        let delete = api.delete(&format!("{path}?dry_run=true"), None).await;
        delete.assert_dry_run();
        assert_eq!(delete.summary_lines(), ["1 address deleted"]);
        assert!(delete.item()["meta"]["deleted"].is_object());
        let got = api.get(&path).await;
        assert_eq!(got.etag, created.etag);
        assert_eq!(got.body["status"], "active");
        assert_eq!(got.body["meta"]["deleted"], Value::Null);
        // A dry run reports conflicts like the real write.
        api.post("/addresses?dry_run=true", &body(10))
            .await
            .assert_problem(409, "ipam.address.duplicate");
    }

    // Conflicts and references.

    #[tokio::test]
    async fn a_duplicate_address_in_a_vrf_is_a_409() {
        let (api, _) = api_with_network().await;
        make_address(&api, 10).await;
        let duplicate = api.post("/addresses", &body(10)).await;
        duplicate.assert_problem(409, "ipam.address.duplicate");
        assert_eq!(duplicate.body["params"]["ip"], "192.0.2.10");
        assert_eq!(duplicate.body["errors"][0]["field"], "ip");
        let other = make_address(&api, 11).await;
        let moved = api
            .patch(
                &format!("/addresses/{other}"),
                None,
                &json!({ "ip": ip4(10) }),
            )
            .await;
        moved.assert_problem(409, "ipam.address.duplicate");
        assert_eq!(api.get("/addresses").await.items().len(), 2);
    }

    #[tokio::test]
    async fn an_address_outside_every_prefix_is_a_409() {
        let (api, _) = api_with_network().await;
        let outside = json!({ "ip": "198.51.100.5" });
        let reply = api.post("/addresses", &outside).await;
        reply.assert_problem(409, "ipam.address.no_prefix");
        assert_eq!(reply.body["params"]["ip"], "198.51.100.5");
        let id = make_address(&api, 10).await;
        api.patch(
            &format!("/addresses/{id}"),
            None,
            &json!({ "ip": "198.51.100.5" }),
        )
        .await
        .assert_problem(409, "ipam.address.no_prefix");
        // The prefix exists in another VRF only.
        let vrf = api
            .create("/vrfs", &json!({ "name": label("vrf", 1) }))
            .await;
        let other = json!({ "ip": ip4(30), "vrf": vrf["id"] });
        api.post("/addresses", &other)
            .await
            .assert_problem(409, "ipam.address.no_prefix");
        assert_eq!(api.get("/addresses").await.items().len(), 1);
    }

    #[tokio::test]
    async fn the_network_and_broadcast_addresses_are_refused() {
        let (api, _) = api_with_network().await;
        for host_part in [0, 255] {
            let reply = api.post("/addresses", &body(host_part)).await;
            reply.assert_problem(409, "ipam.address.network_or_broadcast");
            assert_eq!(reply.body["params"]["cidr"], "192.0.2.0/24");
        }
        api.get("/addresses").await.assert_no_items();
    }

    #[tokio::test]
    async fn references_must_exist_and_ids_must_be_free() {
        let (api, _) = api_with_network().await;
        let missing = unknown_id();
        let cases = [
            (json!({ "ip": ip4(10), "vrf": missing }), "vrf"),
            (json!({ "ip": ip4(10), "interface": missing }), "interface"),
        ];
        for (input, field) in cases {
            let reply = api.post("/addresses", &input).await;
            reply.assert_problem(409, "ipam.reference_missing");
            assert_eq!(reply.body["params"]["field"], field);
            assert_eq!(reply.body["params"]["id"], missing);
        }
        let id = unknown_id();
        let first = json!({ "id": id, "ip": ip4(10) });
        api.post("/addresses", &first).await.assert_write(201);
        let again = json!({ "id": id, "ip": ip4(11) });
        api.post("/addresses", &again)
            .await
            .assert_problem(409, "ipam.id_taken");
        assert_eq!(api.get("/addresses").await.items().len(), 1);
    }

    #[tokio::test]
    async fn the_status_follows_the_allowed_transitions() {
        let (api, _) = api_with_network().await;
        let id = make_address(&api, 10).await;
        let path = format!("/addresses/{id}");
        let back = api
            .patch(&path, None, &json!({ "status": "planned" }))
            .await;
        back.assert_problem(409, "ipam.status.transition");
        assert_eq!(back.body["params"]["from"], "active");
        assert_eq!(back.body["params"]["to"], "planned");
        assert_eq!(back.body["errors"][0]["field"], "status");
        api.patch(&path, None, &json!({ "status": "deprecated" }))
            .await
            .assert_write(200);
    }

    #[tokio::test]
    async fn a_body_that_does_not_fit_is_a_400_problem() {
        let (api, _) = api_with_network().await;
        for bad in [
            json!({}),
            json!({ "ip": "not-an-address" }),
            json!({ "ip": ip4(10), "dns_name": "x" }),
            json!({ "ip": ip4(10), "status": "asleep" }),
        ] {
            let reply = api.post("/addresses", &bad).await;
            reply.assert_problem(400, "sys.invalid_request");
        }
        let plain = api
            .send_text("POST", "/addresses", "text/plain", "192.0.2.10")
            .await;
        plain.assert_problem(415, "sys.invalid_request");
        let created = api.post("/addresses", &body(10)).await;
        let path = format!("/addresses/{}", created.item_id());
        let rejected = api
            .send_text(
                "PATCH",
                &path,
                "application/json",
                "{\"status\": \"asleep\"}",
            )
            .await;
        rejected.assert_problem(400, "sys.invalid_request");
        assert!(
            rejected.body["detail"]
                .as_str()
                .expect("detail")
                .contains("asleep")
        );
        assert_eq!(api.get(&path).await.etag, created.etag);
        assert_eq!(api.get("/addresses").await.items().len(), 1);
    }

    #[tokio::test]
    async fn an_unknown_member_in_the_body_is_a_400_problem() {
        let (api, _) = api_with_network().await;
        let created = api.post("/addresses", &body(10)).await;
        let path = format!("/addresses/{}", created.item_id());
        let colour = api
            .post("/addresses", &json!({ "ip": ip4(11), "colour": "red" }))
            .await;
        colour.assert_problem(400, "sys.invalid_request");
        assert_eq!(colour.body["params"]["part"], "body");
        // The VRF of an address cannot change: it is refused rather than ignored.
        let moved = api
            .patch(&path, None, &json!({ "vrf": unknown_id() }))
            .await;
        moved.assert_problem(400, "sys.invalid_request");
        assert_eq!(moved.body["params"]["part"], "body");
        assert_eq!(api.get(&path).await.etag, created.etag);
        assert_eq!(api.get("/addresses").await.items().len(), 1);
    }

    // Warnings and the DHCP pool rule.

    #[tokio::test]
    async fn an_address_directly_in_a_supernet_is_created_with_a_warning() {
        let api = Api::new();
        api.make_prefix_as(None, "192.0.2.0/24", Some(PrefixRole::Supernet))
            .await;
        let reply = api.post("/addresses", &body(10)).await;
        reply.assert_write(201);
        let warnings = reply.body["warnings"].as_array().expect("warnings");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert_eq!(warnings[0]["code"], "ipam.address.in_supernet");
        assert_eq!(warnings[0]["requires_ack"], false);
        let dry = api.post("/addresses?dry_run=true", &body(11)).await;
        assert_eq!(dry.body["warnings"][0]["code"], "ipam.address.in_supernet");
        assert_eq!(
            dry.body["plan"]["summary"]["warnings"]["ipam.address.in_supernet"],
            1
        );
        // Acknowledging a warning that does not need it does no harm.
        let acknowledged = api
            .post("/addresses?acknowledge=ipam.address.in_supernet", &body(12))
            .await;
        acknowledged.assert_write(201);
    }

    #[tokio::test]
    async fn a_reservation_inside_a_dhcp_pool_is_refused() {
        let (api, prefix) = api_with_network().await;
        let prefix_id = prefix.parse().expect("prefix id");
        api.make_range(prefix_id, "192.0.2.100", "192.0.2.199", RangeRole::DhcpPool)
            .await;
        // An address of nobody in the pool is allowed, with a warning.
        let plain = api.post("/addresses", &body(150)).await;
        plain.assert_write(201);
        assert_eq!(
            plain.body["warnings"][0]["code"],
            "ipam.address.in_dhcp_pool"
        );
        // A reserved host may not have its address there.
        let reserved = json!({
            "name": label("host", 1),
            "mode": "reserved",
            "interfaces": [{ "name": "eth0", "mac": "00-00-5E-00-53-01" }],
        });
        let host = api.create("/hosts", &reserved).await;
        let interfaces = api
            .get(&format!("/hosts/{}/interfaces", id_of(&host)))
            .await;
        let interface = interfaces.ids()[0].clone();
        let inside = json!({ "ip": ip4(160), "interface": interface });
        let refused = api.post("/addresses", &inside).await;
        refused.assert_problem(409, "ipam.address.in_dhcp_pool");
        assert_eq!(refused.body["params"]["ip"], "192.0.2.160");
        assert_eq!(refused.body["params"]["range"], "192.0.2.100-192.0.2.199");
        let outside = json!({ "ip": ip4(50), "interface": interface });
        let created = api.post("/addresses", &outside).await;
        created.assert_write(201);
        assert_eq!(created.body["warnings"], json!([]));
        // Moving it into the pool is refused as well.
        let id = created.item_id();
        api.patch(
            &format!("/addresses/{id}"),
            None,
            &json!({ "ip": ip4(170) }),
        )
        .await
        .assert_problem(409, "ipam.address.in_dhcp_pool");
    }

    // Deletes.

    #[tokio::test]
    async fn delete_soft_deletes_the_address_and_frees_it() {
        let (api, _) = api_with_network().await;
        let created = api.post("/addresses", &body(10)).await;
        let path = format!("/addresses/{}", created.item_id());
        let reply = api.delete(&path, created.etag.as_deref()).await;
        reply.assert_write(200);
        assert!(reply.item()["meta"]["deleted"]["at"].is_string());
        assert!(reply.revision() > created.revision());
        let got = api.get(&path).await;
        got.assert_json(200);
        assert_eq!(got.etag, reply.etag);
        assert_eq!(&got.body, reply.item());
        api.get("/addresses").await.assert_no_items();
        // Deleted twice, or changed after the delete.
        api.delete(&path, None)
            .await
            .assert_problem(409, "ipam.object_deleted");
        api.patch(&path, None, &json!({ "dns_name": "x.example.test" }))
            .await
            .assert_problem(409, "ipam.object_deleted");
        // The place is free again.
        let again = api.post("/addresses", &body(10)).await;
        again.assert_write(201);
        assert_ne!(again.item_id(), created.item_id());
    }

    // Idempotency.

    #[tokio::test]
    async fn a_repeated_idempotency_key_returns_the_first_address() {
        let (api, _) = api_with_network().await;
        let headers = [("idempotency-key", "address-create-1")];
        let first = api.post_with("/addresses", &headers, &body(10)).await;
        first.assert_write(201);
        let replay = api.post_with("/addresses", &headers, &body(10)).await;
        replay.assert_json(200);
        assert_eq!(replay.body["replayed"], true);
        assert_eq!(replay.body["job_id"], Value::Null);
        assert_eq!(replay.body["revision"], first.body["revision"]);
        assert_eq!(replay.item(), first.item());
        assert_eq!(replay.etag, first.etag);
        assert_eq!(api.get("/addresses").await.items().len(), 1);
        let other = api.post_with("/addresses", &headers, &body(11)).await;
        other.assert_problem(422, "ipam.idempotency_mismatch");
        assert_eq!(api.get("/addresses").await.items().len(), 1);
        // Another key makes another address, and the first duplicate is still a conflict.
        let fresh = [("idempotency-key", "address-create-2")];
        api.post_with("/addresses", &fresh, &body(10))
            .await
            .assert_problem(409, "ipam.address.duplicate");
    }

    // Availability and authorization.

    #[tokio::test]
    async fn without_the_ipam_service_every_endpoint_is_a_503() {
        let api = Api::unavailable();
        let path = format!("/addresses/{}", unknown_id());
        let replies = [
            api.get("/addresses").await,
            api.post("/addresses", &body(10)).await,
            api.get(&path).await,
            api.patch(&path, None, &json!({})).await,
            api.delete(&path, None).await,
        ];
        for reply in replies {
            reply.assert_problem(503, "ipam.unavailable");
        }
    }

    #[tokio::test]
    async fn a_principal_that_may_do_nothing_gets_403_on_writes_and_empty_lists() {
        let (api, _) = api_with_network().await;
        let created = api.post("/addresses", &body(10)).await;
        let path = format!("/addresses/{}", created.item_id());
        let denied = api.sibling(AppState {
            authorizer: Some(Policy::new(false, false)),
            ..AppState::default()
        });
        let list = denied.get("/addresses").await;
        list.assert_json(200);
        assert_eq!(list.body["items"], json!([]));
        assert_eq!(list.body["next_cursor"], Value::Null);
        assert!(list.body["revision"].is_u64());
        let replies = [
            (denied.get(&path).await, "read"),
            (denied.post("/addresses", &body(11)).await, "create"),
            (
                denied.post("/addresses?dry_run=true", &body(11)).await,
                "create",
            ),
            (
                denied
                    .patch(&path, None, &json!({ "dns_name": null }))
                    .await,
                "update",
            ),
            (denied.delete(&path, None).await, "delete"),
        ];
        for (reply, action) in replies {
            reply.assert_problem(403, "auth.forbidden");
            assert_eq!(reply.body["params"]["action"], action);
            assert_eq!(reply.body["params"]["kind"], "address");
        }
        let got = api.get(&path).await;
        assert_eq!(got.etag, created.etag);
        assert_eq!(api.get("/addresses").await.items().len(), 1);
    }

    #[tokio::test]
    async fn a_read_only_principal_reads_addresses_and_cannot_write() {
        let (api, _) = api_with_network().await;
        let created = api.post("/addresses", &body(10)).await;
        let reader = api.sibling(AppState {
            authorizer: Some(Policy::new(true, false)),
            ..AppState::default()
        });
        assert_eq!(reader.get("/addresses").await.items().len(), 1);
        let path = format!("/addresses/{}", created.item_id());
        assert_eq!(reader.get(&path).await.etag, created.etag);
        reader
            .post("/addresses", &body(11))
            .await
            .assert_problem(403, "auth.forbidden");
        reader
            .delete(&path, None)
            .await
            .assert_problem(403, "auth.forbidden");
    }

    #[tokio::test]
    async fn each_endpoint_asks_for_the_action_on_the_object() {
        let policy = Policy::new(true, true);
        let api = Api::with_authorizer(policy.clone());
        api.make_prefix(None, "192.0.2.0/24").await;
        let created = api.post("/addresses", &body(10)).await;
        let id: AddressId = created.item_id().parse().expect("address id");
        let object = ObjectRef::from(id);
        let path = format!("/addresses/{id}");
        api.get(&path).await.assert_json(200);
        api.patch(&path, None, &json!({ "dns_name": "a.example.test" }))
            .await
            .assert_write(200);
        api.delete(&path, None).await.assert_write(200);
        assert_eq!(
            policy.asked(),
            [
                (Action::Create, ObjectRef::singleton(ObjectKind::Address)),
                (Action::Read, object),
                (Action::Update, object),
                (Action::Delete, object),
            ]
        );
    }

    // Locks.

    #[tokio::test]
    async fn automation_cannot_touch_the_addresses_of_a_locked_host() {
        let (api, _) = api_with_network().await;
        let locked = json!({
            "name": label("host", 1),
            "lock": true,
            "interfaces": [{ "name": "eth0" }],
        });
        let host = id_of(&api.create("/hosts", &locked).await);
        let interface = api.get(&format!("/hosts/{host}/interfaces")).await.ids()[0].clone();
        // People may assign addresses to a locked host.
        let input = json!({ "ip": ip4(10), "interface": interface });
        let created = api.post("/addresses", &input).await;
        created.assert_write(201);
        let path = format!("/addresses/{}", created.item_id());
        let robot = api.as_automation();
        let more = json!({ "ip": ip4(11), "interface": interface });
        let replies = [
            robot.post("/addresses", &more).await,
            robot
                .patch(&path, None, &json!({ "dns_name": "x.example.test" }))
                .await,
            robot.delete(&path, None).await,
        ];
        for reply in replies {
            reply.assert_problem(423, "ipam.host.locked");
            assert_eq!(reply.body["params"]["host"], label("host", 1));
        }
        // An address of nobody is not locked, and reads are always fine.
        robot.post("/addresses", &body(12)).await.assert_write(201);
        robot.get(&path).await.assert_json(200);
        let got = api.get(&path).await;
        assert_eq!(got.etag, created.etag);
        assert_eq!(api.get("/addresses").await.items().len(), 2);
    }
}
