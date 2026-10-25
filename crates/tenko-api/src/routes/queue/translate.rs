//! The IPAM writes the queue takes (ADR 0013 decision 3), and their translation into
//! planner commands exactly as the endpoint itself would build them.
//!
//! Queueable: the creates, changes, deletes, restores and bulk changes of tenants, VRFs,
//! sites, VLANs, prefixes, ranges, addresses, hosts and interfaces. Not queueable: next-free
//! allocations (their outcome depends on what the cluster allocated meanwhile), custom
//! fields, moves, proposals, adoption policies, VLAN provisioning, imports and every
//! non-IPAM write.

use axum::http::{HeaderMap, HeaderValue, Method, Uri, header};
use serde::de::DeserializeOwned;
use tenko_core::{
    AddressId, HostId, InterfaceId, ObjectKind, ObjectRef, PrefixId, RangeId, SiteId, TenantId,
    VlanId, VrfId,
};
use tenko_ipam::{
    IpamCommand, IpamError, PlanOptions,
    command::{
        AddressInput, AddressPatch, HostInput, HostPatch, InterfaceInput, InterfacePatch,
        PrefixInput, PrefixPatch, RangeInput, RangePatch, SiteInput, SitePatch, TenantInput,
        TenantPatch, UpdateAddress, UpdateHost, UpdateInterface, UpdatePrefix, UpdateRange,
        UpdateSite, UpdateTenant, UpdateVlan, UpdateVrf, VlanInput, VlanPatch, VrfInput, VrfPatch,
    },
    queue::{QueuedRequest, SummaryAction, codes},
};

use crate::{
    API_BASE,
    list::Filters,
    problem::ApiError,
    routes::{
        common::{BulkRequest, if_match, write_args},
        prefixes::NewRange,
    },
};

/// The collections whose writes can be queued, with their object kinds.
const COLLECTIONS: [(&str, ObjectKind); 9] = [
    ("tenants", ObjectKind::Tenant),
    ("vrfs", ObjectKind::Vrf),
    ("sites", ObjectKind::Site),
    ("vlans", ObjectKind::Vlan),
    ("prefixes", ObjectKind::Prefix),
    ("ranges", ObjectKind::Range),
    ("addresses", ObjectKind::Address),
    ("hosts", ObjectKind::Host),
    ("interfaces", ObjectKind::Interface),
];

/// Collections with a `POST /{collection}` create.
const CREATES: [&str; 7] = [
    "tenants",
    "vrfs",
    "sites",
    "vlans",
    "prefixes",
    "addresses",
    "hosts",
];

/// Collections whose delete takes `cascade`.
const CASCADES: [&str; 3] = ["prefixes", "hosts", "interfaces"];

/// One queueable operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Create(ObjectKind),
    Update(ObjectKind),
    Delete(ObjectKind, bool),
    Restore(ObjectKind),
    Bulk(ObjectKind),
    CreateRange,
    CreateInterface,
}

/// The planner commands of a request.
#[derive(Debug, Clone)]
pub(crate) struct Translated {
    /// The commands, creates with their identifiers chosen.
    pub(crate) commands: Vec<IpamCommand>,
    /// The acknowledged warnings.
    pub(crate) options: PlanOptions,
    /// What the request does.
    pub(crate) action: SummaryAction,
    /// The collection's kind.
    pub(crate) kind: ObjectKind,
    /// The path relative to the API base, normalized.
    pub(crate) path: String,
}

fn kind_of(collection: &str) -> Option<ObjectKind> {
    COLLECTIONS
        .iter()
        .find(|(name, _)| *name == collection)
        .map(|(_, kind)| *kind)
}

/// The shape of a request: the method and the path segments, where `{id}` in a template
/// matches any segment.
fn shape(method: &Method, segments: &[&str]) -> Option<Shape> {
    match (method.as_str(), segments) {
        ("POST", [collection]) if CREATES.contains(collection) => {
            kind_of(collection).map(Shape::Create)
        }
        ("POST", [collection, "bulk"]) => kind_of(collection).map(Shape::Bulk),
        ("POST", ["prefixes", _, "ranges"]) => Some(Shape::CreateRange),
        ("POST", ["hosts", _, "interfaces"]) => Some(Shape::CreateInterface),
        ("POST", [collection, _, "restore"]) => kind_of(collection).map(Shape::Restore),
        ("PATCH", [collection, _]) if *collection != "custom-fields" => {
            kind_of(collection).map(Shape::Update)
        }
        ("DELETE", [collection, _]) => {
            kind_of(collection).map(|kind| Shape::Delete(kind, CASCADES.contains(collection)))
        }
        _ => None,
    }
}

/// The segments of a path relative to the API base.
fn segments(path: &str) -> Vec<&str> {
    let path = path.strip_prefix(API_BASE).unwrap_or(path);
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

/// Whether `POST /queue` takes requests to `template` (a route template relative to the
/// API base, as the router matched it) with `method`.
pub(crate) fn queueable(method: &Method, template: &str) -> bool {
    shape(method, &segments(template)).is_some()
}

/// Whether `template` is an operation of the local queue, which writes nothing to the
/// store: queueing and withdrawing.
pub(crate) fn local(method: &Method, template: &str) -> bool {
    matches!(
        (method.as_str(), segments(template).as_slice()),
        ("POST", ["queue"]) | ("DELETE", ["queue", "{id}"])
    )
}

fn not_queueable(detail: impl Into<String>) -> ApiError {
    IpamError::new(codes::NOT_QUEUEABLE, 422, detail)
        .titled("This change cannot be queued")
        .into()
}

/// Translates a request into the commands its endpoint would plan.
///
/// # Errors
///
/// 422 `queue.not_queueable` for a request the queue does not take (another method or
/// path, a dry run, an allocation), and the errors the endpoint itself gives for its query
/// parameters, `If-Match` and body.
pub(crate) fn translate(request: &QueuedRequest) -> Result<Translated, ApiError> {
    let method = Method::from_bytes(request.method.trim().to_ascii_uppercase().as_bytes())
        .map_err(|_| not_queueable(format!("`{}` is not an HTTP method", request.method)))?;
    let path = request.path.split('?').next().unwrap_or_default();
    let parts = segments(path);
    let Some(shape) = shape(&method, &parts) else {
        return Err(not_queueable(format!(
            "{method} {path} cannot be queued: only creates, changes, deletes, restores and bulk \
             changes of tenants, VRFs, sites, VLANs, prefixes, ranges, addresses, hosts and \
             interfaces can"
        )));
    };
    let filters = filters(request.query.as_deref())?;
    let allow_cascade = matches!(shape, Shape::Delete(_, true));
    let args = write_args(&filters, allow_cascade)?;
    if args.dry_run {
        return Err(not_queueable(
            "a dry run writes nothing and is not queued: send it to the endpoint itself",
        ));
    }
    let expected = if_match(&if_match_headers(request.if_match.as_deref())?)?;
    let id = parts.get(1).copied().unwrap_or_default();
    let body = request.body.clone();
    let (commands, action, kind) = match shape {
        Shape::Create(kind) => (vec![create(kind, body)?], SummaryAction::Create, kind),
        Shape::Update(kind) => (
            vec![update(kind, id, expected, body)?],
            SummaryAction::Update,
            kind,
        ),
        Shape::Delete(kind, _) => (
            vec![IpamCommand::Delete {
                object: object(kind, id)?,
                expected,
                cascade: args.cascade,
            }],
            SummaryAction::Delete,
            kind,
        ),
        Shape::Restore(kind) => (
            vec![IpamCommand::Restore {
                object: object(kind, id)?,
                expected,
            }],
            SummaryAction::Restore,
            kind,
        ),
        Shape::Bulk(kind) => (bulk(kind, body)?, SummaryAction::Bulk, kind),
        Shape::CreateRange => {
            let prefix: PrefixId = parse_id(id)?;
            let range: NewRange = parse_body(body)?;
            let command = IpamCommand::CreateRange(RangeInput {
                id: range.id,
                prefix,
                first: range.first,
                last: range.last,
                role: range.role,
                status: range.status,
                lease_secs: range.lease_secs,
                delegated_len: range.delegated_len,
                tags: range.tags,
                custom: range.custom,
                description: range.description,
            });
            (vec![command], SummaryAction::Create, ObjectKind::Range)
        }
        Shape::CreateInterface => {
            let host: HostId = parse_id(id)?;
            let mut input: InterfaceInput = parse_body(body)?;
            if input.host.is_some_and(|named| named != host) {
                return Err(IpamError::invalid(
                    "host",
                    format!(
                        "the interface is added to host {host}, but the body names another host"
                    ),
                )
                .into());
            }
            input.host = Some(host);
            (
                vec![IpamCommand::CreateInterface(input)],
                SummaryAction::Create,
                ObjectKind::Interface,
            )
        }
    };
    let mut commands = commands;
    for command in &mut commands {
        pin(command);
    }
    Ok(Translated {
        commands,
        options: args.options,
        action,
        kind,
        path: format!("/{}", parts.join("/")),
    })
}

fn filters(query: Option<&str>) -> Result<Filters, ApiError> {
    let query = query.unwrap_or_default().trim_start_matches('?');
    if query.is_empty() {
        return Ok(Filters::from_pairs(std::iter::empty::<(String, String)>()));
    }
    let uri: Uri = format!("/?{query}")
        .parse()
        .map_err(|_| ApiError::invalid_query("query", "not a query string"))?;
    Filters::from_uri(&uri)
}

fn if_match_headers(value: Option<&str>) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        let value = HeaderValue::from_str(value)
            .map_err(|_| IpamError::invalid("if_match", "not a header value"))?;
        headers.insert(header::IF_MATCH, value);
    }
    Ok(headers)
}

fn parse_body<T: DeserializeOwned>(body: Option<serde_json::Value>) -> Result<T, ApiError> {
    let body = body.unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
    serde_json::from_value(body).map_err(|error| {
        IpamError::invalid(
            "body",
            format!("the body does not fit the endpoint: {error}"),
        )
        .into()
    })
}

fn parse_id<T: std::str::FromStr>(text: &str) -> Result<T, ApiError> {
    text.parse::<T>()
        .map_err(|_| IpamError::invalid("path", format!("`{text}` is not an identifier")).into())
}

fn object(kind: ObjectKind, id: &str) -> Result<ObjectRef, ApiError> {
    let id: uuid::Uuid = parse_id(id)?;
    Ok(ObjectRef::new(kind, id))
}

fn create(kind: ObjectKind, body: Option<serde_json::Value>) -> Result<IpamCommand, ApiError> {
    Ok(match kind {
        ObjectKind::Tenant => IpamCommand::CreateTenant(parse_body::<TenantInput>(body)?),
        ObjectKind::Vrf => IpamCommand::CreateVrf(parse_body::<VrfInput>(body)?),
        ObjectKind::Site => IpamCommand::CreateSite(parse_body::<SiteInput>(body)?),
        ObjectKind::Vlan => IpamCommand::CreateVlan(parse_body::<VlanInput>(body)?),
        ObjectKind::Prefix => IpamCommand::CreatePrefix(parse_body::<PrefixInput>(body)?),
        ObjectKind::Address => IpamCommand::CreateAddress(parse_body::<AddressInput>(body)?),
        ObjectKind::Host => IpamCommand::CreateHost(parse_body::<HostInput>(body)?),
        other => return Err(not_queueable(format!("a {other} cannot be created here"))),
    })
}

fn update(
    kind: ObjectKind,
    id: &str,
    expected: Option<tenko_core::Revision>,
    body: Option<serde_json::Value>,
) -> Result<IpamCommand, ApiError> {
    Ok(match kind {
        ObjectKind::Tenant => IpamCommand::UpdateTenant(UpdateTenant {
            id: parse_id::<TenantId>(id)?,
            expected,
            patch: parse_body::<TenantPatch>(body)?,
        }),
        ObjectKind::Vrf => IpamCommand::UpdateVrf(UpdateVrf {
            id: parse_id::<VrfId>(id)?,
            expected,
            patch: parse_body::<VrfPatch>(body)?,
        }),
        ObjectKind::Site => IpamCommand::UpdateSite(UpdateSite {
            id: parse_id::<SiteId>(id)?,
            expected,
            patch: parse_body::<SitePatch>(body)?,
        }),
        ObjectKind::Vlan => IpamCommand::UpdateVlan(UpdateVlan {
            id: parse_id::<VlanId>(id)?,
            expected,
            patch: parse_body::<VlanPatch>(body)?,
        }),
        ObjectKind::Prefix => IpamCommand::UpdatePrefix(UpdatePrefix {
            id: parse_id::<PrefixId>(id)?,
            expected,
            patch: parse_body::<PrefixPatch>(body)?,
        }),
        ObjectKind::Range => IpamCommand::UpdateRange(UpdateRange {
            id: parse_id::<RangeId>(id)?,
            expected,
            patch: parse_body::<RangePatch>(body)?,
        }),
        ObjectKind::Address => IpamCommand::UpdateAddress(UpdateAddress {
            id: parse_id::<AddressId>(id)?,
            expected,
            patch: parse_body::<AddressPatch>(body)?,
        }),
        ObjectKind::Host => IpamCommand::UpdateHost(UpdateHost {
            id: parse_id::<HostId>(id)?,
            expected,
            patch: parse_body::<HostPatch>(body)?,
        }),
        ObjectKind::Interface => IpamCommand::UpdateInterface(UpdateInterface {
            id: parse_id::<InterfaceId>(id)?,
            expected,
            patch: parse_body::<InterfacePatch>(body)?,
        }),
        other => return Err(not_queueable(format!("a {other} cannot be changed here"))),
    })
}

/// The operations of a bulk body, checked as the bulk endpoint checks them, without
/// allocations.
fn bulk(kind: ObjectKind, body: Option<serde_json::Value>) -> Result<Vec<IpamCommand>, ApiError> {
    let request: BulkRequest = parse_body(body)?;
    for (index, operation) in request.operations.iter().enumerate() {
        let accepted = operation.kind() == kind
            || (kind == ObjectKind::Host
                && matches!(
                    operation,
                    IpamCommand::CreateInterface(_) | IpamCommand::CreateAddress(_)
                ));
        if matches!(
            operation,
            IpamCommand::AllocateAddress(_) | IpamCommand::AllocatePrefix(_)
        ) {
            return Err(not_queueable(format!(
                "operation {index} allocates the next free address or prefix, which depends on \
                 what the cluster allocated meanwhile: allocations cannot be queued"
            )));
        }
        if matches!(
            operation,
            IpamCommand::CreateCustomField(_)
                | IpamCommand::UpdateCustomField(_)
                | IpamCommand::DeleteCustomField { .. }
                | IpamCommand::SetLock { .. }
                | IpamCommand::SetMode { .. }
        ) || !accepted
        {
            return Err(not_queueable(format!(
                "operation {index} changes a {}, which the bulk endpoint of {kind}s does not take \
                 in a queued change",
                operation.kind()
            )));
        }
    }
    Ok(request.operations)
}

/// Chooses the identifier of an object the command creates, so the plan after the heal
/// creates the same object the queued plan showed.
fn pin(command: &mut IpamCommand) {
    match command {
        IpamCommand::CreateTenant(input) => {
            input.id.get_or_insert_with(TenantId::generate);
        }
        IpamCommand::CreateVrf(input) => {
            input.id.get_or_insert_with(VrfId::generate);
        }
        IpamCommand::CreateSite(input) => {
            input.id.get_or_insert_with(SiteId::generate);
        }
        IpamCommand::CreateVlan(input) => {
            input.id.get_or_insert_with(VlanId::generate);
        }
        IpamCommand::CreatePrefix(input) => {
            input.id.get_or_insert_with(PrefixId::generate);
        }
        IpamCommand::CreateRange(input) => {
            input.id.get_or_insert_with(RangeId::generate);
        }
        IpamCommand::CreateAddress(input) => {
            input.id.get_or_insert_with(AddressId::generate);
        }
        IpamCommand::CreateHost(input) => {
            input.id.get_or_insert_with(HostId::generate);
        }
        IpamCommand::CreateInterface(input) => {
            input.id.get_or_insert_with(InterfaceId::generate);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn request(method: &str, path: &str, body: Option<serde_json::Value>) -> QueuedRequest {
        QueuedRequest {
            method: method.to_owned(),
            path: path.to_owned(),
            query: None,
            body,
            if_match: None,
        }
    }

    #[test]
    fn the_queueable_templates_are_the_ipam_intent_writes() {
        for (method, template) in [
            (Method::POST, "/addresses"),
            (Method::POST, "/api/v1/hosts"),
            (Method::PATCH, "/addresses/{id}"),
            (Method::DELETE, "/prefixes/{id}"),
            (Method::POST, "/vrfs/{id}/restore"),
            (Method::POST, "/interfaces/bulk"),
            (Method::POST, "/prefixes/{id}/ranges"),
            (Method::POST, "/hosts/{id}/interfaces"),
        ] {
            assert!(queueable(&method, template), "{method} {template}");
        }
        for (method, template) in [
            (Method::POST, "/prefixes/{id}/next-free-address"),
            (Method::POST, "/prefixes/{id}/next-free-prefix"),
            (Method::POST, "/custom-fields"),
            (Method::PATCH, "/custom-fields/{key}"),
            (Method::POST, "/moves"),
            (Method::POST, "/users"),
            (Method::POST, "/imports"),
            (Method::PUT, "/prefixes/{id}/adoption"),
            (Method::POST, "/vlans/provision"),
            (Method::POST, "/proposals/{id}/approve"),
            (Method::GET, "/addresses"),
        ] {
            assert!(!queueable(&method, template), "{method} {template}");
        }
    }

    #[test]
    fn only_queueing_and_withdrawing_are_local() {
        assert!(local(&Method::POST, "/queue"));
        assert!(local(&Method::DELETE, "/api/v1/queue/{id}"));
        assert!(!local(&Method::POST, "/queue/conflicts/{id}/reapply"));
        assert!(!local(&Method::DELETE, "/queue/conflicts/{id}"));
    }

    #[test]
    fn a_change_carries_its_if_match_and_acknowledgements() {
        let id = AddressId::generate();
        let mut queued = request(
            "patch",
            &format!("/api/v1/addresses/{id}"),
            Some(json!({ "status": "reserved" })),
        );
        queued.if_match = Some("\"12\"".to_owned());
        queued.query = Some("acknowledge=ipam.address.in_supernet".to_owned());
        let translated = translate(&queued).expect("queueable");
        assert_eq!(translated.action, SummaryAction::Update);
        assert_eq!(translated.kind, ObjectKind::Address);
        assert_eq!(translated.path, format!("/addresses/{id}"));
        assert!(
            translated
                .options
                .acknowledge
                .contains("ipam.address.in_supernet")
        );
        let [IpamCommand::UpdateAddress(update)] = translated.commands.as_slice() else {
            panic!("one address update: {:?}", translated.commands);
        };
        assert_eq!(update.id, id);
        assert_eq!(update.expected, Some(tenko_core::Revision(12)));
    }

    #[test]
    fn creates_get_their_identifiers_at_queue_time() {
        let translated = translate(&request(
            "POST",
            "/addresses",
            Some(json!({ "ip": "192.0.2.10" })),
        ))
        .expect("queueable");
        let [IpamCommand::CreateAddress(input)] = translated.commands.as_slice() else {
            panic!("one address create");
        };
        assert!(input.id.is_some());
    }

    #[test]
    fn dry_runs_allocations_and_other_paths_are_refused() {
        let mut dry = request("DELETE", &format!("/hosts/{}", HostId::generate()), None);
        dry.query = Some("dry_run=true".to_owned());
        for queued in [
            dry,
            request("POST", "/users", Some(json!({}))),
            request(
                "POST",
                &format!("/prefixes/{}/next-free-address", PrefixId::generate()),
                None,
            ),
            request(
                "POST",
                "/hosts/bulk",
                Some(json!({ "operations": [{ "op": "allocate_address", "args": {
                    "prefix": PrefixId::generate().to_string()
                } }] })),
            ),
        ] {
            let error = translate(&queued).expect_err("not queueable");
            assert_eq!(error.coded_error().code, codes::NOT_QUEUEABLE, "{queued:?}");
        }
    }

    #[test]
    fn a_cascade_is_kept_where_the_endpoint_takes_one() {
        let mut queued = request(
            "DELETE",
            &format!("/prefixes/{}", PrefixId::generate()),
            None,
        );
        queued.query = Some("cascade=true".to_owned());
        let translated = translate(&queued).expect("queueable");
        assert!(matches!(
            translated.commands.as_slice(),
            [IpamCommand::Delete { cascade: true, .. }]
        ));
        let mut tenant = request(
            "DELETE",
            &format!("/tenants/{}", TenantId::generate()),
            None,
        );
        tenant.query = Some("cascade=true".to_owned());
        assert!(translate(&tenant).is_err(), "tenants take no cascade");
    }
}
