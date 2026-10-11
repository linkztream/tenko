//! CSV export in the import vocabulary.
//!
//! Area: export. Owner: WP1.5. Requirements: IPAM-11, MIG-14.
//!
//! The exported columns use the names the importer suggests, so an export can be imported
//! again without changes (the round trip of IPAM-11).
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /exports/prefixes.csv` | 200 `text/csv` | 400 `sys.invalid_query`, 403 `auth.forbidden`, 503 `ipam.unavailable` |
//! | `GET /exports/addresses.csv` | 200 `text/csv` | as above |
//! | `GET /exports/hosts.csv` | 200 `text/csv` | as above |
//!
//! # Files
//!
//! Each file is UTF-8 with a byte order mark (so Excel opens it as UTF-8), comma separated,
//! with CRLF line ends and the header line first. The columns, their order and the
//! escaping of cells that a spreadsheet would read as formulas are described in
//! [`tenko_ipam::export`]. Credentials are never exported, and soft-deleted objects are
//! left out.
//!
//! # Streaming
//!
//! The body streams from one read view in chunks of up to 1,000 objects, so a large export
//! does not sit in memory: each chunk is produced on the blocking pool when the connection
//! is ready for it. The first chunk is produced before the response starts, so an error
//! there (the store, a custom field definition) is answered as problem details; an error
//! after that ends the body with a transport error, which a client sees as a truncated
//! download, never as a complete file. The answer carries `Content-Type: text/csv;
//! charset=utf-8`, `Content-Disposition: attachment; filename="prefixes.csv"` and
//! `Cache-Control: no-store`.
//!
//! # Parameters and authorization
//!
//! The only parameter is `at_least=<revision>`, for read-your-writes after a write; any
//! other parameter is refused with 400 `sys.invalid_query`. The IPAM service is a request
//! extension (503 `ipam.unavailable` without it, see [`super::common`]). The principal
//! needs [`Action::Read`] on the kind of the file (prefixes, addresses or hosts).

use std::{io, sync::Arc};

use axum::{
    body::Body,
    extract::State,
    http::{HeaderValue, header},
    response::Response,
};
use bytes::Bytes;
use futures::{Stream, StreamExt, stream};
use tenko_core::{Action, CodedError, ObjectKind, ObjectRef, Revision};
use tenko_ipam::{
    IpamResult,
    export::{CsvExport, ExportKind},
};
use tokio::task::JoinError;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    common::{Ipam, IpamHandle, new_of},
    import::reject_unknown_query,
};
use crate::{
    extract::Ctx,
    list::Filters,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(export_prefixes_csv))
        .routes(routes!(export_addresses_csv))
        .routes(routes!(export_hosts_csv))
}

/// Exports the live prefixes, in the order of VRF and network, with their VRF, role, status,
/// VLAN, site, alarm thresholds, allocation policy, tags and custom fields.
#[utoipa::path(
    get,
    path = "/exports/prefixes.csv",
    tag = "export",
    operation_id = "export_prefixes_csv",
    summary = "Export prefixes as CSV",
    params(("at_least" = Option<u64>, Query, description = "Read at least this store revision (read-your-writes after a write).")),
    responses(
        (status = 200, description = "`prefixes.csv`: UTF-8 with a byte order mark, comma separated, CRLF line ends", body = String, content_type = "text/csv",
            headers(
                ("Content-Disposition" = String, description = "`attachment; filename=\"prefixes.csv\"`"),
                ("Cache-Control" = String, description = "`no-store`")
            )),
        (status = 400, description = "Unknown or malformed query parameter (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn export_prefixes_csv(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
) -> Result<Response, ApiError> {
    export(&app, &cx, &ipam, &filters, ExportKind::Prefixes).await
}

/// Exports the live addresses, in the order of VRF and address, with their status, DNS name,
/// host, interface, MAC address, DUID, tags and custom fields.
#[utoipa::path(
    get,
    path = "/exports/addresses.csv",
    tag = "export",
    operation_id = "export_addresses_csv",
    summary = "Export addresses as CSV",
    params(("at_least" = Option<u64>, Query, description = "Read at least this store revision (read-your-writes after a write).")),
    responses(
        (status = 200, description = "`addresses.csv`: UTF-8 with a byte order mark, comma separated, CRLF line ends", body = String, content_type = "text/csv",
            headers(
                ("Content-Disposition" = String, description = "`attachment; filename=\"addresses.csv\"`"),
                ("Cache-Control" = String, description = "`no-store`")
            )),
        (status = 400, description = "Unknown or malformed query parameter (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn export_addresses_csv(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
) -> Result<Response, ApiError> {
    export(&app, &cx, &ipam, &filters, ExportKind::Addresses).await
}

/// Exports the live hosts, in the order of tenant and name, with their mode, lock, site,
/// interfaces (`name=mac=duid`, joined with `; `), tags and custom fields.
#[utoipa::path(
    get,
    path = "/exports/hosts.csv",
    tag = "export",
    operation_id = "export_hosts_csv",
    summary = "Export hosts as CSV",
    params(("at_least" = Option<u64>, Query, description = "Read at least this store revision (read-your-writes after a write).")),
    responses(
        (status = 200, description = "`hosts.csv`: UTF-8 with a byte order mark, comma separated, CRLF line ends", body = String, content_type = "text/csv",
            headers(
                ("Content-Disposition" = String, description = "`attachment; filename=\"hosts.csv\"`"),
                ("Cache-Control" = String, description = "`no-store`")
            )),
        (status = 400, description = "Unknown or malformed query parameter (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn export_hosts_csv(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    filters: Filters,
) -> Result<Response, ApiError> {
    export(&app, &cx, &ipam, &filters, ExportKind::Hosts).await
}

/// The kind of object a file lists, for the authorization check.
const fn object_kind(kind: ExportKind) -> ObjectKind {
    match kind {
        ExportKind::Prefixes => ObjectKind::Prefix,
        ExportKind::Addresses => ObjectKind::Address,
        ExportKind::Hosts => ObjectKind::Host,
    }
}

/// The `Content-Disposition` of a file.
const fn disposition(kind: ExportKind) -> HeaderValue {
    HeaderValue::from_static(match kind {
        ExportKind::Prefixes => "attachment; filename=\"prefixes.csv\"",
        ExportKind::Addresses => "attachment; filename=\"addresses.csv\"",
        ExportKind::Hosts => "attachment; filename=\"hosts.csv\"",
    })
}

/// Checks the request, opens one read view and answers the file as a stream.
async fn export(
    app: &AppState,
    cx: &tenko_core::RequestCtx,
    ipam: &IpamHandle,
    filters: &Filters,
    kind: ExportKind,
) -> Result<Response, ApiError> {
    reject_unknown_query(filters, &["at_least"])?;
    let at_least = filters.parse::<u64>("at_least")?.map(Revision);
    app.authorize(&cx.principal, Action::Read, &new_of(object_kind(kind)))?;
    let view = ipam.view(at_least).await?;
    // A scoped reader exports only the objects inside its scope (IAM-01).
    let scope = ipam.read_scope(cx, object_kind(kind));
    let mut export = if scope.is_all() {
        CsvExport::new(view, kind)?
    } else {
        CsvExport::with_filter(
            view,
            kind,
            Arc::new(move |object: ObjectRef| scope.admits(&object)),
        )?
    };
    // The first chunk (byte order mark and header) comes before the response starts, so a
    // failure that is there anyway is answered as problem details.
    let (next, first) = pull(move || export.next_chunk())
        .await
        .map_err(|_| ApiError::from_coded_error(CodedError::internal("the export task failed")))?;
    let first = first?;
    let mut response = Response::new(Body::from_stream(chunks(first, next)));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    headers.insert(header::CONTENT_DISPOSITION, disposition(kind));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// Runs one step of a chunk producer on the blocking pool and hands the producer back.
async fn pull<F>(mut next: F) -> Result<(F, IpamResult<Option<Vec<u8>>>), JoinError>
where
    F: FnMut() -> IpamResult<Option<Vec<u8>>> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let chunk = next();
        (next, chunk)
    })
    .await
}

/// The body of a download: `first`, then whatever `next` produces until it says `None`. A
/// chunk is produced only when the previous one has been taken, so the memory use does not
/// depend on the size of the file. An error ends the stream after yielding it.
fn chunks<F>(
    first: Option<Vec<u8>>,
    next: F,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static
where
    F: FnMut() -> IpamResult<Option<Vec<u8>>> + Send + 'static,
{
    let rest = stream::unfold(Some(next), |state| async move {
        let next = state?;
        match pull(next).await {
            Ok((next, Ok(Some(chunk)))) => Some((Ok(Bytes::from(chunk)), Some(next))),
            Ok((_, Ok(None))) => None,
            Ok((_, Err(error))) => Some((Err(io::Error::other(error.to_string())), None)),
            Err(_) => Some((Err(io::Error::other("the export task failed")), None)),
        }
    });
    stream::iter(first.map(|chunk| Ok(Bytes::from(chunk)))).chain(rest)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use axum::http::StatusCode;
    use serde_json::{Value, json};
    use tenko_core::{RequestCtx, SystemComponent};
    use tenko_ipam::{IpamCommand, IpamError, PlanOptions, command::HostInput};

    use super::*;
    use crate::routes::{
        import::testkit::{Api, Setup},
        tenancy::testkit::Policy,
    };

    const BOM: &str = "\u{feff}";

    const PREFIX_HEADER: &str =
        "prefix,vrf,role,status,vlan,vlan_name,site,alarm_warn,alarm_crit,alloc,description,tags";
    const ADDRESS_HEADER: &str =
        "address,vrf,status,dns_name,host,interface,mac,duid,description,tags";
    const HOST_HEADER: &str = "host,tenant,mode,lock,site,description,interfaces,tags";

    /// File name, header line and a row of the fixture workbook for each export.
    const FILES: [(&str, &str, &str); 3] = [
        (
            "prefixes.csv",
            PREFIX_HEADER,
            "192.0.2.0/24,default,supernet,active,,,,,,lowest,\"Network gear, hypervisors\",",
        ),
        (
            "addresses.csv",
            ADDRESS_HEADER,
            "192.0.2.1,default,active,,gateway,nic1,,,,",
        ),
        (
            "hosts.csv",
            HOST_HEADER,
            "gateway,default,static,false,,,nic1,",
        ),
    ];

    /// Creates `count` hosts under `example.test` straight on the service.
    async fn make_hosts(api: &Api, count: usize) {
        let commands: Vec<IpamCommand> = (0..count)
            .map(|n| {
                let input: HostInput =
                    serde_json::from_value(json!({ "name": format!("host-{n:04}.example.test") }))
                        .expect("host input");
                IpamCommand::CreateHost(input)
            })
            .collect();
        let cx = RequestCtx::system(SystemComponent::Api);
        api.ipam
            .execute(&commands, &cx, &PlanOptions::default())
            .await
            .expect("hosts");
    }

    /// The items of a stream made by `chunks`, errors as their text.
    async fn items(
        first: Option<Vec<u8>>,
        script: Vec<IpamResult<Option<Vec<u8>>>>,
    ) -> Vec<Result<String, String>> {
        let mut script: VecDeque<_> = script.into();
        let stream = chunks(first, move || script.pop_front().unwrap_or(Ok(None)));
        stream
            .map(|item| match item {
                Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
                Err(error) => Err(error.to_string()),
            })
            .collect()
            .await
    }

    #[tokio::test]
    async fn each_file_downloads_as_csv_with_its_header_and_rows() {
        let api = Api::new();
        api.import_fixture().await;
        for (file, header, row) in FILES {
            let reply = api.get(&format!("/exports/{file}")).await;
            assert_eq!(reply.status, StatusCode::OK, "{file}");
            assert_eq!(reply.header("content-type"), "text/csv; charset=utf-8");
            assert_eq!(
                reply.header("content-disposition"),
                format!("attachment; filename=\"{file}\"")
            );
            assert_eq!(reply.header("cache-control"), "no-store");
            assert!(reply.bytes.starts_with(&[0xEF, 0xBB, 0xBF]), "{file}");
            let text = reply.text();
            let lines: Vec<&str> = text.split("\r\n").collect();
            assert_eq!(lines[0], format!("{BOM}{header}"), "{file}");
            assert!(lines.contains(&row), "{file} lacks {row}");
            assert_eq!(lines.last(), Some(&""), "{file} ends with a line end");
            assert!(lines.len() > 10, "{file}");
        }
    }

    #[tokio::test]
    async fn an_empty_store_exports_the_header_only() {
        let api = Api::new();
        for (file, header, _) in FILES {
            let reply = api.get(&format!("/exports/{file}")).await;
            assert_eq!(reply.status, StatusCode::OK, "{file}");
            assert_eq!(reply.text(), format!("{BOM}{header}\r\n"), "{file}");
        }
    }

    #[tokio::test]
    async fn a_large_export_streams_in_several_chunks() {
        let api = Api::new();
        let count = CsvExport::CHUNK_ROWS + 150;
        make_hosts(&api, count).await;
        let response = api
            .respond("GET", "/exports/hosts.csv", None, Body::empty())
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body().into_data_stream();
        let (mut frames, mut text) = (0, Vec::new());
        while let Some(frame) = body.next().await {
            text.extend_from_slice(&frame.expect("frame"));
            frames += 1;
        }
        assert!(frames >= 2, "one frame holds the whole file");
        let text = String::from_utf8(text).expect("UTF-8");
        let lines: Vec<&str> = text.split("\r\n").collect();
        assert_eq!(
            lines.len(),
            count + 2,
            "header, rows and the final line end"
        );
        assert!(lines[1].starts_with("host-0000.example.test,default,static,false,"));
        assert!(lines[count].starts_with(&format!("host-{:04}.example.test,", count - 1)));
    }

    #[tokio::test]
    async fn an_export_imports_again_without_changes() {
        let api = Api::new();
        api.import_fixture().await;
        let mut files = Vec::new();
        for (file, _, _) in FILES {
            files.push((file, api.get(&format!("/exports/{file}")).await.bytes));
        }
        let uploads: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(name, bytes)| (*name, bytes.as_slice()))
            .collect();
        let uploaded = api.upload(&uploads).await.assert_json(201);
        let id = uploaded["id"].as_str().expect("id");
        let preview = api
            .get(&format!("/imports/{id}/preview"))
            .await
            .assert_json(200);
        let counts = preview["summary"]["counts"].as_array().expect("counts");
        assert_ne!(counts.len(), 0);
        for count in counts {
            assert_eq!(count["action"], "unchanged", "{counts:?}");
        }
        assert_eq!(preview["can_apply"], true, "{}", preview["blockers"]);
    }

    #[tokio::test]
    async fn at_least_waits_for_a_revision_and_other_parameters_are_refused() {
        let api = Api::new();
        api.import_fixture().await;
        let revision = api.ipam.view(None).await.expect("view").revision().0;
        for (file, _, _) in FILES {
            let ok = format!("/exports/{file}?at_least={revision}");
            assert_eq!(api.get(&ok).await.status, StatusCode::OK, "{ok}");
            for (query, parameter) in [
                ("at_least=soon", "at_least"),
                ("at_least=-1", "at_least"),
                ("at_least=1&at_least=2", "at_least"),
                ("limit=5", "limit"),
                ("cursor=abc", "cursor"),
                ("format=tsv", "format"),
            ] {
                let problem = api
                    .get(&format!("/exports/{file}?{query}"))
                    .await
                    .assert_problem(400, "sys.invalid_query");
                assert_eq!(problem["params"]["parameter"], parameter, "{query}");
            }
        }
    }

    #[tokio::test]
    async fn a_principal_that_may_not_read_the_kind_is_refused() {
        let api = Api::new();
        api.import_fixture().await;
        let policy = Policy::new(false, true);
        let denied = api.sibling(Setup {
            authorizer: Some(policy.clone()),
            ..Setup::default()
        });
        let kinds = [ObjectKind::Prefix, ObjectKind::Address, ObjectKind::Host];
        for ((file, _, _), kind) in FILES.into_iter().zip(kinds) {
            denied
                .get(&format!("/exports/{file}"))
                .await
                .assert_problem(403, "auth.forbidden");
            assert!(
                policy.asked().contains(&(Action::Read, new_of(kind))),
                "{file}"
            );
        }

        let reader = api.sibling(Setup {
            authorizer: Some(Policy::new(true, false)),
            ..Setup::default()
        });
        for (file, _, _) in FILES {
            let reply = reader.get(&format!("/exports/{file}")).await;
            assert_eq!(reply.status, StatusCode::OK, "{file}");
        }
    }

    #[tokio::test]
    async fn the_ipam_service_is_needed_but_the_import_service_is_not() {
        let api = Api::new();
        api.import_fixture().await;
        let without_ipam = api.sibling(Setup {
            without_ipam: true,
            ..Setup::default()
        });
        let without_imports = api.sibling(Setup {
            without_imports: true,
            ..Setup::default()
        });
        for (file, _, _) in FILES {
            let path = format!("/exports/{file}");
            without_ipam
                .get(&path)
                .await
                .assert_problem(503, "ipam.unavailable");
            assert_eq!(without_imports.get(&path).await.status, StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn a_revision_that_never_arrives_is_a_problem_document() {
        let api = Api::new();
        let reply = api.get("/exports/prefixes.csv?at_least=4000000000").await;
        let problem: Value = reply.json();
        assert!(
            reply.status.is_client_error() || reply.status.is_server_error(),
            "{problem}"
        );
        assert_eq!(reply.header("content-type"), crate::problem::PROBLEM_JSON);
        assert!(problem["code"].is_string(), "{problem}");
    }

    #[tokio::test]
    async fn chunks_come_in_order_and_the_stream_ends() {
        let all = items(
            Some(b"a".to_vec()),
            vec![
                Ok(Some(b"b".to_vec())),
                Ok(Some(b"c".to_vec())),
                Ok(None),
                Ok(Some(b"never".to_vec())),
            ],
        )
        .await;
        assert_eq!(
            all,
            vec![Ok("a".to_owned()), Ok("b".to_owned()), Ok("c".to_owned())]
        );
        assert_eq!(
            items(None, vec![Ok(Some(b"only".to_vec()))]).await,
            vec![Ok("only".to_owned())]
        );
        assert_eq!(items(None, Vec::new()).await.len(), 0);
    }

    #[tokio::test]
    async fn an_error_after_the_first_chunk_ends_the_stream_with_an_error() {
        let script = || {
            vec![
                Ok(Some(b"b".to_vec())),
                Err(IpamError::new("sys.internal", 500, "the store failed")),
                Ok(Some(b"never".to_vec())),
            ]
        };
        assert_eq!(
            items(Some(b"a".to_vec()), script()).await,
            vec![
                Ok("a".to_owned()),
                Ok("b".to_owned()),
                Err("the store failed".to_owned())
            ]
        );
        // The body fails as a whole, so a client sees a truncated download.
        let mut remaining: VecDeque<_> = script().into();
        let body = Body::from_stream(chunks(Some(b"a".to_vec()), move || {
            remaining.pop_front().unwrap_or(Ok(None))
        }));
        assert!(axum::body::to_bytes(body, usize::MAX).await.is_err());
    }
}
