# Observability: metrics and traces

This document describes the metrics and the traces of a Tenko DDI controller: where the metrics are served, who may read them, how the gauges are computed, every series with its labels, how to scrape them with Prometheus, what they cost, the live metrics of the start page, and the OpenTelemetry traces exported over OTLP with their span catalogue. It is for administrators who monitor Tenko and for reviewers. Requirements are cited by ID and defined in [REQUIREMENTS.md](REQUIREMENTS.md) (OPS-05, OPS-20, OPS-21); the endpoint is in the [OpenAPI document](api/openapi.json). Where this document and the code disagree, the code is right and the document has a defect.

Contents:

1. [Where the metrics are served](#1-where-the-metrics-are-served)
2. [Who may read them](#2-who-may-read-them)
3. [How values are computed](#3-how-values-are-computed)
4. [Series](#4-series)
5. [Scraping with Prometheus](#5-scraping-with-prometheus)
6. [Cost](#6-cost)
7. [Dashboard](#7-dashboard)
8. [Traces](#8-traces)
9. [Not covered yet](#9-not-covered-yet)

## 1. Where the metrics are served

| Where | Authentication | Settings |
|---|---|---|
| `GET /api/v1/metrics` on the API listener, over the TLS mode of the server | A token with the `metrics` scope, or a principal that reads the system (section 2) | Always on |
| `GET /metrics` on a separate loopback listener, plain HTTP | None | `[metrics] listen`, off by default |

Both answer the same text in the OpenMetrics format (`application/openmetrics-text; version=1.0.0; charset=utf-8`): per family a `# TYPE`, a `# HELP` and, for values with a unit, a `# UNIT` line, then its samples; counters carry the `_total` suffix, histograms their cumulative `_bucket` samples with `le` in seconds, `_sum` and `_count`; the text ends with `# EOF`.

**The loopback listener.** `[metrics] listen` takes an address with a port, such as `127.0.0.1:9464` or `[::1]:9464`. Only loopback addresses are accepted (`tenko config check` refuses any other, because the listener has no authentication); it serves for a scraper or an agent on the same host. It starts in the `api` step with one log line that names the bound address, answers `GET /metrics` only (every other path is 404), and stops with the server. If the port is taken the server does not start (`start.metrics.bind`).

```toml
[metrics]
listen = "127.0.0.1:9464"
gauge_interval_secs = 30
```

## 2. Who may read them

Reading the metrics is the read of the metrics object (owner decision S3-Q7, [access.md](access.md) sections 3.5 and 7):

- A token with the `metrics` scope reads `GET /api/v1/metrics` and nothing else. This is the token for a scraper: create a service account and a token with that scope for it.
- A principal whose roles read the system (the session or personal token of a user with a global role: administrator, operator, viewer or auditor) reads it too.
- A token without the `metrics` scope (a scoped token with grants or with `audit:read` only) gets 403 `auth.forbidden`; a request without credentials gets 401.

```json
POST /api/v1/access/service-accounts
{"name": "prometheus", "display_name": "Prometheus", "roles": []}

POST /api/v1/access/service-accounts/<id>/tokens
{"name": "prometheus", "expires_in_days": 90, "scopes": ["metrics"]}
```

The answer carries the secret (`tnk_...`) once. The token's lifetime is capped by the security profile (TGL-05); renew it before it expires.

The metrics reveal sizes, counts, versions and the health of connected systems, never object names, addresses or secrets. Label values are path templates, ids of controllers, nodes and connector instances, names of audit export sinks and leader services, and the key provider.

## 3. How values are computed

- **Counters and histograms** (requests, refusals, connections, request durations) are updated on the request path and are always current.
- **Gauges** are set by a timer every `[metrics] gauge_interval_secs` seconds (default 30, 5 to 3600), and once at start. The timer reads the status interfaces of the services (the store, Raft, the job engine, the connector host, the node sessions, the leader supervisor, the key service, the audit export cursors, the backup records, the TLS listener); a scrape returns the values of the last round and computes nothing again. A source that cannot be read in a round keeps its last values.
- **At scrape time** only `tenko_uptime_seconds` and `tenko_build_info` are computed.
- **While the start page shows live metrics** (section 7), the gauges that read memory only are also set once per second: the event-stream subscribers, the store revision, audit head, journal and data, the Raft role, term and lag, the store files and the coalescer queue, the jobs (from their state index) and the connected nodes with their buffers. The others keep the timer's values.

A gauge that has no value is left out: for example `tenko_backup_age_seconds` before the first good backup, `tenko_tls_certificate_expiry_seconds` without a certificate (TLS mode c), and every timer gauge before the first round. A family is still listed with its `# TYPE` and `# HELP` lines.

Gauges whose label values are only known at run time (members, nodes, connector instances, sinks, services) have a bounded number of series: 9 members, 256 connected nodes, 64 connector instances, 8 audit export sinks, 32 leader services and 4 key providers. A label value that is not seen in a round leaves the text (a disconnected node, a removed instance); values beyond the bound are not reported.

Counter series are fixed when the server starts. `tenko_http_requests_total` has one series per documented operation (its path template and method), plus the routes `ui` (the web UI) and `other` (an API path that matched no documented operation, or a method the operation does not document) for every method, times the status labels; a series appears in the text once it is not zero.

## 4. Series

Request and process counters:

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `tenko_http_requests_total` | counter | `route`, `method`, `status` | HTTP requests by path template (`/api/v1/prefixes/{id}`, `ui` or `other`), method (`GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `OTHER`) and status (`200`, `201`, `202`, `204`, `303`, `304`, `400`, `401`, `403`, `404`, `405`, `409`, `410`, `412`, `413`, `415`, `422`, `428`, `429`, `500`, `501`, `503`, `other`) |
| `tenko_http_request_duration_seconds` | histogram | `class` | Time from the request to the response head, by route class: the first path segment after `/api/v1/` (`auth`, `prefixes`, `hosts`, `system`, `events`, `cluster`, `connectors`, `jobs`, `metrics` and so on), `ui` or `other`. Buckets from 250 µs to 10 s: 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 |
| `tenko_http_refused_total` | counter | `reason` | Requests refused before the handler: `rate_limit_ip`, `rate_limit_principal`, `csrf` |
| `tenko_http_idempotent_replays_total` | counter | | Responses replayed for a repeated `Idempotency-Key` |
| `tenko_http_connections_total` | counter | `outcome` | Connections of the API listener: `accepted`, `over_limit`, `proxy_only`, `tls_failed`, `proxy_header_failed` |
| `tenko_sse_events_total` | counter | | Events published to server-sent event subscribers (set by the timer) |
| `tenko_store_commit_duration_seconds` | histogram | | Time from a write's proposal on this controller to its commit: on the leader the coalescer's queue and the Raft commit, on another member the forward to the leader and the apply here. Observed once per committed write. Buckets from 100 µs to 10 s: 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 |
| `tenko_ipam_ingest_batches_total` | counter | | Observation batches of connectors and probes that the reconciler ingested on this controller |
| `tenko_ipam_ingest_facts_total` | counter | | Observations (facts) in those batches |

Gauges set by the timer:

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `tenko_sse_subscribers` | gauge | | Open server-sent event streams |
| `tenko_store_revision` | gauge | | Last applied store revision |
| `tenko_audit_head` | gauge | | Sequence number of the newest audit record |
| `tenko_store_journal_entries` | gauge | | Change sets in the store journal |
| `tenko_store_data_bytes` | gauge | | Bytes of live data in the store |
| `tenko_store_file_bytes` | gauge | `file` | Bytes on disk of the store: `log` (the Raft log), `state` (the state file), `snapshots` |
| `tenko_store_state_file_ratio` | gauge | | The state file over the live data; a re-seed is due when it stays above about 2 (ADR 0002) |
| `tenko_store_coalescer_queue_batches` | gauge | | Write batches waiting in the coalescer for a Raft entry |
| `tenko_raft_role` | gauge | `role` | 1 for this member's current role, 0 for the others: `leader`, `follower`, `learner`, `candidate`, `shutdown`, `memory` |
| `tenko_raft_term` | gauge | | The Raft term this member knows |
| `tenko_raft_lag_entries` | gauge | `node` | Log entries a member is behind the leader: every member on the leader, this member on a follower |
| `tenko_jobs` | gauge | `state` | Jobs that are not finished: `queued`, `running`, `waiting`, `rolling_back` |
| `tenko_connector_health` | gauge | `instance`, `health` | 1 for the current health of the remote system of each connector instance, 0 for the others: `healthy`, `degraded`, `unreachable`, `unknown` (no check yet) |
| `tenko_nodes_connected` | gauge | | Nodes connected to this controller |
| `tenko_node_buffer_batches` | gauge | `node` | Observation batches waiting in the disk buffer of each connected node |
| `tenko_leader_service` | gauge | `service`, `state` | 1 for the current state of each leader-only service on this controller, 0 for the others: `idle` (another controller leads), `running`, `restarting`, `finished` |
| `tenko_kek_protection` | gauge | `provider` | The protection of the active key-encryption key: 0 memory, 1 a plain file, 2 DPAPI in machine scope or `systemd-creds` with the host key, 3 DPAPI in user scope or `systemd-creds` with a TPM2 |
| `tenko_audit_export_lag_seconds` | gauge | `sink` | Age of the oldest audit record an enabled sink has not received; 0 when it is current |
| `tenko_backup_age_seconds` | gauge | | Seconds since the last good backup |
| `tenko_tls_certificate_expiry_seconds` | gauge | | Seconds until the served certificate expires |

Computed at scrape time:

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `tenko_uptime_seconds` | gauge | | Seconds since the API started |
| `tenko_build_info` | gauge | | Always 1 |

The `dns` role, while it runs on the node ([dns.md](dns.md) sections 8 and 12.8), counted on the shard of the answering thread:

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `tenko_dns_queries_total` | counter | `proto`, `view`, `rcode` | Queries answered, by transport (`udp`, `tcp`, `dot`, `doh`), view (`default` or `named`) and RCODE (`noerror`, `formerr`, `servfail`, `nxdomain`, `notimp`, `refused`, `notauth`, `badvers`, `badcookie`, `other`); a query the forwarder answers is counted with the RCODE it relayed, a cache hit as any answer of the query path |
| `tenko_dns_query_duration_seconds` | histogram | `proto` | Time from a query's arrival to its answer (for a forwarded query, from the hand-over to the forwarder). Buckets from 50 µs to 2 s: 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2 |
| `tenko_dns_cache_hits_total` | counter | `view` | Forwarded queries the cache answered on the query path, by view (`default` or `named`) ([dns-resolver.md](dns-resolver.md) section 3) |
| `tenko_dns_cache_misses_total` | counter | `view` | Forwarded queries the cache could not answer (no entry, or an expired one) |
| `tenko_dns_cache_stale_total` | counter | | Stale answers (RFC 8767): an expired entry answered while the upstreams failed or were slower than `stale_answer_ms` |
| `tenko_dns_cache_entries` | gauge | | Entries in the cache |
| `tenko_dns_upstream_queries_total` | counter | `rule`, `upstream`, `transport`, `outcome` | Exchanges with upstream resolvers, by forwarding rule (its suffix, `default` for `[dns] forwarders`, `stub:<zone>` and `stub-source:<zone>` for stub zones), upstream (`address:port`), transport (`plain`, `dot`, `doh`) and outcome (`ok`, `servfail`, `timeout`, `unreachable`, `malformed`); a series appears with the first exchange ([dns-resolver.md](dns-resolver.md) section 4) |
| `tenko_dns_upstream_rtt_seconds` | histogram | `upstream` | Round-trip time of the answered exchanges with an upstream, over every rule that names it; the buckets of `tenko_dns_query_duration_seconds` |

The other families of the DNS module (`tenko_dns_rrl_dropped_total`, `tenko_dns_blocked_total`, `tenko_dns_zone_serial`, `tenko_dns_signing_*`, `tenko_dns_log_dropped_total`; [dns-contracts.md](dns-contracts.md) section 7) are declared and registered by the packages that count them. The health of the role is in `GET /api/v1/nodes/{id}/dns` and in the warnings of `GET /api/v1/system/status`: `dns.role.not_serving` (the role stopped answering) and `dns.role.lagging` (its index is more than 1,000 revisions behind the store).

Every controller reports its own values: in a cluster, scrape each controller. The Raft lag of every member and the leader services in state `running` come from the leader.

## 5. Scraping with Prometheus

Through the API listener with a token of the `metrics` scope, verifying the certificate of the internal CA (its root is `<data_dir>/tls/ca-root.pem` on the controller; `tenko ca-root` fetches it):

```yaml
scrape_configs:
  - job_name: tenko
    scheme: https
    metrics_path: /api/v1/metrics
    scrape_interval: 30s
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/tenko.token
    tls_config:
      ca_file: /etc/prometheus/tenko-ca-root.pem
    static_configs:
      - targets: ["ddi.example.test:8443"]
```

From the same host through the loopback listener:

```yaml
scrape_configs:
  - job_name: tenko-local
    metrics_path: /metrics
    static_configs:
      - targets: ["127.0.0.1:9464"]
```

A scrape interval shorter than `[metrics] gauge_interval_secs` returns the same gauge values more than once; the counters and histograms are current at every scrape.

## 6. Cost

The counters and histograms are those of `tenko_core::metrics` (OPS-21): each family keeps one stripe of cells per shard (the number of logical CPUs rounded up to a power of two, at most 32), each stripe on its own cache lines, and an update is one or two relaxed atomic additions on the calling thread's stripe, without a lock, an allocation or formatting. A read sums the stripes. The memory of a family is its series times the shards times 8 bytes; the two request families, the largest by far, use at most 8 shards (the API serves thousands of requests per second at most), about 0.42 MiB in all. The measurements are in `bench/phase1-metrics/` (M8: the cost on a UDP responder's hot path; the zero-allocation check) and `bench/phase1-server/` (M9: the idle memory of the controller).

## 7. Dashboard

The start page shows administrators live metrics of the controllers (OPS-20): one tile per figure, each a number with an SI suffix and a sparkline of the last sixty seconds, no dial gauges. The figures arrive on the event stream, not by polling.

**The topic.** `GET /api/v1/events?topics=metrics` subscribes to the topic `metrics`; a stream that names no topics does not receive it. It is admitted by the read of the metrics object, like `GET /api/v1/metrics` (section 2): a stream of a principal that may not read the metrics does not receive the topic and does not count as its listener. The start page opens a stream of its own for the topic while it is shown and closes it when the page goes.

**The one-second rule.** The controller samples only while at least one stream receives the topic. The publisher sleeps otherwise and wakes with the first subscription; while someone listens it runs a one-second tick, and each tick takes one snapshot of the metrics registry, builds this controller's sample against the snapshot before it, asks the other controllers for theirs, and publishes one system event: `event: metrics`, no id (it is never replayed; a client that reconnects gets the next one), data an `EventData` with `kind` `metrics.snapshot` and the field `metrics`. The frame is encoded once and shared by every stream, so the cost does not grow with the number of subscribers: the acceptance test in `crates/tenko-api/tests/metrics_stream.rs` opens 100 streams, counts five events on each in five seconds from five aggregations, and prints the CPU time of the process (Windows workstation, 2026-10-14: 31 ms over five seconds with 100 streams on the topic, about 0.6 percent of one core, including the clients in the same process).

**The sample.** `metrics.nodes` holds one `MetricsSample` per controller, this controller first, and `metrics.cluster` their sum. A sample covers the interval between two snapshots (`interval_ms`, about 1,000; 0 for the first sample after the publisher wakes, which has no rates):

| Field | Source |
|---|---|
| `node`, `at` | The controller and its clock |
| `api.requests_per_second` | The change of `tenko_http_requests_total` over the interval, without the route `ui` (the files of the web UI) |
| `api.p50_ms`, `api.p99_ms` | Interpolated inside the buckets of the change of `tenko_http_request_duration_seconds`, summed over the route classes without `ui` (as Prometheus' `histogram_quantile` does; a quantile in the `+Inf` bucket reads as the highest bound); absent without requests |
| `store.data_bytes`, `store.file_bytes` | `tenko_store_data_bytes` and the sum of `tenko_store_file_bytes` (absent for an in-memory store) |
| `store.commit_p99_ms` | The change of `tenko_store_commit_duration_seconds`; absent without writes |
| `raft.role`, `raft.term`, `raft.lag` | `tenko_raft_role`, `tenko_raft_term` and `tenko_raft_lag_entries` (every member on the leader, this member on a follower) |
| `jobs.running`, `jobs.waiting` | `tenko_jobs` |
| `ingest.batches_per_second`, `ingest.facts_per_second` | The change of `tenko_ipam_ingest_batches_total` and `tenko_ipam_ingest_facts_total` |
| `sse.subscribers` | `tenko_sse_subscribers` |
| `nodes[]` | `tenko_node_buffer_batches` per connected node, with `drops`, the batches the node's buffer dropped as its last heartbeat reported (absent when the node registry does not say) |

**The cluster merge.** A controller of a cluster asks every other member for its newest sample once per tick, in parallel, with a deadline of 500 ms per peer. A peer that does not answer keeps its last good sample in `nodes`, marked `stale: true` (one that has not answered since the publisher woke appears with `stale: true` and no role); a member of an older build answers `UNIMPLEMENTED` and appears with `unsupported: true` and no figures. `cluster` sums the rates, sizes and counts of the current samples (neither stale nor unsupported) and takes the highest quantiles, term and lag per member; the jobs are shared by the cluster, so it takes the highest job counts rather than their sum. On a single controller `cluster` is its own sample without the node id. The tiles show `cluster`, except the Raft tile, which lists every controller with its role and lag.

**The call between controllers.** `Metrics.Snapshot` (`tenko.cluster.v1`, on the cluster port) answers the callee's newest sample: `node_id`, `at`, `encoding` `cbor/1` and the CBOR of the `MetricsSample` in `payload`. While the callee's own publisher runs, that is the sample of its last tick; otherwise the call takes one on demand, at most one per 500 ms (two callers in the same half second get the same sample). The caller must hold a controller certificate, and when it has a node record (every controller that joined) the record must name the role and hold the certificate; a controller whose API has not started yet answers `UNAVAILABLE` with `cluster.metrics.unavailable`. The bytes travel over the mutual TLS of the cluster port like every other call.

## 8. Traces

A controller exports OpenTelemetry traces (OPS-05) to an OTLP collector over gRPC when `[telemetry] otlp_endpoint` is set. Without it nothing is built: no tracer provider, no exporter, no thread and no task, and every span in the code is a disabled callsite. The code is `crates/tenko/src/telemetry.rs` (the layer, the provider, the flush), `tenko-api` `middleware::trace` (the request span), `tenko-cluster` `trace` (the context between controllers) and `tenko-connect` `host::client` and `sdk` (the context to plugins).

### 8.1 Configuration

```toml
[telemetry]
otlp_endpoint = "http://127.0.0.1:4317"
sampling_ratio = 1.0
```

- `otlp_endpoint`: `http://` or `https://` with host and port, the OTLP/gRPC port of a collector (4317 by convention). `https://` verifies the collector's certificate against the system's root certificates (rustls with aws-lc-rs). Not set (the default): traces are off.
- `sampling_ratio`: the share of traces exported, 0.0 to 1.0 (default 1.0). See 8.4.
- The exporter's timeout is 10 s per export. The SDK also reads the standard OpenTelemetry variables (`OTEL_EXPORTER_OTLP_HEADERS` for headers a collector may need, `OTEL_BSP_*` for the batch processor, `OTEL_RESOURCE_ATTRIBUTES` for more resource attributes); the endpoint and the timeout set here win over theirs.

Any OTLP receiver works: the OpenTelemetry Collector with its `otlp` receiver, or a tracing back end that accepts OTLP over gRPC directly. Run it next to the controller or reach it over TLS; the traces carry no secrets (8.6) but do show the activity of the installation.

The process is the resource: `service.name` is `tenko`, `service.version` the version of the binary, `service.instance.id` the node id of the controller. In a cluster every controller exports its own spans with its own node id, to the collector its own `tenko.toml` names.

When traces are on, the start logs `telemetry: traces are exported over OTLP` with the endpoint (without any `user:password@` part) and the ratio.

### 8.2 Span catalogue

Every span is at level `INFO`. Attribute names follow the OpenTelemetry semantic conventions where one exists; the others are under `tenko.`. The bridge from `tracing` adds the source location (`code.file.path`, `code.module.name`, `code.line.number`), the busy and idle time (`busy_ns`, `idle_ns`) and `target`; spans that end in an error have the status `error` (an HTTP status of 500 or more, a gRPC status other than the expected refusals, a failed connector call).

| Span | Where it is created | Attributes |
|---|---|---|
| `http.server.request` (kind server) | `tenko-api` `middleware::trace`, the outermost layer of the router, for API paths only: it covers the CSRF guard, the rate limits, authentication, the quorum gate and the idempotency replay. Not for `/api/v1/health`, `/api/v1/health/ready`, `GET /api/v1/metrics` or the web UI. The span of an event stream (`/api/v1/events`) ends when the response head is sent, not when the stream closes | `http.request.method` (`_OTHER` for a non-standard method), `http.route` (the path template of the request metrics, such as `/api/v1/prefixes/{id}`, or `other`; never the raw path), `http.response.status_code`, `url.scheme` (as the client reached Tenko, behind a trusted proxy the proxy's scheme), `network.protocol.version` (`1.1`, `2`), `tenko.route_class` (the class label of `tenko_http_request_duration_seconds`) |
| `tenko.store.propose` | `tenko-store`, every proposal of a write batch on any member (`propose_encoded`), and on the leader the acceptance of a batch another member forwarded (`accept_forwarded`) | `tenko.store.batch_bytes`, `tenko.store.forwarded` (true when the leader is another controller), `tenko.store.leader` (the leader's node id), `tenko.store.revision` (on success), `tenko.store.outcome`: `ok`, `refused` (a precondition, an idempotency conflict, a shut-down store and the other refusals), `timeout`, `no_quorum`, `forwarded_error` (the forward got no answer of the leader's store) |
| `tenko.store.coalesce` | `tenko-store`, child of `tenko.store.propose` on the leader: from the batch's enqueue in the coalescer to the commit notification | none in Phase 1 (`tenko.store.coalesced_with` is not known to the caller) |
| `tenko.job.step` | `tenko-jobs` `drive::run_execute`, around the `execute` call of a step handler. The root of a trace of its own: the step belongs to its job, not to the request that created it (`tenko.job.id` connects them). The engine's own writes have no span | `tenko.job.id`, `tenko.job.step` (the index), `tenko.job.kind` (the job kind, such as `ipam.edit`), `tenko.job.attempt`, `tenko.job.outcome`: `ok`, `failed`, `timeout`, `manual` (the step waits for a person), `panicked` |
| `tenko.connector.call` (kind client) | `tenko-connect` `host::client`, every call of the host to a plugin; a poll has one span per page, a migration read one span for the whole stream | `rpc.system` (`grpc`), `rpc.service` (such as `tenko.connect.v1.Inventory`), `rpc.method`, `tenko.connector.instance` (the instance id, for calls made for an instance), `rpc.grpc.status_code`, `tenko.connector.outcome` (`ok` or the error code, such as `connect.timeout` or `connect.plugin.unavailable`) |
| `tenko.cluster.rpc` (kind client) | `tenko-cluster` `trace::rpc`, a call to another controller | `rpc.system` (`grpc`), `rpc.service` (`tenko.cluster.v1.Cluster` or `tenko.cluster.v1.Metrics`), `rpc.method`, `tenko.cluster.peer` (the callee's node id), `rpc.grpc.status_code` |
| `tenko.cluster.request` (kind server) | `tenko-cluster` `trace::span_for`, the handler of a traced call on the callee, its parent the caller's `tenko.cluster.rpc` | the same as `tenko.cluster.rpc`, with `tenko.cluster.peer` the caller's node id |

Only these spans are exported: the layer passes spans of Tenko's own crates and no log events, so neither the spans of libraries (HTTP, gRPC, Raft) nor the text of log lines reach the collector.

A forwarded write reads, on the follower that took the request: `http.server.request` → `tenko.store.propose` (`forwarded = true`) → `tenko.cluster.rpc Cluster/Propose`; on the leader: `tenko.cluster.request Cluster/Propose` → `tenko.store.propose` → `tenko.store.coalesce`; one trace across both controllers.

### 8.3 Propagation

- **API: none inbound.** A `traceparent` on an API request is ignored in Phase 1: every request starts a trace (the context of a proxy or a client is not trusted yet), and no trace id goes back to the client.
- **Between controllers: W3C trace context.** The caller puts `traceparent` and `tracestate` into the gRPC metadata, the callee continues the trace. The cluster port is mutual TLS only, so every caller is a node of the installation and its context is trusted. Traced: the `Cluster` service (`Join`, `Propose`, `ReadIndex`, `Members`, `Digest`, `Campaign`, `Change`) and `Metrics.Snapshot`. Not traced: the `Raft` service (append entries, votes and snapshot chunks; its heartbeats every few hundred milliseconds would drown everything else), the node services (handshake, heartbeats, observations, configuration, commands) and `Cluster.TransferKek`, the key-generation exchange.
- **To plugins: W3C trace context.** Every call of the host carries the context of its `tenko.connector.call` span in the metadata. The SDK's token check puts it into the request extensions as `tenko_connect::sdk::TraceContext { traceparent, tracestate }`, so a plugin that installs a tracer of its own can continue the trace. Plugin processes export nothing in Phase 1 (section 9).

### 8.4 Sampling

The sampler is `ParentBased(TraceIdRatioBased(sampling_ratio))`. The root of a trace (an API request, a job step, a call that arrives without a context) decides by its trace id, and every span below follows its parent: a trace is exported whole or not at all, also across controllers, since the callee follows the caller's sampled flag. With `sampling_ratio = 0.0` no trace is exported while the server runs normally; with `1.0` every trace is.

### 8.5 Shutdown, batching and the log level

Finished spans go to the SDK's batch span processor, which runs on a thread of its own and exports at most every 5 seconds or every 512 spans, whichever comes first (the SDK defaults); it holds at most 2,048 spans and drops new ones while the queue is full (a collector that is down costs memory up to that bound, not more). The exporter's gRPC channel runs on the controller's runtime. At a graceful stop the controller flushes the queue after the server has stopped and before the runtime ends, bounded by 5 seconds, and logs `telemetry: the OTLP traces were flushed` (or that they were not all flushed, when the collector did not answer in time; the spans still queued are then lost).

The trace layer is filtered by the configured log level like the console and the file: traces flow only when `[log] level` is `info` or lower, and `RUST_LOG=warn` (which takes precedence over the configured level) silences traces as well.

### 8.6 Privacy

Span attributes never carry request or response bodies, headers, cookies, tokens, passwords, user names, object names, prefix or address values, secret ids, or anything else from the data. They carry identifiers of the system only: node ids, job ids and kinds, connector instance ids, revisions, sizes, route templates, method names, status codes and outcome codes. Log events are not exported (8.2). The serve test `crates/tenko/tests/serve_telemetry.rs` checks every attribute of every span of a setup, a write and a read against the setup token, the password, the session cookie and the prefix.

### 8.7 Cost

Spans are created with the `tracing` macros. Without the endpoint the layer is absent: each span is a disabled callsite check, nothing is allocated and nothing runs (M9 in `bench/phase1-server/results/2026-10-15-m9-idle-rss.md`: the idle working set of the branch was 0.48 MiB below `main`, within the noise of the pair). With the endpoint, a sampled span is built in the request's task and handed to the batch processor's queue; an unsampled one is not recorded. The quick check `crates/tenko/tests/serve_telemetry_cost.rs` (ignored by default; `cargo nextest run -p tenko --test serve_telemetry_cost --run-ignored only --no-capture`) sends 2,000 `GET /api/v1/prefixes` from one client in sequence to a fresh debug build with the endpoint set (the test collector on loopback, every trace sampled) and without it. Windows workstation, 2026-10-15, four pairs: the server's CPU time over the 2,000 reads was 734 to 828 ms without traces and 750 to 938 ms with them (means 800 and 836 ms, about 18 µs per request, inside the spread of the pairs), and the p99 of `tenko_http_request_duration_seconds{class="prefixes"}` was 0.25 to 0.26 ms without and 0.25 to 0.41 ms with traces (the buckets are 250 and 500 µs wide there). The collector received 2,001 request spans per run.

## 9. Not covered yet

- **Exporters in plugin processes.** A plugin receives the trace context of every call (section 8.3) but the SDK exports no spans; a plugin that wants to continue the trace installs a tracer of its own.
- **Inbound context from a proxy.** The API ignores a `traceparent` it receives; every request starts a trace.
- **Logs and metrics over OTLP.** Only traces use OTLP; the metrics are scraped (sections 1 and 5), the log goes to its sinks.
- **DNS and DHCP.** The `dns` role counts its queries (section 4); the rest of the DNS metrics, the tiles on the start page and the spans arrive with the packages of Slices 5 and 6, DHCP's with Phase 3.
- **Probes.** A node without the controller role exports no traces and reports no metrics samples of its own; its buffers show through the controller it is connected to.
