# Observability: metrics

This document describes the metrics of a Tenko DDI controller: where they are served, who may read them, how the gauges are computed, every series with its labels, how to scrape them with Prometheus, what they cost, and the live metrics of the start page. It is for administrators who monitor Tenko and for reviewers. Requirements are cited by ID and defined in [REQUIREMENTS.md](REQUIREMENTS.md) (OPS-05, OPS-20, OPS-21); the endpoint is in the [OpenAPI document](api/openapi.json). Where this document and the code disagree, the code is right and the document has a defect.

Contents:

1. [Where the metrics are served](#1-where-the-metrics-are-served)
2. [Who may read them](#2-who-may-read-them)
3. [How values are computed](#3-how-values-are-computed)
4. [Series](#4-series)
5. [Scraping with Prometheus](#5-scraping-with-prometheus)
6. [Cost](#6-cost)
7. [Dashboard](#7-dashboard)
8. [Not covered yet](#8-not-covered-yet)

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

## 8. Not covered yet

Traces (OpenTelemetry over OTLP, `[telemetry]`) come with a later package. DNS and DHCP metrics, and their tiles on the start page, arrive with those modules. Probes report no samples of their own; their buffers show through the controller they are connected to.
