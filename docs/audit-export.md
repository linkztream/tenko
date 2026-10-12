# Audit export

This document describes how the audit log of Tenko DDI leaves the installation: the sinks (syslog over UDP, TCP and TLS, and a file), the three formats (RFC 5424, CEF and JSON lines), the chain checkpoints that make truncation and gaps visible, how delivery works in a cluster, what happens when a sink fails, the security profile toggle TGL-21, the API, the command line and the error codes. It is for administrators who connect Tenko to a SIEM or a log shipper, for people who write receivers, and for reviewers. Requirements are cited by ID and defined in [REQUIREMENTS.md](REQUIREMENTS.md) (IAM-18); the toggle TGL-21 is defined in [SECURITY-PROFILES.md](SECURITY-PROFILES.md). The audit log itself and its hash chain are described in [ARCHITECTURE.md](ARCHITECTURE.md), the endpoints in the [OpenAPI document](api/openapi.json). Where this document and the code (`crates/tenko-auth/src/audit_export/`) disagree, the code is right and the document has a defect.

Contents:

1. [Overview](#1-overview)
2. [Sinks](#2-sinks)
3. [Formats](#3-formats)
4. [Checkpoints and verification](#4-checkpoints-and-verification)
5. [Delivery](#5-delivery)
6. [Failure, alarm and status](#6-failure-alarm-and-status)
7. [TGL-21](#7-tgl-21)
8. [API](#8-api)
9. [Command line](#9-command-line)
10. [Configuration, tables, audit actions and error codes](#10-configuration-tables-audit-actions-and-error-codes)
11. [Limits and open items](#11-limits-and-open-items)

## 1. Overview

Every change and every refused or failed action in Tenko writes an audit record in the same atomic step as the change. The records form a hash chain: each record has a gap-free sequence number from 1, carries the hash of its predecessor (`prev`) and is sealed with SHA-256 over the canonical CBOR of its other fields (`hash`). The chain is the same on every controller and `tenko audit verify` checks it.

The audit export sends every record, in order, to one or more **sinks**. Each sink has its own format and its own **cursor**: the last record it was handed. The export runs on the controller that leads the cluster, follows the log as it grows, and writes **checkpoints** into the stream so that a receiver sees when records are missing at the end. A record never leaves Tenko without its sequence number and hash, so a receiver can drop duplicates and verify the chain without Tenko.

## 2. Sinks

A sink is a destination with a name, a format and an on/off switch. The installation holds up to 8 sinks; they are settings in the store, the same on every controller, changed through the API or the settings page and audited.

| Kind | Transport | Default port | Delivery |
|---|---|---|---|
| `syslog`, `udp` | RFC 5426: one message per datagram | 514 | Best effort: nothing confirms receipt |
| `syslog`, `tcp` | RFC 6587 octet counting (`<length> <message>`) | 514 | At least once while the connection holds; see [5](#5-delivery) |
| `syslog`, `tls` (default) | RFC 5425: octet counting over TLS 1.2 or 1.3 | 6514 | As TCP, with the receiver authenticated |
| `file` | One message per line in a file on the exporting controller, rotated by size | | At least once; every write is followed by `fsync` |

Fields of a sink:

| Field | Meaning |
|---|---|
| `id` | Stable id, assigned by the server; the cursor is kept under it. Omit it for a new sink. |
| `name` | 1 to 64 characters, unique (case-insensitive) |
| `enabled` | Default true. A disabled sink keeps its cursor and resumes from it when it is switched on again. |
| `format` | `rfc5424` (default), `cef` or `json` |
| `target.kind` | `syslog` or `file` |
| `target.transport` | `udp`, `tcp` or `tls` (default) |
| `target.host`, `target.port` | The receiver; a host name or an IPv4 or IPv6 address. The port defaults as in the table. |
| `target.facility` | `user`, `daemon`, `auth`, `authpriv` (default, 10), `log_audit` (13), `local0` to `local7` |
| `target.tls.ca_pem` | The certificate authorities that sign the receiver's certificate; empty: the operating system's roots |
| `target.tls.server_name` | The name the receiver's certificate must carry; empty: `host` |
| `target.tls.client_cert_pem`, `target.tls.client_key` | A client certificate chain and the id of the operator secret (see [secrets.md](secrets.md)) that holds its private key in PEM, for receivers that require client authentication. Both or neither. |
| `target.file` | A plain file name (letters, digits, `-`, `_`, `.`, not starting with a dot) inside the export directory of the controller (`[audit_export] file_dir`, by default `<data_dir>/audit-export`) |
| `target.max_bytes` | Rotation size, 64 KiB to 1 TiB, default 64 MiB |
| `target.keep` | Rotated files kept, 0 to 1000, default 10 |

A **new sink exports the whole log from record 1**. Editing a sink keeps its id and its position: pointing an existing sink at a new receiver does not resend the past. To give a new receiver the whole log, add a new sink (and remove the old one).

File sinks: the directory and the file are created with modes 0700 and 0600 on Unix. On rotation `<file>.<n>` becomes `<file>.<n+1>`, the oldest beyond `keep` is removed, `<file>` becomes `<file>.1` and a new `<file>` starts with a checkpoint, so every file verifies on its own ([4](#4-checkpoints-and-verification)). A file sink writes on the controller that leads; after a leader change the next part of the export is in the directory of the new leader. Collect the files with a log shipper on every controller, or prefer a network sink in a cluster.

The TLS client key is read from the vault each time the sink connects and is never logged or audited; the audit trail names only the secret's id.

## 3. Formats

Every message has the record's sequence number and hash; none contains a line break, so a file holds one message per line.

| Format | Syslog sink | File sink |
|---|---|---|
| `rfc5424` | RFC 5424 header, structured data `[tenko@32473 …]`, a UTF-8 BOM, the JSON form | The same line without the BOM |
| `cef` | RFC 5424 header without structured data, the CEF line | The CEF line |
| `json` | RFC 5424 header without structured data, the JSON form | The JSON form (JSON lines) |

**The RFC 5424 header.** `<PRI>1 TIMESTAMP HOSTNAME tenko - MSGID SD MSG`. PRI is facility times 8 plus severity: 5 (notice) for a successful action, 4 (warning) for a denied or failed one, 6 (informational) for a checkpoint or a test. TIMESTAMP is the record's time in UTC with microseconds, so a record sent twice carries the same header. HOSTNAME is the exporting controller's TLS host name (`-` when it has none). MSGID is `audit`, `checkpoint` or `test`.

**Structured data.** SD-ID `tenko@32473` (32473 is the documentation enterprise number of RFC 5612, used until a number is registered) with `seq`, `hash` and `prev` for a record; `checkpoint="1"`, `seq`, `hash` and `store_head` for a checkpoint; `test="1"` for a test message.

```text
<85>1 2026-10-11T12:00:00.123456Z ctl1.example.test tenko - audit [tenko@32473 seq="42" hash="9f2c…" prev="51ab…"] {"type":"record","seq":42,…}
```

**The JSON form.** One object, discriminated by `type`:

- `record`: every field of the audit record (`seq`, `revision`, `at`, `principal`, `request`, `draft` with `action`, `objects`, `outcome`, `source_ip` and `details`, `prev`, `hash`) plus `cbor`, the canonical CBOR of the hashed part of the record in standard base64. `SHA-256(cbor)` equals `hash`, so a receiver checks a record without knowing the encoding rules, and the record before it by `prev`.
- `checkpoint`: `sink`, `seq` and `hash` (the last record sent before the checkpoint; 0 and the zero hash before the first), `store_head` (the newest record of the log at that moment) and `at`.
- `test`: `sink`, `at` and `by` (the subject who asked for it).

```json
{"type":"checkpoint","sink":"siem","seq":42,"hash":"9f2c…","store_head":57,"at":"2026-10-11T12:05:00Z"}
```

**CEF.** `CEF:0|Tenko|Tenko DDI|<version>|<action>|<action>|<severity>|<extension>`, severity 3 for a success, 6 for a failure, 7 for a denial and 1 for a checkpoint or a test. The extension, in this order: `rt` (milliseconds since the epoch), `suser` (the principal's subject, such as `user:<uuid>`), `src` (an IPv4 client address) or `c6a2` with `c6a2Label=source` (IPv6), `outcome` (`success`, `denied`, `failed`), `reason` (the error code of a failure), `cn1`/`cn1Label=seq`, `cs1`/`cs1Label=hash`, `cs2`/`cs2Label=prev`, `cn2`/`cn2Label=revision`, `cs3`/`cs3Label=objects` (`kind/uuid`, comma-separated), `cs4`/`cs4Label=request`, and `msg` with the record's details as JSON. A checkpoint has the signature `audit.export.checkpoint` with `cn1` (seq), `cs1` (hash), `cn3` (`store_head`) and `cs5` (sink); a test `audit.export.test` with `suser` and `cs5`. Header fields escape `\` and `|`; extension values escape `\`, `=`, line feed (`\n`) and carriage return (`\r`).

## 4. Checkpoints and verification

A sink sends a checkpoint when it connects, after every 100 records, every 5 minutes (also while the log is idle) and at the top of every new file after a rotation. A checkpoint names the last record sent before it and the newest record of the log.

What a receiver can see:

- **Gaps** by sequence number: record `n` must follow `n - 1`, and its `prev` must be the hash of `n - 1`.
- **Tampering** by hash: `hash` must match the record (for the JSON form: `SHA-256(cbor) = hash`, and `cbor` must encode the fields).
- **Truncation** by checkpoint: a checkpoint that names record `n` while the receiver holds less, or one that names a `store_head` far ahead of what arrives later, shows that records are missing. Truncation after the last checkpoint is visible at the next checkpoint, at the latest 5 minutes later.
- **Duplicates** by sequence number: delivery is at least once ([5](#5-delivery)). A record that arrives again has the same sequence number and hash and is dropped.

`tenko audit verify --file export.jsonl [--from <seq>:<hash>]` verifies a JSON export offline. The chain starts at the head given with `--from` (which the file must continue), else at the first checkpoint of the file, else at record 1, else at the first record's own `prev` (the report then says the start is not anchored). Every record line must carry canonical bytes that hash to `hash` and encode its fields, and the records must form the chain. Records at or below the verified head are duplicates and must equal the record verified under that number (within the last 100,000 records); a checkpoint must name a position of the verified chain. The first problem ends the check with exit status 9 and names the line and a code: `sys.audit.gap`, `sys.audit.broken_link`, `sys.audit.bad_hash`, `audit.export.verify.cbor`, `audit.export.verify.checkpoint`, `audit.export.verify.duplicate` or `audit.export.verify.malformed`.

To verify a rotated set, verify each file alone (each starts with a checkpoint), or concatenate them oldest first and verify the result. To tie an export to the live log, compare its last head with `GET /audit/{seq}` or run `tenko audit verify` against the server.

## 5. Delivery

The exporter is a leader-only service (`audit.export`, see [cluster.md](cluster.md)): it runs on the controller that leads, starts when that controller takes office and stops when it loses it. It runs one worker per enabled sink. A worker reads the records after its cursor in batches of 500, renders them and hands them to the transport; it wakes on every commit that adds audit records and looks at least once a second.

The cursor is written to `sys.audit_export_cursors` every 5 seconds or 500 records while records flow, when the state of the sink changes and when the worker stops. The write is fenced with the leader epoch, so a controller that lost office cannot move a cursor. A worker that reconnects, and a controller that takes over after a leader change, resumes **at the stored cursor**: the records sent after it may arrive a second time, but none is skipped. Receivers drop duplicates by sequence number.

The guarantee has the limits of the transports:

- **UDP** has no acknowledgement: a lost datagram is lost. A message longer than 65,000 bytes is cut at a character boundary (the structured data with sequence and hash comes first). Use TCP or TLS where completeness matters; the checkpoints still show what is missing.
- **TCP and TLS** syslog have no application acknowledgement either (RFC 5425 and RFC 6587). A message written into the socket just before the connection breaks may be lost by the network; the rewind to the stored cursor after a reconnect resends the last up to 5 seconds or 500 records and closes that window in practice. A receiver that accepts the connection and then discards data cannot be detected by Tenko, only by the checkpoints.
- **Files** are written with `fsync` after every batch.

A change of the settings restarts the workers; each resumes from its cursor.

## 6. Failure, alarm and status

A sink fails when its host does not resolve, the connection is refused or times out (10 seconds), the TLS handshake or the receiver's certificate fails, a write fails or times out (30 seconds), the client key cannot be read, or the file cannot be written. The worker retries with a pause that doubles from 1 second up to 1 minute. The first failure, a change of the failure's code and the recovery are written to the cursor at once.

When a sink has failed for `alert_after_secs` (5 minutes by default, 10 seconds to one day), the exporter raises the alarm **`audit.export.failing`**: an audit record `sys.audit_export.failing` naming the sink and the code; when the sink works again, `sys.audit_export.recovered`. Both are records of the chain and reach the sink once it works.

Every controller computes the status of every sink from the cursors, so the status is the same wherever it is read:

| State | Meaning |
|---|---|
| `disabled` | Switched off |
| `pending` | Has not delivered yet |
| `ok` | Current, or catching up |
| `behind` | Records wait and the cursor has not moved for `alert_after_secs` (the exporter does not run, for example while no controller leads) |
| `failing` | The last attempt failed |
| `alarm` | Failing for at least `alert_after_secs` |

`/system/status` on every controller shows the warning `audit.export.failing` while a sink is in `alarm` or `behind` (params `sinks`, `count`, `since`, and `required`, true when TGL-21 requires an export and no enabled sink works), and the warning `audit.export.required` while TGL-21 requires an export and no sink is enabled. A warning that appears or goes is also a `system` event of kind `audit.export.warning` (params `code`, `active`). Every change of a cursor is a `system` event too, because the tables `sys.audit_export*` map to that topic.

## 7. TGL-21

TGL-21 decides what the installation requires of the export ([SECURITY-PROFILES.md](SECURITY-PROFILES.md)): `local` (Home, Lab), `optional` (Standard) and `required` (Hardened). The audit log itself is never off.

While TGL-21 is `required`, `PUT /settings/audit-export` refuses settings without an enabled sink (409 `audit.export.required`, audited as a failed `sys.audit_export.update`), and the status shows the warning `audit.export.required` when no sink is enabled, for example right after switching to Hardened. `GET /settings/audit-export` reports the policy as `policy.audit_export`, `policy.required` and `policy.satisfied`, which the setup wizard and the banner of the UI use. The settings of the security profile do not consult the export yet; see [11](#11-limits-and-open-items).

## 8. API

| Endpoint | Permission | Success | Errors |
|---|---|---|---|
| `GET /settings/audit-export` (`get_audit_export`) | The global read permission on the audit log, as `GET /audit/verify` (see [access.md](access.md)): an administrator, the auditor role, a token with `audit:read` | 200 `AuditExportView` with `ETag: "<revision>"` | 401, 403, 501 |
| `PUT /settings/audit-export` (`put_audit_export`) | Update on the system (administrators) | 200 `AuditExportView` with the new `ETag` | 400 `audit.export.invalid`, 401, 403, 409 `audit.export.required` or `audit.export.conflict`, 501 |
| `POST /settings/audit-export/test` (`test_audit_export`) | Update on the system | 200 `AuditExportTestResult` | 400, 401, 403, 404 `audit.export.not_found`, 501 |
| `GET /audit/export?from=&limit=` (`export_audit`) | Read on the audit log, globally | 200 `AuditExportPage` | 400 `sys.invalid_query`, 401, 403 |

- `AuditExportView`: `revision`, `alert_after_secs`, `sinks` (each sink's fields with `status`: `state`, `delivered` {`seq`, `hash`}, `lag`, `updated_at`, `last_success_at`, `failing_since`, `last_error` {`code`, `detail`, `at`}, `checkpoint` {`head`, `at`}), `policy` {`audit_export`, `required`, `satisfied`}, `store_head`, `warnings` [{`code`, `detail`, `params`}].
- `AuditExportUpdate` (the `PUT` body): `sinks` (the complete list; a sink without `id` is new, a stored sink left out is removed with its cursor) and `alert_after_secs`. `If-Match: "<revision>"` makes the change conditional. Invalid fields come back in `errors` with codes such as `audit.export.name`, `audit.export.host`, `audit.export.file`.
- `AuditExportTest` (the test body): `sink` (a stored sink's id) or `spec` (a sink as the form holds it), exactly one. The test message is sent from the controller that serves the request (a file sink writes into that controller's directory) and is not part of the chain. `AuditExportTestResult`: `delivered`, `error`, `elapsed_ms`; a failed delivery is a 200 with `delivered: false`. Audited as `sys.audit_export.test`.
- `AuditExportPage`: `anchor` (the record before `from`), `records` in sequence order (up to `limit`, 1 to 5,000, default 1,000), `next` and `store_head`. A principal with scoped grants only is refused, because an export is only verifiable whole.

## 9. Command line

- `tenko audit export [--from <seq>] [--format json|rfc5424|cef] [--output <file>]` writes the log from `--from` (default 1) through the API: a leading checkpoint that anchors the file, the records, a checkpoint after every 100 records and a final one. Without `--output` it writes to standard output.
- `tenko audit verify --file <file> [--from <seq>:<hash>]` verifies a JSON export offline, without a server ([4](#4-checkpoints-and-verification)); exit status 0 when intact, 9 when not. Without `--file`, `tenko audit verify` asks the server to check the live chain as before.

## 10. Configuration, tables, audit actions and error codes

`tenko.toml`:

```toml
[audit_export]
# An absolute directory for the files of file sinks; default: audit-export/ in the data directory.
# file_dir = "/var/log/tenko-audit"
```

Store tables (both on the `system` event topic):

| Table | Key | Value |
|---|---|---|
| `sys.audit_export_settings` | `()` | The sinks and `alert_after_secs` |
| `sys.audit_export_cursors` | sink id | `delivered` (seq and hash), `updated_at`, the last checkpoint, `last_success_at`, `failing_since`, `last_error`, `alarmed` |

Audit actions: `sys.audit_export.update` (a settings change, one field change per added, removed or changed sink and for the alarm delay; never a secret), `sys.audit_export.test`, `sys.audit_export.failing`, `sys.audit_export.recovered`.

Error codes:

| Code | Status | When |
|---|---|---|
| `audit.export.invalid` | 400 | The settings or the test spec are invalid; `errors` names each field with one of `audit.export.name`, `audit.export.duplicate`, `audit.export.unknown_sink`, `audit.export.too_many`, `audit.export.host`, `audit.export.port`, `audit.export.pem`, `audit.export.client_key`, `audit.export.tls_unused`, `audit.export.file`, `audit.export.range`, `audit.export.test_target` |
| `audit.export.required` | 409 | TGL-21 requires an export and no sink would be enabled; also the status warning |
| `audit.export.conflict` | 409 | `If-Match` is stale, or the settings changed during the request (params `expected`, `current`) |
| `audit.export.not_found` | 404 | No sink has the id of a test (param `sink`) |
| `audit.export.failing` | | The alarm and status warning of a sink in `alarm` or `behind` |

Failure codes in a sink's `last_error` and a test result: `audit.export.resolve`, `audit.export.connect`, `audit.export.tls`, `audit.export.send`, `audit.export.file`, `audit.export.client_key`, `audit.export.config` (a file sink on a controller without an export directory, or a record that cannot be encoded).

## 11. Limits and open items

- The security settings (`PATCH /settings/security`) do not yet refuse switching TGL-21 to `required` or the profile to Hardened while no sink is enabled; the status warning `audit.export.required` shows instead. The check is `tenko_auth::audit_export::status::required_unmet`, to be called by the settings service.
- The client certificate of a TLS sink is supplied by the operator; issuing it from the internal CA is not built.
- No HTTPS push to a collector (S3-Q6 option b); webhooks come with API-06.
- `tenko audit verify --file` reads JSON exports only; RFC 5424 and CEF files carry sequence and hash for receivers but are not verified by Tenko.
- A file sink writes on the leading controller only; in a cluster the files of one sink are spread over the controllers that led.
