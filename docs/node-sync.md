# Node sync: configuration, commands and results between controllers and nodes

This page describes how the controllers of Tenko DDI hand configuration, commands and secrets to their data-plane nodes and take the results back: the seven calls of the `Config`, `Commands` and `Observations` services, how a node receives its configuration as deltas from the journal or as a compressed snapshot, how the stream is paced under a bandwidth cap, how a node applies and keeps what it receives, how commands such as scans on demand and the kill switch travel, how a probe gets the SNMP secrets its configuration names, how a resent batch is recognised on every controller, what the controller's own probe role does, and what a partition does to all of it. It is for an administrator who runs probes at several sites and for a developer who adds a node role. It describes the behaviour of the `node_sync` module, the `Config`, `Commands` and `Observations` services and the node agent of the `tenko-cluster` crate, of the scan control in `tenko-scan` and of the scanner supervisor in the `tenko` crate; where this page and the code differ, the code is right. The requirements are OPS-28, SCAN-05, SCAN-09 and IAM-16 in [REQUIREMENTS.md](REQUIREMENTS.md). The messages are defined in [`config.proto`](../crates/tenko-cluster/proto/tenko/cluster/v1/config.proto), [`commands.proto`](../crates/tenko-cluster/proto/tenko/cluster/v1/commands.proto) and [`observations.proto`](../crates/tenko-cluster/proto/tenko/cluster/v1/observations.proto), package `tenko.cluster.v1`.

The transport, enrolment, certificates and heartbeats are in [cluster.md](cluster.md); the scanner that the probe runs, the `[scan]` section and the API of scans are in [scanning.md](scanning.md); what the reconciler does with the batches is in [reconciliation.md](reconciliation.md).

Terms used below: a **node** is an enrolled data-plane installation; today only the role `probe` uses configuration and commands. The **subset** of a node is the set of configuration rows that its roles receive. A **revision** is a revision of the replicated store of the controllers; it counts every committed write, not only those of one node. A **frame** is one `ConfigDelta` message of the stream; a **message** is one revision's worth of configuration, sent as one or more frames.

Contents:

1. [The streams](#1-the-streams)
2. [Deltas and snapshots](#2-deltas-and-snapshots)
3. [Pacing](#3-pacing)
4. [On the node](#4-on-the-node)
5. [Commands and results](#5-commands-and-results)
6. [Secrets](#6-secrets)
7. [Ingest cursors](#7-ingest-cursors)
8. [The relay buffer](#8-the-relay-buffer)
9. [The kill switch](#9-the-kill-switch)
10. [What a partition does](#10-what-a-partition-does)
11. [Files, settings, error codes and audit actions](#11-files-settings-error-codes-and-audit-actions)

## 1. The streams

Every call arrives over the mutual TLS connection of the cluster port. The controller identifies the caller by the serial of its certificate and loads the node record; a node that does not exist or does not hold that certificate is refused with `cluster.node.unknown` or `cluster.node.certificate_unknown` (403). Any controller serves any node, from its own copy of the replicated store; a node that is connected to a follower is served by the follower.

| Call | Who may call | What it does |
|---|---|---|
| `Config.Watch(from_revision)` | Any enrolled node; it sees only its own subset | Server stream. The first message answers `from_revision` (section 2); later messages are deltas as they are committed. It stays open until the node closes it |
| `Config.Secrets(purposes)` | Any enrolled node, for the purposes its roles use (section 6) | Hands over the secrets that the node's configuration names, by purpose. At most 16 purposes per request |
| `Config.Offer(table, encoding, payload)` | Any enrolled node, for the tables its roles use (`scan.probe_config` for `probe`); otherwise 403 `node.config.kind` | Offers the node's own configuration as its initial one (section 4.4) |
| `Config.Report(...)` | Any enrolled node | Reports the revision the node applies, where it came from, an error and, for a probe, its effective scope (section 4.5). A probe's scope is written to the store, so the call needs a controller that can write |
| `Commands.Subscribe(after)` | Any enrolled node; it gets only its own commands | Server stream of the commands the node has not finished (section 5) |
| `Commands.Report(event)` | Any enrolled node, for its own commands only; 404 `node.command.not_found` otherwise | Reports the state of a command |
| `Observations.Ingest(batch)` | A node with the role `probe`; 403 `cluster.node.role` otherwise | Hands one batch of the node's buffer to the reconciler (section 7) |

The node announces the capabilities `config-sync` and `commands` in the handshake. A controller that answers `UNIMPLEMENTED` to `Watch`, `Subscribe`, `Offer` or `Report` makes the node keep working on what it has, without error: it logs that the controller does not sync configuration or send commands.

Message size limits on the cluster port: a request to `Config` or `Commands` is at most 1 MiB; a message the controller sends on `Config` is at most 32 MiB; an `Ingest` request and its answer are at most 32 MiB each. A node reads at most 32 MiB per message.

## 2. Deltas and snapshots

### 2.1 What a node receives

The configuration of a node is the set of rows keyed by its node id in the configuration tables of its roles. The tables are in `node_sync/tables.rs`:

| Table | Role | Contents |
|---|---|---|
| `scan.probe_config` | `probe` | The scan configuration of the probe, one row per node (section 4.3 and [scanning.md](scanning.md#75-configuration-from-the-controller)) |

A node with the roles `dns` or `dhcp` has no configuration table yet: its subset is empty and its stream carries empty messages. Those roles add their tables to the same list.

A row is a CBOR map. A field `secrets` in it names the vault secrets the node may fetch (section 6); other fields are ignored by that mechanism.

### 2.2 Which message the first answer is

The controller reads its local copy at a revision `V` and answers `from_revision` `S` of the node:

- **A snapshot** when `S` is 0, when the journal of the store no longer covers `S` (it was compacted past it, or it ends before `V`), or when more than 50,000 revisions lie between `S` and `V` (`MAX_JOURNAL_SCAN`). The snapshot lists every row of the subset and replaces what the node holds.
- **A delta** otherwise. The controller reads the change sets of `sys.journal` in `(S, V]`, collects the tables of the subset that any of them touched, and lists each such row with its value at `V`, or with no value when the row is gone. Rows are whole values, so applying a delta twice, or one whose rows the node holds already, changes nothing. A delta cannot miss a change, because every revision in `(S, V]` is read in the same view.

The first message is always sent, also when it is empty, and carries `V` as its revision. Later messages follow the change stream of the store, filtered on the tables of the subset. Each wake-up reads the local copy again and sends a delta from the last revision sent; a wake-up that changes none of the node's rows sends nothing. If the journal has a gap by then, a snapshot is sent instead.

A controller whose copy is behind the revision the node holds waits for it for a short time, then refuses with 503 `node.config.behind`. The node tries the next controller (section 10).

### 2.3 Encoding and compression

| Message | `encoding` | Form |
|---|---|---|
| Delta | `cbor/1` | The payload `{entries: [{table, key, value}]}` in CBOR; `key` is the encoded key of the row, `value` the CBOR value of the row, absent for a removed row |
| Snapshot | `cbor+deflate/1` | The same payload, compressed with raw deflate (RFC 1951) |

A node refuses an encoding it does not know with `node.config.encoding` (400) and keeps its configuration. The limits it enforces on every payload it reads: 32 MiB on the wire, 64 MiB after inflating, 100,000 rows, 1,024 bytes per encoded key, table names that are valid table names. A payload that breaks one is refused with `node.config.payload` (400). Command arguments are CBOR (`cbor/1`) of at most 64 KiB.

### 2.4 Frames and continuations

A message is sent as one frame, unless a bandwidth cap is set and the payload is larger than 16 KiB: then it is cut into chunks of 16 KiB. Every frame carries the revision, `snapshot`, the `encoding` and its part of the payload; `partial` is true on all frames but the last. The node joins the payloads of the frames of one message before it decodes them. A frame of another revision, kind or encoding in the middle of a message is an error: the frames so far are dropped (`node.config.payload`, section 4.2).

## 3. Pacing

`[cluster] sync_kbps` caps each configuration stream, in kilobits per second of 1,000 bits. The default is 0, which is no cap; the maximum is 10,000,000 (a larger value stops the start with `config.invalid`). The cap is per `Watch` stream, not per controller or per node, and it is set on the controller, which reads it at start.

The cap is a token bucket over bytes. The rate is `sync_kbps` times 125 bytes per second. The bucket holds a tenth of a second of the rate, and at least 4,096 bytes, when it is full. The sender takes the size of each frame from the bucket before it sends it, and waits while the bucket is in debt, so the average rate of a stream stays at the cap; the first frames after an idle period go out at once, up to the burst. Without a cap a message is one frame and nothing waits.

## 4. On the node

### 4.1 Atomic apply and the file

The node keeps its configuration in `<data_dir>/node/config/state.cbor` (section 11.1): the revision, the time it was applied and the rows, sorted by table and key. Applying a message works on a copy:

- A snapshot replaces every row. A delta replaces the rows it names and removes those it names without a value.
- A message with a revision lower than the one the node holds is ignored. A message with the same revision is applied; it changes nothing the second time.
- The copy is written to a temporary file, flushed to disk and renamed over `state.cbor`, and only then does it replace the configuration in memory and reach the role that uses it. A crash leaves the old file or the new one, never a mix.

The node loads the file at start. The revision it holds is the `from_revision` of every `Watch` it opens, so a node that was offline for two changes receives a delta for both, and one that was offline past a compaction of the journal receives a snapshot. A file that does not decode is logged and treated as no configuration (revision 0); the node then receives a snapshot.

The node keeps using the configuration it holds across restarts and while no controller answers. Nothing deletes it when the connection is lost.

### 4.2 A message that does not apply

A message that cannot be applied (an unknown encoding, frames that do not belong together, a payload over a limit, a file that cannot be written) leaves the configuration as it is. The node logs it, records the cause in the `error` of its next `Config.Report` (at most 2,000 characters), waits 5 seconds and opens `Watch` again from the revision it holds.

A message that applies but holds a row the role cannot use is the role's concern: the probe keeps running its configuration in force and reports the cause (section 4.3).

### 4.3 The probe's configuration

On a probe the row `scan.probe_config` of the node decides what the scanner does:

- **Once the node holds the row**, the controllers' configuration wins. The scanner runs on it; the `[scan]` section of `tenko.toml` is no longer read by the node process.
- **Before the first sync**, and while no row exists for the node, the scanner runs on the `[scan]` section of the node's own `tenko.toml`. The same section serves `tenko node scan run`, with or without `--dry-run`, and `tenko node scan status` when no scanner is running: those commands never read `state.cbor`.
- A new configuration that differs from the one in force replaces the running scanner. The old scanner is stopped first (the node waits up to 10 seconds for it) and a new one starts. An identical configuration changes nothing. `enabled = false` stops the scanner.
- A row that does not decode, does not validate as a stored configuration, or does not build into a scanner is not applied. The scanner in force keeps running and the cause goes to the controllers in the `error` of the report.
- The revision the probe reports for a synced configuration is the revision of the controllers' store that its copy reflects; the controller compares it with the revision of the row ([scanning.md](scanning.md#75-configuration-from-the-controller)).

### 4.4 The offer at the first connection

When a node has no row for a table of its roles, it offers its own configuration of that kind at its first connection: a probe offers its `[scan]` section. The node removes every SNMP password and password-file path from the offer first; vault secret references stay. The controller then:

1. Checks that the table is one of the node's roles and that an offer handler exists (otherwise 403 or 503 `node.config.kind`).
2. Decodes the payload (`cbor/1`, at most 1 MiB) and validates it as a stored configuration, exactly as for `PUT /api/v1/nodes/{id}/scan-config`. A configuration that carries a password or a password file is refused with 422 `node.config.invalid`. The node never sends one; the check is the controller's own.
3. Drops the vault secret references of the offer, because a node cannot name secrets it was never given; an administrator picks them.
4. Keeps it only when it holds no configuration for the node (`accepted: true`). Otherwise `accepted` is false and the controller's configuration wins. The row gets the origin `offer`, and the audit record `scan.config.offer` is written under the node.

The node offers once per process, and only when it holds no row for the table. A refusal or a failed call is tried again at the next connection. Devices of the offered configuration that lacked a password after the removal are logged on the node; they stay unpolled until an administrator gives them vault secrets (section 6 and [scanning.md](scanning.md#123-snmp-devices)).

### 4.5 The config report

The node tells the controllers what it applies. `Config.Report` carries:

| Field | Meaning |
|---|---|
| `revision` | The configuration revision the node applies; 0 when it runs on its own file |
| `source` | `synced` (the controllers') or `local` (the node's own file, before the first sync) |
| `error` | Why the newest configuration does not apply; empty when it does |
| `probe` | A probe's effective scope: `prefixes`, `exclude`, `methods` (those that run on schedule), `vrf`, `active`, `stopped` and `stop_reason` of the kill switch |
| `at` | The node's clock when it applied the configuration |

A probe sends a report after every configuration it applies or refuses, at each connection after the offer, and when the kill switch changes by command. A newer report replaces one not sent yet. A failed call is tried again every 5 seconds. The controller stores the scope of a node with the role `probe` in `scan.scopes`, keyed by node id, and writes only when something other than the timestamps changed. `GET /api/v1/nodes/{id}/scan-config` and `GET /api/v1/scans/probes` show it as `applied`, with `in_sync`.

## 5. Commands and results

### 5.1 The records

A command is a row of `cluster.node_commands`, keyed by node id and command id. The id is a UUIDv7, so the commands of a node sort in the order they were issued.

| Field | Meaning |
|---|---|
| `kind`, `encoding`, `payload` | What to do and its arguments (section 5.2) |
| `issued_at`, `issued_by` | When, and the user who asked, when a person did |
| `run` | The scan run (`scan.runs`) the command belongs to, if any |
| `expires_at` | When it is no longer sent; the commands of a scan run expire at its deadline, those of the kill switch never |
| `state`, `progress`, `detail` | The state, 0 to 100, and the node's last detail in English (at most 2,000 characters) |
| `batches`, `ingested` | The batches the node announced with `done`, and the batches tagged with the command that the controllers ingested |
| `updated_at`, `reported_at` | When the record changed, and the node's clock at its last report |

| State | Set by | Meaning |
|---|---|---|
| `pending` | Controller | Issued; the node has not confirmed it |
| `accepted` | Node | The node took it |
| `running` | Node | The node works on it, with a progress |
| `done` | Node | Finished. For a scan run it is final once the announced batches have arrived (`settled`) |
| `failed` | Node | The node tried and failed |
| `rejected` | Node | The node refused it: an unknown kind, arguments it cannot decode, a scanner that is switched off |
| `expired` | Controller | Not finished before `expires_at` |
| `cancelled` | Controller | Withdrawn by the issuer |

A node reports `accepted`, `running`, `done`, `failed` and `rejected`; any other state in a report is refused with `node.command.invalid` (400). A report never moves a command backwards, progress never decreases, `done` sets the progress to 100, and a command in a final state takes no more reports; a report that arrives twice changes nothing.

### 5.2 The kinds

| Kind | Arguments (CBOR) | What the probe does |
|---|---|---|
| `scan.run` | `methods`: the method names, in order. `target`: an address or prefix inside the probe's scope, or none for the whole scope. `ignore_blackout`: false unless set. `deadline_secs`: when the issuer stops waiting | Runs each method once, now, with the run id; reports `accepted`, then `running` with the method name and `index * 100 / methods` percent, then `done` with the number of batches it queued. It reports `failed` when no method ran and nothing was queued, or when it was cancelled before any batch, and `rejected` when the scanner is switched off or the arguments do not decode. A name that is not a method is noted and skipped. Methods the scanner refuses (a blackout window, the kill switch, `active = false`) are noted. After `deadline_secs` the probe cancels the run itself |
| `scan.cancel` | `command`: the id of the `scan.run` to cancel | Stops that run if it is running, and reports `done` with the detail `cancelled` or `the scan was not running` |
| `scan.stop` | `reason` | Turns the kill switch on (section 9) |
| `scan.resume` | None | Turns the kill switch off |

A node reports an unknown kind as `rejected`. A node whose process has no role that takes commands rejects every command.

### 5.3 How a command reaches the node

Every controller serves `Commands.Subscribe` for the nodes connected to it, from its own copy of the store, so a node reached through a follower gets the same commands. The stream first sends every command of the node that is not final and not expired and whose id is greater than `after`, in issue order. Then it watches `cluster.node_commands` and sends each new one as the store applies it; it also reads again every 30 seconds so that an expiry is noticed. A command is sent once per stream.

The agent subscribes with an empty `after` each time it opens the stream, so every command that is not final comes again after a reconnect; the agent handles each command id once per process and skips the repeats. After a restart of the node process the commands that were not final are handled again: a kill switch command applies again, which changes nothing, and a `scan.run` that was still running when the process stopped runs again unless it has expired.

Commands that were issued while the node was offline are delivered in order when it connects. The command for the controller's own probe role is not sent over the network: that role follows the table directly (section 8).

### 5.4 Reports back

The agent keeps the reports of the commands in an in-memory queue of up to 10,000 reports and sends them in order over whichever controller it is connected to. The controller applies each report to the record with a conditional write and retries a lost race up to four times (409 `node.command.conflict` after that). A failed call is retried every second; a report for a command that does not exist (404), that is malformed (400) or that the controller does not serve is dropped. The queue is not written to disk: reports not sent when the node process stops are lost, and the command is handled again after the restart (section 5.3).

### 5.5 Results

The results of a scan run are not part of the command. The probe puts each batch into its observation buffer tagged with the run id (`run` in `IngestRequest`, the id of the command), and the buffer sends it like any other batch (section 7). The batches are ingested into the reconciler as usual. For a batch with a `run`, the controller also counts it in the `ingested` of the command and keeps what it reported in `scan.run_results`, keyed by command id and batch sequence, cut to 20,000 sightings per batch (with the number left out); this happens in the same write as the ingest cursor. The `done` report names the number of batches (`batches`). A command is settled when it is final and, for `done`, `ingested` has reached `batches`; the scan job waits for that, up to its deadline, and then compares the results with the facts from before the scan ([scanning.md](scanning.md#77-scans-on-demand-from-the-controllers)).

The leader runs a service `scan.housekeeping` every hour. It removes finished commands and their results after 7 days, scan runs and their baselines after 30 days, and the commands, scopes and probe configuration of nodes that no longer exist 24 hours after the commands were issued or the scope was last reported.

## 6. Secrets

The only purpose today is `snmp`, used by nodes with the role `probe`. A node cannot ask for a purpose its roles do not use (403 `node.config.secrets_purpose`).

A configuration names operator secrets of the vault by id; for a probe the scan control derives the list from `auth_secret` and `privacy_secret` of the SNMP devices and stores it in the field `secrets` of the row, each with the purpose `snmp`. The node asks `Config.Secrets` with the purposes it needs, and the controller answers per request:

1. It checks every requested purpose against the roles of the node.
2. It reads the node's own configuration rows from its local copy and takes the secrets they name for the requested purposes. A node gets nothing that its configuration does not name.
3. It looks each secret up in the vault. Only operator secrets are handed out; a system secret or a secret that does not exist is skipped with a warning.
4. It writes the audit record `cluster.node.secrets` (the node, the purposes, the references of the secrets; never a value) through the store, before it opens any value. When the record cannot be written, no secret leaves: 503 `cluster.no_quorum` when the controller cannot write, 503 `node.config.secrets_unavailable` otherwise.
5. It answers with one entry per secret: the purpose, the secret id as the name, and the value.

When the configuration names no secret for the purposes, the answer is empty, with no audit record and no vault needed. A controller without a vault refuses a request that would hand out secrets with 503 `node.config.secrets_unavailable`.

On the probe the values live in memory only, in buffers that are wiped when dropped. Nothing writes them to disk, not `state.cbor` either, which holds the secret ids and never the values. The SNMP method asks at the start of every run; each request has a timeout of 15 seconds, and each run that needs a secret is one audit record. A value that is not valid UTF-8 is left out with a warning. While no controller answers, the probe uses the values of its last fetch in this process. After a restart without a reachable controller it has none: a device that names vault secrets is skipped with a note, the run is partial and the other methods run as usual, until a controller is reachable. This is the decision S3-Q19 of [plans/slice-3-plan.md](plans/slice-3-plan.md), risk R37: no copy of a credential at rest on the probe.

Secrets travel to the node with the matching role and a configuration that names them, over the mutual TLS connection, and nowhere else. For vault concepts see [secrets.md](secrets.md).

## 7. Cursors

A probe sends the batches of its observation buffer (see [cluster.md](cluster.md#61-the-buffer)) one at a time, oldest first, and removes a batch only after `Ingest` answered. A batch sent again after a lost answer must not be ingested twice, also when it reaches another controller or after a controller restarted. The recognition uses the pair (epoch, sequence) of the batch: the epoch is the UUID of the node's buffer, the sequence counts within it.

`cluster.ingest_cursors` holds one row per node: the epoch and the sequence of the last batch ingested, and when. A batch is covered by the cursor when its epoch is the cursor's and its sequence is not greater. Every controller reads and writes the table, so the recognition holds across controllers and restarts. A new epoch (the buffer's epoch file was lost) starts over.

What `Ingest` does, in order:

1. Refuses a node without the role `probe` (403 `cluster.node.role`).
2. Refuses with 503 `cluster.no_quorum` when the controller cannot write (section 10). This comes before the duplicate check, so an isolated controller answers a resend with the refusal and not with `duplicate`.
3. Looks for the batch in a per-process copy of the last (epoch, sequence) of each node; then in the cursor on the local copy of the store; then, when both say no, in the cursor under a linearizable read, so that a batch that another controller ingested a moment ago is found. If the linearizable read fails for lack of a quorum, the batch counts as not seen.
4. Answers a recognised batch with `duplicate: true` and the sequence, and does nothing else.
5. Otherwise decodes the batch (400 `cluster.probe.invalid_batch` when it fails as a whole), ingests it into the reconciler, and writes the cursor. The write is conditional on the cursor it read, is tried up to four times, and a later cursor that covers the batch already counts as success. For a batch with a `run` the same write counts it in the command and stores its result (section 5.5).
6. Updates the per-process copy and the `last_seen` of the node, and answers with the counts: `new`, `changed`, `refreshed`, `unchanged`, `gone` and `skipped`.

The cursor is written after the ingest, not in the same atomic write. A crash of the controller between the two, or a cursor write that loses every race or fails, leaves a batch ingested without a cursor: the node, which got no answer, sends it again, and it is ingested a second time. The write failure is logged and does not fail the call. A second ingest is harmless to the facts: the reconciler keeps one fact per source and subject, and a fact that has not changed is not rewritten, so the same batch twice leaves the facts as they were; only the counts in the answer and the audit record differ (see [reconciliation.md](reconciliation.md)). For a scan run, the count of ingested batches and the stored result are part of the cursor write, so a batch whose cursor was not written is not counted, and counted once when it arrives again.

A batch the controller refuses as a whole (`InvalidArgument`, such as `cluster.probe.invalid_batch`) is dropped by the node, because sending it again cannot help. Every other failure leaves it in the buffer.

## 8. The relay buffer

A controller that has the role `probe` runs the scanner in its own process under its own node id (shown as `controller-<id>` in the scan API). That scanner does not use the cluster port, but it keeps the guarantees of a probe node:

- Its configuration is its row of `scan.probe_config`, followed in the store directly, else the `[scan]` section of its own `tenko.toml`. At its first start the section is offered like a node's offer (passwords removed) and audited as `scan.config.offer`.
- It carries out the commands of `cluster.node_commands` addressed to its node id by following the table, and writes its reports to the store.
- It reads SNMP secrets from the vault through the same procedure and with the same audit record `cluster.node.secrets`.
- It writes its scope to `scan.scopes`; a report that cannot be written (the controller cannot write) is tried again every 5 seconds until a newer one replaces it.
- Every batch goes into a local buffer, `<data_dir>/scan/relay/`, with a size limit of `[cluster] buffer_mib` and the rules of the node's observation buffer (oldest batches are dropped when it is full). A task hands the batches to the controller's own ingest, oldest first, under its node id, with the same cursor recognition as section 7. While the controller cannot write or the ingest fails, the batches wait in the buffer and the task tries again with a pause that grows from 0.5 to 30 seconds. A batch that fails with a 400 error is dropped. A batch that was ingested but not removed before a crash is recognised by its cursor and not ingested again.

The relay is used for every batch of the in-process scanner, not only after a failure. It keeps what an isolated controller's scanner sees until the controller can write again.

## 9. The kill switch

The kill switch stops all scanning of a probe. Three things switch it:

| Way | Reaches |
|---|---|
| `POST /api/v1/nodes/{id}/scan/stop` and `.../resume` | One probe: one `scan.stop` or `scan.resume` command |
| `POST /api/v1/scans/stop` and `/resume` | Every probe known at that moment: one command each, for every enrolled node with the role `probe` and for the controller's own probe role. A probe enrolled later is not covered |
| `tenko node scan stop` and `resume` on the probe | That probe only, through the file (scanning.md, section 7.1) |

The API requests are recorded as one inline job `scan.edit` that writes the commands and the audit record `scan.stop` or `scan.resume` (with the scope `node` or `installation` and the reason) in one commit, and answer 202 with the command id of each probe. The reason is trimmed, at most 200 characters, and defaults to `stopped from the controllers`.

The commands travel as in section 5.3, so a probe that is connected has the command as soon as the controller it talks to applies the write; the probe does not poll. A probe that is offline gets the commands when it connects, in issue order, and they never expire, so a stop is not lost to an outage. On receipt the probe sets the switch through its running scanner, which stops its scans at once (a running scan gets a short grace to hand back what it saw, [scanning.md](scanning.md#71-the-kill-switch)); the controller side of the switch is in [scanning.md](scanning.md#76-the-kill-switch-from-the-controllers) and writes the file `<data_dir>/scan/stop`; with no scanner running it only writes or removes the file. It then reports `done`, or `failed` with the cause when the file cannot be written, and sends a config report so that the scope shows `stopped` and the reason.

The file survives a restart of the process: a scanner that starts finds the file and starts with the switch on, whatever the controllers say. A command that is not final comes again after a restart (section 5.3) and applies again.

`kill_switch` in the answers of `GET /api/v1/nodes/{id}/scan-config` and `GET /api/v1/scans/probes` shows the newest switch command: `stopped` is what the controllers asked for, with the reason, the time and the user, and `confirmed` is true once the probe reported that command `done`, and false while it is pending or accepted (an offline probe stays unconfirmed). Switch commands are pruned 7 days after they finish; with none left, the view shows the switch as the probe last reported it in its scope, and `confirmed` is true.

## 10. What a partition does

A controller that has lost contact with a quorum for `[cluster] isolation_after_ms` refuses writes and serves reads from its local copy (see [cluster.md](cluster.md#12-the-controller-cluster)). For the node sync:

| Call | On a controller without quorum |
|---|---|
| `Ingest` | 503 `cluster.no_quorum`. The node keeps the batch in its buffer and tries the next endpoint after 200 ms |
| `Config.Watch` | Served from the local copy: it reads at the local consistency and does not need a quorum. A controller that has not reached the revision the node holds refuses with 503 `node.config.behind` and the node tries another one |
| `Commands.Subscribe` | Served from the local copy. Commands issued on the other side of the partition arrive when the copy catches up |
| `Commands.Report`, `Config.Report`, `Config.Offer` | Need a write: 503 `cluster.no_quorum`. The agent retries reports (every second for commands, every 5 seconds for config) and offers at the next connection |
| `Config.Secrets` | A request that would hand out secrets needs the audit record, so it fails with 503 `cluster.no_quorum`; one that hands out nothing succeeds |

A node that gets `cluster.no_quorum` or `node.config.behind` ends the session and, when its list has more than one endpoint, connects to the next one after 200 ms; any other failure backs off from 1 to 60 seconds, with jitter. A node refused for another reason (revoked, unknown certificate) pauses 5 minutes. The list of endpoints comes from enrolment and is refreshed at every handshake from `HelloResponse.endpoints`; a controller that announces none leaves the list as it is. A node that has just enrolled and is unknown to the controller it asks (the enrolment has not reached it) is retried like a broken connection for 10 minutes.

While no controller can be reached, the probe keeps scanning on the configuration it holds, keeps its batches in the buffer and sends them when a controller is back; it has no new commands, cannot report, and cannot fetch secrets other than those fetched earlier in this process.

## 11. Files, settings, error codes and audit actions

### 11.1 Files on the node

| File | Contents |
|---|---|
| `<data_dir>/node/config/state.cbor` | The configuration from the controllers: revision, time applied and the rows (section 4.1). Written atomically, mode `0600` in a private directory on Unix. Holds no secret values |
| `<data_dir>/node/buffer/` | The observation buffer (see [cluster.md](cluster.md#61-the-buffer)) |
| `<data_dir>/scan/stop` | The kill switch of the probe ([scanning.md](scanning.md#8-files)) |
| `<data_dir>/scan/relay/` | On a controller with the probe role: the relay buffer (section 8) |

### 11.2 Settings

| Setting | Where | Default | Meaning |
|---|---|---|---|
| `[cluster] sync_kbps` | Controller | 0 | Cap per configuration stream in kilobits per second; 0 is no cap, at most 10,000,000 (section 3) |
| `[cluster] buffer_mib` | Node, and a controller with the probe role | 64 | Size of the observation buffer and of the relay buffer, 1 to 4,096 |
| `[scan]` | Probe | See [scanning.md](scanning.md#12-configuration-reference) | The configuration before the first sync, for `tenko node scan run`, and the source of the offer |

### 11.3 Error codes

The status is the HTTP-like status the code carries; on the cluster port it becomes the gRPC status (400, 413 and 422 `INVALID_ARGUMENT`, 403 `PERMISSION_DENIED`, 404 `NOT_FOUND`, 409 `FAILED_PRECONDITION`, 503 `UNAVAILABLE`, others `INTERNAL`) and the code travels in the metadata entry `tenko-error-code`.

| Code | Status | Meaning |
|---|---|---|
| `cluster.no_quorum` | 503 | The controller cannot write; the node keeps what it sends and tries the next controller |
| `node.config.behind` | 503 | The controller has not reached the revision the node holds; the node tries another |
| `node.config.encoding` | 400 | A payload in an encoding the receiver does not know |
| `node.config.payload` | 400 | A payload that does not decode, breaks a limit, or frames that do not belong together |
| `node.config.invalid` | 422 | A configuration that does not validate, such as an offer with a password |
| `node.config.kind` | 403, 503 | The configuration kind is not one the node's roles use (403), or this controller takes no offers yet (503) |
| `node.config.files` | 500 | The configuration file of the node cannot be read or written |
| `node.config.secrets_unavailable` | 503 | No vault, the hand-over could not be audited, or the node has no secrets from any controller |
| `node.config.secrets_purpose` | 403, 400 | A purpose the node's roles do not use (403), or more than 16 purposes in a request (400) |
| `node.command.not_found` | 404 | The node has no such command |
| `node.command.invalid` | 400 | A command id that is not a UUID, a state a node does not report, or arguments that do not decode or are larger than 64 KiB |
| `node.command.conflict` | 409 | A command report lost every race for the record |
| `cluster.node.role` | 403 | `Ingest` from a node without the role `probe` |
| `cluster.node.unknown`, `cluster.node.certificate_unknown` | 403 | The node is not enrolled or does not hold that certificate |
| `cluster.probe.invalid_batch` | 400 | A batch that fails as a whole; the node drops it |
| `cluster.probe.no_vrf` | 503 | First-run setup has not created the default VRF; the node keeps the batch |

The codes of the scan API (`node.config.not_a_probe`, `node.config.secret`, `node.config.revision_mismatch`, `scan.job.*`) are in [scanning.md](scanning.md#13-error-codes).

### 11.4 Audit actions

| Action | Written when |
|---|---|
| `cluster.node.secrets` | Secrets are handed to a node (section 6); before the first value is opened |
| `scan.config.update` | A probe's configuration is changed through the API |
| `scan.config.offer` | A probe's own configuration became its stored one (section 4.4) |
| `scan.stop`, `scan.resume` | The kill switch is switched from the controllers (section 9) |
| `scan.run` | A scan on demand is asked for |
