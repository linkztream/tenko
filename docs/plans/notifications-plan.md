# Notifications plan: every alarm reaches people who are not signed in

- Status: Draft, waiting for the owner's decisions (NT-Q1 to NT-Q16 of section 6). No package starts before the owner has answered them and scheduled the slice
- Date: 2026-11-11
- Scope: OPS-29, added by the owner on 2026-11-10. Every alarm of the product can be delivered through channels an administrator configures: e-mail by SMTP submission over TLS (Must), an outgoing HTTPS webhook with a signed JSON body (Must), and MQTT as a publish-only channel with retained state and a last will (Should). The delivery path is the one the general event webhooks of API-06 (Phase 5) will build on. Written against `main` at `cbe6c27a`. Requirement IDs refer to [REQUIREMENTS.md](../REQUIREMENTS.md), toggles (TGL) to [SECURITY-PROFILES.md](../SECURITY-PROFILES.md). Exit criteria, measurements and risks continue the project's series: E89 to E99, M73 to M76 and R160 to R174 (the public DNS plan ends at E88, M72 and R159; the discovery plan of the same day starts at E100, M77 and R175)

This plan follows the shape of [public-dns-plan.md](public-dns-plan.md): the goal and the exit criteria as checks, the design decisions the packages share, the contracts, the work packages with owned files, the order, the owner's decisions, the risks and the owner's actions. "(proposed)" marks a choice the documents leave open. Sizes are in builder-days. One record needs an ADR (the lead numbers it; 0036 is proposed, 0035 being proposed by the public DNS plan): the alarm model, the delivery path and its semantics, the local path of a node without quorum, and the publish-only rule for MQTT (section 10 lists what it must decide). The slice number is the lead's; this plan calls it Slice 16 and its packages WP16.0 to WP16.7.

Terms used throughout, explained once:

- **SMTP** (Simple Mail Transfer Protocol, RFC 5321) carries e-mail between servers. **Submission** (RFC 6409) is the part of it a program uses to hand a message to its own mail server, which then delivers it; the program signs in first. **TLS** (Transport Layer Security) encrypts the connection. **Implicit TLS** starts TLS at once on connecting (port 465, RFC 8314); **STARTTLS** (RFC 3207) starts in plain text on port 587 and upgrades on request. **SASL** (Simple Authentication and Security Layer) is the framework for the sign-in mechanisms SMTP offers through its `AUTH` command (RFC 4954); **PLAIN** (RFC 4616) sends the user name and password, so it is only used inside TLS.
- A **webhook** is an HTTPS request Tenko sends to a URL the administrator gives, with a JSON body, for every notification. **HMAC** (hash-based message authentication code, RFC 2104) is a keyed checksum: the receiver, which holds the same secret, can tell that the body came from Tenko and was not changed.
- **MQTT** (an OASIS standard, versions 3.1.1 and 5.0) is a light publish-and-subscribe protocol common in home automation. A **broker** relays messages: clients **publish** a message to a **topic** (a path such as `tenko/site/alarm/...`) and other clients **subscribe** to topics. A **retained** message is kept by the broker and handed to every new subscriber, so it works as "the current state". The **last will** is a message a client deposits with the broker when it connects; the broker publishes it if the client vanishes without saying goodbye. **QoS** (quality of service) 1 means the broker acknowledges each message.
- **At least once** delivery: every notification is delivered one or more times; a receiver drops repeats by the notification's id. **Backoff**: the pause between retries grows after each failure. A **digest** is one message that sums up several alarms. **Dedup key**: the identity of an alarm, so the same condition raised twice is one alarm.
- **JSON** (JavaScript Object Notation) is the text format of the webhook's body and the MQTT payloads. **UUID** (universally unique identifier) is a 128-bit id; the store's ids are of version 7, which sort by time. An **ADR** (architecture decision record, `docs/adr/`) records one design decision and its reasons. **CLI** is Tenko's command-line interface (`tenko ...`).
- In SMTP: **EHLO** is the client's greeting, which the server answers with the list of extensions it offers (STARTTLS, AUTH and its mechanisms); **CRLF** is the carriage return and line feed that ends every line; **dot-stuffing** doubles a dot at the start of a body line so it cannot end the message early; an **`addr-spec`** is the bare address `user@example.test`; **SMTPUTF8** (RFC 6531) is the extension for addresses with non-ASCII characters, which this plan does not use. **OAuth 2.0** is the token-based sign-in of large mail providers; **XOAUTH2** and **OAUTHBEARER** (RFC 7628) are its two SASL forms.
- In MQTT: **CONNECT** and **CONNACK** open a session and acknowledge it; **PUBLISH** carries a message and **PUBACK** acknowledges it at QoS 1; **PINGREQ** and **PINGRESP** keep an idle connection alive within the **keep-alive** interval; **DISCONNECT** ends a session cleanly (no will is published). A **reason code** in MQTT 5.0 says why a broker refused something.
- In HTTP: **`Retry-After`** is the header in which a server says how long to wait before trying again; a **3xx** answer is a redirect to another URL.
- A **hold-down** is the time a condition must last before it is raised, and must be gone before it is cleared, so that a flapping condition makes no noise. A **token bucket** is a rate limit: each message takes a token, tokens refill at a fixed rate up to a maximum (the **burst**).
- Tenko's own terms: the **leader epoch** is a counter that grows each time a node becomes leader; a write **fenced** with it is refused when another node has become leader since, so an old leader cannot overwrite a new one's work. The **KEK** (key-encryption key) is the node-local key that protects the vault's data keys. **CA** is a certificate authority, such as the cluster's internal one. **ACME** (RFC 8555) is the protocol of public certificate authorities such as Let's Encrypt; **TSIG** (RFC 8945) is the shared-key signature of DNS messages; **DNSSEC** signs DNS data, and a **rollover** replaces its keys in timed steps. **TOTP** is the time-based one-time code of an authenticator app. **WebPKI** is the set of rules by which a browser or a client checks a server's certificate against public certificate authorities. **Playwright** is the browser test tool of the UI's end-to-end tests.
- **Quorum**: the majority of controller nodes that the replicated store (Raft, ADR 0002) needs to accept a change. The **leader** is the controller node that runs the cluster-wide services (ADR 0014).

Contents:

1. [Scope and exit](#1-scope-and-exit)
2. [Design decisions the packages share](#2-design-decisions-the-packages-share)
3. [Contracts and shared files (WP16.0)](#3-contracts-and-shared-files-wp160)
4. [Work packages](#4-work-packages)
5. [Order, measurements and exit checks](#5-order-measurements-and-exit-checks)
6. [Owner decisions](#6-owner-decisions)
7. [Requirement rows touched](#7-requirement-rows-touched)
8. [Risks](#8-risks)
9. [Owner actions and the live test](#9-owner-actions-and-the-live-test)
10. [Documents this slice writes](#10-documents-this-slice-writes)
11. [Sources](#11-sources)

## 1. Scope and exit

### 1.1 Goal

**The case this is for.** Today an alarm is something a person sees after signing in: a badge on the dashboard, a row of the findings list, a warning of `/system/status`. Nobody is told at night that the backup failed, that a controller lost its quorum, that the break-glass account was used or that someone is guessing a password. The owner's first use is a webhook to a flow tool on the home network that feeds their home-automation system; e-mail is the channel every site has; MQTT is the light channel of home automation, and its last will is the one way a receiver learns that Tenko itself is gone.

**What changes.**

1. **One alarm model.** Every alarm source of the product (section 1.5) feeds one layer that gives each alarm a stable code, a severity, an area, a dedup key and a state (raised, cleared), and records each change as an alarm event. The sources stay where they are.
2. **Channels and routes.** An administrator configures channels (an SMTP submission server with recipients, a webhook URL, an MQTT broker) and routes that send alarms to channels by severity and area.
3. **Delivery.** A leader service delivers every alarm event to every channel its routes name, at least once, with retries, rate limits, digests under flood, and a visible state per channel and per alarm.
4. **The hard case.** A controller that lost its quorum cannot write to the store, so it cannot use the normal path; it tells its channels itself, from its local copy, through a bounded local path (section 2.7).
5. **A test delivery** from the UI for every channel, with the failing stage named.

**What stays.** The sources of alarms keep their tables, codes and audit records; the findings list (`GET /findings`) stays the place to work through problems; the audit export (TGL-21) stays the channel for the audit log. Nothing Tenko does is ever driven by a message from a channel: Tenko only sends.

### 1.2 Exit criteria

| # | Check | Requirements | Package |
|---|---|---|---|
| E89 | The alarm layer: every source of section 1.5 marked "in" maps to an alarm with its code, severity, area and dedup key (a table test over the fixtures of each source); a condition raised and cleared produces exactly two alarm events; a condition that flaps inside its hold-down produces none; a warning that only a non-leader controller has (its disk low, its API certificate expiring) and a warning of a `dns` node reach the alarm list (lab-cluster); the same key raised twice is one alarm with a count of 2 (property test over random sequences of source states); the `dns` and `dhcp` role subsets never contain an `alarm.*` or `notify.*` table (a test over `Subset::role_tables`) | OPS-29, IPAM-10, OPS-22, OPS-24 | WP16.0, WP16.1 |
| E90 | The alarm list: `GET /api/v1/alarms` lists raised and recently cleared alarms with their deliveries; an acknowledgment stops the reminders of that alarm and is audited (`alarm.acknowledge`); `tenko alarm list|show|ack` does the same | OPS-29 | WP16.1 |
| E91 | Delivery semantics: with the leader killed in the middle of a batch (lab-cluster, `docker kill`), every alarm event reaches the webhook receiver at least once and every repeat carries the same `webhook-id`; a receiver answering 503 gets retries with growing pauses and `Retry-After` honored up to its cap; an event older than the channel's maximum age is marked `expired` for that channel and counted; a channel failing longer than its alert time raises `notify.channel.failing`, which reaches the other channels and never the failing one | OPS-29 | WP16.2 |
| E92 | Flood: 10,000 alarm events of distinct keys in 10 minutes, of mixed severities (`critical`, `warning` and `info`, from a test-only alarm source compiled into test builds only), and in a second round 200 seeded accounts each failing to their lock threshold, reach an e-mail channel as at most its burst plus one digest per digest interval; every `critical` first raise is delivered before any folded `info`; the folded count is in the digest and in `tenko_notify_folded_total`; `notify.flood` is raised once and cleared when the flood ends | OPS-29 | WP16.2 |
| E93 | The webhook: the receiver verifies every request with the Standard Webhooks reference algorithm and the specification's published test values; during a secret rotation the header carries both signatures and either secret verifies; refused with coded errors and nothing sent: `http://` under Standard and Hardened, a loopback, link-local or metadata address given literally or reached by a name; a 3xx answer is never followed and an answer body above the bound is read only up to the bound; the signing secret and a secret URL never appear in a log line, an audit record, an answer or the delivery state | OPS-29, IAM-16 | WP16.2 |
| E94 | E-mail: against Mailpit with implicit TLS and with required STARTTLS, both with AUTH PLAIN, a notification arrives with `Date`, `Message-ID` from the event id, a `Subject` with Swedish characters in RFC 2047 encoding and a plain-text body; against the fake servers of the test suite: a server whose EHLO answer lacks STARTTLS is refused (`notify.smtp.starttls_missing`), bytes sent by the server after its STARTTLS answer and before the handshake abort the session (`notify.smtp.injection`), a certificate for another name is refused (`notify.smtp.tls`), `535` is reported as `notify.smtp.auth`, multi-line replies of up to 512 octets per line parse; the fuzz target `notify_smtp_reply` runs in the weekly smoke | OPS-29 | WP16.3 |
| E95 | MQTT: against Mosquitto 2 with TLS and a password, each controller publishes `online` retained on its status topic after its CONNACK and its will is `offline` retained; a reconnect within the will delay produces no `offline`; a payload above the broker's Maximum Packet Size is a `failed` delivery, not a disconnect; a raised alarm is a retained state message, its clearing replaces it, its purge deletes it with an empty retained message; `docker kill` of a controller makes the broker publish `offline` within 1.5 times the keep-alive; a fake broker that sends an unsolicited PUBLISH is disconnected and nothing in Tenko changes; a capture of the session shows no SUBSCRIBE; the fuzz target `notify_mqtt_packet` runs in the weekly smoke | OPS-29 | WP16.4 |
| E96 | Quorum lost (lab-cluster): a controller cut off from the other two delivers `cluster.quorum_lost` on each channel marked for the local path within its threshold plus 10 s, once per outage, while the two others deliver `cluster.node_unreachable` for it through the normal path; after the heal one `cluster.quorum_restored`; with all three cut off from each other, each sends once; a restart of the isolated node does not send again | OPS-29, OPS-26 | WP16.5 |
| E97 | The UI: channels and routes are created, edited and tested from the settings; the test delivery reports success with its latency or the failing stage (resolve, connect, TLS, authentication, recipient, HTTP status, broker reason code) for each failure case of E93 to E95; the channel list shows state, last success, last error, events behind and folded counts; the alarm list shows deliveries per channel (Playwright over the mock) | OPS-29 | WP16.6 |
| E98 | The security rows `notify.*` of section 4 pass on the release binary | OPS-29, IAM-16, TGL-41 | WP16.7 |
| E99 | The owner's live test of section 9.2: a webhook to the owner's flow tool with the signature checked there, an e-mail through the owner's submission server, MQTT to the owner's broker, recorded without real names | OPS-29 | WP16.7 (owner-run) |

### 1.3 Requirements

| Requirement | What this slice delivers | Phase today |
|---|---|---|
| OPS-29 Notification channels | All of it: e-mail and webhook (Must), MQTT (Should) | 4, Must (MQTT: Should) |
| API-06 Webhooks | Not delivered. The channel, the signing, the delivery worker and the cursor are built so that event subscriptions become a second source of the same path (section 2.12) | 5, Should |
| IPAM-10 Utilization alarms | Delivered through the channels; the thresholds stay as they are | 1, delivered |
| IAM-16 Vault handling | The SMTP and MQTT passwords, the webhook signing secret, a webhook header token and a URL that carries a secret are operator secrets in the vault, referenced by purpose | 1, delivered |
| IAM-18 Audit log | Every change of a channel or a route, every test delivery and every acknowledgment is audited; deliveries are not (section 2.10) | 1, delivered |
| OPS-05 Metrics | New families `tenko_alarms_*` and `tenko_notify_*` | 1, delivered |
| OPS-22 TLS expiry warnings | Delivered as alarms; the cluster's internal certificates gain an expiry alarm | 1, delivered |
| OPS-24 Updates | "Update available" becomes an alarm of severity `info` | 3, delivered |
| OPS-26 Partition behavior | The isolated controller's local path (section 2.7) | 3, delivered |

### 1.4 Left out, with reasons

| Item | Reason | Goes to |
|---|---|---|
| Home Assistant in both directions, entities through MQTT discovery | The ROADMAP lists it as a candidate that needs its own security design; publishing discovery topics makes entities appear in another system, which is the first half of that integration (NT-Q13) | Candidates, not planned |
| Anything that acts on Tenko from a channel (a reply, a button, a subscribed topic) | OPS-29: Tenko publishes only | Not planned; the candidate above needs its own design |
| OAuth 2.0 sign-in to SMTP (XOAUTH2, OAUTHBEARER of RFC 7628) | Needs a token refresh flow and a new secret kind; Microsoft turns basic authentication for SMTP off by default for existing tenants at the end of December 2026 and Google accepts app passwords only (section 11) | A later package (NT-Q11) |
| Push services by their own APIs (ntfy, Gotify, Pushover, chat systems) | The webhook with an optional static header reaches ntfy and Gotify today; a body template per service is a feature, not a channel | Later, as webhook presets |
| SMS and voice calls | Need a paid provider | Not planned |
| DHCP pool utilization as an alarm | The data sits on the `dhcp` nodes as a metric (`tenko_dhcp_pool_utilization`), with no threshold or state; a threshold model per scope belongs to a DHCP package | A DHCP package |
| A `dns` or `dhcp` node sending on its own | Those nodes hold no channel configuration and no secrets of the controllers (their role subsets); their loss is reported by the controllers | Phase 5 with the data plane's cluster work |
| HTML e-mail | Plain text carries everything and opens no remote content (NT-Q16) | Not planned |
| Quiet hours | A critical alarm at night is the point; digests carry the rest (NT-Q4) | Not planned |

### 1.5 Starting point in the code

Facts the packages build on, read on `cbe6c27a` (nothing was run).

**What an alarm is today.** There is no common alarm type. There are three stored alarm tables, one derived list and one list of warnings, which share no type, no dedup rule and no dispatch:

| Source | Where | Shape | Cleared | Shown |
|---|---|---|---|---|
| Security alarms of the auth service | `auth.alarms` (`AlarmRecord`, `AlarmKind` in `crates/tenko-auth/src/model.rs`; written by `stage_alarm` in `service/login.rs`) | `at`, `kind`, a message key, an optional user and client address; key a new UUID per alarm; no severity, area or state | Never | Nowhere: no route, no UI page; only a table event on the event stream's `system` topic |
| Utilization of a prefix (IPAM-10) | `ipam.alarms` (`AlarmEvent`, `AlarmLevel` in `crates/tenko-ipam/src/alarm.rs`) | One row per prefix with the current level `normal`, `warning` or `critical`, written on a change only, audited as `ipam.prefix.alarm` | By a row with level `normal` | The prefix tree, the dashboard, the finding `ipam.prefix.alarm.<level>` |
| The vault's key protection | `vault.alarms` (`VaultAlarm` in `crates/tenko-vault/src/kek_state.rs`) | A string key per node, a count and the first time, code `vault.kek.downgrade` | Never | The event stream only; the same condition is also a status warning |
| Findings | Derived on read in `crates/tenko-ipam/src/findings/` and `crates/tenko-api/src/findings.rs`, never stored | `Finding` with level (`act`, `review`, `info`), area (`FindingArea`), code, subject, `since` | By disappearing | `GET /findings`, the findings view, the dashboard's health row |
| Status warnings | `StatusWarning` (`crates/tenko-api/src/dto/system.rs`), assembled on each read of `/system/status` and `/system/diagnostics` by `crates/tenko-api/src/routes/system.rs` from the serving node's own state (its disk, its API certificate, its DNS and DHCP slots) and the cluster's, and sticky notices (`AppState::set_notice`) | A code, a detail and parameters | By disappearing | The status page; they also become `health` findings |

The auth service's alarm kinds are `break_glass_login`, `break_glass_failure`, `account_locked`, `sign_in_failures` (raised at the lock threshold across every network and again each time the count doubles) and `pin_expired` (once per account, by the hourly sweep of unconfirmed PINs). The last two were added on 2026-11-10.

**Each alarm of OPS-29, as it surfaces today:**

| Alarm of OPS-29 | Today | In this slice |
|---|---|---|
| Sign-in and account alarms | `auth.alarms`, five kinds | In: one code per kind |
| Utilization | `ipam.alarms` per prefix; DHCP pools as a metric only | In for prefixes; DHCP pools left out (section 1.4) |
| A failed or missing backup | Status warnings `backup.failed`, `backup.stale` (after 7 days, Standard and Hardened), `backup.restored` (`crates/tenko/src/backup/service.rs`) | In |
| Certificates and keys about to expire | Warnings `sys.tls.certificate_expiry`, `sys.tls.no_certificate`, `sys.tls.reload_failed` (API certificate); `vault.kek.weak`, `vault.kek.missing`, `vault.kek.rotation_failed`, `vault.kek.downgrade`; `migrate.mirror.token_expiring`. The cluster's internal certificate authority renews node certificates by itself and warns about nothing | In; a new alarm `cluster.tls.renewal_failed` and `cluster.tls.expiring` when renewal has not happened 7 days before expiry (WP16.1). No ACME client exists; TSIG keys carry no expiry |
| A DNSSEC rollover that stalls | No detection. Signature health warnings exist (`dns.dnssec.expiring`, `dns.dnssec.resign_overdue`, `dns.dnssec.expired`, `dns.dnssec.clock_skew`); a rollover is the job `dns.dnssec.rollover`, and a step waiting for a person becomes a `job_waiting` finding | In: the signature warnings, plus a new alarm `dns.dnssec.rollover_stalled` when a rollover job waits in one step longer than twice the step's expected wait (WP16.1) |
| A node or a quorum lost | Event stream `cluster.quorum` (states `single`, `healthy`, `electing`, `isolated`), warnings `cluster.leader.service_failing`, `cluster.clock_skew`, `cluster.protocol.mismatch`, `node.disk.low`; metrics `tenko_raft_*`, `tenko_nodes_connected`. No alarm for an unreachable node | In: new alarms `cluster.node_unreachable` (raised by the leader), `cluster.quorum_lost` and `cluster.quorum_restored` (the local path, section 2.7), plus the warnings |
| An update available | `UpdateStatus.update_available` behind `GET /system/updates`; no warning, finding or event | In, as `sys.update.available`, severity `info` |
| Other warnings already coded | `audit.export.failing`, `audit.export.required`, `dns.role.*`, `dhcp.role.*`, `dns.trust_anchor.stale`, `connect.port_stuck`, connector health on the event stream (`connect.health`), `sys.modules.restart_required` | In, each with the severity of section 2.1 |

**What can already deliver**, and what this slice does with it:

| Building block | Where | Reuse |
|---|---|---|
| The audit export's delivery path | `crates/tenko-auth/src/audit_export/`: the `sys.audit` table is the queue, a cursor per sink fenced with the leader epoch, batches of 500, retries doubling from 1 s to 60 s, at least once, nothing dropped, `failing_since` and an alarm after `alert_after_secs`, a `LeaderService` named `audit.export` | The pattern, not the code: the alarm events table is the queue and each channel has a cursor written the same way. The code stays in `tenko-auth`, whose sinks are syslog and files with their own framing; the notification channels need routes, rate limits, digests and folding that the audit export must never have (it drops nothing) |
| The audit export's TLS client | `sink/net.rs`: `rustls` with `aws_lc_rs::default_provider()`, `tokio-rustls`, roots from a pinned CA or `rustls-native-certs`, an optional client certificate from the vault, connect and write timeouts | The SMTP and MQTT channels build their TLS the same way, with the same crates and the same provider (section 2.11) |
| The outbound fetch policy | `crates/tenko-core/src/egress.rs`: `EgressPolicy` refuses loopback, link-local, multicast, unspecified, broadcast and the cloud metadata addresses unless an allow list names them; `check_url` refuses other schemes and user information; `GuardedResolver` (`crates/tenko/src/serve/lists.rs`) checks every resolved address and refuses the name if any is refused; redirects re-checked, at most 5 | All three channels resolve and connect through the policy. `GuardedResolver` gets one shared home that both the block-list fetch and `tenko-notify` import; WP16.0 chooses it with the lead (candidates: `tenko-connect`'s `sdk::http`, which already holds the bounded client and depends on `reqwest`, or a small shared module), so that there is never a second copy. The webhook follows no redirect at all (NT-Q9) |
| HTTP client | `reqwest` 0.12 with the feature `rustls-tls-native-roots` (workspace dependency), already a dependency of the `tenko` binary. Built plainly, as the block-list fetch does (`use_rustls_tls()`), it sets up rustls with its default provider, `ring`; `tenko-connect`'s `WebClient` instead passes a `rustls::ClientConfig` built on `aws_lc_rs::default_provider()` through `use_preconfigured_tls`, with bounded reads | The webhook uses `reqwest` the way `WebClient` does: a preconfigured `ClientConfig` on `aws-lc-rs`, the fetch policy's resolver, no proxy from the environment, no redirects, bounded reads |
| Leader services | `crates/tenko/src/serve/leader.rs`: `LeaderService`, the leader epoch, fenced writes, `periodic(name, interval, ...)`, restart with backoff | The alarm evaluator and the delivery worker are leader services |
| The jobs runner | `crates/tenko-jobs`: no periodic job kind; schedules come from leader services | Not used: a delivery is not a job (it has no steps, rollback or person) |
| The vault | `Vault::get_system(&RequestCtx::system(SystemComponent::X), SecretRef)`; operator secrets with kind and purpose tags; reveals under TGL-24 | A new `SystemComponent::Notify`; every secret of a channel is an operator secret referenced by purpose |
| The event stream | `GET /events` with topics (`crates/tenko-api/src/sse/`); alarm tables appear as table events on `system`, without content | A new topic `alarms` with the alarm event's reference, for the UI; the stream is for signed-in clients and is not a channel |
| Node-local state | No node-local store table; node-local files exist (`<data_dir>/queue/` of IPAM, the probe's buffer) | The local path keeps its small state in a file under `<data_dir>/notify/` (section 2.7) |
| The quorum state | `RaftStore::quorum()`, a watch of `Single`, `Healthy`, `Electing{since}`, `Isolated{since, last_contact, applied}`, evaluated every 250 ms; reads from the local copy work while isolated (`ReadConsistency::Local`) | The local path's trigger |

**Dependencies in `Cargo.lock` today** that the channels need: `rustls` 0.23.46 with `aws-lc-rs` 1.18.1 as the provider everywhere (`ring` 0.17.14 is also in the lock, pulled by `rustls`, `rustls-webpki`, `quinn-proto` and `hickory-proto`: the standing case of the owner's rule), `tokio-rustls` 0.26.6, `rustls-native-certs` 0.8.4, `rustls-webpki` 0.103.16, `reqwest` 0.12.28, `base64` 0.22.1 and 0.23.1, `sha2` 0.11.0, `serde_json`, `uuid`, `time`. Absent: `hmac`, `lettre`, `rumqttc` and their own dependencies (NT-Q10, NT-Q12). The HMAC of the webhook signature comes from `aws-lc-rs` (`aws_lc_rs::hmac`), so no crate is added for it.

**The store's data format** is 6; the public DNS plan may take format 7 (its R151).

## 2. Design decisions the packages share

### 2.1 One alarm model above the sources (NT-Q1)

An **alarm** is a row of a new namespace `alarm` (proposed), keyed by its dedup key:

| Field | Meaning |
|---|---|
| `key` | The dedup key: the code and the subject, for example `ipam.prefix.utilization/<prefix id>`, `cluster.quorum_lost/<node id>`, `auth.sign_in_failures/<user id>` |
| `code` | A stable, dotted code. Existing warning codes are kept as they are (`backup.failed`, `sys.tls.certificate_expiry`); the auth kinds become `auth.<kind>`; the prefix levels one code `ipam.prefix.utilization` with the level as severity |
| `severity` | `critical`, `warning` or `info` |
| `area` | One of `auth`, `backup`, `certificates`, `cluster`, `dhcp`, `dns`, `ipam`, `vault`, `audit`, `connectors`, `notify`, `system` |
| `kind` | `condition` (raised while something is true, cleared when it no longer is) or `event` (something happened once) |
| `state` | `raised` or `cleared` |
| `subject` | An object reference (prefix, user, node, zone, certificate, channel) |
| `params` | The typed parameters the code's template uses, from a fixed list per code (section 2.9) |
| `first_raised`, `last_change`, `count`, `acknowledged` | Times, the number of raises, and who acknowledged when |

Each change of an alarm (raised, severity changed, cleared, raised again) appends one **alarm event** to `alarm.events`, with a sequence number from the store. The alarm events are the queue of the delivery path (section 2.4).

**The evaluator.** A leader service `alarm.evaluator` keeps `alarm.*` in step with the sources:

- the stored alarm tables (`auth.alarms`, `ipam.alarms`, `vault.alarms`) are followed through the store's journal, as the findings service already follows them; each new row maps to an alarm through a fixed table per source (code, severity, area, key);
- the status warnings are per node: `/system/status` assembles the serving node's own disk, API certificate and role slots. So every controller node runs a small reporter (`alarm.node_report`, not a leader service) that assembles its own warnings every 15 s with the same function and, when they changed, writes them to its own row of `alarm.node_warnings`; the evaluator reads every node's row (and, for `dns` and `dhcp` nodes, the status reports they already send to the controllers; WP16.1 confirms the path before it builds on it) and compares the union with the raised `condition` alarms: a new warning raises, a vanished one clears. A controller without quorum cannot write its row; the local path covers it (section 2.7);
- the new sources of section 1.5 (`cluster.node_unreachable`, `cluster.tls.*`, `dns.dnssec.rollover_stalled`, `sys.update.available`) are small checks inside the evaluator.

A condition is raised only after it held for its **hold-down** (proposed: 30 s, 60 s for `cluster.node_unreachable`) and cleared only after it was absent for its hold-down, so a flapping condition makes no noise. The sources are not changed, apart from their mapping tables: the auth service keeps writing `auth.alarms`, IPAM keeps `ipam.alarms`. The findings list and the alarm list read different things on purpose: a finding is work to do, an alarm is something to be told about; many findings (a proposal waiting, a conflict) are never alarms.

**Severities and areas (proposed).** Three severities, because every receiver the owner named maps three levels (a flow tool's switch, an MQTT sensor's state, a mail filter): `critical` means act now (quorum lost, backup failed, the break-glass account used, a certificate expired, a DNSSEC signature expired, the KEK missing); `warning` means act soon (utilization critical, a certificate expiring within 14 days, sign-in failures, a rollover stalled, a channel failing); `info` means know about it (an update available, a backup restored, utilization at warning). The mapping of every code is a table in the ADR and in `docs/notifications.md`; the findings' levels are not reused, because `review` means "look at this in the list", not a severity of a message.

### 2.2 Event alarms, acknowledgment and reminders (NT-Q2)

The auth service's alarms are `event` alarms: there is nothing to clear when the break-glass account signed in. An `event` alarm stays in the alarm list as raised until a person acknowledges it or for its hold time (proposed 7 days), after which it is cleared quietly, without a notification. What a repeat within the hold time does depends on the code, so that a harmless first alarm can never hide a later one:

- `break_glass_login`, `break_glass_failure` and `account_locked`: every occurrence is delivered (as `alarm.raised` again, with the count), within the channel's rate limit;
- `sign_in_failures`: the key is the account; the auth service writes a new row when the count reaches the lock threshold and again at each doubling, and each such row is delivered as `alarm.changed` with the new count; repeats between doublings only count;
- `pin_expired` and the other event alarms: once per hold time; an acknowledgment ends the hold, so the next occurrence is delivered.

An **acknowledgment** (`POST /api/v1/alarms/{id}/acknowledge`, audited) marks an alarm as seen; it stops reminders and is shown in the list; it does not clear a condition. A **reminder** repeats a raised, unacknowledged alarm on a route's channels every `remind_every` (off by default; proposed choices 1 h, 4 h, 24 h), as one message per alarm or within the route's digest.

A **cleared** condition is delivered on a route only when the route delivered its raise on that channel, so nobody is told that something they never heard of is over. A route may switch off clear messages.

### 2.3 Channels and routes

A **channel** is a row of `notify.channels`: its kind (`smtp`, `webhook`, `mqtt`), its settings (section 2.11), references to its secrets in the vault, its detail level (section 2.9), its rate limit (section 2.5), whether it takes part in the local path (section 2.7), its language (`en` or `sv`, NT-Q16), and `enabled`. A **route** is a row of `notify.routes`: a match (lowest severity, a set of areas or all, codes included or excluded), a list of channels, a mode (`immediate` or `digest` with its interval), reminders and clear messages. An alarm event goes to the union of the channels of every route that matches it, once per channel.

There is no default route until an administrator creates a channel; the first channel offers a route "every area, `warning` and above, immediately". Without any route, the alarm list and the findings still show everything.

**Who may change them.** Channels, routes and their secrets are system settings, with the same permission as the audit export's settings (the update permission on the system); reading the delivery state needs the global read permission; a test delivery needs the update permission. Under Hardened a change of a channel's destination needs an interactive session with the step-up of TGL-24 (NT-Q14), because a channel is a path out of the product.

### 2.4 The delivery path (NT-Q3)

One leader service `notify.delivery` runs one worker per enabled channel, the audit export's pattern:

1. The worker reads alarm events after its cursor (`notify.cursors`, one row per channel), in batches of up to 100.
2. It keeps those that a route sends to this channel, applies the rate limit and the folding (section 2.5), and renders each into the channel's form (section 2.9).
3. It delivers, waits for the channel's acknowledgment (the SMTP server's `250` after the message, the webhook's 2xx, the broker's PUBACK), and records the result in `notify.deliveries` (per alarm event and channel: `delivered`, `failed` with the stage and code, `folded`, `expired`).
4. It writes its cursor, fenced with the leader epoch, every 5 s or 100 events and when it stops. A new leader resumes from the cursor: an event delivered before the write of the cursor is delivered again, with the same id.

**At least once, with a stable id.** Every outgoing message has a message id, kept across its retries: the alarm event's id for the first delivery of an alarm event, and a new UUID, recorded in `notify.deliveries`, for each reminder, digest, test delivery, heartbeat and local-path message. It is the webhook's `webhook-id` header, the e-mail's `Message-ID` (`<message id.channel id@sender domain>`, so that two channels to one mailbox never collide) and the MQTT message's user property `message-id`. Repeats are the receiver's to drop. The webhook's `webhook-timestamp` and signature are computed for each attempt, so a retry hours later still passes a receiver's 5-minute window.

**Retries.** A failed delivery is retried with a pause that doubles from 2 s to 5 min, honoring a webhook's `Retry-After` and an SMTP `4xx` up to that cap; a refusal of the channel itself (HTTP 401, 403, 404 or 410, SMTP `535` or a `5xx` to the sender, an MQTT reason code `0x86`, `0x87` or `0x8C`) stops the worker at once: the cursor does not move, the channel is failing, and the next attempt waits for the longest pause, because a wrong secret or a removed endpoint will not heal by itself. A refusal of one message (HTTP 400 or 413, SMTP `5xx` for one recipient, an MQTT `0x95` for a packet too large) is not retried: the event is recorded as `failed` with its stage and the worker moves on; three in a row make the channel failing. While a channel fails, its worker holds its place; events behind it wait. An event older than the channel's maximum age (proposed 24 h; 1 h for MQTT, whose retained state is republished on reconnect anyway) is marked `expired` for that channel and counted, so a channel that was down for a week does not deliver a week of old news; the digest after the recovery says how many expired.

**A failing channel is an alarm.** A channel failing longer than its alert time (proposed 5 min) raises `notify.channel.failing` (area `notify`, severity `warning`), cleared by its recovery. That alarm is routed like any other, never to the failing channel itself. With every channel failing, the alarm list, the findings, the status page and `tenko_notify_channel_up` show it.

**Bounds.** `alarm.events` keeps 30 days or 100,000 events, whichever is smaller (proposed), except events that an enabled channel's cursor has not yet passed, which are kept up to a hard bound of 1,000,000 events; past the hard bound the oldest are dropped, `info` first and first raises of `critical` last, the cursor jumps, the gap is counted as expired, and the alarm `notify.events_lost` (`critical`) is raised. `notify.deliveries` keeps 30 days or 200,000 rows; its rows are written in batches together with the cursor. Rendering and sending hold one batch per channel in memory; nothing else grows with the number of alarms.

### 2.5 Rate limits, folding and digests (NT-Q4)

The dedup key already turns a repeated condition into one alarm. What remains is a flood of distinct keys: an attacker guessing the passwords of many accounts, a cascade when a controller fails, a misconfigured prefix tree crossing a threshold everywhere at once.

**Per channel, a token bucket** (proposed defaults: e-mail 20 messages per hour with a burst of 5; webhook 60 per minute with a burst of 20; MQTT 20 per second). When the bucket is empty, the channel **folds**: events are not sent one by one but recorded as `folded` in `notify.deliveries`, and the next digest of that channel is built from the stored `folded` rows not yet in a sent digest, sent when the bucket allows one message (at least every 15 min while folding). The digest has its own message id; its send marks the rows it carried. Because the folded rows are stored, a leader change loses no digest: the new leader builds it from the same rows. What is folded first, in order: `info`, then repeats and severity changes, then clear messages, then first raises of `warning`. A first raise of `critical` is never folded: it bypasses the bucket, up to a hard cap per channel (proposed 60 per hour); past the cap it waits, in order, until the cap allows it, and is never dropped. A clear whose raise was folded is folded too.

A **digest** lists counts per code and severity and up to 20 alarms in full, newest state first, with a link to the alarm list; "and 37 more" names what it left out. A route in mode `digest` (proposed intervals 15 min, 1 h, daily at a set time) always works this way, which is the answer for `info` alarms and for people who want one mail a day.

**A flood is shown.** When a channel folds for longer than 10 min, the alarm `notify.flood` (area `notify`, `warning`) is raised once and cleared when the channel has sent normally for 10 min. Folded events are counted per channel and severity (`tenko_notify_folded_total`) and appear as `folded` in the deliveries. The bucket lives in the leader's memory; a new leader starts with an empty bucket of its own, so a hand-over during a flood sends at most one more burst.

**No quiet hours.** A route can be `digest` only; there is no time window in which a `critical` alarm waits.

### 2.6 Delivery in a cluster

The evaluator and the delivery worker are leader services: they run on one controller at a time, their writes are fenced with the leader epoch, and a new leader resumes from the stored cursors. Three things run on every controller node instead: the warnings reporter (section 2.1), the local path (section 2.7) and the MQTT connection (section 2.8), so that each node's own warnings reach the evaluator, a node without quorum can still speak, and each node's last will speaks for that node. A `dns`, `dhcp` or `probe` node takes no part: it holds no channel configuration (the role subsets of E89).

### 2.7 The hard case: a controller without quorum (NT-Q5)

`cluster.quorum_lost` cannot depend on the quorum: a controller that lost it cannot write an alarm event, has no leader to run the delivery worker, and in a full partition no node has one. So each controller node runs a second, small service of its own, **the local path** (`notify.local`, not a leader service):

- **Trigger.** It watches `RaftStore::quorum()`. When the node's state has been `Isolated` or `Electing` for longer than the threshold (proposed 60 s; the store's isolation detection itself takes 3 s), it raises `cluster.quorum_lost` for itself. When the state returns to `Healthy` and stays there for 30 s, it sends `cluster.quorum_restored` and stops.
- **What it reads.** The channels, routes and secret references from its local copy of the store (`ReadConsistency::Local`), which every controller holds; the secrets through the vault, which reads a secret's envelope from the local copy (`ReadConsistency::Local` in `crates/tenko-vault/src/store_vault.rs`) and unwraps it with the node-local KEK; WP16.5 proves the whole read on an isolated node first (R163). It uses only the channels marked `local_path` (proposed: on by default for every channel of severity `critical` routes).
- **What it sends.** Only a fixed list of alarms the node can know alone: `cluster.quorum_lost`, `cluster.quorum_restored`, and its own `node.disk.low` while isolated. Each at most once per outage per channel, plus one reminder after 1 h when the outage lasts (proposed). Delivery is direct, with a short retry (three tries over 5 min) and no folding: these are a handful of messages.
- **On MQTT** it publishes over its own node's connection, on a fixed per-node topic `<prefix>/node/<node>/quorum` (retained `lost` or `ok`), not on an alarm topic: an isolated node has no alarm row and cannot write the retained ledger, and a fixed topic needs neither.
- **What it keeps.** A small file `<data_dir>/notify/local.json` (the outage's start, the message ids, what was sent where), written atomically, so a restart of the isolated node does not send again and the heal knows what to close. When the quorum returns, the node writes its report to its own row of `notify.local_reports` and deletes its file once the write is committed; the evaluator, which alone writes `alarm.*`, ingests the report: it records the `cluster.quorum_lost` and `cluster.quorum_restored` events with deliveries already marked `delivered` under the reported message ids, so the alarm list shows them and the normal path does not send them again.
- **The rest of the cluster.** A leader that still has its quorum sees the cut-off node as unreachable and raises `cluster.node_unreachable` for it through the normal path. A 3-node cluster split one against two therefore sends two messages: one from the lone node about itself, one from the majority about the lone node. A total partition (no node with a majority) sends one message per controller, each naming itself.
- **What the local path cannot do.** A controller whose process or host is down sends nothing. Two answers, both optional: the MQTT last will (section 2.8), which the broker publishes for a node that vanished, and a **heartbeat** of the webhook channel (NT-Q6): a small signed request every `heartbeat_every` (off by default; proposed 5 min) from the leader, so that a flow tool can raise its own alarm when the heartbeats stop. A single-node installation (`QuorumState::Single`) has no quorum to lose; the heartbeat or the will is its only "Tenko is gone".

### 2.8 MQTT: publish only, retained state and a last will (NT-Q12, NT-Q13)

**Version (proposed): MQTT 5.0 only.** It brings the reason codes that make a test delivery say why a broker refused (bad user name or password `0x86`, not authorized `0x87`), the message expiry interval, user properties for the event id, and a maximum packet size the client can learn. Mosquitto has accepted 5.0 since 1.6; Home Assistant's MQTT integration states that it needs a broker that speaks 5.0 (section 11). Version 3.1.1 can be added later as a setting; it is not built now, to keep one code path and one test matrix.

**One connection per controller node.** Each controller connects with the client id `tenko-<installation>-<node id>` (proposed), a keep-alive of 30 s, a will of `offline`, retained, QoS 1, on its status topic, a will delay of 10 s and a session expiry of 60 s. After each CONNACK, and only then, it publishes `online` retained on the same topic (the convention Home Assistant calls birth and will). The will delay covers a quick reconnect: a node that reconnects within 10 s to its session is not reported `offline`, and a will that a broker publishes for an old half-open connection is followed by the new connection's `online`. The client honors the limits the broker announces in CONNACK (Receive Maximum, the number of unacknowledged messages in flight; Maximum Packet Size) and refuses to publish a payload above them as a `failed` delivery. The leader publishes the alarm topics over its own node's connection; an isolated node publishes its local alarms over its own.

**The topic layout (proposed)**, under a configurable prefix, by default `tenko/<installation>`:

| Topic | Retained | Payload |
|---|---|---|
| `<prefix>/node/<node id>/status` | Yes | `online` or `offline` (the will) |
| `<prefix>/node/<node id>/quorum` | Yes | `lost` or `ok`, from the node itself (section 2.7) |
| `<prefix>/alarm/<alarm id>` | Yes | The alarm's state at the channel's detail level (section 2.9) as JSON: `code`, `severity`, `area`, `state`, `since`, `count`; replaced on each change; an empty retained message deletes it when the alarm is purged |
| `<prefix>/summary` | Yes | Counts of raised alarms per severity, and the highest severity raised: one value a dashboard can show |
| `<prefix>/events` | No | Every alarm event, QoS 1, with a message expiry of 1 h |

Topics carry no account names, host names or addresses on any profile: the alarm id is a UUID and a node appears by its short id.

**Publish only, by construction.** The client implements CONNECT, PUBLISH (QoS 0 and 1), PUBACK, PINGREQ and DISCONNECT, and decodes only CONNACK, PUBACK, PINGRESP and DISCONNECT. It has no SUBSCRIBE in its code. A PUBLISH or any other packet from the broker is a protocol violation: the client disconnects, counts it (`tenko_notify_mqtt_violations_total`) and reconnects with backoff. Tenko never reads its own retained messages back: on every connect it republishes the current state of every raised alarm from its store, and it remembers in `notify.mqtt_retained` which alarm topics it has retained on each channel, so that it can delete the ones of purged alarms with an empty message. Nothing a broker says changes anything in Tenko beyond the channel's own delivery state.

**A broker without access control.** Anyone who can connect reads every alarm state, the node ids and when each node went offline, and can publish a forged `online`, a forged alarm or a forged clear under Tenko's topics: a subscriber would believe it, Tenko would not notice. Hence: outside Home and Lab, TLS with a validated certificate and an authenticated broker are required (OPS-29), the payloads are minimal, and `docs/notifications.md` gives the broker access rule to set (only Tenko's user may publish below the prefix; subscribers may only read). Tenko cannot check the broker's access rules; the test delivery says so.

**The door to a two-way integration stays open, and shut.** The topic layout and the JSON payload are versioned (`"schema": 1`) and stable, so a later Home Assistant plugin, or MQTT discovery topics, can be built on them; but no part of this slice subscribes, and the later integration that lets Home Assistant act on Tenko has its own security design first (ROADMAP, "Candidates, not planned").

### 2.9 What a notification says (NT-Q7)

Every notification is rendered from a fixed template per code, in the channel's language, with only the code's declared parameters. There is no free text from a source: a parameter that comes from outside (a host name a DHCP client chose, a zone name) is typed, length-bounded and escaped for the channel (control characters and line breaks removed, so no header injection in e-mail and no JSON surprises). Three detail levels:

| Level | Contains | Default on |
|---|---|---|
| `minimal` | Code, severity, area, state, time, the alarm id, the node's short id, a link to the alarm in the UI if a base URL is set | MQTT on every profile; e-mail and webhook under Hardened |
| `standard` | Also the subject's display name (the account name, the prefix, the zone, the node name, the certificate's subject) and the code's parameters (the utilization, the days left, the number of failures) | E-mail and webhook on Home, Standard and Lab |
| `full` | Also the client address of a security alarm | Only by an administrator's choice per channel, refused under Hardened |

**Never in a notification**, under any level: a secret of any kind (password, PIN, TOTP code, token, key, session id, the channel's own secrets), a URL with a token in it, an audit record, a log excerpt. The security row `notify.secret` checks this by planting canary secrets and searching every captured message.

**What a notification may say about an account**: no more than the alarm does (OPS-29). The auth alarms name an account and a client address; at `standard` the notification names the account, not the address; at `minimal` neither, and the reader signs in to see who. The reason for keeping the address out by default: a mailbox or a home-automation log keeps it longer and with less protection than the audit log.

**The webhook's JSON** (schema 1, proposed), the envelope of the Standard Webhooks specification so that API-06's events fit the same shape later:

```json
{
  "type": "alarm.raised",
  "timestamp": "2026-11-11T07:45:00Z",
  "data": {
    "schema": 1,
    "alarm": "0193a6c0-7d2e-7c41-9b1f-3a5e2c8d4f10",
    "code": "backup.failed",
    "severity": "critical",
    "area": "backup",
    "state": "raised",
    "since": "2026-11-11T07:44:30Z",
    "count": 1,
    "node": "c1",
    "title": "The backup failed",
    "subject": "Scheduled backup",
    "params": {"reason": "disk_full"},
    "link": "https://tenko.example.test/alarms/0193a6c0-7d2e-7c41-9b1f-3a5e2c8d4f10"
  }
}
```

`type` is `alarm.raised`, `alarm.changed`, `alarm.cleared`, `alarm.reminder`, `alarm.digest`, `notify.test` or `notify.heartbeat`. The body is at most 16 KiB.

**E-mail** is plain text in UTF-8, base64 transfer encoding (no dependence on the server's 8-bit support), with the subject `[Tenko] <severity>: <title>` encoded per RFC 2047 when it is not ASCII, a `Date`, a `Message-ID` from the event id and the headers `Auto-Submitted: auto-generated` (RFC 3834, so that auto-replies stay silent) and `X-Tenko-Alarm: <code>` (for mail filters). No HTML, no attachments, no images.

### 2.10 Secrets, audit and metrics

**Secrets.** Each is an operator secret in the vault (IAM-16), referenced by purpose: `notify.smtp.password`, `notify.webhook.signing` (generated by Tenko: 32 random bytes, shown once at creation and at each rotation in the Standard Webhooks form `whsec_<base64>`, later only through a reveal under TGL-24), `notify.webhook.header` (an optional static header value, for receivers that can only check a token), `notify.webhook.url` (the whole URL, when it carries a secret, as a Home Assistant webhook id does: the URL is then stored in the vault and shown as its scheme and host only), `notify.mqtt.password`, and a client key for TLS client certificates (SMTP, webhook and MQTT), as the audit export's `client_key`. The worker reads them with `Vault::get_system` under a new `SystemComponent::Notify`, per connection, and holds them in `Zeroizing` buffers. A use is not audited (it would flood the audit log, and the audit export's sinks are not either); setting or changing a reference is.

**Audit actions** (proposed): `notify.channel.create`, `notify.channel.update`, `notify.channel.delete`, `notify.channel.test`, `notify.channel.rotate_secret`, `notify.route.create`, `notify.route.update`, `notify.route.delete`, `alarm.acknowledge`, and the system's `notify.local.sent` (an isolated node's delivery, recorded when the evaluator ingests its report). A channel's failure and recovery are the alarm `notify.channel.failing` and its clearing, not audit records. Each needs its English unit and Swedish target in `ui/i18n/<language>.d/labels.xlf`. Deliveries are not audit records: they are the delivery state.

**Metrics** (proposed): `tenko_alarms_raised{severity,area}`, `tenko_alarm_events_total{kind}`, `tenko_notify_deliveries_total{channel,result}`, `tenko_notify_delivery_seconds{channel}` (a histogram), `tenko_notify_events_behind{channel}`, `tenko_notify_folded_total{channel,severity}`, `tenko_notify_channel_up{channel}`, `tenko_notify_mqtt_violations_total{channel}`. The channel label is the channel's id, never its URL or host.

### 2.11 Each channel's transport and its security

**SMTP submission (NT-Q10, NT-Q11).**

- **TLS mode**: `implicit` (port 465, the default, as RFC 8314 prefers) or `starttls` (port 587, STARTTLS required: a server that does not offer it is refused, never used in plain text). `none` exists only under Lab, towards a loopback or private address, with the warning of CONTRIBUTING rule 6.
- **STARTTLS done right** (RFC 3207 and the 2011 and 2021 injection findings, section 11): after the server's `220` to STARTTLS the client checks that the server sent nothing more (any byte already buffered aborts the session as `notify.smtp.injection`), runs the handshake, discards everything it learned before (the extension list) and sends EHLO again.
- **Certificate validation** by the WebPKI rules of RFC 7817 and RFC 6125, against the configured host name, with the system roots or a pinned CA; no "insecure" mode outside Lab. The TLS rule, the same for all three channels: TLS 1.2 at least (RFC 8314), a per-channel switch "TLS 1.3 only", and under Hardened a session that negotiated 1.2 is delivered but shown as a channel warning (R167).
- **Authentication**: `AUTH PLAIN` inside TLS, or `AUTH LOGIN` (the older mechanism that sends the user name and the password in two base64 steps, as safe as PLAIN inside TLS) when the server offers only that, with the user name and the password from the vault; the password is never sent before the certificate was validated (RFC 4954). No authentication is allowed only towards a relay the administrator marks as trusting the address (Home and Lab). OAuth 2.0 mechanisms are left out (section 1.4).
- **The envelope**: one configured sender, at most 10 recipients per channel (more is a mailing list's job), every address checked as an ASCII `addr-spec` (no SMTPUTF8 needed), dot-stuffing and CRLF line ends as RFC 5321 requires, lines under 78 characters by the base64 body, the RFC 5321 timeouts.
- **Egress**: the server's address passes the fetch policy (a submission server on loopback needs the allow list).

**Webhook (NT-Q8, NT-Q9).**

- **Signature**: the Standard Webhooks scheme version `v1`: the headers `webhook-id` (the event id), `webhook-timestamp` (Unix seconds) and `webhook-signature: v1,<base64 of HMAC-SHA256 over "id.timestamp.body">`, the secret in the `whsec_` form. During a rotation (`POST /notify/channels/{id}/rotate-secret`) the header carries two signatures, the new and the old, for the overlap the administrator chooses (proposed 24 h, at most 7 days). The receiver checks the timestamp within its tolerance (the specification leaves the window to the receiver; `docs/notifications.md` recommends 5 minutes, as Stripe and Slack use). The comparison of schemes is NT-Q8: Standard Webhooks is the one with an open specification, libraries in many languages, test values, an id for replays and a rotation rule; GitHub's signs the body without a timestamp; Stripe's and Slack's are close relatives with their own header names.
- **For receivers that cannot verify**: an optional static header (`Authorization: Bearer <secret>` or a header name the administrator gives), from the vault. Home Assistant's webhook trigger, ntfy and Gotify check a URL secret or a token and nothing else; the flow tools n8n and Node-RED can check a header out of the box and a signature with a few lines of their own code (`docs/notifications.md` gives the snippets for both).
- **Transport**: HTTPS, with the system roots or a pinned CA; `http://` allowed under Home only towards a private address (RFC 1918, RFC 4193) with a loud warning, and under Lab; refused under Standard and Hardened. Every resolved address passes the fetch policy; private addresses are allowed (the home-automation case), loopback, link-local and metadata are not. **No redirect is followed**: a 3xx is a failure with its status, because a receiver that moves should be reconfigured, not followed. No proxy from the environment. Timeouts: connect 5 s, whole request 15 s. The answer's body is read up to 4 KiB for the delivery state's diagnostics and never logged in full.

**MQTT**: section 2.8, plus: TLS on port 8883 with the system roots or a pinned CA, an optional client certificate, the user name and password from the vault; plain TCP on 1883 only under Home and Lab; the fetch policy for the broker's address.

**Under the Hardened profile** (NT-Q14, proposed): all three channels allowed with TLS and validated certificates only; MQTT with authentication; detail `minimal` on every channel, `full` refused; a change of a channel's destination or secret with the step-up of TGL-24; a channel failing raises `notify.channel.failing` at once, without the alert time; the heartbeat allowed. A new toggle row **TGL-41 "Notification transport"** (TGL-40 is proposed by ADR 0032) records the profile values: Home "TLS preferred; plain webhook to private addresses and plain MQTT allowed with a warning; detail standard", Standard "TLS required on every channel; MQTT authenticated; detail standard", Hardened "TLS required and validated (1.2 at least, a 1.2 session shown as a warning); MQTT authenticated; detail minimal; destination changes with step-up", Lab "Anything, loud".

### 2.12 What API-06 will add, and what this slice must not prevent

API-06 (Phase 5) asks for general event webhooks: a subscriber picks topics of the event stream (a zone changed, a lease issued) and receives them. It needs a second source beside `alarm.events`, subscriptions instead of routes, and a payload per event kind. This slice prepares it by keeping the delivery worker's source an interface (a journal with sequence numbers and a cursor), the webhook envelope the Standard Webhooks one (`type`, `timestamp`, `data`), and the signing, rate limits, fetch policy and delivery state per channel independent of alarms. It builds no subscription, no event payloads and no second source.

## 3. Contracts and shared files (WP16.0)

### 3.1 Types (`tenko-core`)

`crates/tenko-core/src/alarm.rs` (new): `Alarm`, `AlarmKey`, `AlarmCode`, `Severity { Critical, Warning, Info }`, `AlarmArea`, `AlarmKind { Condition, Event }`, `AlarmState { Raised, Cleared }`, `AlarmEvent { id, seq, key, transition, at, severity }`, `AlarmParams` (a typed map per code with bounded strings), the code catalog (code, severity, area, kind, hold-down, template parameters). The message templates live in `crates/tenko-notify/src/render/templates/` in English and Swedish (owned by WP16.2, which adds the templates of every code of the catalog), with a test that every code of the catalog has a template in both languages. `crates/tenko-core/src/notify.rs` (new): `Channel`, `ChannelKind { Smtp(SmtpSettings), Webhook(WebhookSettings), Mqtt(MqttSettings) }`, `Route`, `RouteMatch`, `DetailLevel`, `RateLimit`, `DeliveryResult { Delivered, Failed { stage, code }, Folded, Expired }`, with validation and property tests. `SystemComponent::Notify` in `principal.rs` (a small additive change in a shared file, with the lead).

### 3.2 The crate `tenko-notify` (new)

`crates/tenko-notify/` holds the delivery worker, the rendering, the rate limits and digests, the three channels and the local path, each in its own module directory so that the packages own disjoint files: `src/delivery/`, `src/render/`, `src/webhook/`, `src/smtp/`, `src/mqtt/`, `src/local/`. WP16.0 writes `src/lib.rs` and the service wiring `crates/tenko/src/serve/notify/mod.rs`, which registers every service of the slice through one function per package, each in its own file (`delivery.rs` for WP16.2, `mqtt.rs` for WP16.4, `local.rs` for WP16.5, and `crates/tenko/src/serve/alarms.rs` for WP16.1's evaluator and node reporter), first as stubs that do nothing. Its `Cargo.toml` is written once by WP16.0 with every dependency the slice needs (all in the lock today, unless the owner chooses a library in NT-Q10 or NT-Q12): `tenko-core`, `tenko-store`, `tenko-vault`, `tokio`, `rustls`, `tokio-rustls`, `rustls-native-certs`, `aws-lc-rs`, `reqwest`, `serde`, `serde_json`, `base64`, `time`, `uuid`, `zeroize`, `tracing`.

### 3.3 Store, API, CLI, codes

- The namespaces `alarm` (`alarm.alarms`, `alarm.events`, `alarm.node_warnings`) and `notify` (`notify.channels`, `notify.routes`, `notify.cursors`, `notify.deliveries`, `notify.mqtt_retained`, `notify.local_reports`), absent from every role subset. Whether they need data format 7 (or 8 after the public DNS slice) is WP16.0's first decision, taken with the lead (R160).
- Routes: `GET /api/v1/alarms`, `GET /api/v1/alarms/{id}`, `POST /api/v1/alarms/{id}/acknowledge`; `/api/v1/notify/channels` (create, read, update, delete), `POST /api/v1/notify/channels/{id}/test`, `POST /api/v1/notify/channels/{id}/rotate-secret`; `/api/v1/notify/routes` (create, read, update, delete); `GET /api/v1/notify/deliveries` (filter by channel, alarm, result). Event stream topic `alarms`.
- CLI: `tenko alarm list|show|ack` and `tenko notify channel|route|test|deliveries`.
- Codes `notify.*` (among them `notify.egress`, `notify.tls`, `notify.redirect`, `notify.http_status`, `notify.smtp.starttls_missing`, `notify.smtp.injection`, `notify.smtp.auth`, `notify.smtp.recipient`, `notify.mqtt.refused`, `notify.mqtt.violation`, `notify.secret_missing`, `notify.profile`); the alarm codes, among them this slice's own `notify.channel.failing`, `notify.flood`, `notify.events_lost`; of section 1.5; audit actions and metrics of section 2.10.

### 3.4 Shared fixtures and the lab

- `crates/tenko-notify/tests/fixtures/`: the Standard Webhooks test values from the specification's repository, a test CA with certificates for `smtp.example.test`, `hooks.example.test`, `broker.example.test` and a wrong name, recorded SMTP dialogues (a normal session, a stripped STARTTLS, an injected byte, multi-line replies, every refusal class), recorded MQTT packets (CONNACK with each reason code, an unsolicited PUBLISH).
- `deploy/compose/lab-notify/`: Mailpit (`axllent/mailpit`, the tag pinned by digest when the package starts; implicit TLS and required STARTTLS are separate listeners, so two services), Mosquitto (`eclipse-mosquitto:2.1.2-alpine`, pinned by digest, TLS listener and a password file), a webhook receiver written in the repository's test code (a small Rust example of `tenko-notify`, built by the lab's own Dockerfile from the same tree, that verifies each signature and writes what it received to a volume), and the Tenko image of the lab-cluster (three controllers and the fault container `docker:cli`). Its `smoke.sh` follows the other labs (`IMAGE=`, `KEEP=1`, `TENKO_BUILD_TREE`). Every name in the lab is under `example.test`. WP16.0 writes the skeleton (`compose.yml` with the Tenko services, `smoke.sh` that runs every file under `rounds/`); each later package owns its own override and round (`compose.webhook.yml` and `rounds/webhook.sh` for WP16.2, `compose.smtp.yml` and `rounds/smtp.sh` for WP16.3, `compose.mqtt.yml` and `rounds/mqtt.sh` for WP16.4, `rounds/partition.sh` for WP16.5); WP16.7 then owns the whole directory.
- `fuzz/Cargo.toml` and the weekly smoke's list of fuzz targets get both entries, `notify_smtp_reply` and `notify_mqtt_packet`, from WP16.0, with target files that do nothing; WP16.3 and WP16.4 own their target files.
- `docs/api/openapi.json` is regenerated by each package that changes a route; when two land together, the second regenerates it at the merge (the lead's step).

## 4. Work packages

Every package below owns files under `crates/tenko-core/src/alarm.rs` and `notify.rs` (WP16.0), `crates/tenko-api/src/alarms/**` and `crates/tenko-api/src/routes/{alarms,notify}*`, `crates/tenko-notify/**` (by module), `crates/tenko/src/serve/notify*` (the wiring), `crates/tenko/src/cli/{alarm,notify}*`, `ui/src/alarms/**`, `ui/src/settings/notifications/**`, `deploy/compose/lab-notify/**`, and the documents of section 10; one package owns each file.

#### WP16.0 The contracts and the ADR (3 builder-days)

- **Requirements:** OPS-29.
- **Owns:** section 3 in code: the types with property tests and the code catalog, the crate skeleton and its `Cargo.toml`, the tables and the subset test of E89, the route stubs answering 501, the codes, audit actions with their label units, metric families, the UI route stubs; the fixtures of section 3.4; the data format decision; the ADR (proposed 0036) as Proposed; the JSON schema of section 2.9 in [api/README.md](../api/README.md).
- **Depends on:** the owner's decisions NT-Q1 to NT-Q3, NT-Q7 and NT-Q8.
- **Acceptance:** the workspace builds; the subset test; the catalog test (every code has both templates); the trace regenerated.

#### WP16.1 The alarm layer (6 builder-days)

- **Requirements:** OPS-29, IPAM-10, OPS-22, OPS-24.
- **Owns:** `crates/tenko-api/src/alarms/**` (the evaluator: the journal adapters for `auth.alarms`, `ipam.alarms` and `vault.alarms`, the node reporter and `alarm.node_warnings`, the hold-downs, the new checks of section 1.5 including `cluster.node_unreachable`, acknowledgment, when a reminder is due (it appends a reminder event; WP16.2 sends it), the ingestion of `notify.local_reports`, the purge), `crates/tenko-api/src/routes/alarms.rs`, `crates/tenko/src/serve/alarms.rs`, the event stream topic `alarms`, `crates/tenko/src/cli/alarm*`, the alarm metrics' text for `observability.md` (handed to WP16.2), `bench/notify/results/<date>-M73.md`, the mapping tables in the sources' crates where a source needs one (with the lead; additive).
- **Depends on:** WP16.0.
- **Acceptance:** E89, E90; M73.

#### WP16.2 The delivery path and the webhook (6 builder-days)

- **Requirements:** OPS-29, IAM-16.
- **Owns:** `crates/tenko-notify/src/{delivery,render,webhook}/**` (the leader service, cursors, retries, expiry, the rate limits, folding and stored digests, the sending of reminders, the delivery state, the templates in both languages, the Standard Webhooks signing with `aws_lc_rs::hmac`, rotation, the heartbeat, the preconfigured `aws-lc-rs` TLS of the webhook), the move of `GuardedResolver` to its shared home with its one import in `crates/tenko/src/serve/lists.rs` (with the lead), `crates/tenko-api/src/routes/notify*`, `crates/tenko/src/cli/notify*`, `crates/tenko/src/serve/notify/delivery.rs`, `observability.md`'s section on alarms and notifications, `bench/notify/results/<date>-M74.md` and `-M75.md`, the lab's webhook receiver, `compose.webhook.yml` and `rounds/webhook.sh`.
- **Depends on:** WP16.0; WP16.1 for the end-to-end tests (the worker is tested against a fixture journal alone).
- **Acceptance:** E91, E92, E93; M74, M75.

#### WP16.3 The SMTP channel (4 builder-days with an own client; 2 with a library)

- **Requirements:** OPS-29.
- **Owns:** `crates/tenko-notify/src/smtp/**` (the client of section 2.11 or the library's configuration, NT-Q10), its fake servers and recorded dialogues, `fuzz/fuzz_targets/notify_smtp_reply.rs`, the lab's `compose.smtp.yml` (Mailpit) and `rounds/smtp.sh`.
- **Depends on:** WP16.0; WP16.2's worker for the end-to-end tests.
- **Acceptance:** E94.

#### WP16.4 The MQTT channel (4 builder-days with an own client; 2 with a library)

- **Requirements:** OPS-29.
- **Owns:** `crates/tenko-notify/src/mqtt/**` (the publish-only client, the per-node connection, birth, will and will delay, the broker's limits, the retained state and its ledger, the republish on connect, the violation rule), `crates/tenko/src/serve/notify/mqtt.rs`, `fuzz/fuzz_targets/notify_mqtt_packet.rs`, the lab's `compose.mqtt.yml` (Mosquitto) and `rounds/mqtt.sh`.
- **Depends on:** WP16.0; WP16.2's worker for the end-to-end tests.
- **Acceptance:** E95.

#### WP16.5 The local path of a controller without quorum (3 builder-days)

- **Requirements:** OPS-29, OPS-26.
- **Owns:** `crates/tenko-notify/src/local/**` (the trigger, the local file, the direct delivery through the channels' senders, the MQTT quorum topic over the node's connection, the report to `notify.local_reports` after the heal), `crates/tenko/src/serve/notify/local.rs`, the lab's `rounds/partition.sh`, [partitions.md](../partitions.md)'s section on it, `bench/notify/results/<date>-M76.md`.
- **Depends on:** WP16.1 (`cluster.node_unreachable` and the ingestion of the report) and WP16.2 to WP16.4 (it uses their senders; without MQTT, it uses two).
- **Acceptance:** E96; M76.

#### WP16.6 The UI (5 builder-days)

- **Requirements:** OPS-29.
- **Owns:** `ui/src/settings/notifications/**` (channels, routes, the test delivery with its stage-coded result, the secret fields with their vault references, the rotation with the overlap), `ui/src/alarms/**` (the alarm list with filters by severity, area and state, an alarm's deliveries, acknowledgment), the header's alarm count (one change in the header's file, with the lead), the mock API, the Playwright tests, the texts in both languages.
- **Depends on:** WP16.1 and WP16.2's routes (against the mock earlier).
- **Acceptance:** E97.

#### WP16.7 The lab, the security rows, the documents and the live test (4 builder-days, plus the owner's hour)

- **Requirements:** OPS-29, IAM-16.
- **Owns:** `deploy/compose/lab-notify/**` once the earlier packages have landed their pieces, the rows below in `deploy/security/`, `docs/notifications.md` (the earlier packages hand their sections over as text in their hand-over notes; one writer), the rows of [CONFORMANCE.md](../CONFORMANCE.md), the TGL-41 row of [SECURITY-PROFILES.md](../SECURITY-PROFILES.md) (with the lead), `bench/notify/results/<date>-live.md` (no real names), `docs/plans/notifications-exit.md`.
- **Depends on:** WP16.2 to WP16.6.
- **The rows:**

  | Row | What is checked |
  |---|---|
  | `notify.secret` | Canary values in every secret of every channel, in a user's password and in a TOTP seed never appear in a captured e-mail, webhook body or header other than the signature, MQTT payload or topic, log line, audit record, API answer or delivery state |
  | `notify.publish_only` | A fake broker's unsolicited PUBLISH, a retained message under Tenko's prefix written by another client, and a forged `online` change nothing in Tenko; the capture shows no SUBSCRIBE |
  | `notify.egress` | Loopback, link-local and metadata destinations, literal and by a name, are refused for all three channels; a webhook redirect is not followed |
  | `notify.tls` | A wrong certificate name, an expired certificate and a stripped STARTTLS are refused on every profile but Lab; plain transports are refused under Standard and Hardened |
  | `notify.flood` | The flood of E92 leaves the mailbox within its bound and the controller within M75 |
  | `notify.permission` | Every `notify` route without the update permission is refused; under Hardened a destination change without step-up is refused |

- **Acceptance:** E98; E99 (owner-run).

Total: 35 builder-days with own clients (31 with both libraries). The critical path is WP16.0, WP16.1 or WP16.2, WP16.3 or WP16.4, WP16.5, WP16.7 (20 days).

**Without MQTT** (if the owner defers it in NT-Q15): WP16.4 is dropped whole; WP16.5 loses its MQTT quorum topic and the tests of it and is 2 days; the lab loses Mosquitto and E95; the security row `notify.publish_only` waits with it. Total 30 builder-days. WP16.0 still creates `ChannelKind::Mqtt`, its settings type and the empty `notify.mqtt_retained` table (a few hours, and the data format then needs no change when MQTT follows), with the API refusing an MQTT channel as not available; the ADR records the MQTT decisions so that WP16.4 can follow alone later.

## 5. Order, measurements and exit checks

### 5.1 Order

WP16.0 first. Then WP16.1 and WP16.2 in parallel (disjoint files). Then WP16.3 and WP16.4 in parallel, and WP16.6 beside them against the mock. Then WP16.5, which needs the senders. WP16.7's rows and the live test come last. The slice touches none of the files of Slice 14, Slice 13 or the public DNS slice, apart from one import in `lists.rs` and the additive `SystemComponent` variant; OPS-29 is not a condition of 0.1.0 (ROADMAP), so it never displaces the Kerberos line or the takeover (NT-Q15). The webhook alone (WP16.0, WP16.1, WP16.2 and the webhook's part of WP16.6) is a useful first delivery: it is the owner's first use.

### 5.2 Measurements

| # | Measurement | Threshold | Package |
|---|---|---|---|
| M73 | One evaluator round over a store with 10,000 prefixes, 500 status warnings and 1,000 raised alarms | Under 50 ms per round on the node of M21; no memory growth over 1,000 rounds | WP16.1 |
| M74 | From a raised alarm to its receipt, in the lab | Webhook under 2 s, MQTT under 1 s, e-mail under 5 s at the 99th percentile, the hold-down excluded | WP16.2 |
| M75 | The flood of E92 | Resident memory growth of the leader under 32 MiB; store writes: one per alarm event (the alarm row and its event in one batch), and per channel one batch per 5 s holding the cursor and the delivery rows | WP16.2 |
| M76 | From the cut of a controller to the receipt of its `cluster.quorum_lost` | Under the threshold plus 10 s | WP16.5 |

## 6. Owner decisions

Each question lists its options, the trade-offs under the owner's four headings in order (security, performance, usability, features) and one recommendation.

**NT-Q1. One alarm model, or notifications straight from each source?**
- Options: (a) one alarm layer above the sources (section 2.1): a stored alarm with code, severity, area, dedup key and state, kept in step by an evaluator that follows the existing tables and every controller's warnings; (b) each source calls the notification path itself; (c) deliver the findings list as it is.
- Security: (a) gives the auth alarms, which no page shows today, a list and one place where what leaves the product is decided; (b) spreads that decision over every source crate; (c) has no state to deliver a clear from. Performance: (a) costs an evaluator round every 15 s (M73); (b) costs nothing extra; (c) re-derives findings on every read. Usability: (a) gives one dedup, hold-down and acknowledgment rule; (b) gives each source its own; (c) mixes work items (a waiting proposal) with news. Features: (b) leaves the next source to remember the call.
- **Recommendation: (a), with three severities (`critical`, `warning`, `info`) and the areas of section 2.1.**

**NT-Q2. Event alarms, repeats, acknowledgment and reminders?**
- Options: (a) the rules of section 2.2: every occurrence of a security event alarm is delivered (within the rate limit), a doubling of `sign_in_failures` is delivered as a change, other event alarms once per hold time; acknowledgment in this slice; reminders per route, off by default; (b) treat every alarm as a condition a person must clear; (c) each event alarm once per hold time, no acknowledgment, no reminders.
- Security: (c) lets a harmless first break-glass alarm hide the real one for a week; (a) delivers each; (b) delivers each but never lets the list empty. Performance: equal. Usability: (b) leaves the list full of last month's events and sends clears nobody needs; (a) adds one small route and one setting per route. Features: (c) has the least.
- **Recommendation: (a).**

**NT-Q3. The delivery path?**
- Options: (a) the alarm events table as the queue, a cursor per channel fenced with the leader epoch, at least once with a stable message id (the audit export's pattern); (b) an in-memory queue on the leader; (c) one job per delivery.
- Security: (b) loses what was queued at every leader change or restart, which is when alarms happen; (a) and (c) keep it. Performance: (c) runs every delivery through the job engine's steps and floods the jobs list; (a) writes one cursor and a batch of delivery rows per 5 s per channel; (b) writes nothing. Usability: (a) shows the delivery state per alarm; (c) shows jobs. Features: equal.
- **Recommendation: (a).**

**NT-Q4. Flood: rate limits, folding, digests, quiet hours?**
- Options: (a) a token bucket per channel, folding the excess into stored digests in the order of section 2.5, first raises of `critical` never folded, a `notify.flood` alarm, digest routes, no quiet hours; (b) drop the excess; (c) no limit.
- Security: (c) lets an attacker who triggers many alarms fill a mailbox, which is OPS-29's own example, and can get the sender blocked by its mail provider; (b) hides alarms without a trace; (a) delays some messages and always says how many it folded. Quiet hours would hold a `critical` alarm at night, which is when an attack happens. Performance: (a) bounds the work per channel. Usability: a digest route does for `info` what a quiet hour would. Features: equal.
- **Recommendation: (a), with the defaults of section 2.5.**

**NT-Q5. A controller that lost its quorum?**
- Options: (a) the local path of section 2.7 on every controller: from its local copy, a fixed list of alarms, once per outage per channel, a local file, a report handed back after the heal; (b) only the MQTT will and the heartbeat tell that something is wrong; (c) nothing: monitoring from outside.
- Security: (a) makes a node act without the cluster's agreement and read secrets while isolated, but sends nothing it could not know alone; (b) and (c) leave e-mail silent in exactly the case the requirement names. Performance: negligible for all. Usability: (a) sends one message per controller in a total partition; (c) needs a second monitoring system. Features: (a) is the only one that meets OPS-29's wording.
- **Recommendation: (a).**

**NT-Q6. "Tenko is gone" on channels without a last will?**
- Options: (a) an optional heartbeat on the webhook channel, signed like every delivery, off by default; (b) none: only MQTT's will.
- Security: (b) leaves a single-node installation without MQTT unable to report its own death; (a) tells a receiver within minutes. Performance: (a) costs one small request every few minutes. Usability: (a) needs a flow in the receiver that alarms when heartbeats stop. Features: a heartbeat by e-mail is not offered: a mailbox is not a watchdog.
- **Recommendation: (a).**

**NT-Q7. What may a notification say?**
- Options: (a) the three detail levels of section 2.9: `minimal` on MQTT always and on every channel under Hardened, `standard` (account name, subject, parameters, no client address) by default elsewhere, `full` (with the client address) only by choice and never under Hardened; (b) everything the alarm holds, everywhere; (c) `minimal` everywhere.
- Security: (b) copies account names and attackers' addresses into mailboxes and home-automation logs, kept longer and less protected than the audit log; (c) is the tightest; (a) follows the profile. Performance: equal. Usability: (c) makes every e-mail a "sign in to see what happened", a step backwards for a home user. Features: (b) has the most.
- **Recommendation: (a).**

**NT-Q8. The webhook's signature?**
- Options: (a) Standard Webhooks `v1` (HMAC-SHA256 over id, timestamp and body; headers `webhook-id`, `webhook-timestamp`, `webhook-signature`; two signatures during a rotation), plus an optional static header for receivers that only check a token; (b) GitHub's form (HMAC-SHA256 of the body in `X-Hub-Signature-256`, no timestamp); (c) Stripe's form (`Stripe-Signature: t=..., v1=...`); (d) a static token only.
- Security: (b) has no timestamp, so a recorded request can be replayed forever; (d) proves only that the sender knows a token that travels with every request; (a) and (c) carry a timestamp and allow rotation. Performance: equal (one HMAC per attempt). Usability: (a) is an open specification with libraries in many languages and test values; (c) is one vendor's format. Features: Ed25519 signatures (`v1a`: an asymmetric signature, which a receiver can check without being able to sign) can be added later on the same header; no receiver the owner uses needs them.
- **Recommendation: (a).**

**NT-Q9. The webhook's transport rules?**
- Options: (a) HTTPS required on Standard and Hardened, plain HTTP only to private addresses under Home (with a warning) and under Lab, the fetch policy on every address (private addresses allowed; loopback, link-local and metadata refused unless allowed), no redirects, the URL stored in the vault when it carries a secret; (b) HTTPS on every profile; (c) the rules of the block-list fetch (redirects followed and re-checked).
- Security: (c) lets a receiver that was taken over send Tenko's notifications elsewhere; (b) is the strictest; (a) allows plain HTTP only inside the home network. Performance: equal. Usability: (b) forces the owner to give a flow tool on the home network a certificate before the first test. Features: equal.
- **Recommendation: (a).**

**NT-Q10. The SMTP client: write it, or take a library?**
- Options: (a) a narrow submission client of our own in `tenko-notify`: EHLO, STARTTLS or implicit TLS, `AUTH PLAIN` and `AUTH LOGIN`, `MAIL`, `RCPT`, `DATA` with dot-stuffing, `QUIT`, the reply parser, and the message's headers (RFC 5322 date, RFC 2047 subject) and base64 body; about 900 lines and 500 lines of tests, a fuzz target on the reply parser, on the TLS path of the audit export; (b) `lettre` 0.11.23 with `default-features = false` and the features `tokio1`, `tokio1-rustls`, `aws-lc-rs`, `smtp-transport` and `builder` (never `rustls-tls` or `tokio1-rustls-tls`, which turn on `ring`).
- Use share of (b): the asynchronous SMTP transport and the message builder, perhaps a third of the crate's code once its sendmail and file transports, pool, DKIM (DomainKeys Identified Mail, the signing of outgoing mail by a domain) and native TLS are off. Tree cost of (b), from its published dependency list against our lock (not built, R168): new crates `lettre`, `email_address`, `email-encoding`, `quoted_printable`, and `nom` 8 beside the `nom` 7 already in the lock (a second major version of a parser); the rest (`idna`, `mime`, `httpdate`, `fastrand`, `socket2`, `url`, `percent-encoding`, `base64`, `tokio-rustls`, `rustls-native-certs`) is in the lock already.
- Security: (a) puts the STARTTLS injection guard, the certificate check and the header escaping in code we test ourselves against recorded hostile servers, with a fuzz target; (b) is widely used, had an injection advisory of its own (fixed), and must be kept away from `ring` by hand; both use the same rustls. Performance: equal for a few messages an hour. Usability: (b) has met more odd mail servers; (a) talks only to submission servers, a smaller world, and the owner's live test checks the owner's own. Features: (b) has DKIM and OAuth hooks we do not plan.
- **Recommendation: (a), because the part we use is small, the risky part (TLS and the reply parser) is exactly what we want under our own tests, and it adds no crate; (b) is the fallback if the live test meets a server our client cannot handle within a day's work.**

**NT-Q11. SMTP's TLS and sign-in?**
- Options: (a) implicit TLS by default, required STARTTLS as the alternative, `AUTH PLAIN` or `AUTH LOGIN` inside TLS, plain only under Lab, OAuth 2.0 later; (b) also opportunistic STARTTLS (plain text when the server does not offer it); (c) OAuth 2.0 now.
- Security: (b) sends the password in plain text to anyone who strips one line from the server's answer (RFC 3207's downgrade); (a) and (c) never do. Performance: equal. Usability: (c) adds a token flow and a new secret kind for two providers, of which Microsoft keeps basic authentication available until the end of December 2026 and switchable after that, and Google accepts app passwords; (a) works with the owner's own relay, an ISP's (internet service provider's) submission server and app passwords today. Features: (c) reaches Microsoft 365 and Google without app passwords.
- **Recommendation: (a); OAuth 2.0 (XOAUTH2 and OAUTHBEARER) as a later package when a user needs Microsoft 365 or Google without app passwords.**

**NT-Q12. The MQTT client: write it, or take a library?**
- Options: (a) a narrow publish-only MQTT 5.0 client of our own: CONNECT with the will, PUBLISH at QoS 0 and 1, PUBACK, PINGREQ, DISCONNECT, a decoder for four packet types, about 700 lines and 400 lines of tests, a fuzz target on the decoder; (b) `rumqttc` 0.25.1 with `default-features = false` and `use-rustls-no-provider`, the provider set to `aws-lc-rs` on `tokio-rustls`.
- Use share of (b): connect, publish and the keep-alive of a client whose event loop, request queue, subscriptions and MQTT 3.1.1 types make most of it; its 5.0 module's completeness could not be confirmed (section 11). Tree cost of (b), from its published dependency list against our lock (not built): new crates `rumqttc`, `flume`, `rustls-pemfile`, and `rustls-webpki` 0.102 beside the 0.103 in the lock (a second version of the certificate verifier); `tokio-util`, `tokio-stream`, `bytes`, `fixedbitset`, `futures-util`, `log`, `thiserror` are present.
- Security: (a) has no SUBSCRIBE in its code at all, so "publish only" is a property of the code rather than of its use, and its decoder accepts four packet types; (b) brings a second certificate verifier version and a full client whose subscribe path we would have to prove unused. Performance: equal. Usability: (b) has tested reconnect logic, which (a) writes in a few dozen lines. Features: (b) has 3.1.1, which (a) leaves out.
- **Recommendation: (a).**

**NT-Q13. MQTT's version, connections, and Home Assistant discovery?**
- Options: (a) MQTT 5.0 only; one connection per controller node with its own will on its own status topic; the leader publishes the alarm topics; the topic layout of section 2.8; no discovery topics in this slice; (b) 3.1.1 (or both); (c) one connection for the cluster, from the leader, with one will for the whole installation; (d) also publish Home Assistant discovery topics now.
- Security: (d) makes entities appear in another system, which is the first half of the integration the ROADMAP keeps as a candidate with its own security design; (a), (b) and (c) only publish Tenko's own topics. Performance: equal. Usability: (c) makes every leader change look like "Tenko is gone" and says nothing about which node died; (b) loses the reason codes that make a refused connection explainable, and Home Assistant itself requires a 5.0 broker. Features: the stable topics of (a) let discovery be built later without a change.
- **Recommendation: (a).**

**NT-Q14. The Hardened profile's stance, and the toggle?**
- Options: (a) all three channels allowed with the rules of section 2.11 (TLS validated everywhere, MQTT authenticated, detail `minimal`, destination and secret changes with step-up, a failing channel raised at once), recorded as TGL-41 "Notification transport"; (b) webhook and e-mail only under Hardened; (c) no notification channels under Hardened.
- Security: a channel is a path out; the step-up, the audit and the `minimal` detail make a changed destination visible and limit what it carries; (b) refuses MQTT, whose broker's access rules Tenko cannot check, at the cost of the will; (c) leaves the sites that need it most without a way to be told. Performance: equal. Usability: (c) is the worst. Features: (a) has all three.
- **Recommendation: (a).**

**NT-Q15. When, and is MQTT built in this slice?**
- Options: (a) after the Windows takeover's exit and the Kerberos line's WP13.4, in a free builder slot, the webhook first (WP16.0 to WP16.2), MQTT inside the slice as its last channel; (b) now, beside them; (c) the slice without MQTT, MQTT later (section 4's cut, 30 builder-days); (d) after 0.1.0.
- Security: (b) competes for the builder slots with security work 0.1.0 waits for; the others do not. Performance: none. Usability: (d) leaves the owner's first use, the webhook to the flow tool, waiting for months; (a) delivers it early. Features: (c) saves 5 builder-days and loses the will, which the owner values.
- **Recommendation: (a).**

**NT-Q16. The form of an e-mail and the language of a notification?**
- Options: (a) plain text only, UTF-8, the language chosen per channel (`en` or `sv`), the templates kept in both languages beside the code catalog; (b) plain text and HTML; (c) English only.
- Security: (b) invites remote content and rendering quirks in mail clients; (a) and (c) open nothing. Performance: equal. Usability: (c) is wrong for a Swedish household; (a) uses the language the channel's readers speak. Features: (b) adds a second template per code, for formatting.
- **Recommendation: (a).**

## 7. Requirement rows touched

No new requirement IDs. Proposed edits, applied with the decisions:

| Row | Today | Proposed |
|---|---|---|
| OPS-29 | "... Routing by severity and area, a test delivery from the UI, rate limits and digests ..." | Adds: "Delivery is at least once, with a stable id per notification; a controller that lost its quorum reports it on its own." |
| API-06 | "Webhooks." | "Webhooks: subscriptions to the topics of the event stream, delivered through the notification path of OPS-29 with its signing, rate limits and delivery state." |

ROADMAP: the Phase 4 line for OPS-29 links this plan. SECURITY-PROFILES.md: the new row TGL-41 (section 2.11). The trace script's Phase 4 entry does not list this plan; adding it and E89 to E99 is the lead's choice when the plan is accepted (as for the public DNS plan).

## 8. Risks

| # | Risk | Proposed resolution |
|---|---|---|
| R160 | The new namespaces force a data format, and the public DNS slice may take the same number | WP16.0 decides with the lead; whichever slice lands second adds its tables to the unreleased format or takes the next one; an empty migration with its fixture, as earlier formats |
| R161 | An attacker drives alarms to flood a mailbox or get the sender blocked by its provider | Dedup by key, the token bucket, folding with `critical` first raises protected, `notify.flood`; E92 and M75 |
| R162 | The evaluator raises or clears on a transient warning and makes noise | Hold-downs per code; the flap test of E89 |
| R163 | The vault cannot decrypt on an isolated controller, so the local path cannot read the SMTP password | The envelope is read from the local copy already (`StoreVault::read_envelope` uses `ReadConsistency::Local`); what remains is the node-local KEK's unwrap while isolated, which WP16.5 proves first; if it fails, the local path keeps a copy of the channel's secrets sealed with the node's own key, refreshed while the cluster is healthy, which needs its own decision |
| R164 | A total partition sends one message per controller and a 1-against-2 split two messages | Accepted and documented: each message names its node; bounded to one per outage per node and channel |
| R165 | A receiver that was taken over, or a webhook URL changed by an insider, collects alarm content | Detail levels, no secrets in any notification, the audit of every change, the step-up under Hardened, no redirects |
| R166 | A broker without access control lets anyone forge Tenko's alarm states for the subscribers | TLS and authentication required outside Home and Lab; the broker rule in the documentation; Tenko never reads from the broker, so forgery misleads subscribers, never Tenko |
| R167 | A server offers only TLS 1.2 and Hardened prefers 1.3 | The one rule of section 2.11: 1.2 at least (RFC 8314's minimum), a per-channel "TLS 1.3 only" switch, a 1.2 session under Hardened shown as a channel warning |
| R168 | The tree costs of `lettre` and `rumqttc` in NT-Q10 and NT-Q12 come from their published dependency lists, not from a build | Before a library is taken, its builder measures with `cargo tree` and reports; the recommendation does not depend on it |
| R169 | The own SMTP client meets a server dialect it does not handle | The fake servers cover multi-line replies, enhanced status codes and every refusal class; the live test against the owner's server; the library as fallback (NT-Q10) |
| R170 | A delivery hangs and holds the channel's worker | Timeouts per stage (RFC 5321's for SMTP, 15 s per webhook, the keep-alive for MQTT); a hung delivery counts as failed and is retried |
| R171 | A template renders a parameter that came from outside into an e-mail header or a JSON value | Typed, bounded parameters with escaping per channel; a property test with control characters and line breaks in every string parameter; the `notify.secret` row |
| R172 | Duplicates after a leader change annoy a receiver that does not deduplicate | The stable id in every channel; the documentation's receiver snippets drop repeats by id |
| R173 | The heartbeat and the will report "Tenko gone" during a planned restart or upgrade | The upgrade path publishes a clean `DISCONNECT` (no will) and pauses the heartbeat for the restart's expected time; a receiver's alarm waits two missed heartbeats |
| R174 | Microsoft or Google close password sign-in for SMTP entirely | OAuth 2.0 as the later package of NT-Q11; until then a relay of the owner's or an app password |

## 9. Owner actions and the live test

### 9.1 Owner actions

| When | Action |
|---|---|
| Before WP16.0 | Decide NT-Q1 to NT-Q16 |
| Before the live test | Prepare a webhook endpoint in the flow tool (the documentation's snippet checks the signature), a submission account (the owner's own relay or an app password), and on the broker a user for Tenko with publish rights below one prefix only |
| After the live test | Set the routes the owner wants (for example: `critical` immediately by e-mail and webhook, everything else as a daily digest) |

### 9.2 The live test, step by step

Each step names what to check before the next.

1. **The webhook.** Create a webhook channel to the flow tool with detail `standard`; copy the signing secret into the flow's check. Run the test delivery. *Check:* the flow shows the test with a valid signature; the channel shows `delivered` with its latency; changing one byte of the secret in the flow makes it refuse the next test.
2. **A real alarm.** Fill a test prefix past its critical threshold (a lab prefix in `198.51.100.0/24`). *Check:* one `alarm.raised` within the hold-down plus seconds; after freeing the addresses, one `alarm.cleared`.
3. **E-mail.** Create an SMTP channel with implicit TLS (or STARTTLS if the server has no 465). Test. *Check:* the mail arrives with the Swedish subject intact; the mail's headers show TLS on the submission hop.
4. **MQTT.** Create an MQTT channel to the broker with TLS (or plain under Home). Test. *Check:* a subscriber to `tenko/#` sees `online` on the node's status topic and the test on `events`; stopping Tenko's service with `kill -9` (or pulling the network cable of a test VM) makes `offline` appear within 45 s.
5. **The routes.** Set the routes of section 9.1. *Check:* an `info` alarm (a check for updates when one exists) does not arrive immediately and is in the next digest.
6. **Rotation.** Rotate the webhook's secret with a 24 h overlap. *Check:* the flow still verifies with the old secret; after the new secret is in the flow, the old one can be dropped.

**To undo at any point:** disable or delete the channel; nothing outside Tenko changes except the messages already sent.

## 10. Documents this slice writes

| Document | Package |
|---|---|
| The ADR (proposed 0036) for the alarm model, the delivery path, the local path and the publish-only rule. It must decide: the alarm's identity, severities and areas, and that the sources stay; the event and condition kinds, hold-downs and acknowledgment; the queue as a journal with cursors and at least once with stable ids; folding order and what is never folded; where delivery runs, the local path's trigger, reads and limits; MQTT 5.0, one connection per controller and its will, the topic layout and that no SUBSCRIBE exists; the detail levels and the rule that no secret is ever rendered; the webhook's signature scheme and transport rules; the own clients or the libraries | WP16.0 |
| [api/README.md](../api/README.md): the payload schema 1 and the webhook headers | WP16.0 |
| `docs/notifications.md`: the operator's page (alarms and their codes, channels, routes, detail levels, rate limits and digests, the delivery state, the local path, the broker's access rule, the receiver snippets for n8n and Node-RED, the live test as a runbook) | WP16.7, from the sections WP16.2 to WP16.5 hand over |
| [observability.md](../observability.md): the alarm and notification metrics | WP16.2, with WP16.1's text |
| [partitions.md](../partitions.md): what an isolated controller sends | WP16.5 |
| [SECURITY-PROFILES.md](../SECURITY-PROFILES.md): TGL-41 | WP16.7 |
| [CONFORMANCE.md](../CONFORMANCE.md): rows for RFC 2045 and RFC 2047 (MIME, encoded words), RFC 3207, RFC 3834 (`Auto-Submitted`), RFC 4616, RFC 4954, RFC 5321 (client subset), RFC 5322, RFC 6409, RFC 6125 and RFC 7817 (certificate identity), RFC 8314, RFC 2104 (HMAC), RFC 7628 (deliberately skipped in this slice), and a note on the OASIS MQTT 5.0 standard and the Standard Webhooks specification, which are not RFCs | WP16.7 |
| `deploy/compose/lab-notify/README.md` | WP16.7 |
| `bench/notify/results/`: one file per measurement (M73 by WP16.1, M74 and M75 by WP16.2, M76 by WP16.5) and the live test (WP16.7) | WP16.1, WP16.2, WP16.5, WP16.7 |
| `docs/plans/notifications-exit.md` | WP16.7 |

**The trace.** This plan names OPS-29 and other rows of Phases 1 to 5; regenerating the trace files lists it under them (`node scripts/requirement-trace.mjs` and its `--phase` variants).

## 11. Sources

The facts about Tenko come from the code and the documents read on `cbe6c27a` (section 1.5). The pages below were read on 2026-11-11; what they did not state is marked here.

**E-mail**

- RFC 6409, message submission (port 587, the server may require authentication and add `Date` and `Message-ID`): https://www.rfc-editor.org/rfc/rfc6409.html
- RFC 8314, implicit TLS preferred for submission on port 465, certificate validation required, TLS 1.2 or later: https://www.rfc-editor.org/rfc/rfc8314.html
- RFC 3207, STARTTLS (discard what was learned before TLS, send EHLO again, the downgrade by a deleted `250 STARTTLS`): https://www.rfc-editor.org/rfc/rfc3207.html
- RFC 4954, SMTP `AUTH` (the reply codes, PLAIN only after the certificate was checked): https://www.rfc-editor.org/rfc/rfc4954.html
- RFC 4616, the PLAIN mechanism: https://www.rfc-editor.org/rfc/rfc4616.html
- RFC 7628, OAUTHBEARER (for the later package; XOAUTH2 has no RFC): https://www.rfc-editor.org/rfc/rfc7628.html
- RFC 7817, certificate verification for e-mail (the reference identifier is the configured host name): https://www.rfc-editor.org/rfc/rfc7817.html
- RFC 5321 (line limits, dot-stuffing, timeouts) and RFC 5322 (`Date`, `Message-ID`, line lengths): https://www.rfc-editor.org/rfc/rfc5321.html, https://www.rfc-editor.org/rfc/rfc5322.html
- RFC 2047, encoded words for a non-ASCII subject; RFC 6532 considered and not used (it needs SMTPUTF8): https://www.rfc-editor.org/rfc/rfc2047.html, https://www.rfc-editor.org/rfc/rfc6532.html
- The STARTTLS injection research of 2021 and the 2011 case (no plain-text bytes may be processed after the upgrade; implicit TLS recommended): https://nostarttls.secvuln.info/
- Microsoft's timeline for basic authentication in SMTP AUTH (on hold; off by default for existing tenants at the end of December 2026, switchable; removal date announced in the second half of 2027): https://techcommunity.microsoft.com/blog/Exchange/updated-exchange-online-smtp-auth-basic-authentication-deprecation-timeline/4489835 and https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission
- Google's end of less secure apps on 2025-03-14, app passwords as the exception: https://knowledge.workspace.google.com/admin/sync/transition-from-less-secure-apps-to-oauth

**MQTT**

- MQTT 3.1.1 (retained messages, the empty retained message that deletes, the will, keep-alive at 1.5 times, QoS): https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html
- MQTT 5.0 (will delay, session expiry, clean start, message expiry, maximum packet size, user properties, reason codes `0x86`, `0x87`, `0x95`): https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html
- The port registry of IANA (the Internet Assigned Numbers Authority), port 8883 for MQTT over TLS: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=secure-mqtt
- Home Assistant's MQTT integration (needs a broker with version 5; birth and will `online` and `offline` on `homeassistant/status`; discovery): https://www.home-assistant.io/integrations/mqtt/
- Mosquitto's configuration (no anonymous access by default when listeners are configured; TLS listener options; protocol versions; `max_packet_size`): https://mosquitto.org/man/mosquitto-conf-5.html and https://mosquitto.org/documentation/authentication-methods/

**Webhooks and receivers**

- The Standard Webhooks specification (headers, the signed content `id.timestamp.body`, `v1` and `v1a`, the `whsec_` secret, rotation with two signatures, the id for repeats): https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md
- Svix's verification (the same scheme): https://docs.svix.com/receiving/verifying-payloads/how-manual
- GitHub's `X-Hub-Signature-256` (body only, no timestamp): https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
- Stripe's `Stripe-Signature` (timestamp and body, a 5-minute default tolerance, several `v1` values during a rotation): https://docs.stripe.com/webhooks
- Slack's request signing (`v0`, timestamp, 5 minutes): https://docs.slack.dev/authentication/verifying-requests-from-slack
- Home Assistant's webhook trigger (the id in the URL is the only secret, local only by default): https://www.home-assistant.io/triggers/webhook/
- n8n's Webhook node (basic, header and JWT authentication; raw body available; no built-in HMAC check): https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/
- Node-RED's function nodes (modules through the settings file; whether `crypto` is available by default was not confirmed): https://nodered.org/docs/user-guide/writing-functions
- ntfy (token or basic authentication) and Gotify (application token): https://docs.ntfy.sh/publish/, https://gotify.net/docs/pushmsg

**Lab images**

- Mailpit (SMTP on 1025, STARTTLS, required STARTTLS or implicit TLS per listener, AUTH by file or variable, the REST API under `/api/v1/`; Docker Hub shows only `latest`, so WP16.0 pins a digest): https://hub.docker.com/r/axllent/mailpit, https://mailpit.axllent.org/docs/configuration/smtp/
- Eclipse Mosquitto (tags `2.1.2-alpine` and `2.0.22`; configuration under `/mosquitto/config`): https://hub.docker.com/_/eclipse-mosquitto

**Libraries** (published dependency lists read, nothing downloaded or built)

- `lettre` 0.11.23 (default features with native TLS; `rustls-tls` and `tokio1-rustls-tls` turn on `ring`; `aws-lc-rs` selectable; always-on dependencies `email_address`, `idna`, `nom` 8): https://crates.io/api/v1/crates/lettre/0.11.23/dependencies, https://docs.rs/crate/lettre/0.11.23/features
- `mail-send` 0.7.0 and `mail-builder` 2.0.1 (considered; `smtp-proto`, `gethostname`, `encodify`, `rustls-platform-verifier` would be new): https://crates.io/api/v1/crates/mail-send, https://crates.io/api/v1/crates/mail-builder
- `rumqttc` 0.25.1 (default `use-rustls` with `aws-lc-rs`; `use-rustls-no-provider` pulls `rustls-webpki` 0.102 and `rustls-pemfile`; a `v5` module whose completeness was not confirmed): https://crates.io/api/v1/crates/rumqttc, https://docs.rs/crate/rumqttc/latest/features, https://docs.rs/rumqttc/0.25.1/rumqttc/

**Not confirmed on 2026-11-11**, for the packages to settle: whether Microsoft 365 offers implicit TLS on 465 for submission; the wire format of XOAUTH2; whether Node-RED's function nodes reach `crypto` and the raw body without settings (WP16.7's snippet); Mailpit's individual API routes; the completeness of `rumqttc`'s 5.0 client; the full trees of `lettre` and `rumqttc` (R168).

Specifications not read again but relied on: RFC 2045 (MIME), RFC 2104 (HMAC), RFC 3834 (`Auto-Submitted`), RFC 6125 (service identity), RFC 1918 and RFC 4193 (private addresses), RFC 5737 and RFC 3849 (documentation addresses).

Project documents: [audit-export.md](../audit-export.md), [observability.md](../observability.md), [partitions.md](../partitions.md), [secrets.md](../secrets.md), [cluster.md](../cluster.md), ADR 0002, ADR 0008, ADR 0014, ADR 0016, ADR 0018, ADR 0023, [public-dns-plan.md](public-dns-plan.md).
