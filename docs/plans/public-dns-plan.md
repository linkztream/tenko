# Public DNS plan: a public zone at a provider beside an internal zone of the same name

- Status: Accepted on 2026-11-10: the owner took PD-Q1 to PD-Q12 of section 6 as recommended. The owner keeps PD-Q6 and PD-Q8 open to a better solution and has not yet scheduled the slice; no package starts before the owner says so
- Date: 2026-11-10
- Scope: CONN-22, added by the owner on 2026-11-10. Tenko manages the records of a public zone hosted at a DNS provider through the provider's API, by a plugin per provider, the first for Cloudflare. The public zone is a zone object of its own, kept apart from an internal zone of the same name, and the two are compared, never merged. Written against `main` at `fb0c8f57`. Requirement IDs refer to [REQUIREMENTS.md](../REQUIREMENTS.md), toggles (TGL) to [SECURITY-PROFILES.md](../SECURITY-PROFILES.md). Exit criteria, measurements and risks continue the project's series: E81 onward, M71 onward and R151 onward (the Windows takeover plan ends at E80, M70 and R150)

This plan follows the shape of [windows-takeover-plan.md](windows-takeover-plan.md): the goal and the exit criteria as checks, the design decisions the packages share, the contracts, the work packages with owned files, the order, the owner's decisions, the risks and the owner's actions. "(proposed)" marks a choice the documents leave open. Sizes are in builder-days. One record needs an ADR (the lead numbers it; 0035 is the next free number): the public zone object, the provider capability of the plugin protocol and the ownership rule (sections 2.1 to 2.4). The slice number is the lead's; this plan calls it Slice 15 and its packages WP15.0 to WP15.5.

Every statement about the provider's API was read on the provider's public documentation on 2026-11-10 (section 11). A statement marked **(unconfirmed)** could not be confirmed there and is checked by WP15.1 against the documentation and by the owner's live test before any text or code relies on it.

Contents:

1. [Scope and exit](#1-scope-and-exit)
2. [Design decisions the packages share](#2-design-decisions-the-packages-share)
3. [Contracts and shared files (WP15.0)](#3-contracts-and-shared-files-wp150)
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

**The case this is for.** The owner's site has an Active Directory domain whose DNS name is also the name of a public zone hosted at Cloudflare: a split horizon that was not planned that way. In this plan both are `example.test`. Internally Tenko is, or will be after the Windows takeover, the primary of the AD zone `example.test` with its locator records (`_msdcs`, `_sites`, `_tcp`, `_udp`), the domain controllers and the clients. Publicly the provider serves another set of records under the same name: a web site, mail (MX, SPF, DKIM, DMARC), perhaps a VPN or remote-access name that points at the site's public address (in this plan `203.0.113.10` and `2001:db8:ff::10`), and records other tools write, such as an ACME client's `_acme-challenge` TXT records. Today the two are edited by hand in two places, and nothing says which names exist on one side only.

**What changes.**

1. **A public zone object.** The operator creates a public zone `example.test` bound to a provider connector. It is not a DNS zone of the engine and is never served by Tenko; it holds what Tenko intends at the provider, and beside it the last read of what the provider has.
2. **Read, diff, preview, apply.** The plugin reads the provider's records; the host compares them with the intent, shows the difference, and writes only after a preview, through one atomic batch at the provider, followed by a read-back.
3. **Ownership.** Tenko changes or removes only records it created or was told to adopt. Every other record at the provider is listed as foreign and left alone.
4. **The comparison.** A page shows, name by name, what exists only internally, only publicly, on both sides the same, and on both sides different, and warns about names that must not leak outward and public names that internal clients cannot resolve.
5. **The public address.** A rule keeps chosen A and AAAA records at the provider in step with the site's public address when it changes.

**What stays.** The internal zone and the engine do not change. The provider remains the authoritative server of the public zone; its DNSSEC stays its own. Nothing in the core names Cloudflare: the provider capability of the plugin protocol is generic, and a second provider is a second plugin.

### 1.2 Exit criteria

| # | Check | Requirements | Package |
|---|---|---|---|
| E81 | The Cloudflare plugin against the recorded mock of the provider's API (documentation names and addresses only): a paged read maps every record type of the fixture, `proxied`, the automatic TTL, `settings`, the comment and the tags; a body above the bound, a page count above the bound, a record that does not parse and a redirect are refused with coded errors; a 429 with `retry-after` is reported as `connect.rate_limited` with the delay; `tenko plugin test --bundled cloudflare` passes; the fuzz target `connect_cloudflare_answers` runs in the weekly smoke | CONN-19, CONN-20, CONN-22 | WP15.1 |
| E82 | The model: a public zone `example.test` exists beside a primary zone `example.test`; the `dns` role's subset never contains a public zone table (a test over `Subset::role_tables`); a query to the engine for a name that exists only in the public zone answers from the internal zone (NXDOMAIN); deleting either zone leaves the other untouched | CONN-22, DNS-20 | WP15.0, WP15.2 |
| E83 | Ownership: a plan never contains a change of a foreign record, whatever the intent says (property test over random intents and provider states); adoption of a foreign record moves it to the ledger and writes only its marker; a record changed in the provider's console is reported as drift and not reverted without a preview; a ledger lost with a restore is rebuilt from the markers only after a person confirms each record | CONN-22, IPAM-15, IPAM-16 | WP15.2 |
| E84 | Writes: every apply is preceded by a fresh read and refused when the fingerprint moved; a plan that removes or replaces a record is refused without the confirmation of section 2.6; the leak guards refuse an AD locator name and a non-global address; one audit record per changed record; an instance with `writes_enabled = false` writes nothing | CONN-08, CONN-22, IPAM-17 | WP15.2 |
| E85 | The comparison view lists the five kinds of section 2.7 for the fixture pair of zones, and an internal copy of a public record follows its source | CONN-22, IPAM-21 | WP15.3 |
| E86 | The address follower: a push with the address token changes the address and nothing else (403 on every other operation); a changed address produces one plan for the records of the rule, applied under the rule's mode; a private or unchanged address writes nothing; at most one change per minute | CONN-22, IAM-10 | WP15.4 |
| E87 | The security rows `public_dns.*` of section 4 pass on the release binary | CONN-22, TGL-05 | WP15.5 |
| E88 | The owner's live test of section 9.2, steps 1 to 9, against the real provider, recorded without real names | CONN-22 | WP15.5 (owner-run) |

### 1.3 Requirements

| Requirement | What this slice delivers | Phase today |
|---|---|---|
| CONN-22 Public DNS providers | All of it, for Cloudflare | 4, Should |
| CONN-19 Plugin SDK and host | A new capability `dns_provider` with its service, additive within protocol version 1 | 1, delivered |
| CONN-20 Reference plugins | `cloudflare` joins the bundled plugins | 1, delivered |
| CONN-08 Verify before write | Applied to provider writes: read, diff, preview, apply with the plan, read back | 1, delivered |
| CONN-13 External DNS actuators | Not here: RFC 2136 and Windows DNS stay with their package; this slice shares only the generic actuator discipline | 4, Should |
| DNS-20 Views | Not changed. The public zone is not a scope or a view (section 2.1); views remain the tool for a split horizon that Tenko serves itself | 2, delivered |
| IPAM-12, IPAM-13, IPAM-15 to IPAM-17 | The public zone's intent and its observation are separate; a foreign record becomes a proposal to adopt, never intent by itself; drift is a proposal; every write is a job | 1, delivered |
| IPAM-21 | Not extended: the per-address view stays as it is; the comparison of the two zones is its own view (section 2.7) | 3, delivered |
| IAM-15, IAM-16 | The provider token is an operator secret in the vault, referenced by purpose, injected per call | 1, delivered |

### 1.4 Left out, with reasons

| Item | Reason | Goes to |
|---|---|---|
| Tenko serving the public zone (hidden primary with transfer to the provider) | PD-Q10: the provider offers incoming transfers on its Enterprise plan only; Tenko would answer transfers to the Internet; nothing the owner needs | Not planned |
| Providers other than Cloudflare | One plugin proves the capability; the next provider is a plugin against the same service | Later, one plugin each |
| Provider settings outside DNS records (DNSSEC on or off, the proxy's TLS and cache, page rules, email routing) | The token is scoped to DNS records (section 2.8); changing them needs wider rights | Not planned |
| Registrar operations (name servers, DS at the parent) | Another credential, another blast radius | Not planned |
| Reading the WAN address from the UniFi connector | The plugin reads no WAN address today (`crates/tenko-connect-unifi` maps networks, not the gateway's WAN state); one more address source when it does | A UniFi package |
| Moving the plugin out of the binary (ADR 0032) | The machinery of ADR 0032 does not exist yet (section 1.5) | When ADR 0032 is built (PD-Q2) |

### 1.5 Starting point in the code

Facts the packages build on, read on `fb0c8f57` (nothing was run):

- **The plugin host exists** (`crates/tenko-connect/src/host/`): launch with the stdio handshake, gRPC on a private socket or pipe, supervision with backoff and a circuit breaker, per-call `CallContext` with the instance's settings and the secrets of declared purposes, injected and audited (`connect.secret.inject`), `writes_enabled` per instance, `plan_max_age` for plans. Bundled plugins are entries of `crates/tenko/src/plugin/bundled.rs` (`sample`, `proxmox`, `hass`, `unifi`).
- **The actuator shape exists but is unused.** `tenko.connect.v1.Actuator` (`proto/tenko/connect/v1/actuator.proto`) has `Plan`, `Apply`, `Revert`; the host has `HostService::plan_actuation` and `apply_actuation` (`host/service/calls.rs`), which nothing calls: no job step, no route. Its intents are `DnsRecords` (A, AAAA and optionally PTR of one name) and `DnsRecordsRemove`; it cannot list a zone, carry another record type, a TTL, an ownership marker or a provider attribute. No bundled plugin declares `actuator`.
- **The HTTP pieces exist** (`crates/tenko-connect/src/sdk/http.rs`, feature `http-client`): `WebClient` on `reqwest` 0.12 with rustls and `aws-lc-rs`, TLS modes (system roots, pinned CA, pinned fingerprint, insecure), no proxies from the environment, no redirects, bounded reads (`read_json`, `read_bytes`, default 32 MiB), `status_error`, sensitive headers. The Proxmox VE and Home Assistant plugins use it, with fixture tests against a mock of the remote system, and each has a fuzz target (`fuzz/fuzz_targets/connect_*`).
- **ADR 0032 is Proposed and not built.** No `PluginSupervisor`, no plugin kind of service account, no plugin scopes, no observation write route, no `tenko-plugin@.service` template; the open question "content of plugin API 1.0" recommends inventory only. An out-of-tree provider plugin cannot be run today.
- **Zones** (`crates/tenko-core/src/dns.rs`, `crates/tenko-dns/src/zone/`). `ZoneKind` is `Primary`, `Secondary`, `Stub`, `Forward`, `Rpz`; a zone name is unique (`zone_by_name`, `dns.zone.exists`); the `dns` role receives every `dns.*` table except `dns.sign_state` (ADR 0017 decision 6). `Origin` is `Manual`, `Ipam`, `Dynamic`, `Dhcp`, `Ad`, `Transfer`, `Dnssec`.
- **Views** ([dns.md](../dns.md) section 11) select a scope of each zone per query; a zone exists in every view.
- **Mirrored sources and their token** ([connectors.md](../connectors.md) section 7, ADR 0033): the pattern of a token that writes one object and nothing else, which the address push reuses.
- **The store's data format** is 6 (the contracts of Slice 13 and Slice 14).

## 2. Design decisions the packages share

### 2.1 The public zone is an object of its own (PD-Q1)

A **public zone** is a row of a new namespace `public_dns` (proposed), not of `dns`:

| Table | Holds |
|---|---|
| `public_dns.zones` | id, name (a `DnsName`, unique within the table, not against `dns.zones`), the connector instance, the provider's zone identifier, the write scope (the whole zone or a subtree, section 2.6), the drift mode, the marker text, a description |
| `public_dns.records` | the intent: owner, type, typed data (`RecordData`), TTL or `auto`, the provider attributes of section 2.5, the source (`manual`, `adopted`, `address_rule`), the internal copy link of section 2.7, the ledger part: the provider's record id, the data last applied and when |
| `public_dns.observed` | the observation: the last complete read per zone (every record with its provider id, data, TTL, attributes, comment, tags, `modified_on`), its time and fingerprint; one row per zone, bounded (section 2.9) |
| `public_dns.address` | the address sources and rules of section 2.10 |

Why a namespace of its own: the `dns` role receives `dns.*`; a public zone outside it can never reach a DNS node, by construction rather than by a filter someone can forget. The engine has nothing to serve, so a mistake in this slice cannot leak a public record into internal answers or an internal record into the engine's view of the public zone. The same name in both namespaces is allowed and is the point; the two are joined only by name, in the comparison view, read-only.

Relation to the other models:

- **Views (DNS-20)** are how Tenko serves two versions of a zone it serves. A provider-hosted zone is not served by Tenko, so it is neither a scope nor a view. If the owner later moves the public zone into Tenko (with Tenko facing the Internet), it becomes a scope `external` of the zone and a view; this plan builds nothing for that.
- **Intent and observation (IPAM-12).** `public_dns.records` is intent; `public_dns.observed` is observation; the reconciler-like comparison of the two (section 2.3) produces the plan and the proposals, and observation never becomes intent by itself (IPAM-15).
- **The reconciliation view (IPAM-21)** is per address over networks of intent; public records mostly point at addresses outside them. The provider's A and AAAA records do not join the DNS truth of IPAM-21 (proposed); the zone comparison of section 2.7 is the view for this case.

### 2.2 The plugin: a new capability `dns_provider` (PD-Q2)

The existing `Actuator` service cannot list a zone or carry most types, and its intent is per name. A new service in `tenko.connect.v1`, additive within major version 1 as [plugins.md](../plugins.md) section 6 allows:

| Method | What it does |
|---|---|
| `ListZone` | Reads every record of one provider zone, paged by the plugin, and returns `ProviderRecord` items: the provider id, owner, type, data in presentation form, TTL (or automatic), `proxied`, the provider's other attributes as typed fields of the plugin's attribute schema, comment, tags, `modified_on`. Writes nothing |
| `Plan` | Takes a change set (creates, updates by provider id, deletes by provider id), reads back the records it names, returns the diff and a fingerprint of their state. Writes nothing |
| `Apply` | Re-reads, refuses a stale plan (`connect.verify_mismatch`), writes in `WRITE_MODE_APPLY` only, as one atomic call where the provider has one (Cloudflare's batch endpoint), reads back and reports `verified` and the new provider ids |
| `Revert` | Applies the inverse change set of a receipt, with the same discipline |

The host keeps every decision (ADR 0012 decision 5): which records are owned, what the plan may contain, the guards, the rate, the confirmation. The plugin only maps and calls. The manifest declares the capability, one secret purpose `api_token`, the network target `api.cloudflare.com:443`, and an attribute schema (section 2.5) that the host uses to validate what the plugin reports.

The Cloudflare plugin is a bundled plugin (`tenko plugin run cloudflare`, crate `tenko-connect-cloudflare`) on the gRPC contract of ADR 0012, built with `sdk::http::WebClient` in TLS mode `system` only (the modes `insecure` and `fingerprint` are refused by its settings schema: the provider's certificates rotate and a public API has no lab mode). When ADR 0032's managed plugins exist, the plugin is a candidate for moving out, as ADR 0032 point 9 decides one bundled connector at a time.

### 2.3 Ownership: a ledger, and a marker at the provider (PD-Q3)

**The ledger decides.** A record is owned when `public_dns.records` holds its provider id. Only owned records appear as updates or deletes in a plan; a record of the provider without a ledger entry is **foreign** and is never changed, whatever the intent says (E83). A create is always allowed within the write scope; its new provider id enters the ledger in the same store batch as the receipt.

**The marker helps people and recovery.** Every owned record carries a comment at the provider, for example `Managed by Tenko DDI. Edit in Tenko; changes here are reported. ref 0190d1c2` (under 100 characters, the Free plan's comment limit; comments are available on every plan). Tags are not used: the provider offers them only on paid plans. The marker is a hint, never proof: anyone with console access can write it on any record, so a comment alone never makes a record owned. After a restore that lost ledger entries, the records that carry a marker naming this public zone are offered as adoption proposals, each confirmed by a person.

**Adoption** (IPAM-15). A foreign record becomes owned by an explicit action: per record or for a selection, with a preview that shows exactly one change per record, the marker comment (the record's data, TTL and attributes are taken as they are). The adopted record's intent equals what the provider has, so adoption changes nothing a resolver sees. A record whose type or attributes the attribute schema does not carry (section 2.5) cannot be adopted and stays foreign.

**Edits in the provider's console.** Each read compares owned records with the ledger's last applied state:

| What the read shows | Result (drift mode `report`, proposed default) |
|---|---|
| An owned record changed (data, TTL, `proxied`) | Proposal `public_dns.drift.changed` with both values: keep the console's value (it becomes the intent) or restore the intent (a plan with a preview) |
| An owned record gone | Proposal `public_dns.drift.missing`: create it again (a plan) or drop it from the intent |
| The marker removed or changed | Finding, info; the record stays owned; the next apply writes the marker again |
| A foreign record appeared | Listed; an adoption proposal only when its name and type equal an intended record that has no provider id yet (a conflict, warning) |

The drift mode `restore` (PD-Q4) makes the intent win without a person for changed records only; a missing record is never re-created automatically, because someone deleted it deliberately at the provider.

### 2.4 The write path

One write is one job (IPAM-17) with these steps:

1. **Read** (`ListZone`), stored as the new `public_dns.observed` row.
2. **Plan** in the host: the difference between intent and observation, restricted to owned records and the write scope, checked by the guards of section 2.6.
3. **Preview**: the diff per record (before and after, with the attributes), the counts, the warnings of section 2.7. Creates are marked as such; updates and deletes are marked as replacing or removing.
4. **Confirmation** where section 2.6 requires one.
5. **Apply** with the plan (the plugin re-reads and refuses a moved fingerprint), as one batch.
6. **Verify**: a fresh `ListZone`; the job fails with `connect.verify_mismatch` when the read-back differs, and the rollback step applies the receipt's inverse.
7. **Audit**: one `public_dns.record.change` per changed record (zone, owner, type, before, after, provider id, the job, the principal), never the token.

A dry run (`WRITE_MODE_DRY_RUN`) stops after step 3. The instance's `writes_enabled` is off at creation.

### 2.5 Provider attributes (PD-Q5)

Cloudflare attaches attributes a plain DNS record has no place for. Each is either modeled as a typed, validated field of the plugin's attribute schema, or the record is read-only for Tenko:

| Attribute | Treatment (proposed) |
|---|---|
| `proxied` (A, AAAA, CNAME only) | Modeled as a boolean. The preview says what it means: resolvers get the provider's anycast addresses, not the record's content. The comparison view shows a proxied record's content as the origin, not as what the public sees |
| TTL `1` (automatic; proxied records are always automatic, documented as 5 minutes) | Modeled as `ttl: auto`; a numeric TTL is 60 to 86,400 (30 on Enterprise) |
| `settings.flatten_cname` (paid plans), apex flattening (automatic on every plan) | Apex flattening needs nothing: a CNAME at the apex is allowed in a public zone (the provider flattens it), and the host's apex rule for public zones says so. Per-record `flatten_cname` is modeled as a boolean, refused by the plugin's schema on a Free zone (unconfirmed how the API reports the plan; WP15.1 checks) |
| `settings.ipv4_only`, `settings.ipv6_only` (proxied records only) | Modeled as booleans |
| Anything else (new attributes, record types the schema lacks) | Carried as the provider has it on foreign records; a record with an attribute outside the schema cannot be adopted |

Nothing is carried through untyped on owned records: an opaque value Tenko writes back without understanding it is a value it cannot preview.

**DNSSEC at the provider.** The provider signs the zone itself when the owner turns DNSSEC on in its dashboard, and publishes a DS for the owner to place at the registrar. Tenko neither signs nor touches DNSKEY, DS or the provider's DNSSEC setting; its token cannot. What Tenko does: the read shows whether the zone is signed by asking DNS itself (the DS at the parent and the DNSKEY at the provider's servers, through Tenko's resolver), not the provider's API (a DNSSEC API endpoint exists according to the API reference's structure, unconfirmed). Under Hardened, an unsigned public zone is a finding (TGL-13 asks for signing of zones served externally). The split horizon adds one caveat, shown as a warning on the comparison page: inside, the internal zone answers unsigned for the same name; a client that validates on its own against the public chain of trust sees those answers as bogus. Tenko's resolver answers its own zones authoritatively and is not affected.

### 2.6 Guards, confirmation and the write scope

**Write scope.** A public zone writes to the whole zone or only below a subtree (for example `lab.example.test`); a plan with a change outside the scope is refused by the host. The live test uses a subtree first (section 9.2).

**Leak guards (PD-Q7), refused by the host:**

- owner names of the AD locator: `_msdcs`, `_sites`, `_kerberos`, `_kpasswd`, `_ldap`, `_gc`, `DomainDnsZones`, `ForestDnsZones` at any depth, and `_tcp` and `_udp` names whose service label is one of those;
- A and AAAA data that is not a global unicast address: RFC 1918, RFC 6598, loopback, link-local, unique local (`fc00::/7`), and any address inside a network of IPAM intent that is not marked public (proposed: a prefix flag `public`);
- a name copied from the internal zone in bulk: copying is one name at a time, by a person.

Lab allows the address guard to be switched off per zone; no profile allows a locator name. The documentation ranges (RFC 5737, RFC 3849) count as global for these checks only under Lab and in tests, so that the fixtures can use them.

**Confirmation.** A plan that only creates records is applied by `dns.write` (a token may do it). A plan that replaces or removes a record, adopts, or changes `proxied` needs an interactive session (`tenko_auth::roles::interactive_only`) with the step-up of the profile: none beyond the session on Home, a sign-in within five minutes on Standard, a passkey or hardware key within five minutes on Hardened (the TGL-24 ladder, proposed as its use here). The address rule of section 2.10 is the one exception, by a decision taken once (PD-Q9).

### 2.7 The comparison and the split horizon's practical problems (PD-Q6)

The comparison view joins the internal zone (all scopes, the default first) and the public zone's intent and observation by owner name and type:

| Kind | Meaning | Shown as |
|---|---|---|
| `internal_only` | The name exists only inside | Neutral; with a warning when it is a public-looking name (a `www`, a `mail`, an MX target) that internal clients probably expect to resolve like outside |
| `public_only` | The name exists only at the provider | **Warning**: internal clients get NXDOMAIN from Tenko, because the internal zone answers for the whole name space. Action: "Copy inside" |
| `same` | Both sides hold the same data | Neutral |
| `different` | Both sides hold the name with other data | Neutral when intended (the split), with "Mark as intended" to quiet it; else a warning |
| `leak` | A public record matches a leak guard (written by someone else at the provider) | **Error**, with the record's origin (foreign or owned) |

**Internal copies.** "Copy inside" creates an internal RRset in the internal zone with a new origin `public` (proposed; PD-Q6), linked to the public record: same data by default, or an internal value (the internal address of a web server, so that inside clients do not hairpin through the router). The link keeps the copy in step when the public record's data changes, unless it has its own value. A proxied public record copies its origin content and says so. A person may replace the copy (it then becomes `manual`, as for `ipam` RRsets). Internal names are never copied outward automatically.

**The UI** (proposed, at `/dns/public` and a tab on the internal zone):

- the zone page's header shows the provider, the instance's health, the last read, the write scope, the drift mode, DNSSEC as seen from outside, and a banner "Public zone at Cloudflare with the same name" on the internal zone's page with a link to the comparison;
- **Records**: owned and foreign records in one table with a badge each (owned, adopted, address rule, foreign, drift), the proxy as an orange or gray cloud icon with a text label, filters by badge and type, "Adopt" on foreign rows;
- **Compare**: the table above, grouped by kind, warnings first, with "Copy inside" and "Mark as intended";
- **Changes**: the pending plan with the preview, "Dry run", "Apply" (with the confirmation it needs), and the history of jobs;
- **Address**: the sources, the current address and its age, the rules and their records;
- **Settings**: the connector, the write scope, the drift mode, the marker text.

### 2.8 The provider token

The operator creates a token in the provider's dashboard with one permission, Zone / DNS / Edit, limited to the one zone (the dashboard offers "Edit zone DNS" as a template and lets the resources be one specific zone); the first token of the live test is Zone / DNS / Read only. Two optional limits of the provider are recommended in the documentation: a client IP address filter (the site's public addresses, so a stolen token is useless elsewhere) and an expiration (within TGL-05's maximum, so 30 days under Hardened). The token is an operator secret (`kind: token`, purpose tag `api_token`), stored and referenced as for every connector ([secrets.md](../secrets.md) section 6): an administrator sets the reference, every injection is audited, the plugin keeps nothing. The plugin's `Check` calls the provider's token verification route (`GET /client/v4/user/tokens/verify`) and reports `active` or the reason, and reads the zone to prove the permission. A finding `public_dns.token_expiring` follows the provider's expiration when the verification answer carries it (unconfirmed that it does).

### 2.9 Bounds, rate and backoff

What the provider sends is untrusted input (CONTRIBUTING rule 3, [plugins.md](../plugins.md) section 12):

- at most 10,000 records per zone (the paid plans' limit is 3,500; Free zones created since 2024-09-01 have 200, older ones 1,000), at most 100 pages per read, at most 8 MiB per page body, at most 1,024 bytes per text the host accepts, owner names parsed as `DnsName`, data parsed per type into `RecordData`; a record that does not parse is reported as unreadable and blocks no other record, but a plan touching its name is refused;
- strict decoding of the answers the host bases decisions on (the plan's read-back, the receipt), lenient for the list (one bad record does not discard the read), as [plugins.md](../plugins.md) section 6 does for topology and inventory;
- no redirects, no proxies from the environment, system roots only;
- a fuzz target `connect_cloudflare_answers` over the list, plan and batch answers.

**Rate.** The provider allows 1,200 requests per five minutes per user across dashboard, API keys and tokens, and blocks for five minutes after a 429; its answers carry `Ratelimit` and `Ratelimit-Policy`, and `retry-after` when exceeded. The plugin reports a 429 as `connect.rate_limited` with `tenko-retry-after-ms`; the host then makes no call to that instance until the delay passed (at least 5 minutes when the header is missing), and its own budget is at most 120 requests per five minutes per instance (a tenth of the provider's, so the owner's dashboard and an ACME client keep their share). A scheduled read every 15 minutes (proposed default; 5 to 1,440) costs one to a few requests; a write costs a plan read, one batch and a verify read. Batches hold at most 200 changes on Free and 3,500 on paid plans; a larger plan is split into batches and each is its own job step with its own verify.

### 2.10 The public address (PD-Q8, PD-Q9)

**Sources, in the order the follower trusts them (proposed):**

1. **A push from the router.** Many routers can call a dynamic-DNS URL when their WAN address changes. Tenko offers `PUT /api/v1/public-dns/address-sources/{id}` with a token whose only scope is `address:<id>` (the mirror token's pattern of ADR 0033: no other operation, no read, TLS required, at most one push per 10 s). The body is the address; the source records it with the time and the client address. Tenko never calls the router.
2. **Manual**: an operator sets the address.
3. **Read from a connector** that knows the WAN address. None does today (section 1.4).
4. **A lookup service**, only as an explicit setting with the URL the operator names (for example the provider's own trace endpoint or a self-hosted echo service), off by default, refused under Hardened. It answers with Tenko's outbound address, which is the site's public address only when Tenko leaves through the same WAN; the setting says so.

A new address is accepted only when it is a global unicast address of the source's family, different from the current one, and stable for two observations or 60 s (a flapping router changes nothing); each change is audited (`public_dns.address.change`) and announced on the events stream.

**Rules.** A rule names a source and a list of owned A or AAAA records at the provider (and optionally their internal copies, usually not: inside, the names point at internal addresses). When the source's address changes, the follower plans the change of exactly those records' data, nothing else. Under the mode `automatic` (PD-Q9) the plan is applied without a person, with the guards of section 2.6, at most once a minute, and a finding when it fails; under `confirm` it waits as a pending plan with a notification. Creating or widening a rule is itself confirmed with a preview of the records it will follow; that confirmation is the person's consent to the later automatic replacements.

### 2.11 Security, in the owner's order

**What a compromised Tenko can do to the public zone.** Everything the token allows: change, add and delete any record of that one zone, foreign records included. The ownership rule is Tenko's own policy and protects nothing once Tenko is the attacker. The serious case is not defacement but **certificate issuance**: with the zone's records, an attacker can answer an ACME DNS-01 challenge (`_acme-challenge` TXT) or point a name at itself for HTTP-01, and obtain a publicly trusted certificate for names of `example.test`, and redirect mail (MX). The bounds:

- **the token's scope** is the real boundary: one zone, DNS records only; no account settings, no other zones, no registrar, no DNSSEC switch (the provider has no per-name permission, unconfirmed, so a token cannot be narrowed further);
- **the client IP filter** makes a token copied out of a backup useless off the site;
- **CAA with `accounturi`** (RFC 8657) at the provider, set by the owner and kept foreign (Tenko never writes CAA unless the owner adopts it), limits issuance to the owner's ACME account; a compromised Tenko could still rewrite it, so this raises the bar rather than closing it, and Certificate Transparency monitoring of the domain is the detection (a recommendation to the owner, not built here);
- **the plugin process** (ADR 0012) holds the token only during a call and keeps nothing; it runs as the service account, so it is not a boundary against a compromised Tenko, and under ADR 0032 it would be one against a compromised plugin only;
- **ADR 0023** is untouched: nothing in this slice needs root, adds a capability or address family (HTTPS outbound exists for HIBP and the update check), or runs anything the service account wrote with more privilege.

**What a malicious or compromised provider answer can do to Tenko.** It reaches a memory-safe plugin with bounded, strictly typed decoding and a fuzz target (section 2.9), whose output the host validates again. Its worst plausible effects: a wrong diff (a plan to recreate records that exist, which the preview shows and the verify step catches), a denial of service of the public zone's features (bounded by the page and size limits), or lies about the zone (it is the provider's zone; Tenko cannot know better). It never becomes internal DNS data: the copy inside is per name, by a person, from the intent, never from the observation.

**Preview, confirmation, audit, rate**: sections 2.4, 2.6 and 2.9. **The Hardened profile** (PD-Q11, proposed): the plugin allowed; the token with a client IP filter and an expiration of at most 30 days (a finding when the verification shows neither, unconfirmed whether it can); every replacing or removing plan with a passkey step-up; the address rule in mode `confirm` only; no lookup service; an unsigned public zone a finding; writes off until an administrator turns them on.

## 3. Contracts and shared files (WP15.0)

### 3.1 Types (`tenko-core`)

`crates/tenko-core/src/public_dns.rs` (new): `PublicZone`, `PublicRecord { owner, rtype, data: RecordData, ttl: PublicTtl { Auto, Secs(u32) }, attrs: ProviderAttrs, source: PublicSource { Manual, Adopted, AddressRule(RuleId) }, provider_id: Option<ProviderRecordId>, applied: Option<AppliedState>, internal_copy: Option<CopyLink> }`, `ProviderAttrs { proxied, flatten_cname, ipv4_only, ipv6_only }` (each `Option<bool>`), `ObservedZone`, `AddressSource`, `AddressRule`, `WriteScope { Zone, Subtree(DnsName) }`, `DriftMode { Report, Restore }`, with validation and property tests. `Origin` gains `Public` (PD-Q6), which the update policy treats like `ipam` (a dynamic update replaces it only when `may_replace` says so).

### 3.2 Protocol

`crates/tenko-connect/proto/tenko/connect/v1/dns_provider.proto` (new): the service of section 2.2, the capability `dns_provider` in `Capability`, the conversions in `convert.rs`, the SDK service wrapper in `sdk/services.rs`, the host calls in `host/client.rs` and `host/service/calls.rs`, the conformance check `capability.dns_provider` (a `ListZone` and a `Plan` of a harmless change are read; nothing is applied). Within protocol version 1.

### 3.3 Store, API, CLI, codes

- The namespace `public_dns` with its four tables, and its absence from every role subset; whether it needs data format 7 is WP15.0's first decision (R151).
- Routes under `/api/v1/public-dns/`: zones (CRUD), records (CRUD on intent), `read` (a read now), `plan` (dry run), `apply` (with the plan's id), `adopt`, `compare`, `address-sources` (CRUD and the push), `rules`. Permissions: `dns.read` reads; `dns.write` changes intent and applies create-only plans; the rest as section 2.6.
- CLI: `tenko dns public zone|record|read|plan|apply|adopt|compare|address`.
- Codes `public_dns.*` (among them `public_dns.foreign`, `public_dns.scope`, `public_dns.leak.locator`, `public_dns.leak.address`, `public_dns.confirm_required`, `public_dns.stale_plan`); audit actions `public_dns.zone.*`, `public_dns.record.change`, `public_dns.record.adopt`, `public_dns.address.change`, `public_dns.address.push`; findings `public_dns.drift.*`, `public_dns.leak`, `public_dns.unsigned`, `public_dns.token_expiring`, `public_dns.read_failed`; metric families `tenko_public_dns_*` (reads, writes, rate-limit waits, records by badge).

### 3.4 Shared fixtures

`crates/tenko-connect-cloudflare/tests/fixtures/`: recorded answers of the list (three pages), the batch, the verification, a 429, an error envelope, with `example.test`, `203.0.113.0/24`, `2001:db8::/32` and synthetic ids only; the internal fixture zone `example.test` with AD locator records for the comparison tests. No recording is ever made against the owner's zone into the repository.

## 4. Work packages

Every package below touches `crates/tenko-core/src/public_dns.rs`, `crates/tenko-connect/proto/**` and the host's provider calls, `crates/tenko-connect-cloudflare/**`, `crates/tenko-dns/src/public/**` (the service; the `dns` role never loads it), `crates/tenko-api/src/routes/public_dns*`, `crates/tenko/src/cli/dns_public*`, `ui/src/dns/public/**`, and the documents of section 10; one package owns each file.

#### WP15.0 The contracts and the ADR (3 builder-days)

- **Requirements:** CONN-22, CONN-19.
- **Owns:** section 3 in code: the types with property tests, the protocol file and its conversions, the capability, the tables and the subset test, the route stubs answering 501, codes, audit actions, findings, metric families, the UI route stubs; the fixtures of section 3.4 (with WP15.1); the data format decision; the ADR (proposed 0035) as Proposed.
- **Depends on:** the owner's decisions PD-Q1 to PD-Q3 and PD-Q5.
- **Acceptance:** the workspace builds; the protocol round-trips through `convert.rs`; the subset test of E82; the trace regenerated.

#### WP15.1 The Cloudflare plugin (6 builder-days)

- **Requirements:** CONN-19, CONN-20, CONN-22.
- **Owns:** `crates/tenko-connect-cloudflare/**` (manifest, settings schema, the mapping of every supported type and attribute, `ListZone`, `Plan`, `Apply` through the batch endpoint, `Revert`, `Check` with the token verification, the mock server and its tests), the bundled entry in `crates/tenko/src/plugin/bundled.rs` (with the lead), `fuzz/fuzz_targets/connect_cloudflare_answers.rs`, the plugin's section of [connectors.md](../connectors.md).
- **Depends on:** WP15.0.
- **Content:** before code, the builder re-reads the provider's pages of section 11 and resolves every (unconfirmed) mark it relies on, recording the answer in the crate's README.
- **Acceptance:** E81.

#### WP15.2 The host: ownership, plans, guards and jobs (8 builder-days)

- **Requirements:** CONN-08, CONN-22, IPAM-15 to IPAM-17.
- **Owns:** `crates/tenko-dns/src/public/**` (the service, the ledger, the planner, adoption, drift, the guards, the write scope, the confirmation rule), the job steps and their rollback, the rate budget in the host, `crates/tenko-api/src/routes/public_dns*` (all but compare and address), the CLI's `dns public` except `compare` and `address`.
- **Depends on:** WP15.0; WP15.1 for the end-to-end tests (the planner is tested against the fixture observation alone).
- **Acceptance:** E82, E83, E84; the route tests of [api/README.md](../api/README.md).

#### WP15.3 The comparison and the internal copies (4 builder-days)

- **Requirements:** CONN-22, DNS-20 (read), IPAM-21 (beside it).
- **Owns:** the comparison view and its route and command, the `Public` origin's rules in the zone service and `update/policy.rs`, the copy link and its follower, [dns.md](../dns.md) sections 1 and 13.4 (the origin) and a new section on public zones.
- **Depends on:** WP15.2.
- **Acceptance:** E85.

#### WP15.4 The address follower (4 builder-days)

- **Requirements:** CONN-22, IAM-10.
- **Owns:** the address sources, the push route and its token scope in `tenko-auth`, the rules, their jobs and the stability check, the optional lookup source, the `address` commands.
- **Depends on:** WP15.2.
- **Acceptance:** E86; a test that the lookup source is refused under Hardened.

#### WP15.5 The UI, the security rows and the live test (6 builder-days, plus the owner's hour)

- **Requirements:** CONN-22.
- **Owns:** `ui/src/dns/public/**` (section 2.7's pages) with Playwright tests over the mock; the rows below in `deploy/security/`; `bench/public-dns/results/<date>-live.md` (no real names); `docs/plans/public-dns-exit.md`.
- **Depends on:** WP15.2 to WP15.4.
- **The rows:**

  | Row | What is checked |
  |---|---|
  | `public_dns.foreign` | No API path, CLI command or job changes or removes a foreign record (a plan naming one is refused) |
  | `public_dns.leak` | A locator name and a private address are refused through the API, the CLI and the copy path |
  | `public_dns.confirm` | A replacing or removing plan with a token, and without the profile's step-up, is refused |
  | `public_dns.address_token` | The address token reaches its push and nothing else; plain HTTP refused |
  | `public_dns.secret` | The token never appears in a log line, an audit record, an answer, the environment of the plugin or a command line (grep over the round's captures) |
  | `public_dns.hostile_answers` | The mock answers with oversized bodies, too many pages, redirects and malformed records: the host refuses each and stays up |

- **Acceptance:** E87; E88 (owner-run).

Total: 31 builder-days; the critical path is WP15.0, WP15.2, WP15.3 or WP15.4, WP15.5 (21 days).

## 5. Order, measurements and exit checks

### 5.1 Order

WP15.0 first. Then WP15.1 and WP15.2 in parallel. Then WP15.3 and WP15.4 in parallel. WP15.5's UI follows the routes; the rows and the live test come last. The slice touches none of the files of Slice 14 or Slice 13 and can take a builder slot when one is free; CONN-22 is no condition of 0.1.0 (ROADMAP), so it never displaces the Kerberos line or the takeover (PD-Q12). The live test needs the internal zone in Tenko only for the comparison step; a secondary copy by transfer from the controllers serves as well as the primary.

### 5.2 Measurements

| # | Measurement | Threshold | Package |
|---|---|---|---|
| M71 | A read of a mock zone of 3,500 records (the paid plans' limit), plan and comparison against an internal zone of 5,000 RRsets | At most 4 provider requests; under 2 s end to end on the node of M21; resident memory growth under 20 MiB during the read | WP15.2 |
| M72 | From an address push to a verified apply of a rule of 5 records, against the mock | Under 10 s plus the 60 s stability window; one batch request | WP15.4 |

## 6. Owner decisions

Each question lists its options, the trade-offs in the owner's order (security, performance, usability, features) and one recommendation.

**Decided by the owner (2026-11-10): every question as recommended.** PD-Q6 (the public names that internal clients need) and PD-Q8 (the source of the public address) stand as recommended until the owner returns to them; the owner may replace either with another solution before its package starts.

**PD-Q1. How is a public zone represented beside an internal zone of the same name?**
- Options: (a) a namespace of its own (`public_dns.*`), never fed to the `dns` role, joined to the internal zone by name only in a read-only comparison; (b) a new `ZoneKind::External` row in `dns.zones`, with the uniqueness of zone names relaxed per kind; (c) a scope `external` of the internal zone, synchronized to the provider.
- Trade-offs: (b) puts public data in the tables the engine is fed and relies on a filter to keep it out of answers, and changes a uniqueness rule that the views, the transfers and the API assume; (c) merges the two in one object, against CONN-22's text, shares one SOA, NS set and DNSSEC policy that the provider does not have, and one wrong view would serve the AD zone's records outward or the public ones inward; (a) separates them by construction, at the cost of a second, smaller record model and a namespace (probably data format 7).
- **Recommendation: (a).**

**PD-Q2. Where does the provider plugin run?**
- Options: (a) a bundled plugin on the existing gRPC contract (ADR 0012), with the new `dns_provider` capability; (b) wait for ADR 0032's managed plugins and ship it from `tenko-plugins`; (c) code inside the controller's process.
- Trade-offs: (b) gives the plugin its own transient user, so a parser flaw would not reach the vault, but none of ADR 0032 is built and its first plugins are Hyper-V and vSphere; (c) puts provider answers in the process that holds the vault keys; (a) keeps a process boundary and per-call secrets that exist today, with the plugin's process running as the service account, the risk ADR 0012 records; the boundary against a compromised Tenko is the token's scope in all three.
- **Recommendation: (a), with the plugin built so that moving it under ADR 0032 changes its entry point only.**

**PD-Q3. How is ownership recorded?**
- Options: (a) the ledger in Tenko decides, and a comment marker at the provider serves people and recovery; (b) the comment marker alone; (c) the ledger alone; (d) tags.
- Trade-offs: (b) lets anyone with console access make Tenko own, and later delete, a record by typing a comment; (c) leaves people in the dashboard without a sign that an edit will be reported, and loses ownership with a lost ledger; (d) needs a paid plan; (a) holds against a forged marker and survives a restore with a confirmation per record, at the cost of one comment per owned record (a write at adoption).
- **Recommendation: (a).**

**PD-Q4. What happens when someone edits an owned record in the provider's console?**
- Options: (a) `report`: a proposal to keep the console's value or restore the intent, nothing written without a person; (b) `restore`: the intent wins automatically for changed records, as for `ipam` RRsets; (c) the console wins automatically.
- Trade-offs: (b) can fight a person who fixes an outage in the dashboard at night; (c) makes Tenko's intent meaningless; (a) is slower to converge but never surprises.
- **Recommendation: (a) by default, (b) as a per-zone choice; a missing record is never re-created without a person in either mode.**

**PD-Q5. Provider attributes without a place in a plain record?**
- Options: (a) modeled as typed fields of a per-provider attribute schema (Cloudflare: `proxied`, automatic TTL, `flatten_cname`, `ipv4_only`, `ipv6_only`), anything else makes a record read-only; (b) carried through as an opaque blob; (c) refused: records with any attribute are foreign forever.
- Trade-offs: (b) writes back values nobody previewed; (c) excludes every proxied record, most of a typical Cloudflare zone; (a) previews everything it writes, at the cost of a schema per provider.
- **Recommendation: (a).**

**PD-Q6. Public names that internal clients need?**
- Options: (a) "Copy inside" per name, creating an internal RRset with a new origin `public` linked to the public record, the same value or an internal one; (b) a manual copy (origin `manual`), with a warning in the comparison; (c) only the warning.
- Trade-offs: (b) drifts the first time the public address changes; (c) leaves the problem to the owner; (a) adds an origin to the model (the update policy treats it like `ipam`).
- **Recommendation: (a).**

**PD-Q7. Names and addresses that must never leak outward?**
- Options: (a) refuse AD locator names and non-global addresses (and addresses in internal networks of intent) in every write; (b) warn and let a person proceed; (c) nothing beyond the comparison's `leak` row.
- Trade-offs: (b) and (c) let one hurried click publish the domain's structure or internal addresses, which then stay in resolver caches and passive-DNS databases; (a) may block an unusual deliberate case, for which Lab exists.
- **Recommendation: (a); a prefix flag `public` for networks of intent that do hold public addresses.**

**PD-Q8. How does Tenko learn the site's public address?**
- Options: (a) a push from the router to a route with a token scoped to that one source, plus a manual value; (b) a third-party lookup service by default; (c) read from a connector (UniFi's WAN state); (d) a combination with an order of trust.
- Trade-offs: (b) tells an outside service when Tenko asks, depends on it, and its answer is only as good as the route Tenko takes outward; (c) is not available today; (a) uses what most routers already have (a dynamic-DNS URL) and keeps Tenko from calling out.
- **Recommendation: (a) now, (c) when a connector reads the WAN address, (b) only as an explicit setting with the operator's URL, refused under Hardened.**

**PD-Q9. Does an address change reach the provider without a person?**
- Options: (a) `automatic` within a rule a person confirmed with a preview of its records, the guards applied, at most once a minute; (b) `confirm`: every change waits as a pending plan with a notification.
- Trade-offs: (b) keeps the remote-access name broken until someone reacts, often at the worst moment; (a) lets a forged push move the rule's records, bounded by the push token's scope, the global-address check, the stability window and the audit.
- **Recommendation: (a) on Home and Standard, (b) forced under Hardened.**

**PD-Q10. A hidden primary in Tenko with zone transfers to the provider instead of the API?**
- Options: (a) not planned; (b) planned as an alternative for Enterprise zones.
- Trade-offs: the provider accepts incoming transfers on its Enterprise plan only; Tenko would serve the public zone to the provider's transfer addresses over the Internet (TSIG and NOTIFY support unconfirmed), the public zone would become a zone of the engine with the risks PD-Q1 avoids, and provider attributes such as `proxied` would have no place in the transfer (unconfirmed how the provider handles proxying for secondary zones); its gain, standard protocols instead of an API, does not pay for these on the owner's plan.
- **Recommendation: (a).**

**PD-Q11. The Hardened profile's stance?**
- Options: (a) allowed with the rules of section 2.11 (filtered and expiring token, passkey step-up for replacing and removing plans, address rule in `confirm`, no lookup service, unsigned zone a finding, writes off at creation); (b) read-only under Hardened (the comparison only); (c) refused.
- Trade-offs: (c) and (b) push Hardened sites back to editing in the dashboard, where nothing is previewed or compared; (a) adds a credential with Internet-facing reach to the vault, bounded by its scope and IP filter.
- **Recommendation: (a).**

**PD-Q12. When?**
- Options: (a) after the Windows takeover's exit and the Kerberos line's WP13.4, in a free builder slot, before the real cutover if a slot allows; (b) now, beside them; (c) after 0.1.0.
- Trade-offs: (b) competes for the two-builder limit with work 0.1.0 waits for; (c) leaves the owner's split horizon unexamined during the cutover, when the AD zone moves into Tenko; (a) has the comparison ready for the cutover window at no cost to the release.
- **Recommendation: (a); WP15.0 and the plugin's read-only half can go first, since the read-only diff alone answers the owner's first question.**

## 7. Requirement rows touched

No new requirement IDs. Proposed edits, applied with the decisions:

| Row | Today | Proposed |
|---|---|---|
| CONN-22 | "... a plugin per provider (CONN-19) ... manages the records ... through its API, with a token scoped to that zone ..." | Adds: "Ownership is a ledger in Tenko with a marker comment at the provider; AD locator names and non-global addresses are never written to a public zone." |
| CONN-19 | "... capabilities ..." | Unchanged; the capability `dns_provider` is listed in [plugins.md](../plugins.md) |

ROADMAP: the Phase 4 line for CONN-22 links this plan. SECURITY-PROFILES.md: no new toggle; the Hardened rules of section 2.11 are noted under TGL-13, TGL-24 and TGL-05.

## 8. Risks

| # | Risk | Proposed resolution |
|---|---|---|
| R151 | A new namespace forces data format 7 | WP15.0 decides first; an empty migration with its fixture, as earlier formats |
| R152 | A compromised Tenko uses the token to obtain certificates or redirect mail for `example.test` | The token's one-zone scope and IP filter; CAA with `accounturi` kept foreign; Certificate Transparency monitoring recommended to the owner; the plan says plainly that ownership is no defense against this |
| R153 | The provider changes its API or its plan limits (comment length, batch size, rate limits) | The plugin's README records the read date; the mock's fixtures are versioned; a refused write is a finding, never a silent partial change (the batch is atomic) |
| R154 | A console edit and a Tenko write race | The plan's fingerprint and the re-read in `Apply`; a moved state refuses the write (`connect.verify_mismatch`) |
| R155 | Another writer of the zone (an ACME client, the provider's own features) creates and deletes records continuously | Foreign records are only listed; the comparison quiets `_acme-challenge` names by a default rule; reads are cheap |
| R156 | The internal copy hides a later public change from inside | The copy follows its link; a copy with its own value shows as `different` and intended |
| R157 | The 429 block of five minutes during an outage fix | The host's budget of a tenth of the provider's limit; reads back off first; the UI shows when the next call is allowed |
| R158 | The plugin's process runs as the service account (ADR 0012 R16): a flaw in the answer parsing reaches the vault | Memory-safe decoding, bounds, the fuzz target, the strict re-validation in the host; the move under ADR 0032 when it exists |
| R159 | A forged address push moves the remote-access name | The push token's single scope, global-address and stability checks, the audit, `confirm` under Hardened; the router keeps the token |

## 9. Owner actions and the live test

### 9.1 Owner actions

| When | Action |
|---|---|
| Before WP15.0 | Decide PD-Q1 to PD-Q12 |
| Before the live test | Note in the provider's dashboard which records exist and who writes them (an ACME client, mail settings, the provider's own features) |
| Before the live test | Decide whether the router can push its address (a dynamic-DNS URL setting) |
| After the live test | Recommended: a CAA record with `accounturi` for the owner's ACME account, and Certificate Transparency monitoring of the domain |

### 9.2 The live test, step by step

Each step names what to check before the next. Stop at any surprise; nothing below is hard to undo, but each step proves what the next one relies on.

1. **A read-only token.** In the provider's dashboard: a token with Zone / DNS / Read for the one zone, the site's public addresses as the client IP filter, an expiration in 7 days. In Tenko: the secret, the instance of `cloudflare` with `writes_enabled` off, the public zone `example.test` with the write scope `lab.example.test` (a subtree that does not exist yet). *Check:* the instance's health says the token is active; the dashboard's audit log shows no change.
2. **The first read.** Run "Read now". *Check:* the number of records and every name match the dashboard; every record is foreign; no record is unreadable; the rate counters show a few requests.
3. **The comparison.** Open Compare against the internal zone (secondary or primary). *Check:* `public_only` names are the ones internal clients cannot resolve today; no `leak` row, or each one is understood; the internal AD names appear only as `internal_only`.
4. **The edit token.** Replace the secret's value with a token with Zone / DNS / Edit for the one zone, same filter, 7 days; revoke the read token. Turn `writes_enabled` on. *Check:* health active; a dry run of an empty plan writes nothing.
5. **One record created.** Add the intent `probe.lab.example.test TXT "tenko live test"`; preview; apply. *Check:* the preview showed one create and nothing else; the dashboard shows the record with the marker comment; `dig TXT probe.lab.example.test @<one of the provider's name servers for the zone>` answers it; one audit record.
6. **Drift.** Change the record's text in the dashboard; run a read. *Check:* a `drift.changed` proposal with both values; nothing was written. Choose "restore"; preview; apply. *Check:* the dashboard shows the intended text again.
7. **One record removed.** Delete the intent; preview (it must say "removes 1 record" and ask for confirmation); apply. *Check:* the record is gone in the dashboard and in `dig`; foreign records unchanged (the dashboard's audit log shows exactly the changes of steps 5 to 7).
8. **One adoption.** Adopt one existing record the owner wants Tenko to manage (for example the remote-access name). *Check:* the preview showed only the marker comment; after apply the record answers as before; the dashboard shows the comment. If the router can push its address: create the address source and a rule for this record in mode `confirm`; push the current address. *Check:* no plan (unchanged address).
9. **The real use.** Widen the write scope to the zone; adopt what Tenko should manage; leave the rest foreign; set the token's expiration to the profile's maximum and note its renewal date.

**To undo at any point:** revoke the token in the dashboard. Records stay as they are at the provider; deleting the public zone in Tenko removes nothing there.

## 10. Documents this slice writes

| Document | Package |
|---|---|
| The ADR for public zones, the provider capability and the ownership rule (proposed 0035) | WP15.0 |
| [plugins.md](../plugins.md): the `dns_provider` capability and its methods | WP15.0 |
| [connectors.md](../connectors.md): a section on the Cloudflare plugin (token, settings, limits) | WP15.1 |
| `docs/public-dns.md`: the operator's page (the model, ownership, the comparison, the address follower, the live test of section 9.2 as a runbook) | WP15.2, WP15.3, WP15.4 |
| [dns.md](../dns.md): the `public` origin and a pointer to the public zones | WP15.3 |
| `bench/public-dns/` with M71, M72 and the live test's result | WP15.2, WP15.4, WP15.5 |
| `docs/plans/public-dns-exit.md` | WP15.5 |

**The trace.** This plan names CONN-22 and other Phase 1 to 4 rows; the lead regenerates the trace files with it (`node scripts/requirement-trace.mjs` and its `--phase` variants).

## 11. Sources

The facts about Tenko come from the code and the documents read on `fb0c8f57` (section 1.5). The provider's pages below were read on 2026-11-10; what they did not state is marked (unconfirmed) in the text and listed here:

- Record attributes (comments on every plan, 100 characters on Free and 500 on paid plans; tags on paid plans only, 20 per record, `name:value`): https://developers.cloudflare.com/dns/manage-dns-records/reference/record-attributes/
- List DNS records (`GET /zones/{zone_id}/dns_records`, filters by name, type, comment and tag, the record object, TTL 1 automatic, else 60 to 86,400, 30 on Enterprise): https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/
- Batch record changes (`POST /zones/{zone_id}/dns_records/batch`; deletes, patches, puts, posts in that order; one transaction; 200 changes on Free, 3,500 on paid plans): https://developers.cloudflare.com/dns/manage-dns-records/how-to/batch-record-changes/ and https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/batch/
- API limits (1,200 requests per five minutes per user, 429 and a five-minute block, `Ratelimit`, `Ratelimit-Policy`, `retry-after`): https://developers.cloudflare.com/fundamentals/api/reference/limits/
- Creating a token (zone-scoped permissions, client IP filtering, expiration, `GET /client/v4/user/tokens/verify`): https://developers.cloudflare.com/fundamentals/api/get-started/create-token/
- Records quota (Free 200 or 1,000 by creation date, Pro and Business 3,500): https://developers.cloudflare.com/dns/manage-dns-records/
- Proxy status (A, AAAA, CNAME only; answers with the provider's anycast addresses): https://developers.cloudflare.com/dns/proxy-status/
- CNAME flattening (automatic at the apex on every plan; all or per-record flattening on paid plans): https://developers.cloudflare.com/dns/cname-flattening/set-up-cname-flattening/
- DNSSEC (enabled in the dashboard; the DS to place at the registrar; algorithm 13 preferred): https://developers.cloudflare.com/dns/dnssec/
- Secondary DNS (Enterprise only; AXFR and IXFR): https://developers.cloudflare.com/dns/zone-setups/zone-transfers/cloudflare-as-secondary/

**Unconfirmed on 2026-11-10**, for WP15.1 to settle: the full names of the token permission groups beyond "Edit zone DNS" and "Zone DNS Read"; that no permission narrower than one zone's DNS exists (per name or per type); whether the token verification answer carries the expiration and the IP filter; an API route for the zone's DNSSEC state; how the API reveals the zone's plan (for the Free-plan refusal of `flatten_cname`); the schema of `puts` and the response of the batch endpoint; the effective page size of the list (the reference states a maximum of 5,000,000 per page, which the plugin does not rely on); whether the five-minute block after a 429 can end earlier; whether records can be written on a zone that is not yet active; TSIG and NOTIFY for incoming transfers and how proxying works for secondary zones.

Specifications: RFC 1035 (DNS), RFC 8659 (CAA), RFC 8657 (CAA `accounturi` and `validationmethods`), RFC 8555 (ACME), RFC 1918 and RFC 6598 (private and shared address space), RFC 4193 (unique local IPv6 addresses), RFC 5737 and RFC 3849 (documentation addresses).

Project documents: [plugins.md](../plugins.md), [connectors.md](../connectors.md), [reconciliation.md](../reconciliation.md), [secrets.md](../secrets.md), [dns.md](../dns.md) sections 1, 2, 11 and 13, ADR 0005, ADR 0006, ADR 0012, ADR 0017, ADR 0023, ADR 0032, ADR 0033, [windows-takeover-plan.md](windows-takeover-plan.md).
