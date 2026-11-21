# The OpenAPI document

`openapi.json` is generated from the `#[utoipa::path]` annotations in `crates/tenko-api/src/routes`, never edited by hand. Regenerate it with `cargo run -p tenko -- openapi > docs/api/openapi.json` and the UI types with `npm run api:types` in `ui/`; CI fails when the committed document differs from the generated one.

## Authentication of an operation

Every operation states what it needs to be called, so a reader or a client generator knows where a session or a token is required. The document's default (`security` at the top level, declared on `ApiDoc` in `crates/tenko-api/src/routes/mod.rs`) is a session cookie (`session`) or a bearer token (`token`). An operation deviates from it only through its own `security(...)`:

| The handler | Annotation | Meaning |
|---|---|---|
| takes `Ctx`, and a personal token passes its authorization | none | a session or a token |
| takes `Ctx`, and a token is always refused: it authorizes an action that `tenko_auth::roles::interactive_only` keeps from tokens (administering, revealing, changing users, settings, the system, tokens, sessions, secrets or DNS keys), or it needs the caller's own session (`AuthService::current`, a fresh sign-in) | `security(("session" = []))` | a session only |
| takes no `Ctx` (setup, the sign-in ceremonies, node and integration enrollment, liveness and readiness, the CA root and the integration listener's root, the language list and packs, this document) | `security()` | public |
| takes no `Ctx`, and the client certificate of the integration listener is the credential (the renewal of that certificate, ADR 0035) | `security(("certificate" = []))` | the integration certificate (`mutualTLS`); refused on the API listener |

`POST /auth/password/check` is the one operation that is public before setup and needs a session or a token after it; it declares `security((), ("session" = []), ("token" = []))`.

When you add a route, decide from the handler, not from its path. Three tests in `crates/tenko-api/src/routes/tests.rs` hold the document to the server: `every_operation_declares_its_security_requirement` names every public operation, so a new one must be added there on purpose; `an_anonymous_request_is_refused_on_every_operation_but_the_public_ones` calls each operation without credentials; and `a_personal_token_is_refused_exactly_on_the_session_only_operations_without_a_body` calls each operation that takes no request body with an administrator's token.

### A delegated session

A takeover script (ADR 0038) acts through a delegated session: a session of the administrator who approved its request (`POST /auth/approvals`, `.../lookup`, `.../{id}/approve`, `.../{id}/collect`), presented as `Authorization: Bearer tnka_…` from the request's address only. The document does not mark it as a scheme of its own, because it is not one: it is a session that reaches only the (method, route) pairs of `tenko_auth::delegation::TAKEOVER`, each with a condition, and the authentication layer answers every other operation 403 `auth.delegation.refused` before its handler runs. A listed handler checks its body against the run's plan as well. A route is outside the list until it is added there on purpose with its plan check; `a_delegated_session_reaches_its_allow_list_and_nothing_else` in `crates/tenko-api/src/routes/tests.rs` calls every operation of the document with a delegated session and fails on any other answer.

### The takeover script's approval: the contract

What a takeover script and Tenko must agree on byte for byte. The test vector `crates/tenko-auth/tests/fixtures/approval-code.json` gives every input and intermediate value of the code and the collect; the OpenAPI document gives the schemas. Paths are below `/api/v1`. Octet strings in base64url are RFC 4648 section 5 without padding. Every refusal is `application/problem+json` with `code`, `status` and `params`.

| Method and path | Credential | Request body | Answer |
|---|---|---|---|
| `POST /auth/approvals` | none | the request below, at most 65,536 octets | 201 `{"id": "<uuid>", "nonce": "<base64url of 32 octets>"}` |
| `POST /auth/approvals/lookup` | an administrator's session cookie, signed in within 5 minutes | `{"code": "<typed code>"}` | 200 the approval: `id`, `purpose`, `plan`, `reported` (`machine`, `user`, `version`), `source`, `created_at`, `expires_at`, `state` |
| `POST /auth/approvals/{id}/approve` | the same | `{"code": "<typed code>"}` | 200 the approval, `state` `approved` |
| `POST /auth/approvals/{id}/deny` | an administrator's session cookie | none | 204; a waiting request is denied, an approval not collected yet is withdrawn |
| `POST /auth/approvals/clear` | an administrator's session cookie, signed in within 5 minutes | none, or `{"source": "<address>"}` | 200 `{"denied": <count>}`: every waiting or uncollected approval, or those of that address's source (the address, or its IPv6 /64) |
| `POST /auth/approvals/{id}/collect` | none; the request's source address | `{"signature": "<base64url of 64 octets>"}`, at most 1,024 octets | 200 `{"secret": "tnka_<43 characters>", "session": "<uuid>", "delegation": "<uuid>", "expires_at": "<RFC 3339>", "idle_secs": 900}`, once, with `Cache-Control: no-store` |

**The request.** `Content-Type: application/json`, one object with exactly the fields `purpose` (`"windows-takeover"`), `plan`, `key` and `client`; an unknown or repeated field is refused. `key` is the base64url of the 65-octet uncompressed P-256 point (`0x04 || X || Y`). `client` is `{"machine": <a host label, at most 63 ASCII letters, digits and hyphens>, "user": <a NetBIOS domain of at most 15 such characters, "\", an account name of 1 to 20 characters (spaces and letters of any script allowed) without a control or formatting character, a space at either end, or any of " / \ [ ] : ; | = , + * ? < > &>, "version": <1 to 32 ASCII letters, digits, ".", "+" or "-">}`. `plan` is `domain`, `forest_root`, `controllers` (`[{"name", "addresses", "pdc"}]`, 1 to 16, exactly one `pdc: true`, 1 to 8 addresses each), `zones` (1 to 64: the domain, `_msdcs.<forest_root>`, and reverse zones on octet boundaries that cover a scope or lie inside one), `forwarders` (`[{"zone", "servers"}]`, at most 64, 1 to 8 servers each; `"."` for the server forwarders), `dhcp_servers` (`[{"name", "address"}]`, at most 32), `relationship` (optional, 1 to 64 printable ASCII characters), `scopes` (at most 256 IPv4 networks without host bits, `"192.0.2.0/24"`), `mirror_host` (`{"name", "address"}`, not a controller by name or address), `node_name` (one host label, not `wpad`, `isatap`, `localhost` or the first label of a controller, a DHCP server or the mirror host) and `operations` (one or more of `mirrors`, `secondary_zones`, `forwarding_rules`, `update_policy`, `kerberos_adopt`, `prepare`, `flip`, `takeover`, `release`, each once), and, when zones take secure updates, `kerberos`, there exactly when `operations` lists `kerberos_adopt`: `{"realm": <the domain in upper case>, "account": <node_name and "$", node_name then at most 15 characters>, "spns": <1 to 4 of "DNS/<node_name>" or "DNS/<node_name>.<domain>", each once>}`. Names are DNS names, compared and hashed in lower case without a trailing dot; nothing is listed twice.

**The code.** `code = Crockford-base32(first 80 bits of SHA-256(C || 0x00 || L || D || R || H || K || I))`, where `C` is the 26 ASCII octets `tenko-takeover-approval-v1`, `D` the plan's domain in canonical form (lower-case ASCII, no trailing dot) and `L` its length in one octet, `R` the 32-octet SHA-256 of the DER of the self-signed root of the TLS chain the script built by signature verification, `H` the 32-octet SHA-256 of the request body exactly as sent (every octet of the HTTP body), `K` the 65 octets of the key and `I` the 16 octets of the approval id in RFC 9562 order. The 80 bits are written as 16 characters of `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, five bits each, most significant first, in four groups of four joined by `-`: `G5E3-J50W-RFA4-J4B6`. Tenko computes it over the SHA-256 of the internal authority's root; in another TLS mode the request, the lookup and the approval answer 404 `tls.no_internal_ca`.

**Typing the code.** Tenko drops spaces and `-`, reads the rest in upper case with `O` as `0` and `I` and `L` as `1`, and then needs exactly 16 characters of the alphabet; input longer than 64 octets is refused. It compares the result in constant time with the code of every pending approval.

**The collect.** The signature is ECDSA P-256 with SHA-256 over `M = C' || 0x00 || I || N`, where `C'` is the 25 ASCII octets `tenko-takeover-collect-v1`, `I` the 16 octets of the id and `N` the 32 octets of the nonce, written as `r || s` of 32 octets each (IEEE P1363, what `ECDsa.SignData` writes). Only a request from the approval request's source address is answered.

**The delegated session.** `Authorization: Bearer tnka_…`, from the approval request's source address only; never a cookie. It lives until `expires_at` (at most eight hours after the approval) and ends after `idle_secs` without a request, both on Tenko's clock; `POST /auth/logout` ends it. It reaches only the operations of `tenko_auth::delegation::TAKEOVER`; every other operation answers 403 `auth.delegation.refused`, and from another address it is 401 `auth.unauthenticated` (a public operation answers it as it answers anybody).

| Reached by a delegated session | Condition |
|---|---|
| `GET /health`, `GET /system/ca-root` | always |
| `POST /auth/logout` | always: its own end |
| `POST /migrate/mirrors` | within five minutes of the approval, on Tenko's clock, for a DHCP server of the plan: `name` that server's name, `kind` `windows-dhcp`, `source_prefixes` exactly the mirror host's address as a /32 (or /128) |

Refused for a delegated session until the plan checks exist: a mirror's `GET`, `PATCH`, `DELETE` and snapshot; a scope's `prepare`, `takeover` and `revert`; `GET /jobs/{id}` and the completion of a job's step; the zone list, a zone's creation, `GET`, `PATCH`, `DELETE`, `transfer`, records, `flip` and `release`; `POST /dns/forwarders`; `POST /dns/kerberos/adopt`; and the run's own routes.

**Codes.**

| Code | Status | When |
|---|---|---|
| `auth.approval.plan` | 422 | the request does not parse, or the plan is outside the limits; `params.reason` |
| `auth.approval.limit` | 429 | `params.limit`: `spacing` (one request per address every 10 s), `source` (two pending per IPv4 address or IPv6 /64), `pending` (64 in all), `lookups` (five wrong codes from one browser session in ten minutes lock it for ten), `domain` (another approval of the domain is approved or has a live session) |
| `auth.approval.code` | 403 | the typed code matches no pending approval |
| `auth.approval.ambiguous` | 409 | the typed code matches more than one |
| `auth.approval.not_found` | 404 | no such approval, or a collect from another address |
| `auth.approval.signature` | 403 | the collect's signature does not verify, or its body is not one signature of 64 octets |
| `auth.approval.pending` | 409 | the collect came before the person decided; ask again |
| `auth.approval.denied` | 403 | the person denied it |
| `auth.approval.consumed` | 409 | approved or collected before |
| `auth.approval.expired` | 410 | ten minutes after the request on Tenko's clock, or later than the delegated session could live |
| `auth.delegation.refused` | 403 | a delegated session outside its allow-list, behind a recent sign-in, or with a body outside its plan |
| `tls.no_internal_ca` | 404 | the API listener does not serve the internal authority's root |
| `sys.body_too_large` | 413 | a request body above 64 KiB, a collect body above 1 KiB |

## Retries and the Idempotency-Key

A `POST` that carries an `Idempotency-Key` header (a key the client chooses) can be retried safely: the server keeps the first successful answer for 24 hours and answers a retry with the same key and the same request (method, path and query, content type and body) with that answer and `Idempotency-Replayed: true`. Keys belong to the principal: a session user and each of the user's personal tokens have their own. The middleware is `crates/tenko-api/src/middleware/idempotency.rs`; its module documentation is the reference.

| Answer | When |
|---|---|
| The first answer, `Idempotency-Replayed: true` | A retry of a performed request, and the principal still passes what the first request had to pass |
| 409 `sys.idempotency_in_flight`, `Retry-After: 1` | The first request with the key is still running |
| 422 `sys.idempotency_mismatch` | The key was used for a different request (a retry is read no further than the length of the first request's body) |
| 409 `sys.idempotency_not_replayable` | The request was performed, and its answer is not kept or may not be replayed: it carried a secret, the request body carried one, the answer was too large to keep, the first request made no authorization check that a replay could run again, the principal's session, roles, authentication strength or flags changed since, its grants on a kind the request touched changed since, or the record was written by an earlier version (for up to 24 hours after an upgrade). Do not retry with the same key: read the state, or start again with a new key |
| 401 or 403, as the route would answer | The principal no longer passes a check the first request passed: a role removed, a sign-in older than five minutes where the route needs a fresh one, a password change required. The refusal is audited as `sys.idempotency.replay` with the digest of the key |

A failed request (any status but 2xx) is not kept, so it can be retried with the same key. A request with a key is not buffered before its handler: the route's own body limit and authorization apply as without a key.

**Secrets are never kept.** An answer that carries a secret (a token, a TSIG secret, recovery codes, a TOTP seed, an enrollment or mirror token, a revealed value, a session cookie) leaves only a marker, so a retry is 409 and the handler does not run a second time. A request whose body carries a secret (a password, a passphrase, a keytab, a secret value) is never fingerprinted; its marker holds no fingerprint, so any retry under its key is 409. Which operations these are is read from this document: a request or answer body that reaches the schema `SecretString` (format `password`), a request body that is not JSON (an upload), and any `POST` the document does not list. When you add a field that holds a secret, give it that type; the test `every_field_named_like_a_secret_is_typed_or_listed` fails for a field named like a secret that is a plain string.

**Ceremonies take no part.** First-run setup, the sign-in ceremonies (`/auth/login/*`, `/auth/webauthn/login/*`), the live password check and the enrollment of a node go straight to their handler whatever the key: they are safe to repeat.

## Slow request bodies

Every operation that takes a body, on the API listener and on the integration listener, reads it against a deadline: the server waits for the body at most 30 seconds plus one second for every 8 KiB that arrived, so a body must keep up 8 KiB/s (64 kbit/s) once the first 30 seconds are spent, and a route that admits n MiB has its whole body within 30 seconds plus n times 128 seconds. Only the time the server waits for the client counts. A body that falls behind is answered 408 `sys.body_timeout` with `Connection: close`, and what arrived of it is dropped. The constants are `GRACE` and `MIN_RATE` in `crates/tenko-api/src/middleware/body_deadline.rs`; a route can be stricter (the zone file import allows ten minutes in all, 408 `sys.invalid_request`). The request head has its own limit, `[server] header_read_timeout_secs` (30 seconds), which over HTTP/1.1 also ends a connection that sits idle between requests.

## Through a reverse proxy

With the TLS mode `reverse_proxy` ([certificates.md](../certificates.md) section 7) the server believes forwarded headers only from `[tls] trusted_proxies`, and reads `X-Forwarded-Proto` and `X-Forwarded-Host` from their **last** value: the one the nearest proxy set or appended. A proxy should set these headers, not append to what the client sent. `X-Forwarded-For` is walked from the right over the trusted proxies. A proxy that sends no `X-Forwarded-Proto` (and no PROXY protocol version 2 SSL record) leaves the scheme unstated: the API assumes HTTPS for its security headers and the CSRF origin check, but `POST /nodes/enroll` refuses it outside the Lab profile with 403 `cluster.enrollment.scheme_unknown` (the token is kept).
