# The OpenAPI document

`openapi.json` is generated from the `#[utoipa::path]` annotations in `crates/tenko-api/src/routes`, never edited by hand. Regenerate it with `cargo run -p tenko -- openapi > docs/api/openapi.json` and the UI types with `npm run api:types` in `ui/`; CI fails when the committed document differs from the generated one.

## Authentication of an operation

Every operation states what it needs to be called, so a reader or a client generator knows where a session or a token is required. The document's default (`security` at the top level, declared on `ApiDoc` in `crates/tenko-api/src/routes/mod.rs`) is a session cookie (`session`) or a bearer token (`token`). An operation deviates from it only through its own `security(...)`:

| The handler | Annotation | Meaning |
|---|---|---|
| takes `Ctx`, and a personal token passes its authorization | none | a session or a token |
| takes `Ctx`, and a token is always refused: it authorizes an action that `tenko_auth::roles::interactive_only` keeps from tokens (administering, revealing, changing users, settings, the system, tokens, sessions, secrets or DNS keys), or it needs the caller's own session (`AuthService::current`, a fresh sign-in) | `security(("session" = []))` | a session only |
| takes no `Ctx` (setup, the sign-in ceremonies, node enrollment, liveness and readiness, the CA root, the language list and packs, this document) | `security()` | public |

`POST /auth/password/check` is the one operation that is public before setup and needs a session or a token after it; it declares `security((), ("session" = []), ("token" = []))`.

When you add a route, decide from the handler, not from its path. Three tests in `crates/tenko-api/src/routes/tests.rs` hold the document to the server: `every_operation_declares_its_security_requirement` names every public operation, so a new one must be added there on purpose; `an_anonymous_request_is_refused_on_every_operation_but_the_public_ones` calls each operation without credentials; and `a_personal_token_is_refused_exactly_on_the_session_only_operations_without_a_body` calls each operation that takes no request body with an administrator's token.

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

## Through a reverse proxy

With the TLS mode `reverse_proxy` ([certificates.md](../certificates.md) section 7) the server believes forwarded headers only from `[tls] trusted_proxies`, and reads `X-Forwarded-Proto` and `X-Forwarded-Host` from their **last** value: the one the nearest proxy set or appended. A proxy should set these headers, not append to what the client sent. `X-Forwarded-For` is walked from the right over the trusted proxies. A proxy that sends no `X-Forwarded-Proto` (and no PROXY protocol version 2 SSL record) leaves the scheme unstated: the API assumes HTTPS for its security headers and the CSRF origin check, but `POST /nodes/enroll` refuses it outside the Lab profile with 403 `cluster.enrollment.scheme_unknown` (the token is kept).
