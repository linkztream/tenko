# The OpenAPI document

`openapi.json` is generated from the `#[utoipa::path]` annotations in `crates/tenko-api/src/routes`, never edited by hand. Regenerate it with `cargo run -p tenko -- openapi > docs/api/openapi.json` and the UI types with `npm run api:types` in `ui/`; CI fails when the committed document differs from the generated one.

## Authentication of an operation

Every operation states what it needs to be called, so a reader or a client generator knows where a session or a token is required. The document's default (`security` at the top level, declared on `ApiDoc` in `crates/tenko-api/src/routes/mod.rs`) is a session cookie (`session`) or a bearer token (`token`). An operation deviates from it only through its own `security(...)`:

| The handler | Annotation | Meaning |
|---|---|---|
| takes `Ctx`, and a personal token passes its authorization | none | a session or a token |
| takes `Ctx`, and a token is always refused: it authorizes an action that `tenko_auth::roles::interactive_only` keeps from tokens (administering, revealing, changing users, settings, the system, tokens, sessions, secrets or DNS keys), or it needs the caller's own session (`AuthService::current`, a fresh sign-in) | `security(("session" = []))` | a session only |
| takes no `Ctx` (setup, the sign-in ceremonies, node enrolment, liveness and readiness, the CA root, the language list and packs, this document) | `security()` | public |

`POST /auth/password/check` is the one operation that is public before setup and needs a session or a token after it; it declares `security((), ("session" = []), ("token" = []))`.

When you add a route, decide from the handler, not from its path. Three tests in `crates/tenko-api/src/routes/tests.rs` hold the document to the server: `every_operation_declares_its_security_requirement` names every public operation, so a new one must be added there on purpose; `an_anonymous_request_is_refused_on_every_operation_but_the_public_ones` calls each operation without credentials; and `a_personal_token_is_refused_exactly_on_the_session_only_operations_without_a_body` calls each operation that takes no request body with an administrator's token.
