// Replies of the mock handlers and the problem documents they fail with. A handler returns
// a `Reply` (typed by the operation it answers, see route.ts) or throws a `Problem`, which
// the route wrapper turns into an `application/problem+json` response (RFC 9457 with the
// stable `code`, `params` and `errors` of API-08).
import type { FieldError } from "../problem";

export type HeaderMap = Record<string, string>;

/** A response the handler wants sent: a status, an optional JSON body and headers. */
export class Reply<T = unknown> {
  constructor(
    readonly status: number,
    readonly body: T,
    readonly headers: HeaderMap = {},
    readonly contentType: string = "application/json",
  ) {}

  toResponse(): Response {
    const noBody = this.status === 204 || this.status === 205 || this.body === undefined;
    const headers = new Headers(this.headers);
    if (noBody) return new Response(null, { status: this.status, headers });
    headers.set("content-type", this.contentType);
    return new Response(JSON.stringify(this.body), { status: this.status, headers });
  }
}

export function ok<T>(body: T, headers?: HeaderMap): Reply<T> {
  return new Reply(200, body, headers);
}

export function created<T>(body: T, headers?: HeaderMap): Reply<T> {
  return new Reply(201, body, headers);
}

export function noContent(headers?: HeaderMap): Reply<undefined> {
  return new Reply(204, undefined, headers);
}

// ---------------------------------------------------------------------------------
// Problems

/** The body of every error response. */
export interface ProblemBody {
  type: "about:blank";
  status: number;
  code: string;
  title: string;
  detail: string;
  params: Record<string, string>;
  errors?: FieldError[];
}

/** Default status, title and English detail of each code the mock answers with. */
const CATALOG = {
  "sys.invalid_request": [400, "Bad Request", "the request body is malformed"],
  "sys.invalid_value": [400, "Invalid value", "a value of the request is not valid"],
  "sys.invalid_query": [400, "Invalid query", "a query parameter is missing, repeated or malformed"],
  "sys.invalid_cursor": [400, "Invalid cursor", "the pagination cursor is malformed"],
  "sys.events.unknown_topic": [400, "Unknown event topic", "the event topic is not known"],
  "sys.store.precondition_failed": [
    412,
    "Precondition Failed",
    "the object changed since it was read; reload and retry",
  ],
  "sys.not_implemented": [501, "Not implemented", "this operation is not implemented yet"],
  "sys.internal": [500, "Internal Server Error", "the mock handler failed"],
  "auth.unauthenticated": [401, "Authentication required", "the request carries no valid session"],
  "auth.session_expired": [401, "Session expired", "the session has expired"],
  "auth.invalid_credentials": [401, "Login failed", "the credentials were not accepted"],
  "auth.throttled": [429, "Too many attempts", "too many failed attempts; retry later"],
  "auth.challenge_invalid": [401, "Challenge invalid", "the challenge is unknown or has expired"],
  "auth.forbidden": [403, "Forbidden", "the session is not allowed to do this"],
  "auth.invalid_request": [400, "Invalid request", "a value of the request is not valid"],
  "auth.password.policy": [400, "Password does not meet the policy", "the password does not meet the policy"],
  "auth.password.incorrect": [400, "Password incorrect", "the current password is not correct"],
  "auth.break_glass.hardware_key_only": [
    403,
    "Hardware key only",
    "the break-glass account logs in with a hardware security key only",
  ],
  "auth.totp.already_enrolled": [409, "TOTP already enrolled", "TOTP is already enrolled"],
  "auth.totp.not_enrolled": [409, "TOTP not enrolled", "TOTP is not enrolled"],
  "auth.totp.code_mismatch": [401, "Code does not match", "the TOTP code does not match"],
  "auth.token.lifetime_exceeded": [
    400,
    "Token lifetime exceeded",
    "the token lifetime exceeds the maximum of the profile",
  ],
  "auth.token.not_found": [404, "Not Found", "token not found"],
  "auth.session.not_found": [404, "Not Found", "session not found"],
  "auth.preference.not_found": [404, "Not Found", "preference not found"],
  "auth.preference.too_large": [413, "Content Too Large", "the preference exceeds 16384 bytes"],
  "auth.preference.limit": [409, "Conflict", "a person stores at most 64 preferences"],
  "auth.webauthn.credential_not_found": [404, "Not Found", "credential not found"],
  "auth.webauthn.credential_exists": [409, "Credential exists", "the credential is registered already"],
  "auth.conflict": [409, "Conflict", "the profile requires this factor; enrol another one first"],
  "auth.setup.closed": [409, "Setup is closed", "setup has already been completed"],
  "auth.setup.token_invalid": [401, "Setup token invalid", "the setup token is not valid"],
  "auth.setup.invalid_host_name": [
    400,
    "Host name invalid",
    "the host name is not valid for passkeys: use a DNS name, not an address",
  ],
  "users.not_found": [404, "Not Found", "user not found"],
  "users.name_taken": [409, "User name taken", "the user name is taken"],
  "users.last_administrator": [
    409,
    "Last administrator",
    "the change would leave no active administrator",
  ],
  "settings.pin_coupling": [
    409,
    "PIN coupling rule",
    "a PIN may be the only factor only while the vault holds no operator secrets",
  ],
  "auth.step_up_required": [
    403,
    "Fresh authentication required",
    "a stronger or more recent sign-in is needed",
  ],
  "vault.pin_coupling": [
    409,
    "PIN coupling rule",
    "the vault takes operator secrets only when every account that may reveal them has more than a PIN",
  ],
  "vault.secret.not_found": [404, "Not Found", "operator secret not found"],
  "vault.secret.invalid": [422, "Unprocessable Content", "a value of the secret is not valid"],
  "vault.secret.too_large": [413, "Content Too Large", "the value exceeds 64 KiB"],
  "vault.secret.conflict": [
    409,
    "Conflict",
    "the secret changed since it was read; reload and retry",
  ],
  "vault.secret.in_use": [
    409,
    "Secret in use",
    "the secret is bound to a host or used by a connector",
  ],
  "vault.host_credentials.conflict": [
    409,
    "Conflict",
    "the credentials of the host changed since they were read; reload and retry",
  ],
  "vault.host_credentials.secret_missing": [
    422,
    "Unprocessable Content",
    "a secret of the request is not an operator secret",
  ],
  "vault.reveal.host_required": [
    403,
    "Reveal not allowed here",
    "the reveal policy reveals only secrets bound to the host in view; name the host",
  ],
  "vault.reveal.not_bound": [
    403,
    "Reveal not allowed here",
    "the secret is not bound to the host named",
  ],
  "vault.reveal.rate_limited": [429, "Too many reveals", "too many reveals; retry later"],
  "remote.interface_unknown": [
    422,
    "Unprocessable Content",
    "the interface is not a live interface of this host",
  ],
  "remote.address_unknown": [
    422,
    "Unprocessable Content",
    "the address is not a live address or DNS name of this host or interface",
  ],
} as const satisfies Record<string, readonly [number, string, string]>;

export type ProblemCode = keyof typeof CATALOG;

const STATUS_TITLES: Record<number, string> = {
  400: "Bad Request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not Found",
  409: "Conflict",
  412: "Precondition Failed",
  422: "Unprocessable Content",
  429: "Too Many Requests",
  500: "Internal Server Error",
  501: "Not Implemented",
};

export interface ProblemInit {
  /** Overrides the status of the code (a few codes are answered with two statuses). */
  status?: number;
  detail?: string;
  params?: Record<string, string>;
  errors?: FieldError[];
  headers?: HeaderMap;
}

/** A failure a handler throws; the route wrapper sends it. */
export class Problem extends Error {
  readonly reply: Reply<ProblemBody>;

  constructor(code: string, init: ProblemInit = {}) {
    const entry = (CATALOG as Record<string, readonly [number, string, string]>)[code];
    const status = init.status ?? entry?.[0] ?? 500;
    const title = entry && status === entry[0] ? entry[1] : (STATUS_TITLES[status] ?? "Error");
    const detail = init.detail ?? entry?.[2] ?? title;
    super(`${code}: ${detail}`);
    this.name = "Problem";
    const body: ProblemBody = { type: "about:blank", status, code, title, detail, params: init.params ?? {} };
    if (init.errors?.length) body.errors = init.errors;
    this.reply = new Reply(status, body, init.headers, "application/problem+json");
  }
}

/** Fails the request with the problem of `code`. */
export function fail(code: ProblemCode, init?: ProblemInit): never {
  throw new Problem(code, init);
}

/** The problem document of the 501 stub of an operation. */
export function notImplemented(method: string, path: string): Reply<ProblemBody> {
  return new Problem("sys.not_implemented", {
    detail: `${method} ${path} is not implemented yet`,
    params: { method, path },
  }).reply;
}

/** A field error of a request body. */
export function fieldError(field: string, code: string, params?: Record<string, string>): FieldError {
  return params ? { field, code, params } : { field, code };
}
