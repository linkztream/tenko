// Errors of the API: RFC 9457 problem details with a stable `code` and `params`
// (API-08). The UI never shows the server's English text when it has a translation:
// the message comes from the key `errors.<code>` with the problem's params as arguments.
import { hasMessage, t, tDynamic } from "../i18n";

export interface FieldError {
  /** The field path, for example `cidr` or `interfaces[0].mac`. */
  readonly field: string;
  readonly code: string;
  readonly params?: Readonly<Record<string, string>>;
}

export interface ProblemDetails {
  readonly type?: string;
  readonly status: number;
  readonly code: string;
  readonly title: string;
  readonly detail: string;
  readonly instance?: string | null;
  readonly params?: Readonly<Record<string, string>>;
  readonly errors?: readonly FieldError[];
}

/** Codes the client reports itself, without a server response. */
export const CLIENT_CODES = {
  network: "client.network",
  aborted: "client.aborted",
  badResponse: "client.bad_response",
} as const;

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly title: string;
  readonly detail: string;
  readonly params: Readonly<Record<string, string>>;
  readonly fieldErrors: readonly FieldError[];
  /** Seconds from a `Retry-After` header, when the server sent one. */
  readonly retryAfter: number | undefined;

  constructor(problem: ProblemDetails, retryAfter?: number) {
    super(`${problem.code}: ${problem.detail || problem.title}`);
    this.name = "ApiError";
    this.status = problem.status;
    this.code = problem.code;
    this.title = problem.title;
    this.detail = problem.detail;
    this.params = problem.params ?? {};
    this.fieldErrors = problem.errors ?? [];
    this.retryAfter = retryAfter;
  }

  /** Whether this is the problem with `code` (or one of its sub-codes, `auth.password`). */
  is(code: string): boolean {
    return this.code === code || this.code.startsWith(`${code}.`);
  }

  /** The error of one request field, if the server reported one. */
  field(name: string): FieldError | undefined {
    return this.fieldErrors.find((e) => e.field === name);
  }
}

export function isApiError(err: unknown, code?: string): err is ApiError {
  return err instanceof ApiError && (code === undefined || err.is(code));
}

/** Parses a problem body; anything that is not one becomes a synthetic problem. */
export function toProblem(status: number, body: unknown): ProblemDetails {
  if (body && typeof body === "object" && typeof (body as { code?: unknown }).code === "string") {
    const b = body as Partial<ProblemDetails>;
    return {
      status: typeof b.status === "number" ? b.status : status,
      code: b.code as string,
      title: typeof b.title === "string" ? b.title : "",
      detail: typeof b.detail === "string" ? b.detail : "",
      params: isStringRecord(b.params) ? b.params : {},
      errors: Array.isArray(b.errors) ? b.errors.filter(isFieldError) : [],
      instance: typeof b.instance === "string" ? b.instance : null,
    };
  }
  return { status, code: CLIENT_CODES.badResponse, title: "", detail: "", params: { status: String(status) } };
}

/** Numeric strings become numbers so plural and number arguments format correctly. */
function messageArgs(params: Readonly<Record<string, string>> | undefined): Record<string, string | number> {
  const out: Record<string, string | number> = {};
  for (const [k, v] of Object.entries(params ?? {})) {
    out[k] = /^-?\d+(\.\d+)?$/.test(v) ? Number(v) : v;
  }
  return out;
}

/** The translated, human message for an error of any kind. */
export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    const own = tDynamic(`errors.${err.code}`, messageArgs(err.params));
    if (own !== undefined) return own;
    if (err.status === 501) return t("errors.generic.not_implemented");
    if (err.title) return err.title;
    return err.status >= 500 ? t("errors.generic.server") : t("errors.generic.client");
  }
  if (err instanceof DOMException && err.name === "AbortError") return t("errors.client.aborted");
  return t("errors.generic.unexpected");
}

/** The translated message for one field error. */
export function fieldErrorMessage(err: FieldError): string {
  return tDynamic(`errors.${err.code}`, messageArgs(err.params)) ?? t("errors.generic.field");
}

/** Whether the UI has its own words for this code. */
export function hasErrorMessage(code: string): boolean {
  return hasMessage(`errors.${code}`);
}

function isStringRecord(v: unknown): v is Record<string, string> {
  return !!v && typeof v === "object" && Object.values(v).every((x) => typeof x === "string");
}

function isFieldError(v: unknown): v is FieldError {
  return !!v && typeof v === "object" && typeof (v as FieldError).field === "string" && typeof (v as FieldError).code === "string";
}
