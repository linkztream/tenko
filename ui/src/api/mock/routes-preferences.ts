// The signed-in person's preferences (/api/v1/auth/preferences, docs/access.md section 15):
// the saved table layouts, with the server's schema and bounds. The mock keeps them per user in
// memory; a request without a mock session (a component test that set the session in the UI
// only) uses one shared bucket, since the mock is no security boundary.
import type { HttpHandler } from "msw";
import { currentPrincipal } from "./auth";
import { onMockReset } from "./db";
import { fail, fieldError, noContent, ok } from "./reply";
import { route, wholePage } from "./route";
import { iso } from "./util";

export const MAX_KEYS = 64;
export const MAX_DOCUMENT_BYTES = 16 * 1024;
const MAX_COLUMNS = 128;
const KEY = /^table:[a-z0-9][a-z0-9._-]{0,63}$/;
const COLUMN = /^[A-Za-z0-9._:-]{1,64}$/;
const FIELDS = new Set(["version", "order", "hidden", "widths", "sort"]);

interface Stored {
  document: string;
  updated_at: string;
}

const store = new Map<string, Map<string, Stored>>();
onMockReset(() => store.clear());

function bucket(): Map<string, Stored> {
  const user = currentPrincipal()?.user.id ?? "-";
  let b = store.get(user);
  if (!b) {
    b = new Map();
    store.set(user, b);
  }
  return b;
}

function invalid(field: string, detail: string): never {
  return fail("auth.invalid_request", { detail, params: { field, reason: detail }, errors: [fieldError(field, "auth.invalid_request")] });
}

function checkKey(key: string): void {
  if (!KEY.test(key)) invalid("key", "a preference key is `table:<id>`");
}

function checkList(field: string, v: unknown): void {
  if (v === undefined || v === null) return;
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) fail("sys.invalid_request", { detail: `${field} must be a list of texts` });
  const list = v as string[];
  if (list.length > MAX_COLUMNS) invalid(field, "a layout names at most 128 columns");
  if (list.some((x) => !COLUMN.test(x))) invalid(field, "a column id is 1 to 64 of A-Z, a-z, 0-9, `.`, `_`, `-` and `:`");
  if (new Set(list).size !== list.length) invalid(field, "a column is named twice");
}

/** The canonical document of a valid layout, as the server stores it. */
function validate(body: Record<string, unknown>): string {
  for (const key of Object.keys(body)) {
    if (!FIELDS.has(key)) fail("sys.invalid_request", { detail: "the request body does not match the schema of this endpoint" });
  }
  if (typeof body.version !== "number") fail("sys.invalid_request", { detail: "the request body is missing the field `version`" });
  if (body.version !== 1) invalid("version", "this server knows version 1 of a table layout");
  checkList("order", body.order);
  checkList("hidden", body.hidden);
  const out: Record<string, unknown> = { version: 1 };
  if (Array.isArray(body.order)) out.order = body.order;
  if (Array.isArray(body.hidden)) out.hidden = body.hidden;
  if (body.widths !== undefined && body.widths !== null) {
    if (typeof body.widths !== "object" || Array.isArray(body.widths)) fail("sys.invalid_request", { detail: "widths must be an object" });
    const widths = body.widths as Record<string, unknown>;
    if (Object.keys(widths).length > MAX_COLUMNS) invalid("widths", "a layout names at most 128 columns");
    const sorted: Record<string, number> = {};
    for (const id of Object.keys(widths).sort()) {
      const w = widths[id];
      if (typeof w !== "number" || !Number.isInteger(w) || w < 0) fail("sys.invalid_request", { detail: "a width is a whole number" });
      if (!COLUMN.test(id)) invalid("widths", "a column id is 1 to 64 of A-Z, a-z, 0-9, `.`, `_`, `-` and `:`");
      if (w < 16 || w > 1200) invalid("widths", "a width is 16 to 1200 pixels");
      sorted[id] = w;
    }
    out.widths = sorted;
  }
  if (body.sort !== undefined && body.sort !== null) {
    const sort = body.sort as Record<string, unknown>;
    if (typeof sort !== "object" || Object.keys(sort).some((k) => k !== "column" && k !== "desc") || typeof sort.column !== "string") {
      fail("sys.invalid_request", { detail: "the request body does not match the schema of this endpoint" });
    }
    if (!COLUMN.test(sort.column)) invalid("sort", "a column id is 1 to 64 of A-Z, a-z, 0-9, `.`, `_`, `-` and `:`");
    out.sort = { column: sort.column, desc: sort.desc === true };
  }
  const document = JSON.stringify(out);
  if (document.length > MAX_DOCUMENT_BYTES) {
    fail("auth.preference.too_large", { params: { max_bytes: String(MAX_DOCUMENT_BYTES) } });
  }
  return document;
}

const answer = (key: string, stored: Stored) => ({ key, value: JSON.parse(stored.document) as never, updated_at: stored.updated_at });

const listPreferences = route("get", "/api/v1/auth/preferences", () => {
  const items = [...bucket().entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([key, stored]) => answer(key, stored));
  return ok(wholePage(items, 0));
});

const putPreference = route("put", "/api/v1/auth/preferences/{key}", async (ctx) => {
  const key = ctx.params.key;
  checkKey(key);
  const document = validate((await ctx.body()) as Record<string, unknown>);
  const b = bucket();
  if (!b.has(key) && b.size >= MAX_KEYS) fail("auth.preference.limit", { params: { max_keys: String(MAX_KEYS) } });
  const stored = { document, updated_at: iso(Date.now()) };
  b.set(key, stored);
  return ok(answer(key, stored));
});

const deletePreference = route("delete", "/api/v1/auth/preferences/{key}", (ctx) => {
  const key = ctx.params.key;
  checkKey(key);
  if (!bucket().delete(key)) fail("auth.preference.not_found");
  return noContent();
});

export const preferencesRoutes: HttpHandler[] = [listPreferences, putPreference, deletePreference];

/** For tests: the stored documents of the bucket of the current mock session. */
export function mockPreferences(): Record<string, unknown> {
  return Object.fromEntries([...bucket().entries()].map(([key, stored]) => [key, JSON.parse(stored.document) as unknown]));
}
