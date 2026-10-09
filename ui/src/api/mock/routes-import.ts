// Import and export of the mock API (IPAM-11, MIG-14): upload a CSV file or a workbook, read
// the analysis and the mapping in force, set a mapping, preview the changes, apply them as a
// job, discard the upload, and download the IPAM state as CSV in the import vocabulary. The
// answers and error codes follow `crates/tenko-api/src/routes/import.rs` and `export.rs`;
// the semantics live in the import-*.ts modules next to this file.
//
// Simplifications: a workbook upload is answered with the canned workbook (the mock cannot
// unpack a spreadsheet), the apply job finishes at once, and the credentials of an import
// are remembered as digests in memory (import-store.ts), not in a vault.
import type { HttpHandler } from "msw";
import type { components } from "../generated/schema";
import { analyze, sheetShapes, targetInfos } from "./import-analysis";
import type { SourceFile } from "./import-cells";
import { EXPORT_KINDS, exportCsv, exportFileName, type ExportKind } from "./import-export";
import { MappingError, mappingToWire, readMapping } from "./import-mapping";
import { buildPreview, credentialDigest, credentialGate, evaluate } from "./import-preview";
import { ReadError, readFile } from "./import-sheets";
import { UPLOAD_TTL_MS, importRecords, vaultDigests, type ImportRecord } from "./import-store";
import { PROBLEM } from "./import-vocab";
import { applyCommands } from "./ipam/api";
import { appendAudit } from "./audit-store";
import { requireSession, type Principal } from "./auth";
import { db } from "./db";
import { createJob } from "./job-store";
import { Problem, Reply, created, fieldError, noContent, ok } from "./reply";
import { route } from "./route";
import { ipamState } from "./ipam/api";
import { iso, isUuid, randomId } from "./util";

type S = components["schemas"];

/** Largest upload: all files together. */
const MAX_UPLOAD = 20 * 1024 * 1024;
const DEFAULT_PREVIEW_ROWS = 200;
const MAX_PREVIEW_ROWS = 1000;

/** A problem with the title the server gives it (the shared catalog only knows a few). */
function problem(
  code: string,
  status: number,
  title: string,
  detail: string,
  init: { params?: Record<string, string>; errors?: ReturnType<typeof fieldError>[] } = {},
): Problem {
  const made = new Problem(code, { status, detail, ...init });
  const reply = new Reply(status, { ...made.reply.body, title }, made.reply.headers, made.reply.contentType);
  Object.defineProperty(made, "reply", { value: reply });
  return made;
}

function stateConflict(detail: string): Problem {
  return problem(PROBLEM.stateConflict, 409, "Import busy", detail);
}

/** The upload of the request, for its owner only: 404 for an unknown one, 410 for one that expired. */
function find(id: string, principal: Principal): ImportRecord {
  if (!isUuid(id)) {
    throw new Problem("sys.invalid_request", { status: 400, detail: `\`${id}\` is not a valid identifier`, params: { part: "path" } });
  }
  const records = importRecords();
  const record = records.get(id.toLowerCase());
  if (!record || record.owner !== principal.user.id) {
    throw problem(PROBLEM.notFound, 404, "No such import", `import ${id} does not exist`, { params: { id } });
  }
  if (record.expires < Date.now()) {
    records.delete(record.id);
    throw problem(PROBLEM.expired, 410, "Upload expired", "the staged upload expired; upload the file again", { params: { id } });
  }
  return record;
}

function fileView(file: SourceFile): S["FileView"] {
  return {
    name: file.name,
    format: file.format,
    size: file.size,
    ...(file.text ? { text: file.text } : {}),
  };
}

/** The upload with its analysis and the mapping in force (`ImportView`). */
function renderView(record: ImportRecord): S["ImportView"] {
  const customKeys = [...ipamState().data.custom_field.values()].map((def) => def.key);
  return {
    id: record.id,
    state: record.state,
    created: iso(record.created),
    expires: iso(record.expires),
    files: record.files.map(fileView),
    sheets: record.analysis.sheets,
    mapping: mappingToWire(record.mapping ?? record.analysis.mapping),
    mapped: record.mapping !== null,
    targets: targetInfos(customKeys),
    ...(record.jobId ? { job_id: record.jobId } : {}),
  };
}

// ---------------------------------------------------------------------------------
// Upload

const upload = route("post", "/api/v1/imports", async (ctx) => {
  const principal = requireSession();
  let form: FormData;
  try {
    form = await ctx.request.formData();
  } catch {
    throw problem(PROBLEM.uploadMalformed, 400, "Malformed upload", "the upload must be multipart/form-data with a boundary");
  }
  const parts = form.getAll("files").filter((entry): entry is File => typeof entry !== "string");
  const sizes = parts.reduce((sum, file) => sum + file.size, 0);
  if (parts.length === 0 || sizes === 0) {
    throw problem(PROBLEM.uploadEmpty, 400, "No file", "the upload holds no file");
  }
  if (sizes > MAX_UPLOAD) {
    throw problem(PROBLEM.uploadTooLarge, 413, "Upload too large", `the upload has ${sizes} bytes; the limit is ${MAX_UPLOAD}`, {
      params: { limit: String(MAX_UPLOAD) },
    });
  }
  const files: SourceFile[] = [];
  for (const part of parts) {
    try {
      files.push(readFile(part.name, new Uint8Array(await part.arrayBuffer())));
    } catch (error) {
      if (error instanceof ReadError && error.kind === "unsupported") {
        throw problem(
          PROBLEM.uploadUnsupported,
          415,
          "Unsupported file",
          "the file is not a CSV file or an xlsx, xls or ods workbook",
        );
      }
      const detail = error instanceof Error ? error.message : String(error);
      throw problem(PROBLEM.uploadUnreadable, 422, "Unreadable file", `the file cannot be read: ${detail}`);
    }
  }
  const now = Date.now();
  const record: ImportRecord = {
    id: randomId(),
    owner: principal.user.id,
    created: now,
    expires: now + UPLOAD_TTL_MS,
    files,
    analysis: analyze(files),
    mapping: null,
    state: "uploaded",
    jobId: null,
    applyKey: null,
    mappingRevision: 0,
    stored: null,
  };
  importRecords().set(record.id, record);
  appendAudit({
    action: "import.upload",
    objects: [{ kind: "import", id: record.id }],
    context: { files: String(files.length), bytes: String(sizes) },
  });
  return created(renderView(record), { Location: `/api/v1/imports/${record.id}` });
});

const get = route("get", "/api/v1/imports/{id}", (ctx) => {
  const principal = requireSession();
  return ok(renderView(find(ctx.params.id, principal)));
});

// ---------------------------------------------------------------------------------
// Mapping

const mapping = route("put", "/api/v1/imports/{id}/mapping", async (ctx) => {
  const principal = requireSession();
  const record = find(ctx.params.id, principal);
  const body = await ctx.body();
  if (record.state === "applying" || record.state === "applied") {
    throw stateConflict(
      record.state === "applying"
        ? "the import is being applied; wait for its job to finish"
        : "the import was applied; upload the file again to change the mapping",
    );
  }
  try {
    record.mapping = readMapping(body, sheetShapes(record.analysis.sheets));
    record.mappingRevision += 1;
  } catch (error) {
    if (error instanceof MappingError) {
      throw problem(PROBLEM.mappingInvalid, 422, "Mapping does not fit the upload", error.message, {
        errors: [fieldError(error.field, PROBLEM.mappingInvalid)],
      });
    }
    throw error;
  }
  record.state = "mapped";
  return ok(renderView(record));
});

// ---------------------------------------------------------------------------------
// Preview and apply

function previewRows(url: URL): number {
  for (const name of url.searchParams.keys()) {
    if (name !== "rows") {
      throw new Problem("sys.invalid_query", {
        status: 400,
        detail: `query parameter \`${name}\`: unknown parameter`,
        params: { parameter: name },
        errors: [fieldError(name, "sys.invalid_query")],
      });
    }
  }
  const raw = url.searchParams.get("rows");
  if (raw === null) return DEFAULT_PREVIEW_ROWS;
  const rows = Number(raw);
  if (!/^[0-9]+$/.test(raw) || rows < 1 || rows > MAX_PREVIEW_ROWS) {
    throw new Problem("sys.invalid_query", {
      status: 400,
      detail: `query parameter \`rows\`: must be from 1 to ${MAX_PREVIEW_ROWS}`,
      params: { parameter: "rows" },
      errors: [fieldError("rows", "sys.invalid_query")],
    });
  }
  return rows;
}

const preview = route("get", "/api/v1/imports/{id}/preview", (ctx) => {
  const principal = requireSession();
  const rows = previewRows(ctx.url);
  const record = find(ctx.params.id, principal);
  // Every row is kept with the upload, so the rows endpoint pages them without computing
  // the preview again.
  const full = buildPreview(record, evaluate(record), Number.MAX_SAFE_INTEGER, credentialGate(principal));
  record.stored = { mappingRevision: record.mappingRevision, baseRevision: full.base_revision, rows: full.rows };
  return ok({ ...full, rows: full.rows.slice(0, rows) });
});

// ---------------------------------------------------------------------------------
// Rows of the latest preview, page by page

const DEFAULT_ROWS_PAGE = 200;
const MAX_ROWS_PAGE = 1000;

/** What a rows cursor carries: the import, the mapping revision and the next row. */
interface RowsCursor {
  i: string;
  r: number;
  o: number;
}

function encodeRowsCursor(cursor: RowsCursor): string {
  return btoa(JSON.stringify(cursor)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeRowsCursor(raw: string, id: string): RowsCursor {
  try {
    const value = JSON.parse(atob(raw.replace(/-/g, "+").replace(/_/g, "/"))) as Partial<RowsCursor>;
    if (value.i === id && Number.isInteger(value.r) && Number.isInteger(value.o) && (value.o ?? -1) >= 0) return value as RowsCursor;
  } catch {
    // Not a cursor of this endpoint.
  }
  throw new Problem("sys.invalid_cursor", { status: 400, detail: "the cursor is malformed or belongs to another list", params: { cursor: raw } });
}

function rowsLimit(url: URL): number {
  for (const name of url.searchParams.keys()) {
    if (name !== "limit" && name !== "cursor") {
      throw new Problem("sys.invalid_query", {
        status: 400,
        detail: `query parameter \`${name}\`: unknown parameter`,
        params: { parameter: name },
        errors: [fieldError(name, "sys.invalid_query")],
      });
    }
  }
  const raw = url.searchParams.get("limit");
  if (raw === null) return DEFAULT_ROWS_PAGE;
  const limit = Number(raw);
  if (!/^[0-9]+$/.test(raw) || limit < 1 || limit > MAX_ROWS_PAGE) {
    throw new Problem("sys.invalid_query", {
      status: 400,
      detail: `query parameter \`limit\`: must be from 1 to ${MAX_ROWS_PAGE}`,
      params: { parameter: "limit" },
      errors: [fieldError("limit", "sys.invalid_query")],
    });
  }
  return limit;
}

function previewStale(record: ImportRecord, detail: string): Problem {
  return problem(PROBLEM.previewStale, 409, "Preview out of date", detail, { params: { mapping_revision: String(record.mappingRevision) } });
}

/** A page of the rows of the stored preview (`ImportRowsPage`). */
export function rowsPage(record: ImportRecord, url: URL): S["ImportRowsPage"] {
  const limit = rowsLimit(url);
  const raw = url.searchParams.get("cursor");
  const cursor = raw ? decodeRowsCursor(raw, record.id) : null;
  if (cursor && cursor.r !== record.mappingRevision) {
    throw previewStale(record, "the mapping changed since this page was listed; preview the import again");
  }
  const stored = record.stored;
  if (!stored) throw previewStale(record, "no preview was computed for the current mapping; preview the import first");
  if (stored.mappingRevision !== record.mappingRevision) {
    throw previewStale(record, "the mapping changed since the preview; preview the import again");
  }
  const offset = cursor?.o ?? 0;
  const items = stored.rows.slice(offset, offset + limit);
  const next = offset + items.length;
  return {
    items,
    next_cursor: items.length > 0 && next < stored.rows.length ? encodeRowsCursor({ i: record.id, r: stored.mappingRevision, o: next }) : null,
    total_rows: stored.rows.length,
    base_revision: stored.baseRevision,
  };
}

const rows = route("get", "/api/v1/imports/{id}/rows", (ctx) => {
  const principal = requireSession();
  const record = find(ctx.params.id, principal);
  return ok(rowsPage(record, ctx.url));
});

const apply = route("post", "/api/v1/imports/{id}/apply", async (ctx) => {
  const principal = requireSession();
  const record = find(ctx.params.id, principal);
  const body = await ctx.optionalBody();
  const given = body.acknowledge;
  if (given !== undefined && (!Array.isArray(given) || !given.every((code) => typeof code === "string"))) {
    throw new Problem("sys.invalid_request", {
      status: 400,
      detail: "acknowledge must be a list of warning codes",
      params: { part: "body" },
    });
  }
  const acknowledge = (given as string[] | undefined) ?? [];
  // A retry of the request that applied the import gets the same job again.
  const key = ctx.header("idempotency-key");
  if (key !== null && key === record.applyKey && record.jobId) {
    return new Reply<S["ApplyAccepted"]>(202, { job_id: record.jobId }, { Location: `/jobs/${record.jobId}` });
  }
  if (record.state === "applying") {
    throw stateConflict("the import is being applied; wait for its job to finish");
  }
  if (record.state === "applied") {
    throw stateConflict("the import was applied already; applying again would plan nothing new");
  }

  const ev = evaluate(record, acknowledge);
  const model = ev.translation.model;
  const gate = credentialGate(principal);
  if (ev.mapping.options.credentials === "import" && model.credentials.length > 0 && !gate.allowed) {
    throw problem(
      PROBLEM.vaultRequired,
      403,
      "Credentials need the vault",
      `${model.credentials.length} hosts have credential columns, which become operator secrets in the vault: ${gate.detail}`,
      { params: { reason: gate.reason, hosts: String(model.credentials.length), ...(gate.required ? { required: gate.required } : {}) } },
    );
  }
  if (!ev.plan.ok) throw ev.plan.problem;
  const blocking = [...ev.plan.result.plan.summary.unacknowledged];
  if (ev.reconciled.blocked) blocking.push("import.conflict.kept");
  if (blocking.length > 0) {
    throw problem(
      PROBLEM.planBlocked,
      409,
      "Import blocked",
      `the import cannot be applied yet: ${blocking.join(", ")}`,
      { params: { codes: blocking.join(",") } },
    );
  }

  // The creates and updates, in dependency order, as one change: prefixes, then hosts with
  // their interfaces, then addresses.
  applyCommands(ev.reconciled.commands as never, { acknowledge: ev.mapping.options.acknowledge });
  const vault = vaultDigests();
  let secrets = 0;
  for (const op of ev.reconciled.credentials) {
    const value = ev.translation.credentials.get(op.host);
    if (!value) continue;
    const digest = credentialDigest(value.login, value.password);
    if (vault.get(op.host) !== digest) secrets += 1;
    vault.set(op.host, digest);
  }
  if (secrets > 0) db.vaultHasOperatorSecrets = true;

  const jobId = createJob({
    kind: "import.apply",
    title: "jobs.title.import_apply",
    targets: [{ kind: "import", id: record.id }],
    timeoutSecs: 3600,
    steps: [
      { kind: "import.parse", automatic: true },
      { kind: "import.plan", automatic: true },
      { kind: "import.apply_chunk", automatic: true },
    ],
  });
  record.state = "applied";
  record.jobId = jobId;
  record.applyKey = ctx.header("idempotency-key");
  appendAudit({
    action: "import.apply",
    objects: [{ kind: "import", id: record.id }],
    context: { job: jobId, secrets: String(secrets) },
  });
  return new Reply<S["ApplyAccepted"]>(202, { job_id: jobId }, { Location: `/jobs/${jobId}` });
});

const discard = route("delete", "/api/v1/imports/{id}", (ctx) => {
  const principal = requireSession();
  const record = find(ctx.params.id, principal);
  if (record.state === "applying") throw stateConflict("the import is being applied; wait for its job to finish");
  importRecords().delete(record.id);
  appendAudit({ action: "import.delete", objects: [{ kind: "import", id: record.id }] });
  return noContent();
});

// ---------------------------------------------------------------------------------
// Export

type ExportPath = `/api/v1/exports/${ExportKind}.csv`;

function exportRoute(path: ExportPath, kind: ExportKind): HttpHandler {
  return route("get", path, () => {
    requireSession();
    return new Response(exportCsv(kind), {
      status: 200,
      headers: {
        "content-type": "text/csv; charset=utf-8",
        "content-disposition": `attachment; filename="${exportFileName(kind)}"`,
      },
    });
  });
}

export const importRoutes: HttpHandler[] = [
  upload,
  get,
  mapping,
  preview,
  rows,
  apply,
  discard,
  ...EXPORT_KINDS.map((kind) => exportRoute(`/api/v1/exports/${kind}.csv`, kind)),
];
