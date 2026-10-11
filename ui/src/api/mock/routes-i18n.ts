// Mock routes of the `i18n` API area (OpenAPI tag `i18n`, API-21), after
// crates/tenko-api/src/routes/i18n.rs. The state is i18n-store.ts.
//
// Who may do what: the languages and the messages of an active pack are public (the sign-in
// page needs them); the list, the upload, the report, the candidate, preview, activation,
// discard and removal are for administrators (401 signed out, 403 `auth.forbidden`); the
// template needs the right to read the system, which every role has.
//
// What the mock simplifies: see i18n-store.ts (the report counts the units of the document;
// there is no key set to check against). Every write is committed as an event on the `system`
// topic whose data names the tables `i18n.packs` and `i18n.pack_slots`, which the languages page
// and src/i18n/remote.ts reload on, and audited with the actions `i18n.pack.upload`,
// `i18n.pack.preview`, `i18n.pack.activate`, `i18n.pack.discard` and `i18n.pack.remove`. A
// refused upload is audited as a failure. The installation's default language is
// `db.installation.language`.
import type { HttpHandler } from "msw";
import { appendAudit } from "./audit-store";
import { requireAdmin, requireSession } from "./auth";
import { db } from "./db";
import {
  MAX_PACK_BYTES,
  PACK_OBJECT,
  activateCandidate,
  announcePacks,
  dropAll,
  dropCandidate,
  isBuiltInTag,
  isLanguageTag,
  languageList,
  markPreviewed,
  messagesOf,
  packList,
  reportOf,
  slotsOf,
  storeUpload,
  templateFor,
} from "./i18n-store";
import { Problem, created, noContent, ok } from "./reply";
import { route } from "./route";

/** Throws a problem with a code the mock's catalog does not list. */
function refuse(code: string, status: number, detail: string, params: Record<string, string> = {}): never {
  throw new Problem(code, { status, detail, params });
}

function notFound(tag: string): never {
  return refuse("i18n.pack.not_found", 404, `there is no language pack ${tag}`, { tag });
}

function noCandidate(tag: string): never {
  return refuse("i18n.pack.no_candidate", 404, `the language ${tag} has no uploaded version waiting for activation`, { tag });
}

/** A tag from the path; anything that is not shaped like a language tag is unknown. */
function pathTag(raw: string): string {
  if (!isLanguageTag(raw)) return refuse("i18n.pack.not_found", 404, "there is no language pack with this tag", { tag: raw });
  return raw;
}

/** The change set of a write: the event of the `i18n.*` tables, then the audit record. */
function wrote(action: string, tag: string, context: Record<string, string> = {}): void {
  announcePacks();
  appendAudit({ action, objects: [PACK_OBJECT], context: { tag, ...context } });
}

// ---------------------------------------------------------------------------------
// Public

const getLanguages = route("get", "/api/v1/i18n/languages", () => ok(languageList(), { "Cache-Control": "no-cache" }));

const getPack = route("get", "/api/v1/i18n/packs/{tag}", (ctx) => {
  const tag = pathTag(ctx.params.tag);
  const pack = messagesOf(tag, false);
  if (!pack) return notFound(tag);
  const etag = `"${pack.hash}"`;
  const cache = ctx.query("hash") === pack.hash ? "public, max-age=31536000, immutable" : "no-cache";
  const sent = ctx.header("if-none-match");
  const matches = sent !== null && sent.split(",").some((c) => c.trim().replace(/^W\//, "") === etag || c.trim() === "*");
  if (matches) return new Response(null, { status: 304, headers: { ETag: etag, "Cache-Control": cache } });
  return ok(pack, { ETag: etag, "Cache-Control": cache });
});

// ---------------------------------------------------------------------------------
// The list and the upload

const listPacks = route("get", "/api/v1/i18n/packs", () => {
  requireAdmin();
  return ok(packList());
});

const uploadPack = route("post", "/api/v1/i18n/packs", async (ctx) => {
  requireAdmin();
  let form: FormData;
  try {
    form = await ctx.request.formData();
  } catch {
    return refuse("i18n.upload.malformed", 400, "the upload must be multipart/form-data with a boundary");
  }
  const files = [...form.values()].filter((entry): entry is File => typeof entry !== "string");
  const [file, ...rest] = files;
  if (!file) return refuse("i18n.upload.empty", 400, "the upload has no file");
  if (rest.length > 0) return refuse("i18n.upload.malformed", 400, "upload one language pack at a time");
  if (file.size > MAX_PACK_BYTES) {
    return refuse("i18n.pack.too_large", 413, `a language pack has at most ${MAX_PACK_BYTES} bytes`, { limit: String(MAX_PACK_BYTES) });
  }
  const text = await file.text();
  let result: ReturnType<typeof storeUpload>;
  try {
    result = storeUpload(text);
  } catch (error) {
    if (error instanceof Problem) {
      const body = error.reply.body;
      appendAudit({
        action: "i18n.pack.upload",
        objects: [PACK_OBJECT],
        outcome: { kind: "failed", code: body.code },
        context: { ...body.params },
      });
    }
    throw error;
  }
  const { pack, report, changed } = result;
  // Uploading the active version or the candidate again changes nothing.
  if (changed) wrote("i18n.pack.upload", pack.tag, { version: pack.candidate?.id ?? "", percent: String(report.percent) });
  return created({ pack, report });
});

// ---------------------------------------------------------------------------------
// One language

const getReport = route("get", "/api/v1/i18n/packs/{tag}/report", (ctx) => {
  requireAdmin();
  const tag = pathTag(ctx.params.tag);
  const report = reportOf(tag);
  if (!report) return notFound(tag);
  return ok(report);
});

const getCandidate = route("get", "/api/v1/i18n/packs/{tag}/candidate", (ctx) => {
  requireAdmin();
  const tag = pathTag(ctx.params.tag);
  const pack = messagesOf(tag, true);
  if (!pack) return noCandidate(tag);
  return ok(pack, { "Cache-Control": "no-store" });
});

const previewPack = route("post", "/api/v1/i18n/packs/{tag}/preview", (ctx) => {
  requireAdmin();
  const tag = pathTag(ctx.params.tag);
  const pack = markPreviewed(tag);
  if (!pack) return noCandidate(tag);
  wrote("i18n.pack.preview", tag, { version: pack.candidate?.id ?? "" });
  return ok(pack);
});

const activatePack = route("post", "/api/v1/i18n/packs/{tag}/activate", (ctx) => {
  requireAdmin();
  const tag = pathTag(ctx.params.tag);
  const result = activateCandidate(tag);
  if (result === "no_candidate") return noCandidate(tag);
  if (result === "not_previewed") {
    return refuse("i18n.pack.not_previewed", 409, `preview the uploaded version of ${tag} before activating it`, { tag });
  }
  wrote("i18n.pack.activate", tag, { version: result.version, ...(result.previous ? { previous: result.previous } : {}) });
  return ok(result.pack);
});

const discardCandidate = route("delete", "/api/v1/i18n/packs/{tag}/candidate", (ctx) => {
  requireAdmin();
  const tag = pathTag(ctx.params.tag);
  const result = dropCandidate(tag);
  if (!result) return noCandidate(tag);
  wrote("i18n.pack.discard", tag, { version: result.version });
  return ok(result.pack);
});

const deletePack = route("delete", "/api/v1/i18n/packs/{tag}", (ctx) => {
  requireAdmin();
  const tag = pathTag(ctx.params.tag);
  const slots = slotsOf(tag);
  if (!slots.active && !slots.candidate) return notFound(tag);
  if (!isBuiltInTag(tag) && slots.active && db.installation.language === tag) {
    return refuse(
      "i18n.pack.default_language",
      409,
      `${tag} is the default language of the installation; choose another default first`,
      { tag },
    );
  }
  const gone = dropAll(tag);
  wrote("i18n.pack.remove", tag, {
    ...(gone.active ? { active: gone.active } : {}),
    ...(gone.candidate ? { candidate: gone.candidate } : {}),
  });
  return noContent();
});

// ---------------------------------------------------------------------------------
// The template

const getTemplate = route("get", "/api/v1/i18n/template.xlf", (ctx) => {
  requireSession();
  const language = ctx.query("language");
  const tag = language === null ? "en" : pathTag(language);
  // The route lists a response the typed reply cannot describe (XLIFF text, not JSON).
  return new Response(templateFor(tag), {
    status: 200,
    headers: {
      "Content-Type": "application/xliff+xml; charset=utf-8",
      "Content-Disposition": `attachment; filename="tenko-${tag}.xlf"`,
      "Cache-Control": "no-store",
    },
  });
});

export const i18nRoutes: HttpHandler[] = [
  getLanguages,
  getPack,
  listPacks,
  uploadPack,
  getReport,
  getCandidate,
  previewPack,
  activatePack,
  discardCandidate,
  deletePack,
  getTemplate,
];
